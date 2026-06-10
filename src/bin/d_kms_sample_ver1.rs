use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose;
use futures::StreamExt;
use libp2p::StreamProtocol;
use libp2p::Swarm;
use libp2p::SwarmBuilder;
use libp2p::mdns;
use libp2p::noise;
use libp2p::request_response;
use libp2p::request_response::ProtocolSupport;
use libp2p::swarm::NetworkBehaviour;
use libp2p::swarm::SwarmEvent;
use libp2p::tcp;
use libp2p::yamux;
use log::info;
use log::warn;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::time::Duration;
use threshold_crypto::PublicKeySet;
use threshold_crypto::SecretKeySet;
use threshold_crypto::SecretKeyShare;
use threshold_crypto::Signature;
use threshold_crypto::SignatureShare;
use threshold_crypto::serde_impl::SerdeSecret;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "MyBehaviourEvent")]
struct MyBehaviour {
    req_res: request_response::json::Behaviour<SignRequest, SignResponse>,
    mdns: mdns::tokio::Behaviour,
}

enum MyBehaviourEvent {
    ReqRes(request_response::Event<SignRequest, SignResponse>),
    Mdns(mdns::Event),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignRequest {
    message: String, // base64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignResponse {
    sig_share: Option<String>,    // base64 of SignatureShare
    index: Option<usize>,         // どのシェアか
    pubset_bytes: Option<String>, // base64 of PublicKeySet bytes
    error: Option<String>,
}

impl From<request_response::Event<SignRequest, SignResponse>> for MyBehaviourEvent {
    fn from(e: request_response::Event<SignRequest, SignResponse>) -> Self {
        MyBehaviourEvent::ReqRes(e)
    }
}

impl From<mdns::Event> for MyBehaviourEvent {
    fn from(e: mdns::Event) -> Self {
        MyBehaviourEvent::Mdns(e)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        unsafe {
            env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: cargo run -- <command> [args]");
        eprintln!("Commands:");
        eprintln!("  init <threshold> <n>  - 鍵シェアを生成します (例: 2 3)");
        eprintln!("  server <index>          - KMSサーバーノードを起動します (例: 0)");
        eprintln!("  client <message> <t>  - 署名をリクエストします (例: 'hello' 2)");
        return Ok(());
    }

    match args[1].as_str() {
        "init" => {
            let t: usize = args[2].parse().context("無効な threshold")?;
            let n: usize = args[3].parse().context("無効な n")?;
            init_shares(t, n).await?;
        }
        "server" => {
            let index: usize = args[2].parse().context("無効な index")?;
            start_node(index).await?;
        }
        "client" => {
            let message = args[2].clone();
            let threshold: usize = args[3].parse().context("無効な threshold")?;
            client_sign(&message, threshold).await?;
        }
        _ => {
            eprintln!("不明なコマンド: {}", args[1]);
        }
    }

    Ok(())
}

async fn init_shares(threshold: usize, n: usize) -> Result<()> {
    if n == 0 || threshold + 1 > n {
        return Err(anyhow!("無効な閾値/nの値です (t={}, n={})", threshold, n));
    }

    let mut rng = rand::thread_rng();
    let s = SecretKeySet::random(threshold, &mut rng);
    let public = s.public_keys();
    let pubset_bytes = bincode::serialize(&public)?;

    fs::write("pubset.key", &pubset_bytes)?;
    info!(
        "公開鍵セット 'pubset.key' を保存しました (t={}, n={})",
        threshold, n
    );

    for i in 0..n {
        let share = s.secret_key_share(i);
        let serde_share = SerdeSecret(share);
        let share_bytes = bincode::serialize(&serde_share)?;
        let path = format!("share-{}.key", i);
        fs::write(&path, share_bytes)?;
        info!("鍵シェア '{}' を保存しました", path);
    }

    Ok(())
}

async fn start_node(index: usize) -> Result<()> {
    let mut swarm = create_swarm().await?;
    let (share, pubset) = load_share(index).await?;
    let pubset_bytes_ser = bincode::serialize(&pubset)?;
    let pubset_b64 = general_purpose::STANDARD.encode(&pubset_bytes_ser);

    info!("サーバーがロードした PublicKeySet (Base64): {}", pubset_b64);

    _ = swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?);

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer, addr) in list {
                    info!("mDNS: ピア {} を発見({})", peer, addr);
                    swarm
                        .behaviour_mut()
                        .req_res
                        .add_address(&peer, addr.clone());
                }
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::ReqRes(request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
            })) => {
                info!("ピア {} から署名リクエストを受信", peer);
                let resp = match handle_sign_request(&request, &share).await {
                    Ok((sig_b64, digest)) => {
                        info!("署名シェアを生成しました (digest: {})", hex::encode(digest));
                        SignResponse {
                            sig_share: Some(sig_b64),
                            index: Some(index),
                            pubset_bytes: Some(pubset_b64.clone()),
                            error: None,
                        }
                    }
                    Err(e) => {
                        warn!("署名処理エラー: {:?}", e);
                        SignResponse {
                            sig_share: None,
                            index: None,
                            pubset_bytes: None,
                            error: Some(format!("{:?}", e)),
                        }
                    }
                };

                swarm
                    .behaviour_mut()
                    .req_res
                    .send_response(channel, resp)
                    .ok();
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::ReqRes(
                request_response::Event::ResponseSent { peer, .. },
            )) => {
                info!("ピア {} に署名シェアを送信完了", peer);
            }
            // 新しいリッスンアドレス
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("リッスン中: {}", address);
            }
            // その他のイベントは無視
            _ => {}
        }
    }
}

async fn client_sign(message: &str, threshold: usize) -> Result<()> {
    let mut swarm = create_swarm().await?;
    let pubset = load_pubset().await?;

    let pubset_bytes_ser = bincode::serialize(&pubset)?;
    let pubset_b64 = general_purpose::STANDARD.encode(&pubset_bytes_ser);

    info!(
        "クライアントがロードした PublicKeySet (Base64): {}",
        pubset_b64
    );

    let _ = swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    info!("クライアントノードを開始: {}", swarm.local_peer_id());

    let mut discovered_peers = HashSet::new();
    let mut shares_map: BTreeMap<usize, SignatureShare> = BTreeMap::new();

    info!("ピアを発見中... (5秒間)");
    let discovery_deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) = event {
                    for (peer, addr) in list {
                        if !discovered_peers.contains(&peer) {
                            info!("ピア {} を発見 ({})",peer,addr);
                            discovered_peers.insert(peer);
                            swarm.behaviour_mut().req_res.add_address(&peer, addr);
                        }
                    }
                }
            }

            _ = tokio::time::sleep_until(discovery_deadline) => {
                break;
            }
        }
    }

    if discovered_peers.is_empty() {
        return Err(anyhow!(
            "ピアが発見できませんでした。サーバーノードが実行されているか確認してください。"
        ));
    }
    info!(
        "{} 個のピアに署名リクエストを送信します...",
        discovered_peers.len()
    );

    let req = SignRequest {
        message: general_purpose::STANDARD.encode(message.as_bytes()),
    };

    for peer in &discovered_peers {
        swarm
            .behaviour_mut()
            .req_res
            .send_request(peer, req.clone());
    }

    info!("署名シェアを収集中... ({} 個必要)", threshold);
    let collection_deadline = tokio::time::Instant::now() + Duration::from_secs(60);

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(MyBehaviourEvent::ReqRes(
                    request_response::Event::Message { peer,  message: request_response::Message::Response { response, .. } },
                )
                ) = event {
                    if let Some(err) = &response.error{
                        warn!("ピア {} からエラー: {}", peer, err);
                        continue;
                    }
                    if let (Some(sig_b64), Some(idx)) = (response.sig_share, response.index) {
                        match decode_share(sig_b64) {
                            Ok(share) => {
                                info!("ピア {} から署名シェア (index={}) を受信", peer, idx);
                                shares_map.insert(idx, share);
                            }
                            Err(e) => warn!("ピア {} からのシェアのデコードに失敗: {}", peer, e),
                        }
                    }



                }
            }

            _ = tokio::time::sleep_until(collection_deadline) => {
                 warn!("収集タイムアウト");
                 break;
            }

        }

        if shares_map.len() >= threshold {
            info!(
                "閾値 ({}) 以上の署名シェアを収集完了 ({})",
                threshold,
                shares_map.len()
            );
            break;
        }
    }

    if shares_map.len() < threshold {
        return Err(anyhow!(
            "十分な署名シェアを集められませんでした ({} / {})",
            shares_map.len(),
            threshold
        ));
    }

    let combined_sig: Signature = pubset
        .combine_signatures(&shares_map)
        .map_err(|e| anyhow!("署名の結合に失敗: {:?}", e))?;

    // メッセージのダイジェストを再計算
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let digest = hasher.finalize();

    let pk = pubset.public_key();
    if pk.verify(&combined_sig, &digest) {
        let sig_bytes = bincode::serialize(&combined_sig)?;
        info!("署名の検証に成功しました！");
        println!("---");
        println!("メッセージ: {}", message);
        println!("結合済み署名 (hex): {}", hex::encode(&sig_bytes));
        println!("---");
        Ok(())
    } else {
        Err(anyhow!("結合された署名の検証に失敗しました。"))
    }
}

async fn create_swarm() -> Result<Swarm<MyBehaviour>> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let protocols = vec![(
                StreamProtocol::new("/distributed-kms/1.0.0"),
                ProtocolSupport::Full,
            )];

            let cfg = request_response::Config::default();

            // 【修正箇所】
            // json::Behaviour::new は (protocols, config) の引数のみを取ります。
            // Codec は内部で自動生成されるため不要です。
            let req_res =
                request_response::json::Behaviour::<SignRequest, SignResponse>::new(protocols, cfg);

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                    .unwrap();

            MyBehaviour { req_res, mdns }
        })?
        .build();
    Ok(swarm)
}

async fn load_share(index: usize) -> Result<(SecretKeyShare, PublicKeySet)> {
    let share_path = format!("share-{}.key", index);
    let serde_share_bytes = fs::read(share_path).context("Failed to read share file")?;
    let serde_share: SerdeSecret<SecretKeyShare> =
        bincode::deserialize(&serde_share_bytes).context("Failed to deserialize share serde")?;
    let key_share = serde_share.into_inner();

    let pubset_bytes = fs::read("pubset.key").context("Failed to read pubset.key")?;
    let pubset: PublicKeySet =
        bincode::deserialize(&pubset_bytes).context("Failed to deserialize pubset")?;

    Ok((key_share, pubset))
}

async fn handle_sign_request(
    req: &SignRequest,
    share: &SecretKeyShare,
) -> Result<(String, Vec<u8>)> {
    let msg = general_purpose::STANDARD.decode(&req.message)?;
    let mut hasher = Sha256::new();
    hasher.update(&msg);
    let digest = hasher.finalize();

    let sigshare = share.sign(&digest);
    let bytes = bincode::serialize(&sigshare)?;
    let b64 = general_purpose::STANDARD.encode(&bytes);
    Ok((b64, digest.to_vec()))
}

async fn load_pubset() -> Result<PublicKeySet> {
    let pubset_bytes = fs::read("pubset.key").context("Failed to read pubset.key")?;
    let pubset: PublicKeySet =
        bincode::deserialize(&pubset_bytes).context("Failed to deserialize pubset")?;
    Ok(pubset)
}

fn decode_share(sig_b64: String) -> Result<SignatureShare> {
    let sig_share_bytes = general_purpose::STANDARD.decode(&sig_b64)?;
    let sig_share: SignatureShare = bincode::deserialize(&sig_share_bytes)?;
    Ok(sig_share)
}
