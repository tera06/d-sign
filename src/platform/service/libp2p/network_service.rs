use std::{
    collections::HashSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose};
use futures::StreamExt;
use libp2p::{
    StreamProtocol, Swarm, SwarmBuilder, mdns, noise,
    request_response::{self, Message, ProtocolSupport},
    swarm::SwarmEvent,
    tcp, yamux,
};
use log::info;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    core::{
        model::{
            key::{CombineSignatureShares, Divisible, Signable, Verifiable},
            signature::SignatureShare,
            value::ShareIndex,
        },
        repository::key_repository::{PublicKeyStore, SecretKeyShareStore},
    },
    logic::service::{
        key_service::{GenerateDigest, GenerateKey, KeyService},
        network_service::NetworkService,
    },
    platform::service::libp2p::behaviour::{
        MyBehaviour, MyBehaviourEvent, SignRequest, SignResponse,
    },
};

pub struct P2pNetworkService<T, U, V, W> {
    key_service: KeyService<T, U, V, W>,
}

impl<T, U, V, W> P2pNetworkService<T, U, V, W> {
    pub fn new(key_service: KeyService<T, U, V, W>) -> Self {
        Self { key_service }
    }
    fn create_swarm(&self) -> Result<Swarm<MyBehaviour>, P2pNetworkServiceError> {
        let swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|_| P2pNetworkServiceError::FailedBuildSwarm)?
            .with_behaviour(|key| {
                let protocols = vec![(StreamProtocol::new("/d-sign/1.0.0"), ProtocolSupport::Full)];

                let cfg = request_response::Config::default();

                let req_res = request_response::json::Behaviour::<SignRequest, SignResponse>::new(
                    protocols, cfg,
                );
                let mdns =
                    mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                        .unwrap();

                MyBehaviour { req_res, mdns }
            })
            .map_err(|_| P2pNetworkServiceError::FailedBuildSwarm)?
            .build();

        Ok(swarm)
    }

    fn encode_signature_share<X>(
        &self,
        signature_share: &X,
    ) -> Result<String, P2pNetworkServiceError>
    where
        X: Serialize,
    {
        let signature_share_bytes = bincode::serialize(signature_share)
            .map_err(|_| P2pNetworkServiceError::FailedBincodeSerialize)?;
        let b64_signature_share_bytes = general_purpose::STANDARD.encode(signature_share_bytes);

        Ok(b64_signature_share_bytes)
    }

    fn decode_signature_share<X>(
        &self,
        encoded_signature_share: &str,
    ) -> Result<X, P2pNetworkServiceError>
    where
        X: for<'de> Deserialize<'de>,
    {
        let signature_share_bytes = general_purpose::STANDARD
            .decode(encoded_signature_share)
            .map_err(|_| P2pNetworkServiceError::FailedBase64Decode)?;
        let signature_share: X = bincode::deserialize(&signature_share_bytes)
            .map_err(|_| P2pNetworkServiceError::FailedBincodeDeserialize)?;

        Ok(signature_share)
    }
}

#[async_trait::async_trait]
impl<T, U, V, W> NetworkService for P2pNetworkService<T, U, V, W>
where
    T: PublicKeyStore<TPublicKey = V::TPublicKey> + Send + Sync,
    U: SecretKeyShareStore<TSecretKeyShare = <V::TSecretKey as Divisible>::TSecretKeyShare>
        + Send
        + Sync,
    V: GenerateKey + Send + Sync,
    W: GenerateDigest<TDigest = <V::TPublicKey as Verifiable>::TDigest> + Send + Sync,
    V::TSecretKey: Divisible,
    V::TPublicKey: CombineSignatureShares<TSignature = <V::TPublicKey as Verifiable>::TSignature>
        + Verifiable
        + Send
        + Sync,
    <V::TSecretKey as Divisible>::TSecretKeyShare:
        Signable<TDigest = <V::TPublicKey as Verifiable>::TDigest> + Send + Sync,
    <<<V as GenerateKey>::TSecretKey as Divisible>::TSecretKeyShare as Signable>::TSignatureShare:
        Serialize + for<'de> Deserialize<'de> + Send + Sync,
    <<V as GenerateKey>::TPublicKey as CombineSignatureShares>::TSignatureShare:
        for<'de> Deserialize<'de> + Send + Sync,
{
    type TError = P2pNetworkServiceError;

    async fn start_server(&self, index: ShareIndex) -> Result<(), Self::TError> {
        let mut swarm = self.create_swarm()?;

        let _ = swarm.listen_on(
            "/ip4/0.0.0.0/tcp/0"
                .parse()
                .map_err(|_| P2pNetworkServiceError::FailedAddrParse)?,
        );
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, multi_addr) in list {
                        swarm
                            .behaviour_mut()
                            .req_res
                            .add_address(&peer_id, multi_addr);
                    }
                }
                SwarmEvent::Behaviour(MyBehaviourEvent::ReqRes(
                    request_response::Event::Message {
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    },
                )) => {
                    let now_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    if request.timestamp + 300 < now_time {
                        let resp = SignResponse {
                            request_id: request.request_id.clone(),
                            timestamp: now_time,
                            index: None,
                            sign_share: None,
                            error: Some("stale request".to_string()),
                        };

                        swarm
                            .behaviour_mut()
                            .req_res
                            .send_response(channel, resp)
                            .ok();
                        continue;
                    }

                    let response =
                        match self.key_service.sign_message(index, &request.message).await {
                            Ok(signature_share) => {
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                let signature_share =
                                    self.encode_signature_share(&signature_share.signature_share)?;

                                SignResponse {
                                    request_id: request.request_id.clone(),
                                    timestamp: now,
                                    index: Some(index.get()),
                                    sign_share: Some(signature_share),
                                    error: None,
                                }
                            }
                            Err(e) => {
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                SignResponse {
                                    request_id: request.request_id.clone(),
                                    timestamp: now,
                                    index: None,
                                    sign_share: None,
                                    error: Some(format!("{}", e)),
                                }
                            }
                        };

                    let _ = swarm
                        .behaviour_mut()
                        .req_res
                        .send_response(channel, response);
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on {}", address);
                }
                _ => {}
            }
        }
    }

    async fn client_sign(&self, message: String, threshold: usize) -> Result<(), Self::TError> {
        let mut swarm = self.create_swarm()?;

        let _ = swarm.listen_on(
            "/ip4/0.0.0.0/tcp/0"
                .parse()
                .map_err(|_| P2pNetworkServiceError::FailedAddrParse)?,
        );

        let mut discovered_peer_ids = HashSet::new();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

        loop {
            tokio::select! {
                event = swarm.select_next_some() =>{
                    if let SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) = event{
                        for (peer_id, multi_addr) in list {
                            if !discovered_peer_ids.contains(&peer_id){
                                discovered_peer_ids.insert(peer_id);
                                swarm.behaviour_mut().req_res.add_address(&peer_id, multi_addr);
                            }
                        }
                    }
                }

                _ = tokio::time::sleep_until(deadline)=>{
                    break;
                }
            }
        }

        if discovered_peer_ids.is_empty() {
            return Err(P2pNetworkServiceError::NotFoundPeer);
        }
        info!("discoverd peers");
        let request_id = Uuid::new_v4().to_string();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let req = SignRequest {
            request_id: request_id.clone(),
            timestamp,
            message: message.clone(),
        };

        for peer_id in discovered_peer_ids {
            swarm
                .behaviour_mut()
                .req_res
                .send_request(&peer_id, req.clone());
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut signature_shares = Vec::new();

        loop {
            tokio::select! {
                     event = swarm.select_next_some()=>{
                         if let SwarmEvent::Behaviour(MyBehaviourEvent::ReqRes(request_response::Event::Message {  message : Message::Response { response,.. },.. })) = event{
                             if response.request_id != request_id{
                                 continue;
                             }

                             if response.error.is_some(){
                                 continue;
                             }

                             if let (Some(index), Some(encoded_signature_share)) = (response.index, response.sign_share){
                                 match self.decode_signature_share(&encoded_signature_share){
                                     Ok(signature_share)=>{
                                        let signature_share = SignatureShare::new(ShareIndex::new(index), signature_share);
                                         signature_shares.push(signature_share);

                                     }
                                     Err(_)=>{
                                         continue;
                                     }
                                 }

                             }
                         }
                     }
                     _ = tokio::time::sleep_until(deadline)=>{
                     break;
                 }

            }

            if signature_shares.len() >= threshold {
                break;
            }
        }

        if signature_shares.len() < threshold {
            return Err(P2pNetworkServiceError::NotEnoughSignatureShares);
        }

        let is_verify = self
            .key_service
            .verify_signature(&signature_shares, &message)
            .await
            .map_err(|_| P2pNetworkServiceError::FailedVerifySignatures)?;

        if is_verify {
            info!("Signature verification succeeded");
            println!("---");
            println!("Message: {}", message);
            println!("---");
        } else {
            return Err(P2pNetworkServiceError::FailedVerifySignatures);
        }

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum P2pNetworkServiceError {
    #[error("Failed to build swarm")]
    FailedBuildSwarm,
    #[error("Failed to parse address")]
    FailedAddrParse,

    #[error("Failed to bincode serialize")]
    FailedBincodeSerialize,
    #[error("Not found peer")]
    NotFoundPeer,
    #[error("Failed to base 64 decode")]
    FailedBase64Decode,
    #[error("Failed to bincode deserialize")]
    FailedBincodeDeserialize,
    #[error("Not enough signature shares")]
    NotEnoughSignatureShares,
    #[error("Failed to verify signatures")]
    FailedVerifySignatures,
}
