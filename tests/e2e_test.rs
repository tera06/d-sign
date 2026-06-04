use assert_cmd::Command as AssertCommand;
use base64::Engine;
use base64::engine::general_purpose;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[test]
fn e2e_threshold_sign() {
    unsafe {
        std::env::set_var(
            "DSIGN_MASTER_KEY",
            general_purpose::STANDARD.encode([1u8; 32]),
        );
    }
    // 初期化
    AssertCommand::cargo_bin("d-sign")
        .unwrap()
        .args(["init", "2", "3"])
        .assert()
        .success();

    // サーバー起動
    let exe = assert_cmd::cargo::cargo_bin("d-sign");

    let mut s1 = Command::new(&exe).args(["server", "0"]).spawn().unwrap();

    let mut s2 = Command::new(&exe).args(["server", "1"]).spawn().unwrap();

    let mut s3 = Command::new(&exe).args(["server", "2"]).spawn().unwrap();

    // 起動待ち
    thread::sleep(Duration::from_secs(10));

    // 署名実行
    AssertCommand::cargo_bin("d-sign")
        .unwrap()
        .args(["client", "hello", "2"])
        .assert()
        .success();

    // 後始末
    s1.kill().unwrap();
    s2.kill().unwrap();
    s3.kill().unwrap();

    let _ = s1.wait();
    let _ = s2.wait();
    let _ = s3.wait();
}
