use std::time::Duration;

use base64::{Engine, engine::general_purpose};

use d_sign::ui::runner::{AppAction, AppRunner};

#[tokio::test]
async fn threshold_signature_success() {
    unsafe {
        std::env::set_var(
            "DSIGN_MASTER_KEY",
            general_purpose::STANDARD.encode([1u8; 32]),
        );
    }

    AppRunner::run(AppAction::Init { threshold: 2, n: 3 })
        .await
        .unwrap();

    let server1 = tokio::spawn(async { AppRunner::run(AppAction::Server { index: 0 }).await });

    let server2 = tokio::spawn(async { AppRunner::run(AppAction::Server { index: 1 }).await });

    let server3 = tokio::spawn(async { AppRunner::run(AppAction::Server { index: 2 }).await });

    tokio::time::sleep(Duration::from_secs(10)).await;

    let result = AppRunner::run(AppAction::Client {
        message: "hello".to_string(),
        threshold: 2,
    })
    .await;

    assert!(result.is_ok());

    server1.abort();
    server2.abort();
    server3.abort();
}
