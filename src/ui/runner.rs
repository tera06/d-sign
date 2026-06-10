use thiserror::Error;

use crate::{
    logic::service::{
        key_service_factory::BuildKeyService, network_service::NetworkService,
        network_service_factory::BuildNetworkService,
    },
    platform::service::{
        key_service_factory::KeyServiceFactory,
        libp2p::network_service_factory::P2pNetworkServiceFactory,
    },
};

pub enum AppAction {
    Init { threshold: usize, n: usize },
    Server { index: usize },
    Client { message: String, threshold: usize },
}

pub struct AppRunner;

impl AppRunner {
    pub async fn run(action: AppAction) -> Result<(), AppRunnerError> {
        match action {
            AppAction::Init { threshold, n } => {
                let key_service_factory = KeyServiceFactory;
                let key_service = key_service_factory
                    .build()
                    .map_err(|_| AppRunnerError::FailedBuildKeyService)?;
                key_service
                    .init_keys(threshold, n)
                    .await
                    .map_err(|_| AppRunnerError::FailedInitKeys)?;
            }
            AppAction::Server { index } => {
                let network_service_factory = P2pNetworkServiceFactory;
                let network_service = network_service_factory
                    .build()
                    .map_err(|_| AppRunnerError::FailedBuildNetworkService)?;
                network_service
                    .start_server(index)
                    .await
                    .map_err(|_| AppRunnerError::FailedStartServer)?;
            }
            AppAction::Client { message, threshold } => {
                let network_service_factory = P2pNetworkServiceFactory;
                let network_service = network_service_factory
                    .build()
                    .map_err(|_| AppRunnerError::FailedBuildNetworkService)?;
                network_service
                    .client_sign(message, threshold)
                    .await
                    .map_err(|_| AppRunnerError::FailedClientSign)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum AppRunnerError {
    #[error("Failed to build key service")]
    FailedBuildKeyService,
    #[error("Failed to init keys")]
    FailedInitKeys,
    #[error("Failed to build network service")]
    FailedBuildNetworkService,
    #[error("Failed to start server")]
    FailedStartServer,
    #[error("Failed to client sign")]
    FailedClientSign,
}
