use thiserror::Error;

use crate::{
    logic::service::{key_service::KeyService, network_service_factory::BuildNetworkService},
    platform::{
        key::with_threshold_crypto::key_generator::KeyGenerator,
        repository::with_threshold_crypto::key_repository::{
            Crypter, PublicKeyRepository, SecretKeyShareRepository,
        },
        service::libp2p::network_service::P2pNetworkService,
        signature::digest_generator::DigestGenerator,
    },
};

pub struct P2pNetworkServiceFactory;
impl BuildNetworkService for P2pNetworkServiceFactory {
    type TError = P2pNetworkServiceFactoryError;

    type TNetworkService = P2pNetworkService<
        PublicKeyRepository,
        SecretKeyShareRepository,
        KeyGenerator,
        DigestGenerator,
    >;

    fn build(&self) -> Result<Self::TNetworkService, Self::TError> {
        let crypter = Crypter;
        let public_key_repo =
            PublicKeyRepository::new("public_key.enc".to_string(), crypter.clone());

        let secret_key_share_repo =
            SecretKeyShareRepository::new("secret_key_share.enc".to_string(), crypter.clone())
                .ok_or(P2pNetworkServiceFactoryError::FailedCreateSecretKeyShareRepository)?;

        let key_generator = KeyGenerator;
        let digest_generator = DigestGenerator;

        let key_service = KeyService::new(
            public_key_repo,
            secret_key_share_repo.clone(),
            key_generator,
            digest_generator,
        );
        let network_service = P2pNetworkService::new(key_service);

        Ok(network_service)
    }
}

#[derive(Debug, Error)]
pub enum P2pNetworkServiceFactoryError {
    #[error("Failed to create secret key share repository")]
    FailedCreateSecretKeyShareRepository,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn p2p_network_service_factory_build_success() {
        let factory = P2pNetworkServiceFactory;
        let result = factory.build();
        assert!(result.is_ok());
    }
}
