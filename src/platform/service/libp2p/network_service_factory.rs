use thiserror::Error;

use crate::{
    logic::service::{key_service::KeyService, network_service_factory::BuildNetworkSerivce},
    platform::{
        key::with_threshold_crypto::key_generator::KeyGenerator,
        repository::with_threshold_crypto::key_repository::{
            Crypter, PublicKeyRepository, SecretKeyShareRepository,
        },
        service::libp2p::network_service::P2pNetworkService,
        signature::digest_generator::DigestGenarator,
    },
};

pub struct P2pNetworkServiceFactory;
impl BuildNetworkSerivce for P2pNetworkServiceFactory {
    type TError = P2pNetworkServiceFactoryError;

    type TNetworkService = P2pNetworkService<
        PublicKeyRepository,
        SecretKeyShareRepository,
        KeyGenerator,
        DigestGenarator,
    >;

    fn build(&self) -> Result<Self::TNetworkService, Self::TError> {
        let crypter = Crypter;
        let public_key_repo =
            PublicKeyRepository::new("public_key.enc".to_string(), crypter.clone());

        let secret_key_share_repo =
            SecretKeyShareRepository::new("secrete_key_share.enc".to_string(), crypter.clone())
                .unwrap();

        let key_generator = KeyGenerator;
        let digest_generator = DigestGenarator;

        let key_service = KeyService::new(
            public_key_repo,
            secret_key_share_repo.clone(),
            key_generator,
            digest_generator,
        );
        let network_service = P2pNetworkService::new(secret_key_share_repo, key_service);

        Ok(network_service)
    }
}

#[derive(Debug, Error)]
pub enum P2pNetworkServiceFactoryError {}
