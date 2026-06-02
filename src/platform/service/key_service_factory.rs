use thiserror::Error;

use crate::{
    logic::service::{key_service::KeyService, key_service_factory::BuildKeyService},
    platform::{
        key::with_threshold_crypto::key_generator::KeyGenerator,
        repository::with_threshold_crypto::key_repository::{
            Crypter, PublicKeyRepository, SecretKeyShareRepository,
        },
        signature::digest_generator::DigestGenarator,
    },
};

pub struct KeyServiceFactory;

impl BuildKeyService<PublicKeyRepository, SecretKeyShareRepository, KeyGenerator, DigestGenarator>
    for KeyServiceFactory
{
    type TError = KeyServiceFactoryError;

    fn build(
        &self,
    ) -> Result<
        crate::logic::service::key_service::KeyService<
            PublicKeyRepository,
            SecretKeyShareRepository,
            KeyGenerator,
            DigestGenarator,
        >,
        Self::TError,
    > {
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
            secret_key_share_repo,
            key_generator,
            digest_generator,
        );

        Ok(key_service)
    }
}
#[derive(Debug, Error)]
pub enum KeyServiceFactoryError {}
