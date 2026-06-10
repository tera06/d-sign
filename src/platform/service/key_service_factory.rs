use thiserror::Error;

use crate::{
    logic::service::{key_service::KeyService, key_service_factory::BuildKeyService},
    platform::{
        key::with_threshold_crypto::key_generator::KeyGenerator,
        repository::with_threshold_crypto::key_repository::{
            Crypter, PublicKeyRepository, SecretKeyShareRepository,
        },
        signature::digest_generator::DigestGenerator,
    },
};

pub struct KeyServiceFactory;

impl BuildKeyService<PublicKeyRepository, SecretKeyShareRepository, KeyGenerator, DigestGenerator>
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
            DigestGenerator,
        >,
        Self::TError,
    > {
        let crypter = Crypter;
        let public_key_repo =
            PublicKeyRepository::new("public_key.enc".to_string(), crypter.clone());

        let secret_key_share_repo =
            SecretKeyShareRepository::new("secret_key_share.enc".to_string(), crypter.clone())
                .ok_or_else(|| KeyServiceFactoryError::FailedCreateSecretKeyShareRepository)?;

        let key_generator = KeyGenerator;
        let digest_generator = DigestGenerator;

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
pub enum KeyServiceFactoryError {
    #[error("Failed to create secret key share reepository")]
    FailedCreateSecretKeyShareRepository,
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn key_service_factory_build_success() {
        let factory = KeyServiceFactory;
        let result = factory.build();
        assert!(result.is_ok());
    }
}
