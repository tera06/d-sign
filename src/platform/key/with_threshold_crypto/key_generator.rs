use rand::thread_rng;
use thiserror::Error;
use threshold_crypto::SecretKeySet;

use crate::{
    core::model::key::{PublicKey, SecretKey},
    logic::service::key_service::GenerateKey,
};

pub struct KeyGenerator;

impl GenerateKey for KeyGenerator {
    type TError = KeyGeneratorError;

    type TPublicKey = threshold_crypto::PublicKeySet;

    type TSecretKey = threshold_crypto::SecretKeySet;

    fn generate_keys(
        &self,
        threshold: usize,
        num_divide: usize,
    ) -> Result<
        (
            crate::core::model::key::PublicKey<Self::TPublicKey>,
            crate::core::model::key::SecretKey<Self::TSecretKey>,
        ),
        Self::TError,
    > {
        if (threshold > num_divide) || (num_divide < 1) || (threshold < 1) {
            return Err(KeyGeneratorError::InvalidArgument);
        }
        let mut rng = thread_rng();
        let secret_key_set = SecretKeySet::random(threshold - 1, &mut rng);
        let public_key_set = secret_key_set.public_keys();

        let public_key = PublicKey::new(public_key_set);
        let secret_key = SecretKey::new(threshold, num_divide, secret_key_set)
            .ok_or(KeyGeneratorError::FailedGenerateSecretKey)?;

        Ok((public_key, secret_key))
    }
}

#[derive(Error, Debug)]
pub enum KeyGeneratorError {
    #[error("Invalid argument")]
    InvalidArgument,
    #[error("Failed to generate secret key")]
    FailedGenerateSecretKey,
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn key_generator_generate_keys_success() {
        let key_generator = KeyGenerator;
        let result = key_generator.generate_keys(2, 3);
        assert!(result.is_ok());
    }

    #[test]
    fn key_generator_generate_keys_invalid_arg_threshold_is_greater_num_divide() {
        let key_generator = KeyGenerator;
        let result = key_generator.generate_keys(3, 2);
        assert!(matches!(
            result.err().unwrap(),
            KeyGeneratorError::InvalidArgument
        ));
    }

    #[test]
    fn key_generator_generates_keys_invalid_arg_threshold_is_zero() {
        let key_generator = KeyGenerator;
        let result = key_generator.generate_keys(0, 2);
        assert!(matches!(
            result.err().unwrap(),
            KeyGeneratorError::InvalidArgument
        ));
    }

    #[test]
    fn key_generator_generates_keys_invalid_arg_num_divide_is_zero() {
        let key_generator = KeyGenerator;
        let result = key_generator.generate_keys(2, 0);
        assert!(matches!(
            result.err().unwrap(),
            KeyGeneratorError::InvalidArgument
        ));
    }
}
