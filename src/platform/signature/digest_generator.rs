use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::logic::service::key_service::GenerateDigest;

pub struct DigestGenarator;

impl GenerateDigest for DigestGenarator {
    type TError = DigestGenaratorError;

    type TDigest = Vec<u8>;

    fn generate_digest(
        &self,
        message: &str,
    ) -> Result<crate::core::model::signature::Digest<Self::TDigest>, Self::TError> {
        if message.is_empty() {
            return Err(DigestGenaratorError::MessageIsEmpty);
        }
        let mut hasher = Sha256::new();
        hasher.update(&message);
        let digest = hasher.finalize();

        let digest = crate::core::model::signature::Digest::new(digest.to_vec());

        Ok(digest)
    }
}

#[derive(Error, Debug)]
pub enum DigestGenaratorError {
    #[error("Message is empty")]
    MessageIsEmpty,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_generator_generate_digest_success() {
        let digest_generator = DigestGenarator;

        let message = "message";
        let result = digest_generator.generate_digest(message);
        assert!(result.is_ok());
    }

    #[test]
    fn digest_generator_generate_digest_fail_when_message_is_empty() {
        let digest_generator = DigestGenarator;

        let message = "";
        let result = digest_generator.generate_digest(message);
        assert!(result.is_err());
    }
}
