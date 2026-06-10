use thiserror::Error;

use crate::core::model::{key::Signable, signature::SignatureShare};

impl Signable for threshold_crypto::SecretKeyShare {
    type TDigest = Vec<u8>;

    type TSignatureShare = threshold_crypto::SignatureShare;

    type TError = SecretKeyShareError;

    fn sign(
        &self,
        index: usize,
        digest: &crate::core::model::signature::Digest<Self::TDigest>,
    ) -> Result<crate::core::model::signature::SignatureShare<Self::TSignatureShare>, Self::TError>
    {
        let signature_share = self.sign(&digest.digest);
        let signature_share = SignatureShare::new(index, signature_share);
        Ok(signature_share)
    }
}

#[derive(Error, Debug)]
pub enum SecretKeyShareError {}

#[cfg(test)]
mod test {
    use rand::thread_rng;
    use threshold_crypto::SecretKeySet;

    use crate::{
        logic::service::key_service::GenerateDigest,
        platform::signature::digest_generator::DigestGenerator,
    };

    use super::*;

    #[test]
    fn secret_key_share_sign_success() {
        let mut rng = thread_rng();
        let secret_key_set = SecretKeySet::random(0, &mut rng);

        let secret_key_share = secret_key_set.secret_key_share(0);
        let digest_generator = DigestGenerator;
        let digest = digest_generator.generate_digest("message").unwrap();

        let result = Signable::sign(&secret_key_share, 0, &digest);
        assert!(result.is_ok());
    }
}
