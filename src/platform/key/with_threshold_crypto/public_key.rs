use thiserror::Error;

use crate::core::model::{
    key::{CombineSignatureShares, Verifiable},
    signature::Signature,
};

impl Verifiable for threshold_crypto::PublicKeySet {
    type TSignature = threshold_crypto::Signature;

    type TDigest = Vec<u8>;

    type TError = PublicKeySetError;

    fn verify(
        &self,
        signature: &crate::core::model::signature::Signature<Self::TSignature>,
        digest: &crate::core::model::signature::Digest<Self::TDigest>,
    ) -> Result<bool, Self::TError> {
        let public_key = self.public_key();
        let is_valid = public_key.verify(&signature.signature, &digest.digest);
        Ok(is_valid)
    }
}

impl CombineSignatureShares for threshold_crypto::PublicKeySet {
    type TSignatureShare = threshold_crypto::SignatureShare;

    type TSignature = threshold_crypto::Signature;

    type TError = PublicKeySetError;

    fn combine_signature_shares(
        &self,
        signature_shares: &[crate::core::model::signature::SignatureShare<
            threshold_crypto::SignatureShare,
        >],
    ) -> Result<crate::core::model::signature::Signature<Self::TSignature>, Self::TError> {
        let shares_for_combine = signature_shares
            .iter()
            .map(|s| (s.index.get(), &s.signature_share));

        let signature = self
            .combine_signatures(shares_for_combine)
            .map_err(|_| PublicKeySetError::FailedCombineSignature)?;
        let signature = Signature::new(signature);
        Ok(signature)
    }
}

#[derive(Error, Debug)]
pub enum PublicKeySetError {
    #[error("Failed to combine signature")]
    FailedCombineSignature,
}

#[cfg(test)]
mod test {
    use crate::{
        core::model::{signature::SignatureShare, value::ShareIndex},
        logic::service::key_service::GenerateDigest,
        platform::signature::digest_generator::DigestGenerator,
    };

    use super::*;
    use rand::thread_rng;
    use threshold_crypto::SecretKeySet;

    #[test]
    fn public_key_set_verify_success() {
        let mut rng = thread_rng();
        let secret_key_set = SecretKeySet::random(0, &mut rng);

        let public_key_set = secret_key_set.public_keys();
        let secret_key_share = secret_key_set.secret_key_share(0);

        let message = "message";
        let digest_generator = DigestGenerator;
        let digest = digest_generator.generate_digest(message).unwrap();

        let signature_share = secret_key_share.sign(&digest.digest);
        let signature_shares = vec![SignatureShare::new(ShareIndex::new(0), signature_share)];

        let signature = public_key_set
            .combine_signature_shares(&signature_shares)
            .unwrap();

        let result = public_key_set.verify(&signature, &digest);
        let is_valid = result.ok().unwrap();

        assert!(is_valid);
    }

    #[test]
    fn public_key_set_verify_failed() {
        let mut rng = thread_rng();
        let secret_key_set = SecretKeySet::random(0, &mut rng);

        let public_key_set = secret_key_set.public_keys();
        let secret_key_share = secret_key_set.secret_key_share(0);

        let digest_generator = DigestGenerator;

        let fake_message = "fake_message";
        let fake_digest = digest_generator.generate_digest(fake_message).unwrap();

        let message = "message";
        let digest = digest_generator.generate_digest(message).unwrap();

        let signature_share = secret_key_share.sign(&digest.digest);
        let signature_shares = vec![SignatureShare::new(ShareIndex::new(0), signature_share)];

        let signature = public_key_set
            .combine_signature_shares(&signature_shares)
            .unwrap();

        let result = public_key_set.verify(&signature, &fake_digest);
        let is_valid = result.ok().unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn public_key_set_combine_sinature_shares_success() {
        let mut rng = thread_rng();
        let secret_key_set = SecretKeySet::random(1, &mut rng);

        let public_key_set = secret_key_set.public_keys();

        let message = "message";

        let share1 = secret_key_set.secret_key_share(0).sign(message);
        let share2 = secret_key_set.secret_key_share(1).sign(message);

        let shares = vec![
            SignatureShare::new(ShareIndex::new(0), share1),
            SignatureShare::new(ShareIndex::new(1), share2),
        ];

        let result = public_key_set.combine_signature_shares(&shares);
        assert!(result.is_ok());
    }
    #[test]
    fn publci_key_set_combine_signature_shares_fail() {
        let mut rng = thread_rng();
        let secret_key_set = SecretKeySet::random(1, &mut rng);

        let public_key_set = secret_key_set.public_keys();

        let message = "message";

        let share1 = secret_key_set.secret_key_share(0).sign(message);

        let shares = vec![SignatureShare::new(ShareIndex::new(0), share1)];

        let result = public_key_set.combine_signature_shares(&shares);
        assert!(matches!(
            result.err().unwrap(),
            PublicKeySetError::FailedCombineSignature,
        ));
    }
}
