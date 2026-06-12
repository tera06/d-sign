use crate::core::{
    model::{
        key::{CombineSignatureShares, Divisible, PublicKey, SecretKey, Signable, Verifiable},
        signature::{Digest, SignatureShare},
    },
    repository::key_repository::{PublicKeyStore, SecretKeyShareStore},
};
use thiserror::Error;

pub struct KeyService<T, U, V, W> {
    public_key_repo: T,
    secret_key_share_repo: U,
    key_generator: V,
    digest_generator: W,
}

impl<T, U, V, W> KeyService<T, U, V, W>
where
    T: PublicKeyStore<TPublicKey = V::TPublicKey>,
    U: SecretKeyShareStore<TSecretKeyShare = <V::TSecretKey as Divisible>::TSecretKeyShare>,
    V: GenerateKey,
    W: GenerateDigest<TDigest = <V::TPublicKey as Verifiable>::TDigest>,
    V::TSecretKey: Divisible,
    V::TPublicKey:
        CombineSignatureShares<TSignature = <V::TPublicKey as Verifiable>::TSignature> + Verifiable,
    <V::TSecretKey as Divisible>::TSecretKeyShare:
        Signable<TDigest = <V::TPublicKey as Verifiable>::TDigest>,
{
    pub fn new(
        public_key_repo: T,
        secret_key_share_repo: U,
        key_generator: V,
        digest_generator: W,
    ) -> Self {
        Self {
            public_key_repo,
            secret_key_share_repo,
            key_generator,
            digest_generator,
        }
    }

    pub async fn init_keys(
        &self,
        threshold: usize,
        num_divide: usize,
    ) -> Result<(), KeyServiceError> {
        let (public_key, secret_key) = self
            .key_generator
            .generate_keys(threshold, num_divide)
            .map_err(|_| KeyServiceError::FailedGenerateKeys)?;

        let secret_key_shares = secret_key
            .divide()
            .map_err(|_| KeyServiceError::FailedCreateSecretKeyShares)?;

        self.public_key_repo
            .save(&public_key)
            .await
            .map_err(|_| KeyServiceError::FailedSavePublicKey)?;
        for share in &secret_key_shares {
            self.secret_key_share_repo
                .save(share)
                .await
                .map_err(|_| KeyServiceError::FailedSaveSecretKeyShare)?;
        }

        Ok(())
    }

    pub async fn sign_message(
        &self,
        index: usize,
        message: &str,
    ) -> Result<
        SignatureShare<
            <<V::TSecretKey as Divisible>::TSecretKeyShare as Signable>::TSignatureShare,
        >,
        KeyServiceError,
    > {
        let secret_key_share = self
            .secret_key_share_repo
            .load(index)
            .await
            .map_err(|_| KeyServiceError::FailedLoadSecretKeyShare)?;

        let digest = self
            .digest_generator
            .generate_digest(message)
            .map_err(|_| KeyServiceError::FailedGenerateDigest)?;

        let signature_share = secret_key_share
            .sign(&digest)
            .map_err(|_| KeyServiceError::FailedSignDigest)?;

        Ok(signature_share)
    }

    pub async fn verify_signature(
        &self,
        signature_shares: &Vec<
            SignatureShare<<V::TPublicKey as CombineSignatureShares>::TSignatureShare>,
        >,
        message: &str,
    ) -> Result<bool, KeyServiceError> {
        let public_key = self
            .public_key_repo
            .load()
            .await
            .map_err(|_| KeyServiceError::FailedLoadPublicKey)?;

        let signature = public_key
            .combine_signature_shares(signature_shares)
            .map_err(|_| KeyServiceError::FailedCombineSignatureShares)?;

        let digest = self
            .digest_generator
            .generate_digest(message)
            .map_err(|_| KeyServiceError::FailedGenerateDigest)?;

        let is_verify = public_key
            .verify(&signature, &digest)
            .map_err(|_| KeyServiceError::FailedVerifySignature)?;

        Ok(is_verify)
    }
}

#[derive(Error, Debug)]
pub enum KeyServiceError {
    #[error("Failed to generate keys")]
    FailedGenerateKeys,

    #[error("Failed to create secret key shares")]
    FailedCreateSecretKeyShares,

    #[error("Failed to save public key")]
    FailedSavePublicKey,

    #[error("Failed to load public key")]
    FailedLoadPublicKey,

    #[error("Failed to save secret key share")]
    FailedSaveSecretKeyShare,

    #[error("Failed to load secret key share")]
    FailedLoadSecretKeyShare,

    #[error("Failed to generate digest")]
    FailedGenerateDigest,

    #[error("Failed to sign digest")]
    FailedSignDigest,

    #[error("Failed to combine signature shares")]
    FailedCombineSignatureShares,

    #[error("Failed to verify signature")]
    FailedVerifySignature,
}
pub trait GenerateKey {
    type TError: std::error::Error;
    type TPublicKey;
    type TSecretKey;
    fn generate_keys(
        &self,
        threshold: usize,
        num_divide: usize,
    ) -> Result<(PublicKey<Self::TPublicKey>, SecretKey<Self::TSecretKey>), Self::TError>;
}

pub trait GenerateDigest {
    type TError: std::error::Error;
    type TDigest;

    fn generate_digest(&self, message: &str) -> Result<Digest<Self::TDigest>, Self::TError>;
}

#[cfg(test)]
mod test {

    use mockall::{Sequence, mock};

    use crate::core::model::{key::SecretKeyShare, signature::Signature};
    use crate::core::repository::key_repository::PublicKeyStore;

    use super::*;
    struct DummyPublicKey;
    struct DummySecretKey;
    struct DummySecretKeyShare;
    struct DummyDigest;
    struct DummySignature;
    struct DummySignatureShare;

    #[derive(Error, Debug)]
    enum DummyError {}

    impl Verifiable for DummyPublicKey {
        type TSignature = DummySignature;

        type TDigest = DummyDigest;

        type TError = DummyError;

        fn verify(
            &self,
            _signature: &crate::core::model::signature::Signature<Self::TSignature>,
            _digest: &Digest<Self::TDigest>,
        ) -> Result<bool, Self::TError> {
            Ok(true)
        }
    }

    impl CombineSignatureShares for DummyPublicKey {
        type TSignatureShare = DummySignatureShare;

        type TSignature = DummySignature;

        type TError = DummyError;

        fn combine_signature_shares(
            &self,
            _signature_shares: &Vec<SignatureShare<Self::TSignatureShare>>,
        ) -> Result<crate::core::model::signature::Signature<Self::TSignature>, Self::TError>
        {
            Ok(Signature::new(DummySignature))
        }
    }

    impl Divisible for DummySecretKey {
        type TSecretKeyShare = DummySecretKeyShare;

        type TError = DummyError;

        fn divide(
            &self,
            num_divide: usize,
        ) -> Result<Vec<crate::core::model::key::SecretKeyShare<Self::TSecretKeyShare>>, Self::TError>
        {
            Ok((0..num_divide)
                .map(|i| SecretKeyShare::new(i, DummySecretKeyShare))
                .collect())
        }
    }

    impl Signable for DummySecretKeyShare {
        type TDigest = DummyDigest;

        type TSignatureShare = DummySignatureShare;

        type TError = DummyError;

        fn sign(
            &self,
            index: usize,
            _digest: &Digest<Self::TDigest>,
        ) -> Result<SignatureShare<Self::TSignatureShare>, Self::TError> {
            Ok(SignatureShare {
                index,
                signature_share: DummySignatureShare,
            })
        }
    }

    #[derive(Error, Debug)]
    enum MockError {
        #[error("Failed to generate keys")]
        FailedGenerateKeys,
        #[error("Failed to load secret key share")]
        FailedLoadSecretKeyShare,
        #[error("Failed to load public key")]
        FailedLoadPublicKey,
    }

    mock! {
        PublicKeyStore {}
        #[async_trait::async_trait]
        impl PublicKeyStore for PublicKeyStore {
            type TPublicKey = DummyPublicKey;
            type TError = MockError;

            async fn save(&self, key: &PublicKey<DummyPublicKey>) -> Result<(), MockError>;
            async fn load(&self) -> Result<PublicKey<DummyPublicKey>, MockError>;
        }
    }

    mock! {
        SecretKeyShareStore{}
        #[async_trait::async_trait]
        impl SecretKeyShareStore for SecretKeyShareStore{
            type TSecretKeyShare =DummySecretKeyShare;
            type TError = MockError;

            async fn save(&self, secret_key_share: &SecretKeyShare<DummySecretKeyShare>,) -> Result<(), MockError>;
            async fn load( &self, index: usize) -> Result<SecretKeyShare<DummySecretKeyShare>, MockError>;
        }
    }

    mock! {
        GenerateKey{}

        impl GenerateKey for GenerateKey {
            type TError = MockError;
            type TPublicKey = DummyPublicKey;
            type TSecretKey = DummySecretKey;
            fn generate_keys(
                &self,
                threshold: usize,
                num_divide: usize,
            ) -> Result<(PublicKey<DummyPublicKey>, SecretKey<DummySecretKey>), MockError>;
        }
    }

    mock! {
        GenerateDigest{}
        impl GenerateDigest for GenerateDigest {
            type TError = MockError;
            type TDigest = DummyDigest;

                fn generate_digest(&self, message: &str) -> Result<Digest<DummyDigest>, MockError>;
        }
    }

    #[tokio::test]
    async fn key_service_init_keys_success() {
        let mut public_key_repo = MockPublicKeyStore::new();
        let mut secret_key_share_repo = MockSecretKeyShareStore::new();
        let mut key_generator = MockGenerateKey::new();
        let digest_generator = MockGenerateDigest::new();

        let mut sequence = Sequence::new();

        key_generator
            .expect_generate_keys()
            .times(1)
            .in_sequence(&mut sequence)
            .returning(|_, _| {
                Ok((
                    PublicKey::new(DummyPublicKey),
                    SecretKey::new(2, 3, DummySecretKey).unwrap(),
                ))
            });

        public_key_repo
            .expect_save()
            .times(1)
            .in_sequence(&mut sequence)
            .returning(|_| Ok(()));

        secret_key_share_repo
            .expect_save()
            .times(3)
            .in_sequence(&mut sequence)
            .returning(|_| Ok(()));

        let key_service = KeyService::new(
            public_key_repo,
            secret_key_share_repo,
            key_generator,
            digest_generator,
        );

        let result = key_service.init_keys(2, 3).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn key_service_init_keys_fail_generate_keys() {
        let public_key_repo = MockPublicKeyStore::new();
        let secret_key_share_repo = MockSecretKeyShareStore::new();
        let mut key_generator = MockGenerateKey::new();
        let digest_generator = MockGenerateDigest::new();

        key_generator
            .expect_generate_keys()
            .times(1)
            .returning(|_, _| Err(MockError::FailedGenerateKeys));

        let key_service = KeyService::new(
            public_key_repo,
            secret_key_share_repo,
            key_generator,
            digest_generator,
        );

        let result = key_service.init_keys(2, 3).await;
        assert!(matches!(
            result.unwrap_err(),
            KeyServiceError::FailedGenerateKeys
        ));
    }

    #[tokio::test]
    async fn ker_service_sign_messages_success() {
        let public_key_repo = MockPublicKeyStore::new();
        let mut secret_key_share_repo = MockSecretKeyShareStore::new();
        let key_generator = MockGenerateKey::new();
        let mut digest_generator = MockGenerateDigest::new();

        let mut seq = Sequence::new();

        secret_key_share_repo
            .expect_load()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(SecretKeyShare::new(0, DummySecretKeyShare)));

        digest_generator
            .expect_generate_digest()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(Digest::new(DummyDigest)));

        let key_service = KeyService::new(
            public_key_repo,
            secret_key_share_repo,
            key_generator,
            digest_generator,
        );

        let result = key_service.sign_message(0, "message").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn key_service_sign_messages_fail_load_secret_key_share() {
        let public_key_repo = MockPublicKeyStore::new();
        let mut secret_key_share_repo = MockSecretKeyShareStore::new();
        let key_generator = MockGenerateKey::new();
        let digest_generator = MockGenerateDigest::new();

        secret_key_share_repo
            .expect_load()
            .times(1)
            .returning(|_| Err(MockError::FailedLoadSecretKeyShare));

        let key_service = KeyService::new(
            public_key_repo,
            secret_key_share_repo,
            key_generator,
            digest_generator,
        );

        let result = key_service.sign_message(0, "message").await;
        assert!(matches!(
            result.err().unwrap(),
            KeyServiceError::FailedLoadSecretKeyShare
        ));
    }

    #[tokio::test]
    async fn key_service_verify_signature_success() {
        let mut public_key_repo = MockPublicKeyStore::new();
        let secret_key_share_repo = MockSecretKeyShareStore::new();
        let key_generator = MockGenerateKey::new();
        let mut digest_generator = MockGenerateDigest::new();

        let mut seq = Sequence::new();

        public_key_repo
            .expect_load()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|| Ok(PublicKey::new(DummyPublicKey)));

        digest_generator
            .expect_generate_digest()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(Digest::new(DummyDigest)));
        let key_service = KeyService::new(
            public_key_repo,
            secret_key_share_repo,
            key_generator,
            digest_generator,
        );

        let signature_shares = vec![
            SignatureShare::new(0, DummySignatureShare),
            SignatureShare::new(1, DummySignatureShare),
        ];
        let result = key_service
            .verify_signature(&signature_shares, "message")
            .await;
        assert!(result.ok().unwrap());
    }

    #[tokio::test]
    async fn key_service_verify_signature_fail_load_public_key() {
        let mut public_key_repo = MockPublicKeyStore::new();
        let secret_key_share_repo = MockSecretKeyShareStore::new();
        let key_generator = MockGenerateKey::new();
        let digest_generator = MockGenerateDigest::new();

        let mut seq = Sequence::new();

        public_key_repo
            .expect_load()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|| Err(MockError::FailedLoadPublicKey));

        let key_service = KeyService::new(
            public_key_repo,
            secret_key_share_repo,
            key_generator,
            digest_generator,
        );

        let signature_shares = vec![
            SignatureShare::new(0, DummySignatureShare),
            SignatureShare::new(1, DummySignatureShare),
        ];
        let result = key_service
            .verify_signature(&signature_shares, "message")
            .await;
        assert!(matches!(
            result.err().unwrap(),
            KeyServiceError::FailedLoadPublicKey
        ));
    }
}
