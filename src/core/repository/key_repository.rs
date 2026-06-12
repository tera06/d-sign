use crate::core::model::key::{PublicKey, SecretKeyShare};
#[async_trait::async_trait]
pub trait PublicKeyStore {
    type TPublicKey;
    type TError: std::error::Error + Send + Sync + 'static;
    async fn save(&self, public_key: &PublicKey<Self::TPublicKey>) -> Result<(), Self::TError>;
    async fn load(&self) -> Result<PublicKey<Self::TPublicKey>, Self::TError>;
}

#[async_trait::async_trait]
pub trait SecretKeyShareStore {
    type TSecretKeyShare;
    type TError: std::error::Error + Send + Sync + 'static;
    async fn save(
        &self,
        secret_key_share: &SecretKeyShare<Self::TSecretKeyShare>,
    ) -> Result<(), Self::TError>;
    async fn load(
        &self,
        index: usize,
    ) -> Result<SecretKeyShare<Self::TSecretKeyShare>, Self::TError>;
}
