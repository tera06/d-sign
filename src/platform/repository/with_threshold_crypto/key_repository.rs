use std::{fs, path::Path};

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng},
    aes::cipher::Unsigned,
};
use base64::{Engine, engine::general_purpose};
use thiserror::Error;
use threshold_crypto::serde_impl::SerdeSecret;

use crate::core::{
    model::key::{PublicKey, SecretKeyShare},
    repository::key_repository::{PublicKeyStore, SecretKeyShareStore},
};
pub struct PublicKeyRepository {
    file_path: String,
    crypter: Crypter,
}

impl PublicKeyRepository {
    pub fn new(file_path: String, crypter: Crypter) -> Self {
        Self { file_path, crypter }
    }
}

#[async_trait::async_trait]
impl PublicKeyStore for PublicKeyRepository {
    type TPublicKey = threshold_crypto::PublicKeySet;

    type TError = PublicKeyRepositoryError;

    async fn save(
        &self,
        public_key: &crate::core::model::key::PublicKey<Self::TPublicKey>,
    ) -> Result<(), Self::TError> {
        let public_key_bytes = bincode::serialize(&public_key.public_key)
            .map_err(|_| PublicKeyRepositoryError::FailedSerialize)?;

        let encrypted_public_key_bytes = self
            .crypter
            .encrypt_bytes(&public_key_bytes)
            .map_err(|_| PublicKeyRepositoryError::FailedEncryptPublicKey)?;

        let file_path = Path::new(&self.file_path);
        fs::write(file_path, encrypted_public_key_bytes)
            .map_err(|_| PublicKeyRepositoryError::FailedWriteRepoFile)?;
        Ok(())
    }

    async fn load(
        &self,
    ) -> Result<crate::core::model::key::PublicKey<Self::TPublicKey>, Self::TError> {
        let file_path = Path::new(&self.file_path);
        let encrypted_pub_key_bytes =
            fs::read(file_path).map_err(|_| PublicKeyRepositoryError::FailedReadRepoFile)?;
        let pub_key_bytes = self
            .crypter
            .decrypt_bytes(&encrypted_pub_key_bytes)
            .map_err(|_| PublicKeyRepositoryError::FailedDecryptPublicKey)?;

        let pub_key: Self::TPublicKey = bincode::deserialize(&pub_key_bytes)
            .map_err(|_| PublicKeyRepositoryError::FailedDeserialize)?;

        let pub_key = PublicKey::new(pub_key);

        Ok(pub_key)
    }
}

#[derive(Error, Debug)]
pub enum PublicKeyRepositoryError {
    #[error("Failed to serialize")]
    FailedSerialize,
    #[error("Failed to encrypt public key")]
    FailedEncryptPublicKey,
    #[error("Failed to write public key into repository file")]
    FailedWriteRepoFile,
    #[error("Failed to read public key from repository file")]
    FailedReadRepoFile,
    #[error("Failed to decrypt public key")]
    FailedDecryptPublicKey,
    #[error("Failed to deserialize")]
    FailedDeserialize,
}

#[derive(Clone)]
pub struct SecretKeyShareRepository {
    file_path: String,
    crypter: Crypter,
}

impl SecretKeyShareRepository {
    pub fn new(file_path: String, crypter: Crypter) -> Option<Self> {
        if file_path.trim().is_empty() {
            return None;
        }

        Some(Self { file_path, crypter })
    }
    fn get_file_path_with_index(&self, index: usize) -> String {
        format!("{}-{}", self.file_path, index)
    }
}

#[async_trait::async_trait]
impl SecretKeyShareStore for SecretKeyShareRepository {
    type TSecretKeyShare = threshold_crypto::SecretKeyShare;

    type TError = SecretKeyShareRepositoryError;

    async fn save(
        &self,
        secret_key_share: &crate::core::model::key::SecretKeyShare<Self::TSecretKeyShare>,
    ) -> Result<(), Self::TError> {
        let serde_secret_key_share = SerdeSecret(secret_key_share.secret_key_share.clone());
        let secret_key_share_bytes = bincode::serialize(&serde_secret_key_share)
            .map_err(|_| SecretKeyShareRepositoryError::FailedSerialize)?;
        let encrypted_secret_key_share_bytes = self
            .crypter
            .encrypt_bytes(&secret_key_share_bytes)
            .map_err(|_| SecretKeyShareRepositoryError::FailedEncryptSecretKeyShare)?;

        let file_path = self.get_file_path_with_index(secret_key_share.index);
        let file_path = Path::new(&file_path);
        fs::write(file_path, encrypted_secret_key_share_bytes)
            .map_err(|_| SecretKeyShareRepositoryError::FailedWriteRepoFile)?;
        Ok(())
    }

    async fn load(
        &self,
        index: usize,
    ) -> Result<crate::core::model::key::SecretKeyShare<Self::TSecretKeyShare>, Self::TError> {
        let file_path = self.get_file_path_with_index(index);
        let file_path = Path::new(&file_path);
        let encrypted_serde_secret_key_share_bytes =
            fs::read(file_path).map_err(|_| SecretKeyShareRepositoryError::FailedReadRepoFile)?;
        let serde_secret_key_share_bytes = self
            .crypter
            .decrypt_bytes(&encrypted_serde_secret_key_share_bytes)
            .map_err(|_| SecretKeyShareRepositoryError::FailedDecryptSecretKeyShare)?;
        let serde_secret_key_share: SerdeSecret<Self::TSecretKeyShare> =
            bincode::deserialize(&serde_secret_key_share_bytes)
                .map_err(|_| SecretKeyShareRepositoryError::FailedDeserialize)?;

        let secret_key_share = serde_secret_key_share.into_inner();
        let secret_key_share = SecretKeyShare::new(index, secret_key_share);

        Ok(secret_key_share)
    }
}

#[derive(Error, Debug)]
pub enum SecretKeyShareRepositoryError {
    #[error("Failed to serialize")]
    FailedSerialize,
    #[error("Failed to encrypt secret key share")]
    FailedEncryptSecretKeyShare,
    #[error("Failed to write secret key share into repository file")]
    FailedWriteRepoFile,
    #[error("Failed to read secret key share from repository file")]
    FailedReadRepoFile,
    #[error("Failed to decrypt secret key share")]
    FailedDecryptSecretKeyShare,
    #[error("Failed to deserialize")]
    FailedDeserialize,
}

#[derive(Clone)]
pub struct Crypter;

impl Crypter {
    fn load_master_key(&self) -> Result<Vec<u8>, CrypterError> {
        let base64_key =
            std::env::var("DSIGN_MASTER_KEY").map_err(|_| CrypterError::FailedGetEnvVar)?;
        let key = general_purpose::STANDARD
            .decode(base64_key)
            .map_err(|_| CrypterError::FailedBase64Decode)?;

        if key.len() != 32 {
            return Err(CrypterError::InvalidKeyLength);
        }
        Ok(key)
    }

    fn encrypt_bytes(&self, plain_data: &[u8]) -> Result<Vec<u8>, CrypterError> {
        let master_key = self.load_master_key()?;

        let key = Key::<Aes256Gcm>::from_slice(&master_key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let enc_data = cipher
            .encrypt(&nonce, plain_data)
            .map_err(|_| CrypterError::FailedEncrypt)?;

        let mut final_bytes = Vec::new();
        final_bytes.extend_from_slice(nonce.as_slice());
        final_bytes.extend_from_slice(&enc_data);

        Ok(final_bytes)
    }

    fn decrypt_bytes(&self, encrypted_bytes: &[u8]) -> Result<Vec<u8>, CrypterError> {
        let master_key = self.load_master_key()?;
        type NonceSize = <Aes256Gcm as AeadCore>::NonceSize;
        let nonce_size = NonceSize::to_usize();
        let (nonce_bytes, encrypted_bytes) = encrypted_bytes.split_at(nonce_size);

        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(&master_key);
        let cipher = Aes256Gcm::new(&key);

        let plain_data = cipher
            .decrypt(nonce, encrypted_bytes)
            .map_err(|_| CrypterError::FailedDecrypt)?;

        Ok(plain_data)
    }
}

#[derive(Error, Debug)]
enum CrypterError {
    #[error("Failed to get environment variable")]
    FailedGetEnvVar,
    #[error("Failed to base64 decode")]
    FailedBase64Decode,
    #[error("Key length is invalid")]
    InvalidKeyLength,
    #[error("Failed to encrypt")]
    FailedEncrypt,
    #[error("Failed to decrypt")]
    FailedDecrypt,
}

#[cfg(test)]
mod test {
    use std::env;

    use super::*;
    use rand::thread_rng;
    use serial_test::serial;
    use threshold_crypto::{PublicKeySet, SecretKeySet};

    fn setup_master_key() {
        let key = [1u8; 32];
        let encoded = general_purpose::STANDARD.encode(key);

        unsafe { env::set_var("DSIGN_MASTER_KEY", encoded) };
    }

    fn unsetup_master_key() {
        unsafe { env::remove_var("DSIGN_MASTER_KEY") };
    }

    fn setup_invalid_length_master_key() {
        let key = [1u8; 31];
        let encoded = general_purpose::STANDARD.encode(key);
        unsafe { env::set_var("DSIGN_MASTER_KEY", encoded) };
    }

    fn setup_different_master_key() {
        let key = [1u8; 31];
        let encoded = general_purpose::STANDARD.encode(key);
        unsafe { env::set_var("DSIGN_MASTER_KEY", encoded) };
    }

    fn build_public_key() -> PublicKey<PublicKeySet> {
        let mut rng = thread_rng();
        let secret_key_set = SecretKeySet::random(1, &mut rng);
        let public_key_set = secret_key_set.public_keys();
        PublicKey::new(public_key_set)
    }

    fn build_public_key_repository(path: String) -> PublicKeyRepository {
        let crypter = Crypter;
        PublicKeyRepository::new(path.clone(), crypter)
    }

    fn build_secret_key_share() -> SecretKeyShare<threshold_crypto::SecretKeyShare> {
        let mut rng = thread_rng();
        let secret_key_set = SecretKeySet::random(1, &mut rng);
        let secret_key_share = secret_key_set.secret_key_share(0);
        SecretKeyShare::new(0, secret_key_share)
    }

    fn build_secret_key_share_repository(path: String) -> SecretKeyShareRepository {
        let crypter = Crypter;
        SecretKeyShareRepository::new(path, crypter).unwrap()
    }

    #[tokio::test]
    #[serial]
    async fn public_key_repository_save_success() {
        setup_master_key();
        let public_key = build_public_key();

        let path = "test_public_key.enc".to_string();
        let public_key_repo = build_public_key_repository(path.clone());

        let result = public_key_repo.save(&public_key).await;
        assert!(result.is_ok());

        let path = Path::new(&path);
        assert!(path.exists());

        let plain_bytes = bincode::serialize(&public_key.public_key).unwrap();
        let encrypted_bytes = fs::read(&path).unwrap();

        assert_ne!(plain_bytes, encrypted_bytes);

        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn public_key_repository_save_fail_when_env_var_is_not_set() {
        unsetup_master_key();
        let public_key = build_public_key();

        let path = "test_public_key.enc".to_string();
        let public_key_repo = build_public_key_repository(path.clone());
        let result = public_key_repo.save(&public_key).await;
        assert!(matches!(
            result.err().unwrap(),
            PublicKeyRepositoryError::FailedEncryptPublicKey,
        ))
    }

    #[tokio::test]
    #[serial]
    async fn public_key_repository_save_fail_when_env_var_is_invalid() {
        setup_invalid_length_master_key();

        let public_key = build_public_key();

        let path = "test_public_key.enc".to_string();
        let public_key_repo = build_public_key_repository(path.clone());
        let result = public_key_repo.save(&public_key).await;
        assert!(matches!(
            result.err().unwrap(),
            PublicKeyRepositoryError::FailedEncryptPublicKey,
        ))
    }

    #[tokio::test]
    #[serial]
    async fn public_key_repository_save_fail_when_repo_path_is_invalid() {
        setup_master_key();

        let public_key = build_public_key();

        let path = "".to_string();
        let public_key_repo = build_public_key_repository(path.clone());
        let result = public_key_repo.save(&public_key).await;
        assert!(matches!(
            result.err().unwrap(),
            PublicKeyRepositoryError::FailedWriteRepoFile,
        ))
    }

    #[tokio::test]
    #[serial]
    async fn public_key_repository_load_success() {
        setup_master_key();

        let public_key = build_public_key();

        let path = "test_public_key.enc".to_string();
        let public_key_repo = build_public_key_repository(path.clone());

        public_key_repo.save(&public_key).await.unwrap();
        let result = public_key_repo.load().await.unwrap();

        let original_bytes = bincode::serialize(&public_key.public_key).unwrap();
        let loaded_bytes = bincode::serialize(&result.public_key).unwrap();
        assert_eq!(original_bytes, loaded_bytes);
        let path = Path::new(&path);
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn public_key_repository_load_fail_when_env_var_is_not_set() {
        setup_master_key();

        let public_key = build_public_key();

        let path = "test_public_key.enc".to_string();
        let public_key_repo = build_public_key_repository(path.clone());

        public_key_repo.save(&public_key).await.unwrap();

        unsetup_master_key();
        let result = public_key_repo.load().await;

        assert!(matches!(
            result.err().unwrap(),
            PublicKeyRepositoryError::FailedDecryptPublicKey,
        ));
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn public_key_repository_load_fail_when_env_var_is_invalid() {
        setup_master_key();

        let public_key = build_public_key();

        let path = "test_public_key.enc".to_string();
        let public_key_repo = build_public_key_repository(path.clone());

        public_key_repo.save(&public_key).await.unwrap();

        setup_different_master_key();
        let result = public_key_repo.load().await;

        assert!(matches!(
            result.err().unwrap(),
            PublicKeyRepositoryError::FailedDecryptPublicKey,
        ));
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn public_key_repository_load_fail_when_repo_path_is_invalid() {
        setup_master_key();

        let public_key = build_public_key();

        let path = "test_public_key.enc".to_string();
        let public_key_repo = build_public_key_repository(path.clone());

        public_key_repo.save(&public_key).await.unwrap();

        let invalid_path = "invalid_path".to_string();
        let public_key_repo = build_public_key_repository(invalid_path.clone());
        let result = public_key_repo.load().await;
        assert!(matches!(
            result.err().unwrap(),
            PublicKeyRepositoryError::FailedReadRepoFile,
        ));
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn secret_key_share_repository_save_success() {
        setup_master_key();

        let secret_key_share = build_secret_key_share();
        let path = "test_secret_key_share.enc".to_string();
        let secret_key_share_repo = build_secret_key_share_repository(path.clone());

        let result = secret_key_share_repo.save(&secret_key_share).await;
        assert!(result.is_ok());

        let path = Path::new("test_secret_key_share.enc-0");
        assert!(path.exists());

        let serde_secret_key_share = SerdeSecret(secret_key_share.secret_key_share.clone());
        let plain_bytes = bincode::serialize(&serde_secret_key_share).unwrap();

        let encrypted_bytes = fs::read(&path).unwrap();
        assert_ne!(plain_bytes, encrypted_bytes);

        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn secret_key_share_repository_save_fail_when_env_var_is_not_set() {
        unsetup_master_key();

        let secret_key_share = build_secret_key_share();
        let path = "test_secret_key_share.enc".to_string();
        let secret_key_share_repo = build_secret_key_share_repository(path.clone());

        let result = secret_key_share_repo.save(&secret_key_share).await;

        assert!(matches!(
            result.err().unwrap(),
            SecretKeyShareRepositoryError::FailedEncryptSecretKeyShare
        ));
    }

    #[tokio::test]
    #[serial]
    async fn secret_key_share_repository_save_fail_when_env_var_is_invalid() {
        setup_invalid_length_master_key();
        let secret_key_share = build_secret_key_share();
        let path = "test_secret_key_share.enc".to_string();
        let secret_key_share_repo = build_secret_key_share_repository(path.clone());

        let result = secret_key_share_repo.save(&secret_key_share).await;

        assert!(matches!(
            result.err().unwrap(),
            SecretKeyShareRepositoryError::FailedEncryptSecretKeyShare
        ));
    }

    #[tokio::test]
    #[serial]
    async fn secret_key_share_repository_created_fail_when_repo_path_is_invalid() {
        setup_master_key();

        let path = "".to_string();
        let crypter = Crypter;
        let result = SecretKeyShareRepository::new(path, crypter);

        assert!(result.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn secret_key_share_repository_load_success() {
        setup_master_key();

        let path = "test_secret_key_share.enc".to_string();
        let secret_key_share_repo = build_secret_key_share_repository(path.clone());
        let secret_key_share = build_secret_key_share();

        secret_key_share_repo.save(&secret_key_share).await.unwrap();

        let result = secret_key_share_repo.load(0).await.unwrap();

        let serde_secret_key_share = SerdeSecret(secret_key_share.secret_key_share);
        let save_bytes = bincode::serialize(&serde_secret_key_share).unwrap();

        let serde_secret_key_share = SerdeSecret(result.secret_key_share);
        let load_bytes = bincode::serialize(&serde_secret_key_share).unwrap();

        assert_eq!(save_bytes, load_bytes);

        let path = Path::new("test_secret_key_share.enc-0");
        assert!(path.exists());
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn secret_key_share_repository_load_fail_when_env_var_is_unset() {
        setup_master_key();

        let path = "test_secret_key_share.enc".to_string();
        let secret_key_share_repo = build_secret_key_share_repository(path.clone());
        let secret_key_share = build_secret_key_share();

        secret_key_share_repo.save(&secret_key_share).await.unwrap();

        unsetup_master_key();

        let result = secret_key_share_repo.load(0).await;

        assert!(matches!(
            result.err().unwrap(),
            SecretKeyShareRepositoryError::FailedDecryptSecretKeyShare
        ));
    }

    #[tokio::test]
    #[serial]
    async fn secret_key_share_repository_load_fail_when_env_var_is_invalid() {
        setup_master_key();

        let path = "test_secret_key_share.enc".to_string();
        let secret_key_share_repo = build_secret_key_share_repository(path.clone());
        let secret_key_share = build_secret_key_share();

        secret_key_share_repo.save(&secret_key_share).await.unwrap();

        setup_invalid_length_master_key();

        let result = secret_key_share_repo.load(0).await;

        assert!(matches!(
            result.err().unwrap(),
            SecretKeyShareRepositoryError::FailedDecryptSecretKeyShare
        ));
    }

    #[tokio::test]
    #[serial]
    async fn secret_key_share_repository_load_fail_when_repository_path_is_invalid() {
        setup_master_key();
        let path = "test_secret_key_share.enc".to_string();
        let secret_key_share_repo = build_secret_key_share_repository(path.clone());
        let secret_key_share = build_secret_key_share();

        secret_key_share_repo.save(&secret_key_share).await.unwrap();

        let path = "invalid.enc".to_string();
        let secret_key_share_repo = build_secret_key_share_repository(path.clone());

        let result = secret_key_share_repo.load(0).await;

        assert!(matches!(
            result.err().unwrap(),
            SecretKeyShareRepositoryError::FailedReadRepoFile
        ));
    }
}
