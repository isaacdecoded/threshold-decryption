use thiserror::Error;
use mockall::automock;
use async_trait::async_trait;

#[derive(Error, Debug)]
pub enum CryptographyServiceError {
    #[error("Unable to share public key. {0}")] PublicKeySharingError(String),
    #[error("Unable to decrypt message. {0}")] DecryptionError(String),
    #[error("Unable to encrypt message. {0}")] EncryptionError(String),
}

#[async_trait]
#[automock]
pub trait CryptographyService: Sync + Send {
    async fn share_public_key(&self) -> Result<Vec<u8>, CryptographyServiceError>;
    async fn decrypt_message(&self, message: Vec<u8>) -> Result<Vec<u8>, CryptographyServiceError>;
    async fn encrypt_message(&self, message: String) -> Result<Vec<u8>, CryptographyServiceError>;
}
