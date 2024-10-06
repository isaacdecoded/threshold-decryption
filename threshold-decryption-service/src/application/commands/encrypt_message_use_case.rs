use thiserror::Error;
use crate::domain::services::cryptography_service::CryptographyService;

pub struct EncryptMessageRequestModel {
    pub message: String,
}

pub struct EncryptMessageResponseModel {
    pub encrypted_message: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum EncryptMessageError {
    #[error("Unable to decrypt message from Cryptography Service. {0}")] CryptographyServiceError(
        String,
    ),
    #[error("Invalid or broken message encryption. {0}")] BrokenEncryptionError(String),
}

pub struct EncryptMessageUseCase<'a> {
    cryptography_service: &'a dyn CryptographyService,
}

impl<'a> EncryptMessageUseCase<'a> {
    pub fn new(cryptography_service: &'a dyn CryptographyService) -> Self {
        Self {
            cryptography_service,
        }
    }

    pub async fn interact(
        &self,
        request_model: EncryptMessageRequestModel
    ) -> Result<EncryptMessageResponseModel, EncryptMessageError> {
        let encrypted_message = self.cryptography_service
            .encrypt_message(request_model.message).await
            .map_err(|e| EncryptMessageError::CryptographyServiceError(e.to_string()))?;
        Ok(EncryptMessageResponseModel {
            encrypted_message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::services::cryptography_service::{
        CryptographyServiceError,
        MockCryptographyService,
    };

    #[tokio::test]
    async fn should_encrypt_message_use_case() {
        let mut mock_cryptography_service = MockCryptographyService::new();

        mock_cryptography_service
            .expect_encrypt_message()
            .times(1)
            .returning(|message| { Box::pin(async move { Ok(message.into_bytes()) }) });

        let use_case = EncryptMessageUseCase::new(&mock_cryptography_service);
        let request_model = EncryptMessageRequestModel {
            message: String::from("Hello, World!"),
        };
        let response_model = use_case.interact(request_model).await.unwrap();
        assert_eq!(response_model.encrypted_message, b"Hello, World!".to_vec());
    }

    #[tokio::test]
    async fn should_fail_to_encrypt_message_use_case() {
        let mut mock_cryptography_service = MockCryptographyService::new();

        mock_cryptography_service
            .expect_encrypt_message()
            .times(1)
            .returning(|_| {
                Box::pin(async move {
                    Err(CryptographyServiceError::EncryptionError("Error".to_string()))
                })
            });

        let use_case = EncryptMessageUseCase::new(&mock_cryptography_service);
        let request_model = EncryptMessageRequestModel {
            message: String::from("Hello, World!"),
        };
        let response_model = use_case.interact(request_model).await;
        assert!(response_model.is_err());
    }
}
