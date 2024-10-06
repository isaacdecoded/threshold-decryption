use thiserror::Error;
use crate::domain::services::cryptography_service::CryptographyService;

pub struct DecryptMessageRequestModel {
    pub message: Vec<u8>,
}

pub struct DecryptMessageResponseModel {
    pub decrypted_message: String,
}

#[derive(Error, Debug)]
pub enum DecryptMessageError {
    #[error("Unable to decrypt message from Cryptography Service. {0}")] CryptographyServiceError(
        String,
    ),
    #[error("Invalid or broken message encryption. {0}")] BrokenEncryptionError(String),
}

pub struct DecryptMessageUseCase<'a> {
    cryptography_service: &'a dyn CryptographyService,
}

impl<'a> DecryptMessageUseCase<'a> {
    pub fn new(cryptography_service: &'a dyn CryptographyService) -> Self {
        Self {
            cryptography_service,
        }
    }

    pub async fn interact(
        &self,
        request_model: DecryptMessageRequestModel
    ) -> Result<DecryptMessageResponseModel, DecryptMessageError> {
        let decrypted_message = self.cryptography_service
            .decrypt_message(request_model.message).await
            .map_err(|e| DecryptMessageError::CryptographyServiceError(e.to_string()))?;
        Ok(DecryptMessageResponseModel {
            decrypted_message: String::from_utf8(decrypted_message).map_err(|e| {
                DecryptMessageError::BrokenEncryptionError(e.to_string())
            })?,
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
    async fn should_decrypt_message_use_case() {
        let mut mock_cryptography_service = MockCryptographyService::new();

        mock_cryptography_service
            .expect_decrypt_message()
            .times(1)
            .returning(|message| { Box::pin(async move { Ok(message.to_vec()) }) });

        let use_case = DecryptMessageUseCase::new(&mock_cryptography_service);
        let request_model = DecryptMessageRequestModel {
            message: b"Hello, World!".to_vec(),
        };
        let response_model = use_case.interact(request_model).await.unwrap();
        assert_eq!(response_model.decrypted_message, "Hello, World!");
    }

    #[tokio::test]
    async fn should_fail_to_decrypt_message_use_case() {
        let mut mock_cryptography_service = MockCryptographyService::new();

        mock_cryptography_service
            .expect_decrypt_message()
            .times(1)
            .returning(|_| {
                Box::pin(async move {
                    Err(CryptographyServiceError::DecryptionError("Error".to_string()))
                })
            });

        let use_case = DecryptMessageUseCase::new(&mock_cryptography_service);
        let request_model = DecryptMessageRequestModel {
            message: b"Hello, World!".to_vec(),
        };
        let response_model = use_case.interact(request_model).await;
        assert!(response_model.is_err());
    }
}
