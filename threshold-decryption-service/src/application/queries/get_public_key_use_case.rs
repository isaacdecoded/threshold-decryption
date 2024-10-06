use thiserror::Error;
use crate::domain::services::cryptography_service::CryptographyService;

pub struct GetPublicKeyResponseModel {
    pub public_key: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum GetPublicKeyError {
    #[error("Unable to get public key from Cryptography Service. {0}")] CryptographyServiceError(
        String,
    ),
}

pub struct GetPublicKeyUseCase<'a> {
    cryptography_service: &'a dyn CryptographyService,
}

impl<'a> GetPublicKeyUseCase<'a> {
    pub fn new(cryptography_service: &'a dyn CryptographyService) -> Self {
        Self {
            cryptography_service,
        }
    }

    pub async fn interact(&self) -> Result<GetPublicKeyResponseModel, GetPublicKeyError> {
        let public_key = self.cryptography_service
            .share_public_key().await
            .map_err(|e| GetPublicKeyError::CryptographyServiceError(e.to_string()))?;
        Ok(GetPublicKeyResponseModel { public_key })
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
    async fn should_get_public_key_use_case() {
        let mut mock_cryptography_service = MockCryptographyService::new();

        mock_cryptography_service
            .expect_share_public_key()
            .times(1)
            .returning(|| { Box::pin(async move { Ok(vec![1, 2, 3]) }) });

        let use_case = GetPublicKeyUseCase::new(&mock_cryptography_service);
        let response_model = use_case.interact().await.unwrap();
        assert_eq!(response_model.public_key, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn should_fail_to_get_public_key_use_case() {
        let mut mock_cryptography_service = MockCryptographyService::new();

        mock_cryptography_service
            .expect_share_public_key()
            .times(1)
            .returning(||
                Box::pin(async move {
                    Err(CryptographyServiceError::PublicKeySharingError("Error".to_string()))
                })
            );

        let use_case = GetPublicKeyUseCase::new(&mock_cryptography_service);
        let response_model = use_case.interact().await;
        assert!(response_model.is_err());
    }
}
