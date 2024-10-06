use rocket::{ State, http::Status, response::status, serde::json::Json };
use rocket_okapi::okapi::schemars;
use rocket_okapi::okapi::schemars::JsonSchema;
use rocket_okapi::openapi;
use serde::{ Serialize, Deserialize };
use std::sync::Arc;
use base64::{ engine::general_purpose, Engine };
use crate::{
    application::commands::encrypt_message_use_case::{
        EncryptMessageUseCase,
        EncryptMessageRequestModel,
    },
    infrastructure::{
        guards::{
            authorization_request_guard::AuthorizationHeader,
            rate_limiter_request_guard::RateLimiter,
        },
        routes::http_error_response::HttpErrorResponse,
        services::pairing_cryptography_service::PairingCryptographyService,
    },
};

#[derive(Deserialize, FromForm, JsonSchema)]
pub struct EncryptMessageRequest {
    message: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EncryptMessageResponse {
    encrypted_message: String,
}

#[openapi]
#[post("/encrypt-message", format = "json", data = "<request>")]
pub async fn encrypt_message(
    cryptography_service_state: &State<Arc<PairingCryptographyService>>,
    _rate_limiter: RateLimiter,
    authorization: Result<AuthorizationHeader, String>,
    request: Json<EncryptMessageRequest>
) -> Result<status::Custom<Json<EncryptMessageResponse>>, status::Custom<Json<HttpErrorResponse>>> {
    let _authorization = authorization.map_err(|error| {
        status::Custom(Status::Unauthorized, Json(HttpErrorResponse { error }))
    })?;
    let use_case = EncryptMessageUseCase::new(cryptography_service_state.as_ref());
    let response_model = use_case
        .interact(EncryptMessageRequestModel {
            message: request.message.clone(),
        }).await
        .map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                Json(HttpErrorResponse {
                    error: e.to_string(),
                })
            )
        })?;
    let encrypted_message = general_purpose::STANDARD.encode(response_model.encrypted_message);
    Ok(
        status::Custom(
            Status::Ok,
            Json(EncryptMessageResponse {
                encrypted_message,
            })
        )
    )
}
