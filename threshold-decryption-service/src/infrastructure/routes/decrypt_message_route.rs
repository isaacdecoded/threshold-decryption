use rocket::{ State, http::Status, response::status, serde::json::Json };
use rocket_okapi::okapi::schemars;
use rocket_okapi::okapi::schemars::JsonSchema;
use rocket_okapi::openapi;
use serde::{ Serialize, Deserialize };
use std::sync::Arc;
use base64::{ engine::general_purpose, Engine };
use crate::{
    application::commands::decrypt_message_use_case::{
        DecryptMessageUseCase,
        DecryptMessageRequestModel,
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
pub struct DecryptMessageRequest {
    message: String,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DecryptMessageResponse {
    decrypted_message: String,
}

#[openapi]
#[post("/decrypt-message", format = "json", data = "<request>")]
pub async fn decrypt_message(
    cryptography_service_state: &State<Arc<PairingCryptographyService>>,
    _rate_limiter: RateLimiter,
    authorization: Result<AuthorizationHeader, String>,
    request: Json<DecryptMessageRequest>
) -> Result<status::Custom<Json<DecryptMessageResponse>>, status::Custom<Json<HttpErrorResponse>>> {
    let _authorization = authorization.map_err(|error| {
        status::Custom(Status::Unauthorized, Json(HttpErrorResponse { error }))
    })?;
    let use_case = DecryptMessageUseCase::new(cryptography_service_state.as_ref());
    let message_bytes = general_purpose::STANDARD.decode(&request.message).map_err(|e| {
        status::Custom(
            Status::BadRequest,
            Json(HttpErrorResponse {
                error: e.to_string(),
            })
        )
    })?;
    let response_model = use_case
        .interact(DecryptMessageRequestModel {
            message: message_bytes,
        }).await
        .map_err(|e| {
            status::Custom(
                Status::InternalServerError,
                Json(HttpErrorResponse {
                    error: e.to_string(),
                })
            )
        })?;
    Ok(
        status::Custom(
            Status::Ok,
            Json(DecryptMessageResponse {
                decrypted_message: response_model.decrypted_message,
            })
        )
    )
}
