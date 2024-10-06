use rocket::{ State, http::Status, response::status, serde::json::Json };
use rocket_okapi::openapi;
use rocket_okapi::okapi::schemars;
use rocket_okapi::okapi::schemars::JsonSchema;
use serde::Serialize;
use std::sync::Arc;

use crate::{
    application::queries::get_public_key_use_case::GetPublicKeyUseCase,
    infrastructure::{
        routes::http_error_response::HttpErrorResponse,
        services::pairing_cryptography_service::PairingCryptographyService,
    },
};

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetPublicKeyResponse {
    pub public_key: Vec<u8>,
}

#[openapi]
#[get("/public-key")]
pub async fn get_public_key(
    cryptography_service_state: &State<Arc<PairingCryptographyService>>
) -> Result<status::Custom<Json<GetPublicKeyResponse>>, status::Custom<Json<HttpErrorResponse>>> {
    let use_case = GetPublicKeyUseCase::new(cryptography_service_state.as_ref());
    let response_model = use_case.interact().await.map_err(|e| {
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
            Json(GetPublicKeyResponse {
                public_key: response_model.public_key,
            })
        )
    )
}
