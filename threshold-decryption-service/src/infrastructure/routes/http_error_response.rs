use serde::Serialize;
use rocket_okapi::okapi::schemars;
use rocket_okapi::okapi::schemars::JsonSchema;

#[derive(Serialize, JsonSchema)]
pub struct HttpErrorResponse {
    pub error: String,
}
