#[macro_use]
extern crate rocket;
pub mod domain;
pub mod application;
pub mod infrastructure;

use std::env;
use std::sync::Arc;
use rocket_okapi::{ openapi_get_routes, swagger_ui::* };
use crate::infrastructure::{
    guards::rate_limiter_request_guard::RateLimiter,
    routes::{
        healthz_route::{ healthz, okapi_add_operation_for_healthz_ },
        get_public_key_route::{ get_public_key, okapi_add_operation_for_get_public_key_ },
        decrypt_message_route::{ decrypt_message, okapi_add_operation_for_decrypt_message_ },
        encrypt_message_route::{ encrypt_message, okapi_add_operation_for_encrypt_message_ },
    },
    services::pairing_cryptography_service::PairingCryptographyService,
};

#[launch]
async fn rocket() -> _ {
    let cryptography_service = PairingCryptographyService::new(3, 1).await.unwrap_or_else(|e|
        panic!("{}", e.to_string())
    );
    cryptography_service.propagate_keys().await.unwrap_or_else(|e| panic!("{}", e.to_string()));
    rocket
        ::build()
        .manage(Arc::new(cryptography_service))
        .manage(RateLimiter::new(10))
        .mount("/", openapi_get_routes![healthz, get_public_key, encrypt_message, decrypt_message])
        .mount(
            "/swagger-ui/",
            make_swagger_ui(
                &(SwaggerUIConfig {
                    url: "../openapi.json".to_owned(),
                    ..Default::default()
                })
            )
        )
}
