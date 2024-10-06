use rocket_okapi::openapi;

#[openapi]
#[get("/healthz")]
pub fn healthz() -> &'static str {
    "OK"
}
