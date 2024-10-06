use rocket::request::{ Outcome, Request, FromRequest };
use rocket::http::Status;
use rocket_okapi::okapi::openapi3::{
    Object,
    SecurityRequirement,
    SecurityScheme,
    SecuritySchemeData,
};
use rocket_okapi::{ gen::OpenApiGenerator, request::{ OpenApiFromRequest, RequestHeaderInput } };

#[derive(Debug)]
pub struct AuthorizationHeader {
    pub token: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthorizationHeader {
    type Error = String;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = request.headers().get_one("Authorization");

        match token {
            Some(token) => {
                Outcome::Success(AuthorizationHeader {
                    token: token.to_string(),
                })
            }
            None => {
                Outcome::Error((Status::Unauthorized, String::from("No access token provided")))
            }
        }
    }
}

impl<'a> OpenApiFromRequest<'a> for AuthorizationHeader {
    fn from_request_input(
        _gen: &mut OpenApiGenerator,
        _name: String,
        _required: bool
    ) -> rocket_okapi::Result<RequestHeaderInput> {
        let security_scheme = SecurityScheme {
            description: Some(
                "Requires an Bearer token to access, token is: `mytoken`.".to_owned()
            ),
            data: SecuritySchemeData::Http {
                scheme: "bearer".to_owned(),
                bearer_format: Some("bearer".to_owned()),
            },
            extensions: Object::default(),
        };
        let mut security_req = SecurityRequirement::new();
        security_req.insert("AuthorizationHeader".to_owned(), Vec::new());
        Ok(
            RequestHeaderInput::Security(
                "AuthorizationHeader".to_owned(),
                security_scheme,
                security_req
            )
        )
    }
}
