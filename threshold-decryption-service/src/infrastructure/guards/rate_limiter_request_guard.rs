use rocket::request::{ self, FromRequest, Request };
use rocket_okapi::request::OpenApiFromRequest;
use rocket::outcome::Outcome;
use rocket::http::Status;
use governor::{ Quota, RateLimiter as GovernorRateLimiter };
use governor::state::keyed::DefaultKeyedStateStore;
use governor::clock::DefaultClock;
use std::sync::Arc;
use std::num::NonZeroU32;
use std::collections::hash_map::DefaultHasher;
use std::hash::{ Hash, Hasher };

#[derive(OpenApiFromRequest)]
pub struct RateLimiter {
    limiter: Arc<GovernorRateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>,
}

impl RateLimiter {
    pub fn new(max_requests: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(max_requests).unwrap());
        let limiter = GovernorRateLimiter::keyed(quota);
        RateLimiter {
            limiter: Arc::new(limiter),
        }
    }

    fn get_key(&self, request: &rocket::Request) -> String {
        let mut hasher = DefaultHasher::new();
        request.client_ip().unwrap().to_string().hash(&mut hasher);
        hasher.finish().to_string()
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RateLimiter {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let rate_limiter = request.rocket().state::<RateLimiter>().unwrap();
        let key = rate_limiter.get_key(request);

        match rate_limiter.limiter.check_key(&key) {
            Ok(_) =>
                Outcome::Success(RateLimiter {
                    limiter: Arc::clone(&rate_limiter.limiter),
                }),
            Err(_) => Outcome::Error((Status::TooManyRequests, ())),
        }
    }
}
