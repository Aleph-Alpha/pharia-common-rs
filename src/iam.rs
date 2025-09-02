//! **IAM** is short for **I**dentity **A**ccess **M**anagement. This module contains opinionated
//! adapters to connect to the internal Pharia IAM solution.

use std::borrow::Cow;

use serde::Serialize;

pub struct IamClient {}

/// Body of the the IAM `/check_user` route. The token is not passed in the body but in the
/// authorization header.
#[derive(Serialize)]
pub struct CheckUserBody<'a> {
    /// A list of permissions to query for the specific user.
    permissions: Cow<'a, [Cow<'a, str>]>,
}

#[cfg(test)]
mod tests {
    //! We currently test against the production instance of IAM
    use std::{borrow::Cow, path::PathBuf};

    use dotenvy::dotenv;
    use reqwest::Client;
    use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
    use reqwest_vcr::{VCRMiddleware, VCRMode};

    use super::CheckUserBody;

    /// URL of IAM in our production environment
    pub const IAM_PRODUCTION_URL: &str = "https://pharia-iam.product.pharia.com";

    #[tokio::test]
    async fn invoke_check_user() {
        // /// A one-stop-shop for authentication, authorization and retrieving user information based on a
        // /// token.
        // pub fn check_user(token: impl Display) {}
        dotenv().unwrap();
        let token = std::env::var("PHARIA_AI_TOKEN").unwrap();

        let mut bundle = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        bundle.push("tests/cassettes/invoke_check_user.vcr.json");

        let middleware: VCRMiddleware = VCRMiddleware::try_from(bundle.clone())
            .unwrap()
            .with_mode(VCRMode::Replay)
            .with_modify_request(|request| {
                if let Some(header) = request.headers.get_mut("authorization") {
                    *header = vec!["TOKEN_REMOVED".to_owned()];
                }
            });

        let client = Client::builder().use_rustls_tls().build().expect(
            "Must be able to initialize TLS backend and resolver must be able to load system \
            configuration.",
        );

        let client: ClientWithMiddleware = ClientBuilder::new(client).with(middleware).build();

        let response = client
            .post(format!("{IAM_PRODUCTION_URL}/check_user"))
            .bearer_auth(token)
            .json(&CheckUserBody {
                permissions: Vec::new().into(),
            })
            .send()
            .await
            .unwrap();

        // let text = response.text().await.unwrap();
        // eprintln!("{text}");

        // assert_eq!(text, "ok");
        response.error_for_status().unwrap();

        // {\"sub\":\"295355180126307110\",\"email\":\"markus.klein@aleph-alpha.com\",\"email_verified\":true,\"permissions\":[]}
    }
}
