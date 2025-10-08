//! **IAM** is short for **I**dentity **A**ccess **M**anagement. This module contains opinionated
//! adapters to connect to the internal Pharia IAM solution.

use std::{borrow::Cow, fmt::Display};

use reqwest::{Client, StatusCode};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use serde::{Deserialize, Serialize};

/// URL of IAM in our production environment
pub const IAM_PRODUCTION_URL: &str = "https://pharia-iam.product.pharia.com";

/// Client forPharia **I**dentity **A**ccess **M**anagement. Authenticate and authorize users.
pub struct IamClient {
    /// Environment specific URL to Pharia IAM. E.g. <https://pharia-iam.product.pharia.com>
    base_url: String,
    /// Used for sending the http requests. We are using `ClientWithMiddleware` to allow for VCR
    /// recording in tests.
    http_client: ClientWithMiddleware,
}

impl IamClient {
    pub fn new(base_url: String) -> Self {
        let client = Client::builder().use_rustls_tls().build().expect(
            "Must be able to initialize TLS backend and resolver must be able to load system \
            configuration.",
        );

        let http_client: ClientWithMiddleware = ClientBuilder::new(client).build();

        Self {
            base_url,
            http_client,
        }
    }

    #[cfg(test)]
    pub fn with_vcr(base_url: String, path_to_cassette: std::path::PathBuf) -> Self {
        let cassette_does_exist = path_to_cassette.is_file();
        let vcr_mode = if cassette_does_exist {
            reqwest_vcr::VCRMode::Replay
        } else {
            reqwest_vcr::VCRMode::Record
        };

        let middleware = reqwest_vcr::VCRMiddleware::try_from(path_to_cassette)
            .unwrap()
            .with_mode(vcr_mode)
            .with_modify_request(|request| {
                if let Some(header) = request.headers.get_mut("authorization") {
                    *header = vec!["TOKEN_REMOVED".to_owned()];
                }
            });

        IamClient::with_middleware(base_url, middleware)
    }

    #[cfg(test)]
    fn with_middleware(base_url: String, middleware: impl reqwest_middleware::Middleware) -> Self {
        let client = Client::builder().use_rustls_tls().build().expect(
            "Must be able to initialize TLS backend and resolver must be able to load system \
            configuration.",
        );

        let http_client: ClientWithMiddleware = ClientBuilder::new(client).with(middleware).build();

        IamClient {
            base_url,
            http_client,
        }
    }

    /// One stop shop for both authentication and authorization.
    pub async fn check_user<'a>(
        &self,
        token: impl Display,
        permissions: &'a [Permission<'a>],
    ) -> Result<UserInfoAndPermissions, CheckUserError> {
        let request_body = CheckUserRequestBody { permissions };

        let response = self
            .http_client
            .post(format!("{base_url}/check_user", base_url = self.base_url))
            .bearer_auth(token)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| CheckUserError::ConnectionError(e.into()))?;

        // A long standing quirk of the HTTP standard: Unauthorized 401 actually means
        // "unauthenticated". We consider this a domain specific logic error, rather than a runtime
        // error, which should be fixed with retry. Therfore we categorize this error differently
        // the other connection errors
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(CheckUserError::Unauthenticated);
        }

        if response.status() == StatusCode::UNPROCESSABLE_ENTITY {
            use anyhow::anyhow;
            eprintln!("{}", response.text().await.unwrap());
            return Err(CheckUserError::ConnectionError(anyhow!(
                "Unprocessable entity"
            )));
        }

        // Map all other thing to ConnectionError
        response
            .error_for_status_ref()
            .map_err(|e| CheckUserError::ConnectionError(e.into()))?;

        let user_info = response
            .json()
            .await
            .map_err(|e| CheckUserError::ConnectionError(e.into()))?;

        Ok(user_info)
    }
}

/// Body of the the IAM `/check_user` route. The token is not passed in the body but in the
/// authorization header.
#[derive(Serialize)]
struct CheckUserRequestBody<'a> {
    /// A list of permissions to query for the specific user.
    permissions: &'a [Permission<'a>],
}

/// Returned by [`IamClient::check_user`]. Contains information describing the user as well as the
/// union of the queried permissions and the privileges of the user.
#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct UserInfoAndPermissions {
    /// Unique ID of the User
    sub: String,
    /// Email of the user. `None` for Service users
    email: Option<String>,
    /// May be `None` for Service Users
    email_verified: Option<bool>,
    /// List of requested permissions, which are privieleges of the User Service. They are in the
    /// same order as in the query
    permissions: Vec<Permission<'static>>,
}

/// An error returned by [`IamClient::check_user`]. Note that this does **not** include
/// unauthorized. To check for authorization inspect the permissions of [`UserInfoAndPermissions`]
#[derive(thiserror::Error, Debug)]
pub enum CheckUserError {
    #[error("User is Unauthenticated. Token is invalid")]
    Unauthenticated,
    #[error("User could not be authenticated due to connectivity issue:\n{0:#}")]
    ConnectionError(#[source] anyhow::Error),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Hash)]
#[serde(tag = "permission")]
pub enum Permission<'a> {
    Assistant,
    Numinous,
    /// The kernel uses this permission to authorize skill execution
    KernelAccess,
    /// Used by inference to decide wether a user is authorized to perform any kind of inference
    /// requests.
    ExecuteJob,
    /// Is this user allowed to use this model? "*" Can be used as a model name in order to indicate
    /// access to all models.
    AccessModel {
        model: Cow<'a, str>,
    },
    HasRelation {
        relation: Cow<'a, str>,
        object: Cow<'a, str>,
    },
}

#[cfg(test)]
mod tests {
    use dotenvy::dotenv;
    use std::{env, path::PathBuf};

    use super::{
        CheckUserError, IAM_PRODUCTION_URL, IamClient, Permission, UserInfoAndPermissions,
    };

    #[tokio::test]
    async fn valid_user_token() {
        // We are using cassets to record the request. This makes the test easy to execute even
        // without a connection to Pharia. Additionally it allows us to execute the test even
        // without the specific token of the user who recorded it at hand.
        let mut cassette_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cassette_path.push("tests/cassettes/valid_user_token.vcr.json");

        // Given a client
        let client = IamClient::with_vcr(IAM_PRODUCTION_URL.to_owned(), cassette_path);

        // When sending a check user request with a valid token
        let response = client.check_user(token(), &[]).await.unwrap();

        // Then we recevie an answer, identifying the user
        let expected = UserInfoAndPermissions {
            sub: "295355180126307110".to_owned(),
            email: Some("markus.klein@aleph-alpha.com".to_owned()),
            email_verified: Some(true),
            permissions: vec![],
        };
        assert_eq!(expected, response);
    }

    #[tokio::test]
    async fn invalid_user_token() {
        // We are using cassets to record the request. This makes the test easy to execute even
        // without a connection to Pharia. Additionally it allows us to execute the test even
        // without the specific token of the user who recorded it at hand.
        let mut cassette_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cassette_path.push("tests/cassettes/invalid_user_token.vcr.json");

        // Given an invalid Pharia User Token
        let token = "I-AM-AN-INVALID-TOKEN";
        let client = IamClient::with_vcr(IAM_PRODUCTION_URL.to_owned(), cassette_path);

        // When sending a check user request
        let result = client.check_user(token, &[]).await;

        // Then the user is unauthenticated
        assert!(matches!(result, Err(CheckUserError::Unauthenticated)))
    }

    #[tokio::test]
    async fn asking_for_permissions() {
        // We are using cassets to record the request. This makes the test easy to execute even
        // without a connection to Pharia. Additionally it allows us to execute the test even
        // without the specific token of the user who recorded it at hand.
        let mut cassette_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cassette_path.push("tests/cassettes/asking_for_permissions.vcr.json");

        // Given a client
        let client = IamClient::with_vcr(IAM_PRODUCTION_URL.to_owned(), cassette_path);
        let permissions = [
            Permission::KernelAccess,
            Permission::ExecuteJob,
            Permission::Assistant,
            Permission::Numinous,
            Permission::AccessModel { model: "*".into() },
        ];

        // When sending a check user request with a token authorized for all permission it is
        // asking for.
        let response = client.check_user(token(), &permissions).await.unwrap();

        // Then we recevie an answer, identifying the user and all the permissions are visible
        // in the answer.
        let expected = UserInfoAndPermissions {
            sub: "295355180126307110".to_owned(),
            email: Some("markus.klein@aleph-alpha.com".to_owned()),
            email_verified: Some(true),
            // It seems the IAM backend maintains order. So this assertion works.
            permissions: permissions.to_vec(),
        };
        assert_eq!(expected, response);
    }

    #[tokio::test]
    async fn asking_for_permissions_as_service() {
        // We are using cassets to record the request. This makes the test easy to execute even
        // without a connection to Pharia. Additionally it allows us to execute the test even
        // without the specific token of the user who recorded it at hand.
        let mut cassette_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        cassette_path.push("tests/cassettes/asking_for_permissions_as_service.vcr.json");

        // Given a client
        let client = IamClient::with_vcr(IAM_PRODUCTION_URL.to_owned(), cassette_path);
        let permissions = [Permission::Assistant, Permission::Numinous];

        // When sending a check user request with a token authorized for all permission it is
        // asking for.
        let response = client
            .check_user(service_token(), &permissions)
            .await
            .unwrap();

        // Then we recevie an answer, identifying the user and all the permissions are visible
        // in the answer.
        let expected = UserInfoAndPermissions {
            sub: "336362361919115278".to_owned(),
            email: None,
            email_verified: None,
            // It seems the IAM backend maintains order. So this assertion works.
            permissions: [].to_vec(), // permissions.to_vec(),
        };
        assert_eq!(expected, response);
    }

    /// Service token used for recording cassettes
    ///
    /// Credentials: pharia-internal-rs-test
    /// The user (developers) token from the environment
    fn service_token() -> String {
        _ = dotenv();
        env::var("PHARIA_AI_SERVICE_TOKEN").unwrap_or_else(|_| "DUMMY".to_owned())
    }

    /// The user (developers) token from the environment
    fn token() -> String {
        _ = dotenv();
        env::var("PHARIA_AI_TOKEN").unwrap_or_else(|_| "DUMMY".to_owned())
    }
}
