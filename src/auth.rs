use crate::{App, Response};
use axum::extract::rejection::TypedHeaderRejectionReason;
use axum::extract::FromRequestParts;
use axum::headers::Cookie;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{async_trait, TypedHeader};
use uuid::Uuid;

pub struct Auth {
    user_id: Uuid,
    username: String,
}

pub struct Session {
    token: [u8; 16],
}

pub enum AuthError {
    NotLoggedIn,
    InvalidHeader,
    InvalidSessionTokenFormat,
    InvalidSessionToken,
}

pub enum SessionError {
    Missing,
    InvalidHeader,
    InvalidSessionTokenFormat,
}

impl Auth {
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}

impl Session {
    pub fn token_hex(&self) -> String {
        hex::encode(&self.token)
    }
}

#[async_trait]
impl FromRequestParts<App> for Auth {
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &App) -> Result<Self, Self::Rejection> {
        let session = match Session::from_request_parts(parts, state).await {
            Ok(session) => session,
            Err(SessionError::Missing) => return Err(AuthError::NotLoggedIn),
            Err(SessionError::InvalidHeader) => return Err(AuthError::InvalidHeader),
            Err(SessionError::InvalidSessionTokenFormat) => {
                return Err(AuthError::InvalidSessionTokenFormat)
            }
        };
        let user = state.database.query_one("SELECT u.id, username FROM users u, sessions s WHERE u.id = s.\"user\" AND s.token = $1", &[&session.token_hex()]).await.map_err(|_| AuthError::InvalidSessionToken)?;
        let user_id = user.get(0);
        let username = user.get(1);
        Ok(Auth { user_id, username })
    }
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for Session {
    type Rejection = SessionError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cookie = match TypedHeader::<Cookie>::from_request_parts(parts, state).await {
            Ok(cookie) => cookie,
            Err(e) => {
                return match e.reason() {
                    TypedHeaderRejectionReason::Missing => Err(SessionError::Missing),
                    _ => Err(SessionError::InvalidHeader),
                }
            }
        };
        let token_hex = match cookie.get("session") {
            Some(token_hex) => token_hex,
            None => return Err(SessionError::Missing),
        };
        let mut token = [0; 16];
        match hex::decode_to_slice(token_hex, &mut token) {
            Ok(()) => (),
            Err(_) => return Err(SessionError::InvalidSessionTokenFormat),
        }
        Ok(Session { token })
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        StatusCode::FORBIDDEN.into_response()
    }
}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        StatusCode::BAD_REQUEST.into_response()
    }
}
