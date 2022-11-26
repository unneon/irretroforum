use crate::App;
use axum::extract::rejection::TypedHeaderRejectionReason::Missing;
use axum::extract::FromRequestParts;
use axum::headers::Cookie;
use axum::http::request::Parts;
use axum::{async_trait, TypedHeader};
use std::convert::Infallible;
use uuid::Uuid;

pub struct SessionCookie {
    details: Option<SessionDetails>,
}

struct SessionDetails {
    user_id: Uuid,
    username: String,
    token_hex: String,
}

impl SessionCookie {
    pub fn user_id(&self) -> Option<Uuid> {
        self.details.as_ref().map(|d| d.user_id)
    }

    pub fn username(&self) -> Option<&str> {
        self.details.as_ref().map(|d| d.username.as_str())
    }

    pub fn token_hex(&self) -> Option<&str> {
        self.details.as_ref().map(|d| d.token_hex.as_str())
    }
}

#[async_trait]
impl FromRequestParts<App> for SessionCookie {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &App) -> Result<Self, Self::Rejection> {
        let cookie = match TypedHeader::<Cookie>::from_request_parts(parts, state).await {
            Ok(cookie) => cookie,
            Err(e) if matches!(e.reason(), Missing) => return Ok(SessionCookie { details: None }),
            Err(e) => Err(e).unwrap(),
        };
        if let Some(token_hex) = cookie.get("session") {
            let user = state.database.query_one("SELECT u.id, username FROM users u, sessions s WHERE u.id = s.\"user\" AND s.token = $1", &[&token_hex]).await.unwrap();
            let user_id: Uuid = user.get(0);
            let username: String = user.get(1);
            Ok(SessionCookie {
                details: Some(SessionDetails {
                    user_id,
                    username,
                    token_hex: token_hex.to_owned(),
                }),
            })
        } else {
            Ok(SessionCookie { details: None })
        }
    }
}
