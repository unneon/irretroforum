use crate::{App, Config, PasswordHasher, PasswordVerifier, Response, SaltString, SET_COOKIE};
use argon2::{Argon2, PasswordHash};
use axum::extract::rejection::TypedHeaderRejectionReason;
use axum::extract::FromRequestParts;
use axum::headers::{Cookie, HeaderName};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{async_trait, TypedHeader};
use rand::Rng;
use totp_rs::TOTP;
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

#[derive(Debug)]
pub enum LogInError {
    WrongPassword,
    InvalidTotpToken,
}

pub enum SessionError {
    Missing,
    InvalidHeader,
    InvalidSessionTokenFormat,
}

const SESSION_COOKIE_NAME: &str = "SESSION";

// Parameters recommended by OWASP as of 2022-11-27.
const ARGON2_M_COST_KB: u32 = 37 * 1024;
const ARGON2_T_COST: u32 = 1;
const ARGON2_P_COST: u32 = 1;
const ARGON2_ALGORITHM: argon2::Algorithm = argon2::Algorithm::Argon2id;
const ARGON2_VERSION: argon2::Version = argon2::Version::V0x13;

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
        hex::encode(self.token)
    }

    pub fn set_cookie(&self) -> (HeaderName, String) {
        let hex = self.token_hex();
        let value = format!("{SESSION_COOKIE_NAME}={hex}; Secure; HttpOnly; SameSite=Strict");
        (SET_COOKIE, value)
    }

    pub fn unset_cookie(&self) -> (HeaderName, String) {
        let value = format!("{SESSION_COOKIE_NAME}=; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
        (SET_COOKIE, value)
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
                return Err(AuthError::InvalidSessionTokenFormat);
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
                };
            }
        };
        let token_hex = match cookie.get(SESSION_COOKIE_NAME) {
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

pub fn generate_new_phc(password: &str) -> String {
    let kdf = make_password_kdf();
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = kdf.hash_password(password.as_bytes(), &salt).unwrap();
    hash.to_string()
}

pub fn verify_password(password: &str, password_phc: &str) -> Result<(), LogInError> {
    let kdf = make_password_kdf();
    let hash = PasswordHash::new(password_phc).unwrap();
    kdf.verify_password(password.as_bytes(), &hash)
        .map_err(|_| LogInError::WrongPassword)
}

pub fn verify_totp(
    totp_code: &str,
    totp_secret: &str,
    username: &str,
    config: &Config,
) -> Result<(), LogInError> {
    let totp = make_totp(totp_secret, username, config);
    if !totp.check_current(totp_code).unwrap() {
        return Err(LogInError::InvalidTotpToken);
    }
    Ok(())
}

pub fn generate_session_token() -> Session {
    let token: [u8; 16] = rand::thread_rng().gen();
    Session { token }
}

pub fn generate_totp_qr_html(secret: &str, username: &str, config: &Config) -> String {
    let totp = make_totp(secret, username, config);
    let qr_base64 = totp.get_qr().unwrap();
    format!("<img src=\"data:image/png;base64, {qr_base64}\"/>")
}

fn make_password_kdf() -> Argon2<'static> {
    let params = argon2::Params::new(ARGON2_M_COST_KB, ARGON2_T_COST, ARGON2_P_COST, None).unwrap();
    Argon2::new(ARGON2_ALGORITHM, ARGON2_VERSION, params)
}

fn make_totp<'a>(secret: &'a str, username: &str, config: &Config) -> TOTP<&'a str> {
    let issuer = Some(config.site.name.clone());
    let account_name = username.to_owned();
    let rfc6238 = totp_rs::Rfc6238::new(6, secret, issuer, account_name).unwrap();
    TOTP::from_rfc6238(rfc6238).unwrap()
}
