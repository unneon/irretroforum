use crate::auth::LogInError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
#[allow(dead_code)]
pub enum Error {
    LogIn(LogInError),
    Database(tokio_postgres::Error),
    InputOutput(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Error::LogIn(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Error::Database(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Error::InputOutput(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Self {
        Error::Database(e)
    }
}

impl From<LogInError> for Error {
    fn from(e: LogInError) -> Self {
        Error::LogIn(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::InputOutput(e)
    }
}
