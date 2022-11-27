use crate::auth::LogInError;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
pub enum Error {
    LogInError(LogInError),
    DatabaseError(tokio_postgres::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Error::LogInError(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Error::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Self {
        Error::DatabaseError(e)
    }
}

impl From<LogInError> for Error {
    fn from(e: LogInError) -> Self {
        Error::LogInError(e)
    }
}
