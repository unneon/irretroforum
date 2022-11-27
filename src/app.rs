use crate::auth::Auth;
use crate::config::Config;
use crate::database::{Database, Statements};
use crate::view::View;
use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use std::convert::Infallible;
use std::sync::Arc;
use tera::Tera;
use tokio_postgres::Client;

pub struct Resources {
    pub client: Client,
    pub statements: Statements,
    pub tera: Tera,
    pub config: Arc<Config>,
}

pub struct App {
    pub database: Database,
    pub view: View,
    pub config: Arc<Config>,
}

#[async_trait]
impl FromRequestParts<Arc<Resources>> for App {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<Resources>,
    ) -> Result<Self, Self::Rejection> {
        let auth = Option::<Auth>::from_request_parts(parts, state).await?;
        Ok(App {
            database: Database::new(state.clone()),
            view: View::new(state.clone(), auth),
            config: state.config.clone(),
        })
    }
}
