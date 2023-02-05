use crate::auth::Auth;
use crate::config::Config;
use crate::database;
use crate::database::{Database, Statements};
use crate::view::make_tera;
use crate::view::View;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::USER_AGENT;
use axum::http::request::Parts;
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::{async_trait, RequestPartsExt};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tera::Tera;
use tokio_postgres::Client;
use tracing::{event, span, warn, Instrument, Level};
use uuid::Uuid;

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

impl Resources {
    pub async fn new(config: Config) -> Resources {
        let client = database::connect(&config).await;
        let statements = Statements::new(&client).await.unwrap();
        let tera = make_tera();
        let config = Arc::new(config);
        Resources {
            client,
            statements,
            tera,
            config,
        }
    }
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

pub async fn logging_middleware<B>(req: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    let request_id = Uuid::new_v4();
    let span = span!(Level::INFO, "request", id = request_id.to_string());
    Ok(async move {
        let (mut parts, body) = req.into_parts();
        let connect_info: ConnectInfo<SocketAddr> = parts.extract().await.unwrap();
        let method = &parts.method;
        let path = parts.uri.path();
        let query = parts.uri.query().unwrap_or_default();
        let version = format!("{:?}", parts.version);
        let ip = connect_info.0.ip();
        let user_agent = get_user_agent(&parts);
        event!(Level::DEBUG, %method, path, query, version, %ip, user_agent);
        let req = Request::from_parts(parts, body);
        let response = next.run(req).await;
        let status = response.status().as_u16();
        event!(Level::DEBUG, %status);
        response
    }
    .instrument(span)
    .await)
}

fn get_user_agent(parts: &Parts) -> &str {
    let Some(value) = parts.headers.get(USER_AGENT) else {
        warn!("user agent header not sent by client");
        return "";
    };
    let Ok(user_agent) = value.to_str() else {
        let bytes = value.as_bytes();
        warn!(%bytes, "user agent contains non-ASCII characters");
    };
    user_agent
}
