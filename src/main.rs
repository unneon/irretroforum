mod auth;
mod config;
mod database;
mod error;
mod view;

use crate::auth::{verify_password, verify_totp, Auth, Session};
use crate::config::Config;
use crate::database::Database;
use crate::error::Result;
use crate::view::View;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::header::HeaderName;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{AppendHeaders, Html, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, RequestPartsExt, Router};
use serde::Deserialize;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_postgres::NoTls;
use tracing::{event, info, span, Instrument, Level};
use uuid::Uuid;

#[derive(Clone)]
struct App {
    database: Arc<Database>,
    view: Arc<View>,
    config: Arc<Config>,
}

#[derive(Debug, Deserialize)]
struct PostInThreadForm {
    content: String,
}

#[derive(Debug, Deserialize)]
struct LogInForm {
    username: String,
    password: String,
    totp: String,
}

#[derive(Debug, Deserialize)]
struct RegisterForm {
    username: String,
    password: String,
}

async fn show_homepage(app: State<App>, maybe_auth: Option<Auth>) -> Result<Html<String>> {
    let forums = app.database.all_forums().await?;
    Ok(app.view.homepage(&forums, &maybe_auth))
}

async fn show_forum(
    Path(forum_id): Path<Uuid>,
    app: State<App>,
    maybe_auth: Option<Auth>,
) -> Result<Html<String>> {
    let forum = app.database.forum(forum_id).await?;
    let threads = app.database.forum_threads(forum.id).await?;
    Ok(app.view.forum(&forum, &threads, &maybe_auth))
}

async fn show_thread(
    Path(thread_id): Path<Uuid>,
    app: State<App>,
    maybe_auth: Option<Auth>,
) -> Result<Html<String>> {
    let thread = app.database.thread(thread_id).await?;
    let posts = app.database.thread_posts(thread.id).await?;
    let mut users = HashMap::new();
    for post in &posts {
        if let Entry::Vacant(v) = users.entry(post.author) {
            let author = app.database.user(post.author).await?;
            v.insert(author);
        }
    }
    Ok(app.view.thread(&thread, &posts, &users, &maybe_auth))
}

async fn post_in_thread(
    Path(thread): Path<Uuid>,
    app: State<App>,
    auth: Auth,
    form: Form<PostInThreadForm>,
) -> Result<Redirect> {
    app.database
        .post_insert(thread, auth.user_id(), &form.content)
        .await?;
    Ok(Redirect::to(&format!("/thread/{thread}")))
}

async fn show_user(
    Path(user_id): Path<Uuid>,
    app: State<App>,
    maybe_auth: Option<Auth>,
) -> Result<Html<String>> {
    let user = app.database.user(user_id).await?;
    Ok(app.view.user(&user, &maybe_auth))
}

async fn show_login_form(app: State<App>, maybe_auth: Option<Auth>) -> Html<String> {
    app.view.login(&maybe_auth)
}

async fn login(
    app: State<App>,
    form: Form<LogInForm>,
) -> Result<(AppendHeaders<HeaderName, String, 1>, Redirect)> {
    let user = app.database.user_auth(&form.username).await?;
    verify_password(&form.password, &user.password_phc)?;
    if let Some(totp_secret) = user.totp_secret {
        verify_totp(&form.totp, &totp_secret, &form.username, &app.config)?;
    }
    let session = auth::generate_session_token();
    app.database.session_insert(user.id, &session).await?;
    Ok((AppendHeaders([session.set_cookie()]), Redirect::to("/")))
}

async fn logout(
    app: State<App>,
    session: Session,
) -> Result<(AppendHeaders<HeaderName, String, 1>, Redirect)> {
    app.database.session_delete(&session).await?;
    Ok((AppendHeaders([session.unset_cookie()]), Redirect::to("/")))
}

async fn show_register_form(app: State<App>, maybe_auth: Option<Auth>) -> Html<String> {
    app.view.register(&maybe_auth)
}

async fn register(
    app: State<App>,
    form: Form<RegisterForm>,
) -> Result<(AppendHeaders<HeaderName, String, 1>, Redirect)> {
    let password_phc = auth::generate_new_phc(&form.password);
    let user = app
        .database
        .user_insert(&form.username, &password_phc)
        .await?;
    let session = auth::generate_session_token();
    app.database.session_insert(user.id, &session).await?;
    Ok((AppendHeaders([session.set_cookie()]), Redirect::to("/")))
}

async fn show_settings(app: State<App>, auth: Auth) -> Result<Html<String>> {
    let settings = app.database.settings(auth.user_id()).await?;
    Ok(app.view.settings(&settings, &Some(auth)))
}

async fn show_settings_totp(app: State<App>, auth: Auth) -> Result<Html<String>> {
    let user = app.database.user_totp(auth.user_id()).await?;
    let qr_png_base64 =
        auth::generate_totp_qr(&user.totp_secret.unwrap(), auth.username(), &app.config);
    Ok(app.view.settings_totp(&qr_png_base64, &Some(auth)))
}

async fn totp_enable(app: State<App>, auth: Auth) -> Result<Redirect> {
    let secret = totp_rs::Secret::generate_secret();
    app.database
        .user_totp_update(auth.user_id(), &secret.to_string())
        .await?;
    Ok(Redirect::to("/settings/totp"))
}

async fn show_css() -> &'static str {
    include_str!("css/style.css")
}

async fn logging_middleware<B>(
    req: Request<B>,
    next: Next<B>,
) -> std::result::Result<Response, StatusCode> {
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
        event!(Level::DEBUG, %method, path, query, version, %ip);
        let req = Request::from_parts(parts, body);
        let response = next.run(req).await;
        let status = response.status().as_u16();
        event!(Level::DEBUG, %status);
        response
    }
    .instrument(span)
    .await)
}

#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("irretroforum=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let config = Arc::new(config::load_config());
    let database_connection = tokio_postgres::connect(&config.database.url, NoTls)
        .await
        .unwrap();
    tokio::spawn(database_connection.1);
    let database = Arc::new(Database::new(database_connection.0).await.unwrap());
    let view = Arc::new(View::new(config.clone()));
    let app = App {
        database,
        view,
        config: config.clone(),
    };
    let router = Router::with_state(app)
        .route("/", get(show_homepage))
        .route("/forum/:id", get(show_forum))
        .route("/thread/:id", get(show_thread))
        .route("/thread/:id/post", post(post_in_thread))
        .route("/user/:id", get(show_user))
        .route("/login", get(show_login_form).post(login))
        .route("/logout", post(logout))
        .route("/register", get(show_register_form).post(register))
        .route("/settings", get(show_settings))
        .route("/settings/totp", get(show_settings_totp))
        .route("/settings/totp/enable", post(totp_enable))
        .route("/style.css", get(show_css))
        .layer(axum::middleware::from_fn(logging_middleware));
    let listen_address = SocketAddr::new(config.server.address.0, config.server.port);
    info!("listening on http://{listen_address}");
    axum::Server::bind(&listen_address)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
