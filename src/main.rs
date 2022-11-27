mod app;
mod auth;
mod config;
mod database;
mod error;
mod view;

use crate::app::{App, Resources};
use crate::auth::{verify_password, verify_totp, Auth, Session};
use crate::database::Statements;
use crate::error::Result;
use crate::view::make_tera;
use axum::extract::{ConnectInfo, Path};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{AppendHeaders, Html, IntoResponse, Redirect, Response};
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

async fn show_homepage(app: App) -> Result<Html<String>> {
    let forums = app.database.all_forums().await?;
    Ok(app.view.homepage(&forums))
}

async fn show_forum(forum_id: Path<Uuid>, app: App) -> Result<Html<String>> {
    let forum = app.database.forum(*forum_id).await?;
    let threads = app.database.forum_threads(forum.id).await?;
    Ok(app.view.forum(&forum, &threads))
}

async fn show_thread(thread_id: Path<Uuid>, app: App) -> Result<Html<String>> {
    let thread = app.database.thread(*thread_id).await?;
    let posts = app.database.thread_posts(thread.id).await?;
    let mut users = HashMap::new();
    for post in &posts {
        if let Entry::Vacant(v) = users.entry(post.author) {
            let author = app.database.user(post.author).await?;
            v.insert(author);
        }
    }
    Ok(app.view.thread(&thread, &posts, &users))
}

async fn post_in_thread(
    thread: Path<Uuid>,
    auth: Auth,
    app: App,
    form: Form<PostInThreadForm>,
) -> Result<Redirect> {
    app.database
        .post_insert(*thread, auth.user_id(), &form.content)
        .await?;
    Ok(Redirect::to(&format!("/thread/{}", *thread)))
}

async fn show_user(user_id: Path<Uuid>, app: App) -> Result<Html<String>> {
    let user = app.database.user(*user_id).await?;
    Ok(app.view.user(&user))
}

async fn show_login_form(app: App) -> Html<String> {
    app.view.login()
}

async fn login(app: App, form: Form<LogInForm>) -> Result<impl IntoResponse> {
    let user = app.database.user_auth(&form.username).await?;
    verify_password(&form.password, &user.password_phc)?;
    if let Some(totp_secret) = user.totp_secret {
        verify_totp(&form.totp, &totp_secret, &form.username, &app.config)?;
    }
    let session = auth::generate_session_token();
    app.database.session_insert(user.id, &session).await?;
    Ok((AppendHeaders([session.set_cookie()]), Redirect::to("/")))
}

async fn logout(session: Session, app: App) -> Result<impl IntoResponse> {
    app.database.session_delete(&session).await?;
    Ok((AppendHeaders([session.unset_cookie()]), Redirect::to("/")))
}

async fn show_register_form(app: App) -> Html<String> {
    app.view.register()
}

async fn register(app: App, form: Form<RegisterForm>) -> Result<impl IntoResponse> {
    let password_phc = auth::generate_new_phc(&form.password);
    let user = app
        .database
        .user_insert(&form.username, &password_phc)
        .await?;
    let session = auth::generate_session_token();
    app.database.session_insert(user.id, &session).await?;
    Ok((AppendHeaders([session.set_cookie()]), Redirect::to("/")))
}

async fn show_settings(auth: Auth, app: App) -> Result<Html<String>> {
    let settings = app.database.settings(auth.user_id()).await?;
    Ok(app.view.settings(&settings))
}

async fn show_settings_totp(auth: Auth, app: App) -> Result<Html<String>> {
    let user = app.database.user_totp(auth.user_id()).await?;
    let qr_png_base64 =
        auth::generate_totp_qr(&user.totp_secret.unwrap(), auth.username(), &app.config);
    Ok(app.view.settings_totp(&qr_png_base64))
}

async fn totp_enable(auth: Auth, app: App) -> Result<Redirect> {
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
    let (client, db_conn) = tokio_postgres::connect(&config.database.url, NoTls)
        .await
        .unwrap();
    tokio::spawn(db_conn);
    let listen_address = SocketAddr::new(config.server.address.0, config.server.port);
    let statements = Statements::new(&client).await.unwrap();
    let tera = make_tera();
    let resources = Resources {
        client,
        statements,
        tera,
        config,
    };
    let state = Arc::new(resources);
    let router = Router::with_state(state)
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
    info!("listening on http://{listen_address}");
    axum::Server::bind(&listen_address)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
