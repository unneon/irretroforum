mod app;
mod auth;
mod config;
mod database;
mod error;
mod view;

use crate::app::{logging_middleware, App, Resources};
use crate::auth::{verify_password, verify_totp, Auth, Session};
use crate::error::Result;
use axum::extract::Path;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Form, Router};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
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

async fn show_homepage(app: App) -> Result<impl IntoResponse> {
    let forums = app.database.all_forums().await?;
    Ok(app.view.homepage(&forums))
}

async fn show_forum(forum_id: Path<Uuid>, app: App) -> Result<impl IntoResponse> {
    let forum = app.database.forum(*forum_id).await?;
    let threads = app.database.forum_threads(forum.id).await?;
    Ok(app.view.forum(&forum, &threads))
}

async fn show_thread(thread_id: Path<Uuid>, app: App) -> Result<impl IntoResponse> {
    let thread = app.database.thread(*thread_id).await?;
    let posts = app.database.thread_posts(thread.id).await?;
    Ok(app.view.thread(&thread, &posts))
}

async fn post_in_thread(
    thread: Path<Uuid>,
    auth: Auth,
    app: App,
    form: Form<PostInThreadForm>,
) -> Result<impl IntoResponse> {
    app.database
        .post_insert(*thread, auth.user_id(), &form.content)
        .await?;
    Ok(Redirect::to(&format!("/thread/{}", *thread)))
}

async fn show_user(user_id: Path<Uuid>, app: App) -> Result<impl IntoResponse> {
    let user = app.database.user(*user_id).await?;
    Ok(app.view.user(&user))
}

async fn show_login_form(app: App) -> impl IntoResponse {
    app.view.login()
}

async fn login(cookies: CookieJar, app: App, form: Form<LogInForm>) -> Result<impl IntoResponse> {
    let user = app.database.user_auth(&form.username).await?;
    verify_password(&form.password, &user.password_phc)?;
    if let Some(totp_secret) = user.totp_secret {
        verify_totp(&form.totp, &totp_secret, &form.username, &app.config)?;
    }
    let session = auth::generate_session_token();
    app.database.session_insert(user.id, &session).await?;
    Ok((cookies.add(session.cookie()), Redirect::to("/")))
}

async fn logout(session: Session, cookies: CookieJar, app: App) -> Result<impl IntoResponse> {
    app.database.session_delete(&session).await?;
    Ok((cookies.remove(session.cookie()), Redirect::to("/")))
}

async fn show_register_form(app: App) -> impl IntoResponse {
    app.view.register()
}

async fn register(
    cookies: CookieJar,
    app: App,
    form: Form<RegisterForm>,
) -> Result<impl IntoResponse> {
    let password_phc = auth::generate_new_phc(&form.password);
    let user = app
        .database
        .user_insert(&form.username, &password_phc)
        .await?;
    let session = auth::generate_session_token();
    app.database.session_insert(user.id, &session).await?;
    Ok((cookies.add(session.cookie()), Redirect::to("/")))
}

async fn show_settings(auth: Auth, app: App) -> Result<impl IntoResponse> {
    let settings = app.database.settings(auth.user_id()).await?;
    Ok(app.view.settings(&settings))
}

async fn show_settings_totp(auth: Auth, app: App) -> Result<impl IntoResponse> {
    let user = app.database.user_totp(auth.user_id()).await?;
    let qr_png_base64 =
        auth::generate_totp_qr(&user.totp_secret.unwrap(), auth.username(), &app.config);
    Ok(app.view.settings_totp(&qr_png_base64))
}

async fn totp_enable(auth: Auth, app: App) -> Result<impl IntoResponse> {
    let secret = totp_rs::Secret::generate_secret();
    app.database
        .user_totp_update(auth.user_id(), &secret.to_string())
        .await?;
    Ok(Redirect::to("/settings/totp"))
}

async fn show_css() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/css")], include_str!("css/style.css"))
}

#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("irretroforum=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    let config = config::load_config();
    let listen_address = SocketAddr::new(config.server.address.0, config.server.port);
    let state = Arc::new(Resources::new(config).await);
    let router = Router::new()
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
        .layer(axum::middleware::from_fn(logging_middleware))
        .with_state(state);
    info!("listening on http://{listen_address}");
    axum::Server::bind(&listen_address)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
