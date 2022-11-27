mod auth;
mod config;
mod view;

use crate::auth::{verify_password, verify_totp, Auth, Session};
use crate::config::Config;
use crate::view::wrap_html;
use argon2::password_hash::SaltString;
use argon2::{PasswordHasher, PasswordVerifier};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::header::{HeaderName, SET_COOKIE};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{AppendHeaders, Html, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, RequestPartsExt, Router};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_postgres::NoTls;
use tracing::{event, info, span, Instrument, Level};
use uuid::Uuid;

#[derive(Clone)]
struct App {
    database: Arc<tokio_postgres::Client>,
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

async fn show_homepage(app: State<App>, maybe_auth: Option<Auth>) -> Html<String> {
    let forums = app
        .database
        .query("SELECT id, name FROM forums", &[])
        .await
        .unwrap();
    let mut html = String::new();
    for forum in forums {
        let forum_id: Uuid = forum.get(0);
        let forum_name: &str = forum.get(1);
        html += &format!("<a href=\"/forum/{forum_id}\">{forum_name}</a><br/>");
    }
    wrap_html(&app.config.site.name, &html, maybe_auth)
}

async fn show_forum(
    Path(forum_id): Path<Uuid>,
    app: State<App>,
    maybe_auth: Option<Auth>,
) -> Html<String> {
    let forum = app
        .database
        .query_one("SELECT name FROM forums WHERE id = $1", &[&forum_id])
        .await
        .unwrap();
    let forum_name: &str = forum.get(0);
    let threads = app
        .database
        .query(
            "SELECT id, title FROM threads WHERE forum = $1",
            &[&forum_id],
        )
        .await
        .unwrap();
    let mut html = String::new();
    for thread in threads {
        let thread_id: Uuid = thread.get(0);
        let thread_title: &str = thread.get(1);
        html += &format!("<a href=\"/thread/{thread_id}\">{thread_title}</a><br/>");
    }
    wrap_html(
        &format!("{forum_name} at {}", app.config.site.name),
        &html,
        maybe_auth,
    )
}

async fn show_thread(
    Path(thread_id): Path<Uuid>,
    app: State<App>,
    maybe_auth: Option<Auth>,
) -> Html<String> {
    let thread = app
        .database
        .query_one("SELECT title FROM threads WHERE id = $1", &[&thread_id])
        .await
        .unwrap();
    let thread_title: &str = thread.get(0);
    let posts = app
        .database
        .query(
            r#"
                SELECT author, content, ARRAY_AGG(emoji), ARRAY_AGG(react_count)
                FROM (
                    SELECT p.author, p.time_created, content, emoji, COUNT(r.author) react_count
                    FROM posts p
                    LEFT JOIN reacts r
                    ON p.id = r.post
                    WHERE p.thread = $1
                    GROUP BY p.author, p.time_created, content, emoji
                    ORDER BY react_count DESC, emoji
                ) AS pr
                GROUP BY author, time_created, content
                ORDER BY time_created;
            "#,
            &[&thread_id],
        )
        .await
        .unwrap();
    let mut html = String::new();
    for post in posts {
        let post_author: Uuid = post.get(0);
        let post_content: &str = post.get(1);
        let react_emojis: Vec<Option<&str>> = post.get(2);
        let react_counts: Vec<i64> = post.get(3);
        let author = app
            .database
            .query_one("SELECT username FROM users WHERE id = $1", &[&post_author])
            .await
            .unwrap();
        let author_username: &str = author.get(0);
        let safe_post_content = html_escape::encode_text(post_content);
        html += &format!(
            "<div><a href=\"/user/{post_author}\">{author_username}</a>:<p>{safe_post_content}</p>"
        );
        for (react_emoji, react_count) in react_emojis.into_iter().zip(react_counts.into_iter()) {
            if let Some(react_emoji) = react_emoji {
                html += &format!("<span>{react_emoji}");
                if react_count > 1 {
                    html += &format!(" {react_count}");
                }
                html += "</span>";
            }
        }
        html += "</div>";
    }
    html += &format!(
        include_str!("html/thread-post-form.html"),
        thread_id = thread_id
    );
    wrap_html(thread_title, &html, maybe_auth)
}

async fn post_in_thread(
    Path(thread_id): Path<Uuid>,
    app: State<App>,
    auth: Auth,
    form: Form<PostInThreadForm>,
) -> Redirect {
    app.database
        .execute(
            "INSERT INTO posts (thread, author, content) VALUES ($1, $2, $3)",
            &[&thread_id, &auth.user_id(), &form.content],
        )
        .await
        .unwrap();
    Redirect::to(&format!("/thread/{thread_id}"))
}

async fn show_user(
    Path(user_id): Path<Uuid>,
    app: State<App>,
    maybe_auth: Option<Auth>,
) -> Html<String> {
    let user = app
        .database
        .query_one("SELECT username FROM users WHERE id = $1", &[&user_id])
        .await
        .unwrap();
    let user_username: &str = user.get(0);
    wrap_html(
        &format!("{user_username}'s profile"),
        &format!("<p>{user_username}</p>"),
        maybe_auth,
    )
}

async fn show_login_form(app: State<App>, maybe_auth: Option<Auth>) -> Html<String> {
    wrap_html(
        &format!("Log in to {}", app.config.site.name),
        include_str!("html/login-form.html"),
        maybe_auth,
    )
}

async fn login(
    app: State<App>,
    form: Form<LogInForm>,
) -> (AppendHeaders<HeaderName, String, 1>, Redirect) {
    let user = app
        .database
        .query_one(
            "SELECT id, password_phc, totp_secret FROM users WHERE username = $1",
            &[&form.username],
        )
        .await
        .unwrap();
    let user_id: Uuid = user.get(0);
    let password_phc: &str = user.get(1);
    let totp_secret: Option<&str> = user.get(2);
    verify_password(&form.password, password_phc).unwrap();
    if let Some(totp_secret) = totp_secret {
        verify_totp(&form.totp, totp_secret, &form.username, &app.config).unwrap();
    }
    let session = auth::generate_session_token();
    app.database
        .execute(
            "INSERT INTO sessions (\"user\", token) VALUES ($1, $2)",
            &[&user_id, &session.token_hex()],
        )
        .await
        .unwrap();
    (AppendHeaders([session.set_cookie()]), Redirect::to("/"))
}

async fn logout(
    app: State<App>,
    session: Session,
) -> (AppendHeaders<HeaderName, String, 1>, Redirect) {
    app.database
        .execute(
            "DELETE FROM sessions WHERE token = $1",
            &[&session.token_hex()],
        )
        .await
        .unwrap();
    (AppendHeaders([session.unset_cookie()]), Redirect::to("/"))
}

async fn show_register_form(app: State<App>, maybe_auth: Option<Auth>) -> Html<String> {
    wrap_html(
        &format!("Register on {}", app.config.site.name),
        include_str!("html/register-form.html"),
        maybe_auth,
    )
}

async fn register(app: State<App>, form: Form<RegisterForm>) -> Redirect {
    let password_phc = auth::generate_new_phc(&form.password);
    app.database
        .execute(
            "INSERT INTO users (username, password_phc) VALUES ($1, $2)",
            &[&form.username, &password_phc],
        )
        .await
        .unwrap();
    Redirect::to("/")
}

async fn show_settings(app: State<App>, auth: Auth) -> Html<String> {
    let user = app
        .database
        .query_one(
            "SELECT totp_secret IS NOT NULL FROM users WHERE id = $1",
            &[&auth.user_id()],
        )
        .await
        .unwrap();
    let totp_enabled: bool = user.get(0);
    let mut html = String::new();
    html += match totp_enabled {
        true => include_str!("html/settings-totp-enabled.html"),
        false => include_str!("html/settings-totp-disabled.html"),
    };
    wrap_html(
        &format!("{} settings", app.config.site.name),
        &html,
        Some(auth),
    )
}

async fn show_settings_totp(app: State<App>, auth: Auth) -> Html<String> {
    let user = app
        .database
        .query_one(
            "SELECT totp_secret FROM users WHERE id = $1",
            &[&auth.user_id()],
        )
        .await
        .unwrap();
    let totp_secret: &str = user.get(0);
    let qr_html = auth::generate_totp_qr_html(totp_secret, auth.username(), &app.config);
    wrap_html("TOTP settings", &qr_html, Some(auth))
}

async fn totp_enable(app: State<App>, auth: Auth) -> Redirect {
    let secret = totp_rs::Secret::generate_secret();
    app.database
        .execute(
            "UPDATE users SET totp_secret = $1 WHERE id = $2",
            &[&secret.to_string(), &auth.user_id()],
        )
        .await
        .unwrap();
    Redirect::to("/settings/totp")
}

async fn show_css() -> &'static str {
    include_str!("css/style.css")
}

async fn logging_middleware<B>(req: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
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
    let database = tokio_postgres::connect(&config.database.url, NoTls)
        .await
        .unwrap();
    let app = App {
        database: Arc::new(database.0),
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
    tokio::spawn(database.1);
    let listen_address = SocketAddr::new(config.server.address.0, config.server.port);
    info!("listening on http://{listen_address}");
    axum::Server::bind(&listen_address)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
