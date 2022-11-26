mod config;
mod view;

use crate::view::{begin_html, end_html};
use argon2::password_hash::SaltString;
use argon2::{PasswordHasher, PasswordVerifier};
use axum::extract::{ConnectInfo, Path, State};
use axum::headers::Cookie;
use axum::http::header::{HeaderName, SET_COOKIE};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{AppendHeaders, Html, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, RequestPartsExt, Router, TypedHeader};
use rand::Rng;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_postgres::NoTls;
use tracing::{debug, event, info, span, Instrument, Level};
use uuid::Uuid;

#[derive(Clone)]
struct App {
    database: Arc<tokio_postgres::Client>,
}

#[derive(Debug, Deserialize)]
struct PostInThreadForm {
    content: String,
}

#[derive(Debug, Deserialize)]
struct LogInForm {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct RegisterForm {
    username: String,
    password: String,
}

async fn show_homepage(app: State<App>) -> Html<String> {
    let forums = app
        .database
        .query("SELECT id, name FROM forums", &[])
        .await
        .unwrap();
    let mut html = begin_html("Irretroforum");
    for forum in forums {
        let forum_id: Uuid = forum.get(0);
        let forum_name: &str = forum.get(1);
        html += &format!("<a href=\"/forum/{forum_id}\">{forum_name}</a><br/>");
    }
    end_html(html)
}

async fn show_forum(Path(forum_id): Path<Uuid>, app: State<App>) -> Html<String> {
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
    let mut html = begin_html(&format!("{forum_name} at Irretroforum"));
    for thread in threads {
        let thread_id: Uuid = thread.get(0);
        let thread_title: &str = thread.get(1);
        html += &format!("<a href=\"/thread/{thread_id}\">{thread_title}</a><br/>");
    }
    end_html(html)
}

async fn show_thread(Path(thread_id): Path<Uuid>, app: State<App>) -> Html<String> {
    let thread = app
        .database
        .query_one("SELECT title FROM threads WHERE id = $1", &[&thread_id])
        .await
        .unwrap();
    let thread_title: &str = thread.get(0);
    let posts = app
        .database
        .query(
            "SELECT author, content FROM posts WHERE thread = $1",
            &[&thread_id],
        )
        .await
        .unwrap();
    let mut html = begin_html(thread_title);
    for post in posts {
        let user_id: Uuid = post.get(0);
        let post_content: &str = post.get(1);
        let user = app
            .database
            .query_one("SELECT username FROM users WHERE id = $1", &[&user_id])
            .await
            .unwrap();
        let user_username: &str = user.get(0);
        let safe_post_content: String = post_content
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || c == &' ')
            .collect();
        html +=
            &format!("<a href=\"/user/{user_id}\">{user_username}</a>:<p>{safe_post_content}</p>");
    }
    html += &format!(
        include_str!("html/thread-post-form.html"),
        thread_id = thread_id
    );
    end_html(html)
}

async fn post_in_thread(
    Path(thread_id): Path<Uuid>,
    cookies: TypedHeader<Cookie>,
    app: State<App>,
    form: Form<PostInThreadForm>,
) -> Redirect {
    let session_hex = cookies.get("session").unwrap();
    debug!(
        session = session_hex,
        "Checking authorization for session token"
    );
    let user = app
        .database
        .query_one(
            "SELECT \"user\" FROM sessions WHERE token = $1",
            &[&session_hex],
        )
        .await
        .unwrap();
    let user_id: Uuid = user.get(0);
    app.database
        .execute(
            "INSERT INTO posts (thread, author, content) VALUES ($1, $2, $3)",
            &[&thread_id, &user_id, &form.content],
        )
        .await
        .unwrap();
    Redirect::to(&format!("/thread/{thread_id}"))
}

async fn show_user(Path(user_id): Path<Uuid>, app: State<App>) -> Html<String> {
    let user = app
        .database
        .query_one("SELECT username FROM users WHERE id = $1", &[&user_id])
        .await
        .unwrap();
    let user_username: &str = user.get(0);
    let mut html = begin_html(&format!("{user_username}'s profile"));
    html += &format!("<p>{user_username}</p>");
    end_html(html)
}

async fn show_login_form() -> Html<String> {
    let mut html = begin_html("Log in to Irretroforum");
    html += include_str!("html/login-form.html");
    end_html(html)
}

async fn login(
    app: State<App>,
    form: Form<LogInForm>,
) -> (AppendHeaders<HeaderName, String, 1>, Redirect) {
    let user = app
        .database
        .query_one(
            "SELECT id, password_phc FROM users WHERE username = $1",
            &[&form.username],
        )
        .await
        .unwrap();
    let user_id: Uuid = user.get(0);
    let password_phc: &str = user.get(1);
    let password_hash = argon2::PasswordHash::new(password_phc).unwrap();
    argon2::Argon2::default()
        .verify_password(form.password.as_bytes(), &password_hash)
        .unwrap();
    let session_token: [u8; 128 / 8] = rand::thread_rng().gen();
    let session_token_hex = hex::encode(&session_token);
    app.database
        .execute(
            "INSERT INTO sessions (\"user\", token) VALUES ($1, $2)",
            &[&user_id, &session_token_hex],
        )
        .await
        .unwrap();
    (
        AppendHeaders([(
            SET_COOKIE,
            format!("session={session_token_hex}; Secure; HttpOnly; SameSite=Strict"),
        )]),
        Redirect::to("/"),
    )
}

async fn show_register_form() -> Html<String> {
    let mut html = begin_html("Register on Irretroforum");
    html += include_str!("html/register-form.html");
    end_html(html)
}

async fn register(app: State<App>, form: Form<RegisterForm>) -> Redirect {
    let password_kdf = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(37 * 1024, 1, 1, None).unwrap(),
    );
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_phc = password_kdf
        .hash_password(form.password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    app.database
        .execute(
            "INSERT INTO users (username, password_phc) VALUES ($1, $2)",
            &[&form.username, &password_phc],
        )
        .await
        .unwrap();
    Redirect::to("/")
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
    let config = config::load_config();
    let database = tokio_postgres::connect(&config.database.url, NoTls)
        .await
        .unwrap();
    let app = App {
        database: Arc::new(database.0),
    };
    let router = Router::with_state(app)
        .route("/", get(show_homepage))
        .route("/forum/:id", get(show_forum))
        .route("/thread/:id", get(show_thread))
        .route("/thread/:id/post", post(post_in_thread))
        .route("/user/:id", get(show_user))
        .route("/login", get(show_login_form).post(login))
        .route("/register", get(show_register_form).post(register))
        .route("/style.css", get(show_css))
        .layer(axum::middleware::from_fn(logging_middleware));
    tokio::spawn(database.1);
    let listen_address = SocketAddr::new(config.server.address, config.server.port);
    info!("listening on http://{listen_address}");
    axum::Server::bind(&listen_address)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
