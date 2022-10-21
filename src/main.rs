mod config;
mod view;

use crate::view::{begin_html, end_html};
use axum::extract::{ConnectInfo, Path};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, Response};
use axum::{extract::State, routing::get, RequestPartsExt, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_postgres::NoTls;
use tracing::{event, info, span, Instrument, Level};
use uuid::Uuid;

#[derive(Clone)]
struct App {
    database: Arc<tokio_postgres::Client>,
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
    end_html(html)
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
        .route("/user/:id", get(show_user))
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
