use crate::app::Resources;
use crate::auth::Session;
use crate::config::Config;
use crate::error::Result;
use serde::Serialize;
use std::sync::Arc;
use tokio_postgres::{Client, NoTls, Statement};
use uuid::Uuid;

pub struct Database {
    resources: Arc<Resources>,
}

pub struct Statements {
    all_forums: Statement,
    forum: Statement,
    forum_threads: Statement,
    post_insert: Statement,
    session_delete: Statement,
    session_insert: Statement,
    session_user: Statement,
    settings: Statement,
    thread: Statement,
    thread_posts: Statement,
    user: Statement,
    user_auth: Statement,
    user_insert: Statement,
    user_totp: Statement,
    user_totp_update: Statement,
}

#[derive(Serialize)]
pub struct Forum {
    pub id: Uuid,
    pub name: String,
}

#[derive(Serialize)]
pub struct React {
    pub emoji: String,
    pub count: usize,
}

pub struct SessionUser {
    pub user_id: Uuid,
    pub username: String,
}

#[derive(Serialize)]
pub struct Settings {
    pub totp_enabled: bool,
}

#[derive(Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub title: Title,
}

#[derive(Serialize)]
pub struct Thread {
    pub id: Uuid,
    pub title: String,
}

#[derive(Serialize)]
pub struct ThreadPost {
    pub author: User,
    pub content: String,
    pub reacts: Vec<React>,
}

#[derive(Serialize)]
pub struct Title {
    pub name: String,
    pub color: String,
}

pub struct UserAuth {
    pub id: Uuid,
    pub password_phc: String,
    pub totp_secret: Option<String>,
}

pub struct UserTotp {
    pub id: Uuid,
    pub totp_secret: Option<String>,
}

impl Database {
    pub fn new(resources: Arc<Resources>) -> Database {
        Database { resources }
    }

    pub async fn all_forums(&self) -> Result<Vec<Forum>> {
        let rows = self
            .resources
            .client
            .query(&self.resources.statements.all_forums, &[])
            .await?;
        let forums = rows
            .into_iter()
            .map(|row| Forum {
                id: row.get(0),
                name: row.get(1),
            })
            .collect();
        Ok(forums)
    }

    pub async fn forum(&self, id: Uuid) -> Result<Forum> {
        let row = self
            .resources
            .client
            .query_one(&self.resources.statements.forum, &[&id])
            .await?;
        Ok(Forum {
            id,
            name: row.get(0),
        })
    }

    pub async fn forum_threads(&self, forum_id: Uuid) -> Result<Vec<Thread>> {
        let rows = self
            .resources
            .client
            .query(&self.resources.statements.forum_threads, &[&forum_id])
            .await?;
        let threads = rows
            .into_iter()
            .map(|row| Thread {
                id: row.get(0),
                title: row.get(1),
            })
            .collect();
        Ok(threads)
    }

    pub async fn post_insert(&self, thread: Uuid, author: Uuid, content: &str) -> Result<()> {
        self.resources
            .client
            .execute(
                &self.resources.statements.post_insert,
                &[&thread, &author, &content],
            )
            .await?;
        Ok(())
    }

    pub async fn session_delete(&self, session: &Session) -> Result<()> {
        self.resources
            .client
            .execute(
                &self.resources.statements.session_delete,
                &[&session.token_hex()],
            )
            .await?;
        Ok(())
    }

    pub async fn session_insert(&self, user: Uuid, session: &Session) -> Result<()> {
        self.resources
            .client
            .execute(
                &self.resources.statements.session_insert,
                &[&user, &session.token_hex()],
            )
            .await?;
        Ok(())
    }

    pub async fn session_user(&self, session: &Session) -> Result<SessionUser> {
        let row = self
            .resources
            .client
            .query_one(
                &self.resources.statements.session_user,
                &[&session.token_hex()],
            )
            .await?;
        Ok(SessionUser {
            user_id: row.get(0),
            username: row.get(1),
        })
    }

    pub async fn settings(&self, user: Uuid) -> Result<Settings> {
        let row = self
            .resources
            .client
            .query_one(&self.resources.statements.settings, &[&user])
            .await?;
        Ok(Settings {
            totp_enabled: row.get(0),
        })
    }

    pub async fn thread(&self, id: Uuid) -> Result<Thread> {
        let row = self
            .resources
            .client
            .query_one(&self.resources.statements.thread, &[&id])
            .await?;
        Ok(Thread {
            id,
            title: row.get(0),
        })
    }

    pub async fn thread_posts(&self, thread_id: Uuid) -> Result<Vec<ThreadPost>> {
        let rows = self
            .resources
            .client
            .query(&self.resources.statements.thread_posts, &[&thread_id])
            .await?;
        let posts = rows
            .into_iter()
            .map(|row| {
                let react_emojis: Vec<Option<String>> = row.get(5);
                let react_counts: Vec<i64> = row.get(6);
                ThreadPost {
                    author: User {
                        id: row.get(0),
                        username: row.get(1),
                        title: Title {
                            name: row.get(2),
                            color: row.get(3),
                        },
                    },
                    content: row.get(4),
                    reacts: react_emojis
                        .into_iter()
                        .zip(react_counts.into_iter())
                        .filter_map(|(emoji, count)| {
                            Some(React {
                                emoji: emoji?,
                                count: count as usize,
                            })
                        })
                        .collect(),
                }
            })
            .collect();
        Ok(posts)
    }

    pub async fn user(&self, id: Uuid) -> Result<User> {
        let row = self
            .resources
            .client
            .query_one(&self.resources.statements.user, &[&id])
            .await?;
        Ok(User {
            id,
            username: row.get(0),
            title: Title {
                name: row.get(1),
                color: row.get(2),
            },
        })
    }

    pub async fn user_auth(&self, username: &str) -> Result<UserAuth> {
        let row = self
            .resources
            .client
            .query_one(&self.resources.statements.user_auth, &[&username])
            .await?;
        Ok(UserAuth {
            id: row.get(0),
            password_phc: row.get(1),
            totp_secret: row.get(2),
        })
    }

    pub async fn user_insert(&self, username: &str, password_phc: &str) -> Result<User> {
        let row = self
            .resources
            .client
            .query_one(
                &self.resources.statements.user_insert,
                &[&username, &password_phc],
            )
            .await?;
        Ok(User {
            id: row.get(0),
            username: username.to_owned(),
            // TODO: Return title.
            title: Title {
                name: String::new(),
                color: String::new(),
            },
        })
    }

    pub async fn user_totp(&self, id: Uuid) -> Result<UserTotp> {
        let row = self
            .resources
            .client
            .query_one(&self.resources.statements.user_totp, &[&id])
            .await?;
        Ok(UserTotp {
            id,
            totp_secret: row.get(0),
        })
    }

    pub async fn user_totp_update(&self, id: Uuid, secret: &str) -> Result<()> {
        self.resources
            .client
            .execute(&self.resources.statements.user_totp_update, &[&secret, &id])
            .await?;
        Ok(())
    }
}

impl Statements {
    pub async fn new(client: &Client) -> Result<Statements> {
        let all_forums = client.prepare("SELECT id, name FROM forums").await?;
        let forum = client
            .prepare("SELECT name FROM forums WHERE id = $1")
            .await?;
        let forum_threads = client
            .prepare("SELECT id, title FROM threads WHERE forum = $1")
            .await?;
        let insert_post = client
            .prepare("INSERT INTO posts (thread, author, content) VALUES ($1, $2, $3)")
            .await?;
        let session_delete = client
            .prepare("DELETE FROM sessions WHERE token = $1")
            .await?;
        let session_insert = client
            .prepare("INSERT INTO sessions (\"user\", token) VALUES ($1, $2)")
            .await?;
        let session_user = client.prepare("SELECT u.id, username FROM users u, sessions s WHERE u.id = s.\"user\" AND s.token = $1")
            .await?;
        let settings = client
            .prepare("SELECT totp_secret IS NOT NULL FROM users WHERE id = $1")
            .await?;
        let thread = client
            .prepare("SELECT title FROM threads WHERE id = $1")
            .await?;
        let thread_posts = client
            .prepare(
                "SELECT author, username, t.name, t.color, content, ARRAY_AGG(emoji), ARRAY_AGG(react_count)
                FROM (
                    SELECT p.author, p.time_created, content, emoji, COUNT(r.author) react_count
                    FROM posts p
                    LEFT JOIN reacts r
                    ON p.id = r.post
                    WHERE p.thread = $1
                    GROUP BY p.author, p.time_created, content, emoji
                    ORDER BY react_count DESC, emoji
                ) AS pr, users u, user_titles ut, titles t
                WHERE author = u.id AND u.id = ut.\"user\" AND ut.title = t.id
                GROUP BY author, username, t.name, t.color, pr.time_created, content
                ORDER BY pr.time_created;",
            )
            .await?;
        let user = client
            .prepare("SELECT username, t.name, t.color FROM users u, user_titles ut, titles t WHERE u.id = $1 AND ut.\"user\" = u.id AND ut.title = t.id")
            .await?;
        let user_auth = client
            .prepare("SELECT id, password_phc, totp_secret FROM users WHERE username = $1")
            .await?;
        let user_insert = client
            .prepare("INSERT INTO users (username, password_phc) VALUES ($1, $2) RETURNING id")
            .await?;
        let user_totp = client
            .prepare("SELECT totp_secret FROM users WHERE id = $1")
            .await?;
        let user_totp_update = client
            .prepare("UPDATE users SET totp_secret = $1 WHERE id = $2")
            .await?;
        Ok(Statements {
            all_forums,
            forum,
            forum_threads,
            post_insert: insert_post,
            session_delete,
            session_insert,
            session_user,
            settings,
            thread,
            thread_posts,
            user,
            user_auth,
            user_insert,
            user_totp,
            user_totp_update,
        })
    }
}

pub async fn connect(config: &Config) -> Client {
    let (client, connection) = tokio_postgres::connect(&config.database.url, NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);
    client
}
