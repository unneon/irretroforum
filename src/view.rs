use crate::auth::Auth;
use crate::config::Config;
use crate::database::{Forum, Settings, Thread, ThreadPost, User};
use axum::response::Html;
use std::collections::HashMap;
use std::sync::Arc;
use tera::{Context, Tera};
use uuid::Uuid;

pub struct View {
    tera: Tera,
    config: Arc<Config>,
}

impl View {
    pub fn new(config: Arc<Config>) -> View {
        let tera = Tera::new("template/**/*.html").unwrap();
        View { tera, config }
    }

    pub fn homepage(&self, forums: &[Forum], auth: &Option<Auth>) -> Html<String> {
        let mut ctx = self.make_context(auth);
        ctx.insert("forums", forums);
        Html(self.tera.render("homepage.html", &ctx).unwrap())
    }

    pub fn forum(&self, forum: &Forum, threads: &[Thread], auth: &Option<Auth>) -> Html<String> {
        let mut ctx = self.make_context(auth);
        ctx.insert("forum", forum);
        ctx.insert("threads", threads);
        Html(self.tera.render("forum.html", &ctx).unwrap())
    }

    pub fn thread(
        &self,
        thread: &Thread,
        posts: &[ThreadPost],
        users: &HashMap<Uuid, User>,
        auth: &Option<Auth>,
    ) -> Html<String> {
        let mut ctx = self.make_context(auth);
        ctx.insert("thread", thread);
        ctx.insert("posts", posts);
        ctx.insert("users", users);
        Html(self.tera.render("thread.html", &ctx).unwrap())
    }

    pub fn user(&self, user: &User, auth: &Option<Auth>) -> Html<String> {
        let mut ctx = self.make_context(auth);
        ctx.insert("user", user);
        Html(self.tera.render("user.html", &ctx).unwrap())
    }

    pub fn login(&self, auth: &Option<Auth>) -> Html<String> {
        let ctx = self.make_context(auth);
        Html(self.tera.render("login.html", &ctx).unwrap())
    }

    pub fn register(&self, auth: &Option<Auth>) -> Html<String> {
        let ctx = self.make_context(auth);
        Html(self.tera.render("register.html", &ctx).unwrap())
    }

    pub fn settings(&self, settings: &Settings, auth: &Option<Auth>) -> Html<String> {
        let mut ctx = self.make_context(auth);
        ctx.insert("settings", settings);
        Html(self.tera.render("settings.html", &ctx).unwrap())
    }

    pub fn settings_totp(&self, qr_png_base64: &str, auth: &Option<Auth>) -> Html<String> {
        let mut ctx = self.make_context(auth);
        ctx.insert("qr_png_base64", qr_png_base64);
        Html(self.tera.render("settings-totp.html", &ctx).unwrap())
    }

    fn make_context(&self, auth: &Option<Auth>) -> Context {
        let mut ctx = Context::new();
        if let Some(auth) = auth {
            ctx.insert("auth", auth);
        }
        ctx.insert("site", &self.config.site);
        ctx
    }
}
