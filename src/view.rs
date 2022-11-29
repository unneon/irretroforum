use crate::app::Resources;
use crate::auth::Auth;
use crate::database::{Forum, Settings, Thread, ThreadPost, User};
use axum::response::Html;
use std::sync::Arc;
use tera::{Context, Tera};

pub struct View {
    resources: Arc<Resources>,
    auth: Option<Auth>,
}

impl View {
    pub fn new(resources: Arc<Resources>, auth: Option<Auth>) -> View {
        View { resources, auth }
    }

    pub fn homepage(&self, forums: &[Forum]) -> Html<String> {
        let mut ctx = self.make_context();
        ctx.insert("forums", forums);
        self.render("homepage.html", ctx)
    }

    pub fn forum(&self, forum: &Forum, threads: &[Thread]) -> Html<String> {
        let mut ctx = self.make_context();
        ctx.insert("forum", forum);
        ctx.insert("threads", threads);
        self.render("forum.html", ctx)
    }

    pub fn thread(&self, thread: &Thread, posts: &[ThreadPost]) -> Html<String> {
        let mut ctx = self.make_context();
        ctx.insert("thread", thread);
        ctx.insert("posts", posts);
        self.render("thread.html", ctx)
    }

    pub fn user(&self, user: &User) -> Html<String> {
        let mut ctx = self.make_context();
        ctx.insert("user", user);
        self.render("user.html", ctx)
    }

    pub fn login(&self) -> Html<String> {
        self.render("login.html", self.make_context())
    }

    pub fn register(&self) -> Html<String> {
        self.render("register.html", self.make_context())
    }

    pub fn settings(&self, settings: &Settings) -> Html<String> {
        let mut ctx = self.make_context();
        ctx.insert("settings", settings);
        self.render("settings.html", ctx)
    }

    pub fn settings_totp(&self, qr_png_base64: &str) -> Html<String> {
        let mut ctx = self.make_context();
        ctx.insert("qr_png_base64", qr_png_base64);
        self.render("settings-totp.html", ctx)
    }

    fn make_context(&self) -> Context {
        let mut ctx = Context::new();
        if let Some(auth) = &self.auth {
            ctx.insert("auth", auth);
        }
        ctx.insert("site", &self.resources.config.site);
        ctx
    }

    fn render(&self, template: &str, ctx: Context) -> Html<String> {
        Html(self.resources.tera.render(template, &ctx).unwrap())
    }
}

pub fn make_tera() -> Tera {
    Tera::new("template/**/*.html").unwrap()
}
