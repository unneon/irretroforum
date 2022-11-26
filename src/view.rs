use crate::auth::Auth;
use axum::response::Html;

pub fn wrap_html(title: &str, body: &str, session: Option<Auth>) -> Html<String> {
    let prefix = format!(include_str!("html/base.begin.html"), title = title);
    let suffix = include_str!("html/base.end.html");
    let login_element = match session {
        Some(session) => format!(
            include_str!("html/account-widget-user.html"),
            username = html_escape::encode_text(session.username())
        ),
        None => include_str!("html/account-widget-anonymous.html").to_owned(),
    };
    Html(format!("{prefix}{login_element}{body}{suffix}"))
}
