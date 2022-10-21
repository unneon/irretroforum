use axum::response::Html;

pub fn begin_html(title: &str) -> String {
    format!(include_str!("html/base.begin.html"), title = title)
}

pub fn end_html(mut html: String) -> Html<String> {
    html += include_str!("html/base.end.html");
    Html(html)
}
