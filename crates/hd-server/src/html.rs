//! Server-rendered HTML: escaping, the page layout, and the small pieces
//! every page repeats. Every value that did not come from a string literal
//! in this crate goes through [`esc`].

use std::fmt::Write as _;

/// Escapes text for an HTML element body or a double-quoted attribute.
pub fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    esc_into(&mut out, text);
    out
}

/// [`esc`] appended to `out`. Runs of ordinary text are copied whole, so a
/// large log costs one append per special character rather than one per
/// character.
pub fn esc_into(out: &mut String, text: &str) {
    let mut plain = 0;
    for (i, b) in text.bytes().enumerate() {
        let replacement = match b {
            b'&' => "&amp;",
            b'<' => "&lt;",
            b'>' => "&gt;",
            b'"' => "&quot;",
            b'\'' => "&#39;",
            _ => continue,
        };
        out.push_str(&text[plain..i]);
        out.push_str(replacement);
        plain = i + 1;
    }
    out.push_str(&text[plain..]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Success,
    Warning,
    Danger,
}

impl Tone {
    fn class(self) -> &'static str {
        match self {
            Tone::Success => "flash-success",
            Tone::Warning => "notice-warning",
            Tone::Danger => "notice-danger",
        }
    }
}

/// The navigation, in order: (path, label, key a page passes as `nav`).
pub const NAV: &[(&str, &str, &str)] = &[
    ("/files", "Files", "files"),
    ("/trash", "Trash", "trash"),
    ("/devices", "Devices", "devices"),
];

/// Shown only to admins, after the rest.
pub const ADMIN_NAV: (&str, &str, &str) = ("/admin", "Admin", "admin");

#[derive(Debug, Default)]
pub struct Page {
    pub title: String,
    /// The NAV key of the current page; "" for none.
    pub nav: &'static str,
    /// The CSRF token for the logout form; `None` hides the navigation.
    pub csrf: Option<String>,
    /// Show the admin link.
    pub admin: bool,
    pub flashes: Vec<(Tone, String)>,
    /// Extra classes on <main>, e.g. " page-center".
    pub page_class: &'static str,
    /// The page body, already escaped.
    pub body: String,
}

pub fn render(page: &Page) -> String {
    let mut out = String::with_capacity(page.body.len() + 4096);
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    let _ = writeln!(out, "<title>{} — homedrive</title>", esc(&page.title));
    out.push_str(
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"color-scheme\" content=\"dark light\">\n\
         <link rel=\"icon\" type=\"image/svg+xml\" href=\"/static/favicon.svg\">\n",
    );
    // The version in the URL lets the stylesheet be cached for an hour and
    // still be picked up at once after an upgrade.
    let _ = writeln!(
        out,
        "<link rel=\"stylesheet\" href=\"/static/style.css?v={}\">",
        hd_common::VERSION
    );
    out.push_str(
        "</head>\n<body>\n<a class=\"skip-link\" href=\"#main-content\">Skip to main content</a>\n",
    );
    out.push_str("<header class=\"site-header\">\n<div class=\"header-inner\">\n<p class=\"brand\">homedrive</p>\n");
    if let Some(csrf) = &page.csrf {
        out.push_str("<nav class=\"nav-strip\" aria-label=\"Primary navigation\">\n");
        let admin = page.admin.then_some(&ADMIN_NAV);
        for (path, label, key) in NAV.iter().chain(admin) {
            let current = if *key == page.nav { " aria-current=\"page\"" } else { "" };
            let _ = writeln!(out, "<a href=\"{path}\"{current}>{label}</a>");
        }
        out.push_str(
            "</nav>\n<form class=\"header-actions\" method=\"POST\" action=\"/logout\">\n",
        );
        out.push_str(&csrf_field(csrf));
        out.push_str(
            "<button type=\"submit\" class=\"button button-secondary\">Log out</button>\n</form>\n",
        );
    }
    out.push_str("</div>\n</header>\n");
    let _ = writeln!(out, "<main id=\"main-content\" class=\"page{}\">", page.page_class);
    if !page.flashes.is_empty() {
        out.push_str(
            "<ul class=\"flash-list\" aria-live=\"polite\" aria-label=\"Action results\">\n",
        );
        for (tone, message) in &page.flashes {
            let _ = writeln!(out, "<li class=\"notice {}\">{}</li>", tone.class(), esc(message));
        }
        out.push_str("</ul>\n");
    }
    out.push_str(&page.body);
    out.push_str("\n</main>\n</body>\n</html>\n");
    out
}

pub fn csrf_field(token: &str) -> String {
    format!("<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">\n", esc(token))
}

/// A labelled text input. `kind` is the input type.
pub fn field(
    name: &str,
    label: &str,
    kind: &str,
    value: &str,
    help: &str,
    required: bool,
) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "<div class=\"field\">\n<label for=\"{n}\">{l}</label>\n<input type=\"{kind}\" id=\"{n}\" name=\"{n}\" value=\"{v}\"{r}>\n",
        n = esc(name),
        l = esc(label),
        v = esc(value),
        r = if required { " required" } else { "" },
    );
    if !help.is_empty() {
        let _ = writeln!(out, "<p class=\"field-help\">{}</p>", esc(help));
    }
    out.push_str("</div>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_markup_and_attributes() {
        assert_eq!(
            esc("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn navigation_appears_only_with_a_session() {
        let anonymous = render(&Page { title: "Log in".into(), ..Page::default() });
        assert!(!anonymous.contains("nav-strip"));
        let signed_in = render(&Page {
            title: "Files".into(),
            nav: "files",
            csrf: Some("tok".into()),
            flashes: vec![(Tone::Success, "<saved>".into())],
            ..Page::default()
        });
        assert!(signed_in.contains("<a href=\"/files\" aria-current=\"page\">Files</a>"));
        assert!(!signed_in.contains("/admin"));
        assert!(signed_in.contains("&lt;saved&gt;"));
        assert!(signed_in.contains("value=\"tok\""));
    }
}
