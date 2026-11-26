//! In-memory search of the unlocked vault (R-ITEM-3). Nothing is indexed on disk or sent anywhere.

use crate::item::{Content, Item};

/// Whether `item` matches every whitespace-separated term of `query` (case-insensitive) in its
/// title, username, URLs or tags. An empty query matches everything.
pub fn matches(item: &Item, query: &str) -> bool {
    let mut haystack = item.title.to_lowercase();
    for t in &item.tags {
        haystack.push('\n');
        haystack.push_str(&t.to_lowercase());
    }
    if let Content::Login(l) = &item.content {
        haystack.push('\n');
        haystack.push_str(&l.username.to_lowercase());
        for u in &l.urls {
            haystack.push('\n');
            haystack.push_str(&u.url.to_lowercase());
        }
    }
    query
        .split_whitespace()
        .all(|term| haystack.contains(&term.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{LoginFields, LoginUrl};

    #[test]
    fn matches_title_username_url_and_tags_but_not_secrets() {
        let mut i = Item::new(
            Content::Login(LoginFields {
                username: "alice".into(),
                password: "topsecret".into(),
                urls: vec![LoginUrl {
                    url: "https://GitHub.com".into(),
                    label: String::new(),
                }],
                ..Default::default()
            }),
            "Code host",
            "t",
            "d",
        );
        i.tags.push("work".into());
        for q in ["", "code", "ALICE", "github", "work code"] {
            assert!(matches(&i, q), "{q}");
        }
        for q in ["topsecret", "bob", "code bob"] {
            assert!(!matches(&i, q), "{q}");
        }
    }
}
