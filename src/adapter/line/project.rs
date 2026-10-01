//! Projection from LINE Messaging API webhook events into the shared models.

use std::sync::atomic::{AtomicU64, Ordering};

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::account::{
    AccountId, CallAccess, Capabilities, GifSource, ReactionStyle, StickerAccess,
};
use crate::model::{Chat, ChatId, ChatKind, Content, Delivery, Media, MediaState, Message};

/// Where a LINE conversation lives: a one-to-one user, a group, or a room.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    User(String),
    Group(String),
    Room(String),
}

impl Source {
    fn prefix(&self) -> char {
        match self {
            Self::User(_) => 'u',
            Self::Group(_) => 'g',
            Self::Room(_) => 'r',
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::User(id) | Self::Group(id) | Self::Room(id) => id,
        }
    }
}

pub fn chat_id(account: AccountId, source: &Source) -> ChatId {
    ChatId::new(account, format!("{}{}", source.prefix(), source.id()))
}

pub fn parse_chat(chat: &ChatId) -> Option<Source> {
    let mut characters = chat.peer().chars();
    let prefix = characters.next()?;
    let id = characters.as_str();
    if id.is_empty() {
        return None;
    }
    match prefix {
        'u' => Some(Source::User(id.to_owned())),
        'g' => Some(Source::Group(id.to_owned())),
        'r' => Some(Source::Room(id.to_owned())),
        _ => None,
    }
}

/// What a LINE Official Account can do in this window.
pub fn capabilities() -> Capabilities {
    Capabilities {
        text: true,
        // Sending media needs a public HTTPS URL, which this window does not
        // have.
        files: false,
        voice_notes: false,
        video_notes: false,
        custom_emoji: false,
        reactions: ReactionStyle::None,
        gif: GifSource::None,
        stickers: StickerAccess::None,
        threads: false,
        spaces: false,
        typing: false,
        read_receipts: false,
        edit: false,
        delete_for_everyone: false,
        polls: false,
        calls: CallAccess::None,
    }
}

/// Where an incoming event came from.
pub fn event_source(event: &Value) -> Option<Source> {
    let source = event.get("source")?;
    if let Some(id) = source.get("userId").and_then(Value::as_str) {
        return Some(Source::User(id.to_owned()));
    }
    if let Some(id) = source.get("groupId").and_then(Value::as_str) {
        return Some(Source::Group(id.to_owned()));
    }
    if let Some(id) = source.get("roomId").and_then(Value::as_str) {
        return Some(Source::Room(id.to_owned()));
    }
    None
}

/// The event's own timestamp in milliseconds.
pub fn event_timestamp(event: &Value) -> i64 {
    event.get("timestamp").and_then(Value::as_i64).unwrap_or(0)
}

/// A chat row for a source, before any message arrives.
pub fn chat(account: AccountId, source: &Source, name: String) -> Chat {
    let mut chat = Chat::new(chat_id(account, source), name);
    chat.kind = match source {
        Source::User(_) => ChatKind::Direct,
        Source::Group(_) | Source::Room(_) => ChatKind::Group,
    };
    chat
}

/// A message event projected into a message, or `None` when the event carries
/// nothing this window can show.
pub fn message(chat: &ChatId, event: &Value, sender_name: Option<String>) -> Option<Message> {
    if event.get("type").and_then(Value::as_str) != Some("message") {
        return None;
    }
    let raw = event.get("message")?;
    let id = raw.get("id").and_then(Value::as_str)?.to_owned();
    let kind = raw.get("type").and_then(Value::as_str)?;
    let content = match kind {
        "text" => Content::Text {
            text: raw
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            preview: None,
        },
        "image" => Content::Image {
            caption: None,
            media: media(),
        },
        "video" => Content::Video {
            caption: None,
            media: media(),
            seconds: None,
            gif: false,
            note: false,
        },
        "audio" => Content::Audio {
            media: media(),
            seconds: None,
            voice_note: false,
            waveform: Vec::new(),
        },
        "file" => Content::Document {
            media: media(),
            file_name: raw
                .get("fileName")
                .and_then(Value::as_str)
                .unwrap_or("file")
                .to_owned(),
            caption: None,
            pages: None,
        },
        other => Content::Unsupported {
            what: capitalize(other),
        },
    };
    Some(Message {
        id,
        chat: chat.clone(),
        sender: String::new(),
        sender_name,
        from_me: false,
        timestamp: event_timestamp(event) / 1000,
        content,
        status: Delivery::None,
        delivered_at: None,
        read_at: None,
        quoted: None,
        reactions: Vec::new(),
        edited: false,
        mentions: Vec::new(),
        forwarded: false,
        thumbnail: None,
    })
}

fn media() -> Media {
    Media {
        mime: "application/octet-stream".to_owned(),
        size: 0,
        width: None,
        height: None,
        path: None,
        state: MediaState::Idle,
    }
}

fn capitalize(value: &str) -> String {
    let mut characters = value.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().collect::<String>() + characters.as_str(),
        None => "Message".to_owned(),
    }
}

/// A locally composed message for a send this window made. LINE does not echo
/// the bot's own messages back through the webhook, so the window shows it
/// from here.
pub fn echo(chat: &ChatId, text: String) -> Message {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let now = jiff::Timestamp::now().as_millisecond();
    let id = format!("local-{now}-{}", COUNTER.fetch_add(1, Ordering::Relaxed));
    Message {
        id,
        chat: chat.clone(),
        sender: String::new(),
        sender_name: None,
        from_me: true,
        timestamp: now / 1000,
        content: Content::Text {
            text,
            preview: None,
        },
        status: Delivery::Sent,
        delivered_at: None,
        read_at: None,
        quoted: None,
        reactions: Vec::new(),
        edited: false,
        mentions: Vec::new(),
        forwarded: false,
        thumbnail: None,
    }
}

/// Whether a webhook body matches the `X-Line-Signature` header it arrived
/// with.
pub fn signature(secret: &str, body: &[u8], header: &str) -> bool {
    use base64::Engine;
    let Ok(signature) = base64::engine::general_purpose::STANDARD.decode(header) else {
        return false;
    };
    let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> AccountId {
        AccountId(7)
    }

    fn sign(secret: &str, body: &[u8]) -> String {
        use base64::Engine;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    }

    #[test]
    fn chats_round_trip_through_their_peer_form() {
        for source in [
            Source::User("U123".to_owned()),
            Source::Group("C456".to_owned()),
            Source::Room("R789".to_owned()),
        ] {
            let chat = chat_id(account(), &source);
            assert_eq!(parse_chat(&chat), Some(source));
        }
        assert_eq!(parse_chat(&ChatId::whatsapp("U123")), None);
        assert_eq!(parse_chat(&ChatId::new(account(), "u")), None);
        assert_eq!(parse_chat(&ChatId::new(account(), "x123")), None);
    }

    #[test]
    fn capabilities_are_honest() {
        let capabilities = capabilities();
        assert!(capabilities.text);
        assert!(!capabilities.files);
        assert!(!capabilities.voice_notes);
        assert!(!capabilities.typing);
        assert!(!capabilities.edit);
        assert!(!capabilities.delete_for_everyone);
        assert_eq!(capabilities.reactions, ReactionStyle::None);
        assert_eq!(capabilities.calls, CallAccess::None);
    }

    #[test]
    fn text_events_project_into_messages() {
        let event = serde_json::json!({
            "type": "message",
            "timestamp": 1_700_000_000_000i64,
            "source": { "type": "user", "userId": "U123" },
            "message": { "type": "text", "id": "42", "text": "hello" },
        });
        let chat = chat_id(account(), &Source::User("U123".to_owned()));
        let message = message(&chat, &event, Some("Ada".to_owned())).unwrap();
        assert_eq!(message.id, "42");
        assert_eq!(message.chat, chat);
        assert_eq!(message.timestamp, 1_700_000_000);
        assert_eq!(message.sender_name.as_deref(), Some("Ada"));
        assert!(!message.from_me);
        assert_eq!(
            message.content,
            Content::Text {
                text: "hello".to_owned(),
                preview: None,
            }
        );
    }

    #[test]
    fn media_events_keep_their_kind_and_file_name() {
        let chat = chat_id(account(), &Source::Group("C1".to_owned()));
        let image = serde_json::json!({
            "type": "message",
            "timestamp": 10,
            "message": { "type": "image", "id": "1" },
        });
        assert!(matches!(
            message(&chat, &image, None).unwrap().content,
            Content::Image { .. }
        ));
        let file = serde_json::json!({
            "type": "message",
            "timestamp": 10,
            "message": { "type": "file", "id": "2", "fileName": "plans.pdf" },
        });
        match message(&chat, &file, None).unwrap().content {
            Content::Document { file_name, .. } => assert_eq!(file_name, "plans.pdf"),
            other => panic!("expected a document, got {other:?}"),
        }
    }

    #[test]
    fn events_this_window_cannot_show_are_marked_unsupported() {
        let chat = chat_id(account(), &Source::User("U1".to_owned()));
        let sticker = serde_json::json!({
            "type": "message",
            "timestamp": 10,
            "message": { "type": "sticker", "id": "3", "packageId": "1", "stickerId": "2" },
        });
        assert_eq!(
            message(&chat, &sticker, None).unwrap().content,
            Content::Unsupported {
                what: "Sticker".to_owned(),
            }
        );
        let follow = serde_json::json!({ "type": "follow", "timestamp": 10 });
        assert!(message(&chat, &follow, None).is_none());
    }

    #[test]
    fn events_name_their_source_and_time() {
        let event = serde_json::json!({
            "type": "message",
            "timestamp": 1234,
            "source": { "type": "group", "groupId": "C9" },
            "message": { "type": "text", "id": "1", "text": "hi" },
        });
        assert_eq!(event_source(&event), Some(Source::Group("C9".to_owned())));
        assert_eq!(event_timestamp(&event), 1234);
        let nameless = serde_json::json!({ "type": "message" });
        assert_eq!(event_source(&nameless), None);
        assert_eq!(event_timestamp(&nameless), 0);
    }

    #[test]
    fn a_signature_matches_its_body_and_secret() {
        let body = br#"{"events":[]}"#;
        let header = sign("s3cret", body);
        assert!(signature("s3cret", body, &header));
        assert!(!signature("other", body, &header));
        assert!(!signature("s3cret", b"another body", &header));
        assert!(!signature("s3cret", body, "not base64"));
    }

    #[test]
    fn echoes_are_ours_and_sent() {
        let chat = chat_id(account(), &Source::User("U1".to_owned()));
        let message = echo(&chat, "on my way".to_owned());
        assert!(message.from_me);
        assert_eq!(message.status, Delivery::Sent);
        assert!(message.id.starts_with("local-"));
        assert_eq!(message.chat, chat);
    }
}
