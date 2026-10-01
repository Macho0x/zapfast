//! The local LINE cache. The Messaging API has no chat-list endpoint and no
//! history endpoint, so the window keeps the chats it has seen and their
//! messages under the account directory.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{Chat, ChatId, ChatKind, Delivery, LastMessage, Message};

/// Messages kept per chat. Older ones fall out of the cache.
pub const KEEP: usize = 500;

/// Messages in one page.
pub const PAGE: usize = 50;

/// A chat row as the cache keeps it. The shared [`Chat`] model carries live
/// view state and is not serializable, so the cache stores what it needs.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredChat {
    pub id: ChatId,
    pub name: String,
    pub kind: ChatKind,
    pub unread: u32,
    pub last_activity: i64,
    pub last: Option<StoredLast>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredLast {
    pub from_me: bool,
    pub sender: String,
    pub sender_name: Option<String>,
    pub summary: String,
    pub full: String,
    pub status: Delivery,
}

impl StoredChat {
    pub fn of(chat: &Chat) -> Self {
        Self {
            id: chat.id.clone(),
            name: chat.name.clone(),
            kind: chat.kind,
            unread: chat.unread,
            last_activity: chat.last_activity,
            last: chat.last.as_ref().map(StoredLast::of),
        }
    }

    pub fn chat(&self) -> Chat {
        let mut chat = Chat::new(self.id.clone(), self.name.clone());
        chat.kind = self.kind;
        chat.unread = self.unread;
        chat.last_activity = self.last_activity;
        chat.last = self.last.as_ref().map(StoredLast::last);
        chat
    }
}

impl StoredLast {
    fn of(last: &LastMessage) -> Self {
        Self {
            from_me: last.from_me,
            sender: last.sender.clone(),
            sender_name: last.sender_name.clone(),
            summary: last.summary.clone(),
            full: last.full.clone(),
            status: last.status,
        }
    }

    fn last(&self) -> LastMessage {
        LastMessage {
            from_me: self.from_me,
            sender: self.sender.clone(),
            sender_name: self.sender_name.clone(),
            summary: self.summary.clone(),
            full: self.full.clone(),
            status: self.status,
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct Store {
    pub chats: Vec<StoredChat>,
    pub messages: Vec<Message>,
}

impl Store {
    /// Reads the cache, treating a missing or unreadable file as empty. The
    /// stored ids are stamped with the account that owns the cache, because
    /// chat ids persist as bare peer strings.
    pub fn load(path: &Path, account: crate::account::AccountId) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        match serde_json::from_str::<Self>(&text) {
            Ok(mut store) => {
                store.stamp(account);
                store
            }
            Err(error) => {
                log::warn!("The LINE cache could not be read: {error}");
                Self::default()
            }
        }
    }

    fn stamp(&mut self, account: crate::account::AccountId) {
        for chat in &mut self.chats {
            chat.id = ChatId::new(account, chat.id.peer().to_owned());
        }
        for message in &mut self.messages {
            message.chat = ChatId::new(account, message.chat.peer().to_owned());
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            crate::paths::create_private_dir(parent)?;
        }
        let text = serde_json::to_string_pretty(self).context("Could not encode the LINE cache")?;
        std::fs::write(path, text).with_context(|| format!("Could not write {}", path.display()))
    }

    /// The chat rows, ready for the window.
    pub fn chats(&self) -> Vec<Chat> {
        self.chats.iter().map(StoredChat::chat).collect()
    }

    pub fn chat(&self, id: &ChatId) -> Option<Chat> {
        self.chats
            .iter()
            .find(|chat| &chat.id == id)
            .map(StoredChat::chat)
    }

    pub fn upsert_chat(&mut self, chat: Chat) {
        let chat = StoredChat::of(&chat);
        match self.chats.iter_mut().find(|row| row.id == chat.id) {
            Some(row) => *row = chat,
            None => self.chats.push(chat),
        }
    }

    pub fn message(&self, chat: &ChatId, id: &str) -> Option<&Message> {
        self.messages
            .iter()
            .find(|message| &message.chat == chat && message.id == id)
    }

    /// Adds a message, replacing any copy with the same id, and drops the
    /// oldest ones beyond [`KEEP`].
    pub fn add_message(&mut self, message: Message) {
        let chat = message.chat.clone();
        match self
            .messages
            .iter_mut()
            .find(|existing| existing.chat == chat && existing.id == message.id)
        {
            Some(existing) => *existing = message,
            None => self.messages.push(message),
        }
        self.trim(&chat);
    }

    fn trim(&mut self, chat: &ChatId) {
        let mut indices: Vec<usize> = self
            .messages
            .iter()
            .enumerate()
            .filter(|(_, message)| &message.chat == chat)
            .map(|(index, _)| index)
            .collect();
        if indices.len() <= KEEP {
            return;
        }
        indices.sort_by_key(|&index| {
            (
                self.messages[index].timestamp,
                self.messages[index].id.clone(),
            )
        });
        let mut oldest: Vec<usize> = indices[..indices.len() - KEEP].to_vec();
        oldest.sort_unstable_by(|a, b| b.cmp(a));
        for index in oldest {
            self.messages.remove(index);
        }
    }

    /// One page of a chat's cached messages, oldest first. `before` is the key
    /// of the oldest message already shown. `complete` means no older cached
    /// message remains.
    pub fn page(&self, chat: &ChatId, before: Option<(i64, String)>) -> (Vec<Message>, bool) {
        let mut rows: Vec<&Message> = self
            .messages
            .iter()
            .filter(|message| &message.chat == chat)
            .filter(|message| match &before {
                Some((timestamp, id)) => {
                    message.timestamp < *timestamp
                        || (message.timestamp == *timestamp && &message.id < id)
                }
                None => true,
            })
            .collect();
        rows.sort_by(|a, b| (a.timestamp, &a.id).cmp(&(b.timestamp, &b.id)));
        let older = rows.len() > PAGE;
        let start = rows.len().saturating_sub(PAGE);
        let page: Vec<Message> = rows[start..]
            .iter()
            .map(|message| (*message).clone())
            .collect();
        (page, !older)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Content;

    fn account() -> crate::account::AccountId {
        crate::account::AccountId(7)
    }

    fn chat() -> ChatId {
        crate::adapter::line::project::chat_id(
            account(),
            &crate::adapter::line::project::Source::User("U1".to_owned()),
        )
    }

    fn message(id: &str, timestamp: i64) -> Message {
        Message {
            id: id.to_owned(),
            chat: chat(),
            sender: "U1".to_owned(),
            sender_name: Some("Ada".to_owned()),
            from_me: false,
            timestamp,
            content: Content::Text {
                text: format!("message {id}"),
                preview: None,
            },
            status: Delivery::None,
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

    #[test]
    fn the_cache_round_trips_through_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("line/store.json");
        let mut store = Store::default();
        store.upsert_chat(crate::adapter::line::project::chat(
            account(),
            &crate::adapter::line::project::Source::User("U1".to_owned()),
            "Ada".to_owned(),
        ));
        store.add_message(message("1", 10));
        store.save(&path).unwrap();
        let reopened = Store::load(&path, account());
        assert_eq!(reopened.chats().len(), 1);
        assert_eq!(reopened.chat(&chat()).unwrap().name, "Ada");
        assert_eq!(reopened.messages.len(), 1);
        assert_eq!(reopened.messages[0].id, "1");
    }

    #[test]
    fn a_missing_cache_is_empty() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::load(&directory.path().join("nope.json"), account());
        assert!(store.chats().is_empty());
        assert!(store.messages.is_empty());
    }

    #[test]
    fn a_repeated_id_replaces_its_message() {
        let mut store = Store::default();
        store.add_message(message("1", 10));
        let mut updated = message("1", 10);
        updated.content = Content::Text {
            text: "edited".to_owned(),
            preview: None,
        };
        store.add_message(updated);
        assert_eq!(store.messages.len(), 1);
        match &store.messages[0].content {
            Content::Text { text, .. } => assert_eq!(text, "edited"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn only_the_newest_messages_are_kept() {
        let mut store = Store::default();
        for index in 0..(KEEP + 10) {
            store.add_message(message(&index.to_string(), index as i64));
        }
        assert_eq!(store.messages.len(), KEEP);
        assert_eq!(store.messages[0].id, "10");
    }

    #[test]
    fn pages_walk_backwards_through_the_cache() {
        let mut store = Store::default();
        for index in 0..(PAGE + 5) {
            store.add_message(message(&index.to_string(), index as i64));
        }
        let (newest, complete) = store.page(&chat(), None);
        assert_eq!(newest.len(), PAGE);
        assert!(!complete);
        assert_eq!(newest[0].id, "5");
        assert_eq!(newest[PAGE - 1].id, (PAGE + 4).to_string());
        let oldest = newest.first().unwrap();
        let (older, complete) = store.page(&chat(), Some((oldest.timestamp, oldest.id.clone())));
        assert_eq!(older.len(), 5);
        assert!(complete);
        assert_eq!(older[0].id, "0");
    }
}
