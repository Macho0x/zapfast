//! LINE account runtime: webhook listener, Messaging API calls, and commands.
//!
//! One account is one LINE Official Account (a bot). The Messaging API pushes
//! events to a webhook, so the window listens on 127.0.0.1 and the user
//! exposes that port over HTTPS; the channel access token and channel secret
//! live in the OS keyring. Messages are projected through [`super::project`]
//! and cached in [`super::store`], because the Messaging API offers no chat
//! list and no history.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::account::{AccountId, AuthState};
use crate::backend::{Command, Event, LoginStep, PageKey, Waker};
use crate::model::{ChatId, LastMessage, MediaState, Message};
use crate::paths::AppDirs;

use super::project::{self, Source};
use super::store::Store;

/// The first local webhook port. Each account gets its own port.
const WEBHOOK_BASE: u16 = 8460;

/// How long one Messaging API request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

struct Sink {
    events: std::sync::mpsc::Sender<Event>,
    waker: Waker,
}

impl Sink {
    fn send(&self, event: Event) {
        let _ = self.events.send(event);
        self.waker.wake();
    }
}

pub(crate) async fn run(
    dirs: AppDirs,
    account: AccountId,
    events: std::sync::mpsc::Sender<Event>,
    _commands_tx: mpsc::UnboundedSender<Command>,
    commands: mpsc::UnboundedReceiver<Command>,
    waker: Waker,
) {
    let sink = Sink { events, waker };
    if let Err(error) = serve(&dirs, account, &sink, commands).await {
        log::warn!("LINE stopped: {error}");
        sink.send(Event::Auth {
            account,
            state: AuthState::Failed {
                reason: error.to_string(),
            },
        });
    }
}

async fn serve(
    dirs: &AppDirs,
    account: AccountId,
    sink: &Sink,
    mut commands: mpsc::UnboundedReceiver<Command>,
) -> Result<()> {
    let store_path = dirs.account_dir(account).join("line").join("store.json");
    let mut store = Store::load(&store_path, account);
    let api = match authenticate_account(account, sink, &mut commands).await? {
        Some(api) => api,
        None => return Ok(()),
    };

    sink.send(Event::Me {
        id: api.id.clone(),
        lid: None,
        name: Some(api.name.clone()),
        about: None,
    });
    sink.send(Event::Chats(store.chats()));

    let port = webhook_port(account);
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| {
            format!("LINE needs the local webhook port {port}; another program may be using it")
        })?;
    let (webhook_tx, mut webhook_rx) = mpsc::unbounded_channel::<Vec<Value>>();
    tokio::spawn(webhook_loop(listener, api.secret.clone(), webhook_tx));

    let mut tokens: HashMap<ChatId, PageKey> = HashMap::new();
    let mut names: HashMap<String, String> = HashMap::new();
    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    None | Some(Command::Shutdown) => {
                        store.save(&store_path)?;
                        return Ok(());
                    }
                    Some(command) => {
                        handle_command(
                            &api,
                            &mut store,
                            &store_path,
                            sink,
                            &mut tokens,
                            dirs,
                            command,
                        )
                        .await?;
                    }
                }
            }
            events = webhook_rx.recv() => {
                let Some(events) = events else {
                    continue;
                };
                for event in &events {
                    if let Err(error) =
                        handle_event(&api, &mut store, &store_path, sink, &mut names, account, event)
                            .await
                    {
                        log::warn!("LINE event skipped: {error}");
                    }
                }
            }
        }
    }
}

/// The local webhook port, overridable with `ZAPFAST_LINE_WEBHOOK_PORT` when
/// the default range collides with something else.
fn webhook_port(account: AccountId) -> u16 {
    if let Ok(port) = std::env::var("ZAPFAST_LINE_WEBHOOK_PORT")
        && let Ok(port) = port.parse::<u16>()
    {
        return port;
    }
    WEBHOOK_BASE.saturating_add((account.get() % 1000) as u16)
}

async fn authenticate_account(
    account: AccountId,
    sink: &Sink,
    commands: &mut mpsc::UnboundedReceiver<Command>,
) -> Result<Option<Api>> {
    let identity = format!("line-{}", account.get());
    loop {
        match crate::secrets::load(&identity) {
            Ok(Some(stored)) => match serde_json::from_str::<Value>(&stored) {
                Ok(value) => {
                    let token = value
                        .get("token")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let secret = value
                        .get("secret")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    match Api::new(token, secret).await {
                        Ok(api) => {
                            sink.send(Event::Auth {
                                account,
                                state: AuthState::Ready,
                            });
                            return Ok(Some(api));
                        }
                        Err(error) => sink.send(Event::Auth {
                            account,
                            state: AuthState::Failed {
                                reason: error.to_string(),
                            },
                        }),
                    }
                }
                Err(error) => sink.send(Event::Auth {
                    account,
                    state: AuthState::Failed {
                        reason: format!("The stored LINE tokens could not be read: {error}"),
                    },
                }),
            },
            Ok(None) => sink.send(Event::Auth {
                account,
                state: AuthState::SignedOut,
            }),
            Err(error) => sink.send(Event::Auth {
                account,
                state: AuthState::Failed {
                    reason: error.to_string(),
                },
            }),
        }
        match commands.recv().await {
            None | Some(Command::Shutdown) => return Ok(None),
            Some(Command::Login {
                step: LoginStep::LineTokens { token, secret },
                ..
            }) => {
                let token = token.trim().to_owned();
                let secret = secret.trim().to_owned();
                match Api::new(token.clone(), secret.clone()).await {
                    Ok(api) => {
                        let stored = json!({ "token": token, "secret": secret }).to_string();
                        let _ = crate::secrets::save(&identity, &stored);
                        sink.send(Event::Auth {
                            account,
                            state: AuthState::Ready,
                        });
                        return Ok(Some(api));
                    }
                    Err(error) => sink.send(Event::Auth {
                        account,
                        state: AuthState::Failed {
                            reason: error.to_string(),
                        },
                    }),
                }
            }
            Some(_) => {}
        }
    }
}

struct Api {
    client: reqwest::Client,
    token: String,
    secret: String,
    id: String,
    name: String,
}

impl Api {
    async fn new(token: String, secret: String) -> Result<Self> {
        if token.is_empty() || secret.is_empty() {
            bail!("LINE needs both the channel access token and the channel secret");
        }
        let client = reqwest::Client::builder()
            .user_agent(concat!("ZapFast/", env!("CARGO_PKG_VERSION")))
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("Could not start the LINE HTTP client")?;
        let mut api = Self {
            client,
            token,
            secret,
            id: String::new(),
            name: String::new(),
        };
        let value = api.get("https://api.line.me/v2/bot/info").await?;
        api.id = value
            .get("userId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        api.name = value
            .get("displayName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if api.id.is_empty() {
            bail!("LINE did not say which bot this token belongs to");
        }
        Ok(api)
    }

    async fn get(&self, url: &str) -> Result<Value> {
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("LINE could not be reached")?;
        let status = response.status();
        if !status.is_success() {
            bail!("LINE refused the request with {status}");
        }
        response
            .json()
            .await
            .context("LINE answered with something other than JSON")
    }

    async fn get_raw(&self, url: &str) -> Result<reqwest::Response> {
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("LINE could not be reached for a download")?;
        let status = response.status();
        if !status.is_success() {
            bail!("LINE refused the download with {status}");
        }
        Ok(response)
    }

    async fn push(&self, to: &str, text: &str) -> Result<()> {
        let response = self
            .client
            .post("https://api.line.me/v2/bot/message/push")
            .bearer_auth(&self.token)
            .json(&json!({
                "to": to,
                "messages": [{ "type": "text", "text": text }],
            }))
            .send()
            .await
            .context("LINE could not be reached for a send")?;
        let status = response.status();
        if !status.is_success() {
            bail!("LINE refused the message with {status}");
        }
        Ok(())
    }

    /// A user's display name, from their profile or their membership.
    async fn member_name(&self, source: &Source, user_id: &str) -> Result<String> {
        let url = match source {
            Source::User(_) => format!("https://api.line.me/v2/bot/profile/{user_id}"),
            Source::Group(group) => {
                format!("https://api.line.me/v2/bot/group/{group}/member/{user_id}")
            }
            Source::Room(room) => {
                format!("https://api.line.me/v2/bot/room/{room}/member/{user_id}")
            }
        };
        let value = self.get(&url).await?;
        value
            .get("displayName")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .context("LINE did not name that member")
    }

    /// The name of a chat row, before any message arrives.
    async fn chat_name(&self, source: &Source) -> Result<String> {
        match source {
            Source::User(user) => {
                let value = self
                    .get(&format!("https://api.line.me/v2/bot/profile/{user}"))
                    .await?;
                value
                    .get("displayName")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .context("LINE did not name that user")
            }
            Source::Group(group) => {
                let value = self
                    .get(&format!("https://api.line.me/v2/bot/group/{group}/summary"))
                    .await?;
                value
                    .get("groupName")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .context("LINE did not name that group")
            }
            Source::Room(room) => {
                let value = self
                    .get(&format!("https://api.line.me/v2/bot/room/{room}/summary"))
                    .await?;
                value
                    .get("roomName")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .context("LINE did not name that room")
            }
        }
    }
}

/// Creates the chat row for a source if this window has not seen it yet.
async fn ensure_chat(
    api: &Api,
    store: &mut Store,
    sink: &Sink,
    account: AccountId,
    source: &Source,
) -> ChatId {
    let chat = project::chat_id(account, source);
    if store.chat(&chat).is_none() {
        let name = match api.chat_name(source).await {
            Ok(name) => name,
            Err(error) => {
                log::warn!("A LINE chat row keeps its id as a name: {error}");
                default_name(source)
            }
        };
        store.upsert_chat(project::chat(account, source, name));
        sink.send(Event::Chats(store.chats()));
    }
    chat
}

fn default_name(source: &Source) -> String {
    match source {
        Source::User(_) => "LINE user".to_owned(),
        Source::Group(_) => "LINE group".to_owned(),
        Source::Room(_) => "LINE room".to_owned(),
    }
}

fn last_of(message: &Message) -> LastMessage {
    let summary = message.content.summary();
    let full = match &message.content {
        crate::model::Content::Text { text, .. } => text.clone(),
        _ => summary.clone(),
    };
    LastMessage {
        from_me: message.from_me,
        sender: message.sender.clone(),
        sender_name: message.sender_name.clone(),
        summary,
        full,
        status: message.status,
    }
}

/// Stores a message, updates its chat row, and tells the window about both.
fn record(
    store: &mut Store,
    store_path: &Path,
    sink: &Sink,
    chat: &ChatId,
    message: Message,
) -> Result<()> {
    if let Some(mut row) = store.chat(chat) {
        row.last_activity = message.timestamp;
        row.last = Some(last_of(&message));
        store.upsert_chat(row.clone());
        sink.send(Event::ChatUpdated(Box::new(row)));
    }
    store.add_message(message.clone());
    store.save(store_path)?;
    sink.send(Event::Incoming {
        chat: chat.clone(),
        message: Box::new(message),
    });
    Ok(())
}

async fn handle_event(
    api: &Api,
    store: &mut Store,
    store_path: &Path,
    sink: &Sink,
    names: &mut HashMap<String, String>,
    account: AccountId,
    event: &Value,
) -> Result<()> {
    let kind = event
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if kind != "message" && kind != "follow" && kind != "join" {
        return Ok(());
    }
    let Some(source) = project::event_source(event) else {
        return Ok(());
    };
    let chat = ensure_chat(api, store, sink, account, &source).await;
    if kind != "message" {
        return Ok(());
    }
    let sender_name = match event
        .get("source")
        .and_then(|source| source.get("userId"))
        .and_then(Value::as_str)
    {
        Some(user) => match names.get(user) {
            Some(name) => Some(name.clone()),
            None => match api.member_name(&source, user).await {
                Ok(name) => {
                    names.insert(user.to_owned(), name.clone());
                    Some(name)
                }
                Err(error) => {
                    log::warn!("A LINE sender is shown by id: {error}");
                    None
                }
            },
        },
        None => None,
    };
    let Some(message) = project::message(&chat, event, sender_name) else {
        return Ok(());
    };
    record(store, store_path, sink, &chat, message)
}

async fn handle_command(
    api: &Api,
    store: &mut Store,
    store_path: &Path,
    sink: &Sink,
    tokens: &mut HashMap<ChatId, PageKey>,
    dirs: &AppDirs,
    command: Command,
) -> Result<()> {
    match command {
        Command::SendText { chat, text, .. } => {
            let Some(source) = project::parse_chat(&chat) else {
                return Ok(());
            };
            api.push(source.id(), &text).await?;
            record(store, store_path, sink, &chat, project::echo(&chat, text))?;
        }
        Command::LoadChat { chat, before } => {
            page(store, sink, &chat, before, tokens);
        }
        Command::FetchOlder(chat) => {
            let before = tokens.get(&chat).cloned();
            page(store, sink, &chat, before, tokens);
        }
        Command::Download { chat, message, .. } => {
            download(api, store, store_path, sink, dirs, &chat, &message).await?;
        }
        // LINE bots see no typing, receipts, edits, or deletions through this
        // API, and media sends need a public HTTPS URL this window does not
        // have.
        _ => {}
    }
    Ok(())
}

fn page(
    store: &Store,
    sink: &Sink,
    chat: &ChatId,
    before: Option<PageKey>,
    tokens: &mut HashMap<ChatId, PageKey>,
) {
    let older = before.is_some();
    let (messages, complete) = store.page(chat, before);
    if let Some(oldest) = messages.first() {
        tokens.insert(chat.clone(), (oldest.timestamp, oldest.id.clone()));
    }
    sink.send(Event::Messages {
        chat: chat.clone(),
        messages,
        older,
        complete,
    });
}

async fn download(
    api: &Api,
    store: &mut Store,
    store_path: &Path,
    sink: &Sink,
    dirs: &AppDirs,
    chat: &ChatId,
    message_id: &str,
) -> Result<()> {
    let Some(stored) = store.message(chat, message_id).cloned() else {
        return Ok(());
    };
    if stored.content.media().is_none() {
        return Ok(());
    }
    let path = dirs.media_cache_dir().join(format!(
        "line-{}-{}",
        chat.account().get(),
        safe_name(message_id)
    ));
    let result = fetch_content(api, message_id, &path).await;
    let mut updated = stored;
    if let Some(media) = updated.content.media_mut() {
        match &result {
            Ok(mime) => {
                if let Some(mime) = mime {
                    media.mime = mime.clone();
                }
                media.path = Some(path);
                media.state = MediaState::Idle;
            }
            Err(error) => media.state = MediaState::Failed(error.to_string()),
        }
    }
    store.add_message(updated.clone());
    store.save(store_path)?;
    sink.send(Event::MessageUpdated(Box::new(updated)));
    result.map(|_| ())
}

/// Downloads a message's content and returns the MIME type LINE sent with it.
async fn fetch_content(api: &Api, message_id: &str, path: &Path) -> Result<Option<String>> {
    let url = format!("https://api-data.line.me/v2/bot/message/{message_id}/content");
    let response = api.get_raw(&url).await?;
    let mime = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = response
        .bytes()
        .await
        .context("LINE closed the download early")?;
    std::fs::write(path, &bytes).with_context(|| format!("Could not save {}", path.display()))?;
    Ok(mime)
}

fn safe_name(id: &str) -> String {
    id.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

async fn webhook_loop(
    listener: TcpListener,
    secret: String,
    sender: mpsc::UnboundedSender<Vec<Value>>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let secret = secret.clone();
        let sender = sender.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_webhook(stream, &secret, &sender).await {
                log::warn!("LINE webhook ignored: {error}");
            }
        });
    }
}

async fn handle_webhook(
    mut stream: TcpStream,
    secret: &str,
    sender: &mpsc::UnboundedSender<Vec<Value>>,
) -> Result<()> {
    let (headers, body) = read_request(&mut stream).await?;
    let signature = header_value(&headers, "x-line-signature")
        .unwrap_or_default()
        .to_owned();
    if !project::signature(secret, &body, &signature) {
        let _ = stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        bail!("the signature did not match");
    }
    let _ = stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
    let _ = stream.shutdown().await;
    let value: Value = serde_json::from_slice(&body).context("the webhook body was not JSON")?;
    let events = value
        .get("events")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !events.is_empty() {
        let _ = sender.send(events);
    }
    Ok(())
}

/// Reads one HTTP request and returns its headers and body. LINE sends a small
/// JSON body; anything oversized is refused.
async fn read_request(stream: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = stream
            .read(&mut chunk)
            .await
            .context("The webhook connection dropped")?;
        if read == 0 {
            bail!("the webhook connection closed before its headers");
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find(&buffer, b"\r\n\r\n") {
            break position + 4;
        }
        if buffer.len() > 64 * 1024 {
            bail!("the webhook headers were too large");
        }
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let length = header_value(&headers, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if length > 1024 * 1024 {
        bail!("the webhook body was too large");
    }
    while buffer.len() < header_end + length {
        let read = stream
            .read(&mut chunk)
            .await
            .context("The webhook connection dropped")?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let end = buffer.len().min(header_end + length);
    let body = buffer[header_end.min(end)..end].to_vec();
    Ok((headers, body))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Delivery;

    #[test]
    fn a_port_is_chosen_per_account_and_can_be_overridden() {
        assert_eq!(webhook_port(AccountId(1)), WEBHOOK_BASE + 1);
        assert_eq!(webhook_port(AccountId(1001)), WEBHOOK_BASE + 1);
    }

    #[test]
    fn header_lookup_ignores_case_and_spacing() {
        let headers =
            "POST /callback HTTP/1.1\r\nX-Line-Signature: abc\r\nContent-Length: 2\r\n\r\n";
        assert_eq!(header_value(headers, "x-line-signature"), Some("abc"));
        assert_eq!(header_value(headers, "content-length"), Some("2"));
        assert_eq!(header_value(headers, "missing"), None);
    }

    #[test]
    fn safe_names_keep_only_plain_characters() {
        assert_eq!(safe_name("id/with:odd*chars"), "id_with_odd_chars");
    }

    #[test]
    fn last_messages_carry_their_text() {
        let message = project::echo(&ChatId::new(AccountId(1), "u1"), "hello".to_owned());
        let last = last_of(&message);
        assert!(last.from_me);
        assert_eq!(last.full, "hello");
        assert_eq!(last.summary, "hello");
        assert_eq!(last.status, Delivery::Sent);
    }
}
