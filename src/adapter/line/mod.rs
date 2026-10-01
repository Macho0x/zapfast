//! LINE accounts: an Official Account (a bot) over the Messaging API.
//!
//! The Messaging API has no socket and no chat list: the window listens on a
//! local webhook port that the user exposes over HTTPS, and the chats and
//! messages it has seen are cached under the account directory. Only the bot
//! side of LINE is supported; personal accounts would need a protocol this
//! project does not implement.

pub mod project;
mod runtime;
mod store;
pub(crate) use runtime::run;
