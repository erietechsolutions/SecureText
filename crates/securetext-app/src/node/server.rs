//! Server settings: custom roles with permissions, categories, channel
//! layout, names, topics and the server icon (Discord-style).
//!
//! # How the settings stay consistent without a server
//!
//! A server's settings are a set of independent fields, each stored with a
//! stamp (Lamport clock, author key):
//!
//! | key | value |
//! |---|---|
//! | `server/name`, `server/icon` | string |
//! | `role/<id>` | [`Role`] (`role/everyone` is the default role) |
//! | `member/<identity key hex>` | the member's role ids |
//! | `category/<id>` | [`Category`] |
//! | `channel/<group id hex>` | [`ChannelMeta`] (name, topic, category, position) |
//!
//! Changes travel as `Payload::ServerEdit` MLS messages in the server's
//! group, so only members see them and MLS authenticates the author.
//! Every receiver checks each edit against the author's permissions in its
//! own copy of the settings. Then, per field, the higher stamp wins. Two
//! members editing at once end up with the same result everywhere,
//! whatever order the edits arrive in.
//!
//! # Ownership and permissions
//!
//! The owner is the server's creator: the member in the MLS group's first
//! slot (leaf 0), which a newcomer can check for itself. The owner can do
//! everything and can't be removed. Everyone else gets the permissions of
//! the default role plus the roles they're given. As in Discord:
//! - you can only edit or assign roles positioned below your own highest
//!   role;
//! - you can't give a role permissions you don't have;
//! - you can only remove members whose highest role is below yours.
//!
//! These rules are enforced by every honest client. MLS itself can't stop
//! a member with a modified client from committing a membership change it
//! wasn't entitled to, so such changes are flagged to everyone
//! (`Event::Warning`).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::{NodeState, MAX_NAME_CHARS};
use crate::wire::{self, to_hex, ConversationKind, Edit, Payload, StampedEdit};
use crate::Event;

pub mod perms {
    /// Everything, including managing roles above the default ones.
    pub const ADMINISTRATOR: u32 = 1 << 0;
    /// Rename the server, change its icon.
    pub const MANAGE_SERVER: u32 = 1 << 1;
    /// Create, edit, delete and assign roles (below your own).
    pub const MANAGE_ROLES: u32 = 1 << 2;
    /// Create channels and categories, rename, set topics, move channels,
    /// set channel disappearing-message timers.
    pub const MANAGE_CHANNELS: u32 = 1 << 3;
    /// Remove members (whose highest role is below yours).
    pub const KICK_MEMBERS: u32 = 1 << 4;
    /// Invite contacts into the server.
    pub const INVITE_MEMBERS: u32 = 1 << 5;
    /// Every server-level permission (what roles hold).
    pub const ALL: u32 = (1 << 6) - 1;

    // Channel permissions. Everyone has these by default; channel and
    // category rules (overwrites) take them away or give them back.
    /// See the channel at all. This one is enforced by encryption: it
    /// decides who is in the channel's MLS group.
    pub const VIEW_CHANNEL: u32 = 1 << 6;
    pub const SEND_MESSAGES: u32 = 1 << 7;
    pub const ATTACH_FILES: u32 = 1 << 8;
    pub const ADD_REACTIONS: u32 = 1 << 9;
    /// Start and join calls in the channel.
    pub const CONNECT: u32 = 1 << 10;
    pub const CHANNEL_ALL: u32 = VIEW_CHANNEL | SEND_MESSAGES | ATTACH_FILES | ADD_REACTIONS | CONNECT;
    /// What a channel or category rule may allow or deny.
    pub const OVERWRITABLE: u32 = CHANNEL_ALL | MANAGE_CHANNELS;
}

/// A channel or category rule for one target: `everyone`, `role:<id>`,
/// or `member:<identity key hex>`. Bits in `deny` are taken away, bits in
/// `allow` given (see `State::channel_permissions` for the order).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Overwrite {
    pub target: String,
    #[serde(default)]
    pub allow: u32,
    #[serde(default)]
    pub deny: u32,
}

pub const EVERYONE: &str = "everyone";
const MAX_ROLES: usize = 100;
const MAX_CATEGORIES: usize = 50;
const MAX_TOPIC_CHARS: usize = 256;
const MAX_EDITS: usize = 200;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    pub id: String,
    pub name: String,
    /// `#rrggbb`.
    pub color: String,
    pub permissions: u32,
    /// Higher is more senior. The default role is always 0.
    pub position: i64,
    /// Members with this as their highest hoisted role are listed under it.
    #[serde(default)]
    pub hoist: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub position: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelMeta {
    /// A rename; `None` keeps the name it was created with.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub topic: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub position: i64,
}

/// A server's settings as the UI sees them.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ServerSettings {
    pub server_id: String,
    pub name: String,
    pub icon_color: Option<String>,
    pub owner_key: String,
    /// Most senior first; the default role last.
    pub roles: Vec<Role>,
    /// Member identity key (hex) to role ids.
    pub member_roles: BTreeMap<String, Vec<String>>,
    pub categories: Vec<Category>,
    /// Channel id (hex) to its layout.
    pub channels: BTreeMap<String, ChannelMeta>,
    /// Our own effective permissions here.
    pub my_permissions: u32,
    /// Our own highest role position (the owner ranks above every role).
    pub my_rank: i64,
    /// Channel id (hex) to its own permission rules.
    pub channel_rules: BTreeMap<String, Vec<Overwrite>>,
    /// Category id to its permission rules (they apply to its channels).
    pub category_rules: BTreeMap<String, Vec<Overwrite>>,
}

/// The parsed settings of one server.
#[derive(Clone, Debug, Default)]
pub(crate) struct State {
    name: Option<String>,
    icon: Option<String>,
    roles: HashMap<String, Role>,
    members: HashMap<String, Vec<String>>,
    categories: HashMap<String, Category>,
    channels: HashMap<String, ChannelMeta>,
    channel_rules: HashMap<String, Vec<Overwrite>>,
    category_rules: HashMap<String, Vec<Overwrite>>,
    max_lamport: u64,
}

fn default_everyone() -> Role {
    Role {
        id: EVERYONE.into(),
        name: "@everyone".into(),
        color: "#99aab5".into(),
        permissions: 0,
        position: 0,
        hoist: false,
    }
}

impl State {
    fn from_edits(edits: &[StampedEdit]) -> Self {
        let mut s = State::default();
        for e in edits {
            s.max_lamport = s.max_lamport.max(e.lamport);
            s.set(&e.key, e.value.as_ref());
        }
        s
    }

    fn set(&mut self, key: &str, value: Option<&serde_json::Value>) {
        fn parse<T: serde::de::DeserializeOwned>(v: Option<&serde_json::Value>) -> Option<T> {
            v.cloned().and_then(|v| serde_json::from_value(v).ok())
        }
        if key == "server/name" {
            self.name = parse(value);
        } else if key == "server/icon" {
            self.icon = parse(value);
        } else if let Some(id) = key.strip_prefix("role/") {
            match parse(value) {
                Some(role) => {
                    self.roles.insert(id.to_string(), role);
                }
                None => {
                    self.roles.remove(id);
                }
            }
        } else if let Some(k) = key.strip_prefix("member/") {
            match parse(value) {
                Some(ids) => {
                    self.members.insert(k.to_string(), ids);
                }
                None => {
                    self.members.remove(k);
                }
            }
        } else if let Some(id) = key.strip_prefix("category/") {
            match parse(value) {
                Some(c) => {
                    self.categories.insert(id.to_string(), c);
                }
                None => {
                    self.categories.remove(id);
                }
            }
        } else if let Some(id) = key.strip_prefix("channel/") {
            match parse(value) {
                Some(m) => {
                    self.channels.insert(id.to_string(), m);
                }
                None => {
                    self.channels.remove(id);
                }
            }
        } else if let Some(id) = key.strip_prefix("rules/channel/") {
            match parse(value) {
                Some(r) => {
                    self.channel_rules.insert(id.to_string(), r);
                }
                None => {
                    self.channel_rules.remove(id);
                }
            }
        } else if let Some(id) = key.strip_prefix("rules/category/") {
            match parse(value) {
                Some(r) => {
                    self.category_rules.insert(id.to_string(), r);
                }
                None => {
                    self.category_rules.remove(id);
                }
            }
        }
    }

    /// Effective permissions of `key` in channel `channel_hex`: their
    /// server permissions plus every channel permission, then the
    /// channel's category rules, then the channel's own rules. Within each
    /// layer, as in Discord: @everyone, then all of their roles together
    /// (deny then allow), then rules for them personally. The owner and
    /// Administrators aren't limited by rules.
    ///
    /// `implicit` stands in for rules a channel has no stored rules for
    /// (private channels made before rules existed).
    pub(crate) fn channel_permissions(&self, owner: &[u8], key: &[u8], channel_hex: &str, implicit: Option<&[Overwrite]>) -> u32 {
        let server = self.permissions(owner, key);
        if key == owner || self.role_bits_include_admin(owner, key) {
            return perms::ALL | perms::CHANNEL_ALL;
        }
        let mut p = server | perms::CHANNEL_ALL;
        let hex = to_hex(key);
        let my_roles = self.members.get(&hex).cloned().unwrap_or_default();
        let category = self
            .channels
            .get(channel_hex)
            .and_then(|m| m.category.clone())
            .filter(|c| self.categories.contains_key(c));
        let mut layers: Vec<&[Overwrite]> = Vec::new();
        if let Some(rules) = category.as_ref().and_then(|c| self.category_rules.get(c)) {
            layers.push(rules);
        }
        match self.channel_rules.get(channel_hex) {
            Some(rules) => layers.push(rules),
            None => {
                if let Some(rules) = implicit {
                    layers.push(rules);
                }
            }
        }
        for rules in layers {
            if let Some(o) = rules.iter().find(|o| o.target == EVERYONE) {
                p = (p & !o.deny) | o.allow;
            }
            let (mut deny, mut allow) = (0, 0);
            for o in rules.iter().filter(|o| o.target.strip_prefix("role:").is_some_and(|r| my_roles.iter().any(|m| m == r))) {
                deny |= o.deny;
                allow |= o.allow;
            }
            p = (p & !deny) | allow;
            if let Some(o) = rules.iter().find(|o| o.target.strip_prefix("member:") == Some(hex.as_str())) {
                p = (p & !o.deny) | o.allow;
            }
        }
        p
    }

    fn role_bits_include_admin(&self, owner: &[u8], key: &[u8]) -> bool {
        key != owner && {
            let mut raw = self.role(EVERYONE).map(|r| r.permissions).unwrap_or(0);
            for r in self.roles_of(&to_hex(key)) {
                raw |= r.permissions;
            }
            raw & perms::ADMINISTRATOR != 0
        }
    }

    fn role(&self, id: &str) -> Option<Role> {
        match self.roles.get(id) {
            Some(r) => Some(r.clone()),
            None if id == EVERYONE => Some(default_everyone()),
            None => None,
        }
    }

    fn roles_of(&self, key_hex: &str) -> Vec<Role> {
        self.members
            .get(key_hex)
            .map(|ids| ids.iter().filter_map(|id| self.role(id)).collect())
            .unwrap_or_default()
    }

    fn permissions(&self, owner: &[u8], key: &[u8]) -> u32 {
        if key == owner {
            return perms::ALL;
        }
        let mut p = self.role(EVERYONE).map(|r| r.permissions).unwrap_or(0);
        for r in self.roles_of(&to_hex(key)) {
            p |= r.permissions;
        }
        if p & perms::ADMINISTRATOR != 0 {
            perms::ALL
        } else {
            p & perms::ALL
        }
    }

    /// Highest role position (the owner outranks every role).
    fn rank(&self, owner: &[u8], key: &[u8]) -> i64 {
        if key == owner {
            return i64::MAX;
        }
        self.roles_of(&to_hex(key)).iter().map(|r| r.position).max().unwrap_or(0)
    }
}

fn valid_name(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && t.chars().count() <= MAX_NAME_CHARS && !t.chars().any(char::is_control)
}

fn valid_color(s: &str) -> bool {
    s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Is `author` allowed to make `edit`, given the current `state`? Also
/// validates the value's shape and limits.
fn authorize(state: &State, owner: &[u8], author: &[u8], edit: &Edit) -> Result<(), String> {
    let p = state.permissions(owner, author);
    let is_owner = author == owner;
    let need = |bit: u32, what: &str| if p & bit != 0 { Ok(()) } else { Err(format!("you don't have permission to {what}")) };
    let rank = state.rank(owner, author);
    let v = edit.value.as_ref();
    let key = edit.key.as_str();

    if key == "server/name" {
        need(perms::MANAGE_SERVER, "rename the server")?;
        let name: String = v.cloned().and_then(|v| serde_json::from_value(v).ok()).ok_or("a server needs a name")?;
        if !valid_name(&name) {
            return Err("server names are 1–64 characters".into());
        }
    } else if key == "server/icon" {
        need(perms::MANAGE_SERVER, "change the server icon")?;
        if let Some(v) = v {
            let c: String = serde_json::from_value(v.clone()).map_err(|_| "bad icon color")?;
            if !valid_color(&c) {
                return Err("icon colors look like #7c6cf2".into());
            }
        }
    } else if let Some(id) = key.strip_prefix("role/") {
        need(perms::MANAGE_ROLES, "manage roles")?;
        if !valid_id(id) {
            return Err("bad role id".into());
        }
        let old = state.role(id);
        let new: Option<Role> = match v {
            Some(v) => Some(serde_json::from_value(v.clone()).map_err(|_| "malformed role")?),
            None => None,
        };
        if id == EVERYONE && new.is_none() {
            return Err("the default role can't be deleted".into());
        }
        if let Some(r) = &new {
            if r.id != id || !valid_name(&r.name) || !valid_color(&r.color) || r.permissions & !perms::ALL != 0 {
                return Err("malformed role".into());
            }
            if (id == EVERYONE) != (r.position == 0) || r.position < 0 {
                return Err("only the default role sits at position 0".into());
            }
            if old.is_none() && state.roles.len() >= MAX_ROLES {
                return Err(format!("a server can have at most {MAX_ROLES} roles"));
            }
        }
        if !is_owner {
            let outranks = |r: &Role| r.id == EVERYONE || r.position < rank;
            if old.as_ref().is_some_and(|r| !outranks(r)) || new.as_ref().is_some_and(|r| !outranks(r)) {
                return Err("you can only manage roles below your own highest role".into());
            }
            let mine = state.permissions(owner, author);
            if new.as_ref().is_some_and(|r| r.permissions & !mine != 0) {
                return Err("you can't give a role permissions you don't have".into());
            }
        }
    } else if let Some(k) = key.strip_prefix("member/") {
        need(perms::MANAGE_ROLES, "assign roles")?;
        let old: Vec<String> = state.members.get(k).cloned().unwrap_or_default();
        let new: Vec<String> = match v {
            Some(v) => serde_json::from_value(v.clone()).map_err(|_| "malformed role list")?,
            None => Vec::new(),
        };
        if new.len() > MAX_ROLES || new.iter().any(|id| id == EVERYONE || state.role(id).is_none()) {
            return Err("unknown role".into());
        }
        if !is_owner {
            for id in old.iter().filter(|id| !new.contains(id)).chain(new.iter().filter(|id| !old.contains(id))) {
                if state.role(id).is_some_and(|r| r.position >= rank) {
                    return Err("you can only assign roles below your own highest role".into());
                }
            }
        }
    } else if let Some(id) = key.strip_prefix("category/") {
        need(perms::MANAGE_CHANNELS, "manage categories")?;
        if !valid_id(id) {
            return Err("bad category id".into());
        }
        if let Some(v) = v {
            let c: Category = serde_json::from_value(v.clone()).map_err(|_| "malformed category")?;
            if c.id != id || !valid_name(&c.name) {
                return Err("category names are 1–64 characters".into());
            }
            if !state.categories.contains_key(id) && state.categories.len() >= MAX_CATEGORIES {
                return Err(format!("a server can have at most {MAX_CATEGORIES} categories"));
            }
        }
    } else if let Some(id) = key.strip_prefix("channel/") {
        need(perms::MANAGE_CHANNELS, "manage channels")?;
        if wire::from_hex(id).is_err() {
            return Err("bad channel id".into());
        }
        if let Some(v) = v {
            let m: ChannelMeta = serde_json::from_value(v.clone()).map_err(|_| "malformed channel settings")?;
            if m.name.as_deref().is_some_and(|n| !valid_name(n)) {
                return Err("channel names are 1–64 characters".into());
            }
            if m.topic.chars().count() > MAX_TOPIC_CHARS {
                return Err(format!("topics are limited to {MAX_TOPIC_CHARS} characters"));
            }
        }
    } else if let Some(rest) = key.strip_prefix("rules/") {
        // Changing who can do what in a channel or category: needs Manage
        // roles and Manage channels, and (as with roles) only for targets
        // ranked below you.
        need(perms::MANAGE_ROLES, "change channel permissions")?;
        need(perms::MANAGE_CHANNELS, "change channel permissions")?;
        let ok_scope = match rest.split_once('/') {
            Some(("channel", id)) => wire::from_hex(id).is_ok(),
            Some(("category", id)) => valid_id(id),
            _ => false,
        };
        if !ok_scope {
            return Err("bad permission rule key".into());
        }
        let rules: Vec<Overwrite> = match v {
            Some(v) => serde_json::from_value(v.clone()).map_err(|_| "malformed permission rules")?,
            None => Vec::new(),
        };
        if rules.len() > MAX_ROLES + 50 {
            return Err("too many permission rules".into());
        }
        let mine = state.permissions(owner, author) | perms::CHANNEL_ALL;
        let manageable = |target: &str| {
            is_owner
                || target == EVERYONE
                || target.strip_prefix("role:").is_some_and(|r| state.role(r).is_some_and(|r| r.position < rank))
                || target
                    .strip_prefix("member:")
                    .and_then(|m| wire::from_hex(m).ok())
                    .is_some_and(|k| k != author && k != owner && state.rank(owner, &k) < rank)
        };
        // Rules for targets you can't manage stay exactly as they were.
        let existing = match rest.split_once('/') {
            Some(("channel", id)) => state.channel_rules.get(id),
            Some(("category", id)) => state.category_rules.get(id),
            _ => None,
        };
        for old in existing.into_iter().flatten().filter(|o| !manageable(&o.target)) {
            if !rules.contains(old) {
                return Err("you can only change rules for roles and members ranked below you".into());
            }
        }
        for o in &rules {
            if (o.allow | o.deny) & !perms::OVERWRITABLE != 0 || o.allow & o.deny != 0 {
                return Err("malformed permission rule".into());
            }
            if !is_owner && o.allow & !mine != 0 && !existing.is_some_and(|e| e.contains(o)) {
                return Err("you can't allow something you don't have".into());
            }
            let known = if o.target == EVERYONE {
                true
            } else if let Some(role) = o.target.strip_prefix("role:") {
                state.role(role).is_some()
            } else if let Some(member) = o.target.strip_prefix("member:") {
                wire::from_hex(member).is_ok()
            } else {
                false
            };
            if !known {
                return Err("malformed permission rule".into());
            }
            let unchanged = existing.is_some_and(|e| e.contains(o));
            if !unchanged && !manageable(&o.target) {
                return Err("you can only set rules for roles and members ranked below you".into());
            }
        }
    } else {
        return Err(format!("unknown setting {key}"));
    }
    Ok(())
}

impl NodeState {
    pub(crate) fn server_state(&self, server_gid: &[u8]) -> State {
        State::from_edits(&self.store.server_edits(server_gid).unwrap_or_default())
    }

    /// The server a conversation belongs to (itself, for a server), with
    /// its owner key.
    pub(crate) fn server_of(&self, gid: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let c = self.store.conversation(gid).ok().flatten()?;
        match c.kind {
            ConversationKind::Server => Some((c.group_id, c.admin_key)),
            ConversationKind::Channel => {
                let sid = c.server_id?;
                let s = self.store.conversation(&sid).ok().flatten()?;
                Some((s.group_id, s.admin_key))
            }
            ConversationKind::Dm => None,
        }
    }

    /// `key`'s permissions in the server `gid` belongs to (0 for DMs).
    pub(crate) fn permissions_in(&self, gid: &[u8], key: &[u8]) -> u32 {
        match self.server_of(gid) {
            Some((sid, owner)) => self.server_state(&sid).permissions(&owner, key),
            None => 0,
        }
    }

    pub(crate) fn rank_in(&self, server_gid: &[u8], key: &[u8]) -> i64 {
        match self.server_of(server_gid) {
            Some((sid, owner)) => self.server_state(&sid).rank(&owner, key),
            None => 0,
        }
    }

    /// Fail unless we hold `bit` in the server `gid` belongs to.
    pub(crate) fn require(&self, gid: &[u8], bit: u32, what: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.permissions_in(gid, self.my_key()) & bit != 0,
            "you don't have permission to {what} in this server"
        );
        Ok(())
    }

    pub(crate) fn server_settings(&self, server_id: &str) -> anyhow::Result<ServerSettings> {
        let gid = wire::from_hex(server_id)?;
        let (sid, owner) = self.server_of(&gid).ok_or_else(|| anyhow::anyhow!("not a server"))?;
        let conversation = self.store.conversation(&sid)?.ok_or_else(|| anyhow::anyhow!("no such server"))?;
        let state = self.server_state(&sid);
        let mut roles: Vec<Role> = state.roles.values().filter(|r| r.id != EVERYONE).cloned().collect();
        roles.sort_by(|a, b| b.position.cmp(&a.position).then(a.name.cmp(&b.name)));
        roles.push(state.role(EVERYONE).expect("always present"));
        let mut categories: Vec<Category> = state.categories.values().cloned().collect();
        categories.sort_by(|a, b| a.position.cmp(&b.position).then(a.name.cmp(&b.name)));
        Ok(ServerSettings {
            server_id: to_hex(&sid),
            name: state.name.clone().unwrap_or(conversation.name),
            icon_color: state.icon.clone(),
            owner_key: to_hex(&owner),
            roles,
            member_roles: state.members.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            categories,
            channels: state.channels.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            my_permissions: state.permissions(&owner, self.my_key()),
            my_rank: state.rank(&owner, self.my_key()),
            channel_rules: state.channel_rules.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            category_rules: state.category_rules.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        })
    }

    /// Make changes to a server's settings: checked against our own
    /// permissions exactly as every other member will check them, stored,
    /// and sent to the server's members.
    pub(crate) fn edit_server(&mut self, server_id: &str, edits: Vec<Edit>) -> anyhow::Result<ServerSettings> {
        anyhow::ensure!(!edits.is_empty() && edits.len() <= MAX_EDITS, "nothing to change");
        let gid = wire::from_hex(server_id)?;
        let server = self.active_conversation(&gid)?;
        anyhow::ensure!(server.kind == ConversationKind::Server, "not a server");
        let owner = server.admin_key.clone();
        let me = self.public.public_key.clone();

        // Check (and apply) in order, so an edit can rely on a role created
        // earlier in the same batch.
        let mut state = self.server_state(&gid);
        for e in &edits {
            authorize(&state, &owner, &me, e).map_err(anyhow::Error::msg)?;
            state.set(&e.key, e.value.as_ref());
        }
        let lamport = self.server_state(&gid).max_lamport + 1;
        for e in &edits {
            self.store.put_server_edit(
                &gid,
                &StampedEdit { key: e.key.clone(), value: e.value.clone(), lamport, author: me.clone() },
            )?;
        }
        let payload = Payload::ServerEdit { lamport, edits };
        let group = self.groups.get_mut(&gid).ok_or_else(|| anyhow::anyhow!("group state missing"))?;
        let ciphertext = self.member.encrypt(group, &payload.to_bytes())?;
        self.fan_out(&gid, &ciphertext, &[], None)?;
        self.dirty = true;
        // Anything that can change who may see a channel: bring the
        // channels' encryption groups into line.
        if payload_touches_access(&payload) {
            self.sync_channel_access(&gid);
        }
        self.emit(Event::ServerChanged { server_id: to_hex(&gid) });
        self.emit(Event::ConversationsChanged);
        self.server_settings(server_id)
    }

    /// Another member's edits. Each is checked against the author's
    /// permissions in our copy of the settings; the ones that pass are
    /// applied if they're newer than what we have.
    pub(crate) fn on_server_edit(&mut self, gid: &[u8], author: &[u8], lamport: u64, edits: Vec<Edit>) -> anyhow::Result<()> {
        let server = self.store.conversation(gid)?.ok_or_else(|| anyhow::anyhow!("unknown server"))?;
        anyhow::ensure!(server.kind == ConversationKind::Server, "server edit outside a server");
        anyhow::ensure!(edits.len() <= MAX_EDITS, "too many edits");
        let owner = server.admin_key.clone();
        let mut state = self.server_state(gid);
        let mut refused = 0;
        for e in edits {
            if authorize(&state, &owner, author, &e).is_err() {
                refused += 1;
                continue;
            }
            state.set(&e.key, e.value.as_ref());
            self.store.put_server_edit(gid, &StampedEdit { key: e.key, value: e.value, lamport, author: author.to_vec() })?;
        }
        if refused > 0 {
            eprintln!("[securetext] ignored {refused} server change(s) from {} (not permitted)", super::short(author));
        }
        self.dirty = true;
        self.emit(Event::ServerChanged { server_id: to_hex(gid) });
        self.emit(Event::ConversationsChanged);
        self.emit(Event::MembersChanged { conversation_id: to_hex(gid) });
        Ok(())
    }

    /// Rules standing in for a private channel that has none stored (made
    /// before channel rules existed, or never edited): @everyone can't see
    /// it; the people in it can.
    fn implicit_rules(&self, channel_gid: &[u8]) -> Option<Vec<Overwrite>> {
        let c = self.store.conversation(channel_gid).ok().flatten()?;
        if c.kind != ConversationKind::Channel || !c.private {
            return None;
        }
        let mut rules = vec![Overwrite { target: EVERYONE.into(), allow: 0, deny: perms::VIEW_CHANNEL }];
        for k in self.group_members(channel_gid).unwrap_or_default() {
            rules.push(Overwrite { target: format!("member:{}", to_hex(&k)), allow: perms::VIEW_CHANNEL, deny: 0 });
        }
        Some(rules)
    }

    /// `key`'s effective permissions in conversation `gid`: channel rules
    /// applied for channels, server permissions for a server, everything
    /// for a DM.
    pub(crate) fn permissions_here(&self, gid: &[u8], key: &[u8]) -> u32 {
        let Some(conversation) = self.store.conversation(gid).ok().flatten() else { return 0 };
        match conversation.kind {
            ConversationKind::Dm => perms::CHANNEL_ALL,
            ConversationKind::Server => self.permissions_in(gid, key),
            ConversationKind::Channel => {
                let Some((sid, owner)) = self.server_of(gid) else { return 0 };
                let state = self.server_state(&sid);
                let implicit = self.implicit_rules(gid);
                state.channel_permissions(&owner, key, &to_hex(gid), implicit.as_deref())
            }
        }
    }

    /// Fail unless we hold `bit` in conversation `gid` (after channel rules).
    pub(crate) fn require_here(&self, gid: &[u8], bit: u32, what: &str) -> anyhow::Result<()> {
        anyhow::ensure!(self.permissions_here(gid, self.my_key()) & bit != 0, "you don't have permission to {what} here");
        Ok(())
    }

    /// Bring every channel of a server we're in into line with who may see
    /// it: add server members who can and aren't in its group, remove
    /// those who can't. Called by whoever changes something that affects
    /// visibility. Returns notes on what couldn't be done yet.
    pub(crate) fn sync_channel_access(&mut self, server_gid: &[u8]) -> Vec<String> {
        let mut notes = Vec::new();
        let server_members = self.group_members(server_gid).unwrap_or_default();
        let me = self.public.public_key.clone();
        let channels = self.store.channels_of(server_gid).unwrap_or_default();
        for channel in channels.into_iter().filter(|c| !c.removed) {
            let gid = channel.group_id.clone();
            let current = self.group_members(&gid).unwrap_or_default();
            let can_see = |s: &Self, k: &[u8]| s.permissions_here(&gid, k) & perms::VIEW_CHANNEL != 0;
            let to_remove: Vec<Vec<u8>> =
                current.iter().filter(|k| **k != me && !can_see(self, k)).cloned().collect();
            let to_add: Vec<Vec<u8>> =
                server_members.iter().filter(|k| !current.contains(k) && can_see(self, k)).cloned().collect();
            for k in to_remove {
                if let Err(e) = self.remove_from_group(&gid, &k) {
                    notes.push(format!("couldn't remove {} from #{}: {e}", self.label_for(&k), channel.name));
                }
            }
            for k in to_add {
                let card = match self.store.peer_card(&k) {
                    Ok(Some(card)) => card,
                    _ => {
                        notes.push(format!("{} will be added to #{} once they've connected to you", self.label_for(&k), channel.name));
                        continue;
                    }
                };
                if self.require_key_packages(std::slice::from_ref(&k), 1).is_err() {
                    // Asked for; finished when they arrive.
                    self.access_sync_waiting.entry(k.clone()).or_default().insert(server_gid.to_vec());
                    continue;
                }
                if let Err(e) = self.add_to_group(&gid, &k, &card) {
                    notes.push(format!("couldn't add {} to #{}: {e}", self.label_for(&k), channel.name));
                }
            }
        }
        for n in &notes {
            self.emit(Event::Warning { conversation_id: to_hex(server_gid), message: n.clone() });
        }
        notes
    }

    /// A newcomer's copy of the settings, from the server Welcome.
    pub(crate) fn adopt_server_snapshot(&mut self, gid: &[u8], snapshot: Vec<StampedEdit>) {
        for e in snapshot.into_iter().take(MAX_EDITS * 5) {
            let _ = self.store.put_server_edit(gid, &e);
        }
    }

    pub(crate) fn server_snapshot(&self, gid: &[u8]) -> Option<Vec<StampedEdit>> {
        self.store.server_edits(gid).ok().filter(|e| !e.is_empty())
    }

    /// Move a channel into `category` (or none) at `index` among that
    /// category's channels, renumbering its neighbours.
    pub(crate) fn move_channel(
        &mut self,
        server_id: &str,
        channel_id: &str,
        category: Option<String>,
        index: usize,
    ) -> anyhow::Result<ServerSettings> {
        let gid = wire::from_hex(server_id)?;
        let settings = self.server_settings(server_id)?;
        if let Some(c) = &category {
            anyhow::ensure!(settings.categories.iter().any(|x| &x.id == c), "no such category");
        }
        let channels = self.store.channels_of(&gid)?;
        anyhow::ensure!(channels.iter().any(|c| to_hex(&c.group_id) == channel_id), "no such channel in this server");
        let meta = |id: &str| settings.channels.get(id).cloned().unwrap_or_default();
        // The target category's channels in their current order, minus the
        // one moving, then with it inserted at `index`.
        let mut siblings: Vec<(String, ChannelMeta)> = channels
            .iter()
            .map(|c| to_hex(&c.group_id))
            .filter(|id| id != channel_id)
            .map(|id| (id.clone(), meta(&id)))
            .filter(|(_, m)| m.category == category)
            .collect();
        siblings.sort_by(|a, b| a.1.position.cmp(&b.1.position).then(a.0.cmp(&b.0)));
        let mut moving = meta(channel_id);
        moving.category = category.clone();
        siblings.insert(index.min(siblings.len()), (channel_id.to_string(), moving));
        let edits = siblings
            .into_iter()
            .enumerate()
            .filter_map(|(i, (id, mut m))| {
                let changed = m.position != i as i64 || id == channel_id;
                m.position = i as i64;
                changed.then(|| Edit { key: format!("channel/{id}"), value: Some(serde_json::to_value(m).expect("serializes")) })
            })
            .collect();
        self.edit_server(server_id, edits)
    }

    /// Check a membership change against its committer's permissions.
    /// For a channel, adding and removing people is also how visibility
    /// rules are applied, so role and channel managers may do it too. MLS
    /// can't be made to refuse it (that would split the group), so an
    /// unauthorized one is flagged to the user instead.
    pub(crate) fn check_membership_change(&mut self, gid: &[u8], committer: Option<&[u8]>, added: &[Vec<u8>], removed: &[Vec<u8>]) {
        let Some(committer) = committer else { return };
        if self.server_of(gid).is_none() || (added.is_empty() && removed.is_empty()) {
            return;
        }
        let perms = self.permissions_in(gid, committer);
        let rank = self.rank_in(gid, committer);
        let owner = self.server_of(gid).map(|(_, o)| o).unwrap_or_default();
        let is_channel = self.store.conversation(gid).ok().flatten().is_some_and(|c| c.kind == ConversationKind::Channel);
        let manages_access = is_channel && perms & (perms::MANAGE_ROLES | perms::MANAGE_CHANNELS) != 0;
        let bad_add = !added.is_empty() && perms & perms::INVITE_MEMBERS == 0 && !manages_access;
        let bad_remove = removed.iter().any(|k| {
            let can_remove = perms & perms::KICK_MEMBERS != 0 || (is_channel && perms & perms::MANAGE_ROLES != 0);
            !can_remove || *k == owner || (committer != owner && self.rank_in(gid, k) >= rank)
        });
        if bad_add || bad_remove {
            let who = self.label_for(committer);
            self.emit(Event::Warning {
                conversation_id: to_hex(gid),
                message: format!("{who} changed who's in this server without permission to."),
            });
        }
    }
}

fn payload_touches_access(payload: &Payload) -> bool {
    match payload {
        Payload::ServerEdit { edits, .. } => edits.iter().any(|e| {
            ["rules/", "member/", "role/", "channel/", "category/"].iter().any(|p| e.key.starts_with(p))
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(id: &str, position: i64, permissions: u32) -> Role {
        Role { id: id.into(), name: id.into(), color: "#112233".into(), permissions, position, hoist: false }
    }

    fn edit(key: &str, value: impl Serialize) -> Edit {
        Edit { key: key.into(), value: Some(serde_json::to_value(value).unwrap()) }
    }

    fn state_with(roles: &[Role], members: &[(&[u8], &[&str])]) -> State {
        let mut s = State::default();
        for r in roles {
            s.roles.insert(r.id.clone(), r.clone());
        }
        for (k, ids) in members {
            s.members.insert(to_hex(k), ids.iter().map(|s| s.to_string()).collect());
        }
        s
    }

    const OWNER: &[u8] = &[1; 32];
    const MOD: &[u8] = &[2; 32];
    const MEMBER: &[u8] = &[3; 32];

    #[test]
    fn permissions_come_from_roles_and_the_owner_has_everything() {
        let s = state_with(&[role("mod", 5, perms::KICK_MEMBERS | perms::MANAGE_ROLES)], &[(MOD, &["mod"])]);
        assert_eq!(s.permissions(OWNER, OWNER), perms::ALL);
        assert_eq!(s.permissions(OWNER, MOD), perms::KICK_MEMBERS | perms::MANAGE_ROLES);
        assert_eq!(s.permissions(OWNER, MEMBER), 0);
        let admin = state_with(&[role("admin", 9, perms::ADMINISTRATOR)], &[(MOD, &["admin"])]);
        assert_eq!(admin.permissions(OWNER, MOD), perms::ALL, "administrator implies everything");
        let mut everyone = State::default();
        everyone.roles.insert(EVERYONE.into(), role(EVERYONE, 0, perms::INVITE_MEMBERS));
        assert_eq!(everyone.permissions(OWNER, MEMBER), perms::INVITE_MEMBERS, "the default role applies to all");
    }

    #[test]
    fn role_hierarchy_is_enforced_like_discord() {
        let s = state_with(
            &[role("admin", 10, perms::ALL & !perms::ADMINISTRATOR), role("mod", 5, perms::MANAGE_ROLES), role("helper", 2, 0)],
            &[(MOD, &["mod"])],
        );
        // A mod can edit and assign roles below theirs...
        authorize(&s, OWNER, MOD, &edit("role/helper", role("helper", 2, 0))).unwrap();
        authorize(&s, OWNER, MOD, &edit(&format!("member/{}", to_hex(MEMBER)), vec!["helper"])).unwrap();
        // ...but not their own rank or above,
        assert!(authorize(&s, OWNER, MOD, &edit("role/admin", role("admin", 10, 0))).is_err());
        assert!(authorize(&s, OWNER, MOD, &edit("role/mod", role("mod", 5, perms::ALL))).is_err());
        assert!(authorize(&s, OWNER, MOD, &edit(&format!("member/{}", to_hex(MEMBER)), vec!["mod"])).is_err());
        // can't grant permissions they don't have,
        assert!(authorize(&s, OWNER, MOD, &edit("role/helper", role("helper", 2, perms::KICK_MEMBERS))).is_err());
        // and can't rename the server.
        assert!(authorize(&s, OWNER, MOD, &edit("server/name", "Mine now")).is_err());
        // A plain member can't do any of it; the owner can do all of it.
        assert!(authorize(&s, OWNER, MEMBER, &edit("role/helper", role("helper", 2, 0))).is_err());
        authorize(&s, OWNER, OWNER, &edit("role/admin", role("admin", 10, perms::ALL))).unwrap();
        // The default role stays.
        assert!(authorize(&s, OWNER, OWNER, &Edit { key: "role/everyone".into(), value: None }).is_err());
    }

    #[test]
    fn edits_are_validated() {
        let s = State::default();
        assert!(authorize(&s, OWNER, OWNER, &edit("server/icon", "red")).is_err());
        assert!(authorize(&s, OWNER, OWNER, &edit("server/name", "")).is_err());
        assert!(authorize(&s, OWNER, OWNER, &edit("role/x y", role("x y", 1, 0))).is_err());
        assert!(authorize(&s, OWNER, OWNER, &edit("role/r", role("r", 1, 1 << 20))).is_err(), "unknown permission bit");
        assert!(authorize(&s, OWNER, OWNER, &edit("channel/zz", ChannelMeta::default())).is_err());
        assert!(authorize(&s, OWNER, OWNER, &edit("nonsense/key", 1)).is_err());
        authorize(&s, OWNER, OWNER, &edit("server/icon", "#7c6cf2")).unwrap();
    }

    fn ow(target: &str, allow: u32, deny: u32) -> Overwrite {
        Overwrite { target: target.into(), allow, deny }
    }

    const CH: &str = "aabb";

    #[test]
    fn channel_rules_resolve_category_then_channel_everyone_roles_member() {
        let mut s = state_with(&[role("mod", 5, perms::KICK_MEMBERS), role("muted", 1, 0)], &[(MOD, &["mod"]), (MEMBER, &["muted"])]);
        // With no rules, channel permissions are all allowed.
        assert_eq!(s.channel_permissions(OWNER, MEMBER, CH, None) & perms::CHANNEL_ALL, perms::CHANNEL_ALL);
        // Category hides it from everyone but mods.
        s.categories.insert("staff".into(), Category { id: "staff".into(), name: "Staff".into(), position: 0 });
        s.channels.insert(CH.into(), ChannelMeta { category: Some("staff".into()), ..Default::default() });
        s.category_rules.insert("staff".into(), vec![ow(EVERYONE, 0, perms::VIEW_CHANNEL), ow("role:mod", perms::VIEW_CHANNEL, 0)]);
        assert_eq!(s.channel_permissions(OWNER, MEMBER, CH, None) & perms::VIEW_CHANNEL, 0);
        assert_ne!(s.channel_permissions(OWNER, MOD, CH, None) & perms::VIEW_CHANNEL, 0);
        // The channel's own rules come after: a personal allow lets MEMBER
        // see it, while their role can't send.
        s.channel_rules.insert(
            CH.into(),
            vec![ow("role:muted", 0, perms::SEND_MESSAGES), ow(&format!("member:{}", to_hex(MEMBER)), perms::VIEW_CHANNEL, 0)],
        );
        let p = s.channel_permissions(OWNER, MEMBER, CH, None);
        assert_ne!(p & perms::VIEW_CHANNEL, 0);
        assert_eq!(p & perms::SEND_MESSAGES, 0);
        assert_ne!(p & perms::ADD_REACTIONS, 0);
        // A role allow beats an @everyone deny in the same layer.
        s.channel_rules.insert(CH.into(), vec![ow(EVERYONE, 0, perms::CONNECT), ow("role:mod", perms::CONNECT, 0)]);
        assert_ne!(s.channel_permissions(OWNER, MOD, CH, None) & perms::CONNECT, 0);
        assert_eq!(s.channel_permissions(OWNER, MEMBER, CH, None) & perms::CONNECT, 0);
        // The owner and administrators are never limited.
        s.channel_rules.insert(CH.into(), vec![ow(EVERYONE, 0, perms::CHANNEL_ALL)]);
        assert_eq!(s.channel_permissions(OWNER, OWNER, CH, None) & perms::CHANNEL_ALL, perms::CHANNEL_ALL);
        s.roles.insert("admin".into(), role("admin", 9, perms::ADMINISTRATOR));
        s.members.insert(to_hex(MOD), vec!["admin".into()]);
        assert_eq!(s.channel_permissions(OWNER, MOD, CH, None) & perms::CHANNEL_ALL, perms::CHANNEL_ALL);
    }

    #[test]
    fn implicit_rules_apply_only_without_stored_ones() {
        let mut s = State::default();
        let implicit = [ow(EVERYONE, 0, perms::VIEW_CHANNEL)];
        assert_eq!(s.channel_permissions(OWNER, MEMBER, CH, Some(&implicit)) & perms::VIEW_CHANNEL, 0);
        s.channel_rules.insert(CH.into(), vec![]);
        assert_ne!(s.channel_permissions(OWNER, MEMBER, CH, Some(&implicit)) & perms::VIEW_CHANNEL, 0);
    }

    #[test]
    fn channel_rule_edits_respect_the_hierarchy() {
        let manage = perms::MANAGE_ROLES | perms::MANAGE_CHANNELS;
        let mut s = state_with(
            &[role("admin", 9, manage), role("mod", 5, manage), role("helper", 2, 0)],
            &[(MOD, &["mod"]), (MEMBER, &["helper"])],
        );
        let key = format!("rules/channel/{CH}");
        // A mod can set rules for @everyone and roles/members below them.
        authorize(&s, OWNER, MOD, &edit(&key, vec![ow(EVERYONE, 0, perms::SEND_MESSAGES), ow("role:helper", perms::SEND_MESSAGES, 0)]))
            .unwrap();
        authorize(&s, OWNER, MOD, &edit(&key, vec![ow(&format!("member:{}", to_hex(MEMBER)), 0, perms::VIEW_CHANNEL)])).unwrap();
        // ...not for roles at or above them, themselves or the owner.
        assert!(authorize(&s, OWNER, MOD, &edit(&key, vec![ow("role:admin", 0, perms::VIEW_CHANNEL)])).is_err());
        assert!(authorize(&s, OWNER, MOD, &edit(&key, vec![ow("role:mod", perms::VIEW_CHANNEL, 0)])).is_err());
        assert!(authorize(&s, OWNER, MOD, &edit(&key, vec![ow(&format!("member:{}", to_hex(MOD)), 0, 0)])).is_err());
        assert!(authorize(&s, OWNER, MOD, &edit(&key, vec![ow(&format!("member:{}", to_hex(OWNER)), 0, perms::VIEW_CHANNEL)])).is_err());
        // Can't allow what they don't have; malformed rules are refused.
        assert!(authorize(&s, OWNER, MOD, &edit(&key, vec![ow(EVERYONE, perms::KICK_MEMBERS, 0)])).is_err());
        assert!(authorize(&s, OWNER, MOD, &edit(&key, vec![ow(EVERYONE, perms::VIEW_CHANNEL, perms::VIEW_CHANNEL)])).is_err());
        assert!(authorize(&s, OWNER, MOD, &edit(&key, vec![ow("role:nope", 0, 0)])).is_err());
        assert!(authorize(&s, OWNER, MOD, &edit("rules/channel/not-hex", Vec::<Overwrite>::new())).is_err());
        assert!(authorize(&s, OWNER, MOD, &edit("rules/elsewhere/x", Vec::<Overwrite>::new())).is_err());
        // Without Manage roles + Manage channels, no rules at all.
        assert!(authorize(&s, OWNER, MEMBER, &edit(&key, vec![ow(EVERYONE, 0, 0)])).is_err());
        // Rules the owner set for higher roles survive a mod's edit.
        let admin_rule = ow("role:admin", 0, perms::CONNECT);
        s.channel_rules.insert(CH.into(), vec![admin_rule.clone()]);
        assert!(authorize(&s, OWNER, MOD, &edit(&key, vec![ow(EVERYONE, 0, 0)])).is_err(), "drops the admin rule");
        authorize(&s, OWNER, MOD, &edit(&key, vec![admin_rule, ow(EVERYONE, 0, 0)])).unwrap();
        // The owner can do anything well-formed.
        authorize(&s, OWNER, OWNER, &edit(&key, vec![ow("role:admin", 0, perms::VIEW_CHANNEL)])).unwrap();
        authorize(&s, OWNER, OWNER, &edit("rules/category/staff", vec![ow("role:mod", perms::VIEW_CHANNEL, 0)])).unwrap();
    }

}
