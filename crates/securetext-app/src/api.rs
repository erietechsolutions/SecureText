//! The one entry point a UI shell uses to call into a node: a command name
//! plus JSON arguments in, JSON out. The Tauri shell exposes exactly this
//! as a single command, so any frontend runs against the same dispatch
//! table.
//!
//! Argument names are camelCase, matching what Tauri's JS `invoke`
//! convention produces.

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;

use crate::NodeHandle;

pub async fn dispatch(node: &NodeHandle, cmd: &str, args: Value) -> Result<Value, String> {
    fn to_value<T: serde::Serialize>(v: T) -> Result<Value, String> {
        serde_json::to_value(v).map_err(|e| e.to_string())
    }
    fn parse<T: DeserializeOwned>(args: Value) -> Result<T, String> {
        serde_json::from_value(args).map_err(|e| format!("bad arguments: {e}"))
    }
    let err = |e: anyhow::Error| format!("{e:#}");

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Conversation {
        conversation_id: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Messages {
        conversation_id: String,
        #[serde(default = "default_limit")]
        limit: u32,
    }
    fn default_limit() -> u32 {
        200
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Send {
        conversation_id: String,
        body: String,
        #[serde(default)]
        reply_to: Option<String>,
    }
    #[derive(Deserialize)]
    struct Link {
        link: String,
    }
    #[derive(Deserialize)]
    struct Name {
        name: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Channel {
        server_id: String,
        name: String,
        #[serde(default)]
        private: bool,
        #[serde(default)]
        member_keys: Vec<String>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServerPeer {
        server_id: String,
        peer_key: String,
    }

    match cmd {
        "status" => to_value(node.status().await.map_err(err)?),
        "create_invite" => to_value(node.create_invite().await.map_err(err)?),
        "add_contact" => {
            let a: Link = parse(args)?;
            to_value(node.add_contact(a.link).await.map_err(err)?)
        }
        "conversations" => to_value(node.conversations().await.map_err(err)?),
        "messages" => {
            let a: Messages = parse(args)?;
            to_value(node.messages(a.conversation_id, a.limit).await.map_err(err)?)
        }
        "send_message" => {
            let a: Send = parse(args)?;
            to_value(node.post(a.conversation_id, a.body, a.reply_to).await.map_err(err)?)
        }
        "create_server" => {
            let a: Name = parse(args)?;
            to_value(node.create_server(a.name).await.map_err(err)?)
        }
        "create_channel" => {
            let a: Channel = parse(args)?;
            to_value(node.create_channel(a.server_id, a.name, a.private, a.member_keys).await.map_err(err)?)
        }
        "invite_to_server" => {
            let a: ServerPeer = parse(args)?;
            to_value(node.invite_to_server(a.server_id, a.peer_key).await.map_err(err)?)
        }
        "kick" => {
            let a: ServerPeer = parse(args)?;
            to_value(node.kick(a.server_id, a.peer_key).await.map_err(err)?)
        }
        "members" => {
            let a: Conversation = parse(args)?;
            to_value(node.members(a.conversation_id).await.map_err(err)?)
        }
        "contacts" => to_value(node.contacts().await.map_err(err)?),
        "set_relay" => {
            #[derive(Deserialize)]
            struct Relay {
                #[serde(default)]
                address: Option<String>,
            }
            let a: Relay = parse(args)?;
            to_value(node.set_relay(a.address).await.map_err(err)?)
        }
        "send_file" => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct File {
                conversation_id: String,
                name: String,
                #[serde(default)]
                mime: String,
                /// Base64.
                data: String,
                #[serde(default)]
                caption: String,
                #[serde(default)]
                reply_to: Option<String>,
            }
            let a: File = parse(args)?;
            let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, a.data)
                .map_err(|e| format!("bad file data: {e}"))?;
            to_value(node.send_file(a.conversation_id, a.name, a.mime, data, a.caption, a.reply_to).await.map_err(err)?)
        }
        "react" => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct React {
                conversation_id: String,
                message_id: String,
                emoji: String,
                on: bool,
            }
            let a: React = parse(args)?;
            to_value(node.react(a.conversation_id, a.message_id, a.emoji, a.on).await.map_err(err)?)
        }
        "set_disappearing" => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Timer {
                conversation_id: String,
                #[serde(default)]
                secs: Option<i64>,
            }
            let a: Timer = parse(args)?;
            to_value(node.set_disappearing(a.conversation_id, a.secs).await.map_err(err)?)
        }
        "set_presence" => {
            #[derive(Deserialize)]
            struct Presence {
                status: String,
                #[serde(default)]
                text: String,
            }
            let a: Presence = parse(args)?;
            to_value(node.set_presence(a.status, a.text).await.map_err(err)?)
        }
        "download_attachment" | "attachment_data" | "save_attachment" => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct FileId {
                file_id: String,
            }
            let a: FileId = parse(args)?;
            match cmd {
                "download_attachment" => to_value(node.download_attachment(a.file_id).await.map_err(err)?),
                "attachment_data" => to_value(node.attachment_data(a.file_id).await.map_err(err)?),
                _ => to_value(node.save_attachment(a.file_id, None).await.map_err(err)?),
            }
        }
        "start_call" => {
            #[derive(Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Start {
                conversation_id: String,
                #[serde(default)]
                video: bool,
            }
            let a: Start = parse(args)?;
            to_value(node.start_call(a.conversation_id, a.video).await.map_err(err)?)
        }
        "accept_call" => to_value(node.accept_call().await.map_err(err)?),
        "decline_call" => to_value(node.decline_call().await.map_err(err)?),
        "hang_up" => to_value(node.hang_up().await.map_err(err)?),
        "set_call_muted" => {
            #[derive(Deserialize)]
            struct Muted {
                muted: bool,
            }
            let a: Muted = parse(args)?;
            to_value(node.set_call_muted(a.muted).await.map_err(err)?)
        }
        "call_status" => to_value(node.call_status().await.map_err(err)?),
        "call_stats" => to_value(node.call_stats().await.map_err(err)?),
        "send_video_frame" => {
            #[derive(Deserialize)]
            struct Frame {
                jpeg: String,
            }
            let a: Frame = parse(args)?;
            let jpeg = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, a.jpeg)
                .map_err(|e| format!("bad frame: {e}"))?;
            to_value(node.send_video_frame(jpeg).await.map_err(err)?)
        }
        "call_heard" => to_value(node.call_heard().await.map_err(err)?),
        "turn_servers" => to_value(node.turn_servers().await.map_err(err)?),
        "set_turn_servers" => {
            #[derive(Deserialize)]
            struct Servers {
                servers: Vec<crate::call::TurnServer>,
            }
            let a: Servers = parse(args)?;
            to_value(node.set_turn_servers(a.servers).await.map_err(err)?)
        }
        "update_status" => to_value(node.update_status().await.map_err(err)?),
        "check_for_updates" => to_value(node.check_for_updates().await.map_err(err)?),
        "download_update" => to_value(node.download_update().await.map_err(err)?),
        "set_auto_update" => {
            #[derive(Deserialize)]
            struct Enabled {
                enabled: bool,
            }
            let a: Enabled = parse(args)?;
            to_value(node.set_auto_update(a.enabled).await.map_err(err)?)
        }
        other => Err(format!("unknown command: {other}")),
    }
}
