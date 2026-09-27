//! Custom roles, permissions and server layout across real nodes
//! (Discord-style servers): delegated invites, kicks and channel
//! creation, the role hierarchy, newcomers receiving the settings, moving
//! channels between categories, and concurrent edits converging.

mod common;

use common::*;
use securetext_app::wire::Edit;
use securetext_app::{perms, ChannelMeta, Role, ServerSettings};

fn role(id: &str, name: &str, position: i64, permissions: u32) -> Role {
    Role { id: id.into(), name: name.into(), color: "#e67e22".into(), permissions, position, hoist: true }
}

fn set<T: serde::Serialize>(key: &str, value: T) -> Edit {
    Edit { key: key.into(), value: Some(serde_json::to_value(value).unwrap()) }
}

async fn settings_where(node: &NodeHandle, server: &str, what: &str, pred: impl Fn(&ServerSettings) -> bool + Clone) -> ServerSettings {
    eventually(what, || {
        let node = node.clone();
        let server = server.to_string();
        let pred = pred.clone();
        async move { node.server_settings(server).await.ok().filter(|s| pred(s)) }
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn roles_delegate_server_management_and_everyone_agrees() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await; // owner
    let bob = start(dir.path(), "bob", &net).await; // will be a moderator
    let carol = start(dir.path(), "carol", &net).await; // bob's friend
    befriend(&alice, &bob).await;
    befriend(&bob, &carol).await;
    let (bob_key, carol_key, alice_key) = (my_key(&bob).await, my_key(&carol).await, my_key(&alice).await);

    let server = alice.create_server("Club".into()).await.unwrap();
    alice.invite_to_server(server.clone(), bob_key.clone()).await.unwrap();
    channel_named(&bob, &server, "general").await;

    // Bob, a plain member, can't invite yet.
    let err = bob.invite_to_server(server.clone(), carol_key.clone()).await.unwrap_err().to_string();
    assert!(err.contains("permission"), "{err}");

    // Alice renames the server, makes a Mod role and gives it to Bob.
    let moderation = perms::KICK_MEMBERS | perms::INVITE_MEMBERS | perms::MANAGE_CHANNELS | perms::MANAGE_ROLES;
    alice
        .edit_server(
            server.clone(),
            vec![
                set("server/name", "The Club"),
                set("server/icon", "#e91e63"),
                set("role/mod", role("mod", "Mod", 10, moderation)),
                set("role/regular", role("regular", "Regular", 5, 0)),
                set(&format!("member/{bob_key}"), vec!["mod"]),
            ],
        )
        .await
        .unwrap();
    let bobs_view = settings_where(&bob, &server, "bob to get the Mod role", |s| s.my_permissions == moderation).await;
    assert_eq!(bobs_view.name, "The Club");
    assert_eq!(bobs_view.icon_color.as_deref(), Some("#e91e63"));
    let members = alice.members(server.clone()).await.unwrap();
    let bob_row = members.iter().find(|m| m.key == bob_key).unwrap();
    assert_eq!((bob_row.group.as_deref(), bob_row.color.as_deref()), (Some("Mod"), Some("#e67e22")));

    // Now Bob can invite Carol. She arrives already seeing the settings
    // made before she joined (they ride in the Welcome).
    bob.invite_to_server(server.clone(), carol_key.clone()).await.unwrap();
    let general_c = channel_named(&carol, &server, "general").await;
    let carols_view = settings_where(&carol, &server, "carol to see the settings", |s| s.name == "The Club").await;
    assert!(carols_view.roles.iter().any(|r| r.name == "Mod"));
    assert_eq!(carols_view.my_permissions, 0);
    eventually("alice to see carol in the server", || {
        let alice = alice.clone();
        let server = server.clone();
        let carol_key = carol_key.clone();
        async move { alice.members(server).await.ok()?.iter().any(|m| m.key == carol_key).then_some(()) }
    })
    .await;

    // Bob (Manage Channels) makes a channel; everyone gets it.
    bob.create_channel(server.clone(), "mods-made".into(), false, vec![]).await.unwrap();
    channel_named(&alice, &server, "mods-made").await;
    channel_named(&carol, &server, "mods-made").await;

    // Carol has no permissions: she can't make channels or change settings.
    assert!(carol.create_channel(server.clone(), "nope".into(), false, vec![]).await.is_err());
    assert!(carol.edit_server(server.clone(), vec![set("server/name", "Mine")]).await.is_err());

    // The hierarchy: Bob can assign roles below his (Regular) but can't
    // touch his own rank, and can't remove the owner.
    bob.edit_server(server.clone(), vec![set(&format!("member/{carol_key}"), vec!["regular"])]).await.unwrap();
    assert!(bob.edit_server(server.clone(), vec![set(&format!("member/{carol_key}"), vec!["mod"])]).await.is_err());
    assert!(bob.edit_server(server.clone(), vec![set("role/mod", role("mod", "Mod", 10, perms::ALL))]).await.is_err());
    assert!(bob.kick(server.clone(), alice_key.clone()).await.is_err());
    settings_where(&alice, &server, "alice to see carol's role", |s| {
        s.member_roles.values().any(|r| r == &vec!["regular".to_string()])
    })
    .await;

    // Categories and moving channels: Alice files #general under "Text"
    // at the top; everyone sees the same layout.
    alice
        .edit_server(
            server.clone(),
            vec![set("category/text", securetext_app::Category { id: "text".into(), name: "Text".into(), position: 0 })],
        )
        .await
        .unwrap();
    let general = channel_named(&alice, &server, "general").await;
    alice.move_channel(server.clone(), general.clone(), Some("text".into()), 0).await.unwrap();
    let g = general.clone();
    settings_where(&carol, &server, "carol to see #general moved", move |s| {
        s.channels.get(&g).is_some_and(|m| m.category.as_deref() == Some("text") && m.position == 0)
    })
    .await;
    let conv = carol.conversations().await.unwrap().into_iter().find(|c| c.id == general_c).unwrap();
    assert_eq!(conv.category.as_deref(), Some("text"));

    // Concurrent edits to the same field converge to the same value on
    // every member, whatever order they arrive in.
    let topic = |t: &str| set(&format!("channel/{general}"), ChannelMeta { topic: t.into(), category: Some("text".into()), ..Default::default() });
    let (a, b) = tokio::join!(
        alice.edit_server(server.clone(), vec![topic("from alice")]),
        bob.edit_server(server.clone(), vec![topic("from bob")])
    );
    a.unwrap();
    b.unwrap();
    let g = general.clone();
    let settled = eventually("topics to converge", || {
        let (alice, bob, carol, server, g) = (alice.clone(), bob.clone(), carol.clone(), server.clone(), g.clone());
        async move {
            let t = |s: ServerSettings| s.channels.get(&g).map(|m| m.topic.clone());
            let (x, y, z) = (
                t(alice.server_settings(server.clone()).await.ok()?),
                t(bob.server_settings(server.clone()).await.ok()?),
                t(carol.server_settings(server).await.ok()?),
            );
            (x == y && y == z && x.as_deref() != Some("")).then_some(x)
        }
    })
    .await;
    assert!(matches!(settled.as_deref(), Some("from alice") | Some("from bob")));

    // Bob (Kick Members, above Regular) removes Carol.
    bob.kick(server.clone(), carol_key.clone()).await.unwrap();
    eventually("carol to be removed", || {
        let carol = carol.clone();
        let general_c = general_c.clone();
        async move { carol.conversations().await.ok()?.into_iter().find(|c| c.id == general_c && c.removed).map(|_| ()) }
    })
    .await;
}

async fn removed_is(node: &NodeHandle, conversation: &str, removed: bool) {
    let what = format!("#{conversation} removed={removed}");
    eventually(&what, || {
        let node = node.clone();
        let conversation = conversation.to_string();
        async move { node.conversations().await.ok()?.into_iter().find(|c| c.id == conversation && c.removed == removed).map(|_| ()) }
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_rules_control_who_sees_and_does_what() {
    use securetext_app::Overwrite;
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await; // owner
    let bob = start(dir.path(), "bob", &net).await; // mod
    let carol = start(dir.path(), "carol", &net).await; // member
    befriend(&alice, &bob).await;
    befriend(&alice, &carol).await;
    let (bob_key, carol_key) = (my_key(&bob).await, my_key(&carol).await);
    let server = alice.create_server("Club".into()).await.unwrap();
    alice.invite_to_server(server.clone(), bob_key.clone()).await.unwrap();
    alice.invite_to_server(server.clone(), carol_key.clone()).await.unwrap();
    let staff = alice.create_channel(server.clone(), "staff".into(), false, vec![]).await.unwrap();
    channel_named(&carol, &server, "staff").await;
    let general = channel_named(&alice, &server, "general").await;
    channel_named(&carol, &server, "general").await;
    alice
        .edit_server(server.clone(), vec![set("role/mod", role("mod", "Mod", 10, 0)), set(&format!("member/{bob_key}"), vec!["mod"])])
        .await
        .unwrap();

    // #staff: hidden from @everyone, visible to mods. Carol is taken out
    // of it; Bob stays.
    let rule = |target: &str, allow: u32, deny: u32| Overwrite { target: target.into(), allow, deny };
    alice
        .edit_server(
            server.clone(),
            vec![set(
                &format!("rules/channel/{staff}"),
                vec![rule("everyone", 0, perms::VIEW_CHANNEL), rule("role:mod", perms::VIEW_CHANNEL, 0)],
            )],
        )
        .await
        .unwrap();
    removed_is(&carol, &staff, true).await;
    alice.post(staff.clone(), "mods only".into(), None).await.unwrap();
    wait_for_message(&bob, &staff, "mods only").await;
    assert!(!has_message(&carol, &staff, "mods only").await);

    // #general: @everyone can't post, mods can. Carol's client refuses.
    alice
        .edit_server(
            server.clone(),
            vec![set(
                &format!("rules/channel/{general}"),
                vec![rule("everyone", 0, perms::SEND_MESSAGES), rule("role:mod", perms::SEND_MESSAGES, 0)],
            )],
        )
        .await
        .unwrap();
    eventually("carol to learn she can't post", || {
        let carol = carol.clone();
        let general = general.clone();
        async move {
            let c = carol.conversations().await.ok()?.into_iter().find(|c| c.id == general)?;
            (c.permissions & perms::SEND_MESSAGES == 0).then_some(())
        }
    })
    .await;
    let err = carol.post(general.clone(), "hello?".into(), None).await.unwrap_err().to_string();
    assert!(err.contains("permission"), "{err}");
    // Reacting is still allowed.
    let note = bob.post(general.clone(), "announcement".into(), None).await.unwrap();
    wait_for_message(&carol, &general, "announcement").await;
    carol.react(general.clone(), note.id.clone(), "👍".into(), true).await.unwrap();

    // Access back: Carol rejoins #staff and gets new messages there.
    alice.edit_server(server.clone(), vec![set(&format!("rules/channel/{staff}"), Vec::<Overwrite>::new())]).await.unwrap();
    removed_is(&carol, &staff, false).await;
    bob.post(staff.clone(), "welcome back".into(), None).await.unwrap();
    wait_for_message(&carol, &staff, "welcome back").await;
}
