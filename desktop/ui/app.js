// SecureText desktop UI. Plain JS, no framework and no third-party code:
// the frontend of a privacy tool is attack surface, and nothing here needs
// more than the DOM.
//
// All data comes from the Rust node through one call, `node(cmd, args)`
// (securetext-app's api::dispatch), plus a live event stream. Under Tauri
// that's `invoke`; under the browser dev harness it's same-origin fetch.

(() => {
  'use strict';

  // ------------------------------------------------------------------
  // Bridge
  // ------------------------------------------------------------------
  const TAURI = window.__TAURI__;
  const params = new URLSearchParams(location.search);
  const HARNESS_TOKEN = params.get('token') || '';

  async function post(path, args) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-harness-token': HARNESS_TOKEN },
      body: JSON.stringify(args || {}),
    });
    const json = await res.json();
    if (!res.ok) throw json.error || 'request failed';
    return json.ok;
  }

  function host(cmd, args) {
    return TAURI ? TAURI.core.invoke(cmd, args || {}) : post('/host/' + cmd, args);
  }

  function call(cmd, args) {
    return TAURI ? TAURI.core.invoke('node', { cmd, args: args || {} }) : post('/api/' + cmd, args);
  }

  function onEvent(handler) {
    if (TAURI) {
      TAURI.event.listen('securetext://event', (e) => handler(e.payload));
    } else {
      const source = new EventSource('/events?token=' + encodeURIComponent(HARNESS_TOKEN));
      source.onmessage = (e) => handler(JSON.parse(e.data));
    }
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
  const errText = (e) => (typeof e === 'string' ? e : (e && e.message) || String(e));

  function hue(key) {
    let h = 0;
    for (const ch of String(key || '')) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    return 'hue-' + (h % 8);
  }
  function initials(name) {
    const parts = String(name || '?').trim().split(/\s+/).filter(Boolean);
    const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : (parts[0] || '?')[0];
    return letters.toUpperCase();
  }
  const STATUS_LABEL = { online: 'Online', away: 'Away', dnd: 'Do not disturb', offline: 'Not connected' };
  function avatar(name, key, online, small) {
    // `online` may be a boolean or a status string.
    const status = typeof online === 'string' ? online : online ? 'online' : 'offline';
    const dot = online === undefined ? '' : `<span class="dot ${status === 'offline' ? '' : 'on'} st-${esc(status)}" title="${esc(STATUS_LABEL[status] || status)}"></span>`;
    return `<div class="avatar ${small ? 'small' : ''} ${hue(key)}" aria-hidden="true">${esc(initials(name))}${dot}</div>`;
  }
  const fmtTime = (ms) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const fmtDay = (ms) => new Date(ms).toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });
  const sameDay = (a, b) => new Date(a).toDateString() === new Date(b).toDateString();

  function toast(message, kind) {
    const el = document.createElement('div');
    el.className = 'toast' + (kind === 'error' ? ' error' : '');
    el.textContent = message;
    $('#toasts').appendChild(el);
    setTimeout(() => el.remove(), kind === 'error' ? 7000 : 4500);
  }

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------
  const state = {
    status: null,
    convs: [],
    contacts: [],
    online: new Set(),
    view: { mode: 'home', serverId: null, convId: null },
    lastChannel: {},
    msgs: {},
    unread: {},
    members: [],
    update: null,
    call: null,
    turn: [],
    thread: null,        // root message id of the open thread
    presence: {},        // key -> { status, text }
    myPresence: { status: 'online', text: '' },
    images: {},          // file id -> data: URL (downloaded images)
  };

  const conv = (id) => state.convs.find((c) => c.id === id);
  const servers = () => state.convs.filter((c) => c.kind === 'server');
  const dms = () => state.convs.filter((c) => c.kind === 'dm');
  const channelsOf = (sid) => state.convs.filter((c) => c.kind === 'channel' && c.server_id === sid);
  const peerLabel = (key) => (state.contacts.find((c) => c.key === key) || {}).label;

  // ------------------------------------------------------------------
  // Lock screen
  // ------------------------------------------------------------------
  async function boot() {
    let info;
    try {
      info = await host('profile_info');
    } catch (e) {
      $('#lock').hidden = false;
      $('#lock-error').textContent = errText(e);
      return;
    }
    if (info.unlocked) return enterApp();
    $('#lock').hidden = false;
    if (info.exists) {
      $('#unlock-form').hidden = false;
      $('#lock-sub').textContent = 'Enter your passphrase to open your encrypted profile.';
      $('#unlock-pass').focus();
    } else {
      $('#create-form').hidden = false;
      $('#create-name').focus();
    }
  }

  async function unlock(label, passphrase) {
    $('#lock-error').textContent = '';
    $('#lock-busy').hidden = false;
    document.querySelectorAll('#lock button').forEach((b) => (b.disabled = true));
    try {
      await host('unlock', { label, passphrase });
      $('#lock').hidden = true;
      await enterApp();
    } catch (e) {
      $('#lock-error').textContent = /passphrase|decrypt/i.test(errText(e))
        ? 'That passphrase didn’t open this profile.'
        : errText(e);
    } finally {
      $('#lock-busy').hidden = true;
      document.querySelectorAll('#lock button').forEach((b) => (b.disabled = false));
    }
  }

  $('#unlock-form').addEventListener('submit', (e) => {
    e.preventDefault();
    unlock('', $('#unlock-pass').value);
  });
  $('#create-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const pass = $('#create-pass').value;
    if (pass !== $('#create-pass2').value) {
      $('#lock-error').textContent = 'The passphrases don’t match.';
      return;
    }
    unlock($('#create-name').value.trim(), pass);
  });

  // ------------------------------------------------------------------
  // App
  // ------------------------------------------------------------------
  async function enterApp() {
    $('#app').hidden = false;
    onEvent(handleEvent);
    await Promise.all([refreshStatus(), refreshConvs(), refreshContacts(), refreshUpdate(), refreshCall()]);
    const open = params.get('open');
    if (open && conv(open)) await select(conv(open));
    else render();
    if (params.get('modal') === 'network') showNetworkModal();
    setInterval(refreshStatus, 10000);
  }

  async function refreshStatus() {
    const before = state.status && state.status.network.state;
    try {
      state.status = await call('status');
    } catch (e) {
      return;
    }
    renderMe();
    renderNet();
    // The home screen's "get my invite link" depends on Tor being ready.
    if (before !== state.status.network.state && !state.view.convId) renderMain();
  }

  async function refreshUpdate() {
    try {
      state.update = await call('update_status');
    } catch (e) {
      state.update = null;
    }
    renderUpdate();
  }

  async function refreshConvs() {
    state.convs = await call('conversations');
  }

  async function refreshContacts() {
    state.contacts = await call('contacts');
    state.contacts.forEach((c) => {
      if (c.online) state.online.add(c.key);
      else state.online.delete(c.key);
      state.presence[c.key] = { status: c.status, text: c.status_text };
    });
  }

  async function refreshMembers() {
    const id = state.view.convId;
    if (!id) {
      state.members = [];
    } else {
      try {
        state.members = await call('members', { conversationId: id });
      } catch (e) {
        state.members = [];
      }
    }
    renderMembers();
  }

  async function select(c) {
    if (!c) return;
    if (c.kind === 'server') {
      const chans = channelsOf(c.id);
      const last = state.lastChannel[c.id];
      c = chans.find((x) => x.id === last) || chans[0] || c;
    }
    const serverId = c.kind === 'channel' ? c.server_id : c.kind === 'server' ? c.id : null;
    state.view = { mode: serverId ? 'server' : 'home', serverId, convId: c.id };
    state.thread = null;
    if (serverId) state.lastChannel[serverId] = c.id;
    state.unread[c.id] = 0;
    render();
    if (c.kind !== 'server') {
      state.msgs[c.id] = await call('messages', { conversationId: c.id, limit: 300 });
      if (state.view.convId === c.id) renderMessages(true);
    }
    refreshMembers();
    $('#composer-input').focus();
  }

  function goHome() {
    state.view = { mode: 'home', serverId: null, convId: null };
    state.thread = null;
    render();
    refreshMembers();
  }

  async function handleEvent(ev) {
    switch (ev.type) {
      case 'network':
        refreshStatus();
        break;
      case 'conversations_changed': {
        await refreshConvs();
        await refreshContacts();
        render();
        refreshMembers();
        break;
      }
      case 'members_changed':
        if (ev.conversation_id === state.view.convId || ev.conversation_id === state.view.serverId) refreshMembers();
        break;
      case 'message': {
        const list = state.msgs[ev.conversation_id];
        if (list && !list.some((m) => m.id === ev.message.id)) list.push(ev.message);
        if (ev.conversation_id === state.view.convId) renderThread();
        if (ev.conversation_id === state.view.convId && document.hasFocus()) {
          renderMessages(false);
        } else {
          state.unread[ev.conversation_id] = (state.unread[ev.conversation_id] || 0) + 1;
          if (ev.conversation_id === state.view.convId) renderMessages(false);
          renderRail();
          renderSidebar();
        }
        break;
      }
      case 'message_updated': {
        const list = state.msgs[ev.conversation_id];
        if (list) {
          const i = list.findIndex((m) => m.id === ev.message.id);
          if (i >= 0) list[i] = ev.message;
          if (ev.conversation_id === state.view.convId) { renderMessages(false); renderThread(); }
        }
        break;
      }
      case 'messages_deleted': {
        const list = state.msgs[ev.conversation_id];
        if (list) {
          state.msgs[ev.conversation_id] = list.filter((m) => !ev.ids.includes(m.id));
          if (state.thread && ev.ids.includes(state.thread)) state.thread = null;
          if (ev.conversation_id === state.view.convId) { renderMessages(false); renderThread(); }
        }
        break;
      }
      case 'presence':
        state.presence[ev.key] = { status: ev.status, text: ev.text };
        renderSidebar();
        refreshMembers();
        break;
      case 'message_status': {
        const m = (state.msgs[ev.conversation_id] || []).find((x) => x.id === ev.id);
        if (m) {
          m.status = ev.status;
          if (ev.conversation_id === state.view.convId) { renderMessages(false); renderThread(); }
        }
        break;
      }
      case 'update':
        state.update = ev.status;
        renderUpdate();
        break;
      case 'call':
        onCallEvent(ev.call, ev.ended);
        break;
      case 'call_video':
        showRemoteFrame(ev.peer_key, ev.jpeg);
        break;
      case 'peer':
        if (ev.online) state.online.add(ev.key);
        else state.online.delete(ev.key);
        renderSidebar();
        refreshMembers();
        refreshStatus();
        break;
    }
  }

  window.addEventListener('focus', () => {
    if (state.view.convId && state.unread[state.view.convId]) {
      state.unread[state.view.convId] = 0;
      renderRail();
      renderSidebar();
    }
  });

  // ------------------------------------------------------------------
  // Rendering
  // ------------------------------------------------------------------
  function render() {
    renderRail();
    renderSidebar();
    renderMain();
    renderMe();
    renderNet();
  }

  function renderRail() {
    $('#rail-home').classList.toggle('active', state.view.mode === 'home');
    const dmUnread = dms().reduce((n, c) => n + (state.unread[c.id] || 0), 0);
    $('#rail-home').innerHTML = `<span class="rail-glyph" aria-hidden="true">✉</span>${dmUnread ? `<span class="badge">${dmUnread}</span>` : ''}`;
    $('#rail-servers').innerHTML = servers().map((s) => {
      const unread = channelsOf(s.id).reduce((n, c) => n + (state.unread[c.id] || 0), 0);
      const active = state.view.serverId === s.id;
      return `<button class="rail-btn ${active ? 'active' : ''}" data-server="${esc(s.id)}" title="${esc(s.name)}" aria-label="${esc(s.name)}">
        ${esc(initials(s.name))}${unread ? `<span class="badge">${unread}</span>` : ''}</button>`;
    }).join('');
  }

  function renderSidebar() {
    const head = $('#sidebar-head');
    const body = $('#sidebar-body');
    if (state.view.mode === 'home') {
      head.innerHTML = '<span class="title">Direct messages</span>';
      const list = dms().map((c) => {
        const online = state.online.has(c.peer_key);
        const unread = state.unread[c.id] || 0;
        const active = state.view.convId === c.id;
        const pres = online ? ((state.presence[c.peer_key] || {}).status || 'online') : 'offline';
        return `<button class="item ${active ? 'active' : ''} ${unread ? 'unread' : ''}" data-conv="${esc(c.id)}">
          ${avatar(c.name, c.peer_key, pres, true)}
          <span class="grow">${esc(c.name)}</span>
          ${unread ? `<span class="count">${unread}</span>` : ''}</button>`;
      }).join('');
      body.innerHTML = `
        <div class="side-actions">
          <button class="btn" data-action="add-contact">＋ Add a contact</button>
          <button class="btn" data-action="my-invite">⤴ Share my invite link</button>
        </div>
        <div class="section-label">Direct messages</div>
        ${list || '<div class="empty-note">No conversations yet. Share your invite link or paste someone else’s to start one.</div>'}`;
      return;
    }
    const server = conv(state.view.serverId);
    if (!server) return goHome();
    const admin = server.is_admin && !server.removed;
    head.innerHTML = `<span class="title">${esc(server.name)}</span>
      ${admin ? '<button class="btn small primary" data-action="invite-server">Invite</button>' : ''}`;
    const chans = channelsOf(server.id).map((c) => {
      const unread = state.unread[c.id] || 0;
      const active = state.view.convId === c.id;
      return `<button class="item ${active ? 'active' : ''} ${unread ? 'unread' : ''} ${c.removed ? 'removed' : ''}" data-conv="${esc(c.id)}">
        <span class="hash" aria-hidden="true">${c.private ? '🔒︎' : '#'}</span>
        <span class="grow">${esc(c.name)}</span>
        ${unread ? `<span class="count">${unread}</span>` : ''}</button>`;
    }).join('');
    body.innerHTML = `
      <div class="section-label">Text channels
        ${admin ? '<button class="icon-btn" data-action="new-channel" title="Create channel" aria-label="Create channel">+</button>' : ''}</div>
      ${chans || '<div class="empty-note">No channels.</div>'}
      ${server.removed ? '<div class="empty-note">You were removed from this server. History stays readable on this device.</div>' : ''}`;
  }

  function renderMain() {
    const c = conv(state.view.convId);
    const title = $('#main-title');
    renderHeadActions(c);
    if (!c) {
      $('#thread-panel').hidden = true;
      $('#app').classList.remove('thread-open');
      title.innerHTML = '<span>Home</span>';
      $('#messages').innerHTML = welcomeHtml();
      $('#composer').hidden = true;
      $('#composer-note').hidden = true;
      $('#members-panel').hidden = true;
      return;
    }
    $('#members-panel').hidden = false;
    if (c.kind === 'dm') {
      title.innerHTML = `<span class="hash">@</span><span>${esc(c.name)}</span>`;
    } else {
      const server = conv(c.server_id);
      title.innerHTML = `<span class="hash">${c.private ? '🔒︎' : '#'}</span><span>${esc(c.name)}</span>
        ${c.private ? '<span class="tag">Private</span>' : ''}
        ${server ? `<span class="sub">· ${esc(server.name)}</span>` : ''}`;
    }
    const removed = c.removed || (c.server_id && conv(c.server_id) && conv(c.server_id).removed);
    $('#composer').hidden = !!removed;
    $('#composer-note').hidden = !removed;
    $('#composer-note').textContent = removed
      ? 'You’re no longer a member here, so you can’t send or receive new messages. Earlier history stays on this device.'
      : '';
    $('#composer-input').placeholder = c.kind === 'dm' ? `Message @${c.name}` : `Message #${c.name}`;
    renderMessages(true);
    renderThread();
  }

  function welcomeHtml() {
    const ready = state.status && state.status.network.state === 'ready';
    return `<div class="welcome">
      <h2>Welcome${state.status ? ', ' + esc(state.status.label) : ''}</h2>
      <p>There’s no account and no central server here. You reach people directly, over Tor, using invite links.</p>
      <ol class="steps">
        <li><div><strong>Share your invite link</strong>
          <span>Send it to a friend over a channel you already trust (in person, or another secure app). Each link starts one conversation.</span><br>
          <button class="btn small primary" data-action="my-invite" ${ready ? '' : 'disabled'}>${ready ? 'Get my invite link' : 'Waiting for Tor…'}</button></div></li>
        <li><div><strong>Or paste theirs</strong>
          <span>If a friend sent you a link, add them as a contact to open a private conversation.</span><br>
          <button class="btn small" data-action="add-contact">Add a contact</button></div></li>
        <li><div><strong>Start a server</strong>
          <span>Group chat with channels. Invite contacts, make private channels, and remove people. Only you, as the creator, can change who’s in it.</span><br>
          <button class="btn small" data-action="new-server">Create a server</button></div></li>
      </ol>
    </div>`;
  }

  const QUICK_REACTIONS = ['👍', '❤️', '😂', '😮', '😢', '🎉'];

  function fmtSize(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(0) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  function attachmentHtml(a) {
    if (!a) return '';
    if (a.image && a.state === 'complete') {
      const src = state.images[a.file_id];
      if (!src) loadImage(a.file_id);
      return `<div class="attachment image">${src ? `<img src="${esc(src)}" alt="${esc(a.name)}">` : '<span class="sub">Loading image…</span>'}
        <button class="btn small ghost" data-save="${esc(a.file_id)}">Save</button></div>`;
    }
    let action = '';
    if (a.state === 'available') action = `<button class="btn small" data-download="${esc(a.file_id)}">Download</button>`;
    else if (a.state === 'downloading') action = `<span class="sub">Downloading over Tor… ${a.total ? Math.floor((100 * a.received) / a.total) : 0}%</span>`;
    else if (a.state === 'complete') action = `<button class="btn small" data-save="${esc(a.file_id)}">Save to Downloads</button>`;
    else action = `<span class="sub">Download failed</span> <button class="btn small ghost" data-download="${esc(a.file_id)}">Retry</button>`;
    return `<div class="attachment file"><span class="file-icon" aria-hidden="true">📄︎</span>
      <div class="grow"><div class="name">${esc(a.name)}</div><div class="sub">${esc(fmtSize(a.size))}</div></div>${action}</div>`;
  }

  async function loadImage(fileId) {
    if (state.images[fileId] !== undefined) return;
    state.images[fileId] = '';
    try {
      const d = await call('attachment_data', { fileId });
      state.images[fileId] = `data:${d.mime};base64,${d.data}`;
      renderMessages(false);
      renderThread();
    } catch (_) {
      delete state.images[fileId];
    }
  }

  function reactionsHtml(m) {
    if (!m.reactions || !m.reactions.length) return '';
    return `<div class="reactions">${m.reactions.map((r) => `<button class="reaction ${r.mine ? 'mine' : ''}" data-react="${esc(r.emoji)}" data-msg="${esc(m.id)}" data-on="${r.mine ? '0' : '1'}" title="${esc(r.by.join(', '))}">${esc(r.emoji)} ${r.count}</button>`).join('')}</div>`;
  }

  // Thread sizes come from the messages we hold, so a reply counts once
  // however its news arrives (our own send, or the node's update event).
  function replyCount(c, m) {
    return (state.msgs[c.id] || []).filter((x) => x.reply_to === m.id).length || m.reply_count || 0;
  }

  function messageHtml(c, m, first, inThread) {
    if (m.status === 'system') {
      return `<div class="msg system"><div class="gutter"></div><div class="body note">⏱︎ ${esc(m.sender_label)} ${esc(m.body)}</div></div>`;
    }
    const pending = m.outgoing && m.status === 'pending';
    const relayed = m.outgoing && m.status === 'relayed';
    const timer = m.expires_at ? `<span class="expires" title="Disappears ${esc(new Date(m.expires_at).toLocaleString())}">⏱︎</span>` : '';
    return `<div class="msg ${first ? 'first' : ''} ${pending ? 'pending' : ''}" data-id="${esc(m.id)}">
        <div class="gutter">${first ? avatar(m.sender_label, m.sender_key, undefined) : `<span class="time-hover">${esc(fmtTime(m.sent_at))}</span>`}</div>
        <div>
          ${first ? `<div class="head"><span class="who">${esc(m.sender_label)}</span><span class="when">${esc(fmtTime(m.sent_at))}</span>${timer}</div>` : ''}
          ${m.body ? `<div class="body">${esc(m.body)}</div>` : ''}
          ${attachmentHtml(m.attachment)}
          ${reactionsHtml(m)}
          ${!inThread && replyCount(c, m) ? `<button class="thread-link" data-thread="${esc(m.id)}">${replyCount(c, m)} ${replyCount(c, m) === 1 ? 'reply' : 'replies'} →</button>` : ''}
          ${pending ? `<div class="status pending">◷ Queued on this device — sends automatically when ${c.kind === 'dm' ? esc(c.name) + ' is' : 'members are'} reachable over Tor</div>` : ''}
          ${relayed ? `<div class="status relayed">✓ Left at ${c.kind === 'dm' ? esc(c.name) + '’s' : 'an offline member’s'} relay — delivered when they’re next online</div>` : ''}
        </div>
        <div class="msg-actions">
          <button class="icon-btn" data-react-menu="${esc(m.id)}" title="Add a reaction" aria-label="Add a reaction">☺︎</button>
          ${inThread ? '' : `<button class="icon-btn" data-thread="${esc(m.id)}" title="Reply in thread" aria-label="Reply in thread">↩︎</button>`}
        </div></div>`;
  }

  function renderMessages(forceBottom) {
    const c = conv(state.view.convId);
    const box = $('#messages');
    if (!c || c.kind === 'server') return;
    const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    // Thread replies live in the thread panel, not the main timeline.
    const list = (state.msgs[c.id] || []).filter((m) => !m.reply_to);
    let html = introHtml(c);
    let prev = null;
    for (const m of list) {
      if (!prev || !sameDay(prev.sent_at, m.sent_at)) html += `<div class="day-sep">${esc(fmtDay(m.sent_at))}</div>`;
      const first = !prev || prev.status === 'system' || prev.sender_key !== m.sender_key || m.sent_at - prev.sent_at > 5 * 60 * 1000 || !sameDay(prev.sent_at, m.sent_at);
      html += messageHtml(c, m, first, false);
      prev = m;
    }
    box.innerHTML = html;
    if (forceBottom || nearBottom) box.scrollTop = box.scrollHeight;
  }

  function renderThread() {
    const panel = $('#thread-panel');
    const c = conv(state.view.convId);
    const root = c && state.thread && (state.msgs[c.id] || []).find((m) => m.id === state.thread);
    if (!root) {
      panel.hidden = true;
      $('#app').classList.remove('thread-open');
      $('#members-panel').hidden = !c;
      return;
    }
    panel.hidden = false;
    $('#app').classList.add('thread-open');
    $('#members-panel').hidden = true;
    const replies = (state.msgs[c.id] || []).filter((m) => m.reply_to === root.id);
    $('#thread-body').innerHTML = messageHtml(c, root, true, true)
      + `<div class="day-sep">${replies.length} ${replies.length === 1 ? 'reply' : 'replies'}</div>`
      + replies.map((m) => messageHtml(c, m, true, true)).join('');
    const body = $('#thread-body');
    body.scrollTop = body.scrollHeight;
  }

  function openThread(id) {
    state.thread = id;
    renderThread();
    $('#thread-input').focus();
  }

  function showReactionMenu(button, messageId) {
    document.querySelectorAll('.react-menu').forEach((e) => e.remove());
    const menu = document.createElement('div');
    menu.className = 'react-menu';
    menu.innerHTML = QUICK_REACTIONS.map((e) => `<button data-react="${e}" data-msg="${esc(messageId)}" data-on="1">${e}</button>`).join('');
    button.parentElement.appendChild(menu);
    setTimeout(() => document.addEventListener('click', () => menu.remove(), { once: true }), 0);
  }

  async function react(messageId, emoji, on) {
    try {
      const updated = await call('react', { conversationId: state.view.convId, messageId, emoji, on });
      const list = state.msgs[state.view.convId] || [];
      const i = list.findIndex((m) => m.id === updated.id);
      if (i >= 0) list[i] = updated;
      renderMessages(false);
      renderThread();
    } catch (e) {
      toast(errText(e), 'error');
    }
  }

  async function sendFile(file) {
    const id = state.view.convId;
    if (!id || !file) return;
    if (file.size > 25 * 1024 * 1024) return toast('Files are limited to 25 MB.', 'error');
    const data = await new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(String(r.result).slice(String(r.result).indexOf(',') + 1));
      r.onerror = () => reject(r.error);
      r.readAsDataURL(file);
    });
    try {
      const m = await call('send_file', { conversationId: id, name: file.name, mime: file.type, data, caption: '', replyTo: null });
      const list = state.msgs[id] || (state.msgs[id] = []);
      if (!list.some((x) => x.id === m.id)) list.push(m);
      renderMessages(true);
    } catch (e) {
      toast(errText(e), 'error');
    }
  }

  const TIMER_CHOICES = [[null, 'Off'], [3600, '1 hour'], [86400, '1 day'], [604800, '1 week']];
  function showTimerSettings() {
    const c = conv(state.view.convId);
    if (!c) return;
    modal(`<h3>Disappearing messages</h3>
      <p class="lead">New messages in ${c.kind === 'dm' ? 'this conversation' : '#' + esc(c.name)} delete themselves from everyone’s device after the time you pick, counted from when each one arrives.</p>
      <div class="pick-list">${TIMER_CHOICES.map(([secs, label]) => `<label class="check pick"><input type="radio" name="timer" value="${secs ?? ''}" ${(c.disappear_secs ?? null) === secs ? 'checked' : ''}> ${label}</label>`).join('')}</div>
      <p class="fineprint">It’s enforced by everyone’s SecureText app, so a modified app, a screenshot or a copy can still keep a message. Earlier messages keep their own timer.</p>
      <p class="form-error" id="m-err"></p>
      <div class="actions"><button class="btn ghost" data-close>Cancel</button><button class="btn primary" id="m-go">Save</button></div>`,
    (root, close) => {
      $('#m-go', root).addEventListener('click', async (e) => {
        const v = root.querySelector('input[name=timer]:checked');
        const secs = v && v.value ? Number(v.value) : null;
        busy(e.target, true);
        try {
          await call('set_disappearing', { conversationId: c.id, secs });
          close();
          await refreshConvs();
          renderMain();
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
          busy(e.target, false);
        }
      });
    });
  }

  function showStatusPicker() {
    const p = state.myPresence;
    modal(`<h3>Your status</h3>
      <p class="lead">Shown to the contacts and server members you’re connected to right now. It’s never stored on their devices or left at a relay.</p>
      <div class="pick-list">${['online', 'away', 'dnd'].map((st) => `<label class="check pick"><input type="radio" name="st" value="${st}" ${p.status === st ? 'checked' : ''}> <span class="dot on st-${st}"></span> ${STATUS_LABEL[st]}</label>`).join('')}</div>
      <label>Status message<input id="m-text" maxlength="80" placeholder="What are you up to?" value="${esc(p.text)}"></label>
      <p class="form-error" id="m-err"></p>
      <div class="actions"><button class="btn ghost" data-close>Cancel</button><button class="btn primary" id="m-go">Save</button></div>`,
    (root, close) => {
      $('#m-go', root).addEventListener('click', async (e) => {
        const status = root.querySelector('input[name=st]:checked').value;
        busy(e.target, true);
        try {
          const [st, text] = await call('set_presence', { status, text: $('#m-text', root).value });
          state.myPresence = { status: st, text };
          close();
          renderMe();
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
          busy(e.target, false);
        }
      });
    });
  }

  function introHtml(c) {
    if (c.kind === 'dm') {
      return `<div class="intro">${avatar(c.name, c.peer_key, state.online.has(c.peer_key))}
        <h2>${esc(c.name)}</h2>
        <p>This is the start of your end-to-end encrypted conversation. Only you and ${esc(c.name)} can read it.</p>
        <div class="keyline">Their identity key: ${esc(c.peer_key || '')}</div></div>`;
    }
    return `<div class="intro"><h2>${c.private ? '🔒︎ ' : '# '}${esc(c.name)}</h2>
      <p>${c.private
        ? 'A private channel. It has its own encryption keys, so server members who weren’t added can’t read it, even with access to their own device’s data.'
        : 'The start of this channel. Every member of the server is in it.'}</p></div>`;
  }

  function renderMembers() {
    const panel = $('#members');
    const c = conv(state.view.convId);
    if (!c) {
      panel.innerHTML = '';
      return;
    }
    const server = c.server_id ? conv(c.server_id) : null;
    const canKick = server && server.is_admin && !server.removed;
    const showAdmin = c.kind !== 'dm'; // a DM's "admin" is just whoever started it
    const scopeRemoved = c.removed || (server && server.removed);
    if (scopeRemoved) {
      $('#members-title').textContent = 'Members';
      panel.innerHTML = '<div class="empty-note">You were removed, so this list is no longer kept up to date.</div>';
      return;
    }
    const online = state.members.filter((m) => m.online).length;
    $('#members-title').textContent = `Members — ${online}/${state.members.length} connected`;
    panel.innerHTML = state.members.map((m) => `
      <div class="member ${m.online ? '' : 'offline'}">
        ${avatar(m.label, m.key, m.status || (m.online ? 'online' : 'offline'), true)}
        <div class="grow">
          <div class="name">${esc(m.label)}${m.is_me ? ' <span class="sub">(you)</span>' : ''} ${showAdmin && m.is_admin ? '<span class="crown" title="Server admin">♛</span>' : ''}</div>
          ${m.status_text ? `<div class="sub status-text">${esc(m.status_text)}</div>` : ''}
          <div class="sub" title="Identity key fingerprint">${esc(m.fingerprint)}</div>
        </div>
        ${canKick && !m.is_me ? `<button class="btn small ghost kick" data-kick="${esc(m.key)}" data-name="${esc(m.label)}" title="Remove from server">Remove</button>` : ''}
      </div>`).join('');
  }

  function renderMe() {
    const s = state.status;
    if (!s) return;
    $('#me-name').textContent = s.label;
    const p = state.myPresence;
    $('#me-fp').textContent = p.text || STATUS_LABEL[p.status] || s.fingerprint;
    $('#me-status').title = `Set your status (identity key ${s.fingerprint})`;
    $('#me-avatar').className = 'avatar ' + hue(s.public_key);
    $('#me-avatar').innerHTML = `${esc(initials(s.label))}<span class="dot on st-${esc(p.status)}"></span>`;
  }

  function renderNet() {
    const s = state.status;
    const pill = $('#net-pill');
    const banner = $('#net-banner');
    const net = s ? s.network : { state: 'starting' };
    pill.className = 'net-pill';
    if (net.state === 'ready') {
      pill.classList.add('ready');
      pill.innerHTML = '<span class="onion" aria-hidden="true"></span><span class="label">Tor · onion-routed</span><span class="state-dot"></span>';
      pill.title = 'Connected to the Tor network. Click for details.';
      banner.hidden = true;
    } else if (net.state === 'error') {
      pill.classList.add('error');
      pill.innerHTML = '<span class="onion" aria-hidden="true"></span><span class="label">Tor unavailable</span><span class="state-dot"></span>';
      banner.hidden = false;
      banner.className = 'net-banner error';
      banner.textContent = `Couldn’t connect to the Tor network (${net.detail}). Messages you write will wait on this device. SecureText never falls back to a direct connection.`;
    } else {
      pill.classList.add('connecting');
      pill.innerHTML = '<span class="onion" aria-hidden="true"></span><span class="label">Connecting to Tor…</span><span class="state-dot"></span>';
      banner.hidden = false;
      banner.className = 'net-banner';
      banner.textContent = 'Connecting to the Tor network. This usually takes under a minute. You can read and write now; messages send once connected.';
    }
  }

  // ------------------------------------------------------------------
  // Calls (Phase 7): the one feature that doesn't go over Tor, so every
  // call starts with a plain statement of what that means.
  // ------------------------------------------------------------------
  const video = { stream: null, timer: null, source: 'camera' };

  async function refreshCall() {
    try {
      state.call = await call('call_status');
    } catch (e) {
      state.call = null;
    }
    renderCall();
  }

  function renderHeadActions(c) {
    const box = $('#head-actions');
    const can = c && c.kind !== 'server' && !c.removed && !state.call;
    const timerAllowed = c && !c.removed && (c.kind === 'dm' || (c.kind === 'channel' && c.is_admin));
    const timer = c && c.kind !== 'server' && !c.removed
      ? `<button class="icon-btn ${c.disappear_secs ? 'on' : ''}" data-action="timer" ${timerAllowed ? '' : 'disabled'}
          title="${c.disappear_secs ? 'Messages disappear after ' + esc(TIMER_CHOICES.find(([s]) => s === c.disappear_secs)?.[1] || c.disappear_secs + ' s') : 'Disappearing messages: off'}${timerAllowed ? '' : ' (only the admin can change this)'}"
          aria-label="Disappearing messages">⏱︎</button>`
      : '';
    box.innerHTML = timer + (can
      ? `<button class="icon-btn" data-action="call-voice" title="Start a voice call" aria-label="Start a voice call">📞︎</button>
         <button class="icon-btn" data-action="call-video" title="Start a video call" aria-label="Start a video call">🎥︎</button>`
      : '');
  }

  function disclosureHtml(turnWho) {
    return `<div class="explain disclosure">
        <p><strong>Calls don’t go through Tor.</strong> Voice and video need a faster connection than Tor can give, so a call travels over the regular internet through a relay server (TURN).</p>
        <p><strong>Who can see what.</strong> The relay’s operator${turnWho ? ` (${esc(turnWho)})` : ''} can see your IP address and that you’re on a call. The other people on the call can’t: they only ever see the relay’s address.</p>
        <p><strong>What stays private.</strong> What you say and show is end-to-end encrypted. The relay can’t hear or see it. Your messages aren’t affected; they always go over Tor.</p>
      </div>`;
  }

  function confirmStartCall(withVideo) {
    const c = conv(state.view.convId);
    if (!c) return;
    modal(`<h3>${withVideo ? 'Start a video call' : 'Start a call'} ${c.kind === 'dm' ? 'with ' + esc(c.name) : 'in #' + esc(c.name)}?</h3>
      ${disclosureHtml('the server you set in Settings → Calls')}
      <p class="form-error" id="m-err"></p>
      <div class="actions"><button class="btn ghost" data-close>Cancel</button><button class="btn primary" id="m-go">Start call</button></div>`,
    (root, close) => {
      $('#m-go', root).addEventListener('click', async (e) => {
        busy(e.target, true);
        try {
          state.call = await call('start_call', { conversationId: c.id, video: withVideo });
          close();
          renderCall();
          if (withVideo) startCamera();
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
          busy(e.target, false);
        }
      });
    });
  }

  function showIncomingCall(cv) {
    const where = conv(cv.conversation_id);
    const place = where && where.kind === 'channel' ? ` in #${esc(where.name)}` : '';
    modal(`<h3>${esc(cv.caller_label)} is calling${place}${cv.video ? ' (video)' : ''}</h3>
      ${disclosureHtml(cv.turn === 'yours' ? 'the server you set in Settings → Calls' : 'the caller’s relay, since you haven’t set your own')}
      <p class="form-error" id="m-err"></p>
      <div class="actions"><button class="btn danger" id="m-decline">Decline</button><button class="btn primary" id="m-accept">Join call</button></div>`,
    (root, close) => {
      root.dataset.incoming = cv.call_id;
      $('#m-decline', root).addEventListener('click', async () => {
        close();
        try { await call('decline_call'); } catch (_) { /* already gone */ }
      });
      $('#m-accept', root).addEventListener('click', async (e) => {
        busy(e.target, true);
        try {
          state.call = await call('accept_call');
          close();
          renderCall();
          if (cv.video) startCamera();
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
          busy(e.target, false);
        }
      });
    });
  }

  function onCallEvent(cv, ended) {
    const before = state.call;
    state.call = cv;
    if (cv && cv.state === 'incoming' && (!before || before.call_id !== cv.call_id)) showIncomingCall(cv);
    if (!cv) {
      const open = document.querySelector('#modal-root .modal[data-incoming]');
      if (open) $('#modal-root').innerHTML = '';
      stopCamera();
      if (ended && before) toast(`Call ended: ${ended}.`);
    }
    renderCall();
  }

  function renderCall() {
    const panel = $('#call-panel');
    const cv = state.call;
    renderHeadActions(conv(state.view.convId));
    if (!cv || cv.state === 'incoming') {
      panel.hidden = true;
      panel.innerHTML = '';
      return;
    }
    panel.hidden = false;
    const people = cv.participants.map((p) => `<div class="call-person ${p.state === 'connected' ? 'on' : ''}" data-peer="${esc(p.key)}">
        ${cv.video ? `<img class="tile" alt="" data-video="${esc(p.key)}">` : avatar(p.label, p.key, undefined)}
        <span class="who">${esc(p.label)}</span><span class="sub">${esc(p.state)}</span></div>`).join('');
    const status = cv.state === 'outgoing' ? 'Ringing…' : `${cv.participants.filter((p) => p.state === 'connected').length} connected`;
    panel.innerHTML = `<div class="call-head">
        <span class="call-dot"></span>
        <span class="grow"><strong>${cv.video ? 'Video call' : 'Call'}</strong> · ${esc(cv.conversation_name)} · ${esc(status)}</span>
        <span class="sub" title="Calls go through a TURN relay, not Tor">relayed via ${cv.turn === 'yours' ? 'your' : 'the caller’s'} TURN server</span>
      </div>
      <div class="call-people">
        ${cv.video ? `<div class="call-person self"><video id="self-view" class="tile" autoplay muted playsinline></video><span class="who">You${video.stream && video.source === 'screen' ? ' (screen)' : ''}</span></div>` : ''}
        ${people || '<div class="empty-note">Waiting for someone to join…</div>'}
      </div>
      <div class="call-controls">
        <button class="btn small" data-action="call-mute">${cv.muted ? 'Unmute' : 'Mute'}</button>
        ${cv.video ? `<button class="btn small" data-action="call-camera">${video.stream && video.source === 'camera' ? 'Camera off' : 'Camera on'}</button>` : ''}
        ${cv.video && navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia ? `<button class="btn small" data-action="call-screen">${video.stream && video.source === 'screen' ? 'Stop sharing' : 'Share screen'}</button>` : ''}
        <button class="btn small danger" data-action="call-hangup">${cv.state === 'outgoing' ? 'Cancel' : 'Leave'}</button>
      </div>`;
    const self = $('#self-view');
    if (self && video.stream) self.srcObject = video.stream;
    for (const [key, src] of Object.entries(lastFrames)) {
      const img = panel.querySelector(`img[data-video="${CSS.escape(key)}"]`);
      if (img) img.src = src;
    }
  }

  const lastFrames = {};
  function showRemoteFrame(peerKey, jpegB64) {
    const src = 'data:image/jpeg;base64,' + jpegB64;
    lastFrames[peerKey] = src;
    const img = document.querySelector(`#call-panel img[data-video="${CSS.escape(peerKey)}"]`);
    if (img) img.src = src;
  }

  // Camera frames are captured here (the webview's camera access works on
  // every platform) and handed to the node as small JPEGs, which it seals
  // with the call key and sends over the relayed WebRTC connection.
  async function startCamera(source) {
    if (video.stream) return;
    video.source = source || 'camera';
    try {
      video.stream = video.source === 'screen'
        ? await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false })
        : await navigator.mediaDevices.getUserMedia({ video: { width: 320, height: 240 }, audio: false });
    } catch (e) {
      toast(`Couldn’t ${video.source === 'screen' ? 'share your screen' : 'open the camera'}: ${errText(e)}`, 'error');
      return;
    }
    // Sharing stopped from the system's own controls.
    video.stream.getVideoTracks().forEach((t) => t.addEventListener('ended', () => { stopCamera(); renderCall(); }));
    const el = document.createElement('video');
    el.muted = true;
    el.playsInline = true;
    el.srcObject = video.stream;
    await el.play().catch(() => {});
    const canvas = $('#call-canvas');
    const ctx = canvas.getContext('2d');
    let sending = false;
    video.timer = setInterval(() => {
      if (sending || !state.call || state.call.state === 'incoming') return;
      ctx.drawImage(el, 0, 0, canvas.width, canvas.height);
      const data = canvas.toDataURL('image/jpeg', 0.6);
      const jpeg = data.slice(data.indexOf(',') + 1);
      if (jpeg.length > 76000) return; // the node refuses frames over 60 KiB
      sending = true;
      call('send_video_frame', { jpeg }).catch(() => {}).finally(() => { sending = false; });
    }, 100);
    renderCall();
  }

  function stopCamera() {
    if (video.timer) clearInterval(video.timer);
    video.timer = null;
    if (video.stream) video.stream.getTracks().forEach((t) => t.stop());
    video.stream = null;
  }

  async function callAction(action) {
    try {
      if (action === 'call-voice') return confirmStartCall(false);
      if (action === 'call-video') return confirmStartCall(true);
      if (action === 'call-mute') await call('set_call_muted', { muted: !state.call.muted });
      if (action === 'call-camera' || action === 'call-screen') {
        const wanted = action === 'call-screen' ? 'screen' : 'camera';
        const was = video.stream ? video.source : null;
        stopCamera();
        if (was !== wanted) await startCamera(wanted);
      }
      if (action === 'call-hangup') { stopCamera(); await call('hang_up'); state.call = null; }
      await refreshCall();
    } catch (e) {
      toast(errText(e), 'error');
    }
  }

  // ------------------------------------------------------------------
  // Updates (fetched over Tor, signature-checked by the node)
  // ------------------------------------------------------------------
  const RELEASES_URL = 'https://github.com/erietechsolutions/SecureText/releases';

  function updateLine(u) {
    if (!u) return 'Automatic updates aren’t available in this build.';
    switch (u.state) {
      case 'idle': return u.auto ? 'Checks automatically, over Tor, about once a day.' : 'Automatic checks are off.';
      case 'checking': return 'Checking for updates over Tor…';
      case 'up_to_date': return `Up to date (checked ${fmtTime(u.checked_at)}).`;
      case 'available': return u.installable
        ? `Version ${u.version} is available.`
        : `Version ${u.version} is available. This copy can’t update itself; get it from ${RELEASES_URL}`;
      case 'downloading': return `Downloading version ${u.version} over Tor…`;
      case 'ready': return `Version ${u.version} is downloaded and verified.`;
      case 'failed': return `The last check failed: ${u.error}`;
    }
    return '';
  }

  function renderUpdate() {
    const u = state.update;
    const banner = $('#update-banner');
    if (!u || !(u.state === 'ready' || (u.state === 'available' && !u.auto))) {
      banner.hidden = true;
      return;
    }
    banner.hidden = false;
    const action = u.state === 'ready'
      ? `<button class="btn small primary" data-action="apply-update">${u.system_installer ? 'Install…' : 'Restart to update'}</button>`
      : '<button class="btn small" data-action="settings">Details</button>';
    banner.innerHTML = `<span class="grow">SecureText ${esc(u.version)} ${u.state === 'ready' ? 'is ready to install.' : 'is available.'}</span>
      <button class="btn small ghost" data-action="update-notes">What’s new</button>${action}`;
  }

  function showUpdateNotes() {
    const u = state.update;
    if (!u || !u.version) return;
    modal(`<h3>What’s new in ${esc(u.version)}</h3>
      <div class="notes">${esc(u.notes || 'No release notes.')}</div>
      <p class="fineprint">Signed by the SecureText release key and checked on this device before installing. Downloaded over Tor.</p>
      <div class="actions"><button class="btn primary" data-close>Close</button></div>`);
  }

  async function applyUpdate(btn) {
    if (btn) busy(btn, true);
    try {
      const r = await host('apply_update');
      if (r.outcome === 'system_installer') {
        toast('Your system’s software installer will finish the update. Restart SecureText afterwards.');
      }
    } catch (e) {
      toast(errText(e), 'error');
    } finally {
      if (btn) busy(btn, false);
    }
  }

  // ------------------------------------------------------------------
  // Modals
  // ------------------------------------------------------------------
  function modal(html, mount) {
    const root = $('#modal-root');
    root.innerHTML = `<div class="modal-back"><div class="modal" role="dialog" aria-modal="true">${html}</div></div>`;
    const back = $('.modal-back', root);
    const close = () => {
      root.innerHTML = '';
      document.removeEventListener('keydown', onKey);
    };
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', onKey);
    back.addEventListener('mousedown', (e) => { if (e.target === back) close(); });
    root.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', close));
    if (mount) mount($('.modal', root), close);
    const first = root.querySelector('input, textarea, button.primary');
    if (first) first.focus();
    return close;
  }

  function busy(button, on) {
    button.disabled = on;
    if (on) {
      button.dataset.label = button.textContent;
      button.textContent = 'Working…';
    } else if (button.dataset.label) {
      button.textContent = button.dataset.label;
    }
  }

  function showNetworkModal() {
    const s = state.status || {};
    const net = s.network || {};
    modal(`<h3>How your messages travel</h3>
      <div class="explain">
        <p><strong>Encrypted end to end.</strong> Every message is encrypted on this device with keys only the people in the conversation hold (MLS). Nobody in between can read it.</p>
        <p><strong>Routed over Tor, always.</strong> Messages go through the Tor network straight to the other person’s onion address. No server sits in the middle, and neither side learns the other’s IP address. There’s no “direct” fallback.</p>
        <p><strong>Why it can feel slow.</strong> Tor bounces traffic through several relays. The first message to someone can take up to a minute while a route is built; after that, a few seconds each.</p>
        <p><strong>When someone is offline,</strong> your message waits on this device, marked “Queued”, and sends by itself once you’re both online.</p>
        <dl class="kv">
          <dt>Tor</dt><dd>${esc(net.state === 'ready' ? 'Connected' : net.state === 'error' ? 'Unavailable: ' + (net.detail || '') : 'Connecting…')}</dd>
          <dt>Your address</dt><dd>${esc(s.onion_address || 'not published yet')}</dd>
          <dt>Connected peers</dt><dd>${esc(s.online_peers ?? 0)}</dd>
          <dt>Offline relay</dt><dd>${esc(s.relay || 'none — messages to you wait until you’re both online')}</dd>
          <dt>Your key</dt><dd>${esc(s.public_key || '')}</dd>
        </dl>
      </div>
      <div class="actions"><button class="btn primary" data-close>Got it</button></div>`);
  }

  async function showSettings() {
    const s = state.status || {};
    const u = state.update;
    try { state.turn = await call('turn_servers'); } catch (_) { state.turn = []; }
    const t = state.turn[0] || { url: '', username: '', credential: '' };
    modal(`<h3>Settings</h3>
      <div class="settings-section">
        <h4>Offline delivery</h4>
        <p class="sub">${esc(s.relay ? 'Using a relay: messages sent while you’re away wait there.' : 'No relay: messages reach you only while you’re online at the same time as the sender.')}</p>
        <button class="btn small" id="s-relay">${s.relay ? 'Change relay…' : 'Set up a relay…'}</button>
      </div>
      <div class="settings-section">
        <h4>Calls</h4>
        <p class="sub">Calls are relayed through a TURN server over the regular internet, not Tor. Its operator can see your IP address, but not what’s said. Use one you trust, such as one you run yourself with <code>securetext-turn</code>. If you leave this empty, you can still join calls using the caller’s server.</p>
        <label>TURN server<input id="s-turn-url" spellcheck="false" placeholder="turn:turn.example.org:3478" value="${esc(t.url)}"></label>
        <div class="row">
          <label class="grow">Username<input id="s-turn-user" spellcheck="false" autocomplete="off" value="${esc(t.username)}"></label>
          <label class="grow">Password<input id="s-turn-pass" type="password" autocomplete="off" value="${esc(t.credential)}"></label>
        </div>
        <div class="row"><button class="btn small" id="s-turn-save">Save call relay</button></div>
      </div>
      <div class="settings-section">
        <h4>Updates</h4>
        <p class="sub" id="s-update-line">${esc(updateLine(u))}</p>
        ${u ? `<p class="sub">This is version ${esc(u.current_version)}.</p>
        <label class="check"><input type="checkbox" id="s-auto" ${u.auto ? 'checked' : ''}> Check for updates automatically</label>
        <p class="fineprint">Checks go to GitHub Releases through Tor, at random times, so they don’t reveal your IP address or form a pattern. An update is installed only if it’s signed by the SecureText release key, and only when you choose to restart.</p>
        <div class="row">
          <button class="btn small" id="s-check">Check now</button>
          ${u.state === 'available' && u.installable && !u.auto ? '<button class="btn small primary" id="s-download">Download</button>' : ''}
          ${u.state === 'ready' ? `<button class="btn small primary" data-action="apply-update">${u.system_installer ? 'Install…' : 'Restart to update'}</button>` : ''}
        </div>` : ''}
      </div>
      <p class="form-error" id="m-err"></p>
      <div class="actions"><button class="btn primary" data-close>Done</button></div>`,
    (root, close) => {
      $('#s-relay', root).addEventListener('click', () => { close(); showRelaySettings(); });
      $('#s-turn-save', root).addEventListener('click', async (e) => {
        const url = $('#s-turn-url', root).value.trim();
        const servers = url ? [{ url, username: $('#s-turn-user', root).value.trim(), credential: $('#s-turn-pass', root).value }] : [];
        busy(e.target, true);
        try {
          state.turn = await call('set_turn_servers', { servers });
          $('#m-err', root).textContent = '';
          toast(servers.length ? 'Call relay saved.' : 'Call relay removed.');
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
        } finally {
          busy(e.target, false);
        }
      });
      const auto = $('#s-auto', root);
      if (auto) auto.addEventListener('change', async () => {
        try {
          state.update = await call('set_auto_update', { enabled: auto.checked });
          $('#s-update-line', root).textContent = updateLine(state.update);
          renderUpdate();
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
        }
      });
      const check = $('#s-check', root);
      if (check) check.addEventListener('click', async () => {
        try {
          state.update = await call('check_for_updates');
          $('#s-update-line', root).textContent = updateLine(state.update);
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
        }
      });
      const dl = $('#s-download', root);
      if (dl) dl.addEventListener('click', async () => {
        try {
          state.update = await call('download_update');
          $('#s-update-line', root).textContent = updateLine(state.update);
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
        }
      });
    });
  }

  function showRelaySettings() {
    const current = (state.status && state.status.relay) || '';
    modal(`<h3>Offline delivery</h3>
      <p class="lead">Without a relay, a message only arrives when you and the sender are online at the same time. A relay is a mailbox on the Tor network that holds messages for you until you’re back.</p>
      <div class="explain">
        <p><strong>It can’t read anything.</strong> Messages are sealed before they reach it, and it only knows an anonymous mailbox number, never who you are or who wrote to you. It’s reachable only over Tor, so it never sees anyone’s IP address.</p>
        <p><strong>Use one you trust to stay up.</strong> Anyone can run one with <code>securetext-relay</code>. Your contacts learn your relay automatically; changing it starts a fresh, empty mailbox.</p>
      </div>
      <label>Relay address<input id="m-relay" spellcheck="false" placeholder="securetext-relay1:…" value="${esc(current)}"></label>
      <p class="form-error" id="m-err"></p>
      <div class="actions">
        ${current ? '<button class="btn ghost" id="m-clear">Stop using a relay</button>' : ''}
        <button class="btn ghost" data-close>Cancel</button>
        <button class="btn primary" id="m-go">Save</button>
      </div>`,
    (root, close) => {
      const save = async (btn, address) => {
        busy(btn, true);
        try {
          await call('set_relay', { address });
          close();
          await refreshStatus();
          toast(address ? 'Relay saved. Messages sent to you while you’re away will wait there.' : 'Relay removed.');
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
          busy(btn, false);
        }
      };
      $('#m-go', root).addEventListener('click', (e) => save(e.target, $('#m-relay', root).value.trim() || null));
      const clear = $('#m-clear', root);
      if (clear) clear.addEventListener('click', (e) => save(e.target, null));
    });
  }

  function showAddContact() {
    modal(`<h3>Add a contact</h3>
      <p class="lead">Paste the invite link your friend sent you. It starts a private, encrypted conversation between the two of you.</p>
      <textarea class="link" id="m-link" placeholder="securetext1:…" spellcheck="false"></textarea>
      <p class="form-error" id="m-err"></p>
      <div class="actions"><button class="btn ghost" data-close>Cancel</button><button class="btn primary" id="m-go">Add contact</button></div>`,
    (root, close) => {
      $('#m-go', root).addEventListener('click', async (e) => {
        const link = $('#m-link', root).value.trim();
        if (!link) return;
        busy(e.target, true);
        try {
          const id = await call('add_contact', { link });
          close();
          await refreshConvs();
          await refreshContacts();
          await select(conv(id));
          toast('Contact added. Your first message can take up to a minute while Tor builds a route.');
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
          busy(e.target, false);
        }
      });
    });
  }

  async function showMyInvite() {
    let link;
    try {
      link = await call('create_invite');
    } catch (e) {
      return toast(errText(e), 'error');
    }
    modal(`<h3>Your invite link</h3>
      <p class="lead">Send this to one person, over a channel you trust. Anyone holding it can start a conversation with you. Each link works once, so make a new one for each person.</p>
      <textarea class="link" id="m-link" readonly spellcheck="false">${esc(link)}</textarea>
      <div class="actions"><button class="btn ghost" data-close>Done</button><button class="btn primary" id="m-copy">Copy link</button></div>`,
    (root) => {
      $('#m-copy', root).addEventListener('click', async (e) => {
        const area = $('#m-link', root);
        try {
          await navigator.clipboard.writeText(area.value);
        } catch (_) {
          area.select();
          document.execCommand('copy');
        }
        e.target.textContent = 'Copied';
      });
    });
  }

  function showNewServer() {
    modal(`<h3>Create a server</h3>
      <p class="lead">A server is a group with channels. You’ll be its admin: the only one who can invite, remove, and make channels. It starts with a #general channel.</p>
      <label>Server name<input id="m-name" maxlength="64" placeholder="e.g. Book Club"></label>
      <p class="form-error" id="m-err"></p>
      <div class="actions"><button class="btn ghost" data-close>Cancel</button><button class="btn primary" id="m-go">Create</button></div>`,
    (root, close) => {
      const go = async (btn) => {
        const name = $('#m-name', root).value.trim();
        if (!name) return;
        busy(btn, true);
        try {
          const id = await call('create_server', { name });
          close();
          await refreshConvs();
          await select(conv(id));
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
          busy(btn, false);
        }
      };
      $('#m-go', root).addEventListener('click', (e) => go(e.target));
      $('#m-name', root).addEventListener('keydown', (e) => { if (e.key === 'Enter') go($('#m-go', root)); });
    });
  }

  async function showNewChannel() {
    const server = conv(state.view.serverId);
    if (!server) return;
    const members = (await call('members', { conversationId: server.id })).filter((m) => !m.is_me);
    modal(`<h3>New channel in ${esc(server.name)}</h3>
      <label>Channel name<input id="m-name" maxlength="64" placeholder="e.g. announcements"></label>
      <label class="check"><input type="checkbox" id="m-private"> Private channel</label>
      <p class="fineprint" id="m-private-note">Everyone in the server will be added.</p>
      <div id="m-members" class="pick-list" hidden>
        ${members.map((m) => `<label class="check pick"><input type="checkbox" value="${esc(m.key)}"> ${esc(m.label)} <span class="sub">${esc(m.fingerprint)}</span></label>`).join('')
          || '<div class="empty-note">No one else is in this server yet.</div>'}
      </div>
      <p class="form-error" id="m-err"></p>
      <div class="actions"><button class="btn ghost" data-close>Cancel</button><button class="btn primary" id="m-go">Create channel</button></div>`,
    (root, close) => {
      const priv = $('#m-private', root);
      priv.addEventListener('change', () => {
        $('#m-members', root).hidden = !priv.checked;
        $('#m-private-note', root).textContent = priv.checked
          ? 'Only the people you pick can read it: it gets its own encryption keys.'
          : 'Everyone in the server will be added.';
      });
      $('#m-go', root).addEventListener('click', async (e) => {
        const name = $('#m-name', root).value.trim();
        if (!name) return;
        const memberKeys = [...root.querySelectorAll('#m-members input:checked')].map((i) => i.value);
        busy(e.target, true);
        try {
          const id = await call('create_channel', { serverId: server.id, name, private: priv.checked, memberKeys });
          close();
          await refreshConvs();
          await select(conv(id));
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
          busy(e.target, false);
        }
      });
    });
  }

  async function showInviteToServer() {
    const server = conv(state.view.serverId);
    if (!server) return;
    await refreshContacts();
    const inServer = new Set((await call('members', { conversationId: server.id })).map((m) => m.key));
    const rows = state.contacts.map((c) => {
      let action;
      if (inServer.has(c.key)) action = '<span class="sub">Already a member</span>';
      else if (!c.has_card) action = '<span class="sub">Waiting for them to connect once</span>';
      else action = `<button class="btn small primary" data-invite="${esc(c.key)}">Invite</button>`;
      return `<div class="pick">${avatar(c.label, c.key, c.online, true)}
        <div class="grow">${esc(c.label)}<div class="sub">${esc(c.fingerprint)}</div></div>${action}</div>`;
    }).join('');
    modal(`<h3>Invite to ${esc(server.name)}</h3>
      <p class="lead">Pick from your contacts. They join the server and its public channels, and get everyone’s contact details so members can reach each other directly.</p>
      <div class="pick-list">${rows || '<div class="empty-note">No contacts yet. Add someone from Direct messages first.</div>'}</div>
      <p class="form-error" id="m-err"></p>
      <div class="actions"><button class="btn primary" data-close>Done</button></div>`,
    (root) => {
      root.querySelectorAll('[data-invite]').forEach((b) => b.addEventListener('click', async () => {
        busy(b, true);
        try {
          await call('invite_to_server', { serverId: server.id, peerKey: b.dataset.invite });
          b.textContent = 'Invited';
          refreshMembers();
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
          busy(b, false);
        }
      }));
    });
  }

  function confirmKick(key, name) {
    const server = conv(state.view.serverId);
    if (!server) return;
    modal(`<h3>Remove ${esc(name)}?</h3>
      <p class="lead">${esc(name)} will be removed from ${esc(server.name)} and all of its channels. New keys are made for everyone left, so they can’t read anything sent from now on. Messages they already have stay on their device.</p>
      <p class="form-error" id="m-err"></p>
      <div class="actions"><button class="btn ghost" data-close>Cancel</button><button class="btn danger" id="m-go">Remove</button></div>`,
    (root, close) => {
      $('#m-go', root).addEventListener('click', async (e) => {
        busy(e.target, true);
        try {
          await call('kick', { serverId: server.id, peerKey: key });
          close();
          toast(`${name} was removed.`);
          refreshMembers();
        } catch (err) {
          $('#m-err', root).textContent = errText(err);
          busy(e.target, false);
        }
      });
    });
  }

  // ------------------------------------------------------------------
  // Interaction
  // ------------------------------------------------------------------
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-action], [data-conv], [data-server], [data-kick], [data-react], [data-react-menu], [data-thread], [data-download], [data-save]');
    if (!t) return;
    if (t.dataset.react) return react(t.dataset.msg, t.dataset.react, t.dataset.on === '1');
    if (t.dataset.reactMenu) { e.stopPropagation(); return showReactionMenu(t, t.dataset.reactMenu); }
    if (t.dataset.thread) return openThread(t.dataset.thread);
    if (t.dataset.download) {
      return call('download_attachment', { fileId: t.dataset.download }).catch((err) => toast(errText(err), 'error'));
    }
    if (t.dataset.save) {
      return call('save_attachment', { fileId: t.dataset.save })
        .then((path) => toast('Saved to ' + path))
        .catch((err) => toast(errText(err), 'error'));
    }
    if (t.dataset.conv) return select(conv(t.dataset.conv));
    if (t.dataset.server) return select(conv(t.dataset.server));
    if (t.dataset.kick) return confirmKick(t.dataset.kick, t.dataset.name);
    switch (t.dataset.action) {
      case 'add-contact': return showAddContact();
      case 'my-invite': return showMyInvite();
      case 'new-server': return showNewServer();
      case 'new-channel': return showNewChannel();
      case 'invite-server': return showInviteToServer();
      case 'settings': return showSettings();
      case 'attach': return $('#file-input').click();
      case 'timer': return showTimerSettings();
      case 'close-thread': state.thread = null; return renderThread();
      case 'call-voice': case 'call-video': case 'call-mute': case 'call-camera': case 'call-screen': case 'call-hangup':
        return callAction(t.dataset.action);
      case 'update-notes': return showUpdateNotes();
      case 'apply-update': return applyUpdate(t);
    }
  });
  $('#rail-home').addEventListener('click', goHome);
  $('#rail-add').addEventListener('click', showNewServer);
  $('#net-pill').addEventListener('click', showNetworkModal);
  $('#me-settings').addEventListener('click', showSettings);
  $('#me-status').addEventListener('click', showStatusPicker);
  $('#file-input').addEventListener('change', (e) => {
    const f = e.target.files[0];
    e.target.value = '';
    sendFile(f);
  });
  $('#thread-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      $('#thread-composer').requestSubmit();
    }
  });
  $('#thread-composer').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = state.view.convId;
    const body = $('#thread-input').value.trim();
    if (!id || !body || !state.thread) return;
    $('#thread-input').value = '';
    try {
      const m = await call('send_message', { conversationId: id, body, replyTo: state.thread });
      const list = state.msgs[id] || (state.msgs[id] = []);
      if (!list.some((x) => x.id === m.id)) list.push(m);
      renderMessages(false);
      renderThread();
    } catch (err) {
      $('#thread-input').value = body;
      toast(errText(err), 'error');
    }
  });

  const input = $('#composer-input');
  function autosize() {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, window.innerHeight * 0.4) + 'px';
  }
  input.addEventListener('input', autosize);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      $('#composer').requestSubmit();
    }
  });
  $('#composer').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = state.view.convId;
    const body = input.value.trim();
    if (!id || !body) return;
    input.value = '';
    autosize();
    try {
      const m = await call('send_message', { conversationId: id, body });
      const list = state.msgs[id] || (state.msgs[id] = []);
      if (!list.some((x) => x.id === m.id)) list.push(m);
      if (state.view.convId === id) renderMessages(true);
    } catch (err) {
      input.value = body;
      toast(errText(err), 'error');
    }
  });

  boot();
})();
