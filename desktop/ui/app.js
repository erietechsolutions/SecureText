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
    const letters = parts.length > 1 ? parts[0][0] + parts[1][0] : (parts[0] || '?').slice(0, 2);
    return letters.toUpperCase();
  }
  function avatar(name, key, online, small) {
    const dot = online === undefined ? '' : `<span class="dot ${online ? 'on' : ''}" title="${online ? 'Connected' : 'Not connected'}"></span>`;
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
    await Promise.all([refreshStatus(), refreshConvs(), refreshContacts()]);
    const open = params.get('open');
    if (open && conv(open)) await select(conv(open));
    else render();
    if (params.get('modal') === 'network') showNetworkModal();
    setInterval(refreshStatus, 10000);
  }

  async function refreshStatus() {
    try {
      state.status = await call('status');
    } catch (e) {
      return;
    }
    renderMe();
    renderNet();
  }

  async function refreshConvs() {
    state.convs = await call('conversations');
  }

  async function refreshContacts() {
    state.contacts = await call('contacts');
    state.contacts.forEach((c) => (c.online ? state.online.add(c.key) : state.online.delete(c.key)));
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
      case 'message_status': {
        const m = (state.msgs[ev.conversation_id] || []).find((x) => x.id === ev.id);
        if (m) {
          m.status = ev.status;
          if (ev.conversation_id === state.view.convId) renderMessages(false);
        }
        break;
      }
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
        return `<button class="item ${active ? 'active' : ''} ${unread ? 'unread' : ''}" data-conv="${esc(c.id)}">
          ${avatar(c.name, c.peer_key, online, true)}
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
    if (!c) {
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

  function renderMessages(forceBottom) {
    const c = conv(state.view.convId);
    const box = $('#messages');
    if (!c || c.kind === 'server') return;
    const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    const list = state.msgs[c.id] || [];
    let html = introHtml(c);
    let prev = null;
    for (const m of list) {
      if (!prev || !sameDay(prev.sent_at, m.sent_at)) html += `<div class="day-sep">${esc(fmtDay(m.sent_at))}</div>`;
      const first = !prev || prev.sender_key !== m.sender_key || m.sent_at - prev.sent_at > 5 * 60 * 1000 || !sameDay(prev.sent_at, m.sent_at);
      const pending = m.outgoing && m.status === 'pending';
      const relayed = m.outgoing && m.status === 'relayed';
      html += `<div class="msg ${first ? 'first' : ''} ${pending ? 'pending' : ''}">
        <div class="gutter">${first ? avatar(m.sender_label, m.sender_key, undefined) : `<span class="time-hover">${esc(fmtTime(m.sent_at))}</span>`}</div>
        <div>
          ${first ? `<div class="head"><span class="who">${esc(m.sender_label)}</span><span class="when">${esc(fmtTime(m.sent_at))}</span></div>` : ''}
          <div class="body">${esc(m.body)}</div>
          ${pending ? `<div class="status pending">◷ Queued on this device — sends automatically when ${c.kind === 'dm' ? esc(c.name) + ' is' : 'members are'} reachable over Tor</div>` : ''}
          ${relayed ? `<div class="status relayed">✓ Left at ${c.kind === 'dm' ? esc(c.name) + '’s' : 'an offline member’s'} relay — delivered when they’re next online</div>` : ''}
        </div></div>`;
      prev = m;
    }
    box.innerHTML = html;
    if (forceBottom || nearBottom) box.scrollTop = box.scrollHeight;
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
    const online = state.members.filter((m) => m.online).length;
    $('#members-title').textContent = `Members — ${online}/${state.members.length} connected`;
    panel.innerHTML = state.members.map((m) => `
      <div class="member ${m.online ? '' : 'offline'}">
        ${avatar(m.label, m.key, m.online, true)}
        <div class="grow">
          <div class="name">${esc(m.label)}${m.is_me ? ' <span class="sub">(you)</span>' : ''} ${m.is_admin ? '<span class="crown" title="Server admin">♛</span>' : ''}</div>
          <div class="sub" title="Identity key fingerprint">${esc(m.fingerprint)}</div>
        </div>
        ${canKick && !m.is_me ? `<button class="btn small ghost kick" data-kick="${esc(m.key)}" data-name="${esc(m.label)}" title="Remove from server">Remove</button>` : ''}
      </div>`).join('');
  }

  function renderMe() {
    const s = state.status;
    if (!s) return;
    $('#me-name').textContent = s.label;
    $('#me-fp').textContent = s.fingerprint;
    $('#me-avatar').className = 'avatar ' + hue(s.public_key);
    $('#me-avatar').textContent = initials(s.label);
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
    const t = e.target.closest('[data-action], [data-conv], [data-server], [data-kick]');
    if (!t) return;
    if (t.dataset.conv) return select(conv(t.dataset.conv));
    if (t.dataset.server) return select(conv(t.dataset.server));
    if (t.dataset.kick) return confirmKick(t.dataset.kick, t.dataset.name);
    switch (t.dataset.action) {
      case 'add-contact': return showAddContact();
      case 'my-invite': return showMyInvite();
      case 'new-server': return showNewServer();
      case 'new-channel': return showNewChannel();
      case 'invite-server': return showInviteToServer();
    }
  });
  $('#rail-home').addEventListener('click', goHome);
  $('#rail-add').addEventListener('click', showNewServer);
  $('#net-pill').addEventListener('click', showNetworkModal);
  $('#me-settings').addEventListener('click', showRelaySettings);

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
