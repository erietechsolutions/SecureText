#!/usr/bin/env python3
"""Drive two real SecureText desktop windows through the Phase 4 exit
criterion, via the GUI only: create profiles, share an invite, chat, create
a server, invite the friend, chat in a channel, make a private channel, and
remove a member. Every step goes through the real Tauri binary and the live
Tor network; nothing is stubbed.

It talks W3C WebDriver to two WebKitWebDriver instances (the driver
tauri-driver uses on Linux), one per user. Each driver must already be
running with its own profile directory and automation enabled:

    TAURI_WEBVIEW_AUTOMATION=true SECURETEXT_PROFILE_DIR=/tmp/st-e2e/alice \
        WebKitWebDriver --port=4444 &
    TAURI_WEBVIEW_AUTOMATION=true SECURETEXT_PROFILE_DIR=/tmp/st-e2e/bob \
        WebKitWebDriver --port=4445 &
    python3 desktop/e2e/gui_e2e.py --binary desktop/target/debug/securetext-desktop \
        [--relay securetext-relay1:...]   # adds the Phase 5 offline-delivery stage
        [--turn turn:127.0.0.1:3478,user,password]   # adds the Phase 7 call stage

For the call stage, also start each driver with SECURETEXT_MOCK_MEDIA=1 and
a different SECURETEXT_TEST_TONE (Alice 440, Bob 660), and run a TURN
server (`securetext-turn --listen 127.0.0.1:3478 --public-ip 127.0.0.1
--user user:password`).

The windows need a display. Headless, a virtual compositor works (e.g.
`dbus-run-session -- kwin_wayland --virtual --no-lockscreen --socket X`
with WAYLAND_DISPLAY=X); GTK's Broadway backend does not (WebKit gets a
broken scale factor there; see tech-stack.md).

On Fedora the driver comes from the `webkit2gtk4.1-devel` / `webkitgtk6.0`
packages' WebKitWebDriver binary. Standard library only, on purpose.
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

ELEMENT = "element-6066-11e4-a52e-4f735466cecf"


class Window:
    def __init__(self, name, port, binary, shots):
        self.name = name
        self.base = f"http://127.0.0.1:{port}"
        self.shots = shots
        caps = {"capabilities": {"alwaysMatch": {"webkitgtk:browserOptions": {"binary": binary, "args": []}}}}
        self.sid = self._req("POST", "/session", caps)["sessionId"]

    def _req(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=300) as res:
                return json.loads(res.read() or b"{}").get("value")
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"[{self.name}] {method} {path}: {e.read().decode(errors='replace')}") from None

    def cmd(self, method, path, body=None):
        return self._req(method, f"/session/{self.sid}{path}", body)

    def js(self, script, *args):
        return self.cmd("POST", "/execute/sync", {"script": script, "args": list(args)})

    def find(self, css):
        return self.cmd("POST", "/element", {"using": "css selector", "value": css})[ELEMENT]

    # Native input where the driver supports it (it does under a real or
    # virtual compositor). Some headless setups can't synthesize input
    # ("unsupported operation", "element not interactable"); then fall back
    # to the DOM equivalent: set the value and fire the same `input` event a
    # keystroke would, or call click(). The app's own handlers run either way.
    def click(self, css):
        self._with_retry(css, self._click)

    def type(self, css, text):
        self._with_retry(css, lambda c: self._type(c, text))

    def _with_retry(self, css, action, attempts=10):
        # The UI re-renders lists (sidebar, members) whenever a peer's status
        # changes, so an element found a moment ago can be replaced before
        # the driver acts on it. Look it up again and retry.
        for attempt in range(attempts):
            self.wait(f"present {css}", "const e = document.querySelector(arguments[0]); return !!e && !e.disabled && e.offsetParent !== null;", css)
            try:
                return action(css)
            except RuntimeError as e:
                if attempt + 1 < attempts and ("no such element" in str(e) or "stale element" in str(e)):
                    time.sleep(0.3)
                    continue
                raise

    def _click(self, css):
        try:
            self.cmd("POST", f"/element/{self.find(css)}/click", {})
        except RuntimeError as e:
            if "unsupported operation" not in str(e) and "not interactable" not in str(e) and "intercepted" not in str(e):
                raise
            # The element can be replaced while re-rendering; report that
            # the same way the driver does, so `_with_retry` tries again.
            if not self.js("const e = document.querySelector(arguments[0]); if (e) e.click(); return !!e;", css):
                raise RuntimeError(f"[{self.name}] no such element: {css}")

    def _type(self, css, text):
        try:
            self.cmd("POST", f"/element/{self.find(css)}/value", {"text": text})
        except RuntimeError as e:
            if "unsupported operation" not in str(e):
                raise
            self.js(
                "const e = document.querySelector(arguments[0]); e.focus(); e.value += arguments[1];"
                " e.dispatchEvent(new Event('input', { bubbles: true }));",
                css, text)

    def wait(self, what, script, *args, timeout=240):
        deadline = time.time() + timeout
        while True:
            value = self.js(script, *args)
            if value:
                return value
            if time.time() > deadline:
                self.shot(f"FAILED-{what.replace(' ', '-')[:40]}")
                raise TimeoutError(f"[{self.name}] timed out waiting for: {what}")
            time.sleep(0.5)

    def shot(self, label):
        png = base64.b64decode(self.cmd("GET", "/screenshot"))
        path = os.path.join(self.shots, f"{self.name}-{label}.png")
        with open(path, "wb") as f:
            f.write(png)
        log(f"[{self.name}] screenshot {path}")

    def invoke(self, cmd, args=None):
        """Call the node directly, the way the UI does (for diagnostics)."""
        script = ("const done = arguments[arguments.length - 1];"
                  "window.__TAURI__.core.invoke('node', {cmd: arguments[0], args: arguments[1]})"
                  ".then(r => done({ok: r})).catch(e => done({err: String(e)}));")
        return self.cmd("POST", "/execute/async", {"script": script, "args": [cmd, args or {}]})

    def dump_state(self):
        try:
            log(f"[{self.name}] status: {json.dumps(self.invoke('status'))}")
            log(f"[{self.name}] contacts: {json.dumps(self.invoke('contacts'))}")
            convs = self.invoke("conversations").get("ok") or []
            for c in convs:
                msgs = self.invoke("messages", {"conversationId": c["id"]}).get("ok") or []
                summary = [(m["sender_label"], m["body"][:40], m["status"]) for m in msgs]
                log(f"[{self.name}] {c['kind']} {c['name']!r} removed={c['removed']}: {summary}")
        except Exception as e:
            log(f"[{self.name}] could not dump state: {e}")

    def close(self):
        try:
            self._req("DELETE", f"/session/{self.sid}")
        except Exception:
            pass


START = time.time()


def log(msg):
    print(f"{time.time() - START:7.1f}s  {msg}", flush=True)


# textContent, not innerText: what the app put in the DOM, independent of
# how (or whether) the display backend laid it out.
def text_of(css):
    return f"const e = document.querySelector('{css}'); return e ? e.textContent : '';"


def has_text(css, needle):
    return (f"const e = document.querySelector('{css}');"
            f" return !!e && e.textContent.includes({json.dumps(needle)});")


def create_profile(w, name, passphrase):
    w.wait("create-profile form", "return !document.querySelector('#create-form').hidden;")
    w.type("#create-name", name)
    w.type("#create-pass", passphrase)
    w.type("#create-pass2", passphrase)
    w.shot("01-create-profile")
    w.click("#create-form button[type=submit]")
    w.wait("main window", "return !document.querySelector('#app').hidden;")
    w.shot("02-home-connecting")
    log(f"[{w.name}] profile created; waiting for Tor")
    w.wait("Tor to be ready", "return document.querySelector('#net-pill').classList.contains('ready');", timeout=300)
    log(f"[{w.name}] Tor ready")
    w.shot("03-home-tor-ready")


def send(w, body):
    w.type("#composer-input", body)
    w.click("#composer button[type=submit]")


def call_stage(alice, bob, turn, screen_share=False):
    """Phase 7: a video call from the DM. Signaling goes over the live-Tor
    connection between the two apps; media goes through the TURN server
    given on the command line. Run the apps with SECURETEXT_TEST_TONE
    (a different pitch each) and SECURETEXT_MOCK_MEDIA=1, so what each one
    hears and sees can be checked."""
    url, user, password = turn.split(",", 2)
    alice.click("#me-settings")
    alice.type("#s-turn-url", url)
    alice.type("#s-turn-user", user)
    alice.type("#s-turn-pass", password)
    alice.shot("16-call-settings")
    alice.click("#s-turn-save")
    alice.wait("TURN server saved", "return !!document.querySelector('.toast');")
    alice.click(".modal [data-close]")

    alice.wait("call button", "return !!document.querySelector('[data-action=call-video]');")
    alice.click("[data-action=call-video]")
    alice.wait("call disclosure", has_text(".modal", "Calls don\u2019t go through Tor"))
    alice.shot("17-call-disclosure")
    alice.click("#m-go")
    bob.wait("incoming call", has_text(".modal", "is calling"), timeout=180)
    bob.shot("18-incoming-call")
    bob.click("#m-accept")
    for w in (alice, bob):
        w.wait("call connected", has_text("#call-panel", "1 connected"), timeout=180)
    log("call connected on both sides")
    time.sleep(5)

    tones = {"Alice": 440.0, "Bob": 660.0}
    for w, other in ((alice, "Bob"), (bob, "Alice")):
        stats = w.invoke("call_stats").get("ok")
        assert stats and all(s["local_candidate"] == "relay" and s["remote_candidate"] == "relay" for s in stats), stats
        heard = w.invoke("call_heard").get("ok")
        log(f"[{w.name}] media relayed both ways ({stats[0]['bytes_received']} bytes in); heard {heard}")
        assert heard and abs(heard["frequency"] - tones[other]) < 25, f"{w.name} heard {heard}, expected {other}'s {tones[other]}"
        assert heard["audible_fraction"] > 0.5, f"{w.name}: too many dropouts: {heard}"
        w.wait("remote video frame", "const i = document.querySelector('#call-panel img[data-video]');"
               " return !!i && (i.getAttribute('src') || '').startsWith('data:image/jpeg');", timeout=60)
    log("each side hears the other's tone and sees the other's camera")
    alice.shot("19-in-call")
    bob.shot("19-in-call")

    # Screen sharing replaces Alice's camera; Bob keeps receiving frames.
    # Opt-in: the system's screen picker (xdg-desktop-portal) has to be
    # answered by hand, so this needs a real desktop session.
    if screen_share:
        screen_share_check(alice, bob)

    bob.click("[data-action=call-hangup]")
    alice.wait("call ended for Alice", "return document.querySelector('#call-panel').hidden;", timeout=120)
    log("hang-up ended the call on both sides")


def attach(w, name, mime, make_blob_js):
    """Put a file into the (hidden) file picker the way choosing one would,
    and fire its change event. `make_blob_js` is a JS expression giving a
    Promise of a Blob."""
    script = f"""const done = arguments[arguments.length - 1];
        Promise.resolve({make_blob_js}).then(blob => {{
            const dt = new DataTransfer();
            dt.items.add(new File([blob], {json.dumps(name)}, {{ type: {json.dumps(mime)} }}));
            const input = document.querySelector('#file-input');
            input.files = dt.files;
            input.dispatchEvent(new Event('change'));
            done(blob.size);
        }}, e => done('error: ' + e));"""
    return w.cmd("POST", "/execute/async", {"script": script, "args": []})


def show_actions(w, css):
    # Message actions appear on hover; make them clickable without one.
    w.js("document.querySelectorAll(arguments[0]).forEach(e => e.style.display = 'flex');", css)


def rich_stage(alice, bob):
    """Phase 8 in the DM, through the UI: a reaction, a thread, an inline
    image, a file downloaded on request, status, disappearing messages."""
    show_actions(bob, "#messages .msg-actions")
    bob.click("#messages .msg[data-id]:last-of-type [data-react-menu]")
    bob.click(".react-menu [data-react]")
    alice.wait("Bob's reaction", has_text("#messages .reactions", "1"), timeout=180)
    log("alice sees bob's reaction")

    show_actions(alice, "#messages .msg-actions")
    alice.click("#messages .msg[data-id] [data-thread]")
    alice.type("#thread-input", "Replying in a thread.")
    alice.click("#thread-composer button[type=submit]")
    bob.wait("thread link", has_text("#messages", "1 reply"), timeout=180)
    time.sleep(1)
    assert "2 replies" not in alice.js(text_of("#messages")), "a reply must be counted once"
    alice.wait("thread panel fits the window", "const p = document.querySelector('#thread-panel');"
               " return !p.hidden && p.getBoundingClientRect().right <= window.innerWidth + 1;")
    alice.wait("thread reply marked delivered", "const t = document.querySelector('#thread-body');"
               " return !!t && t.textContent.includes('Replying in a thread.') && !t.textContent.includes('Queued');", timeout=120)
    alice.shot("21-thread-open")
    bob.click("#messages .thread-link")
    bob.wait("thread reply", has_text("#thread-body", "Replying in a thread."))
    log("bob sees alice's thread reply")
    bob.shot("21-thread")
    bob.click("[data-action=close-thread]")

    size = attach(alice, "square.png", "image/png", """new Promise(r => {
        const c = document.createElement('canvas'); c.width = 96; c.height = 64;
        const g = c.getContext('2d'); g.fillStyle = '#7c6cf2'; g.fillRect(0, 0, 96, 64);
        g.fillStyle = '#fff'; g.font = '20px sans-serif'; g.fillText('hi', 36, 40);
        c.toBlob(r, 'image/png'); })""")
    assert isinstance(size, int) and size > 0, size
    bob.wait("inline image", "const i = document.querySelector('#messages .attachment.image img');"
             " return !!i && i.src.startsWith('data:image/png') && i.naturalWidth === 96;", timeout=180)
    log(f"bob sees alice's {size}-byte image inline (downloaded over Tor, decrypted, rendered)")

    attach(alice, "notes.txt", "text/plain", "new Blob(['meeting notes: bring snacks\\n'.repeat(4000)])")
    bob.wait("file offered", "return !!document.querySelector('#messages [data-download]');", timeout=180)
    bob.click("#messages [data-download]")
    bob.wait("file downloaded", "return !!document.querySelector('#messages .attachment.file [data-save]');", timeout=240)
    log("bob downloaded alice's file on request")
    bob.shot("22-files")

    alice.click("#me-status")
    alice.click("input[name=st][value=away]")
    alice.type("#m-text", "testing SecureText")
    alice.click("#m-go")
    bob.wait("alice's status", has_text("#members", "testing SecureText"), timeout=120)
    log("bob sees alice's status")

    alice.click("[data-action=timer]")
    alice.click("input[name=timer][value='3600']")
    alice.click("#m-go")
    bob.wait("timer note", has_text("#messages", "disappear after 1 hour"), timeout=180)
    send(bob, "This one will disappear.")
    alice.wait("expiring message", "return [...document.querySelectorAll('#messages .msg')].some(m =>"
               " m.textContent.includes('This one will disappear.') && !!m.querySelector('.expires'));", timeout=180)
    log("disappearing timer applied on both sides")
    alice.shot("23-rich")
    bob.shot("23-rich")


def select_channel(w, name):
    """Open a channel in the current server by its name."""
    find = f"[...document.querySelectorAll('#sidebar-body [data-conv]')].find(b => b.querySelector('.grow').textContent.trim() === {json.dumps(name)})"
    w.wait(f"#{name} listed", f"return !!{find};")
    w.js(f"{find}.click();")
    w.wait(f"#{name} open", has_text("#main-title", name))


def hops_stage(alice, bob):
    """The Tor hop viewer: whoever opened the live connection sees the
    relays on their side of it (guard, middle, meeting point, with
    countries), and the other person's half is shown as hidden."""
    found = []
    for w in (alice, bob):
        w.click("#net-pill")
        w.wait("network details", "return !!document.querySelector('.modal h4');")
        n = w.js("return Math.max(0, ...[...document.querySelectorAll('.circuit .hops')].map(o => o.querySelectorAll('li:not(.end):not(.hidden-hops)').length));")
        found.append(n)
        if n:
            w.shot("27-tor-hops")
            hops = w.js("return [...document.querySelectorAll('.circuit .hops li:not(.end)')].map(li => li.textContent.replace(/\\s+/g, ' ').trim());")
            log(f"[{w.name}] tor hops: {hops}")
        w.click(".modal [data-close]")
    assert max(found) >= 3, f"expected at least 3 visible relays on one side, got {found}"


def roles_stage(alice, bob):
    """Discord-style server customization through the UI: Alice renames the
    server, colors its icon, creates a hoisted Mod role with Manage
    Channels, gives it to Bob, makes a category, files #general under it
    and sets a topic. Bob sees all of it and can now create channels."""
    alice.click("[data-action=server-settings]")
    alice.wait("server settings", "return !!document.querySelector('#s-name');")
    alice.js("document.querySelector('#s-name').value = '';")
    alice.type("#s-name", "Book Club HQ")
    alice.click("input[name=icon][value='#e91e63'] + span")
    alice.click("#s-save")
    alice.wait("renamed", has_text("#sidebar-head", "Book Club HQ"))

    alice.click("[data-tab=roles]")
    alice.wait("roles tab", "return !!document.querySelector('#s-new-role');")
    alice.click("#s-new-role")
    alice.js("document.querySelector('#r-name').value = '';")
    alice.type("#r-name", "Mod")
    alice.click("input[name=rcolor][value='#2ecc71'] + span")
    alice.click("#r-hoist")
    alice.click(".perm input[value='8']")  # Manage channels
    alice.shot("24-role-editor")
    alice.click("#r-save")
    alice.wait("role listed", has_text(".role-list", "Mod"))
    alice.click("[data-tab=members]")
    alice.wait("members tab", "return [...document.querySelectorAll('.member-roles')].some(r => r.textContent.includes('Bob'));")
    alice.js("[...document.querySelectorAll('.member-roles')].find(r => r.textContent.includes('Bob')).querySelector('input[type=checkbox]').click();")
    alice.wait("role assigned", "return [...document.querySelectorAll('.member-roles')].find(r => r.textContent.includes('Bob')).querySelector('input:checked') !== null;")
    alice.click("[data-tab=categories]")
    alice.type("#s-cat-new", "Reading")
    alice.click("#s-cat-add")
    alice.wait("category listed", "return !!document.querySelector('[data-cat-name]');")
    alice.shot("25-server-settings")
    alice.click(".modal [data-close]")

    alice.js("document.querySelector('[data-channel-settings]').style.visibility = 'visible';")
    select_channel(alice, "general")
    alice.js("document.querySelector('.item.active').parentElement.querySelector('[data-channel-settings]').click();")
    alice.wait("channel settings", "return !!document.querySelector('#m-topic');")
    alice.type("#m-topic", "Talk about this month's book")
    alice.js("const s = document.querySelector('#m-cat'); s.value = s.options[1].value;")
    alice.click("#m-go")
    alice.wait("topic shown", has_text("#main-title", "this month"))

    bob.wait("server renamed for Bob", has_text("#sidebar-head", "Book Club HQ"), timeout=180)
    bob.wait("category for Bob", has_text("#sidebar-body", "Reading"), timeout=180)
    select_channel(bob, "general")
    bob.wait("topic for Bob", has_text("#main-title", "this month"), timeout=180)
    bob.wait("Bob listed under Mod", "const g = [...document.querySelectorAll('#members .group-title')].map(e => e.textContent);"
             " return g.some(t => t.startsWith('Mod'));", timeout=180)
    bob.wait("Bob can create channels", "return !!document.querySelector('[data-action=new-channel]');", timeout=60)
    color = bob.js("return [...document.querySelectorAll('#members .name span[data-fg]')].map(e => getComputedStyle(e).color);")
    icon = bob.js("return getComputedStyle(document.querySelector('#rail-servers .rail-btn')).backgroundColor;")
    log(f"bob sees the rename, category, topic and his Mod role (name color {color}, icon {icon})")
    assert "rgb(46, 204, 113)" in color, color
    assert icon == "rgb(233, 30, 99)", icon
    bob.shot("26-customized-server")
    alice.shot("26-customized-server")


def channel_rules_stage(alice, bob):
    """Per-channel access rules through the UI: Alice stops @everyone
    posting in #general. Bob's composer is replaced by a note; when she
    removes the rule, he can post again."""
    select_channel(alice, "general")
    alice.js("document.querySelector('.item.active').parentElement.querySelector('[data-channel-settings]').click();")
    alice.wait("channel settings", "return !!document.querySelector('#m-perms');")
    alice.click("#m-perms")
    alice.wait("rules editor", "return !!document.querySelector('#rule-add');")
    alice.js("const s = document.querySelector('#rule-add'); s.value = 'everyone'; s.dispatchEvent(new Event('change'));")
    alice.wait("everyone rule", "return !!document.querySelector('input[name=b128][value=deny]');")
    alice.click("input[name=b128][value=deny] + span")  # Send messages: deny
    alice.shot("27-channel-rules")
    alice.click("#rule-save")
    alice.wait("rules saved", "return !document.querySelector('#rule-save');")

    select_channel(bob, "general")
    bob.wait("Bob can't post in #general", "const n = document.querySelector('#composer-note');"
             " return document.querySelector('#composer').hidden && !n.hidden && n.textContent.includes('permission');", timeout=180)
    log("a channel rule stops Bob posting in #general")
    bob.shot("28-channel-rules-muted")

    alice.js("document.querySelector('.item.active').parentElement.querySelector('[data-channel-settings]').click();")
    alice.wait("channel settings", "return !!document.querySelector('#m-perms');")
    alice.click("#m-perms")
    alice.wait("rules editor", "return !!document.querySelector('#rule-remove');")
    alice.click("#rule-remove")
    alice.click("#rule-save")
    alice.wait("rules saved", "return !document.querySelector('#rule-save');")
    bob.wait("Bob can post again", "return !document.querySelector('#composer').hidden;", timeout=180)
    log("removing the rule lets Bob post again")


def rename_stage(alice, bob):
    """Alice changes her display name in Settings; Bob's member list and
    her messages follow."""
    alice.click("#me-settings")
    alice.wait("settings", "return !!document.querySelector('#s-name');")
    alice.js("document.querySelector('#s-name').value = '';")
    alice.type("#s-name", "Alice Liddell")
    alice.click("#s-name-save")
    alice.wait("own name updated", has_text("#me-name", "Alice Liddell"))
    alice.click(".modal [data-close]")
    bob.wait("Bob sees the new name", has_text("#members", "Alice Liddell"), timeout=180)
    log("a display name change reaches the other side")
    bob.shot("29-renamed")


def screen_share_check(alice, bob):
    alice.click("[data-action=call-screen]")
    alice.wait("sharing screen", has_text("#call-panel", "Stop sharing"), timeout=30)
    bob.js("document.querySelector('#call-panel img[data-video]').removeAttribute('src');")
    bob.wait("screen frames arriving", "const i = document.querySelector('#call-panel img[data-video]');"
             " return !!i && (i.getAttribute('src') || '').startsWith('data:image/jpeg');", timeout=60)
    log("screen share frames reach the other side")
    bob.shot("20-screen-share")


def relay_stage(alice, bob, args, binary):
    """Phase 5 over live Tor: Bob picks a relay and goes offline; Alice's
    message is left there; Alice goes offline; Bob comes back and gets it."""
    bob.click("#me-settings")
    bob.click("#s-relay")
    bob.type("#m-relay", args.relay)
    bob.shot("13-relay-settings")
    bob.click("#m-go")
    bob.wait("relay saved", "return !document.querySelector('.modal');")
    # Let Alice receive Bob's updated card over their open connection, and
    # let Bob's profile be sealed to disk (every ~20s) before he quits.
    time.sleep(25)
    bob.close()
    log("bob is offline")

    alice.click("#rail-home")
    alice.click("#sidebar-body [data-conv]")
    alice.wait("DM open", has_text("#main-title", "Bob"))
    send(alice, "Left for you while you were away.")
    alice.wait("message left at Bob's relay", has_text("#messages", "Left at Bob"), timeout=420)
    log("alice's message was left at bob's relay")
    alice.shot("14-left-at-relay")
    time.sleep(25)  # let Alice's profile seal before she quits
    alice.close()
    log("alice is offline")

    bob2 = Window("bob", args.bob_port, binary, args.shots)
    try:
        bob2.wait("unlock form", "return !document.querySelector('#unlock-form').hidden;")
        bob2.type("#unlock-pass", "staple paper clip")
        bob2.click("#unlock-form button[type=submit]")
        bob2.wait("main window", "return !document.querySelector('#app').hidden;")
        bob2.click("#sidebar-body [data-conv]")
        bob2.wait("message collected from relay", has_text("#messages", "Left for you while you were away."), timeout=420)
        log("bob collected alice's message from the relay (alice offline)")
        bob2.shot("15-collected-from-relay")
    except Exception:
        bob2.shot("zz-relay-failure")
        bob2.dump_state()
        raise
    finally:
        bob2.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--alice-port", type=int, default=4444)
    ap.add_argument("--bob-port", type=int, default=4445)
    ap.add_argument("--shots", default="e2e-shots")
    ap.add_argument("--relay", help="a securetext-relay1: address; adds the offline-delivery stage")
    ap.add_argument("--turn", help="turn:host:port,username,password; adds the call stage")
    ap.add_argument("--screen-share", action="store_true", help="also share a screen in the call (answer the system picker by hand)")
    args = ap.parse_args()
    os.makedirs(args.shots, exist_ok=True)
    binary = os.path.abspath(args.binary)

    alice = Window("alice", args.alice_port, binary, args.shots)
    bob = Window("bob", args.bob_port, binary, args.shots)
    try:
        create_profile(alice, "Alice", "correct horse battery")
        create_profile(bob, "Bob", "staple paper clip")

        # Alice shares her invite link.
        alice.click(".side-actions [data-action=my-invite]")
        link = alice.wait("invite link", "const e = document.querySelector('#m-link'); return e && e.value;")
        assert link.startswith("securetext1:"), link
        alice.shot("04-invite-link")
        alice.click(".modal [data-close]")
        log(f"invite link: {len(link)} chars")

        # Bob pastes it. The DM opens on his side immediately.
        bob.click(".side-actions [data-action=add-contact]")
        bob.type("#m-link", link)
        bob.shot("05-add-contact")
        bob.click("#m-go")
        bob.wait("DM with Alice open", has_text("#main-title", "Alice"))
        send(bob, "Hi Alice! It's Bob, over Tor.")
        bob.shot("06-dm-first-message")

        # Alice gets the DM and the message; she replies.
        alice.wait("DM from Bob in sidebar", has_text("#sidebar-body", "Bob"), timeout=300)
        alice.click("#sidebar-body [data-conv]")
        alice.wait("Bob's message", has_text("#messages", "It's Bob, over Tor."), timeout=300)
        log("alice received bob's DM")
        send(alice, "Hey Bob, got it. Welcome!")
        bob.wait("Alice's reply", has_text("#messages", "Welcome!"), timeout=300)
        log("bob received alice's reply")
        alice.shot("07-dm-conversation")
        bob.shot("07-dm-conversation")
        hops_stage(alice, bob)
        if args.turn:
            call_stage(alice, bob, args.turn, args.screen_share)
        rich_stage(alice, bob)

        # Alice creates a server and invites Bob.
        alice.click("#rail-add")
        alice.type("#m-name", "Book Club")
        alice.click("#m-go")
        alice.wait("#general selected", has_text("#main-title", "general"))
        alice.click("[data-action=invite-server]")
        alice.wait("Bob invitable", "return !!document.querySelector('[data-invite]');", timeout=300)
        alice.shot("08-invite-to-server")
        alice.click("[data-invite]")
        alice.wait("invite sent", "const b = document.querySelector('[data-invite]'); return b && b.textContent === 'Invited';")
        alice.click(".modal [data-close]")

        # Bob sees the server appear and posts in #general.
        bob.wait("server in rail", "return !!document.querySelector('#rail-servers [data-server]');", timeout=300)
        bob.click("#rail-servers [data-server]")
        bob.wait("#general open", has_text("#main-title", "general"))
        send(bob, "Hello Book Club!")
        alice.wait("Bob's #general post", has_text("#messages", "Hello Book Club!"), timeout=300)
        log("alice received bob's #general post")
        alice.wait("both members listed", "return document.querySelectorAll('#members .member').length === 2;")
        alice.shot("09-server-general")
        bob.shot("09-server-general")
        roles_stage(alice, bob)
        channel_rules_stage(alice, bob)
        rename_stage(alice, bob)

        # A private channel, then removing Bob.
        alice.click("[data-action=new-channel]")
        alice.type("#m-name", "admins")
        alice.click("#m-private")
        alice.click("#m-go")
        alice.wait("#admins open", has_text("#main-title", "admins"))
        send(alice, "Only I can read this one.")
        alice.shot("10-private-channel")
        time.sleep(3)
        assert "admins" not in bob.js(text_of("#sidebar-body")), "bob must not see the private channel"

        select_channel(alice, "general")
        alice.wait("remove button", "return !!document.querySelector('.member .kick');")
        alice.js("document.querySelector('.member .kick').style.visibility = 'visible';")
        alice.click(".member .kick")
        alice.shot("11-remove-confirm")
        alice.click("#m-go")
        bob.wait("Bob sees he was removed", has_text("#composer-note", "no longer a member"), timeout=300)
        log("bob sees the removal")
        bob.shot("12-removed")
        alice.shot("12-after-remove")
        if args.relay:
            relay_stage(alice, bob, args, binary)
        log("GUI end-to-end run PASSED")
    except Exception:
        for w in (alice, bob):
            try:
                w.shot("zz-failure")
            except Exception:
                pass
            w.dump_state()
        raise
    finally:
        alice.close()
        bob.close()


if __name__ == "__main__":
    sys.exit(main())
