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
            with urllib.request.urlopen(req, timeout=120) as res:
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
            if "unsupported operation" not in str(e) and "not interactable" not in str(e):
                raise
            self.js("document.querySelector(arguments[0]).click();", css)

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


def relay_stage(alice, bob, args, binary):
    """Phase 5 over live Tor: Bob picks a relay and goes offline; Alice's
    message is left there; Alice goes offline; Bob comes back and gets it."""
    bob.click("#me-settings")
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

        alice.click("#sidebar-body [data-conv]")  # back to #general
        alice.wait("#general open again", has_text("#main-title", "general"))
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
