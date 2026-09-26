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
    python3 desktop/e2e/gui_e2e.py --binary desktop/target/debug/securetext-desktop

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

    def click(self, css):
        self.wait(f"clickable {css}", "const e = document.querySelector(arguments[0]); return !!e && !e.disabled && e.offsetParent !== null;", css)
        self.cmd("POST", f"/element/{self.find(css)}/click", {})

    def type(self, css, text):
        self.cmd("POST", f"/element/{self.find(css)}/value", {"text": text})

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

    def close(self):
        try:
            self._req("DELETE", f"/session/{self.sid}")
        except Exception:
            pass


START = time.time()


def log(msg):
    print(f"{time.time() - START:7.1f}s  {msg}", flush=True)


def text_of(css):
    return f"const e = document.querySelector('{css}'); return e ? e.innerText : '';"


def has_text(css, needle):
    return (f"const e = document.querySelector('{css}');"
            f" return !!e && e.innerText.includes({json.dumps(needle)});")


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--alice-port", type=int, default=4444)
    ap.add_argument("--bob-port", type=int, default=4445)
    ap.add_argument("--shots", default="e2e-shots")
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
        log("GUI end-to-end run PASSED")
    except Exception:
        for w in (alice, bob):
            try:
                w.shot("zz-failure")
            except Exception:
                pass
        raise
    finally:
        alice.close()
        bob.close()


if __name__ == "__main__":
    sys.exit(main())
