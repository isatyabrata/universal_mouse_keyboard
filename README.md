# One keyboard and mouse for every computer

Share a single keyboard and mouse across as many Windows and macOS computers as you like,
and arrange the screens by dragging boxes in your browser. Python 3.8+ standard library only:
no PowerShell, no `pip install`, no installer.

**Any computer can be the server.** The server is simply the one your physical keyboard and
mouse are plugged into. Windows and macOS both work in either role.

## Quick start

```
git clone https://github.com/isatyabrata/universal_mouse_keyboard.git
cd universal_mouse_keyboard
```

**1. On the computer with the keyboard and mouse (the server):**

```
python server.py
```

Nothing to configure. It creates its own passphrase and opens the layout editor.

**2. On every other computer:**

```
python client.py
```

Use `python3` instead of `python` on a Mac. The client finds the server on your network by
itself and shows a 6-digit **pairing code**. The server's window shows the same code and asks
you to type `y` if it matches. That's a one-time approval per computer: the passphrase is then
handed over privately (an X25519 key exchange; a man-in-the-middle would produce different
codes on the two screens) and saved, so from then on a plain `python client.py` reconnects,
and re-finds the server if its address changes. Each client is named after its hostname
(`--name` to change). Start order doesn't matter; clients keep retrying.

If your network blocks discovery (some Wi-Fi isolates devices), give the server's IP, which
`server.py` prints: `python client.py 192.168.1.10`. You can still skip pairing entirely with
`python client.py 192.168.1.10 PASSPHRASE`. `python client.py --pair` pairs again.

**3. Arrange the screens.** `server.py` opens a layout editor in your browser
(`http://localhost:24802`). Each computer is a box; drag it to match how your desks are laid out.
Move the mouse off a screen's edge and it crosses to whatever is next to it, including from
one client straight to another (laptop, then desktop, then the third PC). Changes apply
instantly and are saved. Use `--no-browser` to skip auto-opening it.

## Controls

- **Ctrl+Alt+Shift+1..9** jumps straight to a computer (the number is shown on its box).
- **Ctrl+Alt+Shift+0** always returns control to the server. This is your escape hatch.
- Up to 64 clients. Edge-crossing works for all of them, on any side, including client to
  client; the hotkeys cover the first nine.
- **Clipboard:** copied *text* is shared between all connected computers automatically
  (the latest copy wins, up to 100,000 characters). Copy on one, paste on another. Use
  `--no-clipboard` on a machine to opt out of sending and receiving. Images and files are
  not shared.

## One-time setup per OS

- **macOS** (server or client): System Settings > Privacy & Security > grant *Accessibility*
  and *Input Monitoring* to the terminal app you run it from, then restart that terminal.
- **Windows** (server): allow `python.exe` inbound TCP **24801** and UDP **24803** on a private network
  (accept the firewall prompt). Clients only make outgoing connections.
- Clients must be able to reach the server's IP on that port (same network, no blocking firewall).
  If the printed IP isn't the right one for your network, substitute the correct one.

## Options

`server.py`: `--reset` (new passphrase, forget the layout), `--port`, `--no-browser`, `--no-clipboard`, `--debug`.
`client.py`: `--name NAME` (default: hostname), `--invert-scroll`, `--port`, `--no-clipboard`, `--debug`.
Pairing needs UDP port 24803 reachable on the server (discovery) as well as TCP 24801.
Settings live in `~/.kvm_share.json` (readable only by you on macOS/Linux).

Advanced/manual mode without the editor: `python kvm.py server --secret S --client right:laptop
--client left:desktop` and `python kvm.py client --server IP --name laptop --secret S`.

## Troubleshooting: "connected but the mouse doesn't move"

1. **Check which edge to use.** When a client connects, the server prints a line such as
   `push the mouse off this screen's RIGHT edge to reach win-pc`. Use that edge (on the server's
   main display), or drag the box elsewhere in the layout editor. When control switches, the
   server logs `-> controlling win-pc`.
2. **Can the client machine be controlled at all?** On the client run `python kvm.py selftest`.
   It moves that machine's cursor three times and reports `OK`/`FAIL` for each.
3. **See the traffic.** Run both sides with `--debug` (`python server.py --debug`,
   `python client.py --debug`). The server logs where the pointer is near edges and what it
   forwards; the client logs what it receives. Include both outputs in a bug report.
4. A line starting `WARNING: Windows refused injected input` means Windows blocked the
   injection (error 5 = access denied): use a normal, non-admin Command Prompt and check
   security software.

## Behaviour and limits

- Keys map by physical US-keyboard position; the Windows key acts as Command and Alt as
  Option. The characters typed follow the *receiving* machine's keyboard layout.
- Only each machine's primary display is used. Text clipboard only: no images, no file transfer.
- Windows cannot capture or control elevated (administrator) windows or the UAC prompt.
- **Traffic is authenticated (HMAC-SHA256) but not encrypted.** Keystrokes and clipboard text, including
  passwords, cross the network readable. Without the passphrase nobody can connect or inject
  input, but use this only on a network you trust. The passphrase is stored in plain text in
  the settings file.
- The layout editor listens on `localhost` only and rejects requests from other sites.
- Anything that installs low-level keyboard hooks can be flagged by security/EDR software.
  Make sure you are allowed to run it on the machines involved.

## Tests

```
python -m unittest test_kvm
```

Covers the protocol, authentication, replay/tamper rejection, grid layout, edge/hotkey/chain
switching and the editor's HTTP API, using fake input backends over loopback. The Windows and
macOS input backends themselves need a real machine to exercise; bug reports with `--debug`
output are welcome.

## License

[MIT](LICENSE)
