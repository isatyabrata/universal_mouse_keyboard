# kvm.py - one keyboard and mouse for every machine

Share a single keyboard and mouse across as many Windows and macOS computers as you like.
One file, Python 3.8+ standard library only: no PowerShell, no `pip install`, no installer.

**Any machine can be the server.** The server is simply the computer your physical keyboard
and mouse are plugged into. Every other computer is a client. Windows and macOS both work
in either role, so you can pick whichever machine suits you (or change your mind later).

## Quick start

```
git clone https://github.com/isatyabrata/universal_mouse_keyboard.git
cd universal_mouse_keyboard
```

1. Choose the **server**: the machine with the real keyboard and mouse. Find its IP address
   (`ipconfig` on Windows, `ipconfig getifaddr en0` on macOS).
2. Pick one shared passphrase and give every machine a short unique **name**.
3. Start the server, listing the clients you will allow:

```
python kvm.py server --secret MYPASS --client right:laptop --client left:desktop --client spare
```

4. On each client, point it at the server and give it the name listed above:

```
python kvm.py client --server SERVER_IP --name laptop  --secret MYPASS
python kvm.py client --server SERVER_IP --name desktop --secret MYPASS
python kvm.py client --server SERVER_IP --name spare   --secret MYPASS
```

(Use `python3` instead of `python` on macOS.) Start order does not matter: clients keep
retrying until the server is up.

## Switching between machines

- `--client right:laptop` means laptop's screen sits to the **right** of the server's.
  Push the cursor into the right edge to move there; push back past laptop's left edge to
  return. Edges are `left`, `right`, `top`, `bottom`.
- A client with no edge (`spare` above) is hotkey-only. You can list up to 9 clients.
- **Ctrl+Alt+Shift+1..9** jumps to client 1..9 (the order of the `--client` flags).
- **Ctrl+Alt+Shift+0** always returns control to the server. This is your escape hatch.

## Options

| Flag | Where | Meaning |
| --- | --- | --- |
| `--secret` | both | Shared passphrase (or set the `KVM_SECRET` environment variable to keep it out of shell history). Must match everywhere. |
| `--port` | both | TCP port, default 24801. |
| `--invert-scroll` | client | Flip scroll direction (useful with macOS "natural scrolling"). |
| `--debug` | both | Log mouse events, handy when something feels off. |

## One-time setup per OS

- **macOS** (server or client): System Settings > Privacy & Security > grant *Accessibility*
  and *Input Monitoring* to the terminal app you run it from, then restart that terminal.
- **Windows** (server): allow `python.exe` inbound TCP **24801** on a private network
  (accept the firewall prompt, or use `--port`). Clients only make outgoing connections.
- **Any server:** the machine running the server must be reachable from the clients on that
  TCP port, so keep them on the same network and check that no firewall blocks it.

## Behaviour and limits

- Keys map by physical US-keyboard position; the Windows key acts as Command and Alt as
  Option. The characters typed follow the *receiving* machine's keyboard layout.
- Only each machine's primary display is used. No clipboard or file transfer.
- Windows cannot capture or control elevated (administrator) windows or the UAC prompt.
- **Traffic is authenticated (HMAC-SHA256) but not encrypted.** Keystrokes, including
  passwords, cross the network readable. Without the secret nobody can connect or inject
  input, but use this only on a network you trust.
- Anything that installs low-level keyboard hooks can be flagged by security/EDR software.
  Make sure you are allowed to run it on the machines involved.

## Tests

```
python -m unittest test_kvm
```

Covers the protocol, authentication, replay/tamper rejection and edge/hotkey switching using
fake input backends over loopback. The Windows and macOS input backends themselves need a real
machine to exercise; bug reports with `--debug` output are welcome.

## License

[MIT](LICENSE)
