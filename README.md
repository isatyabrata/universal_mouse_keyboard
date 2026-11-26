# kvm.py - one keyboard and mouse for every machine

Single file, Python 3.8+ standard library only. No PowerShell, no `pip install`.
Works on Windows and macOS in either role.

## Run

Pick the machine the keyboard/mouse is plugged into as the **server**; every other
machine is a **client**. Use the same `--secret` everywhere.

```
# server (the machine with the real keyboard + mouse)
python kvm.py server --secret MYPASS --client right:pc2 --client left:macbook --client pc3

# each client
python kvm.py client --server 192.168.1.10 --name pc2     --secret MYPASS
python kvm.py client --server 192.168.1.10 --name macbook --secret MYPASS
python kvm.py client --server 192.168.1.10 --name pc3     --secret MYPASS
```

- `right:pc2` = pc2's screen sits to the right of the server's. Push the cursor into the
  right edge to move there; push back past pc2's left edge to return.
- A client with no edge (`pc3`) is hotkey-only. Up to 9 clients.
- **Ctrl+Alt+Shift+1..9** jumps to client 1..9 (order of `--client`); **Ctrl+Alt+Shift+0**
  returns to the server. This is your escape hatch if anything misbehaves.
- Secret can also come from the `KVM_SECRET` environment variable (keeps it out of history).
- `--invert-scroll` on a client flips scroll direction. `--debug` logs mouse events.

## One-time setup

- **macOS:** System Settings > Privacy & Security > grant *Accessibility* and
  *Input Monitoring* to the terminal app you run it from, then restart that app.
- **Windows server:** allow `python.exe` inbound TCP **24801** on a private network
  (the first-run firewall prompt, or `--port` to change it). Clients only connect out.

## Behaviour and limits

- Keys map by physical US position; Windows key = Command, Alt = Option. Characters typed
  follow the *receiving* machine's layout.
- Only each machine's primary display is used. No clipboard or file transfer.
- Windows hooks cannot see or inject into elevated (admin) windows or the UAC prompt.
- **Traffic is authenticated (HMAC) but not encrypted**: keystrokes, including passwords,
  cross the LAN readable. Use it on a network you trust. (ShareMouse itself ships with
  encryption off by default.) Anyone without the secret cannot connect or inject input.
- Security/EDR software may flag any process that installs low-level keyboard hooks.

## Tests

`python -m unittest test_kvm` - protocol, auth, replay/tamper, edge/hotkey switching, using
fake input backends over loopback. The OS backends themselves need a real machine to test.
