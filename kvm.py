#!/usr/bin/env python3
"""kvm.py - share one keyboard and mouse between Windows and macOS machines.

Standard library only (ctypes talks to the OS). No PowerShell, no pip.
Run `python kvm.py server ...` on the machine the keyboard/mouse is plugged into
and `python kvm.py client ...` on every other machine. See README.md.
"""
import argparse
import hashlib
import hmac
import json
import os
import queue
import re
import socket
import struct
import sys
import threading
import time
import traceback

DEFAULT_PORT = 24801
MARGIN = 4          # px from the edge where the cursor reappears when control returns
RETRY_DELAY = 2.0   # seconds between a client's reconnection attempts
ENTRY_INSET = 6     # px inside a client's edge where the cursor appears (so jitter can't bounce it back)
SETTLE = 0.12       # seconds after taking control during which input is ignored (cursor-warp artefacts)
DEBUG = False


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ------------------------------------------------------------------ key tables
def _key_rows():
    """(canonical name, Windows virtual-key, macOS keycode) - physical US layout."""
    rows = []
    alpha = dict(a=0, s=1, d=2, f=3, h=4, g=5, z=6, x=7, c=8, v=9, b=11, q=12, w=13,
                 e=14, r=15, y=16, t=17, o=31, u=32, i=34, p=35, l=37, j=38, k=40,
                 n=45, m=46)
    for c, m in alpha.items():
        rows.append((c, ord(c.upper()), m))
    digits = {'1': 18, '2': 19, '3': 20, '4': 21, '5': 23, '6': 22, '7': 26, '8': 28,
              '9': 25, '0': 29}
    for c, m in digits.items():
        rows.append((c, ord(c), m))
    rows += [
        ('minus', 0xBD, 27), ('equal', 0xBB, 24), ('lbracket', 0xDB, 33),
        ('rbracket', 0xDD, 30), ('backslash', 0xDC, 42), ('semicolon', 0xBA, 41),
        ('quote', 0xDE, 39), ('comma', 0xBC, 43), ('period', 0xBE, 47),
        ('slash', 0xBF, 44), ('grave', 0xC0, 50),
        ('enter', 0x0D, 36), ('tab', 0x09, 48), ('space', 0x20, 49),
        ('backspace', 0x08, 51), ('esc', 0x1B, 53), ('capslock', 0x14, 57),
        ('left', 0x25, 123), ('right', 0x27, 124), ('down', 0x28, 125), ('up', 0x26, 126),
        ('home', 0x24, 115), ('end', 0x23, 119), ('pageup', 0x21, 116),
        ('pagedown', 0x22, 121), ('delete', 0x2E, 117), ('insert', 0x2D, 114),
        ('lshift', 0xA0, 56), ('rshift', 0xA1, 60), ('lctrl', 0xA2, 59),
        ('rctrl', 0xA3, 62), ('lalt', 0xA4, 58), ('ralt', 0xA5, 61),
        ('lmeta', 0x5B, 55), ('rmeta', 0x5C, 54),     # Windows key == Command
        ('kpmul', 0x6A, 67), ('kpplus', 0x6B, 69), ('kpminus', 0x6D, 78),
        ('kpdot', 0x6E, 65), ('kpdiv', 0x6F, 75), ('kpenter', 0x0D, 76),
    ]
    for i, m in enumerate([122, 120, 99, 118, 96, 97, 98, 100, 101, 109, 103, 111]):
        rows.append(('f%d' % (i + 1), 0x70 + i, m))
    for i, m in enumerate([82, 83, 84, 85, 86, 87, 88, 89, 91, 92]):
        rows.append(('kp%d' % i, 0x60 + i, m))
    return rows


_ROWS = _key_rows()
WIN2NAME = {vk: n for n, vk, _ in _ROWS if n != 'kpenter'}
NAME2WIN = {n: vk for n, vk, _ in _ROWS}
MAC2NAME = {m: n for n, _, m in _ROWS}
NAME2MAC = {n: m for n, _, m in _ROWS}
MODS = {'lshift', 'rshift', 'lctrl', 'rctrl', 'lalt', 'ralt', 'lmeta', 'rmeta'}
WIN_EXTENDED = {'left', 'right', 'up', 'down', 'home', 'end', 'pageup', 'pagedown',
                'insert', 'delete', 'rctrl', 'ralt', 'lmeta', 'rmeta', 'kpdiv', 'kpenter'}


# -------------------------------------------------------------------- protocol
# Length-prefixed JSON frames. After the handshake every frame carries a sequence
# number and an HMAC-SHA256 tag (authenticated, NOT encrypted - see README).
MAX_FRAME = 1 << 21        # authenticated frames (a clipboard can be large)
PRE_AUTH_FRAME = 1 << 16   # handshake frames, before the peer has proved the secret


def derive_key(secret):
    return hashlib.pbkdf2_hmac('sha256', secret.encode(), b'kvm.py/v1', 100000)


def _hm(key, *parts):
    return hmac.new(key, b''.join(parts), hashlib.sha256).digest()


class Wire:
    def __init__(self, sock, is_server):
        self.sock = sock
        self.f = sock.makefile('rb')
        self.key = None
        self.out_dir = b'\x01' if is_server else b'\x02'
        self.in_dir = b'\x02' if is_server else b'\x01'
        self.tx = self.rx = 0

    def send(self, obj):
        body = json.dumps(obj, separators=(',', ':')).encode()
        if self.key:
            payload = struct.pack('!Q', self.tx) + body
            self.tx += 1
            data = payload + _hm(self.key, self.out_dir, payload)
        else:
            data = body
        self.sock.sendall(struct.pack('!I', len(data)) + data)

    def _read(self, n):
        b = self.f.read(n)
        if len(b) < n:
            raise ConnectionError('connection closed')
        return b

    def recv(self):
        n = struct.unpack('!I', self._read(4))[0]
        if n > (MAX_FRAME if self.key else PRE_AUTH_FRAME):
            raise ConnectionError('frame too large')
        data = self._read(n)
        if self.key:
            payload, tag = data[:-32], data[-32:]
            if len(data) < 40 or not hmac.compare_digest(tag, _hm(self.key, self.in_dir, payload)):
                raise ConnectionError('bad MAC')
            if struct.unpack('!Q', payload[:8])[0] != self.rx:
                raise ConnectionError('bad sequence number')
            self.rx += 1
            data = payload[8:]
        return json.loads(data)


# ------------------------------------------------------------ layout + controller
SERVER = 'server'                      # reserved name of the machine running the server
DIRS = {'right': (1, 0), 'left': (-1, 0), 'bottom': (0, 1), 'top': (0, -1)}
OPPOSITE = {'right': 'left', 'left': 'right', 'top': 'bottom', 'bottom': 'top'}
MAX_CLIENTS = 64        # edge-crossing works for all of them; hotkeys 1-9 reach the first nine


class Layout:
    """Which grid cell every screen occupies. Moving the mouse off one screen's edge
    crosses to the screen in the neighbouring cell. The server is always a member."""

    def __init__(self):
        self.pos = {SERVER: (0, 0)}
        self.order = []                # client names; list position = hotkey number

    def add(self, name, prefer=None):
        if name in self.pos:
            return
        cells = set(self.pos.values())
        sx, sy = self.pos[SERVER]
        spots = []
        if prefer in DIRS:
            spots.append((sx + DIRS[prefer][0], sy + DIRS[prefer][1]))
        for anchor in [SERVER] + self.order:
            ax, ay = self.pos[anchor]
            spots += [(ax + DIRS[d][0], ay + DIRS[d][1]) for d in ('right', 'left', 'top', 'bottom')]
        self.pos[name] = next(c for c in spots if c not in cells)
        self.order.append(name)

    def set_positions(self, new):
        """Replace all positions at once (from the layout editor)."""
        try:
            cells = {n: (int(c[0]), int(c[1])) for n, c in new.items()}
        except (TypeError, ValueError, IndexError, AttributeError):
            raise ValueError('bad positions')
        if set(cells) != set(self.pos):
            raise ValueError('screens do not match the current layout')
        if len(set(cells.values())) != len(cells) or any(abs(v) > 100 for c in cells.values() for v in c):
            raise ValueError('two screens in one spot, or out of range')
        self.pos = cells

    def to_json(self):
        return {'pos': {n: list(c) for n, c in self.pos.items()}, 'order': list(self.order)}

    @classmethod
    def from_json(cls, d):
        lay = cls()
        try:
            lay.pos = {n: (int(c[0]), int(c[1])) for n, c in d['pos'].items()}
            lay.order = [n for n in d['order'] if n in lay.pos and n != SERVER]
            if SERVER not in lay.pos or len(set(lay.pos.values())) != len(lay.pos):
                raise ValueError
        except (KeyError, TypeError, ValueError, IndexError, AttributeError):
            return cls()
        return lay


class Controller:
    """Decides what is local and what is forwarded. Called from the OS input hook."""

    def __init__(self, backend, layout):
        self.be = backend
        self.layout = layout
        self.peers = {}
        self.active = None              # Peer currently receiving input, or None = this machine
        self.vx = self.vy = 0           # virtual cursor inside the active peer's screen
        self.mods = set()
        self.eaten = set()              # hotkey keys whose release we must also swallow
        self.cooldown = 0.0
        self._dbg = 0
        self._dbg_t = 0.0
        self.settle_until = 0.0
        self._after = 0

    # -- peers
    def add_peer(self, peer):
        self.peers[peer.name] = peer

    def remove_peer(self, peer):
        if self.peers.get(peer.name) is peer:
            del self.peers[peer.name]
        if self.active is peer:
            self.active = None
            self.be.freeze(False)
            log('active client %s disconnected - control back on this machine' % peer.name)

    def describe(self):
        """Plain-English list of which edge of THIS screen leads where."""
        lines = []
        for edge in ('right', 'left', 'top', 'bottom'):
            n = self._neighbor(SERVER, edge)
            if n:
                lines.append("push the mouse off this screen's %s edge to reach %s" % (edge.upper(), n))
        if not lines:
            lines.append('no connected computer is next to this screen yet - drag it beside the '
                         'Server box in the layout editor (or use Ctrl+Alt+Shift+1)')
        return lines

    def _neighbor(self, name, edge):
        """Name of the connected screen next to `name` across `edge`, or None."""
        if name not in self.layout.pos:
            return None
        x, y = self.layout.pos[name]
        want = (x + DIRS[edge][0], y + DIRS[edge][1])
        for n, c in list(self.layout.pos.items()):
            if c == want and (n == SERVER or n in self.peers):
                return n
        return None

    # -- switching
    def _enter(self, peer, side=None, frac=0.5):
        """Start controlling `peer`; the cursor appears on `side` of its screen, `frac` along it."""
        w, h = self.be.size()
        from_server = self.active is None
        if self.active is not None and self.active is not peer:
            self.active.put({'t': 'leave'})
        mx, my = peer.w - 1, peer.h - 1
        i = ENTRY_INSET
        if side == 'left':
            self.vx, self.vy = i, frac * my
        elif side == 'right':
            self.vx, self.vy = mx - i, frac * my
        elif side == 'top':
            self.vx, self.vy = frac * mx, i
        elif side == 'bottom':
            self.vx, self.vy = frac * mx, my - i
        else:
            self.vx, self.vy = peer.w // 2, peer.h // 2
        self.vx, self.vy = int(self.vx), int(self.vy)
        self.active = peer
        if from_server:
            self.be.freeze(True)                  # stop the real cursor following the mouse
            self.settle_until = time.time() + SETTLE
        self._after = 0
        self.be.warp(w // 2, h // 2)          # park the real cursor in the middle
        peer.put({'t': 'move', 'x': self.vx, 'y': self.vy})
        log('-> controlling', peer.name)

    def _leave(self, pos=None, why=''):
        peer, self.active = self.active, None
        if peer is None:
            return
        peer.put({'t': 'leave'})
        self.be.freeze(False)
        if pos:
            self.be.warp(*pos)
        self.cooldown = time.time() + 0.4
        log('<- control back on this machine' + (' (%s)' % why if why else ''))

    def _hotkey_switch(self, n):
        if n == 0:
            self._leave(why='hotkey')
        elif n <= len(self.layout.order):
            peer = self.peers.get(self.layout.order[n - 1])
            if peer and peer is not self.active:
                self._enter(peer)

    # -- events from the backend; each returns True to swallow the event locally
    def on_move(self, x, y, dx, dy):
        p = self.active
        w, h = self.be.size()
        if p is None:
            if time.time() < self.cooldown:
                return False
            edge = ('right' if x >= w - 2 else 'left' if x <= 1 else
                    'bottom' if y >= h - 2 else 'top' if y <= 1 else None)
            peer = self.peers.get(self._neighbor(SERVER, edge)) if edge else None
            if DEBUG and time.time() - self._dbg_t > 0.5 and (
                    x >= w - 40 or x <= 40 or y >= h - 40 or y <= 40):
                self._dbg_t = time.time()
                log('pointer (%d,%d) on %dx%d screen; edge=%s; computer there=%s'
                    % (x, y, w, h, edge, self._neighbor(SERVER, edge) if edge else None))
            if peer:
                frac = x / max(w - 1, 1) if edge in ('top', 'bottom') else y / max(h - 1, 1)
                self._enter(peer, OPPOSITE[edge], min(max(frac, 0), 1))
                return True
            return False
        if time.time() < self.settle_until:
            if DEBUG:
                log('ignored settling delta (%d,%d)' % (dx, dy))
            return True
        if DEBUG and self._after < 8:
            self._after += 1
            log('delta after taking control: (%d,%d)' % (dx, dy))
        self.vx += dx
        self.vy += dy
        mx, my = max(p.w - 1, 1), max(p.h - 1, 1)
        edge = frac = None
        if self.vx < 0:
            edge, frac = 'left', self.vy / my
        elif self.vx > p.w - 1:
            edge, frac = 'right', self.vy / my
        elif self.vy < 0:
            edge, frac = 'top', self.vx / mx
        elif self.vy > p.h - 1:
            edge, frac = 'bottom', self.vx / mx
        if edge:
            frac = min(max(frac, 0), 1)
            target = self._neighbor(p.name, edge)
            if target == SERVER:
                if edge in ('left', 'right'):
                    pos = (w - 1 - MARGIN if edge == 'left' else MARGIN, int(frac * (h - 1)))
                else:
                    pos = (int(frac * (w - 1)), h - 1 - MARGIN if edge == 'top' else MARGIN)
                self._leave(pos, 'moved off the %s edge of %s: delta (%d,%d), position (%d,%d)'
                            % (edge, p.name, dx, dy, self.vx, self.vy))
                return True
            if target and target in self.peers:
                self._enter(self.peers[target], OPPOSITE[edge], frac)
                return True
        self.vx = min(max(self.vx, 0), p.w - 1)
        self.vy = min(max(self.vy, 0), p.h - 1)
        if DEBUG:
            self._dbg += 1
            if self._dbg % 50 == 1:
                log('forwarding to %s: delta (%d,%d) -> position (%d,%d)' % (p.name, dx, dy, self.vx, self.vy))
        p.put({'t': 'move', 'x': int(self.vx), 'y': int(self.vy)})
        return True

    def on_button(self, b, down):
        if self.active is None:
            return False
        self.active.put({'t': 'btn', 'b': b, 'd': int(down)})
        return True

    def on_wheel(self, dx, dy):
        if self.active is None:
            return False
        self.active.put({'t': 'wheel', 'dx': dx, 'dy': dy})
        return True

    def on_key(self, name, down):
        if name in MODS:
            (self.mods.add if down else self.mods.discard)(name)
        if down and name.isdigit() and len(name) == 1 and self._hotkey_held():
            self.eaten.add(name)
            self._hotkey_switch(int(name))
            return True
        if not down and name in self.eaten:
            self.eaten.discard(name)
            return True
        if self.active is None:
            return False
        self.active.put({'t': 'key', 'k': name, 'd': int(down)})
        return True

    def _hotkey_held(self):
        m = self.mods
        return (m & {'lctrl', 'rctrl'}) and (m & {'lalt', 'ralt'}) and (m & {'lshift', 'rshift'})


# ------------------------------------------------ discovery + one-time pairing
# A new client finds the server by UDP broadcast, then the two run an X25519 key exchange.
# Each side derives the same 6-digit code from the exchange; the person at the server checks
# it matches the one on the new computer and approves. Only then is the passphrase sent,
# encrypted under a key only those two ends know. A man in the middle would end up with
# different codes on the two screens.
DISCOVERY_PORT = DEFAULT_PORT + 2
PAIR_TIMEOUT = 120
_P25519 = 2 ** 255 - 19
_BASE25519 = (9).to_bytes(32, 'little')


def x25519(k, u):
    """RFC 7748 scalar multiplication (pure Python; used for a handful of pairings only)."""
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, 'little')
    u = int.from_bytes(u, 'little') & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = (x2 + z2) % _P25519
        aa = a * a % _P25519
        b = (x2 - z2) % _P25519
        bb = b * b % _P25519
        e = (aa - bb) % _P25519
        c = (x3 + z3) % _P25519
        d = (x3 - z3) % _P25519
        da = d * a % _P25519
        cb = c * b % _P25519
        x3 = pow(da + cb, 2, _P25519)
        z3 = x1 * pow(da - cb, 2, _P25519) % _P25519
        x2 = aa * bb % _P25519
        z2 = e * (aa + 121665 * e) % _P25519
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, _P25519 - 2, _P25519) % _P25519).to_bytes(32, 'little')


def _pair_key(shared, a_pub, b_pub):
    return hashlib.sha256(b'kvm-pair/v1' + shared + a_pub + b_pub).digest()


def _pair_code(k):
    return '%06d' % (int.from_bytes(_hm(k, b'code')[:8], 'big') % 1000000)


def _pair_xor(k, data):
    stream = b''.join(_hm(k, b'enc', struct.pack('!I', i)) for i in range(len(data) // 32 + 1))
    return bytes(a ^ b for a, b in zip(data, stream))


def request_pairing(host, port, name, show_code, wait=PAIR_TIMEOUT + 30):
    """Client side. Calls show_code(code) once the exchange is done, then blocks until the
    person at the server approves. Returns the passphrase; raises ConnectionError otherwise."""
    s = socket.create_connection((host, port), timeout=5)
    try:
        wire = Wire(s, False)
        wire.recv()                                   # the server's normal challenge; unused here
        priv = os.urandom(32)
        a_pub = x25519(priv, _BASE25519)
        wire.send({'t': 'pair', 'name': name, 'pub': a_pub.hex()})
        r = wire.recv()
        if r.get('t') == 'error':
            raise ConnectionError(r.get('msg'))
        b_pub = bytes.fromhex(r['pub'])
        shared = x25519(priv, b_pub)
        if len(b_pub) != 32 or not any(shared):
            raise ConnectionError('bad key from the server')
        k = _pair_key(shared, a_pub, b_pub)
        show_code(_pair_code(k))
        s.settimeout(wait)
        r = wire.recv()
        if r.get('t') == 'error':
            raise ConnectionError(r.get('msg'))
        ct = bytes.fromhex(r['ct'])
        if not hmac.compare_digest(bytes.fromhex(r['mac']), _hm(k, b'mac', ct)):
            raise ConnectionError('pairing reply failed verification')
        return _pair_xor(k, ct).decode()
    finally:
        s.close()


def broadcast_addresses():
    addrs = ['255.255.255.255']
    try:
        ips = socket.gethostbyname_ex(socket.gethostname())[2] + [local_ip()]
    except OSError:
        ips = [local_ip()]
    for ip in ips:
        parts = ip.split('.')
        if len(parts) == 4 and parts[0] != '127' and all(p.isdigit() for p in parts):
            b = '.'.join(parts[:3] + ['255'])
            if b not in addrs:
                addrs.append(b)
    return addrs


def discover(port=DISCOVERY_PORT, targets=None, timeout=3.0):
    """Ask the local network 'is a server here?'. Returns [(ip, tcp_port, hostname), ...]."""
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    u.bind(('', 0))
    msg = json.dumps({'t': 'kvm-discover'}).encode()
    found = {}
    end = time.time() + timeout
    try:
        while time.time() < end:
            for t in (targets or broadcast_addresses()):
                try:
                    u.sendto(msg, (t, port))
                except OSError:
                    pass
            u.settimeout(0.5)
            try:
                data, addr = u.recvfrom(1024)
                r = json.loads(data)
                if r.get('t') == 'kvm-here':
                    found[addr[0]] = (addr[0], int(r['port']), str(r.get('name', '')))
                    end = min(end, time.time() + 0.3)       # take a moment for any others, then go
            except (socket.timeout, ValueError, KeyError):
                pass
    finally:
        u.close()
    return list(found.values())


_stdin_q = queue.Queue()
_stdin_state = {'started': False, 'eof': False}


def _stdin_reader():
    try:
        for line in sys.stdin:
            _stdin_q.put(line)
    except Exception:
        pass
    _stdin_state['eof'] = True
    _stdin_q.put('')


def terminal_approver(name, ip, code, timeout=PAIR_TIMEOUT):
    """Ask the person at the server's terminal whether to let a new computer in."""
    if not _stdin_state['started']:
        _stdin_state['started'] = True
        threading.Thread(target=_stdin_reader, daemon=True).start()
    while not _stdin_q.empty():
        try:
            _stdin_q.get_nowait()                     # drop anything typed earlier
        except queue.Empty:
            break
    if _stdin_state['eof']:
        return False
    print('\n  >>> "%s" (%s) wants to join.' % (name, ip))
    print('      Its screen shows the pairing code   %s' % code)
    print('      Type y + Enter ONLY if that exact code is on its screen (%ds): ' % timeout,
          end='', flush=True)
    try:
        line = _stdin_q.get(timeout=timeout)
    except queue.Empty:
        print('\n      timed out - not paired')
        return False
    return line.strip().lower() in ('y', 'yes')


MAX_CLIP = 100000     # characters of text shared per copy
CLIP_POLL = 0.4       # seconds between clipboard checks


class ClipSync:
    """Mirrors plain-text clipboard changes between machines; the latest copy wins.
    `send(text)` is called when the local clipboard changes; `receive(text)` applies a remote one."""

    def __init__(self, be, send, alive=lambda: True):
        self.be, self.send, self.alive = be, send, alive
        self.last = ''
        self.lock = threading.Lock()
        self.warned = False

    def _read(self):
        try:
            return self.be.clip_get()
        except Exception as e:
            if not self.warned:
                self.warned = True
                log('clipboard sharing unavailable here: %s' % e)
            return None

    def start(self):
        self.last = self._read() or ''           # what is already copied is not broadcast
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.alive():
            time.sleep(CLIP_POLL)
            t = self._read()
            if not t:
                continue
            with self.lock:
                if t == self.last:
                    continue
                self.last = t
            if len(t) > MAX_CLIP:
                log('clipboard text is over %d characters - not shared' % MAX_CLIP)
                continue
            self.send(t)

    def receive(self, text):
        """Apply a remote clipboard. Returns True if it was new (so it should be relayed)."""
        if not isinstance(text, str) or not text or len(text) > MAX_CLIP:
            return False
        with self.lock:
            if text == self.last:
                return False
            self.last = text
        try:
            self.be.clip_set(text)
        except Exception as e:
            log('could not set the clipboard: %s' % e)
        return True


class Peer:
    """One connected client as seen by the server; a writer thread owns the socket."""

    def __init__(self, name, wire, w, h):
        self.name, self.wire, self.w, self.h = name, wire, w, h
        self.q = queue.SimpleQueue()
        self.alive = True

    def put(self, msg):
        if self.alive:
            self.q.put(msg)

    def writer(self):
        try:
            while self.alive:
                try:
                    batch = [self.q.get(timeout=5)]
                except queue.Empty:
                    batch = [{'t': 'ping'}]
                while True:
                    try:
                        batch.append(self.q.get_nowait())
                    except queue.Empty:
                        break
                out = []
                for m in batch:
                    if m is None:
                        return
                    if m['t'] == 'move' and out and out[-1]['t'] == 'move':
                        out[-1] = m          # only the newest absolute position matters
                    else:
                        out.append(m)
                for m in out:
                    self.wire.send(m)
        except (OSError, ConnectionError):
            pass
        finally:
            self.close()

    def close(self):
        self.alive = False
        self.q.put(None)
        try:
            self.wire.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.wire.sock.close()


class Server:
    def __init__(self, backend, layout, port, key, auto=False, on_change=None, clipboard=True,
                 secret=None, approver=None, discovery_port=None):
        """auto=True lets any client that knows the secret join; it is added to the layout
        in the next free cell. on_change() is called whenever the layout changes."""
        self.ctl = Controller(backend, layout)
        self.be = backend
        self.layout = layout
        self.auto, self.on_change = auto, on_change
        self.key = key
        self.clip = None
        self.clipboard = clipboard
        self.secret, self.approver = secret, approver      # for one-time pairing
        self._pairing = threading.Lock()
        self.disc = None
        if discovery_port is not None:
            try:
                self.disc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.disc.bind(('0.0.0.0', discovery_port))
                self.disc.settimeout(1.0)
                self.discovery_port = self.disc.getsockname()[1]
            except OSError as e:
                log('warning: cannot answer discovery requests (%s); clients must use the IP' % e)
                self.disc = None
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))
        self.sock.listen(8)
        self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1]
        self.running = True

    def start(self):
        self.be.start_capture(self.ctl)
        if self.clipboard and hasattr(self.be, 'clip_get'):
            self.clip = ClipSync(self.be, self._broadcast_clip, lambda: self.running)
            self.clip.start()
        threading.Thread(target=self._accept_loop, daemon=True).start()
        if self.disc:
            threading.Thread(target=self._discovery_loop, daemon=True).start()

    def _discovery_loop(self):
        reply = json.dumps({'t': 'kvm-here', 'port': self.port, 'name': socket.gethostname()}).encode()
        while self.running:
            try:
                data, addr = self.disc.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                if json.loads(data).get('t') == 'kvm-discover':
                    self.disc.sendto(reply, addr)
            except (ValueError, AttributeError, OSError):
                pass

    def _pair(self, wire, m, addr):
        if not (self.approver and self.secret):
            wire.send({'t': 'error', 'msg': 'pairing is not enabled on this server'})
            return
        if not self._pairing.acquire(False):
            wire.send({'t': 'error', 'msg': 'another computer is pairing right now - try again'})
            return
        try:
            name = str(m.get('name', ''))
            a_pub = bytes.fromhex(m['pub'])
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', name) or len(a_pub) != 32:
                wire.send({'t': 'error', 'msg': 'bad pairing request'})
                return
            priv = os.urandom(32)
            b_pub = x25519(priv, _BASE25519)
            shared = x25519(priv, a_pub)
            if not any(shared):
                wire.send({'t': 'error', 'msg': 'bad key'})
                return
            k = _pair_key(shared, a_pub, b_pub)
            wire.send({'t': 'pair_pub', 'pub': b_pub.hex()})
            try:
                ok = self.approver(name, addr[0], _pair_code(k))
            except Exception:
                ok = False
            if not ok:
                wire.send({'t': 'error', 'msg': 'pairing was declined on the server'})
                log('pairing with %s declined' % name)
                return
            ct = _pair_xor(k, self.secret.encode())
            wire.send({'t': 'pair_ok', 'ct': ct.hex(), 'mac': _hm(k, b'mac', ct).hex()})
            log('paired with %s (%s)' % (name, addr[0]))
        finally:
            self._pairing.release()

    def _broadcast_clip(self, text, skip=None):
        for p in list(self.ctl.peers.values()):
            if p is not skip:
                p.put({'t': 'clip', 'text': text})

    def _accept_loop(self):
        while self.running:
            try:
                c, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve_conn, args=(c, addr), daemon=True).start()

    def _known(self, name):
        return name != SERVER and name in self.layout.pos

    def _enroll(self, name):
        if not self.auto or name == SERVER or len(self.layout.order) >= MAX_CLIENTS:
            return False
        self.layout.add(name)
        log('new client %s added (hotkey Ctrl+Alt+Shift+%d) - drag it into place in the layout editor'
            % (name, len(self.layout.order)))
        if self.on_change:
            self.on_change()
        return True

    def update_positions(self, positions):
        """Called by the layout editor. Raises ValueError on bad input."""
        self.layout.set_positions(positions)
        if self.on_change:
            self.on_change()

    def _serve_conn(self, c, addr):
        peer = None
        try:
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            c.settimeout(5)
            wire = Wire(c, True)
            s_nonce = os.urandom(16)
            wire.send({'t': 'challenge', 'n': s_nonce.hex()})
            m = wire.recv()
            if m.get('t') == 'pair':
                return self._pair(wire, m, addr)
            name = str(m['name'])
            c_nonce = bytes.fromhex(m['n'])
            want = _hm(self.key, b'client', s_nonce, c_nonce, name.encode())
            if m.get('t') != 'hello' or not hmac.compare_digest(bytes.fromhex(m['proof']), want):
                wire.send({'t': 'error', 'msg': 'authentication failed'})
                raise ConnectionError('authentication failed (wrong secret?)')
            if not self._known(name) and not self._enroll(name):
                wire.send({'t': 'error', 'msg': 'unknown client name'})
                raise ConnectionError('unknown client name %r' % name)
            wire.send({'t': 'welcome', 'proof': _hm(self.key, b'server', s_nonce, c_nonce).hex()})
            wire.key = _hm(self.key, b'session', s_nonce, c_nonce)
            c.settimeout(None)
            peer = Peer(name, wire, int(m['w']), int(m['h']))
            old = self.ctl.peers.get(name)
            if old:
                old.close()
            self.ctl.add_peer(peer)
            threading.Thread(target=peer.writer, daemon=True).start()
            log('client %s connected from %s (%dx%d)' % (name, addr[0], peer.w, peer.h))
            for line in self.ctl.describe():
                log('  ' + line)
            while True:
                m = wire.recv()      # mostly this just detects disconnects
                if m.get('t') == 'clip' and self.clip and self.clip.receive(m.get('text')):
                    self._broadcast_clip(m['text'], skip=peer)     # relay to the other computers
        except (OSError, ConnectionError, ValueError, KeyError) as e:
            log('connection from %s ended: %s' % (addr[0], e))
        finally:
            if peer:
                self.ctl.remove_peer(peer)
                peer.close()
            else:
                c.close()


# ----------------------------------------------------------------------- client
class Client:
    def __init__(self, backend, host, port, name, key, invert_scroll=False, clipboard=True,
                 on_lost=None):
        self.on_lost = on_lost          # called after repeated failures; may return a new (host, port)
        self.connected = False
        self.be, self.host, self.port, self.name, self.key = backend, host, port, name, key
        self.invert = -1 if invert_scroll else 1
        self.keys, self.buttons = set(), set()
        self.running = True
        self.n = 0
        self.got_move = False
        self.wire = None
        self.clip = None
        if clipboard and hasattr(backend, 'clip_get'):
            self.clip = ClipSync(backend, self._send_clip, lambda: self.running)

    def _send_clip(self, text):
        wire = self.wire
        if wire:
            try:
                wire.send({'t': 'clip', 'text': text})
            except OSError:
                pass

    def run(self):
        if self.clip:
            self.clip.start()
        fails = 0
        while self.running:
            self.connected = False
            try:
                self.session()
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                log('disconnected: %s' % e)
            self.release_all()
            fails = 0 if self.connected else fails + 1
            if self.on_lost and fails and fails % 3 == 0:
                new = self.on_lost()                  # -> (host, port) or None
                if new and tuple(new) != (self.host, self.port):
                    log('the server moved to %s:%d' % tuple(new))
                    self.host, self.port = new
            time.sleep(RETRY_DELAY)

    def session(self):
        s = socket.create_connection((self.host, self.port), timeout=5)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            wire = Wire(s, False)
            ch = wire.recv()
            if ch.get('t') != 'challenge':
                raise ConnectionError('unexpected reply from server')
            s_nonce = bytes.fromhex(ch['n'])
            c_nonce = os.urandom(16)
            w, h = self.be.size()
            wire.send({'t': 'hello', 'name': self.name, 'w': w, 'h': h, 'n': c_nonce.hex(),
                       'proof': _hm(self.key, b'client', s_nonce, c_nonce, self.name.encode()).hex()})
            wm = wire.recv()
            if wm.get('t') == 'error':
                raise ConnectionError('server refused: %s' % wm.get('msg'))
            if not hmac.compare_digest(bytes.fromhex(wm['proof']),
                                       _hm(self.key, b'server', s_nonce, c_nonce)):
                raise ConnectionError('server failed authentication')
            wire.key = _hm(self.key, b'session', s_nonce, c_nonce)
            s.settimeout(20)         # server pings every 5 s
            log('connected to %s:%d as %s' % (self.host, self.port, self.name))
            self.got_move = False
            self.connected = True
            self.wire = wire
            while True:
                self.apply(wire.recv())
        finally:
            self.wire = None
            s.close()

    def apply(self, m):
        t = m['t']
        if DEBUG and t != 'ping':
            self.n += 1
            if t != 'move' or self.n <= 10 or self.n % 100 == 0:
                log('recv', m)
        if t == 'move':
            if not self.got_move:
                self.got_move = True
                log('the server is now sending input here (first mouse position %s,%s)' % (m['x'], m['y']))
            self.be.inject_move(int(m['x']), int(m['y']))
        elif t == 'btn':
            (self.buttons.add if m['d'] else self.buttons.discard)(m['b'])
            self.be.inject_button(m['b'], bool(m['d']))
        elif t == 'wheel':
            self.be.inject_wheel(self.invert * int(m['dx']), self.invert * int(m['dy']))
        elif t == 'key':
            (self.keys.add if m['d'] else self.keys.discard)(m['k'])
            self.be.inject_key(m['k'], bool(m['d']))
        elif t == 'leave':
            self.release_all()
        elif t == 'clip' and self.clip:
            self.clip.receive(m.get('text'))

    def release_all(self):
        for k in list(self.keys):
            self.be.inject_key(k, False)
        for b in list(self.buttons):
            self.be.inject_button(b, False)
        self.keys.clear()
        self.buttons.clear()


# --------------------------------------------------------------- Windows backend
class WinBackend:
    """Low-level hooks (capture) + SendInput (inject) through ctypes. No admin needed,
    but it cannot see or control elevated windows / the UAC prompt."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes as wt
        self.ct, self.wt = ctypes, wt
        self.u = ctypes.WinDLL('user32', use_last_error=True)
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        try:
            self.u.SetProcessDPIAware()
        except Exception:
            pass
        c = ctypes
        WPARAM, LPARAM = c.c_size_t, c.c_ssize_t

        class MSLL(c.Structure):
            _fields_ = [('x', wt.LONG), ('y', wt.LONG), ('mouseData', wt.DWORD),
                        ('flags', wt.DWORD), ('time', wt.DWORD), ('extra', c.c_size_t)]

        class KBLL(c.Structure):
            _fields_ = [('vk', wt.DWORD), ('scan', wt.DWORD), ('flags', wt.DWORD),
                        ('time', wt.DWORD), ('extra', c.c_size_t)]

        class MOUSEINPUT(c.Structure):
            _fields_ = [('dx', wt.LONG), ('dy', wt.LONG), ('mouseData', wt.DWORD),
                        ('dwFlags', wt.DWORD), ('time', wt.DWORD), ('extra', c.c_size_t)]

        class KEYBDINPUT(c.Structure):
            _fields_ = [('wVk', wt.WORD), ('wScan', wt.WORD), ('dwFlags', wt.DWORD),
                        ('time', wt.DWORD), ('extra', c.c_size_t)]

        class _U(c.Union):
            _fields_ = [('mi', MOUSEINPUT), ('ki', KEYBDINPUT)]

        class INPUT(c.Structure):
            _fields_ = [('type', wt.DWORD), ('u', _U)]

        self.MSLL, self.KBLL, self.INPUT = MSLL, KBLL, INPUT
        self.MOUSEINPUT, self.KEYBDINPUT = MOUSEINPUT, KEYBDINPUT
        self.HOOKPROC = c.WINFUNCTYPE(c.c_ssize_t, c.c_int, WPARAM, LPARAM)
        u = self.u
        u.SetWindowsHookExW.argtypes = [c.c_int, self.HOOKPROC, c.c_void_p, wt.DWORD]
        u.SetWindowsHookExW.restype = c.c_void_p
        u.CallNextHookEx.argtypes = [c.c_void_p, c.c_int, WPARAM, LPARAM]
        u.CallNextHookEx.restype = c.c_ssize_t
        u.SendInput.argtypes = [wt.UINT, c.POINTER(INPUT), c.c_int]
        u.GetMessageW.argtypes = [c.POINTER(wt.MSG), c.c_void_p, wt.UINT, wt.UINT]
        u.MapVirtualKeyW.argtypes = [wt.UINT, wt.UINT]
        self.k.GetModuleHandleW.argtypes = [wt.LPCWSTR]
        self.k.GetModuleHandleW.restype = c.c_void_p
        self.h = None
        self.ax = self.ay = self.lx = self.ly = 0

    def size(self):
        return self.u.GetSystemMetrics(0), self.u.GetSystemMetrics(1)

    def warp(self, x, y):
        self.ax, self.ay = x, y
        self.u.SetCursorPos(int(x), int(y))

    def freeze(self, on):
        pass

    # ---- clipboard (plain text, CF_UNICODETEXT)
    def _clip_init(self):
        if getattr(self, '_clip_ready', False):
            return
        c, wt, u, k = self.ct, self.wt, self.u, self.k
        vp = c.c_void_p
        u.OpenClipboard.argtypes, u.OpenClipboard.restype = [wt.HWND], wt.BOOL
        u.CloseClipboard.restype = wt.BOOL
        u.EmptyClipboard.restype = wt.BOOL
        u.GetClipboardData.argtypes, u.GetClipboardData.restype = [wt.UINT], vp
        u.SetClipboardData.argtypes, u.SetClipboardData.restype = [wt.UINT, vp], vp
        u.GetClipboardSequenceNumber.restype = wt.DWORD
        k.GlobalAlloc.argtypes, k.GlobalAlloc.restype = [wt.UINT, c.c_size_t], vp
        k.GlobalLock.argtypes, k.GlobalLock.restype = [vp], vp
        k.GlobalUnlock.argtypes, k.GlobalUnlock.restype = [vp], wt.BOOL
        k.GlobalFree.argtypes, k.GlobalFree.restype = [vp], vp
        self._clip_seq = None
        self._clip_ready = True

    def _open_clip(self):
        for _ in range(10):                       # another program may hold it for a moment
            if self.u.OpenClipboard(None):
                return True
            time.sleep(0.02)
        return False

    def clip_get(self):
        self._clip_init()
        seq = self.u.GetClipboardSequenceNumber()
        if seq == self._clip_seq:
            return None                           # unchanged since the last look
        if not self._open_clip():
            return None
        try:
            self._clip_seq = seq
            h = self.u.GetClipboardData(13)       # CF_UNICODETEXT
            if not h:
                return None                       # not text (image, files, ...)
            ptr = self.k.GlobalLock(h)
            if not ptr:
                return None
            try:
                return self.ct.wstring_at(ptr).replace('\r\n', '\n')
            finally:
                self.k.GlobalUnlock(h)
        finally:
            self.u.CloseClipboard()

    def clip_set(self, text):
        self._clip_init()
        data = text.replace('\r\n', '\n').replace('\n', '\r\n')
        raw = (data + '\0').encode('utf-16-le')
        if not self._open_clip():
            raise OSError('clipboard is busy')
        try:
            self.u.EmptyClipboard()
            h = self.k.GlobalAlloc(0x0002, len(raw))   # GMEM_MOVEABLE
            if not h:
                raise OSError('out of memory')
            ptr = self.k.GlobalLock(h)
            self.ct.memmove(ptr, raw, len(raw))
            self.k.GlobalUnlock(h)
            if not self.u.SetClipboardData(13, h):
                self.k.GlobalFree(h)
                raise OSError('SetClipboardData failed (error %d)' % self.ct.get_last_error())
        finally:
            self.u.CloseClipboard()

    def cursor_pos(self):
        pt = self.wt.POINT()
        self.u.GetCursorPos(self.ct.byref(pt))
        return pt.x, pt.y

    # ---- capture
    def start_capture(self, handler):
        self.h = handler
        ready, err = threading.Event(), []

        def loop():
            c = self.ct
            self._mp, self._kp = self.HOOKPROC(self._mouse), self.HOOKPROC(self._kbd)
            mod = self.k.GetModuleHandleW(None)
            hm = self.u.SetWindowsHookExW(14, self._mp, mod, 0)   # WH_MOUSE_LL
            hk = self.u.SetWindowsHookExW(13, self._kp, mod, 0)   # WH_KEYBOARD_LL
            if not hm or not hk:
                err.append(c.get_last_error())
                ready.set()
                return
            ready.set()
            msg = self.wt.MSG()
            while self.u.GetMessageW(c.byref(msg), None, 0, 0) > 0:
                pass

        threading.Thread(target=loop, daemon=True).start()
        ready.wait()
        if err:
            raise OSError('SetWindowsHookEx failed (error %s) - blocked by policy?' % err[0])

    def _mouse(self, code, wparam, lparam):
        if code >= 0:
            try:
                s = self.ct.cast(lparam, self.ct.POINTER(self.MSLL)).contents
                if self._mouse_event(wparam, s):
                    return 1
            except Exception:
                traceback.print_exc()
        return self.u.CallNextHookEx(None, code, wparam, lparam)

    def _mouse_event(self, wp, s):
        h = self.h
        if wp == 0x200:                                   # WM_MOUSEMOVE
            if h.active is not None:                      # cursor is parked at the anchor
                dx, dy = s.x - self.ax, s.y - self.ay
                if dx == 0 and dy == 0:
                    return True
            else:
                dx, dy = s.x - self.lx, s.y - self.ly
            self.lx, self.ly = s.x, s.y
            if DEBUG:
                log('move', s.x, s.y, dx, dy)
            return h.on_move(s.x, s.y, dx, dy)
        buttons = {0x201: ('l', 1), 0x202: ('l', 0), 0x204: ('r', 1), 0x205: ('r', 0),
                   0x207: ('m', 1), 0x208: ('m', 0)}
        if wp in buttons:
            return h.on_button(*buttons[wp])
        if wp in (0x20B, 0x20C):                          # X buttons
            b = 'x1' if (s.mouseData >> 16) == 1 else 'x2'
            return h.on_button(b, wp == 0x20B)
        if wp in (0x20A, 0x20E):                          # wheel / hwheel
            d = self.ct.c_short(s.mouseData >> 16).value
            return h.on_wheel(d, 0) if wp == 0x20E else h.on_wheel(0, d)
        return False

    def _kbd(self, code, wparam, lparam):
        if code >= 0:
            try:
                s = self.ct.cast(lparam, self.ct.POINTER(self.KBLL)).contents
                name = 'kpenter' if (s.vk == 0x0D and s.flags & 1) else WIN2NAME.get(s.vk)
                if name is None:
                    if self.h.active is not None:
                        return 1
                elif self.h.on_key(name, wparam in (0x100, 0x104)):
                    return 1
            except Exception:
                traceback.print_exc()
        return self.u.CallNextHookEx(None, code, wparam, lparam)

    # ---- inject
    def _send(self, inp):
        if self.u.SendInput(1, self.ct.byref(inp), self.ct.sizeof(self.INPUT)) != 1:
            err = self.ct.get_last_error()
            if not getattr(self, '_warned', False):
                self._warned = True
                log('WARNING: Windows refused injected input (SendInput error %d%s). '
                    'Try running from a normal (non-admin) Command Prompt, and check security software.'
                    % (err, ' = access denied' if err == 5 else ''))

    def _mouse_input(self, flags, data=0, dx=0, dy=0):
        i = self.INPUT()
        i.type = 0
        i.u.mi = self.MOUSEINPUT(dx, dy, data & 0xFFFFFFFF, flags, 0, 0)
        self._send(i)

    def inject_move(self, x, y):
        w, h = self.size()
        self._mouse_input(0x8001, 0, x * 65535 // max(w - 1, 1), y * 65535 // max(h - 1, 1))

    def inject_button(self, b, down):
        flags = {'l': (0x2, 0x4), 'r': (0x8, 0x10), 'm': (0x20, 0x40),
                 'x1': (0x80, 0x100), 'x2': (0x80, 0x100)}[b][0 if down else 1]
        self._mouse_input(flags, {'x1': 1, 'x2': 2}.get(b, 0))

    def inject_wheel(self, dx, dy):
        if dy:
            self._mouse_input(0x800, dy)
        if dx:
            self._mouse_input(0x1000, dx)

    def inject_key(self, name, down):
        vk = NAME2WIN.get(name)
        if vk is None:
            return
        i = self.INPUT()
        i.type = 1
        flags = (1 if name in WIN_EXTENDED else 0) | (0 if down else 2)
        i.u.ki = self.KEYBDINPUT(vk, self.u.MapVirtualKeyW(vk, 0), flags, 0, 0)
        self._send(i)


# ----------------------------------------------------------------- macOS backend
class MacBackend:
    """CGEventTap (capture) + CGEventPost (inject) through ctypes. The terminal app
    running this needs Accessibility and Input Monitoring permission."""

    DEVMASK = {'lshift': 0x2, 'rshift': 0x4, 'lctrl': 0x1, 'rctrl': 0x2000, 'lalt': 0x20,
               'ralt': 0x40, 'lmeta': 0x8, 'rmeta': 0x10}
    FLAG = {'lshift': 0x20000, 'rshift': 0x20000, 'lctrl': 0x40000, 'rctrl': 0x40000,
            'lalt': 0x80000, 'ralt': 0x80000, 'lmeta': 0x100000, 'rmeta': 0x100000}
    BTN = {'l': (1, 2, 0), 'r': (3, 4, 1), 'm': (25, 26, 2), 'x1': (25, 26, 3), 'x2': (25, 26, 4)}

    def __init__(self):
        import ctypes
        import ctypes.util
        c = self.c = ctypes

        class CGPoint(c.Structure):
            _fields_ = [('x', c.c_double), ('y', c.c_double)]

        class CGSize(c.Structure):
            _fields_ = [('w', c.c_double), ('h', c.c_double)]

        class CGRect(c.Structure):
            _fields_ = [('o', CGPoint), ('s', CGSize)]

        self.CGPoint = CGPoint
        cg = self.cg = c.CDLL(ctypes.util.find_library('ApplicationServices'))
        cf = self.cf = c.CDLL(ctypes.util.find_library('CoreFoundation'))
        vp, u32, i64, u64 = c.c_void_p, c.c_uint32, c.c_int64, c.c_uint64
        cg.CGMainDisplayID.restype = u32
        cg.CGDisplayBounds.argtypes, cg.CGDisplayBounds.restype = [u32], CGRect
        cg.CGEventCreateMouseEvent.argtypes = [vp, u32, CGPoint, u32]
        cg.CGEventCreateMouseEvent.restype = vp
        cg.CGEventCreateKeyboardEvent.argtypes = [vp, c.c_uint16, c.c_bool]
        cg.CGEventCreateKeyboardEvent.restype = vp
        cg.CGEventCreateScrollWheelEvent2.argtypes = [vp, u32, u32, c.c_int32, c.c_int32, c.c_int32]
        cg.CGEventCreateScrollWheelEvent2.restype = vp
        cg.CGEventSetFlags.argtypes = [vp, u64]
        cg.CGEventGetFlags.argtypes, cg.CGEventGetFlags.restype = [vp], u64
        cg.CGEventPost.argtypes = [u32, vp]
        cg.CGEventSetIntegerValueField.argtypes = [vp, u32, i64]
        cg.CGEventGetIntegerValueField.argtypes, cg.CGEventGetIntegerValueField.restype = [vp, u32], i64
        cg.CGEventGetLocation.argtypes, cg.CGEventGetLocation.restype = [vp], CGPoint
        cg.CGEventCreate.argtypes, cg.CGEventCreate.restype = [vp], vp
        cg.CGAssociateMouseAndMouseCursorPosition.argtypes = [c.c_int32]
        cg.CGDisplayHideCursor.argtypes = [u32]
        cg.CGDisplayShowCursor.argtypes = [u32]
        cg.CGWarpMouseCursorPosition.argtypes = [CGPoint]
        cg.CGEventTapEnable.argtypes = [vp, c.c_bool]
        self.TAPCB = c.CFUNCTYPE(vp, vp, u32, vp, vp)
        cg.CGEventTapCreate.argtypes = [u32, u32, u32, u64, self.TAPCB, vp]
        cg.CGEventTapCreate.restype = vp
        cf.CFRelease.argtypes = [vp]
        cf.CFMachPortCreateRunLoopSource.argtypes = [vp, vp, c.c_long]
        cf.CFMachPortCreateRunLoopSource.restype = vp
        cf.CFRunLoopGetCurrent.restype = vp
        cf.CFRunLoopAddSource.argtypes = [vp, vp, vp]
        try:
            cg.CGSetLocalEventsSuppressionInterval.argtypes = [c.c_double]
            cg.CGSetLocalEventsSuppressionInterval(0.0)   # no 0.25 s freeze after a warp
        except Exception:
            pass
        import atexit
        atexit.register(lambda: (cg.CGAssociateMouseAndMouseCursorPosition(1), self._hide(False)))  # never leave it frozen
        self.hidden = False
        self.pumping = False
        self._calls = queue.SimpleQueue()
        self.drift, self.rehid = 0, 0
        self.park = None                    # while controlling a client: where the real cursor is held
        self.pos = (0, 0)
        self.down_mods, self.held = set(), set()
        self.last_click = (0.0, None, (0, 0), 0)
        self.h = self.tap = None

    def size(self):
        r = self.cg.CGDisplayBounds(self.cg.CGMainDisplayID())
        return int(r.s.w), int(r.s.h)

    def warp(self, x, y):
        self.cg.CGWarpMouseCursorPosition(self.CGPoint(x, y))

    def freeze(self, on):
        """While controlling a client: detach the cursor from the mouse (deltas still arrive),
        hide it, and hold it at the centre. macOS ignores a dropped mouse-move for the cursor
        itself, so each of these is a belt-and-braces layer."""
        self.park = tuple(v // 2 for v in self.size()) if on else None
        if on:
            self.drift = self.rehid = 0
        self._main(lambda: self._apply_freeze(on))

    # The cursor-hiding / association calls only take effect when made from the process's MAIN
    # thread (from the event-tap thread they return success but do nothing, as the --debug log
    # showed), so they are queued to the main loop, which run_server drives through pump().
    def _main(self, fn):
        if self.pumping:
            self._calls.put(fn)
        else:
            fn()

    def pump(self, timeout=1.0):
        self.pumping = True
        try:
            fn = self._calls.get(timeout=0.1 if self.park else timeout)
        except queue.Empty:
            if self.park:                        # controlling a client: keep the cursor frozen + hidden
                fn = self._reassert
            else:
                return
        try:
            fn()
        except Exception:
            traceback.print_exc()

    def _apply_freeze(self, on):
        if on:
            self.warp(*self.park)                # leave whatever was under the cursor (Dock, menu bar...)
        err = self.cg.CGAssociateMouseAndMouseCursorPosition(0 if on else 1)
        if on:
            tries = self._conceal()
        else:
            self._hide(False)
            tries = 0
        if DEBUG:
            log('mac cursor %s (CGAssociate returned %s; hidden=%s after %d tries)'
                % ('frozen' if on else 'released', err, not self.cg.CGCursorIsVisible(), tries))
            if not on and self.drift:
                log('mac cursor position drifted %d times while a client was controlled' % self.drift)

    def _conceal(self):
        """Hide the cursor and check it took. Whatever was under the cursor when control switched
        (the Dock, the menu bar, a window) can keep owning the cursor until the window server
        sees a real mouse event at the new spot, so if it stays visible we post one harmless
        move at the parking spot and try again."""
        for tries in range(1, 7):
            self.hidden = False
            self._hide(True)
            if not self.cg.CGCursorIsVisible():
                return tries
            self._nudge()
            time.sleep(0.04)
        return tries

    def _nudge(self):
        ev = self.cg.CGEventCreateMouseEvent(None, 5, self.CGPoint(*(self.park or self.pos)), 0)
        self.cg.CGEventSetIntegerValueField(ev, 42, self.NUDGE)
        self.cg.CGEventPost(0, ev)
        self.cf.CFRelease(ev)

    def _reassert(self):
        if not self.park:
            return
        self.cg.CGAssociateMouseAndMouseCursorPosition(0)
        if self.cg.CGCursorIsVisible():
            self.rehid += 1
            if DEBUG and self.rehid <= 3:
                log('mac cursor became visible again - hiding it')
            self._conceal()

    def _hold(self, loc):
        """Called for every mouse event swallowed while controlling a client: keep the real
        cursor parked, frozen and hidden, and say so in --debug if macOS fought back."""
        pos = (int(loc.x), int(loc.y))
        if pos != self.park:
            self.drift += 1
            if DEBUG and self.drift <= 5:
                log('mac cursor drifted to %s while frozen (parked at %s) - warping it back' % (pos, self.park))
            self.warp(*self.park)                # dropping the event does not stop the cursor

    def _hide(self, on):
        if on == self.hidden:
            return
        cf, cg, c = self.cf, self.cg, self.c
        try:
            if on:
                # a background process may only hide the cursor with this connection property
                cf.CFStringCreateWithCString.argtypes = [c.c_void_p, c.c_char_p, c.c_uint32]
                cf.CFStringCreateWithCString.restype = c.c_void_p
                key = cf.CFStringCreateWithCString(None, b'SetsCursorInBackground', 0x08000100)
                true = c.c_void_p.in_dll(cf, 'kCFBooleanTrue')
                cg.CGSDefaultConnectionForThread.restype = c.c_int
                cid = cg.CGSDefaultConnectionForThread()
                cg.CGSSetConnectionProperty.argtypes = [c.c_int, c.c_int, c.c_void_p, c.c_void_p]
                cg.CGSSetConnectionProperty(cid, cid, key, true)
                cg.CGDisplayHideCursor(cg.CGMainDisplayID())
            else:
                for _ in range(5):                    # hide/show are counted: undo until visible
                    cg.CGDisplayShowCursor(cg.CGMainDisplayID())
                    if cg.CGCursorIsVisible():
                        break
            self.hidden = on
        except Exception as e:           # private API: if it is missing the cursor just stays visible
            if DEBUG:
                log('could not %s the cursor: %s' % ('hide' if on else 'show', e))

    # ---- clipboard (plain text) via the system tools every Mac has
    @staticmethod
    def _clip_env():
        return dict(os.environ, LANG='en_US.UTF-8', LC_ALL='en_US.UTF-8')

    def clip_get(self):
        import subprocess
        r = subprocess.run(['pbpaste'], capture_output=True, env=self._clip_env(), timeout=5)
        return r.stdout.decode('utf-8', 'replace') if r.returncode == 0 else None

    def clip_set(self, text):
        import subprocess
        subprocess.run(['pbcopy'], input=text.encode('utf-8'), env=self._clip_env(), timeout=5, check=True)

    def cursor_pos(self):
        ev = self.cg.CGEventCreate(None)
        p = self.cg.CGEventGetLocation(ev)
        self.cf.CFRelease(ev)
        return int(round(p.x)), int(round(p.y))

    # ---- capture
    def start_capture(self, handler):
        self.h = handler
        ready, err = threading.Event(), []
        types = [1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 22, 25, 26, 27]
        mask = 0
        for t in types:
            mask |= 1 << t

        def loop():
            self._cb = self.TAPCB(self._tap)
            self.tap = self.cg.CGEventTapCreate(0, 0, 0, mask, self._cb, None)
            if not self.tap:
                err.append(1)
                ready.set()
                return
            src = self.cf.CFMachPortCreateRunLoopSource(None, self.tap, 0)
            mode = self.c.c_void_p.in_dll(self.cf, 'kCFRunLoopCommonModes')
            self.cf.CFRunLoopAddSource(self.cf.CFRunLoopGetCurrent(), src, mode)
            self.cg.CGEventTapEnable(self.tap, True)
            ready.set()
            self.cf.CFRunLoopRun()

        threading.Thread(target=loop, daemon=True).start()
        ready.wait()
        if err:
            raise OSError('cannot create the event tap - grant this terminal app Accessibility '
                          'and Input Monitoring in System Settings > Privacy & Security, then restart it')

    NUDGE = 0x4B564D31      # tags the one mouse-move we post ourselves so our tap lets it through

    def _tap(self, proxy, etype, event, refcon):
        cg, h = self.cg, self.h
        try:
            if etype in (0xFFFFFFFE, 0xFFFFFFFF):          # tap disabled by timeout / user
                cg.CGEventTapEnable(self.tap, True)
                return event
            if cg.CGEventGetIntegerValueField(event, 42) == self.NUDGE:
                return event
            swallow = False
            if etype in (5, 6, 7, 27):
                loc = cg.CGEventGetLocation(event)
                dx = cg.CGEventGetIntegerValueField(event, 4)
                dy = cg.CGEventGetIntegerValueField(event, 5)
                swallow = h.on_move(loc.x, loc.y, dx, dy)
                if swallow and self.park:
                    self._hold(loc)
            elif etype in (1, 2, 3, 4, 25, 26):
                if etype in (1, 2):
                    b = 'l'
                elif etype in (3, 4):
                    b = 'r'
                else:
                    n = cg.CGEventGetIntegerValueField(event, 3)
                    b = {2: 'm', 3: 'x1'}.get(n, 'x2')
                swallow = h.on_button(b, etype in (1, 3, 25))
            elif etype == 22:
                swallow = h.on_wheel(int(cg.CGEventGetIntegerValueField(event, 12)) * 120,
                                     int(cg.CGEventGetIntegerValueField(event, 11)) * 120)
            elif etype in (10, 11, 12):
                name = MAC2NAME.get(cg.CGEventGetIntegerValueField(event, 9))
                if name is None:
                    swallow = h.active is not None
                elif etype == 12 and name == 'capslock':
                    swallow = h.on_key(name, True)
                    h.on_key(name, False)
                elif etype == 12:
                    swallow = h.on_key(name, bool(cg.CGEventGetFlags(event) & self.DEVMASK[name]))
                else:
                    swallow = h.on_key(name, etype == 10)
            return None if swallow else event
        except Exception:
            traceback.print_exc()
            return event

    # ---- inject
    def _post(self, ev):
        flags = 0
        for m in self.down_mods:
            flags |= self.FLAG[m]
        self.cg.CGEventSetFlags(ev, flags)
        self.cg.CGEventPost(0, ev)
        self.cf.CFRelease(ev)

    def inject_move(self, x, y):
        self.pos = (x, y)
        t, btn = 5, 0
        if self.held:
            b = sorted(self.held)[0]
            t, btn = {'l': (6, 0), 'r': (7, 1)}.get(b, (27, self.BTN[b][2]))
        self._post(self.cg.CGEventCreateMouseEvent(None, t, self.CGPoint(x, y), btn))

    def inject_button(self, b, down):
        dn, up, num = self.BTN[b]
        (self.held.add if down else self.held.discard)(b)
        ev = self.cg.CGEventCreateMouseEvent(None, dn if down else up, self.CGPoint(*self.pos), num)
        if down:                                           # apps need a click count for double-click
            now, lb, lp, cnt = self.last_click
            cnt = cnt + 1 if (lb == b and now > time.time() - 0.4 and lp == self.pos) else 1
            self.last_click = (time.time(), b, self.pos, cnt)
            self.cg.CGEventSetIntegerValueField(ev, 1, cnt)
        else:
            self.cg.CGEventSetIntegerValueField(ev, 1, self.last_click[3])
        self._post(ev)

    def inject_wheel(self, dx, dy):
        self._post(self.cg.CGEventCreateScrollWheelEvent2(None, 0, 2, dy // 3, dx // 3, 0))

    def inject_key(self, name, down):
        kc = NAME2MAC.get(name)
        if kc is None:
            return
        if name in self.FLAG:
            (self.down_mods.add if down else self.down_mods.discard)(name)
        self._post(self.cg.CGEventCreateKeyboardEvent(None, kc, down))


# ------------------------------------------------------------------------- main
def make_backend():
    if sys.platform == 'win32':
        return WinBackend()
    if sys.platform == 'darwin':
        return MacBackend()
    sys.exit('kvm.py supports Windows and macOS only')


def selftest():
    """Move the local cursor with the injection code and read it back. Isolates 'can this
    machine be controlled?' from networking. Run it on any machine that will be a client."""
    be = make_backend()
    w, h = be.size()
    print('screen size seen by the script: %dx%d' % (w, h))
    start = be.cursor_pos()
    ok = True
    for x, y in ((w // 4, h // 4), (w // 2, h // 2), (3 * w // 4, 3 * h // 4)):
        be.inject_move(x, y)
        time.sleep(0.3)
        got = be.cursor_pos()
        good = abs(got[0] - x) <= 3 and abs(got[1] - y) <= 3
        ok = ok and good
        print('  asked for %-12s cursor is at %-12s %s' % ((x, y), got, 'OK' if good else 'FAIL'))
    be.inject_move(*start)
    print('RESULT:', 'injection works - this machine can be controlled.' if ok else
          'injection FAILED - the cursor did not follow. Send this output to the developer.')
    return 0 if ok else 1


def parse_layout(items):
    layout = Layout()
    for it in items:
        edge, _, name = it.rpartition(':')
        if edge not in ('', 'left', 'right', 'top', 'bottom'):
            sys.exit('bad --client %r: use [left|right|top|bottom:]NAME' % it)
        if not name or name == SERVER:
            sys.exit('bad client name %r' % name)
        layout.add(name, edge or None)
    if len(layout.order) > MAX_CLIENTS:
        sys.exit('at most %d clients' % MAX_CLIENTS)
    return layout


def main(argv=None):
    global DEBUG
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='mode', required=True)
    for mode in ('server', 'client'):
        p = sub.add_parser(mode)
        p.add_argument('--secret', default=os.environ.get('KVM_SECRET'),
                       help='shared passphrase (or set KVM_SECRET); must match on all machines')
        p.add_argument('--port', type=int, default=DEFAULT_PORT)
        p.add_argument('--debug', action='store_true')
        p.add_argument('--no-clipboard', action='store_true', help='do not share the text clipboard')
    sp = sub.choices['server']
    sp.add_argument('--client', action='append', required=True, metavar='[EDGE:]NAME',
                    help='allowed client; EDGE is where its screen sits relative to this one. '
                         'Order = hotkey number (Ctrl+Alt+Shift+1..9 for the first nine)')
    cp = sub.choices['client']
    cp.add_argument('--server', required=True, help='IP or hostname of the server')
    cp.add_argument('--name', required=True, help='this client\'s name as listed on the server')
    cp.add_argument('--invert-scroll', action='store_true')
    sub.add_parser('selftest', help='move the local cursor to check input injection works')
    a = ap.parse_args(argv)
    DEBUG = getattr(a, 'debug', False)
    if a.mode == 'selftest':
        sys.exit(selftest())
    if not a.secret:
        sys.exit('set --secret or KVM_SECRET')
    if a.mode == 'server':
        run_server(parse_layout(a.client), a.port, a.secret, clipboard=not a.no_clipboard)
    else:
        run_client(a.server, a.port, a.name, a.secret, a.invert_scroll, not a.no_clipboard)


def run_server(layout, port, secret, auto=False, on_change=None, on_ready=None, clipboard=True,
               pairing=False):
    try:
        be = make_backend()
        srv = Server(be, layout, port, derive_key(secret), auto, on_change, clipboard,
                     secret=secret if pairing else None,
                     approver=terminal_approver if pairing else None,
                     discovery_port=DISCOVERY_PORT if pairing else None)
        srv.start()
        log('server listening on port %d; screen %dx%d' % (srv.port, *be.size()))
        for i, n in enumerate(layout.order, 1):
            log('  client %-12s hotkey Ctrl+Alt+Shift+%d' % (n, i))
        if on_ready:
            on_ready(srv)
        if auto:
            log('  waiting for clients to connect...')
        log('  return to this machine: Ctrl+Alt+Shift+0 (or cross the screen edge back)')
        log('  press Ctrl+C here to stop')
        pump = getattr(be, 'pump', time.sleep)
        while True:
            pump(1.0)
    except KeyboardInterrupt:
        pass
    except OSError as e:
        sys.exit('error: %s' % e)


def run_client(host, port, name, secret, invert_scroll=False, clipboard=True, on_lost=None):
    try:
        Client(make_backend(), host, port, name, derive_key(secret), invert_scroll, clipboard,
               on_lost).run()
    except KeyboardInterrupt:
        pass
    except OSError as e:
        sys.exit('error: %s' % e)


# ------------------------------------------- helpers for server.py / client.py
CONFIG_PATH = os.path.join(os.path.expanduser('~'), '.kvm_share.json')


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_section(name, value):
    """Update just one section ('server' or 'client') so the two never overwrite each other."""
    cfg = load_config()
    cfg[name] = value
    save_config(cfg)


def save_config(cfg):
    """Settings include the shared passphrase, so keep the file private to this user."""
    try:
        fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(cfg, f, indent=2)
    except OSError as e:
        log('could not save settings: %s' % e)


def local_ip():
    """Best guess at this machine's LAN address (no traffic is actually sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return '<this machine\'s IP>'


if __name__ == '__main__':
    main()
