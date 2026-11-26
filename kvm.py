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
import socket
import struct
import sys
import threading
import time
import traceback

DEFAULT_PORT = 24801
MARGIN = 4          # px from the edge where the cursor reappears when control returns
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
MAX_FRAME = 1 << 16


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
        if n > MAX_FRAME:
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
MAX_CLIENTS = 9


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

    # -- peers
    def add_peer(self, peer):
        self.peers[peer.name] = peer

    def remove_peer(self, peer):
        if self.peers.get(peer.name) is peer:
            del self.peers[peer.name]
        if self.active is peer:
            self.active = None
            log('active client %s disconnected - control back on this machine' % peer.name)

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
        if self.active is not None and self.active is not peer:
            self.active.put({'t': 'leave'})
        mx, my = peer.w - 1, peer.h - 1
        if side == 'left':
            self.vx, self.vy = 0, frac * my
        elif side == 'right':
            self.vx, self.vy = mx, frac * my
        elif side == 'top':
            self.vx, self.vy = frac * mx, 0
        elif side == 'bottom':
            self.vx, self.vy = frac * mx, my
        else:
            self.vx, self.vy = peer.w // 2, peer.h // 2
        self.vx, self.vy = int(self.vx), int(self.vy)
        self.active = peer
        self.be.warp(w // 2, h // 2)          # park the real cursor in the middle
        peer.put({'t': 'move', 'x': self.vx, 'y': self.vy})
        log('-> controlling', peer.name)

    def _leave(self, pos=None):
        peer, self.active = self.active, None
        if peer is None:
            return
        peer.put({'t': 'leave'})
        if pos:
            self.be.warp(*pos)
        self.cooldown = time.time() + 0.4
        log('<- control back on this machine')

    def _hotkey_switch(self, n):
        if n == 0:
            self._leave()
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
            if peer:
                frac = x / max(w - 1, 1) if edge in ('top', 'bottom') else y / max(h - 1, 1)
                self._enter(peer, OPPOSITE[edge], min(max(frac, 0), 1))
                return True
            return False
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
                self._leave(pos)
                return True
            if target and target in self.peers:
                self._enter(self.peers[target], OPPOSITE[edge], frac)
                return True
        self.vx = min(max(self.vx, 0), p.w - 1)
        self.vy = min(max(self.vy, 0), p.h - 1)
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
    def __init__(self, backend, layout, port, key, auto=False, on_change=None):
        """auto=True lets any client that knows the secret join; it is added to the layout
        in the next free cell. on_change() is called whenever the layout changes."""
        self.ctl = Controller(backend, layout)
        self.be = backend
        self.layout = layout
        self.auto, self.on_change = auto, on_change
        self.key = key
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', port))
        self.sock.listen(8)
        self.sock.settimeout(1.0)
        self.port = self.sock.getsockname()[1]
        self.running = True

    def start(self):
        self.be.start_capture(self.ctl)
        threading.Thread(target=self._accept_loop, daemon=True).start()

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
            while True:
                wire.recv()          # clients send nothing; this just detects disconnects
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
    def __init__(self, backend, host, port, name, key, invert_scroll=False):
        self.be, self.host, self.port, self.name, self.key = backend, host, port, name, key
        self.invert = -1 if invert_scroll else 1
        self.keys, self.buttons = set(), set()
        self.running = True

    def run(self):
        while self.running:
            try:
                self.session()
            except (OSError, ConnectionError, ValueError, KeyError) as e:
                log('disconnected: %s' % e)
            self.release_all()
            time.sleep(2)

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
            while True:
                self.apply(wire.recv())
        finally:
            s.close()

    def apply(self, m):
        t = m['t']
        if t == 'move':
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
        self.u.SendInput(1, self.ct.byref(inp), self.ct.sizeof(self.INPUT))

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
        self.pos = (0, 0)
        self.down_mods, self.held = set(), set()
        self.last_click = (0.0, None, (0, 0), 0)
        self.h = self.tap = None

    def size(self):
        r = self.cg.CGDisplayBounds(self.cg.CGMainDisplayID())
        return int(r.s.w), int(r.s.h)

    def warp(self, x, y):
        self.cg.CGWarpMouseCursorPosition(self.CGPoint(x, y))

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

    def _tap(self, proxy, etype, event, refcon):
        cg, h = self.cg, self.h
        try:
            if etype in (0xFFFFFFFE, 0xFFFFFFFF):          # tap disabled by timeout / user
                cg.CGEventTapEnable(self.tap, True)
                return event
            swallow = False
            if etype in (5, 6, 7, 27):
                loc = cg.CGEventGetLocation(event)
                dx = cg.CGEventGetIntegerValueField(event, 4)
                dy = cg.CGEventGetIntegerValueField(event, 5)
                swallow = h.on_move(loc.x, loc.y, dx, dy)
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
        sys.exit('at most %d clients (hotkeys 1-9)' % MAX_CLIENTS)
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
    sp = sub.choices['server']
    sp.add_argument('--client', action='append', required=True, metavar='[EDGE:]NAME',
                    help='allowed client; EDGE is where its screen sits relative to this one. '
                         'Order = hotkey number (Ctrl+Alt+Shift+1..9)')
    cp = sub.choices['client']
    cp.add_argument('--server', required=True, help='IP or hostname of the server')
    cp.add_argument('--name', required=True, help='this client\'s name as listed on the server')
    cp.add_argument('--invert-scroll', action='store_true')
    a = ap.parse_args(argv)
    DEBUG = a.debug
    if not a.secret:
        sys.exit('set --secret or KVM_SECRET')
    if a.mode == 'server':
        run_server(parse_layout(a.client), a.port, a.secret)
    else:
        run_client(a.server, a.port, a.name, a.secret, a.invert_scroll)


def run_server(layout, port, secret, auto=False, on_change=None, on_ready=None):
    try:
        be = make_backend()
        srv = Server(be, layout, port, derive_key(secret), auto, on_change)
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
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    except OSError as e:
        sys.exit('error: %s' % e)


def run_client(host, port, name, secret, invert_scroll=False):
    try:
        Client(make_backend(), host, port, name, derive_key(secret), invert_scroll).run()
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
