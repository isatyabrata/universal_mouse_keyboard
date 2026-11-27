"""Loopback tests: real sockets + handshake + controller logic, fake input backends."""
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import client
import kvm

kvm.RETRY_DELAY = 0.05
kvm.CLIP_POLL = 0.02    # poll the (fake) clipboards quickly
kvm.SETTLE = 0          # most tests drive input instantly; one test restores the real value


class FakeServerBackend:
    def __init__(self, w=1000, h=800):
        self.w, self.h, self.warps, self.freezes = w, h, [], []

    def freeze(self, on):
        self.freezes.append(on)

    def size(self):
        return self.w, self.h

    def warp(self, x, y):
        self.warps.append((x, y))

    def start_capture(self, handler):
        self.h_ = handler

    clip = ''

    def clip_get(self):
        return self.clip

    def clip_set(self, text):
        self.clip = text


class FakeClientBackend:
    def __init__(self, w=500, h=400):
        self.w, self.h, self.calls = w, h, []

    def size(self):
        return self.w, self.h

    def inject_move(self, x, y):
        self.calls.append(('move', x, y))

    def inject_button(self, b, d):
        self.calls.append(('btn', b, d))

    def inject_wheel(self, dx, dy):
        self.calls.append(('wheel', dx, dy))

    def inject_key(self, k, d):
        self.calls.append(('key', k, d))

    clip = ''

    def clip_get(self):
        return self.clip

    def clip_set(self, text):
        self.clip = text


def wait_for(cond, t=3.0):
    end = time.time() + t
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


class Rig:
    def __init__(self, layout, secret='s3cret', client_secret=None, name='pc2'):
        self.sb, self.cb = FakeServerBackend(), FakeClientBackend()
        self.srv = kvm.Server(self.sb, kvm.parse_layout(layout), 0, kvm.derive_key(secret))
        self.srv.start()
        self.ctl = self.srv.ctl
        self.cli = kvm.Client(self.cb, '127.0.0.1', self.srv.port, name,
                              kvm.derive_key(client_secret or secret))
        threading.Thread(target=self.cli.run, daemon=True).start()

    def stop(self):
        self.cli.running = False
        self.srv.running = False


class Tests(unittest.TestCase):
    def test_edge_switch_move_and_return(self):
        r = Rig(['right:pc2'])
        try:
            self.assertTrue(wait_for(lambda: 'pc2' in r.ctl.peers))
            self.assertFalse(r.ctl.on_move(500, 400, 3, 0))            # normal move stays local
            self.assertTrue(r.ctl.on_move(999, 400, 3, 0))             # touches right edge -> captured
            self.assertIsNotNone(r.ctl.active)
            self.assertEqual(r.sb.warps[-1], (500, 400))               # real cursor parked mid-screen
            self.assertTrue(wait_for(lambda: ('move', kvm.ENTRY_INSET, 199) in r.cb.calls))   # just inside client's left edge
            self.assertTrue(r.ctl.on_move(500, 400, 50, 10))
            self.assertTrue(wait_for(lambda: ('move', 56, 209) in r.cb.calls))
            self.assertTrue(r.ctl.on_button('l', True))
            self.assertTrue(r.ctl.on_wheel(0, 120))
            self.assertTrue(r.ctl.on_key('a', True))
            self.assertTrue(wait_for(lambda: ('key', 'a', 1) in r.cb.calls))
            self.assertIn(('btn', 'l', 1), r.cb.calls)
            self.assertIn(('wheel', 0, 120), r.cb.calls)
            self.assertTrue(r.ctl.on_move(500, 400, -80, 0))           # back past client's left edge
            self.assertIsNone(r.ctl.active)
            self.assertEqual(r.sb.warps[-1][0], 1000 - 1 - kvm.MARGIN)
            self.assertFalse(r.ctl.on_key('b', True))                  # local again
            # leaving released the held key and button on the client
            self.assertTrue(wait_for(lambda: ('key', 'a', 0) in r.cb.calls))
            self.assertIn(('btn', 'l', 0), r.cb.calls)
        finally:
            r.stop()

    def test_entry_jitter_does_not_bounce_back(self):
        r = Rig(['right:pc2'])
        try:
            self.assertTrue(wait_for(lambda: 'pc2' in r.ctl.peers))
            r.ctl.on_move(999, 400, 3, 0)                              # enter pc2
            r.ctl.on_move(500, 400, -3, 0)                             # small jitter toward the edge we came from
            self.assertEqual(r.ctl.active.name, 'pc2')
        finally:
            r.stop()

    def test_input_is_ignored_briefly_after_taking_control(self):
        r = Rig(['right:pc2'])
        try:
            self.assertTrue(wait_for(lambda: 'pc2' in r.ctl.peers))
            with mock.patch.object(kvm, 'SETTLE', 0.3):
                r.ctl.on_move(999, 400, 3, 0)
                start = r.ctl.vx
                self.assertTrue(r.ctl.on_move(500, 400, -100, 0))      # a warp artefact: swallowed, not acted on
                self.assertEqual((r.ctl.active.name, r.ctl.vx), ('pc2', start))
                time.sleep(0.35)
                r.ctl.on_move(500, 400, -100, 0)                       # same move after settling is real
                self.assertIsNone(r.ctl.active)
        finally:
            r.stop()

    def test_cursor_is_frozen_only_while_controlling_a_client(self):
        r = Rig(['right:pc2'])
        try:
            self.assertTrue(wait_for(lambda: 'pc2' in r.ctl.peers))
            r.ctl.on_move(999, 400, 3, 0)
            self.assertEqual(r.sb.freezes, [True])
            r.ctl.on_move(500, 400, -100, 0)                           # leave
            self.assertEqual(r.sb.freezes, [True, False])
        finally:
            r.stop()

    def test_hotkey_switch_without_edge(self):
        r = Rig(['pc2'])
        try:
            self.assertTrue(wait_for(lambda: 'pc2' in r.ctl.peers))
            for k in ('lctrl', 'lalt', 'lshift'):
                r.ctl.on_key(k, True)
            self.assertTrue(r.ctl.on_key('1', True))                   # swallowed hotkey
            self.assertEqual(r.ctl.active.name, 'pc2')
            self.assertTrue(wait_for(lambda: ('move', 250, 200) in r.cb.calls))
            self.assertTrue(r.ctl.on_key('1', False))                  # release also swallowed
            self.assertTrue(r.ctl.on_key('0', True))
            self.assertIsNone(r.ctl.active)
        finally:
            r.stop()

    def test_wrong_secret_is_rejected(self):
        r = Rig(['right:pc2'], client_secret='nope')
        try:
            time.sleep(0.8)
            self.assertNotIn('pc2', r.ctl.peers)
        finally:
            r.stop()

    def test_unknown_client_name_is_rejected(self):
        r = Rig(['right:pc2'], name='intruder')
        try:
            time.sleep(0.8)
            self.assertEqual(r.ctl.peers, {})
        finally:
            r.stop()

    def test_client_disconnect_returns_control(self):
        r = Rig(['right:pc2'])
        try:
            self.assertTrue(wait_for(lambda: 'pc2' in r.ctl.peers))
            r.ctl.on_move(999, 400, 3, 0)
            self.assertIsNotNone(r.ctl.active)
            r.ctl.active.close()
            self.assertTrue(wait_for(lambda: r.ctl.active is None))
            self.assertFalse(r.ctl.on_key('a', True))
        finally:
            r.stop()

    def test_tampered_frame_and_replay_rejected(self):
        a, b = socket.socketpair()
        key = kvm.derive_key('x')
        wa, wb = kvm.Wire(a, True), kvm.Wire(b, False)
        wa.key = wb.key = kvm._hm(key, b'session')
        wa.send({'t': 'key', 'k': 'a', 'd': 1})
        self.assertEqual(wb.recv()['k'], 'a')
        # replay the same first frame bytes: sequence number must not match
        wa.tx = 0
        wa.send({'t': 'key', 'k': 'a', 'd': 1})
        with self.assertRaises(ConnectionError):
            wb.recv()
        # flip one bit of the body
        c, d = socket.socketpair()
        wc, wd = kvm.Wire(c, True), kvm.Wire(d, False)
        wc.key = wd.key = kvm._hm(key, b'session')
        body = b'{"t":"key","k":"a","d":1}'
        import struct
        payload = struct.pack('!Q', 0) + body
        data = payload + kvm._hm(wc.key, wc.out_dir, payload)
        data = data[:12] + bytes([data[12] ^ 1]) + data[13:]
        c.sendall(struct.pack('!I', len(data)) + data)
        with self.assertRaises(ConnectionError):
            wd.recv()

    def test_key_tables_roundtrip(self):
        for name, vk in kvm.NAME2WIN.items():
            if name != 'kpenter':
                self.assertEqual(kvm.WIN2NAME[vk], name)
        for name, mc in kvm.NAME2MAC.items():
            self.assertEqual(kvm.MAC2NAME[mc], name)


def _join(srv, name, secret='pw', size=(500, 400)):
    be = FakeClientBackend(*size)
    cli = kvm.Client(be, '127.0.0.1', srv.port, name, kvm.derive_key(secret))
    threading.Thread(target=cli.run, daemon=True).start()
    return cli, be


class AutoEnrollTests(unittest.TestCase):
    def _start(self, secret='pw', layout=None):
        changes = []
        srv = kvm.Server(FakeServerBackend(), layout or kvm.Layout(), 0, kvm.derive_key(secret),
                         auto=True, on_change=lambda: changes.append(1))
        srv.start()
        return srv, changes

    def test_clients_fill_free_cells_next_to_existing_screens(self):
        srv, changes = self._start()
        clients = []
        try:
            for i in range(6):
                clients.append(_join(srv, 'c%d' % i)[0])
                self.assertTrue(wait_for(lambda i=i: 'c%d' % i in srv.ctl.peers))
            self.assertEqual([srv.layout.pos['c%d' % i] for i in range(6)],
                             [(1, 0), (-1, 0), (0, -1), (0, 1), (2, 0), (1, -1)])
            self.assertEqual(len(changes), 6)
        finally:
            for c in clients:
                c.running = False
            srv.running = False

    def test_saved_layout_is_respected(self):
        lay = kvm.Layout.from_json({'pos': {'server': [0, 0], 'old': [-1, 0]}, 'order': ['old']})
        srv, _ = self._start(layout=lay)
        c, _ = _join(srv, 'new')
        try:
            self.assertTrue(wait_for(lambda: 'new' in srv.ctl.peers))
            self.assertEqual(srv.layout.pos, {'server': (0, 0), 'old': (-1, 0), 'new': (1, 0)})
        finally:
            c.running = False
            srv.running = False

    def test_auto_enroll_still_requires_the_passphrase(self):
        srv, changes = self._start()
        c, _ = _join(srv, 'intruder', secret='wrong')
        try:
            time.sleep(0.8)
            self.assertEqual(list(srv.layout.pos), ['server'])
            self.assertEqual(changes, [])
        finally:
            c.running = False
            srv.running = False

    def test_a_client_cannot_call_itself_server(self):
        srv, _ = self._start()
        c, _ = _join(srv, 'server')
        try:
            time.sleep(0.8)
            self.assertEqual(srv.ctl.peers, {})
        finally:
            c.running = False
            srv.running = False


class LayoutTests(unittest.TestCase):
    def test_set_positions_validation(self):
        lay = kvm.Layout()
        lay.add('a')
        lay.set_positions({'server': [0, 0], 'a': [0, 3]})
        self.assertEqual(lay.pos['a'], (0, 3))
        for bad in ({'server': [0, 0], 'a': [0, 0]},            # same cell
                    {'server': [0, 0]},                         # missing screen
                    {'server': [0, 0], 'a': [0, 1], 'x': [1, 1]},   # unknown screen
                    {'server': [0, 0], 'a': [999, 0]},          # out of range
                    {'server': [0, 0], 'a': 'nope'}):
            with self.assertRaises(ValueError):
                lay.set_positions(bad)
        self.assertEqual(lay.pos['a'], (0, 3))                  # unchanged after rejections

    def test_json_roundtrip_and_garbage(self):
        lay = kvm.Layout()
        lay.add('a')
        lay.add('b')
        again = kvm.Layout.from_json(lay.to_json())
        self.assertEqual((again.pos, again.order), (lay.pos, lay.order))
        self.assertEqual(kvm.Layout.from_json({'pos': 5}).pos, {'server': (0, 0)})


class ChainTests(unittest.TestCase):
    """server | a | b laid out left to right: crossing a's edge must land on b, then back."""

    def _rig(self, connect_b=True):
        lay = kvm.Layout.from_json({'pos': {'server': [0, 0], 'a': [1, 0], 'b': [2, 0]},
                                    'order': ['a', 'b']})
        srv = kvm.Server(FakeServerBackend(), lay, 0, kvm.derive_key('pw'), auto=False)
        srv.start()
        clients = [_join(srv, 'a')[0]]
        self.assertTrue(wait_for(lambda: 'a' in srv.ctl.peers))
        be_b = None
        if connect_b:
            c, be_b = _join(srv, 'b')
            clients.append(c)
            self.assertTrue(wait_for(lambda: 'b' in srv.ctl.peers))
        return srv, clients, be_b

    def test_cross_client_to_client_and_back(self):
        srv, clients, be_b = self._rig()
        ctl = srv.ctl
        try:
            self.assertTrue(ctl.on_move(999, 400, 3, 0))                 # server -> a
            self.assertEqual(ctl.active.name, 'a')
            self.assertTrue(ctl.on_move(0, 0, 600, 0))                   # off a's right edge -> b
            self.assertEqual(ctl.active.name, 'b')
            self.assertTrue(wait_for(lambda: ('move', kvm.ENTRY_INSET, 199) in be_b.calls))   # same height, just inside b's left edge
            self.assertTrue(ctl.on_move(0, 0, -50, 0))                   # off b's left edge -> back to a
            self.assertEqual(ctl.active.name, 'a')
            self.assertEqual(ctl.vx, 499 - kvm.ENTRY_INSET)              # lands just inside a's right edge
        finally:
            for c in clients:
                c.running = False
            srv.running = False

    def test_back_across_both_screens_to_server(self):
        srv, clients, be_b = self._rig()
        ctl = srv.ctl
        try:
            ctl.on_move(999, 400, 3, 0)
            ctl.on_move(0, 0, 600, 0)                                    # now in b at x=0
            ctl.on_move(0, 0, -10, 0)                                    # off b's left edge -> a
            self.assertEqual(ctl.active.name, 'a')
            ctl.on_move(0, 0, -600, 0)                                   # off a's left edge -> server
            self.assertIsNone(ctl.active)
            self.assertEqual(srv.be.warps[-1][0], 1000 - 1 - kvm.MARGIN)
        finally:
            for c in clients:
                c.running = False
            srv.running = False

    def test_missing_neighbour_clamps(self):
        srv, clients, _ = self._rig(connect_b=False)                     # b is in the layout but offline
        ctl = srv.ctl
        try:
            ctl.on_move(999, 400, 3, 0)
            self.assertTrue(ctl.on_move(0, 0, 900, 0))
            self.assertEqual(ctl.active.name, 'a')
            self.assertEqual(ctl.vx, 499)
        finally:
            for c in clients:
                c.running = False
            srv.running = False


class EditorApiTests(unittest.TestCase):
    def test_api_state_update_and_protections(self):
        import json
        import urllib.error
        import urllib.request
        import layout_ui
        lay = kvm.Layout()
        srv = kvm.Server(FakeServerBackend(), lay, 0, kvm.derive_key('pw'), auto=True)
        srv.start()
        c, _ = _join(srv, 'pc2')
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        base = layout_ui.start(srv, port)
        try:
            self.assertTrue(wait_for(lambda: 'pc2' in srv.ctl.peers))

            def call(path, body=None, headers=None):
                req = urllib.request.Request(base + path, data=body and json.dumps(body).encode(),
                                             headers=headers or {})
                try:
                    with urllib.request.urlopen(req) as r:
                        return r.status, r.read().decode()
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode()

            st, body = call('/api/state')
            nodes = {n['name']: n for n in json.loads(body)['nodes']}
            self.assertEqual((st, nodes['pc2']['connected'], nodes['server']['w']), (200, True, 1000))
            self.assertEqual(call('/')[0], 200)
            good = {'positions': {'server': [0, 0], 'pc2': [0, 1]}}
            self.assertEqual(call('/api/layout', good)[0], 403)          # no X-KVM header (cross-site POST)
            self.assertEqual(call('/api/state', headers={'Host': 'evil.example'})[0], 403)   # DNS rebinding
            self.assertEqual(call('/api/layout', {'positions': {'server': [0, 0], 'pc2': [0, 0]}},
                                  {'X-KVM': '1'})[0], 400)               # same cell
            self.assertEqual(call('/api/layout', good, {'X-KVM': '1'})[0], 200)
            self.assertEqual(lay.pos['pc2'], (0, 1))
        finally:
            c.running = False
            srv.running = False


class ConfigTests(unittest.TestCase):
    def test_config_roundtrip_is_private(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(kvm, 'CONFIG_PATH', os.path.join(d, 'c.json')):
            self.assertEqual(kvm.load_config(), {})
            kvm.save_section('server', {'secret': 'x'})
            kvm.save_section('client', {'host': 'h'})      # must not clobber the server section
            self.assertEqual(kvm.load_config()['server']['secret'], 'x')
            self.assertEqual(kvm.load_config()['client']['host'], 'h')
            if os.name == 'posix':
                self.assertEqual(os.stat(kvm.CONFIG_PATH).st_mode & 0o077, 0)

    def test_client_default_name_is_valid(self):
        import re
        self.assertTrue(re.fullmatch(r'[A-Za-z0-9_-]+', client.default_name()))


class ClipboardTests(unittest.TestCase):
    def _rig(self, n=2, **kw):
        sb = FakeServerBackend()
        srv = kvm.Server(sb, kvm.Layout(), 0, kvm.derive_key('pw'), auto=True, **kw)
        srv.start()
        clients = [_join(srv, 'c%d' % i) for i in range(n)]
        for i in range(n):
            self.assertTrue(wait_for(lambda i=i: 'c%d' % i in srv.ctl.peers))
        time.sleep(0.2)                    # let every sync loop take its baseline
        return srv, sb, clients

    def test_server_copy_reaches_every_client(self):
        srv, sb, clients = self._rig()
        try:
            sb.clip = 'hello from the server \u00e9\u4e2d'
            for _, be in clients:
                self.assertTrue(wait_for(lambda be=be: be.clip == sb.clip))
        finally:
            srv.running = False

    def test_client_copy_reaches_server_and_other_clients(self):
        srv, sb, clients = self._rig()
        try:
            clients[0][1].clip = 'line1\nline2'
            self.assertTrue(wait_for(lambda: sb.clip == 'line1\nline2'))
            self.assertTrue(wait_for(lambda: clients[1][1].clip == 'line1\nline2'))
            self.assertEqual(clients[0][1].clip, 'line1\nline2')
        finally:
            srv.running = False

    def test_no_echo_loop(self):
        srv, sb, clients = self._rig()
        sets = []
        orig = clients[1][1].clip_set
        clients[1][1].clip_set = lambda t: (sets.append(t), orig(t))
        try:
            sb.clip = 'once'
            self.assertTrue(wait_for(lambda: sets == ['once']))
            time.sleep(0.3)
            self.assertEqual(sets, ['once'])
        finally:
            srv.running = False

    def test_existing_clipboard_is_not_broadcast_at_startup(self):
        sb = FakeServerBackend()
        sb.clip = 'private, copied before starting'
        srv = kvm.Server(sb, kvm.Layout(), 0, kvm.derive_key('pw'), auto=True)
        srv.start()
        cli, be = _join(srv, 'c0')
        try:
            self.assertTrue(wait_for(lambda: 'c0' in srv.ctl.peers))
            time.sleep(0.3)
            self.assertEqual(be.clip, '')
        finally:
            srv.running = False

    def test_too_large_is_not_shared(self):
        srv, sb, clients = self._rig(1)
        try:
            sb.clip = 'x' * (kvm.MAX_CLIP + 1)
            time.sleep(0.3)
            self.assertEqual(clients[0][1].clip, '')
            sb.clip = 'ok again'
            self.assertTrue(wait_for(lambda: clients[0][1].clip == 'ok again'))
        finally:
            srv.running = False

    def test_big_non_ascii_text_fits_in_a_frame(self):
        srv, sb, clients = self._rig(1)
        try:
            sb.clip = '\U0001F600' * kvm.MAX_CLIP          # worst case: 12 bytes each once escaped
            self.assertTrue(wait_for(lambda: clients[0][1].clip == sb.clip, 8))
        finally:
            srv.running = False

    def test_disabled_on_server_shares_nothing(self):
        srv, sb, clients = self._rig(1, clipboard=False)
        try:
            sb.clip = 'secret'
            clients[0][1].clip = 'other'
            time.sleep(0.3)
            self.assertEqual(clients[0][1].clip, 'other')
            self.assertEqual(sb.clip, 'secret')
        finally:
            srv.running = False

    def test_unauthenticated_frame_size_limit_is_small(self):
        s = socket.create_connection(('127.0.0.1', self._rig(0)[0].port))
        try:
            s.recv(4096)                                    # challenge
            s.sendall((kvm.PRE_AUTH_FRAME + 1).to_bytes(4, 'big') + b'x' * 10)
            s.settimeout(3)
            self.assertEqual(s.recv(4096), b'')             # server hangs up
        finally:
            s.close()


class PairingTests(unittest.TestCase):
    def _server(self, approver, secret='pw'):
        srv = kvm.Server(FakeServerBackend(), kvm.Layout(), 0, kvm.derive_key(secret), auto=True,
                         secret=secret, approver=approver, discovery_port=0)
        srv.start()
        return srv

    def test_x25519_rfc7748_vectors(self):
        a = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
        b = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
        pa, pb = kvm.x25519(a, kvm._BASE25519), kvm.x25519(b, kvm._BASE25519)
        self.assertEqual(pa.hex(), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
        shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'
        self.assertEqual(kvm.x25519(a, pb).hex(), shared)
        self.assertEqual(kvm.x25519(b, pa).hex(), shared)

    def test_discovery_finds_the_server(self):
        srv = self._server(lambda *a: True)
        try:
            found = kvm.discover(srv.discovery_port, ['127.0.0.1'], timeout=3)
            self.assertEqual([(ip, port) for ip, port, _ in found], [('127.0.0.1', srv.port)])
        finally:
            srv.running = False

    def test_discovery_finds_nothing_when_no_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('127.0.0.1', 0))                     # a port nobody answers on
        try:
            self.assertEqual(kvm.discover(s.getsockname()[1], ['127.0.0.1'], timeout=0.6), [])
        finally:
            s.close()

    def test_approved_pairing_hands_over_the_secret_and_codes_match(self):
        seen = {}
        srv = self._server(lambda name, ip, code: seen.update(name=name, ip=ip, code=code) or True,
                           secret='Xk3pQ9aB-long-and-\u00e9')
        try:
            shown = []
            secret = kvm.request_pairing('127.0.0.1', srv.port, 'win-pc', shown.append, wait=5)
            self.assertEqual(secret, 'Xk3pQ9aB-long-and-\u00e9')
            self.assertEqual(shown, [seen['code']])
            self.assertEqual((seen['name'], seen['ip']), ('win-pc', '127.0.0.1'))
            self.assertRegex(seen['code'], r'^\d{6}$')
            # and the handed-over secret really lets the client in
            cli, be = _join(srv, 'win-pc', secret)
            self.assertTrue(wait_for(lambda: 'win-pc' in srv.ctl.peers))
        finally:
            srv.running = False

    def test_declined_pairing_reveals_nothing(self):
        srv = self._server(lambda *a: False)
        try:
            with self.assertRaises(ConnectionError) as cm:
                kvm.request_pairing('127.0.0.1', srv.port, 'win-pc', lambda c: None, wait=5)
            self.assertIn('declined', str(cm.exception))
        finally:
            srv.running = False

    def test_pairing_disabled_without_approver(self):
        srv = kvm.Server(FakeServerBackend(), kvm.Layout(), 0, kvm.derive_key('pw'), auto=True)
        srv.start()
        try:
            with self.assertRaises(ConnectionError):
                kvm.request_pairing('127.0.0.1', srv.port, 'win-pc', lambda c: None, wait=5)
        finally:
            srv.running = False

    def test_only_one_pairing_at_a_time(self):
        gate = threading.Event()
        srv = self._server(lambda *a: gate.wait(5) or True)
        try:
            first = []
            t = threading.Thread(target=lambda: first.append(
                kvm.request_pairing('127.0.0.1', srv.port, 'a', lambda c: None, wait=8)))
            t.start()
            time.sleep(0.5)
            with self.assertRaises(ConnectionError) as cm:
                kvm.request_pairing('127.0.0.1', srv.port, 'b', lambda c: None, wait=5)
            self.assertIn('another', str(cm.exception))
            gate.set()
            t.join(5)
            self.assertEqual(first, ['pw'])
        finally:
            gate.set()
            srv.running = False

    def test_bad_names_and_keys_are_rejected(self):
        srv = self._server(lambda *a: True)
        try:
            with self.assertRaises(ConnectionError):
                kvm.request_pairing('127.0.0.1', srv.port, 'bad name!', lambda c: None, wait=5)
        finally:
            srv.running = False

    def test_client_refinds_a_moved_server(self):
        srv = self._server(lambda *a: True)
        be = FakeClientBackend()
        real, calls = socket.create_connection, []

        def flaky(addr, *a, **kw):
            calls.append(addr[0])
            if addr[0] == '10.9.9.9':                 # the server's old address: nothing there
                raise ConnectionRefusedError('no route')
            return real(addr, *a, **kw)

        cli = kvm.Client(be, '10.9.9.9', srv.port, 'pc9', kvm.derive_key('pw'),
                         on_lost=lambda: ('127.0.0.1', srv.port))
        try:
            with mock.patch('kvm.socket.create_connection', flaky):
                threading.Thread(target=cli.run, daemon=True).start()
                self.assertTrue(wait_for(lambda: 'pc9' in srv.ctl.peers, 8))
            self.assertEqual(cli.host, '127.0.0.1')
            self.assertEqual(calls.count('10.9.9.9'), 3)      # gave up on the old address after 3 tries
        finally:
            cli.running = False
            srv.running = False


class MacClipboardTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'darwin', 'macOS only')
    def test_pbcopy_roundtrip(self):
        be = kvm.MacBackend()
        saved = be.clip_get()
        try:
            text = 'caf\u00e9 \u4e2d\u6587\nsecond line'
            be.clip_set(text)
            self.assertEqual(be.clip_get(), text)
        finally:
            if saved:
                be.clip_set(saved)


class MacCursorTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'darwin', 'macOS only')
    def test_freeze_from_the_tap_thread_really_hides_the_cursor(self):
        """Regression: hiding from a non-main thread silently did nothing. freeze() must be
        queued to the main thread (which run_server drives through pump())."""
        be = kvm.MacBackend()
        be.pumping = True
        res = {}

        def tap_thread():
            time.sleep(0.1)
            be.freeze(True)
            time.sleep(0.4)
            res['hidden'] = not be.cg.CGCursorIsVisible()
            be.freeze(False)
            time.sleep(0.4)
            res['shown'] = bool(be.cg.CGCursorIsVisible())
            res['done'] = True

        threading.Thread(target=tap_thread, daemon=True).start()
        end = time.time() + 5
        while not res.get('done') and time.time() < end:
            be.pump(0.05)
        self.assertTrue(res.get('hidden'), 'cursor was not hidden')
        self.assertTrue(res.get('shown'), 'cursor was not restored')


if __name__ == '__main__':
    unittest.main()
