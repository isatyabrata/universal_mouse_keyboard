"""Loopback tests: real sockets + handshake + controller logic, fake input backends."""
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

import client
import kvm


class FakeServerBackend:
    def __init__(self, w=1000, h=800):
        self.w, self.h, self.warps = w, h, []

    def size(self):
        return self.w, self.h

    def warp(self, x, y):
        self.warps.append((x, y))

    def start_capture(self, handler):
        self.h_ = handler


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
            self.assertTrue(wait_for(lambda: ('move', 0, 199) in r.cb.calls))   # enters client's left edge
            self.assertTrue(r.ctl.on_move(500, 400, 50, 10))
            self.assertTrue(wait_for(lambda: ('move', 50, 209) in r.cb.calls))
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
            self.assertTrue(wait_for(lambda: ('move', 0, 199) in be_b.calls))   # same height, left edge of b
            self.assertTrue(ctl.on_move(0, 0, -50, 0))                   # off b's left edge -> back to a
            self.assertEqual(ctl.active.name, 'a')
            self.assertEqual(ctl.vx, 499)                                # lands on a's right edge
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
            ctl.on_move(0, 0, -5, 0)                                     # off b's left edge -> a
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


if __name__ == '__main__':
    unittest.main()
