"""Loopback tests: real sockets + handshake + controller logic, fake input backends."""
import socket
import threading
import time
import unittest

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


if __name__ == '__main__':
    unittest.main()
