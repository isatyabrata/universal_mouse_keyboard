#!/usr/bin/env python3
"""Run this on every computer that should be controlled by the server's keyboard and mouse.

    python client.py                 (python3 on a Mac)

The first time, it finds the server on your network, shows a 6-digit code, and the server
asks its owner to confirm the same code; the passphrase is then handed over privately and
saved. After that a plain `python client.py` just reconnects (and re-finds the server if its
address changes). If discovery is blocked on your network, give the server's IP:
`python client.py SERVER_IP`. `python client.py SERVER_IP PASSPHRASE` still works too.
"""
import argparse
import re
import socket
import sys

import kvm


def default_name():
    return re.sub(r'[^A-Za-z0-9_-]', '', socket.gethostname().split('.')[0]) or 'client'


def pair(a, saved):
    """First-time setup: find the server, show a code, wait for the owner to approve it."""
    host, port = a.server, a.port or kvm.DEFAULT_PORT
    if not host:
        print('Looking for the server on your network...')
        found = kvm.discover(timeout=4)
        if not found:
            sys.exit('Could not find a server. Is `python server.py` running on the other computer, '
                     'on the same network?\nIf your network blocks discovery, run: '
                     'python client.py SERVER_IP')
        host, port, hostname = found[0]
        print('Found the server at %s (%s).' % (host, hostname))
    name = (saved or {}).get('name') if not a.name else a.name
    name = name or default_name()

    def show(code):
        print('\n  Pairing code:   %s\n' % code)
        print('  On the server, check it shows this same code, then type y + Enter there.')
        print('  Waiting for approval (up to 2 minutes)...')

    try:
        secret = kvm.request_pairing(host, port, name, show)
    except (OSError, ConnectionError, ValueError) as e:
        sys.exit('Pairing failed: %s' % e)
    print('\nPaired. Saved; next time just run `python client.py`.')
    s = {'host': host, 'port': port, 'secret': secret, 'name': name, 'invert': a.invert_scroll}
    kvm.save_section('client', s)
    return s


def main():
    p = argparse.ArgumentParser(description='Client for kvm.py - run the command the server prints.')
    p.add_argument('server', nargs='?', help='IP address of the server (optional: it is found automatically)')
    p.add_argument('passphrase', nargs='?', help='optional: skip pairing by giving the passphrase')
    p.add_argument('--pair', action='store_true', help='pair again even if this computer already has saved settings')
    p.add_argument('--name', help='name for this computer (default: its hostname)')
    p.add_argument('--invert-scroll', action='store_true', help='flip scroll direction')
    p.add_argument('--port', type=int, help='server port (default: found automatically, else %d)' % kvm.DEFAULT_PORT)
    p.add_argument('--debug', action='store_true')
    p.add_argument('--no-clipboard', action='store_true', help='do not share the text clipboard')
    a = p.parse_args()
    kvm.DEBUG = a.debug

    cfg = kvm.load_config()
    saved = cfg.get('client')
    if a.passphrase and not a.server:
        p.error('give SERVER_IP before the passphrase')
    if a.server and a.passphrase:
        s = {'host': a.server, 'secret': a.passphrase, 'name': a.name or default_name(),
             'invert': a.invert_scroll}
        kvm.save_section('client', s)
    elif saved and not a.server and not a.pair:
        s = saved
    else:
        s = pair(a, saved)

    def relocate():
        """The server's address changed (DHCP)? Find it again and remember the new one."""
        found = kvm.discover(timeout=3)
        if found:
            s['host'], s['port'] = found[0][0], found[0][1]
            kvm.save_section('client', s)
            return s['host'], s['port']

    print('\nConnecting to %s as "%s" - it keeps retrying until the server is up. Ctrl+C to stop.\n'
          % (s['host'], s['name']))
    kvm.run_client(s['host'], a.port or s.get('port') or kvm.DEFAULT_PORT, s['name'], s['secret'], s['invert'],
                   clipboard=not a.no_clipboard, on_lost=relocate)


if __name__ == '__main__':
    main()
