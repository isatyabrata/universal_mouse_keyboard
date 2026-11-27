#!/usr/bin/env python3
"""Run this on every computer that should be controlled by the server's keyboard and mouse.

    python client.py SERVER_IP PASSPHRASE      (python3 on a Mac)

The server prints exactly this command. Afterwards a plain `python client.py` reconnects
using the saved settings. This computer's name defaults to its hostname.
"""
import argparse
import re
import socket
import sys

import kvm


def default_name():
    return re.sub(r'[^A-Za-z0-9_-]', '', socket.gethostname().split('.')[0]) or 'client'


def main():
    p = argparse.ArgumentParser(description='Client for kvm.py - run the command the server prints.')
    p.add_argument('server', nargs='?', help='IP address (or hostname) of the server')
    p.add_argument('passphrase', nargs='?', help='passphrase printed by the server')
    p.add_argument('--name', help='name for this computer (default: its hostname)')
    p.add_argument('--invert-scroll', action='store_true', help='flip scroll direction')
    p.add_argument('--port', type=int, default=kvm.DEFAULT_PORT)
    p.add_argument('--debug', action='store_true')
    p.add_argument('--no-clipboard', action='store_true', help='do not share the text clipboard')
    a = p.parse_args()
    kvm.DEBUG = a.debug

    cfg = kvm.load_config()
    if a.server and a.passphrase:
        s = {'host': a.server, 'secret': a.passphrase, 'name': a.name or default_name(),
             'invert': a.invert_scroll}
        kvm.save_section('client', s)
    elif a.server or a.passphrase:
        p.error('give both SERVER_IP and PASSPHRASE (the server prints the full command)')
    elif cfg.get('client'):
        s = cfg['client']
    else:
        p.error('run the command the server printed: python client.py SERVER_IP PASSPHRASE')

    print('\nConnecting to %s as "%s" - it keeps retrying until the server is up. Ctrl+C to stop.\n'
          % (s['host'], s['name']))
    kvm.run_client(s['host'], a.port, s['name'], s['secret'], s['invert'],
                   clipboard=not a.no_clipboard)


if __name__ == '__main__':
    main()
