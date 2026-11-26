#!/usr/bin/env python3
"""Run this on the computer your keyboard and mouse are plugged into.

No questions asked: it finds its own IP address, creates (and remembers) a passphrase,
prints the one command to run on the other computers, and opens a drag-and-drop screen
layout editor in your browser. Clients that connect appear in the editor automatically.

    python server.py            (python3 on a Mac)
"""
import argparse
import secrets
import threading
import webbrowser

import kvm
import layout_ui


def main():
    p = argparse.ArgumentParser(description='Server for kvm.py - just run it.')
    p.add_argument('--reset', action='store_true',
                   help='forget the saved passphrase and screen layout')
    p.add_argument('--port', type=int, default=kvm.DEFAULT_PORT)
    p.add_argument('--no-browser', action='store_true', help='do not open the layout editor automatically')
    p.add_argument('--debug', action='store_true')
    a = p.parse_args()
    kvm.DEBUG = a.debug

    s = kvm.load_config().get('server') or {}
    if a.reset or 'secret' not in s:
        s = {'secret': secrets.token_urlsafe(6), 'layout': None}
    layout = kvm.Layout.from_json(s['layout']) if s.get('layout') else kvm.Layout()

    def save():
        s['layout'] = layout.to_json()
        kvm.save_section('server', s)

    save()

    def ready(srv):
        url = layout_ui.start(srv, a.port + 1)
        if url:
            kvm.log('layout editor: %s' % url)
            if not a.no_browser:
                threading.Timer(0.5, webbrowser.open, (url,)).start()

    print('\n' + '=' * 64)
    print('  Server ready. On every OTHER computer, run:\n')
    print('      python client.py %s %s\n' % (kvm.local_ip(), s['secret']))
    print('  (use python3 on a Mac)')
    print('=' * 64)
    print('Each computer appears in the layout editor (opens in your browser) as it')
    print('connects - drag the boxes to match your desk. Ctrl+Alt+Shift+1..9 jumps to')
    print('a computer; Ctrl+Alt+Shift+0 always returns here.\n')
    kvm.run_server(layout, a.port, s['secret'], auto=True, on_change=save, on_ready=ready)


if __name__ == '__main__':
    main()
