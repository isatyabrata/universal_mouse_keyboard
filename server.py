#!/usr/bin/env python3
"""Run this on the computer your keyboard and mouse are plugged into.

Nothing to configure: it creates (and remembers) a passphrase and opens a drag-and-drop
screen layout editor in your browser. On every other computer just run `python client.py`:
it finds this server by itself, and you approve it once by checking a 6-digit code.

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
    p.add_argument('--no-clipboard', action='store_true', help='do not share the text clipboard')
    p.add_argument('--no-files', action='store_true', help='do not send or receive files')
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
    print('  Server ready (%s). On every OTHER computer, just run:\n' % kvm.local_ip())
    print('      python client.py\n')
    print('  (python3 on a Mac). It finds this server by itself and shows a 6-digit')
    print('  code; this window then asks you to confirm the same code - type y.')
    print('  That happens once per computer; after that it simply reconnects.')
    print('=' * 64)
    print('If a network blocks discovery: python client.py %s   (still needs the y)' % kvm.local_ip())
    print('Each computer appears in the layout editor (opens in your browser) as it')
    print('connects - drag the boxes to match your desk. Ctrl+Alt+Shift+1..9 jumps to')
    print('a computer; Ctrl+Alt+Shift+0 always returns here.\n')
    kvm.run_server(layout, a.port, s['secret'], auto=True, on_change=save, on_ready=ready,
                   clipboard=not a.no_clipboard, pairing=True, files=not a.no_files)


if __name__ == '__main__':
    main()
