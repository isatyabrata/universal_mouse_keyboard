#!/usr/bin/env python3
"""Send files to another computer in your setup.

    python send.py report.pdf photo.jpg             (python3 on a Mac)
    python send.py report.pdf --to win-laptop       (a client's name, 'server', or 'all')

Run on a client it sends to the server by default; run on the server it sends to every client.
Files land in the Downloads folder, in "KVM Received". Uses the settings saved by server.py /
client.py. Single files only (zip a folder first). From the server you can also drag files onto
a computer's box in the layout editor. Like the rest of this tool the data is authenticated but
not encrypted.
"""
import argparse
import os
import sys

import kvm


def main():
    p = argparse.ArgumentParser(description='Send files to another computer.')
    p.add_argument('files', nargs='+', help='file(s) to send')
    p.add_argument('--to', action='append', metavar='NAME',
                   help="destination: a client's name, 'server', or 'all' (repeatable)")
    p.add_argument('--as-server', action='store_true',
                   help='this machine is the server (used if it has both settings)')
    p.add_argument('--port', type=int)
    a = p.parse_args()

    cfg = kvm.load_config()
    if cfg.get('client') and not a.as_server:
        c = cfg['client']
        host, port, secret, name = c['host'], a.port or c.get('port') or kvm.DEFAULT_PORT, c['secret'], c['name']
        to = a.to or [kvm.SERVER]
    elif cfg.get('server'):
        host, port, secret, name = '127.0.0.1', a.port or kvm.DEFAULT_PORT, cfg['server']['secret'], kvm.SERVER
        to = a.to or ['all']
    else:
        sys.exit('No saved settings here. Run server.py or client.py on this computer first.')

    def progress(path, done, total):
        pct = 100 * done // total if total else 100
        print('\r  %s: %d%%' % (os.path.basename(path), pct), end='', flush=True)

    try:
        for path, res in kvm.send_files(host, port, kvm.derive_key(secret), name, a.files, to, progress):
            where = ', '.join('the server' if t == kvm.SERVER else t for t in res['delivered'])
            print('\r  %s: sent to %s (%s)' % (os.path.basename(path), where,
                                                kvm.human(os.path.getsize(path))))
    except (OSError, ConnectionError, ValueError) as e:
        sys.exit('\nCould not send: %s' % e)


if __name__ == '__main__':
    main()
