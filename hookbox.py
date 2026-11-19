#!/usr/bin/env python3
"""A loopback-only webhook inbox for testing JSON integrations. Python 3.9+."""
import argparse
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from urllib.parse import urlsplit

MAX_BODY = 64 * 1024
REDACT = re.compile(r'authorization|cookie|token|secret|signature|api[-_]?key', re.I)


def strict_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('Duplicate JSON object key')
        obj[key] = value
    return obj


def reject_constant(_):
    raise ValueError('Non-finite JSON number')


class Inbox:
    def __init__(self, path, keep=100):
        if not 1 <= keep <= 1000:
            raise ValueError('Keep must be between 1 and 1000')
        self.path, self.keep = str(path), keep
        if Path(path).is_symlink():
            raise ValueError('Database must not be a symbolic link')
        if not Path(path).exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        with self.connect() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, received INTEGER NOT NULL, hook TEXT NOT NULL, headers TEXT NOT NULL, payload TEXT NOT NULL, bytes INTEGER NOT NULL)')

    def connect(self):
        return sqlite3.connect(self.path, timeout=3)

    def add(self, hook, headers, payload, size):
        filtered = {k.lower(): '[redacted]' if REDACT.search(k) else v for k, v in headers.items()}
        with self.connect() as conn:
            cursor = conn.execute('INSERT INTO events(received, hook, headers, payload, bytes) VALUES(?,?,?,?,?)',
                                  (int(time.time()), hook, json.dumps(filtered), json.dumps(payload, ensure_ascii=False, allow_nan=False), size))
            identifier = cursor.lastrowid
            conn.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)', (self.keep,))
        return identifier

    def recent(self):
        with self.connect() as conn:
            return [dict(zip(['id', 'received_unix_seconds', 'hook', 'body_bytes'], row))
                    for row in conn.execute('SELECT id, received, hook, bytes FROM events ORDER BY id DESC LIMIT 100')]

    def get(self, identifier):
        with self.connect() as conn:
            row = conn.execute('SELECT id, received, hook, headers, payload, bytes FROM events WHERE id=?', (identifier,)).fetchone()
        if row is None:
            return None
        return dict(id=row[0], received_unix_seconds=row[1], hook=row[2], headers=json.loads(row[3]), payload=json.loads(row[4]), body_bytes=row[5])


def make_server(path, port=8767, token='', signing_secret='', keep=100):
    inbox = Inbox(path, keep)

    class Handler(BaseHTTPRequestHandler):
        server_version = 'Hookbox/0.1'

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_):
            # Avoid recording credentials, query strings, or body content in logs.
            pass

        def reply(self, status, body):
            raw = json.dumps(body, ensure_ascii=False, allow_nan=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(raw)
            self.close_connection = True

        def authorized(self):
            expected = 'Bearer ' + token
            if token and not hmac.compare_digest(self.headers.get('Authorization', '').encode(), expected.encode()):
                self.reply(401, {'error':'Bearer token required'})
                return False
            return True

        def do_GET(self):
            if not self.authorized():
                return
            path = urlsplit(self.path).path
            if path == '/health':
                self.reply(200, {'status':'ok', 'version':'0.1.0', 'listen':'127.0.0.1'})
            elif path == '/events':
                self.reply(200, {'events':inbox.recent(), 'retention':keep})
            elif re.fullmatch(r'/events/[1-9][0-9]{0,15}', path):
                event = inbox.get(int(path.rsplit('/', 1)[1]))
                self.reply(200 if event else 404, event or {'error':'Event not found'})
            else:
                self.reply(404, {'error':'Route not found'})

        def do_POST(self):
            if not self.authorized():
                return
            path = urlsplit(self.path).path
            if not re.fullmatch(r'/hooks/[A-Za-z0-9_-]{1,80}', path):
                self.reply(404, {'error':'Use /hooks/NAME'})
                return
            lengths = self.headers.get_all('Content-Length', [])
            if self.headers.get('Transfer-Encoding'):
                self.reply(400, {'error':'Transfer-Encoding is not supported'})
                return
            if not lengths:
                self.reply(411, {'error':'Content-Length required'})
                return
            if len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,10}', lengths[0]):
                self.reply(400, {'error':'Invalid Content-Length'})
                return
            size = int(lengths[0])
            if size > MAX_BODY:
                self.reply(413, {'error':'Body exceeds 64 KiB'})
                return
            if self.headers.get_content_type() != 'application/json':
                self.reply(415, {'error':'Content-Type must be application/json'})
                return
            try:
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError('Truncated body')
                if signing_secret:
                    expected = 'sha256=' + hmac.new(signing_secret.encode(), raw, hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(self.headers.get('X-Hookbox-Signature', '').encode(), expected.encode()):
                        self.reply(401, {'error':'Invalid body signature'})
                        return
                payload = json.loads(raw.decode('utf-8'), object_pairs_hook=strict_object, parse_constant=reject_constant)
                identifier = inbox.add(path, dict(self.headers), payload, size)
            except (ValueError, UnicodeError, RecursionError) as error:
                self.reply(400, {'error':str(error)})
                return
            except (OSError, sqlite3.Error):
                self.reply(503, {'error':'Body read or local storage failed'})
                return
            self.reply(201, {'id':identifier, 'detail':'/events/'+str(identifier)})

        def do_OPTIONS(self):
            self.reply(405, {'error':'Browser cross-origin requests are not enabled'})

    return HTTPServer(('127.0.0.1', port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=Path('hookbox.sqlite3'))
    parser.add_argument('--port', type=int, default=8767)
    parser.add_argument('--keep', type=int, default=100)
    parser.add_argument('--resume', action='store_true', help='Explicitly reuse an existing Hookbox database')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Port must be 1..65535')
    if args.db.exists() and not args.resume:
        parser.error('Database exists; choose a new path or use --resume')
    token, secret = os.environ.get('HOOKBOX_TOKEN', ''), os.environ.get('HOOKBOX_SIGNING_SECRET', '')
    if token and len(token) < 16:
        parser.error('HOOKBOX_TOKEN must contain at least 16 characters')
    server = make_server(args.db, args.port, token, secret, args.keep)
    print('Hookbox listening at http://127.0.0.1:%d — Ctrl-C to stop' % args.port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
