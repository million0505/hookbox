import hashlib
import hmac
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from hookbox import make_server, MAX_BODY


class InboxChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.token, self.secret = 'test-token-not-a-live-credential', 'synthetic-signing-key'
        self.server = make_server(Path(self.temp.name)/'inbox.sqlite3', 0, self.token, self.secret, keep=2)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def call(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        conn.request(method, path, body, headers if headers is not None else {'Authorization':'Bearer '+self.token})
        result = conn.getresponse()
        status, data = result.status, json.loads(result.read())
        conn.close()
        return status, data

    def post(self, raw, extra=None):
        headers = {'Authorization':'Bearer '+self.token, 'Content-Type':'application/json',
                   'X-Hookbox-Signature':'sha256='+hmac.new(self.secret.encode(), raw, hashlib.sha256).hexdigest(),
                   'X-Api-Key':'do-not-store-this', 'Cookie':'private=test'}
        headers.update(extra or {})
        return self.call('POST', '/hooks/orders?token=not-persisted', raw, headers)

    def test_receive_utf8_and_redact_sensitive_headers(self):
        status, result = self.post('{"name":"Олена","id":"001"}'.encode())
        self.assertEqual(status, 201)
        status, event = self.call('GET', '/events/'+str(result['id']))
        self.assertEqual(event['payload']['id'], '001')
        self.assertEqual(event['payload']['name'], 'Олена')
        self.assertEqual(event['hook'], '/hooks/orders')
        for key in ['authorization', 'x-api-key', 'cookie', 'x-hookbox-signature']:
            self.assertEqual(event['headers'][key], '[redacted]')

    def test_retention_and_missing_record(self):
        for n in range(3):
            self.assertEqual(self.post(json.dumps({'n':n}).encode())[0], 201)
        status, result = self.call('GET', '/events')
        self.assertEqual([e['id'] for e in result['events']], [3, 2])
        self.assertEqual(self.call('GET', '/events/1')[0], 404)

    def test_auth_and_signature(self):
        self.assertEqual(self.call('GET', '/events', headers={})[0], 401)
        self.assertEqual(self.post(b'{}', {'X-Hookbox-Signature':'sha256=wrong'})[0], 401)
        self.assertEqual(self.call('GET', '/events')[1]['events'], [])

    def test_invalid_json_duplicate_keys_and_nonfinite_numbers(self):
        for raw in [b'{', b'{"id":1,"id":2}', b'{"n":NaN}', b'\xff']:
            self.assertEqual(self.post(raw)[0], 400, raw)
        self.assertEqual(self.call('GET', '/events')[1]['events'], [])

    def test_limits_type_and_cross_origin_preflight(self):
        self.assertEqual(self.post(b'{}', {'Content-Type':'text/plain'})[0], 415)
        self.assertEqual(self.post(b'x'*(MAX_BODY+1))[0], 413)
        self.assertEqual(self.call('OPTIONS', '/hooks/orders')[0], 405)


if __name__ == '__main__':
    unittest.main()
