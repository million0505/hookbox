"""Send a synthetic event to a local Hookbox instance."""
import hashlib
import hmac
import json
import os
import urllib.request

body = json.dumps({'event':'order.created', 'order':{'id':'demo-001', 'amount_cents':1250, 'currency':'USD'}}, separators=(',', ':')).encode()
headers = {'Content-Type':'application/json', 'X-Demo':'synthetic'}
if os.environ.get('HOOKBOX_TOKEN'):
    headers['Authorization'] = 'Bearer '+os.environ['HOOKBOX_TOKEN']
if os.environ.get('HOOKBOX_SIGNING_SECRET'):
    headers['X-Hookbox-Signature'] = 'sha256='+hmac.new(os.environ['HOOKBOX_SIGNING_SECRET'].encode(), body, hashlib.sha256).hexdigest()
request = urllib.request.Request('http://127.0.0.1:8767/hooks/orders', data=body, headers=headers)
with urllib.request.urlopen(request, timeout=5) as response:
    print(response.read().decode())
