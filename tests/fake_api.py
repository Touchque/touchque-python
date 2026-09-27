"""Spawns the shared Node fake TouchQue API (testing/fake-touchque-api.mjs)
for contract tests: verifies this SDK's requests are signed exactly like the
real backend expects, using a real HTTP round trip (not mocks)."""
import json
import shutil
import subprocess
import time
from typing import Optional

import pytest

_SCRIPT = None


def _find_script() -> str:
    global _SCRIPT
    if _SCRIPT is None:
        import os
        here = os.path.dirname(__file__)
        _SCRIPT = os.path.normpath(os.path.join(here, '..', 'testing', 'fake-touchque-api.mjs'))
    return _SCRIPT


class FakeApi:
    def __init__(self, base_url: str, proc: subprocess.Popen):
        self.base_url = base_url
        self._proc = proc

    def _call(self, path: str, body: Optional[dict] = None):
        import urllib.request
        data = json.dumps(body or {}).encode('utf-8')
        req = urllib.request.Request(self.base_url + path, data=data, headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())

    def reset(self):
        self._call('/__test/reset')

    def link(self, user: str):
        self._call('/__test/link', {'user': user})

    def opts(self, **kwargs):
        self._call('/__test/opts', kwargs)

    def approve(self, id: Optional[str] = None, via: str = 'DEVICE'):
        self._call('/__test/approve', {'id': id, 'via': via})

    def reject(self, id: Optional[str] = None):
        self._call('/__test/reject', {'id': id})

    def calls(self):
        import urllib.request
        with urllib.request.urlopen(self.base_url + '/__test/calls') as resp:
            return json.loads(resp.read())

    def close(self):
        self._proc.terminate()
        self._proc.wait(timeout=5)


@pytest.fixture
def fake_api():
    if not shutil.which('node'):
        pytest.skip('node is required for contract tests')
    proc = subprocess.Popen(['node', _find_script()], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = proc.stdout.readline()
    deadline = time.time() + 5
    while not line and time.time() < deadline:
        line = proc.stdout.readline()
    port = json.loads(line)['port']
    api = FakeApi(f'http://127.0.0.1:{port}', proc)
    try:
        yield api
    finally:
        api.close()
