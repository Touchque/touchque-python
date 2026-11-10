"""Agent framework helpers against the shared fake API: a decorated tool runs only
after the phone approved (the fake's /__test/approve stands for the phone), with
the approval token in current_approval(); a rejection stops it; the OpenAI Agents
SDK interruptions, the Claude Agent SDK callback and an MCP session are driven by
stand-ins of those libraries."""

import asyncio
import json
import threading
import urllib.request

import pytest

from touchque import (
    ApprovalPolicy, Config, TouchQue, TouchQueAgent, approve_interruptions_with_touchque, current_approval, generate_agent_key,
    guard_mcp_session, touchque_can_use_tool, with_touchque_approval,
)
from touchque.exceptions import TouchQueApprovalError

from .fake_api import fake_api  # noqa: F401 (fixture)

USER = 'frameworks@example.com'
IBAN = 'TR330006100519786457841326'


def _post(api, path, body):
    req = urllib.request.Request(api.base_url + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'}, method='POST')
    urllib.request.urlopen(req).read()


def _setup(api):
    tq = TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=api.base_url))
    api.link(USER)
    tq.action_types.define('PAY_INVOICE', critical=False)
    keys = generate_agent_key()
    created = tq.agents.create('Framework bot', ['PAY_INVOICE'], public_key=keys['public_jwk'])
    return TouchQueAgent(agent_id=created['id'], private_key=keys['private_jwk'], base_url=api.base_url)


def _policy(api, agent, approve: bool) -> ApprovalPolicy:
    def phone(state, tool):
        threading.Timer(0.05, lambda: _post(api, '/__test/approve' if approve else '/__test/reject', {'id': state['approvalId']})).start()
    return ApprovalPolicy(
        agent, user=USER, type='PAY_INVOICE',
        details=lambda args, tool: [{'type': 'payment_initiation', 'instructedAmount': {'currency': 'TRY', 'amount': args['amount']}, 'creditorAccount': {'iban': args['iban']}}],
        on_challenge=phone, timeout=20,
    )


def test_decorated_tool_runs_after_the_phone(fake_api):
    agent = _setup(fake_api)
    seen = []

    @with_touchque_approval(_policy(fake_api, agent, True))
    def pay(iban: str, amount: str) -> str:
        seen.append((iban, bool(current_approval()['approvalToken'])))
        return 'paid'

    assert pay(IBAN, amount='500.00') == 'paid'
    assert seen == [(IBAN, True)] and current_approval() is None

    @with_touchque_approval(_policy(fake_api, agent, True))
    async def pay_async(iban: str, amount: str) -> str:
        return 'paid ' + ('with token' if current_approval()['approvalToken'] else 'without')

    assert asyncio.run(pay_async(IBAN, '10.00')) == 'paid with token'

    @with_touchque_approval(_policy(fake_api, agent, False))
    def refused(iban: str, amount: str) -> str:
        return 'paid'

    with pytest.raises(TouchQueApprovalError):
        refused(IBAN, '9.00')


def test_framework_hooks(fake_api):
    agent = _setup(fake_api)
    args = json.dumps({'iban': IBAN, 'amount': '20.00'})

    class Item:
        def __init__(self, name):
            self.raw_item = type('Raw', (), {'name': name, 'arguments': args})()

    class State:
        def __init__(self):
            self.approved, self.rejected = [], []

        def approve(self, item):
            self.approved.append(item.raw_item.name)

        def reject(self, item):
            self.rejected.append(item.raw_item.name)

    state = State()
    result = type('Result', (), {'interruptions': [Item('pay'), Item('refund'), Item('other')], 'to_state': lambda self: state})()
    approve_interruptions_with_touchque(result, {'pay': _policy(fake_api, agent, True), 'refund': _policy(fake_api, agent, False)})
    assert (state.approved, state.rejected) == (['pay'], ['refund'])

    can = touchque_can_use_tool({'pay': _policy(fake_api, agent, True)}, token_field='approvalToken')
    allowed = asyncio.run(can('pay', {'iban': IBAN, 'amount': '30.00'}, None))
    updated = allowed.updated_input if hasattr(allowed, 'updated_input') else allowed['updatedInput']
    assert updated['approvalToken'] and updated['iban'] == IBAN

    class Session:
        def __init__(self):
            self.sent = []

        async def call_tool(self, name, arguments=None, meta=None):
            self.sent.append((name, meta))
            return {'content': []}

    session = Session()
    guarded = guard_mcp_session(session, {'pay': _policy(fake_api, agent, True)})
    asyncio.run(guarded.call_tool('pay', {'iban': IBAN, 'amount': '50.00'}))
    asyncio.run(guarded.call_tool('list', {}))
    assert session.sent[0][1]['touchque/approvalToken'] and session.sent[1][1] is None


def test_async_helpers_run_without_asyncio_to_thread(fake_api, monkeypatch):
    """Python 3.7 and 3.8 have no asyncio.to_thread."""
    agent = _setup(fake_api)
    monkeypatch.delattr(asyncio, 'to_thread', raising=False)

    @with_touchque_approval(_policy(fake_api, agent, True))
    async def pay_async(iban: str, amount: str) -> str:
        return 'paid ' + ('with token' if current_approval()['approvalToken'] else 'without')

    assert asyncio.run(pay_async(IBAN, '10.00')) == 'paid with token'
    can = touchque_can_use_tool({'pay': _policy(fake_api, agent, True)}, token_field='approvalToken')
    allowed = asyncio.run(can('pay', {'iban': IBAN, 'amount': '30.00'}, None))
    updated = allowed.updated_input if hasattr(allowed, 'updated_input') else allowed['updatedInput']
    assert updated['approvalToken']
