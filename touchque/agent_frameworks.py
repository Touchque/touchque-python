"""A person approves an AI agent's tool call on their phone before it runs, in
whichever agent framework the agent is built with.

One rule, an ``ApprovalPolicy``, says who approves (``user``), as which action
type, and what the phone shows (``details``: RFC 9396 authorization details
drawn from the tool's arguments). Touchque draws the rows, the person types the
number the conversation shows and confirms with Face ID, and the call runs only
once they approved. The approval token (single use, bound to exactly what was
approved) is there for the service that executes: ``current_approval()`` inside
the tool, or the MCP request's ``_meta``::

    policy = ApprovalPolicy(agent, user='ada@acme.com', type='PAY_INVOICE',
                            details=lambda args, tool: [{'type': 'payment_initiation',
                                                         'instructedAmount': {'currency': 'TRY', 'amount': args['amount']},
                                                         'creditorAccount': {'iban': args['iban']}}],
                            on_challenge=lambda state, tool: reply(f"Type {state['challengeCode']} in the Touchque app."))

    @with_touchque_approval(policy)
    def pay(iban: str, amount: str) -> str:
        return bank.pay(iban, amount, current_approval()['approvalToken'])

The decorated function keeps its signature, so LangChain's ``@tool``,
LlamaIndex's ``FunctionTool.from_defaults`` and the OpenAI Agents SDK's
``@function_tool`` read the same arguments (async functions work too). For
frameworks with their own approval step: ``approve_interruptions_with_touchque``
(OpenAI Agents SDK), ``touchque_can_use_tool`` (Claude Agent SDK) and
``guard_mcp_session`` (an MCP ClientSession).
"""

import asyncio
import contextvars
import functools
import inspect
import json
from typing import Any, Callable, Dict, List, Optional, Union

from .exceptions import TouchqueApprovalError, TouchqueTimeoutException

_current: contextvars.ContextVar = contextvars.ContextVar('touchque_approval', default=None)

Pick = Union[str, Callable[[Dict[str, Any], str], str]]


class ApprovalPolicy:
    """Who approves which tool calls, and what their phone shows."""

    def __init__(self, agent, user: Pick, type: Pick, details: Callable[[Dict[str, Any], str], List[Dict[str, Any]]],
                 reason: Optional[Pick] = None, presence: Optional[str] = None, locale: Optional[str] = None,
                 mandate_id: Optional[str] = None, on_challenge: Optional[Callable[[Dict[str, Any], str], Any]] = None,
                 timeout: float = 300):
        self.agent = agent
        self.user = user
        self.type = type
        self.details = details
        self.reason = reason
        self.presence = presence
        self.locale = locale
        self.mandate_id = mandate_id
        self.on_challenge = on_challenge
        self.timeout = timeout


async def _to_thread(fn, *args):
    """``asyncio.to_thread`` (Python 3.9+), also on 3.7 and 3.8: the blocking wait for the phone
    runs in the loop's default executor, with this context's variables."""
    if hasattr(asyncio, 'to_thread'):
        return await asyncio.to_thread(fn, *args)
    ctx = contextvars.copy_context()
    return await asyncio.get_running_loop().run_in_executor(None, functools.partial(ctx.run, fn, *args))


def current_approval() -> Optional[Dict[str, Any]]:
    """Inside a tool wrapped by ``with_touchque_approval``: the approval it runs under."""
    return _current.get()


def _pick(value, args: Dict[str, Any], tool: str):
    return value(args, tool) if callable(value) else value


def require_agent_approval(policy: ApprovalPolicy, args: Dict[str, Any], tool: str = 'tool') -> Dict[str, Any]:
    """Asks the person's phone and waits: the approved state (with ``approvalToken``),
    or TouchqueApprovalError (rejected, blocked, expired...) / TouchqueTimeoutException."""
    asked = policy.agent.request_approval(
        _pick(policy.user, args, tool), _pick(policy.type, args, tool), policy.details(args, tool),
        reason=_pick(policy.reason, args, tool) if policy.reason is not None else None,
        presence=policy.presence, locale=policy.locale, mandate_id=policy.mandate_id,
    )
    if asked.get('status') == 'approved' and asked.get('approvalToken'):
        return asked
    if asked.get('challengeCode') and policy.on_challenge:
        policy.on_challenge(asked, tool)
    return policy.agent.wait_for_approval(asked['approvalId'], timeout=policy.timeout)


def _bound_args(fn, args, kwargs) -> Dict[str, Any]:
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return dict(kwargs)


def with_touchque_approval(policy: ApprovalPolicy, tool: Optional[str] = None):
    """Decorator: the function runs only after the person approved on the phone;
    ``current_approval()`` is set while it runs. Works on plain and async functions."""

    def wrap(fn):
        name = tool or fn.__name__
        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def run_async(*args, **kwargs):
                approval = await _to_thread(require_agent_approval, policy, _bound_args(fn, args, kwargs), name)
                token = _current.set(approval)
                try:
                    return await fn(*args, **kwargs)
                finally:
                    _current.reset(token)
            return run_async

        @functools.wraps(fn)
        def run(*args, **kwargs):
            approval = require_agent_approval(policy, _bound_args(fn, args, kwargs), name)
            token = _current.set(approval)
            try:
                return fn(*args, **kwargs)
            finally:
                _current.reset(token)
        return run

    return wrap


def _args_of(raw) -> Dict[str, Any]:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return {}
    return raw or {}


def approve_interruptions_with_touchque(result, policies: Dict[str, ApprovalPolicy]):
    """OpenAI Agents SDK: tools with ``needs_approval`` interrupt the run; this asks the
    phone for each interruption in ``policies`` (by tool name) and approves or rejects it
    on the run state. Returns the state to resume with ``Runner.run(agent, state)``."""
    state = result.to_state() if hasattr(result, 'to_state') else result.state
    for item in getattr(result, 'interruptions', None) or []:
        raw = getattr(item, 'raw_item', None) or getattr(item, 'rawItem', None) or item
        name = getattr(raw, 'name', None) or (raw.get('name') if isinstance(raw, dict) else None)
        policy = policies.get(name)
        if not policy:
            continue
        arguments = getattr(raw, 'arguments', None) if not isinstance(raw, dict) else raw.get('arguments')
        try:
            require_agent_approval(policy, _args_of(arguments), name)
            state.approve(item)
        except (TouchqueApprovalError, TouchqueTimeoutException):
            state.reject(item)
    return state


def touchque_can_use_tool(policies: Dict[str, ApprovalPolicy], token_field: Optional[str] = None, deny_others: bool = False):
    """Claude Agent SDK: a ``can_use_tool`` callback. Tools with a policy run only after
    the phone approved (``token_field``: put the approval token into the tool's input);
    others are allowed or, with ``deny_others``, denied."""
    try:
        from claude_agent_sdk import PermissionResultAllow, PermissionResultDeny  # type: ignore
    except ImportError:  # the SDK's own result types when installed, plain dicts otherwise
        PermissionResultAllow = PermissionResultDeny = None

    def allow(updated):
        return PermissionResultAllow(updated_input=updated) if PermissionResultAllow else {'behavior': 'allow', 'updatedInput': updated}

    def deny(message):
        return PermissionResultDeny(message=message) if PermissionResultDeny else {'behavior': 'deny', 'message': message}

    async def can_use_tool(tool_name: str, input_data: Dict[str, Any], context: Any = None):
        policy = policies.get(tool_name)
        if not policy:
            return deny(f'{tool_name} is not allowed for this agent') if deny_others else allow(input_data)
        try:
            approval = await _to_thread(require_agent_approval, policy, input_data, tool_name)
        except (TouchqueApprovalError, TouchqueTimeoutException) as err:
            return deny(f"The person did not approve {tool_name} on their phone ({getattr(err, 'status', 'timeout')})")
        return allow({**input_data, token_field: approval.get('approvalToken')} if token_field else input_data)

    return can_use_tool


class _GuardedSession:
    def __init__(self, session, policies: Dict[str, ApprovalPolicy]):
        self._session = session
        self._policies = policies

    def __getattr__(self, name):
        return getattr(self._session, name)

    async def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None, *args, **kwargs):
        policy = self._policies.get(name)
        if policy:
            approval = await _to_thread(require_agent_approval, policy, arguments or {}, name)
            meta = dict(kwargs.pop('meta', None) or {})
            meta['touchque/approvalToken'] = approval.get('approvalToken')
            try:
                return await self._session.call_tool(name, arguments, *args, meta=meta, **kwargs)
            except TypeError:  # an MCP SDK too old to send _meta: the call still waited for the phone
                return await self._session.call_tool(name, arguments, *args, **kwargs)
        return await self._session.call_tool(name, arguments, *args, **kwargs)


def guard_mcp_session(session, policies: Dict[str, ApprovalPolicy]):
    """An MCP ``ClientSession``: the tools in ``policies`` are called only after the phone
    approved; the approval token goes to the server in ``_meta`` ("touchque/approvalToken")."""
    return _GuardedSession(session, policies)
