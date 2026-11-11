import logging as _logging

from .config import Config
from .client import Touchque, get_default_client
from .exceptions import (
    TouchqueException,
    TouchqueAPIException,
    TouchqueFeatureException,
    TouchqueFeatureNotInPlanException,
    TouchqueFeatureReadOnlyException,
    TouchqueFeatureOffException,
    TouchqueNetworkException,
    TouchqueTimeoutException,
    TouchqueRejectedException,
    TouchqueWebhookSignatureException,
    TouchqueWebhookReplayException,
    TouchqueConfigException,
    TouchquePasskeyRequiredError,
    TouchqueApprovalError,
    TouchqueApprovalMismatchError,
)
from .resources.webhook import ReplayCache, MemoryReplayCache, WebhookReasons, WebhookEvents
from .steps import normalize_details, details_digest
from .approval_proof import verify_approval_proof
from .code_reply import new_code_reply_key, open_code_reply
from .safe_guard import (
    safe_approval_message, safe_display_digest, safe_governance_hash, safe_schedule_call, safe_tx_hash, verify_safe_approval,
    with_safe_approvals,
)
from .guard import run_guard, guard_input_from_headers, silent_input_from_headers, BROWSER_HEADER
from .resources.risk import parse_risk_check
from .resources.recovery import is_recovery_open
from .resources.mobile import is_mobile_push_expired, mobile_push_from_webhook
from .resources.assist import is_assist_check_passed
from .resources.qr_pairings import QR_PAIRING_REFUSAL_REASONS, qr_pairing_uri
from .resources.device_risk import DEVICE_RISK_EVENTS, DEVICE_RISK_REPORTS, parse_device_risk_check
from .resources.action_types import SECOND_THOUGHT_QUESTIONS
from .relay import RelayHandler, RelayResponse, RELAY_ROUTES
from .rate_limiter import FixedWindowLimiter
from .agent import TouchqueAgent, generate_agent_key, jwk_thumbprint
from .agent_frameworks import (
    ApprovalPolicy, approve_interruptions_with_touchque, current_approval, guard_mcp_session, require_agent_approval,
    touchque_can_use_tool, with_touchque_approval,
)
from .org_agent import TouchqueOrgAgent, file_token, github_actions_token
from .mcp_auth import McpAuth, McpAuthError
from .cross_app_access import (
    ID_JAG_TOKEN_TYPE, IdJagError, IdJagVerifier, redeem_id_jag, request_id_jag,
)
from .security_events import (
    SECURITY_EVENT_TYPES, SecurityEvent, SecurityEventError, SecurityEventVerifier, poll_security_events,
)
from .agent_card import AgentCardError, canonical_json, sign_agent_card, verify_agent_card
from .approval_token import matches_authorization_details, verify_approval_token_with
from .hosted_login import HostedLogin, HostedLoginError, AuthorizationRequest, TokenSet, UserApprovalRequest, CONNECTION_TOKEN_TYPE
from .my_account import MyAccount, MyAccountError

__all__ = [
    'Touchque',
    'Config',
    'get_default_client',
    'TouchqueException',
    'TouchqueAPIException',
    'TouchqueFeatureException',
    'TouchqueFeatureNotInPlanException',
    'TouchqueFeatureReadOnlyException',
    'TouchqueFeatureOffException',
    'TouchqueNetworkException',
    'TouchqueTimeoutException',
    'TouchqueRejectedException',
    'TouchqueWebhookSignatureException',
    'TouchqueWebhookReplayException',
    'ReplayCache',
    'MemoryReplayCache',
    'WebhookReasons',
    'WebhookEvents',
    'TouchqueConfigException',
    'TouchquePasskeyRequiredError',
    'normalize_details',
    'details_digest',
    'verify_approval_proof',
    'new_code_reply_key',
    'open_code_reply',
    'safe_tx_hash',
    'safe_governance_hash',
    'safe_approval_message',
    'safe_display_digest',
    'verify_safe_approval',
    'with_safe_approvals',
    'safe_schedule_call',
    'run_guard',
    'guard_input_from_headers',
    'silent_input_from_headers',
    'BROWSER_HEADER',
    'parse_risk_check',
    'is_recovery_open',
    'is_mobile_push_expired',
    'mobile_push_from_webhook',
    'is_assist_check_passed',
    'QR_PAIRING_REFUSAL_REASONS',
    'qr_pairing_uri',
    'DEVICE_RISK_EVENTS',
    'DEVICE_RISK_REPORTS',
    'parse_device_risk_check',
    'SECOND_THOUGHT_QUESTIONS',
    'RelayHandler',
    'RelayResponse',
    'RELAY_ROUTES',
    'FixedWindowLimiter',
    'TouchqueAgent',
    'ApprovalPolicy',
    'with_touchque_approval',
    'current_approval',
    'require_agent_approval',
    'approve_interruptions_with_touchque',
    'touchque_can_use_tool',
    'guard_mcp_session',
    'generate_agent_key',
    'TouchqueOrgAgent',
    'github_actions_token',
    'file_token',
    'McpAuth',
    'McpAuthError',
    'ID_JAG_TOKEN_TYPE',
    'IdJagError',
    'IdJagVerifier',
    'SECURITY_EVENT_TYPES', 'SecurityEvent', 'SecurityEventError', 'SecurityEventVerifier', 'poll_security_events',
    'request_id_jag',
    'redeem_id_jag',
    'AgentCardError',
    'canonical_json',
    'sign_agent_card',
    'verify_agent_card',
    'jwk_thumbprint',
    'HostedLogin',
    'CONNECTION_TOKEN_TYPE',
    'HostedLoginError',
    'UserApprovalRequest',
    'MyAccount',
    'MyAccountError',
    'AuthorizationRequest',
    'TokenSet',
]

# The SDK's own problems (a misconfigured guard, a failed on_challenge, a relay without
# get_login_user) go to logging.getLogger('touchque'). Silent by default: nothing is printed
# unless your app configures logging (logging.basicConfig, or a handler on 'touchque').
_logging.getLogger('touchque').addHandler(_logging.NullHandler())
