"""Shared helpers for the relay tests: a stub TouchQue client whose resource
methods are ``Mock``s (like the Node router tests' ``fakeTq``), and a real
client pointed at the shared fake API."""
from types import SimpleNamespace
from unittest.mock import Mock

from touchque import Config, TouchQue


def fake_tq():
    return SimpleNamespace(
        auth=SimpleNamespace(
            generate_secret=Mock(return_value={'secret': 'S3CR3T', 'qrCodeDataUrl': 'data:image/png;base64,x'}),
            reset_secret=Mock(return_value={'secret': 'NEWSECRET', 'qrCodeDataUrl': 'data:image/png;base64,y'}),
            get_user=Mock(return_value={'used': False, 'deviceId': None}),
        ),
        login=SimpleNamespace(request=Mock(side_effect=AssertionError('no push expected'))),
        offline=SimpleNamespace(
            challenge=Mock(return_value={'challengeId': 'c1', 'qr': 'TQ1.a.b', 'qrDataUrl': 'data:image/png;base64,q',
                                         'expiresAt': 't', 'expiresInSeconds': 120, 'totpAvailable': True}),
            verify=Mock(return_value={'approved': True, 'challengeId': 'c1', 'externalUsername': 'user@example.com',
                                      'type': 'LOGIN'}),
            verify_totp=Mock(return_value={'approved': True, 'externalUsername': 'user@example.com'}),
        ),
        webauthn=SimpleNamespace(
            primary_options=Mock(return_value={'attemptId': 'att_1', 'options': {}}),
            primary_verify=Mock(return_value={'success': True, 'externalUsername': 'user@example.com',
                                              'requestId': 'req_2'}),
            authenticate_options=Mock(return_value={'someOption': True}),
            authenticate_verify=Mock(return_value={'success': True, 'message': 'approved'}),
            register_options=Mock(return_value={}),
            register_verify=Mock(return_value={'verified': True, 'credentialId': 'cred_1'}),
            list_credentials=Mock(return_value={'credentials': []}),
            delete_credential=Mock(return_value={'deleted': True}),
        ),
    )


def real_tq(fake_api):
    return TouchQue(Config(api_key='tq_test_key', api_secret='test_secret', base_url=fake_api.base_url))
