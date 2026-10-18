"""parse_risk_check against the cross-SDK vectors
(fixtures/silent-sign-in-vectors.json riskCheck.cases, shared with Node, PHP,
Go and web): every SDK must read every POST /risk/check answer the same way."""
import pytest

from touchque import parse_risk_check
from .silent_vectors import VECTORS


@pytest.mark.parametrize('case', VECTORS['riskCheck']['cases'], ids=lambda c: c['name'])
def test_risk_check_vector(case):
    res = parse_risk_check(case['response'])
    assert res['prompt'] is case['expected']['prompt']
    assert [r['code'] for r in res['reasons']] == case['expected']['reasonCodes']
    assert res['assurance'] == case['expected']['assurance']


@pytest.mark.parametrize('raw', [None, 'false', False, 0, [], {'prompt': 0}, {'prompt': None}, {'prompt': 'no'}])
def test_anything_but_a_json_object_with_prompt_false_asks(raw):
    assert parse_risk_check(raw) == {'prompt': True, 'reasons': [], 'assurance': 'normal', 'silentMode': 'enforce'}


def test_reason_entries_without_a_string_code_are_dropped_and_a_missing_text_is_empty():
    res = parse_risk_check({'prompt': True, 'reasons': [
        None, {'code': 1}, {'code': 'new_browser'}, 'x', {'code': 'risk_signal', 'text': 'Risk signal: tor_exit_node'},
    ]})
    assert res['reasons'] == [{'code': 'new_browser', 'text': ''},
                              {'code': 'risk_signal', 'text': 'Risk signal: tor_exit_node'}]


def test_unknown_assurance_is_normal_and_silent_mode_is_shadow_or_enforce():
    res = parse_risk_check({'prompt': False, 'assurance': 'certain', 'silentMode': 'other'})
    assert res == {'prompt': False, 'reasons': [], 'assurance': 'normal', 'silentMode': 'enforce'}
    assert parse_risk_check({'prompt': True, 'silentMode': 'shadow'})['silentMode'] == 'shadow'
