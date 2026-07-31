"""Unit tests for cybersec_toolkit.modules.password_analyzer"""

import pytest

from cybersec_toolkit.modules.password_analyzer import (
    analyze_password,
    calculate_entropy,
    detect_keyboard_pattern,
    detect_repeated_chars,
    AnalysisResult,
)


# ──────────────────────────────────────────────────────────────────────────────
# Test 5: calculate_entropy
# ──────────────────────────────────────────────────────────────────────────────
class TestCalculateEntropy:
    def test_empty_password_returns_zero(self):
        assert calculate_entropy("") == 0.0

    def test_only_lowercase_uses_charset_26(self):
        # charset = 26, length = 1 → log2(26) ≈ 4.70
        import math
        entropy = calculate_entropy("a")
        assert abs(entropy - math.log2(26)) < 0.01

    def test_mixed_case_digits_special_higher_entropy(self):
        simple = calculate_entropy("aaaaaa")
        complex_ = calculate_entropy("aA1!aA")
        assert complex_ > simple

    def test_longer_password_higher_entropy(self):
        short = calculate_entropy("abc")
        long_ = calculate_entropy("abcdefghijklmnop")
        assert long_ > short


# ──────────────────────────────────────────────────────────────────────────────
# Test 6: detect_keyboard_pattern / detect_repeated_chars
# ──────────────────────────────────────────────────────────────────────────────
class TestPatternDetection:
    def test_qwerty_detected(self):
        assert detect_keyboard_pattern("myQwerty!") is True

    def test_1234_detected(self):
        assert detect_keyboard_pattern("pass1234") is True

    def test_random_no_pattern(self):
        assert detect_keyboard_pattern("xkP9$mQ2") is False

    def test_repeated_chars_aaa_detected(self):
        assert detect_repeated_chars("paaaaword") is True

    def test_repeated_two_not_detected(self):
        # Only >2 consecutive triggers the rule
        assert detect_repeated_chars("aa") is False

    def test_no_repeated_chars(self):
        assert detect_repeated_chars("abcdef") is False


# ──────────────────────────────────────────────────────────────────────────────
# Test 7: analyze_password – scoring & labels
# ──────────────────────────────────────────────────────────────────────────────
class TestAnalyzePassword:
    def test_common_password_scored_zero_common_pts(self):
        result = analyze_password("password")
        assert result.criteria["common"]["is_common"] is True
        assert result.criteria["common"]["score"] == 0

    def test_strong_password_high_score(self):
        result = analyze_password("Tr0ub4dor&3_CellarDoor!")
        assert result.score >= 70

    def test_very_weak_label(self):
        result = analyze_password("a")
        assert result.strength == "Very Weak"

    def test_percentage_between_0_and_100(self):
        result = analyze_password("SomePass1!")
        assert 0 <= result.percentage <= 100

    def test_short_password_has_issue(self):
        result = analyze_password("ab")
        issues_text = " ".join(result.issues)
        assert "short" in issues_text.lower()

    def test_keyboard_pattern_penalised(self):
        result_clean = analyze_password("Xk9!LmP2#RvT")
        result_pattern = analyze_password("qwerty12!Xk9a")
        assert result_clean.criteria["patterns"]["score"] >= result_pattern.criteria["patterns"]["score"]

    def test_all_charsets_present_variety_score_max(self):
        result = analyze_password("Abc1!")
        assert result.criteria["variety"]["score"] == 30  # 7+8+7+8

    def test_result_is_analysis_result_instance(self):
        assert isinstance(analyze_password("test"), AnalysisResult)
