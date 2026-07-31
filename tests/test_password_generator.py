"""Unit tests for cybersec_toolkit.modules.password_generator"""

import string
import pytest

from cybersec_toolkit.modules.password_generator import (
    generate_password,
    generate_passphrase,
    generate_pin,
    estimate_crack_time,
    GeneratorConfig,
    SPECIAL,
    AMBIGUOUS,
    WORDLIST,
)


# ──────────────────────────────────────────────────────────────────────────────
# Test 8: generate_password
# ──────────────────────────────────────────────────────────────────────────────
class TestGeneratePassword:
    def test_default_length_16(self):
        pw = generate_password()
        assert len(pw) == 16

    def test_custom_length(self):
        cfg = GeneratorConfig(length=24)
        pw = generate_password(cfg)
        assert len(pw) == 24

    def test_contains_required_charsets(self):
        cfg = GeneratorConfig(use_lowercase=True, use_uppercase=True, use_digits=True, use_special=True, length=20)
        pw = generate_password(cfg)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SPECIAL for c in pw)

    def test_no_charset_raises(self):
        cfg = GeneratorConfig(use_lowercase=False, use_uppercase=False, use_digits=False, use_special=False)
        with pytest.raises(ValueError, match="At least one character set must be selected"):
            generate_password(cfg)

    def test_exclude_ambiguous(self):
        cfg = GeneratorConfig(exclude_ambiguous=True, length=50)
        pw = generate_password(cfg)
        for ch in pw:
            assert ch not in AMBIGUOUS, f"Ambiguous char '{ch}' found in password"

    def test_custom_exclude(self):
        cfg = GeneratorConfig(custom_exclude="0123456789", use_digits=False, length=30)
        pw = generate_password(cfg)
        assert not any(c.isdigit() for c in pw)

    def test_uniqueness_across_calls(self):
        pws = {generate_password() for _ in range(10)}
        # Extremely unlikely all 10 are identical
        assert len(pws) > 1

    def test_empty_charset_after_exclusions_raises(self):
        # Only digits selected but all digits excluded
        cfg = GeneratorConfig(
            use_lowercase=False, use_uppercase=False, use_digits=True, use_special=False,
            custom_exclude=string.digits
        )
        with pytest.raises(ValueError, match="Character set is empty after exclusions"):
            generate_password(cfg)


# ──────────────────────────────────────────────────────────────────────────────
# Test 9: generate_passphrase / generate_pin
# ──────────────────────────────────────────────────────────────────────────────
class TestPassphraseAndPin:
    def test_passphrase_word_count(self):
        phrase = generate_passphrase(num_words=4, separator="-")
        # Words + trailing number → 5 parts
        parts = phrase.split("-")
        assert len(parts) == 5

    def test_passphrase_capitalize(self):
        phrase = generate_passphrase(num_words=3, capitalize=True)
        words = phrase.split("-")[:-1]  # exclude trailing number
        for w in words:
            assert w[0].isupper()

    def test_passphrase_no_capitalize(self):
        phrase = generate_passphrase(num_words=3, capitalize=False)
        words = phrase.split("-")[:-1]
        for w in words:
            assert w[0].islower() or not w[0].isalpha()

    def test_passphrase_words_from_wordlist(self):
        phrase = generate_passphrase(num_words=3, capitalize=False)
        words = phrase.split("-")[:-1]
        for w in words:
            assert w in WORDLIST

    def test_pin_default_length_6(self):
        pin = generate_pin()
        assert len(pin) == 6

    def test_pin_only_digits(self):
        pin = generate_pin(8)
        assert pin.isdigit()

    def test_pin_custom_length(self):
        assert len(generate_pin(12)) == 12


# ──────────────────────────────────────────────────────────────────────────────
# Test 10: estimate_crack_time
# ──────────────────────────────────────────────────────────────────────────────
class TestEstimateCrackTime:
    def test_returns_combinations_and_estimates(self):
        result = estimate_crack_time("Abc1!")
        assert "combinations" in result
        assert "estimates" in result
        assert result["combinations"] > 0

    def test_longer_password_more_combinations(self):
        short = estimate_crack_time("Aa1!")["combinations"]
        long_ = estimate_crack_time("Aa1!Bb2@Cc3#Dd4$")["combinations"]
        assert long_ > short

    def test_empty_password_returns_zero_combinations(self):
        result = estimate_crack_time("")
        assert result["combinations"] == 0

    def test_all_expected_attack_scenarios_present(self):
        result = estimate_crack_time("Pass1!")
        expected_keys = {
            "Online attack (10/s)",
            "Online attack (1K/s)",
            "Offline attack (1B/s)",
            "GPU cluster (100B/s)",
            "Nation-state (1T/s)",
        }
        assert expected_keys == set(result["estimates"].keys())
