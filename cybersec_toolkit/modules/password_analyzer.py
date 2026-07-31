"""
Password Strength Analyzer
Evaluates password strength based on multiple security criteria.
"""

import re
import math
from dataclasses import dataclass, field
from typing import List

# Common weak passwords (truncated list of most-used passwords)
COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "password2", "admin", "welcome", "login", "hello",
    "charlie", "donald", "password123", "qwerty123", "1q2w3e", "12345",
    "111111", "1234567890", "000000", "123456789", "test", "pass",
}

# Keyboard patterns to detect
KEYBOARD_PATTERNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321", "qazwsx", "edcrfv",
]


@dataclass
class AnalysisResult:
    score: int = 0
    max_score: int = 100
    strength: str = "Very Weak"
    entropy_bits: float = 0.0
    issues: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    criteria: dict = field(default_factory=dict)

    @property
    def percentage(self) -> int:
        return int((self.score / self.max_score) * 100)


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of a password."""
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"\d", password):
        charset_size += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password):
        charset_size += 32
    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def detect_keyboard_pattern(password: str) -> bool:
    """Detect sequential keyboard patterns."""
    lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        for i in range(len(pattern) - 2):
            if pattern[i:i+3] in lower:
                return True
    return False


def detect_repeated_chars(password: str) -> bool:
    """Detect more than 2 consecutive repeated characters."""
    return bool(re.search(r"(.)\1{2,}", password))


def analyze_password(password: str) -> AnalysisResult:
    """
    Analyze password strength and return detailed results.

    Scoring breakdown (100 points total):
    - Length: up to 30 pts
    - Character variety: up to 30 pts
    - Entropy: up to 20 pts
    - No common patterns: 10 pts
    - Not a common password: 10 pts
    """
    result = AnalysisResult()
    length = len(password)

    # --- Length scoring (30 pts) ---
    if length >= 20:
        length_score = 30
    elif length >= 16:
        length_score = 25
    elif length >= 12:
        length_score = 20
    elif length >= 10:
        length_score = 15
    elif length >= 8:
        length_score = 10
    elif length >= 6:
        length_score = 5
    else:
        length_score = 0

    result.criteria["length"] = {"value": length, "score": length_score, "max": 30}
    result.score += length_score

    if length < 8:
        result.issues.append(f"Password is too short ({length} chars)")
        result.suggestions.append("Use at least 8 characters (12+ recommended)")
    elif length < 12:
        result.suggestions.append("Consider using 12 or more characters for better security")

    # --- Character variety (30 pts) ---
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?`~]", password))

    variety_score = sum([has_lower * 7, has_upper * 8, has_digit * 7, has_special * 8])
    result.criteria["variety"] = {
        "lowercase": has_lower,
        "uppercase": has_upper,
        "digits": has_digit,
        "special": has_special,
        "score": variety_score,
        "max": 30,
    }
    result.score += variety_score

    missing = []
    if not has_lower:
        missing.append("lowercase letters")
    if not has_upper:
        missing.append("uppercase letters")
    if not has_digit:
        missing.append("numbers")
    if not has_special:
        missing.append("special characters (!@#$...)")
    if missing:
        result.issues.append(f"Missing: {', '.join(missing)}")
        result.suggestions.append(f"Add {', '.join(missing)} to increase strength")

    # --- Entropy scoring (20 pts) ---
    entropy = calculate_entropy(password)
    result.entropy_bits = round(entropy, 1)
    if entropy >= 80:
        entropy_score = 20
    elif entropy >= 60:
        entropy_score = 15
    elif entropy >= 40:
        entropy_score = 10
    elif entropy >= 25:
        entropy_score = 5
    else:
        entropy_score = 0

    result.criteria["entropy"] = {"bits": result.entropy_bits, "score": entropy_score, "max": 20}
    result.score += entropy_score

    # --- Pattern detection (10 pts) ---
    pattern_score = 10
    if detect_keyboard_pattern(password):
        pattern_score -= 5
        result.issues.append("Contains keyboard pattern (e.g. 'qwerty', '1234')")
        result.suggestions.append("Avoid sequential keyboard patterns")
    if detect_repeated_chars(password):
        pattern_score -= 5
        result.issues.append("Contains repeated characters (e.g. 'aaa')")
        result.suggestions.append("Avoid repeating the same character consecutively")

    result.criteria["patterns"] = {"score": max(0, pattern_score), "max": 10}
    result.score += max(0, pattern_score)

    # --- Common password check (10 pts) ---
    common_score = 10
    if password.lower() in COMMON_PASSWORDS:
        common_score = 0
        result.issues.append("This is a commonly used password!")
        result.suggestions.append("Choose a unique password not found in common password lists")

    result.criteria["common"] = {"is_common": password.lower() in COMMON_PASSWORDS, "score": common_score, "max": 10}
    result.score += common_score

    # --- Determine strength label ---
    pct = result.percentage
    if pct >= 85:
        result.strength = "Very Strong"
    elif pct >= 70:
        result.strength = "Strong"
    elif pct >= 50:
        result.strength = "Moderate"
    elif pct >= 30:
        result.strength = "Weak"
    else:
        result.strength = "Very Weak"

    if not result.suggestions and pct < 100:
        result.suggestions.append("Great password! Consider using a password manager to store it safely.")

    return result
