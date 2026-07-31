"""
Secure Password Generator
Generates cryptographically secure passwords using Python's `secrets` module.
"""

import secrets
import string
from dataclasses import dataclass


LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?"

# Ambiguous characters that can be confused visually
AMBIGUOUS = set("0O1lI")

WORDLIST = [
    "apple", "beach", "cabin", "dance", "eagle", "flame", "globe", "house",
    "igloo", "jumbo", "kiwi", "laser", "maple", "noble", "ocean", "piano",
    "queen", "river", "solar", "tiger", "ultra", "vivid", "witch", "xenon",
    "yacht", "zebra", "amber", "brave", "coral", "dusk", "ember", "frost",
    "grove", "haven", "ivory", "jade", "knoll", "lunar", "mango", "ninja",
    "onyx", "prism", "quartz", "ridge", "stone", "thorn", "unity", "vapor",
    "willow", "xray", "yield", "zeal", "arrow", "blaze", "creek", "drift",
    "echo", "forge", "glass", "haze", "inlet", "jewel", "karma", "lark",
    "marsh", "nectar", "orbit", "pulse", "quest", "realm", "swift", "trail",
    "umber", "vault", "wave", "xerus", "yonder", "zinc",
]


@dataclass
class GeneratorConfig:
    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_special: bool = True
    exclude_ambiguous: bool = False
    custom_exclude: str = ""


def generate_password(config: GeneratorConfig = None) -> str:
    """
    Generate a cryptographically secure random password.

    Uses `secrets` module which is suitable for generating tokens,
    passwords, and other security-sensitive values.
    """
    if config is None:
        config = GeneratorConfig()

    charset = ""
    required_chars = []

    if config.use_lowercase:
        charset += LOWERCASE
        required_chars.append(secrets.choice(LOWERCASE))
    if config.use_uppercase:
        charset += UPPERCASE
        required_chars.append(secrets.choice(UPPERCASE))
    if config.use_digits:
        charset += DIGITS
        required_chars.append(secrets.choice(DIGITS))
    if config.use_special:
        charset += SPECIAL
        required_chars.append(secrets.choice(SPECIAL))

    if not charset:
        raise ValueError("At least one character set must be selected")

    # Remove ambiguous characters if requested
    if config.exclude_ambiguous:
        charset = "".join(c for c in charset if c not in AMBIGUOUS)
        required_chars = [c for c in required_chars if c not in AMBIGUOUS]

    # Remove custom excluded characters
    if config.custom_exclude:
        excluded = set(config.custom_exclude)
        charset = "".join(c for c in charset if c not in excluded)
        required_chars = [c for c in required_chars if c not in excluded]

    if not charset:
        raise ValueError("Character set is empty after exclusions")

    remaining_length = max(0, config.length - len(required_chars))
    password_chars = required_chars + [secrets.choice(charset) for _ in range(remaining_length)]

    # Shuffle to avoid predictable positions for required chars
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars[:config.length])


def generate_passphrase(num_words: int = 4, separator: str = "-", capitalize: bool = True) -> str:
    """
    Generate a memorable passphrase using random words.
    Passphrases are both strong and easier to remember than random strings.

    Example: "Amber-Tiger-Quartz-Ocean"
    """
    words = [secrets.choice(WORDLIST) for _ in range(num_words)]
    if capitalize:
        words = [w.capitalize() for w in words]
    # Append a random number for extra entropy
    words.append(str(secrets.randbelow(900) + 100))
    return separator.join(words)


def generate_pin(length: int = 6) -> str:
    """Generate a cryptographically secure numeric PIN."""
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def estimate_crack_time(password: str) -> dict:
    """
    Estimate time to crack a password with brute-force at various speeds.
    Returns human-readable estimates.
    """
    import math

    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in SPECIAL for c in password):
        charset_size += len(SPECIAL)

    if charset_size == 0:
        return {"combinations": 0, "estimates": {}}

    combinations = charset_size ** len(password)

    def format_time(seconds: float) -> str:
        if seconds < 1:
            return "< 1 second"
        elif seconds < 60:
            return f"{int(seconds)} second(s)"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minute(s)"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hour(s)"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} day(s)"
        elif seconds < 3.154e10:
            return f"{seconds/31536000:.1f} year(s)"
        elif seconds < 3.154e13:
            return f"{seconds/3.154e10:.1f} thousand year(s)"
        elif seconds < 3.154e16:
            return f"{seconds/3.154e13:.1f} million year(s)"
        else:
            return f"{seconds/3.154e16:.1f} billion year(s)"

    return {
        "combinations": combinations,
        "entropy_bits": round(math.log2(combinations), 1) if combinations > 0 else 0,
        "estimates": {
            "Online attack (10/s)": format_time(combinations / 10),
            "Online attack (1K/s)": format_time(combinations / 1_000),
            "Offline attack (1B/s)": format_time(combinations / 1_000_000_000),
            "GPU cluster (100B/s)": format_time(combinations / 100_000_000_000),
            "Nation-state (1T/s)": format_time(combinations / 1_000_000_000_000),
        },
    }
