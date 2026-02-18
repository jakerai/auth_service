import secrets
import string
from typing import Dict


class PasswordGenerator:
    """
    Cryptographically secure password generator.

    Suitable for authentication systems, temporary passwords,
    admin resets, and automated credential provisioning.
    """

    # Character set constants
    LOWER = string.ascii_lowercase
    UPPER = string.ascii_uppercase
    DIGITS = string.digits
    SPECIAL = "$#@&*%!"

    MIN_ALLOWED_LENGTH = 8  

    @classmethod
    def generate(
        cls,
        length: int = 32,
        min_lower: int = 1,
        min_upper: int = 1,
        min_digits: int = 1,
        min_special: int = 1,
    ) -> str:
        """
        Generate a secure random password.

        Args:
            length: Total length of the password.
            min_lower: Minimum lowercase characters.
            min_upper: Minimum uppercase characters.
            min_digits: Minimum digits.
            min_special: Minimum special characters.

        Raises:
            ValueError: If configuration is invalid.
        """

        # ---- Validate inputs ----
        if length < cls.MIN_ALLOWED_LENGTH:
            raise ValueError(
                f"Password length must be at least {cls.MIN_ALLOWED_LENGTH}"
            )

        if any(x < 0 for x in [min_lower, min_upper, min_digits, min_special]):
            raise ValueError("Minimum character requirements cannot be negative")

        required_total = min_lower + min_upper + min_digits + min_special
        if required_total > length:
            raise ValueError(
                f"Minimum character requirements ({required_total}) "
                f"exceed requested password length ({length})"
            )

        password_chars: list[str] = []

        # ---- Mandatory characters ----
        password_chars.extend(secrets.choice(cls.LOWER) for _ in range(min_lower))
        password_chars.extend(secrets.choice(cls.UPPER) for _ in range(min_upper))
        password_chars.extend(secrets.choice(cls.DIGITS) for _ in range(min_digits))
        password_chars.extend(secrets.choice(cls.SPECIAL) for _ in range(min_special))

        # ---- Fill remaining ----
        all_allowed = cls.LOWER + cls.UPPER + cls.DIGITS + cls.SPECIAL
        remaining = length - len(password_chars)
        password_chars.extend(secrets.choice(all_allowed) for _ in range(remaining))

        # ---- Secure shuffle ----
        secrets.SystemRandom().shuffle(password_chars)

        return "".join(password_chars)

    @classmethod
    def validate_strength(cls, password: str) -> Dict[str, int]:
        """
        Analyze password composition.

        Returns:
            Dictionary with counts of each character type.
        """
        return {
            "length": len(password),
            "upper": sum(1 for c in password if c in cls.UPPER),
            "lower": sum(1 for c in password if c in cls.LOWER),
            "digits": sum(1 for c in password if c in cls.DIGITS),
            "special": sum(1 for c in password if c in cls.SPECIAL),
        }


if __name__ == "__main__":
    try:
        pw = PasswordGenerator.generate()
        print("Generated:", pw)
        print("Stats:", PasswordGenerator.validate_strength(pw))

        short_pw = PasswordGenerator.generate(length=12, min_digits=5)
        print("\nDigit heavy:", short_pw)

    except ValueError as e:
        print("Error:", e)
