"""Classical Encryption Ciphers, Frequency Analysis, and Public-Key Number Theory Helpers."""

from collections import Counter
import string
from typing import Tuple


def caesar_encrypt(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


def vigenere_encrypt(text: str, key: str) -> str:
    key_clean = [k.upper() for k in key if k.isalpha()]
    if not key_clean:
        raise ValueError("Key must contain at least one alphabetic character.")
    result = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            shift = ord(key_clean[ki % len(key_clean)]) - ord("A")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_decrypt(text: str, key: str) -> str:
    key_clean = [k.upper() for k in key if k.isalpha()]
    inv_key = "".join(chr((26 - (ord(k) - ord("A"))) % 26 + ord("A")) for k in key_clean)
    return vigenere_encrypt(text, inv_key)


def frequency_analysis(ciphertext: str) -> list[tuple[str, float]]:
    letters = [ch.upper() for ch in ciphertext if ch.isalpha()]
    total = len(letters)
    if total == 0:
        return []
    counts = Counter(letters)
    return [(char, round((count / total) * 100, 2)) for char, count in counts.most_common()]


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_exp(base: int, exp: int, mod: int) -> int:
    """Fast modular exponentiation used in RSA and Diffie-Hellman."""
    return pow(base, exp, mod)


if __name__ == "__main__":
    sample = "Network Security Foundations"
    enc = vigenere_encrypt(sample, "KEY")
    print("Vigenere Encrypted:", enc)
    print("Vigenere Decrypted:", vigenere_decrypt(enc, "KEY"))
    print("Top Frequencies:", frequency_analysis(enc)[:5])
    print("mod_exp(4, 13, 497):", mod_exp(4, 13, 497))
