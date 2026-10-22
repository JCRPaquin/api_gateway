import re
import unicodedata

import idna


def canonicalize_domain(domain: str) -> str:
    domain = domain.strip()
    if domain.endswith("."):
        domain = domain[:-1]
    if not domain:
        raise ValueError("Invalid email domain")
    try:
        canonical = idna.encode(domain, uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise ValueError("Invalid email domain") from exc
    labels = canonical.split(".")
    if len(canonical) > 253 or any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9-]+", label)
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        raise ValueError("Invalid email domain")
    return canonical


def canonicalize_email(email: str) -> str:
    if not isinstance(email, str) or email.count("@") != 1:
        raise ValueError("Invalid email address")
    local, domain = email.rsplit("@", 1)
    local = unicodedata.normalize("NFC", local)
    if not local or any(ord(char) < 32 or ord(char) == 127 for char in local):
        raise ValueError("Invalid email address")
    if local.isascii():
        local = local.lower()
    canonical = f"{local}@{canonicalize_domain(domain)}"
    if len(canonical) > 254:
        raise ValueError("Invalid email address")
    return canonical


def canonicalize_email_domain(email: str) -> str:
    return canonicalize_email(email).rsplit("@", 1)[1]
