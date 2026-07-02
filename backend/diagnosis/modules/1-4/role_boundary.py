"""Dynamic authorization-boundary discovery from OpenAPI declarations and JWTs."""

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from models import ScanTarget
from payload_injector import PayloadInjector


ROLE_CLAIM_KEYS = {"role", "roles", "authority", "authorities"}


def _normalized(value: str) -> str:
    key = str(value).strip().casefold()
    return key[5:] if key.startswith("role_") else key


def _claim_aliases(value: str) -> List[str]:
    raw = str(value).strip()
    aliases = [raw]
    if raw.upper().startswith("ROLE_"):
        aliases.append(raw[5:])
    return [value for value in aliases if value]


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    """Decode claims without verification; the target server still verifies the JWT."""
    clean = token.strip()
    if clean.lower().startswith("bearer "):
        clean = clean[7:].strip()
    parts = clean.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


def extract_role_claims(claims: Dict[str, Any]) -> List[str]:
    roles: List[str] = []

    def walk(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, child_key)
        elif key.casefold() in ROLE_CLAIM_KEYS:
            values = value if isinstance(value, list) else [value]
            for item in values:
                if isinstance(item, (str, int)):
                    for alias in _claim_aliases(str(item)):
                        if _normalized(alias) not in {_normalized(r) for r in roles}:
                            roles.append(alias)

    walk(claims)
    return roles


def extract_resource_ids(claims: Dict[str, Any]) -> Dict[str, List[str]]:
    resource_ids: Dict[str, List[str]] = {}

    def add(key: str, value: Any) -> None:
        if not isinstance(value, (str, int)) or value == "":
            return
        name = key.strip()
        values = resource_ids.setdefault(name, [])
        text = str(value)
        if text not in values:
            values.append(text)

    def walk(value: Any, key: str = "") -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                walk(child, child_key)
        elif key.casefold() == "sub" or key.casefold().endswith("id"):
            add(key, value)

    walk(claims)
    return resource_ids


@dataclass
class TokenIdentity:
    name: str
    token: str
    claims: Dict[str, Any]
    role_claims: List[str] = field(default_factory=list)
    resource_ids: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def aliases(self) -> List[str]:
        values = [self.name, *self.role_claims]
        result: List[str] = []
        for value in values:
            for alias in _claim_aliases(value):
                if _normalized(alias) not in {_normalized(v) for v in result}:
                    result.append(alias)
        return result


def parse_token_sets(raw_values: Iterable[str]) -> List[TokenIdentity]:
    identities: List[TokenIdentity] = []
    seen = set()
    for raw in raw_values:
        if "=" not in raw:
            raise ValueError(f"Invalid --token-set {raw!r}; use ROLE_NAME=JWT")
        declared_name, token = raw.split("=", 1)
        declared_name, token = declared_name.strip(), token.strip()
        if not declared_name or not token:
            raise ValueError(f"Invalid --token-set {raw!r}; use ROLE_NAME=JWT")

        claims = decode_jwt_payload(token)
        claim_roles = extract_role_claims(claims)
        name = claim_roles[0] if declared_name.casefold() == "auto" and claim_roles else declared_name
        if _normalized(name) in seen:
            raise ValueError(f"Duplicate token role name: {name}")
        seen.add(_normalized(name))
        identities.append(TokenIdentity(
            name=name,
            token=token,
            claims=claims,
            role_claims=claim_roles,
            resource_ids=extract_resource_ids(claims),
        ))
    return identities


def apply_explicit_resource_ids(identities: List[TokenIdentity],
                                raw_values: Iterable[str]) -> None:
    """Apply ROLE:param=value values; explicit values precede JWT-derived IDs."""
    by_name = {
        _normalized(alias): identity
        for identity in identities
        for alias in identity.aliases
    }
    for raw in raw_values:
        match = re.fullmatch(r"([^:]+):([^=]+)=(.+)", raw.strip())
        if not match:
            raise ValueError(f"Invalid --resource-id {raw!r}; use ROLE:param=value")
        role, param, value = (part.strip() for part in match.groups())
        identity = by_name.get(_normalized(role))
        if identity is None:
            raise ValueError(f"Unknown role in --resource-id: {role}")
        existing = identity.resource_ids.setdefault(param, [])
        if value in existing:
            existing.remove(value)
        existing.insert(0, value)


def _role_declared_for(identity: TokenIdentity, target: ScanTarget) -> bool:
    aliases = {_normalized(value) for value in identity.aliases}
    return bool(aliases.intersection(_normalized(role) for role in target.allowed_roles))


class RoleBoundaryDiscoverer:
    def __init__(self, identities: List[TokenIdentity], timeout: int = 6,
                 auth_refresh_callbacks: Optional[Dict[str, Callable]] = None):
        self.identities = identities
        self.timeout = timeout
        self.auth_refresh_callbacks = auth_refresh_callbacks or {}

    def discover(self, targets: List[ScanTarget]):
        decisions: Dict[str, Dict[Tuple[str, str], bool]] = {
            identity.name: {} for identity in self.identities
        }
        matrix: List[dict] = []

        unique_targets = {}
        for target in targets:
            unique_targets[(target.method, target.full_url)] = target

        for identity in self.identities:
            clean_token = identity.token.strip()
            if clean_token.lower().startswith("bearer "):
                clean_token = clean_token[7:].strip()
            injector = PayloadInjector(
                timeout=self.timeout,
                delay_between_requests=0,
                auth_headers={"Authorization": f"Bearer {clean_token}"},
                resource_ids=identity.resource_ids,
                auth_refresh_callback=self.auth_refresh_callbacks.get(identity.name),
            )
            for key, target in unique_targets.items():
                if target.allowed_roles and not _role_declared_for(identity, target):
                    decisions[identity.name][key] = False
                    matrix.append({
                        "role": identity.name,
                        "method": target.method,
                        "url": target.full_url,
                        "accessible": False,
                        "reason": "OPENAPI_ROLE_DECLARATION_DENIED",
                        "declared_roles": target.allowed_roles,
                    })
                    continue

                probe = injector.probe_target_access(target)
                status = probe.response.status_code if probe.response is not None else None
                # Network/validation failures are inconclusive and must not silently remove coverage.
                accessible = status not in (401, 403) if status is not None else True
                decisions[identity.name][key] = accessible
                matrix.append({
                    "role": identity.name,
                    "role_claims": identity.role_claims,
                    "method": target.method,
                    "url": target.full_url,
                    "accessible": accessible,
                    "declared_roles": target.allowed_roles,
                    **probe.to_dict(),
                })

        return decisions, matrix
