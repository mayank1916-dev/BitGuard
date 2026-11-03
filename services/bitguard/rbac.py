"""Development-grade RBAC, JWT issuance, permission matrix and access control dependencies (Milestone S05 / F9 basic)."""

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import Depends, Header, HTTPException, Request

from services.bitguard.config import settings
from services.bitguard.models import Permission, Role, UserResponse

logger = logging.getLogger(__name__)

# --- In-memory Denied Access Audit Store ---
access_denied_log: list[dict[str, Any]] = []


def log_access_denied(
    user: str,
    route: str,
    method: str,
    role: str,
    missing_permissions: list[str] | None = None,
    required_roles: list[str] | None = None,
) -> None:
    """Logs denied access attempt with user, route and time."""
    timestamp_iso = datetime.now(UTC).isoformat()
    entry = {
        "user": user,
        "route": route,
        "method": method,
        "role": role,
        "missing_permissions": missing_permissions or [],
        "required_roles": required_roles or [],
        "timestamp": timestamp_iso,
    }
    access_denied_log.append(entry)
    logger.warning(
        "RBAC access denied: user=%s route=%s method=%s role=%s time=%s",
        user,
        route,
        method,
        role,
        timestamp_iso,
        extra=entry,
    )


# --- Permission Matrix Definition ---
# Viewer reads; Operator marks false positives and tightens policy;
# SecOps controls breaker; Compliance reads audit and reports;
# Approver approves holds; Admin manages users and policy loosening requests.

BASE_READ_PERMISSIONS: set[Permission] = {
    Permission.READ_DECISIONS,
    Permission.READ_METRICS,
    Permission.READ_CHECKLIST,
    Permission.READ_BREAKER,
    Permission.READ_WALLET_GROUPS,
    Permission.EVALUATE_TX,
}

PERMISSION_MATRIX: dict[Role, set[Permission]] = {
    Role.VIEWER: set(BASE_READ_PERMISSIONS),
    Role.OPERATOR: set(BASE_READ_PERMISSIONS)
    | {
        Permission.SUBMIT_SIGN_REQUEST,
        Permission.LABEL_FALSE_POSITIVE,
        Permission.POLICY_TIGHTEN,
    },
    Role.SECOPS: set(BASE_READ_PERMISSIONS)
    | {
        Permission.SUBMIT_SIGN_REQUEST,
        Permission.CONTROL_BREAKER,
        Permission.POLICY_TIGHTEN,
        Permission.PROMOTE_GROUP_OVERRIDE,
        Permission.READ_AUDIT,
    },
    Role.COMPLIANCE: set(BASE_READ_PERMISSIONS)
    | {
        Permission.READ_AUDIT,
        Permission.READ_REPORTS,
    },
    Role.APPROVER: set(BASE_READ_PERMISSIONS)
    | {
        Permission.APPROVE_HOLD,
    },
    Role.ADMIN: {
        # Admin has all permissions
        *Permission,
    },
}

# --- Seeded Test Users (One per role) ---
SEEDED_USERS: dict[Role, UserResponse] = {
    Role.VIEWER: UserResponse(
        id="usr-viewer-01",
        email="viewer@bitguard.local",
        name="Alice Viewer",
        role=Role.VIEWER,
        permissions=sorted(PERMISSION_MATRIX[Role.VIEWER]),
    ),
    Role.OPERATOR: UserResponse(
        id="usr-operator-01",
        email="operator@bitguard.local",
        name="Bob Operator",
        role=Role.OPERATOR,
        permissions=sorted(PERMISSION_MATRIX[Role.OPERATOR]),
    ),
    Role.SECOPS: UserResponse(
        id="usr-secops-01",
        email="secops@bitguard.local",
        name="Charlie SecOps",
        role=Role.SECOPS,
        permissions=sorted(PERMISSION_MATRIX[Role.SECOPS]),
    ),
    Role.COMPLIANCE: UserResponse(
        id="usr-compliance-01",
        email="compliance@bitguard.local",
        name="Diana Compliance",
        role=Role.COMPLIANCE,
        permissions=sorted(PERMISSION_MATRIX[Role.COMPLIANCE]),
    ),
    Role.APPROVER: UserResponse(
        id="usr-approver-01",
        email="approver@bitguard.local",
        name="Evan Approver",
        role=Role.APPROVER,
        permissions=sorted(PERMISSION_MATRIX[Role.APPROVER]),
    ),
    Role.ADMIN: UserResponse(
        id="usr-admin-01",
        email="admin@bitguard.local",
        name="Grace Admin",
        role=Role.ADMIN,
        permissions=sorted(PERMISSION_MATRIX[Role.ADMIN]),
    ),
}


# --- JWT Token Issuance & Verification ---


def create_access_token(user: UserResponse, expires_delta: timedelta | None = None) -> str:
    """Signs and issues a short-lived JWT for the specified user."""
    now = datetime.now(UTC)
    expire = now + (expires_delta or timedelta(seconds=settings.jwt_expiration_seconds))
    payload = {
        "sub": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role.value,
        "permissions": [p.value for p in user.permissions],
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    """Verifies cryptographic signature and claims of incoming JWT."""
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token has expired") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token signature or claims") from exc


# --- FastAPI Auth Dependencies ---


def get_current_user(
    request: Request,
    authorization: str | None = Header(default=None),
    x_user_role: str | None = Header(default=None, alias="X-User-Role"),
    x_anonymous: str | None = Header(default=None, alias="X-Anonymous"),
) -> UserResponse:
    """Resolves active user from Bearer JWT, dev role header, or dev fallback."""
    # 1. Explicit unauthenticated header
    if x_anonymous and x_anonymous.lower() == "true":
        raise HTTPException(status_code=401, detail="Authentication credentials required")

    # 2. Bearer JWT Token
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            payload = decode_access_token(parts[1])
            role_val = payload.get("role")
            matched_role = None
            for r in Role:
                if r.value.lower() == str(role_val).lower():
                    matched_role = r
                    break
            if not matched_role:
                raise HTTPException(status_code=401, detail=f"Unrecognized role '{role_val}' in token")
            return UserResponse(
                id=payload.get("sub", f"usr-{matched_role.value.lower()}"),
                email=payload.get("email", f"{matched_role.value.lower()}@bitguard.local"),
                name=payload.get("name", matched_role.value),
                role=matched_role,
                permissions=sorted(PERMISSION_MATRIX[matched_role]),
            )
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header; expected 'Bearer <token>'",
        )

    # 3. Direct X-User-Role header for dev convenience
    if x_user_role:
        for r in Role:
            if r.value.lower() == x_user_role.lower():
                return SEEDED_USERS[r]
        raise HTTPException(status_code=401, detail=f"Unknown role in X-User-Role: '{x_user_role}'")

    # 4. Dev environment fallback when no credentials supplied
    if settings.environment.lower() != "production" and settings.dev_auth_bypass:
        return SEEDED_USERS[Role.ADMIN]

    raise HTTPException(status_code=401, detail="Authentication credentials required")


def require_role(*allowed_roles: Role) -> Callable[..., UserResponse]:
    """Reusable dependency verifying the active user holds an allowed role."""

    def role_checker(
        request: Request,
        user: UserResponse = Depends(get_current_user),
    ) -> UserResponse:
        if user.role not in allowed_roles:
            log_access_denied(
                user=user.email,
                route=request.url.path,
                method=request.method,
                role=user.role.value,
                required_roles=[r.value for r in allowed_roles],
            )
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: role '{user.role.value}' lacks required role {[r.value for r in allowed_roles]}",
            )
        return user

    return role_checker


def require_permission(*required_perms: Permission) -> Callable[..., UserResponse]:
    """Reusable dependency verifying active user permissions against permission matrix."""

    def permission_checker(
        request: Request,
        user: UserResponse = Depends(get_current_user),
    ) -> UserResponse:
        user_perms = PERMISSION_MATRIX.get(user.role, set())
        missing = [p for p in required_perms if p not in user_perms]
        if missing:
            log_access_denied(
                user=user.email,
                route=request.url.path,
                method=request.method,
                role=user.role.value,
                missing_permissions=[p.value for p in missing],
            )
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: missing permissions {[p.value for p in missing]}",
            )
        return user

    return permission_checker


# --- Separation of Duties Hooks (to be completed in future steps) ---


def hook_requester_cannot_approve_own_request(requester_id: str, approver_id: str) -> bool:
    """Separation of duties hook: A transaction requester cannot approve their own hold ticket."""
    if requester_id and approver_id and requester_id.strip() == approver_id.strip():
        logger.warning(
            "Separation of duties violation: requester cannot approve own request",
            extra={"requester_id": requester_id, "approver_id": approver_id},
        )
        return False
    return True


def hook_policy_author_cannot_approve_own_change(author_id: str, approver_id: str) -> bool:
    """Separation of duties hook: A policy change author cannot approve their own change."""
    if author_id and approver_id and author_id.strip() == approver_id.strip():
        logger.warning(
            "Separation of duties violation: policy author cannot approve own change",
            extra={"author_id": author_id, "approver_id": approver_id},
        )
        return False
    return True
