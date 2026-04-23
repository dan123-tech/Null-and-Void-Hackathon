from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import session_scope
from .orm import UserRow


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def jwt_secret() -> str:
    return os.getenv("JWT_SECRET", "change-me")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(subject: str, expires_minutes: int = 60 * 24) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    return jwt.encode(payload, jwt_secret(), algorithm="HS256")


def get_db() -> Session:
    # dependency wrapper
    with session_scope() as db:
        yield db


def get_user_by_email(db: Session, email: str) -> Optional[UserRow]:
    return db.scalar(select(UserRow).where(UserRow.email == email))


def authenticate_user(db: Session, email: str, password: str) -> Optional[UserRow]:
    user = get_user_by_email(db, email)
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> UserRow:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, jwt_secret(), algorithms=["HS256"])
        email = payload.get("sub")
        if not isinstance(email, str) or not email:
            raise cred_exc
    except JWTError:
        raise cred_exc

    user = get_user_by_email(db, email)
    if not user:
        raise cred_exc
    return user


def token_from_ws_query(ws) -> str | None:
    return ws.query_params.get("token")

