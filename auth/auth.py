from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session
import logging

from db.database import get_db
from db.models import User, Token
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secure-secret-key-123")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

logger = logging.getLogger(__name__)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a new JWT token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """Get the current authenticated user with debug logging."""
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        logger.info(f"[AUTH] Received token: {token}")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        logger.info(f"[AUTH] Decoded payload: {payload}")
        if user_id is None:
            logger.warning("[AUTH] No 'sub' in token payload")
            raise credentials_exception
        # Ensure user_id is an int
        user_id = int(user_id)
    except JWTError as e:
        logger.warning(f"[AUTH] JWT decode error: {e}")
        raise credentials_exception

    # Check if token is in database and not revoked
    db_token = (
        db.query(Token)
        .filter(Token.access_token == token, Token.revoked == False)
        .first()
    )
    if not db_token:
        logger.warning("[AUTH] Token not found in DB or revoked")
        raise credentials_exception

    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        logger.warning(f"[AUTH] User not found for user_id: {user_id}")
        raise credentials_exception
    logger.info(f"[AUTH] Authenticated user: {user.email} (id={user.user_id})")
    return user
