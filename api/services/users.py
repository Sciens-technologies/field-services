import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from sqlalchemy import create_engine, Column, String, Integer, DateTime, ForeignKey, Enum, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.orm import joinedload
from passlib.hash import bcrypt  # For password hashing
import jwt  # PyJWT for token-based authentication
from pydantic import ValidationError
from enum import Enum as PyEnum
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict
from sqlalchemy.orm import Session
from sqlalchemy import func

from db.models import *
from api.schemas import *
from api.utils.util import get_db

security = HTTPBearer()

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()


def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()


def get_work_order_by_id(db: Session, work_order_id: int) -> Optional[WorkOrder]:
    return db.query(WorkOrder).filter(WorkOrder.id == work_order_id).first()


def create_user(db: Session, user: UserCreate, hashed_password: str) -> User:
    db_user = User(
        email=user.email,
        hashed_password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
        role=user.role
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def generate_password() -> str:
    """Generates a random password."""
    return uuid4().hex[:8]  # Example: 8-character random string


def create_jwt_token(user_id: int, email: str, role: UserRole, expires_in: int) -> str:
    """Generates a JWT token for authentication."""
    payload = {
        "sub": str(user_id),  # Use string for user ID in token
        "email": email,
        "role": role.value,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)



def decode_jwt_token(token: str) -> dict:
    """Decodes a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")



def get_current_user(db: Session = Depends(get_db), token: HTTPAuthorizationCredentials = Security(security)) -> User:
    """
    Validates the JWT token and returns the current user.
    Raises an exception if the token is invalid or expired.
    """
    payload = decode_jwt_token(token.credentials)
    user_id = int(payload.get("sub"))  # Convert sub back to integer
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def has_role(allowed_roles: List[UserRole]):
    """
    Checks if the current user has the required role.
    """
    def _has_role(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return _has_role