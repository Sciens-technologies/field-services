import datetime
from typing import List, Optional
from uuid import UUID, uuid4
from functools import wraps

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import text
import jwt
import os
from dotenv import load_dotenv

from db.models import (
    User, UserRole, Role, Permission, RolePermission,
    UserStatusAudit, UserAuthProvider, UserAuthMetadata
)
from db.database import get_db
from auth.auth import create_access_token, get_current_user

# Load environment variables
load_dotenv()

# JWT settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRES_IN = datetime.timedelta(seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES_IN", "86400")))  # 24 hours
JWT_REFRESH_TOKEN_EXPIRES_IN = datetime.timedelta(seconds=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES_IN", "2592000")))  # 30 days

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")
security = HTTPBearer(auto_error=False)


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email.ilike(email.strip())).first()

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username.ilike(username.strip())).first()

def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.user_id == user_id).first()

def get_user_by_uuid(db: Session, uuid: str) -> Optional[User]:
    return db.query(User).filter(User.uuid == uuid).first()

def create_jwt_token(data: dict, expires_delta: datetime.timedelta = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + JWT_ACCESS_TOKEN_EXPIRES_IN
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    try:
        payload = decode_jwt_token(token)
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user = get_user_by_id(db, user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        if not user.activated:
            raise HTTPException(status_code=401, detail="User is not activated")
        
        if user.status != 'ACTIVE':
            raise HTTPException(status_code=401, detail=f"User is {user.status}")
        
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def get_current_user_optional(
    request: Request, 
    db: Session = Depends(get_db)
) -> Optional[User]:
    try:
        auth = request.headers.get("Authorization")
        if not auth:
            return None
        
        scheme, token = auth.split()
        if scheme.lower() != "bearer":
            return None
        
        return get_current_user(db, token)
    except Exception:
        return None

def has_role(allowed_roles: List[str]):
    def role_checker(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        user_roles = db.query(UserRole).filter(
            UserRole.user_id == current_user.user_id,
            UserRole.active == True
        ).all()
        
        user_role_names = []
        for user_role in user_roles:
            role = db.query(Role).filter(Role.role_id == user_role.role_id).first()
            if role:
                user_role_names.append(role.role_name)
        
        if not any(role in allowed_roles for role in user_role_names):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this resource"
            )
        return current_user
    return role_checker

def has_permission(current_user: User, permission_feature: str, db: Session = None) -> bool:
    if not db:
        db = next(get_db())
    
    # Check role permissions
    user_roles = db.query(UserRole).filter(
        UserRole.user_id == current_user.user_id,
        UserRole.active == True
    ).all()
    
    for user_role in user_roles:
        permission = db.query(Permission).join(RolePermission).filter(
            RolePermission.role_id == user_role.role_id,
            Permission.feature == permission_feature,
            Permission.active == True
        ).first()
        
        if permission:
            return True
    
    return False

def log_user_status_change(
    db: Session,
    user_id: int,
    old_status: str,
    new_status: str,
    changed_by: str,
    reason: str,
    remarks: Optional[str] = None
):
    audit = UserStatusAudit(
        user_id=user_id,
        old_status=old_status,
        new_status=new_status,
        changed_by=changed_by,
        reason=reason,
        remarks=remarks,
        changed_at=datetime.datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    return audit

def get_user_auth_provider(
    db: Session,
    user_id: int,
    provider: str
) -> Optional[UserAuthProvider]:
    return db.query(UserAuthProvider).filter(
        UserAuthProvider.user_id == user_id,
        UserAuthProvider.provider == provider
    ).first()

def get_user_auth_metadata(
    db: Session,
    user_id: int,
    provider: str
) -> Optional[UserAuthMetadata]:
    return db.query(UserAuthMetadata).filter(
        UserAuthMetadata.user_id == user_id,
        UserAuthMetadata.provider == provider
    ).first()

def update_user_auth_metadata(
    db: Session,
    user_id: int,
    provider: str,
    access_token: str,
    refresh_token: Optional[str] = None,
    token_expires_at: Optional[datetime.datetime] = None
):
    metadata = get_user_auth_metadata(db, user_id, provider)
    if metadata:
        metadata.access_token = access_token
        metadata.refresh_token = refresh_token
        metadata.token_expires_at = token_expires_at
    else:
        metadata = UserAuthMetadata(
            user_id=user_id,
            provider=provider,
            external_user_id=str(user_id),  # This should be the provider's user ID
            access_token=access_token,
            refresh_token=refresh_token,
            token_expires_at=token_expires_at
        )
        db.add(metadata)
    
    db.commit()
    return metadata

def get_user_from_token(token: str, db: Session) -> Optional[User]:
    try:
        payload = decode_jwt_token(token)
        user_id = payload.get("user_id")
        if user_id is None:
            return None
        
        user = get_user_by_id(db, user_id)
        if user is None or not user.activated or user.status != 'ACTIVE':
            return None
        
        return user
    except jwt.PyJWTError:
        return None

def role_required(allowed_roles: List[str]):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), db: Session = Depends(get_db), **kwargs):
            # Check if user has any of the allowed roles
            user_roles = db.query(UserRole).filter(
                UserRole.user_id == current_user.user_id,
                UserRole.active == True
            ).all()
            
            user_role_names = []
            for user_role in user_roles:
                role = db.query(Role).filter(Role.role_id == user_role.role_id).first()
                if role:
                    user_role_names.append(role.role_name)
            
            if not any(role in allowed_roles for role in user_role_names):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"This action requires one of these roles: {', '.join(allowed_roles)}"
                )
            
            return await func(*args, current_user=current_user, db=db, **kwargs)
        return wrapper
    return decorator

def user_to_response(user: User, db: Session) -> dict:
    """Convert a User model instance to a response dictionary"""
    # Get user roles
    user_roles = db.query(UserRole).filter(
        UserRole.user_id == user.user_id,
        UserRole.active == True
    ).all()
    
    roles = []
    for user_role in user_roles:
        role = db.query(Role).filter(Role.role_id == user_role.role_id).first()
        if role:
            roles.append(role.role_name)
    
    return {
        "user_id": user.user_id,
        "uuid": user.uuid,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "profile_image": user.profile_image,
        "preferred_lang": user.preferred_lang,
        "timezone_id": user.timezone_id,
        "phone_number": user.phone_number,
        "address": user.address,
        "bio": user.bio,
        "status": user.status,
        "is_2fa_enabled": user.is_2fa_enabled,
        "activated": user.activated,
        "roles": roles,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None
    }

def admin_required(func):
    @wraps(func)
    async def wrapper(*args, current_user: User = Depends(get_current_user), db: Session = Depends(get_db), **kwargs):
        # Check if user has admin role
        admin_role = db.query(Role).filter(Role.role_name == "admin").first()
        if not admin_role:
            raise HTTPException(status_code=403, detail="Admin role not found")
        user_role = db.query(UserRole).filter(
            UserRole.user_id == current_user.user_id,
            UserRole.role_id == admin_role.role_id,
            UserRole.active == True
        ).first()
        if not user_role:
            raise HTTPException(status_code=403, detail="Admin access required")
        return await func(*args, current_user=current_user, db=db, **kwargs)
    return wrapper
