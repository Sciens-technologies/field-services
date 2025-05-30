import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import text
import jwt
import os
from dotenv import load_dotenv

from db.models import User, UserRole, Role, Permission, RolePermission
from db.database import get_db

# Load environment variables
load_dotenv()

# JWT settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRES_IN = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES_IN", "86400"))  # 24 hours
JWT_REFRESH_TOKEN_EXPIRES_IN = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES_IN", "2592000"))  # 30 days

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/users/token")
security = HTTPBearer(auto_error=False)

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email.ilike(email.strip())).first()

def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()

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
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub"))
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def get_current_user_optional(
    request: Request, 
    db: Session = Depends(get_db)
) -> Optional[User]:
    try:
        return get_current_user(request, db)
    except Exception:
        return None

def has_role(allowed_roles):
    async def role_checker(current_user: User = Depends(get_current_user)):
        role_name = None
        if hasattr(current_user, 'role') and current_user.role:
            role_name = current_user.role.name
        elif hasattr(current_user, 'role_id'):
            role_id_to_name = {
                1: UserRole.SUPER_ADMIN.value,
                2: UserRole.MANAGER.value,
                3: UserRole.AGENT.value
            }
            role_name = role_id_to_name.get(current_user.role_id)
        if not role_name or role_name not in [role.value for role in allowed_roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to access this resource",
            )
        return current_user
    return role_checker

def get_user_from_token(
    token: str,
    db: Session = Depends(get_db)
) -> User:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is required",
        )
    try:
        payload = decode_jwt_token(token)
        user_id = int(payload.get("sub"))
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except Exception as e:
        print(f"Error in get_user_from_token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate token: {str(e)}",
        )

def has_permission(required_permission):
    async def permission_checker(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        result = db.execute(
            text("""
            SELECT EXISTS (
                SELECT 1 FROM users u
                JOIN roles r ON u.role_id = r.id
                JOIN role_permissions rp ON r.id = rp.role_id
                JOIN permissions p ON rp.permission_id = p.id
                WHERE u.id = :user_id AND p.name = :permission_name
            )
            """),
            {"user_id": current_user.id, "permission_name": required_permission}
        ).scalar()
        if not result:
            result = db.execute(
                text("""
                SELECT EXISTS (
                    SELECT 1 FROM user_permissions up
                    JOIN permissions p ON up.permission_id = p.id
                    WHERE up.user_id = :user_id AND p.name = :permission_name
                )
                """),
                {"user_id": current_user.id, "permission_name": required_permission}
            ).scalar()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"You don't have the required permission: {required_permission}",
            )
        return current_user
    return permission_checker

def generate_secure_password(length=12):
    import secrets, string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def create_jwt_token(user_id: int, email: str, role_id: int, expires_in: int) -> str:
    payload = {
        "sub": str(user_id),
        "email": email,
        "role_id": role_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def ensure_datetime(dt_value):
    if dt_value is None:
        return datetime.datetime.utcnow()
    if isinstance(dt_value, str):
        try:
            if 'T' in dt_value:
                if dt_value.endswith('Z'):
                    dt_value = dt_value[:-1] + '+00:00'
                return datetime.datetime.fromisoformat(dt_value)
            else:
                return datetime.datetime.strptime(dt_value, "%Y-%m-%d")
        except ValueError:
            print(f"Could not parse datetime: {dt_value}")
            return datetime.datetime.utcnow()
    return dt_value

def user_to_response(user, db=None):
    role_name = None
    if hasattr(user, 'role') and user.role:
        if hasattr(user.role, 'name'):
            role_name = user.role.name
        else:
            role_name = str(user.role)
    elif hasattr(user, 'role_id') and user.role_id and db:
        role = db.query(Role).filter(Role.id == user.role_id).first()
        role_name = role.name if role else None
    return {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": role_name,
        "status": user.status,
        "phone_number": getattr(user, 'phone_number', None),
        "created_at": ensure_datetime(user.created_at),
        "updated_at": ensure_datetime(user.updated_at)
    }
def role_required(allowed_roles: list[str]):
    def wrapper(
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> User:
        role = db.query(Role).filter(Role.id == current_user.role_id).first()
        if not role or role.name.lower() not in [r.lower() for r in allowed_roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to perform this action"
            )
        return current_user
    return wrapper
