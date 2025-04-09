from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
# auth.py
#from .database import get_user_by_email  # на вскякий случай чтобы норм работали импорты с точками
#from .models import User
from sqlalchemy.orm import Session

from database import SessionLocal
from models import User

auth_router = APIRouter()

pwd_ctx = CryptContext(schemes=["bcrypt"])
SECRET = "kLq9!pR4$zX2@vN7"
ALGO = "HS256"
token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjNAZ21haWwuY29tIiwiZXhwIjoxNzUwMTkxMTQyfQ.nuoG472rgq5mLS9g2zvdgdSEijT-tvAu0UblJkMBYXo'
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")
print(oauth2_scheme == token)

class UserCreate(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    token: str


def hash_pwd(p):
    return pwd_ctx.hash(p)


def verify_pwd(p, h):
    return pwd_ctx.verify(p, h)


def create_jwt(d):
    exp = datetime.utcnow() + timedelta(days=69)
    return jwt.encode({**d, "exp": exp}, SECRET, algorithm=ALGO)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    print("Token received:", token)  # Отладочный вывод
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGO])
        print("Payload decoded:", payload)  # Проверьте payload
        email = payload.get("sub")
        if not email:
            raise HTTPException(401, "Invalid token")
    except JWTError as e:
        print("JWT Error:", str(e))
        raise HTTPException(401, "Invalid token")
    print("Searching user with email:", email)
    user = db.query(User).filter(User.email == email).first()
    print("User found:", user)  # Должен быть объект User
    if not user:
        raise HTTPException(401, "User not found")
    return user


# Добавьте новую модель для ответа /users/me/
class UserMeResponse(BaseModel):
    id: int
    email: str

@auth_router.get("/users/me/", response_model=UserMeResponse)
async def read_users_me(
    current_user: User = Depends(get_current_user)
):
    return current_user  # Возвращаем объект User напрямую

@auth_router.post("/sign-up/", response_model=UserResponse)
def signup(data: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise HTTPException(400, "Email exists")

    hashed = hash_pwd(data.password)
    new_user = User(email=data.email, password_hash=hashed)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_jwt({"sub": new_user.email})
    return {"id": new_user.id, "email": new_user.email, "token": token}


@auth_router.post("/login/", response_model=UserResponse)
def login(data: UserCreate, db: Session = Depends(get_db)):
    u = db.query(User).filter(User.email == data.email).first()
    if not u or not verify_pwd(data.password, u.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    tkn = create_jwt({"sub": u.email})
    return {"id": u.id, "email": u.email, "token": tkn}