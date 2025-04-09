from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from database import SessionLocal
from models import User

auth_router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "YourSecretKey123"
ALGORITHM = "HS256"


class UserCreate(BaseModel):
    email: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


def verify_password(plain_pass, hashed_pass):
    return pwd_context.verify(plain_pass, hashed_pass)


def get_user(email: str):
    db = SessionLocal()
    return db.query(User).filter(User.email == email).first()


def create_user(email: str, password: str):
    db = SessionLocal()
    user = User(email=email, password_hash=pwd_context.hash(password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@auth_router.post("/register", response_model=Token)
def register(user: UserCreate):
    existing_user = get_user(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    new_user = create_user(user.email, user.password)
    token = create_token(data={"sub": new_user.email})
    return {"access_token": token, "token_type": "bearer"}


@auth_router.post("/login", response_model=Token)
def login(user: UserCreate):
    db_user = get_user(user.email)
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    token = create_token(data={"sub": db_user.email})
    return {"access_token": token, "token_type": "bearer"}