import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from passlib.context import CryptContext
from jose import jwt

import motor.motor_asyncio

# =========================================
# FastAPI App
# =========================================

app = FastAPI(title="Washify Auth Service")

# =========================================
# CORS
# =========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================
# MongoDB
# =========================================

MONGO_URL = os.getenv("MONGO_URL")

if not MONGO_URL:
    raise Exception("MONGO_URL environment variable not found")

client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)

db = client.washify_auth

users_collection = db.get_collection("users")

# =========================================
# JWT
# =========================================

JWT_SECRET = os.getenv("JWT_SECRET", "washifysecret")

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# =========================================
# Models
# =========================================

class UserCreate(BaseModel):
    email: EmailStr
    phone_number: str
    password: str
    role: str = "user"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

# =========================================
# Helper Functions
# =========================================

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(
        plain_password,
        hashed_password
    )

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
):
    to_encode = data.copy()

    expire = datetime.utcnow() + (
        expires_delta
        if expires_delta
        else timedelta(minutes=15)
    )

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode,
        JWT_SECRET,
        algorithm=ALGORITHM
    )

    return encoded_jwt

# =========================================
# Routes
# =========================================

@app.get("/")
def root():
    return {
        "message": "Washify Auth Service Running"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }

@app.post("/register")
async def register(user: UserCreate):

    existing_user = await users_collection.find_one(
        {"email": user.email}
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    user_dict = user.dict()

    user_dict["password"] = get_password_hash(
        user_dict["password"]
    )

    user_dict["is_verified"] = True

    result = await users_collection.insert_one(
        user_dict
    )

    return {
        "message": "User registered successfully"
    }

@app.post("/login")
async def login(user: UserLogin):

    db_user = await users_collection.find_one(
        {"email": user.email}
    )

    if not db_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not verify_password(
        user.password,
        db_user["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    access_token = create_access_token(
        data={
            "sub": db_user["email"],
            "role": db_user["role"]
        },
        expires_delta=timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
