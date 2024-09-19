import os
from fastapi import FastAPI, HTTPException, Depends, Response, Request
from pydantic import BaseModel, EmailStr
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional

load_dotenv()

# Load MongoDB URI from environment variable
MONGO_DB_URI = os.getenv("MONGO_DB_URI")
SECRET_KEY = os.getenv("SECRET_KEY", "secret")  # Change this to a strong secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# MongoDB helper
client = AsyncIOMotorClient(MONGO_DB_URI)
db = client['fastapi_db']
users_collection = db['users']

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic models
class UserIn(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str
    image_url: Optional[str] = None

class UserOut(BaseModel):
    id: str
    first_name: str
    last_name: str
    email: EmailStr
    image_url: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserInDB(UserOut):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str

# Utility functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_user_by_email(email: str) -> Optional[UserInDB]:
    user = await users_collection.find_one({"email": email})
    if user:
        return UserInDB(id=str(user["_id"]), first_name=user["first_name"], last_name=user["last_name"], email=user["email"], hashed_password=user["password"], image_url=user.get("image_url"))
    return None

# FastAPI instance
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace "*" with the actual frontend URL (e.g., ["http://localhost:3000"])
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

# Set a cookie with the access token
def set_access_token_cookie(response: Response, access_token: str):
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,  # More secure, HTTP-only cookies cannot be accessed by JavaScript
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Cookie expires in 30 minutes
        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",  # Adjust SameSite attribute based on your needs
    )

# User registration
@app.post("/register", response_model=UserOut)
async def register_user(user: UserIn, response: Response):
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(user.password)
    new_user = {
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "password": hashed_password,
        "image_url": user.image_url
    }
    result = await users_collection.insert_one(new_user)

    # Generate access token and set in cookie
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"email": user.email}, expires_delta=access_token_expires)
    set_access_token_cookie(response, access_token)

    return UserOut(id=str(result.inserted_id), first_name=user.first_name, last_name=user.last_name, email=user.email, image_url=user.image_url)

# User login
@app.post("/login", response_model=UserOut)
async def login_user(login_data: UserLogin, response: Response):
    user = await get_user_by_email(login_data.email)
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    # Generate access token and set in cookie
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"email": user.email}, expires_delta=access_token_expires)
    set_access_token_cookie(response, access_token)

    return user

# Get user info using the access token from cookies
@app.get("/users/me", response_model=UserOut)
async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="No access token found")
    
    try:
        token = token.replace("Bearer ", "")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("email")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await get_user_by_email(email=email)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
