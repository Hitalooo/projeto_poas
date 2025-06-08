from typing import Optional
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import timedelta

from models import User, UserInDB, UserCreate
from auth import verify_password, get_password_hash, create_access_token, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

from models import User, UserInDB, UserCreate
from auth import (
    verify_password, 
    get_password_hash, 
    create_access_token, 
    SECRET_KEY, 
    ALGORITHM, 
    ACCESS_TOKEN_EXPIRE_MINUTES
)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# "Banco de dados" em memória
fake_db = {}

def get_user(username: str) -> Optional[UserInDB]:
    user = fake_db.get(username)
    if user:
        return UserInDB(**user)
    return None

def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

@app.post("/register", response_model=User)
def register(user: UserCreate):
    if user.username in fake_db:
        raise HTTPException(status_code=400, detail="Nome de usuário já cadastrado")
    hashed_password = get_password_hash(user.password)
    db_user = UserInDB(**user.dict(exclude={"password"}), hashed_password=hashed_password)
    fake_db[user.username] = db_user.dict()
    return db_user

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Nome de usuário ou senha incorretos")
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
def read_users_me(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user