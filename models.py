from pydantic import BaseModel
from typing import Optional

# Modelo de usuário para resposta
class User(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None

# Modelo usado para cadastro
class UserCreate(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    password: str

# Modelo que simula usuário no "banco"
class UserInDB(User):
    hashed_password: str