import schemas
import models
import jwt
from datetime import datetime 
from models import User,TokenTable
from database import Base, engine, SessionLocal
from sqlalchemy.orm import Session
from fastapi import FastAPI, Depends, HTTPException,status
from fastapi.security import OAuth2PasswordBearer
from auth_bearer import JWTBearer
from functools import wraps
from utils import create_access_token,create_refresh_token,verify_password,get_hashed_password

from decouple import config
from routes.user import routerUser
import os
import uvicorn

app = FastAPI(
    title="Auth FastAPI",
    description="Api AUTH User",
    version="0.0.1",
)

app.include_router(routerUser)

@app.get('/', tags=["Inicio"])
def read_root():
    return {'message':'Hello world'}


# ALGORITHM = config("ALGORITHM")
# JWT_SECRET_KEY = config("JWT_SECRET_KEY")   # should be kept secret
# JWT_REFRESH_SECRET_KEY = config("JWT_REFRESH_SECRET_KEY")



if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000)) 
    uvicorn.run("main:app", host="0.0.0.0", port=port) 

