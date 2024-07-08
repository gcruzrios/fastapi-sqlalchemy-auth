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
from auth_bearer import JWTBearer
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


ALGORITHM = config("ALGORITHM")
JWT_SECRET_KEY = config("JWT_SECRET_KEY")   # should be kept secret
JWT_REFRESH_SECRET_KEY = config("JWT_REFRESH_SECRET_KEY")

def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
    
        payload = jwt.decode(kwargs['dependencies'], JWT_SECRET_KEY, ALGORITHM)
        user_id = payload['sub']
        data= kwargs['session'].query(models.TokenTable).filter_by(user_id=user_id,access_toke=kwargs['dependencies'],status=True).first()
        if data:
            return func(kwargs['dependencies'],kwargs['session'])
        
        else:
            return {'msg': "Token blocked"}
        
    return wrapper

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000)) 
    uvicorn.run("main:app", host="0.0.0.0", port=port) 

