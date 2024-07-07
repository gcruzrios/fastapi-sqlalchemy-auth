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

from routes.user import routerUser



app = FastAPI(
    title="Auth FastAPI",
    description="Api en primeros pasos",
    version="0.0.1",
)

app.include_router(routerUser)

@app.get('/', tags=["Inicio"])
def read_root():
    return {'message':'Hello world'}




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
