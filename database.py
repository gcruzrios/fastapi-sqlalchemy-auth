from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

url = "postgresql+psycopg2://postgres:Grvn240675$$@localhost:5432/authpg"
engine = create_engine(url, echo=True)

Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)
