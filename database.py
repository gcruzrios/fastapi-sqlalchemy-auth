import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

#SQLite

sqliteName = 'users.sqlite'
base_dir = os.path.dirname(os.path.realpath(__file__))
databaseUrl = f'sqlite:///{os.path.join(base_dir, sqliteName)}'
engine = create_engine(databaseUrl, echo =True)

#Postgres
#url = "postgresql+psycopg2://postgres:Grvn240675$$@localhost:5432/authpg"
#engine = create_engine(url, echo=True)

Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)
