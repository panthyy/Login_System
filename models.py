from datetime import datetime
from sqlalchemy import Boolean, Column, Integer, String,DateTime
from database import Base

class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    email_confirmed = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    Created = Column(DateTime,default=datetime.now)

    def getjson(self):
        return {
            "first_name" : self.first_name,
            "last_name" : self.last_name,
            "username": self.username,
            "email" : self.email
        }
