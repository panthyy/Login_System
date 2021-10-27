from fastapi.param_functions import Depends
from sqlalchemy.orm import Session
import models

def delete_user(db : Session, user :models.User):
    db.delete(user)
    db.commit()
    
def create_user():
    pass
