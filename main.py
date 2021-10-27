from typing import Optional
import html
from fastapi import FastAPI
from dotenv import load_dotenv
from fastapi.exceptions import HTTPException
from fastapi.param_functions import Depends
from pydantic.fields import Field
from pydantic.networks import EmailStr
from sqlalchemy.orm.session import Session
from starlette.requests import Request
from starlette.responses import JSONResponse
from models import User
from routers import auth
from pydantic import BaseModel
from routers.auth import Session_Auth, get_db

load_dotenv()

app = FastAPI()

app.include_router(auth.router)

class Search_Data(BaseModel):
    username: str
    limit: Optional[int] = Field(
        default=10
    )
class Search_Response(BaseModel):
    first_name : str
    last_name : str
    email : EmailStr

@app.post("/user/search",response_model=Search_Response)
async def search_users(request : Request,SearchData: Search_Data, db: Session = Depends(get_db)):
    users = db.query(User).filter(User.username.contains(SearchData.username)).limit(SearchData.limit)
    if users is None:
        raise HTTPException(status_code=404, detail="none found") 
    output = []
    for user in users:
        output.append(user.getjson())
    return JSONResponse(content=output, status_code=200)