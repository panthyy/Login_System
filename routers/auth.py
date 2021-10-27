from datetime import datetime
from logging import currentframe
from fastapi import requests, responses
from fastapi.param_functions import Form
import redis
import secrets
from sqlalchemy.orm.session import Session
from sqlalchemy.sql.expression import false
from fastapi.templating import Jinja2Templates
from fastapi import APIRouter,Response,Depends , HTTPException, Request
from starlette.responses import JSONResponse
from database import SessionLocal
from pydantic import BaseModel,EmailStr
from fastapi_mail import FastMail, MessageSchema,ConnectionConfig
from fastapi.responses import RedirectResponse
import os
import crud
import models
import bcrypt
from sqlalchemy.sql import exists
from fastapi import BackgroundTasks
from models import  User

from dotenv import load_dotenv

conf = ConnectionConfig(
    MAIL_USERNAME = os.environ.get("GMAIL_USERNAME"),
    MAIL_PASSWORD = os.environ.get("GMAIL_PASSWORD"),
    MAIL_FROM = os.environ.get("GMAIL_USERNAME"),
    MAIL_PORT = 587,
    MAIL_SERVER = "smtp.gmail.com",
    MAIL_TLS = True,
    MAIL_SSL = False,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)

templates = Jinja2Templates(directory="templates")


class InvalidSessionHandler(HTTPException):
    pass
    
def InvalidSessionRedirect(request,exc):
    return RedirectResponse("/")

r = redis.Redis(host=os.environ.get("redis_host"), port=6379)

load_dotenv()

class Authdata(BaseModel):
    email: EmailStr
    password: str

class RegisterData(BaseModel):
    username : str
    email: EmailStr
    password: str
    first_name : str
    last_name : str

class TokenData(BaseModel):
    Token : str
class ForgotData(BaseModel):
    email: EmailStr

router = APIRouter(
    responses={404: {"description": "Not found"}},
    tags=["account"]
)

class UserAuth(BaseModel):
    email: EmailStr
    password: str

async def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def email_exists(email : str,db : Session ):
    return db.query(exists().where(models.User.email == email)).scalar()
    

def Auth_User(db:Session,email:str,password:str):
    user =  db.query(models.User).filter(models.User.email == email).first()

    if user is not None and bcrypt.checkpw(password.encode("utf8"),user.password.encode('utf8')):
        return user
    else:
        return None

async def Session_Auth(request : Request): 
    if "Session" not in request.cookies:
        raise HTTPException(status_code=401, detail="missing session cookie")  
    
    session_id = request.cookies["Session"]

    user_id = r.hget(session_id,"user_id")

    if user_id is None:
        raise InvalidSessionHandler(status_code=401)
    
    r.expire(name=session_id,time=3600)

    return user_id.decode("ascii")

async def Validate_CSRF(request:Request):
    if "X-CSRF-TOKEN" not in request.headers:
        raise HTTPException(status_code=403, detail="missing CSRF token")

    if "Session" not in request.cookies:
        raise HTTPException(status_code=401, detail="missing session cookie")  
    
    session_id = request.cookies["Session"]
    
    if not secrets.compare_digest(str(request.headers["X-CSRF-TOKEN"]), str(r.hget(session_id,"csrf_token").decode("ascii"))):
        raise HTTPException(status_code=401, detail="invalid csrf token")

@router.post('/logout')
async def logut( response:Response,request:Request, user_id : int = Depends(Session_Auth)): 
    r.delete(request.cookies["Session"])
    response.delete_cookie(key="Session")
    response.delete_cookie(key="CSRF-Token")

    return RedirectResponse(status_code=302, url="/")

async def Send_Email_Confirm(request: Request,userid: int,user_email : str,db : Session):

    CurrentUser = db.query(User).filter(User.id == userid).first()

    if(not CurrentUser.email_confirmed ):

        token = secrets.token_urlsafe(16)

        ##unsafe probably 
        r.hmset(token, {"user_id": CurrentUser.id})
        r.expire(token,600) ## 10 minute expire

        message = MessageSchema(
            subject="Login System Email Confirmation",
            recipients=[CurrentUser.email],  # List of recipients, as many as you can pass 
            body="<html><a href='" +request.url.hostname+"/confirm/"+ token+"' > reset password </a></html>",
            subtype="html"
            )
        fm = FastMail(conf)
        await fm.send_message(message=message)

async def Send_password_reset(request: Request,email : str,db : Session):
        
        CurrentUser = db.query(User).filter(User.email == email).first()
        resettoken = secrets.token_urlsafe(16)

        ##unsafe probably 
        r.hmset(resettoken, {"user_id": CurrentUser.id})
        r.expire(resettoken,300) ## 5 minute expire

        message = MessageSchema(
            subject="Login System password reset",
            recipients=[email],  
            body=str('<html><a href="' +request.url.hostname+'/reset/'+ resettoken+'" > reset password </a></html>'),
            subtype="html"
            )
        fm = FastMail(conf)
        await fm.send_message(message=message)

@router.delete("/account")
async def Delete_Account(request: Request, user_auth_data : UserAuth,db : Session = Depends(get_db)):

    current_user = Auth_User(db=db, email=user_auth_data.email,password=user_auth_data.password)

    if current_user is None:
        raise HTTPException(status_code=401, detail="bad password or email")  
    
    crud.delete_user(db=db,user= current_user)
    await logut(response=Response(status_code=200),request=request)
    return JSONResponse(status_code=200)

@router.post('/register')
async def register(request: Request,background_tasks : BackgroundTasks,register_data : RegisterData, db : Session = Depends(get_db)):

    if email_exists(email=register_data.email,db=db):
        raise HTTPException(status_code=400, detail="email already exists") 
    if db.query(User).filter(User.username == register_data.username).first() is not None:
        raise HTTPException(status_code=400, detail="username already exists") 
    ## check password security
    user = User (
        username = register_data.username,
        first_name= register_data.first_name,
        last_name = register_data.last_name,
        email = register_data.email,
        password = bcrypt.hashpw(register_data.password.encode("utf8"), bcrypt.gensalt())
    )

    db.add(user)
    db.commit()
    
    background_tasks.add_task(Send_Email_Confirm,userid = user.id, user_email = register_data.email, db=db,request=request)
    return JSONResponse(status_code=200)

@router.get("/confirm/{token}")
async def confirm_Token(token : str, db : Session = Depends(get_db)):
    ##probably unsafe
    userid = r.hgetall(token).get(b'user_id').decode("UTF-8")

    if userid is not None:
        db.query(User).filter(User.id == userid).first().email_confirmed = True

    db.commit()


@router.post("/reset/{reset_token}")
async def reset_password(new_password : str,reset_token : str, db : Session = Depends(get_db)):
 
    if  r.exists(reset_token):
        userdict = r.hgetall(reset_token)
        user_id = userdict.get(b'user_id').decode("UTF-8")
        CurrentUser = db.query(User).filter(User.id == user_id).first()

        if CurrentUser is not None:
            CurrentUser.password = bcrypt.hashpw(new_password.encode("utf8"), bcrypt.gensalt())
            db.commit()
            r.delete(reset_token)
            return JSONResponse(status_code=200)
    raise HTTPException(status_code=400, detail="expired")

@router.post("/forgotpassword")
async def forgot_password(request : Request,forgotdata: ForgotData,background_tasks : BackgroundTasks,db : Session = Depends(get_db)):
    if email_exists(forgotdata.email, db=db):
        background_tasks.add_task(Send_password_reset,email= forgotdata.email,db=db,request=request)
        return JSONResponse(status_code=200, content={"detail": "sending reset link to "+ forgotdata.email})
    raise HTTPException(status_code=404, detail="email does not exist")

@router.post('/login')
async def Login(response : JSONResponse,request: Request, user_auth_data : UserAuth,session : Session = Depends(get_db)):
    
    current_user = Auth_User(db=session, email=user_auth_data.email,password=user_auth_data.password)

    if current_user is None:
        raise HTTPException(status_code=401, detail="bad password or email")  
    
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(key="Session", value=session_id,httponly=True)
    response.set_cookie(key="CSRF-Token", value=csrf_token)
    r.hset(name=session_id, mapping={"user_id" : current_user.id, "csrf_token": csrf_token})
    #r.hset(name=session_id, mapping={"user_id" : current_user.id,"time": datetime.now()})
    r.expire(name=session_id,time=3600)

    response.status_code = 200
    return response
