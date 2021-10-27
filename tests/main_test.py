from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import create_database, drop_database

from main import app
from routers.auth import get_db
from database import Base

@pytest.fixture()
def test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def override_get_db():
    """" Override """
    try:
        db = Session(autocommit=False, autoflush=False, bind=engine)
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app=app)

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db?check_same_thread=False"


engine = create_engine(SQLALCHEMY_DATABASE_URL, pool_pre_ping=True)

def test_search(test_db):
    response = client.post(
        "/register",
        headers={"Content-Type" : "application/json"},
        json={
            "username": "testuser",
            "first_name": "albert",
            "last_name":"petersson",
            "email" : "emailhere@hotmail.com",
            "password": "testpassword"
        }
    )
    assert response.status_code == 200
    
    response = client.post("/user/search",
    json={
        "username" : "testuser"
    }
    )
    assert response.status_code == 200
    assert response.json()[0]["first_name"] == "albert"
    assert response.json()[0]["last_name"] == "petersson"
    assert response.json()[0]["username"] == "testuser"

def test_register(test_db): 
    response = client.post(
        "/register",
        headers={"Content-Type" : "application/json"},
        json={
            "username": "testuser",
            "first_name": "albert",
            "last_name":"petersson",
            "email" : "emailhere@hotmail.com",
            "password": "testpassword"
        }
    )
    assert response.status_code == 200
def test_login(test_db):

    response = client.post(
        "/register",
        headers={"Content-Type" : "application/json"},
        json={
            "username": "testuser",
            "first_name": "albert",
            "last_name":"petersson",
            "email" : "emailhere@hotmail.com",
            "password": "testpassword"
        }
    )
    assert response.status_code == 200

    response = client.post(
        "/login",
        headers={"Content-Type" : "application/json"},
        json={
            "email" :"emailhere@hotmail.com",
            "password" : "testpassword"
        }
    )
    assert response.status_code == 200