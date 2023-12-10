from typing import Annotated
from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer
from pymongo import MongoClient
from bson.objectid import ObjectId
from passlib.hash import bcrypt
from datetime import datetime, timedelta
import jwt
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
from fastapi import Response

# preparing fastAPI and collections"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)
security = HTTPBasic()
client = MongoClient('mongodb://localhost:27017/')
db = client['ciphernotes']
users = db['users']
notes = db["notes"]

# jwt token params (key ,algorithm and expiration)
JWT_SECRET = 'ciphernotes'
JWT_EXPIRATION_TIME_MINUTES = 500
def generate_access_token(user_id: str,password: str):
    payload = {'exp': datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_TIME_MINUTES), 'iat': datetime.utcnow(),
               'sub': user_id, 'pass': password}
    access_token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return access_token
@app.post('/api/v1/register')
async def register(email: str = Body(...),username : str = Body(...) ,password: str = Body(...)):
    # Check if the username already exists
    if users.count_documents({'email': email}) > 0:
        raise HTTPException(status_code=400, detail='Email already exists')

    # Hash the password and store the user in the database
    hashed_password = bcrypt.hash(password)
    user = {"email": email, 'username': username, 'password': hashed_password}
    result = users.insert_one(user)

    # Generate and return the access token
    user_id = str(result.inserted_id)
    access_token = generate_access_token(user_id,password)
    return {'access_token':access_token,'token_type':'bearer'}


@app.post('/api/v1/login')
async def login(email: str = Body(...), password: str = Body(...)):
    # Find the user in the database
    user = users.find_one({'email': email})

    # Check if the user exists and the password is correct
    if user and bcrypt.verify(password, user['password']):
        # Generate and return the access token
        user_id = str(user['_id'])
        access_token = generate_access_token(user_id,password)
        return {'access_token':access_token, 'token_type':'bearer'}
    else:
        raise HTTPException(status_code=401, detail='Invalid email or password')

@app.get('/api/v1/account')
async def account(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get('sub')
        password = bcrypt.hash(payload.get('pass'))
        user = users.find_one({'_id': ObjectId(user_id)})
        notes_list = notes.find({'user_id':ObjectId(user_id)},{'user_id':False})
        if not notes_list :
            return {"result" : "empty"}
        for item in notes_list:
            item["_id"] = str(item['id'])
        if password == user["password"]:
            raise HTTPException(status_code=401, detail='Invalid token')
        if user is None:
            raise HTTPException(status_code=404, detail='User not found')
        result = {'username': user['username'],'notes':notes_list}
        return result
    except:
        raise HTTPException(status_code=401, detail='Invalid token')
@app.post('/api/v1/create_note')
async def create_note(token: Annotated[str, Depends(oauth2_scheme)],note : str = Body(...)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get('sub')
        password = bcrypt.hash(payload.get('pass'))
        user = users.find_one({'_id': ObjectId(user_id)})
        if password == user["password"]:
            raise HTTPException(status_code=401, detail='Invalid token')
        if user is None:
            raise HTTPException(status_code=404, detail='User not found')
        notes.insert_one({"content":note,"user_id":user_id})
        return {"success" : "note created successfully"}
    except:
        raise HTTPException(status_code=401, detail='Invalid token')
@app.post("/api/v1/delete_note")
async def delete_note(token: Annotated[str, Depends(oauth2_scheme)],id : str = Body(...)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get('sub')
        password = bcrypt.hash(payload.get('pass'))
        user = users.find_one({'_id': ObjectId(user_id)})
        if password == user["password"]:
            raise HTTPException(status_code=401, detail='Invalid token')
        if user is None:
            raise HTTPException(status_code=404, detail='User not found')
        if notes.find_one({"_id" : ObjectId(id)}):
            raise HTTPException(status_code=404, detail='note not found')
        notes.delete_one({"_id" : ObjectId(id)})
        return {"success": "note deleted successfully"}
    except:
        raise HTTPException(status_code=401, detail='Invalid token')
@app.post('/api/v1/update_note')
async def update_note(token: Annotated[str, Depends(oauth2_scheme)],note : str = Body(...),id : str = Body(...)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get('sub')
        password = bcrypt.hash(payload.get('pass'))
        user = users.find_one({'_id': ObjectId(user_id)})
        if password == user["password"]:
            raise HTTPException(status_code=401, detail='Invalid token')
        if user is None:
            raise HTTPException(status_code=404, detail='User not found')
        if notes.find_one({"_id" : ObjectId(id)}):
            raise HTTPException(status_code=404, detail='note not found')
        notes.update_one({"_id" : ObjectId(id)},
                         {"$set":{
                             "content" : note
                         }})
        return {"success" : "note updated successfully"}
    except:
        raise HTTPException(status_code=401, detail='Invalid token')






