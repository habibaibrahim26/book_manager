from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from pymongo import MongoClient
from pydantic import BaseModel
import os
from bson.objectid import ObjectId
from dotenv import load_dotenv
from typing import List, Optional
import redis
import json
import time
import functools

# LOAD ENV VARS
load_dotenv()

# JWT CONFIG
secretKey = "secret"
algo = "HS256"
exp_time = 30
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="token")

# INIT MONGO CLIENT
client = MongoClient(os.getenv("MONGO_URI"))
db = client['library']
collection = db['books']
user_collection = db['Users']

# INIT REDIS CLIENT
redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST"),
    port=int(os.getenv("REDIS_PORT")),
    db=int(os.getenv("REDIS_DB"))
)

app = FastAPI()


@app.on_event("shutdown")
def shutdown_db_client():
    client.close()  # Close the MongoDB client when the app shuts down
    redis_client.close()


# PYDANTIC MODELS
class Book(BaseModel):
    name: str


class BookResponse(Book):
    id: str
    status: bool


class User(BaseModel):
    username: str
    password: str


class UserInDB(User):
    hashed_pwd: Optional[str] = None


def create_token(data: dict, exp_delta: Optional[timedelta]):
    to_encode = data.copy()

    expire = datetime.now() + exp_delta

    to_encode.update({"exp": expire})
    encodedJWT = jwt.encode(to_encode, secretKey, algorithm=algo)
    return encodedJWT


def get_user(username: str):
    user = user_collection.find_one({"username": username})
    if user:
        return user
    return None


def pwdVerify(plain_pwd, hashed_pwd):
    return pwd.verify(plain_pwd, hashed_pwd)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if user is None:
        return None

    if not pwdVerify(password, user["hashed_pwd"]):
        return None
    return user


@app.post("/token")
def login_get_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="username or password incorrect",

        )
    access_token_expires = timedelta(minutes=exp_time)
    access_token = create_token(data={"sub": user["username"]}, exp_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/register", status_code=201)
def register_user(user: User):
    existing_user = get_user(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Error username already exists")

    try:
        hashed_password = pwd.hash(user.password)
    except Exception as e:
        print(f"Error hashing password: {e}")
        raise HTTPException(status_code=500, detail="Error hashing password")

    new_user = {
        "username": user.username,
        "hashed_pwd": hashed_password
    }

    try:
        result = user_collection.insert_one(new_user)
        return {"Success"}
    except Exception as e:
        print(f"Error inserting user into the database: {e}")
        raise HTTPException(status_code=500, detail="Error inserting user into the database")


def get_current_user(token: str = Depends(oauth2)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="could not validate credintials",

    )
    try:
        data = jwt.decode(token, secretKey, algorithms=algo)
        username: str = data.get("sub")
        if username is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = get_user(username)
    if user is None:
        raise credentials_exception

    return user


def get_books_from_mongo():
    books = list(collection.find())
    for book in books:
        book['id'] = str(book['_id'])
        del book['_id']
    return books


def time_exec(func):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        result = await func(*args, **kwargs)
        end_time = time.time()
        time_taken = end_time - start_time

        # If the result is a list of books, wrap it in a dict with time_taken
        return JSONResponse(content={"data": result, "time_taken": time_taken})

    return wrapper


@app.get('/books', response_model=List[BookResponse])
@time_exec
async def get_books(current_user: User = Depends(get_current_user)):
    cached_books = redis_client.get('books_cache')

    if cached_books:
        books = json.loads(cached_books)

    else:
        books = get_books_from_mongo()
        redis_client.setex('books_cache', timedelta(minutes=15), json.dumps(books))

    return books


@app.get('/books/{book_id}', response_model=BookResponse)
@time_exec
async def get_book(book_id: str, current_user: User = Depends(get_current_user)):
    cached_book = redis_client.get(f'book_{book_id}')
    if cached_book:
        book = json.loads(cached_book)

    else:
        book = collection.find_one({'_id': ObjectId(book_id)})
        if book is None:
             raise HTTPException(status_code=404, detail="Book not found")
        book['_id'] = str(book['_id'])
        redis_client.setex(f'book_{book_id}', timedelta(minutes=15), json.dumps(book))

    return book


@app.post('/books/add', response_model=BookResponse, status_code=201)
@time_exec
async def add_books(book: Book, current_user: User = Depends(get_current_user)):
    # if not book.name:
    #     raise HTTPException(status_code=400, detail="Book name is required")

    new_book = {
        'name': book.name,
        'status': True
    }

    op = collection.insert_one(new_book)

    new_book['id'] = str(op.inserted_id)

    redis_client.delete('books_cache')

    return new_book


@app.delete('/books/delete/{book_id}', status_code=200)
@time_exec
async def delete_book(book_id: str, current_user: User = Depends(get_current_user)):
    # if not book_id:
    #     raise HTTPException(status_code=400, detail="Book ID is required")

    op = collection.delete_one({'_id': ObjectId(book_id)})

    if op.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Book not found")

    redis_client.delete('books_cache')
    redis_client.delete(f'book_{book_id}')

    return {"message": "Book deleted successfully"}


@app.patch('/books/status/{book_id}')
@time_exec
async def update_book(book_id: str, current_user: User = Depends(get_current_user)):
    # if not book_id:
    #     raise HTTPException(status_code=400, detail="Book ID is required")

    op = collection.update_one({'_id': ObjectId(book_id)}, {"$set": {"status": False}})

    redis_client.delete('books_cache')
    redis_client.delete(f'book_{book_id}')

    if op.matched_count == 0:
        raise HTTPException(status_code=404, detail="Book not found")

    if op.modified_count > 0:
        return {"message": "Book's status successfully updated"}
    else:
        return {"message": "Book's status is already False"}








