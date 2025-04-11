from fastapi import FastAPI, HTTPException, Request, Depends, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
import uvicorn
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

# Simple token configuration
SECRET_KEY = "YOUR_SECRET_KEY_HERE"  # Replace with a proper secret key in production
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Load and prepare the data
data = pd.read_excel(r'housingsheet.xlsx', engine='openpyxl')
data.columns = [col.strip().lower() for col in data.columns]

# Define features and target
X = data[['area', 'bathrooms', 'bedrooms', 'guestroom', 'basement', 'parking']]
y = data['price']

# Convert categorical columns to numeric
X = pd.get_dummies(X, drop_first=True)

# Split data and train model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = LinearRegression()
model.fit(X_train, y_train)

# Define FastAPI app
app = FastAPI()

# Mount static files directory

# Initialize templates
templates = Jinja2Templates(directory="template")

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Store active tokens
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tokens (
        username TEXT PRIMARY KEY,
        token TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL
    )
    ''')
    
    conn.commit()
    conn.close()

# Call init_db at startup
init_db()

# Pydantic models
class User(BaseModel):
    username: str
    email: str
    password: str

class UserInDB(User):
    id: int
    created_at: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class HouseInput(BaseModel):
    area: int
    bathrooms: int
    bedrooms: int
    guestroom: str
    basement: int
    parking: int

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

# Helper functions for authentication (replacing jose/bcrypt)
def create_access_token(username: str):
    # Generate a random token
    token = secrets.token_hex(32)
    
    # Calculate expiration time
    expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Store the token in the database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Remove any existing tokens for this user
    cursor.execute("DELETE FROM tokens WHERE username = ?", (username,))
    
    # Insert the new token
    cursor.execute(
        "INSERT INTO tokens (username, token, expires_at) VALUES (?, ?, ?)",
        (username, token, expires_at)
    )
    conn.commit()
    conn.close()
    
    return token

def verify_token(token: str):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Check if token exists and is not expired
    cursor.execute(
        "SELECT username FROM tokens WHERE token = ? AND expires_at > ?", 
        (token, datetime.utcnow())
    )
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {"username": result[0]}
    return None

def get_password_hash(password: str):
    # Generate a random salt
    salt = secrets.token_hex(16)
    
    # Hash the password with the salt
    hash_obj = hashlib.sha256(password.encode() + salt.encode())
    password_hash = hash_obj.hexdigest()
    
    return password_hash, salt

def verify_password(plain_password: str, stored_hash: str, salt: str):
    # Hash the provided password with the stored salt
    hash_obj = hashlib.sha256(plain_password.encode() + salt.encode())
    password_hash = hash_obj.hexdigest()
    
    # Compare the hashes
    return password_hash == stored_hash

async def get_current_user(token: str = Depends(oauth2_scheme)):
    if token is None:
        return None
    
    # Extract token from "Bearer {token}"
    if token.startswith("Bearer "):
        token = token.split(" ")[1]
    
    user = verify_token(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def get_user_by_username(username: str):
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return dict(user)
    return None

def authenticate_user(username: str, password: str):
    user = get_user_by_username(username)
    if not user:
        return False
    if not verify_password(password, user["password"], user["salt"]):
        return False
    return user

# Routes
@app.get('/', response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get('/signup', response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post('/signup')
async def signup(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    try:
        # Check if user already exists
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            return templates.TemplateResponse(
                "signup.html", 
                {"request": request, "error": "Username or email already exists"}
            )
        
        # Hash the password
        hashed_password, salt = get_password_hash(password)
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, salt)
        )
        conn.commit()
        conn.close()
        
        # Redirect to login page
        response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        return response
        
    except Exception as e:
        return templates.TemplateResponse(
            "signup.html", 
            {"request": request, "error": f"An error occurred: {str(e)}"}
        )

@app.post('/login')
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends()
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Incorrect username or password"}
        )
    
    # Create access token
    access_token = create_access_token(user["username"])
    
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response

@app.get('/logout')
async def logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="access_token")
    return response

@app.get('/predication', response_class=HTMLResponse)
async def prediction_form(request: Request, current_user: dict = Depends(get_current_user)):
    if current_user is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("prediction.html", {"request": request, "user": current_user})

@app.get('/About us', response_class=HTMLResponse)
def about(request: Request):
    # No authentication needed for about page
    return templates.TemplateResponse("aboutus.html", {"request": request})

@app.post('/predict')
async def predict_price(house: HouseInput, current_user: dict = Depends(get_current_user)):
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You must be logged in to use this feature",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        # Prepare input data
        guestroom_val = 1 if house.guestroom.lower() == 'yes' else 0
        input_data = [[house.area, house.bathrooms, house.bedrooms, guestroom_val, house.basement, house.parking]]
        predicted_price = model.predict(input_data)
        return {"predicted_price": round(predicted_price[0], 2)}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
   uvicorn.run("script:app", host="0.0.0.0", port=8000, reload=True)