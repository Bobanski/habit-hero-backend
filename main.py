"""
📦 FastAPI backend for Habit Hero
- Stores and returns user XP, habits, streaks, PRs, and to-dos
- User authentication with username
- Stores user data in separate JSON files
"""

from fastapi import FastAPI, HTTPException, Depends, Cookie, Response, Form, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
import json
import os
from datetime import datetime
import secrets
import re
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from starlette.requests import Request
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware

# Initialize FastAPI app
app = FastAPI(
    title="Habit Hero API",
    description="Backend for the Habit Hero habit tracking app",
    version="1.0.0"
)

# Add middleware to handle /api prefix
class APIPathPrefixMiddleware(BaseHTTPMiddleware):
    """Middleware to handle /api prefix in requests"""
    
    async def dispatch(self, request: Request, call_next):
        # Check if request path starts with /api/
        if request.url.path.startswith("/api/"):
            # Strip /api prefix from path
            path_without_prefix = request.url.path[4:]  # Remove "/api"
            
            # Update path in request scope
            request.scope["path"] = path_without_prefix
            
            # Update raw_path if it exists
            if "raw_path" in request.scope:
                request.scope["raw_path"] = path_without_prefix.encode()
        
        # Continue with request processing
        response = await call_next(request)
        return response

# Add the middleware to the app
app.add_middleware(APIPathPrefixMiddleware)

# Update the CORS middleware configuration
# Update the CORS middleware configuration

# Configure CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite dev server
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Explicitly allow OPTIONS
    allow_headers=["Content-Type", "Set-Cookie", "Access-Control-Allow-Headers", 
                  "Access-Control-Allow-Origin", "Authorization"],
    expose_headers=["Content-Type", "Set-Cookie"],
    max_age=600,  # Preflight requests can be cached for 10 minutes
)

# Directory to store user data
DATA_DIR = "user_data"
# Create the directory if it doesn't exist
os.makedirs(DATA_DIR, exist_ok=True)

# User sessions data
SESSIONS = {}

# Default user data structure
def get_default_user_data():
    return {
        "xp": 0,
        "level": 1,
        "habits": [
            {"id": 1, "name": "Stretching", "completed": False, "selected": False, "xp": 10, "streak": 0, "lastCompletedDate": None},
            {"id": 2, "name": "Exercise", "completed": False, "selected": False, "xp": 15, "streak": 0, "lastCompletedDate": None}
        ],
        "prs": [
            {"id": 1, "name": "Push-ups", "current": 0, "unit": "reps"},
            {"id": 2, "name": "Plank time", "current": 0, "unit": "seconds"}
        ],
        "todos": [
            {"id": 1, "text": "Fill out habits", "completed": False},
            {"id": 2, "text": "Fill out personal records", "completed": False}
        ]
    }

# Pydantic models
class Habit(BaseModel):
    id: int
    name: str
    completed: bool
    selected: bool = False
    xp: int
    streak: int
    lastCompletedDate: Optional[str] = None

class PersonalRecord(BaseModel):
    id: int
    name: str
    current: int
    unit: str

class Todo(BaseModel):
    id: int
    text: str
    completed: bool

class UserData(BaseModel):
    xp: int
    level: int
    habits: List[Habit]
    prs: List[PersonalRecord]
    todos: List[Todo]

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    
    @validator('username')
    def username_valid(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username can only contain letters, numbers, underscores, and hyphens')
        return v

class LoginResponse(BaseModel):
    username: str
    session_id: str
    message: str

# Utility functions
def get_user_file_path(username: str) -> str:
    """Get the file path for a user's data file"""
    # Create a valid filename from the username
    valid_filename = re.sub(r'[^a-zA-Z0-9_-]', '', username.lower())
    return os.path.join(DATA_DIR, f"{valid_filename}.json")

def user_exists(username: str) -> bool:
    """Check if a user exists"""
    return os.path.exists(get_user_file_path(username))

def load_user_data(username: str) -> dict:
    """Load user data from file or return default if file doesn't exist"""
    file_path = get_user_file_path(username)
    try:
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                return json.load(f)
        return get_default_user_data()
    except Exception as e:
        print(f"Error loading user data: {e}")
        return get_default_user_data()

def save_user_data(username: str, data: dict) -> bool:
    """Save user data to file"""
    file_path = get_user_file_path(username)
    try:
        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving user data: {e}")
        return False

def get_current_user(session_id: Optional[str] = Cookie(None)) -> str:
    """Get the current user from the session cookie"""
    if not session_id or session_id not in SESSIONS:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return SESSIONS[session_id]

# Endpoints for authentication
@app.post("/auth/register", response_model=LoginResponse)
def register(user: UserCreate, response: Response):
    """Register a new user"""
    if user_exists(user.username):
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create a new session
    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = user.username
    
    # Create user data file with default data
    save_user_data(user.username, get_default_user_data())
    
    # Set cookie - update these parameters
    response.set_cookie(
        key="session_id", 
        value=session_id, 
        httponly=True, 
        max_age=7 * 24 * 60 * 60,  # 7 days
        samesite="lax",  # Changed from strict to lax for cross-site requests
        secure=False     # Set to True in production with HTTPS
    )
    
    return {
        "username": user.username,
        "session_id": session_id,
        "message": f"User {user.username} registered successfully"
    }

@app.post("/auth/login", response_model=LoginResponse)
def login(user: UserCreate, response: Response):
    """Login an existing user"""
    if not user_exists(user.username):
        raise HTTPException(status_code=404, detail="User not found")
    
    # Create a new session
    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = user.username
    
    # Set cookie - update these parameters
    response.set_cookie(
        key="session_id", 
        value=session_id, 
        httponly=True, 
        max_age=7 * 24 * 60 * 60,  # 7 days
        samesite="lax",  # Changed from strict to lax for cross-site requests
        secure=False     # Set to True in production with HTTPS
    )
    
    return {
        "username": user.username,
        "session_id": session_id,
        "message": f"Welcome back, {user.username}!"
    }

@app.post("/auth/logout")
def logout(response: Response, session_id: Optional[str] = Cookie(None)):
    """Logout the current user"""
    if session_id and session_id in SESSIONS:
        del SESSIONS[session_id]
    
    # Clear cookie
    response.delete_cookie(key="session_id")
    
    return {"message": "Logged out successfully"}

@app.get("/auth/me")
def get_current_user_info(username: str = Depends(get_current_user)):
    """Get information about the current user"""
    return {"username": username}

# Endpoints for user data
@app.get("/user")
def get_user_data(session_id: Optional[str] = Cookie(None), authorization: Optional[str] = Header(None)):
    # Try to get username from session_id cookie first
    username = None
    if session_id and session_id in SESSIONS:
        username = SESSIONS[session_id]
    
    # If no valid session cookie, try token auth
    if not username and authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        if token in SESSIONS:
            username = SESSIONS[token]
    
    if not username:
        raise HTTPException(status_code=401, detail="User not authenticated")
    
    # Now we have the username, get user data
    return load_user_data(username)

@app.post("/user")
def update_user_data(
    user_data: dict, 
    session_id: Optional[str] = Cookie(None), 
    authorization: Optional[str] = Header(None)
):
    # Try to get username from session_id cookie first
    username = None
    if session_id and session_id in SESSIONS:
        username = SESSIONS[session_id]
    
    # If no valid session cookie, try token auth
    if not username and authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        if token in SESSIONS:
            username = SESSIONS[token]
    
    if not username:
        raise HTTPException(status_code=401, detail="User not authenticated")
    
    # Now we have the username, save user data
    save_user_data(username, user_data)
    return {"message": "User data updated successfully"}

# Health check endpoint
@app.get("/health")
def health_check():
    """Simple health check endpoint"""
    return {"status": "ok", "timestamp": datetime.now().isoformat()}

# Run the application with: uvicorn main:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


# Add this to your backend/main.py file
@app.get("/debug/cookies")
def debug_cookies(session_id: Optional[str] = Cookie(None)):
    """Debug endpoint to check cookies"""
    return {
        "has_session_id": session_id is not None,
        "session_id_prefix": session_id[:10] + "..." if session_id else None,
        "valid_session": session_id in SESSIONS if session_id else False,
        "sessions_count": len(SESSIONS),
        "time": datetime.now().isoformat()
    }

# Add these new endpoints for form-based auth
@app.post("/auth/form-login")
def form_login(username: str = Form(...), response: Response = None):
    """Login with form data"""
    if not user_exists(username):
        raise HTTPException(status_code=404, detail="User not found")
    
    # Create a new session
    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = username
    
    # Set cookie
    response.set_cookie(
        key="session_id", 
        value=session_id, 
        httponly=True, 
        max_age=7 * 24 * 60 * 60,
        samesite="lax",
        secure=False
    )
    
    return {
        "username": username,
        "session_id": session_id,
        "message": f"Welcome back, {username}!"
    }

@app.post("/auth/form-register")
def form_register(username: str = Form(...), response: Response = None):
    """Register with form data"""
    # Basic validation - correct any implementation details to match your exact code
    if not username or len(username) < 3 or len(username) > 20:
        raise HTTPException(status_code=400, detail="Username must be between 3 and 20 characters")
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        raise HTTPException(status_code=400, detail="Username can only contain letters, numbers, underscores, and hyphens")
    
    # Check if user already exists
    if user_exists(username):
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create a new session
    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = username
    
    # Create user data file with default data
    save_user_data(username, get_default_user_data())
    
    # Set cookie
    response.set_cookie(
        key="session_id", 
        value=session_id, 
        httponly=True, 
        max_age=7 * 24 * 60 * 60,
        samesite="lax",
        secure=False
    )
    
    return {
        "username": username,
        "session_id": session_id,
        "message": f"User {username} registered successfully"
    }

@app.post("/auth/token-login")
def token_login(username: str = Form(...), response: Response = None):
    """Login with username and return a token, creating user if needed"""
    # Create user if they don't exist
    if not user_exists(username):
        # Create user data file with default data
        save_user_data(username, get_default_user_data())
    
    # Create a simple token
    token = secrets.token_urlsafe(16)
    SESSIONS[token] = username
    
    # Also set a session cookie for cookie-based auth
    if response:
        response.set_cookie(
            key="session_id", 
            value=token, 
            httponly=True, 
            max_age=7 * 24 * 60 * 60,
            samesite="lax",
            secure=False
        )
    
    return {
        "username": username,
        "access_token": token,
        "token_type": "bearer"
    }

# Add a token auth endpoint
@app.get("/auth/verify-token")
def verify_token(authorization: str = Header(None)):
    """Verify a token from Authorization header"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    
    token = authorization.replace("Bearer ", "")
    if token not in SESSIONS:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    username = SESSIONS[token]
    return {"username": username}