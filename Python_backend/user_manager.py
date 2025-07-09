import json
import os
import bcrypt
import datetime
import re
from typing import Dict, Any, Optional, Tuple

USERS_FILE = "users.json"

class UserManager:
    def __init__(self, users_file: str = USERS_FILE):
        self.users_file = users_file
        self._initialize_users_file()
    
    def _initialize_users_file(self):
        """Initialize users file if it doesn't exist"""
        if not os.path.exists(self.users_file):
            with open(self.users_file, "w") as f:
                json.dump({}, f)
    
    def load_users(self) -> Dict[str, Any]:
        """Load users from JSON file with error handling"""
        try:
            with open(self.users_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading users: {e}")
            return {}
    
    def save_users(self, users: Dict[str, Any]) -> bool:
        """Save users to JSON file with error handling"""
        try:
            with open(self.users_file, "w") as f:
                json.dump(users, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving users: {e}")
            return False
    
    def _validate_username(self, username: str) -> bool:
        """Validate username format"""
        if not username or len(username) < 3 or len(username) > 20:
            return False
        return re.match(r'^[a-zA-Z0-9_]+$', username) is not None
    
    def _validate_password(self, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        return True, "Password is valid"
    
    def register_user(self, username: str, password: str, user_data: Dict[str, Any] = None) -> Tuple[bool, str]:
        """Register a new user with validation"""
        if user_data is None:
            user_data = {}
        
        # Validate username
        if not self._validate_username(username):
            return False, "Username must be 3-20 characters long and contain only letters, numbers, and underscores"
        
        # Validate password
        is_valid, message = self._validate_password(password)
        if not is_valid:
            return False, message
        
        users = self.load_users()
        
        # Check if user already exists
        if username in users:
            return False, "User already exists"
        
        # Hash password
        try:
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        except Exception as e:
            return False, f"Error hashing password: {e}"
        
        # Create user record
        users[username] = {
            "password_hash": password_hash,
            "created_at": datetime.datetime.now().isoformat(),
            "last_login": None,
            "is_active": True,
            "login_attempts": 0,
            "locked_until": None,
            **user_data
        }
        
        if self.save_users(users):
            return True, "User registered successfully"
        else:
            return False, "Failed to save user data"
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Authenticate user with account lockout protection"""
        users = self.load_users()
        
        if username not in users:
            return False, None, "Invalid username or password"
        
        user = users[username]
        
        # Check if account is active
        if not user.get("is_active", True):
            return False, None, "Account is deactivated"
        
        # Check if account is locked
        if user.get("locked_until"):
            locked_until = datetime.datetime.fromisoformat(user["locked_until"])
            if datetime.datetime.now() < locked_until:
                return False, None, f"Account is locked until {locked_until.strftime('%Y-%m-%d %H:%M:%S')}"
            else:
                # Unlock account
                user["locked_until"] = None
                user["login_attempts"] = 0
        
        # Check password
        try:
            stored_hash = user["password_hash"].encode()
            if bcrypt.checkpw(password.encode(), stored_hash):
                # Successful login
                user["last_login"] = datetime.datetime.now().isoformat()
                user["login_attempts"] = 0
                user["locked_until"] = None
                self.save_users(users)
                return True, user, "Login successful"
            else:
                # Failed login
                user["login_attempts"] = user.get("login_attempts", 0) + 1
                if user["login_attempts"] >= 5:
                    # Lock account for 30 minutes
                    lock_time = datetime.datetime.now() + datetime.timedelta(minutes=30)
                    user["locked_until"] = lock_time.isoformat()
                    self.save_users(users)
                    return False, None, "Account locked due to too many failed attempts"
                else:
                    self.save_users(users)
                    return False, None, f"Invalid username or password. {5 - user['login_attempts']} attempts remaining"
        except Exception as e:
            return False, None, f"Authentication error: {e}"
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password"""
        # Authenticate with old password
        auth_success, user_data, message = self.authenticate_user(username, old_password)
        if not auth_success:
            return False, "Current password is incorrect"
        
        # Validate new password
        is_valid, validation_message = self._validate_password(new_password)
        if not is_valid:
            return False, validation_message
        
        # Update password
        users = self.load_users()
        try:
            new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            users[username]["password_hash"] = new_hash
            if self.save_users(users):
                return True, "Password changed successfully"
            else:
                return False, "Failed to save new password"
        except Exception as e:
            return False, f"Error changing password: {e}"
    
    def update_user_data(self, username: str, new_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Update user data"""
        users = self.load_users()
        if username not in users:
            return False, "User not found"
        
        # Don't allow updating sensitive fields
        protected_fields = ["password_hash", "created_at", "login_attempts", "locked_until"]
        for field in protected_fields:
            if field in new_data:
                del new_data[field]
        
        users[username].update(new_data)
        
        if self.save_users(users):
            return True, "User data updated successfully"
        else:
            return False, "Failed to update user data"
    
    def deactivate_user(self, username: str) -> Tuple[bool, str]:
        """Deactivate user account"""
        users = self.load_users()
        if username not in users:
            return False, "User not found"
        
        users[username]["is_active"] = False
        if self.save_users(users):
            return True, "User account deactivated"
        else:
            return False, "Failed to deactivate user account"
    
    def activate_user(self, username: str) -> Tuple[bool, str]:
        """Activate user account"""
        users = self.load_users()
        if username not in users:
            return False, "User not found"
        
        users[username]["is_active"] = True
        users[username]["login_attempts"] = 0
        users[username]["locked_until"] = None
        
        if self.save_users(users):
            return True, "User account activated"
        else:
            return False, "Failed to activate user account"
    
    def delete_user(self, username: str) -> Tuple[bool, str]:
        """Delete user account"""
        users = self.load_users()
        if username not in users:
            return False, "User not found"
        
        del users[username]
        if self.save_users(users):
            return True, "User deleted successfully"
        else:
            return False, "Failed to delete user"
    
    def get_user_info(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user information (without password hash)"""
        users = self.load_users()
        if username not in users:
            return None
        
        user_info = users[username].copy()
        user_info.pop("password_hash", None)  # Remove password hash for security
        return user_info
    
    def list_users(self) -> Dict[str, Dict[str, Any]]:
        """List all users (without password hashes)"""
        users = self.load_users()
        safe_users = {}
        
        for username, user_data in users.items():
            safe_user_data = user_data.copy()
            safe_user_data.pop("password_hash", None)
            safe_users[username] = safe_user_data
        
        return safe_users
    
    def unlock_user(self, username: str) -> Tuple[bool, str]:
        """Manually unlock a locked user account"""
        users = self.load_users()
        if username not in users:
            return False, "User not found"
        
        users[username]["locked_until"] = None
        users[username]["login_attempts"] = 0
        
        if self.save_users(users):
            return True, "User account unlocked"
        else:
            return False, "Failed to unlock user account"