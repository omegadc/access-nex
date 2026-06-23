# =============================================================================
# IMPORTS
# =============================================================================

import json
# Used to read user information from the users.json file.

import os
# Used for environment variables and file path handling.

from datetime import datetime, timedelta
# datetime is used to create token expiration timestamps.
# timedelta allows us to specify how long a token remains valid.

from typing import Optional
# Used for type hints when a function may return None.

from jose import JWTError, jwt
# jose provides JWT functionality:
# - jwt.encode() creates tokens
# - jwt.decode() validates and reads tokens
# - JWTError catches token-related errors

from passlib.context import CryptContext
# Provides password hashing and verification functionality using bcrypt.

from sqlalchemy.orm import Session
# SQLAlchemy database session object used to interact with the database.

from models.database import UserDB
# Database model representing users stored in the SQL database.


# =============================================================================
# CONFIGURATION
# =============================================================================

# Secret key used to sign and verify JWT tokens.
# In production, this should ALWAYS come from an environment variable
# and should never be hardcoded.
SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "changeme-use-a-long-random-string-in-production"
)

# JWT signing algorithm.
# HS256 = HMAC + SHA256
ALGORITHM = "HS256"

# Default JWT expiration time (in minutes).
TOKEN_EXPIRE_MINUTES = 60

# Configure password hashing.
# bcrypt is considered one of the safest password hashing algorithms.
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# Build the path to users.json.
# Example result:
# project_root/data/users.json
USERS_JSON = os.path.join(
    os.path.dirname(__file__),
    "../data/users.json"
)


# =============================================================================
# PASSWORD HELPER FUNCTIONS
# =============================================================================

def hash_password(plain: str) -> str:
    """
    Converts a plain-text password into a bcrypt hash.

    Example:
        Input:
            password123

        Output:
            $2b$12$H3K....

    The hash is what gets stored in the database.
    Plain-text passwords should never be stored.
    """

    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Compares a plain-text password against a stored hash.

    Parameters:
        plain:
            Password entered by the user.

        hashed:
            Password hash stored in the database.

    Returns:
        True  -> Password is correct
        False -> Password is incorrect
    """

    return pwd_context.verify(plain, hashed)


# =============================================================================
# JWT TOKEN HELPER FUNCTIONS
# =============================================================================

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Creates a JWT access token.

    Parameters:
        data:
            Information to store inside the token.

            Example:
            {
                "sub": "admin",
                "role": "admin"
            }

        expires_delta:
            Optional custom expiration time.

    Returns:
        Encoded JWT token string.
    """

    # Create a copy of the payload to avoid modifying the original.
    to_encode = data.copy()

    # Calculate token expiration time.
    # If a custom expiration is provided, use it.
    # Otherwise use TOKEN_EXPIRE_MINUTES.
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    )

    # Add expiration timestamp to payload.
    to_encode.update({"exp": expire})

    # Encode payload into a JWT token.
    return jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def decode_token(token: str) -> Optional[dict]:
    """
    Validates and decodes a JWT token.

    Parameters:
        token:
            JWT token received from the client.

    Returns:
        Decoded payload dictionary if valid.

        Example:
        {
            "sub": "admin",
            "role": "admin",
            "exp": ...
        }

        Returns None if:
        - Token is invalid
        - Token is expired
        - Signature verification fails
    """

    try:

        # Decode and verify token signature.
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

    except JWTError:

        # Invalid token or expired token.
        return None


# =============================================================================
# JSON-BASED AUTHENTICATION (PHASE 1)
# =============================================================================

def authenticate_user_json(
    username: str,
    password: str
) -> Optional[dict]:
    """
    Authenticate a user using users.json.

    This was designed as the Phase 1 authentication system
    before database authentication was implemented.

    Process:
        1. Open users.json
        2. Find matching username
        3. Verify password
        4. Return user data if valid

    Returns:
        User dictionary if authentication succeeds.

        Example:
        {
            "username": "admin",
            "password": "...",
            "role": "admin"
        }

        Returns None if authentication fails.
    """

    try:

        # Open users.json and load all users.
        with open(USERS_JSON) as f:
            users = json.load(f)

    except FileNotFoundError:

        # If the file doesn't exist,
        # authentication cannot proceed.
        return None

    # Loop through every user record.
    for user in users:

        # Check if usernames match.
        if user["username"] == username:

            # -----------------------------------------------------------------
            # DEVELOPMENT MODE PASSWORD CHECK
            # -----------------------------------------------------------------
            #
            # Allows plain-text password matching.
            # Useful during early development.
            #
            # Example:
            # {
            #     "username": "admin",
            #     "password": "password123"
            # }
            #
            plain_match = (
                password == user["password"]
            )

            # -----------------------------------------------------------------
            # HASHED PASSWORD CHECK
            # -----------------------------------------------------------------
            #
            # Production-style password validation using bcrypt.
            #
            hashed_match = False

            try:

                hashed_match = verify_password(
                    password,
                    user["password"]
                )

            except Exception:

                # If stored password isn't a valid bcrypt hash,
                # simply ignore the error and continue.
                pass

            # Login succeeds if either check passes.
            if plain_match or hashed_match:
                return user

    # No matching user found.
    return None


# =============================================================================
# DATABASE AUTHENTICATION (PHASE 2)
# =============================================================================

def authenticate_user_db(
    db: Session,
    username: str,
    password: str
) -> Optional[UserDB]:
    """
    Authenticate a user using the SQL database.

    Parameters:
        db:
            Active SQLAlchemy database session.

        username:
            Username entered during login.

        password:
            Password entered during login.

    Returns:
        UserDB object if authentication succeeds.

        Returns None if:
        - User does not exist
        - Password is incorrect
    """

    # Query database for the user.
    user = (
        db.query(UserDB)
        .filter(UserDB.username == username)
        .first()
    )

    # Verify user exists and password matches.
    if user and verify_password(
        password,
        user.hashed_password
    ):
        return user

    # Authentication failed.
    return None


