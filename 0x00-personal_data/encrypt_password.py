#!/usr/bin/env python3
""" Returns a salted, hashed password, byte in string """
import bcrypt


def hash_password(password: str) -> bytes:
    """ Returns byte string password """
    return bcrypt.hashpw(password.encode('hashpw'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Implement is_valid to validate provided password
    matched hashed_password
    """
    return bcrypt.checkpw(password.encode('hashpw'), hashed_password)
