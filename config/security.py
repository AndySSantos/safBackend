import bcrypt
from dotenv import load_dotenv
import os
import uuid

load_dotenv()

HASH_LEVEL = os.environ.get('HASH_LEVEL')
ENCODING = os.environ.get('ENCODING')

HOST = os.environ.get('MAIL_HOST')
USERNAME = os.environ.get('MAIL_USERNAME')
PASSWORD = os.environ.get('MAIL_PASSWORD')
PORT = os.environ.get('MAIL_PORT',465)

def salt_hash() -> str:
    salt_bytes = bcrypt.gensalt(int(HASH_LEVEL))
    return salt_bytes.decode(ENCODING)

def hash_password(password: str) -> (str, str):
    salt = salt_hash()
    hash = bcrypt.hashpw(password.encode(ENCODING), salt.encode(ENCODING))
    return (hash.decode(ENCODING), salt)

def match_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(ENCODING), hashed_password.encode(ENCODING))


def generator_code() -> str:
    code = uuid.uuid4()
    code = str(code)[:8]
    return code