import bcrypt
from dotenv import load_dotenv
import os, re,uuid
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

load_dotenv()

HASH_LEVEL = os.environ.get('HASH_LEVEL')
ENCODING = os.environ.get('ENCODING')

HOST = os.environ.get('MAIL_HOST')
USERNAME = os.environ.get('MAIL_USERNAME')
PASSWORD = os.environ.get('MAIL_PASSWORD')
PORT = os.environ.get('MAIL_PORT',465)

SECRET_KEY =os.environ.get('SECRET_KEY')
ALGORITHM = os.environ.get('ALGORITHM')

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

def generator_token(payload: dict) -> str:
    to_encode = payload.copy()
    token = jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return token

def decode_token(token: str)-> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(payload)
        return payload
    except Exception:
        return None

def is_hex(string:str)-> bool:
    length = 24
    patern_hexa = re.compile(r'^[0-9a-fA-F]{%d}$' % length)
    return bool(patern_hexa.match(string))


#token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NThhNTcyOTcyZTdkMGJiYTMzZDdlZDMiLCJuYW1lIjoiY2JpMjE4MzA1MTA5OCJ9.AL1Yyp_Ic8PSvl5Qht9zrWu8cHK5ONdkIVl3ubBs0QQ"
#decode_token(token)