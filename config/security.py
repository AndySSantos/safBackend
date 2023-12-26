import bcrypt

HASH_LEVEL = 12
ENCODING = 'utf-8'

def salt_hash() -> str:
    salt_bytes = bcrypt.gensalt(HASH_LEVEL)
    return salt_bytes.decode(ENCODING)

def hash_password(password: str) -> (str, str):
    salt = salt_hash()
    hash = bcrypt.hashpw(password.encode(ENCODING), salt.encode(ENCODING))
    return (hash.decode(ENCODING), salt)

def match_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(ENCODING), hashed_password.encode(ENCODING))