

def userEntity(item) -> dict:
    return {
        "id": item["id"],
        "name":item["name"],
        "email":item["email"],
        "hashPassword":item["hashPassword"],
        "saltPassword":item["saltPassword"],
        "emailVerified":item["emailVerified"],
        "codeVerified": item["codeVerification"],
        "faceCaptured": item["faceCaptured"],
        "lastUpgradeFace": item["lastUpgradeFace"]
    }
    

def usersEntity(entity) -> list:
    return [userEntity(item) for item in entity]