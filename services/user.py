from __future__ import annotations

from dependencies import *

from schemas.user import *

from config.database import data_base
from config.security import *

from bson.objectid import ObjectId

import uuid


COLLECTION = data_base['user']


def _substring(string: str,character: str ) -> str:
    substring = ""
    position_character = list(string).index(character)
    substring = string[:position_character]
    return substring


def create_user(credentials: Credentials) -> Union[TokenSession, Error]:
    """Business rules:
        1.- Non-empty credentials
        2.- Mail not existing in the system
    Args:
        credentials (Credentials): email and password 
    """
    
    
    if credentials is None:
        return Error(
            message="Credenciales no válidas",
            code=400
        )
        
    new_user = dict(credentials)
    
    if new_user["email"]=="" or new_user["password"]=="":
        return Error(
            message="Credenciales no válidas",
            code=400
        )
    
    email = new_user["email"]
    name = _substring(email,"@")
    hashPassword,saltPassword = hash_password(new_user["password"])
    emailVerified = False
    codeVerification = ""
    faceCaptured = False
    lastUpgradeFace = None
    
    new_account = User(name=name,
                       email=email,
                       hashPassword=hashPassword,
                       saltPassword=saltPassword,
                       emailVerified=emailVerified,
                       codeVerification=codeVerification,
                       faceCaptured=faceCaptured,
                       lastUpgradeFace=lastUpgradeFace)
    
    # create in database
    result = COLLECTION.insert_one(dict(new_account))
    
    return TokenSession(token=uuid.uuid4(),userId=str(result.inserted_id))


def login(credentials: Credentials) -> Union[TokenSession, Error]:
    """Business rules
        1.- Non-empty credentials
        2.- Existing mail
        3.- Correct password
    Args:
        credentials (Credentials): _description_

    Returns:
        Union[TokenSession, Error]: _description_
    """
    
    if credentials is None:
        return Error(
            message="Credenciales no válidas",
            code=400
        )
    
    user = dict(credentials)
    
    if user["email"]=="":
        return Error(
            message="Credenciales no válidas",
            code=400
        )
    
    user_repository = COLLECTION.find_one(filter={"email":user["email"]})
    
    if user_repository is None:
        return Error(
            message="Usuario no encontrado",
            code=404
        )
    
    hash_password = user_repository["hashPassword"]
    
    if not match_password(user["password"],hash_password):
        return Error(
            message="Credenciales no válidas",
            code=400
        )
    
    return TokenSession(token=uuid.uuid4(),userId=str(user_repository["_id"]))


def update_info_by_block(profile: ProfileUpdate, userId: str) -> Union[Profile, Error]:
    """Business rules:
        1.- Request not empty and user id required 2.
        2.- Existence of a user in the repository associated to the id provided.
        3.- The password in the request body must match the one stored in the repository.
        4.- Identify which fields will be updated.
        5.- If the password is changed, it will be encrypted.
        6.- Update in the repository the data of the request body.
        7.- Return the summary of the user named Profile.

    Args:
        profile (ProfileUpdate): _description_
        useId (str): _description_
    Returns:
        Union[Profile, Error]: _description_
    """
    
    #1
    if profile is None or userId is None:
        return Error(
            message="Error",
            code=403
        )
    
    userId = ObjectId(userId)
    user_profile = dict(profile)
    user_repository = COLLECTION.find_one(filter={"_id": userId})
    #2
    if user_repository is None:
        return Error(
            message="Usuario no encontrado",
            code=404
        )
    
    #3 check password
    if not match_password(user_profile["currentPassword"],user_repository["hashPassword"]):
        return Error(
            message="Usuario no autorizado",
            code=401
        )
    
    #4
    #update user
    map_fields = {"newEmail":"email", "newUser": "name", "newPassword": "hashPassword"}
    
    # Crear un diccionario con los campos que se actualizarán
    update_fields = {map_fields[key]: value for key, value in user_profile.items() if value is not None and value != "" and key != 'currentPassword' }
    
        #5
    if 'hashPassword' in update_fields.keys():
        update_fields['saltPassword'] = ""
        
        update_fields['hashPassword'],update_fields["saltPassword"] = hash_password(user_profile["newPassword"])
    
    if not update_fields:
        # Not fields update
        return Profile(
            userId=str(user_repository["_id"]),
            user=user_repository["name"],
            email=user_repository["email"],
            emailVerified=user_repository["emailVerified"],
            lastUpgradeFace=user_repository["lastUpgradeFace"]
        )
    #6
    # Update data by block
    COLLECTION.update_one(filter={"_id": userId}, update={"$set": update_fields})
    
    
    # recover profile updated
    updated_user = COLLECTION.find_one(filter={"_id": userId})
    
    #7
    return Profile(
        userId=str(updated_user["_id"]),
        user=updated_user["name"],
        email=updated_user["email"],
        emailVerified=updated_user["emailVerified"],
        lastUpgradeFace=updated_user["lastUpgradeFace"]
    )
 
    
async def send_code_verification():
    pass

async def verification_code():
    pass


    
    
    
    