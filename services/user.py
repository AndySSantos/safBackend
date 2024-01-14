from __future__ import annotations

from dependencies import *

from schemas.user import *
from datetime import date

from config.database import data_base
from config.security import *
from ssl import create_default_context
from email.mime.text import MIMEText
from smtplib import SMTP
import smtplib

from bson.objectid import ObjectId

import re


COLLECTION = data_base['user']


def _substring(string: str,character: str ) -> str:
    substring = ""
    position_character = list(string).index(character)
    substring = string[:position_character]
    return substring

def _is_hex(string:str)-> bool:
    length = 24
    patern_hexa = re.compile(r'^[0-9a-fA-F]{%d}$' % length)
    return bool(patern_hexa.match(string))


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
    
    user_repository = COLLECTION.find_one(filter={"email":new_user["email"]})
    
    if user_repository:
        return Error(
            message="Correo exitente", 
            code=403
        )
    
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
    token = generator_token({"userId":str(result.inserted_id),"name": name})
    return TokenSession(token=token,userId=str(result.inserted_id))


def login(credentials: Credentials) -> Union[TokenSession, Error]:
    """Business rules
        1.- Non-empty credentials
        2.- Existing mail
        3.- Correct password
        4.- Email verified
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
    """if not user_repository["emailVerified"]: 
        return Error(
            message="Email no verificado",
            code=403
        )"""
    token = generator_token({"userId":str(user_repository["_id"]),"name": user_repository["name"]})
    return TokenSession(token=token,userId=str(user_repository["_id"]))


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
    print("Recibi llamado")
    #1
    if profile is None or userId is None or len(userId)-24!=0:
        return Error(
            message="No puedo responder a esta solicitud",
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
    lastUpdateFace = user_repository['lastUpgradeFace'] if user_repository['lastUpgradeFace'] else date(1999, 8, 8)
    return Profile(
        userId=str(updated_user["_id"]),
        user=updated_user["name"],
        email=updated_user["email"],
        emailVerified=updated_user["emailVerified"],
        lastUpgradeFace=lastUpdateFace
    )
 
    
def send_code_verification(userId: str) -> Union[None, Error]:
    """Business rules:
        1.- User id is not empty 2.
        2.- User exists in the repository 2.
        3.- The user does not have verified email address
        4.- The code is 8 characters long.
        5.- The code can be resent as long as point 3 is fulfilled.

    Args:
        userId (str): _description_

    Returns:
        Union[None, Error]: _description_
    """
    
    #1 
    if userId is None or userId=="" or len(userId)-24!=0:
        return Error(message="No puedo responder a esta solicitud", code=403)
    
    #2 y 3
    userId = ObjectId(userId)
    user_repository = COLLECTION.find_one(filter={"_id": userId})
    if user_repository is None or  user_repository["emailVerified"]:
        return Error(message="Usuario no autorizado a esta accion", code=401)
    
    #4
    verification_code = generator_code()
    COLLECTION.update_one(filter={"_id": userId}, update={"$set": {"codeVerification":verification_code}})
    
    username = user_repository["name"]
    
    
    email_body = f"""
    Hola {username},

    Gracias por registrarte en SafUAMI. Para completar tu registro, utiliza el siguiente codigo de verificacion:
    
    Codigo de verificacion: {verification_code}
    
    Este codigo de verificacion no caducara, pero puedes solicitar otro desde la app
     
    ¡Gracias!
    SafUAMI by SoftMinds
    """ 
    
    
    msg = Email(
        to=user_repository["email"],
        subject="SafUAMI Verification code",
        body=email_body
    )
    
    message = MIMEText(msg.body, "html")
    message["From"] = USERNAME
    message["To"] = msg.to#",".join(msg.to)
    message["Subject"] = msg.subject
    
    try:
        smtp = SMTP(HOST,PORT)
        status_code, response = smtp.ehlo()
        print(f"[*] Echoing the server: {status_code} {response}")
        
        status_code, response = smtp.starttls()
        print(f"[*] Starting TLS connection: {status_code} {response}")
        
        status_code, response = smtp.login(USERNAME,PASSWORD)
        print(f"[*] Logging in: {status_code} {response}")
        
        smtp.send_message(message)
        #smtp.sendmail(from_addr=USERNAME,to_addrs=user_repository["email"],msg=email_body)
        
        #smtp.quit()
        print("enviado")
        return Error(message=f"Codigo enviado a {msg.to}", code=204)
    except Exception as e:
        return Error(message=f"error servidor: {e}",code=500)


def verification_code(userId: str, code: CodeVerification) -> Union[None, Error]:
    """Business rules:
            1.- User and code received not empty.
            2.- User exists in the system repository.
            3.- The code is the same as the one sent to the user.
            4.- User account is activated

    Args:
        userId (str): _description_
        code (CodeVerification): _description_

    Returns:
        Union[None, Error]: _description_
    """
    #1
    if code is None or userId is None or userId=="" or len(userId)-24!=0:
        return Error(
            message="No puedo responder a esta solicitud",
            code=403
        )
    
    #2
    userId = ObjectId(userId)
    user_repository = COLLECTION.find_one(filter={"_id": userId})
    
    if not user_repository: 
        return Error(
            message="Usuario no encontrado",
            code=404
        )
    
    #3 
    code_verification = dict(code)
    if user_repository["codeVerification"] != code_verification["code"] or user_repository["emailVerified"]:
        return Error(
            message="Usuario no autorizado",
            code=401
        )
    
    #4
    COLLECTION.update_one(filter={"_id": userId}, update={"$set": {"emailVerified":True}})
    return Error(message=f"Cuenta {user_repository['email']} activada", code=204)  # Verificacion exitosa

def profile(userId: str) -> Union[Profile, Error]:
    """Business rules:
        1.- Id user not empty
        2.- There is a user associated to that Id in the repository.
        3.- The email has been verify
        4.- We return information of the user as a profile.

    Args:
        userId (str): _description_

    Returns:
        Union[Profile, Error]: _description_
    """
    
    #? 1
    if userId is None or userId=="" or len(userId)-24!=0:
        return Error(
            message="No puedo responder a esta solicitud",
            code=403
        )
    
    #? 2
    userId = ObjectId(userId)
    user_repository = COLLECTION.find_one(filter={"_id": userId})
    
    if not user_repository: 
        return Error(
            message="Usuario no encontrado",
            code=404
        )
        
    #? 3
    if not user_repository["emailVerified"]: 
        return Error(
            message="Email no verificado",
            code=406
        )
    
    #? 4
    lastUpdateFace = user_repository['lastUpgradeFace'] if user_repository['lastUpgradeFace'] else date(1999, 8, 8)
    return Profile(userId=str(userId),user=user_repository['name'],email=user_repository['email'],emailVerified=user_repository['emailVerified'],lastUpgradeFace=lastUpdateFace);



def delete_account(userId: str) -> Union[Error, None]:
    """Business rules:
        1.- Id user not empty
        2.- There is a user associated to that Id in the repository.
        3.- We delete the user from the database.

    Args:
        userId (str): _description_

    Returns:
        Union[Error, None]: _description_
    """
     #? 1
    if userId is None or userId=="" or len(userId)-24!=0:
        return Error(
            message="No puedo responder a esta solicitud",
            code=403
        )
    
    #? 2
    userId = ObjectId(userId)
    user_repository = COLLECTION.find_one(filter={"_id": userId})
    
    if not user_repository: 
        return Error(
            message="Usuario no encontrado",
            code=404
        )
    
    #? 3
    COLLECTION.delete_one(filter={"_id": userId});
    return Error(
            message="",
            code=204
        )
    
    
def reset_password(forgot_password: ForgotPassword) -> Union[TokenSession, Error]:
    """Business rules:
        1.- Validate non-empty or null mail
        2.- Validate existing mail in the database
        3.- Validation of verified email
        4.- Send code to reset password

    Args:
        forgot_password (ForgotPassword): _description_
    """
    
    #? 1
    if forgot_password is None:
        return Error(
            message="Sin respuesta",
            code=403
        )
    
    #? 2
    user = dict(forgot_password)
    #* check if email is email or userId
    #** detect on body 
    userId = ObjectId(user['email']) if _is_hex(user["email"]) else ""
    print(userId)    #** search on database depending userId 
    user_repository = COLLECTION.find_one(filter={"email":user["email"]}) if userId == "" else COLLECTION.find_one(filter={"_id": userId})
    
    """user_repository = COLLECTION.find_one(filter={"email":forgot_password["email"]})
    userId = ObjectId(forgot_password["email"]) if user_repository is None else ""
    user_repository = COLLECTION.find_one(filter={"_id": userId}) if user_repository!="" else user_repository
     """   
    if not user_repository:
        return Error(
            message="Correo asociado a ninguna cuenta", 
            code=404
        )
    
    #? 3
    
    #? 4
    verification_code = generator_code()
    userId = str(user_repository["_id"])
    userId = ObjectId(userId)
    COLLECTION.update_one(filter={"_id": userId}, update={"$set": {"codeVerification":verification_code}})
    
    username = user_repository["name"]
    
    
    email_body = f"""
    Hola {username},

    Utiliza el siguiente codigo de verificacion, dentro de la apliacion para confirmar el cambio de contraseña
    de tu cuenta.
    
    Codigo de verificacion: {verification_code}
    
    Este codigo de verificacion no caducara, pero puedes solicitar otro desde la app
     
    Saludos!
    SafUAMI by SoftMinds
    """ 
    
    
    msg = Email(
        to=user_repository["email"],
        subject="SafUAMI Reset password",
        body=email_body
    )
    
    message = MIMEText(msg.body, "html")
    message["From"] = USERNAME
    message["To"] = msg.to#",".join(msg.to)
    message["Subject"] = msg.subject
    
    try:
        smtp = SMTP(HOST,PORT)
        status_code, response = smtp.ehlo()
        print(f"[*] Echoing the server: {status_code} {response}")
        
        status_code, response = smtp.starttls()
        print(f"[*] Starting TLS connection: {status_code} {response}")
        
        status_code, response = smtp.login(USERNAME,PASSWORD)
        print(f"[*] Logging in: {status_code} {response}")
        
        smtp.send_message(message)
        
        token = generator_token({"userId":str(user_repository["_id"]),"name": user_repository["name"]})
        return TokenSession(token=token,userId=str(user_repository["_id"]))
        
    except Exception as e:
        return Error(message=f"error servidor: {e}",code=500)
    

def change_password_from_user(userId: str, resetPassword: ResetPassword) -> Union[None, Error]:
    """business rules:
        1. User id and request body not empty are needed.
        2. Verify that the code inside the request is the same as the one that was sent by mail.
        3. Update password in the database.
        4. Send confirmation of password change by email.

    Args:
        userId (str): _description_
        resetPassword (ResetPassword): _description_

    Returns:
        Union[None, Error]: _description_
    """
    
    #? 1
    
    #* Check user id not empty and exist on database
    userId = ObjectId(userId) if userId!="" and _is_hex(userId) else ""
    user_repository = COLLECTION.find_one(filter={"_id": userId}) if userId!="" else ""
    
    if user_repository == "" or not user_repository:
        return Error(
            message="Usuario no encontrado",
            code=404
        )
    
    
    #* chech all body request not empty
    reset = dict(resetPassword)
    if not resetPassword or len(reset['code'])!=8 or reset['password']=="" :
        return Error(
            message="No puedo responder a esta peticion",
            code=403
        )
        
    
    #? 2
    
    #* check code
    check_code: bool = reset['code'] == user_repository['codeVerification']
    if not check_code:
        return Error(
            message="Codigo erroneo",
            code=401
        )
    #** active account if is needed
    if not user_repository['emailVerified']:
        # !print("cuenta no activa")
        COLLECTION.update_one(filter={"_id": userId}, update={"$set": {"emailVerified":True}})
    #? 3
    
    #* create hash password
    new_password, new_salt = hash_password(reset['password'])
    
    #* update password and salt
    COLLECTION.update_one(filter={"_id": userId}, update={"$set": {"hashPassword":new_password}})
    COLLECTION.update_one(filter={"_id": userId}, update={"$set": {"saltPassword":new_salt}})
    
    #? 4
    username = user_repository["name"]
    
    
    email_body = f"""
    Hola {username},

    Haz cambiado tu contraseña con exito.
     
    ¡Saludos cordiales!
    SafUAMI by SoftMinds
    """ 
    
    
    msg = Email(
        to=user_repository["email"],
        subject="SafUAMI Updated password",
        body=email_body
    )
    
    message = MIMEText(msg.body, "html")
    message["From"] = USERNAME
    message["To"] = msg.to#",".join(msg.to)
    message["Subject"] = msg.subject
    
    try:
        smtp = SMTP(HOST,PORT)
        status_code, response = smtp.ehlo()
        print(f"[*] Echoing the server: {status_code} {response}")
        
        status_code, response = smtp.starttls()
        print(f"[*] Starting TLS connection: {status_code} {response}")
        
        status_code, response = smtp.login(USERNAME,PASSWORD)
        print(f"[*] Logging in: {status_code} {response}")
        
        smtp.send_message(message)
        
        return Error(message="Actualizacion completada", code=204)
        
    except Exception as e:
        return Error(message=f"error servidor: {e}",code=500)