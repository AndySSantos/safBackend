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

import shutil
import os
import tarfile
import zipfile
import re
from fastapi import HTTPException, UploadFile, File
from saf.OptimSAF import *

COLLECTION = data_base['user']
COLLECTION_T = data_base['turnstile']


def system_autentication_facial(userId:str, image:str,turnstileId:str)->Error:
    #? 1
    #* Check if userId is not empty and in the correct format
    userId = ObjectId(userId) if userId and ObjectId.is_valid(userId) else None

    if not userId:
        return Error(
            message="Invalid User ID",
            code=400
        )

    #* Check if there is a user associated with the id in the repository
    user_repository = COLLECTION.find_one({"_id": userId})

    if not user_repository:
        return Error(
            message="User not found",
            code=404
        )
    #? 2
    #* Check if turnstileId is not empty and in the correct format
    turnstileId = ObjectId(turnstileId) if turnstileId and ObjectId.is_valid(turnstileId) else None

    if not turnstileId:
        return Error(
            message="Invalid turnstile ID",
            code=400
        )

    #* Check if there is a user associated with the id in the repository
    turnstile_repository = COLLECTION_T.find_one({"_id": turnstileId})

    if not turnstile_repository:
        return Error(
            message="Turnstile not found",
            code=404
        )
    
    gestor = Gestor('./saf/dataset/faces')
    
    print(userId)
    print(f'Imagen: {image}')
    print(turnstileId)
    match_user = gestor.recognition(image)
    match_user = match_user[:match_user.find('.')] if match_user!='' or match_user!='Unknown' else 'Unknown'
    print(f'Usuario: {match_user}')
    os.remove(image)
    if match_user != str(userId):
        return Error(message="Acceso denegado", code=401)
    return Error(message="Acceso concedido", code=201)