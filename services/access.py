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

COLLECTION = data_base['user']


def system_autentication_facial(userId:str, image:str,turnstileId:str)->Error:
    print(userId)
    print(image)
    print(turnstileId)
    return Error(message="Coincidencia", code=201)