from __future__ import annotations

from dependencies import *

from schemas.turnstile import *
from datetime import date

from config.database import data_base
from config.security import *
from bson.objectid import ObjectId


COLLECTION = data_base['turnstile']

def create(turnstile :Turnstile) -> Union[None, Error]:
    """Business rules:
        1. Request not empty in any of its fields 2.
        2. Creation in the database

    Args:
        turnstile (Turnstile): _description_

    Returns:
        Union[None, Error]: _description_
    """
    #? 1
    if not turnstile:
        return Error(message="Peticion vacia", code=403)
    
    new_turnstile = dict(turnstile)

    for key, value in new_turnstile.items():
        if value == "" and key != 'id':
            return Error(message=f"Campo {key} vacio", code=403)
    
    #? 2
    #* Take value from StateTurnstile
    new_turnstile['state'] = new_turnstile['state'].value
    
    #* Insert document in collection
    COLLECTION.insert_one(new_turnstile)
    
    return Error(
        message="CREADO",
        code=201
    )


def update_state(turnstile: TurnstileUpdate, turnstileId : str) -> Union[Turnstile, Error]:
    pass


def find_all() -> ElectronicTurnstiles:
    return ElectronicTurnstiles(turnstiles=turnstilesEntity(COLLECTION.find()))

def find_by_id(turnstileId: str) -> Union[Turnstile,Error]:
    """Business rules:
        1. Id in valid format
        2. Id associated to some entity in the repository.
        3. Return Turnstile entity

    Args:
        turnstileId (str): _description_

    Returns:
        Union[Turnstile,Error]: _description_
    """
    
    #? 1
    if not is_hex(turnstileId):
        return Error(
            message="Id erroneo",
            code=401
        )
    #? 2
    turnstileId = ObjectId(turnstileId)
    turnstile_repository = COLLECTION.find_one(filter={'_id':turnstileId})
    if turnstile_repository is None:
        return Error(
            message="Sin coincidencias",
            code=404
        )
    #? 3
    return Turnstile(id=str(turnstileId), gate=turnstile_repository['gate'], location=turnstile_repository['location'],urlPhoto=turnstile_repository['urlPhoto'],state=turnstile_repository['state'])

def remove(turnstileId: str) -> Union[None,Error]:
    """Business rules:
        1. Id in valid format
        2. Id associated to some entity in the repository.
        3. Delete turnstile 

    Args:
        turnstileId (str): _description_

    Returns:
        Union[Turnstile,Error]: _description_
    """
    
    #? 1
    if not is_hex(turnstileId):
        return Error(
            message="Id erroneo",
            code=401
        )
    #? 2
    turnstileId = ObjectId(turnstileId)
    turnstile_repository = COLLECTION.delete_one(filter={'_id':turnstileId})
    print(turnstile_repository)
    if turnstile_repository.deleted_count == 0:
        return Error(
            message="Sin coincidencias",
            code=404
        )
    #? 3
    return Error(
        message="Proceso completado",
        code=204
    )
