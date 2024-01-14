from __future__ import annotations

from dependencies import *

from schemas.user import *
from datetime import date

from config.database import data_base
from config.security import *

def create(turnstile :Turnstile) -> Union[None, Error]:
    
    pass


def update_state(turnstile: Turnstile, turnstile_id : str) -> Union[None, Error]:
    pass


