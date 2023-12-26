def accessEntity(item) -> dict:
    return {
        "id": item["id"],
        "date": item["date"],
        "state": item["state"],
        "userId": item["userId"],
        "turnstileId": item["turnstileId"]
    }
    

def accessesEntity(entity) -> list:
    return [accessEntity(item) for item in entity]