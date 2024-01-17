def turnstileEntity(item) -> dict:
    return {
        "id": str(item["_id"]),
        "gate": item["gate"],
        "location": item["location"],
        "urlPhoto": item["urlPhoto"],
        "state": item["state"]
    }
    
def turnstilesEntity(entity) -> list:
    return [turnstileEntity(item) for item in entity]