
# Correr contenedor
# docker run -d --name mongodb -p 27017:27017 mongo

# Conectar a mongo
# docker exec -it mongodb mongosh

from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/')

data_base = client['safDB']