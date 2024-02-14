class Face:
    def __init__(self):
        self._data_ruta = './saf/dataset'  # ruta del dataset original
        self._min_pictures = 5
        self.track_people = []
        
    @property
    def data_path(self):
        return self._data_ruta
    
    
    @property
    def min_pictures(self):
        return self._min_pictures
    
#Pruebas
if __name__ == "__main__":
    fc = Face()
    print(fc.data_path)
