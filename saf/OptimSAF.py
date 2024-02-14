import os, sys, shutil
import random
import cv2 as cv
import numpy as np
import math
import torch, face_recognition
import torchvision.transforms as transforms
from torch.autograd import Variable
from torchvision.models import resnet18
from PIL import Image
from saf.face import Face


class Detector(Face):
    
    def __init__(self) -> None:
        super().__init__() 

    
    def configure_dataset(self)-> None:
        
        self.__detect_face()
        #self.__regerate_dataset_by_face_delimited()
        
    def __detect_face(self):
       #invoque delimiter face openCV
        delimiter = cv.CascadeClassifier('./saf/utils/haarcascade_frontalface_default.xml') 
        people = os.listdir(self.data_path)
        if '.DS_Store' in people:
            people.remove('.DS_Store')
        if 'faces'in people :
            people.remove('faces')              
        
        if len(people)==0:
            return   
        print(f'Personas: {people}')
        #delimit to face
        id_photo = 0
        photos = []
        for person in people:
            if person in self.track_people: 
                continue
            id_photo = 1
            photos = os.listdir(self.data_path+'/'+person)
            if '.DS_Store' in photos:
                photos.remove('.DS_Store')
            for photo in photos:
                
                #OpenCv algorithm
                camera = cv.imread(self.data_path+'/'+person+"/"+photo)
                gray_scale = cv.cvtColor(camera,cv.COLOR_BGR2GRAY) 
                id_capture = camera.copy()
                
                face = delimiter.detectMultiScale(gray_scale,1.3,5)
                for(x,y,e1,e2) in face:
        
                    snap=id_capture[y:y+e2,x:x+e1] 
                    snap = cv.resize(snap,(224,224),interpolation=cv.INTER_CUBIC) 
                    cv.imwrite('{}/image_{}.jpg'.format(self.data_path+'/'+person,id_photo),snap)
                    
                id_photo+=1
                
                os.remove(self.data_path+'/'+person+"/"+photo)
            if id_photo >4: 
                self.track_people.append(person) 

    def __regerate_dataset_by_face_delimited(self):
        path_origin = ''
        people = os.listdir(self.data_path)
        if '.DS_Store' in people:
            people.remove('.DS_Store')
        if 'faces'in people :
            people.remove('faces')
        
        if len(people)==0:
            return              
        
        #taking min_pictures by person using random selection
        people = list(filter(lambda x: len(os.listdir(self.data_path+'/'+x))>= self.min_pictures, people))
        
        for person in people:
            path_origin = self.data_path+'/'+person
            photos_by_person = set(os.listdir(path_origin))
            
            photos_to_use = set(random.sample(os.listdir(path_origin),self.min_pictures))
            
            photos_no_use = list(photos_by_person - photos_to_use)
            
            for photo in photos_no_use:
                os.remove(self.data_path+'/'+person+'/'+photo)
                
class Selector():
    
    def __init__(self) -> None:
        self.__configuration()
    
    def __configuration(self)->None:
        # Define the transformation to adapt the images to the ResNet input.
        self.transform = transforms.Compose([
            transforms.Resize((224,224)),
            transforms.ToTensor(),
        ])
        
        # Load the pretrained ResNet18 model
        self.model = resnet18(pretrained=True)
        self.model.eval()

    def evaluate_illumination(self,image_path:str):
        # load image
        image = Image.open(image_path).convert('RGB')
        image = self.transform(image).unsqueeze(0)

        # get output ResNet18 model
        with torch.no_grad():
            output = self.model(Variable(image))

        # Return illumination prediction (higher probability)
        return output[0][0].item()

    def select_best_image(self,folder_path:str) -> str: 
        images = os.listdir(folder_path)
        images_jpg = list(filter(lambda x: x.lower().endswith('.jpg'), images))
        images = images_jpg.copy()
        mejores_iluminaciones = []

        for image in images:
            image_path = os.path.join(folder_path, image)
            iluminacion = self.evaluate_illumination(image_path)
            mejores_iluminaciones.append((image_path, iluminacion))

        # Select the image with the best illumination
        best_image = max(mejores_iluminaciones, key=lambda x: x[1])[0]

        return best_image
    def get_best_image(self, folder_src:str, folder_dst:str)-> None:
        #path from best image
        best_image = self.select_best_image(folder_src)
        #copy image
        shutil.copyfile(best_image, folder_dst)
        #remove folder source
        shutil.rmtree(folder_src)
 
def face_confidence(face_distance,face_match_threshold=0.6):
  range = (1.0- face_match_threshold)
  linear_val = (1.0-face_distance)/ (range*2.0)

  if face_distance > face_match_threshold:
    return str(round(linear_val*100,2))+'%'
  else:
    value = (linear_val+((1.0-linear_val)* math.pow((linear_val-0.5)*2,0.2)))*100
    return str(round(value,2))+'%'

class Gestor:
  face_locations = []
  face_encodings = []
  faces_names=[]
  known_face_encodings=[]
  known_face_names=[]
  process_current_frame= True

  def __init__(self, dataset_path):
     self.encode_faces(dataset_path)

  def encode_faces(self, dataset_path) -> None:
    imagenes = os.listdir(dataset_path)
    imagenes_jpg = list(filter(lambda x: x.lower().endswith('.jpg'), imagenes))
    imagenes = imagenes_jpg.copy()

    for image in imagenes:
      face_image = face_recognition.load_image_file(f'{dataset_path}/{image}')
      face_encoding = face_recognition.face_encodings(face_image)[0]
      self.known_face_encodings.append(face_encoding)
      self.known_face_names.append(image)

    print(f'Usuarios: {self.known_face_names}')

  def recognition(self, image_path:str) -> None:
    name = ''
    confidence = ''
    frame = cv.imread(image_path)
    small_frame = cv.resize(frame,(0,0),fx=0.25,fy=0.25)
    rgb_small_frame = small_frame[:,:,::-1]

    self.face_locations = face_recognition.face_locations(rgb_small_frame)
    self.face_encodings = face_recognition.face_encodings(rgb_small_frame,self.face_locations)

    self.faces_names=[]
    for face_encoding in self.face_encodings:
        matches = face_recognition.compare_faces(self.known_face_encodings,face_encoding)
        name = 'Unknown'
        confidence = 'Unknown'


        face_distances = face_recognition.face_distance(self.known_face_encodings, face_encoding)
        best_math_index = np.argmin(face_distances)

        if matches[best_math_index]:
          name = self.known_face_names[best_math_index]
          confidence = face_confidence(face_distances[best_math_index])


        self.faces_names.append(f'{name}({confidence})')
      #self.process_current_frame = not self.process_current_frame
    print(f'Usuario: {name}')
    return name
    #self.face_locations.clear()
    #self.face_encodings.clear()
      


#Test
if __name__=='__main__':
    
    """selector = Selector()
    userId = 'Arnold'
    selector.get_best_image('./dataset/Arnold',f'./dataset/{userId}.jpg')"""
    gestor = Gestor('./saf/dataset/faces')
    userId='Arnold'
    match_user = gestor.recognition('./saf/otros/spencer.jpg')
    match_user = match_user[:match_user.find('.')] if match_user!='' or match_user!='Unknown' else 'Unknown'
    print(f'Usuario: {match_user}')
    """detector = Detector()
    detector.configure_dataset()
    print(detector.track_people)
    
    userId = 'Arnold'
    if not userId in detector.track_people:
        print("Registro facial erroneo")
    
    selector = Selector()
    selector.get_best_image(f'./dataset/{userId}',f'./dataset/faces/{userId}.jpg')
    print('Registro facial existoso')"""
    
    