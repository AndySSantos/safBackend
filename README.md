## Proyecto SafUAMI

# Descriptcion:
Este proyecto se trata sobre un mecanismo nuevo de seguridad para los accesos a la universidad Autonoma Metropolitana - Iztapala, de donde actualmente el acceso se realiza mediante targetas fisicas, sin embargo estas pueden extraviarse 
lo que resulta en que no estar seguros si la persona que ingresa a las instalaciones de la universidad sea un integrante de la comunidad universitaria, por lo que estre proyecto (fase prototipo) utiliza multiples tecnologias de la ciencias de la computacion
incluyendo Machine Learning, analisis biometrico, bases de datos e ingenieria de software.

El conjunto de todas las anteriores diciplinas me permitio, en conjunto a mi asesor de proyecto de titulacion Benjamin Moreno Montiel, construir un sistema (prototipo) de acceso mediante reconocimiento facial, mediante una aplicacion movil, la cual se conecta aun servidor 
que se encargara de establecer quien accedera, mediante un proceso biometrico.

# Ademas:
Este es el backend del proyecto, donde se encuentra el modelo de reconocimiento facial, el API de conexion entre cliente[Flutter movil app]-servidor[fastAPI], la conexion a la base de datos No-SQL local donde se hicieron pruebas. La parte del frontend se encuentra en el 
repositorio https://github.com/AndySSantos/safFrontend
