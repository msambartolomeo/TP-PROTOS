# TP-PROTOS
# Grupo 8
## Integrantes
+ Juan Manuel Negro - Legajo 61225
+ Mauro Daniel Sambartolomeo - Legajo 61279
+ Agustín Omar Morantes - Legajo 61306

## _Proxy SOCKSv5_
Se implementó un _proxy SOCKSv5_ utilizando los _RFCs_ 1928 y 1929. A diferencia de el estándar pedido, el _proxy_ sólo
acepta conexiones de tipo _TCP_, y no _UDP_, no provee soporte para autenticación mediante _GSSAPI_, y solo acepta 
pedidos del comando _CONNECT_, todas estas decisiones fueron aceptadas por la Cátedra. 

Además, el _proxy_ también hace un _log_ a `stdout` de las conexiones realizadas y, si está habilitado el _password
dissector_, también lo hace de los usuarios y constraseñas que son ingresadas mediante el protocolo _POP3_. 

## Protocolo de monitoreo y administración _SHOES_
En el archivo `shoes-protocol.txt` se encuentra la descripción del protocolo de monitoreo y administración diseñado. Se 
encuentra detallado en estilo RFC para que sea posible su implementación y extensión. Se lo nombró _SHOES_ en relación a
_SOCKSv5_, y porque hace referencia a la frase _**Sho**uld **Es**tablish a connection_.

Se lo diseñó como protocolo binario basado en _TCP_ y orientado a sesión, tomando similitudes del protocolo _SOCKSv5_.
Se podrán encontrar más detalles sobre decisiones de implementación, problemas encontrados, y posibles extensiones en
el informe provisto por el grupo.

## Guía de instalación
1. Primero, correr desde la carpeta raíz del proyecto el comando `make` para compilar tanto el _proxy_ como el cliente 
de configuración.
   
2. Luego, los binarios se encontrarán en la subcarpeta `build` con los nombres `socks5d` para el _proxy SOCKSv5_ y `shoesc`
para el cliente de _SHOES_.
   
3. Ejecutar los binarios con los flags deseados. Estos binarios se llaman `socks5d` y `shoesc`, respectivamente para
servidor y cliente; y se encuentran tanto en los directorios `server` y `client` como también en el directorio `build`.


## Guía de uso
Se prove un archivo llamado `socks5d.8`, que se puede utilizar con el comando `man ./socks5d.8` para poder ver las
opciones de uso. Sin embargo, también se podrán ver aquí.

### Servidor
Corriendo el comando `./build/socks5d` se iniciará el servidor _SOCKSv5_, y se pueden utilizar las distintas opciones
como argumentos:
+ `-h`     Imprime la ayuda y termina.
+ `-v`     Imprime información sobre la versión versión y termina.
+ `-l dirección-socks`
Establece la dirección donde servirá el proxy SOCKSv5.  Por defecto escucha en todas las interfaces.
+ `-N`     Deshabilita los _passwords disectors_.
+ `-L dirección-de-management`
Establece la dirección donde servirá el servicio de _management_. Por defecto escucha únicamente en _loopback_.
+ `-p puerto-local`
Puerto _TCP_ donde escuchará por conexiones entrantes _SOCKSv5_.  Por defecto el valor es 1080.
+ `-P puerto-conf`
Puerto _TCP_ donde escuchará por conexiones entrante del protocolo de configuración. Por defecto el valor es 8080.
+ `-u user:pass`
Declara un usuario del _proxy SOCKSv5_ con su contraseña. Se puede utilizar hasta 10 veces.
+ `-U user:pass`
Declara un usuario para el servicio de configuración con su contraseña. Se puede utilizar hasta 10 veces.


El registro de acceso del _proxy_ consiste en:
+ **Fecha**  que se procesó la conexión en formato _ISO-8601_.  Ejemplo 2022-06-15T19:56:34Z.
+ **Nombre** de usuario que hace el requerimiento.  Ejemplo juan.
+ **Tipo de registro**. Siempre el caracter A.
+ **Direccion IP origen** desde donde se conectó el usuario.  Ejemplo ::1.
+ **Puerto origen** desde donde se conectó el usuario.  Ejemplo 54786.
+ **Destino** a donde nos conectamos. nombre o dirección _IP_ (según _ATY_).  Ejemplo www.itba.edu.ar.  Ejemplo ::1.
+ **Puerto destino**. Ejemplo 443.
+ **_Status code_** de _SOCKSv5_. Ejemplo 0.

El registro de monitorio del _sniffer_ de contraseñas consiste en:
+ **Fecha** que se procesó la conexión en formato _ISO-8601_.  Ejemplo 2020-06-15T19:56:34Z.
+ **Nombre de usuario** que hace el requerimiento.  Ejemplo juan.
+ **Tipo de registro**. Siempre el caracter P.
+ **Protocolo** del que se trata. _HTTP_ o _POP3_.
+ **Destino** a donde nos conectamos. Nombre o dirección _IP_ (según ATY).  Ejemplo www.itba.edu.ar.  Ejemplo ::1.
+ **Puerto destino** Ejemplo 443.
+ **Usuario** Usuario descubierto.
+ **_Password_** descubierta.

### Cliente
Corriendo el comando `./build/shoesc` se iniciará el servidor _SHOES_, y se pueden utilizar las distintas opciones
como argumentos:
+ `-h`               Imprime la ayuda y termina.
+ `-u <name>:<pass>` Usuario admin y contraseña para acceder al servidor _SHOES_.
+ `-g`               Lista los usuarios del _proxy SOCKSv5_.
+ `-m `              Muestra las métricas volátiles del servidor. Estas son la cantidad de conexiones históricas, la cantidad de 
conexiones concurrentes, y la cantidad de _bytes_ transferidos. 
+ `-s`               Muestra el estado del _password spoofing_.
+ `-s1 `             Enciende el _password spoofing_.
+ `-s0`              Desactiva el _password spoofing_.
+ `-b <size>`        Cambia el tamaño del _buffer_. Este valor no podrá ser mayor a 65535 _bytes_.
+ `-a <name>:<pass>` Agrega un nuevo usuario del _proxy SOCKSv5_ con dichas `name` y `pass`.
+ `-r <name>`        Elimina un usuario del _proxy SOCKSv5_.
+ `-e <name>:<pass>` Edita un usuario del _proxy SOCKSv5_. Se reemplazará el usuario `name` por la nueva contraseña `pass`.
+ `-l <FQDN/IP>`     Dirección del _proxy SOCKSv5_ a configurar.
+ `-p <puerto>`      Puerto del servicio de _management_ del _proxy_.
+ `-v`               Imprime información sobre la versión de _shoesc_ y termina.
