# 🐍 Basilisk 🐍

### Version 1.0.0

#### A Tool using Shodan and RTSP to find vulnerable cameras around the world.

![](basilisk.PNG)

[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://forthebadge.com)
[![forthebadge](https://forthebadge.com/images/badges/built-with-love.svg)](https://forthebadge.com)

### 🛠 Installation

```sh
git clone https://github.com/spicesouls/basilisk
cd basilisk && pip install -r requirements.txt
chmod +x basilisk.py
```

### 📃 Usage

```sh
./basilisk.py [ SHODAN API KEY ] -t [ THREAD COUNT ]
```

<pre>┌──────────────────────────────────────────────────┐
│<font color="#00FF00">__________               .__.__  .__        __    </font>│
│<font color="#00FF00">\______   \_____    _____|__|  | |__| _____|  | __</font>│
│<font color="#00FF00"> |    |  _/\__  \  /  ___/  |  | |  |/  ___/  |/ /</font>│
│<font color="#00FF00"> |    |   \ / __ \_\___ \|  |  |_|  |\___ \|    &lt; </font>│
│<font color="#00FF00"> |______  /(____  /____  &gt;__|____/__/____  &gt;__|_ \</font>│
│<font color="#00FF00">        \/      \/     \/                \/     \/</font>│
├───────────────┬─────────────────┬────────────────┤
│ <font color="#00FFD7">By SpiceSouls</font> │ <font color="#00FFD7">Beyond Root Sec</font> │ <font color="#00FFD7">Version: 1.0.0</font> │
└───────────────┴─────────────────┴────────────────┘

[<span style="background-color:#00AFFF"><font color="#000000">!</font></span>] Final Results:
+----------------+----------------+---------+---------+
|       IP       | Authentication | Country |   City  |
+----------------+----------------+---------+---------+
| 103.242.236.2  |  admin:admin   |  India  | Chennai |
| 179.155.126.29 |  admin:admin   |  Brazil | Uberaba |
+----------------+----------------+---------+---------+</pre>

### 📌 To Do

* 💹 Add Honeypot Detection 

* ❎ Add 'Timeouts' to speed up the probing process

* ❎ Add option to use Proxies

* ❎ Add option to use Tor (?)

My Blog: https://beyondrootsec.wordpress.com

BTC Donations: 1CQvmpRCDasK7YKyjsQTZPUobRygqt86t7

**🚧! THIS IS FOR STRICTLY EDUCATIONAL PURPOSES, I AM NOT RESPONSIBLE FOR YOUR USE OF THIS !🚧**
