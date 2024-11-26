+++
title = 'Windows Password Cracking - Part 1'
date = 2024-11-25T12:34:24+01:00
draft = false
type = "post"
excerpt = "Windows Password Cracking Attack"
authors = ["Hassan AL ACHEK"]
tags = []
categories = []
readingTime = 5  
hero = "/images/winpasscracking.jpg"
+++

# Authentication:
Of course, you have heard this question from an aging person:
"Who are you? You are the child of who?" (Enta eben min :p)

Yeah, and that's exactly what we call authentication. The person wants to know, **"Who are you?"**
Once they know who you are, they’ll say, **"Ohh, that's you, enter, enter."** *(In Lebanon, they’ll say, "Ahhh, eben flen ta3a yl3an le7yet bayak" – okay, at least in Baalbeck.)*

The same applies to a digital system. I want to protect it from unauthorized people, so basically, I should check your identity and verify that you are who you say you are.

## Authentication Factors:
1. Something you know (password, pin code, ...)
2. Something you have (Passport, security key, yubi key, authenticator app)
3. Something you are (Fingerprint, Retina pattern, Face recognition ...)

![Yubi key image](/images/yubikey.jpg)

These security factors may not all be used; it depends on the sensitivity of the information or systems and whether multiple factors of verification are required due to their significance.

# Authorization:
Once you are authenticated, the system now knows who you are, and it’s time to determine what you can do. That’s what we call authorization. 

The privileges and permissions you have depend on whether you are authorized to have them.

# Statistic:
I will provide a link to a Google statistic about password complexity, password reuse, and common passwords.

[Google Statistic - Password](https://storage.googleapis.com/gweb-uniblog-publish-prod/documents/PasswordCheckup-HarrisPoll-InfographicFINAL.pdf)

# How Does Windows Authenticate Users?
The authentication process in windows is a complex process that need an interaction between different component to verify the user.

## Local Security Authority (LSA):
The LSA validates users for local and remote sign-ins and enforces local security policies. LSA handles user authentication and authorization processes. It is also responsible for password changes and access token creation.

### Windows Interactive Logon:
Interactive logon occurs through the interaction of different components:

![Windows Logon Process](/images/logonWindowsProcess.png)

- **The logon process (`Winlogon.exe`):**  
  This is a trusted process responsible for managing security-related user interactions. It coordinates logon, starts the user's first process at logon, and handles logoff. It launches LogonUI for entering passwords at logon, changing passwords, and locking and unlocking the workstation.

- **The logon user interface process (`LogonUI.exe`) and its credential providers:**  
  Winlogon relies on the credential providers installed on the system to obtain a user's account name or password. Credential providers are COM objects located inside DLLs. The default providers are `authui.dll`, `SmartcardCredentialProvider.dll`, and `FaceCredentialProvider.dll`, which support password, smartcard, PIN, and face-recognition authentication. Additional credential providers can be installed to enable Windows to use alternative user-identification mechanisms.


![Credential Providers](/images/credentialprovoders.png)


- **`Lsass.exe` (Local Security Authority Subsystem Service):**  
  This is a user-mode process running the image of `Lsass.exe`, responsible for the local system security policy, user authentication, and sending security audit messages to the event log. This process loads the Local Security Authority service (`Lsasrv.dll`), a library that implements most of its functionality.

- **One or more authentication packages:**  
Authentication packages are DLLs that perform authentication checks. For example:  
1. `Kerberos` is the Windows authentication package for interactive logon to a domain.  
2. `MSV1_0` is the Windows authentication package for interactive logon to a local computer, domain logons to trusted pre-Windows 2000 domains, and cases where no domain controller is accessible.

- **SAM (Security Accounts Manager):**  
1. **Service:** The SAM service is responsible for managing the database that contains the usernames and groups defined on the local machine. It is implemented in the `Samsrv.dll`, which is loaded into the `Lsass` process.  

2. **Database:** The SAM database contains the defined local users and groups, along with their passwords and other attributes. On domain controllers, SAM does not store domain-defined users but holds the system’s administrator recovery account definition and password.

- **Active Directory:**  
  On domain-joined systems, Active Directory is used for authentication, replacing the local SAM database for domain-defined users and groups.



