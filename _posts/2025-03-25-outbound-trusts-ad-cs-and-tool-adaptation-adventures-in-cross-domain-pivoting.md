---
layout: post
read_time: true
show_date: true
title: Outbound Trusts, AD CS, and Tool Adaptation, Adventures in Cross-Domain Pivoting
date: 2025-03-25 8:00:00 -0100
description: A blog post to explain how we can perform cross-domain pivoting through an outbound trust.
img: posts/20250325/ad-red-team.jpeg
tags: [Red Team, Windows, Pivoting, AD CS, Active Directory]
author: Dram4ck
mathjax: yes
---
# Table of Content

* [Introduction](#introduction)
* [Setting the Scene](#setting-the-scene)
* [Steps to Victory](#steps-to-victory)
    * [Step 1: Getting a Foothold](#step-1-getting-a-foothold)
    * [Step 2: Extracting the Trust Account](#step-2-extracting-the-trust-account)
        * [Confirm the Trust Exists](#confirm-the-trust-exists)
        * [Find the Trust Object](#find-the-trust-object)
        * [Extract the Trust Account Hash](#extract-the-trust-account-hash)
        * [Alternate Method: Dump It From Memory](#alternate-method-dump-it-from-memory)
        * [Accessing Resources in domain-b.local](#accessing-resources-in-domain-b-local)
    * [Step 3: Exploiting AD CS](#step-3-exploiting-ad-cs)
        * [Certify on Windows: The DIY Method](#certify-on-windows-the-diy-method)
            * [The Problem](#the-problem)
                * [Not Working Case 1: Using a Non-Domain-Joined Machine with an Injected TGT](#not-working-case-1)
                * [Not Working Case 2: Using a Domain-A User Context with an Injected TGT](#not-working-case-2)
                * [Not Working Case 3: Using a Domain-B User Context](#not-working-case-3)
            * [The Working Case:](#the-working-case)
                * [Step 1: Enumerating Vulnerable Templates](#step-1-enumerating-vulnerable-templates)
                * [Step 2: Requesting a Certificate](#step-2-requesting-a-certificate)
                * [Step 3: Patching Certify](#step-3-patching-certify)
                * [Step 4: Resolving Dependency Errors](#step-4-resolving-dependency-errors)
                * [Step 5: Getting a Certificate](#step-5-getting-a-certificate)
                * [Step 6: Converting the Certificate](#step-6-converting-the-certificate)
                * [Step 7: Obtaining a TGT](#step-7-obtaining-a-tgt)
                * [Step 8: Authenticating and Escalating](#step-8-authenticating-and-escalating)
            * [Why Patching Certify?](#why-patching-certify)
        * [Certipy on Linux: The Simplified Approach](#certipy-on-linux-the-simplified-approach)
            * [Step 1: Preparing the Ticket](#step-1-preparing-the-ticket)
            * [Step 2: Validating the Ticket](#step-2-validating-the-ticket)
            * [Step 3: Finding Vulnerable Templates](#step-3-finding-vulnerable-templates)
            * [Step 4: Requesting a Certificate](#step-4-requesting-a-certificate)
            * [Step 5: Authenticating and Escalating](#step-5-authenticating-and-escalating)
* [Final Thoughts](#final-thoughts)

# 1. Introduction <a id="introduction"></a>

In Active Directory environments, [trust relationships](https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust#trust-relationship-flows) enable multiple domains to work together, allowing authentication and access to other domain's resources seamlessly. But what happens if this link becomes a vulnerability? That's exactly what this blog post is intended to cover: Using an outbound trust relationship to pivot from a compromised domain to a second domain, ultimately compromising it with a misconfiguration in an Active Directory Certificate Services (AD CS) template.

What started out as a simple "Why doesn't Certify work on a non-domain host?" question very quickly became a challenge mixing trust Account, NTLM vs. Kerberos issues and privilege escalation via AD CS.
In this post, I'll go through every step of the way, from extracting the trust account to compromising the second domain.

Whether you're a Red Teamer looking for new methods or a Blue Teamer wanting to strengthen your environment, this blog post highlights the risks associated with outbound trust links, as well as problems associated with AD CS misconfigurations.


---
# 2. Setting the Scene <a id="setting-the-scene"></a>

So let's put it on stage:

- **`domain-a.local`**: The compromised domain.
- **`domain-b.local`**: The target domain

Between these two domains we find an outbound approval relationship, where `domain-a.local` trusts `domain-b.local`. This allows `domain-b.local`'s resources to authenticate to `domain-a.local`, but not vice versa. To an admin, this configuration might seem flawless, but we're about to see that it isn't.

![Lab Environment](assets/img/posts/20250325/lab-environment.png)

The lab setup:

- **DC01**: Domain Controller for `domain-a.local` (192.168.1.201).
- **DC02**: Domain Controller for `domain-b.local` (192.168.1.202).
- **Workstations**: A Windows 11 machine (192.168.1.139) and a Linux box for maximum versatility during the attack.

**The goal ?** Leverage the trust account used to manage the outbound relationship and pivot into `domain-b.local`.

---
# 3. Steps to Victory <a id="steps-to-victory"></a>

## Step 1: Getting a Foothold <a id="step-1-getting-a-foothold"></a>

First of all, I need access to `domain-a.local`. Whether it's through phishing or an exploited vulnerability, we'll assume that I've been able to obtain initial access and then the credentials for account `admin-a@domain-a.local`. 

## Step 2: Extracting the Trust Account <a id="step-2-extracting-the-trust-account"></a>

### **2.1 Confirm the Trust Exists**  <a id="confirm-the-trust-exists"></a>

First, I confirmed the outbound trust with a PowerShell cmdlet:
```powershell
Get-ADTrust -Filter * | Select Direction, Source, Target
```
![Trust Link](assets/img/posts/20250325/trust-link.png)

The output revealed the trust relationship between `domain-a.local` and `domain-b.local`.

### 2.2 Find the Trust Object <a id="find-the-trust-object"></a>

I then searched for the trust object via LDAP to find its GUID:

```powershell
Get-ADObject -LDAPFilter "(objectCategory=trustedDomain)"
```
![Trust Object](assets/img/posts/20250325/trust-object.png)

### **2.3.1 Extract the Trust Account Hash**  <a id="extract-the-trust-account-hash"></a>

With the GUID in hand, it was time to use **[Mimikatz](https://github.com/gentilkiwi/mimikatz)**. So, I launched a **[DCSync](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync)** attack to extract the NT hash of the trust account:
```cmd
lsadump::dcsync /domain:domain-a.local /guid:{GUID}
```
![DCSync Result](assets/img/posts/20250325/dcsync-result.png)

The `[OUT]` hash was what I needed. Once recovered, I used **Rubeus** to request a **TGT (Ticket-Granting Ticket)** for the trust account (`DOMAIN-A$`):
```cmd
.\Rubeus.exe asktgt /domain:domain-b.local /user:DOMAIN-A$ /rc4:<hash> /nowrap /ptt
```
![TGT Obtained](assets/img/posts/20250325/tgt-obtained.png)
This step enabled me to impersonate the trust account in `domain-b.local`, setting the stage for privilege escalation.

### **2.3.2 Alternate Method: Dump It From Memory**  <a id="alternate-method-dump-it-from-memory"></a>

For those who like to take risks, there is an alternative method which consists of extracting the hash of the trust account from the Domain Controller's memory:
```cmd
mimikatz lsadump::trust /patch
```

This is a [riskier approach](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-trust-accountusd-accessing-resources-on-a-trusted-domain-from-a-trusting-domain), as it involves patching the memory, but it’s good to have options .

### **2.4 Accessing Resources in `domain-b.local`**  <a id="accessing-resources-in-domain-b-local"></a>

With the TGT injected, I tried to get the `domain-b.local` information to confirm that the authentication was working:
```powershell
Get-ADDomain -Identity domain-b.local
```
![Domain Interaction](assets/img/posts/20250325/Domain-Interaction.png)

I was officially inside `domain-b.local`.

## Step 3: Exploiting AD CS <a id="step-3-exploiting-ad-cs"></a>

The next step was to target **Active Directory Certificate Services (AD CS)** in `domain-b.local`. A misconfiguration in a template can enable a user to request a certificate for another user and thus perform a privilege escalation. **[ESC1](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#misconfigured-certificate-templates-esc1)** is a good example:

### 3.1 Certify on Windows: The DIY Method <a id="certify-on-windows-the-diy-method"></a>

We're going to start with the most problematic but also the most famous AD CS exploitation tool for Windows, **[Certify](https://github.com/GhostPack/Certify)**.
But we're going to see that in certain contexts, using it can be a challenge.

#### The Problem <a id="the-problem"></a>

After running a number of tests, I discovered that Certify has trouble working from a host outside the domain. I'll start by showing the cases where I was unable to obtain a certificate:

##### Not Working Case 1: Using a Non-Domain-Joined Machine with an Injected TGT <a id="not-working-case-1"></a>

For the first case, I'll try to obtain a certificate via my Windows 11 host outside the domain.

I started by getting a TGT for the trust account as before:

![TGT obtained](assets/img/posts/20250325/tgt-obtained.png)

But when I ran Certify to enumerate AD CS templates, I got an error for **"incorrect credentials"**:

![Certify Error Case1](assets/img/posts/20250325/Certify-Error-Case1.png)

Looking with Wireshark, I could see that a TGS was obtained for the LDAP service from `DC02.domain-b.local`:

![Certify Error Wireshark](assets/img/posts/20250325/Certify-Error-Wireshark.png)

In addition, the following queries showed that Certify was attempting to authenticate to LDAP via NTLM instead of Kerberos (and yes, there's no flag to force Kerberos use), despite obtaining the TGS. Since the tool is used in the context of my local user, the authentication failed:

![Certify Error NTLM Authentication](assets/img/posts/20250325/Certify-Error-NTLM-Authentication.png)

Despite a valid TGT and TGS for the LDAP service, Certify was unable to enumerate LDAP templates due to its dependence on the NTLM protocol for certain queries.

##### Not Working Case 2: Using a Domain-A User Context with an Injected TGT <a id="not-working-case-2"></a>

For the second case, also using the windows 11 host outside the domain.

I used the `runas` command to simulate the context of a `domain-a.local` user:
```cmd
runas /netonly /user:admin-a@domain-a.local powershell
```

Without further adjustments, I can't interact with `domain-b.local`'s LDAP service (which is normal since the trust works the other way around):

![Certify Error Case2 Runas](assets/img/posts/20250325/Certify-Error-Case2-Runas.png)

So I can't list the AD CS templates in `domain-b.local` (either through the LDAP services of DC01 and DC02):

![Certify Error Case2 LDAP](assets/img/posts/20250325/Certify-Error-Case2-LDAP.png)

To get around this, I obtained a TGT for the trust account as in the previous case:

![Tgt obtained](assets/img/posts/20250325/tgt-obtained.png)

Now I can interact with `domain-b.local`'s LDAP service via Kerberos authentication:

![Certify Error Case2 Kerberos](assets/img/posts/20250325/Certify-Error-Case2-Kerberos.png)

Interestingly, I discovered that I could enumerate `domain-b.local`'s AD CS templates indirectly via `DC01.domain-a.local`'s LDAP service and only after injecting the TGT from the trust account:

![Certify Error Case2 Indirect Enumeration](assets/img/posts/20250325/Certify-Error-Case2-Indirect-Enumeration.png)

But a direct enumeration of AD CS templates on `domain-b.local` fails due to the same NTLM authentication issue as seen in case 1:

![Certify Error Case2 Failed Enumeration](assets/img/posts/20250325/Certify-Error-Case2-Failed-Enumeration.png)

So the question I asked myself was the following: Why, using the context of an `domain-a.local` user, am I able to enumerate `domain-b.local`'s ADCS templates but only via `domain-a.local`'s LDAP service and only when I use the trust account's TGT?

So, again I took wireshark to look at this.
In the case where I didn't inject the TGT of the trust account, Certify tries to authenticate directly to `domain-b.local` despite the fact that I gave it `domain-a.local`'s LDAP as an argument, which doesn't work since I'm using the context of a `domain-a.local` user:

![Certify Error Case2 Wireshark](assets/img/posts/20250325/Certify-Error-Case2-Wireshark.png)

Now, the same thing but with the TGT of the trust account injected. Certify uses the TGT to obtain a TGS giving access to `domain-b.local`'s LDAP, despite the fact that I gave `domain-a.local`'s LDAP service as an argument:

![Certify Error Case2 Kerberos Use](assets/img/posts/20250325/Certify-Error-Case2-Kerberos-Use.png)

Certify then tries to authenticate to the `domain-a.local` LDAP using the context of our user in the same domain:

![Certify Error Case2 LDAP Authentication](assets/img/posts/20250325/Certify-Error-Case2-LDAP-Authentication.png)

So, injecting the TGT allowed me to interact with `DC01.domain-a.local`'s LDAP service, while Certify's dependence on the NTLM protocol to enumerate AD CS templates prevented me from interacting directly with `domain-b.local`.

##### Not Working Case 3: Using a Domain-B User Context <a id="not-working-case-3"></a>

For the third case, back on the windows 11 host.

I switched to the context of a `domain-b.local` user (created only for this test) using the `runas` command:
```cmd
runas /netonly /user:admin-b@domain-b.local powershell
```

This time, I successfully enumerated AD CS templates directly on `DC02.domain-b.local`:

![Certify Error Case3](assets/img/posts/20250325/Certify-Error-Case3.png)

NTLM authentication succeeded because the context was the one of a valid `domain-b.local` user:

![Certify Error Case3 NTLM Authentication](assets/img/posts/20250325/Certify-Error-Case3-NTLM-Authentication.png)

Even with AD CS enumeration working, I couldn’t request a certificate:

![Certify Error Case3 Certificate Request](assets/img/posts/20250325/Certify-Error-Case3-Certificate-Request.png)

This time wireshark showed me an attempt to resolve the domain name based on the host name of my machine and not on the domain name given as an argument:

![Certify Error Case3 Certificate Error](assets/img/posts/20250325/Certify-Error-Case3-Certificate-Error.png)

Using the context of a user from domain `domain-b.local` solved the NTLM authentication problem, but still failed to obtain a certificate, due to to Certify’s name resolution behavior.

Despite these failures, there is still one case where Certify is able to obtain a certificate with the trust account. But this will require pivoting to `DC01.domain-a.local`. Using Cetify directly from the domain controller allowed me to bypass the problems I had from a machine not attached to the domain. This blog post does not cover pivoting methods or bypassing AV/EDR systems, as I assume those are already handled.

#### The Working Case: <a id="the-working-case"></a>
##### Step 1: Enumerating Vulnerable Templates <a id="step-1-enumerating-vulnerable-templates"></a>

From `DC01.domain-a.local`, I needed to inject a TGT for the trust account:

![Tgt obtained](assets/img/posts/20250325/tgt-obtained.png)

I enumerated vulnerable certificate templates in the target domain (`domain-b.local`) using Certify:
```cmd
.\Certify.exe find /domain:domain-b.local /vulnerable
```
![Certify Working Enumeration](assets/img/posts/20250325/Certify-Working-Enumeration.png)

Certify confirms that template `ESC1VulnerableTemplate` is vulnerable to ESC1.

##### Step 2: Requesting a Certificate <a id="step-2-requesting-a-certificate"></a>

Next, I attempted to request a certificate for the `administrator@domain-b.local` account:
```cmd
.\Certify.exe request /ca:DC02.domain-b.local\domain-b.DC02-CA /template:ESC1VulnerableTemplate /altname:administrator
```
![Certify Error An Enrollement Policy Server](assets/img/posts/20250325/Certify-Error-An-Enrollment-Policy-Server.png)

But Certify threw an error: **"An enrollment policy server cannot be located."**

##### Step 3: Patching Certify <a id="step-3-patching-certify"></a>

Fortunately, a solution exists.  **[Eliotsehr](https://github.com/Eliotsehr)** offers a patch on a **[Github issue](https://github.com/GhostPack/Certify/issues/13)**. This involves a slight change to the source code.
in the Cert.cs file we need to comment this line :
```
objPkcs10.InitializeFromPrivateKey(context, privateKey, templateName);
```

Then replace with the following content:
```
objPkcs10.InitializeFromPrivateKey(context, privateKey, "");

CX509ExtensionTemplateName templateExtension = new CX509ExtensionTemplateName();
templateExtension.InitializeEncode(templateName);
objPkcs10.X509Extensions.Add((CX509Extension)templateExtension);
```

By initializing the template name as an X.509 extension rather than directly in `InitializeFromPrivateKey`, this seems to get around the problem.

##### Step 4: Resolving Dependency Errors <a id="step-4-resolving-dependency-errors"></a>

When compiling Certify I got a dependency error (due to Visual Studio 2022), just add it to the `packages.config` file:
```
<package id="Interop.CERTENROLLLib" version="1.0.0" targetFramework="net40" developmentDependency="true" />
```

##### Step 5: Getting a Certificate <a id="step-5-getting-a-certificate"></a>

With the patched Certify, I successfully requested the certificate:
```cmd
.\Certify.exe request /ca:DC02.domain-b.local\domain-b-DC02-CA /template:ESC1VulnerableTemplate /altname:administrator
```
![Certify Successful Request](assets/img/posts/20250325/Certify-Successful-Request.png)

##### Step 6: Converting the Certificate <a id="step-6-converting-the-certificate"></a>

Next, I converted the certificate to a format compatible with **Rubeus** for further use:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
![Certify Conversion Command](assets/img/posts/20250325/Certify-Conversion-Command.png)

##### Step 7: Obtaining a TGT <a id="step-7-obtaining-a-tgt"></a>

Using the converted certificate, I requested a TGT for the `administrator@domain-b.local` account:
```cmd
.\Rubeus.exe asktgt /user:administrator /certificate:[CERTIFICATE] /password:[PASSWORD] /nowrap /domain:domain-b.local /ptt
```
![Certify Tgt Request](assets/img/posts/20250325/Certify-TGT-Request.png)

##### Step 8: Authenticating and Escalating <a id="step-8-authenticating-and-escalating"></a>

Now that we have a TGT for `administrator@domain-b.local`, we can imagine any type of scenario such as extracting the NT hast for the krbtgt account:
```cmd
lsadump::dcsync /domain:domain-b.local /user:krbtgt
```
![Certify NTLM Extraction](assets/img/posts/20250325/Certify-NTLM-Extraction.png)

#### Why Patching Certify? <a id="why-patching-certify"></a>

Whether you want to use it with a dotnet loader or just because you prefer to use Windows, you may need (prefer?) to use Certify rather than Certipy.
This just goes to show how important it is to adapt your tools to the scenarios you face.


### 3.2 Certipy on Linux: The Simplified Approach <a id="certipy-on-linux-the-simplified-approach"></a>

For those who prefer to work with Linux, **[Certipy](https://github.com/ly4k/Certipy)** is a game-changer. This tool simplifies the exploitation of AD CS vulnerabilities, and is perfectly compatible with Kerberos. Here's how I used Certipy to identify and exploit a configuration flaw in a template in `domain-b.local`.

#### Step 1: Preparing the Ticket <a id="step-1-preparing-the-ticket"></a>

The first step was to make the TGT of the trust account previously obtained readable by tools on Linux. Using **[Impacket’s ticketConverter](https://github.com/fortra/impacket/blob/master/examples/ticketConverter.py)**  I converted the ticket from `.kirbi` format to `.ccache` format, then set the `KRB5CCNAME` environment variable to point to our converted ticket:
```bash
cat ticket.b64 | base64 -d > ticket.kirbi
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=[PATH]/ticket.ccache
```
![Certipy Ticket Conversion](assets/img/posts/20250325/Certipy-Ticket-Conversion.png)

#### Step 2: Validating the Ticket <a id="step-2-validating-the-ticket"></a>

Before diving deeper, I checked that the TGT was valid by authenticating to `domain-b.local` using **[NetExec](https://github.com/Pennyw0rth/NetExec)** :

![Certipy Tgt Validation](assets/img/posts/20250325/Certipy-TGT-Validation.png)

The successful authentication confirmed the ticket was correctly configured and ready for use.

#### Step 3: Finding Vulnerable Templates <a id="step-3-finding-vulnerable-templates"></a>

Next, I used Certipy to enumerate the AD CS environment in `domain-b.local` to identify misconfigured certificate templates:
```bash
certipy-ad find -k -target DC02.domain-b.local -vulnerable
```
![Certipy Vulnerable Teamplate Discovery](assets/img/posts/20250325/Certipy-Vulnerable-Template-Discovery.png)
```bash
cat 20241209160535_Certipy.txt
```
![Certipy Vulnerable Template Detail](assets/img/posts/20250325/Certipy-Vulnerable-Template-Detail.png)

Certipy quickly discovered that the `ESC1VulnerableTemplate` could be exploited.

#### Step 4: Requesting a Certificate <a id="step-4-requesting-a-certificate"></a>

With the vulnerable template identified, I submitted a certificate request for user `administrator@domain-b.local`. Certify simplified the process, using the TGT to interact with the AD CS:
```bash
certipy-ad req -k -target DC02.domain-b.local -ca "domain-b.DC02-CA" -template "ESC1VulnerableTemplate" -upn administrator
```
![Certipy Certificate Request](assets/img/posts/20250325/Certipy-Certificate-Request.png)

The certificate request was a success, giving me a certificate tied to the domain administrator account.

#### Step 5: Authenticating and Escalating <a id="step-5-authentificating-and-escalating"></a>

Using the obtained certificate, Certipy allowed me to authenticate as `administrator@domain-b.local`, to request a TGT and then to **[UnPac the hash](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash)** for the `administrator` account.
```bash
certipy-ad auth -dc-ip 192.168.1.202 -pfx 'administrator.pfx' -username 'administrator' -domain 'domain-b.local'
```
![Certipy Authentication](assets/img/posts/20250325/Certipy-Authentication.png)
If you’re looking for efficiency, Certipy should be part of your toolkit.

---

# 4. Final Thoughts <a id="final-thoughts"></a>

What started out as a simple question "**_Why does Certify fail from a non-domain-joined machine to exploit through an outbound trust ?_**" evolved into a deeper exploration of how Active Directory works. Through this, I was able to highlight how a trust account can interact with domain services, dig into authentication concerns with NTLM and Kerberos as well as learn to understand the problems associated with tools such as Certify and Certipy.

This journey not only solves the initial problem, but illustrates how an outbound trust combined with a misconfiguration in an AD CS template can become a critical escalation path.
It's a reminder that small obstacles in an operation can lead to big discoveries.
