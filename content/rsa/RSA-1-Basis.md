---
title: "RSA n°1 | Principes Fondamentaux"
date: 2022-11-26T12:00:00Z
description: "Fonctionnement du chiffrement RSA"
tags: ["rsa","cryptographie","crypto"]
keywords: ["tuto", "rsa", "RSA", "crypto","maths","euclide","cryptographie","cryptography","pgcd"]
---
[//]: <> (Created By Vozec 26/11/2021)
---

# Introduction
Le chiffrement RSA est utilisé pour chiffrer des communications, il est aujourd'hui souvent utilisé pour les certificats SSL sur internet ou encore les clés de connections via le protocole **ssh**.
Il est dit ``asymétrique`` car il fonctionne par paires de clés. Toute la sécurité de ce chiffrement repose sur le fait qu'il est aujourd'hui infiniment long de factoriser un nombre cryptographique rapidement .  
*Ronald Rivest*, *Adi Shamir* et *Leonard Adleman* ont ainsi crée un chiffrement basé sur l'arithmétique modulaire, encore d'actualité aujourd'hui.


# Principe
On va choisir :  
- **2 nombres premiers** qu'on note $q$ et $p$
- Un exposant de chiffrement, souvent ``3`` ou ``65537`` par convention  

## Clé Publique :
On définit la clé publique comme la paire :
  - **e**
  - **$n = p*q$**

## Clé Privée

On note ``phi`` le produit des résultat de l'indice d'euler des 2 nombres premiers ``p`` et ``q``:

$ \Phi(n) = \Phi(p\*q) = \Phi(p)\*\Phi(q) = (p-1)\*(q-1)$

On définit la clé privée comme la paire :
  - **$e$**
  - **$d = e^{-1} \pmod {phi}$**

## Formats des clés :
Il existe plusieurs formats pour les clés RSA mais la plus connu est le format ``PEM``  
Voici un exemple d'une **clé publique** :

```
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANApsiIIiDNYH4IEo7X2/sIpwSq42UTa
Ftzz07hMy9XkKxX73qXlEQMDJ6KDFXwpgo1o/WcdXwGg2Ei55heo1ZkCAwEAAQ==
-----END PUBLIC KEY-----
```
et d'une **clé privée**:  

```
-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANApsiIIiDNYH4IEo7X2/sIpwSq42UTaFtzz07hMy9XkKxX73qXl
EQMDJ6KDFXwpgo1o/WcdXwGg2Ei55heo1ZkCAwEAAQJAW1yxjjZocQCQc6RNpiPO
FLH20iVnVszRlBCAMDekjy9WxMcEIMd99u9d2yvG7btWJDiN7/lBPSqkGQ5Ux2/E
8QIhAPLBTG05qi3Ygz0nSEI3gfUlKdk+e9a+Y0YZCobf9GuLAiEA24U6WK67+/5F
xiWPv5FjWALVbOunwGHkqpxQlph19+sCIQDlDbsdfMG0zIzY0Q3/XPzE4TIhiDG1
qKNnaw1hwkOQjQIhANJ3b7NrBEzcQyVxCdtPl4HgZaPiZJlswgJZkGJyllg1AiAT
Cy4iUPRbeDmT2BJetFLfHEBvXDXHAi68FCHLWg0xdQ==
-----END RSA PRIVATE KEY-----
```

Les données sont encodés en **Base64** et les clés contiennent respectivement **$(e,n)$** pour l'une et **$(d,e,n,p,q)$** pour l'autre.
En réalité , seul **d** est réellement utile car **n** et **e** sont publiques.

Grâce à un outils comme **[OpenSSL](https://www.openssl.org)** , on peut vérifier le contenu dès clés :

```bash
$openssl rsa -pubin -in public_key.pub -noout -text -modulus

Public-Key: (512 bit)
Modulus:
    00:d0:29:b2:22:08:88:33:58:1f:82:04:a3:b5:f6:
    fe:c2:29:c1:2a:b8:d9:44:da:16:dc:f3:d3:b8:4c:
    cb:d5:e4:2b:15:fb:de:a5:e5:11:03:03:27:a2:83:
    15:7c:29:82:8d:68:fd:67:1d:5f:01:a0:d8:48:b9:
    e6:17:a8:d5:99
Exponent: 65537 (0x10001)
Modulus=D029B222088833581F8204A3B5F6FEC229C12AB8D944DA16DCF3D3B84CCBD5E42B15FBDEA5E511030327A283157C29828D68FD671D5F01A0D848B9E617A8D599
```

et

```bash
$ openssl rsa -in private_key.pem -noout -text

Private-Key: (512 bit, 2 primes)
modulus:
    00:d0:29:b2:22:08:88:33:58:1f:82:04:a3:b5:f6:
    fe:c2:29:c1:2a:b8:d9:44:da:16:dc:f3:d3:b8:4c:
    cb:d5:e4:2b:15:fb:de:a5:e5:11:03:03:27:a2:83:
    15:7c:29:82:8d:68:fd:67:1d:5f:01:a0:d8:48:b9:
    e6:17:a8:d5:99
publicExponent: 65537 (0x10001)
privateExponent:
    5b:5c:b1:8e:36:68:71:00:90:73:a4:4d:a6:23:ce:
    14:b1:f6:d2:25:67:56:cc:d1:94:10:80:30:37:a4:
    8f:2f:56:c4:c7:04:20:c7:7d:f6:ef:5d:db:2b:c6:
    ed:bb:56:24:38:8d:ef:f9:41:3d:2a:a4:19:0e:54:
    c7:6f:c4:f1
prime1:
    00:f2:c1:4c:6d:39:aa:2d:d8:83:3d:27:48:42:37:
    81:f5:25:29:d9:3e:7b:d6:be:63:46:19:0a:86:df:
    f4:6b:8b
prime2:
    00:db:85:3a:58:ae:bb:fb:fe:45:c6:25:8f:bf:91:
    63:58:02:d5:6c:eb:a7:c0:61:e4:aa:9c:50:96:98:
    75:f7:eb
exponent1:
    00:e5:0d:bb:1d:7c:c1:b4:cc:8c:d8:d1:0d:ff:5c:
    fc:c4:e1:32:21:88:31:b5:a8:a3:67:6b:0d:61:c2:
    43:90:8d
exponent2:
    00:d2:77:6f:b3:6b:04:4c:dc:43:25:71:09:db:4f:
    97:81:e0:65:a3:e2:64:99:6c:c2:02:59:90:62:72:
    96:58:35
coefficient:
    13:0b:2e:22:50:f4:5b:78:39:93:d8:12:5e:b4:52:
    df:1c:40:6f:5c:35:c7:02:2e:bc:14:21:cb:5a:0d:
    31:75
```

# Chiffrement & Déchiffrement:

- Chiffrement:  
  Soit $m$ un message en clair .
  On chiffre ``m`` de la manière suivante :

  **$c = m^e\pmod n$** *(avec $c$ le message chiffré)*.

- Déchiffrement:  
  Soit $c$ un message chiffré .
  On déchiffre ``c`` de la manière suivante :

  **$m = c^d\pmod n$** .

## Explications Mathématiques :

Avant de comprendre directement le comportement du RSA , il faut comprendre le ``petit théorème de Fermat``.

### Petit théorème de Fermat:
Soit ``p`` un nombre premier, si ``m`` n'est pas un multiple de ``p`` , alors :  
  **$m^{p-1} \equiv 1 \pmod p$**

Si on reprend les données du problèmes, on a :
- $p$ un $1^{er}$ nombre premier
- $q$ un $2nd$ nombre premier
- $e$ une constante $(= 3~ou~65537)$
- $n$ le produit de $p$ et $q$
- $\phi = (p-1)(q-1)$ *([voir ici](https://vozec.fr/crypto-rsa/rsa-0-maths-basis/))*
- $d = e^{-1} \pmod \phi$


Finalement :  

$ed \equiv 1 \pmod {\phi}$  
$\implies \exists k \in {\Bbb N}~|~ed=1+k*\phi$

$c^{d} \equiv (m^e)^d \pmod n$  
$\implies c^{d} \equiv  m^{ed} \pmod n$  
$\implies m^{ed} \equiv m^{1+k*\phi} \pmod p$  
$\implies m^{ed} \equiv m\*m^{k*\phi} \pmod p$  

$\implies \begin{cases}
m^{ed} \equiv m\*(m^{q-1})^{k*(p-1)} \pmod p \newline
m^{ed} \equiv m\*(m^{p-1})^{k*(q-1)} \pmod q
\end{cases}$

$\implies \begin{cases}
m^{ed} \equiv m \pmod p \newline
m^{ed} \equiv m \pmod q
\end{cases}$


# Implémentation en python :
*On utilise la bibliothèque [pycryptodome](https://pycryptodome.readthedocs.io/en/latest/index.html)*

```python
from Crypto.Util.number import getPrime,long_to_bytes,bytes_to_long

class RSA():
	def __init__(self):
		self.e = 65537
		self.p = getPrime(1024)
		self.q = getPrime(1024)
		self.n = self.p*self.q
		self.phi = (self.p-1)*(self.q-1)
		self.d = pow(self.e,-1,self.phi)

	def get_publickey(self):
		return (self.e,self.n)

	def get_privatekey(self):
		return (self.d)

	def encrypt(self,message):
		return pow(bytes_to_long(message),self.e,self.n)

	def decrypt(self,message):
		return long_to_bytes(pow(message,self.d,self.n))

cipher = RSA()
msg    = b'Hello World'
print('Message is "%s"'%msg.decode())

print('Public Key is %s,%s'%cipher.get_publickey())
print('Private Key is %s'%cipher.get_privatekey())

encoded = cipher.encrypt(msg)
print('Ciphertext is %s'%encoded)

decoded = cipher.decrypt(encoded)
print('Plaintext is %s'%decoded)

```


**Output**:
```bash
Message is Hello World
Public Key is 65537,21083306307072454625189141647059116509042816472464216431407906461409083846610336064816109265916002833058732545729421874835501954581004269715288635713818254869909028306488956643954786440984896602427994961524731406030576868552886522119466961246419761897271246921895637891973131084987339840313676011129246013257411516556876053941612549933650443194880828260357144680423336005251076337025055323367511320008960132661574986150260812930124743153979114002191943569202806619411233724976380194498680949762327708940640826771214172909155176319156990185813203239991779355179570942325705017482562064434866687292783291801691033547191
Private Key is 2596447277177499447333591135288678599027794554972896086453350215146142114011810463999432654610495733183042104102753619356963795648615064175535874068789037262234093221564495919455560696479684765524762307314434703725724184904563027297957151597110851858841207774335408905291898332040417166656570778122650480995440524657903139109201895252377098822122318275822524969030415216788553494652144765518628631129199992040553949249186013004503703884888763415416293428384425453161513437844889737414004039435127922542315620298537031562216146232397507751486698431941408183989337357080545429581977291848109836434199307726615835361945
Ciphertext is 8293847393803862666655242093819799047068653312646360436100744804815257681734372088993537721337747949465614240774116370560224759338967109705511233446303386029391203731909794276093961073350378373467073944395633942992858950279503510269386897750488622084241161560682537502652497539204423040505848181253776075163114617658535259363966780394794532149282829981570355666254758064403945151827091621988740809753326563998649830371992597999878696275738199769777633083402330128954890297434500963733488288464380250285297274505706504734028827756409731524709631949281168827073694566206590242309393948666388543015578936523056941841678
Plaintext is b'Hello World'
```
