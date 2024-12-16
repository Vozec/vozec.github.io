---
title: "RSA n°9 | Breaking Signature Shema"
date: 2022-12-09T14:00:00Z
description: "Attaques sur les signatures du chiffrement RSA"
tags: ["rsa","cryptographie","crypto"]
keywords: ["tuto", "rsa", "RSA", "crypto","maths","euclide","cryptographie","cryptography","pgcd"]
---
[//]: <> (Created By Vozec 30/11/2021)
---

# Introduction :  

Le chiffrement RSA permet l'utilisation d'un système de signature des messages lors de la transmission de ceux-ci.  
Ainsi, un message chiffré peut être accompagné de sa signature qui atteste de son intégrité au prêt du serveur.  
Voici un message chiffré & signé :
- **$<s,c>$**

## Fonctionnement global.  
Le chiffrement RSA se compose :
- un exposant de chiffrement
- une clé publique
- une clé privée

On va réutiliser les propriétés arithmétiques du chiffrement pour inventer la signature noté $s$ .

### Création de la signature :  
Soit $m$ un message clair et $hash$ une fonction de hash classique *(sha256,md5)*:
- On calcul $h = hash(m)$
- On a : $s = h^d \pmod n$

### Vérification de la signature :
- On déchiffre le message $c$ comme un RSA classique  
- On calcul $h = hash(m)$
- On déchiffre $h' = s^e \pmod n$
- On compare $h$ et $h'$.

### Relation mathématique :
$h' = s^e \pmod n = (h^d)^e \pmod n = h$


## Première attaque : *Choosen Message*

On va supposer avoir a disposition un **Oracle de signature** qui nous permet de signer n'importe quel message .

On souhaite obtenir la signature :  
- $s = h^d \pmod n$

Alors, grâce à **deux autres** signatures, on peut obtenir $s$.

##### Etapes :
- On signe un message connu $h_1$:  
	$s_1 = h_1^d \mod n$

- On signe un second message $h_2$ tel que :  
	$\begin{cases}
	h_2 = h * h_1^{-1} \pmod n \newline
	s_2 = h_2^d \mod n
	\end{cases}$

- Alors on peut récupérer la signature de $m$ , noté $s$:  
	$s = s_1 *s_2 \pmod n$

#### Relation mathématique :  
$s \equiv s_1\*s_2 \equiv m_1^d\*m_2^d\equiv m_1^d\*(m \* m_1^{-1})^d \equiv m_1^d\*m^d \* m_1^{-d} \equiv m^d \pmod n$

*Source:[Chosen-Message-Attack RSA-Signature](https://crypto.stackexchange.com/questions/35644/chosen-message-attack-rsa-signature)*


## Seconde Attaque : *Fault attack*

Pour calculer des signatures, on utilise souvent le *[Théorème des restes chinois](https://vozec.fr/crypto-rsa/rsa-0-maths-basis/)* pour accélerer les temps de calcul.

Ainsi, pour calculer $s = hash(m)^d \pmod n$.  
On calcul :  
-	$\begin{cases}
	d_p = d\pmod{p-1}\newline
	d_q = d\pmod{q-1}\newline
	S_p = m^{d_p} \pmod p \newline
	S_q = m^{d_q} \pmod q
	\end{cases}$  

En utilisant le théorème, on obtient $s$ grâce à $S_p$ et $S_q$

#### Injection de Faute:
Si on arrive à injecter une faute (en faisant baisser la tension du processeur par exemple), on peut rendre un des calculs de $S_p$ ou $S_q$ faux.

On a donc :

$\begin{cases}
	S_p = m^{d_p} \pmod p \newline
	S_q ≠ m^{d_q} \pmod q
\end{cases}$  

$\implies S = crt([S_p,S_q],n)$

$\implies \begin{cases}
	S^e = m \pmod p \newline
	S^e ≠ m \pmod q
\end{cases}$  

$\implies \begin{cases}
	S^e - m = 0 \pmod p \newline
	S^e -m ≠ 0 \pmod q
\end{cases}$  

$\implies \begin{cases}
	p~\mid~S^e - m \newline
	q~\nmid~S^e - m \pmod q
\end{cases}$  

On peut ainsi retrouver un des 2 facteurs de la clé publique de la manière suivante :

- **$q = gcd(S^e-m,n)$**  

### Implémentation en python

```python
from Crypto.Util.number import *
from hashlib import sha256

def gen():
	e,p,q = (0x10001,getPrime(256),getPrime(256))
	n = p*q
	d = inverse(e,(p-1)*(q-1))
	return e,p,q,n,d

def sign(m,e,n,p,q,d):
	dp,dq = (d % (p-1),
			 d % (q-1))
	sp,sq = (pow(m,dp,p),
			 pow(m,dq,q))

	# Fault
	sq = sq+1

	h = ((sp-sq) * pow(q,-1,p)) % p
	return sq + q*h

def attack_sig(m,e,n,s):
	return GCD(s**e - m,n)


e,p,q,n,d = gen()
hash  = bytes_to_long(sha256(b'Hello From Vozec').digest())
sig   = sign(hash,e,n,p,q,d)

q = attack_sig(hash,e,n,sig)
p = n//q
#...
```


*Source:[Fault Attacks on RSA Signatures with Partially Unknown Messages⋆](https://eprint.iacr.org/2009/309.pdf)*


## Troisième Attaque : *Signature Forgery*

#### Le Standard *PKCS#1 v1.5*
*PKCS* est un standard de formatage du chiffrement RSA.  
Il permet de formater un message avec de le signer.

Il fonctionne de la manière suivante :  
	- ``0x00 0x01 || pad() || 0x00 || ASN.1 || hash(M) ``

Avec :  
	- ``0x00 0x01``:  Deux bytes qui annoncent le début du message  
	- ``pad()``: Du padding de **0xff**.  
	- ``0x00``: Un byte qui annonce la fin du padding.  
	- ``ASN.1``: byte identifiant le hash  
	- ``hash(M)``: Le message hashé

### Vulnérabilité sur la fonction de Vérification :
Avant de vérifier la signature , les serveurs vérifient souvent la forme du message reçu: ``0x00 0x01 || 0xff 0xff ...  || 0x00 || ASN.1 || hash(M) ``

Or , certain serveur ne regarde pas le contenue du padding. Ainsi , dans le cas ou $e=3$ , il est possible d'envoyer un message valide de la forme:

-  ``0x00 0x01  || 0xff || 0x00 || ASN.1 || hash(M) || Garbage``

Le module $n$ n'est pas appliqué car le message est inférieur à n.  
Alors , si il n'y a pas de vérification du contenue du padding de ``0xFF`` , alors il est possible de placer des bytes voulu entre ``0x00 0x01`` et ``0x00``

On peut brute-forcer et permettre la création d'une signature tel que celle-ci mise à la puissance $e=3$ , elle soit valide et commence par ``0x00 || ASN.1 || hash(M)``

```python
import hashlib
from os import urandom
from gmpy2 import mpz, iroot

set_bit   = lambda n,b,x: ~(1 << b) & n if x == 0 else  (1 << b) | n
to_bytes  = lambda n: n.to_bytes((n.bit_length() // 8) + 1, byteorder='big')
from_bytes= lambda b: int.from_bytes(b, byteorder='big')
get_bit   = lambda n,b: ((1 << b) & n) >> b
cube_root = lambda n: int(iroot(mpz(n), 3)[0])

message = b"Ciao, mamma!!"

# Suffix
hash_msg    = hashlib.sha256(message).digest()
asn1_sha256 = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
suffix      = b'\x00' + asn1_sha256 + hash_msg

sig_suffix = 1
for b in range(len(suffix)*8):
    if get_bit(sig_suffix ** 3, b) != get_bit(from_bytes(suffix), b):
        sig_suffix = set_bit(sig_suffix, b, 1)

while True:
    sig = (
        to_bytes(cube_root(
                from_bytes(b'\x00\x01' + urandom(2048//8 - 2)
                ))
    )[:-len(suffix)] \
        + b'\x00' * len(suffix))[:-len(suffix)] \
        + to_bytes(sig_suffix)

    if b'\x00' not in to_bytes(from_bytes(sig) ** 3)[:-len(suffix)]:
        break

assert to_bytes(from_bytes(sig) ** 3).endswith(suffix)
assert to_bytes(from_bytes(sig) ** 3).startswith(b'\x01')
assert len(to_bytes(from_bytes(sig) ** 3)) == 2048//8 - 1
assert b'\x00' not in to_bytes(from_bytes(sig) ** 3)[:-len(suffix)]

print(sig)
```
*Code repris de la ressource ci dessous*

*Source: [BLEICHENBACHER'06 SIGNATURE FORGERY IN PYTHON-RSA](https://words.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/)*
