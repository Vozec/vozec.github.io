---
title: "RSA n°3 | Module/Premier commun"
date: 2022-11-29T13:00:00Z
description: "Attaques du module/premier commun sur le chiffrement RSA"
tags: ["rsa","cryptographie","crypto"]
keywords: ["tuto", "rsa", "RSA", "crypto","maths","euclide","cryptographie","cryptography","pgcd"]
---
[//]: <> (Created By Vozec 26/11/2021)
---


# Introduction
Nous allons ici voir ``2`` vulnérabilités sur RSA liés à une mauvaise gestion des clés publiques .

# Common Modulus .

On suppose le schéma suivant :

On dispose de ``2`` chiffrés différents à partir d'un même ``message`` et d'une clé commune *(n)*:  
- $c_1 = e_1^{-1} \pmod {\Phi(n)}$
- $c_2 = e_2^{-1} \pmod {\Phi(n)}$

Alors ``si`` on a les égalité suivantes, ``alors`` on peut décoder le message $c_1$ *( = $c_2$)*:  
- $gcd(e_1,e_2) = 1$
- $gcd(c_2,n) = 1$

Comme évoqué dans le [premier article](https://vozec.fr/crypto-rsa/rsa-0-maths-basis/) , le ``théorème de Bézout`` nous assure de l'existence de $a$ et $b$ tel que :
- $a\*e_1+b\*e_2=1$

Ainsi, on a :

${c_1}^a * {c_1}^b = {M^{e_1}}^a*{M^{e_2}}^b$  
$\implies {c_1}^a * {c_1}^b = M^{e_1\*a}\*{M^{e_2\*b}}$  
$\implies {c_1}^a * {c_1}^b = M^{e_1\*a+e_2\*b}$  
$\implies {c_1}^a * {c_1}^b = M$

Une petite subtilité évoqué [ici](https://infosecwriteups.com/rsa-attacks-common-modulus-7bdb34f331a5) est que $b$ peut-être négatif.

Si on pose : $x = -b$ ; alors $c_2^{-a} = {c_2^{-1}}^a = = {1/c_2}^a$ .  
Or $c_2$ doit rester inversible modulo $n$ .  
C'est pour cela que :
 - $gcd(c_2,n) = 1$ est une des conditions de l'attaque .

## Implémentation Python :

```python
import gmpy2

def egcd(a, b):
    if (a == 0):return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def npow(a, b, n):
    assert b < 0
    assert gmpy2.gcd(a, n) == 1
    return pow(int(gmpy2.invert(a, n)), b*(-1), n)

def common_modulus(e1, e2, n, c1, c2):
    g, a, b = egcd(e1, e2)
    return int(
        gmpy2.iroot((
            (npow(c1, a, n) if a < 0 else pow(c1, a, n)) *
            (npow(c2, b, n) if b < 0 else pow(c2, b, n))
            )%n, g)[0]
        )
```

# Common Prime.

On va maintenant se placer dans un autre schéma.  
On dispose de ``2`` messages quelconque, de ``2`` exposant commun *(65537)* et de 2 clé publiques avec un facteurs en communs: 

- $c_1 = (m_1)^e \pmod {n_1}$
- $c_2 = (m_2)^e \pmod {n_2}$  
et  
- n_1 = $p*q$
- n_2 = $p*q'$

Alors, il est facile de retrouver les facteurs $p$ , $q$ et $q'$ !  
Il suffit de prendre le ``PGCD`` des ``2`` clés pour retrouver le facteur commun. De là, une simple division permet de retrouver les 2 facteurs suivant .

$p = gcd(n_1,n_2)$

## Implémentation Python:

```python
from gmpy2 import gcd

def common_prime(n1,n2,e,c1,c2):
    p = gcd(n1,n2)
    q1 = n1//p
    q2 = n2//p

    m1 = pow(c1, pow(e,-1, (p-1) * (q1-1)), p*q1)
    m2 = pow(c2, pow(e,-1, (p-1) * (q2-1)), p*q2)

    return (m1,m2)
```

On peut généraliser pour supporter une liste de **clés publiques**:  

```python
def read_pem(directory='./keys'):
    from Crypto.PublicKey import RSA
    from glob import glob
    return [
        RSA.importKey(open(file, "rb").read()).n
        for file in glob("%s/*.pem"%directory)
    ]

def common_prime(c,n,e=0x10001):
    from gmpy2 import gcd
    for a in range(len(n)):
        for b in range(len(n)):
            if a != b:
                p = gcd(n[a],n[b])
                if p != 1:
                    q1 = n[a]//p
                    q2 = n[b]//p
                    m1 = pow(c[a], pow(e,-1, (p-1) * (q1-1)), p*q1)
                    m2 = pow(c[b], pow(e,-1, (p-1) * (q2-1)), p*q2)
                    return (m1,m2)
    return (0,0)    

public_keys = read_pem()
messages    = [int(open('secret.txt','r').read().strip())]*len(public_keys)
m1,m2       = common_prime(messages,public_keys)
```
