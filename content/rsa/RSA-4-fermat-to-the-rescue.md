---
title: "RSA n°4 | Fermat is Watching U"
date: 2022-11-29T14:00:00Z
description: "Attaques par factorisation de Fermat sur le chiffrement RSA"
tags: ["rsa","cryptographie","crypto"]
keywords: ["tuto", "rsa", "RSA", "crypto","maths","euclide","cryptographie","cryptography","pgcd"]
---
[//]: <> (Created By Vozec 29/11/2021)
---

# Introduction
Nous allons ici voir une vulnérabilité sur RSA liée à une mauvaise génération de clé publique.

# Vulnérabilité :

On rappelle que $n$ et généré avec $p$ et $q$ très grands:    
- $n = p*q$ .  

On se place dans un cas idéal ou $p$ et $q$ sont cryptographiques et que donc $n$ n'est pas cassable par force brute .

La vulnérabilités réside dans le fait que $p$ et $q$ ``sont très proches``.

On peut imaginer une génération de clé vulnérable comme celle-ci :
```python
from Crypto.Util.number import getPrime
from sympy import nextprime

def get_public(bits=1024):
    p = getPrime(bits)
    q = nextprime(p)
    return p*q

n = get_public()
```

En effet, le fait que $p$ et $q$ soient proches implique que la racine de la clé publique $n$ soit une bonne approximation d'un des 2 facteurs $p$ ou $q$

La condition pour que l'algorithme fonctionne est que $p-q < n^{1/4}$ .  
Si elle est vérifiée ; alors la factorisation se fera sans problèmes.

## Algorithme :
Pierre de Fermat se base sur la représentation d'un nombre pair comme la différence de ``2`` aires de carrés de côté ``a`` et ``b``  .

Il pose :  
$n = p*q$  
$\implies n = (\dfrac{(q-p)}{2})^{2} \* (\dfrac{(p+q)}{2})^{2} $  
$\implies n = x^2 - y^2$  

Avec :

$\begin{cases}
x =  \dfrac{(q-p)}{2} \newline
y =  \dfrac{(q+p)}{2}
\end{cases}$

$\implies n = (x-y)(x+y)$  

## Pseudo-Code
```python
fermat(n):
  a = Racine(n)
  b = a*a - n
  Tant que b n'est pas un carré parfait :
      a = a + 1
      b = a*a -n
  p = a-Racine(b)
  q = a+Racine(b)
  return (p,q)
```

Ce qui donne en python :

```python
from gmpy2 import mpz,sqrt,ceil,get_context

def Fermat(n):
    get_context().precision=10000
    is_square = lambda n: sqrt(n).is_integer()
    a = mpz(ceil(sqrt(n)))
    b = mpz((a*a) - n)
    while not is_square(b):
        a = a + 1
        b = (a * a) - n
    p = a - sqrt(b)
    q = a + sqrt(b)
    return p,q
```  
ou
```python
def Fermat(n):    
    def isqrt(n):
        if n == 0:return 0
        x, y = n, (n + 1) >> 1
        while y < x:x, y = y, (y + n // y) >> 1
        return x
    a = b = isqrt(n)
    b2 = pow(a, 2) - n
    while pow(b, 2) != b2:
        a += 1
        b2 = pow(a, 2) - n
        b = isqrt(b2)
    p, q = (a + b), (a - b)
    return p,q
```


## Amélioration de l'algorithme :

*reference : [The Fermat factorization method revisited](https://hsbp.org/tiki-download_wiki_attachment.php?attId=174)*

L'efficacité de l'algorithme de Fermat peut être écrite :

$\Theta (\dfrac{\Delta}{4*n^{1/2}})$ avec $\Delta = p-q$

# Idée de CopperSmith *(1996)*:
CopperSmith propose une méthode pour trouver les racines d'un 'polynôme modulaire invariant' *(univariate polynomial modular equation)* et une autre méthode pour trouver les racines d'une équation polynomiale bivariante *(bivariate polynomial integer equation)*

Grâce à cela , CopperSmith est capable de factoriser $n$ si :
- $p-q < n^{5/18}$  
puis quelques mois après , si :  
- $p-q < n^{1/3}$ avec $p$ et $q$ de 512 bits

La factorisation est possible si on connait les bits de poids fort d'un des 2 facteurs premiers.

Une implémentation de l'attaque est disponible [ici](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/coppersmith.sage) et expliqué par son créateur [ici](https://github.com/mimoo/RSA-and-LLL-attacks#factoring-with-high-bits-known)
