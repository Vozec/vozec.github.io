---
title: "RSA n°5 | E takes confidence"
date: 2022-11-30T14:00:00Z
description: "Attaques Wiener et Boneh Durfee sur le chiffrement RSA"
tags: ["rsa","cryptographie","crypto"]
keywords: ["tuto", "rsa", "RSA", "crypto","maths","euclide","cryptographie","cryptography","pgcd"]
---
[//]: <> (Created By Vozec 30/11/2021)
---


# Introduction
Nous allons ici voir ``3`` vulnérabilités sur RSA liées à un mauvais choix de l'exposant $e$.

# Contextualisation

On sait que $d$ , clé privée du chiffrement **RSA** est généré de la sorte:  
- $d = e^{-1} \pmod \Phi(n)$

Par convention, on utilise souvent $e=3$ ou $e=65537$ .

## Pourquoi ?  
Ces nombres présentes plusieurs propriétés intéressante, d'abord :
- ils sont ``premiers``
- ils sont ``petits``

C'est $2$ premières propriétés sont majeures , elles permettent un temps de calcul raisonnable pour le chiffrement/déchiffrement des messages .

De plus , ils sont de la forme $e = 2*k + 1$ . *( 65537 = 2^16+1)* .  
Ils sont appelé ``nombres premiers de Fermat`` et surtout, ils vérifient la propriété :  

$gcd(p-1,e) = 1$  
$\implies p \not\equiv 1 \pmod e$

A la liste peuvent donc s'ajouter : ``5``,``17``,``257``.

## Problème

Que se passe t'il si on décide de choisir un exposant $e$ très grand ?   
On pourrait de dire que intuitivement, le chiffrement n'en serait que plus robuste et plus long en calcul. En réalité, **il n'en ai rien et vous faites une grosse erreur en pensant cela .**

En augmentant $e$ , vous pouvez influencer la taille de la clé privée $d=e^{-1} \pmod \Phi$ et ``2`` attaques permettent de retrouver cette si précieuse clé privée .

## Attaque de Wiener

### Conditions :  
L'attaque requiert ``2`` conditions :
$\begin{cases}
d < \dfrac{1}{3}\*N^{\dfrac{1}{4}} \newline
q < p < 2\*q \newline
\end{cases}$

### Théorème de Wiener :
Si $\begin{cases}
d < \dfrac{1}{3}\*N^{\dfrac{1}{4}} \newline
q < p < 2\*q \newline
\end{cases}$   

Alors **d** peut être retrouvé en cherchant la bonne fraction $\dfrac{k}{d}$ parmi les convergentes de $\dfrac{e}{n}$

### Démonstration:
*On sait que* :  

$d=e^{-1} \pmod \Phi$  
$\implies e\*d \equiv 1 \pmod \Phi$  
$\implies\exists k ~tel~que : e\*d = k*\Phi(n)+1$  
$\implies\exists k ~tel~que : |e\*d-k*\Phi(n)| = 1$  
$\implies\exists k ~tel~que : |\dfrac{e}{\Phi(n)} - \dfrac{k}{d} = | \dfrac{1}{d*\Phi(n)}$



*De plus* :  
$\Phi(n)=(p-1)\*(q-1)$  
$\implies\Phi(n)=n-q-p+1$  
$\implies |n - \Phi(n)| = p+q-1 < 3 \sqrt n$  *(car q<p<2q)*

*Finalement* :  
$\exists k ~tel~que : |\dfrac{e}{n} - \dfrac{k}{d} = | \dfrac{e\*d - k\*n}{n\*d}| $  
$ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~= | \dfrac{e\*d - k\*n -k\*\Phi(n) +k*\Phi(n)}{n*d}| $  
$ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~= | \dfrac{1-k\*(n-\Phi(n))}{n\*d}| $ 
$ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~= | \dfrac{k\*(n-\Phi(n))-1}{n\*d}| $ 
$ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~= | \dfrac{k\*(p+q-1)-1}{n\*d}| $ 
$ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~< | \dfrac{3\*k\*\sqrt n}{n\*d}| $  

*Or* :
$k\*e < k\*\Phi(n) = d\*e-1 < d\*e$  
$\implies k  < d < \frac{1}{3}*n^{\frac{1}{4}}$

*D'où* :  
$\exists k ~tel~que : |\dfrac{e}{n} - \dfrac{k}{d} < | \dfrac{3\*\frac{1}{3}*n^{\frac{1}{4}}\*\sqrt n}{n\*d}|$   
$ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~< | \dfrac{1}{d\*n^{\dfrac{1}{4}}\*\sqrt n}| $  
$ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~< | \dfrac{1}{d\*n^{\dfrac{1}{4}}}| $  
$ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~< | \dfrac{1}{3\*d^3}| $  


*([Reference: Sage.io](https://sagi.io/crypto-classics-wieners-rsa-attack/))*

### Polynôme $\Phi(n)$:
*On sait que* :  
$\Phi(n) = (p-1)\*(q-1)$
$\implies \Phi(n) = n-q-p + 1$  
$\implies \Phi(n) =  n - p - \dfrac{n}{p} + 1$  
**$\implies p^2 + p\*(\Phi(n)-n-1)-n = 0$**

### Algorithme de factorisation :

Voici les étapes à suivre :
- Déterminer les [fractions continues](https://fr.wikipedia.org/wiki/Fraction_continue) de $\dfrac{e}{n}$
- Déterminer les approximation des $\dfrac{e}{n}$ qu'on note $\dfrac{k}{d}$
- Pour chaque $\dfrac{k}{d}$ , on calcule $\Phi(n) = \dfrac{e\*d-1}{k}$ avant de résoudre l'équation polynomial évoqué plus haut .
- Les racines du polynôme peuvent être les facteurs $p$ et $q$. Il suffit de recalculer $n$ et comparer le résultat avec sa valeur connue.

### Implémentation Python:

```python
from sympy import *

def convergents(e):
    n,d = [e[0],e[1]*e[0] + 1],[1,e[1]]
    yield (n[0], n[0]);yield (n[1], n[1])
    for i in range(2,len(e)):
        ni,di = e[i]*n[i-1] + n[i-2],e[i]*d[i-1] + d[i-2]
        [x.append(y) for x,y in [(n,ni),(d,di)]]
        yield (ni, di)

continued_frac = lambda e,n: list(continued_fraction_iterator(Rational(e,n)))     
validity_check = lambda r,n: len(r) == 2 and n == r[0]*r[1]

def Wiener(e,n):
    def solver(phi,n):
        p = Symbol('p', integer=True)
        return solve(p**2 + (phi - n - 1)*p + n, p)
    for pk, pd in convergents(continued_frac(e, n)):
        if pk == 0:
            continue;
        roots = solver((e*pd - 1)//pk,n)
        if validity_check(roots,n):
            return roots
    return (0,0)
```

## Attaque de Boneh Durfee

Cette attaque est dans la continuité de l'attaque Wiener et est possible dans des conditions similaires :  
- $d < n^{\dfrac{1}{2}\*{(2-\sqrt{2})}}  \approx n^{0,292}$

On sait que :  

$e\*d \equiv 1 \pmod{\Phi{(n)}}$  
$\implies e\*d = k\*\Phi{(n)} +1$  
$\implies 1 = e\*d + \dfrac{k'\*\Phi{(n)}}{2}$  
$\implies 1 = e\*d + \dfrac{k'\*(p-1)\*(q-1)}{2}$  
$\implies 1 = e\*d + \dfrac{k'\*(n-q-p+1)}{2}$  
$\implies 1 = e\*d + k'\*\bigg(\dfrac{(n+1)}{2}+\dfrac{(-p-q)}{2}\bigg)$  
$\implies 1 = e\*d + k'\*(x+y)$

avec :
- $x = \dfrac{(n+1)}{2}$  
- $y = \dfrac{(-p-q)}{2}$  

On peut réécrire l'équation comme :   
- $\mathbf{2\*k''\*(x+y)+1 \equiv 0 \pmod e}$

[David Wong](https://twitter.com/cryptodavidw) explique [ici](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/survey_final.pdf) que cette équation peut être reformulée sous la forme :  

$\mathbf{f(x,y) = x*(a+y)}$  
et :
- $a=n+1$
- $y = -q-p$

Ainsi , les racines de ce polynôme nous permettent de calculer la clé privée $d$.  
Pour les trouver , on peut utiliser la méthode de ``Coppersmith's`` pour les polynômes à plusieurs variables ainsi que le théorème de ``Howgrave-Graham`` pour les *polynômes bivariants*  

Voici une implémentation efficace de cette attaque : [ici](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage)


## Attaque d'un RSA avec e de la forme 2^k
Quand ``e`` est une puissance de *2*, il est possible de calculer la racine carré modulaire *k* fois grâce à l'algorithme de Tonelli Shanks et retrouver le message déchiffré !

```python
from Crypto.Util.number import long_to_bytes

n = ...
c = ...
e = 64

def legendre(a, p):
    return pow(a, (p - 1) // 2, p)
 
def tonelli(n, p):
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r

def find_square_roots(c, e):
    if e == 1:
        plaintext = long_to_bytes(c)
        print(plaintext)
        return

    elif pow(c,(n-1)//2,n) != 1:
        return

    else:
        rt1 = tonelli(c, n)
        find_square_roots(rt1, e//2)
        rt2 = n - rt1
        find_square_roots(rt2, e//2)
    return

find_square_roots(c, e)
```


Sagemath est aussi capable de le faire automatiquement: 
```python
n = ...
c = ...
e = 2**5

X = GF(n, 'X').gen()
for r, _ in (X^e - c).roots():
    print(bytes.fromhex(hex(r)[2:]))
```