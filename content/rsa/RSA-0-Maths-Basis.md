---
title: "RSA n°0 | Bases Mathématiques"
date: 2022-11-25T12:00:00Z
description: "Bases mathématiques pour la cryptographie"
tags: ["rsa","cryptographie","crypto"]
keywords: ["tuto", "rsa", "RSA", "crypto","maths","euclide","cryptographie","cryptography","pgcd"]
---
[//]: <> (Created By Vozec 25/11/2021)
---
## Introduction
Voici les différents théorèmes et application pour comprendre le chiffrement RSA

## Opération Modulaires

L'opérateur modulo est une opération qui retourne le reste de la division euclidienne d'un nombre A par B:

$a \equiv r \pmod b$  
$\Rightarrow~\exists~k \in N~|~a = b*k + r$

Si r = 0 , on dit que ``n divise a``

## Pgcd

Le ``PGCD`` *(ou gcd)* de 2 nombres est le plus grand diviseur commun de ces deux nombres :

Exemple:
  - PGCD(96,36) = 12  
  12 divise 96 et 36

L'[Algorithme](https://fr.wikipedia.org/wiki/Algorithme_d%27Euclide) d'Euclide permet de retrouver ce diviseur :

```python
def gcd(a,b):
  return a if b==0 else gcd(b,a%b)
```
```python
>>> gcd(96,36)
12
```


## Nombre premiers

- On dit qu'un nombre est premier s’il n'est divisible que par 1 ou lui-même :  
```
2, 3, 5, 7, 11, 13, 17, 19 ..
```

- On dit que deux nombres sont premiers entre eux si leur unique diviseur commun est 1 i.e. si $PGDC(a,b)=1$   

## Inverse modulaire
Soit $x$ un entier, on appèle **l'inverse modulaire** de $x$ modulo $n$ , l'entier $u$ tel que :

$x*u \equiv 1 \pmod n$

```python
u = pow(x, -1, n)
```

## Théorème de Bezout

Soient A et B deux nombres premiers, alors il existe u et v tq: ``A*u+B*v=1``

$\forall (a,b) \in {\Bbb R}~|~GCD(a,b)=1~ \Rightarrow~\exists~(u,v)~\in{\Bbb N}~,~au+bv=1$

Pour trouver ces deux réels ``u`` et ``v`` , on peut utiliser l'[Algorithme ](https://fr.wikipedia.org/wiki/Algorithme_d%27Euclide_étendu)étendu d’Euclide

- Exemple: *(a,b) = (120,23)*  
  Alors , **-9×120 + 47×23 = 1** ; (u,v)=(-9,47)

```python
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x
```
*Output :*
```python
>>> extended_gcd(120,23)
(1, -9, 47)
```

## Théorème des restes chinois

Ce théorème permet de résoudre des équations modulaires du type :

$\begin{cases}
x \equiv r  \pmod {b} \newline
x\equiv r' \pmod {b'}
\end{cases}$
*(avec x l'inconnu*)

*Exemple :*  

$\begin{cases}
x \equiv 4  \pmod{15} \newline
x\equiv 7 \pmod {11}
\end{cases}$

On cherche $x$ de la forme $x=4y+7z$ tel que :  

$\begin{cases}
y \equiv 1 \pmod{15}~et~z~\equiv 0  \pmod{15} \newline
z \equiv 1 \pmod{11}~et~y~\equiv 0  \pmod{11}
\end{cases}$

$\exists~(k,l)~\in{\Bbb N} , x = 4\*11\*k + 7\*15*l$  et

$\begin{cases}
11\*k \equiv 1 \pmod{15} \newline
15\*l \equiv 1 \pmod{11}
\end{cases}$

$\implies \begin{cases}
k = -4 \newline
l = 3
\end{cases}$  

$\implies x = 4\*11\*(-4)+7\*15*3$  
$\implies x = 139$

```python
from functools import reduce

def crt(r,n):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, r_i in zip(n, r):
        p = prod // n_i
        sum += r_i * pow(p,-1,n_i) * p
    return sum % prod

```

```python
>>> crt([4,7],[15,11])
139
```

$x = \begin{cases}
   a &\text{if } b \newline
   c &\text{if } d
\end{cases}$

## Indicatrice D’Euler $\Phi$


On appelé $\Phi$  , l'indicatrice d’Euler , la fonction qui à un entier ``n`` lui associe le nombre de nombres premiers à ``n``

$\Phi~:n~\rightarrow~Card(\{m \in {\Bbb N^{*}~|~m <= n~et~gcd(m,n)=1}\})$

Si on pose $p$ un nombre premier, alors il y a $p-1$ nombres premiers a $x$ , d'où :

$\Phi(p) = p-1$

## Indicatrice de Carmichael $\lambda$
On appele $\lambda$ , l'indicatrice de Carmichael , la fonction qui à un entier ``n`` lui associe le plus petit entier $n$ tel que :  

$a^m \equiv 1 \pmod n$
