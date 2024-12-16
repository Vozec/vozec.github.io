---
title: "RSA n°10 | Oracle tell me the True"
date: 2022-12-10T14:00:00Z
description: "Attaques sur un Oracle RSA"
tags: ["rsa","cryptographie","crypto"]
keywords: ["tuto", "rsa", "RSA", "crypto","maths","euclide","cryptographie","cryptography","pgcd"]
---
[//]: <> (Created By Vozec 10/12/2021)
---

# Introduction :  
Généralement, dans un contexte de CTF , il est possible de tomber sur un oracle de déchiffrement RSA , on nous donne accès :
- **à un oracle permettant de déchiffrer des messages sauf le flag chiffré**
- **le flag chiffré**

Voici donc plusieurs méthodes pour trouver le flag en clair :

## Méthode 1:

La première méthode est de Factoriser le message $c$ .
On peut ainsi demander de déchiffrer les facteurs du flag puis re-multiplier les clairs entre eux pour récupérer le message original:

$c_{original} =c_1 * c_2 * c_3$  
$\implies m_{original} = [f^{-1}(c_1)* f^{-1}(c_2)* f^{-1}(c_3)] \pmod n$  
*(Avec $f^{-1}$  la fonction de déchiffrement)*

## Méthode 2:
Le RSA a des propriétés **Homomorphique** , ce qui veut dire que:
 - $f^{-1}(a*b) = f^{-1}(a)*f^{-1}(b)$  

C'est la propriété utilisée dans la *méthode 1*  
Ainsi , on peut demander le déchiffrement d'un produit de $c$

$m_{original} = f^{-1}(2*c) * [({f^{-1}(2)})^{-1}\pmod n] \pmod n$


## Méthode 3:
On peut aussi envoyer :
- $c+k*n$  
*($k \in N$)*

On utilise ici les propriétés du RSA , en appliquant le *modulo n* , le serveur va directement déchiffrer *c*

## Méthode 4:
On peut demander le déchiffrement de :
- $-c$
- $-1$

Puis :
- $m_{original} = f^{-1}(-c) * f^{-1}(-1) \pmod n$

## Méthode 5:
On sait que :  
$c \equiv m^e \pmod n$  

On doit envoyer : $c^{e+1}$
- On a:  
  $\implies (c^{e+1})^d \equiv (c^{e*d} + c^d ) \pmod n$  
  $\implies (c^{e+1})^d \equiv c * c^d \pmod n$  
  $\implies (c^{e+1})^d \equiv c * m \pmod n$  

- Finalement :  
  $m_{original} =  (c^{e+1})^d * c^{-1} \pmod n$

## Méthode 6:

On sait que :  
$c \equiv m^e \pmod n$  
- Soit $\lambda \in N$  
$\implies \lambda^ec \equiv (\lambda\*m)^e \pmod n$  
$\implies (\lambda^ec)^d \equiv ((\lambda\*m)^e)^d \pmod n$  
$\implies (\lambda^ec)^d \equiv \lambda\*m \pmod n$  
$\implies \dfrac{(\lambda^ec)^d}{\lambda} \equiv m \pmod n$  

On peut donc envoyer : $\lambda^e \pmod n$ et diviser par $\lambda$

## Retrouver le module $n$:
Toutes les attaques précédentes requièrent de connaitre $n$.
On peut le retrouver de la manière suivante :

On demande le chiffrement de :
- 2
- 4
- 3
- 9
- 5
- 25

On obtient donc :

$\implies \begin{cases}
c_2 = 2 ^ e \pmod n \newline
c_4 = 4 ^ e \pmod n \newline
c_3 = 3 ^ e \pmod n \newline
c_9 = 9 ^ e \pmod n \newline
c_5 = 5 ^ e \pmod n \newline
c_{25} = {25} ^ e \pmod n \newline
\end{cases}$

$\implies \begin{cases}
{c_2} ^ 2 = c_4 \pmod n \newline
{c_3} ^ 2 = c_9 \pmod n \newline
{c_5} ^ 2 = c_{25}  \pmod n \newline
\end{cases}$

$\implies \begin{cases}
k_1 = {c_2} ^ 2 - c_4  \newline
k_2 = {c_3} ^ 2 - c_9  \newline
k_3 = {c_5} ^ 2 - c_{25} \newline
\end{cases}$

$\implies n = GCD(k_1,GCD(k_2,k_3))$
