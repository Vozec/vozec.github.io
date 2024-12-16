---
title: "RSA n°6 | Message for all"
date: 2022-12-03T14:00:00Z
description: "Attaque Hastads-Broadcast sur le chiffrement RSA"
tags: ["rsa","cryptographie","crypto"]
keywords: ["tuto", "rsa", "RSA", "crypto","maths","euclide","cryptographie","cryptography","pgcd"]
---
[//]: <> (Created By Vozec 30/11/2021)
---

# Introduction
Il est courant d'envoyer le même message à plusieurs personnes et cela pose un gros problème de sécurité pour l'intégrité du message si une personne arrive à intercepter plusieurs communications.  
Nous allons ici parler de l'``attaque Hastads-Broadcast``.

# Contextualisation
On sait qu'un message chiffré par **RSA** est de la forme :
- $c = m^e \pmod n$

Nous avions vu [ici](https://vozec.fr/crypto-rsa/rsa-2-first-attacks/) que si $m$ était petit, on pouvait déchiffrer le message en appliquant une racine $3^{ième}$ au texte chiffré.

Imaginons maintenant que nous interceptions $e$ fois, un même message chiffré .

On va donc obtenir un système suivant :   

$\begin{cases}
c_1 = m^e \pmod {n_1} \newline
c_2 = m^e \pmod {n_2} \newline
...   \newline
c_e = m^e \pmod {n_e} \newline
\end{cases}$

## Attaque Hastads-Broadcast

Le théorème des [restes chinois](https://vozec.fr/crypto-rsa/rsa-0-maths-basis/) nous indique qu'il existe une solution à ce système modulo le produit des $n_i$:  

$N = {\prod\limits_{k=1}^{e}{n_i}}$  
$\exists~M~tel~que~M~\pmod N$ vérifie le système précédent.

Pour résoudre le système , *Hastads-Broadcast* posent :
-  $\forall i \in [[1,..,e]]~;~N_i = \dfrac{N}{n_i}$

puis :

- $\forall i \in [[1,..,e]]~;~x_i = N_i^{-1}\pmod{N}$  

Finalement , on a :  
- $\forall i \in [[1,..,e]]~;~x_i\*N_i \equiv 1 \pmod {n_i}$

On peut donc déchiffrer le message d'origine :

$\mathbf{m = {({\prod\limits_{k=1}^{e}{c_i\*x_i\*N_i}})}^{\dfrac{1}{e}}}$

## Implémentation en Python

```python
from Crypto.Util.number import long_to_bytes

def hastad_broadcast(n,c,e=3):
	from gmpy import root
	assert len(n) == len(c) and e == len(n),'You have to provide %s couples of (n,c)'%e
	N = 1;
	for ni in n:
		N *= ni
	all_N = []
	all_x = []
	for i in range(len(n)):
		all_N.append(N//n[i])
		all_x.append(pow(all_N[-1],-1,n[i]))
	M = 0
	for _ in range(len(n)):
		M += (all_x[_]*all_N[_]*c[_])
	return root(M % N,e)[0]

n = [
  617139077659107484719642514515150599813,
  455501368683163575511029416282855516761,
  1220811363170363608054081272266092543733,
  744868697249383486872904964447584353871,
  1056623804661697063783855734111105962533
]

c = [
  267928735532011070728314243534627468467,
  90057125104859539155361452457872521237,
  703309972654724303918744740970618275473,
  712717592418034733819257980333485326670,
  719326504986102016457335197929146422287
]

m = hastad_broadcast(n,c,len(n))
print(long_to_bytes(m))

```

*Source: [A Tutorial paper on Hastad Broadcast Attack](http://koclab.cs.ucsb.edu/teaching/cren/project/2017/chennagiri.pdf)*
