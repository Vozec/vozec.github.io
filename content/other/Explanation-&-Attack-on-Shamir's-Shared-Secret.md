---
title: "Shamir's Secret Sharing Sheme (SSSS)"
date: 2022-12-20T12:00:00Z
description: "Explication et attaque sur le CryptoSystème SSS."
tags: ["other","cryptographie","crypto"]
keywords: ["tuto", "LLL", "shamir", "secret","maths","SSS","lagrange","cryptography","polynomial"]
---
[//]: <> (Created By Vozec 20/12/2021)
---
## Introduction

[Adi Shamir](https://fr.wikipedia.org/wiki/Adi_Shamir) , né le 6 juillet 1952 à Tel Aviv, est un mathématicien et un cryptologue israélien reconnu comme l'un des experts les plus éminents en cryptanalyse. Il a créé un algorithme de cryptographie utilisant le concept de partage de clé secrète.  
L'idée principal de son chiffrement est de partagé la clé de déchiffrement d'un algorithme quelconque en plusieurs parties. Seul la réunion de celles-ci conduiront au texte déchiffré.

## Idée d'Adi Shamir
Pour se faire , Adi Shamir se base sur une idée simple.
Il faut:  
- **$2~points$** pour former une droite
- **$3~points$** pour former une parabole
- **$4~points$** pour former une courbe cubique
- **$k~points$** pour former un ``polynôme de degrés`` _$k-1$_

## Shamir's Secret Sharing

On se place par la suite dans un champ fini de taille $p$ avec $p$ premier  
On note $S$ le message a chiffrer et $n$ le nombre de parties de clé utile pour retrouver le secret.  

On a:  $\forall p \in P~|~ p > S,P > n$

### Chiffrement

On définit :

$\begin{cases}
(a_1,a_2,...,a_{k-1}) \in R^{k-1} \newline
a_0 = S ~(Le~message~clair)
\end{cases}$

Et:  
$f(x) = a_0 + a_1\*x + a_2\*x^2 + ... + a_{k-1}\*x^{k-1}$  
**$\implies f(x) = a_0 + \sum_{i=1}^{k-1} a_i\*x^i \pmod p$**

Enfin, on forme **k couples** de la forme *$(x,f(x)~mod~p)$* distincts

### Déchiffrement

Supposons que nous ayons k couples *$(x,f(x)~mod~p)$* , nous devons retrouver le polynôme d'origine pour retrouver $x_0 = S$.


#### Polynômes de Lagrange
Pour se faire, nous allons utiliser les **Polynômes d'interpolation de Lagranges**.

[Joseph-Louis-Lagrange](https://fr.wikipedia.org/wiki/Joseph-Louis_Lagrange) est un mathématicien qui s'est intéressé à l’interpolation polynomial , c'est à dire trouver un polynôme $L$ vérifiant :
- $L(x_i) = y_i$ pour une liste de $(x_i,y_i)$ données

Le polynôme d'interpolation L est définit par :  

**$\begin{cases}
\forall i \in N~;l_j(X) =  \prod_{j=0~,j\neq 0}^{n}{\dfrac{X-x_j}{x_i-xj}} \newline
L(X) = \sum_{j=0}^{n}{y_i \* l_j(X)}
\end{cases}$**

*Une propriété remarquable pour notre chiffrement est l'unicité du polynôme !*

Pour retrouver nôtre polynôme , il suffit de calculer tous les $l_i$ avec les couples *$(x,f(x))$* , puis d'en faire la somme pondéré à leur image pour obtenir le polynôme original.

*Il est possible que $S$ soit négatif, or nous sommes ici dans le champ fini $Z_{p}$ , ainsi S est égal à $S' = S + p$*

[Wikipedia](https://fr.wikipedia.org/wiki/Partage_de_clé_secrète_de_Shamir) nous donne ici un exemple :  

$\begin{cases}
(x_0,y0) = (2,1942) \newline
(x_1,y1) = (4,3402) \newline
(x_2,y2) = (5,4414)
\end{cases}$


$\implies \begin{cases}
l_0 = \dfrac{x-x_1}{x_0-x_1}\*\dfrac{x-x_2}{x_0-x_2} = \dfrac{x-4}{2-4}\*\dfrac{x-5}{2-5} =\dfrac{1}{6}x^2-\dfrac{3}{2}\*x+ \dfrac{10}{3}\newline
l_0 = \dfrac{x-x_0}{x_1-x_0}\*\dfrac{x-x_2}{x_1-x_2} = \dfrac{x-2}{4-2}\*\dfrac{x-5}{4-5} =-\dfrac{1}{2}x^2-\dfrac{7}{2}\*x-5 \newline
l_0 = \dfrac{x-x_0}{x_2-x_0}\*\dfrac{x-x_1}{x_2-x_1} = \dfrac{x-2}{5-2}\*\dfrac{x-4}{5-4} =\dfrac{1}{3}x^2-2\*x+ \dfrac{8}{3}
\end{cases}$

$\implies f(x) = 1942\* (\dfrac{1}{6}\*x^2-\dfrac{3}{2}\*x+ \dfrac{10}{3}) + 3042\*(\dfrac{1}{2}\*x^2-\dfrac{7}{2}\*x-5)+4414\*(\dfrac{1}{3}\*x^2-2\*x+ \dfrac{8}{3})$

$\implies f(x) = 1234 + 166\*x+94\*x^2$

Le secret ici est *$S = x_0 = 1234$*


### Implementation en python

```python
from Crypto.Util.number import isPrime,getPrime,long_to_bytes,bytes_to_long
from random import randint

class SSS():
	def __init__(self,N,k,p):
		assert isPrime(p), "P has to be a Prime-Number"
		assert p > N, "P must be superior to N"
		self.N = N
		self.k = k
		self.p = p

	def encrypt(self,S):
		assert self.p > S, "Prime is to weak , P must be superior to S"
		eval_polynomial = lambda coeff,x : sum([coeff[i] * x**(i+1) for i in range(len(coeff))])
		coeff  = [randint(1,self.p) for _ in range(self.k-1)]
		self.shares = [
			(x,S + eval_polynomial(coeff,x))
			for x in range(1,self.N+1)
		]
		return self.shares

	def decrypt(self,shares):
		from sympy.polys.polyfuncs import interpolate
		from sympy import Poly
		from sympy.abc import a, b, x
		return Poly(interpolate(shares, x)).EC()

engine = SSS(
	N = 5,
	k = 3,
	p = getPrime(256)
)

S = bytes_to_long(b'Hello this is Vozec !')
shares = engine.encrypt(S)

secret = engine.decrypt(shares)
print(long_to_bytes(secret))
```