---
title: "RSA n°7 | Hey this is Franklin (Reiter)"
date: 2022-12-04T14:00:00Z
description: "Attaque Franklin-Reiter sur le chiffrement RSA"
tags: ["rsa","cryptographie","crypto"]
keywords: ["tuto", "rsa", "RSA", "crypto","maths","euclide","cryptographie","cryptography","pgcd"]
---
[//]: <> (Created By Vozec 30/11/2021)
---


# Introduction
L'attaque Franklin-Reiter sur le chiffrement RSA requiert d'avoir deux messages chiffrés avec une relation linéaire connu entre les deux messages.

# Contextualisation
Exemple :
- $m_1 = 100000000000$
- $m_2 = 100000000999$

Ici , si la relation entre les deux messages est linéaire puisque  $m_1 + 999 == m_2$.
Il est alors possible de retrouver le message à partir de :
- $c_1 = m_1^e \pmod n$
- $c_2 = m_2^e \pmod n$

A l’origine, cet attaque était faisable pour $e=3$ puis elle a était généralisée pour n'importe quel $e$ .  
(*Plus e est grand, plus l'attaque est longue*)

# Première approche :

## $e = 3$
	-	$\begin{cases}
	m_2 = \alpha*m_1+\beta \newline
	c_1 = m_1^3 \pmod n \newline
	c_2 = m_2^3 \pmod n
	\end{cases}$

	$\implies \dfrac{\beta(c_2+2\alpha^3c_1+\beta^3)}{\alpha(c_2-\alpha^3c_1+2\beta^3)} = \dfrac{3\alpha^3\beta{m_1}^3+3\alpha^2\beta^2{m_1^2}+3\alpha\beta^3m_1}{3\alpha^3\beta{m_1}^2+3\alpha^2\beta^2m1+3\alpha\beta^3} = m_1 \pmod n$


## $e = 5$
	-	$\begin{cases}
	m_2 = \alpha*m_1+\beta~(avec~\alpha=\beta=1) \newline
	c_1 = m_1^5 \pmod n \newline
	c_2 = m_2^5 \pmod n
	\end{cases}$

	$\implies\begin{cases}
	P(m)=c_2^3-3c_1c_2^2+3c_1^2c_2-c_1^3+37c_2^2+176c_1c_2+37c_1^2+73c_1^2+73c_2-73c_1+14 \newline
	mP(m)=2c_2^3-c_1c_2^2-4c_1^2c_2+3c_1^3+14c_2^2-88c_1c_2-51c_2-9c_2+64c_1-7 \newline
	m = \dfrac{mP(m)}{P(m)}
	\end{cases}$


Cette méthode est longue mais fonctionnelle, elle permet pour tout $e$ de déterminer un polynôme $P$ pour retrouver les $m_i$

# Seconde approche :

## Théorème de Franklin-Reiter :
Soit **(n,e)** une clé RSA publique , et $m_1 ≈ m_2$ tel que :  
- $\mathbf{m_1 = f(m_2) \pmod n}$  

Si $f$ est une fonction affine $f:x \rightarrow a*x+b$  
Alors avec *$(n,e,c_1,c_2,f)$* il est possible de retrouver $m_1~et~m_2$

## Démonstration :
On a :  

$\begin{cases}
c_1 = m_1^e \pmod n \newline
c_2 = m_2^e \pmod n
\end{cases}$

$\implies\begin{cases}
z^e  - c_1 \equiv 0 \pmod n \newline
(\alpha*z+\beta)^e  - c_2 \equiv 0 \pmod n
\end{cases}$

$\implies \begin{cases}
m_2~est~racine~de~: g_1(x) = f(x)^e - c_1\newline
m_2~est~racine~de~: g_2(x) = x^e - c_2
\end{cases}$

et  
$x-m_2$ divise les deux polynômes.  
Ainsi , on peut utiliser le [PGCD](https://vozec.fr/crypto-rsa/rsa-0-maths-basis/) entre $g_1$ et $g_2$ pour retrouver $m_2$ dans l'anneau $Z/N$

$\implies z-m_1 = gcd(z^e  - c_1,(\alpha\*z+\beta)^e  - c_2) \in Z/N[m_1]$

Le temps d'exécution de cette méthode dépend de la puissance de calcul du PGCD , elle reste efficace jusqu'a des $e$ de 32 bits environ .
Elle est donc possible contre des $e=65537$ par exemple.

```python
>>> e = 65537
>>> e.bit_length()
17
```

## Implémentation en Python

- $m2 = a\*m1 + b$

### Avec Sympy
```python
def franklin_reiter(c1,c2,e,n,a,b):
	from sympy import poly,gcdex
	from sympy.abc import x

	g1 = poly((a*x + b)**e - c1)
	g2 = poly(x**e - c2)
	for res in gcdex(g1,g2):
		z = -res.coeffs()[-1]
		if z.is_integer and \
			len(res.coeffs()) == 2 :
			return z
```

### Avec SageMath
```python
def franklin_reiter(c1,c2,e,n,a,b):
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a.monic()
    P.<X> = PolynomialRing(Zmod(n))
    g1 = (a*X + b)^e - c1
    g2 = X^e - c2
    result = -gcd(g1, g2).coefficients()[0]
    return result
```


*Reference : [Low-Exponent RSA with Related Message](https://link.springer.com/content/pdf/10.1007/3-540-68339-9_1.pdf)*
