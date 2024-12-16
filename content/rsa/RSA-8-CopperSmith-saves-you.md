---
title: "RSA n°8 | CopperSmith saves you"
date: 2022-12-08T14:00:00Z
description: "Attaques de CopperSmith sur le chiffrement RSA"
tags: ["rsa","cryptographie","crypto"]
keywords: ["tuto", "rsa", "RSA", "crypto","maths","euclide","cryptographie","cryptography","pgcd"]
---
[//]: <> (Created By Vozec 30/11/2021)
---

# Introduction :  
Don Coppersmith est un mathématicien et cryptologue américain né en 1950.
Il a contribué dans de nombreux domaines de la ``Cryptographie`` et en particulier le chiffrement RSA.  
Il s'intéresse particulièrement aux liens possibles entre des **notions d'algèbres** et les mathématiques arithmétiques du chiffrement RSA

# Papier de recherche:  
CopperSmith présente un papier de recherche mathématique nommé : [*Finding Small Solutions to Small Degree Polynomials*](https://cr.yp.to/bib/2001/coppersmith.pdf)  
Il y explique comment trouver les racines de polynômes à ``1`` et ``2`` variables , modulo un entier **n**  grâce à la réduction de base via des matrices et l'algorithme ``Lenstra–Lenstra–Lovász`` *(LLL)*.
C'est racines sont appelées *Small Roots* et la technique de Coppersmith a été optimisée par ``Howgrave-Graham``.


# Application au RSA:

## Premier cas : *Clair connu*  
On suppose qu'on soit en présence d'un message chiffré classiquement ainsi qu'une partie de texte déchiffré.

- Exemple:
	c = *Bonjours , voici votre clé privée : XXXXXX"*  
Ici *"Bonjours , voici votre clé privée :"* est une clair connu et on peut l'exploiter pour retrouver le message d'origine , complet.

### Condition & Mise en équation :  

On a d'habitude :  
-	$\begin{cases}
	n = p*q \newline
	c = m^e \pmod n
	\end{cases}$

Ici , on peut écrire ``M`` la partie connu et ``m`` la fin du message :  
-	$\begin{cases}
	n = p*q \newline
	c = (M+m)^e \pmod n
	\end{cases}$

### Condition:
*(Cas e=3)* CopperSmith a montré que cette attaque était efficace si :  
 - $x < \dfrac{1}{2} N^{\dfrac{1}{δ}-e}$  
	 $\implies x < 0.167$

On se place ici dans **$Z/nZ$**  , on pose le polynôme *(e=3)*:  
- $f:x \rightarrow (m+x)^e - c$  
	$\implies f(x) = x^3+3mx^2+3m^2x+m^3-c$  
	$\implies δ=3$  

On cherche $x$ tel que **$f(x) = 0 \pmod n$**.
Ce $x$ correspond au bits manquants du message, la partie ``m`` du message complet.
Cela est possible grâce à l'algorithme LLL de réduction de base.


### Résolution :
On peut utiliser SageMath qui contient directement *Small Roots* d'implémenté pour résoudre cette équation polynomiale:

```python
def coppersmith(msg,c,n,e,eps=1/20):
	def get_limit(msg):
		spl = msg.split('\x00')
		x = max(len(spl[0]),1)
		x_2 = 1
		while(x_2 < x):
			x_2 *= 2
		y = max(len(spl[-1]),1)
		return x_2,y

	a,b = get_limit(msg)
	msg = int(msg.encode("utf-8").hex(), 16)

	P.<x> = PolynomialRing(Zmod(n))
	f = (msg + (a^b)*x)^e - c
	f = f.monic()
	return f.small_roots(epsilon=eps)
```

- Exemple:
	```python
	n = 805467500635696403604126524373650578882729068725582344971555936471728279008969317394226798274039587275908735628164913963756789131471531490012281262137708844664619411648776174742900969650281132608104486439462068493207388096754400356209191212924158917441463852311090597438686723680422989566039830705971272945580630621308622704812919416445637277433384864510484266136345300166188170847768250622904194100556098235897898548354386415341541887443486684297114240486341073977172459860420916964212739802004276614553755113124726331629822694410052832980560107812738167277181748569891715410067156205497753620739994002924247168259596220654379789860120944816884358006621854492232604827642867109476922149510767118658715534476782931763110787389666428593557178061972898056782926023179701767472969849999844288795597293792471883445525249025377326859655523448211020675915933552601140243332965620235850177872856558184848182439374292376522160931072677877590262080551636962148104050583711183119856867201924407132152091888936970437318064654447142605921825771487108398034919404885812834444299826080204996660391375038388918601615609593999711720104533648851576138805705999947802739408729788376315233147532770988216608571607302006681600662261521288802804512781133
	e = 5
	c = 321344338551168130701947757669249162791535374419225256466002854387287697945811581844875867845545337575193797350159207497966826027124926618458827324785590115214765980153475875175895244152171945352397663605222668892070894285036685408001675776259216704639659684767335997326195127379070104670798191048101430782486785148455557975065509824478935393935463232461294974471055239751453456270779997852527271795223623224696998441762750417393944955667837832299195592347653873362173157136283926817115042942127695355760288879165245940595259284499711202547364332122472169897570069773912201877037737474884548477516093671861643329899650704311880900221217905929830674467383904928054908475945599046498840246878554674443087280023564313470872269644230953001876937807402083390603760508851259383686896871724061532464374712413952574633098739843484563001012414107193262431117290853995664646176812763789444386869148000606985026530596652927567162641583951775993815884965569050328445927871220492529331846189285588168127051152438658813934744257031316581112434690871286836998078235766836485498780504037745116357109237384369621143931229920342036890494878183569174869563857473355851368119174926388706612127773670862261189669510108216517652686402185979222505401328291

	msg = "this challenge was supposed to be babyrsa but i screwed up and now i have to redo the challenge.\nhopefully this challenge proves to be more worthy of 250 points compared to the 200 points i gave out for babyrsa :D :D :D\nyour super secret flag is: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nyou know what i'm going to add an extra line here just to make your life miserable so deal with it"
	msg = msg.replace("X","\x00")
	m = coppersmith(msg,c,n,e)
	```
[Exemple du UIUCTF](https://github.com/hgarrereyn/Th3g3ntl3man-CTF-Writeups/tree/master/2017/UIUCTF/problems/Cryptography/papaRSA)

## Deuxième cas : *ShortPad Attack*

Dans cette nouvelle attaque, on possède *2* fois le même message chiffré mais paddé de deux manières différentes .  

**CopperSmith** nous indique qu'il est possible , à condition que la padding ne soit pas trop grand , de trouver le contenu du message.

Il utilise ses précédentes recherches sur la résolution polynomiale dans **$Z/nZ$** ainsi que les recherches sur la récupération de messages par lien affines. *([voir franklin reiter ici](https://vozec.fr/crypto-rsa/rsa-7-hey-this-is-franklin/))*.


### Démonstration

-	$\begin{cases}
	g_1(x,y) = x^e - C_1 \newline
	g_2(x,y) = (x+y)^e - C_2 \pmod n
	\end{cases}$

Alors quand $y = r_2 - r_1$ , alors $g_1$ et $g_2$ ont pour racine commune : $x=m_1$
On pose *res* la [résultante](https://en.wikipedia.org/wiki/Resultant) de 2 polynômes
$\implies \begin{cases}
\Delta = r_2-r_1 \newline
h(y) = res_x(g1,g2) \in Z_n[y]\pmod n \newline
h(\Delta) = 0 % n
\end{cases}$

- $|\Delta| < 2^m < N^{\dfrac{1}{e^2}}$  
D'ou $\Delta$ est *small roots* de $h$ *$\pmod n$* et peut donc être retrouvé grâce à la méthode de Coppersmith.  
Quand $\Delta$ est connu, **Franklin–Reiter** permet de retrouver $m_2$

[Référence: Wikipedia](https://en.wikipedia.org/wiki/Coppersmith%27s_attack)

### Implémentation en python :

```python
def short_pad_attack(c1, c2, e, n):
    PRxy.<x,y>   = PolynomialRing(Zmod(n))
    PRx.<xn>     = PolynomialRing(Zmod(n))
    PRZZ.<xz,yz> = PolynomialRing(Zmod(n))

    g1 = x^e - c1
    g2 = (x+y)^e - c2

    q1 = g1.change_ring(PRZZ)
    q2 = g2.change_ring(PRZZ)

    h = q2.resultant(q1)
    h = h.univariate_polynomial()
    h = h.change_ring(PRx).subs(y=xn)
    h = h.monic()

    kbits = n.nbits()//(2*e*e)
    delta = h.small_roots(X=2^kbits, beta=0.5)[0]

    return delta
```
*(Script SageMath)*

Un fois $\Delta$ retrouvé, on peut appliquer [Franklin Reiter](https://vozec.fr/crypto-rsa/rsa-7-hey-this-is-franklin/) :

```python
def franklin_reiter(c1,c2,e,n,delta):
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a.monic()
    P.<x> = PolynomialRing(Zmod(n))
    g1 = x^e - c1
    g2 = (x+delta)^e - c2
    result = -gcd(g1, g2).coefficients()[0]
    return result
```
