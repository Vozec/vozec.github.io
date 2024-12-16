---
title: "Like a Whispering Entropy | PWNME CTF 2023"
date: 2023-05-07T12:00:00Z
description: "Voici un writeup complet du dernier challenge Crypto du pwnme ctf"
tags: ["prng","lcg","aes","lwe"]
keywords: ["prng","lcg","aes","lattice"]
---
[//]: <> (Wrote By Vozec 07/05/2023)
---

# Introduction du challenge:

```
I don't trust those who wrote crypto implementations, so I had to write my own ...
I created everything from scratch so I know it is safe ! No one backdoored my Diffie-Hellman implementation !

Btw, I gave you an output of a connection to my service, but anyway you won't be able to get back the secret message
```

# Like a Whispering Entropy

Avec le challenge sont fournis 2 fichiers :
- logs
- chall.sage

Dans le premier, on a 100 fois ce groupe de lignes :  
```bash
-------------------------
Alice s public key: 303944725738104736773292818682761237676539243408422159733529747956894368678621645049645070627114278218945685944600948944992220099312948739268425436680143720194562111453986315120087316070223849151163596063751581483286506901176907235
User #99 public key: 809564025375502966704086026543808060813039551725974913290658576413572207289606703462020431496140057417889518191378472574633592651459369801336171048329445802174676004530841151781034766965662208992430242268851471075994293985371787031
encrypt(shared_secret, iv, FLAG) = {"iv": "17aa1262102cbb1ec366f7646e9ba610", "encrypted_msg": "587fd55183514a484382abf9bd79d882b10593de0b75782b1184b0ee38717c4f0570ed62780caf86f02c203e32c70d3c8f840f6b3e11b509cd422876fb8f1d550a8901db9ffa6204a8b7e947f7dde57a"}
-------------------------
```

Dans le second fichier, on a le challenge :
```python
#!/bin/env sage

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from Crypto.Util.number import getStrongPrime, long_to_bytes, bytes_to_long

import hashlib

from os import getenv, urandom
from random import getrandbits


FLAG = getenv("FLAG", "PWNME{dummyflag}").encode()


class PRNG(object):
    def __init__(self):
        self._seed = None
        self.q = 279622638356169037213136872013126932777
        self.n = 12
        self.A = Matrix(GF(self.q), 1, self.n, [
                19159356164385140466,
                19848194065535878410,
                33461959522325830456,
                12213590058439028697,
                35299014249932143965,
                13327781436808877193,
                20921178705527762622,
                9371898426952684667,
                9769023908222006322,
                28712160343104144896,
                32272228797175569095,
                14666990089233663894
            ])

        # LCG props
        self.a = getrandbits(32)
        self.c = getrandbits(32)
        self._lcgseed = getrandbits(32)
        self.mod = 2551431067

    @property
    def noise(self):
        self._lcgseed = (self.a * self._lcgseed + self.c) % self.mod
        return self._lcgseed

    @property
    def seed(self):
        if self._seed is None:
            self._seed = Matrix(GF(self.q), self.n, 1, [
                    getrandbits(102) for i in range(self.n)
                ])
            print('#################')
            print(self._seed)

        return self._seed

    def randint(self):        
        b = (self.A * self.seed + self.noise)[0][0]

        self.A = Matrix(GF(self.q), 1, self.n, [
                int(x * b^(i+1)) % 2^65 for i, x in enumerate(self.A[0])
            ])

        return b




def encrypt(shared_secret: int, iv: bytes, msg: bytes):
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(msg, 16))

    data = {}
    data['iv'] = iv.hex()
    data['encrypted_msg'] = ciphertext.hex()
    return data


def main():
    # Initialize PRNG:
    rng = PRNG()

    g = 2
    p = 1552518092300708935130918131258481755631334049434514313202351194902966239949102107258669453876591642442910007680288864229150803718918046342632727613031282983744380820890196288509170691316593175367469551763119843371637221007210577919

    n = 100

    ivs = [
        long_to_bytes(int(rng.randint())).ljust(16, b'\0') for _ in range(n)
    ]

    secret_keys = [
        int(rng.randint()) |
            int(rng.randint() << 128) |
            int(rng.randint() << 256) |
            int(rng.randint() << 384) |
            int(rng.randint() << 512) |
            int(rng.randint() << 640) for _ in range(n)
    ]

    public_keys = [
        pow(g, sk, p) for sk in secret_keys
    ]

    for i, e in enumerate(zip(ivs, secret_keys, public_keys)):
        iv, sk, pk = e
        print(f"Alice's public key: { pk }")

        pk2 = bytes_to_long(urandom(0x60))
        print(f"User #{i} public key: { pk2 }")

        shared_secret = pow(pk2, sk, p)

        print(f"{encrypt(shared_secret, iv, FLAG) = }")
        print(shared_secret)

        print("-------------------------")


if __name__ == '__main__':
    main()
```

# Analyse du code.

La première partie du code défini une *class* ``PRNG`` qui semble être un générateur de nombre.  
Nous y reviendrons plus tard.

Le code suivant fait ceci :
- Génère une liste d'``ivs``
- Génère une liste de clé ``publique``
- Génère une liste de clé ``privée``
- Génère 100 fois:
  - un nombre aléatoire *pk2*
  - $shared_{secret} = {pk2}^{sk} \pmod p$
  - Une clé AES à partir de $shared_{secret}$
  - Chiffre en ``AES CBC`` le flag avec cette clé.


Ainsi, si on arrive à récupérer une clé privée, on peut en utilisant la clé publique correspondante, présente dans le fichier *logs*, recalculer la clé **AES** et déchiffrer le flag chiffré !

Les ivs sont présents dans fichier *logs*, ceux-ci sont générés juste après l'initialisation de l'objet ``rng = PRNG()`` ce qui veut dire que nous avons les *100* premières valeurs du PRNG.

Si nous arrivons à récupérer l'état interne du PRNG en utilisant ces 100 ivs, nous pourrons re-générer les clés privées et ainsi flag.


## Analyse du Prng

Voici le code du PRNG :
```python
class PRNG(object):
    def __init__(self):
        self._seed = None
        self.q = 279622638356169037213136872013126932777
        self.n = 12
        self.A = Matrix(GF(self.q), 1, self.n, [
                19159356164385140466,
                19848194065535878410,
                33461959522325830456,
                12213590058439028697,
                35299014249932143965,
                13327781436808877193,
                20921178705527762622,
                9371898426952684667,
                9769023908222006322,
                28712160343104144896,
                32272228797175569095,
                14666990089233663894
            ])

        # LCG props
        self.a = getrandbits(32)
        self.c = getrandbits(32)
        self._lcgseed = getrandbits(32)
        self.mod = 2551431067

    @property
    def noise(self):
        self._lcgseed = (self.a * self._lcgseed + self.c) % self.mod
        return self._lcgseed

    @property
    def seed(self):
        if self._seed is None:
            self._seed = Matrix(GF(self.q), self.n, 1, [
                    getrandbits(102) for i in range(self.n)
                ])
        return self._seed

    def randint(self):        
        b = (self.A * self.seed + self.noise)[0][0]

        self.A = Matrix(GF(self.q), 1, self.n, [
                int(x * b^(i+1)) % 2^65 for i, x in enumerate(self.A[0])
            ])

        return b
```

A l'initialisation de l'objet, python génère 3 int de ``32`` bits:
- $a$
- $c$
- $lcgseed$

De plus il définit:
- $q$ à 279622638356169037213136872013126932777
- $n$ à 12
- $A$ une matrice dans $GF(q)$ de 12 éléments

A chaque appel à ``noise``, celui si se re-définit de la sorte:  
- $lcgseed = (a * lcgseed + c) % mod$


Au premier appel à ``seed``, on la génération d'une matrice colonne de 12 composantes de 102 bits:
```python
_seed = Matrix(GF(q), n, 1, [
    getrandbits(102) for i in range(n)
])
```
Par la suite, on notera $S_i$, la ième composante de la *seed*.


Enfin, à chaque appel à la fonction ``randint``
- un nombre $b$ est calculé de la manière suivante :  
  $b = (A\*seed + noise) \pmod q$
- La matrice $A$ est re-définit à partir de son statut actuel et du nombre généré $b$.
  Si on décompose la matrice $A$ au rang $i$ comme :
  - $A_i=(a_1,a_2,...,a_{12})$  
  alors nous avons:
  - $A_{i+1}=(a_1\*b^1,a_2\*b^2,...,a_{12}\*b^{12})$  

Ainsi, à chaque appel à la fonction ``randint``, si on note $N_i$ la valeur de *noise*; on a:  
- $b = A_i\*Seed + N_i$  
  $~= (a_{i,1},...,a_{i,12})*\begin{pmatrix}
  S_1  \newline
  S_2  \newline
  ...  \newline
  S_{12}  \newline
  \end{pmatrix} + N_i$


Ce type de générateur de nombre aléatoire ressemble à un ``LCG`` *(Linear Congruence Générator)* .  
Pourtant on remarque une différence avec un LCG classique :
- Le 2nd terme *noise* n'est pas constant !

En effet, la forme classique d'un ``LCG`` est :
- $state_{i+1} = state_{i}*m + c \pmod q$ avec c **constant** !

Cette différence est primordiale pour la suite.

## Premières recherches sur le LCG.

La première chose à faire est de recalculer toutes les matrices $A_i$ à partir de $A_0$ et des ivs générés:

```python
from Crypto.Util.number import bytes_to_long,long_to_bytes
from binascii import unhexlify
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getStrongPrime, long_to_bytes, bytes_to_long



def decode_iv(iv):
	b = unhexlify(bytes(iv,'utf-8')).strip(b'\0')
	return bytes_to_long(b)

def parser(data):
	alice,user,iv,enc = [],[],[],[]
	for line in data.split('\n'):
		if 'Alice' in line:
			alice.append(int(line.split("public key: ")[1]))
		if 'User' in line:
			user.append(int(line.split("public key: ")[1]))
		if 'encrypt' in line:
			info = eval(line.split("= ")[1])
			iv.append(decode_iv(info['iv']))
			enc.append(info['encrypted_msg'])
	return alice,user,iv,enc

alice,user,iv,enc = parser(open('logs','r').read())

q = 279622638356169037213136872013126932777
n = 12
As = [Matrix(GF(q), 1, n, [
	19159356164385140466,
	19848194065535878410,
	33461959522325830456,
	12213590058439028697,
	35299014249932143965,
	13327781436808877193,
	20921178705527762622,
	9371898426952684667,
	9769023908222006322,
	28712160343104144896,
	32272228797175569095,
	14666990089233663894
])]

for b in iv:
	As.append(Matrix(GF(q), 1,n, [ int(x * b^(i+1)) % 2^65 for i, x in enumerate(As[-1][0])]))

```


Une méthode d'attaque classique sur ce genre de PRNG serait de faire des combinaisons linéaires des nombres générés *(les ivs)* pour ainsi obtenir ce genre d'équations:

$b_{i+1}-b_{i} = A_{i+1}\*Seed + c - (A_i\*Seed + c) \pmod q$  
$\qquad\qquad= (A_{i+1}-A_i)\*Seed + c - c \pmod q$  
$\qquad\qquad= (A_{i+1}-A_i)\*Seed \pmod q$

On peut ainsi retrouver la valeur de la *seed*.

Ici, notre terme ``c`` n'est pas constant ce qui donnerai :  
$b_{i+1}-b_{i} = A_{i+1}\*Seed + c - (A_i\*Seed + c) \pmod q$  
$b_{i+1}-b_{i} = (A_{i+1}-A_i)\*Seed + (c_0 - c_1) \pmod{q}$

On peut ainsi exprimer de façon polynomial les $c_i$ de cette manière:

- $b0 = A0\*Seed + No$  
- $b1 = A0\*Seed + (N_0\*A+C)$

*(En notant $N_0$, le state initial (lcgseed dans le code))*

On a:  

$b_1-b_0 = ((A_1-A_0)\*Seed) \pmod{q} + (N_1 - N_0) \pmod{q_2}$  
$\qquad\quad= ((A_1-A_0)\*Seed) \pmod{q} + [ N0*a - N_0 + c] \pmod{q_2}$  

$b_2-b_1 = ((A_2-A_1)\*Seed) \pmod{q} + (N_2 - N_1) \pmod{q_2}$  
$\qquad\quad= ((A_2-A_1)\*Seed) \pmod{q} + (N_2 - (N_0\*a + c) ) \pmod{q_2}$  
$\qquad\quad= ((A_2-A_1)\*Seed) \pmod{q} + [((N_0\*a + c)\*a + c ) - (N_0\*a + c)] \pmod{q_2}$  
$\qquad\quad= ((A_2-A_1)\*Seed) \pmod{q} + [(N_0\*a^2 + c\*a +c)  - (N_0\*a + c)] \pmod{q_2}$  
$\qquad\quad= ((A_2-A_1)\*Seed) \pmod{q} + [N_0\*a^2 + c\*a + c - N_0\*a - c] \pmod{q_2}$  
$\qquad\quad= ((A_2-A_1)\*Seed) \pmod{q} + [N_0\*a^2 - N_0\*a + c*a] \pmod{q_2}$  
$\qquad\quad= ((A_2-A_1)\*Seed) \pmod{q} + [N_0\*a - N_0 + c] \* a \pmod{q_2}$  

$b_3-b_2 = ((A_3-A_2)\*Seed) \pmod{q} + (N_3 - N_2) \pmod{q_2}$  
$\qquad\quad= ((A_3-A_2)\*Seed) \pmod{q} + [N_3 - (N_0\*a^2 + c\*a +c)] \pmod{q_2}$  
$\qquad\quad= ((A_3-A_2)\*Seed) \pmod{q} + [(N_0\*a^2 + c\*a +c)\*a+c - (N_0\*a^2 + c\*a + c )] \pmod{q_2}$  
$\qquad\quad= ((A_3-A_2)\*Seed) \pmod{q} + [N_0\*a^3 + c\*a^2 +c\*a +c - N_0\*a^2 - c\*a - c] \pmod{q_2}$  
$\qquad\quad= ((A_3-A_2)\*Seed) \pmod{q} + [N_0\*a^3 - N_0\*a^2 + c\*a^2] \pmod{q_2}$  
$\qquad\quad= ((A_3-A_2)\*Seed) \pmod{q} + [ N0*a - N_0 + c] \* a^2 \pmod{q_2}$  

$b_4-b_3 = ((A_4-A_3)\*Seed) \pmod{q} + (N_4 - N_3) \pmod{q_2}$  
$\qquad\quad= ((A_4-A_3)\*Seed) \pmod{q} + [N_4 - (N_0\*a^3 + c\*a^2 +c\*a +c)] \pmod{q_2}$  
$\qquad\quad= ((A_4-A_3)\*Seed) \pmod{q} + [N_0\*a^4 + c\*a^3 + c\*a^2 +c \*a + c - N_0\*a^3 - c\*a^2 - c\*a - c]$  
$\qquad\quad= ((A_4-A_3)\*Seed) \pmod{q} + [N_0\*a^4 + c\*a^3 - N_0\*a^3] \pmod{q_2}$  
$\qquad\quad= ((A_4-A_3)\*Seed) \pmod{q} + [N_0\*a^4 - N_0\*a^3 + c\*a^3 ] \pmod{q_2}$  
$\qquad\quad= ((A_4-A_3)\*Seed) \pmod{q} + [ N_0\*a - N_0 + c] \* a^3 \pmod{q_2}$

*(En notant $q_2$, le modulo du 2nd LCG (mod dans le code))*


On obtient ainsi la relation de récurrence :
- $b_{i+1}-b{i} = (A_{i+1}-A_{i})\*Seed \pmod{q} + [N0*a-N_0+c]\*a^i \pmod{q_2}$

On peut compter le nombre d’inconnus :
- 12 pour la $Seed$
- $N_0$, $a$ et $c$  

Ainsi avec 15 équations de cette forme, nous devrions être capable de retrouver tous les inconnus.  

A ce stade du CTF, j'ai stoppé cette piste pour une simple.  
Pourtant, la méthode présentée devrait très bien fonctionner mais j'ai préféré faire autrement pour m'éviter l'implémentation d'un solver pour ce genre de système.  


## From Lattice to Crypto

Une chose notable est que le *noise* ne fait que 32 bits, il est ainsi bien inférieur au résultat de la multiplication matricielle $A_{i}\*Seed$ qui elle est dans $GF(q)=GF(279622638356169037213136872013126932777)$

Il est ainsi raisonnable d'écrire :
-  $\begin{cases}
  b_i = A_i\*Seed + N_i \pmod{q} \newline
  N_i << A_i\*Seed
  \end{cases}$

Ce genre de problème s'appelle un ``LWE`` crypto-système et l'utilisation de lattice nous permet de le résoudre.

Nous avons 100 IV d'où: $\exists~(k_1,k_2,...,k_{100})~\in~Z^{100}$ tel que:  

$\begin{cases}
b_1 - N_1 - k_{1}\*q = A_1\*Seed \newline
b_2 - N_2 - k_{2}\*q = A_2\*Seed \newline
...  \newline
\end{cases}$

  ce qui donne:

$\begin{cases}
b_1 - N_1 = A_1\*Seed + k_{1}\*q \newline
b_2 - N_2 = A_2\*Seed + k_{2}\*q \newline
...  \newline
b_{100} - N_{100} = A_{100}\*Seed + k_{100}\*q \newline
\end{cases}$

Sous forme matricielle, nous avons :  

$\begin{bmatrix}
   A_{1,1} & A_{1,1} & ... & A_{1,12} & q    & 0   & ... & 0 \newline
   A_{2,1} & ⋱       &     & ⋮        & 0    & q   & ... & 0 \newline
   ⋮       &         & ⋱   & ⋮        & ⋮     &     & ⋱ & 0 \newline
   A_{12,1} & ... & ... & A_{12,12}  & 0     & ... & ... & q \newline
\end{bmatrix}\*\begin{bmatrix}
S_1 \newline
⋮ \newline
S_{12} \newline
k_{1} \newline
⋮ \newline
k_{100} \newline
\end{bmatrix} = b-N$

et

$S_1\*\begin{bmatrix}
A_{1,1 }\newline
⋮ \newline
⋮ \newline
A_{100,1} \newline
\end{bmatrix} +~...~+S_n\begin{bmatrix}
A_{1,12} \newline
⋮ \newline
⋮ \newline
A_{100,12} \newline
\end{bmatrix} + k_1\* \begin{bmatrix}
q \newline
0 \newline
⋮ \newline
0 \newline
\end{bmatrix} + k_2\* \begin{bmatrix}
0 \newline
q \newline
⋮ \newline
0 \newline
\end{bmatrix} +~...~+ k_{100}\* \begin{bmatrix}
0 \newline
0 \newline
⋮ \newline
q \newline
\end{bmatrix} = b-N$

On a ainsi un réseau (Lattice) dans une base de $100+12=112$ vecteurs et nous devons trouver le plus petit vecteur s'approchant de $b-N$

L'erreur $N$ étant petite, on peut combiner l'utilisation de l'algorithme *LLL* ainsi que l'algorithme *du plan le plus proche de Babai* pour retrouver ce vecteur qui nous donnera la seed.

On a :
```python
def babai_closest_vector(M, G, target):
	small = target
	for i in reversed(range(M.nrows())):
		c = ((small * G[i]) / (G[i] * G[i])).round()
		small -=  M[i] * c
	return target - small

A = [list(As[i][0]) for i in range(1,2*n+1)]
B = [iv[i] for i in range(1,2*n+1)]

T = vector(B)
m = len(A)

L = matrix(ZZ, m + n,m)
L.set_block(0, 0, matrix(A).transpose())
L.set_block(n, 0, matrix.identity(m) * q)

X = L.LLL()
G = X.gram_schmidt()[0]

solution = babai_closest_vector(X[-m:, -m:], G, T)
seed = matrix(GF(q),matrix(GF(q), A).solve_right(solution)).transpose()
```

Ce cette manière on retrouve la seed !
```
[3058268284241006487061442364908]
[2402808679325168210186933401485]
[ 912561198398914062812833580123]
[3447026327735407212640466127880]
[3579826512545358844840553316487]
[3929680478630796447813590253380]
[3926341848877002242261661718906]
[ 292072138037108009618964395474]
[ 483084212078556642759837397862]
[1251756688835572777877914645198]
[ 473590955827537442363235226794]
[ 803861956621296089474035124354]
```

On peut donc isoler les $N_i$:
- $N_i \pmod{q_2} = b_i-A_i\*Seed$

```python
mod = 2551431067
Ni = [
  	int(GF(q)(iv[i]) - (matrix(GF(q), As[i])*seed)[0][0])
  	for i in range(len(A))
]
```

Nous avons enfin accès aux valeurs du 2nd PRNG qui lui est trivial à casser:

```python
m = ((Ni[2] - Ni[1]) * pow(Ni[1] - Ni[0],-1,mod)) % mod
c = (Ni[1] - Ni[0]*m) % mod
```

On obtient :
  - $m=1989529305$
  - $c=2273245205$

On peut ainsi retrouver $N_0$ = *self._lcgseed* initial:
```python
state_initial = pow(a,-1,mod)*(Ni[0]-c)%mod
```

Il ne nous reste plus qu'a modifier la Class d'origine pour y mettre l'état du PRNG :

```python
class PRNG(object):
	def __init__(self,a,c,state,seed):
		self._seed = None
		self.q = 279622638356169037213136872013126932777
		self.n = 12
		self.A = Matrix(GF(self.q), 1, self.n, [
				19159356164385140466,
				19848194065535878410,
				33461959522325830456,
				12213590058439028697,
				35299014249932143965,
				13327781436808877193,
				20921178705527762622,
				9371898426952684667,
				9769023908222006322,
				28712160343104144896,
				32272228797175569095,
				14666990089233663894
			])

		# LCG props
		self.a = int(a)
		self.c = int(c)
		self._lcgseed = int(state)
		self.mod = int(2551431067)

		# LCG
		self._seed = seed

	@property
	def noise(self):
		self._lcgseed = (self.a * self._lcgseed + self.c) % self.mod
		return self._lcgseed

	@property
	def seed(self):
		return self._seed

	def randint(self):
		b = (self.A * self.seed + self.noise)[0][0]
		self.A = Matrix(GF(self.q), 1, self.n, [
			int(x * b^(i+1)) % 2^65 for i, x in enumerate(self.A[0])
		])
		return b

rng = PRNG(
	a=a,
	c=c,
	state=state_initial,
	seed=seed
)

```


Enfin, on regénère les clés privées pour déchiffrer le flag :

```python
n = 100
p = 1552518092300708935130918131258481755631334049434514313202351194902966239949102107258669453876591642442910007680288864229150803718918046342632727613031282983744380820890196288509170691316593175367469551763119843371637221007210577919


ivs = [long_to_bytes(int(rng.randint())).ljust(16, b'\0') for _ in range(n)]
secret_keys = [int(rng.randint()) | int(rng.randint() << 128) | int(rng.randint() << 256) | int(rng.randint() << 384) | int(rng.randint() << 512) | int(rng.randint() << 640) for _ in range(n)]

shared_secret = pow(user[0], secret_keys[0], p)
sha1 = hashlib.sha1()
sha1.update(str(shared_secret).encode('ascii'))
key = sha1.digest()[:16]

cipher = AES.new(key, AES.MODE_CBC, ivs[0])
print(unpad(cipher.decrypt(unhexlify(bytes(enc[0],'utf-8'))),16))
```

*Ouput*:
```bash
⚡ root  share  ✘  sage solver3.sage
b'PWNME{d334d082994743b12464c529ea597ed85dcd08e49e6d2d644b46f295b24a2f25}'
```

Voici le code complet de solve:
```python
from Crypto.Util.number import bytes_to_long,long_to_bytes
from binascii import unhexlify
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getStrongPrime, long_to_bytes, bytes_to_long

class PRNG(object):
	def __init__(self,a,c,state,seed):
		self._seed = None
		self.q = 279622638356169037213136872013126932777
		self.n = 12
    self.A = Matrix(GF(self.q), 1, self.n, [19159356164385140466,19848194065535878410,33461959522325830456,12213590058439028697,35299014249932143965,13327781436808877193,20921178705527762622,9371898426952684667,9769023908222006322,28712160343104144896,32272228797175569095,14666990089233663894])
		# LCG props
		self.a = int(a)
		self.c = int(c)
		self._lcgseed = int(state)
		self.mod = int(2551431067)

		# LCG
		self._seed = seed

	@property
	def noise(self):
		self._lcgseed = (self.a * self._lcgseed + self.c) % self.mod
		return self._lcgseed

	@property
	def seed(self):
		return self._seed

	def randint(self):
		b = (self.A * self.seed + self.noise)[0][0]
		self.A = Matrix(GF(self.q), 1, self.n, [
			int(x * b^(i+1)) % 2^65 for i, x in enumerate(self.A[0])
		])
		return b

def decode_iv(iv):
	b = unhexlify(bytes(iv,'utf-8')).strip(b'\0')
	return bytes_to_long(b)

def parser(data):
	alice,user,iv,enc = [],[],[],[]
	for line in data.split('\n'):
		if 'Alice' in line:
			alice.append(int(line.split("public key: ")[1]))
		if 'User' in line:
			user.append(int(line.split("public key: ")[1]))
		if 'encrypt' in line:
			info = eval(line.split("= ")[1])
			iv.append(decode_iv(info['iv']))
			enc.append(info['encrypted_msg'])
	return alice,user,iv,enc

logs = open('logs','r').read()
alice,user,iv,enc = parser(logs)

# Re-Calculate Matrix Ai
q = 279622638356169037213136872013126932777
n = 12
As = [Matrix(GF(q), 1, n, [
	19159356164385140466,
	19848194065535878410,
	33461959522325830456,
	12213590058439028697,
	35299014249932143965,
	13327781436808877193,
	20921178705527762622,
	9371898426952684667,
	9769023908222006322,
	28712160343104144896,
	32272228797175569095,
	14666990089233663894
])]

for b in iv:
	As.append(Matrix(GF(q), 1,n, [ int(x * b^(i+1)) % 2^65 for i, x in enumerate(As[-1][0])]))

def babai_closest_vector(M, G, target):
	small = target
	for i in reversed(range(M.nrows())):
		c = ((small * G[i]) / (G[i] * G[i])).round()
		small -=  M[i] * c
	return target - small

A = [list(As[i][0]) for i in range(1,2*n+1)]
B = [iv[i] for i in range(1,2*n+1)]

T = vector(B)
m = len(A)

L = matrix(ZZ, m + n,m)
L.set_block(0, 0, matrix(A).transpose())
L.set_block(n, 0, matrix.identity(m) * q)

X = L.LLL()
G = X.gram_schmidt()[0]

solution = babai_closest_vector(X[-m:, -m:], G, T)

seed = matrix(GF(q),matrix(GF(q), A).solve_right(solution)).transpose()


Ni = [
	int(GF(q)(iv[i]) - (matrix(GF(q), As[i])*seed)[0][0])
	for i in range(len(A))
]

mod = 2551431067
a = ((Ni[2] - Ni[1]) * pow(Ni[1] - Ni[0],-1,mod)) % mod
c = (Ni[1] - Ni[0]*a) % mod

state_initial = pow(a,-1,mod)*(Ni[0]-c)%mod
rng = PRNG(
	a=a,
	c=c,
	state=state_initial,
	seed=seed
)

n,p =100,1552518092300708935130918131258481755631334049434514313202351194902966239949102107258669453876591642442910007680288864229150803718918046342632727613031282983744380820890196288509170691316593175367469551763119843371637221007210577919

ivs = [long_to_bytes(int(rng.randint())).ljust(16, b'\0') for _ in range(n)]
secret_keys = [
  int(rng.randint()) |
  int(rng.randint() << 128) |
  int(rng.randint() << 256) |
  int(rng.randint() << 384) |
  int(rng.randint() << 512) |
  int(rng.randint() << 640)
  for _ in range(n)
]

shared_secret = pow(user[0], secret_keys[0], p)

sha1 = hashlib.sha1()
sha1.update(str(shared_secret).encode('ascii'))
key = sha1.digest()[:16]

cipher = AES.new(key, AES.MODE_CBC, ivs[0])
print(unpad(cipher.decrypt(unhexlify(bytes(enc[0],'utf-8'))),16))
```
