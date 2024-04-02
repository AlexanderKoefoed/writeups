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



## Lab: 

**Lab Description**: 

### Lab solution
