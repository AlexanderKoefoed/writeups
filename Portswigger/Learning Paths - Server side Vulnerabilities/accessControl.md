# Access Control

The next step of this path, considers access control.

## Part 1: Vertical privilege escalation

Vertical privilege escalation is when a user can gain access to functionality that they are not permitted to access. An example could be a non-admin user gaining access to the admin control panel in a web application.

### Unprotected Functionality

Vertical privilege escalation arises when an application does not enforce any protection (at its most basic).

This means that the url `www.insecure.com/admin` might be accessible when authenticated as a non-admin user. The path can be found by using brute-forcing methods (dirbuster etc) or by viewing the robots.txt file.

## Lab: Unprotected admin functionality

**Lab Description**: This lab has an unprotected admin panel. Solve the lab by deleting the user `carlos.`

### Lab solution

The lab presents a webshop with login functionality. We are not provided a user, which hints that we should find the admin panel without authenticating or bruteforce a user. As bruteforcing is unlikely in this lab scenario, I chose to see if the robots.txt file included any information:

`https://0ad8006704bd270d807bf9fe004d005c.web-security-academy.net/robots.txt` contained the following:

``` JSON
User-agent: *
Disallow: /administrator-panel
```

Visiting the `/administrator-panel` path, presents us with the required functionality to delete the `carlos` account, thus solving the lab.

## Unprotected Functionality - Continued

An example of "security by obscurity" is given next, where some applications try to "hide" their privleged functionality behind obscure paths. An example is `https://insecure-website.com/administrator-panel-yb556` where the panel might not be guessable, but can still be bruteforced or discovered in source code, like a link to the admin panel is given if the authenticated user has admin privileges.

``` html
<script>
 var isAdmin = false;
 if (isAdmin) {
  ...
  var adminPanelTag = document.createElement('a');
  adminPanelTag.setAttribute('https://insecure-website.com/administrator-panel-yb556');
  adminPanelTag.innerText = 'Admin panel';
  ...
 }
</script>
```

The above script adds a link to the UI if the user is authenticated as an admin. The admin panel URL (path) is visible to anyone inspecting the code however.

## Lab: Unprotected admin functionality with unpredictable URL

**Lab Description**  This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application. Solve the lab by accessing the admin panel, and using it to delete the user `carlos`.

### Lab solution

As described in the earlier paragraph, the vulnerability lies in the javascript generating the admin URL, present the admin URL in plaintext:

``` Javascript
var isAdmin = false;
if (isAdmin) {
   var topLinksTag = document.getElementsByClassName("top-links")[0];
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', '/admin-or17mv');
   adminPanelTag.innerText = 'Admin panel';
   topLinksTag.append(adminPanelTag);
   var pTag = document.createElement('p');
   pTag.innerText = '|';
   topLinksTag.appendChild(pTag);
}
```

After appending the `admin-or17mv` to the URL of the webshop we are presented with the admin functionality.

## Parameter-based access control methods

This type of access control defines the access rights (permissions) and/role (authorization) at login and stores this information in user-controllable locations:

- A hidden field
- A cookie
- A preset query string parameter (`https://insecure-website.com/login/home.jsp?admin=true`)

If the user is able to modify these parameters (as they often are, in query parameters and un-encrypted cookies) they can access admin functionality.

## Lab: User role controlled by request parameter

**Lab Description**:  This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie. Solve the lab by accessing the admin panel and using it to delete the user `carlos`. You can log in to your own account using the following credentials: `wiener:peter`

### Lab solution

When logging in to the provided account, we see that a cookie is set: `Admin=false`. This cookie is not encrypted or protected in anyway, which means that the user can modify it. By simply setting the cookie in the browser to `Admin=true` and reloading the Account panel, the admin panel link appears.

## Part 2: Horizontal privilege escalation

Horizontal privilege escalation occurs when user can gain access to other users data and functions. With horizontal escalation does not necessarily grant more permissions than the user currently has, just access to resources which do not belong to the escalating user. This type of vulnerability is also called "Insecure direct object reference" or IDOR. It arises when a user-controlled parameter is used to access resources or functions directly.

## Lab: User ID controlled by request parameter, with unpredictable user IDs

**Lab Description**:  This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs. To solve the lab, find the GUID for `carlos`, then submit his API key as the solution. You can log in to your own account using the following credentials: `wiener:peter`.

### Lab solution

We are presented with a blog site, where users can post and comment on blogs. Also, we are provided with a user. When logging in to this user we see that the user IDs are GUID (Globally unique identifiers), which aren't predictable. Since the task is to leak Carlos' API key, we should find a way to figure out the GUID of his account.

The author of each blog post is presented, with a link to their other posts using the URL `/blogs?userId={some-id}`. This suggest we can find the GUID of Carlos by viewing the HTML `<a>` tag. 

Sure enough, contained in the HTML is the GUID of Carlos: 

``` HTML
<span id="blog-author">
    <a href="/blogs?userId=a8d45891-eac2-48b4-a05c-a659e39ed692">carlos</a>
</span>

```

We then to "My account" (`https://0a7f003b04cce46981116bf700330095.web-security-academy.net/my-account?id=3f4e530d-69ae-492c-8842-b03d1c60992c`) and substitute the id with Carlos GUID like so: `https://0a7f003b04cce46981116bf700330095.web-security-academy.net/my-account?id=a8d45891-eac2-48b4-a05c-a659e39ed692`.

After submitting his API key we solve the lab:

``` HTML
    <p>Your username is: carlos</p>
    <div>Your API Key is: htwVq11IkuERmqfN9cErj0Oz2wF0jaCu</div>
```

## Horizontal to vertical privilege escalation

This kind of privilege escalation happens when a user can gain access to a different user with a higher level of privilege, such as an admin account. 

## Lab: User ID controlled by request parameter with password disclosure

**Lab Description**: This lab has user account page that contains the current user's existing password, prefilled in a masked input. To solve the lab retrieve the administrator's password, then use it to delete the user `carlos`. You can log in to your own account using the following credentials: `wiener:peter`

### Lab solution

An account is supplied and when logging in, it is seen that the URL contains the account id. This time the username is used as the ID as follows: `https://0aa2005b036186dd83536ebd009d00fb.web-security-academy.net/my-account?id=wiener`. Futhermore the my account page provides a update password functionality which shows the current password (it is masked, but visible in the HTML form.):

``` HTML
<input required="" type="password" name="password" value="peter">
```

If the query param `id` is changed to `administrator` like so: `my-account?id=administrator`, the account page will be loaded for the admin account, a long with the prefilled password change field. The admin password is obtained by finding it in the HTML or by viewing it in the raw response from the server.

admin password : *ns5aspxaj656s0hlo58e*

Then, the password is used to login as the admin, and complete the lab by deleting the user *Carlos*.

