# Introduction
In this challenge we have a web services where user can register, login, and upload/download file.
# Solution analysis
Looking at the source code we see that the flag is saved in the file flag.txt from the user intruder:
```python
save_file_into_db(2, "intruder", "flag.txt", bytes(os.environ["FLAG"], 'utf8'))
```
The intruder user is created with a random password, so we can't do the login as the intruder.
This is how the file is saved:
```python
def save_file_into_db(user: int, username: str, filename: str, content: str):
    total_name = bytes(f"{username}/{filename}", "utf8")
    z = secp192k1.hash_bits(total_name)
    r, s = secp192k1.sign(z, next(rng), private_key)
    save_file(r, s, user, filename, content)
    return f"/files/{s:x}?key={r:x}"
```
Where `secp192k1` is a custom elliptic curve implementation, that follows the standard.
The `private_key` isn't leaked anywhere and is saved in a file where we don't have access to his value. (In test we have different value from the real challenge).
The nonce is calculated by `next(rng)` that use a PRNG:
```python
def BlumBlumShub(p: int, q: int, seed: int):
    assert q % 4 == 3 and p % 4 == 3
    M = q * p
    xn = seed * q % M
    while True:
        xn = (xn * xn) % M
        yield xn
```
A good test to do is to check if the value will be loop (looking at the [official solve](https://github.com/WuerthPhoenix/wpctf2024/blob/main/crypto/hard/safe-fileshare/writeup.md), this happens because $x_0$ isn't co-prime with $M$). So we know that the nonce is reused, we see that because the value of $r$ will be the same, since $r$ depends only to the nonce.
Using this information we can check on internet how to exploit this vulnerability, arriving for example at this [page](https://www.halborn.com/blog/post/how-hackers-can-exploit-weak-ecdsa-signatures) that tell us how to calculate the `private_key`.
Having the `private_key, r, s` we can calculate `k`.
Now we can check for all `r, s` the used `k` and calculate the `r, s` for the file where the flag is stored and look for a response that give us 200.
# Script
```python
import requests
import random
import string
from math import gcd
from sympy import mod_inverse, sqrt_mod
from ec import secp192k1

BASE_URL = "http://challenges.wpctf.it:35868"
REGISTER_URL = f"{BASE_URL}/auth/register.html"
LOGIN_URL = f"{BASE_URL}/auth/login.html"
UPLOAD_URL = f"{BASE_URL}/upload"
USERNAME = "testuser"
PASSWORD = "testpassword"

# Lista to save all r e s
uploaded_r_s = []

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def register_user(username, password):
    response = requests.post(REGISTER_URL, data={"username": username, "password": password})
    if response.status_code == 200:
        print(f"User {username} registered successfully.")
    else:
        print(f"Registration failed for {username}. Status code: {response.status_code}")

def login_user(username, password):
    session = requests.Session()
    response = session.post(LOGIN_URL, data={"username": username, "password": password})
    if response.status_code == 200:
        print(f"User {username} logged in successfully.")
        return session
    else:
        print(f"Login failed for {username}. Status code: {response.status_code}")
        return None

def upload_file(session, filename, content):
    files = {'file': (filename, content)}
    response = session.post(UPLOAD_URL, files=files)
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"File upload failed. Status code: {response.status_code}")
    return None

def check_previous_r(r_value):
    for prev_r, prev_s, upload_number in uploaded_r_s:
        if r_value == prev_r:
            return upload_number
    return None

def calculate_k(total_name: str, r: int, s: int, private_key: int) -> int:
    z = secp192k1.hash_bits(total_name.encode("utf-8"))
    n = secp192k1.n
    s_inv = mod_inverse(s, n)

    k = (s_inv * (z + r * private_key)) % n

    return k

def calculate_private_key(r, s1, s2, total_name1, total_name2):
    denominator = (r * (s1 - s2)) % secp192k1.n
    if denominator == 0:
        raise ValueError("Denominator is zero, cannot calculate private key.")
    denominator_inv = mod_inverse(denominator, secp192k1.n)
    private_key = (secp192k1.hash_bits(total_name1.encode('utf-8')) * s2 - secp192k1.hash_bits(total_name2.encode('utf-8')) * s1) * denominator_inv % secp192k1.n
    return private_key

def get_flag(session, r,s):
    try:
        url = f"{BASE_URL}/files/{s:x}?key={r:x}"
        response = session.get(url)
        if response.status_code == 200:
            print("DONE", url)
    except Exception as e:
        print(e)
        pass

def main():
    register_user(USERNAME, PASSWORD)
    
    session = login_user(USERNAME, PASSWORD)

    upload_count = 1
    all_filename=[]
    while True:
        filename = random_string()+"txt"
        all_filename.append(filename)
        response = upload_file(session, filename, "TEST")
        if response:
            for url in response["download_urls"]:
                if "/files/" in url and "?key=" in url:
                    s_value = url.split('/files/')[1].split('?key=')[0]
                    r_value = url.split('?key=')[1] 

                    
                    upload_number = check_previous_r(r_value, s_value, upload_count)
                    if upload_number != None:
                        prev_r, prev_s, upload = uploaded_r_s[upload_number-1]
                        prev_filename= all_filename[upload_number-1]

                        private_key = calculate_private_key(int(r_value, 16),int(prev_s,16), int(s_value,16), USERNAME + "/" + prev_filename, USERNAME +"/"+filename)

                        k = int(calculate_k(USERNAME +"/" + filename, int(r_value,16), int(s_value,16), private_key))

                        hash_flag = secp192k1.hash_bits("intruder/flag.txt".encode("utf-8"))
                        #We found the loop so now we have to check all k in order to find the r and s 
                        for i in range(upload_count):
                            response = upload_file(session, filename, "TEST")
                            s_value = response["download_urls"][0].split('/files/')[1].split('?key=')[0]
                            r_value = response["download_urls"][0].split('?key=')[1]
                            k = int(calculate_k(USERNAME + "/" + filename, int(r_value,16), int(s_value,16), private_key))
                            r, s = secp192k1.sign(hash_flag, k, private_key)
                            get_flag(session,r,s)
                        return

                    uploaded_r_s.append((r_value, s_value, upload_count))

        upload_count += 1

if __name__ == "__main__":
    main()
```