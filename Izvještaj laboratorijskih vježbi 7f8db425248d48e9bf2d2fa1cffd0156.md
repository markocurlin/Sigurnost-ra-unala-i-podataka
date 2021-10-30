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

```
./start.sh
./stop.sh
```

### Pokrećanje iteraktivnog shella u station-1 kontenjeru

```
docker exec -it station-1 bash
```

### Provjera nalazi li se station-2 na istoj mreži

```
ping station-2
```

### Pokrećanje iteraktivnog shella u station-2 kontenjeru

```
docker exec -it station-2 bash
```

### Pomoću netcat-a otvaramo server na portu 9000 na kontenjeru station-1

```
netcat -lp 9000
```

### Pomoću netcat-a otvaramo client na hostname-u station-1 9000 na kontenjeru station-2

```
netcat station-1 9000
```

### Pokrećanje iteraktivnog shella u evil-station kontenjeru

```
docker exec -it evil-station bash
```

### Pokrećemo arpspoof u kontenjeru evil-station

```
arpspoof -t station-1 station-2
```

### U kontenjeru evil-station pokrećemo tcpdump i pratimo promet

```
tcpdump
```

```
tcpdump -X host station-1 and not arp
```

### Prekidamo napad

```
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

```jsx
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