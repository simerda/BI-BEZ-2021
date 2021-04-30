# Úkol 4 - Hybridní šifrování

## Deklarce hlavičky zašifrovaného souboru

| Pozice | Délka | Struktura | Popis |
|:----------|:-------------|:-------------|:------|
| 0 | 4 B | int | Nid - A numerical identifier for an OpenSSL object. (použitá symetrická šifra) |
| 4 | 4 B | int | elk - Délka zašifrovaného klíče |
| 8 | ekl B | unsigned char\[ekl\] | Zašifrovaný klíč pomocí RSA |
| 8 + ekl | ivLen B | unsigned char\[ivLen\] | Inicializační vektor použité symetrické šifry |
| 8 + ekl + ivLen | délka in_soubor + padding B | binární data | zašifrovaná data |

## Použití

### Kompilace

```console
foo@bar:~$ make all
g++ -Wall -pedantic -o open.out  open.cpp -lcrypto
g++ -Wall -pedantic -o seal.out  seal.cpp -lcrypto
```

### Spuštění

> *Upozornění:* Všechny 3 parametry jsou pro spuštění `seal.out` vyžadovány. Jako argument pro symetrickou šifru je požadováno textové označení přijímané funkcí `EVP_get_cipherbyname()`. 

```console
foo@bar:~$ ./seal.out pubkey.pem inFile.bin camellia-192-cbc
foo@bar:~$ ./open.out privkey.pem inFile.bin_seal
foo@bar:~$ diff inFile.bin inFile.bin_seal_opened
```