### Compilation:
```
g++ -std=c++11 run_my_aes.c++ my_aes.c++ -o run_my_aes
```


### Usage:
(Encryption)
```
./run_my_aes --keysize 128 --keyfile test_files/key --inputfile test_files/input --outputfile test_files/cipher
```

(Decryption)
```
./run_my_aes -s 128 -k test_files/key -i test_files/cipher -o test_files/output --mode decrypt
```
    
(Print Help Menu)
```
./run_my_aes --help
```



 ### Testing:
   We provided a tool 'read_hex', so that you can easily read the cipher-text produced by our program. To compile it:
   
```
g++ -std=c++11 read_hex.c++ -o read_hex
```
   
 **(Sample 1)** 128-bit
 
`key1: 00000000000000000000000000000000`

`input1: 00000000000000000000000000000000`
     
```
./run_my_aes --keyfile test_files/key1 --inputfile test_files/input1 --outputfile test_files/cipher1
./read_hex test_files/cipher1
```
   
> cipher-text: 66E94BD4EF8A2C3B884CFA59CA342B2E
   
   
**(Sample 2)** 256-bit

`key2: 00000000000000000000000000000000`

`input2: 00112233445566778899AABBCCDDEEFF`
     
```
./run_my_aes -k test_files/key2 -i test_files/input2 -o test_files/cipher2 -s 256
./read_hex test_files/cipher2
```
   
> cipher-text: 1C060F4C9E7EA8D6CA961A2D64C05C18
   
   
**(Sample 3)** 128-bit w/CBC Mode

`key3: 000102030405060708090A0B0C0D0E0F2b7e151628aed2a6abf7158809cf4f3c`

`input3: 6bc1bee22e409f96e93d7e117393172a`

```
./run_my_aes -k test_files/key3 -i test_files/input3 -o test_files/cipher3 --cbc
./read_hex test_files/cipher3
```

> cipher-text: 7649abac8119b246cee98e9b12e9197d
   


**(Sample 4)** 256-bit w/CBC Mode

`key4: F58C4C04D6E5F1BA779EABFB5F7BFBD6603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4`

`input4: ae2d8a571e03ac9c9eb76fac45af8e51`

```
./run_my_aes -s 256 -k test_files/key4 -i test_files/input4 -o test_files/cipher4 -c
./read_hex test_files/cipher4
```

> cipher-text: 9cfc4e967edb808d679f777bc6702c7d


**CBC mode note:** When CBC mode is enabled, our program will use the first 16 bytes of the key file to fill in the initialization vector. The actual key should begin AFTER those initial 16 bytes of the key file. For instance, in *Sample 3* the I.V. is "000102030405060708090A0B0C0D0E0F" and the actual 128-bit key is "2b7e151628aed2a6abf7158809cf4f3c".
