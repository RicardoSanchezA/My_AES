#### Compile Time:
  g++ -std=c++11 run_my_aes.c++ my_aes.c++ -o run_my_aes

#### Usage:
  (Encryption)
    ```
    ./run_my_aes -s 128 -k key.txt -i input.txt -o cipher.txt
    ```
  (Decryption)
    ```
    ./run_my_aes -s 128 -k key.txt -i cipher.txt -o output.txt -m decrypt
    ```
  (Print Help Menu)
    ```
    ./run_my_aes -h
    ```

 #### Testing:
   We provided a tool 'read_hex', so that you can easily read the cipher-
   text produced by our program.
   **(Sample 1)**
     >key: 00000000000000000000000000000000
     >input1: 00000000000000000000000000000000 
   ```
   ./run_my_aes -k key -i input1 -o out
   ./read_hex out
   ```
     >cipher-text: 66E94BD4EF8A2C3B884CFA59CA342B2E
   
   **(Sample 2)**
     >input2: 00112233445566778899AABBCCDDEEFF
   ```
   ./run_my_aes -k key -i input2 -o out2 -s 256
   ./read_hex out2
   ```
     >cipher-text: 1C060F4C9E7EA8D6CA961A2D64C05C18

##### Note when using CBC mode:
  When CBC mode is enabled, the program will use the first 16 bytes of the 
  key file to fill in the initialization vector. The actual key should begin
  AFTER those initial 16 bytes of the key file. 


