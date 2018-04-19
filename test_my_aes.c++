#include<iostream>
#include <string>
#include<stdio.h>
#include<ctype.h>
#include<stdlib.h>
#include <getopt.h>

#include "my_aes.h"

using namespace std;


int main(int argc, char **argv)
{
  // Initialize parameters with default values
  short key_size = 128;
  string key_file = "key.txt", input_file = "input.txt",
    output_file = "output.txt";
  bool ecb_mode = false;

  // Replace parameters with options sent to program
  const char* short_options = "k:f:i:o:eh";
  const struct option long_options[] = {
    {"keysize", required_argument, 0, 'k'},
    {"keyfile", required_argument, 0, 'f'},
    {"inputfile", required_argument, 0, 'i'},
    {"outputfile", required_argument, 0, 'o'},
    {"ecb", no_argument, 0, 'e'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };
  int opt;
  while ((opt = getopt_long(argc, argv, short_options, long_options, nullptr)) 
          != -1) {
    switch(opt) {
      case 'k': key_size = std::stoi(optarg); break;
      case 'f': key_file = optarg; break;
      case 'i': input_file = optarg; break;
      case 'o': output_file = optarg; break;
      case 'e': ecb_mode = true; break;
      case 'h':
      case '?': fprintf(stderr, "usuage is \n -k, --keysize <keysize> \n -f, 
        --keyfile <key file> \n -i, --inputfile <input file> \n -o, 
        --outputfile <output file> \n -e, --ecb to enable ECB mode \n 
        -h, --help to print this message \n");
      default: cout<<endl; abort();
    }
  }

  // Initialize AES instance with provided parameters
  MyAES my_aes(key_size, key_file, input_file, output_file);

  my_aes.GenerateKeys();
  my_aes.Encrypt();

  return 0;
}
