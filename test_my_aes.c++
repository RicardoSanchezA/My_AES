#include <iostream>
#include <string.h>
#include <getopt.h>

#include "my_aes.h"

using namespace std;

static void GetOptions(const int& argc, char* argv[], short& key_size, 
                       string& key_file, string& input_file, string& output_file,
                       bool& encrypt_mode, bool& ecb_mode) {
  const char* short_options = "k:f:i:o:m:ch";
  const struct option long_options[] = {
    {"keysize", required_argument, 0, 'k'},
    {"keyfile", required_argument, 0, 'f'},
    {"inputfile", required_argument, 0, 'i'},
    {"outputfile", required_argument, 0, 'o'},
    {"mode", required_argument, 0, 'm'},
    {"cbc", no_argument, 0, 'c'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };
  int opt;
  while ((opt = getopt_long(argc, argv, short_options, long_options, nullptr)) 
          != -1) {
    switch(opt) {
      case 'k': if(strcmp(optarg, "256") == 0)
                  key_size = 256; 
                break;
      case 'f': key_file = optarg; break;
      case 'i': input_file = optarg; break;
      case 'o': output_file = optarg; break;
      case 'm': if(strcmp(optarg, "decrypt") == 0)
                  encrypt_mode = false;
                break;
      case 'c': ecb_mode = true; break;
      case 'h':
      case '?': fprintf(stderr, "Program options are: \n -k, --keysize <keysize> \n -f, \
--keyfile <key file> \n -i, --inputfile <input file> \n -o, \
--outputfile <output file> \n -m, --mode <encrypty/decrypt> \n \
-c, --cbc to enable CBC mode \n -h, --help to print this message \n");
      default: cout<<"\n"; exit(0);
    }
  }
}


int main(const int argc, char* argv[])
{
  // Initialize parameters with default values
  short key_size = 128;
  string key_file = "key.txt", input_file = "input.txt",
    output_file = "output.txt";
  bool ecb_mode = false;
  bool encrypt_mode = true;

  // Replace parameters with options sent to program
  GetOptions(argc, argv, key_size, key_file, input_file, output_file, encrypt_mode, ecb_mode);

  // Initialize AES instance with provided parameters
  MyAES my_aes(key_size, key_file, input_file, output_file);

  my_aes.GenerateKeys();
  if(encrypt_mode)
    my_aes.Encrypt();
  else
    cout << "decrypt\n";

  return 0;
}
