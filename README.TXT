------------------------------------------------------------------------
This is the project README file. Here, you should describe your project.
Tell the reader (someone who does not know anything about this project)
all he/she needs to know. The comments should usually include at least:
------------------------------------------------------------------------

PROJECT TITLE: Crypto
PURPOSE OF PROJECT: Encrypt or decrypt file
VERSION or DATE: 04/03/2016
HOW TO START THIS PROJECT: Run Crypto
AUTHORS: 2331131
USER INSTRUCTIONS: Command line arguments!

PROGRAM FUNCTIONALITIES:
The main and only class of the program is Crypto. Crypto.main() take in three command line arguments: An operation (encrypt or decrypt), a path to an input file
and a path to an output file. The content of the files is irrelevant.

If the operation is encrypt the program asks the user to enter a password. The dialog provides real-time feedback on the strength of the password. The strength of the password
is determnined using the following criteria: is the password only numbers? is the password numbers and letters? is the password numbers and uppercase letters? is the password numbers,
uppercase letters and lowercase letters? how long is the password?
Each of these criteria influences the strength of the password. The strength is calculated by a score over 100. Each character adds one to the score and each of the other criteria
add 20,30,40,60 depending on which criteria.
Once the user had entered a password and selected the entrypt button the program generates a random salt, a key based on the password and encrypts the input file. The program then generates
an output file with the encrypted data, the salt is stored at the beignning of the encrypted file.

If the operation is decrypt the program asks the user to enter a password. Once the user has entered a password and selected the decrypt button the program reads the salt from the input file
and generates a key based on the password. The program then tries to decrypt the file using the salt and the key. If the password is the same as the one that was used to encrypt the file
and the encrypted file hasn't been modified then the decryption is successful and the program writes the decrypted data to an output file.

Other possible password criterias could be to check if the password also contains symbols. However it is worth mentioning that a long alphanumeric (uppercase and lowercase) password is technically
safe enough to encrypt data as cracking it would require too much time.