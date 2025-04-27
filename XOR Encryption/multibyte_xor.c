#include <stdio.h>
#include <windows.h>

void xor(unsigned char* shellcode, size_t shellcodesize, unsigned char* key, size_t keysize) {
    for (size_t i = 0, j = 0; i < shellcodesize; i++, j++) {
        if (j >= keysize) {
            j = 0;
        }
        shellcode[i] = shellcode[i] ^ key[j];  // Use key[j] to XOR
    }
}

void printshellcode(unsigned char* shellcode, size_t shellcodesize, size_t keysize) {
    for (size_t i = 0; i < shellcodesize; i++) {
        printf("\\x%02x", shellcode[i]);  // Print each byte in the correct format
    }
    printf("\n");  // Optionally add a newline at the end of all output
}


int main() {
   unsigned char shellcode[] =
    "SHELLCODE";

    size_t shellcodesize = sizeof(shellcode) - 1;
    unsigned char key[] = "KEY";
    size_t keysize = sizeof(key) - 1;

    printf("<-------------------- Original shellcode: --------------------> \n");
    printshellcode(shellcode, shellcodesize, keysize);

    printf("<--------------------  Encrypted shellcode: --------------------> \n");
    xor(shellcode, shellcodesize, key, keysize);
    printshellcode(shellcode, shellcodesize, keysize);

    printf("<-------------------- Decrypted shellcode: -------------------->\n"); // Should be the same Original shellcode
    xor(shellcode, shellcodesize, key, keysize);
    printshellcode(shellcode, shellcodesize, keysize);
}
