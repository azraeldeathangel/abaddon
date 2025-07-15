import sys

def xor(shellcode: bytes, key: str) -> bytes:
    result = bytearray()
    key_length = len(key)
    key_index = 0

    for byte in shellcode:
        if key_index >= key_length:
            key_index = 0
        result.append(byte ^ ord(key[key_index]))
        key_index += 1

    return bytes(result)

def usage():
    print("Usage: python file.py <shellcode_file> <key> <output_file>")
    exit(1)

def main():
    if len(sys.argv) < 2: 
        usage()
    
    shellcode = open(sys.argv[1], "rb").read()
    key = sys.argv[2]
    new_shellcode = xor(shellcode, key)
    with open(sys.argv[3], "wb") as f:
        print("Shellcode written to output.bin")
        f.write(new_shellcode)

if __name__ == "__main__":
    main()
