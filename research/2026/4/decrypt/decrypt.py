from Crypto.Cipher import AES
from Cryptodome.Hash import CMAC
import struct
from struct import pack
# AES KeyWrap Unwrap Implementation
def aes_keywrap_unwrap(key, ciphertext):
    BLOCK_SIZE = 8  # AES KeyWrap processes 64-bit blocks
    ROUND_COUNT = 6  # Standard AES KeyWrap uses 6 rounds
    IV = 0xA6A6A6A6A6A6A6A6  # Integrity check constant as a 64-bit integer

    blocks = [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    A = int.from_bytes(blocks[0], 'big')  # Convert A to a 64-bit integer
    R = blocks[1:]  # Encrypted data blocks

    cipher = AES.new(key, AES.MODE_ECB)
    for round_index in range(ROUND_COUNT, 0, -1):  # Reverse round loop
        for block_index in range(len(R), 0, -1):  # Reverse block loop
            # Calculate the iteration count (t)
            iteration_count = (len(R) * (round_index - 1)) + block_index

            # XOR A with the iteration count
            A ^= iteration_count

            # Create the input block: (A XOR t | R[i])
            input_block = A.to_bytes(BLOCK_SIZE, 'big') + R[block_index - 1]

            # Decrypt the block
            decrypted = cipher.decrypt(input_block)

            # Update A and the current block R[i-1]
            A = int.from_bytes(decrypted[:BLOCK_SIZE], 'big')  # Update A as a 64-bit integer
            R[block_index - 1] = decrypted[BLOCK_SIZE:]  # Store unwrapped plaintext

    # Integrity check
    if A != IV:
        raise ValueError(f"Integrity check failed. A: {hex(A)}, Expected: {hex(IV)}")

    return b''.join(R)
def oem_aes_128_kdf_ctr(deriver_key_hex: str, label_key_hex: str, context_hex: str | None) -> str:
    label_key = bytes.fromhex(label_key_hex)
    deriver_key = bytes.fromhex(deriver_key_hex)
    context = bytes.fromhex(context_hex) if context_hex else bytes(16)  # Use 16 zeroes if context is None

    # Build the key derivation input
    data = bytearray()
    data.append(1)  # Counter (1 byte)
    data.extend(label_key)  # Label (16 bytes)
    data.append(0)  # Separator (1 byte)
    data.extend(context)  # Context (16 bytes)
    data.extend(pack(">H", 128))  # Output length in bits, 16-bit network byte order

    # Generate the derived key using CMAC
    cmac = CMAC.new(deriver_key, ciphermod=AES)
    cmac.update(data)
    return cmac.digest()

# # Read the ciphertext
with open('zgpriv_protected.dat', 'rb') as f:
#with open('stage-1.dat', 'rb') as f:
   ciphertext = f.read()
   # FOR 176 ONLY
   # DO ECB FIRST
   ciphertext = ciphertext[80+16:][:48]

deriver_key_hex = "8b222ffd1e76195659cf2703898c427f"
label_key_hex = "9ce93432c7d74016ba684763f801e136"
context_hex = "00000000000000000000000000000000".replace(" ", "")
#context_hex = "FC 29 A2 37 B3 B0 49 B2 96 FC 54 D8 FE FF B3 2E".replace(" ", "")

try:
    key = oem_aes_128_kdf_ctr(deriver_key_hex, label_key_hex, context_hex)
    print(key.hex())
    #ciphertext = "09 01 00 C0 48 27 00 00 81 A7 CB A5 16 49 E7 60 F4 E2 C8 DD EF C3 A8 67 56 E0 69 82 90 62 7D 1E DC 8E 27 9E 34 AE 12 CA 8E BD 51 E7 00 00 06 83".replace(" ", "")
    #unwrapped_data = aes_keywrap_unwrap(key, bytes.fromhex(ciphertext))
    unwrapped_data = aes_keywrap_unwrap(key, ciphertext)
    
    ecc_private_key = unwrapped_data[:32]
    auxiliary_data = unwrapped_data[32:]
    print("ECC Private Key (Hex):", ecc_private_key.hex())

    with open("zgpriv.dat", "wb") as f:
        f.write(ecc_private_key)
except ValueError as e:
    print("Unwrapping failed:", str(e))
