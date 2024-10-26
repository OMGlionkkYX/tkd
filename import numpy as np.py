import tkinter as tk
from tkinter import messagebox
import random

# S-Box for substitution step
S_BOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_S_BOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]

# Key expansion and round keys generation
def key_expansion(key):
    # Key should be 16 bits, so split into two 8-bit words
    w = [(key >> 8) & 0xFF, key & 0xFF]
    rcon = 0x80
    for i in range(2, 6):
        if i % 2 == 0:
            # Substitution and RCON only for new words based on S_BOX
            temp = (S_BOX[(w[i - 1] >> 4) & 0xF] << 4) + S_BOX[w[i - 1] & 0x0F]
            temp ^= rcon
            rcon >>= 1
        else:
            temp = w[i - 1]
        w.append(w[i - 2] ^ temp)
    return [((w[2*i] << 8) + w[2*i + 1]) for i in range(3)]

# Substitute Nibbles
def substitute(state, sbox):
    return (sbox[(state >> 4) & 0x0F] << 4) + sbox[state & 0x0F]

# Shift rows
def shift_rows(state):
    return state

# Mix columns
def mix_columns(s):
    return ((0x2 * (s >> 4) & 0xF) ^ (0x3 * (s & 0xF) & 0xF)) << 4 | ((0x3 * (s >> 4) & 0xF) ^ (0x2 * (s & 0xF) & 0xF))

# Add round key
def add_round_key(state, key):
    return state ^ key

# Encrypt one round S-AES
def s_aes_encrypt_block(plaintext, key):
    round_keys = key_expansion(key)
    state = add_round_key(plaintext, round_keys[0])
    state = mix_columns(substitute(state, S_BOX))
    state = add_round_key(state, round_keys[1])
    state = substitute(state, S_BOX)
    state = add_round_key(state, round_keys[2])
    return state

# Decrypt one round S-AES
def s_aes_decrypt_block(ciphertext, key):
    round_keys = key_expansion(key)
    state = add_round_key(ciphertext, round_keys[2])
    state = substitute(state, INV_S_BOX)
    state = add_round_key(state, round_keys[1])
    state = mix_columns(substitute(state, INV_S_BOX))
    state = add_round_key(state, round_keys[0])
    return state

# Double encryption using S-AES
def double_encrypt(plaintext, key1, key2):
    return s_aes_encrypt_block(s_aes_encrypt_block(plaintext, key1), key2)

# Triple encryption (mode 1) using S-AES
def triple_encrypt(plaintext, key1, key2):
    return s_aes_encrypt_block(s_aes_decrypt_block(s_aes_encrypt_block(plaintext, key1), key2), key1)

# CBC mode encryption with S-AES
def cbc_encrypt(plaintext, key, iv):
    ciphertext = []
    prev_block = iv
    for i in range(0, len(plaintext), 2):
        block = int(plaintext[i:i+2], 16)
        encrypted_block = s_aes_encrypt_block(block ^ prev_block, key)
        ciphertext.append(encrypted_block)
        prev_block = encrypted_block
    return ciphertext

# GUI with tkinter
class SAESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES Encryption")
        self.init_gui()

    def init_gui(self):
        tk.Label(self.root, text="Plaintext (16-bit hex):").grid(row=0, column=0)
        tk.Label(self.root, text="Key (16-bit hex):").grid(row=1, column=0)
        
        self.plaintext_entry = tk.Entry(self.root)
        self.key_entry = tk.Entry(self.root)
        
        self.plaintext_entry.grid(row=0, column=1)
        self.key_entry.grid(row=1, column=1)
        
        tk.Button(self.root, text="Encrypt", command=self.encrypt).grid(row=2, column=0)
        tk.Button(self.root, text="Decrypt", command=self.decrypt).grid(row=2, column=1)
        
        self.result_text = tk.Text(self.root, height=5, width=40)
        self.result_text.grid(row=3, column=0, columnspan=2)

    def encrypt(self):
        try:
            plaintext = int(self.plaintext_entry.get(), 16)
            key = int(self.key_entry.get(), 16)
            ciphertext = s_aes_encrypt_block(plaintext, key)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Ciphertext (hex): {ciphertext:04X}\n")
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid hexadecimal values.")

    def decrypt(self):
        try:
            ciphertext = int(self.plaintext_entry.get(), 16)
            key = int(self.key_entry.get(), 16)
            plaintext = s_aes_decrypt_block(ciphertext, key)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Decrypted Plaintext (hex): {plaintext:04X}\n")
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid hexadecimal values.")

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = SAESApp(root)
    root.mainloop()
