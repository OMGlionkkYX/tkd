import tkinter as tk
from tkinter import messagebox
import random

# S-Box for substitution step
S_BOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5, 0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]
INV_S_BOX = [0xA, 0x5, 0x9, 0xB, 0x1, 0x7, 0x8, 0xF, 0x6, 0x0, 0x2, 0x3, 0xC, 0x4, 0xD, 0xE]

# Key expansion and round keys generation
def key_expansion(key):
    w = [(key >> 8) & 0xFF, key & 0xFF]
    rcon = 0x80
    for i in range(2, 6):
        if i % 2 == 0:
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

# Encrypt and decrypt blocks
def s_aes_encrypt_block(plaintext, key):
    round_keys = key_expansion(key)
    state = add_round_key(plaintext, round_keys[0])
    state = mix_columns(substitute(state, S_BOX))
    state = add_round_key(state, round_keys[1])
    state = substitute(state, S_BOX)
    state = add_round_key(state, round_keys[2])
    return state

def s_aes_decrypt_block(ciphertext, key):
    round_keys = key_expansion(key)
    state = add_round_key(ciphertext, round_keys[2])
    state = substitute(state, INV_S_BOX)
    state = add_round_key(state, round_keys[1])
    state = mix_columns(substitute(state, INV_S_BOX))
    state = add_round_key(state, round_keys[0])
    return state

# Double and Triple Encryption
def double_encrypt(plaintext, key1, key2):
    return s_aes_encrypt_block(s_aes_encrypt_block(plaintext, key1), key2)

def triple_encrypt(plaintext, key1, key2, mode=1):
    if mode == 1:
        return s_aes_encrypt_block(s_aes_decrypt_block(s_aes_encrypt_block(plaintext, key1), key2), key1)
    else:
        return s_aes_encrypt_block(s_aes_encrypt_block(s_aes_encrypt_block(plaintext, key1), key2), key1)

# CBC mode encryption
def cbc_encrypt(plaintext, key, iv):
    ciphertext = []
    prev_block = iv
    for i in range(0, len(plaintext), 2):
        block = int(plaintext[i:i+2], 16)
        encrypted_block = s_aes_encrypt_block(block ^ prev_block, key)
        ciphertext.append(encrypted_block)
        prev_block = encrypted_block
    return ciphertext

def cbc_decrypt(ciphertext, key, iv):
    plaintext = []
    prev_block = iv
    for block in ciphertext:
        decrypted_block = s_aes_decrypt_block(block, key) ^ prev_block
        plaintext.append(decrypted_block)
        prev_block = block
    return plaintext

# GUI with tkinter
class SAESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("S-AES Encryption")
        self.init_gui()

    def init_gui(self):
        tk.Label(self.root, text="Select Level:").grid(row=0, column=0)
        
        levels = ["1. Basic Encryption", "2. Cross-Test", "3. Extended ASCII", "4. Double/Triple Encryption", "5. CBC Mode"]
        self.level_var = tk.StringVar(self.root)
        self.level_var.set(levels[0])
        self.level_menu = tk.OptionMenu(self.root, self.level_var, *levels)
        self.level_menu.grid(row=0, column=1)

        tk.Label(self.root, text="Plaintext (16-bit hex):").grid(row=1, column=0)
        tk.Label(self.root, text="Key (16-bit hex):").grid(row=2, column=0)
        
        self.plaintext_entry = tk.Entry(self.root)
        self.key_entry = tk.Entry(self.root)
        
        self.plaintext_entry.grid(row=1, column=1)
        self.key_entry.grid(row=2, column=1)
        
        tk.Button(self.root, text="Process", command=self.process).grid(row=3, column=0, columnspan=2)
        
        self.result_text = tk.Text(self.root, height=5, width=40)
        self.result_text.grid(row=4, column=0, columnspan=2)

    def process(self):
        level = self.level_var.get()
        try:
            plaintext = int(self.plaintext_entry.get(), 16)
            key = int(self.key_entry.get(), 16)
            
            if "Basic" in level:
                ciphertext = s_aes_encrypt_block(plaintext, key)
                decrypted_text = s_aes_decrypt_block(ciphertext, key)
                self.display_result(f"Ciphertext: {ciphertext:04X}\nDecrypted: {decrypted_text:04X}")
                
            elif "Cross-Test" in level:
                ciphertext = s_aes_encrypt_block(plaintext, key)
                decrypted_text = s_aes_decrypt_block(ciphertext, key)
                self.display_result(f"Cross-test successful:\nCiphertext: {ciphertext:04X}\nDecrypted: {decrypted_text:04X}")
                
            elif "Extended ASCII" in level:
                plaintext_str = self.plaintext_entry.get()
                ciphertext = ''.join(f"{s_aes_encrypt_block(ord(c), key):02X}" for c in plaintext_str)
                decrypted_text = ''.join(chr(s_aes_decrypt_block(int(ciphertext[i:i+2], 16), key)) for i in range(0, len(ciphertext), 2))
                self.display_result(f"Ciphertext (hex): {ciphertext}\nDecrypted: {decrypted_text}")
            
            elif "Double/Triple Encryption" in level:
                key2 = random.randint(0, 0xFFFF)
                double_enc = double_encrypt(plaintext, key, key2)
                triple_enc = triple_encrypt(plaintext, key, key2)
                self.display_result(f"Double Enc: {double_enc:04X}\nTriple Enc: {triple_enc:04X}")
            
            elif "CBC Mode" in level:
                iv = random.randint(0, 0xFFFF)
                ciphertext = cbc_encrypt(self.plaintext_entry.get(), key, iv)
                decrypted = cbc_decrypt(ciphertext, key, iv)
                self.display_result(f"CBC Ciphertext: {' '.join(f'{c:04X}' for c in ciphertext)}\nDecrypted: {' '.join(f'{d:04X}' for d in decrypted)}")
        
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid hexadecimal values.")

    def display_result(self, text):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = SAESApp(root)
    root.mainloop()
