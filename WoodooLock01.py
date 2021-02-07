# !/usr/bin/python3
import os
import sys
from os import stat
import tkinter as tk
from tkinter import filedialog, StringVar, IntVar, messagebox
from cryptography.fernet import Fernet
import pyAesCrypt
from tkmacosx import Button

#Aes buffer
bufferSize = 64 * 1024
#Colors
dbrown = "#060401"
dorange = "#ff4d04"
mbrown = "#29211f"
#MainWindow Config
window = tk.Tk()
window.iconbitmap('wl.ico')
window.configure(bg=dbrown)
window.title("WoodooLock - 0.0.1")
window.resizable(width=False, height=False)
title = tk.Label(window,text="Select encryption type",bg=dbrown,fg="#D4D494")
#Define Key/File status Label
keystatus = StringVar()
keystatus.set("Select Key")
filestatus = StringVar()
filestatus.set("Select File")

#Loading/Making fernet key function
def make_fernet_Key():
    messagebox.showwarning("Please Read"," Keep this safe! If you lose a KEY you’ll no longer be able to decrypt files; if anyone else gains access to it, they’ll be able to decrypt your files. You can create an encrypt files with different keys.")
    clave = Fernet.generate_key()
    fileclave = filedialog.asksaveasfilename(title="Save your Key",defaultextension=".key")
    with open(fileclave,"wb") as archivo_clave:
            archivo_clave.write(clave)

def fernet_load_Key():
    global key
    key = filedialog.askopenfilename(defaultextension=".key")
    keystatus.set(os.path.basename(key))

#Loading file
def load_File():
    global filename 
    filename = filedialog.askopenfilename()
    filestatus.set(os.path.basename(filename))
#encrypt function
def fernet_encrypt(filename,key):
    try: 
        fkey = open(key,"rb").read()
        f = Fernet(fkey)
        with open(filename, "rb") as file:
            archivo_info = file.read()
        encrypted_data = f.encrypt(archivo_info)
        with open(filename+".flock","wb") as file:
            file.write(encrypted_data)
            messagebox.showinfo("Encryption Successful", "Your file is encrypted :)")
    except:
        messagebox.showerror("Encryption ERROR", "ERROR: Key or File incorrect.")

#decrypt function
def fernet_decrypt (filename,key):
    try:    
        fkey = open(key,"rb").read()
        f = Fernet(fkey)
        with open(filename, "rb") as file:
            archivo_info = file.read()
        decrypted_data = f.decrypt(archivo_info)
        with open(filename[:-6],"wb") as file:
            file.write(decrypted_data)
            messagebox.showinfo("Decryption Successful", "Your file is decrypted :)")
    except:
        messagebox.showerror("Decryption ERROR", "ERROR: Key or File incorrect.")

def aes_encrypt(filename):
    try:
        password = aes_password.get()
        with open(filename, "rb") as fIn:
            with open(filename + ".alock", "wb") as fOut:
                pyAesCrypt.encryptStream(fIn, fOut, password, bufferSize)
                messagebox.showinfo("Encryption Successful", "Your file is encrypted :)")
    except: 
        messagebox.showerror("Encryption ERROR", "ERROR: Password or File incorrect.")
                
        
def aes_decrypt(filename):
    try:
        password = aes_password.get()
        encFileSize = stat(filename).st_size
        with open(filename, "rb") as fIn:
            with open(filename[:-6], "wb") as fOut:
                pyAesCrypt.decryptStream(fIn, fOut, password, bufferSize, encFileSize)
                messagebox.showinfo("Decryption Successful", "Your file is decrypted :)")
    except:
        messagebox.showerror("Decryption ERROR", "ERROR: Password or File incorrect.")

def hide_frames():
    fernetFrame.grid_forget()
    aesFrame.grid_forget()
    fernetButton.configure(state="normal")
    aesButton.configure(state="normal")
def fernet_menu():
    hide_frames()
    fernetFrame.grid(row=3,columnspan=4)
    fernetButton.configure(state="active")

def aes_menu():
    hide_frames()
    aesFrame.grid(row=3,columnspan=4)
    aesButton.configure(state="active")


key = None
filename = None
#Declare GUI
fernetButton = Button(window,activebackground=('#000000', '#D4D494'),bg=dbrown,fg="white",width=250,height=50,text="Fernet Crypt",command=lambda: fernet_menu())
aesButton = Button(window,activebackground=('#000000', '#D4D494'),bg=dbrown,fg="white",width=250,height=50,text="AES Crypt", command=lambda: aes_menu())
#Fernet GUI
fernetFrame = tk.Frame(window)
fernet_makeKey = Button(fernetFrame,bg=dbrown,fg="white",width=125,height=50,text="Generate a Key",command=make_fernet_Key)
fernet_selectKey = Button(fernetFrame,bg=dbrown,fg="white",width=125,height=50,textvariable=keystatus,command=fernet_load_Key)
fernet_selectFile = Button(fernetFrame,bg=dbrown,fg="white",width=250,height=50,textvariable=filestatus,command=load_File)
fernet_encryptFile = Button(fernetFrame,bg=dbrown,fg="white",width=250,height=50,text="Encrypt File",command=lambda: fernet_encrypt(filename,key))
fernet_decryptFile = Button(fernetFrame,bg=dbrown,fg="white",width=250,height=50,text="Decrypt File",command=lambda: fernet_decrypt(filename,key))


#AES GUI
aesFrame = tk.Frame(window,bg=dbrown)

miniframe = tk.Frame(aesFrame,bg=dbrown)

aes_label = tk.Label(miniframe,text="Enter Password: ",bg=dbrown,fg="white",)
aes_password = tk.Entry(miniframe,justify="center",show="*",bg=mbrown,fg="white",)
aes_selectFile = Button(aesFrame,bg=dbrown,fg="white",width=250,height=50,textvariable=filestatus,command=load_File)
aes_encryptFile = Button(aesFrame,bg=dbrown,fg="white",width=250,height=50,text="Encrypt File",command=lambda: aes_encrypt(filename))
aes_decryptFile = Button(aesFrame,bg=dbrown,fg="white",width=250,height=50,text="Decrypt File",command=lambda: aes_decrypt(filename))


#Positioning objects
title.grid(row=0,columnspan=4)
fernetButton.grid(row=1,column=0,columnspan=2)
aesButton.grid(row=1,column=2,columnspan=2)
#Fernet Controls
fernet_makeKey.grid(row=0,column=1,columnspan=1)
fernet_selectKey.grid(row=0,column=0,columnspan=1)
fernet_selectFile.grid(row=1,column=0,columnspan=2)
fernet_encryptFile.grid(row=0,column=2,columnspan=2)
fernet_decryptFile.grid(row=1,column=2,columnspan=2)
#AES Controls
aes_label.grid(row=0,column=0,columnspan=2)
aes_password.grid(row=1,column=0,columnspan=2)
miniframe.grid(row=0,column=0,columnspan=2)
aes_selectFile.grid(row=1,column=0,columnspan=2)
aes_encryptFile.grid(row=0,column=2,columnspan=2)
aes_decryptFile.grid(row=1,column=2,columnspan=2)


window.mainloop()



