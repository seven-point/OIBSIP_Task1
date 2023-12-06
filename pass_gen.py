import tkinter as tk
from tkinter import messagebox
import random
import string

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")

        self.length_label = tk.Label(master, text="Password Length:")
        self.length_label.grid(row=0, column=0, sticky=tk.W, padx=10, pady=10)

        self.length_var = tk.IntVar()
        self.length_entry = tk.Entry(master, textvariable=self.length_var)
        self.length_entry.grid(row=0, column=1, padx=10, pady=10)

        self.uppercase_var = tk.IntVar()
        self.uppercase_check = tk.Checkbutton(master, text="Uppercase", variable=self.uppercase_var)
        self.uppercase_check.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

        self.lowercase_var = tk.IntVar()
        self.lowercase_check = tk.Checkbutton(master, text="Lowercase", variable=self.lowercase_var)
        self.lowercase_check.grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)

        self.numbers_var = tk.IntVar()
        self.numbers_check = tk.Checkbutton(master, text="Numbers", variable=self.numbers_var)
        self.numbers_check.grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)

        self.symbols_var = tk.IntVar()
        self.symbols_check = tk.Checkbutton(master, text="Symbols", variable=self.symbols_var)
        self.symbols_check.grid(row=4, column=0, sticky=tk.W, padx=10, pady=5)

        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=5, column=0, columnspan=2, pady=10)

        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.grid(row=6, column=0, columnspan=2, pady=10)

        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(master, textvariable=self.password_var, state=tk.DISABLED)
        self.password_entry.grid(row=7, column=0, columnspan=2, pady=10)

    def generate_password(self):
        length = self.length_var.get()
        if length <= 0:
            messagebox.showwarning("Invalid Length", "Please enter a valid password length.")
            return

        chars = ""
        if self.uppercase_var.get():
            chars += string.ascii_uppercase
        if self.lowercase_var.get():
            chars += string.ascii_lowercase
        if self.numbers_var.get():
            chars += string.digits
        if self.symbols_var.get():
            chars += string.punctuation

        if not chars:
            messagebox.showwarning("No Character Set", "Please select at least one character set.")
            return

        password = ''.join(random.choice(chars) for _ in range(length))
        self.password_var.set(password)
        self.password_entry.config(state=tk.NORMAL)

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            self.master.update()
            messagebox.showinfo("Copied", "Password copied to clipboard.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()
