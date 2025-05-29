import requests
import hashlib
import re
import string
import random
import tkinter as tk
from tkinter import ttk, messagebox


def check_password_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[!@#$%^&*|()?{}~:]", password) is None
    password_ok = not (
        length_error
        or digit_error
        or uppercase_error
        or lowercase_error
        or symbol_error
    )

    errors = {
        "length_error": length_error,
        "digit_error": digit_error,
        "uppercase_error": uppercase_error,
        "lowercase_error": lowercase_error,
        "symbol_error": symbol_error,
    }

    return password_ok, errors


def check_pwned_password(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    url = f"https://api.pwnedpasswords.com/range/{first5_char}"
    response = requests.get(url)
    hashes = (line.split(":") for line in response.text.splitlines())
    count = next((int(count) for h, count in hashes if h == tail), 0)
    return count


def generate_strong_password(length):
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    digits = string.digits
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    symbols = "@!#$%^&*|()<>?/}{~:"
    password = [
        random.choice(digits),
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(symbols),
    ]
    all_characters = digits + lowercase + uppercase + symbols
    password += random.choices(all_characters, k=length - 4)
    random.shuffle(password)
    return "".join(password)


# ASCII Art Banner
banner = r"""
██████╗  █████╗ ███████╗███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
██████╔╝███████║███████╗███████╗███████╗███████║██║█████╗  ██║     ██║  ██║
██╔═══╝ ██╔══██║╚════██║╚════██║╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
██║     ██║  ██║███████║███████║███████║██║  ██║██║███████╗███████╗██████╔╝
      """

credit = "made by Chintan.H"


class PasswordApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PassShield - Password Tool")
        self.geometry("600x500")
        self.configure(bg="#f0f0f0")
        
        # Add banner at the top
        banner_frame = tk.Frame(self, bg="#f0f0f0")
        banner_frame.pack(fill=tk.X, padx=10, pady=(10, 0))
        
        # Use a monospace font for ASCII art
        banner_label = tk.Label(
            banner_frame, 
            text=banner,
            font=("Courier", 7),
            bg="#f0f0f0",
            fg="#333333",
            justify=tk.LEFT
        )
        banner_label.pack()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.strength_tab = ttk.Frame(self.notebook)
        self.leaked_tab = ttk.Frame(self.notebook)
        self.generate_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.strength_tab, text="Check Password Strength")
        self.notebook.add(self.leaked_tab, text="Check Password Leaks")
        self.notebook.add(self.generate_tab, text="Generate Password")
        
        # Setup each tab
        self.setup_strength_tab()
        self.setup_leaked_tab()
        self.setup_generate_tab()
        
        # Add footer with credit
        footer = tk.Label(self, text=credit, bg="#f0f0f0", fg="#666666")
        footer.pack(side=tk.BOTTOM, pady=5)
    
    def setup_strength_tab(self):
        frame = ttk.Frame(self.strength_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Enter password to check strength:").pack(anchor=tk.W, pady=(0, 5))
        
        self.strength_password = ttk.Entry(frame, width=40, show="•")
        self.strength_password.pack(fill=tk.X, pady=(0, 10))
        
        # Strength indicators
        self.strength_frame = ttk.LabelFrame(frame, text="Password Requirements")
        self.strength_frame.pack(fill=tk.X, pady=10)
        
        # Create indicators for each requirement
        self.indicators = {}
        requirements = [
            ("length_error", "At least 8 characters"),
            ("digit_error", "At least one digit"),
            ("uppercase_error", "At least one uppercase letter"),
            ("lowercase_error", "At least one lowercase letter"),
            ("symbol_error", "At least one special character")
        ]
        
        for key, text in requirements:
            container = ttk.Frame(self.strength_frame)
            container.pack(fill=tk.X, pady=2)
            
            self.indicators[key] = ttk.Label(container, text="❌", width=3)
            self.indicators[key].pack(side=tk.LEFT)
            
            ttk.Label(container, text=text).pack(side=tk.LEFT)
        
        # Check button
        ttk.Button(frame, text="Check Password", command=self.check_strength).pack(pady=10)
        
        # Result label
        self.strength_result = ttk.Label(frame, text="")
        self.strength_result.pack(pady=10)
        
        # Add show/hide password toggle
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Show Password", variable=self.show_password_var, 
                       command=self.toggle_password_visibility).pack(anchor=tk.W)
    
    def setup_leaked_tab(self):
        frame = ttk.Frame(self.leaked_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Enter password to check for leaks:").pack(anchor=tk.W, pady=(0, 5))
        
        self.leak_password = ttk.Entry(frame, width=40, show="•")
        self.leak_password.pack(fill=tk.X, pady=(0, 10))
        
        # Check button
        ttk.Button(frame, text="Check Password", command=self.check_leaked).pack(pady=10)
        
        # Result label
        self.leak_result = ttk.Label(frame, text="")
        self.leak_result.pack(pady=10)
        
        # Add show/hide password toggle
        self.show_leak_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Show Password", variable=self.show_leak_var, 
                       command=self.toggle_leak_visibility).pack(anchor=tk.W)
    
    def setup_generate_tab(self):
        frame = ttk.Frame(self.generate_tab, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Password Length:").pack(anchor=tk.W, pady=(0, 5))
        
        # Length slider
        self.length_var = tk.IntVar(value=12)
        self.length_slider = ttk.Scale(frame, from_=8, to=32, variable=self.length_var, 
                                    orient=tk.HORIZONTAL, length=200)
        self.length_slider.pack(fill=tk.X, pady=(0, 5))
        
        # Length display
        self.length_label = ttk.Label(frame, text="12 characters")
        self.length_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Update length label when slider moves
        self.length_var.trace_add("write", self.update_length_label)
        
        # Generate button
        ttk.Button(frame, text="Generate Password", command=self.generate_password).pack(pady=10)
        
        # Generated password display
        ttk.Label(frame, text="Generated Password:").pack(anchor=tk.W, pady=(10, 5))
        
        self.generated_password = ttk.Entry(frame, width=40)
        self.generated_password.pack(fill=tk.X, pady=(0, 10))
        
        # Copy button
        ttk.Button(frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(pady=5)
    
    def check_strength(self):
        password = self.strength_password.get()
        if not password:
            messagebox.showwarning("Empty Password", "Please enter a password to check.")
            return
            
        password_ok, errors = check_password_strength(password)
        
        # Update indicators
        for error_type, error_value in errors.items():
            if error_value:  # If there's an error
                self.indicators[error_type].config(text="❌", foreground="red")
            else:
                self.indicators[error_type].config(text="✓", foreground="green")
        
        # Update result text
        if password_ok:
            self.strength_result.config(text="Password is strong!", foreground="green")
        else:
            self.strength_result.config(text="Password is weak. Please fix the issues above.", foreground="red")
    
    def check_leaked(self):
        password = self.leak_password.get()
        if not password:
            messagebox.showwarning("Empty Password", "Please enter a password to check.")
            return
            
        try:
            count = check_pwned_password(password)
            if count:
                self.leak_result.config(
                    text=f"Password found in {count} data breaches!",
                    foreground="red"
                )
            else:
                self.leak_result.config(
                    text="Good news! Password not found in any known data breaches.",
                    foreground="green"
                )
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.leak_result.config(text="")
    
    def generate_password(self):
        try:
            length = self.length_var.get()
            password = generate_strong_password(length)
            self.generated_password.delete(0, tk.END)
            self.generated_password.insert(0, password)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def copy_to_clipboard(self):
        password = self.generated_password.get()
        if password:
            self.clipboard_clear()
            self.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
    
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.strength_password.config(show="")
        else:
            self.strength_password.config(show="•")
    
    def toggle_leak_visibility(self):
        if self.show_leak_var.get():
            self.leak_password.config(show="")
        else:
            self.leak_password.config(show="•")
    
    def update_length_label(self, *args):
        self.length_label.config(text=f"{self.length_var.get()} characters")


def main():
    # Check if we should run GUI or CLI version
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        run_cli()
    else:
        app = PasswordApp()
        app.mainloop()


def run_cli():
    print(banner)
    print("                                                          " + credit)

    while True:
        print("\nChoose an option:")
        print("1. Check password strength")
        print("2. Check if password has been leaked")
        print("3. Generate a strong password")
        print("4. Exit")

        choice = input("Enter your choice (1/2/3/4): ")

        if choice == "1":
            password = input("Enter the password to check its strength: ")
            password_ok, errors = check_password_strength(password)
            if password_ok:
                print("Password is strong.")
            else:
                print("Password is weak. Errors:")
                print(errors)

        elif choice == "2":
            password = input("Enter the password to check if it has been leaked: ")
            count = check_pwned_password(password)
            if count:
                print(f"Password found in {count} leaks.")
            else:
                print("Password not found in leaks.")

        elif choice == "3":
            length = int(input("Enter the length of the password to generate: "))
            try:
                strong_password = generate_strong_password(length)
                print(f"Generated strong password: {strong_password}")
            except ValueError as e:
                print(e)

        elif choice == "4":
            print("Exiting the program. Goodbye!")
            break

        else:
            print("Invalid choice. Please enter a valid option.")


if __name__ == "__main__":
    main()