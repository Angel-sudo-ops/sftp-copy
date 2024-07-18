import paramiko
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import font, ttk
import threading
import json
import re
import sys
# import pystray
# from PIL import Image

# Default paths for remote directory

def sftp_transfer(host, port, username, password, local_path, remote_path, status_widget):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        status_widget.insert(tk.END, f"Transfer to {host} in progress...\n")
        status_widget.yview(tk.END)
        ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10)
        sftp = ssh.open_sftp()

        if os.path.isfile(local_path):
            sftp.put(local_path, os.path.join(remote_path, os.path.basename(local_path)))
            status_widget.insert(tk.END, f"Successfully transferred {local_path} to {host}:{remote_path}\n")
        else:
            for root_dir, dirs, files in os.walk(local_path):
                for dir_name in dirs:
                    local_dir = os.path.join(root_dir, dir_name)
                    remote_dir = os.path.join(remote_path, os.path.relpath(local_dir, local_path))
                    try:
                        sftp.mkdir(remote_dir)
                    except:
                        pass  # Ignore if the directory already exists
                for file_name in files:
                    local_file = os.path.join(root_dir, file_name)
                    remote_file = os.path.join(remote_path, os.path.relpath(local_file, local_path))
                    sftp.put(local_file, remote_file)
                    status_widget.insert(tk.END, f"Successfully transferred {local_file} to {host}:{remote_file}\n")

        sftp.close()
        ssh.close()
    except Exception as e:
        status_widget.insert(tk.END, f"Failed to transfer {local_path} to {host}:{remote_path}. Error: {e}\n")
    finally:
        status_widget.yview(tk.END)

def parse_ip_ranges(base_ip, range_input):
    ip_list = []

    if not range_input:
        return None
    else:
        ranges = range_input.split(',')
        for r in ranges:
            if '-' in r:
                start, end = map(int, r.split('-'))
                ip_list.extend([f"{base_ip}.{i}" for i in range(start, end + 1)])
            else:
                ip_list.append(f"{base_ip}.{r.strip()}")

    return ip_list

def start_transfer(status_widget):
    local_path = file_path.get()
    base_ip = ip_entry.get()
    range_input = range_entry.get()
    remote_dir = remote_dir_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    port = 20022

    if not local_path:
        messagebox.showerror("Input Error", "Please choose a file or folder to transfer.")
        return
    if not base_ip or base_ip == "e.g., 7.204.194":
        messagebox.showerror("Input Error", "Please enter the base IP.")
        return
    if not range_input or range_input == "e.g., 10-25, 27, 29, 31-40":
        messagebox.showerror("Input Error", "Please enter the IP range.")
        return
    if not remote_dir:
        messagebox.showerror("Input Error", "Please enter the remote directory.")
        return
    if not username:
        messagebox.showerror("Input Error", "Please enter the username.")
        return
    if not password:
        messagebox.showerror("Input Error", "Please enter the password.")
        return

    status_widget.delete(1.0, tk.END)  # Clear previous status messages
    ip_list = parse_ip_ranges(base_ip, range_input)

    if ip_list is None:
        messagebox.showerror("Input Error", "Please provide a valid IP range.")
        return

    for host in ip_list:
        threading.Thread(target=sftp_transfer, args=(host, port, username, password, local_path, remote_dir, status_widget)).start()

def choose_file_or_folder():
    file_path.set("")  # Clear previous selection
    if selection.get() == 'file':
        file_or_folder = filedialog.askopenfilenames()  # Select files
        if file_or_folder:
            file_path.set(", ".join(file_or_folder))
    elif selection.get() == 'folder':
        file_or_folder = filedialog.askdirectory()  # Select a folder
        if file_or_folder:
            file_path.set(file_or_folder)

################################################## Placeholder #######################################################################
def create_placeholder(entry, placeholder_text):
    entry.insert(0, placeholder_text)
    entry.bind("<FocusIn>", lambda event: on_focus_in(entry, placeholder_text))
    entry.bind("<FocusOut>", lambda event: on_focus_out(entry, placeholder_text))

def on_focus_in(entry, placeholder_text):
    if entry.get() == placeholder_text:
        entry.delete(0, tk.END)
        entry.config(fg='black')

def on_focus_out(entry, placeholder_text):
    if not entry.get():
        entry.insert(0, placeholder_text)
        entry.config(fg='grey')

# ############################################### Function to validate IP address format ################################################
def validate_ip_format(event):
    ip = ip_entry.get()
    pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if pattern.match(ip):
        segments = ip.split('.')
        valid = all(0 <= int(segment) <= 255 for segment in segments)
        if valid:
            ip_entry.config(bg="white")
        else:
            ip_entry.config(bg="yellow")
    else:
        ip_entry.config(bg="yellow")

###################################################### Custom paths ##########################################################
default_paths = ("/Config", "/TwinCAT/Boot", "/Layout")

# Load custom paths from a file
def load_custom_paths():
    try:
        with open("custom_paths.json", "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return []

# Save custom paths to a file
def save_custom_paths(paths):
    with open("custom_paths.json", "w") as file:
        json.dump(paths, file)

# Initialize custom paths
custom_paths = load_custom_paths()

def save_custom_path():
    custom_path = remote_dir_entry.get()
    if custom_path and custom_path not in remote_dir_entry['values']:
        custom_paths.append(custom_path)
        save_custom_paths(custom_paths)
        remote_dir_entry['values'] = default_paths + tuple(custom_paths)
        messagebox.showinfo("Saved", f"Path '{custom_path}' saved successfully.")

####################################################### Profiles ###############################################################

default_profile = {
    "name":     "Default",
    "base_ip":  "192.168.0",
    "ip_range": "10-20",
    "username": "Administrator",
    "password": "1"
}

def load_custom_profiles():
    try:
        with open("custom_profiles.json", "r") as file:
            data = json.load(file)
             # Check if the loaded data is a dict with "profiles" key or a list
            if isinstance(data, dict) and "profiles" in data:
                return data["profiles"]
            elif isinstance(data, list):
                return data
            else:
                raise ValueError("Unexpected JSON structure")
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_custom_profiles(custom_profiles):
    with open("custom_profiles.json", "w") as file:
        json.dump(custom_profiles, file, indent=4)

custom_profiles = load_custom_profiles()

profile_names = [profile["name"] for profile in custom_profiles]

def save_custom_profile():
    custom_profile_name = profiles_combobox.get()
    if not custom_profile_name:
        messagebox.showerror("Error", "Profile name cannot be empty")
        return
    
    custom_profile = {
        "name":     custom_profile_name,
        "base_ip":  ip_entry.get(),
        "ip_range": range_entry.get(),
        "username": username_entry.get(),
        "password": password_entry.get()
    }

    # Check for duplicate profile names and update if found
    for existing_profile in custom_profiles:
        if existing_profile["name"] == custom_profile_name:
            existing_profile.update(custom_profile)
            break
    else:
        custom_profiles.append(custom_profile)
    
    save_custom_profiles(custom_profiles)
    profiles_combobox['values'] = default_profile["name"] + tuple(custom_profiles["name"])
    messagebox.showinfo("Success", "Profile saved successfully")

    
def set_profile(profile):
    ip_entry.delete(0, tk.END)
    ip_entry.insert(0, profile["base_ip"])

    range_entry.delete(0, tk.END)
    range_entry.insert(0, profile["ip_range"])

    username_entry.delete(0, tk.END)
    username_entry.insert(0, profile["username"])

    password_entry.delete(0, tk.END)
    password_entry.insert(0, profile["password"])

def load_profile_by_name(event=None):
    selected_profile_name = profiles_combobox.get()
    profiles = load_custom_profiles()
    for profile in profiles:
        if profile["name"] == selected_profile_name:
            set_profile(profile)
            break

######################################################## Create UI ##################################################

root = tk.Tk()
root.title("SFTP File Transfer")

root.resizable(False, False)

# Variable to store the file or folder path
file_path = tk.StringVar()
# Variable to store the user's choice (file or folder)
selection = tk.StringVar(value='file')

# Radio buttons for selecting file or folder
tk.Radiobutton(root, text="Files", variable=selection, value='file').grid(row=0, column=0, padx=10, pady=10, sticky='w')
tk.Radiobutton(root, text="Folder", variable=selection, value='folder').grid(row=0, column=0, padx=60, pady=10, sticky='w')

# Create a listbox to display saved profiles
profiles_combobox = ttk.Combobox(root, values= (profile["name"] for profile in custom_profiles), width=40)
# profiles_combobox.insert(0, default_profile["name"])
profiles_combobox.set("Select a profile")
profiles_combobox.grid(row=0, column=1,padx=10, pady=10)
profiles_combobox.bind("<<ComboboxSelected>>", load_profile_by_name)

tk.Button(root, text="Save Profile", command=save_custom_profile).grid(row=0, column=2, padx=10, pady=10)

tk.Button(root, text="Browse", command=choose_file_or_folder).grid(row=1, column=2, padx=5, pady=10)
tk.Label(root, text="Choose file or folder to transfer:").grid(row=1, column=0, padx=10, pady=10)
tk.Entry(root, textvariable=file_path, width=50).grid(row=1, column=1, padx=10, pady=10)

tk.Label(root, text="Enter base IP (first three parts):").grid(row=2, column=0, padx=10, pady=10)
ip_entry = tk.Entry(root, width=50, fg="grey")
create_placeholder(ip_entry, "e.g., 7.204.194")
ip_entry.grid(row=2, column=1, padx=10, pady=10)
ip_entry.bind("<KeyRelease>", validate_ip_format)

tk.Label(root, text="Enter IP range:").grid(row=3, column=0, padx=10, pady=10)
range_entry = tk.Entry(root, width=50, fg="grey")
range_entry.grid(row=3, column=1, padx=10, pady=10)
create_placeholder(range_entry, "e.g., 10-25, 27, 29, 31-40")

tk.Label(root, text="Enter remote directory:").grid(row=4, column=0, padx=10, pady=10)
remote_dir_entry = ttk.Combobox(root, values=default_paths + tuple(custom_paths), width=47)
remote_dir_entry.insert(0, default_paths[0])
remote_dir_entry.grid(row=4, column=1, padx=10, pady=10)

# Add a button to save a custom path
tk.Button(root, text="Save Path", command=save_custom_path).grid(row=4, column=2, padx=5, pady=10)

# create_placeholder(remote_dir_entry, "e.g., /remote/config/")

tk.Label(root, text="Enter username:").grid(row=5, column=0, padx=10, pady=10)
username_entry = tk.Entry(root, width=50)
username_entry.insert(0, "Administrator")
username_entry.grid(row=5, column=1, padx=10, pady=10)

tk.Label(root, text="Enter password:").grid(row=6, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, width=50, show="*")
password_entry.grid(row=6, column=1, padx=10, pady=10)

tk.Button(root, text="Start Transfer", command=lambda: start_transfer(status_widget)).grid(row=7, column=0, columnspan=3, pady=20)

status_widget = tk.Text(root, height=10, width=80)
status_font = font.Font(family="Consolas", size=10)
status_widget.configure(font=status_font)
status_widget.grid(row=8, column=0, columnspan=3, padx=10, pady=10)

root.mainloop()

## not showing connection timeout fix that
## add profiles to save data just like routes

