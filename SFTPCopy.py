import paramiko
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import font, ttk
import tkinter.scrolledtext as scrolledtext
import threading
import json
import re
import sys
from ftplib import FTP, error_perm
from ftplib import FTP_PORT
# import pystray
# from PIL import Image

############################################### SFTP Transfer ###############################################

def sftp_transfer(host, port, username, password, local_path, remote_path, status_widget):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        status_widget.insert(tk.END, f"Transfer to {host} in progress...\n")
        status_widget.yview(tk.END)
        ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10, auth_timeout=10)
        sftp = ssh.open_sftp()

        if os.path.isfile(local_path):
            sftp.put(local_path, os.path.join(remote_path, os.path.basename(local_path)))
            status_widget.insert(tk.END, f"\nSuccessfully transferred {local_path} to\n\\\{host}{remote_path}\n")
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
                    status_widget.insert(tk.END, f"\nSuccessfully transferred {local_file} to\n\\\{host}{remote_file}\n")
        sftp.close()
        ssh.close()
    except Exception as e:
        status_widget.insert(tk.END, f"\nFailed to transfer {local_path} to\n\\\{host}{remote_path}. Error: {e}\n")
    finally:
        status_widget.yview(tk.END)
    
################################################ FTP transfer ###############################################################
def ftp_transfer(host, username, password, local_path, remote_path, status_widget):
    try:
        status_widget.insert(tk.END, f"Transfer to {host} in progress...\n")
        status_widget.yview(tk.END)
        
        # Connect to the FTP server
        ftp = FTP(host)
        ftp.login(user=username, passwd=password)
        # ftp.login(user='anonymous', passwd='anonymous@example.com')  # You can use any email as password

        if os.path.isfile(local_path):
            with open(local_path, 'rb') as file:
                ftp.storbinary(f"STOR {os.path.join(remote_path, os.path.basename(local_path))}", file)
            status_widget.insert(tk.END, f"\nSuccessfully transferred {local_path} to\n\\{host}{remote_path}\n")
        else:
            for root_dir, dirs, files in os.walk(local_path):
                for dir_name in dirs:
                    local_dir = os.path.join(root_dir, dir_name)
                    remote_dir = os.path.join(remote_path, os.path.relpath(local_dir, local_path)).replace("\\", "/")
                    try:
                        ftp.mkd(remote_dir)
                    except Exception as e:
                        status_widget.insert(tk.END, f"\nDirectory {remote_dir} might already exist. Error: {e}\n")
                for file_name in files:
                    local_file = os.path.join(root_dir, file_name)
                    remote_file = os.path.join(remote_path, os.path.relpath(local_file, local_path)).replace("\\", "/")
                    with open(local_file, 'rb') as file:
                        ftp.storbinary(f"STOR {remote_file}", file)
                    status_widget.insert(tk.END, f"\nSuccessfully transferred {local_file} to\n\\{host}{remote_file}\n")
        
        # Close the FTP connection
        ftp.quit()
    except Exception as e:
        status_widget.insert(tk.END, f"\nFailed to transfer {local_path} to\n\\{host}{remote_path}. Error: {e}\n")
    finally:
        status_widget.yview(tk.END)

def ftp_transfer_anonymous(host, username, password, local_path, remote_path, status_widget):
    try:
        status_widget.insert(tk.END, f"Anonymous transfer to {host} in progress...\n")
        status_widget.yview(tk.END)
        
        # Connect to the FTP server with anonymous login
        ftp = FTP(host)
        ftp.login(user=username, passwd=password)  # You can use any email as password
        
        def upload_file(local_file, remote_file):
            try:
                with open(local_file, 'rb') as file:
                    ftp.storbinary(f"STOR {remote_file}", file)
                status_widget.insert(tk.END, f"\nSuccessfully transferred {local_file} to\n\\{host}{remote_file}\n")
            except error_perm as e:
                status_widget.insert(tk.END, f"\nFailed to transfer {local_file} to\n\\{host}{remote_file}. Error: {e}\n")
                if '552' in str(e):
                    status_widget.insert(tk.END, "\nError 552: Exceeded storage allocation.\n")
        
        if os.path.isfile(local_path):
            upload_file(local_path, os.path.join(remote_path, os.path.basename(local_path)).replace("\\", "/"))
        else:
            for root_dir, dirs, files in os.walk(local_path):
                for dir_name in dirs:
                    local_dir = os.path.join(root_dir, dir_name)
                    remote_dir = os.path.join(remote_path, os.path.relpath(local_dir, local_path)).replace("\\", "/")
                    try:
                        ftp.mkd(remote_dir)
                    except error_perm:
                        pass  # Ignore if the directory already exists
                for file_name in files:
                    local_file = os.path.join(root_dir, file_name)
                    remote_file = os.path.join(remote_path, os.path.relpath(local_file, local_path)).replace("\\", "/")
                    upload_file(local_file, remote_file)
        
        # Close the FTP connection
        ftp.quit()
    except Exception as e:
        status_widget.insert(tk.END, f"\nFailed to transfer {local_path} to\n\\{host}{remote_path}. Error: {e}\n")
    finally:
        status_widget.yview(tk.END)

####################################################### Get IPs #############################################################
def parse_ip_ranges(base_ip, range_input):
    ip_list = []
    base_ip_parts = base_ip.rsplit('.', 1)
    base_ip_root = base_ip_parts[0]
    base_ip_last_digit = int(base_ip_parts[1])

    if not range_input:
        return None
    else:
        ranges = range_input.split(',')
        for r in ranges:
            if '-' in r:
                start, end = map(int, r.split('-'))
                ip_list.extend([f"{base_ip_root}.{i + base_ip_last_digit}" for i in range(start, end + 1)])
            else:
                ip_list.append(f"{base_ip_root}.{int(r.strip()) + base_ip_last_digit}")
    # print(ip_list)
    return ip_list


def start_transfer(status_widget):
    local_path = file_path.get()
    base_ip = ip_entry.get()
    range_input = range_entry.get()
    remote_dir = remote_dir_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    
    if transfer_type_sel.get() == 'SFTP':
        port = 20022
        # 20022 
    elif transfer_type_sel.get() == 'FTP':
        port = FTP_PORT

    print (f"Selected port is {port}")
    print(f"Login is {username}")
    print(f"Passwprd is {password}")
    print(f"{anonymous_check.get()}")

    if not local_path:
        messagebox.showerror("Input Error", "Please choose a file or folder to transfer.")
        return
    if not base_ip or base_ip == placeholders[ip_entry]:
        messagebox.showerror("Input Error", "Please enter the base IP.")
        return
    if not range_input or range_input == placeholders[range_entry]:
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
        if transfer_type_sel.get() == 'SFTP': 
            threading.Thread(target=sftp_transfer, args=(host, port, username, password, local_path, remote_dir, status_widget)).start()
        elif transfer_type_sel.get() == 'FTP':
            threading.Thread(target=ftp_transfer, args=(host, username, password, local_path, remote_dir, status_widget)).start()
            # threading.Thread(target=ftp_transfer_anonymous, args=(host, username, password, local_path, remote_dir, status_widget)).start()

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
# Dictionary to store entry widgets and their placeholder texts
placeholders = {}
entries = []

def create_placeholder(entry, placeholder_text):
    entry.insert(0, placeholder_text)
    entry.bind("<FocusIn>", lambda event: on_focus_in(entry, placeholder_text))
    entry.bind("<FocusOut>", lambda event: on_focus_out(entry, placeholder_text))
    entry.config(fg="grey")
    placeholders[entry] = placeholder_text
    entries.append(entry)

def on_focus_in(entry, placeholder_text):
    if entry.get() == placeholder_text:
        entry.delete(0, tk.END)
        entry.config(fg='black')

def on_focus_out(entry, placeholder_text):
    if not entry.get():
        entry.insert(0, placeholder_text)
        entry.config(fg='grey')

def disable_placeholder(entry):
    entry.unbind("<FocusIn>")
    entry.unbind("<FocusOut>")
    if entry.get() == placeholders[entry]:
        entry.delete(0, tk.END)
    entry.config(fg='black')

def on_combobox_change(event):
    for entry in entries:
        disable_placeholder(entry)

def combined_combobox_selected(event):
    on_combobox_change(event)
    load_profile_by_name(event)
    set_paths()

# ############################################### Validate IP address format ################################################
def validate_ip_format(event):
    ip = ip_entry.get()
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')  # Match format 'xxx.xxx.xxx.xxx'
    if pattern.match(ip):
        segments = ip.split('.')
        valid = all(0 <= int(segment) <= 255 for segment in segments)
        if valid:
            ip_entry.config(bg="white")
            return True
        else:
            ip_entry.config(bg="yellow")
            return False     
    else:
        ip_entry.config(bg="yellow")
        return False

############################################## Other methods ###############################################################
def set_anonymous_login():
    username_entry.delete(0, tk.END)
    username_entry.insert(0, "anonymous")
    username_entry.config(state='disabled')
    
    password_entry.delete(0, tk.END)
    password_entry.insert(0, "anonymous@example.com")
    password_entry.config(state='disabled')

def on_anonymous_check():
    if anonymous_check.get():
        set_anonymous_login()
    else:
        set_default_login()

def set_default_login():
    username_entry.config(state='normal')
    username_entry.delete(0, tk.END)
    username_entry.insert(0, "Administrator")

    password_entry.config(state='normal')
    password_entry.delete(0, tk.END)
    password_entry.insert(0, "1")

###################################################### Custom paths ##########################################################
# Global variable to store default paths
default_paths = []
custom_paths = []

def set_paths():
    global default_paths, custom_paths
    default_paths_sftp = ("\Config", "\TwinCAT\Boot", "\Layout")
    default_paths_ftp = ("/Hard Disk/Backup/", "/Hard Disk/Backup/export_to_agv", "/Hard Disk/TwinCAT/Boot")
    transfer_type = transfer_type_sel.get()

    # Load custom paths based on the transfer type
    custom_paths = load_custom_paths(transfer_type)

    if transfer_type == 'SFTP':
        default_paths = default_paths_sftp
        anonymous_check.set(0)
        anonymous.config(state='disabled')
        set_default_login()

    elif transfer_type == 'FTP':
        default_paths = default_paths_ftp
        anonymous.config(state='normal')

    # Update the Combobox values
    remote_dir_entry['values'] = default_paths + tuple(custom_paths)
    
    # Optionally, reset the displayed value to the first default path
    if default_paths:
        remote_dir_entry.set(default_paths[0])

    print(f"Default paths set to: {default_paths}")


# Load custom paths from a file
def load_custom_paths(transfer_type):
    try:
        with open("custom_paths.json", "r") as file:
            all_paths = json.load(file)
            return all_paths.get(transfer_type, [])
    except FileNotFoundError:
        return []

# Save custom paths to a file
def save_custom_paths(paths, transfer_type):
    try:
        with open("custom_paths.json", "r") as file:
            all_paths = json.load(file)
    except FileNotFoundError:
        all_paths = {}

    all_paths[transfer_type] = paths

    with open("custom_paths.json", "w") as file:
        json.dump(all_paths, file)

# Initialize custom paths
# custom_paths = load_custom_paths()

# not used
def save_custom_path():
    custom_path = remote_dir_entry.get()
    if custom_path and custom_path not in remote_dir_entry['values']:
        custom_paths.append(custom_path)
        save_custom_paths(custom_paths)
        remote_dir_entry['values'] = default_paths + tuple(custom_paths)
        messagebox.showinfo("Saved", f"Path '{custom_path}' saved successfully.")

def add_path(new_path):
    transfer_type = transfer_type_sel.get()
    paths = load_custom_paths(transfer_type)
    if new_path not in paths:
        paths.append(new_path)
        save_custom_paths(paths, transfer_type)
        messagebox.showinfo("Saved", f"Path '{new_path}' saved successfully.")

def on_add_path():
    new_path = remote_dir_entry.get()
    if new_path:
        add_path(new_path)
        set_paths()  # Update the paths to reflect the new addition
        # remote_dir_entry.delete(0, tk.END)  # Clear the entry widget

####################################################### Profiles ###############################################################

default_profile = {
    "name":     "Default",
    "base_ip":  "192.168.80.10", 
    "ip_range": "1-15,20-35",
    "username": "Administrator",
    "password": "***********",
    "remote_dir": "\\Config",
    "transfer_type": "SFTP"
}

def set_profile(profile):
    ip_entry.delete(0, tk.END)
    ip_entry.insert(0, profile["base_ip"])

    range_entry.delete(0, tk.END)
    range_entry.insert(0, profile["ip_range"])

    remote_dir_entry.delete(0, tk.END)
    remote_dir_entry.insert(0, profile["remote_dir"])

    username_entry.delete(0, tk.END)
    username_entry.insert(0, profile["username"])

    password_entry.delete(0, tk.END)
    password_entry.insert(0, profile["password"])

    transfer_type_sel.set(profile["transfer_type"])

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

def save_custom_profiles(profile):
    with open("custom_profiles.json", "w") as file:
        json.dump(profile, file, indent=4)


def save_custom_profile():
    custom_profile_name = profiles_combobox.get()
    base_ip = ip_entry.get()
    range_input = range_entry.get()
    dir_entry = remote_dir_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    transfer_mode = transfer_type.get()

    if not custom_profile_name or custom_profile_name == "Select a profile":
        messagebox.showerror("Error", "Please enter a profile name")
        return
    if not base_ip or base_ip == placeholders[ip_entry] or not validate_ip_format("<KeyRelease>"):
        messagebox.showerror("Input Error", "Please enter the base IP.")
        return
    if not range_input or range_input == placeholders[range_entry]:
        messagebox.showerror("Input Error", "Please enter the IP range.")
        return
    if not dir_entry:
        messagebox.showerror("Input Error", "Please enter the remote directory.")
        return
    if not username:
        messagebox.showerror("Input Error", "Please enter the username.")
        return
    if not password:
        messagebox.showerror("Input Error", "Please enter the password.")
        return
    # if not transfer_mode:
    #     messagebox.showerror("Input Error", "Please enter the transfer type.")
    #     return
    
    custom_profile = {
        "name":             custom_profile_name,
        "base_ip":          ip_entry.get(),
        "ip_range":         range_entry.get(),
        "remote_dir":       remote_dir_entry.get(),
        "username":         username_entry.get(),
        "password":         password_entry.get(),
        "transfer_type":    transfer_type_sel.get()    
    }

    custom_profiles = load_custom_profiles()
    profile_names = [profile["name"] for profile in custom_profiles]

    # Check for duplicate profile names and update if found
    for existing_profile in custom_profiles:
        if existing_profile["name"] == custom_profile_name:
            existing_profile.update(custom_profile)
            break
    else:
        custom_profiles.append(custom_profile)
    
    save_custom_profiles(custom_profiles)
    profiles_combobox['values'] = tuple(profile_names) + ("Default",)
    messagebox.showinfo("Success", "Profile saved successfully")

def load_profile_by_name(event=None):
    selected_profile_name = profiles_combobox.get()
    # save_custom_profiles([default_profile]) #option to save default profile on file at first cycle
    profiles = load_custom_profiles()

    if selected_profile_name == "Default":
        set_profile(default_profile)
    else:
        for profile in profiles:
            if profile["name"] == selected_profile_name:
                set_profile(profile)
                break

def load_profile_names(event=None):
    custom_profiles = load_custom_profiles()
    profile_names = [profile["name"] for profile in custom_profiles]
    profiles_combobox['values'] = tuple(profile_names) + ("Default",)

####################################################################################################################
def on_enter(e):
    e.widget['background'] = 'LightSkyBlue1'

def on_leave(e):
    e.widget['background'] = 'ghost white'

######################################################## Create UI ##################################################

root = tk.Tk()
root.title("Super File Transfer")

root.resizable(False, False)

transfer_type = tk.StringVar()
transfer_type_sel = tk.StringVar(value='SFTP')

# Radio buttons for selecting file or folder
tk.Radiobutton(root, text="FTP", variable=transfer_type_sel, value='FTP', command=set_paths).grid(row=0, column=0, padx=10, pady=0, sticky='w')
tk.Radiobutton(root, text="SFTP", variable=transfer_type_sel, value='SFTP', command=set_paths).grid(row=0, column=0, padx=60, pady=0, sticky='w')

# Variable to store the file or folder path
file_path = tk.StringVar()
# Variable to store the user's choice (file or folder)
selection = tk.StringVar(value='file')

# Radio buttons for selecting file or folder
tk.Radiobutton(root, text="File", variable=selection, value='file').grid(row=1, column=0, padx=10, pady=10, sticky='w')
tk.Radiobutton(root, text="Folder:", variable=selection, value='folder').grid(row=1, column=0, padx=60, pady=10, sticky='w')

# Create a listbox to display saved profiles
profiles_combobox = ttk.Combobox(root, width=40)
# profiles_combobox.insert(0, default_profile["name"])
profiles_combobox.set("Select a profile")
profiles_combobox.grid(row=0, column=1,padx=10, pady=10)
profiles_combobox.bind("<ButtonPress>", load_profile_names)
profiles_combobox.bind("<<ComboboxSelected>>", combined_combobox_selected)

save = tk.Button(root, text="Save Profile", command=save_custom_profile)
save.grid(row=0, column=2, padx=10, pady=10)
# save.bind("<Button-1>", validate_ip_format)

tk.Button(root, text="Browse", command=choose_file_or_folder).grid(row=1, column=2, padx=5, pady=10)

# tk.Label(root, text="Choose file or folder to transfer:").grid(row=1, column=0, padx=10, pady=10)
tk.Entry(root, textvariable=file_path, width=50).grid(row=1, column=1, padx=10, pady=10)

tk.Label(root, text="Enter Root IP:").grid(row=2, column=0, padx=10, pady=10)
ip_entry = tk.Entry(root, width=50)
ip_entry.grid(row=2, column=1, padx=10, pady=10)
create_placeholder(ip_entry, "e.g., 7.204.194.10")
ip_entry.bind("<KeyRelease>", validate_ip_format)


tk.Label(root, text="Enter LGV range:").grid(row=3, column=0, padx=10, pady=10)
range_entry = tk.Entry(root, width=50)
range_entry.grid(row=3, column=1, padx=10, pady=10)
create_placeholder(range_entry, "e.g., 1-9,11-25,27,29,31-40")


tk.Label(root, text="Enter remote directory:").grid(row=4, column=0, padx=10, pady=10)
remote_dir_entry = ttk.Combobox(root, 
                                # values=default_paths + tuple(custom_paths), 
                                width=47)
# if default_paths:
#     remote_dir_entry.insert(0, default_paths[0])
remote_dir_entry.grid(row=4, column=1, padx=10, pady=10)

# Add a button to save a custom path
save_path = tk.Button(root, text="Save Path", 
        #   command=save_custom_path)
        command=on_add_path)
save_path.grid(row=4, column=2, padx=5, pady=10)

# create_placeholder(remote_dir_entry, "e.g., /remote/config/")

tk.Label(root, text="Enter username:").grid(row=5, column=0, padx=10, pady=10)
username_entry = tk.Entry(root, width=50)
username_entry.insert(0, "Administrator")
username_entry.grid(row=5, column=1, padx=10, pady=10)

anonymous_check = tk.IntVar()
anonymous = tk.Checkbutton(root, text="Anonymous", variable=anonymous_check, command=on_anonymous_check)
anonymous.grid(row=5, column=2)

tk.Label(root, text="Enter password:").grid(row=6, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, width=50, show="*")
password_entry.grid(row=6, column=1, padx=10, pady=10)


transfer = tk.Button(root, text="Start Transfer", 
                     borderwidth=0,
                     highlightthickness=0,
                     background='white',
                     command=lambda: start_transfer(status_widget)
                     )
transfer.grid(row=7, column=0, columnspan=3, pady=20)
transfer.configure(font=('Lucida Sans', 12))
transfer.bind("<Enter>", on_enter)
transfer.bind("<Leave>", on_leave)
transfer.bind("<Button-1>", on_enter)

# status_widget = tk.Text(root, height=10, width=80)
status_widget = scrolledtext.ScrolledText(root, 
                                          undo=True,
                                          height=15,
                                          width=70
                                          )
status_font = font.Font(family="Consolas", size=11)
status_widget.configure(font=status_font)
status_widget.grid(row=8, column=0, columnspan=3, padx=10, pady=10)
status_widget.bind("<Key>", lambda e: "break")

set_paths()

root.mainloop()

## not showing connection timeout fix that
## add profiles to save data just like routes

## fix data still gray even after placeholder is not the same
##  cannot send several files at the same time

## create tool for layout zipper