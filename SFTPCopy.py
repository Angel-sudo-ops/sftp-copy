import paramiko
import stat
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import font, ttk
import tkinter.scrolledtext as scrolledtext
import threading
import queue
import json
import re
import sys
from ftplib import FTP, error_perm
from ftplib import FTP_PORT
# import pystray
# from PIL import Image

__version__ = '3.3.2'

############################################### SFTP Transfer ###############################################

def sftp_transfer(host, port, username, password, local_path, remote_path, status_widget, result_queue):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    success = True  # Track overall success for the entire transfer process

    try:
        status_widget.insert(tk.END, f"Transfer to {host} in progress...\n")
        status_widget.yview(tk.END)
        ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10, auth_timeout=10)
        sftp = ssh.open_sftp()

        if os.path.isfile(local_path):
            try:
                sftp.put(local_path, os.path.join(remote_path, os.path.basename(local_path)))
                status_widget.insert(tk.END, f"\nSuccessfully transferred {local_path} to\n\\{host}{remote_path}\n")
            except Exception as e:
                status_widget.insert(tk.END, f"\nFailed to transfer {local_path} to\n\\{host}{remote_path}. Error: {e}\n")
                success = False
        else:
            for root_dir, dirs, files in os.walk(local_path):
                for dir_name in dirs:
                    local_dir = os.path.join(root_dir, dir_name)
                    remote_dir = os.path.join(remote_path, os.path.relpath(local_dir, local_path))
                    try:
                        sftp.mkdir(remote_dir)
                    except Exception as e: #One error is when directory already exists, maybe remove this condition for folder
                        status_widget.insert(tk.END, f"\nFailed to create directory {remote_dir} on {host}: {e}\n")
                        # success = False
                        continue  # Continue with other directories/files even if one fails

                for file_name in files:
                    local_file = os.path.join(root_dir, file_name)
                    remote_file = os.path.join(remote_path, os.path.relpath(local_file, local_path))
                    try:
                        sftp.put(local_file, remote_file)
                        status_widget.insert(tk.END, f"\nSuccessfully transferred {local_file} to\n\\{host}{remote_file}\n")
                    except Exception as e:
                        status_widget.insert(tk.END, f"\nFailed to transfer {local_file} to {remote_file} on {host}: {e}\n")
                        success = False

        sftp.close()
        ssh.close()
    except Exception as e:
        status_widget.insert(tk.END, f"\nFailed to initiate transfer to \\{host}. \nError: {e}\n")
        success = False
    finally:
        result = "Success" if success else "Failed"
        status_widget.yview(tk.END)
        # Put the result in the queue with associated host information
        result_queue.put((host, result))

############################################### SFTP Download ###############################################

def sftp_download(host, port, username, password, remote_path, local_path, status_widget, result_queue):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    success = True  # Track overall success for the entire download process

    try:
        status_widget.insert(tk.END, f"Download from {host} in progress...\n")
        status_widget.yview(tk.END)
        ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10, auth_timeout=10)
        sftp = ssh.open_sftp()
        
        def download_file(sftp, remote_file_path, local_file_path):
            try:
                sftp.get(remote_file_path, local_file_path)
                status_widget.insert(tk.END, f"\nSuccessfully downloaded {remote_file_path} to {local_file_path}\n")
            except Exception as e:
                status_widget.insert(tk.END, f"\nFailed to download {remote_file_path} to {local_file_path}. Error: {e}\n")
                nonlocal success
                success = False
            finally:
                status_widget.yview(tk.END)

        def download_folder(sftp, remote_folder_path, local_folder_path):
            os.makedirs(local_folder_path, exist_ok=True)
            for entry in sftp.listdir_attr(remote_folder_path):
                remote_path = os.path.join(remote_folder_path, entry.filename).replace('\\', '/')
                local_path = os.path.join(local_folder_path, entry.filename)
                if stat.S_ISDIR(entry.st_mode):
                    download_folder(sftp, remote_path, local_path)
                else:
                    download_file(sftp, remote_path, local_path)

        def is_sftp_dir(sftp, path):
            try:
                return stat.S_ISDIR(sftp.stat(path).st_mode)
            except IOError:
                return False
        
        if is_sftp_dir(sftp, remote_path):
            download_folder(sftp, remote_path, local_path)
        else:
            download_file(sftp, remote_path, local_path)

        sftp.close()
        ssh.close()
        if success:
            status_widget.insert(tk.END, f"\nDownload from {host} completed successfully.\n")
        else:
            status_widget.insert(tk.END, f"\nDownload from {host} completed with some errors.\n")
    except Exception as e:
        status_widget.insert(tk.END, f"\nFailed to initiate download from \\{host}. \nError: {e}\n")
        success = False
    finally:
        result = "Success" if success else "Failed"
        status_widget.yview(tk.END)
        result_queue.put((host, result))

################################################ FTP transfer ###############################################################

def ftp_transfer(host, username, password, local_path, remote_path, status_widget, result_queue):
    success = True  # Track overall success for the entire transfer process

    try:
        status_widget.insert(tk.END, f"Transfer to {host} in progress...\n")
        status_widget.yview(tk.END)
        
        # Connect to the FTP server
        ftp = FTP(host, timeout=15)
        ftp.login(user=username, passwd=password)

        if os.path.isfile(local_path):
            try:
                with open(local_path, 'rb') as file:
                    ftp.storbinary(f"STOR {os.path.join(remote_path, os.path.basename(local_path)).replace('\\', '/')}", file)
                status_widget.insert(tk.END, f"\nSuccessfully transferred {local_path} to\n\\{host}{remote_path}\n")
            except Exception as e:
                status_widget.insert(tk.END, f"\nFailed to transfer {local_path} to\n\\{host}{remote_path}. Error: {e}\n")
                success = False
        else:
            for root_dir, dirs, files in os.walk(local_path):
                for dir_name in dirs:
                    local_dir = os.path.join(root_dir, dir_name)
                    remote_dir = os.path.join(remote_path, os.path.relpath(local_dir, local_path)).replace("\\", "/")
                    try:
                        ftp.mkd(remote_dir)
                    except Exception as e: #One error is when directory already exists, maybe remove this condition for folder
                        status_widget.insert(tk.END, f"\nFailed to create directory {remote_dir} on {host}. Error: {e}\n")
                        # success = False
                        continue  # Continue with other directories/files even if one fails

                for file_name in files:
                    local_file = os.path.join(root_dir, file_name)
                    remote_file = os.path.join(remote_path, os.path.relpath(local_file, local_path)).replace("\\", "/")
                    try:
                        with open(local_file, 'rb') as file:
                            ftp.storbinary(f"STOR {remote_file}", file)
                        status_widget.insert(tk.END, f"\nSuccessfully transferred {local_file} to\n\\{host}{remote_file}\n")
                    except Exception as e:
                        status_widget.insert(tk.END, f"\nFailed to transfer {local_file} to {remote_file} on {host}. Error: {e}\n")
                        success = False
        
        # Close the FTP connection
        ftp.quit()
    except Exception as e:
        status_widget.insert(tk.END, f"\nFailed to initiate transfer to \\{host}. \nError: {e}\n")
        success = False
    finally:
        result = "Success" if success else "Failed"
        status_widget.yview(tk.END)
        result_queue.put((host, result))

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

################################################ FTP download ###############################################################

def ftp_download(host, username, password, remote_path, local_path, status_widget, result_queue):
    success = True  # Track overall success for the entire download process

    try:
        status_widget.insert(tk.END, f"Download from {host} in progress...\n")
        status_widget.yview(tk.END)
        
        # Connect to the FTP server
        ftp = FTP(host)
        ftp.login(user=username, passwd=password)
        
        try:
            ftp.cwd(remote_path)
        except Exception as e:
            status_widget.insert(tk.END, f"Error navigating to {remote_path}. {e}\n")
            ftp.quit()
            success = False
            return

        def download_file(ftp, remote_file_path, local_file_path):
            try:
                with open(local_file_path, 'wb') as local_file:
                    ftp.retrbinary(f'RETR {remote_file_path}', local_file.write)
                status_widget.insert(tk.END, f"\nSuccessfully downloaded {remote_file_path} to\n{local_file_path}\n")
            except Exception as e:
                status_widget.insert(tk.END, f"\nFailed to download {remote_file_path} to\n{local_file_path}. \nError: {e}\n")
                nonlocal success
                success = False
            finally:
                status_widget.yview(tk.END)

        def download_folder(ftp, remote_folder_path, local_folder_path):
            os.makedirs(local_folder_path, exist_ok=True)
            ftp.cwd(remote_folder_path)
            
            file_list = ftp.nlst()
            
            for file_name in file_list:
                local_path = os.path.join(local_folder_path, file_name)
                remote_path = os.path.join(remote_folder_path, file_name).replace('\\', '/')
                
                if is_ftp_dir(ftp, file_name):
                    download_folder(ftp, remote_path, local_path)
                else:
                    download_file(ftp, remote_path, local_path)
        
        def download_files_only(ftp, remote_folder_path, local_folder_path):
            os.makedirs(local_folder_path, exist_ok=True)
            ftp.cwd(remote_folder_path)
            
            file_list = ftp.nlst()
            
            for file_name in file_list:
                remote_item_path = os.path.join(remote_folder_path, file_name).replace('\\', '/')
                local_item_path = os.path.join(local_folder_path, file_name)
                
                if not is_ftp_dir(ftp, file_name):
                    download_file(ftp, remote_item_path, local_item_path)

        def is_ftp_dir(ftp, name):
            try:
                ftp.cwd(name)
                ftp.cwd('..')
                return True
            except Exception as e:
                return False

        download_files_only(ftp, remote_path, local_path)
        
        # Close the FTP connection
        ftp.quit()

        if success:
            status_widget.insert(tk.END, f"\nDownload from {host} completed successfully.\n")
        else:
            status_widget.insert(tk.END, f"\nDownload from {host} completed with some errors.\n")
    except Exception as e:
        status_widget.insert(tk.END, f"\nFailed to initiate download {remote_path} from {host}. \nError: {e}\n")
        success = False
    finally:
        result = "Success" if success else "Failed"
        status_widget.yview(tk.END)
        result_queue.put((host, result))

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

############################################# Transfer files to remote server ################################################
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
    print(f"Password is {password}")
    print(f"{anonymous_check.get()}")
    print(local_path)

    if not local_path:
        messagebox.showerror("Input Error", "Please choose a file or folder to transfer.")
        return
    # if not base_ip or base_ip == placeholders[ip_entry]:
    if not validate_base_ip():
        messagebox.showerror("Input Error", "Please enter the base IP.")
        return
    # if not range_input or range_input == placeholders[range_entry]:
    if not validate_range():
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

    result_queue = queue.Queue()
    threads = []

    for host in ip_list:
        if transfer_type_sel.get() == 'SFTP': 
            t = threading.Thread(target=sftp_transfer, args=(host, port, username, password, local_path, remote_dir, status_widget, result_queue))
        elif transfer_type_sel.get() == 'FTP':
            t = threading.Thread(target=ftp_transfer, args=(host, username, password, local_path, remote_dir, status_widget, result_queue))
            # threading.Thread(target=ftp_transfer_anonymous, args=(host, username, password, local_path, remote_dir, status_widget)).start()
        
        t.start()
        threads.append(t)

    # Start a separate thread to monitor the worker threads
    threading.Thread(target=monitor_threads, args=(threads, result_queue, status_widget)).start()

################################ Monitor threads ############################################
def monitor_threads(threads, result_queue, status_widget):
    # Wait for all threads to complete
    for t in threads:
        t.join()
    
    # Check for any failed results
    failed_hosts = []
    failed = 0
    total = 0

    while not result_queue.empty():
        host, result = result_queue.get()
        if result == "Failed":
            failed_hosts.append(host)
            failed=failed+1
        total=total+1

    if failed_hosts:
        status_widget.insert(tk.END, f"\n\n*****Connection failed for {failed} out of {total} hosts*****\n")
        for host in failed_hosts:
            status_widget.insert(tk.END, f"{host}\n")
    else:
        status_widget.insert(tk.END, "\n\n*****All transfers successfull*****\n")

    # Ensure the status widget updates properly
    status_widget.yview(tk.END)

############################################# Download files from remote server ################################################

def start_download(status_widget):
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
    print(f"Password is {password}")
    print(f"{anonymous_check.get()}")


    # if not base_ip or base_ip == placeholders[ip_entry]:
    if not validate_range():
        messagebox.showerror("Input Error", "Please enter a valid IP.")
        return
    # if not range_input or range_input == placeholders[range_entry]:
    if not validate_base_ip():
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

    # local_root_path = file_path.get()
    local_root_path = filedialog.askdirectory()
    if not local_root_path:
        messagebox.showerror("Input Error", "Please choose a folder where to download.")
        return
    new_folder_name = "Download"
    new_folder_path = os.path.join(local_root_path, new_folder_name)
    if not os.path.exists(new_folder_path):
        os.makedirs(new_folder_path)
    print(new_folder_path)
    print(local_root_path)

    if not local_root_path:
        messagebox.showerror("Input Error", "Please choose a folder where to download.")
        return

    status_widget.delete(1.0, tk.END)  # Clear previous status messages
    ip_list = parse_ip_ranges(base_ip, range_input)

    if ip_list is None:
        messagebox.showerror("Input Error", "Please provide a valid IP range.")
        return

    result_queue = queue.Queue()
    threads = []

    for host in ip_list:
        # local_path = os.path.join(local_root_path, f"{host}")
        local_path = os.path.join(new_folder_path, f"{host}")
        if transfer_type_sel.get() == 'SFTP': 
            t = threading.Thread(target=sftp_download, args=(host, port, username, password, remote_dir, local_path, status_widget, result_queue))
        if transfer_type_sel.get() == 'FTP':
            t = threading.Thread(target=ftp_download, args=(host, username, password, remote_dir, local_path, status_widget, result_queue))
            # threading.Thread(target=ftp_transfer_anonymous, args=(host, username, password, local_path, remote_dir, status_widget)).start()

        t.start()
        threads.append(t)
    
    # Start a separate thread to monitor the worker threads
    threading.Thread(target=monitor_threads, args=(threads, result_queue, status_widget)).start()

############################################################ Choose file to transfer ################################################
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
entries = {}

def create_placeholder(entry, placeholder_text, entry_style, placeholder_style):
    entry.insert(0, placeholder_text)
    entry.config(style=placeholder_style)
    entry.bind("<FocusIn>", lambda event: on_focus_in(entry, placeholder_text, entry_style))
    entry.bind("<FocusOut>", lambda event: on_focus_out(entry, placeholder_text, placeholder_style))
    placeholders[entry] = placeholder_text
    entries[entry] = entry_style

def on_focus_in(entry, placeholder_text, entry_style):
    if entry.get() == placeholder_text:
        entry.delete(0, tk.END)
        entry.config(style=entry_style)

def on_focus_out(entry, placeholder_text, placeholder_style):
    if not entry.get():
        entry.insert(0, placeholder_text)
        entry.config(style=placeholder_style)

def disable_placeholder(entry, entry_style):
    entry.unbind("<FocusIn>")
    entry.unbind("<FocusOut>")
    if entry.get() == placeholders[entry]:
        entry.delete(0, tk.END)
    # entry.config(fg='black')
    entry.config(style=entry_style)
    # entry.bind("<KeyRelease>")

def on_combobox_change(event):
    for entry in entries:
        entry.config(style=entries[entry])
        # disable_placeholder(entry, entries[entry])

def combined_combobox_selected(event):
    style.configure('RootIP.TEntry', foreground=good_input_fg)
    style.configure('Range.TEntry', foreground=good_input_fg) 
    on_combobox_change(event)
    # validate_entry(ip_entry, 'RootIP.TEntry', validate_base_ip)
    # validate_entry(range_entry, 'Range.TEntry', validate_range)
    load_profile_by_name(event)
    set_paths()

# ############################################### Validate inputs ################################################
good_input_bg = 'white'
bad_input_bg = '#fbcbcb' # light red
good_input_fg = 'black'
bad_input_fg = '#de021a' # red 
placeholder_fg = 'grey'

def validate_entry(entry, style_name, validate_func):
    def inner_validate(*args):
        if entry.get() != placeholders[entry]:
            result = validate_func(entry)
            if result:
                style.configure(style_name, background=good_input_bg, foreground=good_input_fg)
            else:
                style.configure(style_name, background=bad_input_bg, foreground=bad_input_fg)
        else:
             style.configure(style_name, background=good_input_bg, foreground=placeholder_fg)
    # print(inner_validate)
    return inner_validate

def validate_range(*args):
    pattern = r"^\d+(-\d+)?(,\d+(-\d+)?)*$"
    input_range = range_entry.get().strip()
    
    # If the input is empty, reset to good input colors and return False
    if not input_range or input_range == placeholders[range_entry]:
        return False
    
    # Check if the input matches the pattern
    if re.match(pattern, input_range):
        ranges = input_range.split(',')
        
        # Check that each range is in increasing order, starts with a number greater than 0,
        # and does not have leading zeros
        for r in ranges:
            if '-' in r:
                start, end = r.split('-')
                if not start.isdigit() or not end.isdigit() or int(start) <= 0 or int(start) > int(end) or start != str(int(start)) or end != str(int(end)):
                    return False
            else:
                # If it's a single number, ensure it's greater than 0 and does not have leading zeros
                if not r.isdigit() or int(r) <= 0 or r != str(int(r)):
                    return False
        return True
    else:
        return False
    
def validate_base_ip(*args):
    base_ip = ip_entry.get().strip()
    if validate_ip(base_ip):
        return True
    elif not base_ip or base_ip == placeholders[ip_entry]:      
        return False
    else:
        return False

# Function to validate IP address format
def validate_ip(ip):
    # Compile the regex pattern for the base IP format 'xxx.xxx.xxx.xxx'
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')  # Match format 'xxx.xxx.xxx.xxx'
    # Check if the input matches the pattern
    if pattern.match(ip):
        # Split the IP into parts and check if each part is between 0 and 255
        parts = ip.split('.')
        return all(0 <= int(num) <= 255 for num in parts)
    return False

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
    default_paths_sftp = (r"\Config", r"\TwinCAT\Boot", r"\Layout")
    default_paths_ftp = ("/Hard Disk/Backup/", "/Hard Disk/Backup/export_to_agv", "/Hard Disk/TwinCAT/Boot")
    default_paths_net = (r"\Backup", r"\Backup\export_to_agv") #examples for now, get real ones later
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
    
    elif transfer_type == 'NET':
        default_paths = default_paths_net

    # Update the Combobox values
    remote_dir_entry['values'] = default_paths + tuple(custom_paths)
    
    # Optionally, reset the displayed value to the first default path
    if default_paths:
        remote_dir_entry.set(default_paths[0])

    print(f"Default paths set to: {default_paths}")


def select_mode():
    mode_selected = mode_selection.get()
    if mode_selected == 'transfer':
        transfer.config(state='normal')
        download.config(state="disabled")
        file_path_entry.config(state='normal')
        browse_btn.config(state='normal')
        folder_radio.config(state='normal')
        file_radio.config(state='normal')

    elif mode_selected == 'download':
        transfer.config(state='disabled')
        download.config(state="normal")
        file_path_entry.config(state='disabled')
        browse_btn.config(state='disabled')
        folder_radio.config(state='disabled')
        file_radio.config(state='disabled')
    print(f"Selected mode {mode_selected}")

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
    if (new_path not in paths) and (new_path not in default_paths):
        paths.append(new_path)
        save_custom_paths(paths, transfer_type)
        messagebox.showinfo("Saved", f"Path '{new_path}' saved successfully.")
    else:
        messagebox.showinfo("Info", f"Path '{new_path}' already exists.")

def on_add_path():
    new_path = remote_dir_entry.get()
    if new_path:
        add_path(new_path)
        set_paths()  # Update the paths to reflect the new addition
        remote_dir_entry.delete(0, tk.END)  # Clear the entry widget
        remote_dir_entry.insert(0, new_path)

####################################################### Profiles ###############################################################

default_profile = {
    "name":         "Default",
    "base_ip":      "192.168.80.10", 
    "ip_range":     "1-15,20-35",
    "username":     "Administrator",
    "password":     "***********",
    "remote_dir":   "\\Config",
    "transfer_type":"SFTP"
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
    transfer_mode = transfer_type_sel.get()

    if not custom_profile_name or custom_profile_name.lower() == "select a profile" or custom_profile_name.lower() == "default":
        messagebox.showerror("Error", "Please enter a profile name")
        return
    # if not base_ip or base_ip == placeholders[ip_entry] or not validate_ip_format("<KeyRelease>"):
    if not validate_base_ip():
        messagebox.showerror("Input Error", "Please enter valid base IP.")
        return
    # if not range_input or range_input == placeholders[range_entry]:
    if not validate_range():
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
        "base_ip":          base_ip,
        "ip_range":         range_input,
        "remote_dir":       dir_entry,
        "username":         username,
        "password":         password,
        "transfer_type":    transfer_mode
    }

    custom_profiles = load_custom_profiles()
    profile_names = [profile['name'] for profile in custom_profiles]

    # Check for duplicate profile names and update if found
    for existing_profile in custom_profiles:
        if (existing_profile['name'] == custom_profile_name):
            existing_profile.update(custom_profile)
            messagebox.showinfo("Success", "Existing profile updated.")
            break
        # fix default profile is updated with same name, not save that profile, that is just an example!!!
    else:
        custom_profiles.append(custom_profile)
        messagebox.showinfo("Success", "New profile saved successfully")
    
    save_custom_profiles(custom_profiles)
    profiles_combobox['values'] = tuple(profile_names) + ("Default",)
    # messagebox.showinfo("Success", "Profile saved successfully")

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
    if e.widget['state']== "normal":
        e.widget['background'] = 'LightSkyBlue1'

def on_leave(e):
    if e.widget['state'] == "normal":
        e.widget['background'] = 'ghost white'

def button_design(entry):
    entry.bind("<Enter>", on_enter)
    entry.bind("<Leave>", on_leave)
    entry.bind("<Button-1>", on_enter)

############################Closing window ##################################
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):

        root.destroy()

############################ Remove focus ############################
def remove_focus(event):
    root.focus()

def disable_focus(widget):
    try:
        widget.configure(takefocus=0)
    except tk.TclError:
        pass  # Skip widgets that do not support takefocus
    for child in widget.winfo_children():
        disable_focus(child)

############################# Set GUI icon ##########################
def set_icon():
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    else:
        print("Icon file not found.")


######################################################## Create UI ##################################################

root = tk.Tk()
root.title(f"Super File Transfer {__version__}")

# Check if running as a script or frozen executable
if getattr(sys, 'frozen', False):
    icon_path = os.path.join(sys._MEIPASS, "./transfer.ico")
else:
    icon_path = os.path.abspath("./transfer.ico")
# root.iconbitmap(icon_path)

window_width = 600
window_lenght = 670
root.geometry(f"{window_width}x{window_lenght}")
root.minsize(window_width, window_lenght)

# root.resizable(False, False)

# Apply the icon after the window is initialized
root.after(100, set_icon)

style = ttk.Style()
# Create a style for the Entry widget
style.configure('RootIP.TEntry', foreground='black')
style.configure('Range.TEntry', foreground='black')

style.configure('Placeholder.TEntry', foreground='grey')

frame_profile = tk.Frame(root)
frame_profile.grid(row=0, column=1, padx=10, pady=5, sticky='w')
# Create a listbox to display saved profiles
profiles_combobox = ttk.Combobox(frame_profile, width=40)
profiles_combobox.set("Select a profile")
profiles_combobox.grid(row=0, column=0, padx=10, pady=5, sticky='w')
profiles_combobox.bind("<ButtonPress>", load_profile_names)
profiles_combobox.bind("<<ComboboxSelected>>", combined_combobox_selected)

save_profile = ttk.Button(frame_profile, 
                          text="Save Profile", 
                        #   bg='ghost white', 
                          command=save_custom_profile)
save_profile.grid(row=0, column=1, padx=5, pady=5)
# button_design(save_profile)


# Customize the focus ring (or border) of the Radiobutton
style.configure("Custom.TRadiobutton", focuscolor="lightblue", highlightthickness=2)


# transfer_type = tk.StringVar()
transfer_type_sel = tk.StringVar(value='SFTP')
# style.configure("Transfer.TLabelframe.Label", relief='groove', font=("Segoe UI", 10, "italic"))
frame_transfer = tk.Frame(root, bd=1, relief='groove')
frame_transfer.grid(row=0, column=0, padx=0, pady=5, sticky='e')
# Radio buttons for selecting file or folder
sftp_option = ttk.Radiobutton(frame_transfer, text="FTP", variable=transfer_type_sel, value='FTP', command=set_paths, style="Custom.TRadiobutton")
sftp_option.grid(row=0, column=0, padx=0, pady=0, sticky='w')
ftp_option = ttk.Radiobutton(frame_transfer, text="SFTP", variable=transfer_type_sel, value='SFTP', command=set_paths, style="Custom.TRadiobutton")
ftp_option.grid(row=0, column=1, padx=0, pady=0, sticky='w')
net_option = ttk.Radiobutton(frame_transfer, text="NetFolder", variable=transfer_type_sel, value='NET', command=set_paths, style="Custom.TRadiobutton")
net_option.grid(row=0, column=2, padx=0, pady=0, sticky='w')

# Bind the radio buttons to the function that removes focus
# ftp_option.bind("<ButtonRelease-1>", remove_focus)
# sftp_option.bind("<ButtonRelease-1>", remove_focus)
# net_option.bind("<ButtonRelease-1>", remove_focus)


frame_path = tk.Frame(root)
frame_path.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

frame_file = tk.Frame(frame_path)
frame_file.grid (row=0, column=0, columnspan=2, padx=5, pady=5)
# Variable to store the user's choice (file or folder)
selection = tk.StringVar(value='file')

frame_file_selection = tk.Frame(frame_file)
frame_file_selection.grid(row=0, column=0, padx=5, pady=5)

# Radio buttons for selecting file or folder
file_radio = ttk.Radiobutton(frame_file_selection, text="File:", variable=selection, value='file')
file_radio.grid(row=0, column=1, padx=0, pady=0)
folder_radio = ttk.Radiobutton(frame_file_selection, text="Folder", variable=selection, value='folder')
folder_radio.grid(row=0, column=0, padx=0, pady=0)

# Variable to store the file or folder path
file_path = tk.StringVar()
# tk.Label(root, text="Choose file or folder to transfer:").grid(row=1, column=0, padx=10, pady=10)
file_path_entry = ttk.Entry(frame_file, textvariable=file_path, width=60)
file_path_entry.grid(row=0, column=1, padx=5, pady=5)

browse_btn = ttk.Button(frame_file, text="Browse",
                        # bg='ghost white', 
                        command=choose_file_or_folder)
browse_btn.grid(row=0, column=2, padx=5, pady=5)
# button_design(browse_btn)


frame_remote = tk.Frame(frame_path)
frame_remote.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

remote_dir_label = ttk.Label(frame_remote, text="Remote directory:")
remote_dir_label.grid(row=0, column=0, padx=10, pady=10)

remote_dir_entry = ttk.Combobox(frame_remote, 
                                # values=default_paths + tuple(custom_paths), 
                                width=55)
# if default_paths:
#     remote_dir_entry.insert(0, default_paths[0])
remote_dir_entry.grid(row=0, column=1, padx=5, pady=5)

# Add a button to save a custom path
save_path = ttk.Button(frame_remote, text="Save Path",
                    #   bg='ghost white',
                      command=on_add_path)
save_path.grid(row=0, column=2, padx=5, pady=10)
# button_design(save_path)


frame_lgv_login = tk.Frame(root)
frame_lgv_login.grid(row=3, column=0, columnspan=2, padx=5, pady=0)


frame_lgvs = tk.Frame(frame_lgv_login)
frame_lgvs.grid(row=0, column=0, columnspan=1, padx=5, pady=5, sticky='e')

frame_ip = tk.Frame(frame_lgvs)
frame_ip.grid(row=0, column=0, padx=5, pady=5)

ip_label = ttk.Label(frame_ip, text="Root IP:")
ip_label.grid(row=0, column=0, padx=5, pady=5)

ip_entry = ttk.Entry(frame_ip, width=25)
ip_entry.grid(row=0, column=1, padx=5, pady=5)
create_placeholder(ip_entry, "e.g., 7.204.194.10", "RootIP.TEntry", "Placeholder.TEntry")
ip_entry.bind("<KeyRelease>", validate_entry(ip_entry, 'RootIP.TEntry', validate_base_ip))

frame_range = tk.Frame(frame_lgvs)
frame_range.grid(row=1, column=0, padx=5, pady=10)

range_label = ttk.Label(frame_range, text="Range:")
range_label.grid(row=0, column=0, padx=5, pady=5)

range_entry = ttk.Entry(frame_range, width=25)
range_entry.grid(row=0, column=1, padx=5, pady=5)
create_placeholder(range_entry, "e.g., 1-9,27,29,31-40", "Range.TEntry", "Placeholder.TEntry")
range_entry.bind("<KeyRelease>", validate_entry(range_entry, 'Range.TEntry', validate_range))


frame_login = tk.Frame(frame_lgv_login)
frame_login.grid(row=0, column=1, columnspan=1, padx=5, pady=5)

frame_user = tk.Frame(frame_login)
frame_user.grid(row=0, column=0, padx=5, pady=5)

username_label = ttk.Label(frame_user, text="Username:")
username_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

username_entry = ttk.Entry(frame_user)
username_entry.insert(0, "Administrator")
username_entry.grid(row=0, column=1, padx=5, pady=5)

frame_password = tk.Frame(frame_login)
frame_password.grid(row=1, column=0, padx=5, pady=10)

password_label = ttk.Label(frame_password, text="Password:")
password_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

password_entry = ttk.Entry(frame_password, show="*")
password_entry.grid(row=0, column=1, padx=5, pady=5)

anonymous_check = tk.IntVar()
anonymous = ttk.Checkbutton(frame_login, text="Anonymous", variable=anonymous_check, command=on_anonymous_check)
anonymous.grid(row=0, rowspan=2, column=1, padx=5, pady=5)


frame_mode = tk.Frame(root)
frame_mode.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

mode_selection = tk.StringVar(value='transfer')
# Radio buttons for selecting file or folder

frame_transfer = tk.Frame(frame_mode)
frame_transfer.grid(row=0, column=0, padx=20, pady=10)

radio_transfer = ttk.Radiobutton(frame_transfer, 
                                # text="Transfer", 
                                variable=mode_selection, 
                                value='transfer', 
                                takefocus=0,
                                command=select_mode
                                )
radio_transfer.grid(row=0, column=0, padx=0, pady=0, sticky='e')

style.configure('TD.TButton', font=('Lucida Sans', 12))
transfer = ttk.Button(frame_transfer, 
                      text="Transfer", 
                    #  borderwidth=0,
                    #  highlightthickness=0,
                    #  background='white',
                    #  bg='ghost white',
                      style="TD.TButton",
                      command=lambda: start_transfer(status_widget)
                    )
transfer.grid(row=0, 
              column=1, 
              pady=0,
              padx=0, 
              sticky='w')
# transfer.configure(font=('Lucida Sans', 12))
# button_design(transfer)
print(f"Transfer button state: {transfer['state']}")

frame_download = tk.Frame(frame_mode)
frame_download.grid(row=0, column=1, padx=20, pady=10)

radio_download = ttk.Radiobutton(frame_download, 
                                # text="Download", 
                                variable=mode_selection, 
                                value='download',
                                takefocus=0,
                                command=select_mode
                                )
radio_download.grid(row=0, column=2, padx=0, pady=0, sticky='w')

download = ttk.Button(frame_download, text="Download", 
                    #  borderwidth=0,
                    #  highlightthickness=0,
                    #  background='white',
                    #  bg='ghost white',
                     style="TD.TButton",
                     command=lambda: start_download(status_widget)
                     )
download.grid(row=0, 
              column=0,  
              pady=0,
              padx=0,
              sticky='e')
# download.configure(font=('Lucida Sans', 12))
# button_design(download)
download.config(state="disabled")
print(f"Download button state: {download['state']}")
# Avoid color change when hovering when button is disabled

# status_widget = tk.Text(root, height=10, width=80)
status_widget = scrolledtext.ScrolledText(root, 
                                          undo=True,
                                          wrap = tk.WORD,
                                          height=17,
                                          width=70
                                          )
status_font = font.Font(family="Consolas", size=11)
status_widget.configure(font=status_font)
status_widget.grid(row=5, column=0, columnspan=2, padx=15, pady=15)
status_widget.bind("<Key>", lambda e: "break")

set_paths()

# Disable focus for all widgets
# disable_focus(root)

# root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()

## not showing connection timeout fix that
## add profiles to save data just like routes - DONE

## fix data still gray even after placeholder is not the same - DONE
##  cannot send several files at the same time

## create tool for layout zipper

##check that range is valid for the root IP (not exceding .255)
##check the input range to be in the format 1-5,10-15,45
## also check that the range is ascending, i.e. 1-5, 10-15, not in the form 15-10,9-1+

##CAmbiar a tabla en vez de label
