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
from datetime import datetime
# import pystray
# from PIL import Image
import xml.etree.ElementTree as ET
from xml.dom import minidom
import sqlite3
import configparser

__version__ = '3.4.9.4'

CONFIG_FILE = "config.ini"

LGV_DATA_FILE = "lgv_address_list.xml"
############################################## Load/Save LGV Data #############################################
def extract_lgv_name(input_name):
    # Regex pattern to capture 'LGV' followed by numbers
    pattern = r"(LGV\d+)"
    match = re.search(pattern, input_name)
    if match:
        return match.group(1)  # Return the matched 'LGVxx' or 'LGVxxx'
    return None

def populate_table_from_xml(path=None):
    if not path:
        # Ask the user to select an XML file
        file_path = filedialog.askopenfilename(title="Select StaticRoutes file", 
                                            initialdir="C:\\TwinCAT\\3.1\\Target",
                                            filetypes=[("XML files", "*.xml")])
    else:
        file_path = path

    if file_path and not os.path.exists(file_path):
        print(f"The file {path} does not exist.")
        return
    
    if file_path:
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
        except ET.ParseError:
            messagebox.showerror("Error", "The selected file is not a valid XML file.")
            return

        # Check for the expected root elements
        remote_connections = root.find('RemoteConnections')
        if remote_connections is None:
            messagebox.showerror("Error", "XML file does not contain the expected 'RemoteConnections' structure.")
            return
        
        open_lgv_table_window_cond()

        data = treeview.get_children()
        # Clear the existing table data
        if data is not None:
            for i in data:
                treeview.delete(i)
            
        # Initialize an empty list to hold the data
        routes_data = []
        seen_lgv_names = set()
        invalid_routes = []
        
        # Iterate through each <Route> element in the XML
        for route in remote_connections.findall('Route'):
            name = route.find('Name')
            address = route.find('Address')
            net_id = route.find('NetId')

            if None in (name, address, net_id):
                messagebox.showwarning("Warning", "One or more routes are missing required fields (Name, Address, NetId).")
                invalid_routes.append("Missing fields (Name, Address, NetId)")
                continue  # Skip this route and move to the next

            name = name.text
            address = address.text
            net_id = net_id.text

            # Extract the LGV name
            lgv_name = extract_lgv_name(name)
            if not lgv_name:
                invalid_routes.append(f"Invalid name format: {name}")
                continue

            # Check for duplicate LGV names
            if lgv_name in seen_lgv_names:
                messagebox.showerror("Duplicate Entry", f"Duplicate LGV name found: {lgv_name}. File cannot be loaded.")
                return None  # Abort loading the file

            # Mark the LGV name as seen
            seen_lgv_names.add(lgv_name)

            type_tc = "TC3" if route.find('Flags') is not None else "TC2"
            
            # Append the tuple to the list
            routes_data.append((lgv_name, address, type_tc))
        
        # Warn the user about invalid routes
        if invalid_routes:
            messagebox.showwarning(
                "Invalid Routes",
                f"The following routes were skipped:\n" + "\n".join(invalid_routes)
            )
        
        # Populate the Treeview with the data
        for item in routes_data:
            treeview.insert("", "end", values=item)
        # messagebox.showinfo("Success", "Data loaded successfully from the XML file.")
        
    save_table_data_to_xml(treeview)

    # Enable menu for Show LGV Table if table is updated
    update_menu_state()


def read_db3_file(db3_file_path, table_name):
    try:
        # Connect to the .db3 file
        conn = sqlite3.connect(db3_file_path)
        cursor = conn.cursor()

        # Check if the table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        if not cursor.fetchone():
            # messagebox.showerror("Error", f"Table '{table_name}' does not exist in the database.")
            messagebox.showerror("Error", f"Wrong database format.")
            conn.close()
            return None

        # Query to get all rows from the specified table
        cursor.execute(f"SELECT * FROM {table_name}")
        
        # Fetch all rows
        rows = cursor.fetchall()

        # Get column names
        column_names = [description[0] for description in cursor.description]

        # Convert the rows into a list of dictionaries
        dict_rows = [dict(zip(column_names, row)) for row in rows]

        # Close the connection
        conn.close()

        return dict_rows
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")
        return None


def populate_table_from_db3():
    db3_path = filedialog.askopenfilename(title="Select config.db3 file", 
                                          initialdir="C:\\Program Files (x86)\\Elettric80",
                                          filetypes=[("DB3 files", "*.db3")])
    if not db3_path:
        return
    
    table_agvs = "tbl_AGVs"
    rows_agvs = read_db3_file(db3_path, table_agvs)
    if rows_agvs is None:
        return
    
    table_param = "tbl_Parameter"
    rows_param = read_db3_file(db3_path, table_param)
    if rows_param is None:
        return
    
    open_lgv_table_window_cond()

    # # print(columns, rows)
    
    # Clear the existing table data
    for i in treeview.get_children():
        treeview.delete(i)
    
    # Default type_tc based on the transfer mode
    default_type_tc = "TC2"  # Assume TC2 unless specified otherwise
    for row_param in rows_param:
        if row_param['dbf_Name'] == "agvlayoutloadmethod" and row_param['dbf_Value'] == "SFTP":
            default_type_tc = "TC3" # If SFTP, set all to TC3

    # Initialize an empty list to hold the data
    routes_data = []
    # Iterate through each <Route> element in the XML
    for route in rows_agvs:
        if route['dbf_Enabled']: 
        # if None in (name, address, net_id):
        #     messagebox.showwarning("Warning", "One or more routes are missing required fields (Name, Address, NetId).")
        #     continue  # Skip this route and move to the next

            name = f"LGV{str(route['dbf_ID']).zfill(2)}"
            address = route['dbf_IP']
            net_id = f"{address}.1.1"
            
            # if route['Dbf_Comm_Library']>20 or 
            if str(route['LayoutCopy_Protocol']).lower()=="sftp":
                type_tc = "TC3" 
            elif str(route['LayoutCopy_Protocol']).lower()=="ftp" or str(route['LayoutCopy_Protocol']).lower()=="netfolder":
                type_tc = "TC2" 
            else:
                type_tc = default_type_tc 
        
            # Append the tuple to the list
            routes_data.append((name, address, type_tc))
    
    # Populate the Treeview with the data
    for item in routes_data:
        treeview.insert("", "end", values=item)

    save_table_data_to_xml(treeview)

    # Enable menu for Show LGV Table if table is updated
    update_menu_state()


# Save data to XML
def save_table_data_to_xml(tree, filename=LGV_DATA_FILE):

    # Check if there is any data in the Treeview
    if not tree.get_children():
        print("Treeview is empty. No data to save.")
        return  # Exit the function if the Treeview is empty
    
    # Create the current data structure from the Treeview
    current_data = []
    for row in tree.get_children():
        lgv_data = tree.item(row)["values"]
        current_data.append({
            "Name": lgv_data[0],
            "IPAddress": lgv_data[1],
            # "AMSNetId": lgv_data[2],
            "Type": lgv_data[2]
        })

    # Sort the current data to ensure consistent ordering
    current_data.sort(key=lambda x: x["Name"])


    # If the file exists, compare it with the current data
    if os.path.exists(filename):
        tree_xml = ET.parse(filename)
        lgv_list = tree_xml.getroot()

        # Extract the existing data from the XML file
        existing_data = []
        for lgv in lgv_list.findall("LGV"):
            existing_data.append({
                "Name": lgv.find("Name").text,
                "IPAddress": lgv.find("IPAddress").text,
                # "AMSNetId": lgv.find("AMSNetId").text,
                "Type": lgv.find("Type").text
            })

        # Sort the existing data to ensure consistent ordering
        existing_data.sort(key=lambda x: x["Name"])

        # Compare existing data with current data
        if existing_data == current_data:
            print("No changes detected. Data not saved.")
            return  # Exit if there are no changes
        
    lgv_list = ET.Element("LGVData")
    for lgv in current_data:
        lgv_element = ET.SubElement(lgv_list, "LGV")
        ET.SubElement(lgv_element, "Name").text = lgv["Name"]
        ET.SubElement(lgv_element, "IPAddress").text = lgv["IPAddress"]
        # ET.SubElement(lgv_element, "AMSNetId").text = lgv["AMSNetId"]
        ET.SubElement(lgv_element, "Type").text = lgv["Type"]
    
    # Convert to a pretty XML string
    xmlstr = minidom.parseString(ET.tostring(lgv_list, 'utf-8')).toprettyxml(indent="    ")

    # Write to a file
    with open(filename, "w", encoding='utf-8') as f:
        f.write(xmlstr)

    print(f"Data successfully saved to {filename}.")
    messagebox.showinfo("Attention", f"LGV data successfully saved to {filename}.")

# Load data from XML
def load_table_data_from_xml(tree=None, filename=LGV_DATA_FILE, return_data=False):
    """Load LGV data from XML. Populate Treeview or return structured data."""
    if not os.path.exists(filename):
        print(f"File '{filename}' not found.")
        return [] if return_data else None

    try:
        tree_xml = ET.parse(filename)
        lgv_list = tree_xml.getroot()

        # Check if there are any <LGV> elements
        if not lgv_list.findall("LGV"):
            print("The XML file has no LGV data.")
            return [] if return_data else None

        # Prepare data for return
        data = []
        for lgv in lgv_list.findall("LGV"):
            lgv_name = lgv.find("Name").text
            ip_address = lgv.find("IPAddress").text
            tc_type = lgv.find("Type").text

            # Collect data for returning
            lgv_entry = {"name": lgv_name, "ip_address": ip_address, "type": tc_type}
            data.append(lgv_entry)

            # Populate a treeview if provided
            if tree is not None:
                tree.insert("", "end", values=(lgv_name, ip_address, tc_type))
        
        return data if return_data else None
    
    except ET.ParseError:
        print(f"Error parsing the file '{filename}.")
        return [] if return_data else None


def delete_lgv_data_file():
    """Delete the LGV data XML file after confirmation."""
    if os.path.exists(LGV_DATA_FILE):
        # Confirm deletion
        confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete '{LGV_DATA_FILE}'?")
        if confirm:
            try:
                os.remove(LGV_DATA_FILE)
                messagebox.showinfo("Success", f"'{LGV_DATA_FILE}' has been deleted.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while deleting the file: {e}")
    # Update the menu state regardless of success or failure
    update_menu_state()

def update_menu_state():
    if os.path.exists(LGV_DATA_FILE):
        options_menu.entryconfig("Show LGV Table", state="normal")  # Enable if file exists
        options_menu.entryconfig("Remove LGV Table", state="normal")
    else:
        options_menu.entryconfig("Show LGV Table", state="disabled")  # Disable if file doesn't exist
        options_menu.entryconfig("Remove LGV Table", state="disabled")

############################################## Open LGV Table Window ####################################
lgv_table_window = None

def open_lgv_table_window_cond():
    global lgv_table_window

    if lgv_table_window is not None and lgv_table_window.winfo_exists():
        lgv_table_window.lift()
        lgv_table_window.focus_force()
    else:
        open_lgv_table_window()

def open_lgv_table_window():
    global lgv_table_window

    lgv_table_window = tk.Toplevel(root)
    lgv_table_window.title("LGV Data ")

    window_width = 300
    window_lenght = 300
    lgv_table_window.geometry(f"{window_width}x{window_lenght}")
    lgv_table_window.minsize(window_width, window_lenght)

    global treeview

    # # With DEL key
    # def delete_selected_record(event):
    #     selected_items = treeview.selection()
    #     for item in selected_items:
    #         if item:
    #             treeview.delete(item)

    # Dictionary to maintain custom headings
    headings = {
        'Name'      : 'Name',
        'IPAddress' : 'IPAddress',
        'Type'      : 'Type'
    }

    def setup_treeview():
        for col in treeview['columns']:
            treeview.heading(col, text=headings[col], command=lambda _col=col: treeview_sort_column(treeview, _col, False), anchor='w')

    def treeview_sort_column(tv, col, reverse):
        # Retrieve all data from the treeview
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        
        # Sort the data
        l.sort(reverse=reverse, key=lambda t: natural_keys(t[0]))

        # Rearrange items in sorted positions
        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)

        # Change the heading to show the sort direction
        for column in tv['columns']:
            heading_text = headings[column] + (' ↓' if reverse and column == col else ' ↑' if not reverse and column == col else '')
            tv.heading(column, text=heading_text, command=lambda _col=column: treeview_sort_column(tv, _col, not reverse))

    def natural_keys(text):
        """
        Alphanumeric (natural) sort to handle numbers within strings correctly
        """
        return [int(c) if c.isdigit() else c for c in re.split(r'(\d+)', text)]

    # Create a frame for the table (Treeview)
    table_frame = ttk.Frame(lgv_table_window)
    table_frame.grid(row=0, column=0, padx=10, pady=20, sticky='nsew')

    treeview_style = ttk.Style()
    treeview_style.configure("Treeview", rowheight=23)  # Increase row height for more space between items
    treeview_style.configure("Treeview", font=("Segoe UI", 10))  # Adjust font size if necessary
    treeview_style.configure("Treeview", padding=(5, 5))  # Add padding to rows (optional)

    # Create the Treeview (table)
    columns = ("Name", "IPAddress", "Type")
    treeview = ttk.Treeview(table_frame, columns=columns, show="headings")

    # Define the column widths
    treeview.column("Name", width=80, anchor='w')
    treeview.column("IPAddress", width=120, anchor='w')
    treeview.column("Type", width=50, anchor='w')

    setup_treeview()

    # Add the treeview to the table frame
    treeview.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # treeview.bind("<<TreeviewSelect>>", on_treeview_select)
    # treeview.bind('<Delete>', delete_selected_record)

    # bind_treeview_focus_action(treeview, focus_shortcuts=['<Control-t>', '<Control-T>'])

    # Create a vertical scrollbar for the table
    scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=treeview.yview)
    treeview.configure(yscroll=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    load_table_data_from_xml(treeview)


#######################################################################################################################
############################################### Transfer to remote server #############################################
#######################################################################################################################

def start_transfer():
    # Reset labels at the start of a new transfer
    summary_label.config(text="Status result", fg="black")
    timestamp_label.config(text="Last operation: 00:00:00")

    local_path_string = file_path.get()
    base_ip = ip_entry.get()
    range_input = range_entry.get()
    remote_dir = remote_dir_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    
    if transfer_type_sel.get() == 'SFTP':
        port = 20022
    elif transfer_type_sel.get() == 'FTP':
        port = FTP_PORT


    # Parse local paths
    local_paths = [path.strip() for path in local_path_string.split(',')]
    if not local_paths:
        messagebox.showerror("Input Error", "Please choose a file or folder to transfer.")
        return

    if not validate_range():
        messagebox.showerror("Input Error", "Please enter the IP range.")
        return
    
    # Check LGV data availability
    lgv_data_exists = os.path.exists(LGV_DATA_FILE)

    # Validate IP source
    if lgv_data_exists:
        ip_list = validate_and_link_lgv()
        if not ip_list:
            messagebox.showerror("Input Error", "Invalid LGV range or no matching data in the LGV table.")
            return
    else:
        base_ip = ip_entry.get()
        if not validate_base_ip():
            messagebox.showerror("Input Error", "Please enter the base IP.")
            return
        if not validate_range():
            messagebox.showerror("Input Error", "Please enter a valid range.")
            return
        ip_list = parse_ip_ranges(base_ip, range_input)
        if not ip_list:
            messagebox.showerror("Input Error", "Please provide a valid IP range.")
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
    
    print (f"Selected port is {port}")
    print(f"Login is {username}")
    print(f"Password is {password}")
    print(local_paths)

    # Clear and populate the status table
    status_table.delete(*status_table.get_children())
    for item in ip_list:
        lgv_name = f"LGV{int(item["number"]):02}" if lgv_data_exists else ""
        ip_address = item["ip_address"] if lgv_data_exists else item
        status_table.insert("", "end", values=(lgv_name, ip_address, "Queued", ""))

    result_queue = queue.Queue()
    threads = []

    for item in ip_list:
        lgv_name = f"LGV{int(item["number"]):02}" if lgv_data_exists else ""
        host = item["ip_address"] if lgv_data_exists else item
        file_count = len(local_paths)

        # Update the table with a summary of the transfer
        description = (
            f"Transferring {file_count} files..." 
            if file_count > 1 
            else f"Transferring {os.path.basename(local_paths[0])}..."
        )
        update_status_table(host, lgv_name, "In Progress", description)

        for local_path in local_paths:
            if transfer_type_sel.get() == 'SFTP': 
                t = threading.Thread(target=sftp_transfer, args=(host, port, username, password, local_path, remote_dir, result_queue, lgv_name))
            elif transfer_type_sel.get() == 'FTP':
                t = threading.Thread(target=ftp_transfer, args=(host, username, password, local_path, remote_dir, result_queue, lgv_name))
            
            threads.append(t)
            t.start()

    # Start a separate thread to monitor the worker threads
    threading.Thread(target=monitor_threads, args=(threads, result_queue)).start()


############################################### SFTP Transfer ###############################################

def sftp_transfer(host, port, username, password, local_path, remote_path, result_queue, lgv_name=""):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    local_file_name = os.path.basename(local_path)
    success = True  # Track overall success for the entire transfer process

    try:   
        ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10, auth_timeout=10)
        sftp = ssh.open_sftp()

        if os.path.isfile(local_path):
            try:
                sftp.put(local_path, os.path.join(remote_path, local_file_name))
            except Exception as e:
                success = False
                
        else:
            for root_dir, dirs, files in os.walk(local_path):
                for dir_name in dirs:
                    local_dir = os.path.join(root_dir, dir_name)
                    remote_dir = os.path.join(remote_path, os.path.relpath(local_dir, local_path)).replace("\\", "/")
                    try:
                        # Check if the remote directory exists
                        sftp.stat(remote_dir)  # This will throw an exception if the directory does not exist
                    except IOError:  # Directory does not exist, so we create it
                        try:
                            sftp.mkdir(remote_dir)
                            description = f"Created directory {remote_dir} on {host}"
                        except Exception as e:
                            description = f"Failed to create directory {remote_dir} on {host}: {e}"
                            continue  # Continue with other directories/files even if one fails
                        finally:
                            update_status_table(host, lgv_name, "In Progress", description)

                for file_name in files:
                    local_file = os.path.join(root_dir, file_name)
                    remote_file = os.path.join(remote_path, os.path.relpath(local_file, local_path))
                    try:
                        sftp.put(local_file, remote_file)
                        description = f"Successfully transferred {local_file}"
                    except Exception as e:
                        description = f"Failed to transfer {local_file}"
                        success = False
                    finally:
                        update_status_table(host, lgv_name, "In Progress", description)

        sftp.close()
        ssh.close()

        # After completing all transfers, update the table
        description = "All files transferred successfully!" if success else "Some transfers failed."
        status = "Completed" if success else "Failed"
    except Exception as e:
        description = f"Connection failed: {e}"
        status = "Failed"
        success = False
    finally:
        update_status_table(host, lgv_name, status, description)
        result_queue.put((host, "Success" if success else "Failed"))


################################################ FTP transfer ###############################################################

def ftp_transfer(host, username, password, local_path, remote_path, result_queue, lgv_name=""):
    success = True  # Track overall success for the entire transfer process
    local_file_name = os.path.basename(local_path)
    try:        
        # Connect to the FTP server
        ftp = FTP(host, timeout=15)
        ftp.login(user=username, passwd=password)

        if os.path.isfile(local_path):
            try:
                with open(local_path, 'rb') as file:
                    ftp.storbinary(f"STOR {os.path.join(remote_path, local_file_name).replace('\\', '/')}", file)
            except Exception as e:
                success = False

        else:
            for root_dir, dirs, files in os.walk(local_path):
                for dir_name in dirs:
                    local_dir = os.path.join(root_dir, dir_name)
                    remote_dir = os.path.join(remote_path, os.path.relpath(local_dir, local_path)).replace("\\", "/")
                    try:
                        # Change to the directory to check if it exists
                        ftp.cwd(remote_dir)
                    except Exception as e:
                        # If the directory does not exist, create it
                        try:
                            ftp.mkd(remote_dir)
                            description = f"Created directory {remote_dir} on {host}"
                        except Exception as e:
                            description = f"Failed to create directory {remote_dir} on {host}: {e}"
                            continue  # Continue with other directories/files even if one fails
                        finally:
                            update_status_table(host, lgv_name, "In Progress", description)

                for file_name in files:
                    local_file = os.path.join(root_dir, file_name)
                    remote_file = os.path.join(remote_path, os.path.relpath(local_file, local_path)).replace("\\", "/")
                    try:
                        with open(local_file, 'rb') as file:
                            ftp.storbinary(f"STOR {remote_file}", file)
                        description = f"Successfully transferred {local_file}"
                    except Exception as e:
                        description = f"Failed to transfer {local_file}"
                        success = False
                    finally:
                        update_status_table(host, lgv_name, "In Progress", description)
        
        # Close the FTP connection
        ftp.quit()

        # After completing all transfers, update the table
        description = "All files transferred successfully!" if success else "Some transfers failed."
        status = "Completed" if success else "Failed"
    except Exception as e:
        description = f"Connection failed: {e}"
        status = "Failed"
        success = False
    finally:
        update_status_table(host, lgv_name, status, description)
        result_queue.put((host, "Success" if success else "Failed"))

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

#######################################################################################################################
############################################# Download from remote server #############################################
#######################################################################################################################

def start_download():
    # Reset labels at the start of a new download
    summary_label.config(text="Status result", fg="black")
    timestamp_label.config(text="Last operation: 00:00:00")

    range_input = range_entry.get()
    remote_dir = remote_dir_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    if transfer_type_sel.get() == 'SFTP':
        port = 20022
    elif transfer_type_sel.get() == 'FTP':
        port = FTP_PORT

    # Check LGV data availability
    lgv_data_exists = os.path.exists(LGV_DATA_FILE)

    # Validate IP source
    if lgv_data_exists:
        ip_list = validate_and_link_lgv()
        if not ip_list:
            messagebox.showerror("Input Error", "Invalid LGV range or no matching data in the LGV table.")
            return
    else:
        base_ip = ip_entry.get()
        if not validate_base_ip():
            messagebox.showerror("Input Error", "Please enter the base IP.")
            return
        if not validate_range():
            messagebox.showerror("Input Error", "Please enter a valid range.")
            return
        ip_list = parse_ip_ranges(base_ip, range_input)
        if not ip_list:
            messagebox.showerror("Input Error", "Please provide a valid IP range.")
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

    local_root_path = filedialog.askdirectory(title="Choose a folder to save downloads")
    if not local_root_path:
        messagebox.showerror("Input Error", "Please choose a folder where to download.")
        return
    
    download_folder = os.path.join(local_root_path, "Download")
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)
    
    print (f"Selected port is {port}")
    print(f"Login is {username}")
    print(f"Password is {password}")
    print(download_folder)
    print(local_root_path)


    # Clear and populate the status table
    status_table.delete(*status_table.get_children())
    for item in ip_list:
        lgv_name = f"LGV{int(item['number']):02}" if lgv_data_exists else ""
        ip_address = item["ip_address"] if lgv_data_exists else item
        status_table.insert("", "end", values=(lgv_name, ip_address, "Queued", "")) 


    result_queue = queue.Queue()
    threads = []

    for item in ip_list:
        lgv_name = f"LGV{int(item['number']):02}" if lgv_data_exists else ""
        host = item["ip_address"] if lgv_data_exists else item

        folder_name = lgv_name if lgv_data_exists else host
        local_path = os.path.join(download_folder, folder_name)

        # Update the table with a summary of the download
        description = f"Preparing to download {remote_dir}..."
        update_status_table(host, lgv_name, "In Progress", description)

        if transfer_type_sel.get() == 'SFTP': 
            t = threading.Thread(target=sftp_download, args=(host, port, username, password, remote_dir, local_path, result_queue, lgv_name))
        if transfer_type_sel.get() == 'FTP':
            t = threading.Thread(target=ftp_download, args=(host, username, password, remote_dir, local_path, result_queue, lgv_name))

        threads.append(t)
        t.start()
    
    # Start a separate thread to monitor the worker threads
    threading.Thread(target=monitor_threads, args=(threads, result_queue)).start()


############################################### SFTP Download ###############################################

def sftp_download(host, port, username, password, remote_path, local_path, result_queue, lgv_name=""):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    success = True  # Track overall success for the entire download process
    description = ""
    status = "In Progress"  # Default status

    try:
        # Update table with "In Progress" status
        update_status_table(host, lgv_name, status, f"Downloading {os.path.basename(remote_path)}")

        ssh.connect(hostname=host, port=port, username=username, password=password, timeout=10, auth_timeout=10)
        sftp = ssh.open_sftp()
        
        def download_file(sftp, remote_file_path, local_file_path):
            nonlocal success, description
            try:
                sftp.get(remote_file_path, local_file_path)
                description = f"Successfully downloaded {remote_file_path}"
            except Exception as e:
                description = f"Failed to download {remote_file_path}: {e}"
                success = False
            finally:
                update_status_table(host, lgv_name, status, description)

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

        # Final status if all files are downloaded successfully
        description = "Download completed successfully!" if success else "Download completed with errors."
        status = "Completed" if success else "Failed"
        
    except Exception as e:
        description = f"Failed to initiate download: {e}"
        status="Failed"
        success = False
    finally:
        update_status_table(host, lgv_name, status, description)
        result_queue.put((host, "Success" if success else "Failed"))

################################################ FTP download ###############################################################

def ftp_download(host, username, password, remote_path, local_path, result_queue, lgv_name=""):
    success = True  # Track overall success for the entire download process
    description = ""
    status = "In Progress"

    try:
        # Update table with "In Progress" status
        update_status_table(host, lgv_name, status, f"Downloading {os.path.basename(remote_path)}")
        
        # Connect to the FTP server
        ftp = FTP(host)
        ftp.login(user=username, passwd=password)
        
        try:
            ftp.cwd(remote_path)
        except Exception as e:
            description = f"Error navigating to {remote_path}: {e}"
            ftp.quit()
            success = False
            return
        finally:
            update_status_table(host, lgv_name, status, description)

        def download_file(ftp, remote_file_path, local_file_path):
            nonlocal success, description
            try:
                with open(local_file_path, 'wb') as local_file:
                    ftp.retrbinary(f'RETR {remote_file_path}', local_file.write)
                description = f"Successfully downloaded {remote_file_path}"
            except Exception as e:
                description = f"Failed to download {remote_file_path}: {e}"
                success = False
            finally:
                update_status_table(host, lgv_name, "In Progress", description)

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

        description = "Download completed successfully!" if success else "Download completed with errors."
        status = "Completed" if success else "Failed"

    except Exception as e:
        description = f"Failed to initiate download: {e}"
        status = "Failed"
        success = False
    finally:
        update_status_table(host, lgv_name, status, description)
        result_queue.put((host, "Success" if success else "Failed"))


############################################ Monitor threads ##################################################
def monitor_threads_deprecated(threads, result_queue, status_widget):
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
    
    current_time = datetime.now()
    formatted_time = current_time.strftime("%H:%M:%S")
    print(f"At {formatted_time}")
    status_widget.insert(tk.END, f"\nOperation performed at {formatted_time}")

    # Ensure the status widget updates properly
    status_widget.yview(tk.END)


def monitor_threads(threads, result_queue):
    # Wait for all threads to complete
    for t in threads:
        t.join()

    # Check for any failed results grouped by host
    results_by_host = {}
    while not result_queue.empty():
        host, result = result_queue.get()
        if host not in results_by_host:
            results_by_host[host] = {"total": 0, "failed": 0}
        results_by_host[host]["total"] += 1
        if result == "Failed":
            results_by_host[host]["failed"] += 1

    # Calculate summary
    failed_hosts_count = 0
    total_hosts = len(results_by_host)

    for host, counts in results_by_host.items():
        if counts["failed"] > 0:
            failed_hosts_count += 1


    # Update the summary label
    if failed_hosts_count > 0:
        summary_label.config(
            text=f"Transfers completed with issues: {failed_hosts_count} / {total_hosts} hosts failed.",
            foreground="red"
        )
    else:
        summary_label.config(
            text="All transfers completed successfully!",
            foreground="green"
        )

    # Update the timestamp label
    current_time = datetime.now()
    formatted_time = current_time.strftime("%H:%M:%S")
    timestamp_label.config(text=f"Last operation: {formatted_time}")


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

####################################################### Get LGV Numbers ########################################################

def parse_lgv_range(range_str):
    """Parse LGV range input into a list of LGV numbers."""
    lgv_numbers = set()
    parts = range_str.split(",")
    for part in parts:
        if "-" in part:
            start, end = map(int, part.split("-"))
            lgv_numbers.update(range(start, end + 1))
        else:
            lgv_numbers.add(int(part))
    return lgv_numbers


def validate_and_link_lgv():
    """
    Validate the LGV range and link IP addresses from the LGV data table.
    """
    try:
        # Check if the LGV range entry is empty
        if range_entry.get().strip() == '':
            print("LGV range is empty!")
            # log_message("LGV range is empty!")
            return None

        # Parse the LGV range input into a set of numbers
        lgv_numbers = parse_lgv_range(range_entry.get())
        found_entries = []

        # Load data from the LGV XML table
        lgv_data = load_table_data_from_xml(return_data=True)
        available_lgvs = {int(lgv["name"].replace("LGV", "")): lgv for lgv in lgv_data}  # Extract LGV numbers

        # Match entered LGVs with the XML data
        for lgv in lgv_numbers:
            if lgv in available_lgvs:
                found_entries.append({
                    "number": lgv,
                    "ip_address": available_lgvs[lgv]["ip_address"],  # Using ip_address
                    "type": available_lgvs[lgv]["type"],  # Keep type for future use
                })
            else:
                print(f"LGV {lgv} not found in the table.")

        # Check if all LGVs in the range were found
        if len(found_entries) == len(lgv_numbers) and found_entries:
            print("All LGVs found!")
            return found_entries
        else:
            overflow = len(lgv_numbers) - len(found_entries)
            if overflow > 0:
                raise ValueError(f"Range contains {overflow} extra elements not in the table.")
            else:
                raise ValueError("Some LGVs were not found; check the range.")

    except ValueError as e:
        print(f"Invalid input. Error: {e}")
        # log_message(f"Invalid input. Error: {e}")
        return None


############################################################ Choose file to transfer ################################################
def choose_file_or_folder():
    file_path.set("")  # Clear previous selection
    if selection.get() == 'file':
        file_or_folder = filedialog.askopenfilenames()  # Select files
        if file_or_folder:
            file_path.set(", ".join(file_or_folder))
            check_source_path_for_keywords(file_or_folder)
    elif selection.get() == 'folder':
        file_or_folder = filedialog.askdirectory()  # Select a folder
        if file_or_folder:
            file_path.set(file_or_folder)
            check_source_path_for_keywords(file_or_folder)


def browse_local_path():
    """Open a dialog to ask the user if they want to browse files or folders."""
    # file_path.set("")  # Clear previous selection

    response = messagebox.askyesnocancel(
        "Browse Files or Folder",
        "'Yes' to select Files\n'No' to select a Folder",
    )

    if response is True:  # User clicked 'Yes' for Files
        selected_files = filedialog.askopenfilenames(
            title="Select files"
        )  # Select files
        if selected_files:
            file_path.set(", ".join(selected_files))
            check_source_path_for_keywords(selected_files)

    elif response is False:  # User clicked 'No' for Folders
        selected_folder = filedialog.askdirectory(
            title="Select a folder"
        )  # Select a folder
        if selected_folder:
            file_path.set(selected_folder)
            check_source_path_for_keywords(selected_folder)

    else:  # User clicked 'Cancel'
        print("Action canceled")

############################################################ Check source path for keywords ################################################
def check_source_path_for_keywords(file_or_folder):
    # Convert the selected path to a string
    source_path = str(file_or_folder)
    
    # Check if the source path contains specific keywords
    if "boot" in source_path.lower() or "twincat" in source_path.lower():
        remote_dir_entry.set(default_paths[1])
    elif "layout" in source_path.lower() or "segments" in source_path.lower():
        remote_dir_entry.set(default_paths[2])
    else:
        remote_dir_entry.set(default_paths[0])  # Or set to a default path if needed

######################################################################################################################################
################################################## Placeholder #######################################################################
######################################################################################################################################

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

def combined_combobox_selected_profile(event):
    style.configure('RootIP.TEntry', foreground=good_input_fg)
    style.configure('Range.TEntry', foreground=good_input_fg) 
    on_combobox_change(event)
    # validate_entry(ip_entry, 'RootIP.TEntry', validate_base_ip)
    # validate_entry(range_entry, 'Range.TEntry', validate_range)
    # set_paths()
    clear_entries(event)
    update_rename_button_state(event)
    subprofiles_combobox.set("")

def combined_combobox_selected_subprofile(event):
    style.configure('RootIP.TEntry', foreground=good_input_fg)
    style.configure('Range.TEntry', foreground=good_input_fg) 
    on_combobox_change(event)
    load_data_from_selection(event)
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
    
    password_entry.delete(0, tk.END)
    password_entry.insert(0, "anonymous@example.com")

def set_default_login():
    username_entry.delete(0, tk.END)
    username_entry.insert(0, "Administrator")

    password_entry.delete(0, tk.END)
    password_entry.insert(0, "1")


def clear_entries(event=None):
    ip_entry.delete(0, tk.END)
    range_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk. END)
    remote_dir_entry.delete(0, tk.END)
    file_path_entry.delete(0, tk.END)


###################################################### Custom paths ##########################################################
# Global variable to store default paths
default_paths = []
custom_paths = []

def set_paths():
    global default_paths, custom_paths
    default_paths_sftp = [r"\Config", r"\TwinCAT\Boot", r"\Layout"]
    default_paths_ftp = ["/Hard Disk/Backup", "/Hard Disk/TwinCAT/Boot", "/Hard Disk/Backup/export_to_agv"]
    default_paths_net = [r"\Backup", r"\TwinCAT\Boot", r"\Backup\export_to_agv"] #examples for now, get real ones later
    transfer_type = transfer_type_sel.get()

    # Load custom paths based on the transfer type
    custom_paths = load_custom_paths(transfer_type)

    if transfer_type == 'SFTP':
        default_paths = default_paths_sftp

    elif transfer_type == 'FTP':
        default_paths = default_paths_ftp
    
    elif transfer_type == 'NET':
        default_paths = default_paths_net

    # Update the Combobox values
    remote_dir_entry['values'] = default_paths + custom_paths
    
    # Optionally, reset the displayed value to the first default path
    if default_paths and not remote_dir_entry.get():
        remote_dir_entry.set(default_paths[0])

    print(f"Default paths set to: {default_paths}")
    

def set_path_on_selection(*args):
    transfer_type = transfer_type_sel.get()
    remote_dir_entry.delete(0, tk.END)
    if transfer_type == 'SFTP' or transfer_type == 'NET':
        set_default_login()
    elif transfer_type == 'FTP':
        set_anonymous_login()
    set_paths()
    print(f"Password: {password_entry.get()}")


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

# Helper function to load a JSON file 
def load_json_file(file_path):
    try:
        with open(file_path, "r") as file:
            try:
                return json.load(file)
            except json.JSONDecodeError:
                # Handle case when file is empty or not a valid JSON
                return {}
    except FileNotFoundError:
        return {}

# Load custom paths from a file
def load_custom_paths(transfer_type):
    all_paths = load_json_file("custom_paths.json")
    return all_paths.get(transfer_type, [])

# Save custom paths to a file
def save_custom_paths(paths, transfer_type):
    all_paths = load_json_file("custom_paths.json")

    all_paths[transfer_type] = paths

    with open("custom_paths.json", "w") as file:
        json.dump(all_paths, file, indent=4)

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

################################################################################################################################
####################################################### Profiles ###############################################################
################################################################################################################################

default_profile = {
    "profile_name": "CCXXXX_PlantName_Example",
    "sub_profiles": [
        {
            "sub_name"      : "Default_Type1_TC2",
            "base_ip"       : "192.168.80.10", 
            "ip_range"      : "1-15",
            "username"      : "Administrator",
            "password"      : "*",
            "local_dir"     : "C:/Backup",
            "remote_dir"    : "/Hard Disk/Backup",
            "transfer_type" : "FTP"
        },
        {
            "sub_name"      : "Default_Type2_TC3_config",
            "base_ip"       : "192.168.80.10", 
            "ip_range"      : "21-29",
            "username"      : "Administrator",
            "password"      : "***********",
            "local_dir"     : "C:/Backup",
            "remote_dir"    : "\\Config",
            "transfer_type" : "SFTP"
        },
        {
            "sub_name"      : "Default_Type2_TC3_boot",
            "base_ip"       : "192.168.80.10", 
            "ip_range"      : "21-29",
            "username"      : "Administrator",
            "password"      : "***********",
            "local_dir"     : "C:/Boot",
            "remote_dir"    : "\\TwinCAT\\Boot",
            "transfer_type" : "SFTP"
        }
    ]
}

def set_profile(subprofile):
    """Set the entries based on the selected sub-profile."""

    # Handle IP Entry
    ip_entry.delete(0, tk.END)
    if "e.g." in subprofile.get("base_ip", ""):
        create_placeholder(ip_entry, "e.g., 7.204.194.10", "RootIP.TEntry", "Placeholder.TEntry")
    else:
        ip_entry.insert(0, subprofile.get("base_ip", ""))
        ip_entry.config(style="RootIP.TEntry")

    # Handle Range Entry
    range_entry.delete(0, tk.END)
    if "e.g." in subprofile.get("ip_range", ""):
        create_placeholder(range_entry, "e.g., 1-9,27,29,31-40", "Range.TEntry", "Placeholder.TEntry")
    else:
        range_entry.insert(0, subprofile.get("ip_range", ""))
        range_entry.config(style="Range.TEntry")

    file_path_entry.delete(0, tk.END)
    file_path_entry.insert(0, subprofile["local_dir"])

    remote_dir_entry.delete(0, tk.END)
    remote_dir_entry.insert(0, subprofile["remote_dir"])

    username_entry.delete(0, tk.END)
    username_entry.insert(0, subprofile["username"])

    password_entry.delete(0, tk.END)
    password_entry.insert(0, subprofile["password"])

    transfer_type_sel.set(subprofile["transfer_type"])

def load_custom_profiles():
    try:
        with open("custom_profiles.json", "r") as file:
            data = json.load(file)

            # Detect and handle the new structure
            if isinstance(data, list) and all("profile_name" in profile for profile in data):
                return data

            # Detect and convert the old structure
            elif isinstance(data, list) and all("name" in profile for profile in data):
                print("Old structure detected. Converting to new structure...")

                # Group old profiles by base name
                grouped_profiles = {}
                for old_profile in data:
                    # Extract the base profile name (everything before the first "_")
                    full_name = old_profile.pop("name")
                    base_name = "_".join(full_name.split("_")[:2])  # E.g., "CC1527_GP_Portland"

                    # Create the sub-profile structure
                    sub_profile = {
                        "sub_name": full_name,  # Use the old profile name as sub_name
                        **old_profile,  # Include all other keys
                        "local_dir": old_profile.get("local_dir", "C:/default_path/")  # Add default local_dir
                    }

                    # Add the sub-profile to the grouped profile
                    if base_name not in grouped_profiles:
                        grouped_profiles[base_name] = {"profile_name": base_name, "sub_profiles": []}

                    # Avoid duplicates
                    if sub_profile not in grouped_profiles[base_name]["sub_profiles"]:
                        grouped_profiles[base_name]["sub_profiles"].append(sub_profile)

                # Convert grouped profiles to a list
                converted_data = list(grouped_profiles.values())

                # Save the converted data back to the file
                with open("custom_profiles.json", "w") as outfile:
                    json.dump(converted_data, outfile, indent=4)

                return converted_data

            else:
                raise ValueError("Unexpected JSON structure")

    except (FileNotFoundError, json.JSONDecodeError):
        # Return an empty list if the file doesn't exist or is invalid
        return []


def save_custom_profiles(profile):
    with open("custom_profiles.json", "w") as file:
        json.dump(profile, file, indent=4)


def save_custom_profile():
    """Save a custom profile and its sub-profile."""
    profile_name = profiles_combobox.get().strip()
    subprofile_name = subprofiles_combobox.get().strip()

    base_ip = ip_entry.get().strip()
    range_input = range_entry.get().strip()
    local_dir = file_path_entry.get() # Be careful with this as it might have spaces at the end but also in the middle of the path
    remote_dir = remote_dir_entry.get() # Same as previous
    username = username_entry.get().strip()
    password = password_entry.get() # what if password has a space
    transfer_mode = transfer_type_sel.get()

    if not profile_name or profile_name.lower() == "select a profile" or profile_name.lower() == str(default_profile["profile_name"]).lower():
        messagebox.showerror("Error", "Please enter a valid profile name")
        return
    
    if not subprofile_name or subprofile_name.lower() == "select a subprofile":
        messagebox.showerror("Error", "Please enter a valid subprofile name.")
        return
    
    if not validate_base_ip():
        messagebox.showerror("Input Error", "Please enter valid base IP.")
        return
    
    if not validate_range():
        messagebox.showerror("Input Error", "Please enter the IP range.")
        return
    
    if not local_dir:
        messagebox.showerror("Input Error", "Please enter a local directory.")
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
    
    # if not transfer_mode:
    #     messagebox.showerror("Input Error", "Please enter the transfer type.")
    #     return
    
    subprofile = {
        "sub_name":         subprofile_name,
        "base_ip":          base_ip,
        "ip_range":         range_input,
        "local_dir":        local_dir,
        "remote_dir":       remote_dir,
        "username":         username,
        "password":         password,
        "transfer_type":    transfer_mode
    }

    custom_profiles = load_custom_profiles()

    # profile_names = [profile['name'] for profile in custom_profiles]

    # Check for duplicate profile names and update if found
    for profile in custom_profiles:
        if profile['profile_name'] == profile_name:
            # Check if the sub-profile exists
            for existing_subprofile in profile.get("sub_profiles", []):
                if existing_subprofile["sub_name"] == subprofile_name:
                    # Update the existing sub-profile
                    existing_subprofile.update(subprofile)
                    messagebox.showinfo("Success", f"Sub-profile '{subprofile_name}' updated successfully.")
                    break
            else:
                # Add a new sub-profile to the profile
                profile.setdefault("sub_profiles", []).append(subprofile)
                messagebox.showinfo("Success", f"New sub-profile '{subprofile_name}' added to profile '{profile_name}'.")
            break 
    else:
        # Add a new profile with the sub-profile
        custom_profiles.append({
            "profile_name": profile_name,
            "sub_profiles": [subprofile]
        })
        messagebox.showinfo("Success", f"New profile '{profile_name}' created with sub-profile '{subprofile_name}'.")
    
    save_custom_profiles(custom_profiles)

    # # Update combobox values
    # profile_names = [profile["profile_name"] for profile in custom_profiles]
    # profiles_combobox['values'] = tuple(profile_names) + ("Default",)

    # # Update sub-profiles for the current profile
    # if profile_name == profiles_combobox.get():
    #     subprofile_names = [sub["sub_name"] for sub in custom_profiles[-1]["sub_profiles"]]
    #     subprofiles_combobox['values'] = tuple(subprofile_names)


def load_data_from_selection(event=None):
    """Load the selected profile and sub-profile."""
    selected_profile_name = profiles_combobox.get().strip()
    selected_subprofile_name = subprofiles_combobox.get().strip()

    profiles = load_custom_profiles() + [default_profile]

    # Define the fallback structure for placeholders
    fallback_data = {
        "base_ip": "e.g., 1-9,27,29,31-40",
        "ip_range": "e.g., 1-9,27,29,31-40",
        "username": "Administrator",
        "password": "",
        "local_dir": "",
        "remote_dir": "",
        "transfer_type": "SFTP"
    }
    
    # Find the selected profile
    for profile in profiles:
        if profile["profile_name"] == selected_profile_name:
            # If a sub-profile is selected, set its data
            if selected_subprofile_name:
                for subprofile in profile.get("sub_profiles", []):
                    if subprofile["sub_name"] == selected_subprofile_name:
                        set_profile(subprofile)
                        print(f"Password: {subprofile["password"]}")
                        return

            # If no sub-profile is selected, apply fallback data
            set_profile(fallback_data)
            return

    # If no matching profile is found, apply fallback data
    set_profile(fallback_data)


def load_subprofile_names(event=None):
    """Load sub-profiles into the subprofiles_combobox based on the selected profile."""
    selected_profile_name = profiles_combobox.get().strip()

    # Combine the default profile with custom profiles
    profiles = [default_profile] + load_custom_profiles()

    # Find the selected profile
    for profile in profiles:
        if profile["profile_name"] == selected_profile_name:
            # Populate subprofiles_combobox with sorted subprofile names
            subprofile_names = sorted(
                [sub["sub_name"] for sub in profile.get("sub_profiles", [])],
                key=str.lower
            )
            subprofiles_combobox['values'] = tuple(subprofile_names)
            return

    # If no matching profile is found, clear the subprofiles_combobox
    subprofiles_combobox['values'] = []
    # subprofiles_combobox.set("")

def load_profile_names(event=None):
    """Load profiles into the profiles_combobox."""
    custom_profiles = load_custom_profiles()

    # Populate the profiles_combobox with sorted profile names
    profile_names = sorted(
        [profile["profile_name"] for profile in custom_profiles],
        key=str.lower
    )
    # Combine custom profiles with the default one
    profiles_combobox['values'] = tuple(profile_names) + (default_profile["profile_name"],)
    # subprofiles_combobox.set("")

def delete_profile_or_subprofile():
    """Delete Sub-Profile:
        If a sub-profile is selected in the subprofiles_combobox, delete that sub-profile from its parent profile.
        Delete Profile:
        If no sub-profile is selected (or the sub-profile field is empty), delete the entire profile."""
    
    profile_name = profiles_combobox.get().strip()
    subprofile_name = subprofiles_combobox.get().strip()

    if not profile_name or profile_name.lower() == str(default_profile["profile_name"]).lower():
        messagebox.showerror("Error", "Cannot delete the default profile.")
        return

    custom_profiles = load_custom_profiles()

    for profile in custom_profiles:
        if profile["profile_name"] == profile_name:
            if subprofile_name:
                # Delete the sub-profile
                subprofiles = profile.get("sub_profiles", [])
                for subprofile in subprofiles:
                    if subprofile["sub_name"] == subprofile_name:
                        confirm = messagebox.askyesno(
                        "Confirmation", 
                        f"Are you sure you want to delete sub-profile '{subprofile_name}'?"
                        )
                        if confirm:
                            subprofiles.remove(subprofile)
                            subprofiles_combobox.set("")
                            messagebox.showinfo("Success", f"Sub-profile '{subprofile_name}' deleted successfully.")
                        break
                else:
                    messagebox.showerror("Error", f"Sub-profile '{subprofile_name}' not found.")
                    return
                
                # Update subprofiles_combobox after deletion
                subprofile_names = [sub["sub_name"] for sub in subprofiles]
                subprofiles_combobox['values'] = tuple(subprofile_names)

                # If no sub-profiles are left, ask if the user wants to delete the entire profile
                if not subprofiles:
                    confirm = messagebox.askyesno(
                        "Confirmation", 
                        f"Profile '{profile_name}' has no sub-profiles left. Do you want to delete it?"
                    )
                    if confirm:
                        custom_profiles.remove(profile)
                        messagebox.showinfo("Success", f"Profile '{profile_name}' deleted successfully.")
                        profiles_combobox.set("") # Clear profile selection
                break
            else:
                # Delete the profile
                confirm = messagebox.askyesno(
                    "Confirmation", 
                    f"Are you sure you want to delete the profile '{profile_name}' and all its sub-profiles?"
                )
                if confirm:
                    custom_profiles.remove(profile)
                    messagebox.showinfo("Success", f"Profile '{profile_name}' deleted successfully.")
                    profiles_combobox.set("") # Clear profile selection
            break
    else:
        messagebox.showerror("Error", f"Profile '{profile_name}' not found.")
        return

    # Save updated profiles to file
    save_custom_profiles(custom_profiles)


# Filter profiles on Tab key
def filter_profiles(event):
    """Filter profiles in the profiles_combobox based on user input."""
    typed_text = profiles_combobox.get().strip()

    custom_profiles = load_custom_profiles() + [default_profile]

    # Get matching profile names and sort them
    profile_names = sorted(
        [profile["profile_name"] for profile in custom_profiles],
        key=str.lower
    )
    filtered_profiles = [name for name in profile_names if typed_text.lower() in name.lower()]

    # Update the combobox with filtered profiles
    profiles_combobox['values'] = tuple(filtered_profiles)
    if filtered_profiles:
        profiles_combobox.event_generate("<Down>")

# Filter sub-profiles on Tab key
def filter_subprofiles(event):
    """Filter sub-profiles in the subprofiles_combobox based on user input."""
    typed_text = subprofiles_combobox.get().strip()
    selected_profile_name = profiles_combobox.get().strip()

    custom_profiles = load_custom_profiles() + [default_profile]

    # Find the selected profile and its sub-profiles
    for profile in custom_profiles:
        if profile["profile_name"] == selected_profile_name:
            subprofile_names = sorted(
                [sub["sub_name"] for sub in profile.get("sub_profiles", [])],
                key=str.lower
            )
            break
    else:
        subprofile_names = []

    # Get matching sub-profile names and sort them
    filtered_subprofiles = [name for name in subprofile_names if typed_text.lower() in name.lower()]

    # Update the combobox with filtered sub-profiles
    subprofiles_combobox['values'] = tuple(filtered_subprofiles)
    if filtered_subprofiles:
        subprofiles_combobox.event_generate("<Down>")

def update_rename_button_state(event=None):
    """Enable or disable the Rename button based on selection."""
    profile_name = profiles_combobox.get().strip()

    if not profile_name or profile_name.lower() == str(default_profile["profile_name"]).lower() or profile_name.lower()=="select a profile":
        rename_prof.config(state="disabled")
    else:
        rename_prof.config(state="normal")

rename_popup = None

def open_rename_popup_cond():
    global rename_popup

    if rename_popup is not None and rename_popup.winfo_exists():
        rename_popup.lift()
        rename_popup.focus_force()
    else:
        open_rename_popup()

def open_rename_popup():
    """Open a popup window for renaming profiles or sub-profiles dynamically based on selection."""
    selected_profile_name = profiles_combobox.get().strip()
    selected_subprofile_name = subprofiles_combobox.get().strip()

    if not selected_profile_name:
        messagebox.showerror("Error", "Please select a profile to rename.")
        return

    # Popup window
    global rename_popup

    rename_popup = tk.Toplevel(root)
    rename_popup.title("Rename ")
    rename_popup.geometry("250x200")

    # Determine what is being renamed
    if selected_subprofile_name:
        rename_target = "subprofile"
        target_name = selected_subprofile_name
        instruction_text = f"Renaming sub-profile under \n'{selected_profile_name}'"
    else:
        rename_target = "profile"
        target_name = selected_profile_name
        instruction_text = f"Renaming profile \n'{selected_profile_name}'"

    # Instruction Label
    tk.Label(rename_popup, text=instruction_text, wraplength=280, justify="center").pack(pady=10)

    # Entry field for the new name
    ttk.Label(rename_popup, text="New Name:").pack(pady=5)
    new_name_entry = ttk.Entry(rename_popup, width=30)
    new_name_entry.pack(pady=5)
    new_name_entry.insert(0, target_name)  # Pre-fill with the current name

    # Confirm button
    def confirm_rename():
        new_name = new_name_entry.get().strip()
        if not new_name:
            messagebox.showerror("Error", "The new name cannot be empty.")
            return

        if rename_target == "profile":
            rename_profile(new_name)
        elif rename_target == "subprofile":
            rename_subprofile(new_name)

        rename_popup.destroy()  # Close the rename_popup after renaming

    ttk.Button(rename_popup, text="Rename", command=confirm_rename).pack(pady=10)

    # Close button
    ttk.Button(rename_popup, text="Cancel", command=rename_popup.destroy).pack(pady=5)


def rename_profile(new_name):
    """Rename the selected profile."""
    selected_profile_name = profiles_combobox.get().strip()

    if not selected_profile_name:
        messagebox.showerror("Error", "Please select a profile to rename.")
        return

    # Load profiles
    profiles = load_custom_profiles()

    # Rename logic (same as shared earlier)
    for profile in profiles:
        if profile["profile_name"] == selected_profile_name:
            if any(p["profile_name"] == new_name.strip() for p in profiles):
                messagebox.showerror("Error", f"A profile with the name '{new_name.strip()}' already exists.")
                return

            profile["profile_name"] = new_name.strip()
            save_custom_profiles(profiles)
            load_profile_names()
            profiles_combobox.set(new_name.strip())
            messagebox.showinfo("Success", f"Profile renamed to '{new_name.strip()}'.")
            return

    messagebox.showerror("Error", f"Profile '{selected_profile_name}' not found.")

def rename_subprofile(new_name):
    """Rename the selected sub-profile."""
    selected_profile_name = profiles_combobox.get().strip()
    selected_subprofile_name = subprofiles_combobox.get().strip()

    if not selected_profile_name:
        messagebox.showerror("Error", "Please select a profile first.")
        return

    if not selected_subprofile_name:
        messagebox.showerror("Error", "Please select a sub-profile to rename.")
        return

    # Load profiles
    profiles = load_custom_profiles()

    # Rename logic (same as shared earlier)
    for profile in profiles:
        if profile["profile_name"] == selected_profile_name:
            for subprofile in profile.get("sub_profiles", []):
                if subprofile["sub_name"] == selected_subprofile_name:
                    if any(sp["sub_name"] == new_name.strip() for sp in profile["sub_profiles"]):
                        messagebox.showerror("Error", f"A sub-profile with the name '{new_name.strip()}' already exists.")
                        return

                    subprofile["sub_name"] = new_name.strip()
                    save_custom_profiles(profiles)
                    load_subprofile_names()
                    subprofiles_combobox.set(new_name.strip())
                    messagebox.showinfo("Success", f"Sub-profile renamed to '{new_name.strip()}'.")
                    return

    messagebox.showerror("Error", f"Sub-profile '{selected_subprofile_name}' not found.")

####################################################################################################################
############################################## Save Last Session ###################################################
####################################################################################################################

def save_last_session_to_config():
    """Save the last selected profile and subprofile to a config file."""
    config = configparser.ConfigParser()

    # Add the last session data
    config["LastSession"] = {
        "profile": profiles_combobox.get().strip(),
        "subprofile": subprofiles_combobox.get().strip()
    }

    # Write to the config file
    with open(CONFIG_FILE, "w") as file:
        config.write(file)


def load_last_session_from_config():
    """Load the last selected profile and subprofile from the config file."""
    config = configparser.ConfigParser()

    try:
        config.read(CONFIG_FILE)

        if "LastSession" in config:
            profile = config["LastSession"].get("profile", "")
            subprofile = config["LastSession"].get("subprofile", "")

            if profile:
                profiles_combobox.set(profile)
                load_profile_names()  # Load the profile data into fields

                if subprofile:
                    subprofiles_combobox.set(subprofile)
                    load_subprofile_names()  # Load the subprofile data into fields
    except Exception as e:
        print(f"Error reading config file: {e}")
        # Handle missing or corrupt config file gracefully

####################################################################################################################

# Filter profiles on Tab key
def filter_remote_dir(event=None):
    """Filter remote paths in the combobox based on user input."""
    typed_text = remote_dir_entry.get().strip()

    # Always reload the full dataset
    transfer_type = transfer_type_sel.get()

    combined_paths = load_custom_paths(transfer_type) + default_paths

     # Get matching path names and sort them
    sorted_paths = sorted(
        [path for path in combined_paths],
        key=str.lower
    )
    filtered_paths = [path for path in sorted_paths if typed_text.lower() in path.lower()]

    # Update the combobox with filtered paths
    remote_dir_entry['values'] = tuple(filtered_paths)

    # Show the dropdown if matches exist
    if filtered_paths:
        remote_dir_entry.event_generate("<Down>")

def load_remote_paths(event=None):
    """Load all remote paths into the remote_dir_entry combobox."""
    transfer_type = transfer_type_sel.get()
    combined_paths = load_custom_paths(transfer_type) + default_paths

    # Populate the combobox with sorted paths
    remote_dir_entry['values'] = tuple(sorted(combined_paths, key=str.lower))

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
def on_close():
    """Save the last session and close the app."""
    save_last_session_to_config()
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

################################################# Setup Status table ##############################################
# Dictionary to maintain custom headings

headings = {
    'Name'       : 'Name',
    'IPAddress'  : 'IPAddress',
    'Status'     : 'Status',
    'Description': 'Description'
}

def setup_treeview(treeview):
    for col in treeview['columns']:
        treeview.heading(col, text=headings[col], command=lambda _col=col: treeview_sort_column(treeview, _col, False), anchor='w')

def treeview_sort_column(tv, col, reverse):
    # Retrieve all data from the treeview
    l = [(tv.set(k, col), k) for k in tv.get_children('')]
    
    # Sort the data
    l.sort(reverse=reverse, key=lambda t: natural_keys(t[0]))

    # Rearrange items in sorted positions
    for index, (val, k) in enumerate(l):
        tv.move(k, '', index)

    # Change the heading to show the sort direction
    for column in tv['columns']:
        heading_text = headings[column] + (' ↓' if reverse and column == col else ' ↑' if not reverse and column == col else '')
        tv.heading(column, text=heading_text, command=lambda _col=column: treeview_sort_column(tv, _col, not reverse))

def natural_keys(text):
    """
    Alphanumeric (natural) sort to handle numbers within strings correctly
    """
    return [int(c) if c.isdigit() else c for c in re.split(r'(\d+)', text)]

###################################################### Update Status Table ################################################

def update_status_table(host, lgv_name, status, description):
    """
    Update the status table with the given host, LGV name, status, and description.

    Args:
        host (str): IP address or host identifier.
        lgv_name (str): LGV number or identifier.
        status (str): Current status (e.g., "In Progress", "Completed", "Failed").
        description (str): Additional description or details.
        status_table (ttk.Treeview): The Treeview table to update.
    """
    for child in status_table.get_children():
        row_values = status_table.item(child, "values")
        if row_values[1] == host:
            status_table.item(child, values=(lgv_name, host, status, description))
            break


######################################################## Create UI ##################################################

root = tk.Tk()
root.title(f"Super File Transfer {__version__}")

# Check if running as a script or frozen executable
if getattr(sys, 'frozen', False):
    icon_path = os.path.join(sys._MEIPASS, "./transfer.ico")
else:
    icon_path = os.path.abspath("./transfer.ico")
# root.iconbitmap(icon_path)

window_width = 557
window_lenght = 670 # 670
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

# Create a custom style for the LabelFrame with an italic font
style.configure("Custom.TLabelframe.Label", font=("Segoe UI", 10, "italic"))


# Create the menu bar
menu_bar = tk.Menu(root)

file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label=" Load Config.db3 ", command=populate_table_from_db3)  # Add Load Config option
file_menu.add_command(label=" Load StaticRoutes.xml", command=populate_table_from_xml) # Add Load StaticRoutes option
file_menu.add_command(label=" Exit ", command=root.quit)  # Add Exit option
menu_bar.add_cascade(label="  File ", menu=file_menu)

options_menu = tk.Menu(menu_bar, tearoff=0)
options_menu.add_command(label="Show LGV Table", command=open_lgv_table_window_cond)
options_menu.add_command(label="Remove LGV Table", command=delete_lgv_data_file)
menu_bar.add_cascade(label=" Options ", menu=options_menu) 

# about_menu = tk.Menu(menu_bar, tearoff=0)
# about_menu.add_command(label="Info    ", command=open_shortcuts_window_cond)
# menu_bar.add_cascade(label=" About", menu=about_menu)

root.config(menu=menu_bar)


frame_profile = ttk.Labelframe(root, text="Profiles", labelanchor='nw', style="Custom.TLabelframe")
frame_profile.grid(row=0, column=0, padx=10, pady=(5,10), ipadx=3)

profile_label = ttk.Label(frame_profile, text="Profile:")
profile_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

# Create a listbox to display saved profiles
profiles_combobox = ttk.Combobox(frame_profile, width=40)
profiles_combobox.set("Select a profile")
profiles_combobox.grid(row=0, column=1, padx=10, pady=5, sticky='w')
profiles_combobox.bind("<ButtonPress>", load_profile_names)
profiles_combobox.bind("<<ComboboxSelected>>", combined_combobox_selected_profile)
profiles_combobox.bind("<Tab>", filter_profiles)

subprofile_label = ttk.Label(frame_profile, text="Subprofile:")
subprofile_label.grid(row=1, column=0, padx=5, pady=5, sticky='e')

subprofiles_combobox = ttk.Combobox(frame_profile, width=40)
subprofiles_combobox.set("Select a subprofile")
subprofiles_combobox.grid(row=1, column=1, padx=10, pady=5, sticky='w')
subprofiles_combobox.bind("<ButtonPress>", load_subprofile_names)
subprofiles_combobox.bind("<<ComboboxSelected>>", combined_combobox_selected_subprofile)
subprofiles_combobox.bind("<Tab>", filter_subprofiles)
# subprofiles_combobox.bind()

save_profile = ttk.Button(frame_profile, 
                          text="Save/Update", 
                          command=save_custom_profile)
save_profile.grid(row=0, column=2, padx=5, pady=5)
# button_design(save_profile)

delete_profile = ttk.Button(frame_profile, 
                          text=" Delete ", 
                          command=delete_profile_or_subprofile)
delete_profile.grid(row=1, column=2, padx=5, pady=5)

rename_prof = ttk.Button(frame_profile, 
                          text=" Rename ", 
                          command=open_rename_popup_cond)
rename_prof.grid(row=0, column=3, rowspan=2, padx=5, pady=5)


frame_path = ttk.Labelframe(root, text="Directory", labelanchor='ne', style="Custom.TLabelframe")
frame_path.grid(row=1, column=0, columnspan=2, padx=0, pady=0, ipadx=8)

frame_local = tk.Frame(frame_path)
frame_local.grid (row=0, column=0, columnspan=2, padx=0, pady=0)


local_dir_label = ttk.Label(frame_local, text="Local:")
local_dir_label.grid(row=0, column=0, padx=5, pady=5)

# Variable to store the file or folder path
file_path = tk.StringVar()
file_path_entry = ttk.Entry(frame_local, textvariable=file_path, width=58)
# file_path_entry = ttk.Combobox(frame_local, width=55)
file_path_entry.grid(row=0, column=1, padx=5, pady=5)

browse_btn = ttk.Button(frame_local, 
                        text="Browse",
                        command=browse_local_path)
browse_btn.grid(row=0, column=2, padx=(5,0), pady=5)


frame_remote = tk.Frame(frame_path)
frame_remote.grid(row=1, column=0, columnspan=2, padx=(0,14), pady=0)

remote_dir_label = ttk.Label(frame_remote, text="Remote:")
remote_dir_label.grid(row=0, column=0, padx=5, pady=5)

remote_dir_entry = ttk.Combobox(frame_remote, width=55)
remote_dir_entry.grid(row=0, column=1, padx=5, pady=5)

remote_dir_entry.bind("<Tab>", filter_remote_dir)
remote_dir_entry.bind("<ButtonPress>", load_remote_paths)

# Add a button to save a custom path
save_path = ttk.Button(frame_remote, 
                       text="Save Path",
                       command=on_add_path)
save_path.grid(row=0, column=2, padx=(5,0), pady=5)


frame_lgv_login = ttk.Labelframe(root, text="Connection settings", labelanchor='nw', style="Custom.TLabelframe")
frame_lgv_login.grid(row=3, column=0, columnspan=3, padx=5, pady=(10,5))


frame_lgvs = tk.Frame(frame_lgv_login)
frame_lgvs.grid(row=0, column=0, columnspan=1, padx=(5,0), pady=5)

frame_ip = tk.Frame(frame_lgvs)
frame_ip.grid(row=0, column=0, padx=0, pady=0)

ip_label = ttk.Label(frame_ip, text="Root IP:")
ip_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

ip_entry = ttk.Entry(frame_ip, width=25)
ip_entry.grid(row=0, column=1, padx=5, pady=5)
create_placeholder(ip_entry, "e.g., 7.204.194.10", "RootIP.TEntry", "Placeholder.TEntry")
ip_entry.bind("<KeyRelease>", validate_entry(ip_entry, 'RootIP.TEntry', validate_base_ip))

frame_range = tk.Frame(frame_lgvs)
frame_range.grid(row=1, column=0, padx=0, pady=0)

range_label = ttk.Label(frame_range, text="Range:")
range_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

range_entry = ttk.Entry(frame_range, width=25)
range_entry.grid(row=0, column=1, padx=5, pady=5)
create_placeholder(range_entry, "e.g., 1-9,27,29,31-40", "Range.TEntry", "Placeholder.TEntry")
range_entry.bind("<KeyRelease>", validate_entry(range_entry, 'Range.TEntry', validate_range))


frame_login = tk.Frame(frame_lgv_login)
frame_login.grid(row=0, column=1, columnspan=1, padx=(5,0), pady=5)

frame_user = tk.Frame(frame_login)
frame_user.grid(row=0, column=0, padx=0, pady=0)

username_label = ttk.Label(frame_user, text="Username:")
username_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

username_entry = ttk.Entry(frame_user)
username_entry.insert(0, "Administrator")
username_entry.grid(row=0, column=1, padx=5, pady=5)

frame_password = tk.Frame(frame_login)
frame_password.grid(row=1, column=0, padx=0, pady=0)

password_label = ttk.Label(frame_password, text="Password:")
password_label.grid(row=0, column=0, padx=5, pady=5, sticky='e')

password_entry = ttk.Entry(frame_password, show="*")
password_entry.grid(row=0, column=1, padx=5, pady=5)

frame_typetransfer = tk.Frame(frame_lgv_login)
frame_typetransfer.grid(row=0, column=2, padx=5, pady=5)

# Transfer Type Combobox
transfer_type_sel = tk.StringVar(value='SFTP')

transfer_type_label = ttk.Label(frame_typetransfer, text="Transfer type:")
transfer_type_label.grid(row=0, column=0, padx=5, pady=5)
transfer_type_combobox = ttk.Combobox(frame_typetransfer, textvariable=transfer_type_sel, width=7, state="readonly")
transfer_type_combobox['values'] = ("SFTP", "FTP", "NET")
transfer_type_combobox.set(transfer_type_sel.get())  # Default selection
transfer_type_combobox.grid(row=1, column=0, padx=5, pady=5)
transfer_type_combobox.bind("<<ComboboxSelected>>", set_path_on_selection)


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
                    style="TD.TButton",
                    command=start_transfer
                    )
transfer.grid(row=0, 
              column=1, 
              pady=0,
              padx=0, 
              sticky='w')

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

download = ttk.Button(frame_download,
                    text="Download", 
                    style="TD.TButton",
                    command=start_download
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
# status_widget = scrolledtext.ScrolledText(root, 
#                                           undo=True,
#                                           wrap = tk.WORD,
#                                           height=17,
#                                           width=70
#                                           )
# status_font = font.Font(family="Consolas", size=11)
# status_widget.configure(font=status_font)
# status_widget.grid(row=5, column=0, columnspan=2, padx=15, pady=15)
# status_widget.bind("<Key>", lambda e: "break")

# Create the Treeview (table)
table_frame = tk.Frame(root)
table_frame.grid(row=5, column=0, columnspan=2, padx=(10,0), pady=(10,0), sticky='nsew')

treeview_style = ttk.Style()
treeview_style.configure("Treeview", rowheight=23)  # Increase row height for more space between items
treeview_style.configure("Treeview", font=("Segoe UI", 10))  # Adjust font size if necessary
treeview_style.configure("Treeview", padding=(5, 5))  # Add padding to rows (optional)

columns = ("Name", "IPAddress", "Status", "Description")
status_table = ttk.Treeview(table_frame, columns=columns, show="headings")

# Define column properties
status_table.column("Name", width=10, anchor='w')
status_table.column("IPAddress", width=60, anchor='w')
status_table.column("Status", width=30, anchor='w')
status_table.column('Description', width=200, anchor='w')

setup_treeview(status_table)

status_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Add a scrollbar
scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=status_table.yview)
status_table.configure(yscroll=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)


# Create the Description frame
description_frame = tk.Frame(root)
description_frame.grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky='nsew')

# Configure column weights to control alignment
description_frame.columnconfigure(0, weight=1)  # Left column (summary label)
description_frame.columnconfigure(1, weight=0)  # Right column (timestamp label)

# Create the status summary label
summary_label = tk.Label(description_frame, text="Status result", font=("Arial", 10), anchor="w")
summary_label.grid(row=0, column=0, sticky='w', padx=10, pady=5)

# Create the timestamp label
timestamp_label = tk.Label(description_frame, text="Last operation: 00:00:00", font=("Arial", 10), anchor="e")
timestamp_label.grid(row=0, column=1, sticky='e', padx=10, pady=5)



set_paths()

# Enable menu for Show LGV Table if table is updated
update_menu_state()


# Load last session
load_last_session_from_config()
load_data_from_selection()

update_rename_button_state()

# Disable focus for all widgets
# disable_focus(root)

root.protocol("WM_DELETE_WINDOW", on_close)
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


# Add time when transfer is done

# Poner Files para que el usuario sepa que puede seleccionar varios

# Line 586, make user able to save local paths, and separate if they are either folders or filesand when opening a new one pop up a message if they want to actually save that path