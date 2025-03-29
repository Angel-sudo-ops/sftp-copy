import os
import shutil
import subprocess
from tkinter import filedialog

def netfolder_download(host, username, password, shared_folder, local_path, lgv_name=""):
    success = True
    description = ""
    status = "In Progress"
    unc_path = fr"\\{host}{shared_folder}"

    try:

        # Disconnect existing connections to the host
        subprocess.run(["net", "use", f"\\\\{host}", "/delete"], shell=True)
        # Connect to the shared folder using credentials
        subprocess.run(
            ["net", "use", unc_path, password, f"/user:{username}"],
            check=True,
            shell=True
        )

        print(host, lgv_name, status, f"Copying from {unc_path}")
        os.makedirs(local_path, exist_ok=True)

        for item in os.listdir(unc_path):
            src_item = os.path.join(unc_path, item)
            dst_item = os.path.join(local_path, item)

            if os.path.isfile(src_item):
                try:
                    shutil.copy2(src_item, dst_item)
                    description = f"Copied {item}"
                except Exception as e:
                    description = f"Failed to copy {item}: {e}"
                    success = False

                print(host, lgv_name, "In Progress", description)

        status = "Completed" if success else "Failed"
        description = "Copy completed successfully!" if success else "Copy completed with errors."

    except Exception as e:
        success = False
        status = "Failed"
        description = f"Error: {e}"

    finally:
        # Disconnect from the network share
        subprocess.run(["net", "use", unc_path, "/delete"], shell=True)
        print(host, lgv_name, status, description)
        # result_queue.put((host, "Success" if success else "Failed"))



def netfolder_transfer(host, username, password, local_path, shared_folder, lgv_name=""):
    success = True
    description = ""
    status = "In Progress"
    unc_path = fr"\\{host}{shared_folder}"

    try:
        # Disconnect first to avoid conflicts (1219 error)
        subprocess.run(["net", "use", f"\\\\{host}", "/delete"], shell=True)

        # Connect to the network folder using credentials
        subprocess.run(
            ["net", "use", unc_path, password, f"/user:{username}"],
            check=True,
            shell=True
        )

        print(host, lgv_name, status, f"Transferring to {unc_path}")

        # Handle file or folder transfer
        if os.path.isfile(local_path):
            try:
                file_name = os.path.basename(local_path)
                dst_file = os.path.join(unc_path, file_name)
                shutil.copy2(local_path, dst_file)
                description = f"Successfully transferred {file_name}"
            except Exception as e:
                description = f"Failed to transfer {file_name}: {e}"
                success = False
            finally:
                print(host, lgv_name, "In Progress", description)

        else:
            for root, dirs, files in os.walk(local_path):
                rel_path = os.path.relpath(root, local_path)
                target_dir = os.path.join(unc_path, rel_path)

                try:
                    os.makedirs(target_dir, exist_ok=True)
                except Exception as e:
                    print(host, lgv_name, "In Progress", f"Failed to create {target_dir}: {e}")
                    success = False
                    continue

                for file in files:
                    src_file = os.path.join(root, file)
                    dst_file = os.path.join(target_dir, file)

                    try:
                        shutil.copy2(src_file, dst_file)
                        description = f"Transferred {file}"
                    except Exception as e:
                        description = f"Failed to transfer {file}: {e}"
                        success = False
                    finally:
                        print(host, lgv_name, "In Progress", description)

        status = "Completed" if success else "Failed"
        description = "Transfer completed successfully!" if success else "Transfer completed with errors."

    except Exception as e:
        success = False
        status = "Failed"
        description = f"Connection failed: {e}"

    finally:
        subprocess.run(["net", "use", f"\\\\{host}", "/delete"], shell=True)
        print(host, lgv_name, status, description)
        # result_queue.put((host, "Success" if success else "Failed"))





host= "172.16.12.105"
user= "Administrator"
pass_="1"
remote_folder="\Backup"

local_path = filedialog.askdirectory(title="Choose a folder to save downloads")


# local_path = r'C:\Users\contreras.j\Desktop\NetFolder_Test\test'



netfolder_download(host, user, pass_, remote_folder, local_path, "LGV05")

# netfolder_transfer(host, user, pass_, local_path, remote_folder, "LGV02")
