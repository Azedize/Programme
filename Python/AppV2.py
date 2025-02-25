import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLabel,
    QFrame, QSpinBox, QComboBox, QCheckBox, QLineEdit , QMessageBox ,QHeaderView , QTableWidget , QListWidget , QTabWidget , QScrollArea
)
from cryptography.fernet import Fernet
from PyQt6.QtGui import QIcon , QCursor 
from PyQt6.QtCore import Qt , QTimer , QThread, pyqtSignal
import winreg as reg
from PyQt6 import  uic
import shutil
import signal
import time
import subprocess
import psutil
import uuid
import random
import string
import re
import datetime
import requests
import sys
from time import sleep
import zipfile
import traceback
import urllib3
urllib3.disable_warnings()




process_pids = []
notification_badges = {}
extraction_thread = None 
close_chrome_thread = None 
new_version = None

script_dir = os.path.dirname(os.path.realpath(__file__))
base_directory = os.path.join(script_dir, '..', 'tools', 'ExtensionEmail')
template_directory = os.path.join(script_dir, '..', 'tools', 'ExtensionTemplate')

print(f"Base Directory: {base_directory}")
print(f"Template Directory: {template_directory}")


def check_directory(path, name):
    if os.path.exists(path):
        print(f"✅ {name} existe : {path}")
    else:
        print(f"❌ {name} n'existe pas : {path}")





def DownloadFile(new_versions):

    print('🎉 New version(s) detected:', new_versions)
    local_filename = os.path.join(script_dir, "Programme-main.zip")

    print(f"🚀 [INFO] Starting download process for: {local_filename}")
    print(f"📁 [DEBUG] Script directory: {script_dir}")
    print(f"💾 [DEBUG] Local filename: {local_filename}")
    try:
        if os.path.exists(local_filename):
            print(f"🔍 [INFO] File '{local_filename}' already exists.")
            try:
                os.remove(local_filename)
                print(f"🧹 [INFO] Old file '{local_filename}' removed successfully.")
            except Exception as e:
                print(f"⚠️ [WARNING] Failed to remove old file: {e}")
                print(f"   └─ Details: {e}")
                print(f"   └─ [DEBUG] Error type: {type(e)}")
        else:
            print(f"✅ [INFO] File '{local_filename}' does not exist. Ready to download.")

    except Exception as e:
        print(f"❌ [ERROR] Error while checking/removing existing file: {e}")
        print(f"   └─ Details: {e}")
        print(f"   └─ [DEBUG] Error type: {type(e)}")
        traceback.print_exc()
        return -1

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/39.0.2171.95 Safari/537.36'
    }

    url = "https://github.com/Azedize/Programme/archive/refs/heads/main.zip"
    print(f"🌐 [INFO] Sending request to URL: {url}")

    try:
        response = requests.get(url, stream=True, headers=headers, verify=False)
        print(f"✅ [INFO] HTTP status code: {response.status_code}")

        if response.status_code != 200:
            print(f"❌ [ERROR] Failed to download file. HTTP status: {response.status_code}")
            print(f"   └─ [DEBUG] HTTP status code: {response.status_code}")
            return -1

        total_size = int(response.headers.get('content-length', 0))
        print(f"📦 [INFO] Total file size: {total_size} bytes")
        print(f"📏 [DEBUG] Content-Length header: {response.headers.get('content-length')}")

        with open(local_filename, "wb") as handle:
            print("⏳ [INFO] Starting download progress bar...")
            sys.stdout.write('[' + ' ' * 50 + ']')
            sys.stdout.write('\b' * 50)
            sys.stdout.flush()

            dl = 0
            downloaded_bytes = 0
            chunk_count = 0

            for chunk in response.iter_content(chunk_size=4096):
                if chunk:
                    handle.write(chunk)
                    downloaded_bytes += len(chunk)
                    chunk_count += 1

                    if chunk_count % 100 == 0:
                        progress = int((downloaded_bytes / total_size) * 50) if total_size else 0
                        sys.stdout.write('\r[' + '=' * progress + ' ' * (50 - progress) + ']')
                        sys.stdout.flush()

                    if downloaded_bytes % 100000 == 0:
                        percent = (downloaded_bytes / total_size) * 100 if total_size else 0
                        print(f"\nℹ️ [INFO] Downloaded: {downloaded_bytes}/{total_size} bytes ({percent:.2f}%)")

            sys.stdout.write('\r[' + '=' * 50 + ']\n')
            print(f"✅ [INFO] File '{local_filename}' downloaded successfully.")


        # Prepare for extraction by removing specific directories
        tools_dir = "Programme-main"
        tools_dir_path = os.path.join(script_dir, tools_dir)
        print(f"📁 [DEBUG] Tools directory path: {tools_dir_path}")

        # Delete specific directories within the tools directory BEFORE extraction
        if os.path.exists(tools_dir_path):
            if 'version_python' in new_versions and os.path.exists(os.path.join(tools_dir_path, 'Python')):
                try:
                    shutil.rmtree(os.path.join(tools_dir_path, 'Python'))
                    print("🗑️ [INFO] Removing existing 'Python' directory.")
                except Exception as e:
                    print(f"⚠️ [WARNING] Failed to remove 'Python' directory: {e}")
                    print(f"   └─ Details: {e}")
                    print(f"   └─ [DEBUG] Error type: {type(e)}")
            elif 'version_python' in new_versions:
                print("❓ [INFO] 'version_python' detected, but 'Python' directory not found. Possible issue with existing installation.")

            if 'version_interface' in new_versions and os.path.exists(os.path.join(tools_dir_path, 'interface')):
                try:
                    shutil.rmtree(os.path.join(tools_dir_path, 'interface'))
                    print("🗑️ [INFO] Removing existing 'interface' directory.")
                except Exception as e:
                    print(f"⚠️ [WARNING] Failed to remove 'interface' directory: {e}")
                    print(f"   └─ Details: {e}")
                    print(f"   └─ [DEBUG] Error type: {type(e)}")
            elif 'version_interface' in new_versions:
                print("❓ [INFO] 'version_interface' detected, but 'interface' directory not found. Possible issue with existing installation.")

            if 'version_extention' in new_versions and os.path.exists(os.path.join(tools_dir_path, 'tools')):
                try:
                    shutil.rmtree(os.path.join(tools_dir_path, 'tools'))
                    print("🗑️ [INFO] Removing existing 'tools' directory.")
                except Exception as e:
                    print(f"⚠️ [WARNING] Failed to remove 'tools' directory: {e}")
                    print(f"   └─ Details: {e}")
                    print(f"   └─ [DEBUG] Error type: {type(e)}")
            elif 'version_extention' in new_versions:
                print("❓ [INFO] 'version_extention' detected, but 'tools' directory not found. Possible issue with existing installation.")

            # If all versions are present, remove the entire directory for a clean slate
            if all(key in new_versions for key in ['version_python', 'version_interface', 'version_extention']):
                try:
                    shutil.rmtree(tools_dir_path)
                    print(f"🗑️ [INFO] Removing entire folder '{tools_dir}'.")
                except Exception as e:
                    print(f"⚠️ [WARNING] Failed to remove entire folder '{tools_dir}': {e}")
                    print(f"   └─ Details: {e}")
                    print(f"   └─ [DEBUG] Error type: {type(e)}")
        else:
            print(f"✅ [INFO] Folder '{tools_dir}' does not exist. Ready for extraction.")


    except requests.exceptions.RequestException as e:
        print(f"❌ [ERROR] Request failed: {e}")
        print(f"   └─ Details: {e}")
        print(f"   └─ [DEBUG] Error type: {type(e)}")
        traceback.print_exc()
        return -1
    except Exception as e:
        print(f"❌ [ERROR] Exception occurred: {e}")
        print(f"   └─ Details: {e}")
        print(f"   └─ [DEBUG] Error type: {type(e)}")
        traceback.print_exc()
        return -1

    print("✅ [INFO] Download process completed.")
    return 0





def extractAll(new_versions):
    tools_dir = "Programme-main"
    try:
        sleep(1)
        local_filename = os.path.join(script_dir, "Programme-main.zip")

        print(f"⚙️ [INFO] Starting extraction process in directory: {script_dir}")
        print(f"📁 [DEBUG] Script directory: {script_dir}")
        print(f"💾 [DEBUG] Local filename: {local_filename}")

        if os.path.exists(local_filename):
            print(f"🔍 [INFO] Found zip file: {local_filename}")
            try:
                # Extract the entire zip file to a temporary directory
                temp_extract_dir = os.path.join(script_dir, "temp_extract")  # Create a temporary directory
                os.makedirs(temp_extract_dir, exist_ok=True) # Make sure the directory exists
                print(f"🏗️ [INFO] Creating temporary directory: {temp_extract_dir}")
                with zipfile.ZipFile(local_filename, 'r') as zip_ref:
                    print(f"📦 [DEBUG] Extracting all files to temporary directory: {temp_extract_dir}")
                    zip_ref.extractall(temp_extract_dir)

                # Determine the source directory inside the zip (assuming it's 'Programme-main')
                source_dir = os.path.join(temp_extract_dir, 'Programme-main')  # Correct source directory
                dest_dir = os.path.join(script_dir, tools_dir)

                # Selective copying based on new_versions
                if 'version_python' in new_versions:
                    source_path = os.path.join(source_dir, 'Python')
                    dest_path = os.path.join(dest_dir, 'Python')
                    if os.path.exists(source_path):  # Check source exists
                        print(f"➡️ [INFO] Copying 'Python' from {source_path} to {dest_path}")
                        shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
                    else:
                        print(f"⚠️ [WARNING] 'Python' directory not found in extracted zip. Extraction may be incomplete.")

                if 'version_interface' in new_versions:
                    source_path = os.path.join(source_dir, 'interface')
                    dest_path = os.path.join(dest_dir, 'interface')
                    if os.path.exists(source_path):  # Check source exists
                        print(f"➡️ [INFO] Copying 'interface' from {source_path} to {dest_path}")
                        shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
                    else:
                        print(f"⚠️ [WARNING] 'interface' directory not found in extracted zip. Extraction may be incomplete.")

                if 'version_extention' in new_versions:
                    source_path = os.path.join(source_dir, 'tools')
                    dest_path = os.path.join(dest_dir, 'tools')
                    if os.path.exists(source_path):  # Check source exists
                        print(f"➡️ [INFO] Copying 'tools' from {source_path} to {dest_path}")
                        shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
                    else:
                        print(f"⚠️ [WARNING] 'tools' directory not found in extracted zip. Extraction may be incomplete.")


                # If all versions are new, copy the entire extracted directory (if it exists)
                if all(key in new_versions for key in ['version_python', 'version_interface', 'version_extention']):
                    if os.path.exists(source_dir):
                        print(f"➡️ [INFO] Copying entire directory '{source_dir}' to '{dest_dir}'")
                        shutil.copytree(source_dir, dest_dir, dirs_exist_ok=True)
                    else:
                        print(f"⚠️ [WARNING] Source directory '{source_dir}' does not exist.  Full copy failed.")

                print("✅ [INFO] Extraction and selective copy completed successfully.")

                # Clean up: Remove the zip file and the temporary extraction directory
                os.remove(local_filename)
                print(f"🗑️ [INFO] Deleted zip file: {local_filename}")

                shutil.rmtree(temp_extract_dir)  # Remove the temporary directory
                print(f"🧹 [INFO] Deleted temporary extraction directory: {temp_extract_dir}")


            except Exception as e:
                print(f"❌ [ERROR] Failed to extract zip file: {e}")
                print(f"   └─ Details: {e}")
                print(f"   └─ [DEBUG] Error type: {type(e)}")
                traceback.print_exc()
                os.system("pause")
                exit()
        else:
            print(f"⚠️ [WARNING] Zip file '{local_filename}' not found!")
            os.system("pause")
    except Exception as e:
        print(f"❌ [ERROR] Unexpected error during extraction: {e}")
        print(f"   └─ Details: {e}")
        print(f"   └─ [DEBUG] Error type: {type(e)}")
        traceback.print_exc()
        os.system("pause")
        exit()












def checkVersion():

    url = "https://www.dropbox.com/scl/fi/78a38bc4papwzlw80hxti/version.json?rlkey=n7dx5mb8tcctvprn0wq4ojw7m&st=z6vzw0ox&dl=1"
    print(f"🔎 [INFO] Checking version from URL: {url}")

    try:
        response = requests.get(url)
        print(f"✅ [INFO] HTTP Status Code: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"📦 [INFO] Response Data: {data}")

            
            version_updates = {}

            server_version_python = data.get("version_python")
            server_version_interface =data.get("version_interface")
            server_version_Extention =data.get("version_Extention")
            if not server_version_python or not server_version_interface or not server_version_Extention :
                print("❌ [ERROR] version key is missing in server response.")
                os.system("pause")
                exit()
            
            client_version_path_Python = os.path.join(script_dir, "..","version.txt")
            client_version_path_Extention = os.path.join(script_dir, "..", "tools","version.txt")
            client_version_path_interface  = os.path.join(script_dir, "..","interface" ,"version.txt")

            client_version_Python = ""
            client_version_Extention = ""
            client_version_interface = ""

            if os.path.exists(client_version_path_Python):
                with open(client_version_path_Python, 'r') as file:
                    client_version_Python = file.read().strip()

            if os.path.exists(client_version_path_Extention):
                with open(client_version_path_Extention, 'r') as file:
                    client_version_Extention = file.read().strip()    

            if os.path.exists(client_version_path_interface):
                with open(client_version_path_interface, 'r') as file:
                    client_version_interface = file.read().strip()


            print(f"🌐 [INFO] Server Version Python: {server_version_python}")
            print(f"💻 [INFO] Local Client Version Python: {client_version_Python}")

            print(f"🌐 [INFO] Server Version interface: {server_version_interface}")
            print(f"💻 [INFO] Local Client Version interface: {client_version_interface}")

            print(f"🌐 [INFO] Server Version Extention: {server_version_Extention}")
            print(f"💻 [INFO] Local Client Version Extention: {client_version_Extention}")


            if server_version_python != client_version_Python:
                version_updates["version_python"] = server_version_python

            if server_version_interface != client_version_interface:
                version_updates["version_interface"] = server_version_interface


            if server_version_Extention != client_version_Extention:
                version_updates["version_extention"] = server_version_Extention




            if version_updates:
                print(f"🎉 [INFO] New versions detected: {version_updates}")
                return version_updates
            else:
                print("👍 [INFO] All versions are up-to-date.")
                return None
     

        else:
            print(f"❌ [ERROR] Failed to retrieve version. HTTP Status: {response.status_code}")
            os.system("pause")
            exit()

    except Exception as e:
        print(f"❌ [ERROR] Exception occurred during version check: {e}")
        print(f"   └─ Details: {e}")
        traceback.print_exc()
        os.system("pause")
        exit()








def read_result_and_update_list(window):
    print("🔵 Attente de 10 secondes avant de commencer...")
    time.sleep(10)
    result_file_path = os.path.join(script_dir,"..", "tools","result.txt")
    print("🔍 Début de la lecture du fichier result.txt...")
    while process_pids:
        time.sleep(1)

    print("✅ Tous les processus sont terminés, mise à jour de l'interface...")

    if not os.path.exists(result_file_path):
        print("❌ Erreur : Le fichier result.txt est introuvable.")
        QMessageBox.warning(window, "Erreur", "Le fichier result.txt est introuvable.")
        return  

    errors_dict = {}
    notifications = {}

    try:
        print(f"📖 Lecture du fichier : {result_file_path}")
        with open(result_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        with open(result_file_path, 'w', encoding='utf-8') as file:
            file.truncate(0) 
            print("🗑️ Contenu du fichier result.txt supprimé.")

        if not lines:
            print("⚠️ Le fichier result.txt est vide.")
            QMessageBox.warning(window, "Avertissement", "Le fichier result.txt est vide.")
            return
        
        for line in lines:
            print(f"📌 Lecture de la ligne : {line.strip()}")
            parts = line.strip().split(":")
            if len(parts) == 4:
                session_id, pid, email, status = parts  
                if status not in errors_dict:
                    errors_dict[status] = []
                errors_dict[status].append(email)  

        print("📌 Données extraites :", errors_dict)

        result_tab_widget = window.findChild(QTabWidget, "tabWidgetResult")
        if not result_tab_widget:
            print("❌ Impossible de trouver 'tabWidgetResult'.")
            QMessageBox.critical(window, "Erreur", "Impossible de trouver 'tabWidgetResult'.")
            return

        for status in ["bad_proxy", "completed", "account_closed", "password_changed", "recoverychanged", "Activite_suspecte", "validation_capcha"]:
            tab_widget = result_tab_widget.findChild(QWidget, status)
            if tab_widget:
                tab_index = result_tab_widget.indexOf(tab_widget)
                print(f"📌 Vérification de l'onglet : {status} (index {tab_index})")

                list_widgets = tab_widget.findChildren(QListWidget)
                if list_widgets:
                    list_widget = list_widgets[0]
                    
                    if status in errors_dict and errors_dict[status]:
                        list_widget.clear()
                        list_widget.addItems(errors_dict[status])
                        list_widget.scrollToBottom()
                        list_widget.show()

                        notifications[tab_index] = len(errors_dict[status])
                        print(f"📌 Emails trouvés pour {status} : {len(errors_dict[status])}")

                        message_label = tab_widget.findChild(QLabel, "no_data_message")
                        if message_label:
                            message_label.deleteLater()

                    else:
                        print(f"⚠️ Aucun email pour {status}, masquage du QListWidget et affichage d'un message.")
                        list_widget.hide()

                        message_label = QLabel("⚠ No email data available for this category.\nPlease check later.", tab_widget)
                        message_label.setObjectName("no_data_message")
                        message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                        message_label.setStyleSheet("""
                            color: #27445D; 
                            font-size: 16px; 
                            font-weight: bold; 
                            font-family: Arial; 
                            background-color: rgba(0, 0, 0, 0.1);
                            border: 2px solid #27445D;
                            padding: 10px;
                            border-radius: 8px;
                        """)

                        layout = tab_widget.layout()
                        if layout is None:
                            layout = QVBoxLayout(tab_widget)
                        layout.addWidget(message_label)
                else:
                    print(f"⚠️ Aucun QListWidget trouvé dans l'onglet {status}. Vérifiez votre interface UI.")
        print(f"📌 Notifications à ajouter : {notifications}")
        for tab_index, count in notifications.items():
            print(f"📌 Ajout d'un badge de notification pour l'onglet {tab_index} ({count} nouveaux éléments)")
            add_notification_badge(result_tab_widget, tab_index, count)
        result_tab_widget.currentChanged.connect(remove_notification)
    except Exception as e:
        print(f"❌ Erreur lors de la lecture du fichier result.txt : {e}")
        QMessageBox.critical(window, "Erreur", f"Erreur lors de la lecture du fichier result.txt : {e}")



def remove_notification(index):
    if index in notification_badges:
        print(f"📌 Suppression du badge de notification pour l'onglet {index}")
        badge = notification_badges.pop(index, None)
        if badge:
            badge.deleteLater()




def add_notification_badge(tab_widget, tab_index, count):
    if tab_index in notification_badges:
        notification_badges[tab_index].deleteLater()
        del notification_badges[tab_index]

    print(f"🔍 Tentative d'ajout d'un badge pour l'onglet {tab_index} avec {count} notifications")

    tab_bar = tab_widget.tabBar()
    tab_rect = tab_bar.tabRect(tab_index)

    print(f"📌 tab_rect pour l'index {tab_index} → X: {tab_rect.x()}, Y: {tab_rect.y()}, W: {tab_rect.width()}, H: {tab_rect.height()}")

    if tab_widget.tabPosition() in [QTabWidget.TabPosition.West, QTabWidget.TabPosition.East]:
        badge_x = tab_rect.left() + 13  
        badge_y = tab_rect.center().y()
        badge_x = tab_rect.right() - 20  
        badge_y = tab_rect.top() 

    badge_label = QLabel(f"{count}", tab_widget)
    badge_label.setStyleSheet("""
    background-color: red;
    color: white;
    font-weight: bold;
    font-size: 12px;
    padding: 3px;
    border-radius: 10px;
    min-width: 15px;
    min-height: 15px;
    text-align: center;
    """)
    badge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

    try:
        badge_label.setParent(tab_widget)
        badge_label.move(badge_x, badge_y)

        QTimer.singleShot(100, lambda: badge_label.show())

        notification_badges[tab_index] = badge_label

        tab_widget.update()
        tab_bar.update()

        print(f"✅ Badge ajouté à l'onglet {tab_index} à la position ({badge_x}, {badge_y})")

    except Exception as e:
        print(f"❌ Erreur lors de l'ajout du badge : {e}")






    
# Génère un identifiant unique de session de longueur spécifiée à partir d'un UUID.
def generate_session_id(length=5):
    if length <= 0:
        raise ValueError("The length must be a positive integer.")
    return str(uuid.uuid4()).replace("-", "")[:length]





session_id = generate_session_id()





def show_critical_message(window, title, message):
    msg = QMessageBox(window)
    msg.setIcon(QMessageBox.Icon.Critical)  
    msg.setWindowTitle(title)  
    msg.setText(message) 
    msg.setStyleSheet("""
        QMessageBox {
            background-color: #f8f9fa;
            color: #333333;
            font-family: 'Arial';
            font-size: 14px;
            border: 2px solid #d9534f;
            border-radius: 8px;
            padding: 10px;
        }
        QMessageBox QLabel {
            color: #333333;
            font-size: 14px;
        }
        QMessageBox QPushButton {
            background-color: #d9534f;
            color: white;
            border-radius: 6px;
            padding: 5px 15px;
            font-size: 14px;
            font-weight: bold;
        }
        QMessageBox QPushButton:hover {
            background-color: #c9302c;
        }
        QMessageBox QPushButton:pressed {
            background-color: #ac2925;
        }
    """)  
    msg.exec()





def generate_gmail_password(length=12):
    if length < 12:
        raise ValueError("The recommended minimum length for a secure password is 12 characters.")
    
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_chars = "!@#$%^&*()-_+=<>?/|"

    password = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(special_chars),
    ]
    remaining_length = length - len(password)
    all_chars = lowercase + uppercase + digits + special_chars
    password += random.choices(all_chars, k=remaining_length)
    random.shuffle(password)
    return ''.join(password)








def print_json_detailed(message, json_data):
    print(f"\n{message}\n{'-' * 80}")
    print(json.dumps(json_data, indent=4, ensure_ascii=False))
    print(f"{'-' * 80}\n")






# Récupère le chemin d'installation de Google Chrome à partir du registre Windows.
def get_chrome_path():
    try:
        key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, key) as reg_key:
            chrome_path, _ = reg.QueryValueEx(reg_key, None)
            return chrome_path
    except FileNotFoundError:
        return "Google Chrome is not installed or the path is not registered in the registry."
    







def create_extension_for_email(email, password, host, port, user, passwordP, recovry, new_password, new_recovry, IDL):
    if not os.path.exists(base_directory):
        os.makedirs(base_directory)

    email_folder = os.path.join(base_directory, email)

    if os.path.exists(email_folder):
        shutil.rmtree(email_folder)  
    os.makedirs(email_folder)  

    for item in os.listdir(template_directory):
        source_item = os.path.join(template_directory, item)
        destination_item = os.path.join(email_folder, item)

        if os.path.isdir(source_item):
            shutil.copytree(source_item, destination_item, dirs_exist_ok=True)
        else:
            shutil.copy2(source_item, destination_item)

    content_js_path = os.path.join(email_folder, "content.js")
    if os.path.exists(content_js_path):
        with open(content_js_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        content = content.replace("__IDL__", IDL).replace("__email__", f'"{email}"')
        with open(content_js_path, 'w', encoding='utf-8') as file:
            file.write(content)

    background_js_path = os.path.join(email_folder, "background.js")
    if os.path.exists(background_js_path):
        with open(background_js_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        content = (content
                   .replace("__host__", host)
                   .replace("__port__", port)
                   .replace("__user__", user)
                   .replace("__pass__", passwordP)
                    .replace("__IDL__", IDL))
        with open(background_js_path, 'w', encoding='utf-8') as file:
            file.write(content)

    gmail_process_js_path = os.path.join(email_folder, "gmail_process.js")
    if os.path.exists(gmail_process_js_path):
        with open(gmail_process_js_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        content = (content.replace("__email__", f'"{email}"')
                          .replace("__password__", f'"{password}"')
                          .replace("__recovry__", f'"{recovry}"')
                          .replace("__newPassword__", f'"{new_password}"')
                          .replace("__newRecovry__", f'"{new_recovry}"'))
        with open(gmail_process_js_path, 'w', encoding='utf-8') as file:
            file.write(content)

    print(f"✅ Extension créée et modifiée pour l'email : {email}")








def add_pid_to_text_file(pid, email):
    text_file_path = os.path.join(base_directory, email, ".." ,"Tools" , "data.txt")

    os.makedirs(os.path.dirname(text_file_path), exist_ok=True)

    if os.path.exists(text_file_path):
        with open(text_file_path, 'r', encoding='utf-8') as file:
            existing_entries = set(file.read().splitlines())
    else:
        print(f"Le fichier {text_file_path} n'existe pas. Il sera créé.")
        existing_entries = set()

    entry = f"{pid}:{email}:{session_id}" 

    if entry not in existing_entries:
        with open(text_file_path, 'a', encoding='utf-8') as file:
            file.write(f"{entry}\n")
        print(f"L'entrée {entry} a été ajoutée au fichier {text_file_path}.")
    else:
        print(f"L'entrée {entry} existe déjà dans le fichier {text_file_path}.")








# Arrête tous les threads et termine les processus Chrome en cours en gérant les exceptions.
def stop_all_processes(window):
    """Arrêter tous les threads et processus en cours avec un seul message."""
    global extraction_thread, close_chrome_thread, process_pids

    print("Entering stop_all_processes function.")

    if extraction_thread:
        print("Stopping extraction_thread.")
        extraction_thread.stop_flag = True
        extraction_thread.wait()
        extraction_thread = None
    else:
        print("No extraction_thread to stop.")

    if close_chrome_thread:
        print("Stopping close_chrome_thread.")
        close_chrome_thread.stop_flag = True
        close_chrome_thread.wait()
        close_chrome_thread = None
    else:
        print("No close_chrome_thread to stop.")

    if process_pids:
        print(f"Attempting to terminate processes with PIDs: {process_pids}")
    else:
        print("No processes to terminate.")

    for pid in process_pids[:]:
        try:
            print(f"Attempting to terminate process with PID {pid}.")
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=5) 
            print(f"Chrome process with PID {pid} has been terminated.")
        except psutil.NoSuchProcess:
            print(f"The process with PID {pid} no longer exists.")
        except psutil.AccessDenied:
            print(f"Permission denied to terminate the process with PID {pid}.")
        except Exception as e:
            print(f"Error while terminating the process with PID {pid}: {e}")
        finally:
            if pid in process_pids:
                process_pids.remove(pid)

    print("Exiting stop_all_processes function.")
    print("All processes have been stopped and threads have been terminated.")







# Lance un thread pour fermer les processus Chrome liés à une session donnée et affiche les messages de progression.
def launch_close_chrome( ):
    global close_chrome_thread
    close_chrome_thread = CloseChromeThread()
    close_chrome_thread.progress.connect(lambda msg: print(msg))
    close_chrome_thread.start()





def parse_input_to_json(window):
    input_data = window.textEdit_3.toPlainText().strip()
    entered_number = window.textEdit_4.toPlainText().strip()

    if not input_data:
        QMessageBox.warning(window, "Error", "Please enter the data.")
        return

    if not entered_number.isdigit():
        QMessageBox.warning(window, "Error", "Please enter a valid number.")
        return



    entered_number = int(entered_number)

    try:
        lines = input_data.strip().split("\n")

        keys = lines[0].split(";")

        mandatory_keys_patterns = [
            ["email", "passwordEmail", "ipAddress", "port"],
            ["Email", "password_email", "ip_address", "port"]
        ]

        if not any(set(pattern).issubset(set(keys)) for pattern in mandatory_keys_patterns):
            missing_keys = [key for pattern in mandatory_keys_patterns for key in pattern if key not in keys]
            pattern_message = (
                "<b>The required keys are missing in your input.</b><br><br>"
                "Please include the required keys in one of the following formats:<br>"
                "1. <i>email; passwordEmail; ipAddress; port</i><br>"
                "2. <i>Email; password_email; ip_address; port</i><br><br>"
                f"<b>Missing keys detected:</b> {', '.join(missing_keys)}"
            )

            show_critical_message(window, "Erreur - Clés obligatoires manquantes", pattern_message)
            return

        optional_keys_patterns = [
            ["login", "password", "recoveryEmail", "newrecoveryEmail"],
            ["login", "password", "recovery_email", "New_recovery_email"]
        ]


        valid_optional_keys = list(set(optional_keys_patterns[0] + optional_keys_patterns[1]))
        all_valid_keys = list(set(mandatory_keys_patterns[0] + valid_optional_keys))


        invalid_keys = [key for key in keys if key not in all_valid_keys]
        if invalid_keys:
            pattern_message = (
                "<b>Les clés fournies contiennent des valeurs non valides.</b><br><br>"
                f"<b>Clés non valides détectées :</b> {', '.join(invalid_keys)}"
            )
            show_critical_message(window, "Erreur - Clés invalides", pattern_message)
            return

        data_list = []
        for line in lines[1:]:
            values = line.split(";")
            if len(keys) == len(values):  
                data_list.append(dict(zip(keys, values)))
            else:
                raise ValueError("The number of keys and values does not match.")

        if entered_number > len(data_list):
            QMessageBox.warning(window, "Error", f"The number must be less than or equal to the number of emails ({len(data_list)}).")
            return

        afficher_json(data_list)
        return data_list, entered_number

    except Exception as e:
        QMessageBox.critical(window, "Error", f"Error while processing the data: {e}")
        return




def afficher_json(data):
    print(json.dumps(data, indent=4, ensure_ascii=False))




def get_key_value( email_data, possible_keys):
    for key in possible_keys:
        if key in email_data:
            if not email_data[key]:  
                return key
            return email_data[key]
    return possible_keys[0]





def start_extraction(window, data_list, entered_number):
    global extraction_thread 
    
    logs_directory = os.path.join(script_dir, '..', 'Tools', 'logs')
    
    if not os.path.exists(logs_directory):
        os.makedirs(logs_directory)
    

    try:
        entered_number = int(entered_number)
    except ValueError:
        QMessageBox.warning(window, "Erreur de saisie", "Veuillez entrer un nombre valide.")
        return

    email_count = len(data_list)
    if entered_number > email_count:
        QMessageBox.warning(window, "Nombre incorrect", f"Le nombre doit être inférieur ou égal au nombre d'e-mails ({email_count}).")
        return
    

    # submit_button = window.findChild(QPushButton, "submitButton")  
    # submit_button.setStyleSheet("background-color: gray; color: lightgray; border: 1px solid darkgray;")  # Applique un style désactivé

    # submit_button.setDisabled(True)  

    # if submit_button.isEnabled():
    #     print("Le bouton est activé.")
    # else:
    #     print("Le bouton est désactivé.")




    launch_close_chrome()

    chrome_path = get_chrome_path()
    
    extraction_thread = ExtractionThread(
        data_list, session_id, entered_number, chrome_path, base_directory
    )
    
    extraction_thread.progress.connect(lambda msg: print(msg))
    extraction_thread.finished.connect(lambda: QMessageBox.information(window, "Terminé", "L'extraction est terminée."))
    extraction_thread.stopped.connect(lambda msg: QMessageBox.warning(window, "Arrêté", msg))
    
    extraction_thread.start()









class ExtractionThread(QThread):
    progress = pyqtSignal(str)  
    finished = pyqtSignal()  
    stopped = pyqtSignal(str)  

    def __init__(self, data_list, session_id, entered_number, chrome_path, base_directory):
        super().__init__()
        self.data_list = data_list  
        self.session_id = session_id  
        self.entered_number = entered_number  
        self.chrome_path = chrome_path 
        self.base_directory = base_directory  
        self.stop_flag = False  



    def run(self):
        global process_pids 
        remaining_emails = self.data_list[:]  

        while remaining_emails or process_pids:  
            if self.stop_flag:  
                self.stopped.emit("Processing stopped by the user.")
                break

            if len(process_pids) < self.entered_number and remaining_emails:
                next_email = remaining_emails.pop(0)  
                email_value = get_key_value(next_email, ["email", "Email"])
                self.progress.emit(f"Traitement de l'email : {email_value}")

                try:
                    profile_email = get_key_value(next_email, ["email", "Email"])
                    profile_password = get_key_value(next_email, ["password_email", "passwordEmail"])
                    ip_address =get_key_value(next_email, ["ip_address", "ipAddress"])
                    port = get_key_value(next_email, ["port"])
                    login = get_key_value(next_email, ["login"])
                    password = get_key_value(next_email, ["password"])
                    recovery_email = get_key_value(next_email, ["recovery_email", "recoveryEmail"])
                    new_recovery_email = get_key_value(next_email, ["new_recovery_email", "neWrecoveryEmail"])

                    new_password = generate_gmail_password(16)



                    logs_directory = os.path.join(script_dir, '..' ,'Tools','logs')
                    session_directory = os.path.join(logs_directory, f"{current_date}_{current_hour}")

                    os.makedirs(session_directory, exist_ok=True)

                    logs_subdirs = [os.path.join(logs_directory, d) for d in os.listdir(logs_directory) if os.path.isdir(os.path.join(logs_directory, d))]
                    logs_subdirs.sort(key=os.path.getctime)

                    if len(logs_subdirs) > 4:
                        to_delete = logs_subdirs[:4]


                        for dir_to_delete in to_delete:
                            try:
                                shutil.rmtree(dir_to_delete)
                            except Exception as e:
                                print(f"❌ Erreur lors de la suppression de {dir_to_delete} : {e}")




                    file_name = f"{profile_email}_{current_hour}.txt"
                    file_path = os.path.join(session_directory, file_name)



                    with open(file_path, "w") as file:
                        file.write(f"Extraction démarrée pour cet email à {current_hour}.\n")

                    create_extension_for_email(
                        profile_email, profile_password,
                        f'"{ip_address}"', f'"{port}"',
                        f'"{login}"', f'"{password}"', f'{recovery_email}',
                        new_password, new_recovery_email, f'"{self.session_id}"'
                    )

                    command = [
                        self.chrome_path,
                        f"--user-data-dir={os.path.join(script_dir,'..','Tools', 'Profiles', profile_email)}",
                        f"--load-extension={os.path.join(self.base_directory, profile_email)}",
                        "--no-first-run",
                        "--no-default-browser-check"
                    ]
                    process = subprocess.Popen(command) 
                    process_pids.append(process.pid) 
                    add_pid_to_text_file(process.pid, profile_email)  
                except Exception as e:
                    self.progress.emit(f"Erreur : {e}")

            self.msleep(1000) 

        self.finished.emit()  




# Gère la fermeture des processus Chrome liés à une session en surveillant les fichiers de téléchargement correspondants et en supprimant les processus et fichiers associés.
class CloseChromeThread(QThread):
    progress = pyqtSignal(str)  

    def __init__(self):
        super().__init__()
        self.session_id = session_id  
        self.stop_flag = False  

    def run(self):
        downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")  
        self.progress.emit("🔵 Attente de 10 secondes avant de commencer...")  
        print("🔵 Attente de 10 secondes avant de commencer...")
        self.sleep(10)

        while not self.stop_flag:  
            print("🔄 Vérification des fichiers de logs...")

            if not process_pids:  
                self.progress.emit("⚠️ La liste des PID est vide. Fin du processus.")  
                print("⚠️ La liste des PID est vide. Fin du processus.")
                break

            files = [f for f in os.listdir(downloads_folder) if f.startswith(self.session_id) and f.endswith(".txt")]
            log_files = [f for f in os.listdir(downloads_folder) if f.startswith("log_") and f.endswith(".txt")]

            print(f"📂 Fichiers session trouvés : {files}")
            print(f"📂 Fichiers logs trouvés : {log_files}")

            # Traitement des fichiers logs en parallèle
            print("⚙️ Démarrage du traitement des fichiers logs en parallèle...")
            with ThreadPoolExecutor() as executor:
                futures = []
                for log_file in log_files:
                    futures.append(executor.submit(self.process_log_file, log_file, downloads_folder))

                for future in as_completed(futures):
                    result = future.result()  # Attendre et récupérer le résultat
                    print(f"✅ Résultat du traitement de log : {result}")
            print("✅ Traitement des fichiers logs terminé.")

            # Traitement des fichiers session en parallèle
            print("⚙️ Démarrage du traitement des fichiers session en parallèle...")
            with ThreadPoolExecutor() as executor:
                futures = []
                for file_name in files:
                    futures.append(executor.submit(self.process_session_file, file_name, downloads_folder))

                for future in as_completed(futures):
                    result = future.result()  # Attendre et récupérer le résultat
                    print(f"✅ Résultat du traitement de session : {result}")
            print("✅ Traitement des fichiers session terminé.")

            time.sleep(1)


    def process_log_file(self, log_file, downloads_folder):
        """ Traiter un fichier log spécifique """
        log_file_path = os.path.join(downloads_folder, log_file)
        print(f"📖 Lecture du fichier de log : {log_file_path}")

        try:
            global current_hour, current_date
            print(f"🕒 Heure actuelle : {current_hour}, 📅 Date actuelle : {current_date}")

            email = self.get_email_from_log_file(log_file_path)  
            if not email:
                print(f"⚠️ Impossible d'extraire l'email du fichier : {log_file}")
                return f"⚠️ Erreur dans le fichier {log_file}: Email non trouvé."

            print(f"📧 Email extrait du fichier : {email}")

            logs_directory = os.path.join(script_dir, 'logs')

            session_folder = f"{current_date}_{current_hour}"
            target_folder = os.path.join(logs_directory, session_folder)

            print(f"📁 Vérification du dossier cible : {target_folder}")
            if not os.path.exists(target_folder):
                print(f"⚠️ Dossier {target_folder} inexistant, création en cours...")


            target_file_path = os.path.join(target_folder, f"{email}_{current_hour}.txt")
            print(f"📑 Destination du fichier log : {target_file_path}")

            try:
                with open(log_file_path, 'r', encoding='utf-8') as log_file_reader:
                    log_content = log_file_reader.read()
            except Exception as e:
                print(f"⚠️ Erreur lors de la lecture du fichier {log_file_path} : {e}")
                return f"⚠️ Erreur lors de la lecture du fichier {log_file}: {e}"

            try:
                with open(target_file_path, 'a', encoding='utf-8') as target_file_writer:
                    target_file_writer.write(log_content + "\n")
                print(f"✅ Contenu ajouté à {target_file_path}")
            except Exception as e:
                print(f"⚠️ Erreur lors de l'écriture dans {target_file_path} : {e}")
                return f"⚠️ Erreur lors de l'écriture dans {target_file_path}: {e}"

            # Suppression du fichier log après traitement
            try:
                os.remove(log_file_path)
                print(f"🗑️ Fichier log supprimé : {log_file_path}")
                return f"🗑️ Fichier log supprimé : {log_file_path}"
            except Exception as e:
                print(f"⚠️ Erreur lors de la suppression du fichier {log_file_path} : {e}")
                return f"⚠️ Erreur lors de la suppression du fichier {log_file_path}: {e}"

        except Exception as e:
            print(f"⚠️ Erreur globale lors du traitement du fichier {log_file} : {e}")
            return f"⚠️ Erreur dans le fichier {log_file} : {e}"


    def process_session_file(self, file_name, downloads_folder):
        """ Traiter un fichier session spécifique """
        file_path = os.path.join(downloads_folder, file_name)  
        print(f"📖 Lecture du fichier : {file_path}")

        try:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    file_content = file.read().strip()
            except Exception as e:
                print(f"⚠️ Erreur lors de la lecture du fichier {file_path}: {e}")
                return f"⚠️ Erreur lors de la lecture du fichier {file_name}: {e}"


            print(f"📜 Contenu du fichier {file_name} : {file_content}")

            match = re.search(r"session_id:(\w+)_PID:(\d+)_Email:([\w.@]+)_Status:(\w+)", file_content)

            if not match:
                print(f"❌ Format incorrect dans {file_name}: {file_content}")
                return f"⚠️ Format incorrect dans {file_name}: {file_content}"

            session_id, pid, email, etat = match.groups()
            print(f"✅ Données extraites - Session ID: {session_id}, PID: {pid}, Email: {email}, Status: {etat}")

            result_file_path = os.path.join(script_dir, "Tools-main", "result.txt")
            try:
                with open(result_file_path, 'a', encoding='utf-8') as result_file:
                    result_file.write(f"{session_id}:{pid}:{email}:{etat}\n")
            except Exception as e:
                print(f"⚠️ Erreur lors de l'écriture dans le fichier {result_file_path}: {e}")
                return f"⚠️ Erreur lors de l'écriture dans le fichier {file_name}: {e}"


            pid = int(pid)
            if pid in process_pids:
                print(f"🛑 Fermeture du processus {pid}")
                try:
                    os.kill(pid, signal.SIGTERM)
                    process_pids.remove(pid)
                    print(f"✅ Processus {pid} terminé.")
                except Exception as e:
                    print(f"⚠️ Erreur lors de la fermeture du processus {pid}: {e}")
                    return f"⚠️ Erreur lors de la fermeture du processus {file_name}: {e}"


            try:
                os.remove(file_path)
                print(f"🗑️ Suppression du fichier : {file_path}")
                return f"🗑️ Fichier session supprimé : {file_path}"
            except Exception as e:
                print(f"⚠️ Erreur lors de la suppression du fichier {file_path}: {e}")
                return f"⚠️ Erreur lors de la suppression du fichier {file_name}: {e}"


        except Exception as e:
            print(f"⚠️ Erreur globale lors du traitement du fichier {file_name} : {e}")
            return f"⚠️ Erreur dans le fichier {file_name} : {e}"


    def get_email_from_log_file(self, file_name):
        """ Extraire l'email depuis le nom du fichier """
        print(f"📜 Nom du fichier log : {file_name}")


        file_name = os.path.basename(file_name)
        match = re.search(r"log_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z_([\w.+-]+@[\w.-]+\.[a-zA-Z]{2,6})\.txt", file_name)
        if match:
            email = match.group(1)
            print(f"📧 Email extrait du fichier : {email}")
            return email
        else:
            print("⚠️ Email non trouvé dans le nom du fichier.")
            return None



            
def launch_new_window():
    try:
        python_executable = sys.executable
        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)
        script_path_run = os.path.join(script_dir, '..', '..', 'checkV2.py')


        command = [python_executable, script_path_run]
        subprocess.Popen(command,
                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
                         close_fds=True)

        print("[INFO] New instance of the application launched.")
    except Exception as e:
        print(f"❌ [ERROR] Failed to launch new instance: {e}")




class MainWindow(QMainWindow):
    def __init__(self, json_data):
        super(MainWindow, self).__init__()

        ui_path = os.path.join(script_dir, '..',  "interface"  , "interface.ui")
        uic.loadUi(ui_path, self)

        self.states = json_data
        self.state_stack = []
        self.reset_options_container = self.findChild(QWidget, "resetOptionsContainer")
        self.reset_options_layout = QVBoxLayout(self.reset_options_container)

        self.scenario_container = self.findChild(QWidget, "scenarioContainer")
        self.scenario_layout = QVBoxLayout(self.scenario_container)

  
  
        
        self.template_button = self.findChild(QPushButton, "TemepleteButton")
        self.template_button.hide()

        self.template_Frame1 = self.findChild(QFrame, "Template1")
        self.template_Frame1.hide()

        self.template_Frame2 = self.findChild(QFrame, "Template2")
        self.template_Frame2.hide()

        self.reset_options_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scenario_layout.setAlignment(Qt.AlignmentFlag.AlignTop)


        self.Button_Initaile_state = self.findChild(QPushButton, "Button_Initaile_state")
        if self.Button_Initaile_state:
            self.Button_Initaile_state.clicked.connect(self.load_initial_options)

        self.submit_button = self.findChild(QPushButton, "submitButton")
        if self.submit_button:
            self.submit_button.clicked.connect(lambda: self.on_submit_button_clicked(self))

        self.lineEdit_search = self.findChild(QLineEdit, "lineEdit_search")
        if self.lineEdit_search:
            self.lineEdit_search.hide()

        self.tabWidgetResult = self.findChild(QTabWidget, "tabWidgetResult")

        # Apply Stylesheet to Rotate Text
        self.tabWidgetResult.setStyleSheet("""

        QTabBar::tab {
            width: 29px;
            max-width: 100px;
            min-width: 20px;
        }

        QTabBar::tab:selected {
            background: #0E94A0;
            color: white; 
        }

        QTabBar::tab {
            color: #000000; 
        }

        QTabBar::tab::!selected {
            color: #0E94A0; 
        }

        QTabBar::tab {
            font-size: 14px;
            font-weight: bold; 
            margin: 5px; 
            padding: 5px; 
            border: 2px solid #0E94A0;
            border-radius: 10px; 
        }

        QTabBar::tab > QLabel {
            qproperty-alignment: AlignCenter; 
           transform: translate(0,10px) rotate(-90deg);
                   
        }

        QTabBar::tab:selected > QLabel {
            qproperty-alignment: AlignCenter; 
            transform: translate(0,10px) rotate(-90deg);
             
        }

        """)
        
        
        default_icon_path = os.path.join(script_dir, '..', "Tools", "icons")
        if os.path.exists(default_icon_path):
            icon_size = (36, 36)  
            for i in range(self.tabWidgetResult.count()):
                tab_text = self.tabWidgetResult.tabText(i)
                icon_name = tab_text.lower().replace(" ", "_") + ".png"
                icon_path = os.path.join(default_icon_path, icon_name)

                if os.path.exists(icon_path):
                    icon = QIcon(icon_path)
                    icon_pixmap = icon.pixmap(icon_size[0], icon_size[1])
                    icon = QIcon(icon_pixmap)

                    self.tabWidgetResult.setTabIcon(i, icon)
                else:
                    print(f"Icon file not found: {icon_path}")
        else:
            print(f"Icon directory not found: {default_icon_path}")


        self.textEdit_3.setPlaceholderText(
            "Please enter the data in the following format:\n"
            "Email*; passwordEmail*; ipAddress*; port*; login; password; recovery_email,new_recovery_email"
        )
        self.textEdit_4.setPlaceholderText(
            "Specify the maximum number of operations to process"
        )
        
        
        for table in self.findChildren(QTableWidget):
            for col in range(table.columnCount()):
                table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.Stretch)
        self.tabWidgetResult = self.findChild(QTabWidget, "tabWidgetResult")
        self.load_initial_options()




    def save_json_to_file(self,json_data):
        traitement_file_path = os.path.join(template_directory, 'traitement.json')
        if not os.path.exists(template_directory):
            os.makedirs(template_directory)
        if os.path.exists(traitement_file_path):
            os.remove(traitement_file_path)
        try:
            with open(traitement_file_path, 'w', encoding='utf-8') as file:
                json.dump(json_data, file, ensure_ascii=False, indent=4)
            print(f"The file {traitement_file_path} has been successfully created.")
        except Exception as e:
            print(f"Error while creating the file {traitement_file_path}: {e}")





    def process_and_split_json(self, input_json):
        output_json = []  
        current_section = []
        current_start = None

        def finalize_section():
            if current_section:
                output_json.extend(current_section)

        for element in input_json:
            # تجاهل الحلقات الفارغة
            if element.get("process") == "loop" and "sub_process" in element and not element["sub_process"]:
                continue

            # بدء قسم جديد عند العثور على "open_inbox" أو "open_spam"
            if element.get("process") in ["open_inbox", "open_spam"]:
                finalize_section()
                current_section = [element]
                current_start = element.get("process")
                continue

            # معالجة الحلقات مع العمليات الفرعية
            if element.get("process") == "loop" and "sub_process" in element:
                sub_process = element["sub_process"]

                # تحديد العناصر المسموح بها بناءً على الحالة الحالية
                items = []
                if current_start == "open_inbox":
                    items = ["report_spam", "delete", "archive"]
                elif current_start == "open_spam":
                    items = ["not_spam", "delete", "report_spam"]

                # التحقق من وجود "select_all" في `sub_process`
                contains_select_all = any(sp.get("process") == "select_all" for sp in sub_process)

                # إذا كانت `select_all` موجودة، قم بإزالة "return_back" و "next"
                if contains_select_all:
                    sub_process = [
                        sp for sp in sub_process if sp.get("process") not in ["return_back", "next"]
                    ]

                # التحقق من وجود عناصر مطابقة في `items`
                contains_allowed_item = any(sp.get("process") in items for sp in sub_process)

                # إذا كانت تحتوي على عناصر مطابقة، قم بتحديث `sub_process`
                if contains_allowed_item:
                    sub_process = [
                        sp for sp in sub_process if sp.get("process") not in ["return_back", "next"]
                    ]

                # تحديث `sub_process`
                element["sub_process"] = sub_process

                # إضافة العنصر المعدل إلى القسم الحالي
                current_section.append(element)
                continue

            # إضافة العناصر الأخرى إلى القسم الحالي
            current_section.append(element)

        # إنهاء القسم الأخير
        finalize_section()
        return output_json






    def process_and_handle_last_element(self, input_json):
        output_json = []  

        for element in input_json:
            if element.get("process") == "loop" and "sub_process" in element:
                sub_process = element["sub_process"]

                if sub_process:
                    last_element = sub_process[-1] 

                    if last_element.get("process") in ["next"]:
                        output_json.append({
                            "process": "open_message",
                            "sleep": 2
                        })

                        sub_process = [sp for sp in sub_process if sp.get("process") != "open_message"]

                    elif last_element.get("process") not in ["delete", "archive", "not_spam", "report_spam"]:
                        for i, sp in enumerate(sub_process):
                            if sp.get("process") == "open_message":
                                sub_process[i] = {
                                    "process": "OPEN_MESSAGE_ONE_BY_ONE",
                                    "sleep": 0
                                }

                element["sub_process"] = sub_process

            output_json.append(element)
            
        return output_json


    




    def on_submit_button_clicked(self, window):
        new_versions = checkVersion()

        print(f"🔍 Debug: new_version = {new_versions}")  

        if not new_versions:
            print("❌ [ERROR] checkVersion() لم يُرجع أي بيانات! تأكد من عمله بشكل صحيح.")
            return  
        if 'version_interface' in new_versions:
            print("[INFO] Version mismatch detected. Closing current window...")
            window.close()

            print("[INFO] Starting download...")
            download_result = DownloadFile(new_versions)
            if download_result == -1:
                print("❌ [ERROR] Download failed. Aborting update.")
                return

            print("[INFO] Starting extraction...")
            extractAll(new_versions)

            print("[INFO] Launching new window...")
            launch_new_window()  
        else:
            print("[INFO] No interface update. Starting download of other tools...")
            download_result = DownloadFile(new_versions)
            if download_result == -1:
                print("❌ [ERROR] Download failed. Aborting update.")
                return

            print("[INFO] Starting extraction...")
            extractAll(new_versions)
        
        global current_hour, current_date

        output_json = [
            {
                "process": "login",  
                "sleep": 1  
            }
        ]

        if self.scenario_layout.count() == 0:
            QMessageBox.warning(window, "Error - Empty Scenario", "No actions added. Please add actions before submitting.")
            return

    

        if self.scenario_layout.count() == 0:
            QMessageBox.warning(window, "Error - Empty Scenario", "No actions have been added to the scenario. Please add at least one action before submitting.")
            return  
        
        i = 0
        while i < self.scenario_layout.count():
            widget = self.scenario_layout.itemAt(i).widget()  
            if widget:
                full_state = widget.property("full_state")
                hidden_id = full_state.get("id") if full_state else None

                if full_state and not full_state.get("showOnInit", False):
                    spinbox = next((child.value() for child in widget.children() if isinstance(child, QSpinBox)), 0)
                    output_json.append({
                        "process": hidden_id,
                        "sleep": spinbox
                    })
                    i += 1
                    continue

                checkbox = next((child for child in widget.children() if isinstance(child, QCheckBox)), None)
                if full_state and full_state.get("showOnInit", False) and checkbox:
                    sub_process = []  
                    spinbox = next((child.value() for child in widget.children() if isinstance(child, QSpinBox)), 0)

                    output_json.append({
                        "process": hidden_id,
                        "sleep": spinbox
                    })

                    if checkbox.isChecked():
                        search_value = next((child.text() for child in reversed(widget.children()) if isinstance(child, QLineEdit)), None)
                        
                        if output_json and output_json[-1]["process"] == "open_spam":
                            output_json.append({
                                "process": "search",
                                "value": f"in:spam {search_value}"
                            })
                            print("🟢 Action ajoutée : Recherche dans 'in:spam' avec la valeur :", search_value)
                        else:
                            output_json.append({
                                "process": "search",
                                "value": search_value
                            })
                            print("🔵 Action ajoutée : Recherche normale avec la valeur :", search_value)



                    i += 1
                    while i < self.scenario_layout.count():
                        sub_widget = self.scenario_layout.itemAt(i).widget()
                        if not sub_widget:
                            break

                        sub_full_state = sub_widget.property("full_state")
                        sub_hidden_id = sub_full_state.get("id") if sub_full_state else None
                        sub_spinbox = next((child.value() for child in sub_widget.children() if isinstance(child, QSpinBox)), 0)
                        sub_checkbox = next((child for child in sub_widget.children() if isinstance(child, QCheckBox)), None)

                        combobox = next((child for child in widget.children() if isinstance(child, QComboBox)), None)
                        combo_value = combobox.currentText() if combobox else None

                        if sub_full_state and sub_full_state.get("showOnInit", False):
                            break

                        if not sub_checkbox:
                            sub_process.append({
                                "process": sub_hidden_id,
                                "sleep": sub_spinbox
                            })
                        else:
                            break

                        i += 1

                    if len(sub_process) > 0:
                        action = "return_back" if combo_value == "Return back" else "next"
                        sub_process.append({
                            "process": action
                        })

                    limit_loop = next((child.text() for child in widget.children() if isinstance(child, QLineEdit)), "0")
                    try:
                        limit_loop = int(limit_loop)
                    except ValueError:
                        limit_loop = 0

                    output_json.append({
                        "process": "loop",
                        "check": "is_empty_folder",
                        "limit_loop": limit_loop,
                        "sub_process": sub_process
                    })
                    continue

                if full_state and full_state.get("showOnInit", False) and not checkbox:
                    spinbox = next((child.value() for child in widget.children() if isinstance(child, QSpinBox)), 0)
                    output_json.append({
                        "process": hidden_id,
                        "sleep": spinbox
                    })

            i += 1


        try:
            result = parse_input_to_json(window)

            if not result:  
                print("Invalid or empty JSON. Stopping the function.")
                return
            data_list, entered_number = result  

        except Exception as e:
            QMessageBox.critical(window, "Error", f"Error while parsing the JSON: {e}")
            return
        
        current_time = datetime.datetime.now()
        current_date = current_time.strftime("%Y-%m-%d")
        current_hour = current_time.strftime("%H-%M-%S") 
        print_json_detailed("JSON généré avant modification", output_json)
        modified_json = self.process_and_split_json(output_json)
        print_json_detailed("JSON généré après modification", modified_json)
        output_json_final = self.process_and_handle_last_element(modified_json)
        print_json_detailed("JSON généré après modification final", output_json_final)
        self.save_json_to_file(output_json_final)
        start_extraction(window, data_list , entered_number)
        read_result_and_update_list(window)




    def load_initial_options(self):
        """Charger les actions initiales qui ont showOnInit=true."""
        # Avant de charger l'état initial, supprimer les anciennes options si elles existent
        while self.reset_options_layout.count() > 0:
            item = self.reset_options_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Charger les nouvelles options initiales
        for key, state in self.states.items():
            if state.get("showOnInit", False):
                self.create_option_button(state)
        # self.state_stack.clear()
        # print("state_stack après suppression:", self.state_stack)






    def create_option_button(self, state):
        """Crée dynamiquement un bouton pour une action donnée."""
        default_icon_path = os.path.join(script_dir, '..' ,"Tools", "icons", "icon.png")

        button = QPushButton(state["label"], self.reset_options_container)
        button.setStyleSheet(self.template_button.styleSheet())
        button.setFixedSize(self.template_button.size())
        button.clicked.connect(lambda _, s=state: self.load_state(s))
        self.reset_options_layout.addWidget(button)
        
        button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        
        if os.path.exists(default_icon_path):
            button.setIcon(QIcon(default_icon_path))
        else:
            print(f"Default icon not found: {default_icon_path}")






    def load_state(self, state):
        """Charger une action et ses sous-actions."""
        self.state_stack.append(state)

        self.update_scenario(state.get("Template", ""), state)
        self.update_reset_options(state.get("actions", []))
        self.update_actions_color_and_handle_last_button()
        self.remove_copier()
        # print('state_stack Apres Add : ', self.state_stack)
        self.remove_INITAILE()





    def update_actions_color_and_handle_last_button(self):
        for i in range(self.scenario_layout.count()):
            widget = self.scenario_layout.itemAt(i).widget()
            if widget:
                # Mettre à jour le style des widgets sauf le dernier
                if i != self.scenario_layout.count() - 1:
                    widget.setStyleSheet("background-color: #ffffff; border: 1px solid #0E94A0; border-radius: 8px;")
                    buttons = [child for child in widget.children() if isinstance(child, QPushButton)]
                    if buttons:
                        last_button = buttons[-1]
                        last_button.setVisible(False)  # Cacher le bouton

                # Pour le dernier élément dans scenario_layout
                if i == self.scenario_layout.count() - 1:
                    widget.setStyleSheet("background-color: #0E94A0; border-radius: 8px;")

                    buttons = [child for child in widget.children() if isinstance(child, QPushButton)]
                    if buttons:
                        last_button = buttons[0]
                        last_button.setVisible(True)

                        # **Déconnecter toutes les connexions existantes avant d'ajouter une nouvelle**
                        try:
                            last_button.clicked.disconnect()
                        except TypeError:
                            pass  # Ignore l'erreur si aucune connexion n'existe
                        
                        last_button.clicked.connect(self.go_to_previous_state)







    def remove_copier(self):
        """
        1. Parcourir scenarioContainer pour trouver la dernière action contenant une QCheckBox et l'enregistrer dans lastactionLoop.
        2. Parcourir scenarioContainer à nouveau pour collecter les actions APRÈS lastactionLoop dans scenarioContainertableauAdd (enregistrer le tableau contient le texte du premier QLabel).
        3. Parcourir resetOptionsContainer pour collecter toutes les actions dans resetOptionsContainertableauALL (enregistrer le texte directement des QPushButton).
        4. Calculer la différence entre resetOptionsContainertableauALL et scenarioContainertableauAdd.
        5. Supprimer les actions de resetOptionsContainer qui existent dans les deux tableaux.
        6. Afficher les actions dans diff_texts pour debug.
        """
        lastactionLoop = None
        scenarioContainertableauAdd = []
        resetOptionsContainertableauALL = []
        found_checkbox = False

        # 1. Boucle pour trouver la dernière action contenant une QCheckBox
        for i in range(self.scenario_layout.count()):
            widget = self.scenario_layout.itemAt(i).widget()
            if widget:
                for child in widget.children():
                    if isinstance(child, QCheckBox):
                        lastactionLoop = i  # Sauvegarder l'index de l'action
                        found_checkbox = True
        
        if not found_checkbox:
            # print("Aucune action contenant QCheckBox trouvée.")
            return
        else:
            print("Action containing QCheckBox found.")

        # 2. Boucle pour collecter les actions APRÈS lastactionLoop (texte du premier QLabel)
        for i in range(lastactionLoop + 1, self.scenario_layout.count()):
            widget = self.scenario_layout.itemAt(i).widget()
            if widget:
                labels = [child.text() for child in widget.children() if isinstance(child, QLabel)]
                if labels:
                    scenarioContainertableauAdd.append(labels[0])

        # 3. Boucle pour collecter toutes les actions dans resetOptionsContainer (texte directement des QPushButton)
        for i in range(self.reset_options_layout.count()):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget and isinstance(widget, QPushButton):
                resetOptionsContainertableauALL.append(widget.text())

        # 4. Calculer la différence entre les deux tableaux
        diff_texts = [text for text in resetOptionsContainertableauALL if text not in scenarioContainertableauAdd]

        # Afficher les actions dans diff_texts pour debug
        # print("Actions dans diff_texts:", diff_texts)

        # 5. Supprimer les actions de resetOptionsContainer qui existent dans les deux tableaux
        for i in reversed(range(self.reset_options_layout.count())):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget and isinstance(widget, QPushButton):
                if widget.text() not in diff_texts:
                    widget.deleteLater()
                    self.reset_options_layout.removeWidget(widget)
        
        # 6. Afficher les tableaux pour debug
        # print("ScenarioContainerTableauAdd:", scenarioContainertableauAdd)
        # print("ResetOptionsContainerTableauALL:", resetOptionsContainertableauALL)







    def remove_INITAILE(self):
        """
        Supprimer les options contenant INITAILE=True de resetOptionsContainer 
        si elles ne sont pas présentes dans scenarioContainer.
        """
        scenarioContainertableauAdd = []  # Liste pour stocker les éléments avec INITAILE=True
        resetOptionsContainertableauALL = []  # Liste pour stocker les textes des boutons

        # 1. Collecter les éléments contenant "INITAILE=True" dans scenarioContainer
        # print("\n--- Collecte des éléments avec INITAILE=True ---")
        for i in range(self.scenario_layout.count()):
            widget = self.scenario_layout.itemAt(i).widget()
            if widget:
                sub_full_state = widget.property("full_state")
                sub_hidden_id = sub_full_state.get("INITAILE")
                if sub_hidden_id:
                    scenarioContainertableauAdd.append(sub_full_state.get("label"))  # Ajouter le premier QLabel au tableau
                    # print(f"Élément {i} : Texte QLabel ajouté = '{sub_full_state.get('label')}'")

        # print("scenarioContainertableauAdd (Textes des éléments avec INITAILE=True) :", scenarioContainertableauAdd)

        # 2. Collecter les textes visibles de tous les boutons dans resetOptionsContainer
        # print("\n--- Collecte des textes des boutons dans resetOptionsContainer ---")
        for i in range(self.reset_options_layout.count()):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget and isinstance(widget, QPushButton):
                resetOptionsContainertableauALL.append(widget.text())
                # print(f"Bouton {i} : texte = '{widget.text()}' ajouté à resetOptionsContainertableauALL")

        # print("resetOptionsContainertableauALL (Textes visibles des boutons) :", resetOptionsContainertableauALL)

        # 3. Calculer la différence entre les textes
        diff_texts = [text for text in resetOptionsContainertableauALL if text not in scenarioContainertableauAdd]
        # print("\n--- Textes qui seront supprimés (diff_texts) ---")
        # print("diff_texts :", diff_texts)

        # 4. Supprimer les options inutiles de resetOptionsContainer
        # print("\n--- Suppression des boutons de resetOptionsContainer ---")
        for i in reversed(range(self.reset_options_layout.count())):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget and isinstance(widget, QPushButton):
                if widget.text() not in diff_texts:
                    print(f"Suppression du bouton '{widget.text()}' de resetOptionsContainer")
                    widget.deleteLater()
                    self.reset_options_layout.removeWidget(widget)

        # 5. Afficher les résultats finaux pour vérification
        # print("\n--- Éléments supprimés et état final ---")
        # print("Actions supprimées contenant INITAILE=True :", scenarioContainertableauAdd)





    def update_reset_options(self, actions):
        """Mettre à jour les options en supprimant les anciennes et ajoutant les nouvelles."""
        # Supprimer les boutons actuels
        for i in reversed(range(self.reset_options_layout.count())):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()

        # Si la liste des actions est vide, recharger les options initiales
        if not actions:
            # print("No options detected. Resetting to initial state.")
            self.load_initial_options()
            return

        # Ajouter les nouveaux boutons pour chaque action
        for action_key in actions:
            state = self.states.get(action_key)
            if state:
                self.create_option_button(state)





    def handle_checkbox_state(self, state, lineedit):
        if lineedit:  
            if state == 2: 
                lineedit.show()
            else:  

                lineedit.hide()




    def update_scenario(self, template_name, state):
        """تحديث السيناريو باستخدام القالب المناسب."""
        template_frame = None

        if template_name == "Template1":
            template_frame = self.template_Frame1
        elif template_name == "Template2":
            template_frame = self.template_Frame2
        else:
            print(f"القالب {template_name} غير موجود.")
            return

        if template_frame:
            new_template = QFrame()
            new_template.setStyleSheet(template_frame.styleSheet())
            new_template.setMaximumHeight(51)
            new_template.setMinimumHeight(51)

            lineedits = []
            checkboxes = []
            first_label_updated = False

            for child in template_frame.children():
                if isinstance(child, QLabel):
                    new_label = QLabel(new_template)
                    if not first_label_updated:
                        new_label.setText(state.get("label", ""))
                        first_label_updated = True
                    else:
                        new_label.setText(child.text())
                    new_label.setStyleSheet(child.styleSheet())
                    new_label.setGeometry(child.geometry())
                elif isinstance(child, QPushButton):
                    new_button = QPushButton(child.text(), new_template)
                    new_button.setStyleSheet(child.styleSheet())
                    new_button.setGeometry(child.geometry())
                    new_button.clicked.connect(child.clicked)
                elif isinstance(child, QSpinBox):
                    new_spinbox = QSpinBox(new_template)
                    new_spinbox.setValue(child.value())
                    new_spinbox.setGeometry(child.geometry())
                    new_spinbox.setStyleSheet(child.styleSheet())
                elif isinstance(child, QLineEdit):
                    new_lineedit = QLineEdit(new_template)
                    new_lineedit.setText(child.text())
                    new_lineedit.setGeometry(child.geometry())
                    new_lineedit.setStyleSheet(child.styleSheet())
                    lineedits.append(new_lineedit)
                elif isinstance(child, QCheckBox):
                    new_checkbox = QCheckBox(child.text(), new_template)
                    new_checkbox.setChecked(child.isChecked())
                    new_checkbox.setGeometry(child.geometry())
                    new_checkbox.setStyleSheet(child.styleSheet())
                    checkboxes.append(new_checkbox)
                elif isinstance(child, QComboBox):
                    new_combobox = QComboBox(new_template)
                    new_combobox.setCurrentIndex(child.currentIndex())
                    new_combobox.addItems([child.itemText(i) for i in range(child.count())])
                    new_combobox.setGeometry(child.geometry())
                    new_combobox.setStyleSheet(child.styleSheet())

            for checkbox in checkboxes:
                if lineedits:
                    linked_lineedit = lineedits[-1]
                    linked_lineedit.hide()
                    checkbox.stateChanged.connect(
                        lambda state, lineedit=linked_lineedit: self.handle_checkbox_state(state, lineedit)
                    )
                else:
                    print("No QLineEdit currently available to link with QCheckBox.")

            new_template.setProperty("full_state", state)

            self.scenario_layout.addWidget(new_template)



    def go_to_previous_state(self):
        """العودة إلى الحالة السابقة وتنظيف المكدس والواجهة."""
        # print("\n####################################################################################################")
        
        # print("state_stack avant pop():")
        # for idx, state in enumerate(self.state_stack):
        #     print(f"{idx + 1}: ID = {state.get('id', 'N/A')}")
        # print("count state_stack avant pop():", len(self.state_stack))
        

        if len(self.state_stack) > 1:
            if self.scenario_layout.count() > 0:
                last_item = self.scenario_layout.takeAt(self.scenario_layout.count() - 1)
                if last_item.widget():
                    last_item.widget().deleteLater()
            
            # حذف آخر حالة من المكدس
            self.state_stack.pop()

            # طباعة الـ ID لكل عنصر في state_stack بعد pop
            # print("\nstate_stack Apres pop():")
            # for idx, state in enumerate(self.state_stack):
            #     print(f"{idx + 1}: ID = {state.get('id', 'N/A')}")
            # print("count state_stack Apres pop():", len(self.state_stack))

            # الحالة السابقة بعد الحذف
            previous_state = self.state_stack[-1]
            # print("state previous : ID =", previous_state.get("id", "N/A"))

            # تحديث الخيارات في resetOptionsContainer
            self.update_reset_options(previous_state.get("actions", []))
        else:
            # عند العودة إلى الحالة الأولية
            print("Revenir à l'état initial.")
            self.state_stack.clear()
            while self.scenario_layout.count() > 0:
                last_item = self.scenario_layout.takeAt(0)
                if last_item.widget():
                    last_item.widget().deleteLater()

            self.load_initial_options()

        # إعادة ضبط الألوان والتأكد من عرض الزر الصحيح
        self.update_actions_color_and_handle_last_button()
        self.remove_copier()












def verify_key(encrypted_key: str, secret_key: str) -> bool:
    try:
        fernet = Fernet(secret_key.encode())
        decrypted = fernet.decrypt(encrypted_key.encode())
        if decrypted == b"authorized":
            return True
        else:
            print("Le contenu déchiffré n'est pas valide.")
            return False
    except Exception as e:
        print("La vérification de la clé a échoué :", e)
        return False



def main():
    if len(sys.argv) < 3:
        print("Clés insuffisantes fournies, arrêt du programme.")
        sys.exit(1)
    else:
        encrypted_key = sys.argv[1]
        secret_key = sys.argv[2]
        if not verify_key(encrypted_key, secret_key):
            print("Clé invalide fournie, arrêt du programme.")
            sys.exit(1)
        else:
            print("[INFO] Clé validée, lancement du programme.")

    check_directory(script_dir, "script_dir")
    check_directory(base_directory, "base_directory")
    check_directory(template_directory, "template_directory")

    json_path = os.path.join(script_dir,'..',"Tools", "action.json")
    print('json_path :', json_path)

    with open(json_path, "r") as file:
        json_data = json.load(file)

    if json_data is None:
        print("Échec du chargement de action.json. Arrêt du programme...")
        sys.exit(1)

    app = QApplication([])
    window = MainWindow(json_data)
    window.stopButton.clicked.connect(lambda: stop_all_processes(window))
    window.setWindowTitle("Automatisation des Processus Gmail")
    window.show()
    app.exec()

if __name__ == "__main__":
    main()
