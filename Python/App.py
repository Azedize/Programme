import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from PyQt6.QtWidgets import *
from cryptography.fernet import Fernet
from PyQt6.QtGui import QIcon , QCursor 
from PyQt6.QtCore import Qt , QTimer , QThread, pyqtSignal , QSize
import winreg as reg
from PyQt6 import  uic ,  QtWidgets, QtGui, QtCore
import shutil
import signal
import time
import subprocess
import uuid
import random
import string                           
import re
import datetime
import requests
import sys
import zipfile
import traceback
import urllib3
import psutil
import PyQt6
from typing import Optional, Dict
import configparser
from platformdirs import user_downloads_dir
import win32gui       
import win32process
import win32con
import tempfile
urllib3.disable_warnings()



firefox_launch = []
logs= []
process_pids = []
notification_badges = {}
extraction_thread = None 
close_Browser_thread = None 
new_version = None
logs_running = True  
selected_Browser_Global=None

script_dir = os.path.dirname(os.path.realpath(__file__))
base_directory = os.path.join(script_dir, '..', 'tools', 'ExtensionEmail')
template_directory_Chrome = os.path.join(script_dir, '..', 'tools', 'ExtensionTemplateChrome')
template_directory_Firefox = os.path.join(script_dir, '..', 'tools', 'ExtensionTemplateFirefox')





# 📦 Fonction pour s'assurer que Node.js est installé.
# Si ce n'est pas le cas, il tente de l'installer via Chocolatey (et installe aussi npm).
def ensure_node_installed():
    if shutil.which("node") is not None:
        print("✅ Node.js est déjà installé.")
        return True

    print("❌ Node.js n'est pas installé. Tentative d'installation via Chocolatey...")

    if shutil.which("choco") is None:
        print("🔍 Chocolatey non trouvé. Installation...")
        try:
            subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "Set-ExecutionPolicy Bypass -Scope Process -Force; "
                    "[System.Net.ServicePointManager]::SecurityProtocol = "
                    "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; "
                    "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
                ],
                check=True
            )
            print("✅ Chocolatey installé.")
        except subprocess.CalledProcessError:
            print("❌ Échec de l'installation de Chocolatey.")
            return False

    try:
        subprocess.run(["choco", "install", "nodejs-lts", "-y"], check=True)
        print("✅ Node.js installé avec succès.")
        return True
    except subprocess.CalledProcessError:
        print("❌ Échec de l'installation de Node.js.")
        return False







# Cette fonction retourne le chemin de l'exécutable web-ext s'il est trouvé
def get_web_ext_path():
    path = shutil.which("web-ext")
    if path:
        return path
    else:
        return None




# 🔍📦 Vérifie si 'web-ext' est installé, sinon l'installe globalement via npm
def ensure_web_ext_installed():
    if not ensure_node_installed():
        print("⚠️ Impossible de continuer sans Node.js.")
        return

    if shutil.which('npm') is None:
        print("❌ npm n'est pas installé. Vérifiez l'installation de Node.js.")
        return

    if shutil.which('web-ext') is not None:
        print("✅ 'web-ext' est déjà installé.")
        return

    print("🔍 'web-ext' n'est pas installé. Installation via npm...")
    try:
        subprocess.run('npm install --global web-ext', check=True, shell=True)
        print("✅ 'web-ext' a été installé avec succès.")
    except subprocess.CalledProcessError:
        print("❌ Échec de l'installation de 'web-ext' via npm.")





# 🔍  Analyse le fichier profiles.ini de Firefox et retourne un dictionnaire des profils existants avec leurs chemins complets
def parse_firefox_profiles_ini() -> Dict[str, str]:
    appdata = os.getenv('APPDATA')
    ini_path = os.path.join(appdata, 'Mozilla', 'Firefox', 'profiles.ini')
    config = configparser.ConfigParser()
    config.read(ini_path, encoding='utf-8')

    profiles = {}
    base_dir = os.path.dirname(ini_path)
    for section in config.sections():
        if section.startswith('Profile'):
            name = config.get(section, 'Name', fallback=None)
            path = config.get(section, 'Path', fallback=None)
            is_rel = config.getint(section, 'IsRelative', fallback=1)
            if name and path:
                full_path = os.path.join(base_dir, path) if is_rel else path
                profiles[name] = os.path.normpath(full_path)
    return profiles








# 🛠️ Crée un profil Firefox avec un nom donné s'il n'existe pas déjà, et affiche les profils avant/après la création
def create_firefox_profile(profile_name: str) -> Optional[str]:
    # Vérifier la présence de firefox.exe
    path_firefox = get_browser_path("firefox.exe")
    if not path_firefox:
        print("❌ Firefox introuvable dans le registre.")
        return None
    print(f"🧭 Firefox détecté : {path_firefox}\n")

    # Afficher les profils existants avant la création
    print("=== Profils existants AVANT la création ===")
    existing_profiles = parse_firefox_profiles_ini()
    for name, path in existing_profiles.items():
        print(f" - {name}: {path}")
    print()

    # Définir le chemin de base pour les profils: script_dir/firefox
    path_profile = os.path.join(script_dir,'..','Tools', 'Profiles', 'firefox')
    print(f"📁 Répertoire de base des profils : {path_profile}")

    # Vérifier et créer le répertoire racine des profils si nécessaire
    if not os.path.exists(path_profile):
        print(f"🔧 Création du dossier racine des profils : {path_profile}")
        os.makedirs(path_profile, exist_ok=True)

    # Chemin complet du profil spécifique
    custom_dir = os.path.join(path_profile, profile_name)
    print("=== VÉRIFICATION DANS path_profile ===")
    if os.path.isdir(custom_dir):
        print(f"✅ Profil '{profile_name}' déjà existant : {custom_dir}")
        return custom_dir

    # Créer le profil via subprocess
    print(f"🔧 Création du profil '{profile_name}' dans {custom_dir}\n")
    cmd = f"{profile_name} {custom_dir}"
    result = subprocess.run(
        [path_firefox, '--CreateProfile', cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # Afficher résultats
    print("🪵 stdout :", result.stdout.strip() or "<vide>")
    print("🪵 stderr :", result.stderr.strip() or "<vide>", "\n")

    if result.returncode != 0:
        print(f"❌ Échec de la création (code {result.returncode})")
        return None

    # Vérifier l'existence après création
    if os.path.isdir(custom_dir):
        print(f"✅ Profil créé avec succès : {custom_dir}")
    else:
        print("❌ Le dossier du profil n'a pas été trouvé après création.")
        return None

    # Afficher les profils existants après la création
    print("=== Profils existants APRÈS la création ===")
    updated_profiles = parse_firefox_profiles_ini()
    for name, path in updated_profiles.items():
        print(f" - {name}: {path}")
    print()

    return custom_dir











# ✅ Vérifie si une clé chiffrée est valide en la déchiffrant avec une clé secrète
def verify_key(encrypted_key: str, secret_key: str) -> bool:
    try:
        fernet = Fernet(secret_key.encode())
        decrypted = fernet.decrypt(encrypted_key.encode())
        if decrypted == b"authorized":
            return True
        else:
            return False
    except Exception as e:
        return False






# 🚀 Lance discrètement un nouveau script Python (checkV3.pyc) dans une nouvelle fenêtre sans console
def launch_new_window():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    target_dir = os.path.dirname(parent_dir)
    script_path = os.path.join(target_dir, "checkV3.pyc")
    time.sleep(1)

    if not os.path.exists(script_path):
        return None  

    time.sleep(1)

    try:
        python_executable = sys.executable
        command = [python_executable, script_path]
        process = subprocess.Popen(
            command,
            creationflags=subprocess.CREATE_NO_WINDOW ,
            close_fds=True
        )
        stdout, stderr = process.communicate()  
        if process.returncode != 0:
            try:
                print(f"   📝 [ERROR] Standard Error: {stderr.decode(encoding='utf-8', errors='replace')}") 
            except Exception as decode_err:
                print(f"   ⚠️ [ERROR] Failed to decode stderr: {decode_err}")
                print(f"   📝 [ERROR] Raw stderr: {stderr}") 
            try:
                print(f"   📤 [INFO] Standard Output: {stdout.decode(encoding='utf-8', errors='replace')}") 
            except Exception as decode_err:
                print(f"   ⚠️ [ERROR] Failed to decode stdout: {decode_err}")
                print(f"   📤 [INFO] Raw stdout: {stdout}") 
            return None

        time.sleep(1)

    except Exception as e:
        print(f"💥 [CRITICAL ERROR] Failed to launch: {str(e)}")
        print("💡 [TIP] Check execution permissions or file integrity.")
        print(f"   📌 [ERROR] Details: {traceback.format_exc()}")  
        return None

    return target_dir






# 📝 Ajoute un message au journal global 'logs'
def log_message(text):
    global logs
    logs.append(text)





# 📦 Télécharge le fichier ZIP du dépôt GitHub, le remplace si déjà présent, et l’extrait
def DownloadFile(new_versions):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(script_dir)
    path_DownloadFile = os.path.dirname(parent_dir)

    local_filename = os.path.join(path_DownloadFile, "Programme-main.zip")  

    try:
        if os.path.exists(local_filename):
            os.remove(local_filename)
    except Exception:
        return -1

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/39.0.2171.95 Safari/537.36'
    }

    url = "https://github.com/Azedize/Programme/archive/refs/heads/main.zip"

    try:
        response = requests.get(url, stream=True, headers=headers, verify=False)
        if response.status_code != 200:
            return -1

        total_size = int(response.headers.get('content-length', 0))
        
        with open(local_filename, "wb") as handle:
            for chunk in response.iter_content(chunk_size=4096):
                if chunk:
                    handle.write(chunk)

        tools_dir = "Programme-main"
        tools_dir_path = os.path.join(path_DownloadFile, tools_dir)
        
        if os.path.exists(tools_dir_path):
            try:
                shutil.rmtree(tools_dir_path)
            except Exception:
                return -1

        try:
            with zipfile.ZipFile(local_filename, 'r') as zip_ref:
                zip_ref.extractall(path_DownloadFile)
        except Exception:
            return -1

    except requests.exceptions.RequestException:
        return -1
    except Exception:
        return -1
    return 0





# 📂 Extrait le contenu du fichier ZIP téléchargé et le supprime s’il existe
def extractAll():
    try:
        time.sleep(1)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(script_dir)
        path_DownloadFile = os.path.dirname(parent_dir) 

        local_filename = os.path.join(path_DownloadFile, "Programme-main.zip")  



        if not os.path.exists(local_filename):
            return -1 

        try:
            with zipfile.ZipFile(local_filename, 'r') as zip_ref:
                zip_ref.extractall(path_DownloadFile)


            try:
                os.remove(local_filename)
            except PermissionError as e:
                print(f"⚠️ [WARNING] Impossible de supprimer le fichier ZIP: {e}")
            except Exception as e:
                traceback.print_exc()

        except zipfile.BadZipFile:
            return -1
        except Exception as e:
            traceback.print_exc()
            return -1

    except Exception as e:
        traceback.print_exc()
        return -1
    return 0 





# 🔍 Vérifie les versions distantes et locales des composants, puis signale les mises à jour nécessaires
def checkVersion():
    url = "https://www.dropbox.com/scl/fi/78a38bc4papwzlw80hxti/version.json?rlkey=n7dx5mb8tcctvprn0wq4ojw7m&st=z6vzw0ox&dl=1"

    try:
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            version_updates = {}

            server_version_python = data.get("version_python")
            server_version_interface =data.get("version_interface")
            server_version_Extention =data.get("version_Extention")
            if not server_version_python or not server_version_interface or not server_version_Extention :
                os.system("pause")
                exit()
            
            script_dir = os.path.dirname(os.path.abspath(__file__))

            client_version_path_Python = os.path.join(script_dir, "version.txt")
            client_version_path_Extention = os.path.join(os.path.dirname(script_dir), "tools", "version.txt") 
            client_version_path_interface = os.path.join(os.path.dirname(script_dir), "interface", "version.txt") 

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

            if server_version_python != client_version_Python:
                version_updates["version_python"] = server_version_python

            if server_version_interface != client_version_interface:
                version_updates["version_interface"] = server_version_interface

            if server_version_Extention != client_version_Extention:
                version_updates["version_extention"] = server_version_Extention

            if version_updates:
                log_message(f"[INFO] Detected new version(s):\n\t {version_updates}")
                return version_updates
            else:
                log_message("[INFO] All software versions are up to date.")
                return None
        else:
            os.system("pause")
            exit()

    except Exception as e:
        traceback.print_exc()
        os.system("pause")
        exit()






# 📊 Lit les résultats depuis un fichier et met à jour l'affichage de l'interface avec les emails par statut
def read_result_and_update_list(window):
    result_file_path = os.path.join(os.path.dirname(__file__), "..", "tools", "result.txt")

    if not os.path.exists(result_file_path):
        show_critical_message(window, "Information", "No email messages have been processed.\nCheck the filter criteria or new data.")
        return

    errors_dict = {}
    notifications = {}

    try:
        with open(result_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        with open(result_file_path, 'w', encoding='utf-8') as file:
            file.truncate(0)

        if not lines:
            QMessageBox.warning(window, "Warning", "No results available.")
            return

        completed_count = 0
        no_completed_count = 0

        for line in lines:
            line = line.strip()
            if not line:
                continue

            parts = line.split(":")
            if len(parts) != 4:
                continue

            session_id, pid, email, status = parts
            status = status.strip()

            if status not in errors_dict:
                errors_dict[status] = []
            errors_dict[status].append(email)

            if status == "completed":
                completed_count += 1
            else:
                no_completed_count += 1


        interface_tab_widget = window.findChild(QTabWidget, "interface_2")
        if interface_tab_widget:
            result_found = False
            for i in range(interface_tab_widget.count()):
                tab_text = interface_tab_widget.tabText(i)
                if tab_text == "Result":
                    new_tab_text = f"Result ({completed_count} completed / {no_completed_count} not completed)"
                    interface_tab_widget.setTabText(i, new_tab_text)
                    result_found = True
                    break
            if not result_found:
                return
        else:
            return

        result_tab_widget = window.findChild(QTabWidget, "tabWidgetResult")
        if not result_tab_widget:
            return

        status_list = ["bad_proxy", "completed", "account_closed", "password_changed",
                       "recoverychanged", "Activite_suspecte", "validation_capcha" , "restore_account"]

        for status in status_list:
            tab_widget = result_tab_widget.findChild(QWidget, status)
            if tab_widget:
                tab_index = result_tab_widget.indexOf(tab_widget)

                list_widgets = tab_widget.findChildren(QListWidget)

                if list_widgets:
                    list_widget = list_widgets[0]
                    list_widget.clear()

                    if status in errors_dict and errors_dict[status]:
                        list_widget.addItems(errors_dict[status])
                        list_widget.scrollToBottom()
                        list_widget.show()
                        count = len(errors_dict[status])
                        notifications[tab_index] = count
                        add_notification_badge(result_tab_widget, tab_index, count)

                        message_label = tab_widget.findChild(QLabel, "no_data_message")
                        if message_label:
                            message_label.deleteLater()
                    else:
                        list_widget.addItem("⚠ No email data available for this category.\nPlease check again later.")
                        list_widget.show()
        result_tab_widget.currentChanged.connect(remove_notification)
    except Exception as e:
        QMessageBox.critical(window, "Error", f"An error occurred while displaying the result: {e}")







# 🧹 Supprime les badges de notification d'un onglet donné quand il est sélectionné
def remove_notification(index):
    if index in notification_badges:
        badge = notification_badges.pop(index, None)
        if badge:
            badge.deleteLater()





# 🔔 Ajoute un badge de notification rouge sur un onglet spécifique pour indiquer le nombre de résultats
def add_notification_badge(tab_widget, tab_index, count):
    if tab_index in notification_badges:
        notification_badges[tab_index].deleteLater()
        del notification_badges[tab_index]

    tab_bar = tab_widget.tabBar()
    tab_rect = tab_bar.tabRect(tab_index)

    if tab_widget.tabPosition() in [QTabWidget.TabPosition.West, QTabWidget.TabPosition.East]:
        badge_x = tab_rect.right() - 14 
        badge_y = tab_rect.top() + 2  
    else:  
        badge_x = tab_rect.right() - 14
        badge_y = tab_rect.top() + 2

    badge_label = QLabel(f"{count}", tab_widget)
    badge_label.setStyleSheet("""
        background-color: #d90429;
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
    except Exception as e:
        print(f"❌ Erreur lors de l'ajout du badge : {e}")






# 🆔 Génère un ID de session aléatoire basé sur UUID (tronqué à la longueur désirée)
def generate_session_id(length=5):
    if length <= 0:
        raise ValueError("The length must be a positive integer.")
    return str(uuid.uuid4()).replace("-", "")[:length]





# 🧪 Exemple de génération d'un ID de session
session_id = generate_session_id()





# ❗ Affiche une boîte de dialogue critique (QMessageBox) avec un style personnalisé
def show_critical_message(window, title, message):
    msg = QMessageBox(window)
    msg.setIcon(QMessageBox.Icon.Critical)
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.setStyleSheet("""
        QMessageBox {
            background-color: #ffffff;
            color: #333333;
            font-family: 'Times', 'Times New Roman', serif;
            font-size: 15px;
            border: 1px solid transparent;
            border-radius: 10px;
            padding: 20px;
        }
        QMessageBox QLabel {
            color: #333333;
            font-family: 'Times', 'Times New Roman', serif;
            font-size: 15px;
        }
        QMessageBox QPushButton {
            background-color: #e74c3c;
            color: white;
            font-family: 'Times', 'Times New Roman', serif;
            border: none;
            border-radius: 5px;
            padding: 8px;
            font-size: 15px;
            font-weight: 600;
            min-width: 60px;
            text-align: center;
        }
        QMessageBox QPushButton:hover {
            background-color: #c0392b;
        }
        QMessageBox QPushButton:pressed {
            background-color: #a93226;
        }
    """)
    msg.exec()






# 🔐 Génère un mot de passe sécurisé aléatoire pour Gmail avec au moins 12 caractères
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







# 🔍 Récupère le chemin absolu d'un exécutable de navigateur en consultant le registre Windows.
def get_browser_path(exe_name: str) -> Optional[str]:
    key_app_paths = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}"
    hives = [
        (reg.HKEY_LOCAL_MACHINE, reg.KEY_READ | reg.KEY_WOW64_32KEY),
        (reg.HKEY_LOCAL_MACHINE, reg.KEY_READ | reg.KEY_WOW64_64KEY),
        (reg.HKEY_CURRENT_USER,  reg.KEY_READ)
    ]
    for hive, access in hives:
        try:
            with reg.OpenKey(hive, key_app_paths, 0, access) as key_obj:
                path, _ = reg.QueryValueEx(key_obj, None)
                return path
        except FileNotFoundError:
            continue
    return None






# 🧩 Génère une extension Chrome personnalisée en copiant et modifiant des fichiers modèles selon les données de l'utilisateur.
def create_extension_for_email(email, password, host, port, user, passwordP, recovry, new_password, new_recovry, IDL ,selected_Browser):
    print(f"Function create_extension_for_email called with selected_Browser: {selected_Browser}")
    template_directory = (
        template_directory_Firefox
        if selected_Browser.lower() == "firefox"
        else template_directory_Chrome
    )
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

    content_js_path = os.path.join(email_folder, "actions.js")
    if os.path.exists(content_js_path):
        with open(content_js_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        content = content.replace("__IDL__", IDL).replace("__email__", email)
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
                    .replace("__IDL__", IDL)
                    .replace("__email__", email))
        with open(background_js_path, 'w', encoding='utf-8') as file:
            file.write(content)

    gmail_process_js_path = os.path.join(email_folder, "gmail_process.js")
    if os.path.exists(gmail_process_js_path):
        with open(gmail_process_js_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        content = (content.replace("__email__", f'{email}')
                          .replace("__password__", f'{password}')
                          .replace("__recovry__", f'{recovry}')
                          .replace("__newPassword__", f'{new_password}')
                          .replace("__newRecovry__", f'{new_recovry}'))
        with open(gmail_process_js_path, 'w', encoding='utf-8') as file:
            file.write(content)







# 📝 Enregistre de façon unique le PID, l'email et l'ID de session dans un fichier texte lié à l'email.
def add_pid_to_text_file(pid, email):
    print(f"🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴 Function add_pid_to_text_file called with PID: {pid}, Email: {email}")
    text_file_path = os.path.join(base_directory, email , "data.txt")

    os.makedirs(os.path.dirname(text_file_path), exist_ok=True)

    if os.path.exists(text_file_path):
        with open(text_file_path, 'r', encoding='utf-8') as file:
            existing_entries = set(file.read().splitlines())
    else:
        existing_entries = set()

    print(f"PID: {pid}, Email: {email}")
    entry = f"{pid}:{email}:{session_id}" 

    if entry not in existing_entries:
        with open(text_file_path, 'w', encoding='utf-8') as file:
            file.write(f"{entry}\n")






def get_firefox_profiles_in_use():
    """Retourne les profils Firefox actuellement utilisés (lockés)"""
    base_path = os.path.join(script_dir, ".." ,"tools", "Profiles", "firefox")

    profiles = []
    if not os.path.exists(base_path):
        return profiles

    for folder in os.listdir(base_path):
        profile_path = os.path.join(base_path, folder)
        lock_file = os.path.join(profile_path, 'parent.lock')
        if os.path.isdir(profile_path) and os.path.exists(lock_file):
            profiles.append({'name': folder, 'path': profile_path})
    return profiles

def get_profile_by_pid(pid, active_profiles):
    """Associe un PID Firefox à un profil actif"""
    try:
        proc = psutil.Process(pid)
        for f in proc.open_files():
            for profile in active_profiles:
                if os.path.commonpath([f.path, profile['path']]) == profile['path']:
                    return profile
                if profile['name'] in f.path:
                    return profile
    except Exception:
        pass
    return None


def get_firefox_windows():
    active_profiles = get_firefox_profiles_in_use()
    windows = []

    def window_callback(hwnd, _):
        if win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd) == 'MozillaWindowClass':
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                profile = get_profile_by_pid(pid, active_profiles)
                if profile:
                    windows.append({
                        'hwnd': hwnd,
                        'title': win32gui.GetWindowText(hwnd),
                        'pid': pid,
                        'profile': profile['name']
                    })
            except Exception:
                pass
        return True

    win32gui.EnumWindows(window_callback, None)
    return windows

def close_windows_by_profiles(profiles_list):
    noms_profils = [p["profile"] for p in profiles_list]  
    
    print(f"\n🔎 Recherche des fenêtres pour les profils : {', '.join(noms_profils)}")
    all_windows = get_firefox_windows()
    

    target_windows = [w for w in all_windows if w["profile"] in noms_profils]

    if not target_windows:
        print("❌ Aucune fenêtre trouvée pour ces profils")
        return


    for window in target_windows:
        try:
            win32gui.PostMessage(window["hwnd"], win32con.WM_CLOSE, 0, 0)
            print(f"✅ Fermeture : {window['profile']} - {window['title']}")
        except Exception as e:
            print(f"❌ Erreur avec {window['profile']} : {str(e)}")


def stop_all_processes(window):
    global extraction_thread, close_Browser_thread, process_pids, logs_running, selected_Browser_Global

    print("Stopping all processes...")
    logs_running = False

    if extraction_thread:
        print("Stopping extraction thread...")
        extraction_thread.stop_flag = True
        extraction_thread.wait()
        extraction_thread = None
        print("Extraction thread stopped.")


    if close_Browser_thread:
        print("Stopping close Chrome thread...")
        close_Browser_thread.stop_flag = True
        close_Browser_thread.wait()
        close_Browser_thread = None
        print("Close Chrome thread stopped.")

    if extraction_thread and extraction_thread.isRunning():
        print("Waiting for extraction thread to finish before updating UI...")
        extraction_thread.finished.connect(
            lambda: QTimer.singleShot(100, 
            lambda: read_result_and_update_list(window))
        )

    if selected_Browser_Global != "firefox":
        for pid in process_pids[:]:
            try:
                print(f"Attempting to terminate process with PID {pid}...")
                process = psutil.Process(pid)
                process.terminate()
                process.wait(timeout=5)
                print(f"Process {pid} terminated successfully.")
            except psutil.NoSuchProcess:
                print(f"The process with PID {pid} no longer exists.")
            except psutil.AccessDenied:
                print(f"Permission denied to terminate the process with PID {pid}.")
            except Exception as e:
                print(f"An error occurred while terminating PID {pid}: {e}")
            finally:
                if pid in process_pids:
                    process_pids.remove(pid)
                    print(f"PID {pid} removed from process list.")
    else:
            try:
                close_windows_by_profiles(firefox_launch)
            except Exception as e:
                print(f"⚠️ Erreur lors de la fermeture des profils Firefox: {e}")
 
            finally:
                for pid in process_pids[:]:
                    process_pids.remove(pid)
                    print(f"PID {pid} removed from process list.")











# 🚀 Lance un thread pour fermer automatiquement les processus Chrome actifs.
def launch_close_chrome(selected_Browser ):
    global close_Browser_thread
    close_Browser_thread = CloseBrowserThread( selected_Browser)
    close_Browser_thread.progress.connect(lambda msg: print(msg))
    close_Browser_thread.start()






# 📥 Analyse l'entrée utilisateur au format texte, la valide et la convertit en liste de dictionnaires JSON pour traitement.
def parse_input_to_json(window):
    input_data = window.textEdit_3.toPlainText().strip()
    entered_number = window.textEdit_4.toPlainText().strip()

    if not input_data:
        show_critical_message(
            window,
            "Error - Missing Data",
            "Please enter the required information before proceeding."
        )
        return

    if not entered_number.isdigit():
        show_critical_message(
            window,
            "Error - Invalid Input",
            "Please enter a valid numerical value in the number field."
        )
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
            show_critical_message(
                window,
                "Error - Invalid Range",
                f"Please enter a value between 1 and {len(data_list)}.\n"
                f"Selected entries cannot exceed available items."
            )
            return

        return data_list, entered_number

    except Exception as e:
        show_critical_message(
            window,
            "Operation Failed - System Error",
            f"Critical failure during data processing:\n"
            f"(Technical details: {str(e).capitalize()})"
        )
        return







# 🔍 Recherche la première clé disponible dans email_data parmi une liste de clés possibles et_
def get_key_value( email_data, possible_keys):
    for key in possible_keys:
        if key in email_data:
            if not email_data[key]:  
                return key
            return email_data[key]
    return possible_keys[0]







# 🛠️ Démarre le processus d'extraction en lançant le thread principal avec les paramètres utilisateur, après validation des entrées et préparation de l'environnement.
def start_extraction(window, data_list, entered_number , selected_Browser):
    global extraction_thread 

    logs_directory = os.path.join(script_dir, '..', 'Tools', 'logs')
    
    if not os.path.exists(logs_directory):
        os.makedirs(logs_directory)
    
    try:
        entered_number = int(entered_number)
    except ValueError:
        show_critical_message(
            window,
            "Input Error - Invalid Format",
            "Numeric value required. Please check your input and try again."
        )
        return

    email_count = len(data_list)
    if entered_number > email_count:
        show_critical_message(
            window,
            "Range Error - Exceeded Limit",
            f"Maximum allowed entries: {email_count}\n"
            f"Please enter a value between 1 and {email_count}."
        )
        return
    
    # submit_button = window.findChild(QPushButton, "submitButton")  
    # if submit_button:
    #     submit_button.setEnabled(False)
    #     submit_button.setStyleSheet("""
    #         QPushButton {
    #             background-color: #a0a0a0; /* Greyed-out background */
    #             color: #c0c0c0;          /* Greyed-out text */
    #             border: 1px solid #808080; /* Grey border */
    #             border-radius: 5px;
    #         }
    #     """)


    launch_close_chrome(selected_Browser)
    browser_path = (
        get_browser_path("chrome.exe") if selected_Browser == "chrome" 
        else get_browser_path("firefox.exe") if selected_Browser == "firefox" 
        else get_browser_path("msedge.exe") if selected_Browser == "edge" 
        else get_browser_path("dragon.exe")  
    )

    if selected_Browser == "firefox":
        ensure_web_ext_installed()

    print("browser path   :",   browser_path    or "Non trouvé")

    # return browser_path;
    extraction_thread = ExtractionThread(
        data_list, session_id, entered_number, browser_path, base_directory, window ,selected_Browser
    )
    extraction_thread.progress.connect(lambda msg: print(msg))
    extraction_thread.finished.connect(lambda: QMessageBox.information(window, "Terminé", "L'extraction est terminée."))
    extraction_thread.stopped.connect(lambda msg: QMessageBox.warning(window, "Arrêté", msg))
    extraction_thread.start()







# 🔍 Trouve la fenêtre principale d'un processus donné en utilisant son PID.
def find_main_window_handle( target_pid):
    """Trouve le handle de la fenêtre principale de Firefox et affiche ses informations détaillées."""
    def enum_windows_callback(hwnd, hwnds):
        # Vérifier si la fenêtre est visible et a un titre
        if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd) != '':
            # Obtenir IDs de thread et de processus
            thread_id, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid == target_pid:
                # Récupérer les informations de la fenêtre
                title = win32gui.GetWindowText(hwnd)
                class_name = win32gui.GetClassName(hwnd)
                rect = win32gui.GetWindowRect(hwnd)
                style = win32gui.GetWindowLong(hwnd, win32con.GWL_STYLE)
                ex_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)

                # Afficher toutes les informations collectées
                print(f"[INFO] HWND           : {hwnd}")
                print(f"       Titre          : {title}")
                print(f"       Classe         : {class_name}")
                print(f"       PID            : {pid}")
                print(f"       Thread ID      : {thread_id}")
                print(f"       Position/Size  : (left={rect[0]}, top={rect[1]}, right={rect[2]}, bottom={rect[3]})")
                print(f"       Style          : 0x{style:08X}")
                print(f"       Ex-Style       : 0x{ex_style:08X}")

                hwnds.append(hwnd)
        return True

    hwnds = []
    # Enumérer les fenêtres pour trouver la fenêtre principale
    win32gui.EnumWindows(enum_windows_callback, hwnds)
    return hwnds[0] if hwnds else None










# Thread pour afficher les logs en temps réel depuis une liste partagée.
# Émet un signal log_signal à chaque nouvelle entrée de log.
class LogsDisplayThread(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self, logs, parent=None):
        super().__init__(parent)
        self.logs = logs
        self.stop_flag = False

    def run(self):
        """Boucle d'affichage continue tant que logs_running est actif."""
        global logs_running 
        while logs_running: 
            if self.logs:
                log_entry = self.logs.pop(0)
                self.log_signal.emit(log_entry)
            else:
                time.sleep(1)  

    def stop(self):
        self.stop_flag = True
        self.wait()











# Thread responsable du traitement de l'extraction des emails.
# Gère l'exécution des navigateurs avec les extensions, l'enregistrement des logs,
# et la gestion des processus.
class ExtractionThread(QThread):

    progress = pyqtSignal(str)  
    finished = pyqtSignal()  
    stopped = pyqtSignal(str)

    def __init__(self, data_list, session_id, entered_number, Browser_path, base_directory, main_window ,selected_Browser):  
        super().__init__()
        self.data_list = data_list  
        self.session_id = session_id  
        self.entered_number = entered_number  
        self.Browser_path = Browser_path 
        self.base_directory = base_directory  
        self.stop_flag = False
        self.emails_processed = 0 
        self.selected_Browser = selected_Browser
        self.main_window = main_window 

    def run(self):
        # Exécute la boucle principale de traitement des emails :
        # - Création des profils/extensions
        # - Lancement des navigateurs
        # - Gestion des processus
        global process_pids, logs_running  ,selected_Browser_Global
        selected_Browser_Global=self.selected_Browser
        remaining_emails = self.data_list[:]  
        log_message("[INFO] Processing started")
        total_emails = len(self.data_list) 

        while remaining_emails or process_pids:  
            if self.stop_flag:  
                logs_running=False 
                log_message("[INFO] Processing interrupted by user.")
                break


            if len(process_pids) < self.entered_number and remaining_emails:
                next_email = remaining_emails.pop(0)  
                email_value = get_key_value(next_email, ["email", "Email"])
                log_message(f"[INFO] Processing the email:\n - {email_value}")

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
                                log_message(f"[INFO]  Erreur lors de la suppression de {dir_to_delete} : {e}")

                    create_extension_for_email(
                        profile_email, profile_password,
                        f'"{ip_address}"', f'"{port}"',
                        f'"{login}"', f'"{password}"', f'{recovery_email}',
                        new_password, new_recovery_email, f'"{self.session_id}"' , self.selected_Browser 
                    )

                    if self.selected_Browser == "firefox":
                        create_firefox_profile(profile_email)
                        print('➡️➡️➡️➡️➡️➡️ process_pids : ' ,process_pids)

                        eb_ext_path = get_web_ext_path()
                        print("eb_ext_path : ", eb_ext_path)
                        command = [
                            eb_ext_path,
                            "run",
                            "--source-dir", os.path.join(self.base_directory, profile_email),
                            "--firefox-profile", os.path.join(script_dir, '..', 'Tools', 'Profiles', 'firefox', profile_email),
                            "--keep-profile-changes",  
                            "--no-reload"
                        ]
              


                        process = subprocess.Popen(command) 
                        process_pids.append(process.pid) 
                        ts   = time.time()
                        firefox_launch.append({
                            'profile': profile_email,
                            'create_time': ts,
                            'proc': process,
                            'hwnd': None
                        })
                        print("Firefox launched with PID: ", process.pid)
                        add_pid_to_text_file(process.pid, profile_email)
                    else:
                        # command = [
                        #     self.Browser_path,
                        #     f"--user-data-dir={os.path.join(script_dir,'..','Tools', 'Profiles','chrome', profile_email)}",
                        #     f"--load-extension={os.path.join(self.base_directory, profile_email)}",
                        #     "--no-first-run",
                        #     "--no-default-browser-check"
                        # ]
                        
                        command = [
                            self.Browser_path,
                            f"--user-data-dir={os.path.join(script_dir,'..','Tools', 'Profiles','chrome', profile_email)}",
                            f"--disable-extensions-except={os.path.join(self.base_directory, profile_email)}",
                            f"--load-extension={os.path.join(self.base_directory, profile_email)}",
                            "--no-first-run",
                            "--no-default-browser-check"
                        ]
                        process = subprocess.Popen(command) 
                        process_pids.append(process.pid) 
                        print('➡️➡️➡️➡️➡️➡️ process_pids : ' ,process_pids)
                        add_pid_to_text_file(process.pid, profile_email)
                    self.emails_processed += 1  

                except Exception as e:
                    log_message(f"[INFO] Erreur : {e}")
            self.msleep(1000) 

        log_message("[INFO] Processing finished for all emails.") 
        time.sleep(3)
        logs_running=False
        self.finished.emit()





def afficher_fichiers(dossier):
    try:
        elements = os.listdir(dossier)
        fichiers = [f for f in elements if os.path.isfile(os.path.join(dossier, f))]
        if fichiers:
            print(f"📁 Fichiers dans le dossier '{dossier}' :")
            for fichier in fichiers:
                print(f"  - {fichier}")
        else:
            print(f"📁 Aucun fichier trouvé dans le dossier '{dossier}'.")
    except Exception as e:
        print(f"❌ Une erreur est survenue lors de la lecture du dossier : {e}")



# Thread qui surveille la fin des processus Chrome/Firefox lancés
# et qui traite les fichiers de session et logs générés dans le dossier Downloads.
class CloseBrowserThread(QThread):

    progress = pyqtSignal(str)  


    def __init__(self , selected_Browser):
        super().__init__()
        self.selected_Browser = selected_Browser
        self.session_id = session_id  
        self.stop_flag = False 
        self.downloads_folder = user_downloads_dir() 




    def run(self):
        # Boucle de surveillance continue tant que tous les processus ne sont pas terminés.
        # Traite les fichiers de session et de log détectés.

        print("Dossier Téléchargements :", self.downloads_folder)
        print("[DEBUG] Run CloseBrowserThread")
        print("[Thread] Dossier Téléchargements :", self.downloads_folder)
        print("[Thread] Démarrage du thread de fermeture des navigateurs...")
        time.sleep(10)

        while not self.stop_flag:  
            print("🫀🫀🫀🫀🫀🫀🫀🫀🫀 process_pids : ", process_pids)
            print("[Thread] Vérification des processus restants...")

            if not process_pids:
                print("🧠🧠🧠🧠🧠🧠🧠🧠🧠 process_pids : ", process_pids)

                print("[Thread] Tous les processus ont été arrêtés. Fin du thread.")
                # ici fais active de button
                break

            files = [f for f in os.listdir(self.downloads_folder) if f.startswith(self.session_id) and f.endswith(".txt")]
            log_files = [f for f in os.listdir(self.downloads_folder) if f.startswith("log_") and f.endswith(".txt")]
            # affiche les files de log et de session détectés
      
            if files:
                print("Fichiers de session détectés :")
                for file in files:
                    print(f" - {file}")
            else:
                print("Aucun files de session détecté.")

            # Affichage des fichiers de log
            if log_files:
                print("Fichiers de log détectés :")
                for file in log_files:
                    print(f" - {file}")
            else:
                print("Aucun fichier de log détecté.")




            # la probleme cet partie de code affiche mais les autre print dans cet classe ne s'affiche pas
            print("Dossier Téléchargements :", self.downloads_folder)
            print(f"[Thread] Fichiers de session détectés: {files}")
            print(f"[Thread] Fichiers de log détectés: {log_files}")
            print(f"[Thread] session_id: {self.session_id}")

            for file_name in files:
                file_path = os.path.join(self.downloads_folder, file_name)
                if os.path.exists(file_path):
                    print(f"[Thread] Fichier de session détecté: {file_name}")

            # afficher_fichiers(self.downloads_folder)

            with ThreadPoolExecutor() as executor:
                futures = []
                for log_file in log_files:
                    futures.append(executor.submit(self.process_log_file, log_file, self.downloads_folder))

                for future in as_completed(futures):
                    result = future.result() 

                # print("[Thread][Log] Résultat:", result)

            with ThreadPoolExecutor() as executor:
                futures = []
                for file_name in files:
                    futures.append(executor.submit(self.process_session_file, file_name, self.downloads_folder , self.selected_Browser))

                for future in as_completed(futures):
                    result = future.result() 

                # print("[Thread][Session] Résultat:", result)

            time.sleep(1)


    

    def process_log_file(self, log_file, downloads_folder):
        #  Traite un fichier de log :
        # - Lit le contenu
        # - Déplace les données vers le fichier de log global
        # - Supprime le fichier de log
        print(f"[Traitement Log] Début du traitement de {log_file}")

        log_file_path = os.path.join(downloads_folder, log_file)

        try:
            global current_hour, current_date

            email = self.get_email_from_log_file(log_file_path)  
            if not email:
                return f"⚠️ Erreur dans le fichier {log_file}: Email non trouvé."

            logs_directory = os.path.join(script_dir, '..','Tools', 'logs')
            session_folder = f"{current_date}_{current_hour}"
            target_folder = os.path.join(logs_directory, session_folder)
            target_file_path = os.path.join(target_folder, f"{email}_{current_hour}.txt")

            try:
                with open(log_file_path, 'r', encoding='utf-8') as log_file_reader:
                    log_content = log_file_reader.read()
            except Exception as e:
                return f"⚠️ Erreur lors de la lecture du fichier {log_file}: {e}"

            try:
                with open(target_file_path, 'a', encoding='utf-8') as target_file_writer:
                    target_file_writer.write(log_content + "\n")
            except Exception as e:
                return f"⚠️ Erreur lors de l'écriture dans {target_file_path}: {e}"
            print(f"Fichier log supprimé et contenu déplacé: {log_file_path}")

            # Suppression du fichier log après traitement
            try:
                os.remove(log_file_path)
                return f"🗑️ Fichier log supprimé : {log_file_path}"
            except Exception as e:
                return f"⚠️ Erreur lors de la suppression du fichier {log_file_path}: {e}"

        except Exception as e:
            return f"⚠️ Erreur dans le fichier {log_file} : {e}"




    def process_session_file(self, file_name, downloads_folder , selected_Browser):
        # Traite un fichier de session :
        # - Récupère les infos de session (pid, email, état)
        # - Écrit dans le fichier result.txt
        # - Termine le processus si actif
        # - Supprime le fichier
        print(f"[Traitement Session] Début du traitement de {file_name}")
        file_path = os.path.join(downloads_folder, file_name)  

        try:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    file_content = file.read().strip()
            except Exception as e:
                return f"⚠️ Erreur lors de la lecture du fichier {file_name}: {e}"

            match = re.search(r"session_id:(\w+)_PID:(\d+)_Email:([\w.@]+)_Status:(\w+)", file_content)
            if not match:
                os.remove(file_path)
                return f"⚠️ Format incorrect dans {file_name}: {file_content}"

            session_id, pid, email, etat = match.groups()
            print(f"[Session Info] PID: {pid}, Email: {email}, État: {etat}")

            log_message(f"[INFO] Email {email} has completed \n processing with status {etat}.")

            result_file_path = os.path.join(script_dir, '..','Tools', "result.txt")
            try:
                with open(result_file_path, 'a', encoding='utf-8') as result_file:
                    result_file.write(f"{session_id}:{pid}:{email}:{etat}\n")
            except Exception as e:
                return f"⚠️ Erreur lors de l'écriture dans le fichier {file_name}: {e}"


            pid = int(pid)
            if pid in process_pids: 
                print(f"[Session] Tentative de fermeture du processus PID {pid} ({email})")
                log_message(f"[INFO] Attempting to terminate process: \n -{email}.")
                if selected_Browser == "firefox":
                    try:
                        print("browser : ", selected_Browser)
                        print('✅✅✅✅✅✅✅✅PID : ', pid)
                        self.find_firefox_window(email)
                        self.wait_then_close(email, delay=20)
                        process_pids.remove(pid)   
                        print(f"Processus {pid} ({email}) terminé.")
                    except Exception as e:
                        print(f"⚠️ Erreur lors de la fermeture du processus {pid} ({email}): {e}")
                    
                else:
                    try:
                        print('✅✅✅✅✅✅✅✅✅✅ PID : ', pid)
                        os.kill(pid, signal.SIGTERM) 
                        process_pids.remove(pid)   
                        print(f"Processus {pid} ({email}) terminé.")
    
                    except Exception as e:
                        return f"⚠️ Erreur lors de la fermeture du processus {file_name}: {e}"
            try:
                os.remove(file_path)
                print(f"Fichier session supprimé: {file_path}")
                return f"🗑️ Fichier session supprimé : {file_path}"
            except Exception as e:
                return f"⚠️ Erreur lors de la suppression du fichier {file_name}: {e}"


        except Exception as e:
            return f"⚠️ Erreur dans le fichier {file_name} : {e}"




    def find_firefox_window(self, profile_email, timeout=30):
        print(f"\n{'='*50}\n🔍 DÉBUT RECHERCHE FENÊTRE POUR {profile_email.upper()}\n{'='*50}")
        entry = next((e for e in firefox_launch if e['profile'] == profile_email), None)
        if not entry:
            raise ValueError(f"❌ ERREUR: Profil '{profile_email}' non trouvé.")

        target_title = f"EXT:{profile_email}"
        print(f"• Titre recherché : {target_title}")
        print(f"• Timeout : {timeout}s\n")

        start_time = time.time()
        attempt = 0

        while time.time() - start_time < timeout:
            attempt += 1
            elapsed = time.time() - start_time
            print(f"\n🔎 Tentative #{attempt} (écoulé: {elapsed:.1f}s)")

            found = [False]

            def window_processor(hwnd, _):
                if found[0]:
                    return False

                if not win32gui.IsWindowVisible(hwnd):
                    return True

                try:
                    class_name = win32gui.GetClassName(hwnd)
                    if class_name != 'MozillaWindowClass':
                        return True

                    window_title = win32gui.GetWindowText(hwnd)
                    print(f"🔸 Fenêtre détectée - HWND: {hwnd} | Title: {window_title}")

                    if target_title in window_title:
                        entry['hwnd'] = hwnd
                        found[0] = True
                        print(f"\n✅ FENÊTRE MATCHÉE PAR TITRE:")
                        print(f"  • HWND  : {hwnd}")
                        print(f"  • Title : {window_title}")
                        return False
                except Exception as e:
                    print(f"⚠️ Erreur lors du traitement de la fenêtre HWND={hwnd} : {e}")
                return True
            try:
                win32gui.EnumWindows(window_processor, None)
            except Exception as e:
                print(f"⚠️ Exception EnumWindows : {e}")
            if entry['hwnd']:
                print(f"\n🎯 Fenêtre correspondante trouvée (HWND={entry['hwnd']})")
                return entry['hwnd']
            print("⏳ Nouvelle tentative dans 2 secondes...")
            time.sleep(2)

        print("❌ Timeout. Aucune fenêtre Firefox avec le titre spécifié.")
        raise TimeoutError(f"Impossible de trouver la fenêtre pour {profile_email}")




    def wait_then_close(self, profile_email, delay=20):
        entry = next((e for e in firefox_launch if e['profile'] == profile_email), None)
        if not entry or not entry.get('hwnd'):
            print(f"❌ Aucune fenêtre trouvée pour {profile_email}.")
            return

        target = entry['create_time'] + delay
        print(f"🕒 Attente de {delay}s pour {profile_email}...")

        while time.time() < target:
            remaining = int(target - time.time())
            print(f"   - {remaining} seconde(s) restantes...")
            time.sleep(1)

        print(f"⏰ Fermeture de la fenêtre (HWND={entry['hwnd']})")
        self.close_window_by_hwnd(entry['hwnd'], entry['proc'])




    def close_confirmation_dialogs(self, pid):
        def _enum(hwnd, _):
            if win32gui.IsWindowVisible(hwnd):
                _, p = win32process.GetWindowThreadProcessId(hwnd)
                if p == pid and win32gui.GetClassName(hwnd) == '#32770':
                    win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
            return True

        win32gui.EnumWindows(_enum, None)




    def close_window_by_hwnd(self, hwnd, proc, wait_grace=2, wait_force=3):
        win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
        time.sleep(wait_grace)

        if not win32gui.IsWindow(hwnd):
            return

        self.close_confirmation_dialogs(proc.pid)
        time.sleep(0.5)

        if not win32gui.IsWindow(hwnd):
            return

        try:
            proc.terminate()
            proc.wait(timeout=wait_force)
        except Exception:
            pass




    def get_email_from_log_file(self, file_name):
        # Extrait l'adresse email depuis un nom de fichier log formaté.
        print(f"🔎 Extraction de l'adresse email depuis le fichier {file_name}...")
        file_name = os.path.basename(file_name)
        match = re.search(r"log_\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z_([\w.+-]+@[\w.-]+\.[a-zA-Z]{2,6})\.txt", file_name)
        if match:
            print(f"   - Email extrait : {match.group(1)}")
            email = match.group(1)
            return email
        else:
            print(f"[Email Extraction] Aucun email trouvé dans {file_name}")
            return None




# QTabBar personnalisé pour un affichage vertical avec des styles adaptés.
# Affiche les onglets avec icônes, couleurs personnalisées et texte formaté.

class VerticalTabBar(QtWidgets.QTabBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setShape(QtWidgets.QTabBar.Shape.RoundedWest)

        self.tab_margin = 0
        self.left_margin = 0
        self.right_margin = 0

    def tabSizeHint(self, index):
        # Retourne la taille personnalisée d'un onglet vertical.
        size_hint = super().tabSizeHint(index)
        size_hint.transpose()
        size_hint.setWidth(180)
        size_hint.setHeight(60)
        return size_hint

    def tabRect(self, index):
        rect = super().tabRect(index)
        rect.adjust(self.left_margin, self.tab_margin, -self.right_margin, -self.tab_margin)
        return rect

    def paintEvent(self, event):
        # Redessine les onglets avec le style défini (couleurs, bordures, icônes, texte).
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)

        for i in range(self.count()):
            rect = self.tabRect(i)
            text = self.tabText(i)
            icon = self.tabIcon(i)

            painter.save()
            if self.currentIndex() == i:
                painter.setBrush(QtGui.QBrush(QtGui.QColor("#12BFCE")))
            else:
                painter.setBrush(QtGui.QBrush(QtGui.QColor("#F5F5F5")))
            painter.setPen(QtCore.Qt.PenStyle.NoPen)
            painter.drawRect(rect)  
            border_pen = QtGui.QPen(QtGui.QColor("#12BFCE"))
            border_pen.setWidth(1)
            painter.setPen(border_pen)
            painter.drawLine(rect.bottomLeft(), rect.bottomRight())
            painter.drawLine(rect.topRight(), rect.bottomRight())
            painter.restore()
            painter.save()

            if not icon.isNull():
                pixmap = icon.pixmap(24, 24)
                icon_pos = QtCore.QPoint(rect.left() + 8, rect.top() + 15)
                painter.drawPixmap(icon_pos, pixmap)

            painter.setPen(QtGui.QPen(QtGui.QColor("#333")))
            font = painter.font()
            font.setPointSize(10)
            font.setFamily("Times New Roman")
            painter.setFont(font)

            text_rect = QtCore.QRect(
                rect.left() + 44,
                rect.top(),
                rect.width() - 45,
                rect.height() - 8
            )
            painter.drawText(text_rect, QtCore.Qt.AlignmentFlag.AlignVCenter | QtCore.Qt.AlignmentFlag.AlignLeft, text)
            painter.restore()



# QTabWidget personnalisé pour utiliser VerticalTabBar comme barre d'onglets.
# Position des onglets sur le côté gauche (Ouest).
class VerticalTabWidget(QtWidgets.QTabWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTabBar(VerticalTabBar())
        self.setTabPosition(QtWidgets.QTabWidget.TabPosition.West)





class MainWindow(QMainWindow):
    # Initialise l'interface graphique principale de l'application.
    # - Charge le fichier `.ui` et connecte les éléments de l'interface.
    # - Configure les templates, boutons, onglets, styles, icônes, champs, et autres éléments de la GUI.
    # - Initialise les conteneurs de scénarios, options de reset et de logs.
    # - Connecte les signaux aux slots pour les boutons cliqués.
    # - Applique le style personnalisé aux QSpinBox, QComboBox et onglets verticaux.
    # - Prépare la zone d'affichage des logs et lance le thread associé.
    def __init__(self, json_data):

        super(MainWindow, self).__init__()

        # Charger l'interface utilisateur depuis le fichier .ui
        ui_path = os.path.join(script_dir, '..',  "interface"  , "interface.ui")
        uic.loadUi(ui_path, self)


        # Initialiser les données et layouts principaux
        self.states = json_data
        self.state_stack = []

        self.reset_options_container = self.findChild(QWidget, "resetOptionsContainer")
        self.reset_options_layout = QVBoxLayout(self.reset_options_container)
        self.reset_options_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.scenario_container = self.findChild(QWidget, "scenarioContainer")
        self.scenario_layout = QVBoxLayout(self.scenario_container)
        self.scenario_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Masquer les templates visuels non utilisés par défaut
        self.template_button = self.findChild(QPushButton, "TemepleteButton")
        self.template_button.hide()

        self.template_Frame1 = self.findChild(QFrame, "Template1")
        self.template_Frame1.hide()

        self.template_Frame2 = self.findChild(QFrame, "Template2")
        self.template_Frame2.hide()


        # Connexion du bouton d'état initial
        self.Button_Initaile_state = self.findChild(QPushButton, "Button_Initaile_state")
        if self.Button_Initaile_state:
            self.Button_Initaile_state.clicked.connect(self.load_initial_options)

        # Connexion du bouton de soumission
        self.submit_button = self.findChild(QPushButton, "submitButton")
        if self.submit_button:
            self.submit_button.clicked.connect(lambda: self.on_submit_button_clicked(self))

        # Icône et action pour le bouton de nettoyage
        self.ClearButton = self.findChild(QPushButton, "ClearButton")
        if self.ClearButton:
            clear_path = os.path.join(script_dir, '..', "interface", "icons", "clear.png").replace("\\", "/")
            if os.path.exists(clear_path):
                icon = QIcon(clear_path)
                self.ClearButton.setIcon(icon)
                self.ClearButton.setIconSize(QSize(32, 32))
            self.ClearButton.clicked.connect(self.on_Clear_Button_clicked)


        # Champ de recherche (masqué au démarrage)
        self.lineEdit_search = self.findChild(QLineEdit, "lineEdit_search")
        if self.lineEdit_search:
            self.lineEdit_search.hide()
        
        # Configuration des onglets principaux avec icônes personnalisés
        self.tabWidgetResult = self.findChild(QTabWidget, "tabWidgetResult")
        if self.tabWidgetResult:
            self.tabWidgetResult.tabBar().setCursor(Qt.CursorShape.PointingHandCursor)
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



        # if self.tabWidgetResult:
        #     for i in range(self.tabWidgetResult.count()):
        #         widget = self.tabWidgetResult.widget(i)
        #         text = self.tabWidgetResult.tabText(i)

            # Remplacement du QTabWidget par un VerticalTabWidget personnalisé
            self.vertical_tab_widget = VerticalTabWidget()
            parent_widget = self.tabWidgetResult.parentWidget()
            geometry = self.tabWidgetResult.geometry()

            while self.tabWidgetResult.count() > 0:
                widget = self.tabWidgetResult.widget(0)
                text = self.tabWidgetResult.tabText(0)
                icon = self.tabWidgetResult.tabIcon(0)


                self.vertical_tab_widget.addTab(widget, icon, text)
                style_sheet = widget.styleSheet()
                object_name = widget.objectName()
                self.vertical_tab_widget.widget(self.vertical_tab_widget.count() - 1).setStyleSheet(style_sheet)
                self.vertical_tab_widget.widget(self.vertical_tab_widget.count() - 1).setObjectName(object_name)

            self.tabWidgetResult.setParent(None)
            self.vertical_tab_widget.setParent(parent_widget)
            self.vertical_tab_widget.setObjectName("tabWidgetResult") 
            self.vertical_tab_widget.setGeometry(geometry)  
            self.vertical_tab_widget.show()


            self.tabWidgetResult = self.vertical_tab_widget
            self.tabWidgetResult.tabBar().setCursor(Qt.CursorShape.PointingHandCursor)



        # Mise en forme des onglets secondaires (interface_2)
        self.Interface = self.findChild(QTabWidget, "interface_2")
        if self.Interface:
            self.Interface.tabBar().setCursor(Qt.CursorShape.PointingHandCursor)
            for i in range(self.Interface.count()):
                tab_text = self.Interface.tabText(i)
                if tab_text.startswith("Result"):
                    tab_widget = self.Interface.widget(i)
                    frame = QFrame(tab_widget)
                    frame.setStyleSheet("background-color: #F5F5F5; border-right: 1px solid #12BFCE;")
                    frame.setGeometry(0, 480, 179, 445)
                    frame.show()
                    break

        # Placeholder dans les champs textEdit
        self.textEdit_3.setPlaceholderText(
            "Please enter the data in the following format : \n"
            "Email* ; passwordEmail* ; ipAddress* ; port* ; login ; password ; recovery_email , new_recovery_email"
        )
        self.textEdit_4.setPlaceholderText(
            "Specify the maximum number of operations to process"
        )
        
        # Étirement automatique des colonnes dans les tableaux
        for table in self.findChildren(QTableWidget):
            for col in range(table.columnCount()):
                table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.Stretch)

        # Personnalisation des boutons de QSpinBox avec des flèches    
        spin_boxes = self.findChildren(QSpinBox)
        arrow_down_path = os.path.join(script_dir, '..', "interface", "icons", "arrow_Down.png").replace("\\", "/")
        arrow_up_path = os.path.join(script_dir, '..', "interface", "icons", "arrow_up.png").replace("\\", "/")
        down_exists = os.path.exists(arrow_down_path)
        up_exists = os.path.exists(arrow_up_path)
        if down_exists and up_exists:
            for spin_box in spin_boxes:
                spin_box.setStyleSheet(f"""
                    QSpinBox::down-button {{
                        image: url("{arrow_down_path}");
                        width: 13px;
                        height: 13px;
                        padding: 2px;  
                        border-top-left-radius: 5px;
                        border-bottom-left-radius: 5px;
                    }}
                    QSpinBox::up-button {{
                        image: url("{arrow_up_path}");
                        width: 13px;
                        height: 13px;
                        padding: 2px;
                        border-top-left-radius: 5px;
                        border-bottom-left-radius: 5px;
                    }}
                """)

        # Initialisation du thread d'affichage des logs
        self.logs_thread = LogsDisplayThread(logs)
        self.logs_thread.log_signal.connect(self.update_logs_display)

        # Configuration du QComboBox "browsers" avec icônes et style
        self.browser = self.findChild(QComboBox, "browsers")
        if self.browser is not None:
            if os.path.exists(arrow_down_path):
                new_style = f'''
                    QComboBox::down-arrow {{
                        image: url("{arrow_down_path}");
                        width: 16px;
                        height: 16px;
                    }}
                '''
                old_style = self.browser.styleSheet()
                self.browser.setStyleSheet(old_style + new_style)


            icons_dir = os.path.join(script_dir, '..', "interface", "icons")
            self.browser.addItem(QIcon(os.path.join(icons_dir, "chrome.png")), "Chrome")
            self.browser.addItem(QIcon(os.path.join(icons_dir, "firefox.png")), "Firefox")
            self.browser.addItem(QIcon(os.path.join(icons_dir, "edge.png")), "Edge")
            self.browser.addItem(QIcon(os.path.join(icons_dir, "comodo.png")), "Comodo")
                
            # Application du style à deux zones scrollables
            self.scrollAreaWidget1 = self.findChild(QWidget, "scrollAreaWidgetContents")
            self.scrollAreaWidget2 = self.findChild(QWidget, "scrollAreaWidgetContents_3")
            self.apply_scroll_area_style(self.scrollAreaWidget1)
            self.apply_scroll_area_style(self.scrollAreaWidget2)
        
        # Initialisation de l'affichage des logs
        self.log_container = self.findChild(QWidget, "log")
        self.log_layout = QVBoxLayout(self.log_container)  
        self.log_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.log_container.adjustSize() 
        self.log_container.setFixedWidth(402)

        # Chargement initial des options
        self.load_initial_options()


    # Applique un style personnalisé à la zone de défilement associée à un widget.
    # Cela permet d'harmoniser l'apparence des barres de défilement avec le thème général.
    def apply_scroll_area_style(self, scroll_widget):
        if scroll_widget is not None:
            scroll_area = scroll_widget.parent().parent()
            if isinstance(scroll_area, QScrollArea):
                scroll_area.setStyleSheet(self.get_scroll_area_styles())




    # Retourne une feuille de style CSS personnalisée pour les QScrollArea verticales.
    # Permet un look moderne avec une poignée arrondie et des couleurs discrètes.
    def get_scroll_area_styles(self):
        return """
            QScrollArea {
                background: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background: #F3F3F3;
                width: 8px;
                margin: 10px 0px 5px 0px; 
                border-radius: 20px;

            }
            QScrollBar::handle:vertical {
                background: #C0C0C0;
                min-height: 25px;
                border-radius: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background: #A8A8A8;
            }
            QScrollBar::add-line:vertical, 
            QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical {
                background: none;
            }
        """





    #Ajoute une nouvelle ligne de log dans la zone de log (interface utilisateur).
    #Chaque log est stylisé pour rester lisible avec fond transparent.
    def update_logs_display(self, log_entry):
        log_label = QLabel(log_entry)
        log_label.setStyleSheet("""
            QLabel {
                color: #ffffff;
                font-size: 12px;
                background-color: transparent;
                font-family: Arial;
                padding: 2px;
            }
        """)
        self.log_layout.addWidget(log_label)



    # Fonction appelée automatiquement à la fermeture de la fenêtre principale.
    # Permet d'arrêter proprement le thread de logs avant la fermeture de l'application.
    def closeEvent(self, event):
        self.logs_thread.stop()  
        super().closeEvent(event)



    # Enregistre les données JSON traitées dans un fichier appelé 'traitement.json'.
    # Supprime l'ancien fichier s'il existe, puis écrit le nouveau proprement.
    def save_json_to_file(self,json_data, selected_browser):
        template_directory = template_directory_Firefox if selected_browser.lower() == "firefox" else template_directory_Chrome
        os.makedirs(template_directory, exist_ok=True)
        traitement_file_path = os.path.join(template_directory, 'traitement.json')
        try:
            with open(traitement_file_path, 'w', encoding='utf-8') as file:
                json.dump(json_data, file, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"Error while creating the file {traitement_file_path}: {e}")




    # Traite et restructure les données JSON pour les séparer selon les actions spécifiques (comme open_inbox / open_spam).
    # - Ignore les boucles vides.
    # - Nettoie les sous-process en supprimant certains éléments inutiles selon le contexte.
    # - Génère une nouvelle structure de JSON à utiliser pour les traitements suivants.
    def process_and_split_json(self, input_json):
        output_json = []  
        current_section = []
        current_start = None

        def finalize_section():
            if current_section:
                output_json.extend(current_section)

        for element in input_json:
            if element.get("process") == "loop" and "sub_process" in element and not element["sub_process"]:
                continue

            if element.get("process") in ["open_inbox", "open_spam"]:
                finalize_section()
                current_section = [element]
                current_start = element.get("process")
                continue

            if element.get("process") == "loop" and "sub_process" in element:
                sub_process = element["sub_process"]

                items = []
                if current_start == "open_inbox":
                    items = ["report_spam", "delete", "archive"]
                elif current_start == "open_spam":
                    items = ["not_spam", "delete", "report_spam"]

                contains_select_all = any(sp.get("process") == "select_all" for sp in sub_process)

                if contains_select_all:
                    sub_process = [
                        sp for sp in sub_process if sp.get("process") not in ["return_back", "next"]
                    ]

                contains_allowed_item = any(sp.get("process") in items for sp in sub_process)

                if contains_allowed_item:
                    sub_process = [
                        sp for sp in sub_process if sp.get("process") not in ["return_back", "next"]
                    ]

                element["sub_process"] = sub_process

                current_section.append(element)
                continue

            current_section.append(element)

        finalize_section()
        return output_json



    # Parcourt les éléments du JSON pour gérer le dernier sous-processus de chaque boucle ("loop").
    # - Si le dernier élément est "next", ajoute un "open_message" avec délai.
    # - Si le dernier élément n'est pas une action finale (delete, archive, etc.),
    #     transforme "open_message" en "OPEN_MESSAGE_ONE_BY_ONE".
    # - Nettoie aussi les anciens "open_message" si besoin.
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



    # Modifie les éléments JSON contenant "loop" si un "open_message" a été trouvé avant.
    # - Supprime la clé "check" si le sous-process contient "next".
    # - Permet d’adapter dynamiquement certaines boucles selon les éléments précédents.
    def process_and_modify_json(self,input_json):
        output_json = []  
        current_section = []
        found_open_message = False

        def finalize_section():
            """Ajoute la section courante à la sortie finale."""
            if current_section:
                output_json.extend(current_section)

        for element in input_json:
            if element.get("process") == "open_message":
                found_open_message = True
            
            elif element.get("process") == "loop":
                if found_open_message:
                    sub_process = element.get("sub_process", [])
                    contains_next = any(sp.get("process") == "next" for sp in sub_process)
                    if contains_next:
                        element.pop("check", None)  
                current_section.append(element)
                continue
            current_section.append(element)
        finalize_section()
        return output_json


    # Appelée une fois l'extraction des données terminée.
    # - Arrête proprement le thread de logs.
    # - Lance la mise à jour de la liste des résultats après un court délai.
    def on_extraction_finished(self, window):
        self.logs_thread.stop()  
        self.logs_thread.wait()  
        QTimer.singleShot(100, lambda: read_result_and_update_list(window))



    # Fonction déclenchée lors du clic sur le bouton "Submit".
    # - Gère l'initialisation de l'extraction, la création du JSON de scénario,
    #     la vérification des champs, et le lancement de l'extraction dans un thread.
    def on_submit_button_clicked(self, window):
        global current_hour, current_date , logs_running

        # new_version = checkVersion()
        # if new_version:
        #     if 'version_python' in new_version or 'version_interface' in new_version:
        #         window.close()
        #         launch_new_window()
        #         sys.exit(0)
        #     else:
        #         download_result = DownloadFile(new_version)
        #         if download_result == -1:
        #             return
        #         time.sleep(5) 
        #         extractAll()

   

        selected_Browser = self.browser.currentText().lower()
        print('selected_Browser : ', selected_Browser)
        
        interface_tab_widget = window.findChild(QTabWidget, "interface_2")
        if interface_tab_widget:
            for i in range(interface_tab_widget.count()):
                tab_text = interface_tab_widget.tabText(i)
                if tab_text.startswith("Result"):
                    interface_tab_widget.setTabText(i, "Result")
                    break
        
        logs_running =True

        output_json = [
            {
                "process": "login",  
                "sleep": 1  
            }
        ]

        if self.scenario_layout.count() == 0:
            show_critical_message(
                window,  
                "Error - Empty Scenario", 
                "No actions added. Please add actions before submitting." 
            )
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
                        else:
                            output_json.append({
                                "process": "search",
                                "value": search_value
                            })



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
                return
            data_list, entered_number = result  

        except Exception as e:
            QMessageBox.critical(window, "Error", f"Error while parsing the JSON: {e}")
            return
        
        current_time = datetime.datetime.now()
        current_date = current_time.strftime("%Y-%m-%d")
        current_hour = current_time.strftime("%H-%M-%S") 
        modified_json = self.process_and_split_json(output_json)
        output_json = self.process_and_handle_last_element(modified_json)
        output_json_final=self.process_and_modify_json(output_json)
        self.save_json_to_file(output_json_final , selected_Browser)
        with ThreadPoolExecutor(max_workers=2) as executor:
            executor.submit(start_extraction, window, data_list , entered_number, selected_Browser)
            executor.submit(self.logs_thread.start)
        extraction_thread.finished.connect(lambda: self.on_extraction_finished(window))



    # Charge les options visibles dès le démarrage de l'application.
    # - Supprime les anciens widgets.
    # - Crée un bouton pour chaque option avec `showOnInit = True`.
    def load_initial_options(self):
        while self.reset_options_layout.count() > 0:
            item = self.reset_options_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for key, state in self.states.items():
            if state.get("showOnInit", False):
                self.create_option_button(state)



    #Crée dynamiquement un bouton d'option basé sur un état donné.
    #Ce bouton est ajouté à un conteneur prédéfini, reprend le style d'un bouton modèle,
    #et est relié à la fonction `load_state`.
    #:param state: Dictionnaire contenant les informations de l'état à charger.
    def create_option_button(self, state):
        default_icon_path = os.path.join(script_dir, '..' ,"Tools", "icons", "icon.png")

        button = QPushButton(state["label"], self.reset_options_container)
        button.setStyleSheet(self.template_button.styleSheet())
        button.setFixedSize(self.template_button.size())
        button.clicked.connect(lambda _, s=state: self.load_state(s))
        self.reset_options_layout.addWidget(button)
        
        button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        
        if os.path.exists(default_icon_path):
            button.setIcon(QIcon(default_icon_path))



    #Charge un nouvel état de scénario. Met à jour l'interface avec les nouvelles actions,
    #le template associé, et remet les éléments spécifiques à zéro (copieur, INITAILE...).
    #:param state: Dictionnaire représentant l'état à charger.
    def load_state(self, state):
        self.state_stack.append(state)
        self.update_scenario(state.get("Template", ""), state)
        self.update_reset_options(state.get("actions", []))
        self.update_actions_color_and_handle_last_button()
        self.remove_copier()
        self.remove_INITAILE()



    # Met à jour dynamiquement le style de tous les widgets enfants dans le layout du scénario.
    # Différencie le dernier bloc des autres :
    # - Applique des styles personnalisés pour les QLabels, QSpinBox, QCheckBox, et QComboBox.
    # - Cache le dernier bouton dans chaque bloc sauf le dernier, où il devient visible et fonctionnel.
    # - Applique des styles conditionnels selon les icônes disponibles.
    def update_actions_color_and_handle_last_button(self):

        arrow_down_path = os.path.join(script_dir, '..', "interface", "icons", "arrow_Down.png").replace("\\", "/")
        arrow_up_path = os.path.join(script_dir, '..', "interface", "icons", "arrow_up.png").replace("\\", "/")
        arrow_down_path_w = os.path.join(script_dir, '..', "interface", "icons", "arrow_Down_w.png").replace("\\", "/")
        arrow_up_path_w = os.path.join(script_dir, '..', "interface", "icons", "arrow_up_w.png").replace("\\", "/")


        down_exists = os.path.exists(arrow_down_path)
        up_exists = os.path.exists(arrow_up_path)
        down_exists_w = os.path.exists(arrow_down_path)
        up_exists_w = os.path.exists(arrow_up_path)

       
        for i in range(self.scenario_layout.count()):
            widget = self.scenario_layout.itemAt(i).widget()

            if widget:
                if i != self.scenario_layout.count() - 1:
                    widget.setStyleSheet("background-color: #ffffff; border: 1px solid #0E94A0; border-radius: 8px;")

                    label_list = [child for child in widget.children() if isinstance(child, QLabel)]
                    if label_list:
                        label_list[0].setStyleSheet("""
                            QLabel {
                                color: #0E94A0;
                                font-weight: bold;
                                font-size: 16px;
                                border: none;
                                border-radius: 4px;
                                text-align: center;
                                background-color: transparent;
                                font-family: "Times", "Times New Roman", serif;
                                margin-left: 10px;
                            }
                        """)
                        for label in label_list[1:]: 
                            label.setStyleSheet("""
                                QLabel {
                                    color: #0E94A0;
                                    font-weight: bold;
                                    font-size: 16px;
                                    border: none;
                                    border-radius: 4px;
                                    text-align: center;
                                    background-color: transparent;
                                    font-family: "Times", "Times New Roman", serif;
                                }
                            """)


                     


                    buttons = [child for child in widget.children() if isinstance(child, QPushButton)]
                    if buttons:
                        last_button = buttons[-1]
                        last_button.setVisible(False)  


                    spin_boxes = [child for child in widget.children() if isinstance(child, QSpinBox)]
                    if spin_boxes and down_exists and up_exists:

                        new_style = f"""
                            QSpinBox {{
                                padding: 2px; 
                                border: 1px solid #0E94A0; 
                                color: black;
                            }}
                            QSpinBox::down-button {{
                                image: url("{arrow_down_path}");
                                width: 13px;
                                height: 13px;
                                padding: 2px;  
                                border-top-left-radius: 5px;
                                border-bottom-left-radius: 5px;
                            }}
                            QSpinBox::up-button {{
                                image: url("{arrow_up_path}");
                                width: 13px;
                                height: 13px;
                                padding: 2px;
                                border-top-left-radius: 5px;
                                border-bottom-left-radius: 5px;
                            }}
                        """
                        spin_boxes[0].setStyleSheet(new_style)  



                    QCheckBox_list = [child for child in widget.children() if isinstance(child, QCheckBox)]

                    if QCheckBox_list:  
                        checkbox = QCheckBox_list[0]
                        
                        if checkbox.isChecked():
                            additional_style = """
                                QCheckBox::indicator:checked  {
                                    background-color: #0E94A0;
                                    border: 2px solid #0E94A0;
                                }
                            """
                        else:
                            additional_style = """
                                QCheckBox::indicator {
                                    color: gray;
                                    background-color: #e0e0e0; 
                                    border: 1px solid #cccccc;
                                }
                            """


                        current_style = checkbox.styleSheet()
                        new_style = f"{current_style} {additional_style}" if current_style else additional_style
                        checkbox.setStyleSheet(new_style)

                    QComboBox_list = [child for child in widget.children() if isinstance(child, PyQt6.QtWidgets.QComboBox)]

                    if QComboBox_list:
                        QComboBox = QComboBox_list[0]
                        arrow_down_path = os.path.join(script_dir, '..', "interface", "icons", "arrow_Down.png").replace("\\", "/")

                        down_exists = os.path.exists(arrow_down_path)
                        if down_exists:
                            old_style = QComboBox.styleSheet()
                            new_style = f"""
                                QComboBox::down-arrow {{
                                    image: url("{arrow_down_path}");
                                    width: 13px;
                                    height: 13px;
                                    border: 1px solid #0E94A0; 
                                    background-color: white;
                                }}
                                QComboBox::drop-down {{
                                    border: 1px solid #0E94A0; 
                                    width: 20px;
                                    outline: none;
                                }}
                                
                                QComboBox QAbstractItemView {{
                                    min-width: 90px; 
                                    border: 1px solid #0E94A0; 
                                    background: white;
                                    selection-background-color: #0E94A0;
                                    selection-color: white;
                                    padding: 3px; 
                                    margin: 0px;  
                                    alignment: center; 
                                }}
                                QComboBox {{
                                    padding-left: 10px; 
                                    font-size: 12px;
                                    font-family: "Times", "Times New Roman", serif;
                                    border: 1px solid #0E94A0; 
                                }}
                                QComboBox QAbstractItemView::item {{
                                    padding: 5px; 
                                    font-size: 12px;
                                    color: #333;
                                    border: none; 
                                }}
                                QComboBox QAbstractItemView::item:selected {{
                                    background-color: #0E94A0;
                                    color: white;
                                    border-radius: 3px;
                                }}
                                QComboBox:focus {{
                                    border: 1px solid #0E94A0; 
                                }}
                            """
                            combined_style = old_style + new_style
                            QComboBox.setStyleSheet(combined_style)

                if i == self.scenario_layout.count() - 1:



                    widget.setStyleSheet("background-color: #0E94A0; border-radius: 8px;")
                    label_list = [child for child in widget.children() if isinstance(child, QLabel)]
                    if label_list:
                        label_list[0].setStyleSheet("""
                            QLabel {
                                color: #0E94A0;
                                font-weight: bold;
                                font-size: 16px;
                                border: none;
                                border-radius: 4px;
                                text-align: center;
                                background-color: #f9f9f9;
                                font-family: "Times", "Times New Roman", serif;
                                margin-left: 8px; 
                            }
                        """)
                        for label in label_list[1:]: 
                            label.setStyleSheet("""
                                QLabel {
                                    color: #0E94A0;
                                    font-weight: bold;
                                    font-size: 16px;
                                    border: none;
                                    border-radius: 4px;
                                    text-align: center;
                                    background-color: #f9f9f9;
                                    font-family: "Times", "Times New Roman", serif;
                                }
                            """)


                    buttons = [child for child in widget.children() if isinstance(child, QPushButton)]
                    if buttons:
                        last_button = buttons[0]
                        last_button.setVisible(True)
                        last_button.setCursor(Qt.CursorShape.PointingHandCursor)

                        try:
                            last_button.clicked.disconnect()
                        except TypeError:
                            pass  
                        last_button.clicked.connect(self.go_to_previous_state)
            
                    spin_boxes = [child for child in widget.children() if isinstance(child, QSpinBox)]
                    if spin_boxes and down_exists_w and up_exists_w:
                        new_style = f"""
                            QSpinBox {{
                                padding: 2px; 
                                border: 1px solid white; 
                                color: white;
                            }}
                            QSpinBox::down-button {{
                                image: url("{arrow_down_path_w}");
                                width: 13px;
                                height: 13px;
                                padding: 2px;  
                                border-top-left-radius: 5px;
                                border-bottom-left-radius: 5px;
                            }}
                            QSpinBox::up-button {{
                                image: url("{arrow_up_path_w}");
                                width: 13px;
                                height: 13px;
                                padding: 2px;
                                border-top-left-radius: 5px;
                                border-bottom-left-radius: 5px;
                            }}
                        """
                        spin_boxes[0].setStyleSheet(new_style)  



                    QCheckBox_list_last = [child for child in widget.children() if isinstance(child, QCheckBox)]
                    if QCheckBox_list_last:  
                        checkbox = QCheckBox_list_last[0]
                        
                        if checkbox.isChecked():
                            additional_style = """
                                QCheckBox::indicator:checked  {
                                    background-color: #0E94A0;
                                    border: 2px solid #ffffff;
                                }
                            """
                        else:
                            additional_style = """
                                QCheckBox::indicator {
                                    color: gray;
                                    background-color: #e0e0e0; 
                                    border: 1px solid #cccccc;
                                }
                            """


                        current_style = checkbox.styleSheet()
                        new_style = f"{current_style} {additional_style}" if current_style else additional_style
                        checkbox.setStyleSheet(new_style)


                QComboBox_list = [child for child in widget.children() if isinstance(child, PyQt6.QtWidgets.QComboBox)]
                if QComboBox_list:
                    QComboBox = QComboBox_list[0]
                    arrow_down_path = os.path.join(script_dir, '..', "interface", "icons", "arrow_Down.png").replace("\\", "/")

                    down_exists = os.path.exists(arrow_down_path)
                    if down_exists:
                        old_style = QComboBox.styleSheet()
                        new_style = f"""
                            QComboBox::down-arrow {{
                                image: url("{arrow_down_path}");
                                width: 13px;
                                height: 13px;
                                border: none;
                                background-color: white;
                            }}
                            QComboBox::drop-down {{
                                border: none;
                                width: 20px;
                                outline: none;
                            }}
                            
                            QComboBox QAbstractItemView {{
                                min-width: 90px; 
                                border: none; 
                                background: white;
                                selection-background-color: #0E94A0;
                                selection-color: white;
                                padding: 3px; 
                                margin: 0px;  
                                alignment: center; 
                            }}
                            QComboBox {{
                                padding-left: 10px; 
                                font-size: 12px;
                                font-family: "Times", "Times New Roman", serif;
                                border: 1px solid #0E94A0; 
                                outline: none; 
                            }}
                            QComboBox QAbstractItemView::item {{
                                padding: 5px; 
                                font-size: 12px;
                                color: #333;
                                border: none; 
                            }}
                            QComboBox QAbstractItemView::item:selected {{
                                background-color: #0E94A0;
                                color: white;
                                border-radius: 3px;
                            }}
                            QComboBox:focus {{
                                border: 1px solid #0E94A0; 
                            }}
                        """
                        combined_style = old_style + new_style
                        QComboBox.setStyleSheet(combined_style)



    # Supprime tous les boutons de réinitialisation liés aux blocs ajoutés *après* le dernier bloc contenant une checkbox.
    # Cette fonction :
    # - Identifie l'index du dernier bloc contenant une QCheckBox.
    # - Récupère les labels des blocs ajoutés après celui-ci.
    # - Compare avec les boutons existants dans le layout des options de reset.
    # - Supprime ceux qui sont déjà couverts par les labels détectés.
    def remove_copier(self):
        lastactionLoop = None
        scenarioContainertableauAdd = []
        resetOptionsContainertableauALL = []
        found_checkbox = False

        for i in range(self.scenario_layout.count()):
            widget = self.scenario_layout.itemAt(i).widget()
            if widget:
                for child in widget.children():
                    if isinstance(child, QCheckBox):
                        lastactionLoop = i 
                        found_checkbox = True
        
        if not found_checkbox:
            return


        for i in range(lastactionLoop + 1, self.scenario_layout.count()):
            widget = self.scenario_layout.itemAt(i).widget()
            if widget:
                labels = [child.text() for child in widget.children() if isinstance(child, QLabel)]
                if labels:
                    scenarioContainertableauAdd.append(labels[0])

        for i in range(self.reset_options_layout.count()):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget and isinstance(widget, QPushButton):
                resetOptionsContainertableauALL.append(widget.text())

        diff_texts = [text for text in resetOptionsContainertableauALL if text not in scenarioContainertableauAdd]

        for i in reversed(range(self.reset_options_layout.count())):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget and isinstance(widget, QPushButton):
                if widget.text() not in diff_texts:
                    widget.deleteLater()
                    self.reset_options_layout.removeWidget(widget)



    # Supprime les boutons de réinitialisation associés aux blocs ayant l’attribut `INITAILE`.
    # Cette fonction :
    # - Récupère tous les labels associés à un bloc contenant l'attribut `INITAILE`.
    # - Supprime de l'UI les boutons de réinitialisation qui ne sont pas dans cette liste.
    def remove_INITAILE(self):

        scenarioContainertableauAdd = []  
        resetOptionsContainertableauALL = []  

        for i in range(self.scenario_layout.count()):
            widget = self.scenario_layout.itemAt(i).widget()
            if widget:
                sub_full_state = widget.property("full_state")
                sub_hidden_id = sub_full_state.get("INITAILE")
                if sub_hidden_id:
                    scenarioContainertableauAdd.append(sub_full_state.get("label"))  



        for i in range(self.reset_options_layout.count()):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget and isinstance(widget, QPushButton):
                resetOptionsContainertableauALL.append(widget.text())


        diff_texts = [text for text in resetOptionsContainertableauALL if text not in scenarioContainertableauAdd]

        for i in reversed(range(self.reset_options_layout.count())):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget and isinstance(widget, QPushButton):
                if widget.text() not in diff_texts:
                    widget.deleteLater()
                    self.reset_options_layout.removeWidget(widget)



    # Met à jour dynamiquement les boutons d'options de réinitialisation à partir d’une liste d’actions.
    # :param actions: Liste des clés d'action à afficher comme options. Si vide, recharge les options initiales.
    def update_reset_options(self, actions):
        for i in reversed(range(self.reset_options_layout.count())):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()

        if not actions:
            self.load_initial_options()
            return

        for action_key in actions:
            state = self.states.get(action_key)
            if state:
                self.create_option_button(state)




    # Affiche ou cache un champ QLineEdit en fonction de l'état d'une checkbox.
    # :param state: État de la QCheckBox (0: décochée, 2: cochée)
    # :param lineedit: Référence au champ QLineEdit à afficher/cacher
    def handle_checkbox_state(self, state, lineedit):
        if lineedit:  
            if state == 2: 
                lineedit.show()
            else:  

                lineedit.hide()



    # Génère un nouveau bloc de scénario basé sur un template existant et le remplit avec les données d'état.
    # :param template_name: Nom du template ("Template1" ou "Template2")
    # :param state: Dictionnaire contenant les valeurs à insérer dans le bloc
    def update_scenario(self, template_name, state):
        template_frame = None

        if template_name == "Template1":
            template_frame = self.template_Frame1
        elif template_name == "Template2":
            template_frame = self.template_Frame2
        else:
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


            new_template.setProperty("full_state", state)

            self.scenario_layout.addWidget(new_template)


    # Revient à l'état précédent du scénario :
    # - Supprime le dernier bloc visuel du scénario.
    # - Restaure les actions de l'état précédent.
    # - Si aucun historique n’est disponible, réinitialise complètement.
    # - Met à jour le style et nettoie les boutons redondants.
    def go_to_previous_state(self):
        if len(self.state_stack) > 1:
            if self.scenario_layout.count() > 0:
                last_item = self.scenario_layout.takeAt(self.scenario_layout.count() - 1)
                if last_item.widget():
                    last_item.widget().deleteLater()
            
            self.state_stack.pop()
            previous_state = self.state_stack[-1]

            self.update_reset_options(previous_state.get("actions", []))
        else:
            self.state_stack.clear()
            while self.scenario_layout.count() > 0:
                last_item = self.scenario_layout.takeAt(0)
                if last_item.widget():
                    last_item.widget().deleteLater()

            self.load_initial_options()

        self.update_actions_color_and_handle_last_button()
        self.remove_copier()




    # Nettoie entièrement les logs affichés à l'écran et vide la variable globale `logs`.
    def on_Clear_Button_clicked(self):
        while self.log_layout.count():
            item = self.log_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        global logs
        logs = []










def main():
    if len(sys.argv) < 3:
        sys.exit(1)
    else:
        encrypted_key = sys.argv[1]
        secret_key = sys.argv[2]
        if not verify_key(encrypted_key, secret_key):
            sys.exit(1)

    json_path = os.path.join(script_dir,'..',"Tools", "action.json")

    with open(json_path, "r") as file:
        json_data = json.load(file)
        
    if json_data is None:
        sys.exit(1)

    app = QApplication([])
    icon_path = os.path.join(script_dir, "icons", "logo.jpg")  
    app_icon = QIcon(icon_path)
    app.setWindowIcon(app_icon) 

    window = MainWindow(json_data)
    window.setFixedSize(1700, 1000)  
    window.stopButton.clicked.connect(lambda: stop_all_processes(window))
    window.setWindowTitle("Gmail Process Automation")
    window.show()
    app.exec()


if __name__ == "__main__":
    main()



