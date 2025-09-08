import os
import json
from base64 import b64encode, b64decode
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
from datetime import  timedelta
from PyQt6.QtGui import QColor, QPixmap
from PyQt6 import uic
from PyQt6.QtGui import QGuiApplication
import pytz
import copy
import glob
import warnings
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import zipfile
import tempfile
import stat
warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

urllib3.disable_warnings()



SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)

# =========================================
# 📁 Constantes de chemins et fichiers
# =========================================
SCRIPT_DIR       = os.path.dirname(os.path.abspath(__file__))
CONFIG_PROFILE   = r"C:\RepProxy\template Profile"
EXTENTION_REP  = r"C:\RepProxy\extRep"
MANIFEST_PATH    = os.path.join(EXTENTION_REP, "manifest.json")
LAST_VERSION_TXT = os.path.join(EXTENTION_REP, "version.txt")




# Recherche clés spécifiques
RESULTATS=[]
CLES_RECHERCHE_EX2 = ["cglaeklndjbecchejgkdpblljkmgkacg","eoblcnapnenpmgdcmecapipdojplafpm", "developer_mode"]
RESULTATS_EX = []




# =========================================
# 🔑 Paramètres cryptographie
# =========================================
PBKDF2_ITERATIONS = 100_000
SALT_LEN = 16
IV_LEN = 12
KEY_LEN = 32

# =========================================
# 🌐 URLs externes
# =========================================
DROPBOX_URL    = "https://www.dropbox.com/scl/fi/78a38bc4papwzlw80hxti/version.json?rlkey=n7dx5mb8tcctvprn0wq4ojw7m&st=ormvslid&dl=1"
GITHUB_ZIP_URL = "https://github.com/Azedize/Extention-Repo/archive/refs/heads/main.zip"






FIREFOX_LAUNCH = []
logs= []
PROCESS_PIDS = []
NOTIFICATION_BADGES = {}
EXTRACTION_THREAD = None 
CLOSE_BROWSER_THREAD = None 
NEW_VERSION = None
LOGS_RUNNING = True  
SELECTED_BROWSER_GLOBAL=None

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
BASE_DIRECTORY = os.path.join(SCRIPT_DIR, '..', 'tools', 'ExtensionEmail')
TEMPLATE_DIRECTORY_CHROME = os.path.join(SCRIPT_DIR, '..', 'tools', 'ExtensionTemplateChrome')
TEMPLATE_DIRECTORY_FIREFOX  = os.path.join(SCRIPT_DIR, '..', 'tools', 'ExtensionTemplateFirefox')

APP_NAME = "SecureDesk"
APPDATA_DIR = os.path.join(os.getenv("APPDATA"), APP_NAME)
os.makedirs(APPDATA_DIR, exist_ok=True)
key = b"ThisKeyIsExactly32ByteAESKey!!!!" 



# les clés pour générer la clé finale
CLE1 = "R2"
CLE2 = "PR"
combined_keys = f"&{CLE1}&{CLE2}"


def encrypt_date(date_str: str, key: bytes) -> str:
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded_data = padder.update(date_str.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted = b64encode(iv + ciphertext).decode()
    return encrypted





def decrypt_date(encrypted_str: str, key: bytes) -> str:
    raw = b64decode(encrypted_str)
    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()







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

    # Définir le chemin de base pour les profils: SCRIPT_DIR/firefox
    path_profile = os.path.join(SCRIPT_DIR,'..','Tools', 'Profiles', 'firefox')
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
    target_dir = os.path.dirname(PARENT_DIR)
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









def DownloadAndExtract(new_versions):
    """
    Download a single ZIP from GitHub, extract it,
    and replace Tools subfolders (Firefox/Chrome) if needed.
    Detailed progress messages included with emojis.
    """
    try:
        if not isinstance(new_versions, dict):
            print("❌ [ERROR] Invalid new_versions (not a dict).")
            return -1

        path_DownloadFile = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))
        local_zip = os.path.join(path_DownloadFile, "Programme-main.zip")

        need_firefox = "version_Extention_firefox" in new_versions
        need_chrome = "version_Extention_Family_Chrome" in new_versions

        if not need_firefox and not need_chrome:
            print("✅ [INFO] No extension updates required.")
            return 0

        # Remove old ZIP if exists
        if os.path.exists(local_zip):
            print(f"🗑️ Removing old ZIP: {local_zip}")
            os.remove(local_zip)

        # Download ZIP
        print("⬇️ Downloading update ZIP from GitHub...")
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        url = "https://github.com/Azedize/Programme/archive/refs/heads/main.zip"

        resp = requests.get(url, stream=True, headers=headers, verify=False, timeout=60)
        if resp.status_code != 200:
            print(f"❌ [ERROR] Failed to download ZIP: HTTP {resp.status_code}")
            return -1

        with open(local_zip, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        print(f"✅ Download completed: {local_zip}")

        # Extract ZIP
        print("📂 Extracting ZIP file...")
        with zipfile.ZipFile(local_zip, 'r') as zip_ref:
            names = [n for n in zip_ref.namelist() if n.strip()]
            if not names:
                print("❌ [ERROR] ZIP is empty.")
                return -1
            topdir = names[0].split('/')[0]
            extracted_dir = os.path.join(path_DownloadFile, topdir)

            if os.path.exists(extracted_dir):
                print(f"🗑️ Removing existing extracted folder: {extracted_dir}")
                shutil.rmtree(extracted_dir)

            zip_ref.extractall(path_DownloadFile)
        print(f"✅ Extraction completed: {extracted_dir}")

        # Remove ZIP file after extraction
        if os.path.exists(local_zip):
            print(f"🗑️ Removing downloaded ZIP file: {local_zip}")
            os.remove(local_zip)

        # Prepare Tools folder
        tools_target = os.path.join(PARENT_DIR, "tools")
        new_tools_root = os.path.join(extracted_dir, "tools")
        os.makedirs(tools_target, exist_ok=True)

        # Firefox update
        if need_firefox:
            print("🧩 Updating Firefox extension...")
            src = os.path.join(new_tools_root, "ExtensionTemplateFirefox")
            dst = os.path.join(tools_target, "ExtensionTemplateFirefox")
            if os.path.exists(src):
                if os.path.exists(dst):
                    print(f"🗑️ Removing old Firefox extension: {dst}")
                    shutil.rmtree(dst)
                print(f"🚚 Moving new Firefox extension to {tools_target}")
                shutil.move(src, tools_target)
                print("✅ Firefox extension updated successfully")
            else:
                print("❌ [ERROR] New Firefox extension folder not found in archive.")

        # Chrome update
        if need_chrome:
            print("🧩 Updating Chrome extension...")
            src = os.path.join(new_tools_root, "Extention_Family_Chrome")
            dst = os.path.join(tools_target, "Extention_Family_Chrome")
            if os.path.exists(src):
                if os.path.exists(dst):
                    print(f"🗑️ Removing old Chrome extension: {dst}")
                    shutil.rmtree(dst)
                print(f"🚚 Moving new Chrome extension to {tools_target}")
                shutil.move(src, tools_target)
                print("✅ Chrome extension updated successfully")
            else:
                print("❌ [ERROR] New Chrome extension folder not found in archive.")

        # Cleanup extracted folder
        if os.path.exists(extracted_dir):
            print(f"🧹 Cleaning up extracted folder: {extracted_dir}")
            shutil.rmtree(extracted_dir)

        print("🎉 [SUCCESS] Download and update process completed.")
        return 0

    except Exception as e:
        traceback.print_exc()
        print(f"❌ [EXCEPTION] Unexpected error in DownloadAndExtract: {e}")
        return -1



# 🔍 Vérifie les versions distantes et locales des composants, puis signale les mises à jour nécessaires
def checkVersion():
    """
    Check remote and local versions of Python, interface, and extensions.
    Returns a dict with updates if available, "_1" on error, or None if up to date.
    Detailed logging with emojis.
    """
    url = "https://www.dropbox.com/scl/fi/78a38bc4papwzlw80hxti/version.json?rlkey=n7dx5mb8tcctvprn0wq4ojw7m&st=z6vzw0ox&dl=1"

    try:
        print("🌐 Checking latest versions from server...")
        response = requests.get(url, timeout=15)
        if response.status_code != 200:
            print(f"❌ [ERROR] Failed to fetch versions: HTTP {response.status_code}")
            return "_1"

        data = response.json()
        version_updates = {}

        # Server versions
        server_version_python = data.get("version_python")
        server_version_interface = data.get("version_interface")
        server_version_Extention_firefox = data.get("version_Extention_firefox")
        server_version_Extention_Family_Chrome = data.get("version_Extention_Family_Chrome")

        if not all([server_version_python, server_version_interface,
                    server_version_Extention_firefox, server_version_Extention_Family_Chrome]):
            print("❌ [ERROR] Missing version information on server.")
            return "_1"

        # Local versions files
        client_files = {
            "version_python": os.path.join(SCRIPT_DIR, "version.txt"),
            "version_interface": os.path.join(PARENT_DIR, "interface", "version.txt"),
            "version_Extention_firefox": os.path.join(PARENT_DIR, "Tools", "ExtensionTemplateFirefox", "version.txt"),
            "version_Extention_Family_Chrome": os.path.join(PARENT_DIR, "Tools", "Extention_Family_Chrome", "version.txt"),
        }

        client_versions = {}
        for key, path in client_files.items():
            if os.path.exists(path):
                with open(path, "r") as f:
                    client_versions[key] = f.read().strip()
                print(f"📄 {key}: Local version = {client_versions[key]}")
            else:
                client_versions[key] = None
                print(f"⚠️ {key}: Local version file not found.")
                return "_1" 
        # Compare versions
        if server_version_python != client_versions["version_python"]:
            version_updates["version_python"] = server_version_python
            print(f"⬆️ Python update available: {server_version_python}")
        if server_version_interface != client_versions["version_interface"]:
            version_updates["version_interface"] = server_version_interface
            print(f"⬆️ Interface update available: {server_version_interface}")
        if server_version_Extention_firefox != client_versions["version_Extention_firefox"]:
            version_updates["version_Extention_firefox"] = server_version_Extention_firefox
            print(f"⬆️ Firefox extension update available: {server_version_Extention_firefox}")
        if server_version_Extention_Family_Chrome != client_versions["version_Extention_Family_Chrome"]:
            version_updates["version_Extention_Family_Chrome"] = server_version_Extention_Family_Chrome
            print(f"⬆️ Chrome extension update available: {server_version_Extention_Family_Chrome}")

        if version_updates:
            print(f"✅ Updates detected: {version_updates}")
            return version_updates
        else:
            print("✅ All software versions are up to date.")
            return None

    except Exception as e:
        traceback.print_exc()
        print(f"❌ [EXCEPTION] Error checking versions: {e}")
        return "_1"







def set_custom_colored_tab(tab_widget, index, completed_count, not_completed_count):
    # HTML التنسيق
    html_text = (
        f'<div style="text-align:center;margin: 0px;padding: 0px;">'
        f'<span style="font-family:\'Segoe UI\', sans-serif; font-size:14px;">Result ('
        f'<span style="color:#008000;">{completed_count} completed</span> / '
        f'<span style="color:#d90429;">{not_completed_count} not completed</span>)</span>'
        f'</div>'
    )

    tab_widget.setTabText(index, "")

    # إنشاء QLabel وتخصيصه
    label = QLabel()
    label.setTextFormat(Qt.TextFormat.RichText)
    label.setText(html_text)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)


    # تخصيص الحجم: ليأخذ الحجم الكامل للتبويب
    label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    # label.setMinimumSize(tab_widget.tabBar().tabRect(index).size())
    label.setStyleSheet("""
        padding: 0px;
        margin: 0px;
        width:300px;
        margin: 0px auto;
    """)
    # لفه في Widget وتوسيطه بالكامل
    wrapper = QWidget()
    layout = QHBoxLayout(wrapper)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)
    layout.addWidget(label)

    # إضافة العنصر في وسط التبويب
    tab_widget.tabBar().setTabButton(index, QTabBar.ButtonPosition.LeftSide, None)
    tab_widget.tabBar().setTabButton(index, QTabBar.ButtonPosition.RightSide, None)
    tab_widget.tabBar().setTabButton(index, QTabBar.ButtonPosition.LeftSide, wrapper)









# 📊 Lit les résultats depuis un fichier et met à jour l'affichage de l'interface avec les emails par statut
def read_result_and_update_list(window):
    result_file_path = os.path.join(os.path.dirname(__file__), "..", "tools", "result.txt")
    print(f"[INFO] Chemin du fichier résultat : {result_file_path}")

    if not os.path.exists(result_file_path):
        print("[WARNING] Fichier résultat non trouvé.")
        show_critical_message(window, "Information", "No email messages have been processed.\nCheck the filter criteria or new data.")
        return

    errors_dict = {}
    notifications = {}

    try:
        with open(result_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        print(f"[INFO] Nombre de lignes lues : {len(lines)}")

        with open(result_file_path, 'w', encoding='utf-8') as file:
            file.truncate(0)
        print("[INFO] Fichier résultat vidé après lecture.")

        if not lines:
            print("[WARNING] Aucune donnée dans le fichier.")
            QMessageBox.warning(window, "Warning", "No results available.")
            return

        completed_count = 0
        no_completed_count = 0
        all_emails = []
        all_emails_except_completed = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            parts = line.split(":")
            if len(parts) != 4:
                print(f"[WARNING] Ligne ignorée (format incorrect) : {line}")
                continue

            session_id, pid, email, status = parts
            status = status.strip()
            print(f"[DATA] Email traité : {email} | Statut : {status}")

            all_emails.append(email)
            if status != "completed":
                all_emails_except_completed.append(email)
            if status not in errors_dict:
                errors_dict[status] = []
            errors_dict[status].append(email)

            if status == "completed":
                completed_count += 1
            else:
                no_completed_count += 1
        print(f"[INFO] Emails traités : {len(all_emails)}")
        print(f"[INFO] completed = {completed_count} | autres = {no_completed_count}")
        print(f"[DEBUG] Statuts détectés : {list(errors_dict.keys())}")

        # ➕ Ajouter tous les emails dans la catégorie "all"
        errors_dict["all"] = all_emails

        interface_tab_widget = window.findChild(QTabWidget, "interface_2")
        if interface_tab_widget:
            result_found = False
            for i in range(interface_tab_widget.count()):
                tab_text = interface_tab_widget.tabText(i)
                if tab_text.startswith("Result"):
                    print(f"[INFO] Onglet Result trouvé : index {i}")
                    set_custom_colored_tab(interface_tab_widget, i, completed_count, no_completed_count)
                    result_found = True
                    break
            if not result_found:
                print("[ERROR] Onglet commençant par 'Result' introuvable.")
                return
        else:
            print("[ERROR] QTabWidget 'interface_2' introuvable.")
            return

        result_tab_widget = window.findChild(QTabWidget, "tabWidgetResult")
        if not result_tab_widget:
            print("[ERROR] QTabWidget 'tabWidgetResult' introuvable.")
            return

        status_list = ["all", "bad_proxy", "completed", "account_closed", "password_changed", "code_de_validation",
                       "recoverychanged", "Activite_suspecte", "validation_capcha", "restore_account", "others"]

        for status in status_list:
            tab_widget = result_tab_widget.findChild(QWidget, status)
            if tab_widget:
                print(f"[INFO] Traitement du statut : {status}")
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
                        print(f"[INFO] ➕ {count} emails affichés dans l'onglet '{status}'")

                        message_label = tab_widget.findChild(QLabel, "no_data_message")
                        if message_label:
                            message_label.deleteLater()
                    else:
                        list_widget.addItem("⚠ No email data available for this category.\nPlease check again later.")
                        list_widget.show()

        # result_tab_widget.currentChanged.connect(remove_notification)

    except Exception as e:
        QMessageBox.critical(window, "Error", f"An error occurred while displaying the result: {e}")








# 🧹 Supprime les badges de notification d'un onglet donné quand il est sélectionné
def remove_notification(index):
    if index in NOTIFICATION_BADGES:
        badge = NOTIFICATION_BADGES.pop(index, None)
        if badge:
            badge.deleteLater()









# 🔔 Ajoute un badge de notification rouge sur un onglet spécifique pour indiquer le nombre de résultats
def add_notification_badge(tab_widget, tab_index, count):
    if tab_index in NOTIFICATION_BADGES:
        NOTIFICATION_BADGES[tab_index].deleteLater()
        del NOTIFICATION_BADGES[tab_index]

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
        font-size: 14px;
        padding: 3px;
        border-radius: 10px;
        min-width: 15px;
        min-width : 15px;
        text-align: center;
    """)
    badge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    try:
        badge_label.setParent(tab_widget)
        badge_label.move(badge_x, badge_y)
        QTimer.singleShot(100, lambda: badge_label.show())
        NOTIFICATION_BADGES[tab_index] = badge_label
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
            font-family: "Times", "Times New Roman", serif;
            font-size: 16px;
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
            font-size: 16px;
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







def extraire_bloc_complet(contenu, process_key):
    start = contenu.find(f'"{process_key}": [')
    if start == -1:
        return None

    pos = start + len(f'"{process_key}": [')
    depth = 1
    while pos < len(contenu):
        char = contenu[pos]
        if char == '[':
            depth += 1
        elif char == ']':
            depth -= 1
            if depth == 0:
                return contenu[start:pos+1]
        pos += 1
    return None  







def modifier_extension_par_traitement(email_folder):
    traitement_path = os.path.join(email_folder, 'traitement.json')
    gmail_process_path = os.path.join(email_folder, 'gmail_process.js')

    print(f"📁 Vérification de l'existence des fichiers nécessaires...")
    print(f"Chemin traitement.json : {traitement_path}")
    print(f"Chemin gmail_process.js : {gmail_process_path}")

    if not os.path.exists(traitement_path) or not os.path.exists(gmail_process_path):
        print("❌ Fichier traitement.json ou gmail_process.js introuvable.")
        return

    print("✅ Lecture du fichier traitement.json ...")
    with open(traitement_path, 'r', encoding='utf-8') as f:
        traitement_data = json.load(f)

    print("\n📘 Contenu de traitement.json (formaté):")
    print("=" * 60)
    print(json.dumps(traitement_data, indent=2, ensure_ascii=False))
    print("=" * 60)

    remplacement_dict = {}
    print("🔍 Analyse du contenu de traitement.json ...")
    for obj in traitement_data:
        process_name = obj.get("process", "")
        if process_name.startswith("google") and "search" in obj:
            remplacement_dict[process_name] = obj["search"]
            print(f"✅ Processus détecté: {process_name} | 🔁 Valeur à remplacer: {obj['search']}")

    if not remplacement_dict:
        print("⚠️ Aucun processus avec clé 'search' trouvé dans traitement.json.")
        return

    print("📄 Lecture du fichier gmail_process.js ...")
    with open(gmail_process_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    for process_key, search_value in remplacement_dict.items():
        print(f"\n🔧 Traitement du bloc : {process_key}")

        bloc_complet = extraire_bloc_complet(content, process_key)

        if bloc_complet is None:
            print(f"⚠️ Le processus '{process_key}' n'existe pas ou le bloc est mal formé dans gmail_process.js.")
            continue

        if '__search_value__' not in bloc_complet:
            print(f"⚠️ Aucun '__search_value__' à remplacer dans {process_key}")
            print("🔍 Contenu du bloc pour inspection:")
            print("=" * 50)
            print(bloc_complet[:500] + ('...' if len(bloc_complet) > 500 else ''))
            print("=" * 50)
            continue

        # Remplacement
        bloc_modifie = bloc_complet.replace('"__search_value__"', f'"{search_value}"')

        print("📋 Bloc AVANT modification:")
        print("=" * 50)
        print(bloc_complet)
        print("=" * 50)

        print("✅ Bloc APRÈS modification:")
        print("=" * 50)
        print(bloc_modifie)
        print("=" * 50)

        # Appliquer dans le contenu complet
        content = content.replace(bloc_complet, bloc_modifie)

    print("💾 Enregistrement du fichier gmail_process.js avec les modifications ...")
    with open(gmail_process_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print("✅✅ Le fichier gmail_process.js a été mis à jour avec succès !")







# 🧩 Génère une extension Chrome personnalisée en copiant et modifiant des fichiers modèles selon les données de l'utilisateur.
def create_extension_for_email(email, password, host, port, user, passwordP, recovry, new_password, new_recovry, IDL ,selected_Browser):
    print(f"Function create_extension_for_email called with selected_Browser: {selected_Browser}")
    template_directory = (
        TEMPLATE_DIRECTORY_FIREFOX 
        if selected_Browser.lower() == "firefox"
        else TEMPLATE_DIRECTORY_CHROME
    )
    if not os.path.exists(BASE_DIRECTORY):
        os.makedirs(BASE_DIRECTORY)
        
    email_folder = os.path.join(BASE_DIRECTORY, email)

    if os.path.exists(email_folder):
        shutil.rmtree(email_folder)  
    os.makedirs(email_folder)  

    session_path = os.path.join(APPDATA_DIR, "session.txt")
    session = ""
    if os.path.exists(session_path):
        with open(session_path, "r", encoding="utf-8") as f:
            session = f.read().strip()
    else:
        print("[❌] session.txt introuvable")


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
        content = content.replace("__IDL__", IDL).replace("__email__", email).replace("___session_user__", session);
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
                    .replace("__email__", email)
                    )
        with open(background_js_path, 'w', encoding='utf-8') as file:
            file.write(content)

    gmail_process_js_path = os.path.join(email_folder, "gmail_process.js")
    if os.path.exists(gmail_process_js_path):
        with open(gmail_process_js_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        content = (content
                            .replace("__email__", f'{email}')
                            .replace("__password__", f'{password}')
                            .replace("__recovry__", f'{recovry}')
                            .replace("__newPassword__", f'{new_password}')
                            .replace("__newRecovry__", f'{new_recovry}')
                            )
        with open(gmail_process_js_path, 'w', encoding='utf-8') as file:
            file.write(content)

    reporting_actions_js_path = os.path.join(email_folder, "ReportingActions.js")
    if os.path.exists(reporting_actions_js_path):
        with open(reporting_actions_js_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read()
        content = (content
                    .replace("__IDL__", IDL)
                    .replace("__email__", email)
                )
        with open(reporting_actions_js_path, 'w', encoding='utf-8') as file:
            file.write(content)

    modifier_extension_par_traitement(email_folder )








# 📝 Enregistre de façon unique le PID, l'email et l'ID de session dans un fichier texte lié à l'email.
def add_pid_to_text_file(pid, email , inserted_id):
    print(f"🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴🔴 Function add_pid_to_text_file called with PID: {pid}, Email: {email}")
    text_file_path = os.path.join(BASE_DIRECTORY, email , "data.txt")

    os.makedirs(os.path.dirname(text_file_path), exist_ok=True)

    if os.path.exists(text_file_path):
        with open(text_file_path, 'r', encoding='utf-8') as file:
            existing_entries = set(file.read().splitlines())
    else:
        existing_entries = set()

    print(f"PID: {pid}, Email: {email}")
    entry = f"{pid}:{email}:{session_id}:{inserted_id}" 

    if entry not in existing_entries:
        with open(text_file_path, 'w', encoding='utf-8') as file:
            file.write(f"{entry}\n")








def get_firefox_profiles_in_use():
    """Retourne les profils Firefox actuellement utilisés (lockés)"""
    base_path = os.path.join(SCRIPT_DIR, ".." ,"tools", "Profiles", "firefox")

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
    global EXTRACTION_THREAD, CLOSE_BROWSER_THREAD, PROCESS_PIDS, LOGS_RUNNING, SELECTED_BROWSER_GLOBAL

    print("Stopping all processes...")
    LOGS_RUNNING = False

    if EXTRACTION_THREAD:
        print("Stopping extraction thread...")
        EXTRACTION_THREAD.stop_flag = True
        EXTRACTION_THREAD.wait()
        EXTRACTION_THREAD = None
        print("Extraction thread stopped.")


    if CLOSE_BROWSER_THREAD:
        print("Stopping close Chrome thread...")
        CLOSE_BROWSER_THREAD.stop_flag = True
        CLOSE_BROWSER_THREAD.wait()
        CLOSE_BROWSER_THREAD = None
        print("Close Chrome thread stopped.")

    if EXTRACTION_THREAD and EXTRACTION_THREAD.isRunning():
        print("Waiting for extraction thread to finish before updating UI...")
        EXTRACTION_THREAD.finished.connect(
            lambda: QTimer.singleShot(100, 
            lambda: read_result_and_update_list(window))
        )

    if SELECTED_BROWSER_GLOBAL != "firefox":
        for pid in PROCESS_PIDS[:]:
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
                if pid in PROCESS_PIDS:
                    PROCESS_PIDS.remove(pid)
                    print(f"PID {pid} removed from process list.")
    else:
            try:
                close_windows_by_profiles(FIREFOX_LAUNCH)
            except Exception as e:
                print(f"⚠️ Erreur lors de la fermeture des profils Firefox: {e}")
 
            finally:
                for pid in PROCESS_PIDS[:]:
                    PROCESS_PIDS.remove(pid)
                    print(f"PID {pid} removed from process list.")








# 🚀 Lance un thread pour fermer automatiquement les processus Chrome actifs.
def launch_close_chrome(selected_Browser , username):
    global CLOSE_BROWSER_THREAD
    CLOSE_BROWSER_THREAD = CloseBrowserThread( selected_Browser ,username)
    CLOSE_BROWSER_THREAD.progress.connect(lambda msg: print(msg))
    CLOSE_BROWSER_THREAD.start()








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








def find_chrome_for_testing(base_dir=None):
    if base_dir is None:
        base_dir = os.path.expanduser(r"~\chrome")  # dossier par défaut Puppeteer
    print(f"🔍 Recherche dans le dossier : {base_dir}")

    # Recherche tous les chrome.exe dans les sous-dossiers
    pattern = os.path.join(base_dir, "**", "chrome.exe")
    matches = glob.glob(pattern, recursive=True)

    if matches:
        print(f"✅ {len(matches)} version(s) de Chrome for Testing trouvée(s) :")
        for i, path in enumerate(matches, 1):
            print(f"  {i}. {path}")
        return matches[0]  # Retourne le premier chemin trouvé (modifiable selon besoin)
    else:
        print("❌ Aucune version de Chrome for Testing trouvée.")
        return None







# 🛠️ Démarre le processus d'extraction en lançant le thread principal avec les paramètres utilisateur, après validation des entrées et préparation de l'environnement.
def start_extraction(window, data_list, entered_number , selected_Browser , Isp , unique_id , output_json_final , username):
    global EXTRACTION_THREAD 

    logs_directory = os.path.join(SCRIPT_DIR, '..', 'Tools', 'logs')
    
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


    launch_close_chrome(selected_Browser , username)
    # find_chrome_for_testing() 
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
    EXTRACTION_THREAD = ExtractionThread(
        data_list, session_id, entered_number, browser_path, BASE_DIRECTORY, window ,selected_Browser , Isp , unique_id , output_json_final
    )
    EXTRACTION_THREAD.progress.connect(lambda msg: print(msg))
    EXTRACTION_THREAD.finished.connect(lambda: QMessageBox.information(window, "Terminé", "L'extraction est terminée."))
    EXTRACTION_THREAD.stopped.connect(lambda msg: QMessageBox.warning(window, "Arrêté", msg))
    EXTRACTION_THREAD.start()







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







def parse_random_range(text):
    try:
        if ',' in text:
            min_val, max_val = map(int, text.split(','))
            return random.randint(min_val, max_val)
        return int(text)
    except:
        return 0







def saveEmail(params):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0'
    }
    API = "https://reporting.nrb-apps.com/pub/h_new.php?k=mP5Q2XYrK9E67Y1&rID=1&rv4=1"
    
    response_text = ''
    
    while response_text == '':
        try:
            print(f"🌐 [API] Envoi de la requête ➜ {API}")
            print(f"📤 [DATA] Paramètres envoyés: {params}")

            response = requests.post(API, headers=headers, verify=False, data=params)
            
            print(f"📥 [HTTP] Code de réponse: {response.status_code}")
            print(f"📄 [HTTP] Réponse brute:\n{response.text}")

            # Vérification d'erreur HTTP
            response.raise_for_status()

            response_text = response.text
            break

        except requests.exceptions.RequestException as req_err:
            print(f"💥 [ERREUR DE REQUÊTE] : {req_err}")
            print("⏳ Nouvelle tentative dans 5 secondes...")
            time.sleep(5)
        except Exception as e:
            print(f"💥 [EXCEPTION] Erreur inconnue : {e}")
            print("⏳ Nouvelle tentative dans 5 secondes...")
            time.sleep(5)

    return response_text








def sendStatus(params):
    print( "\n📤 Préparation de l'envoi du statut à l'API...")
    print("🧾 Paramètres envoyés :")
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0'
    }
    API = "http://reporting.nrb-apps.com:8585/rep/pub/email_status.php?k=mP5Q2XYrK9E67Y1&rID=1&rv4=1"

    response = ''
    cpt = 0

    print("\n📤 Envoi du statut de l'email à l'API...")

    while response == '':
        try:
            res = requests.post(API, headers=headers, verify=False, data=params)
            response = res.text

            print("✅ Statut envoyé avec succès !")
            print("🔽 Détails de la réponse de l'API :")
            print(response)

            break
        except Exception as e:
            print(f"\n❌ Erreur [API:h CG] : Connexion refusée par le serveur... ({e})")
            print("🕒 Nouvelle tentative dans 5 secondes...")

            cpt += 1
            if cpt == 5:
                print("❌ Échec après 5 tentatives.")
                break
            time.sleep(5)
            continue

    return response







# Thread pour afficher les logs en temps réel depuis une liste partagée.
# Émet un signal log_signal à chaque nouvelle entrée de log.
class LogsDisplayThread(QThread):

    log_signal = pyqtSignal(str)


    def __init__(self, logs, parent=None):
        super().__init__(parent)
        self.logs = logs
        self.stop_flag = False


    def run(self):
        """Boucle d'affichage continue tant que LOGS_RUNNING est actif."""
        global LOGS_RUNNING 
        while LOGS_RUNNING: 
            if self.logs:
                log_entry = self.logs.pop(0)
                self.log_signal.emit(log_entry)
            else:
                time.sleep(1)  


    def stop(self):
        self.stop_flag = True
        self.wait()









def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))







def encrypt_aes_gcm(password: str, plaintext: str) -> str:
    salt = os.urandom(SALT_LEN)
    key = _derive_key(password, salt)
    iv = os.urandom(IV_LEN)

    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)

    payload = salt + iv + ct_and_tag
    # ✅ Retourner en hexadécimal (minuscule garanti)
    return payload.hex()





def updated_secure_preferences(profile_name, RESULTATS_EX):
    try:
        secure_preferences_path = os.path.abspath(os.path.join(
            SCRIPT_DIR, "..", "tools", "Profiles", "chrome", profile_name, profile_name, "Secure Preferences"
        ))

        # 🖨️ Affichage du chemin complet
        print("🔍 Étape 1 : Vérification du chemin du fichier Secure Preferences...")
        print(f"📂 Chemin complet du fichier 'Secure Preferences' : {secure_preferences_path}")

        # Vérification existence fichier
        if not os.path.exists(secure_preferences_path):
            print(f"❌ Le fichier 'Secure Preferences' est introuvable pour le profil '{profile_name}'.")
            print("👉 Veuillez contacter le support technique pour assistance.")
            return None

        print("✅ Étape 2 : Fichier trouvé. Lecture du contenu JSON...")
        with open(secure_preferences_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Vérification structure
        if "extensions" not in data:
            print("⚠️ Aucune clé 'extensions' trouvée. Initialisation forcée...")
            data["extensions"] = {}

        data["extensions"].setdefault("ui", {})
        # data["extensions"].setdefault("settings", {})
        # data.setdefault("protection", {}).setdefault("macs", {}).setdefault("extensions", {}).setdefault("settings", {})
        # data["protection"]["macs"]["extensions"].setdefault("ui", {})

        print("✅ Étape 3 : Structure JSON vérifiée et préparée.")

        # 🔄 Ajouter les résultats sans supprimer les anciennes valeurs
        print("🔄 Étape 4 : Mise à jour des paramètres avec RESULTATS_EX...")
        for idx, item in enumerate(RESULTATS_EX, start=1):
            print(f"➡️ Traitement de l'élément {idx} : {item}")

            if not isinstance(item, dict):
                print("⚠️ Ignoré (élément non dict).")
                continue

            for k, v in item.items():
                if isinstance(v, dict) and "account_extension_type" in v:
                    data["extensions"]["settings"][k] = v
                    print(f"   📝 Ajout/maj dans extensions.settings[{k}] = {v}")

                elif isinstance(v, str) and len(v) > 30 and k != "developer_mode":
                    data["protection"]["macs"]["extensions"]["settings"][k] = v
                    print(f"   🔐 Ajout/maj MAC dans protection.macs.extensions.settings[{k}]")

                elif isinstance(v, bool) and k == "developer_mode":
                    data["extensions"]["ui"]["developer_mode"] = v
                    print(f"   ⚙️ developer_mode activé/désactivé (extensions.ui) : {v}")

                elif isinstance(v, str) and k == "developer_mode":
                    data["protection"]["macs"]["extensions"]["ui"]["developer_mode"] = v
                    print(f"   🔐 MAC pour developer_mode ajouté dans protection.macs.extensions.ui")

        # Sauvegarde
        print("💾 Étape 5 : Écriture du fichier JSON mis à jour...")
        with open(secure_preferences_path, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(',', ':'), ensure_ascii=False)

        print("✅ Étape 6 : Mise à jour terminée avec succès !")
        return data

    except Exception as e:
        print(f"❌ Erreur lors de la mise à jour du fichier Secure Preferences : {e}")
        return None






def search_keys(data, CLES_RECHERCHE, RESULTATS):
    """Recherche récursive des clés spécifiques dans le JSON"""
    if isinstance(data, dict):
        for key, value in data.items():
            if key in CLES_RECHERCHE:
                print(f"🔑 Clé trouvée : {key} ➜ Valeur : {value}")  # Affichage détaillé
                RESULTATS.append({key: value})
            # Recherche récursive dans les sous-éléments
            search_keys(value, CLES_RECHERCHE, RESULTATS)
    elif isinstance(data, list):
        for item in data:
            search_keys(item, CLES_RECHERCHE, RESULTATS)








def Upload_EXTENTION_PROXY(profile_name, CLES_RECHERCHE, RESULTATS):
    print("====================================================")
    print(f"📂 Début du traitement pour le profil : {profile_name}")
    print("====================================================")

    # Construction du chemin complet du fichier "Secure Preferences"
    profile_path_file_secure_preferences = os.path.join(
        CONFIG_PROFILE, profile_name, "Secure Preferences"
    )
    print(f"🔍 Chemin du fichier Secure Preferences : {profile_path_file_secure_preferences}")

    # Vérification si le fichier existe
    if not os.path.exists(profile_path_file_secure_preferences):
        print("❌ Erreur : le fichier 'Secure Preferences' est introuvable !")
        print("👉 Vérifiez que le profil Chrome existe correctement ou contactez le support.")
        return None

    try:
        # Lecture du fichier JSON
        print("📖 Lecture du fichier JSON en cours ...")
        with open(profile_path_file_secure_preferences, "r", encoding="utf-8") as f:
            data = json.load(f)
        print("✅ Lecture réussie du fichier Secure Preferences.")

        # Nettoyage de la liste des résultats
        RESULTATS.clear()
        print("🧹 Initialisation de la liste des résultats (RESULTATS) ...")

        # Recherche des clés
        print(f"🔎 Début de la recherche des clés : {CLES_RECHERCHE}")
        search_keys(data, CLES_RECHERCHE, RESULTATS)

        # Affichage des résultats trouvés
        print("📌 Résultats trouvés :")
        if RESULTATS:
            for idx, item in enumerate(RESULTATS, start=1):
                print(f"   {idx}. {item}")
        else:
            print("⚠️ Aucun résultat trouvé pour les clés spécifiées.")

        print("====================================================")
        print(f"✅ Fin du traitement pour le profil : {profile_name}")
        print("====================================================")

        return RESULTATS

    except Exception as e:
        print("❌ Une erreur inattendue est survenue lors du traitement du fichier Secure Preferences.")
        print(f"➡️ Détail de l'erreur : {e}")
        return None







def run_browser_create_profile(profile_name):
    """
    🚀 Crée un profil Chrome spécifique et lance un navigateur temporairement.
    
    Arguments:
        profile_name (str): Nom du profil Chrome à créer ou à utiliser.
    """

    print("=============================================")
    print("🔧 Initialisation de la création du profil...")
    print("=============================================")

    # 📂 Définir le chemin du profil (remontée de 2 niveaux pour Desktop\Tools)
    profile_path = os.path.abspath(os.path.join(SCRIPT_DIR, '..', 'Tools', 'Profiles', 'chrome', profile_name))
    print(f"📂 Chemin complet du profil : {profile_path}")

    # Créer le dossier si non existant
    if not os.path.exists(profile_path):
        os.makedirs(profile_path)
        print(f"✅ Dossier de profil créé : {profile_path}")
    else:
        print(f"✅ Profil déjà existant : {profile_path}")

    # ⚙️ Configuration des options Chrome
    chrome_options = Options()
    chrome_options.add_argument(f"--user-data-dir={profile_path}")
    chrome_options.add_argument(f"--profile-directory={profile_name}")
    chrome_options.add_argument("--lang=en-US")
    chrome_options.add_argument("--no-first-run")
    chrome_options.add_argument("--no-default-browser-check")
    chrome_options.add_argument("--disable-sync")

    print("⚙️ Options appliquées à Chrome :")
    for arg in chrome_options.arguments:
        print(f"   ➜ {arg}")

    # 🚀 Lancement du navigateur
    print("🌐 Lancement de Chrome avec ce profil...")
    driver = None
    try:
        driver = webdriver.Chrome(options=chrome_options)
        print("✅ Navigateur lancé avec succès !")
        print("⏳ Attente de 2 secondes pour stabilisation...")
        time.sleep(2)

    except Exception as e:
        print(f"❌ Erreur lors du lancement du navigateur : {e}")

    finally:
        if driver:
            print("🛑 Fermeture du navigateur...")
            driver.quit()
            print("✅ Navigateur fermé proprement.")

        print("=============================================")
        print("🎉 Profil créé et testé avec succès.")
        print("=============================================")






# Thread responsable du traitement de l'extraction des emails.
# Gère l'exécution des navigateurs avec les extensions, l'enregistrement des logs,
# et la gestion des processus.
class ExtractionThread(QThread):

    progress = pyqtSignal(str)  
    finished = pyqtSignal()  
    stopped = pyqtSignal(str)

    def __init__(self, data_list, session_id, entered_number, Browser_path, BASE_DIRECTORY, main_window ,selected_Browser,Isp , unique_id , output_json_final):  
        super().__init__()
        self.data_list = data_list  
        self.session_id = session_id  
        self.entered_number = entered_number  
        self.Browser_path = Browser_path 
        self.BASE_DIRECTORY = BASE_DIRECTORY  
        self.stop_flag = False
        self.emails_processed = 0 
        self.selected_Browser = selected_Browser
        self.main_window = main_window 
        self.Isp=Isp
        self.unique_id=unique_id
        self.output_json_final = output_json_final

    def run(self):
        # Exécute la boucle principale de traitement des emails :
        # - Création des profils/extensions
        # - Lancement des navigateurs
        # - Gestion des processus

        global PROCESS_PIDS, LOGS_RUNNING  ,SELECTED_BROWSER_GLOBAL  ,RESULTATS_EX 
        SELECTED_BROWSER_GLOBAL=self.selected_Browser
        remaining_emails = self.data_list[:]  
        log_message("[INFO] Processing started")
        total_emails = len(self.data_list) 

        session_path = os.path.join(APPDATA_DIR, "session.txt")
        session = ""
        if os.path.exists(session_path):
            with open(session_path, "r") as f:
                encrypted = f.read().strip()
                if encrypted:
                    print("🔐 [SESSION] Déchiffrement des données de session...")
                    decrypted = decrypt_date(encrypted, key)

                    if "::" in decrypted:
                        parts = decrypted.split("::", 2)
                        if len(parts) == 3:
                            username = parts[0].strip()
                            date_str = parts[1].strip()
                            p_entity = parts[2].strip()
        else:
            print("[❌] session.txt introuvable")

        if self.selected_Browser == "chrome":
            print(f"✅ Navigateur sélectionné : {self.selected_Browser}")


            RESULTATS_EX = Upload_EXTENTION_PROXY("default", CLES_RECHERCHE_EX2, RESULTATS)
            print("👽👽👽👽👽👽👽👽 Résultats EX2 :")
            for item in RESULTATS_EX:
                print(json.dumps(item, indent=4, ensure_ascii=False))


        while remaining_emails or PROCESS_PIDS:  
            if self.stop_flag:  
                LOGS_RUNNING=False 
                log_message("[INFO] Processing interrupted by user.")
                break


            if len(PROCESS_PIDS) < self.entered_number and remaining_emails:
                next_email = remaining_emails.pop(0)  
                email_value = get_key_value(next_email, ["email", "Email"])
                log_message(f"[INFO] Processing the email:  {email_value}")

        

                try:
                    profile_email = get_key_value(next_email, ["email", "Email"])
                    profile_password = get_key_value(next_email, ["password_email", "passwordEmail"])
                    ip_address =get_key_value(next_email, ["ip_address", "ipAddress"])
                    port = get_key_value(next_email, ["port"])
                    login = get_key_value(next_email, ["login"])
                    password = get_key_value(next_email, ["password"])
                    recovery_email = get_key_value(next_email, ["recovery_email", "recoveryEmail"])
                    new_recovery_email = get_key_value(next_email, ["new_recovery_email", "neWrecoveryEmail"])


                    params = {
                        'l':encrypt_date(username,key),
                        'login': username,
                        'entity': p_entity,
                        'isp': self.Isp,
                        'action': json.dumps(self.output_json_final),
                        'email': email_value,
                        'password': '',
                        'proxy_ip': ip_address+":"+port,
                        'proxy_login': f"{login};{password}" if login != username else "",
                        'email_recovery': '',
                        'line': '',
                        'app': "V4",
                        'e_pid':self.unique_id
                    }
                    inserted_id=saveEmail(params)
                    new_password = generate_gmail_password(16)

                    logs_directory = os.path.join(SCRIPT_DIR, '..' ,'Tools','logs')
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

                  




                    if self.selected_Browser == "firefox":
                        create_extension_for_email(
                            profile_email, profile_password,
                            f'"{ip_address}"', f'"{port}"',
                            f'"{login}"', f'"{password}"', f'{recovery_email}',
                            new_password, new_recovery_email, f'"{self.session_id}"' , self.selected_Browser 
                        )
                        create_firefox_profile(profile_email)
                        print('➡️➡️➡️➡️➡️➡️ PROCESS_PIDS : ' ,PROCESS_PIDS)

                        eb_ext_path = get_web_ext_path()
                        print("eb_ext_path : ", eb_ext_path)

                        command = [
                            eb_ext_path,
                            "run",
                            "--source-dir", os.path.join(self.BASE_DIRECTORY, profile_email),
                            "--firefox-profile", os.path.join(SCRIPT_DIR, '..', 'Tools', 'Profiles', 'firefox', profile_email),
                            "--keep-profile-changes",  
                            "--no-reload"
                        ]
              


                        process = subprocess.Popen(command) 
                        PROCESS_PIDS.append(process.pid) 
                        ts   = time.time()
                        FIREFOX_LAUNCH.append({
                            'profile': profile_email,
                            'create_time': ts,
                            'proc': process,
                            'hwnd': None
                        })
                        print("Firefox launched with PID: ", process.pid)
                        add_pid_to_text_file(process.pid, profile_email , inserted_id)

                    elif self.selected_Browser in ["edge", "icedragon", "Comodo"]:
                        print(f"✅ Navigateur sélectionné : {self.selected_Browser}")
                        command = [
                            self.Browser_path,
                            f"--user-data-dir={os.path.join(SCRIPT_DIR, '..', 'Tools', 'Profiles', 'chrome', profile_email)}",
                            f"--disable-extensions-except={os.path.join(self.BASE_DIRECTORY, profile_email)}",
                            f"--load-extension={os.path.join(self.BASE_DIRECTORY, profile_email)}",
                            "--no-first-run",
                            "--no-default-browser-check",
                            "--disable-sync"
                        ]
                        process = subprocess.Popen(command) 
                        PROCESS_PIDS.append(process.pid) 
                        print('➡️➡️➡️➡️➡️➡️ PROCESS_PIDS : ' ,PROCESS_PIDS)
                        add_pid_to_text_file(process.pid, profile_email , inserted_id)
                    
                    else:

                        
                        # command = [
                        #     self.Browser_path,
                        #     f"--user-data-dir={os.path.join(SCRIPT_DIR,'..','Tools', 'Profiles','chrome', profile_email)}",
                        #     f"--disable-extensions-except={os.path.join(self.BASE_DIRECTORY, profile_email)}",
                        #     f"--load-extension={os.path.join(self.BASE_DIRECTORY, profile_email)}",
                        #     "--no-first-run",
                        #     "--no-default-browser-check",
                        #     "--disable-sync"
                        # ]

                   

                        profiles_dir = os.path.join(SCRIPT_DIR,'..','Tools', 'Profiles','chrome')
                        if not os.path.exists(profiles_dir):
                            os.makedirs(profiles_dir)

                        profile_path = os.path.join(profiles_dir,profile_email)
                        if not os.path.exists(profile_path):
                            print(f"🆕 Création du profil pour {profile_email}")
                            run_browser_create_profile(profile_email)
                            time.sleep(3)
                        else:
                            print(f"✅ Profil déjà existant pour {profile_email}")   


                        if not  RESULTATS_EX:
                            error_msg = (
                                "❌ An issue occurred while copying the JSON file to the template profile.\n"
                                "➡ Please contact support."
                            )
                            log_message(error_msg)   
                            self.stopped.emit(error_msg)  
                            self.stop_flag = True   
                            return                   
                        else:
                            print(f"✅ Profil prêt pour {profile_email} avec les paramètres proxy.")
                            updated_secure_preferences(profile_email, RESULTATS_EX)
                            time.sleep(2)



                        cmd = [
                            self.Browser_path,
                            f"--user-data-dir={os.path.join(SCRIPT_DIR, '..', 'Tools', 'Profiles', 'chrome', profile_email)}",
                            f'--profile-directory={profile_email}',
                            '--lang=En-US',
                            '--no-first-run',
                        ]

                        process = subprocess.Popen(cmd)

                        time.sleep(3)
                        b64 = encrypt_aes_gcm("A9!fP3z$wQ8@rX7kM2#dN6^bH1&yL4t*", f"{ip_address};{port};{login};{password};{profile_email};{profile_password};{recovery_email}")
                        command = [
                            get_browser_path("chrome.exe"),
                            f"--user-data-dir={os.path.join(SCRIPT_DIR, '..', 'Tools', 'Profiles', 'chrome', profile_email)}",
                            f'--profile-directory={profile_email}',
                            f'https://{b64}{combined_keys}.com',
                            '--lang=En-US',
                            '--no-first-run',
                        ]



                        process1 = subprocess.Popen(command) 
                        PROCESS_PIDS.append(process.pid) 
                        print('➡️➡️➡️➡️➡️➡️ PROCESS_PIDS : ' ,PROCESS_PIDS)
                        add_pid_to_text_file(process.pid, profile_email , inserted_id)
             
                    self.emails_processed += 1  

                except Exception as e:
                    log_message(f"[INFO] Erreur : {e}")
            self.msleep(1000) 

        log_message("[INFO] Processing finished for all emails.") 
        time.sleep(3)
        LOGS_RUNNING=False
        self.finished.emit()















# Thread qui surveille la fin des processus Chrome/Firefox lancés
# et qui traite les fichiers de session et logs générés dans le dossier Downloads.
class CloseBrowserThread(QThread):


    progress = pyqtSignal(str)  


    def __init__(self , selected_Browser, username):
        super().__init__()
        self.selected_Browser = selected_Browser
        self.username =username
        self.session_id = session_id  
        self.stop_flag = False 
        self.downloads_folder = user_downloads_dir() 




    def run(self):
        # Boucle de surveillance continue tant que tous les processus ne sont pas terminés.
        # Traite les fichiers de session et de log détectés.

        # print("Dossier Téléchargements :", self.downloads_folder)
        # print("[DEBUG] Run CloseBrowserThread")
        # print("[Thread] Dossier Téléchargements :", self.downloads_folder)
        # print("[Thread] Démarrage du thread de fermeture des navigateurs...")
        time.sleep(10)
        session_path = os.path.join(APPDATA_DIR, "session.txt")
        session = ""
        if os.path.exists(session_path):
            with open(session_path, "r", encoding="utf-8") as f:
                session = f.read().strip()
        else:
            print("[❌] session.txt introuvable")

        while not self.stop_flag:  
            # print("🫀🫀🫀🫀🫀🫀🫀🫀🫀 PROCESS_PIDS : ", PROCESS_PIDS)
            # print("[Thread] Vérification des processus restants...")

            if not PROCESS_PIDS:
                # print("🧠🧠🧠🧠🧠🧠🧠🧠🧠 PROCESS_PIDS : ", PROCESS_PIDS)

                # print("[Thread] Tous les processus ont été arrêtés. Fin du thread.")
                # ici fais active de button
                break

            files = [f for f in os.listdir(self.downloads_folder) if f.startswith(self.session_id) and f.endswith(".txt")]
            log_files = [f for f in os.listdir(self.downloads_folder) if f.startswith("log_") and f.endswith(".txt")]
            # affiche les files de log et de session détectés
      
            # if files:
            #     print("Fichiers de session détectés :")
            #     for file in files:
            #         print(f" - {file}")
            # else:
            #     print("Aucun files de session détecté.")

            # # Affichage des fichiers de log
            # if log_files:
            #     print("Fichiers de log détectés :")
            #     for file in log_files:
            #         print(f" - {file}")
            # else:
            #     print("Aucun fichier de log détecté.")




            # la probleme cet partie de code affiche mais les autre print dans cet classe ne s'affiche pas
            # print("Dossier Téléchargements :", self.downloads_folder)
            # print(f"[Thread] Fichiers de session détectés: {files}")
            # print(f"[Thread] Fichiers de log détectés: {log_files}")
            # print(f"[Thread] session_id: {self.session_id}")

            for file_name in files:
                file_path = os.path.join(self.downloads_folder, file_name)
                if os.path.exists(file_path):
                    print(f"[Thread] Fichier de session détecté: {file_name}")


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
                    futures.append(executor.submit(self.process_session_file, file_name, self.downloads_folder , self.selected_Browser, session))

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

            logs_directory = os.path.join(SCRIPT_DIR, '..','Tools', 'logs')
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





    def process_session_file(self, file_name, downloads_folder , selected_Browser, session):
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

            session_id, pid, email, etat  = match.groups()
            print(f"[Session Info] PID: {pid}, Email: {email}, État: {etat}")

            log_message(f"[INFO] Email {email} has completed  processing with status {etat}.")

            # text_file_path = os.path.join(BASE_DIRECTORY, email , "data.txt")

            text_file_path = os.path.join(BASE_DIRECTORY, email , "data.txt")

            try:
                with open(text_file_path, 'r', encoding='utf-8') as file:
                    first_line = file.readline().strip()  # lire juste la première ligne

                    parts = first_line.split(":")
                    if len(parts) >= 4:
                        inserted_id = parts[3]
                        print(f"😶‍🌫️😶‍🌫️ ID extrait : {inserted_id}")
                    else:
                        return f"⚠️ Format de ligne invalide dans le fichier : {first_line}"

            except Exception as e:
                return f"⚠️ Erreur lors de la lecture du fichier {file_path}: {e}"

            
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    file_content = file.read().strip()
            except Exception as e:
                return f"⚠️ Erreur lors de la lecture du fichier {file_name}: {e}"
            
            result_file_path = os.path.join(SCRIPT_DIR, '..','Tools', "result.txt")
            try:
                with open(result_file_path, 'a', encoding='utf-8') as result_file:
                    result_file.write(f"{session_id}:{pid}:{email}:{etat}\n")
                    params = {
                        'id': inserted_id,
                        'login': self.username,
                        'status': 'OK' if etat == "completed" else 'NotOK',
                        'error':  '' if etat == "completed" else etat
                    }

                    sendStatus(params)

            except Exception as e:
                return f"⚠️ Erreur lors de l'écriture dans le fichier {file_name}: {e}"

         
            pid = int(pid)
            if pid in PROCESS_PIDS: 
                print(f"[Session] Tentative de fermeture du processus PID {pid} ({email})")
                log_message(f"[INFO] Attempting to terminate process:  {email}.")
                if selected_Browser == "firefox":
                    try:
                        print("browser : ", selected_Browser)
                        print('✅✅✅✅✅✅✅✅PID : ', pid)
                        self.find_firefox_window(email)
                        self.wait_then_close(email)
                        PROCESS_PIDS.remove(pid)   
                        print(f"Processus {pid} ({email}) terminé.")
                    except Exception as e:
                        print(f"⚠️ Erreur lors de la fermeture du processus {pid} ({email}): {e}")
                    
                else:
                    try:
                        print('✅✅✅✅✅✅✅✅✅✅ PID : ', pid)
                        os.kill(pid, signal.SIGTERM) 
                        PROCESS_PIDS.remove(pid)   
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
        entry = next((e for e in FIREFOX_LAUNCH if e['profile'] == profile_email), None)
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




    def wait_then_close(self, profile_email):
        entry = next((e for e in FIREFOX_LAUNCH if e['profile'] == profile_email), None)
        if not entry or not entry.get('hwnd'):
            print(f"❌ Aucune fenêtre trouvée pour {profile_email}.")
            return
        
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
                painter.setBrush(QtGui.QBrush(QtGui.QColor("#669bbc")))
            else:
                painter.setBrush(QtGui.QBrush(QtGui.QColor("#F5F5F5")))
            painter.setPen(QtCore.Qt.PenStyle.NoPen)
            painter.drawRect(rect)  
            border_pen = QtGui.QPen(QtGui.QColor("#669bbc"))
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








# 📥 Télécharger fichier depuis URL
def download_file(url, dest_path):
    try:
        print(f"⬇️ Téléchargement depuis : {url}")
        response = requests.get(url, stream=True, verify=False)
        response.raise_for_status()
        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0

        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(1024):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        percent = (downloaded / total_size) * 100
                        print(f"   → Progression : {percent:.2f}%", end="\r")
        print(f"\n✅ Téléchargement terminé : {dest_path}")
        return True
    except Exception as e:
        print("❌ Erreur lors du téléchargement :", e)
        return False





# 🔧 Forcer suppression même si fichier en lecture seule
def remove_readonly(func, path, exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)






# 📦 Télécharger et extraire le projet GitHub
def update_from_github(remote_version=None):
    try:
        print("📥 Téléchargement de la dernière version depuis GitHub ...")
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = os.path.join(tmpdir, "extRepo.zip")

            if not download_file(GITHUB_ZIP_URL, zip_path):
                print("❌ Impossible de télécharger le fichier ZIP depuis GitHub.")
                return False

            if os.path.exists(EXTENTION_REP):
                print(f"🗑️ Suppression de l'ancien dossier {EXTENTION_REP} ...")
                shutil.rmtree(EXTENTION_REP, onerror=remove_readonly)

            print("📂 Extraction du fichier ZIP ...")
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(tmpdir)

            extracted_dir = None
            for item in os.listdir(tmpdir):
                item_path = os.path.join(tmpdir, item)
                if os.path.isdir(item_path):
                    extracted_dir = item_path
                    break

            if extracted_dir is None:
                print("❌ Impossible de trouver le dossier extrait dans le ZIP.")
                return False

            shutil.move(extracted_dir, EXTENTION_REP)



            print(f"✅ Mise à jour réussie : {EXTENTION_REP}")
            return True

    except Exception as e:
        print("❌ Erreur lors de la mise à jour :", e)
        traceback.print_exc()
        return False






def check_version_Extention(window):
    """
    Vérifie et met à jour l'extension Chrome si nécessaire.
    Retour:
        str  -> retourne la version distante (si une mise à jour est nécessaire)
        True -> extension présente et déjà à jour
        False -> échec (download, fetch remote, manifest mismatch, etc.)
    """
    try:
        print("\n🔎 Vérification des versions locales et distantes...")

        if not os.path.exists(EXTENTION_REP):
            print(f"⚠️ Le dossier '{EXTENTION_REP}' est introuvable. Tentative de téléchargement...")
            ok = update_from_github(None)
            if not ok:
                print("❌ Échec du téléchargement de l'extension.")
                show_critical_message(window, "Échec téléchargement extension",
                                      "Impossible de télécharger l'extension depuis GitHub. Veuillez contacter le support.")
                return False
            print("✅ Dossier extension téléchargé avec succès.")

        try:
            response = requests.get(DROPBOX_URL, verify=False, timeout=10)
            response.raise_for_status()
            data = response.json()
            remote_version = data.get("version_Extention")
            remote_manifest_version = data.get("manifest_version")
        except Exception as e:
            print(f"❌ Impossible de récupérer la version distante : {e}")
            show_critical_message(window, "Erreur réseau / version distante",
                                  "Impossible de récupérer la version distante. Vérifiez votre connexion ou contactez le support.")
            return False

        if not os.path.exists(MANIFEST_PATH) or not os.path.exists(LAST_VERSION_TXT):
            print("⚠️ Fichiers locaux manquants pour la vérification des versions.")
            show_critical_message(window, "Fichiers locaux manquants",
                                  "Les fichiers locaux de l'extension sont introuvables. Veuillez réinstaller l'extension.")
            return False

        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)
        local_manifest_version = manifest_data.get("version", None)

        with open(LAST_VERSION_TXT, "r", encoding="utf-8") as f:
            local_version = f.read().strip()

        print(f"📄 Version locale : {local_version}, Manifest local : {local_manifest_version}")
        print(f"🌍 Version distante : {remote_version}, Manifest distant : {remote_manifest_version}")

        if str(local_manifest_version) != str(remote_manifest_version):
            show_critical_message(window, "Incompatibilité de manifest",
                                  "La version locale du manifest ne correspond pas à la version distante.\nVeuillez contacter le support.")
            print("⚠️ Manifest incompatible, aucune mise à jour automatique possible.")
            return False

        if local_version != remote_version:
            print(f"🔄 Mise à jour nécessaire (nouvelle version : {remote_version})")
            return remote_version  # 🔥 retourne la version distante
        else:
            print("✅ Extension locale à jour.")
            return True  # 🔥 déjà à jour

    except Exception as e:
        print(f"❌ Erreur inattendue dans check_version_Extention : {e}")
        show_critical_message(window, "Erreur interne",
                              "Une erreur inattendue est survenue lors de la vérification de l'extension. Veuillez contacter le support.")
        return False



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
        ui_path = os.path.join(SCRIPT_DIR, '..',  "interface"  , "interface.ui")
        uic.loadUi(ui_path, self)
        
        # selectinner Qframe avec Object Name "LogOut"
        # fais backgroud image  os.path.join(icons_dir, "LogOut.png")

        # Initialiser les données et layouts principaux
        self.states = json_data
        self.state_stack = []

        # print("\n ☎️​☎️​☎️​☎️​☎️​ ===== Contenu de json_data fourni à MainWindow =====")
        # pprint.pprint(self.states)
        # print("=====================================================\n")


        self.reset_options_container = self.findChild(QWidget, "resetOptionsContainer")
        self.reset_options_layout = QVBoxLayout(self.reset_options_container)
        self.reset_options_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.scenario_container = self.findChild(QWidget, "scenarioContainer")
        self.scenario_layout = QVBoxLayout(self.scenario_container)
        self.scenario_layout.setAlignment(Qt.AlignmentFlag.AlignTop )


        # Masquer les templates visuels non utilisés par défaut
        self.template_button = self.findChild(QPushButton, "TemepleteButton")
        self.template_button.hide()

        self.Temeplete_Button_2 = self.findChild(QPushButton, "TemepleteButton_2")
        self.Temeplete_Button_2.hide()

        self.template_Frame1 = self.findChild(QFrame, "Template1")
        self.template_Frame1.hide()

        self.template_Frame2 = self.findChild(QFrame, "Template2")
        self.template_Frame2.hide()

        self.template_Frame3 = self.findChild(QFrame, "Template3")
        self.template_Frame3.hide()

        self.template_Frame4 = self.findChild(QFrame, "Template4")
        self.template_Frame4.hide()




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
            clear_path = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "clear.png").replace("\\", "/")
            if os.path.exists(clear_path):
                icon = QIcon(clear_path)
                self.ClearButton.setIcon(icon)
                self.ClearButton.setIconSize(QSize(32, 32))

            # جعل الأيقونة في المنتصف وإزالة النص
            self.ClearButton.setText("")
            self.ClearButton.setFixedSize(36, 36)  # حسب حجم الأيقونة

            self.ClearButton.setStyleSheet("""
                QPushButton {
                    border: none;
                    background-color: transparent;
                    padding: 0px;
                    margin: 0px;
                }
                QPushButton::icon {
                    alignment: center;
                }
            """)

            self.ClearButton.clicked.connect(self.on_Clear_Button_clicked)



        self.CopyButton = self.findChild(QPushButton, "CopyButton")

        if self.CopyButton:
            clear_path = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "copyLog.png").replace("\\", "/")
            if os.path.exists(clear_path):
                icon = QIcon(clear_path)
                self.CopyButton.setIcon(icon)
                self.CopyButton.setIconSize(QSize(26, 26))

                # إخفاء النص داخل الزر
                self.CopyButton.setText("")

                # إزالة المساحات وتوسيط المحتوى
                self.CopyButton.setStyleSheet("""
                    QPushButton {
                        border: none;
                        padding: 0px;
                        margin: 0px;
                        background-color: transparent;
                    }
                    QPushButton::icon {
                        alignment: center;
                    }
                """)

                # اختياري: جعل الزر مربع الشكل لتناسب الأيقونة
                self.CopyButton.setFixedSize(38, 38)  # حسب الحاجة
                self.CopyButton.clicked.connect(self.copy_logs_to_clipboard)



        self.SaveButton = self.findChild(QPushButton, "saveButton")

        if self.SaveButton:
            icon_path_save = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "save.png").replace("\\", "/")
            if os.path.exists(icon_path_save):
                icon = QIcon(icon_path_save)
                self.SaveButton.setIcon(icon)
                self.SaveButton.setIconSize(QSize(16, 16))
                self.SaveButton.clicked.connect(self.handle_save)

        # Champ de recherche (masqué au démarrage)
        self.lineEdit_search = self.findChild(QLineEdit, "lineEdit_search")

        if self.lineEdit_search:
            self.lineEdit_search.hide()
        
        # Configuration des onglets principaux avec icônes personnalisés
        self.tabWidgetResult = self.findChild(QTabWidget, "tabWidgetResult")

        if self.tabWidgetResult:
            self.tabWidgetResult.tabBar().setCursor(Qt.CursorShape.PointingHandCursor)
            default_icon_path = os.path.join(SCRIPT_DIR, '..', "Tools", "icons")
            if os.path.exists(default_icon_path):
                icon_size = (40, 40)  
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
                    frame.setStyleSheet("background-color: #F5F5F5; border-right: 1px solid #669bbc;")
                    frame.setGeometry(0, 660, 179, 300)
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
        arrow_down_path = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "arrow_Down.png").replace("\\", "/")
        arrow_up_path = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "arrow_up.png").replace("\\", "/")
        down_exists = os.path.exists(arrow_down_path)
        up_exists = os.path.exists(arrow_up_path)
        if down_exists and up_exists:
            for spin_box in spin_boxes:
                old_style = spin_box.styleSheet()  # حفظ التنسيق القديم

                # دمج التنسيق القديم مع الجديد
                spin_box.setStyleSheet(old_style + f"""
                    QSpinBox::down-button {{
                        image: url("{arrow_down_path}");
                        width: 13px;
                        height: 13px;
                        border-top-left-radius: 5px;
                        border-bottom-left-radius: 5px;
                    }}
                    QSpinBox::up-button {{
                        image: url("{arrow_up_path}");
                        width: 13px;
                        height: 13px;
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


            icons_dir = os.path.join(SCRIPT_DIR, '..', "interface", "icons")
            self.browser.addItem(QIcon(os.path.join(icons_dir, "chrome.png")), "Chrome")
            self.browser.addItem(QIcon(os.path.join(icons_dir, "firefox.png")), "Firefox")
            self.browser.addItem(QIcon(os.path.join(icons_dir, "edge.png")), "Edge")
            self.browser.addItem(QIcon(os.path.join(icons_dir, "comodo.png")), "Comodo")
    


        self.Isp = self.findChild(QComboBox, "Isps")
        if self.Isp is not None:
            print("✅ QComboBox 'Isps' trouvé.")

            # 🔽 Style de flèche personnalisée
            if os.path.exists(arrow_down_path):
                print(f"🎨 Fichier flèche trouvé : {arrow_down_path}")
                new_style = f'''
                    QComboBox::down-arrow {{
                        image: url("{arrow_down_path}");
                        width: 16px;
                        height: 16px;
                    }}
                '''
                old_style = self.Isp.styleSheet()
                self.Isp.setStyleSheet(old_style + new_style)
            else:
                print(f"❌ Fichier flèche manquant : {arrow_down_path}")

            # 📁 Icônes
            icons_dir = os.path.join(SCRIPT_DIR, '..', "interface", "icons")
            print(f"📁 Dossier d'icônes : {icons_dir}")
            self.Isp.clear()

            services = {
                "Gmail": "Gmail.png",
                # "Hotmail": "Hotmail.png",
                # "Yahoo": "Yahoo.png"
            }

            for name, icon_file in services.items():
                icon_path = os.path.join(icons_dir, icon_file)
                if os.path.exists(icon_path):
                    self.Isp.addItem(QIcon(icon_path), name)
                    print(f"✅ Ajout de l'élément '{name}' avec icône : {icon_path}")
                else:
                    self.Isp.addItem(name)
                    print(f"⚠️ Icône manquante pour '{name}' : {icon_path}, ajouté sans icône.")

            # 📄 Lire le fichier Isp.txt si existe
            text_file_path_Isp = os.path.join(SCRIPT_DIR, "Isp.txt")
            selected_isp = None

            if os.path.exists(text_file_path_Isp):
                print(f"📄 Lecture de : {text_file_path_Isp}")
                with open(text_file_path_Isp, 'r', encoding='utf-8') as f:
                    line = f.readline().strip().lower()
                    print(f"🔍 Valeur lue dans Isp.txt : '{line}'")
                    if "gmail" in line:
                        selected_isp = "Gmail"
                    elif "hotmail" in line:
                        selected_isp = "Hotmail"
                    elif "yahoo" in line:
                        selected_isp = "Yahoo"
                    else:
                        print("⚠️ Aucune correspondance trouvée dans le fichier.")
            else:
                print(f"❌ Fichier Isp.txt non trouvé : {text_file_path_Isp}")



            # ✅ Définir la valeur sélectionnée par défaut
            if selected_isp:
                index = self.Isp.findText(selected_isp)
                if index >= 0:
                    self.Isp.setCurrentIndex(index)
                    print(f"✅ Élément '{selected_isp}' sélectionné dans la QComboBox.")
                else:
                    print(f"❌ Élément '{selected_isp}' introuvable dans la QComboBox.")
        else:
            print("❌ QComboBox 'Isps' introuvable.")



            
        self.saveSanario = self.findChild(QComboBox, "saveSanario")
        if self.saveSanario is not None:
                    if os.path.exists(arrow_down_path):
                        new_style = f'''
                            QComboBox::down-arrow {{
                                image: url("{arrow_down_path}");
                                width: 16px;
                                height: 16px;
                            }}
                        '''
                        old_style = self.saveSanario.styleSheet()
                        self.saveSanario.setStyleSheet(old_style + new_style)
                        self.saveSanario.currentTextChanged.connect(self.on_scenario_changed)


        # selectinner Qframe avec Object souName "LogOut"
        # fais backgroud image  os.path.join(icons_dir, "LogOut.png")
  

        self.image_path = os.path.join(icons_dir, "LogOut4.png")
        self.log_out_Button = self.findChild(QPushButton, "LogOut")

        if self.log_out_Button:
            self.log_out_Button.setLayoutDirection(Qt.LayoutDirection.RightToLeft)  
            self.log_out_Button.clicked.connect(self.logOut)

            if os.path.exists(self.image_path):
                self.log_out_Button.setIcon(QIcon(self.image_path))
                self.log_out_Button.setIconSize(QSize(18, 18))




        # Initialisation de l'affichage des logs
        self.log_container = self.findChild(QWidget, "log")
        self.log_layout = QVBoxLayout(self.log_container)  
        self.log_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.log_container.adjustSize() 
        self.log_container.setFixedWidth(1627)

        self.result_tab_widget = self.findChild(QTabWidget, "tabWidgetResult")

        if self.result_tab_widget:
            print("[DEBUG] ✅ tabWidgetResult trouvé dans l'interface.")
        else:
            print("[DEBUG] ❌ tabWidgetResult introuvable. Vérifiez le nom de l'objet dans le fichier .ui.")
        

        self.set_icon_for_existing_buttons()
        self.load_scenarios_into_combobox()

        # Chargement initial des options
        self.load_initial_options()




    def saveProcess(self, parameters):
        _pVersion = str(sys.version[:3])
        header = {
            "User-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        }
        url = "https://reporting.nrb-apps.com/pub/SaveProcess.php?k=mP5QXYrK9E67Y&rID=1&rv4=1"

        try:
            response = requests.post(url, data=parameters, headers=header)
            print(f"🌐 [POST] URL: {url}")
            print(f"📤 [POST] Paramètres envoyés: {parameters}")
            print(f"📥 [HTTP] Code de réponse: {response.status_code}")
            print(f"📄 [HTTP] Réponse brute:\n{response.text}")

            results = response.json()
            status = results.get('status', False)

            if status is True:
                print(f"✅ [API] Insertion réussie ➜ ID inséré: {results.get('inserted_id')}")
                return results.get('inserted_id')
            else:
                print(f"❌ [API] Échec de l'insertion ➜ Détails: {results}")
                return -1

        except ValueError as ve:
            print(f"💥 [JSON ERROR] Impossible de parser la réponse JSON: {ve}")
            return -1
        except Exception as e:
            print(f"💥 [EXCEPTION] Erreur lors de l'appel POST: {e}")
            return -1

        


    def handle_save(self):
        if not self.state_stack:
            msg = "Aucune Actions Added"
            print("[❌] " + msg)
            show_critical_message(self, "Aucune donnée", msg)
            return

        session_path = os.path.join(APPDATA_DIR, "session.txt")
        if not os.path.exists(session_path):
            msg = "Le fichier de session est manquant."
            print("[❌] " + msg)
            show_critical_message(self, "Session introuvable", msg)
            return

        with open(session_path, "r", encoding="utf-8") as f:
            encrypted_key = f.read().strip()

        payload = {
            "decreapted key": encrypted_key,
            "state": self.state_stack[-1],
            "state_stack": self.state_stack
        }

        try:
            response = requests.post("http://localhost/auth-api/add_scenario.php", json=payload)

            if response.status_code == 200:
                result = response.json()

                # 🔐 Vérification de session
                if result.get("session") is False:
                    print("[🔒] Session expirée. Redirection vers la page de connexion.")
                    self.login_window = LoginWindow()
                    self.login_window.setFixedSize(1710, 1005)

                    screen = QGuiApplication.primaryScreen()
                    screen_geometry = screen.availableGeometry()
                    x = (screen_geometry.width() - self.login_window.width()) // 2
                    y = (screen_geometry.height() - self.login_window.height()) // 2
                    self.login_window.move(x, y)
                    self.login_window.show()

                    # Fermer la fenêtre actuelle (MainWindow)
                    self.close()
                    return

                # ✅ Succès
                if result.get("success"):
                    print("[✅] Scénario envoyé avec succès.")
                    self.load_scenarios_into_combobox()
                    show_critical_message(self, "Succès", "Scénario envoyé avec succès.")
                else:
                    msg = result.get("error", "Erreur inconnue.")
                    print(f"[❌] Erreur côté API : {msg}")
                    show_critical_message(self, "Erreur API", msg)

            else:
                print(f"[❌] Erreur HTTP - Code : {response.status_code}")
                show_critical_message(self, "Erreur HTTP", f"Code {response.status_code}")

        except Exception as e:
            print(f"[❌] Exception lors de la requête : {str(e)}")
            show_critical_message(self, "Exception", str(e))





    def load_scenarios_into_combobox(self):
        print("📥 [INFO] Début du chargement des scénarios...")

        session_path = os.path.join(APPDATA_DIR, "session.txt")
        print(f"[📂] Chemin du fichier de session: {session_path}")

        if not os.path.exists(session_path):
            print("[❌] Fichier session.txt introuvable.")
            return

        with open(session_path, "r", encoding="utf-8") as f:
            encrypted_key = f.read().strip()
        print(f"[🔐] Clé chiffrée lue: {encrypted_key}")

        payload = {"encrypted": encrypted_key}
        print(f"[📦] Payload préparé pour la requête: {payload}")

        try:
            response = requests.post("http://localhost/auth-api/get_scenarios.php", json=payload)
            print(f"[🌐] Requête envoyée. Code HTTP: {response.status_code}")

            if response.status_code == 200:
                result = response.json()
                # print(f"[📨] Réponse reçue (JSON): {result}")

                # 🟡 Vérification de session expirée
                if result.get("session") is False:
                    print("[🔒] Session expirée. Redirection vers la page de connexion.")
                    self.login_window = LoginWindow()
                    self.login_window.setFixedSize(1710, 1005)

                    screen = QGuiApplication.primaryScreen()
                    screen_geometry = screen.availableGeometry()
                    x = (screen_geometry.width() - self.login_window.width()) // 2
                    y = (screen_geometry.height() - self.login_window.height()) // 2
                    self.login_window.move(x, y)
                    self.login_window.show()

                    print("[🔁] Fenêtre de connexion affichée. Fermeture de la fenêtre actuelle...")
                    self.close()
                    return

                # ✅ Session valide → remplir la combo
                scenarios = result.get("scenarios", [])
                if scenarios:
                    print(f"✅ [INFO] Nombre de scénarios reçus: {len(scenarios)}")

                    self.saveSanario.clear()
                    self.saveSanario.addItem("None")

                    for index, scenario in enumerate(scenarios, 1):
                        name = scenario.get("name", f"Scénario {index}")
                        self.saveSanario.addItem(name)
                        print(f"   ➕ Scénario {index}: {name}")

                    print("[✅] Scénarios chargés dans la liste déroulante avec succès.")
                else:
                    self.saveSanario.addItem("None")

                    print("")
            else:
                print(f"[❌] Erreur HTTP {response.status_code}")
                print(f"[❗] Contenu de la réponse: {response.text}")

        except Exception as e:
            print(f"[❌] Erreur lors de la récupération des scénarios: {e}")






    def set_icon_for_existing_buttons(self):
        if not self.result_tab_widget:
            print("[DEBUG] ❌ tabWidgetResult introuvable. Vérifiez le nom.")
            return

        print("[DEBUG] ✅ tabWidgetResult trouvé.")

        for i in range(self.result_tab_widget.count()):
            tab_widget = self.result_tab_widget.widget(i)
            buttons = tab_widget.findChildren(QPushButton)

            for button in buttons:
                object_name = button.objectName()

                if object_name.startswith("copy"):
                    icon_path = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "copy.png")
                    button.setIcon(QIcon(icon_path))
                    button.setIconSize(QtCore.QSize(20, 20))
                    # print(f"[DEBUG] 🎯 Icône ajoutée au bouton '{object_name}' dans l'onglet {i}")

                    # ✅ ربط الزر بدالة النسخ (مرة واحدة)
                    try:
                        button.clicked.disconnect()
                    except Exception:
                        pass  # لم يكن هناك ربط سابق

                    button.clicked.connect(lambda _, idx=i: self.copy_result_from_tab(idx))
                else:
                    print(f"[DEBUG] ⏭️ Bouton ignoré: '{object_name}'")





    def copy_result_from_tab(self, tab_index):
        tab_widget = self.result_tab_widget.widget(tab_index)
        list_widgets = tab_widget.findChildren(QListWidget)

        if list_widgets:
            list_widget = list_widgets[0]
            items = [list_widget.item(i).text() for i in range(list_widget.count())]
            text_to_copy = "\n".join(items)
            clipboard = QApplication.clipboard()
            clipboard.setText(text_to_copy)
            print(f"[DEBUG] 📋 {len(items)} éléments copiés dans le presse-papiers.")
        else:
            print("[DEBUG] ⚠️ Aucun QListWidget trouvé dans cet onglet.")

            


    def copy_logs_to_clipboard(self):
        log_box = self.findChild(QGroupBox, "log")
        if not log_box:
            print("[DEBUG] ❌ QGroupBox 'log' introuvable.")
            return

        labels = log_box.findChildren(QLabel)

        if not labels:
            print("[DEBUG] ⚠️ Aucun QLabel trouvé dans 'log'.")
            return

        log_lines = [label.text() for label in labels]
        text_to_copy = "\n".join(log_lines)

        QApplication.clipboard().setText(text_to_copy)
        print(f"[DEBUG] 📋 {len(log_lines)} lignes de logs copiées dans le presse-papiers.")





    def logOut(self  ):
        global SELECTED_BROWSER_GLOBAL;
        try:
            # Supprimer la session
            session_path = os.path.join(APPDATA_DIR, "session.txt")
            if os.path.exists(session_path):
                os.remove(session_path)
                print("[LOGOUT] Session supprimée.")



            # selected_browser
            if(SELECTED_BROWSER_GLOBAL):
                stop_all_processes(self)


            # Revenir à la fenêtre de connexion
            self.login_window = LoginWindow()
            self.login_window.setFixedSize(1710, 1005)

            screen = QGuiApplication.primaryScreen()
            screen_geometry = screen.availableGeometry()
            x = (screen_geometry.width() - self.login_window.width()) // 2
            y = (screen_geometry.height() - self.login_window.height()) // 2
            self.login_window.move(x, y)
            self.login_window.show()

            # Fermer la fenêtre actuelle (MainWindow)
            self.close()

        except Exception as e:
            print(f"[LOGOUT ERROR] {e}")




    #Ajoute une nouvelle ligne de log dans la zone de log (interface utilisateur).
    #Chaque log est stylisé pour rester lisible avec fond transparent.
    def update_logs_display(self, log_entry):
        log_label = QLabel(log_entry)
        log_label.setStyleSheet("""
            QLabel {
                color: #ffffff;
                font-size: 14px;
                background-color: transparent;
                font-family: "Times", "Times New Roman", serif;
                padding: 2px;
            }
        """)
        self.log_layout.addWidget(log_label)



    # Fonction appelée automatiquement à la fermeture de la fenêtre principale.
    # Permet d'arrêter proprement le thread de logs avant la fermeture de l'application.
    def closeEvent(self, event):
        self.logs_thread.stop()  
        super().closeEvent(event)



    # modifier extention d apres traitement.json
    # entre vers fichier JSON traitement.json
    
    # Enregistre les données JSON traitées dans un fichier appelé 'traitement.json'.
    # Supprime l'ancien fichier s'il existe, puis écrit le nouveau proprement.
    def save_json_to_file(self,json_data, selected_browser):
        template_directory = TEMPLATE_DIRECTORY_FIREFOX  if selected_browser.lower() == "firefox" else TEMPLATE_DIRECTORY_CHROME
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
            # ✅ شرط الحذف: تجاهل العنصر إذا كان من نوع google_maps_actions أو save_location
            if element.get("process") in ["google_maps_actions", "save_location", "search_activities"]:
                continue  # لا نضيفه إلى الإخراج
   
            if element.get("process") == "loop" and "sub_process" in element:
                sub_process = element["sub_process"]

                if sub_process:
                    last_element = sub_process[-1]

                    if last_element.get("process") in ["next"]:
                        output_json.append({
                            "process": "open_message",
                            "sleep": random.randint(1, 3)
                        })
                        sub_process = [sp for sp in sub_process if sp.get("process") != "open_message"]

                    elif last_element.get("process") not in ["delete", "archive", "not_spam", "report_spam"]:
                        for i, sp in enumerate(sub_process):
                            if sp.get("process") == "open_message":
                                original_sleep = sp.get("sleep", 0)
                                sub_process[i] = {
                                    "process": "OPEN_MESSAGE_ONE_BY_ONE",
                                    "sleep": original_sleep
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
        global current_hour, current_date, LOGS_RUNNING , NOTIFICATION_BADGES


        session_path = os.path.join(APPDATA_DIR, "session.txt")
        session_valid = False

        print(f"[INFO] Chemin du fichier session : {session_path}")

        if os.path.exists(session_path):
            print("[INFO] Le fichier session.txt existe ✅")
            try:
                with open(session_path, "r", encoding="utf-8") as f:
                    encrypted = f.read().strip()

                print(f"[INFO] Contenu chiffré lu :\n'{encrypted}'")
                print(f"[INFO] Longueur du contenu chiffré : {len(encrypted)} caractères")

                if not encrypted:
                    print("[AVERTISSEMENT SESSION] Le fichier session.txt est vide ❌")
                else:
                    try:
                        decrypted = decrypt_date(encrypted, key)
                        print(f"[INFO] Contenu déchiffré complet :\n'{decrypted}'")
                        print(f"[INFO] Longueur du contenu déchiffré : {len(decrypted)} caractères")
                    except Exception as e:
                        print(f"[ERREUR DECHIFFREMENT] Erreur lors du déchiffrement : {e}")
                        decrypted = ""

                    # Analyse du contenu déchiffré
                    if decrypted:
                        parts = decrypted.split("::", 2)  # Découpe en 3 parties maximum
                        print(f"[INFO] Contenu découpé en {len(parts)} parties : {parts}")

                        if len(parts) == 3:
                            username = parts[0].strip()
                            date_str = parts[1].strip()
                            p_entity = parts[2].strip()

                            print(f"[INFO] Nom d'utilisateur : '{username}'")
                            print(f"[INFO] Date de session (date_str) : '{date_str}'")
                            print(f"[INFO] p_entity : '{p_entity}'")

                            try:
                                tz = pytz.timezone("Africa/Casablanca")
                                print(f"[DEBUG] Conversion de la date '{date_str}' en datetime...")
                                last_session = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                                last_session = tz.localize(last_session)

                                now = datetime.datetime.now(tz)
                                print(f"[INFO] Date de la session : {last_session}")
                                print(f"[INFO] Date actuelle : {now}")

                                if (now - last_session) < timedelta(days=2):
                                    session_valid = True
                                    print(f"[SESSION] ✅ Session valide pour l'utilisateur '{username}' (p_entity = {p_entity})")
                                else:
                                    print("[SESSION EXPIRÉE] ⌛ La session a expiré depuis plus de 2 jours")
                            except ValueError as e:
                                print(f"[ERREUR FORMAT DATE] ❌ Format de date invalide : {e}")
                                print(f"[DEBUG] Contenu complet de date_str : '{date_str}'")
                                print(f"[DEBUG] Contenu déchiffré complet : '{decrypted}'")
                        else:
                            print("[ERREUR FORMAT SESSION] ❌ Format invalide (attendu : username::date::p_entity)")
                            print(f"[DEBUG] Contenu déchiffré complet : '{decrypted}'")
                    else:
                        print("[ERREUR SESSION] ❌ Impossible de déchiffrer correctement les données")
            except Exception as e:
                print(f"[ERREUR LECTURE SESSION] ❌ Exception lors de la lecture du fichier : {e}")
        else:
            print("[AVERTISSEMENT SESSION] ❌ Le fichier session.txt n'existe pas")

        # Si la session est invalide, ouvrir la fenêtre de login
        if not session_valid:
            print("[SESSION] ❌ Session invalide => ouverture de la fenêtre LoginWindow...")

            self.login_window = LoginWindow()
            self.login_window.setFixedSize(1710, 1005)

            screen = QGuiApplication.primaryScreen()
            screen_geometry = screen.availableGeometry()
            x = (screen_geometry.width() - self.login_window.width()) // 2
            y = (screen_geometry.height() - self.login_window.height()) // 2
            self.login_window.move(x, y)

            self.login_window.show()

            print("[SESSION] 🔒 Fermeture de la fenêtre principale MainWindow...")
            self.close()

            # Nettoyage du fichier session
            try:
                with open(session_path, "w", encoding="utf-8") as f:
                    f.write("")
                print("[SESSION] 🧼 Fichier session.txt nettoyé.")
            except Exception as e:
                print(f"[ERREUR NETTOYAGE SESSION] ❌ {e}")

            return




        # 🧹 Supprimer tous les badges de notification dans les onglets de résultats
        try:
            if self.result_tab_widget:
                # print("[DEBUG] ✅ tabWidgetResult est prêt.")
                # print(f"[DEBUG] عدد التبويبات داخل tabWidgetResult: {self.result_tab_widget.count()}")
                # print(f"[DEBUG] الفهارس التي تحتوي على شارات NOTIFICATION_BADGES: {list(NOTIFICATION_BADGES.keys())}")
                # print(f"[DEBUG] NOTIFICATION_BADGES actuel : {NOTIFICATION_BADGES}")

                # إزالة البادجز
                for tab_index, badge in NOTIFICATION_BADGES.items():
                    # print(f"[DEBUG] Suppression du badge à l'onglet index {tab_index}")
                    if badge:
                        badge.deleteLater()
                        # print(f"[DEBUG] Badge supprimé à l'index {tab_index}.")
                    # else:
                    #     print(f"[DEBUG] Aucun badge trouvé à l'index {tab_index}.")
                NOTIFICATION_BADGES.clear()
                # print("[BADGES] Tous les badges de notification ont été supprimés.")

                # ➕ إزالة كل الإيميلات المعروضة في القوائم داخل التبويبات
                for i in range(self.result_tab_widget.count()):
                    tab = self.result_tab_widget.widget(i)
                    if tab:
                        list_widgets = tab.findChildren(QListWidget)
                        for lw in list_widgets:
                            lw.clear()  # تنظيف القائمة من كل الإيميلات المعروضة
                # print("[LISTS] تم مسح جميع القوائم داخل التبويبات.")

            # else:
            #     print("[DEBUG] ❌ tabWidgetResult est vide.")
        except Exception as e:
            print(f"[BADGES ERROR] Erreur lors de la suppression des badges : {e}")




        # mon besoin dans cet function remove all badge de notification dans self.result_tab_widget

        # new_versions = checkVersion()
        # if window:
        #     if 'version_python' in new_versions or 'version_interface' in new_versions:
        #         window.close()
        #         launch_new_window()
        #         sys.exit(0)
        #     else:
        #         download_result = DownloadFile(new_versions)
        #         if download_result == -1:
        #             return
        #         time.sleep(5) 
        #         extractAll()

        new_versions = checkVersion()

        if new_versions == "_1":
            show_critical_message(
                window,
                "Connection Error",
                "We were unable to reach the server or retrieve the necessary version information.\n"
                "Please check your internet connection or try again later.\n"
                "If the problem persists, contact Support for assistance."
            )
            return

        if not new_versions:
            log_message("✅ Everything is up to date, no updates required")
            return

        if 'version_python' in new_versions or 'version_interface' in new_versions:
            print("🔄 Python or interface update detected, restarting the program")
            window.close()
            launch_new_window()
            sys.exit(0)
        else:
            # تحديث الإضافات
            if 'version_Extention_firefox' in new_versions:
                print("⬇️ Downloading new Firefox extension update...")
            if 'version_Extention_Family_Chrome' in new_versions:
                print("⬇️ Downloading new Chrome extension update...")

            if DownloadAndExtract(new_versions) == 0:
                if 'version_Extention_firefox' in new_versions:
                    print("✅ Firefox extension updated successfully")
                if 'version_Extention_Family_Chrome' in new_versions:
                    print("✅ Chrome extension updated successfully")
            else:
                print("❌ Failed to update one or more extensions")
                show_critical_message(
                    window,
                    "❌ Update Failed",
                    "We were unable to complete the update of one or more browser extensions.\n\n"
                    "Possible causes:\n"
                    " • Internet connection issues\n"
                    " • Server temporarily unavailable\n"
                    "Please check your connection and try again.\n"
                    "If the problem persists, contact Support for further assistance."
                )
                return





        selected_Browser = self.browser.currentText().lower()
        print('selected_Browser : ', selected_Browser)

        if selected_Browser == "chrome":
            print('selected_Browser :', selected_Browser)

            print("\n🔍 Étape 1 : Vérification du dossier de configuration ...")
            if not os.path.exists(CONFIG_PROFILE):
                print(f"⚠️ Le dossier requis '{CONFIG_PROFILE}' est introuvable.")
                print("👉 Veuillez contacter le support avant de continuer.")
                return
            print("📂 Dossier de configuration trouvé :", CONFIG_PROFILE)

            print("\n🔍 Étape 2 : Vérification de l'extension locale ...")
            if not os.path.exists(EXTENTION_REP):
                os.makedirs(EXTENTION_REP, exist_ok=True)
                print(f"📂 Le dossier '{EXTENTION_REP}' a été créé car il n'existait pas.")
                print("📥 Téléchargement de la dernière version de l'extension...")
                if update_from_github(None):
                    print("✅ Extension installée avec succès.")
                else:
                    show_critical_message(window, "Échec installation extension",
                                        "❌ Échec de l'installation de l'extension. Veuillez contacter le support.")
                    return
            else:
                print(f"📂 Extension trouvée : {EXTENTION_REP}")
                remote_version = check_version_Extention(window)

                if isinstance(remote_version, str):  # 🔥 veut dire mise à jour nécessaire
                    if update_from_github(remote_version):
                        print("✅ Mise à jour réussie : l'extension a été mise à jour avec succès !")
                    else:
                        show_critical_message(window, "Échec mise à jour extension",
                                            "❌ Échec de la mise à jour depuis GitHub. Veuillez contacter le support.")
                        return
                elif remote_version is True:
                    print("✅ L'extension locale est déjà à jour.")
                else:
                    show_critical_message(window, "Erreur version extension",
                                        "⚠️ Impossible de vérifier la version correctement. Veuillez contacter le support.")
                    return





        
        interface_tab_widget = window.findChild(QTabWidget, "interface_2")
        if interface_tab_widget:
            for i in range(interface_tab_widget.count()):
                tab_text = interface_tab_widget.tabText(i)
                if tab_text.startswith("Result"):
                    interface_tab_widget.setTabText(i, "Result")
                    break
        
        LOGS_RUNNING =True

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
                
                print(f"📋 full_state: {full_state}")  # عرض محتوى full_state
                print(f"📋 hidden_id: {hidden_id}")    # عرض قيمة hidden_id
                checkbox = next((child for child in widget.children() if isinstance(child, QCheckBox)), None)

                if full_state and not full_state.get("showOnInit", False) and not hidden_id.startswith("google") and  hidden_id.startswith("youtube"):
                    print(f"✅ Condition remplie ! Le code à l'intérieur du if sera exécuté ✅ hidden_id : {hidden_id}")
                    qlineedits = [child for child in widget.children() if isinstance(child, QLineEdit)]

                    if len(qlineedits) > 1:
                        limit_text = qlineedits[0].text()
                        sleep_text = qlineedits[1].text()

                        try:
                            limit_value = parse_random_range(limit_text)
                        except ValueError:
                            limit_value = 0

                        try:
                            sleep_value = parse_random_range(sleep_text)
                        except ValueError:
                            sleep_value = 0

                        # 👇 Ajouter UN SEUL objet avec process, limit et sleep
                        if  hidden_id.startswith("youtube"):
                            output_json.append({
                                "process": "CheckLoginYoutube",
                                "sleep":  random.randint(1, 3)
                            })
                            output_json.append({
                                "process": hidden_id,
                                "limit": limit_value,
                                "sleep": sleep_value
                            })
                        else:
                            output_json.append({
                                "process": hidden_id,
                                "limit": limit_value,
                                "sleep": sleep_value
                            })

                    else:
                        # S'il n'y a qu'un seul QLineEdit → utilisé pour sleep seulement
                        sleep_text = qlineedits[0].text() if qlineedits else "0"
                        print("✅ QLineEdit utilisé comme sleep uniquement:", sleep_text)

                        try:
                            sleep_value = parse_random_range(sleep_text)
                        except ValueError:
                            sleep_value = 0

                        output_json.append({
                            "process": hidden_id,
                            "sleep": sleep_value
                        })

                    i += 1
                    continue

                if full_state and full_state.get("showOnInit", False) and checkbox:
                    sub_process = []  
                    # spinbox = next((child.value() for child in widget.children() if isinstance(child, QSpinBox)), 0)
                    # openInbox
                    output_json.append({
                        "process": hidden_id,
                        "sleep": random.randint(1, 3)
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
                        # sub_spinbox = next((child.value() for child in sub_widget.children() if isinstance(child, QSpinBox)), 0)
                        wait_process_txt = next((child.text() for child in sub_widget.children() if isinstance(child, QLineEdit)), "0")
                        try:
                            wait_process = parse_random_range(wait_process_txt)
                        except ValueError:
                            wait_process = 0
                        sub_checkbox = next((child for child in sub_widget.children() if isinstance(child, QCheckBox)), None)

                        combobox = next((child for child in widget.children() if isinstance(child, QComboBox)), None)
                        combo_value = combobox.currentText() if combobox else None

                        if sub_full_state and sub_full_state.get("showOnInit", False) or sub_hidden_id.startswith("google") or sub_hidden_id.startswith("youtube"):
                            break

                        if not sub_checkbox:
                            sub_process.append({
                                "process": sub_hidden_id,
                                "sleep": wait_process
                            })
                        else:
                            break

                        i += 1

                    if len(sub_process) > 0:
                        action = "return_back" if combo_value == "Return back" else "next"
                        sub_process.append({
                            "process": action
                        })
                    qlineedits = [child for child in widget.children() if isinstance(child, QLineEdit)]

                    limit_loop_text = qlineedits[0].text() if len(qlineedits) > 1 else "0"
                    Start_loop_text =qlineedits[1].text() if len(qlineedits) > 1 else "0"

                    try:
                        limit_loop = parse_random_range(limit_loop_text)
                        Start_loop =  parse_random_range(Start_loop_text)
                    except ValueError:
                        limit_loop = 0

                    output_json.append({
                        "process": "loop",
                        "check": "is_empty_folder",
                        "limit_loop": limit_loop,
                        "start": Start_loop,
                        "sub_process": sub_process
                    })
                    continue

                if full_state and full_state.get("showOnInit", False) and not checkbox:
                    # spinbox = next((child.value() for child in widget.children() if isinstance(child, QSpinBox)), 0)
                    wait_process_txt = next((child.text() for child in widget.children() if isinstance(child, QLineEdit)), "0")
                    try:
                        wait_process = parse_random_range(wait_process_txt)
                    except ValueError:
                        wait_process = 0
                    output_json.append({
                        "process": hidden_id,
                        "sleep": wait_process
                    })


                if full_state and not full_state.get("showOnInit", False) and (hidden_id.startswith("google") or hidden_id.startswith("youtube")):
                    print("🔍 ✅ Condition principale remplie (if)")
                    print(f"🔸 Identifiant caché (hidden_id) : {hidden_id}")
                    
                    print(f"📋 État de la case à cocher : {'trouvée' if checkbox else 'non trouvée'}")
                    
                    wait_process_txt = next((child.text() for child in widget.children() if isinstance(child, QLineEdit)), "0")
                    print(f"📥 Valeur du champ de délai (wait_process_txt) : {wait_process_txt}")
                    
                    try:
                        wait_process = parse_random_range(wait_process_txt)
                        print(f"⏳ Délai après conversion (wait_process) : {wait_process}")
                    except ValueError:
                        wait_process = 0
                        print("⚠️ Erreur lors de la conversion du délai. Valeur par défaut utilisée : 0")
                    
                    if checkbox and checkbox.isChecked():
                        print("✅ La case à cocher est activée")

                        qlineedits = [child for child in widget.children() if isinstance(child, QLineEdit)]
                        print(f"✏️ Nombre total de champs QLineEdit trouvés : {len(qlineedits)}")

                        for idx, line_edit in enumerate(qlineedits, start=1):
                            print(f"   ➤ Champ QLineEdit {idx} : \"{line_edit.text()}\"")

                        if len(qlineedits) > 1:
                            search_value = qlineedits[1].text()
                            print(f"🔎 Valeur de recherche utilisée (deuxième champ) : {search_value}")
                        elif len(qlineedits) == 1:
                            search_value = qlineedits[0].text()
                            print(f"🔎 Un seul champ trouvé, valeur de recherche utilisée : {search_value}")
                        else:
                            search_value = ""
                            print("⚠️ Aucun champ QLineEdit trouvé, valeur de recherche vide.")

                        output_json.append({
                            "process": hidden_id,
                            "search": search_value,
                            "sleep": wait_process
                        })
                        print("📤 Données ajoutées à output_json avec valeur de recherche.")
                    else:
                        output_json.append({
                            "process": hidden_id,
                            "sleep": wait_process
                        })
                        print("🚫 La case à cocher n’est pas activée. Aucune donnée ajoutée.")



            i += 1


        try:
            result = parse_input_to_json(window)

            if not result:  
                return
            data_list, entered_number = result  

        except Exception as e:
            QMessageBox.critical(window, "Error", f"Error while parsing the JSON: {e}")
            return
    
        print("📦 JSON test:")

        print(json.dumps(output_json, indent=4, ensure_ascii=False))
        
        current_time = datetime.datetime.now()
        current_date = current_time.strftime("%Y-%m-%d")
        current_hour = current_time.strftime("%H-%M-%S") 
        modified_json = self.process_and_split_json(output_json)
        output_json = self.process_and_handle_last_element(modified_json)
        output_json_final=self.process_and_modify_json(output_json)
        self.save_json_to_file(output_json_final , selected_Browser)
        print("📦 JSON Final:")
        print(json.dumps(output_json_final, indent=4, ensure_ascii=False))

 
        try:
            with open( os.path.join(SCRIPT_DIR, "Isp.txt"), 'w', encoding='utf-8') as f:
                f.write(self.Isp.currentText().strip())
            print(f"📄 Fichier Isp.txt mis à jour avec : '{self.Isp.currentText().strip()}'")
        except Exception as e:
            print(f"❌ Erreur lors de l'écriture dans Isp.txt : {e}")



        json_string = json.dumps(output_json_final)
        print("✈️​✈️​✈️​✈️​✈️​✈️​ : ",json_string)

        parameters = { 
            'p_owner':username,
            'p_entity':p_entity,
            'p_isp': self.Isp.currentText(),
            'p_action_name': json.dumps(output_json_final), 
            'p_app':'V4',
            'p_python_version': f"{sys.version_info.major}.{sys.version_info.minor}", 
            'p_browser': self.browser.currentText(),
        }

        unique_id=self.saveProcess(parameters)

        if unique_id==-1:
            # print("Error getting process ID ")
            # os.system("pause")
            # exit()
            return


        with ThreadPoolExecutor(max_workers=2) as executor:
            executor.submit(start_extraction, window, data_list , entered_number, selected_Browser, self.Isp.currentText() , unique_id , output_json_final, username)
            executor.submit(self.logs_thread.start)
        EXTRACTION_THREAD.finished.connect(lambda: self.on_extraction_finished(window))



    # Charge les options visibles dès le démarrage de l'application.
    # - Supprime les anciens widgets.
    # - Crée un bouton pour chaque option avec `showOnInit = True`.
    def load_initial_options(self):
        # Clear existing widgets from the layout
        while self.reset_options_layout.count() > 0:
            item = self.reset_options_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Add option buttons for states with showOnInit=True
        for key, state in self.states.items():
            if state.get("showOnInit", False):
                # print(f"Displayed option for: {key}")
                # print(f"state: {state}") 
                self.create_option_button(state)
                # print(f"Displayed option for: {key}") 
        # print("🫁​🫁​🫁​🫀​🫀​🫀​🫀​ self.state_stack : ",  self.state_stack)



    #Crée dynamiquement un bouton d'option basé sur un état donné.
    #Ce bouton est ajouté à un conteneur prédéfini, reprend le style d'un bouton modèle,
    #et est relié à la fonction `load_state`.
    #:param state: Dictionnaire contenant les informations de l'état à charger.
    def create_option_button(self, state):
        default_icon_path = os.path.join(SCRIPT_DIR, '..', "Tools", "icons", "icon.png")
        default_icon_path_Templete2 = os.path.join(SCRIPT_DIR, '..', "Tools", "icons", "next.png")

        # Create and configure the button
        # button = QPushButton(state.get("label", "Unnamed"), self.reset_options_container)
        # button.setStyleSheet(self.template_button.styleSheet())
        # button.setFixedSize(self.template_button.size())
        # button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        
        # # Connect button to state loader
        # button.clicked.connect(lambda _, s=state: self.load_state(s))

        # # Set icon if it exists
        # if os.path.exists(default_icon_path):
        #     button.setIcon(QIcon(default_icon_path))
        # else:
        #     print(f"[Warning] Icon not found at: {default_icon_path}")

        # # Add button to layout
        # self.reset_options_layout.addWidget(button)

        # Detailed display output
        # print(f"[Info] Option button created:")
        # print(f"       Label     : {state.get('label', 'N/A')}")
        # print(f"       State id : {state.get('id', 'N/A')}")
        # print(f"       ShowOnInit: {state.get('showOnInit', False)}")
        # print(f"       Icon Path : {'Found' if os.path.exists(default_icon_path) else 'Missing'}")
        # Vérifie si c'est un bouton multi-sélection
        is_multi = state.get("isMultiSelect", False)

        # اختيار القالب والأيقونة حسب الحالة
        if is_multi:
            template_button = self.Temeplete_Button_2
            icon_path = default_icon_path_Templete2
        else:
            template_button = self.template_button
            icon_path = default_icon_path

        # إنشاء الزر
        button = QPushButton(state.get("label", "Unnamed"), self.reset_options_container)
        button.setStyleSheet(template_button.styleSheet())
        button.setFixedSize(template_button.size())

        # تعيين شكل المؤشر فقط إذا كانت isMultiSelect = True
        button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        # جعل الأيقونة على اليسار
        button.setLayoutDirection(Qt.LayoutDirection.RightToLeft)


        # ربط الزر بالحالة
        button.clicked.connect(lambda _, s=state: self.load_state(s))

        # تعيين الأيقونة إذا كانت موجودة
        if os.path.exists(icon_path):
            button.setIcon(QIcon(icon_path))
        else:
            print(f"[Warning] Icon not found at: {icon_path}")

        # إضافة الزر إلى الواجهة
        self.reset_options_layout.addWidget(button)
        # Detailed display output
        # print(f"[Info] Option button created:")
        # print(f"       Label     : {state.get('label', 'N/A')}")
        # print(f"       State id : {state.get('id', 'N/A')}")
        # print(f"       ShowOnInit: {state.get('showOnInit', False)}")
        # print(f"       Icon Path : {'Found' if os.path.exists(default_icon_path) else 'Missing'}")
        # Vérifie si c'est un bouton multi-sélection




    def display_state_stack_as_table(self):
        if not self.state_stack:
            print("📭 La pile d'états est vide.\n")
            return

        print("\n📦 Pile des états (🧱 du plus ancien au plus récent) :\n")
        for i, state in enumerate(self.state_stack):
            print(f"🧱 État {i+1:02d} :")
            print(json.dumps(state, indent=4, ensure_ascii=False))  # JSON واضح ومنسق
            print("-" * 50)




    #Charge un nouvel état de scénario. Met à jour l'interface avec les nouvelles actions,
    #le template associé, et remet les éléments spécifiques à zéro (copieur, INITAILE...).
    #:param state: Dictionnaire représentant l'état à charger.
    def load_state(self, state):

        print("\n📥 ===== Début du chargement d’un nouvel état =====")
        print(f"🔹 État reçu : {state}")

        # 🧾 Affichage de la pile avant mise à jour
        print("\n🪜 Pile d'états AVANT mise à jour :")
        self.display_state_stack_as_table()
        is_multi = state.get("isMultiSelect", False)

        if not is_multi:
        # Ajout de l’état à la pile
            self.state_stack.append(state)

        print(f"Pile d’états mise à jour (taille : {len(self.state_stack)}).")

        # print("➡️​➡️​➡️​➡️​➡️​➡️​ Contenu actuel de state_stack :")
        self.display_state_stack_as_table()

        # Mise à jour du scénario
        # template = state.get("Template", "")
        # print(f"Chargement du scénario avec le template : '{template}'")
        # self.update_scenario(template, state)

        if not is_multi:
            template = state.get("Template", "")
            self.update_scenario(template, state)


        # Mise à jour des options de réinitialisation
        actions = state.get("actions", [])
        print(f"Actions à charger : {actions}")
        self.update_reset_options(actions)

        # Mise à jour des couleurs et gestion du dernier bouton
        print("Mise à jour des couleurs et du dernier bouton...")
        self.update_actions_color_and_handle_last_button()

        # Suppression des éléments inutiles
        print("Suppression des éléments : copier et INITAILE")
        self.remove_copier()
        self.remove_INITAILE()

        # 🧾 Affichage de la pile après mise à jour
        print("\n📦 Pile d'états APRÈS mise à jour :")
        self.display_state_stack_as_table()

        print("✅ ===== Fin du chargement de l’état =====\n")






    def inject_border_into_style(self, old_style: str, border_line: str = "border: 2px solid #cc4c4c;") -> str:
        print("\n[🔍] Style avant injection :\n", old_style)
        pattern = r"(QLineEdit\s*{[^}]*?)\s*}"  # يبحث عن بداية كتلة QLineEdit
        match = re.search(pattern, old_style, re.DOTALL)

        if match:
            before_close = match.group(1)
            if "border" not in before_close:
                new_block = before_close + f"\n    {border_line}\n}}"
                result = re.sub(pattern, new_block, old_style, flags=re.DOTALL)
                print("[✅] Nouveau style après injection dans QLineEdit:\n", result)
                return result
            else:
                print("[⚠️] 'border' déjà présent, aucun changement.")
                return old_style
        else:
            appended = old_style + f"""
            QLineEdit {{
                {border_line}
            }}"""
            print("[➕] Bloc QLineEdit ajouté car manquant:\n", appended)
            return appended





    def remove_border_from_style(self, style: str) -> str:
        # نحذف أي سطر فيه border داخل QLineEdit أو بشكل عام
        cleaned_style = re.sub(r'border\s*:\s*[^;]+;', '', style, flags=re.IGNORECASE)
        return cleaned_style.strip()






    def validate_qlineedit(self, qlineedit: QLineEdit, default_value="50,50"):
        text = qlineedit.text().strip()
        pattern = r"^\s*(\d+)(?:\s*,\s*(\d+))?\s*$"
        match = re.match(pattern, text)

        if match:
            min_val = int(match.group(1))
            max_val = int(match.group(2)) if match.group(2) else min_val

            if min_val > max_val:
                qlineedit.setText(f"{min_val},{min_val}")
                old_style = qlineedit.styleSheet()
                def apply_style():
                    new_style = self.inject_border_into_style(old_style)
                    qlineedit.setStyleSheet(new_style)
                    qlineedit.setToolTip("La valeur Min est supérieure à Max. Correction appliquée.")
                QTimer.singleShot(0, apply_style)
            else:
                old_style = qlineedit.styleSheet()
                cleaned = self.remove_border_from_style(old_style)
                qlineedit.setStyleSheet(cleaned)
                qlineedit.setToolTip("")
        else:
            qlineedit.setText(default_value)
            old_style = qlineedit.styleSheet()
            def apply_error():
                new_style = self.inject_border_into_style(old_style)
                qlineedit.setStyleSheet(new_style)
                qlineedit.setToolTip("Veuillez entrer une valeur sous la forme 'Min,Max' ou un seul nombre.")
            QTimer.singleShot(0, apply_error)






    # Met à jour dynamiquement le style de tous les widgets enfants dans le layout du scénario.
    # Différencie le dernier bloc des autres :
    # - Applique des styles personnalisés pour les QLabels, QSpinBox, QCheckBox, et QComboBox.
    # - Cache le dernier bouton dans chaque bloc sauf le dernier, où il devient visible et fonctionnel.
    # - Applique des styles conditionnels selon les icônes disponibles.

    def update_actions_color_and_handle_last_button(self):

        arrow_down_path = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "arrow_Down.png").replace("\\", "/")
        arrow_up_path = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "arrow_up.png").replace("\\", "/")
        arrow_down_path_w = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "arrow_Down_w.png").replace("\\", "/")
        arrow_up_path_w = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "arrow_up_w.png").replace("\\", "/")


        down_exists = os.path.exists(arrow_down_path)
        up_exists = os.path.exists(arrow_up_path)
        down_exists_w = os.path.exists(arrow_down_path)
        up_exists_w = os.path.exists(arrow_up_path)

       
        for i in range(self.scenario_layout.count()):
            widget = self.scenario_layout.itemAt(i).widget()

            if widget:
                if i != self.scenario_layout.count() - 1:
                    widget.setStyleSheet("background-color: #ffffff; border: 1px solid #b2cddd; border-radius: 8px;")
                    label_list = [child for child in widget.children() if isinstance(child, QLabel)]
                    if label_list:
                        first_label = label_list[0]

                        # 🖌️ Appliquer style par défaut à la première QLabel
                        first_label.setStyleSheet("""
                            QLabel {
                                color: #669bbc;
                                font-size: 16px;
                                border: none;
                                border-radius: 4px;
                                text-align: center;
                                background-color: transparent;
                                font-family: "Times", "Times New Roman", serif;
                                margin-left: 10px;
                            }
                        """)

                        # 🎯 Si elle commence par "Random", remplacer le style
                        if first_label.text().startswith("Random"):
                            first_label.setStyleSheet("""
                                QLabel {
                                    color: #669bbc;
                                    font-size: 9px;
                                    border: none;
                                    border-radius: 4px;
                                    background-color: transparent;
                                    font-family: "Monaco", monospace;
                                    padding: 0px;
                                    margin: 0px;
                                    border:None;
                                }
                            """)
                            print(f"[🎯] Style appliqué sur QLabel (index 0): '{first_label.text()}'")

                        # 🎨 Appliquer style aux autres QLabels
                        for label in label_list[1:]:
                            label.setStyleSheet("""
                                QLabel {
                                    color: #669bbc;
                                    font-size: 14px;
                                    border: none;
                                    border-radius: 4px;
                                    text-align: center;
                                    background-color: transparent;
                                    font-family: "Times", "Times New Roman", serif;
                                }
                            """)

                            # 🎯 S'il commence par "Random", on remplace
                            if label.text().startswith("Random"):
                                label.setStyleSheet("""
                                    QLabel {
                                        color: #669bbc;
                                        font-size: 9px;
                                        border: none;
                                        border-radius: 4px;
                                        background-color: transparent;
                                        font-family: "Monaco", monospace;
                                        padding: 0px;
                                        margin: 0px;
                                        border:None;
                                    }
                                """)
                                print(f"[🎯] Style appliqué sur QLabel: '{label.text()}'")


                    buttons = [child for child in widget.children() if isinstance(child, QPushButton)]
                    if buttons:
                        last_button = buttons[-1]
                        last_button.setVisible(False)  


                    spin_boxes = [child for child in widget.children() if isinstance(child, QSpinBox)]
                    if spin_boxes and down_exists and up_exists:
                        new_style = f"""
                            QSpinBox {{
                                padding: 2px; 
                                border: 1px solid #669bbc; 
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
                                    background-color: #669bbc;
                                    border: 2px solid #669bbc;
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
                        arrow_down_path = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "arrow_Down.png").replace("\\", "/")
                        down_exists = os.path.exists(arrow_down_path)
                        if down_exists:
                            old_style = QComboBox.styleSheet()
                            new_style = f"""
                                QComboBox::down-arrow {{
                                    image: url("{arrow_down_path}");
                                    width: 13px;
                                    height: 13px;
                                    border: 1px solid #669bbc; 
                                    background-color: white;
                                }}
                                QComboBox::drop-down {{
                                    border: 1px solid #669bbc; 
                                    width: 20px;
                                    outline: none;
                                }}
                                
                                QComboBox QAbstractItemView {{
                                    min-width: 90px; 
                                    border: 1px solid #669bbc; 
                                    background: white;
                                    selection-background-color: #669bbc;
                                    selection-color: white;
                                    padding: 3px; 
                                    margin: 0px;  
                                    alignment: center; 
                                }}
                                QComboBox {{
                                    padding-left: 10px; 
                                    font-size: 12px;
                                    font-family: "Times", "Times New Roman", serif;
                                    border: 1px solid #669bbc; 
                                }}
                                QComboBox QAbstractItemView::item {{
                                    padding: 5px; 
                                    font-size: 12px;
                                    color: #333;
                                    border: none; 
                                }}
                                QComboBox QAbstractItemView::item:selected {{
                                    background-color: #669bbc;
                                    color: white;
                                    border-radius: 3px;
                                }}
                                QComboBox:focus {{
                                    border: 1px solid #669bbc; 
                                }}
                            """
                            combined_style = old_style + new_style
                            QComboBox.setStyleSheet(combined_style)

                if i == self.scenario_layout.count() - 1:
                    widget.setStyleSheet("background-color: #669bbc; border-radius: 8px;")

                    label_list = [child for child in widget.children() if isinstance(child, QLabel)]

                    if label_list:
                        # 🎯 Première QLabel (souvent le titre)
                        label_list[0].setStyleSheet("""
                            QLabel {
                                color: white;
                                font-size: 16px;
                                border: none;
                                border-radius: 4px;
                                text-align: center;
                                background-color: #669bbc;
                                font-family: "Times", "Times New Roman", serif;
                                margin-left: 8px;
                            }
                        """)

                        # ➕ Vérifier si c’est un "Random"
                        if label_list[0].text().startswith("Random"):
                            label_list[0].setStyleSheet("""
                                QLabel {
                                    color: white;
                                    font-size: 9px;
                                    border: 1px dashed #ffffff;
                                    border-radius: 4px;
                                    background-color: transparent;
                                    font-family: "Monaco", monospace;
                                    padding: 0px;
                                    margin: 0px;
                                    border:None;
                                }
                            """)
                            print(f"[🎯] Dernier widget - QLabel (0) spéciale: '{label_list[0].text()}'")

                        # 🎨 Toutes les autres QLabels
                        for label in label_list[1:]:
                            label.setStyleSheet("""
                                QLabel {
                                    color: white;
                                    font-size: 16px;
                                    border: none;
                                    border-radius: 4px;
                                    text-align: center;
                                    background-color: #669bbc;
                                    font-family: "Times", "Times New Roman", serif;
                                }
                            """)

                            # 🎯 Appliquer style spécial si commence par "Random"
                            if label.text().startswith("Random"):
                                label.setStyleSheet("""
                                    QLabel {
                                        color: white;
                                        font-size: 9px;
                                        border: 1px dashed #ffffff;
                                        border-radius: 4px;
                                        background-color: transparent;
                                        font-family: "Monaco", monospace;
                                        padding: 0px;
                                        margin: 0px;
                                        border:None;
                                    }
                                """)
                                print(f"[🎯] Dernier widget - QLabel Random: '{label.text()}'")



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
                                    background-color: #669bbc;
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
                    arrow_down_path = os.path.join(SCRIPT_DIR, '..', "interface", "icons", "arrow_Down.png").replace("\\", "/")

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
                                selection-background-color: #669bbc;
                                selection-color: white;
                                padding: 3px; 
                                margin: 0px;  
                                alignment: center; 
                            }}
                            QComboBox {{
                                padding-left: 10px; 
                                font-size: 12px;
                                font-family: "Times", "Times New Roman", serif;
                                border: 1px solid #669bbc; 
                                outline: none; 
                            }}
                            QComboBox QAbstractItemView::item {{
                                padding: 5px; 
                                font-size: 12px;
                                color: #333;
                                border: none; 
                            }}
                            QComboBox QAbstractItemView::item:selected {{
                                background-color: #669bbc;
                                color: white;
                                border-radius: 3px;
                            }}
                            QComboBox:focus {{
                                border: 1px solid #669bbc; 
                            }}
                        """
                        combined_style = old_style + new_style
                        QComboBox.setStyleSheet(combined_style)

            
                # qlineedits = [child for child in widget.children() if isinstance(child, QLineEdit)]

                # for idx, qlineedit in enumerate(qlineedits):
                #     # لحفظ قيمة idx داخل كل حلقة
                #     def create_validator(line_edit, default_val):
                #         def validator():
                #             self.validate_qlineedit(line_edit, default_val)
                #         return validator

                #     if len(qlineedits) > 1 and idx == 0:
                #         qlineedit.editingFinished.connect(create_validator(qlineedit, "50,50"))
                #     else:
                #         qlineedit.editingFinished.connect(create_validator(qlineedit, "1,1"))


                qlineedits = [child for child in widget.children() if isinstance(child, QLineEdit)]
                checkbox_qlineedit = None  # ⚠️ تخزين QLineEdit المرتبط بـ QCheckBox

                print("[🔍] Total QLineEdits détectés:", len(qlineedits))

                # إذا كان آخر QLineEdit داخل widget يحتوي على QCheckBox، نحذفه من القائمة
                if qlineedits:
                    last_qlineedit = qlineedits[-1]
                    parent_widget = last_qlineedit.parent()
                    if parent_widget:
                        contains_checkbox = any(isinstance(child, QCheckBox) for child in parent_widget.children())
                        print(f"[🧩] Dernier QLineEdit détecté. Contient QCheckBox ? {contains_checkbox}")
                        if contains_checkbox:
                            checkbox_qlineedit = last_qlineedit  # ✅ نحفظه ولكن لا نحذفه
                            qlineedits.pop()  # حذف العنصر الأخير
                            print("[📦] QLineEdit avec QCheckBox stocké séparément.")

                # ربط المحققين للـ QLineEdits العادية
                for idx, qlineedit in enumerate(qlineedits):
                    def create_validator(line_edit, default_val):
                        def validator():
                            print(f"[📝] Validation déclenchée pour QLineEdit[{idx}] avec valeur par défaut: {default_val}")
                            self.validate_qlineedit(line_edit, default_val)
                        return validator

                    if len(qlineedits) > 1 and idx == 0:
                        qlineedit.editingFinished.connect(create_validator(qlineedit, "50,50"))
                    else:
                        qlineedit.editingFinished.connect(create_validator(qlineedit, "1,1"))

                # ربط المحقق الخاص بـ QLineEdit مع QCheckBox
                if checkbox_qlineedit:
                    print("[🔗] Connexion du QLineEdit contenant QCheckBox à une validation personnalisée.")
                    def validate_checkbox_qlineedit():
                        print("[✅] Validation personnalisée déclenchée pour QLineEdit avec QCheckBox.")
                        self.validate_checkbox_linked_qlineedit(checkbox_qlineedit)

                    checkbox_qlineedit.editingFinished.connect(validate_checkbox_qlineedit)
                else:
                    print("[⚠️] Aucun QLineEdit avec QCheckBox détecté.")






    def validate_checkbox_linked_qlineedit(self, qlineedit: QLineEdit):
        if qlineedit is None:
            print("[❌ ERREUR] Le QLineEdit est None. Validation ignorée.")
            return

        parent_widget = qlineedit.parent()
        full_state = parent_widget.property("full_state") if parent_widget else None

        text = qlineedit.text().strip()
        print(f"[🔍 INFO] Texte saisi dans QLineEdit associé à QCheckBox : '{text}'")

        old_style = qlineedit.styleSheet()
        cleaned_style = self.remove_border_from_style(old_style)

        # ✅ Vérification conditionnelle selon full_state
        if full_state and isinstance(full_state, dict):
            sub_id = full_state.get("id", "")
            sub_label = full_state.get("label", "Google")

            # Chercher le QCheckBox associé dans le même parent
            checkbox = next((child for child in parent_widget.children() if isinstance(child, QCheckBox)), None)

            if sub_id in ["open_spam", "open_inbox"]:
                if checkbox and checkbox.isChecked():
                    if text :
                        print("[✅ CONDITION VALIDE] Checkbox cochée et texte valide.")
                        def apply_ok():
                            qlineedit.setStyleSheet(cleaned_style)
                            qlineedit.setToolTip("")
                            print("[🔔 INFO] Bordure retirée et tooltip supprimé.")
                        QTimer.singleShot(0, apply_ok)
                        return
                    else:
                        print("[⚠️ TEXTE INVALIDE] Champ vide ou numérique malgré checkbox cochée.")
                        qlineedit.setText(sub_label or "Google")

                        def apply_error():
                            new_style = self.inject_border_into_style(cleaned_style)
                            qlineedit.setStyleSheet(new_style)
                            qlineedit.setToolTip("Texte invalide. Valeur remplacée par défaut depuis full_state.")
                            print("[🔔 INFO] Erreur appliquée avec bordure rouge.")
                        QTimer.singleShot(0, apply_error)
                        return

        # 🧾 Sinon: validation classique (ancienne logique)
        if text.isdigit() or len(text) < 4:
            print("[⚠️ INVALIDE] Le texte est un nombre ou trop court (<4).")
            qlineedit.setText("Google")

            def apply_error():
                new_style = self.inject_border_into_style(cleaned_style)
                qlineedit.setStyleSheet(new_style)
                qlineedit.setToolTip("Le texte est un nombre ou trop court, veuillez corriger la saisie.")
                print("[🔔 INFO] Bordure rouge appliquée et tooltip invitant à corriger la saisie.")
            QTimer.singleShot(0, apply_error)
        else:
            print("[✅ VALIDE] Texte non numérique et au moins 4 caractères.")

            def apply_ok():
                qlineedit.setStyleSheet(cleaned_style)
                qlineedit.setToolTip("")
                print("[🔔 INFO] Bordure retirée et tooltip supprimé.")
            QTimer.singleShot(0, apply_ok)





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
        print("\n===== Mise à jour des options de réinitialisation =====")

        count = self.reset_options_layout.count()
        print(f"Suppression des {count} widgets existants dans reset_options_layout.")
        for i in reversed(range(count)):
            widget = self.reset_options_layout.itemAt(i).widget()
            if widget:
                print(f"Suppression du widget à l'indice {i}.")
                widget.deleteLater()

        if not actions:
            print("Aucune action trouvée. Chargement des options initiales.")
            self.load_initial_options()
            print("Options initiales chargées.")
            return

        # print(f"Création des boutons pour {len(actions)} actions:")
        for action_key in actions:
            state = self.states.get(action_key)
            if state:
                label = state.get('label', action_key)
                print(f"🔘 {label}")
                self.create_option_button(state)
            else:
                print(f"⚠️ Aucune définition trouvée pour l'action : '{action_key}'.")

        print("===== Mise à jour terminée =====\n")





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
        elif template_name == "Template3":
            template_frame = self.template_Frame3
        elif template_name == "Template4":
            template_frame = self.template_Frame4
        else:
            return

        if template_frame:
            new_template = QFrame()
            new_template.setStyleSheet(template_frame.styleSheet())
            new_template.setMaximumHeight(51)
            new_template.setMinimumHeight(51)
            new_template.setMaximumWidth(780)  # ← Ajout ici (ajuste selon ton besoin)

            lineedits = []
            checkboxes = []
            first_label_updated = False

            for child in template_frame.children():
                # print(f"[👁️] Found: {type(child).__name__} | Text: {getattr(child, 'text', lambda: '')()}")

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
                    # print(f"[📝] Copied QLineEdit → Value: {child.text()}")

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
        # print("\n===== Retour à l'état précédent =====")
        # print("\n 🫁🫁🫁🫁🫁🫁​​ ===== Contenu de json_data fourni à MainWindow avant  =====")
        self.display_state_stack_as_table()
        print("=====================================================\n")
        if len(self.state_stack) > 1:
            # print(f"Plus d’un état dans la pile ({len(self.state_stack)}). Suppression de l’état actuel...")

            if self.scenario_layout.count() > 0:
                # print("Suppression du dernier widget du scénario affiché.")
                last_item = self.scenario_layout.takeAt(self.scenario_layout.count() - 1)
                if last_item.widget():
                    last_item.widget().deleteLater()
            
            self.state_stack.pop()
            previous_state = self.state_stack[-1]
            # print(f"État précédent restauré : {previous_state.get('label', 'Sans nom')}")

            self.update_reset_options(previous_state.get("actions", []))
        else:
            # print("Un seul état ou aucun. Réinitialisation complète de l’interface.")
            self.state_stack.clear()

            while self.scenario_layout.count() > 0:
                last_item = self.scenario_layout.takeAt(0)
                if last_item.widget():
                    last_item.widget().deleteLater()

            self.load_initial_options()
            # print("Options initiales rechargées.")

        self.update_actions_color_and_handle_last_button()
        # print("Couleurs et état du dernier bouton mis à jour.")

        self.remove_copier()
        # print("Élément 'copier' supprimé s’il existe.")
        # print("\n 🎁​🎁​🎁​🎁​🎁​​ ===== Contenu de json_data fourni à MainWindow apres =====")
        # self.display_state_stack_as_table()
        # print("=====================================================\n")
        # print("===== Retour terminé =====\n")
        print("\n🪜 go_to_previous_state mise à jour apres go_to_previous_state:")
        self.display_state_stack_as_table()




    # Nettoie entièrement les logs affichés à l'écran et vide la variable globale `logs`.

    def on_Clear_Button_clicked(self):
        while self.log_layout.count():
            item = self.log_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        global logs
        logs = []





    def on_scenario_changed(self, name_selected):
        session_path = os.path.join(APPDATA_DIR, "session.txt")
        if not os.path.exists(session_path):
            print("[❌] session.txt introuvable")
            return

        with open(session_path, "r", encoding="utf-8") as f:
            encrypted_key = f.read().strip()

        payload = {
            "encrypted": encrypted_key,
            "name": name_selected
        }

        try:
            response = requests.post("http://localhost/auth-api/get_scenario_by_name.php", json=payload)
            if response.status_code == 200:
                result = response.json()

                # 🔐 vérifier la session
                if result.get("session") is False:
                    print("[🔒] Session expirée. Redirection vers la page de connexion.")
                    self.login_window = LoginWindow()
                    self.login_window.setFixedSize(1710, 1005)

                    screen = QGuiApplication.primaryScreen()
                    screen_geometry = screen.availableGeometry()
                    x = (screen_geometry.width() - self.login_window.width()) // 2
                    y = (screen_geometry.height() - self.login_window.height()) // 2
                    self.login_window.move(x, y)
                    self.login_window.show()
                    self.close()
                    return

                # ✅ session valide et scénario trouvé


                if result.get("success"):
                    scenario = result["scenario"]
                    print("[✅] Scénario récupéré:", scenario)

                    self.state_stack = scenario['state_stack']
                    print("🤖 state_stack récupéré :", self.state_stack)

                    # Cloner la stack pour itération sécurisée
                    state_stack_copy = copy.deepcopy(self.state_stack)

                    for index, state in enumerate(state_stack_copy, start=1):
                        print(f"\n[🧩] État #{index} dans la pile:")
                        try:
                            print(json.dumps(state, indent=4, ensure_ascii=False))
                        except TypeError:
                            print("[⚠️] Impossible de formater l'état : non sérialisable en JSON")

                        print(f"[🚀] Appel de load_state() pour l'état #{index}")
                        try:
                            self.load_state(state)
                            self.update_actions_color_and_handle_last_button()
                        except Exception as e:
                            print(f"[❌] Erreur pendant load_state(): {e}")

                    print("[✅] Scénario chargé avec succès")

                    # ✅ Supprimer les doublons dans self.state_stack
                    try:
                        # Utiliser set avec tuple trié des items pour détecter unicité
                        unique_states = []
                        seen = set()
                        for state in self.state_stack:
                            # Convert dict to immutable, hashable form (tuple)
                            state_key = json.dumps(state, sort_keys=True, ensure_ascii=False)
                            if state_key not in seen:
                                seen.add(state_key)
                                unique_states.append(state)

                        self.state_stack = unique_states
                        print("[🧹] self.state_stack dédupliqué avec succès")
                    except Exception as e:
                        print(f"[⚠️] Échec de suppression des doublons: {e}")

                else:
                    print("[❌]", result.get("error")) #  [❌] Aucun scénario trouvé 


            else:
                print(f"[❌] Erreur HTTP {response.status_code}")

        except Exception as e:
            print("[❌] Exception:", str(e))











class LoginWindow(QMainWindow):



    def __init__(self):
        super().__init__()

        # Charger le bon fichier .ui
        self.ui_path = self.select_ui_file()
        uic.loadUi(self.ui_path, self)

        # Initialiser les widgets si Auth.ui
        if "Auth.ui" in self.ui_path:
            self.initialize_login_ui()

        self.setWindowTitle("AutoMailPro")



    def select_ui_file(self) -> str:
        """Retourne le chemin du .ui à charger (interface ou login)"""
        session_path = os.path.join(APPDATA_DIR, "session.txt")

        if os.path.exists(session_path):
            try:
                with open(session_path, "r") as f:
                    encrypted = f.read().strip()

                decrypted = decrypt_date(encrypted, key)

                # Extraction du username et de la date
                if "::" in decrypted:
                    username, date_str = decrypted.split("::", 1)
                    username = username.strip()
                    date_str = date_str.strip()

                    # Affichage dans la console
                    print(f"[SESSION INFO] Utilisateur: {username}")
                    print(f"[SESSION INFO] Dernière session: {date_str}")

                    last_session = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                    now = datetime.datetime.utcnow()

                    if now - last_session < timedelta(days=2):
                        return os.path.abspath(os.path.join(os.path.dirname(__file__), "..",  "interface", "interface.ui"))

            except Exception as e:
                print(f"[SESSION ERROR] {e}")

        # Retourne le chemin absolu vers Auth.ui
        return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "interface", "login_ui", "Auth.ui"))



    def initialize_login_ui(self):
        """Initialise l'interface de connexion"""
        self.login_input = self.findChild(QLineEdit, "loginInput")
        self.password_input = self.findChild(QLineEdit, "passwordInput")
        self.login_button = self.findChild(QPushButton, "loginButton")
        self.title = self.findChild(QPushButton, "title")
        self.erreur_label = self.findChild(QLabel, "erreur")

        if self.erreur_label:
            self.erreur_label.hide()

        if self.title:
            self.title.clicked.connect(self.handle_show_session_date)
        if self.login_button:
            self.login_button.clicked.connect(self.handle_login)

        # Ajout ombre panneau droit
        right_frame = self.findChild(QWidget, "rightFrame")
        if right_frame:
            shadow = QGraphicsDropShadowEffect(self)
            shadow.setBlurRadius(25)
            shadow.setXOffset(0)
            shadow.setYOffset(8)
            shadow.setColor(QColor(0, 0, 0, 80))
            right_frame.setGraphicsEffect(shadow)

        # Image de fond
        self.background_image_path = os.path.join(SCRIPT_DIR, "icons", "baghround.jpg")
        self.background_frame = self.findChild(QFrame, "background")
        if self.background_frame:
            self.background_label = QLabel(self.background_frame)
            self.background_label.setStyleSheet("""
                border-top-left-radius: 30px;
                border-bottom-left-radius: 30px;
                border-top-right-radius: 0px;
                border-bottom-right-radius: 0px;
                overflow: hidden;
            """)
            self.background_label.setScaledContents(True)
            self.background_label.lower()
            self.update_background_image()


            self.logoFrame = self.findChild(QFrame, "logoFrame")

            if self.logoFrame:
                self.logo_label = QLabel(self.logoFrame)
                self.logo_label.setScaledContents(True)
                logo_path = os.path.join(SCRIPT_DIR, "icons", "logo.jpg")
                pixmap = QPixmap(logo_path)
                if not pixmap.isNull():
                    self.logo_label.setPixmap(pixmap)
                    self.logo_label.setGeometry(0, 0, self.logoFrame.width(), self.logoFrame.height())
                    self.logo_label.show()
 
            self.UseFrame = self.findChild(QFrame, "userFrame")
            if self.UseFrame:
                self.user_label = QLabel(self.UseFrame)
                self.user_label.setScaledContents(True)
                user_path = os.path.join(SCRIPT_DIR, "icons", "user.png")
                user_pixmap = QPixmap(user_path)
                if not user_pixmap.isNull():
                    self.user_label.setPixmap(user_pixmap)
                    self.user_label.setGeometry(0, 0, self.UseFrame.width(), self.UseFrame.height())
                    self.user_label.show()



    def update_background_image(self):
        if hasattr(self, "background_frame") and hasattr(self, "background_label"):
            pixmap = QPixmap(self.background_image_path)
            if not pixmap.isNull():
                self.background_label.resize(self.background_frame.size())
                self.background_label.setPixmap(pixmap)



    def resizeEvent(self, event):
        self.update_background_image()
        return super().resizeEvent(event)



    def _APIaccess(self, username, password):
        try:
            print("\u23f3 [DEBUG] D\u00e9but d'authentification via API")
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36'
            }
            _API = "https://reporting.nrb-apps.com/pub/chk_usr1.php?rv4=1"
            data = {
                "rID": "1", "u": username, "p": password,
                "k": "mP5QXYrK9E67Y", "l": "1"
            }

            print(f"📤 [DEBUG] Envoi des donn\u00e9es \u00e0 l'API : {data}")
            for i in range(5):
                try:
                    response = requests.post(_API, headers=headers, data=data, verify=False).text
                    print(f"✅ [DEBUG] R\u00e9ponse re\u00e7ue \u00e0 la tentative {i+1} : {response}")
                    break
                except Exception as e:
                    print(f"⚠️ [DEBUG] \u00c9chec tentative {i+1} : {str(e)}")
                    time.sleep(5)
            else:
                print("❌ [DEBUG] \u00c9chec apr\u00e8s 5 tentatives")
                return -3

            if response == "-1":
                print("❌ [DEBUG] Identifiants incorrects")
                return -1
            elif response == "-2":
                print("❌ [DEBUG] Appareil non autoris\u00e9")
                return -2
            else:
                print(f"🔐 [DEBUG] Donn\u00e9es chiffr\u00e9es re\u00e7ues : {response}")
                entity = decrypt_date(response, key)
                print(f"🔓 [DEBUG] Donn\u00e9es d\u00e9chiffr\u00e9es : {entity}")
                return (entity, response) if entity != -1 else -4
        except Exception as e:
            print(f"🔥 [DEBUG] Erreur inattendue dans _APIaccess : {str(e)}")
            return -5



    def handle_login(self):
        username = self.login_input.text().strip() if self.login_input else ""
        password = self.password_input.text().strip() if self.password_input else ""

        print(f"📅 [DEBUG] Nom d'utilisateur : '{username}', Mot de passe : {'*' * len(password)}")

        if not username or not password:
            print("⚠️ [DEBUG] Champs vides détectés")
            self.erreur_label.setText("Veuillez remplir tous les champs obligatoires.")
            self.erreur_label.show()
            return

        auth_result = self._APIaccess(username, password)
        print(f"🔁 [DEBUG] Résultat de l'authentification : {auth_result}")

        if isinstance(auth_result, int):
            messages = {
                -1: "Identifiants incorrects. Veuillez réessayer.",
                -2: "Cet appareil n'est pas autorisé. Contactez l'équipe de support.",
                -3: "Impossible de se connecter au serveur. Réessayez plus tard.",
                -4: "Accès refusé à cette application.",
                -5: "Erreur inconnue pendant l'authentification."
            }
            self.erreur_label.setText(messages.get(auth_result, "Erreur inconnue."))
            self.erreur_label.show()
            return

        entity, encrypted_response = auth_result
        self.erreur_label.hide()

        # هنا نفك تشفير الـ encrypted_response قبل إضافته للجلسة
        decrypted_response = decrypt_date(encrypted_response, key)
        print(f"🔓 [DEBUG] Réponse déchiffrée pour session : {decrypted_response}")

        casablanca_time = datetime.datetime.now(pytz.timezone("Africa/Casablanca"))
        print(f"🕒 [DEBUG] Heure Casablanca : {casablanca_time}")

        # دمج اسم المستخدم + الوقت + البيانات المفكوكة في نص الجلسة
        session_data = f"{username}::{casablanca_time.strftime('%Y-%m-%d %H:%M:%S')}::{decrypted_response}"
        print(f"🔐 [DEBUG] Session à chiffrer : {session_data}")

        encrypted = encrypt_date(session_data, key)

        os.makedirs(APPDATA_DIR, exist_ok=True)
        session_file_path = os.path.join(APPDATA_DIR, "session.txt")
        print(f"📂 [DEBUG] Sauvegarde de la session dans : {session_file_path}")
        with open(session_file_path, "w") as f:
            f.write(encrypted)

        # تحميل ملف التكوين كما في الكود الأصلي
        json_path = os.path.join(SCRIPT_DIR, '..', "Tools", "action.json")
        print(f"📂 [DEBUG] Chargement du fichier de configuration : {json_path}")
        try:
            with open(json_path, "r", encoding='utf-8') as file:
                json_data = json.load(file)

            if not json_data:
                raise ValueError("Fichier de configuration vide")

        except Exception as e:
            print(f"❌ [DEBUG] Erreur de lecture configuration : {str(e)}")
            self.erreur_label.setText(f"Erreur configuration : {str(e)}")
            self.erreur_label.show()
            return

        print("🚀 [DEBUG] Lancement de la fenêtre principale")
        self.main_window = MainWindow(json_data)
        self.main_window.setFixedSize(1710, 1005)
        self.main_window.setWindowTitle("AutoMailPro")
        self.main_window.stopButton.clicked.connect(lambda: stop_all_processes(self.main_window))

        screen = QGuiApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()
        x = (screen_geometry.width() - self.main_window.width()) // 2
        y = (screen_geometry.height() - self.main_window.height()) // 2
        self.main_window.move(x, y)
        self.main_window.show()
        self.close()



    def handle_show_session_date(self):
        session_path = os.path.join(APPDATA_DIR, "session.txt")
        if not os.path.exists(session_path):
            self.erreur_label.setText("Aucune session enregistrée.")
            self.erreur_label.show()
            return
        try:
            with open(session_path, "r") as f:
                encrypted = f.read().strip()
            decrypted = decrypt_date(encrypted, key)
            self.erreur_label.setText(f"Date session : {decrypted}")
            self.erreur_label.show()
        except Exception as e:
            self.erreur_label.setText(f"Erreur lecture session : {e}")
            self.erreur_label.show()














def main():
    session_path = os.path.join(APPDATA_DIR, "session.txt")

    if len(sys.argv) < 3:
        sys.exit(1)

    encrypted_key = sys.argv[1]
    secret_key = sys.argv[2]
    if not verify_key(encrypted_key, secret_key):
        sys.exit(1)

    session_valid = False
    username = None


    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36'
    }

    if os.path.exists(session_path):
        try:
            print("📂 [SESSION] Lecture du fichier de session...")
            with open(session_path, "r") as f:
                encrypted = f.read().strip()

            if encrypted:
                print("🔐 [SESSION] Déchiffrement des données de session...")
                decrypted = decrypt_date(encrypted, key)

                if "::" in decrypted:
                    parts = decrypted.split("::", 2)
                    if len(parts) == 3:
                        username = parts[0].strip()
                        date_str = parts[1].strip()
                        p_entity = parts[2].strip()
                        print(f"🧾 [SESSION] Données extraites ➜ Utilisateur: `{username}`, Date: `{date_str}`, Entité: `{p_entity}`")
                    else:
                        print("❌ [ERREUR] Format invalide : 3 parties attendues (username::date::entity)")
                        session_valid = False
                        return

                    try:
                        last_session = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                        now = datetime.datetime.utcnow()

                        if (now - last_session) < timedelta(days=2):
                            print("⏳ [VALIDATION] Vérification de la session via API...")

                            try:
                                url = "https://apps1.nrb-apps.com/pub/chk_usr1.php"
                                params = {
                                    "k": "mP5QXYrK9E67Y",
                                    "rID": "4",
                                    "u": username,
                                    "entity": p_entity
                                }

                                print(f"🌐 [API] Envoi de la requête ➜ {url}")
                                response = requests.get(url, params=params, headers=headers, verify=False)
                                print(f"📥 [API] Code de réponse: {response.status_code}")
                                print(f"📄 [API] Contenu brut de la réponse:\n{response.text}")
                                if response.status_code == 200:
                                    print(f"📥 [API] Réponse HTTP 200 reçue ✅")
                                    data = response.json()

                                    if data.get("data")[0].get("n") == "1":
                                        session_valid = True
                                        print(f"✅ [SESSION] Session valide pour l'utilisateur `{username}` 🎉")

                                else:
                                    session_valid = False
                                    print(f"🚫 [API ERROR] Erreur HTTP ➜ Code {response.status_code}")
                            except Exception as e:
                                session_valid = False
                                print(f"💥 [API EXCEPTION] Erreur lors de l'appel API : {str(e)}")
                        else:
                            session_valid = False
                            print(f"⏱️ [SESSION] Session expirée (⏳ date: `{date_str}`)")
                    except ValueError as e:
                        session_valid = False
                        print(f"❌ [DATE ERROR] Format de date invalide : {e}")
                else:
                    session_valid = False
                    print("⚠️ [FORMAT] Format de session invalide (manque `username::date::entity`)")
            else:
                session_valid = False
                print("🕳️ [SESSION] Fichier de session vide.")
        except Exception as e:
            session_valid = False
            print(f"💣 [SESSION ERROR] Erreur inattendue : {str(e)}")




    app = QApplication(sys.argv)


    icon_path = os.path.join(SCRIPT_DIR, "icons", "logo.jpg")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    if session_valid:
        try:
            json_path = os.path.join(SCRIPT_DIR, '..', "Tools", "action.json")
            with open(json_path, "r", encoding='utf-8') as file:
                json_data = json.load(file)

            if json_data:
                window = MainWindow(json_data)
                window.setFixedSize(1710, 1005)
                screen = QGuiApplication.primaryScreen()
                screen_geometry = screen.availableGeometry()
                x = (screen_geometry.width() - window.width()) // 2
                y = (screen_geometry.height() - window.height()) // 2
                window.move(x, y)
                window.stopButton.clicked.connect(lambda: stop_all_processes(window))
                window.setWindowTitle("AutoMailPro")
                window.show()
            else:
                raise ValueError("Fichier de configuration vide")
        except Exception as e:
            print(f"[CONFIG ERROR] {e}")
            window = LoginWindow()
            window.setFixedSize(1710, 1005)
            screen = QGuiApplication.primaryScreen()
            screen_geometry = screen.availableGeometry()
            x = (screen_geometry.width() - window.width()) // 2
            y = (screen_geometry.height() - window.height()) // 2
            window.move(x, y)
            window.show()
    else:
        window = LoginWindow()
        window.setFixedSize(1710, 1005)
        screen = QGuiApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()
        x = (screen_geometry.width() - window.width()) // 2
        y = (screen_geometry.height() - window.height()) // 2
        window.move(x, y)
        window.show()

    sys.exit(app.exec())








if __name__ == "__main__":
    main()
