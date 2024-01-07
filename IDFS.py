#!/usr/bin/python
# -*- encoding: latin-1 -*-
from pathlib import Path
import os
import subprocess
import logging
import bcrypt  # Module pour le chiffrement des mots de passe
import argparse
import shutil

# Obtenir le répertoire du script en cours
script_directory = Path(__file__).resolve().parent

# Créer le répertoire racine IDFS s'il n'existe pas
main_directory = script_directory / 'IDFS'
if not main_directory.exists():
    main_directory.mkdir()
# Créer le répertoire bin
bin_directory = main_directory / 'bin'
if not bin_directory.exists():
    bin_directory.mkdir()

# Créer le répertoire etc
etc_directory = main_directory / 'etc'
if not etc_directory.exists():
    etc_directory.mkdir()

# Créer les fichiers shadow, group, passwd et metadata dans le répertoire etc
etc_files = ['shadow', 'group', 'passwd']
for filename in etc_files:
    file_path = etc_directory / filename
    if not file_path.exists():
        file_path.touch()
       

# Initialiser root dans le fichier etc/passwd
passwd_path = etc_directory / 'passwd'
with open(passwd_path, 'a') as passwd_file:
    # Remplacez ces valeurs par celles que vous souhaitez utiliser pour root
    username = 'root'
    uid = 0
    gid = 0
    home_dir = '/root'
    shell = '/bin/bash'
    passwd_file.write(f"{username}:x:{uid}:{gid}::{home_dir}:{shell}\n")

# Initialiser root dans le fichier etc/group
group_path = etc_directory / 'group'
with open(group_path, 'a') as group_file:
    # Remplacez ces valeurs par celles que vous souhaitez utiliser pour root
    groupname = 'root'
    gid = 0
    group_file.write(f"{groupname}:x:{gid}:\n")

# Initialiser root dans le fichier etc/shadow
shadow_path = etc_directory / 'shadow'
with open(shadow_path, 'a') as shadow_file:
    # Remplacez 'your_password' par le mot de passe souhaité pour root
    encrypted_password = bcrypt.hashpw('your_password'.encode('utf-8'), bcrypt.gensalt())
    shadow_file.write(f"root:{encrypted_password}:18400:0:99999:7:::\n")

# Créer le répertoire var
var_directory = main_directory / 'var'
if not var_directory.exists():
    var_directory.mkdir()
    

# Créer le répertoire log avec le fichier logfile.log à l'intérieur
log_directory = var_directory / 'log'
logfile_path = log_directory / 'logfile.log'

if not log_directory.exists():
    log_directory.mkdir(parents=True)

if not logfile_path.exists():
    logfile_path.touch()

# Créer le répertoire home
home_directory = main_directory / 'home'
if not home_directory.exists():
    home_directory.mkdir()
bin_directory.chmod(0o755)  # Définir les permissions à rwxr-xr-x (755)



# Scripts des commandes avec leurs noms respectifs
command_scripts = [
    {"name": "adresse",
     "content": """#!/usr/bin/env python3
import subprocess

def adresse():
    try:
        result = subprocess.run(["ip", "addr"], capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Une erreur s'est produite : {e}")

if __name__ == "__main__":
    adresse()
"""},
    {"name": "calw",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-     
import argparse
import logging

def wc(file_path, option):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
        lines = content.count('/n')
        words = len(content.split())
        bytes_count = len(content.encode('utf-8'))
        characters = len(content)

        if option == '-l':
            logging.info(f"Number of lines: {lines}".encode('utf-8'))
        elif option == '-m':
            logging.info(f"Number of words: {words}".encode('utf-8'))
        elif option == '-c':
            logging.info(f"Number of characters: {characters}".encode('utf-8'))
        elif option == '-b':
            logging.info(f"Number of bytes: {bytes_count}".encode('utf-8'))
        else:
            logging.warning("Unknown option")

def main():
    logging.basicConfig(filename='/home/IDFS/var/log/logfile.log', level=logging.INFO, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    parser = argparse.ArgumentParser(description='Emettre la commande wc en Python')
    parser.add_argument('file_path', metavar='FILE', type=str, help='Path to the file to count')
    parser.add_argument('-l', action='store_const', const='-l', dest='option', help='Display the number of lines.')
    parser.add_argument('-m', action='store_const', const='-m', dest='option', help='Display the number of words.')
    parser.add_argument('-c', action='store_const', const='-c', dest='option', help='Display the number of characters.')
    parser.add_argument('-b', action='store_const', const='-b', dest='option', help='Display the number of bytes')
    args = parser.parse_args()

    wc(args.file_path, args.option)

if __name__ == "__main__":
    main()

"""},
    {"name": "clean",
     "content": """#!/usr/bin/env python3 
# -*- coding: utf-8 -*-
import os
import subprocess
import logging

def clean():
    try:
        # Obtenir le chemin du repertoire log
        base_directory = "/home/IDFS/var"
        log_directory = os.path.join(base_directory, "log")
        log_file = log_directory / "logfile.log"
        os.makedirs(log_directory, exist_ok=True)

        # Configuration du logging
        logging.basicConfig(filename=log_file, level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        # Effacer le terminal
        os.system('clear')  # Utilisez 'cls' a la place de 'clear' sur Windows

        # Enregistrez le nettoyage dans le fichier de logs
        logging.info("Terminal nettoye avec succes.".encode('utf-8'))

    except Exception as e:
        print(f"Une erreur inattendue s'est produite : {e}")
        logging.error(f"Erreur inattendue : {e}".encode('utf-8'))

if __name__ == "__main__":
    clean()
"""},
    {"name": "copy",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-          
import shutil
import os
import argparse
import logging

def copier_fichier(source, destination):
    try:
        shutil.copy(source, destination)
        logging.info(f"Fichier {source} copie avec succes vers {destination}".encode('utf-8'))
    except FileNotFoundError:
        logging.error(f"Erreur : le fichier {source} n\'existe pas.".encode('utf-8'))
    except PermissionError:
        logging.error(f"Erreur : vous n\'avez pas la permission de copier le fichier {source}.".encode('utf-8'))
    except Exception as e:
        logging.error(f"Erreur inattendue : {e}".encode('utf-8'))

def main():
    # Configuration du logging
    logging.basicConfig(filename='/home/IDFS/var/log/logfile.log',level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description='Emuler la commande cp en Python.')
    parser.add_argument('source', help='Chemin du fichier source.')
    parser.add_argument('destination', help='Chemin de la destination.')
    args = parser.parse_args()

    copier_fichier(args.source, args.destination)

if __name__ == '__main__':
    main()
"""},
    {"name": "ctop",
     "content": """#!/usr/bin/python3
import subprocess
import logging

# Configuration du système de logging
log_file_path = '/home/IDFS/var/log/logfile.log'
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def run_top():
    try:
        subprocess.run(['top', '-bn', '1'])
    except Exception as e:
        logging.error(f"Une erreur s'est produite : {e}".encode('utf-8'))

if __name__ == "__main__":
    run_top()
"""},
    {"name": "cwd",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-     
import os
import logging

def configure_logging():
    # Configurer le logging
    base_directory = "/home/IDFS/var"
    log_directory = os.path.join(base_directory, "log")
    log_file = log_directory / "logfile.log"
    os.makedirs(log_directory, exist_ok=True)

    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def cwd():
    try:
        # Obtenir le repertoire de travail actuel
        current_working_directory = os.getcwd()

        # Afficher le repertoire de travail actuel
        print(current_working_directory)

        # Enregistrer le répertoire de travail actuel dans le fichier de logs
        logging.info(f"Repertoire de travail actuel : {current_working_directory}".encode('utf-8'))

    except Exception as e:
        # Gérer les erreurs et les enregistrer dans le fichier de logs
        print(f"Une erreur s'est produite : {e}")
        logging.error(f"Erreur lors de l'obtention du repertoire de travail actuel : {e}".encode('utf-8'))

if __name__ == "__main__":
    configure_logging()
    cwd()
"""},
    {"name": "dcache",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-          
import os
import sys
import stat
import datetime
import logging
import getpass

logfile_path = "/home/IDFS/var/log/logfile.log"

logging.basicConfig(filename=logfile_path, level=logging.DEBUG, format="%(user)s | %(levelname)s | %(asctime)s | %(message)s")
user = getpass.getuser()
logger = logging.getLogger(__name__)
logger = logging.LoggerAdapter(logger, {"user": user})

def fct_l(directory='.', long_format=False):
    try:
        files = os.listdir(directory)
        for file in files:
            file_path = os.path.join(directory, file)
            if long_format:
                file_info = os.stat(file_path)
                mode = stat.filemode(file_info.st_mode)
                size = file_info.st_size
                mtime = datetime.datetime.fromtimestamp(file_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                print(f"{mode} {size:8} {mtime} {file}")
                logger.info("Affichage des informations du contenu du repertoire actuel")
            else:
                print(file)
                logger.info("Ce n'est pas un repertoire")
    except FileNotFoundError:
        print(f"Le repertoire '{directory}' n'a pas ete trouve.")
        logger.error("Le repertoire n'existe pas")
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")
        logger.error("Erreur")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        fct_l()
        logger.info("Affichage du contenu du repertoire actuel")


"""},{"name":"ignite",
"content":"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-     
import os
import sys
from pathlib import Path
from datetime import datetime
import json
import getpass
import logging

# Emplacement du fichier simulé IDFS/var/log/file.log (chemin relatif)
log_file_path = '/home/IDFS/var/log/logfile.log'

# Configuration du logging
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def create_file(file_path):
    try:
        # Get the current username
        username = getpass.getuser()

        # Check if the current user is root
        is_root = os.geteuid() == 0

        if is_root:
            # If root creates a file, use "root" as the username
            username = "root"

            # Create the home directory for root in /home (absolute path)
            root_home_directory = f'/home/IDFS/home/{username}'
            Path(root_home_directory).mkdir(parents=True, exist_ok=True)

        # User's home directory path in IDFS (absolute path)
        base_directory = f'/home/IDFS/home/{username}'

        file_path = Path(os.path.join(base_directory, file_path))

        # Check if the file already exists
        if file_path.is_file():
            message = f"Failure: The file '{file_path}' already exists."
            logging.warning(message.encode('utf-8'))
            print(message)
        else:
            file_path.touch()
            message = f"File created successfully: {file_path}"
            logging.info(message.encode('utf-8'))
            print(message)

            # Record metadata after file creation
            update_metadata(file_path, username)

    except Exception as e:
        message = f"Error creating the file: {str(e)}"
        logging.error(message.encode('utf-8'))
        print(message)

def update_metadata(filename, username):
    try:
        # Retrieve file information
        stat_info = os.stat(filename)

        # Convert the creation date timestamp to a readable format
        creation_date = datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')

        # Convert the last modification date timestamp to a readable format
        modification_date = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

        # Create a metadata dictionary
        metadata = {
            "File Name": str(filename),
            "Creation Date": creation_date,
            "Modification Date": modification_date,
            "File Size": stat_info.st_size,
            "Permissions": oct(stat_info.st_mode)[-3:],  # Octal format
        }

        # Metadata file path
        output_file = f'/home/IDFS/etc/metadata_{username}'

        # Check if the metadata file exists
        if not Path(output_file).is_file():
            # If it doesn't exist, create the file and add the new metadata
            with open(output_file, "w") as f:
                f.write(json.dumps([metadata], indent=2))
            print(f"Metadata file created at {output_file}")
        else:
            # If it exists, read the existing metadata
            with open(output_file, "r") as f:
                try:
                    existing_metadata = json.load(f)
                except json.JSONDecodeError:
                    existing_metadata = []

            # Add the new metadata to the existing list
            existing_metadata.append(metadata)

            # Write the updated list to the file
            with open(output_file, "w") as f:
                f.write(json.dumps(existing_metadata, indent=2))

            print(f"Metadata added to {output_file}")

    except FileNotFoundError:
        message = f"The file '{filename}' does not exist."
        logging.error(message.encode('utf-8'))
        print(message)
    except Exception as e:
        message = f"An error occurred: {e}"
        logging.error(message.encode('utf-8'))
        print(message)

# Usage of the file command
if len(sys.argv) != 2:
    message = f"Usage: python script.py <file_path>"
    logging.error(message.encode('utf-8'))
    print(message)
else:
    username=getpass.getuser()
    file_path = sys.argv[1]
    create_file(file_path)
    update_metadata(file_path,{username})
   """},{"name": "ddetail",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import stat
import datetime
import pwd
import grp
import logging

def list_detailed_content(directory='.'):
    try:
        # Get the list of files and directories in the specified directory
        content = os.listdir(directory)

        # Display details for each item
        for element in content:
            full_path = os.path.join(directory, element)
            stat_info = os.stat(full_path)

            # Convert timestamp to readable format
            last_modified_date = datetime.datetime.fromtimestamp(stat_info.st_mtime)

            # Get the username and group name
            owner = pwd.getpwuid(stat_info.st_uid).pw_name
            group = grp.getgrgid(stat_info.st_gid).gr_name

            # Display permissions as a string
            permissions = stat.filemode(stat_info.st_mode)

            # Display detailed information to the console
            print(f"{permissions}\t{stat_info.st_nlink}\t{owner}\t{group}\t{stat_info.st_size}\t{last_modified_date}\t{element}")
    except Exception as e:
        logging.error(f'Unexpected error: {e}'.encode('utf-8'))

def main():
    # Use the function to list detailed content of the current directory
    list_detailed_content()

if __name__ == '__main__':
    main()
"""},{"name": "deld",
     "content": """#!/usr/bin/env python3
# -*- encoding: latin-1 -*-         
import os
import sys
import getpass
import logging

# Configuration du système de logging
log_file_path = '/home/IDFS/var/log/logfile.log'
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_current_username():
    try:
        return getpass.getuser()
    except Exception as e:
        logging.error("Impossible d'obtenir le nom d'utilisateur : %s", e)
        sys.exit(1)

def remove_directory(directory_name):
    try:
        # Obtenir le nom d'utilisateur actuel
        username = get_current_username()
        user_home_dir = f"/home/IDFS/home/{username}"

        # Si l'utilisateur actuel n'est pas root, vérifier les droits de l'utilisateur
        if username != 'root':
            if not os.path.samefile(user_home_dir, '/home/IDFS/home/root'):
                raise PermissionError(f"Permission refusée. Assurez-vous d'avoir les droits nécessaires pour supprimer le dossier {directory_name}.")

        # Construire le chemin complet du dossier à supprimer
        directory_path = os.path.join(user_home_dir, directory_name)

        # Vérifier si le dossier existe avant de le supprimer
        if os.path.exists(directory_path):
            # Supprimer le dossier
            os.rmdir(directory_path)
            print(f"Le dossier {directory_name} a été supprimé du répertoire personnel de l'utilisateur {username}.")
        else:
            print(f"Le dossier {directory_name} n'existe pas.")
    except Exception as e:
        logging.error("Erreur lors de la suppression du dossier : %s", e)

# Exemple d'utilisation
if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.error("Usage: supprimer_dossier <nom_dossier>")
        sys.exit(1)

    directory_to_remove = sys.argv[1]
    remove_directory(directory_to_remove)

"""},{"name": "delgr",
     "content":"""#!/usr/bin/env python3
import os
import logging

def galaxygdel():
    try:
        # Configuration du logging
        logging.basicConfig(filename='/home/IDFS/var/log/logfile.log',level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')

        # Vérifier si l'utilisateur actuel est root
        if os.geteuid() != 0:
            logging.warning("Permission denied. Vous devez exécuter ce script en tant que superutilisateur (root).")
            return

        # Saisie du nom du groupe à supprimer
        groupname = input("Entrez le nom du groupe à supprimer : ")

        # Emplacement du fichier simulé ID1FS/etc/group (chemin absolu)
        group_file_path = '/home/IDFS/etc/group'

        # Vérifier si le groupe existe
        with open(group_file_path, 'r') as group_file:
            existing_groups = [line.split(':')[0] for line in group_file.readlines()]

        if groupname not in existing_groups:
            logging.warning(f"Le groupe {groupname} n'existe pas.")
            return

        # Supprimer l'entrée dans le fichier simulé ID1FS/etc/group
        with open(group_file_path, 'w') as group_file:
            # Réécrire le fichier sans le groupe à supprimer
            for line in existing_groups:
                if line != groupname:
                    group_file.write(f"{line}\n")

        logging.info(f"Le groupe {groupname} a été supprimé avec succès.")
    except Exception as e:
        logging.error(f"Erreur lors de la suppression du groupe {groupname} : {e}")

# Utilisation de la fonction
galaxygdel()
"""},{"name": "delus",
     "content":"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import shutil
import logging
import sys
import pwd
import grp
from datetime import datetime

# Emplacement du fichier simulé IDFS/var/log/logfile.log (chemin absolu)
log_file_path = '/home/IDFS/var/log/logfile.log'

# Configuration du logging
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def delus(username):
    try:
        print(f"Suppression de l'utilisateur {username} en cours...")

        # Vérifier si l'utilisateur actuel est root
        if os.geteuid() != 0:
            message = "Permission denied. Vous devez executer ce script en tant que superutilisateur (root)."
            logging.error(message.encode('utf-8'))
            print(message)
            return

        # Emplacement du répertoire home dans IDFS (chemin absolu)
        idfs_home_dir = '/home/IDFS/home'

        # Chemins absolus des fichiers simulés IDFS/etc/passwd, IDFS/etc/shadow et IDFS/etc/group
        passwd_file_path = '/home/IDFS/etc/passwd'
        shadow_file_path = '/home/IDFS/etc/shadow'
        group_file_path = '/home/IDFS/etc/group'

        # Récupérer les informations de l'utilisateur et du groupe
        user_info = pwd.getpwnam(username)
        group_info = grp.getgrgid(user_info.pw_gid)

        # Lire les lignes des fichiers passwd, shadow, et group
        with open(passwd_file_path, 'r') as passwd_file, \
             open(shadow_file_path, 'r') as shadow_file, \
             open(group_file_path, 'r') as group_file:
            passwd_lines = passwd_file.readlines()
            shadow_lines = shadow_file.readlines()
            group_lines = group_file.readlines()

        # Filtrer les lignes pour exclure l'utilisateur à supprimer
        new_passwd_lines = [line for line in passwd_lines if not line.startswith(f"{username}:")]
        new_shadow_lines = [line for line in shadow_lines if not line.startswith(f"{username}:")]
        new_group_lines = [line for line in group_lines if not line.startswith(f"{username}:")]

        # Écrire les nouvelles lignes dans les fichiers passwd, shadow, et group
        with open(passwd_file_path, 'w') as passwd_file, \
             open(shadow_file_path, 'w') as shadow_file, \
             open(group_file_path, 'w') as group_file:
            passwd_file.writelines(new_passwd_lines)
            shadow_file.writelines(new_shadow_lines)
            group_file.writelines(new_group_lines)

        # Supprimer le répertoire personnel de l'utilisateur
        user_home_dir = os.path.join(idfs_home_dir, username)
        shutil.rmtree(user_home_dir)

        message = f"L'utilisateur {username} a ete supprime avec succes du fichier shadow, group et du repertoire personnel."
        logging.info(message.encode('utf-8'))
        print(message)

    except Exception as e:
        message = f"Erreur lors de l'ecriture dans les fichiers ou suppression du repertoire personnel : {e}"
        logging.error(message.encode('utf-8'))
        print(message)

# Vérifier si l'argument est spécifié et est égal à "delus"
if len(sys.argv) > 1 and sys.argv[1] == "delus":
    if len(sys.argv) > 2:
        username = sys.argv[2]
        delus(username)
    else:
        message = "Veuillez specifier le nom d'utilisateur a supprimer."
        logging.error(message.encode('utf-8'))
        print(message)
 """},
{"name": "dis",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-          
import os
import logging

def lister_fichiers_non_caches(repertoire='.'):
    try:
        # Configuration du logging
        logging.basicConfig(filename='/home/IDFS/var/log/logfile.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

        # Récupérer la liste des fichiers et répertoires dans le répertoire spécifié
        contenu = os.listdir(repertoire)

        # Afficher uniquement les fichiers non cachés
        for element in contenu:
            chemin_complet = os.path.join(repertoire, element)
            if os.path.isfile(chemin_complet) and not element.startswith('.'):
                logging.info(element.encode('utf-8'))

    except Exception as e:
        logging.error(f'Erreur inattendue : {e}'.encode('utf-8'))

def main():
    # Utiliser la fonction pour lister les fichiers non cachés du repertoire actuel
    lister_fichiers_non_caches()

if __name__ == '__main__':
    main()

"""},{"name": "eliminate",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-          
import os
import signal
import argparse
import logging

def tuer_processus(pid, signal_num=signal.SIGTERM):
    try:
        # Configuration du logging
        logging.basicConfig(filename='/home/IDFS/var/log/logfile.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        os.kill(pid, signal_num)
        logging.info(f"Signal {signal_num} envoye au processus {pid}.".encode('utf-8'))
    except ProcessLookupError:
        logging.error(f"Erreur : le processus {pid} n'existe pas.".encode('utf-8'))
    except PermissionError:
        logging.error(f"Erreur : vous n'avez pas la permission de tuer le processus {pid}.".encode('utf-8'))
    except Exception as e:
        logging.error(f"Erreur inattendue : {e}".encode('utf-8'))

def main():
    parser = argparse.ArgumentParser(description='Emuler la commande kill en Python.')
    parser.add_argument('pid', type=int, help='ID du processus a tuer.')
    parser.add_argument('--signal', type=int, default=signal.SIGTERM, help='Numero du signal (par defaut: SIGTERM).')
    args = parser.parse_args()

    tuer_processus(args.pid, args.signal)

if __name__ == '__main__':
    main()

"""},{"name": "fmask",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-          
import os
import sys
import logging

def configure_logging():
    # Configurer le logging
    base_directory = "/home/IDFS/var"
    log_directory = os.path.join(base_directory, "log")
    log_file = log_directory / "logfile.log"
    os.makedirs(log_directory, exist_ok=True)

    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def fmask(new_mask=None):
    try:
        if new_mask is not None:
            # Convertir le nouveau masque en octal
            new_mask = int(new_mask, 8)
            os.umask(new_mask)
            logging.info(f"Le masque de creation de fichiers a ete temporairement mis a jour : {new_mask:o}".encode('utf-8'))
            print(f"Le masque de creation de fichiers a ete temporairement mis a jour : {new_mask:o}")
        else:
            current_mask = os.umask(0)  # Obtient le masque actuel sans le modifier
            os.umask(current_mask)     # Rétablit le masque à sa valeur initiale
            logging.info(f"Le masque de creation de fichiers actuel est : {current_mask:o}".encode('utf-8'))
            print(f"Le masque de creation de fichiers actuel est : {current_mask:o}")
    except ValueError:
        error_message = f"Veuillez specifier un masque valide en octal."
        logging.error(error_message.encode('utf-8'))
        print(error_message)

if __name__ == "__main__":
    configure_logging()

    if len(sys.argv) == 2:
        fmask(sys.argv[1])
    else:
        fmask()

"""},{"name": "galaxyautg",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-          
import os
import logging

# Emplacement du fichier simulé IDFS/var/log/logfile.log (chemin relatif)
log_file_path = '/home/IDFS/var/log/logfile.log'

# Configuration du logging
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def galaxyautg():
    try:
        # Vérifier si l'utilisateur actuel est root
        if os.geteuid() != 0:
            logging.error(f"Permission denied. Vous devez executer ce script en tant que superutilisateur (root).".encode('utf-8'))
            return

        # Saisie du nom d'utilisateur
        username = input("Entrez le nom d'utilisateur : ")

        # Saisie du nom du groupe
        groupname = input("Entrez le nom du groupe : ")

        # Emplacement du fichier simulé IDFS/etc/group (chemin relatif)
        group_file_path = '/home/IDFS/etc/group'

        # Vérifier si le groupe existe
        with open(group_file_path, 'r') as group_file:
            existing_groups = [line.strip() for line in group_file.readlines()]

        # Vérifier si le groupe existe
        group_found = False
        for i, line in enumerate(existing_groups):
            parts = line.split(':')
            if parts[0] == groupname:
                group_found = True
                parts[3] += f',{username}'  # Ajouter l'utilisateur à la fin de la liste
                existing_groups[i] = ':'.join(parts)  # Mettre à jour la ligne dans la liste

        if not group_found:
            logging.warning(f"Le groupe {groupname} n'existe pas.".encode('utf-8'))
            return

        # Réécrire le fichier simulé ID1FS/etc/group avec les modifications
        with open(group_file_path, 'w') as group_file:
             group_file.write(' '.join(existing_groups) + ' ')

        logging.info(f"L'utilisateur {username} a ete ajoute au groupe {groupname} avec succes.".encode('utf-8'))

    except Exception as e:
        logging.exception(f"Une erreur inattendue s'est produite : {e}".encode('utf-8'))

# Utilisation de la fonction
galaxyautg()

"""},{"name": "galaxycat",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-          
import sys
import logging
from pathlib import Path

def configure_logging():
    # Configurer le logging
    base_directory = "/home/IDFS/var"
    log_directory = Path(base_directory) / "log"
    log_file = log_directory / "logfile.log"
    log_directory.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def galaxycat(chemin):
    try:
        chemin_fichier = Path(chemin).resolve()
        # V�rifier si le fichier existe
        if not chemin_fichier.is_file():
            error_message = f"Echec : Le fichier '{chemin_fichier}' n'existe pas."
            print(error_message)
            logging.error(error_message)
        else:
            # Lire et afficher le contenu du fichier
            with open(chemin_fichier, 'r') as fichier:
                content = fichier.read()
                print(content)
                logging.info(f"Contenu du fichier '{chemin_fichier}': {content}")

    except FileNotFoundError as e:
        error_message = f"Echec : Le fichier '{chemin}' n'a pas �t� trouv� : {str(e)}"
        print(error_message)
        logging.error(error_message)
    except Exception as e:
        error_message = f"Erreur lors de la lecture du fichier '{chemin}' : {str(e)}"
        print(error_message)
        logging.error(error_message)

if __name__ == "__main__":
    configure_logging()

    # Utilisation de la commande content
    if len(sys.argv) != 2:
        print("Usage: python script.py <chemin_du_fichier>")
    else:
        chemin_fichier = sys.argv[1]
        galaxycat(chemin_fichier)
        

"""},{"name": "galaxyfy",
     "content": """#!/usr/bin/env python3
# -- coding: utf-8 --          
import os
import sys
import json
import getpass
import logging
from datetime import datetime
import shutil

# Configuration du système de logging
log_file_path = '/home/IDFS/var/log/logfile.log'  # Correction du chemin du fichier journal
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_current_username():
    try:
        return getpass.getuser()
    except Exception as e:
        logging.error("Impossible d'obtenir le nom d'utilisateur : %s", e)
        sys.exit(1)

def create_directory(directory_name):
    try:
        # Obtenir le nom d'utilisateur actuel
        username = get_current_username()
        user_home_dir = f"/home/IDFS/home/{username}"

        # Si l'utilisateur actuel n'est pas root, vérifier les droits de l'utilisateur
        if username == 'root':
            if not os.path.samefile(user_home_dir, '/home/IDFS/home/root'):
                raise PermissionError(f"Permission refusée. Assurez-vous d'avoir les droits nécessaires pour créer un dossier dans {user_home_dir}.")

        # Construire le chemin complet du nouveau dossier
        new_directory_path = os.path.join(user_home_dir, directory_name)

        # Créer le dossier
        os.makedirs(new_directory_path, exist_ok=True)  # Ajout de exist_ok pour éviter une erreur si le dossier existe déjà
        print(f"Le dossier {directory_name} a été créé dans le répertoire personnel de l'utilisateur {username}.")
    except Exception as e:
        logging.error("Erreur lors de la création du dossier : %s", e)

# Exemple d'utilisation
if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.error("Usage: creer_dossier <nom_dossier>")  # Suppression de encode('utf-8')
        sys.exit(1)

    new_directory_name = sys.argv[1]
    create_directory(new_directory_name)

"""},{"name": "galaxygadd",
     "content": """#!/usr/bin/env python3
import os
import logging

def galaxygadd():
    # Configurer le logging
    log_directory = '/home/IDFS/var/log'  # Assurez-vous que le répertoire existe et a les permissions nécessaires
    log_file_path = os.path.join(log_directory, 'logfile.log')

    # Créer le répertoire s'il n'existe pas
    os.makedirs(log_directory, exist_ok=True)

    logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Vérifier si l'utilisateur actuel est root
    if os.geteuid() != 0:
        logging.error("Permission denied. Vous devez exécuter ce script en tant que superutilisateur (root).")
        return

    # Saisie du nom du groupe
    groupname = input("Entrez le nom du groupe : ")

    # Emplacement du fichier simulé ID1FS/etc/group (chemin absolu)
    group_file_path = '/home/IDFS/etc/group'

    # Vérifier si le groupe existe déjà
    with open(group_file_path, 'r') as group_file:
        existing_groupnames = [line.split(':')[0] for line in group_file.readlines()]

    if groupname in existing_groupnames:
        logging.warning(f"Le groupe {groupname} existe déjà.")
        return

    # Ajouter l'entrée dans le fichier simulé ID1FS/etc/group
    try:
        gid = len(existing_groupnames) + 1000  # Générer un GID unique (à adapter selon les besoins)

        group_entry = f"{groupname}:x:{gid}:\n"
        with open(group_file_path, 'a') as group_file:
            group_file.write(group_entry)

        logging.info(f"Le groupe {groupname} a été ajouté avec succès.")
    except Exception as e:
        logging.error(f"Erreur lors de l'ajout du groupe {groupname} : {e}")

# Utilisation de la fonction
galaxygadd()
"""},{"name": "galaxyown",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-          
import os
import sys
import pwd
import logging

def nchow(path, owner):
    try:
        # Obtenir le chemin du répertoire log
        base_directory = "/home/IDFS/var"
        log_directory = os.path.join(base_directory, "log")
        log_file = os.path.join(log_directory, "logfile.log")
        os.makedirs(log_directory, exist_ok=True)

        # Configuration du logging
        logging.basicConfig(filename=log_file, level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        # Correction de la ligne pour changer le propriétaire
        os.chown(path, -1, pwd.getpwnam(owner).pw_uid)
        logging.info(f"Changement de proprietaire de {path} a {owner} effectue avec succes.".encode('utf-8'))
        print(f"Changement de proprietaire de {path} a {owner} effectue avec succes.")

    except FileNotFoundError:
        error_message = f"Le fichier ou dossier {path} n'existe pas."
        logging.error(error_message.encode('utf-8'))
        print(error_message)

    except PermissionError:
        error_message = f"Permission refusee pour changer le proprietaire de {path}. Veuillez executer en tant qu'administrateur."
        logging.error(error_message.encode('utf-8'))
        print(error_message)

    except Exception as e:
        error_message = f"Une erreur s'est produite : {e}"
        logging.error(error_message.encode('utf-8'))
        print(error_message)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: nchow <chemin> <nouveau_proprietaire>")
        sys.exit(1)

    chemin = sys.argv[1]
    nouveau_proprietaire = sys.argv[2]

    nchow(chemin, nouveau_proprietaire)
"""},{"name": "galaxyscan",
     "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-          
import sys
import os
import logging

def more(file_path):
    # Configurer le logging
    log_directory = '/home/IDFS/var'  # Assurez-vous que le répertoire existe et a les permissions nécessaires
    log_file_path = os.path.join(log_directory, 'log', 'logfile.log')

    # Créer le répertoire s'il n'existe pas
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

    logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            page_size = 10
            current_line = 0

            while current_line < len(lines):
                for line in lines[current_line:current_line + page_size]:
                    print(line, end='')

                user_input = input("Press Enter for more, q to quit: ")
                if user_input.lower() == 'q':
                    break

                current_line += page_size

    except FileNotFoundError:
        logging.error(f"Le fichier '{file_path}' n'existe pas.".encode('utf-8'))
    except Exception as e:
        logging.error(f"Une erreur s'est produite : {e}")

if __name__== "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <nom_fichier>")
    else:
        file_path = sys.argv[1]
        more(file_path)
"""},{"name": "ginp",
 "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*- 
import subprocess
import sys
import os
import logging

def ginp(hostname):
    log_path = '/home/IDFS/var/log/logfile.log'
    logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(message)s')
    
    try:
        result = subprocess.run(["ping", "-c", "4", hostname], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Enregistrement dans le fichier journal
        logging.info(f"Ping result for {hostname}:{result.stdout}".encode('utf-8'))

        # Affichage dans la console
        print(f"Ping result for {hostname}:{result.stdout}")

    except subprocess.CalledProcessError as e:
        # Enregistrement dans le fichier journal en cas d'erreur
        logging.error(f"Ping result for {hostname}: {result.stdout}".encode('utf-8'))
        logging.error(f"Error output: {e.stderr}".encode('utf-8'))

        # Affichage dans la console en cas d'erreur
        print(f"Ping result for {hostname}: {result.stdout}")
        print(f"Error output: {e.stderr}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Utilisation : ginp <hostname>")
        sys.exit(1)

    hostname = sys.argv[1]
    ginp(hostname)

"""},{"name":"upper",
 "content" :"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import logging
from pathlib import Path

def head(file_path, num_lines=None, num_chars=None):
    try:
       

        # Chemin du fichier de logs (chemin relatif)
        log_file_path = 'IDFS/var/log/logfile.log'

        # Configuration du logging
        logging.basicConfig(filename=log_file_path, level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        # Chemin du fichier à ouvrir (chemin relatif)
        file_path = file_path

        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()

            if num_chars:
                logging.info(f"Affichage des premiers {num_chars} caracteres du fichier {file_path}.".encode('utf-8'))
                print(content[:num_chars])
            elif num_lines:
                lines = content.splitlines()[:num_lines]
                logging.info(f"Affichage des premieres {num_lines} lignes du fichier {file_path}.".encode('utf-8'))
                print(' '.join(lines))
            else:
                logging.info(f"Affichage du contenu complet du fichier {file_path}.".encode('utf-8'))
                print(content.upper())

    except Exception as e:
        logging.error(f"Erreur inattendue : {e}".encode('utf-8'))

def main():
    parser = argparse.ArgumentParser(description='Imiter la commande head en Python.')
    parser.add_argument('file_path', metavar='FICHIER', type=str, help='Chemin du fichier a afficher.')
    parser.add_argument('-n', '--lines', metavar='NOMBRE', type=int, default=None, help='Nombre de lignes a afficher.')
    parser.add_argument('-c', '--chars', metavar='NOMBRE', type=int, default=None, help='Nombre de caracteres a afficher.')
    args = parser.parse_args()

    head(args.file_path, args.lines, args.chars)

if __name__ == "__main__":
    main()

"""},{"name":"utr",
"content":"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import logging
import os  # Ajout d'une importation manquante pour 'os'
from pathlib import Path  # Ajout d'une importation manquante pour 'Path'

def configure_logging():
    try:
        # Chemin du répertoire log (chemin relatif)
        log_directory = '/home/IDFS/var/log'

        # Chemin du fichier de logs (chemin relatif)
        log_file = log_directory / "logfile.log"


        # Créer le répertoire log s'il n'existe pas
        Path(log_directory).mkdir(parents=True, exist_ok=True)

        # Configuration du logging
        logging.basicConfig(filename=os.path.join(log_directory, log_file), level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')
    except Exception as e:
        print(f"Une erreur s'est produite lors de la configuration du logging : {e}")
        logging.error(f"Erreur lors de la configuration du logging : {e}")  # Ajout d'une entrée de log en cas d'erreur

def utr():
    try:
        # Utiliser subprocess pour changer à l'utilisateur root
        subprocess.check_call(["sudo", "su"])
        success_message = "Changement a l'utilisateur root effectue avec succes."
        print(success_message)
        logging.info(success_message.encode('utf-8'))
    except subprocess.CalledProcessError:
        error_message = "Impossible de changer a l'utilisateur root."
        print(error_message)
        logging.error(error_message.encode('utf-8'))

if __name__ == "__main__":  # Correction de la condition pour le bloc principal
    configure_logging()
    utr()

"""},{"name":"ufs",
"content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-     
import subprocess
import sys
import logging
from pathlib import Path

def configure_logging():
    try:
        # Chemin du r�pertoire log (chemin absolu)
        log_directory = '/home/IDFS/var/log'
        log_file_path = log_directory / "logfile.log"

        # Cr�er le r�pertoire log s'il n'existe pas
        log_directory.mkdir(parents=True, exist_ok=True)

        # Configuration du logging (correction du nom de la variable)
        logging.basicConfig(filename=log_file_path, level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')
    except Exception as e:
        print(f"Une erreur s'est produite lors de la configuration du logging : {e}")

def rfs():
    try:
        # Utiliser subprocess pour lancer une nouvelle coquille avec droits d'administration
        subprocess.check_call(["sudo", "su", "-"])
        success_message = f"Changement a l'utilisateur root effectue avec succes."
        print(success_message)
        logging.info(success_message.encode('utf-8'))
    except subprocess.CalledProcessError:
        error_message = f"Impossible de changer a l'utilisateur root."
        print(error_message)
        logging.error(error_message.encode('utf-8'))

if __name__ == "__main__":
    configure_logging()
    rfs()
"""},{"name":"trv",
"content":"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import sys
import logging
from pathlib import Path

def configure_logging():
    try:
        # Chemin du r�pertoire log (chemin absolu)
        log_directory = '/home/IDFS/var/log'
        log_file_path = log_directory / "logfile.log"

        # Cr�er le r�pertoire log s'il n'existe pas
        log_directory.mkdir(parents=True, exist_ok=True)

        # Configuration du logging
        logging.basicConfig(filename=log_file_path, level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')
    except Exception as e:
        print(f"Une erreur s'est produite lors de la configuration du logging : {e}")

def custom_grep(pattern, directory='.', recursive=False, line_numbers=False, whole_word=False, invert_match=False):
    try:
        flags = 0

        if whole_word:
            pattern = r'\b' + re.escape(pattern) + r'\b'

        if invert_match:
            flags |= re.IGNORECASE

        regex = re.compile(pattern, flags)

        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)

                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()

                        for i, line in enumerate(lines, start=1):
                            match = regex.search(line)
                            if (match and not invert_match) or (invert_match and not match):
                                if line_numbers:
                                    print(f"{file_path}:{i}:{line.strip()}")
                                    logging.info(f"{file_path}:{i}:{line.strip()}".encode('utf-8'))
                                else:
                                    print(f"{file_path}:{line.strip()}")
                                    logging.info(f"{file_path}:{line.strip()}".encode('utf-8'))

                except (OSError, UnicodeDecodeError):
                    # G�rer les exceptions lors de l'ouverture ou de la lecture des fichiers
                    error_message = f"Erreur lors de la lecture du fichier {file_path}."
                    print(error_message)
                    logging.error(error_message.encode('utf-8'))

    except Exception as e:
        error_message = f"Une erreur s'est produite : {e}"
        print(error_message)
        logging.error(error_message.encode('utf-8'))

if __name__ == "__main__":
    configure_logging()

    if len(sys.argv) < 2:
        error_message = "Usage: python script.py <pattern> [options]"
        print(error_message)
        logging.error(error_message.encode('utf-8'))
        sys.exit(1)

    pattern = sys.argv[1]
    options = sys.argv[2:]

    directory = '.'
    recursive = '-r' in options
    line_numbers = '-n' in options
    whole_word = '-w' in options
    invert_match = '-v' in options

    custom_grep(pattern, directory, recursive, line_numbers, whole_word, invert_match)

"""},{"name":"tat",
"content":"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tarfile
import os
import sys
import logging
from pathlib import Path

def configure_logging():
    try:
        # Chemin du répertoire log (chemin relatif)
        log_directory = '/home/IDFS/var/log'
        # Configuration du logging
        logging.basicConfig(filename=os.path.join(log_directory, 'logfile.log'), level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
    except Exception as e:
        print(f"Une erreur s'est produite lors de la configuration du logging : {e}")

def create_tar_archive(output_filename, files_to_archive):
    try:
        with tarfile.open(output_filename, 'w') as tar:
            for file in files_to_archive:
                tar.add(file)
        logging.info(f"Archive {output_filename} creee avec succes.")
    except Exception as e:
        logging.error(f"Une erreur s'est produite : {e}")

if __name__ == "__main__":
    configure_logging()

    if len(sys.argv) < 3:
        print("Utilisation : tat <nom_archive.tar> <fichier1> <fichier2> ...")
        logging.error("Nombre incorrect d'arguments passes.")
        sys.exit(1)

    archive_name = sys.argv[1]
    files_to_archive = sys.argv[2:]

    create_tar_archive(archive_name, files_to_archive)


 """},{"name":"tr",
 "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import logging
from pathlib import Path

def configure_logging():
    try:
        # Chemin du repertoire log (chemin absolu)
        log_directory = '/home/IDFS/var/log'
        log_file_path = log_directory / "logfile.log"

        # Creer le repertoire log s'il n'existe pas
        log_directory.mkdir(parents=True, exist_ok=True)

        # Configuration du logging
        logging.basicConfig(filename=log_file_path, level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')
    except Exception as e:
        error_message = f"Une erreur s'est produite lors de la configuration du logging : {e}"
        print(error_message)
        logging.error(error_message.encode('utf-8'))

def tr(directory, file_extension=None):
    try:
        # Utiliser os.walk pour parcourir la hierarchie de fichiers
        for root, dirs, files in os.walk(directory):
            for file in files:
                # Verifier si une extension de fichier est specifiee
                if file_extension:
                    if file.endswith(file_extension):
                        file_path = os.path.join(root, file)
                        print(file_path)
                        logging.info(f"Fichier trouve : {file_path}")
                else:
                    file_path = os.path.join(root, file)
                    print(file_path)
                    logging.info(f"Fichier trouve : {file_path}")
    except Exception as e:
        error_message = f"Erreur lors de la recherche : {e}"
        print(error_message)
        logging.error(error_message)

if __name__ == "__main__":
    configure_logging()

    if len(sys.argv) < 2:
        error_message = f"Usage: {sys.argv[0]} <directory> [file_extension]"
        print(error_message)
        logging.error(error_message)
        sys.exit(1)

    directory = sys.argv[1]
    file_extension = sys.argv[2] if len(sys.argv) == 3 else None

    tr(directory, file_extension)

  """},{"name":"prinxy",
  "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import logging
from pathlib import Path

def echo(text, no_newline=False, interpret_special_chars=False):
    try:
        # Chemin du repertoire log (chemin absolu)
        log_directory = '/home/IDFS/var/log'
        log_file_path = log_directory / "logfile.log"

        # Configuration du logging
        logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

        if interpret_special_chars:
            # Interpreter les caracteres speciaux
            text = text.encode('utf-8').decode('unicode_escape')

        # Enregistrement de l'action dans le fichier de logs
        logging.info(f"Affichage du texte : {text}")

        # Affichage du texte a la console
        print(text, end='' if no_newline else '\n')

    except Exception as e:
        # Gerer les erreurs et enregistrer dans le fichier de logs
        logging.error(f"Erreur inattendue : {e}")

def main():
    try:
        parser = argparse.ArgumentParser(description='Imiter la commande echo en Python.')
        parser.add_argument('text', metavar='TEXTE', type=str, help='Texte a afficher.')
        parser.add_argument('-n', '--no-newline', action='store_true', help="Ne pas ajouter une nouvelle ligne a la fin.")
        parser.add_argument('-e', '--interpret-special-chars', action='store_true', help="Interpreter les caracteres speciaux comme \\n, \\t, etc.")
        args = parser.parse_args()

        echo(args.text, no_newline=args.no_newline, interpret_special_chars=args.interpret_special_chars)

    except Exception as e:
        # Gerer les erreurs lors de l'analyse des arguments de la ligne de commande
        print(f"Erreur lors de l'analyse des arguments : {e}")
        logging.error(f"Erreur lors de l'analyse des arguments : {e}")

if __name__ == "__main__":
    main()
"""},
    {"name":"galaxyuadd",
  "content": """#!/usr/bin/env python3
# -- coding: utf-8 --
import os
import bcrypt
from getpass import getpass
import logging
from pathlib import Path

def configure_logging():
    try:
        log_directory = '/home/IDFS/var/log'
        log_file = Path(log_directory) / "logfile.log"
        log_directory = Path(log_directory)

        # Create log directory if it doesn't exist
        log_directory.mkdir(parents=True, exist_ok=True)

        # Configuration du logging
        logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    except Exception as e:
        print(f"Une erreur s'est produite lors de la configuration du logging : {e}")

def galaxyuadd():
    # Configurer le logging
    configure_logging()

    # Vérifier si l'utilisateur actuel est root
    if os.geteuid() != 0:
        logging.error("Permission denied. Vous devez executer ce script en tant que superutilisateur (root).".encode('utf-8'))
        return

    # Saisie du nom d'utilisateur
    username = input("Entrez le nom d'utilisateur : ")

    # Saisie du mot de passe en masquant la saisie
    password = getpass("Entrez le mot de passe : ")

    try:
        # Emplacement des fichiers simulés IDFS/etc/passwd, IDFS/etc/shadow et IDFS/etc/group (chemins absolus)
        passwd_file_path = '/home/IDFS/etc/passwd'
        shadow_file_path = '/home/IDFS/etc/shadow'
        group_file_path = '/home/IDFS/etc/group'

        # Emplacement du répertoire home dans IDFS (chemin absolu)
        idfs_home_dir = '/home/IDFS/home'

        # Vérifier si le nom d'utilisateur existe déjà
        with open(passwd_file_path, 'r') as passwd_file:
            existing_usernames = [line.split(':')[0] for line in passwd_file.readlines()]

        if username in existing_usernames:
            logging.error(f"L'utilisateur {username} existe deja.".encode('utf-8'))
            return

        # Ajouter l'entrée dans le fichier simulé IDFS/etc/passwd
        uid = len(existing_usernames) + 1000  # Générer un UID unique (à adapter selon les besoins)
        gid = uid  # Générer un GID identique à l'UID (à adapter selon les besoins)
        home_dir = f'{idfs_home_dir}/{username}'  # Définir le répertoire personnel dans IDFS
        shell = '/bin/bash'  # Définir le shell par défaut (à adapter selon les besoins)

        # Générer le hash du mot de passe
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Ajouter l'entrée dans le fichier IDFS/etc/shadow
        shadow_entry = f"{username}:{password_hash.decode('utf-8')}:"
        with open(shadow_file_path, 'a') as shadow_file:
            shadow_file.write(shadow_entry)

        # Ajouter l'entrée dans le fichier IDFS/etc/passwd avec un placeholder x
        passwd_entry = f"{username}:x:{uid}:{gid}::{home_dir}:{shell}"
        with open(passwd_file_path, 'a') as passwd_file:
            passwd_file.write(passwd_entry)

        # Créer le répertoire personnel avec le nom d'utilisateur dans IDFS/home
        os.makedirs(home_dir, exist_ok=True)

        # Ajouter l'entrée dans le fichier IDFS/etc/group
        with open(group_file_path, 'a') as group_file:
            group_entry = f"{username}:x:{gid}:"
            group_file.write(group_entry)

        logging.info(f"L'utilisateur {username} a ete ajoute avec succes.".encode('utf-8'))
    except Exception as e:
        logging.error(f"Erreur lors de l'ajout de l'utilisateur {username} : {e}".encode('utf-8'))

# Utilisation de la fonction
galaxyuadd()

"""},{"name":"shiftt",
"content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-          
import os
import sys
import getpass
import logging
import shutil

# Configuration du système de logging
log_file_path = '/home/IDFS/var/log/logfile.log'
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_current_username():
    try:
        return getpass.getuser()
    except Exception as e:
        logging.error("Impossible d'obtenir le nom d'utilisateur : %s", e)
        sys.exit(1)

def move_file(source_path, destination_path):
    try:
        # Obtenir le nom d'utilisateur actuel
        username = get_current_username()
        user_home_dir = f"/home/IDFS/home/{username}"

        # Construire les chemins complets du fichier source et du dossier de destination
        source_file = os.path.join(user_home_dir, source_path)
        destination_folder = os.path.join(user_home_dir, destination_path)

        # Vérifier si le fichier source existe avant de le déplacer
        if os.path.exists(source_file):
            # Vérifier si le dossier de destination existe, sinon le créer
            if not os.path.exists(destination_folder):
                os.makedirs(destination_folder)

            # Déplacer le fichier
            shutil.move(source_file, os.path.join(destination_folder, os.path.basename(source_file)))
            print(f"Le fichier {source_path} a été déplacé vers {destination_path}.")
        else:
            print(f"Le fichier {source_path} n'existe pas.")
    except Exception as e:
        logging.error("Erreur lors du déplacement du fichier : %s", e)

# Exemple d'utilisation
if __name__ == "__main__":
    if len(sys.argv) != 3:
        logging.error("Usage: shiftt <source> <destination>")
        sys.exit(1)

    source_file = sys.argv[1]
    destination_folder = sys.argv[2]
    move_file(source_file, destination_folder)
 """},{"name":"sp",
 "content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import psutil
import logging
from pathlib import Path

def main():
    try:
     
        log_directory = '/home/IDFS/var/log'

        # Chemin du fichier de logs (chemin relatif)
        log_file = log_directory / "logfile.log"


        # Créer le répertoire log s'il n'existe pas
        log_directory.mkdir(parents=True, exist_ok=True)

        # Configuration du logging
        logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

        processes = psutil.process_iter(['pid', 'name', 'username'])
       
        for process in processes:
            logging.info(process.info.encode('utf-8'))
    except Exception as e:
        logging.error(f"Une erreur s'est produite : {e}".encode('utf-8'))

if __name__ == "__main__":
    main()
"""},{"name":"nameu",
"content": """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import getpass
import logging
from pathlib import Path

def configure_logging():
    try:
       
        # Chemin du répertoire log (chemin relatif)
        log_directory =  '/home/IDFS/var/log'

        # Chemin du fichier de logs (chemin relatif)
        log_file = log_directory / "logfile.log"


        # Créer le répertoire log s'il n'existe pas
        log_directory.mkdir(parents=True, exist_ok=True)

        # Configuration du logging
        logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    except Exception as e:
        print(f"Une erreur s'est produite lors de la configuration du logging : {e}")

def get_username():
    try:
        # Obtenir le nom d'utilisateur actuel
        username = getpass.getuser()

        # Afficher le nom d'utilisateur
        print(f"User name : {username}")

        # Enregistrer le nom d'utilisateur dans le fichier de logs
        logging.info(f"Nom d'utilisateur actuel : {username}".encode('utf-8'))

    except Exception as e:
        # Gérer les erreurs et les enregistrer dans le fichier de logs
        print(f"Une erreur s'est produite : {e}")
        logging.error(f"Erreur lors de l'obtention du nom d'utilisateur : {e}")

if __name__ == "__main__":
    configure_logging()
    get_username()
"""},{"name":"nchow",
"content":"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import pwd  # Ajouter cette ligne pour importer le module pwd
from pathlib import Path

def nchow(path, owner):
    try:
        # Obtenir le répertoire du script en cours
        script_directory = Path(__file__).resolve().parent

        # Utilisez la fonction os.chown pour changer le proprietaire du fichier/dossier
        os.chown(path, -1, pwd.getpwnam(owner).pw_uid)  # Correction de cette ligne
        print(f"Changement de propriétaire de {path} à {owner} effectué avec succès.")
    except FileNotFoundError:
        print(f"Le fichier ou dossier {path} n'existe pas.")
    except PermissionError:
        print(f"Permission refusée pour changer le propriétaire de {path}. Veuillez exécuter en tant qu'administrateur.")
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")

if __name__ == "__main__":
    # Vérifier si les arguments nécessaires sont fournis
    if len(sys.argv) != 3:
        print("Usage: nchow <chemin> <nouveau_proprietaire>")
        sys.exit(1)

    # Extraire les arguments de la ligne de commande
    chemin = sys.argv[1]
    nouveau_proprietaire = sys.argv[2]

    # Appeler la fonction nchow avec les arguments fournis
    nchow(chemin, nouveau_proprietaire)
 """},{"name":"md",
 "content": """#!/usr/bin/env python3
# -- encoding: latin-1 --
import os
import json
import sys

def get_current_username():
    return os.environ.get("USER") or os.environ.get("LOGNAME") or os.environ.get("USERNAME")

def lire_metadonnees(nom_fichier):
    username = get_current_username()
    # Si l'utilisateur est root, utilisez "/home/IDFS/etc/metadata_root" au lieu de "/home/IDFS/etc/metadata_{username}"
    chemin_metadata = f'/home/IDFS/etc/metadata_root' if username == 'root' else f'/home/IDFS/etc/metadata_{username}'

    if os.path.exists(chemin_metadata):
        with open(chemin_metadata, 'r') as fichier_metadata:
            metadonnees_globales = json.load(fichier_metadata)
            # Chercher les mÃ©tadonnÃ©es spÃ©cifiques au fichier
            for metadonnees in metadonnees_globales:
                # Vérifier si la clé 'Nom du fichier' est présente avant de l'accéder
                if 'Nom du fichier' in metadonnees and metadonnees['Nom du fichier'] == nom_fichier:
                    return metadonnees
            # Si les mÃ©tadonnÃ©es pour le fichier spÃ©cifiÃ© ne sont pas trouvÃ©es
            return None
    else:
        return None

# VÃ©rification de la prÃ©sence du nom de fichier en ligne de commande
if len(sys.argv) != 2:
    print("Utilisation: python script.py <nom_fichier>")
    sys.exit(1)

nom_fichier = sys.argv[1]

metadonnees = lire_metadonnees(nom_fichier)

if metadonnees:
    print(f"Métadonnées pour le fichier '{nom_fichier}' de l'utilisateur '{get_current_username()}':")
    for cle, valeur in metadonnees.items():
        print(f"{cle}: {valeur}")
else:
    print(f"Aucune métadonnée trouvée pour le fichier '{nom_fichier}' de l'utilisateur '{get_current_username()}'.")


  """},{"name":"mochdl",
  "content": """#!/usr/bin/env python3
# -- coding: utf-8 --

import sys
import os
import json
from datetime import datetime
import logging

def configure_logging():
    # Chemin du répertoire log (chemin relatif)
    log_dir = 'IDFS/var/log'
    log_file = "logfile.log"
    log_path = os.path.join(log_dir, log_file)

    # Créer le répertoire log s'il n'existe pas
    os.makedirs(log_dir, exist_ok=True)

    # Configuration du logging
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def mochd(arguments):
    # Configurer le logging
    configure_logging()

    if len(arguments) != 3:
        logging.error("Usage: mochd <+x> <file>".encode('utf-8'))
        sys.exit(1)

    mode_str, filename = arguments[1], arguments[2]

    if mode_str != "+x":
        logging.error("Invalid mode. Please use '+x' to add execute permission.".encode('utf-8'))
        sys.exit(1)

    try:
        current_mode = os.stat(filename).st_mode
        new_mode = current_mode | 0o111
        os.chmod(filename, new_mode)
        logging.info(f"Added execute permission to '{filename}'".encode('utf-8'))

        # Update metadata
        update_metadata(filename)

    except FileNotFoundError:
        logging.error(f"File '{filename}' not found.".encode('utf-8'))
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permission denied: '{filename}'".encode('utf-8'))
        sys.exit(1)
    except Exception as e:
        logging.error(f"An error occurred: {e}".encode('utf-8'))
        sys.exit(1)

def update_metadata(filename):
    try:
        # Metadata file path (chemin relatif)
        output_file = "IDFS/etc/metadata"

        # Check if metadata file exists
        if os.path.isfile(output_file):
            # If it exists, read existing metadata
            with open(output_file, "r") as f:
                try:
                    existing_metadata = json.load(f)
                except json.JSONDecodeError:
                    existing_metadata = []

            # Find the metadata entry for the specified file
            for entry in existing_metadata:
                if entry["Nom du fichier"] == filename:
                    # Update the modification time
                    entry["Date de derniere modification"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    # Update the permissions
                    entry["Permissions"] = oct(os.stat(filename).st_mode)[-3:]

                    # Write the updated list to the file
                    with open(output_file, "w") as f:
                        json.dump(existing_metadata, f, indent=2)

                    logging.info(f"Metadata updated for '{filename}'".encode('utf-8'))
                    return

            logging.error(f"Metadata entry not found for '{filename}'".encode('utf-8'))

        else:
            logging.error(f"Metadata file not found at {output_file}".encode('utf-8'))

    except FileNotFoundError:
        logging.error(f"File '{filename}' does not exist.")
    except Exception as e:
        logging.error(f"An error occurred: {e}".encode('utf-8'))

if __name__ == "__main__":
    mochd(sys.argv)
  """},{"name":"mochdn",
  "content":"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
from datetime import datetime
import logging

def configure_logging():
    # Chemin du répertoire log (chemin relatif)
    log_dir = 'IDFS/var/log'
    log_file = "logfile.log"
    log_path = os.path.join(log_dir, log_file)

    # Créer le répertoire log s'il n'existe pas
    os.makedirs(log_dir, exist_ok=True)

    # Configuration du logging
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def mochd(arguments):
    # Configurer le logging
    configure_logging()

    if len(arguments) != 3:
        logging.error("Usage: mochd <mode> <file>")
        sys.exit(1)

    mode_str, filename = arguments[1], arguments[2]

    try:
        current_mode = os.stat(filename).st_mode
        if mode_str[0] == '+':
            mode = current_mode | int(mode_str[1:], 8)
        else:
            mode = int(mode_str, 8)
    except ValueError:
        logging.error("Invalid mode. Please provide a valid octal mode.")
        sys.exit(1)

    try:
        os.chmod(filename, mode)
        logging.info(f"Changed permissions of '{filename}' to {oct(mode)[2:]}")

        # Update metadata
        update_metadata(filename, mode)

    except FileNotFoundError:
        logging.error(f"File '{filename}' not found.")
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permission denied: '{filename}'")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

def update_metadata(filename, new_mode):
    try:
        # Metadata file path (chemin relatif)
        output_file = "IDFS/etc/metadata"

        # Check if metadata file exists
        if os.path.isfile(output_file):
            # If it exists, read existing metadata
            with open(output_file, "r") as f:
                try:
                    existing_metadata = json.load(f)
                except json.JSONDecodeError:
                    existing_metadata = []

            # Find the metadata entry for the specified file
            for entry in existing_metadata:
                if entry["Nom du fichier"] == filename:
                    # Update the modification time
                    entry["Date de derniere modification"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    # Update the permissions in the metadata
                    entry["Permissions"] = oct(new_mode)[-3:]

                    # Write the updated list to the file
                    with open(output_file, "w") as f:
                        json.dump(existing_metadata, f, indent=2)

                    logging.info(f"Metadata updated for '{filename}'")
                    return

            logging.error(f"Metadata entry not found for '{filename}'")

        else:
            logging.error(f"Metadata file not found at {output_file}")

    except FileNotFoundError:
        logging.error(f"File '{filename}' does not exist.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    mochd(sys.argv)

 """},{"name":"voidrm",
 "content":"""#!/usr/bin/env python3
 # -*- coding: utf-8 -*-
import os
import sys
import logging

def configure_logging():
    # Configurer le logging
    base_directory = "/home/IDFS/var"
    log_directory = os.path.join(base_directory, "log")
    log_file = os.path.join(log_directory,"logfile.log")
    os.makedirs(log_directory, exist_ok=True)

    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def delet(chemin):
    try:
        chemin_fichier = os.path.abspath(chemin)  # Obtient le chemin absolu du fichier
        os.remove(chemin_fichier)
        success_message = f"Fichier supprime avec succes : {chemin_fichier}"
        print(success_message)
        logging.info(success_message.encode('utf-8'))
    except FileNotFoundError:
        error_message = f"Echec : Le fichier '{chemin}' n'existe pas."
        print(error_message.encode('utf-8'))
        logging.warning(error_message.encode('utf-8'))
    except Exception as e:
        error_message = f"Erreur lors de la suppression du fichier : {str(e)}"
        print(error_message.encode('utf-8'))
        logging.error(error_message.encode('utf-8'))

if __name__ == "__main__":
    configure_logging()

    # Utilisation de la commande delet
    if len(sys.argv) != 2:
        print("Usage: python script.py <chemin_du_fichier>")
    else:
        chemin_fichier = sys.argv[1]
        delet(chemin_fichier)
 """},{"name":"voidrmf",
 "content":"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import shutil
import logging

def configure_logging():
    # Configurer le logging
    base_directory = "IDFS/var"
    log_directory = os.path.join(base_directory, "log")
    log_file =  os.path.join(log_directory, "logfile.log")
    os.makedirs(log_directory,exist_ok=True)
    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def deletef(target_path):
    try:
        if os.path.isfile(target_path):
            os.remove(target_path)
            success_message = f"Le fichier {target_path} a ete supprime."
            print(success_message)
            logging.info(success_message.encode('utf-8'))
        elif os.path.isdir(target_path):
            shutil.rmtree(target_path)
            success_message = f"Le repertoire {target_path} et son contenu ont ete supprimes."
            print(success_message)
            logging.info(success_message.encode('utf-8'))
        else:
            error_message = f"{target_path} n'est ni un fichier ni un repertoire."
            print(error_message)
            logging.warning(error_message.encode('utf-8'))
    except FileNotFoundError:
        error_message = f"Le fichier ou le repertoire {target_path} n'existe pas."
        print(error_message)
        logging.warning(error_message.encode('utf-8'))
    except Exception as e:
        error_message = f"Une erreur s'est produite : {e}"
        print(error_message)
        logging.error(error_message.encode('utf-8'))

if __name__ == "__main__":
    configure_logging()

    if len(sys.argv) != 2:
        error_message = "Usage: python my_rm.py <target_path>"
        print(error_message)
        logging.error(error_message.encode('utf-8'))
        sys.exit(1)

    target_path = sys.argv[1]
    deletef(target_path)
"""},{"name":"writ",
"content":"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import subprocess
import sys
import json
import pwd
import logging
from datetime import datetime
import shutil

# Configuration du système de logging
log_file_path = '/home/IDFS/var/log/logfile.log'
logging.basicConfig(filename=log_file_path, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def write(filename):
    try:
        subprocess.run(["nano", filename], check=True)
        update_metadata(filename)
    except subprocess.CalledProcessError as e:
        logging.error("Une erreur s'est produite lors de l'edition : %s", e)
        sys.exit(1)

def update_metadata(filename):
    try:
        stat_info = os.stat(filename)
        date_creation = datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        date_modification = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        user_info = pwd.getpwuid(stat_info.st_uid)
        username = user_info.pw_name
        user_home_dir = f"/home/IDFS/home/{username}"

        if not os.path.exists(user_home_dir):
            os.makedirs(user_home_dir)

        destination_path = os.path.join(user_home_dir, os.path.basename(filename))
        shutil.move(filename, destination_path)

        metadata = {
            "Nom du fichier": filename,
            "Date de creation": date_creation,
            "Date de derniere modification": date_modification,
            "Taille du fichier": stat_info.st_size,
            "Permissions": oct(stat_info.st_mode)[-3:],
            "Nom d'utilisateur": username,
        }

        output_file = f"/home/IDFS/etc/metadata_{username}"

        if not os.path.isfile(output_file):
            with open(output_file, "w") as f:
                json.dump([metadata], f, indent=2)
            logging.info("Fichier de metadonnees cree a %s", output_file)
        else:
            with open(output_file, "r") as f:
                try:
                    existing_metadata = json.load(f)
                except json.JSONDecodeError:
                    existing_metadata = []

            existing_metadata.append(metadata)

            with open(output_file, "w") as f:
                json.dump(existing_metadata, f, indent=2)

            logging.info("Metadonnees ajoutees dans %s", output_file)

    except FileNotFoundError:
        logging.error("Le fichier '%s' n'existe pas.", filename)
    except Exception as e:
        logging.error("Une erreur s'est produite : %s", e)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: write <file>")
        logging.error("Nombre incorrect d'arguments passes.")
        sys.exit(1)

    filename = sys.argv[1]
    write(filename)


 """},{"name":"timin",
"content":"""#!/usr/bin/env python3
# -*- coding: Latin-1 -*-
import datetime

def afficher_date_et_heure():
    # Obtenir la date et l'heure actuelles
    maintenant = datetime.datetime.now()

    # Formater la date et l'heure dans une chaine
    format_date = maintenant.strftime("%Y-%m-%d %H:%M:%S")

    # Afficher le résultat
    print(f"{format_date}")

if __name__ == "__main__":
    afficher_date_et_heure()
	  """},	
	  ]

# Créer des fichiers de commandes individuels dans le dossier bin
for script in command_scripts:
    script_file_path = os.path.join(bin_directory, script['name'])
    with open(script_file_path, 'w') as script_file:
        script_file.write(script['content'])
    os.chmod(script_file_path, 0o755)  # Définir les permissions à rwxr-xr-x (755)

