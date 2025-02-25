import os
import py_compile

def compile_python_files():
    try:
        print("🔄 Compilation des fichiers Python en cours...")
        exclude_dirs = {'Lib', 'Scripts', 'Include', '__pycache__', 'build', 'dist'}  # Exclusion des répertoires inutiles

        # On va chercher uniquement dans le dossier 'Tools'
        print("📂 Exploration du dossier 'Tools' pour les fichiers Python...")
        for root, dirs, files in os.walk('Tools'):  # Spécifie le dossier "Tools"
            print(f"🔍 En cours d'exploration: {root}")
            
            # Exclure certains répertoires (si présents dans Tools)
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            print(f"   ➖ Répertoires exclus: {exclude_dirs}")
            print(f"   ➡️ Répertoires à explorer: {dirs}")
            
            # Trouver les fichiers .py dans ce dossier
            py_files = [os.path.join(root, f) for f in files if f.endswith('.py')]
            if py_files:
                print(f"   🔍 Fichiers Python trouvés: {py_files}")
            else:
                print(f"   🚫 Aucun fichier Python trouvé dans {root}.")
            
            # Compiler chaque fichier Python trouvé
            for py_file in py_files:  # Boucle sur chaque fichier Python
                print(f"   ➡️ Compilation du fichier : {py_file}")
                try:
                    py_compile.compile(py_file, cfile=py_file + 'c', doraise=True)
                    print(f"   ✅ Compilation réussie pour {py_file}")
                except py_compile.PyCompileError as e:
                    print(f"❌ Erreur de compilation pour {py_file} : {e}")
                    continue  # Passer au fichier suivant en cas d'erreur

        print("✅ Compilation terminée avec succès pour tous les fichiers.")
        return True

    except Exception as e:
        print(f"❌ Erreur lors de la compilation des fichiers Python : {e}")
        return False
