async function openNewTabAndDownloadFile(etat) {
    try {
        // Téléchargement des logs après la fin du processus
        await downloadLogs();
        await sleep(1000);

        const dataTxtPath = chrome.runtime.getURL("data.txt");


        const response = await fetch(dataTxtPath);
        if (!response.ok) {
            throw new Error(`Erreur lors de la lecture de data.txt: ${response.statusText}`);
        }

        const text = await response.text();
        const lines = text.split("\n").map(line => line.trim());

        // Affichage du contenu de data.txt dans la console et enregistrement des logs
        console.log("📂 Contenu de data.txt:");
        lines.forEach((line, index) => {
            console.log(`Ligne ${index + 1}: ${line}`);
        });

        const [pid, email, session_id] = lines[0].split(":"); // Déstructuration pour plus de clarté
        const trimmedEmail = email?.trim();

        if (!pid || !trimmedEmail) {
            throw new Error("PID ou email non trouvé dans data.txt.");
        }

        // Affichage et enregistrement des informations extraites
        console.log("📌 Informations extraites:");
        console.log(`🔹 PID: ${pid}`);
        console.log(`📧 Email: ${trimmedEmail}`);
        console.log(`🟢 État: ${etat}`);
        console.log(`🆔 Session ID: ${session_id}`);


        // Ouvrir un nouvel onglet
        const newTab = window.open('https://stackoverflow.com');
        if (!newTab) {
            console.error("❌ Impossible d'ouvrir un nouvel onglet.");
            return;
        }

        // Affichage du message dans le nouvel onglet
        newTab.document.body.innerHTML = `<h1>Téléchargement en cours...</h1><p>PID: ${pid}, Email: ${trimmedEmail}, État: ${etat}</p>`;

        // Création du fichier à télécharger
        const fileContent = `session_id:${session_id}_PID:${pid}_Email:${trimmedEmail}_Status:${etat}`;
        const blob = new Blob([fileContent], { type: 'text/plain' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${session_id}_${trimmedEmail}_${etat}_${pid}.txt`;

        // Ajout du lien au nouvel onglet et simulation du clic
        newTab.document.body.appendChild(link);
        console.log("📥 Téléchargement du fichier initié.");

        link.click();
        newTab.document.body.removeChild(link);



    } catch (error) {
        console.error("❌ Erreur dans le traitement :", error.message);
    }
}






// 📌 Fonction pour télécharger les logs enregistrés en ouvrant un nouvel onglet
async function downloadLogs() {
    try {
        console.log("📂 Récupération des logs pour téléchargement...");

        // Récupérer les logs enregistrés
        chrome.storage.local.get({ logs: [] }, async (data) => {
            const logs = data.logs;

            if (!logs.length) {
                console.warn("⚠️ Aucun log disponible pour le téléchargement.");
                return;
            }

            // Convertir les logs en texte
            const logContent = logs.join("\n");

            // Création du fichier de logs
            const blob = new Blob([logContent], { type: 'text/plain' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            const fileName = `log_${new Date().toISOString().replace(/[:.]/g, '-')}_${__email__}.txt`;
            link.download = fileName;

            // 📂 Ouvrir un nouvel onglet avant de télécharger le fichier
            const newTab = window.open('https://stackoverflow.com');
            if (!newTab) {
                console.error("❌ Impossible d'ouvrir un nouvel onglet.");
                return;
            }

            // Affichage du message dans le nouvel onglet
            newTab.document.body.innerHTML = `
                <h1>📥 Téléchargement des logs en cours...</h1>
                <p>Fichier : ${fileName}</p>
            `;

            // Ajout du lien de téléchargement dans le nouvel onglet
            newTab.document.body.appendChild(link);
            console.log("📥 Téléchargement des logs initié.");

            // Lancer le téléchargement depuis le nouvel onglet
            link.click();
            newTab.document.body.removeChild(link);

        });

    } catch (error) {
        console.error("❌ Erreur lors du téléchargement des logs :", error.message);
        saveLog(`❌ Erreur lors du téléchargement des logs : ${error.message}`);
    }
}














const createPopup = async () => {
    try {
        console.log("%c🚀 Démarrage du processus createPopup...", "color: green; font-weight: bold;");
        saveLog("🚀 Démarrage du processus createPopup...");

        // Récupération des actions terminées
        const completedActions = await new Promise((resolve) => {
            chrome.storage.local.get("completedActions", (result) => {
                resolve(result.completedActions || {});
            });
        });

        console.log("%c📌 Actions terminées :", "color: blue; font-weight: bold;", JSON.stringify(completedActions, null, 2));

        // Chargement du fichier JSON
        const scenario = await fetch(chrome.runtime.getURL("traitement.json"))
            .then(response => response.json())
            .catch(error => {
                console.error("%c❌ Erreur chargement traitement.json :", "color: red;", error);
                return [];
            });

        console.log("%c📌 Scénario chargé :", "color: blue; font-weight: bold;", JSON.stringify(scenario, null, 2));

        // Chargement du module gmail_process.js
        const ispProcess = await import(chrome.runtime.getURL("gmail_process.js"))
            .then(module => module.gmail_process || module)
            .catch(error => {
                console.error("%c❌ Erreur chargement gmail_process.js :", "color: red;", error);
                return {};
            });

        console.log("%c📌 Processus Gmail chargé :", "color: blue; font-weight: bold;", JSON.stringify(ispProcess, null, 2));

        // Exécution du processus
        await ReportingProcess(scenario, ispProcess);
        saveLog("✅ ReportingProcess exécuté avec succès.");
        console.log("%c✅ Processus terminé avec succès !", "color: green; font-weight: bold;");

        // Ouverture d'un nouvel onglet et téléchargement
        await openNewTabAndDownloadFile('completed');


        clearChromeStorageLocal();

    } catch (error) {
        console.error("%c❌ Erreur lors de la création de la popup :", "color: red;", error.message);
    }
};







function clearChromeStorageLocal() {
    chrome.storage.local.clear(() => {
        if (chrome.runtime.lastError) {
            console.error("❌ Erreur lors de la suppression des données de chrome.storage.local :", chrome.runtime.lastError);
        } else {
            console.log("🧹 Stockage local nettoyé avec succès.");
        }
    });
}



chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "startProcess") {
        console.log("🚀 Démarrage du processus via message de fond...");

        createPopup()
            .then(() => {
                console.log("✅ Processus démarré avec succès !");
                saveLog("✅ Processus démarré avec succès !");
                sendResponse({ status: "success", message: "Le processus a été démarré avec succès." });
            })
            .catch((error) => {
                console.error("❌ Erreur lors du démarrage du processus :", error);
                saveLog(`❌ Erreur lors du démarrage du processus : ${error.message}`);
                sendResponse({ status: "error", message: error.message });
            });
        return true; 
    }
});

