
// 📌 Fonction pour stocker les logs dans chrome.storage.local
function saveLog(message) {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${message}`;
    
    const emojis = ["🔔"];
    const randomEmoji = emojis[Math.floor(Math.random() * emojis.length)];

    chrome.storage.local.get({ logs: [] }, (data) => {
        const updatedLogs = [...(data.logs || []), `${randomEmoji} ${logMessage}`];

        chrome.storage.local.set({ logs: updatedLogs });
    });
}






async function waitForElement(xpath, timeout = 30) {
    const maxWait = timeout * 1000; 
    const interval = 1000; 
    let elapsed = 0;

    console.log(`⌛ Début de l'attente de l'élément avec XPath: ${xpath} (Max: ${timeout} secondes)`);
    saveLog(`⌛ Début de l'attente de l'élément avec XPath: ${xpath} (Max: ${timeout} secondes)`);

    try {
        while (elapsed < maxWait) {
            const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
            if (element) {
                console.log(`✅ Élément trouvé: ${xpath}`);
                saveLog(`✅ Élément trouvé: ${xpath}`);
                await sleep(7000);
                return true;
            }
            await sleep(interval);
            elapsed += interval;
            console.log(`⏳ ${elapsed / 1000} secondes écoulées...`);
            saveLog(`⏳ ${elapsed / 1000} secondes écoulées...`);
        }
    } catch (error) {
        console.error(`❌ Erreur lors de la recherche de l'élément: ${error.message}`);
        saveLog(`❌ Erreur lors de la recherche de l'élément: ${error.message}`);
        return false;
    }

    console.log(`❌ Temps écoulé. Élément non trouvé après ${timeout} secondes.`);
    saveLog(`❌ Temps écoulé. Élément non trouvé après ${timeout} secondes.`);
    await sleep(7000);
    return false;
}




// 📌 Fonction améliorée pour rechercher un élément avec XPath
async function findElementByXPath(xpath, timeout = 10, obligatoire = false, type = undefined) {
    const maxWait = timeout * 1000;
    const interval = 500;
    let elapsed = 0;

    console.log(`🔍 Recherche de l'élément avec XPath: ${xpath}... (Max: ${timeout} secondes)`);
    saveLog(`🔍 Recherche de l'élément avec XPath: ${xpath}... (Max: ${timeout} secondes)`);

    try {
        while (elapsed < maxWait) {
            const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
            if (element) {
                console.log(`✅ Élément trouvé avec XPath: ${xpath}`);
                saveLog(`✅ Élément trouvé avec XPath: ${xpath}`);
                return element;
            }

            await sleep(interval);
            elapsed += interval;
            console.log(`⏳ En attente... Temps écoulé: ${elapsed / 1000} secondes.`);
            saveLog(`⏳ En attente... Temps écoulé: ${elapsed / 1000} secondes.`);
        }
    } catch (error) {
        console.error(`❌ Erreur lors de la recherche de l'élément: ${error.message}`);
        saveLog(`❌ Erreur lors de la recherche de l'élément: ${error.message}`);
        return null;
    }

    if (obligatoire) {
        console.warn(`❗ L'élément obligatoire n'a pas été trouvé après ${timeout} secondes. XPath: ${xpath}`);
        saveLog(`❗ L'élément obligatoire n'a pas été trouvé après ${timeout} secondes. XPath: ${xpath}`);
        await openNewTabAndDownloadFile(type);
    } else {
        console.error(`❌ Élément non trouvé après ${timeout} secondes. XPath: ${xpath}`);
        saveLog(`❌ Élément non trouvé après ${timeout} secondes. XPath: ${xpath}`);
    }

    return null;
}



// 📌 Fonction améliorée pour récupérer le texte d'un élément par XPath
function getElementTextByXPath(xpath) {
    try {
        console.log(`🔍 Recherche de l'élément avec XPath: ${xpath}...`);
        saveLog(`🔍 Recherche de l'élément avec XPath: ${xpath}...`);

        const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        if (element) {
            const text = element.textContent.trim();
            console.log(`✅ Élément trouvé avec XPath: ${xpath} | Texte: "${text}"`);
            saveLog(`✅ Élément trouvé avec XPath: ${xpath} | Texte: "${text}"`);
            return text;
        } else {
            console.warn(`⚠️ L'élément avec XPath: ${xpath} n'a pas été trouvé.`);
            saveLog(`⚠️ L'élément avec XPath: ${xpath} n'a pas été trouvé.`);
            return null;
        }
    } catch (error) {
        console.error(`❌ Erreur lors de la recherche de l'élément avec XPath: ${xpath}`, error);
        saveLog(`❌ Erreur lors de la recherche de l'élément avec XPath: ${xpath} | ${error.message}`);
        return null;
    }
}







// 📌 Fonction améliorée pour compter le nombre d'éléments avec XPath
function getElementCountByXPath(xpath) {
    try {
        console.log(`🔍 Recherche du nombre d'éléments avec XPath: ${xpath}...`);
        saveLog(`🔍 Recherche du nombre d'éléments avec XPath: ${xpath}...`);

        const result = document.evaluate(xpath, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
        const count = result.snapshotLength;

        console.log(`✅ Nombre d'éléments trouvés avec XPath: ${xpath} est ${count}`);
        saveLog(`✅ Nombre d'éléments trouvés avec XPath: ${xpath} est ${count}`);

        return count;
    } catch (error) {
        console.error(`❌ Erreur lors de la recherche des éléments avec XPath: ${xpath}`, error);
        saveLog(`❌ Erreur lors de la recherche des éléments avec XPath: ${xpath} | ${error.message}`);

        return 0;
    }
}










// 📌 Fonction améliorée `ReportingProcess`
async function ReportingProcess(scenario, ispProcess) {
    let messagesProcessed = 0;

    for (const process of scenario) {
        try {
            const currentURL = window.location.href;
            console.log(`🔄 Traitement de l'étape : ${process.process}`);

            // Ignorer l'étape "login" si déjà sur une page de Google
            if (
                (
                    currentURL.includes("https://mail.google.com/mail") || 
                    currentURL.startsWith("https://gds.google.com/") || 
                    currentURL.includes("https://myaccount.google.com/?pli=") ||
                    currentURL.startsWith("https://myaccount.google.com/")
                ) &&
                process.process === "login"
            ) {
                console.log(`🚫 Ignorer l'étape "login" car nous sommes déjà sur une page de Google`);
                continue;
            }

            if (process.process === "loop") {
                const limitLoop = process.limit_loop;
                let stopAllLoops = false;

                console.log(`🔄 Début de la boucle, limite de ${limitLoop} messages`);

                while (messagesProcessed < limitLoop) {
                    if (stopAllLoops) {
                        console.log(`🛑 Boucle arrêtée prématurément`);
                        break;
                    }

                    if (process.check) {
                        console.log(`🔍 Vérification de la condition pour l'étape ${process.check}...`);

                        const checkResult = await ReportingActions(ispProcess[process.check], process.process);

                        if (!checkResult) {
                            console.log(`🚫 Condition échouée pour ${process.check}. Arrêt de la boucle.`);
                            stopAllLoops = true;
                            break;
                        }
                    }

                    const xpath = `//table[.//colgroup]//tbody/tr`;
                    const messagesOnPage = await getElementCountByXPath(xpath);
                    console.log(`📄 Nombre de messages sur la page actuelle: ${messagesOnPage}`);

                    for (let i = 0; i < messagesOnPage; i++) {
                        if (stopAllLoops || messagesProcessed >= limitLoop) {
                            stopAllLoops = true;
                            break;
                        }

                        for (const subProcess of process.sub_process) {
                            if (stopAllLoops) {
                                break;
                            }

                            console.log(`⚙️ Traitement du sous-processus: ${subProcess.process}`);
                            
                            const prcss = [...ispProcess[subProcess.process]];
                            addUniqueIdsToActions(prcss);

                            if (subProcess.process === "OPEN_MESSAGE_ONE_BY_ONE") {
                                prcss.forEach(p => {
                                    p.xpath = p.xpath.replace(/\[(\d+)\]/, `[${i + 1}]`);
                                });

                                console.log(`📬 Ouverture du message ${i + 1}`);
                                await ReportingActions(prcss, process.process);
                                continue;
                            }

                            if (subProcess.process === "next" || subProcess.process === "next_page") {
                                const checkNextResult = await ReportingActions(ispProcess["CHECK_NEXT"], process.process);
                                if (!checkNextResult) {
                                    console.log(`🚫 Pas de page suivante`);
                                    break;
                                }

                                console.log(`➡️ Passage à la page suivante`);
                                await ReportingActions(ispProcess[subProcess.process], process.process);
                            }

                            await ReportingActions(ispProcess[subProcess.process], process.process);
                        }

                        messagesProcessed++;
                        console.log(`✔️ Message ${messagesProcessed} traité`);
                    }

                    if (!stopAllLoops && messagesProcessed < limitLoop) {
                        console.log(`📖 Vérification de la présence d'une page suivante...`);

                        const checkNextResult = await ReportingActions(ispProcess["CHECK_NEXT"], process.process);
                        if (!checkNextResult) {
                            console.log(`🚫 Aucune page suivante trouvée`);
                            break;
                        }

                        const nextPageActions = [...ispProcess["next_page"]];
                        addUniqueIdsToActions(nextPageActions);
                        console.log(`➡️ Aller à la page suivante`);
                        await ReportingActions(nextPageActions, process.process);
                    }
                }

                if (stopAllLoops) {
                    console.log(`🛑 La boucle a été arrêtée prématurément`);
                    continue;
                }
            } else if (process.process === "search") {
                console.log(`🔍 Recherche avec valeur: ${process.value}`);

                const updatedProcesses = ispProcess[process.process].map(item => {
                    const updatedItem = { ...item };
                    if (updatedItem.value && updatedItem.value.includes("__search__")) {
                        updatedItem.value = updatedItem.value.replace("__search__", process.value);
                    }
                    return updatedItem;
                });

                await ReportingActions(updatedProcesses, process.process);
            } else if (process.process === "CHECK_FOLDER") {
                console.log(`📂 Vérification du dossier avec la procédure: ${process.check}`);

                const checkFolderResult = await ReportingActions(ispProcess[process.check], process.process);
                if (!checkFolderResult) {
                    console.log(`🚫 Échec de la vérification du dossier`);
                    break;
                }
            } else {
                console.log(`⚙️ Exécution de la procédure: ${process.process}`);
                await ReportingActions(ispProcess[process.process], process.process);
            }

        } catch (error) {
            console.error(`❌ [ERREUR] Processus '${process.process}' :`, error);
        }
    }
}









async function ReportingActions(actions, process) {

    const completedActions = await new Promise((resolve) => {
        chrome.storage.local.get("completedActions", (result) => {
            resolve(result.completedActions || {}); 
        });
    });

    const currentProcessCompleted = completedActions[process] || [];

    function normalize(obj) {
        const sortedKeys = Object.keys(obj).sort(); 
        const normalizedObj = sortedKeys.reduce((acc, key) => {
            acc[key] = obj[key];
            return acc;
        }, {});
        return JSON.stringify(normalizedObj)
            .replace(/[\u200B-\u200D\uFEFF\u00A0]/g, "") 
            .trim(); 
    }

    console.log("📜 Détails des actions terminées :");
    console.log("====================================");
    console.log(JSON.stringify(completedActions, null, 2));  
    console.log("====================================\n");
    console.log(`🚀 [CURRENT PROCESS COMPLETED] Actions terminées pour le processus en cours: ${process}`);
    console.log("📜 Détails des actions terminées pour le processus actuel :");
    console.log("====================================");
    console.log(JSON.stringify(currentProcessCompleted, null, 2));  
    console.log("====================================\n");

    // 📌 Vérification si une action a déjà été complétée
    function isActionCompleted(action) {
        const normalizedAction = normalize({ ...action, sub_action: undefined });

        console.log("🔍 Normalized action:", normalizedAction);

        return currentProcessCompleted.some((completed) => {
            const normalizedCompleted = normalize({ ...completed, sub_action: undefined });

            console.log("✅ Normalized completed:", normalizedCompleted);

            const comparisonResult = normalizedAction === normalizedCompleted;
            console.log("⚖️ Comparison result:", comparisonResult ? "Match" : "No match");

            return comparisonResult;
        });
    }
        



    // 📌 Fonction pour ajouter une action complétée à chrome.storage.local
    async function addToCompletedActions(action, process) {
        try {
            const completedAction = { ...action };
            delete completedAction.sub_action; 

            console.log("📝 Action to add:", JSON.stringify(completedAction));

            currentProcessCompleted.push(completedAction);
            console.log("✅ Action added to currentProcessCompleted:", JSON.stringify(currentProcessCompleted));

            completedActions[process] = currentProcessCompleted;
            console.log("📦 Updated completedActions:", JSON.stringify(completedActions));

            await new Promise((resolve) => {
                chrome.storage.local.set({ completedActions }, resolve);
                console.log("🔒 Completed actions saved to storage.");
            });
        } catch (error) {
            console.error("❌ Erreur lors de l'ajout de l'action complétée :", error);
        }
    }
    
    for (const action of actions) {

        console.log("\n-----------------------------------");
        console.log("🔶 [DÉBUT DE L'ACTION] Début du traitement d'une action...");
        console.log("💡 [DÉTAILS DE L'ACTION] Informations sur l'action :", JSON.stringify(action, null, 2));
        console.log("-----------------------------------");
        

        

        if (isActionCompleted(action)) {
            if (action.sub_action?.length > 0) {
                await ReportingActions(action.sub_action, process);
            } else {
                console.log("✔️ [AUCUNE ACTION SUPPLÉMENTAIRE] Aucune sous-action à exécuter.");
                saveLog("✔️ [AUCUNE ACTION SUPPLÉMENTAIRE] Aucune sous-action à exécuter.");
            }
            continue; 
        }

        await addToCompletedActions(action);

        try {
            if (action.action === "check_if_exist") {
                console.log("🔍 [VÉRIFICATION DE L'ÉLÉMENT] Vérification de l'existence de l'élément...");
                saveLog("🔍 [VÉRIFICATION DE L'ÉLÉMENT] Vérification de l'existence de l'élément...");
            
                const elementExists = await waitForElement(action.xpath, action.wait);
                
                if (elementExists) {
                    console.log(`✅ [ÉLÉMENT TROUVÉ] L'élément existe : ${action.xpath}`);
                    saveLog(`✅ [ÉLÉMENT TROUVÉ] L'élément existe : ${action.xpath}`);
            
                    if (action.type) {
                        await openNewTabAndDownloadFile(action.type);
                    } 
                    else if (action.sub_action?.length > 0) {
                        console.log("🔄 [TRAITEMENT DES SOUS-ACTIONS] Exécution des sous-actions...");
                        saveLog("🔄 [TRAITEMENT DES SOUS-ACTIONS] Exécution des sous-actions...");
                        await ReportingActions(action.sub_action, process);
                    } 
                    else {
                        console.log("✔️ [AUCUNE ACTION SUPPLÉMENTAIRE] Pas de sous-actions à exécuter.");
                        saveLog("✔️ [AUCUNE ACTION SUPPLÉMENTAIRE] Pas de sous-actions à exécuter.");
                    }
            
                    await sleep(9000);
                } else {
                    console.warn(`❌ [ÉLÉMENT NON TROUVÉ] L'élément est introuvable : ${action.xpath}`);
                    saveLog(`❌ [ÉLÉMENT NON TROUVÉ] L'élément est introuvable : ${action.xpath}`);
                    await sleep(9000);
                }
            }
            

            else {
                switch (action.action) {
                    case "open_url":
                        console.log(`🌐 [OUVERTURE D'URL] Navigation vers : ${action.url}`);
                        saveLog(`🌐 [OUVERTURE D'URL] Navigation vers : ${action.url}`);
                        window.location.href = action.url;
                        break;
                    
                    case "replace_url_1":
                        let url1 = window.location.href.replace("rescuephone", "password");
                        console.log(`🔄 [REMPLACEMENT D'URL] Remplacement de l'URL : ${window.location.href} ➡️ ${url1}`);
                        saveLog(`🔄 [REMPLACEMENT D'URL] Remplacement de l'URL : ${window.location.href} ➡️ ${url1}`);
                        window.location.href = url1;
                        break;
                        
                    case "replace_url_2":
                        let url2 = window.location.href.replace("signinoptions/rescuephone", "recovery/email");
                        console.log(`🔄 [REMPLACEMENT D'URL] Remplacement de l'URL : ${window.location.href} ➡️ ${url2}`);
                        saveLog(`🔄 [REMPLACEMENT D'URL] Remplacement de l'URL : ${window.location.href} ➡️ ${url2}`);
                        window.location.href = url2;
                        break;
                        
                    
                    case "clear":
                        let clearElement;
                        if (action.obligatoire) {
                            clearElement = await findElementByXPath(action.xpath, undefined, action.obligatoire, action.type);
                        } else {
                            clearElement = await findElementByXPath(action.xpath);
                        }
                    
                        if (clearElement) {
                            clearElement.value = "";
                            console.log(`🧹 [CLEAR] Champ vidé : ${action.xpath}`);
                            saveLog(`🧹 [CLEAR] Champ vidé : ${action.xpath}`);
                        } else {
                            console.warn(`⚠️ [CLEAR] Élément introuvable : ${action.xpath}`);
                            saveLog(`⚠️ [CLEAR] Échec du vidage du champ, élément introuvable : ${action.xpath}`);
                        }
                        break;
                        
                        
            
                    case "click":
                        let clickElement;
                        if (action.obligatoire) {
                            clickElement = await findElementByXPath(action.xpath, undefined, action.obligatoire, action.type);
                        } else {
                            clickElement = await findElementByXPath(action.xpath);
                        }
                    
                        if (clickElement) {
                            clickElement.click();
                            console.log(`✅ [CLICK] Clic effectué sur l'élément avec XPath : ${action.xpath}`);
                            console.log(`✅ [CLICK] Affichage après le clic terminé pour XPath : ${action.xpath}`);
                            saveLog(`✅ [CLICK] Clic effectué avec succès sur l'élément : ${action.xpath}`);
                        } else {
                            console.log(`❌ [CLICK] Élément introuvable pour XPath : ${action.xpath}`);
                            saveLog(`❌ [CLICK] Échec : élément introuvable pour XPath : ${action.xpath}`);
                        }
                        break;
                        
                    case "dispatchEvent":
                        let Element;
                        if (action.obligatoire) {
                            Element = await findElementByXPath(action.xpath, undefined, action.obligatoire, action.type);
                        } else {
                            Element = await findElementByXPath(action.xpath);
                        }
                    
                        if (Element) {
                            // Déclenchement des événements souris
                            Element.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                            Element.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
                            Element.click();
                            console.log(`✅ [DISPATCH EVENT] Événements envoyés à l'élément pour XPath : ${action.xpath}`);
                            saveLog(`✅ [DISPATCH EVENT] Événements 'mousedown', 'mouseup' et 'click' envoyés avec succès à l'élément : ${action.xpath}`);
                        } else {
                            console.log(`❌ [DISPATCH EVENT] Élément introuvable pour XPath : ${action.xpath}`);
                            saveLog(`❌ [DISPATCH EVENT] Échec : élément introuvable pour XPath : ${action.xpath}`);
                        }
                        break;
                        
                        
                    
                    case "dispatchEventTwo":
                        let elementXpath;
                        if (action.obligatoire) {
                            elementXpath = await findElementByXPath(action.xpath, undefined, action.obligatoire, action.type);
                        } else {
                            elementXpath = await findElementByXPath(action.xpath);
                        }
                    
                        if (elementXpath) {
                            // Déclenchement des événements souris deux fois
                            elementXpath.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                            elementXpath.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
                            elementXpath.click();
                    
                            elementXpath.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                            elementXpath.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
                            elementXpath.click();
                    
                            console.log(`✅ [DISPATCH EVENT TWO] Deux événements de souris envoyés à l'élément pour XPath : ${action.xpath}`);
                            saveLog(`✅ [DISPATCH EVENT TWO] Double interaction souris effectuée avec succès sur l'élément : ${action.xpath}`);
                        } else {
                            console.log(`❌ [DISPATCH EVENT TWO] Élément introuvable pour XPath : ${action.xpath}`);
                            saveLog(`❌ [DISPATCH EVENT TWO] Échec : Élément introuvable pour XPath : ${action.xpath}`);
                        }
                        break;
                        
                    
                    case "send_keys":
                        let inputElement;
                        if (action.obligatoire) {
                            inputElement = await findElementByXPath(action.xpath, undefined, action.obligatoire, action.type);
                        } else {
                            inputElement = await findElementByXPath(action.xpath);
                        }
                    
                        if (inputElement) {
                            inputElement.value = action.value;
                            console.log(`✅ [SEND KEYS] Valeur envoyée à l'élément avec XPath : ${action.xpath}`);
                            saveLog(`✅ [SEND KEYS] Texte "${action.value}" saisi dans l'élément : ${action.xpath}`);
                        } else {
                            console.log(`❌ [SEND KEYS] L'élément avec XPath "${action.xpath}" est introuvable.`);
                            saveLog(`❌ [SEND KEYS] Échec : Élément introuvable pour XPath "${action.xpath}"`);
                        }
                        break;
                    
                    case "send_keys_Reply":
                        let elementReply;
                        if (action.obligatoire) {
                            elementReply = await findElementByXPath(action.xpath, undefined, action.obligatoire, action.type);
                        } else {
                            elementReply = await findElementByXPath(action.xpath);
                        }
                    
                        if (elementReply) {
                            elementReply.textContent = ""; 
                            elementReply.textContent = action.value; 
                            console.log(`✅ [SEND KEYS REPLY] Valeur de réponse envoyée à l'élément avec XPath : ${action.xpath}`);
                            saveLog(`✅ [SEND KEYS REPLY] Réponse "${action.value}" envoyée dans l'élément : ${action.xpath}`);
                        } else {
                            console.log(`❌ [SEND KEYS REPLY] L'élément avec XPath "${action.xpath}" est introuvable.`);
                            saveLog(`❌ [SEND KEYS REPLY] Échec : Élément introuvable pour XPath "${action.xpath}"`);
                        }
                        break;
                        
                    
                    
                    case "press_keys":
                        let pressElement;
                        if (action.obligatoire) {
                            pressElement = await findElementByXPath(action.xpath, undefined, action.obligatoire, action.type);
                        } else {
                            pressElement = await findElementByXPath(action.xpath);
                        }
                    
                        if (pressElement) {
                            pressElement.click();
                            console.log(`✅ [PRESS KEYS] Clic effectué sur l'élément avec XPath : ${action.xpath}`);
                            saveLog(`✅ [PRESS KEYS] Clic sur l'élément : ${action.xpath}`);
                        } else {
                            console.log(`❌ [PRESS KEYS] Élément introuvable pour XPath : ${action.xpath}`);
                            saveLog(`❌ [PRESS KEYS] Échec : Élément introuvable pour XPath : ${action.xpath}`);
                        }
                    
                        if (action.sub_action?.length > 0) {
                            console.log("🔄 [PROCESSING SUB-ACTIONS] Traitement des sous-actions dans press_keys...");
                            await ReportingActions(action.sub_action, process);
                        } else {
                            console.log("✔️ [NO SUB-ACTIONS] Pas d'actions supplémentaires à traiter dans press_keys.");
                            saveLog("✔️ [NO SUB-ACTIONS] Aucune sous-action pour press_keys.");
                        }
                        break;
                    
                    case "check":
                        try {
                            const elementExists = await waitForElement(action.xpath, action.wait);
                    
                            if (elementExists) {
                                console.log(`✅ [CHECK] L'élément avec XPath : ${action.xpath} existe.`);
                                saveLog(`✅ [CHECK] Élément trouvé : ${action.xpath}`);
                                return true;
                            } else {
                                console.log(`❌ [CHECK] L'élément avec XPath : ${action.xpath} n'a pas été trouvé.`);
                                saveLog(`❌ [CHECK] Échec : Élément non trouvé : ${action.xpath}`);
                                return false;
                            }
                        } catch (error) {
                            console.log(`❌ [CHECK] Erreur lors de la vérification de l'élément avec XPath : ${action.xpath}`);
                            saveLog(`❌ [CHECK] Erreur : ${error.message} (XPath : ${action.xpath})`);
                            return false;
                        }
                        break;
                    
                        
        
                    case "search_for_link_and_click":
                        try {
                            const mainWindow = window;
                            const openTabs = [];
                            console.log(`🔍 [SEARCH] Recherche de l'élément avec XPath : ${action.xpath}`);
                            saveLog(`🔍 [SEARCH] Recherche de l'élément avec XPath : ${action.xpath}`);
                    
                            const xpathResult = document.evaluate(action.xpath, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
                    
                            if (xpathResult.snapshotLength === 0) {
                                console.log(`❌ [SEARCH] Aucun élément trouvé pour XPath : ${action.xpath}`);
                                saveLog(`❌ [SEARCH] Aucun élément trouvé pour XPath : ${action.xpath}`);
                                break;
                            }
                    
                            const element = xpathResult.snapshotItem(0);
                            const href = element?.href || element?.getAttribute('href');
                    
                            if (!href) {
                                console.log(`🚫 [SEARCH] Aucun lien trouvé pour l’élément avec XPath : ${action.xpath}`);
                                saveLog(`🚫 [SEARCH] Aucun lien trouvé pour XPath : ${action.xpath}`);
                                break;
                            }
                    
                            const newTab = window.open(href, '_blank');
                            if (newTab) {
                                openTabs.push(newTab);
                                console.log(`🌐 [SEARCH] Lien trouvé et nouvel onglet ouvert : ${href}`);
                                saveLog(`🌐 [SEARCH] Lien ouvert : ${href}`);
                            } else {
                                console.error(`❌ [SEARCH] Échec de l’ouverture de l’onglet pour ${href}`);
                                saveLog(`❌ [SEARCH] Impossible d’ouvrir l’onglet pour ${href}`);
                            }
                    
                            for (const tab of openTabs) {
                                if (!tab || tab.closed) {
                                    continue;
                                }
                                tab.focus();
                                await sleep(3000);
                    
                                tab.close();
                                console.log(`💨 [SEARCH] Onglet fermé après interaction pour ${href}`);
                                saveLog(`💨 [SEARCH] Onglet fermé pour ${href}`);
                            }
                    
                            mainWindow.focus();
                        } catch (error) {
                            console.error(`⚠️ [SEARCH] Une erreur est survenue lors de la gestion des onglets : ${error}`);
                            saveLog(`⚠️ [SEARCH] Erreur : ${error.message}`);
                        }
                        break;
                        
                    
                    case 'contact':
                        console.log("🔍 [CONTACT] Recherche de l'élément cible...");
                        saveLog("🔍 [CONTACT] Recherche de l'élément cible...");
                    
                        const targetSpann = document.evaluate(
                            "(//span[@email and @name and @data-hovercard-id])[1]",
                            document,
                            null,
                            XPathResult.FIRST_ORDERED_NODE_TYPE,
                            null
                        ).singleNodeValue;
                    
                        if (!targetSpann) {
                            console.error("🚫 [CONTACT] Élément cible introuvable.");
                            saveLog("🚫 [CONTACT] Élément cible introuvable.");
                            return;
                        }
                    
                        const cleanEmail = targetSpann.getAttribute("email");
                        console.log(`📧 [CONTACT] Email trouvé : ${cleanEmail}`);
                        saveLog(`📧 [CONTACT] Email trouvé : ${cleanEmail}`);
                    
                        const sendMessageAndWait = (message) => {
                            return new Promise((resolve, reject) => {
                                chrome.runtime.sendMessage(message, (response) => {
                                    if (chrome.runtime.lastError) {
                                        reject(chrome.runtime.lastError);
                                    } else {
                                        resolve(response);
                                    }
                                });
                            });
                        };
                    
                        const waitForContinueProcessing = (timeout = 10000) => {
                            return new Promise((resolve, reject) => {
                                const listener = (message, sender, sendResponse) => {
                                    if (message.action === "continueProcessing") {
                                        chrome.runtime.onMessage.removeListener(listener);
                                        resolve(message);
                                    }
                                };
                                chrome.runtime.onMessage.addListener(listener);
                            });
                        };
                    
                        (async () => {
                            try {
                                console.log("📩 [CONTACT] Envoi du message pour interagir avec l'email...");
                                saveLog("📩 [CONTACT] Envoi du message pour interagir avec l'email...");
                    
                                const response = await sendMessageAndWait({
                                    type: "openTabAndInteract",
                                    email: cleanEmail,
                                });
                    
                                if (response.status === "Succès") {
                                    console.log("✔️ [CONTACT] Interaction réussie. En attente de la continuation du traitement.");
                                    saveLog("✔️ [CONTACT] Interaction réussie. En attente de la continuation du traitement.");
                                    
                                    const continueResponse = await waitForContinueProcessing();
                                    saveLog(`🔄 [CONTACT] Continuation du traitement : ${JSON.stringify(continueResponse)}`);
                                } else {
                                    console.error("❌ [CONTACT] Une erreur est survenue :", response);
                                    saveLog(`❌ [CONTACT] Erreur lors de l'interaction : ${JSON.stringify(response)}`);
                                }
                            } catch (error) {
                                console.error("⚠️ [CONTACT] Une erreur est survenue lors de l'envoi du message :", error);
                                saveLog(`⚠️ [CONTACT] Erreur lors de l'envoi du message : ${error.message}`);
                            }
                        })();
                        break;
                    


                    default:
                        console.warn(`⚠️ Action inconnue : ${action.action}`);
                        saveLog(`⚠️ Action inconnue : ${action.action}`);
                                        
                }

                await sleep(9000)
            
                if (action.sleep) {
                    await new Promise((resolve) => setTimeout(resolve, action.sleep * 1000));
                }            
            }

  
        } catch (error) {
            console.error(`❌ [ERROR] Error while executing the action ${action.action}:`, error);
            saveLog(`❌ [ERROR] Erreur lors de l'exécution de l'action ${action.action}: ${error.message}`);
                    
        }
    }

    return true ;
}














function sleep(ms) {
    console.log(`⏳ Suspension du processus pour ${ms} millisecondes...`);
    saveLog(`⏳ Pause de ${ms} millisecondes`);
    return new Promise(resolve => setTimeout(resolve, ms));
}





function genererIdUnique() {
    const timestamp = Date.now().toString(36); // Timestamp en base 36
    const random = Math.random().toString(36).substring(2, 10); // Générer une chaîne aléatoire en base 36
    const uniqueId = `${timestamp}-${random}`; // Combiner timestamp et aléatoire
    
    console.log("🆔 ID unique généré :", uniqueId);

    return uniqueId;
}







// Fonction pour ajouter des identifiants uniques aux actions
function addUniqueIdsToActions(actions) {
    console.log("🔧 Ajout d'IDs uniques aux actions...");
    
    actions.forEach(action => {
        action.id = genererIdUnique();
        console.log(`🆔 ID unique ajouté : ${action.id}`); 
        
        if (action.sub_action && Array.isArray(action.sub_action)) {
            console.log("🔁 Recherche de sous-actions pour ajouter des IDs...");
            addUniqueIdsToActions(action.sub_action); 
        }
    });

    console.log("✅ Ajout des IDs uniques terminé !");
}







chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    if (message.action === "fillForm") {
        const email = message.email;
        console.log("📝 Début du remplissage du formulaire...");

        sendResponse({ status: "Formulaire rempli avec succès." });

        try {
            // Recherche du champ email
            const emailInput = document.evaluate(
                "//input[@aria-label='E-mail']",
                document,
                null,
                XPathResult.FIRST_ORDERED_NODE_TYPE,
                null
            ).singleNodeValue;

            if (emailInput) {
                console.log("✏️ Champ email trouvé, remplissage en cours...");
                
                emailInput.value = email;
                emailInput.dispatchEvent(new Event("input", { bubbles: true }));
                console.log(`📧 Email renseigné : ${email}`);

                await sleep(2000); // Attente avant de cliquer sur le bouton de sauvegarde

                // Recherche du bouton de sauvegarde
                const saveButton = document.evaluate(
                    "//button[@aria-label='Enregistrer']",
                    document,
                    null,
                    XPathResult.FIRST_ORDERED_NODE_TYPE,
                    null
                ).singleNodeValue;

                if (saveButton) {
                    console.log("💾 Bouton de sauvegarde trouvé, envoi en cours...");
                    
                    saveButton.click();
                    console.log("✅ Formulaire soumis avec succès !");
                    
                    await sleep(9000);  // Attente après soumission du formulaire
                } else {
                    console.error("❌ Bouton de sauvegarde introuvable.");
                }

                // Envoi d'un message pour fermer l'onglet
                chrome.runtime.sendMessage(
                    { action: "closeTab", success: true },
                    (response) => {
                        console.log("🔒 Onglet fermé avec succès !");
                    }
                );

            } else {
                console.error("❌ Champ d'email introuvable.");
            }

        } catch (error) {
            console.error("❌ Erreur lors du remplissage du formulaire :", error);
            sendResponse({ status: "Erreur lors du remplissage du formulaire.", error: error.message });
        }
    }
});
