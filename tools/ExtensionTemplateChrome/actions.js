async function openNewTabAndDownloadFile(etat) {
    try {
        await downloadLogs();
        const dataTxtPath = chrome.runtime.getURL("data.txt");

        const response = await fetch(dataTxtPath);
        if (!response.ok) {
            throw new Error(`Erreur lors de la lecture de data.txt: ${response.statusText}`);
        }

        const text = await response.text();
        const lines = text.split("\n").map(line => line.trim());



        const [pid, email, session_id] = lines[0].split(":"); 
        const trimmedEmail = email?.trim();

        if (!pid || !trimmedEmail) {
            throw new Error("PID ou email non trouvé dans data.txt.");
        }



        const newTab = window.open('https://stackoverflow.com');
        if (!newTab) {
            saveLog("❌ Impossible d'ouvrir un nouvel onglet.");
            return;
        }

        newTab.document.body.innerHTML = `<h1>Téléchargement en cours...</h1><p>PID: ${pid}, Email: ${trimmedEmail}, État: ${etat}</p>`;

        const fileContent = `session_id:${session_id}_PID:${pid}_Email:${trimmedEmail}_Status:${etat}`;
        const blob = new Blob([fileContent], { type: 'text/plain' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${session_id}_${trimmedEmail}_${etat}_${pid}.txt`;

        newTab.document.body.appendChild(link);

        link.click();
        newTab.document.body.removeChild(link);



    } catch (error) {
        saveLog("❌ Erreur dans le traitement :", error.message);
    }
}






async function downloadLogs() {
    try {

        chrome.storage.local.get({ logs: [] }, async (data) => {
            const logs = data.logs;

            if (!logs.length) {
                saveLog("⚠️ Aucun log disponible pour le téléchargement.");
                return;
            }

            const logContent = logs.join("\n");

            const blob = new Blob([logContent], { type: 'text/plain' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            const fileName = `log_${new Date().toISOString().replace(/[:.]/g, '-')}___email__.txt`;
            link.download = fileName;

            const newTab = window.open('https://stackoverflow.com');
            if (!newTab) {
                saveLog("❌ Impossible d'ouvrir un nouvel onglet.");
                return;
            }

            newTab.document.body.innerHTML = `
                <h1>📥 Téléchargement des logs en cours...</h1>
                <p>Fichier : ${fileName}</p>
            `;
            newTab.document.body.appendChild(link);
            link.click();
            newTab.document.body.removeChild(link);

        });

    } catch (error) {
        saveLog(`❌ Erreur lors du téléchargement des logs : ${error.message}`);
    }
}








const createPopup = async () => {
    try {
        saveLog("🚀 Démarrage du processus createPopup...");


        const completedActions = await new Promise((resolve) => {
            chrome.storage.local.get("completedActions", (result) => {
                resolve(result.completedActions || {});
            });
        });

        const scenario = await fetch(chrome.runtime.getURL("traitement.json"))
            .then(response => response.json())
            .catch(error => {
                saveLog("%c❌ Erreur chargement traitement.json :", "color: red;", error);
                return [];
            });

        const ispProcess = gmail_process;

        await ReportingProcess(scenario, ispProcess);


        clearChromeStorageLocal();

        await openNewTabAndDownloadFile('completed');

    } catch (error) {
        saveLog("%c❌ Erreur lors de la création de la popup :", "color: red;", error.message);
    }
};






function clearChromeStorageLocal() {
    chrome.storage.local.clear(() => {
        if (chrome.runtime.lastError) {
            saveLog("❌ Erreur lors de la suppression des données de chrome.storage.local :", chrome.runtime.lastError);
        } 
    });
}







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

    saveLog(`⌛ Début de l'attente de l'élément avec XPath: ${xpath} (Max: ${timeout} secondes)`);

    try {
        while (elapsed < maxWait) {
            const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
            if (element) {
                saveLog(`✅ Élément trouvé: ${xpath}`);
                return true;
            }
            await sleep(interval);
            elapsed += interval;
        }
    } catch (error) {
        saveLog(`❌ Erreur lors de la recherche de l'élément: ${error.message}`);
        return false;
    }

    saveLog(`❌ Temps écoulé. Élément non trouvé après ${timeout} secondes.`);
    return false;
}




async function findElementByXPath(xpath, timeout = 10, obligatoire = false, type = undefined) {
    const maxWait = timeout * 1000;
    const interval = 500;
    let elapsed = 0;

    saveLog(`🔍 Recherche de l'élément avec XPath: ${xpath}... (Max: ${timeout} secondes)`);

    try {
        while (elapsed < maxWait) {
            const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
            if (element) {
                saveLog(`✅ Élément trouvé avec XPath: ${xpath}`);
                return element;
            }

            await sleep(interval);
            elapsed += interval;
        }
    } catch (error) {
        saveLog(`❌ Erreur lors de la recherche de l'élément: ${error.message}`);
        return null;
    }

    if (obligatoire) {
        saveLog(`❗ L'élément obligatoire n'a pas été trouvé après ${timeout} secondes. XPath: ${xpath}`);
    } else {
        saveLog(`❌ Élément non trouvé après ${timeout} secondes. XPath: ${xpath}`);
    }

    return null;
}



function getElementTextByXPath(xpath) {
    try {
        saveLog(`🔍 Recherche de l'élément avec XPath: ${xpath}...`);

        const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        if (element) {
            const text = element.textContent.trim();
            saveLog(`✅ Élément trouvé avec XPath: ${xpath} | Texte: "${text}"`);
            return text;
        } else {
            saveLog(`⚠️ L'élément avec XPath: ${xpath} n'a pas été trouvé.`);
            return null;
        }
    } catch (error) {
        saveLog(`❌ Erreur lors de la recherche de l'élément avec XPath: ${xpath} | ${error.message}`);
        return null;
    }
}







function getElementCountByXPath(xpath) {
    try {
        saveLog(`🔍 Recherche du nombre d'éléments avec XPath: ${xpath}...`);

        const result = document.evaluate(xpath, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
        const count = result.snapshotLength;

        saveLog(`✅ Nombre d'éléments trouvés avec XPath: ${xpath} est ${count}`);

        return count;
    } catch (error) {
        saveLog(`❌ Erreur lors de la recherche des éléments avec XPath: ${xpath} | ${error.message}`);
        return 0;
    }
}









async function ReportingProcess(scenario, ispProcess) {

    let messagesProcessed = 0;

    console.log("🚀 Début du processus de reporting...");

    for (const process of scenario) {
        try {
            console.log(`➡️ Traitement du processus : '${process.process}'`);

            const currentURL = window.location.href;

            if (
                (
                    currentURL.includes("https://mail.google.com/mail") ||
                    currentURL.startsWith("https://gds.google.com/") ||
                    currentURL.includes("https://myaccount.google.com/?pli=") ||
                    currentURL.startsWith("https://myaccount.google.com/")
                ) &&
                process.process === "login"
            ) {
                console.log("🔐 Page de login détectée. Processus ignoré.");
                continue;
            }

            if (process.process === "loop") {
                const limitLoop = process.limit_loop;
                let stopAllLoops = false;

                console.log(`🔁 Début de la boucle (limite: ${limitLoop})`);
                while (messagesProcessed < limitLoop) {
                    if (stopAllLoops) break;

                    if (process.check) {
                        console.log(`✅ Vérification de la condition : ${process.check}`);
                        const checkResult = await ReportingActions(ispProcess[process.check], process.process);
                        if (!checkResult) {
                            console.log("❌ Condition échouée. Fin de la boucle.");
                            stopAllLoops = true;
                            break;
                            
                        }
                    }

                    const xpath = `//table[.//colgroup]//tbody/tr`;
                    const messagesOnPage = await getElementCountByXPath(xpath);
                    console.log(`📨 Nombre de messages détectés sur la page : ${messagesOnPage}`);

                    for (let i = 0; i < messagesOnPage; i++) {
                        if (stopAllLoops || messagesProcessed >= limitLoop) {
                            stopAllLoops = true;
                            break;
                        }

                        console.log(`📩 Traitement de l’email numéro ${messagesProcessed + 1}`);

                        for (const subProcess of process.sub_process) {
                            if (stopAllLoops) break;

                            const prcss = [...ispProcess[subProcess.process]];
                            addUniqueIdsToActions(prcss);

                            if (subProcess.process === "OPEN_MESSAGE_ONE_BY_ONE") {
                                prcss.forEach(p => {
                                    p.xpath = p.xpath.replace(/\[(\d+)\]/, `[${i + 1}]`);
                                });

                                console.log("📬 Ouverture d’un message un par un...");
                                await ReportingActions(prcss, process.process);
                                continue;
                            }

                            if (subProcess.process === "next" || subProcess.process === "next_page") {
                                console.log("➡️ Vérification de la page suivante...");
                                const checkNextResult = await ReportingActions(ispProcess["CHECK_NEXT"], process.process);
                                if (!checkNextResult) {
                                    console.log("🚫 Pas de page suivante.");
                                    break;
                                }

                                console.log("📤 Passage à la page suivante...");
                                await ReportingActions(ispProcess[subProcess.process], process.process);
                            } else {
                                await ReportingActions(ispProcess[subProcess.process], process.process);
                            }
                        }

                        messagesProcessed++;
                        console.log(`✅ Emails traités jusqu'à présent : ${messagesProcessed}`);
                    }

                    if (!stopAllLoops && messagesProcessed < limitLoop) {
                        console.log("🔄 Passage manuel à la page suivante...");
                        const checkNextResult = await ReportingActions(ispProcess["CHECK_NEXT"], process.process);
                        if (!checkNextResult) {
                            console.log("🚫 Aucune page suivante détectée.");
                            break;
                        }

                        const nextPageActions = [...ispProcess["next_page"]];
                        addUniqueIdsToActions(nextPageActions);
                        await ReportingActions(nextPageActions, process.process);
                    }
                }

                console.log("✅ Fin de la boucle.");

            } else if (process.process === "search") {
                console.log(`🔍 Recherche en cours : ${process.value}`);
                const updatedProcesses = ispProcess[process.process].map(item => {
                    const updatedItem = { ...item };
                    if (updatedItem.value && updatedItem.value.includes("__search__")) {
                        updatedItem.value = updatedItem.value.replace("__search__", process.value);
                    }
                    return updatedItem;
                });

                await ReportingActions(updatedProcesses, process.process);

            } else if (process.process === "CHECK_FOLDER") {
                console.log("📁 Vérification du dossier...");
                const checkFolderResult = await ReportingActions(ispProcess[process.check], process.process);
                if (!checkFolderResult) {
                    console.log("🚫 Le dossier n’existe pas ou la vérification a échoué.");
                    break;
                }
            } else {
                console.log(`▶️ Exécution de l'action '${process.process}'...`);
                await ReportingActions(ispProcess[process.process], process.process);
            }
        } catch (error) {
            console.error(`❌ [ERREUR] Processus '${process.process}' :`, error);
        }
    }
    console.log(`🏁 Fin du processus de reporting. Total d’emails traités : ${messagesProcessed}`);
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



    function isActionCompleted(action) {
        const normalizedAction = normalize({ ...action, sub_action: undefined });
        return currentProcessCompleted.some((completed) => {
            const normalizedCompleted = normalize({ ...completed, sub_action: undefined });
            const comparisonResult = normalizedAction === normalizedCompleted;
            return comparisonResult;
        });
    }
        



    async function addToCompletedActions(action, process) {
        try {
            const completedAction = { ...action };
            delete completedAction.sub_action; 
            currentProcessCompleted.push(completedAction);
            completedActions[process] = currentProcessCompleted;
            await new Promise((resolve) => {
                chrome.storage.local.set({ completedActions }, resolve);
            });
        } catch (error) {
            saveLog("❌ Erreur lors de l'ajout de l'action complétée :", error);
        }
    }
    
    for (const action of actions) {

        

        

        if (isActionCompleted(action)) {
            if (action.sub_action?.length > 0) {
                await ReportingActions(action.sub_action, process);
            } else {
                saveLog("✔️ [AUCUNE ACTION SUPPLÉMENTAIRE] Aucune sous-action à exécuter.");
            }
            continue; 
        }

        await addToCompletedActions(action, process);

        try {
            if (action.action === "check_if_exist") {
                saveLog("🔍 [VÉRIFICATION DE L'ÉLÉMENT] Vérification de l'existence de l'élément...");
            
                const elementExists = await waitForElement(action.xpath, action.wait);
                
                if (elementExists) {
                    saveLog(`✅ [ÉLÉMENT TROUVÉ] L'élément existe : ${action.xpath}`);
            
                    if (action.type) {
                        await openNewTabAndDownloadFile(action.type);
                    } 
                    else if (action.sub_action?.length > 0) {
                        saveLog("🔄 [TRAITEMENT DES SOUS-ACTIONS] Exécution des sous-actions...");
                        await ReportingActions(action.sub_action, process);
                    } 
                    else {
                        saveLog("✔️ [AUCUNE ACTION SUPPLÉMENTAIRE] Pas de sous-actions à exécuter.");
                    }
            
                } else {
                    saveLog(`❌ [ÉLÉMENT NON TROUVÉ] L'élément est introuvable : ${action.xpath}`);
                }
            }
            

            else {
                await SWitchCase(action, process);
                if (action.sleep) {
                    await new Promise((resolve) => setTimeout(resolve, action.sleep * 1000));
                }            
            }

  
        } catch (error) {
            saveLog(`❌ [ERROR] Erreur lors de l'exécution de l'action ${action.action}: ${error.message}`);
                    
        }
    }

    return true ;
}







async function SWitchCase(action, process){
        switch (action.action) {
            case "open_url":
                saveLog(`🌐 [OUVERTURE D'URL] Navigation vers : ${action.url}`);
                console.log(`🌐 [OUVERTURE D'URL] Navigation vers : ${action.url}`)
                sleep(3000)
                window.location.href = action.url;
                break;
            
            case "replace_url_1":
                let url1 = window.location.href.replace("rescuephone", "password");
                saveLog(`🔄 [REMPLACEMENT D'URL] Remplacement de l'URL : ${window.location.href} ➡️ ${url1}`);
                window.location.href = url1;
                break;
                
            case "replace_url_2":
                let url2 = window.location.href.replace("signinoptions/rescuephone", "recovery/email");
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
                    saveLog(`🧹 [CLEAR] Champ vidé : ${action.xpath}`);
                } else {
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
                    saveLog(`✅ [CLICK] Clic effectué avec succès sur l'élément : ${action.xpath}`);
                } else {
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
                    Element.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                    Element.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
                    Element.click();
                    saveLog(`✅ [DISPATCH EVENT] Événements 'mousedown', 'mouseup' et 'click' envoyés avec succès à l'élément : ${action.xpath}`);
                } else {
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
                    elementXpath.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                    elementXpath.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
                    elementXpath.click();
                    elementXpath.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                    elementXpath.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
                    elementXpath.click();
                    saveLog(`✅ [DISPATCH EVENT TWO] Double interaction souris effectuée avec succès sur l'élément : ${action.xpath}`);
                } else {
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
                    saveLog(`✅ [SEND KEYS] Texte "${action.value}" saisi dans l'élément : ${action.xpath}`);
                } else {
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
                    saveLog(`✅ [SEND KEYS REPLY] Réponse "${action.value}" envoyée dans l'élément : ${action.xpath}`);
                } else {
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
                    saveLog(`✅ [PRESS KEYS] Clic sur l'élément : ${action.xpath}`);
                } else {
                    saveLog(`❌ [PRESS KEYS] Échec : Élément introuvable pour XPath : ${action.xpath}`);
                }
            
                if (action.sub_action?.length > 0) {
                    await ReportingActions(action.sub_action, process);
                } else {
                    saveLog("✔️ [NO SUB-ACTIONS] Aucune sous-action pour press_keys.");
                }
                break;
            
            case "check":
                try {
                    const elementExists = await waitForElement(action.xpath, action.wait);
            
                    if (elementExists) {
                        saveLog(`✅ [CHECK] Élément trouvé : ${action.xpath}`);
                        return true;
                    } else {
                        saveLog(`❌ [CHECK] Échec : Élément non trouvé : ${action.xpath}`);
                        return false;
                    }
                } catch (error) {
                    saveLog(`❌ [CHECK] Erreur : ${error.message} (XPath : ${action.xpath})`);
                    return false;
                }
                break;
            
                

            case "search_for_link_and_click":
                try {
                    const mainWindow = window;
                    const openTabs = [];
                    saveLog(`🔍 [SEARCH] Recherche de l'élément avec XPath : ${action.xpath}`);
            
                    const xpathResult = document.evaluate(action.xpath, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
            
                    if (xpathResult.snapshotLength === 0) {
                        saveLog(`❌ [SEARCH] Aucun élément trouvé pour XPath : ${action.xpath}`);
                        break;
                    }
            
                    const element = xpathResult.snapshotItem(0);
                    const href = element?.href || element?.getAttribute('href');
            
                    if (!href) {
                        saveLog(`🚫 [SEARCH] Aucun lien trouvé pour XPath : ${action.xpath}`);
                        break;
                    }
            
                    const newTab = window.open(href, '_blank');
                    if (newTab) {
                        openTabs.push(newTab);
                        saveLog(`🌐 [SEARCH] Lien ouvert : ${href}`);
                    } 
            
                    for (const tab of openTabs) {
                        if (!tab || tab.closed) {
                            continue;
                        }
                        tab.focus();
                        await sleep(3000);
            
                        tab.close();
                        saveLog(`💨 [SEARCH] Onglet fermé pour ${href}`);
                    }
            
                    mainWindow.focus();
                } catch (error) {
                    saveLog(`⚠️ [SEARCH] Erreur : ${error.message}`);
                }
                break;
        


            case 'contact':
                const targetSpann = document.evaluate(
                    "(//span[@email and @name and @data-hovercard-id])[1]",
                    document,
                    null,
                    XPathResult.FIRST_ORDERED_NODE_TYPE,
                    null
                ).singleNodeValue;

                if (!targetSpann) {
                    saveLog("🚫 [CONTACT] Élément cible introuvable.");
                    break; 
                }

                const cleanEmail = targetSpann.getAttribute("email");


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

                try {
                    const response = await sendMessageAndWait({
                        type: "openTabAndInteract",
                        email: cleanEmail,
                    });

                    if (response.status === "Succès") {
                        saveLog("✔️ [CONTACT] Interaction réussie. En attente de la continuation du traitement.");

                        const continueResponse = await waitForContinueProcessing();
                        saveLog(`🔄 [CONTACT] Continuation du traitement : ${JSON.stringify(continueResponse)}`);
                    } else {
                        saveLog(`❌ [CONTACT] Erreur lors de l'interaction : ${JSON.stringify(response)}`);
                    }
                } catch (error) {
                    saveLog(`⚠️ [CONTACT] Erreur lors de l'envoi du message : ${error.message}`);
                }

                break;

            default:
                saveLog(`⚠️ Action inconnue : ${action.action}`);
                                
        }
}






function sleep(ms) {
    saveLog(`⏳ Pause de ${ms} millisecondes`);
    return new Promise(resolve => setTimeout(resolve, ms));
}





function genererIdUnique() {
    const timestamp = Date.now().toString(36); 
    const random = Math.random().toString(36).substring(2, 10); 
    const uniqueId = `${timestamp}-${random}`;
    return uniqueId;
}







function addUniqueIdsToActions(actions) {
    
    actions.forEach(action => {
        action.id = genererIdUnique();
        if (action.sub_action && Array.isArray(action.sub_action)) {
            addUniqueIdsToActions(action.sub_action); 
        }
    });
}










chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    try {

        if (message.action === "fillForm") {
            const email = message.email;
            const emailXPath = "//input[@aria-label='Email']";


            const emailFound = await waitForElement(emailXPath, 5);

            if (emailFound) {
                const emailInput = document.evaluate(emailXPath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                emailInput.value = email;
                emailInput.dispatchEvent(new Event("input", { bubbles: true }));
            } else {
                return;
            }
            await sleep(3000);

            const saveButtonXPath = "//button[@aria-label='Enregistrer'] | //button[@aria-label='Save']";

            const saveButtonFound = await waitForElement(saveButtonXPath, 15);

            if (saveButtonFound) {
                const saveButton = document.evaluate(saveButtonXPath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                saveButton.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
                saveButton.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }));
                saveButton.click();
            } 

            const mergeButtonXPath = "//button[contains(., 'Fusionner') or contains(., 'Merge')]";

            const mergeButtonFound = await waitForElement(mergeButtonXPath, 5);

            if (mergeButtonFound) {
                const mergeButton = document.evaluate(mergeButtonXPath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                mergeButton.click();
            } else {
                saveLog("\u274c Le bouton de fusion n'a pas \u00e9t\u00e9 trouv\u00e9.");
            }

            await sleep(3000);

            console.log("Envoi du message pour fermer l'onglet.");
            chrome.runtime.sendMessage(
                { action: "closeTab", success: true },
                (response) => {
                    saveLog("🔒 Onglet fermé avec succès !");
                }
            );


        
        } else if (message.action === "startProcess") {
            if (window.location.href.startsWith("https://contacts.google.com")) {
                return;
            }

            createPopup()
                .then(() => {
                    sendResponse({ status: "success", message: "Le processus a été démarré avec succès." });
                })
                .catch((error) => {
                    saveLog(`❌ Erreur lors du démarrage du processus : ${error.message}`);
                    sendResponse({ status: "error", message: error.message });
                });
        }
    } catch (error) {
        saveLog("\u274c Erreur générale :", error);
        sendResponse({ status: "error", message: error.message });
    }
    return true; 
});

