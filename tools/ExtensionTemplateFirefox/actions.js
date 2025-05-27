async function SendMessageDownloadFile(etat) {
    await browser.runtime.sendMessage({ action: "downloadFile", etat });

}




const createPopup = async () => {
    document.title = "EXT:" + "__email__"; 

    try {
      // 1. Récupérer completedActions depuis le stockage
      const completedActions = await new Promise((resolve, reject) => {
        browser.storage.local.get("completedActions", (result) => {
          if (browser.runtime.lastError) {
            console.error(`❌ Erreur browser.storage.local.get: ${browser.runtime.lastError.message}`);
            return reject(new Error(browser.runtime.lastError.message));
          }
          resolve(result.completedActions || {});
        });
      });
  
      // 2. Charger le scénario depuis traitement.json
      const scenarioUrl = browser.runtime.getURL("traitement.json");
      const scenarioResponse = await fetch(scenarioUrl);
      if (!scenarioResponse.ok) {
        throw new Error(`Erreur HTTP ${scenarioResponse.status} lors du chargement de traitement.json`);
      }
      const scenario = await scenarioResponse.json();
  
      // 3. Importer dynamiquement gmail_process.js
      const processUrl = browser.runtime.getURL("gmail_process.js");
      const module = await import(processUrl);
      const ispProcess = module.gmail_process || module.default || module;
      if (typeof ispProcess !== 'object' || ispProcess === null) {
        throw new Error("❌ Export 'gmail_process' ou 'default' non trouvé ou n'est pas un objet dans gmail_process.js");
      }
      console.groupCollapsed("%c[ReportingProcess] Contenu de ispProcess", "color: #2980b9; font-weight: bold;");
      console.dir(ispProcess);
      console.groupEnd();
  

      await ReportingProcess(scenario, ispProcess);
  


      await SendMessageDownloadFile('completed');
  
      await clearbrowserStorageLocal();
  
    } catch (error) {
      console.error("❌ Erreur générale lors de l'exécution de createPopup:", error);
    }
};
  



function clearbrowserStorageLocal() {
    browser.storage.local.clear().catch(() => {});
}







function saveLog(message) {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${message}`;
    
    const emojis = ["🔔"];
    const randomEmoji = emojis[Math.floor(Math.random() * emojis.length)];

    browser.storage.local.get({ logs: [] }, (data) => {
        const updatedLogs = [...(data.logs || []), `${randomEmoji} ${logMessage}`];
        browser.storage.local.set({ logs: updatedLogs });
    });

}






async function waitForElement(xpath, timeout = 30) {
  const maxWait = timeout * 1000;
  const interval = 1000; // Vérifie toutes les secondes
  let elapsed = 0;

  const startMsg = `⌛ Début de l'attente de l'élément avec XPath: ${xpath} (Max: ${timeout} secondes)`;
  saveLog(startMsg);

  try {
    while (elapsed < maxWait) {

      const element = document.evaluate(
        xpath,
        document,
        null,
        XPathResult.FIRST_ORDERED_NODE_TYPE,
        null
      ).singleNodeValue;

      if (element) {
        const successMsg = `✅ Élément trouvé: ${xpath}`;
        saveLog(successMsg);
        return true; 
      }

      await sleep(interval);
      elapsed += interval;
    }
  } catch (error) {
    saveLog(errorMsg); 
    console.error(`[waitForElement] ${errorMsg}`, error);
    return false; 
  }

  const timeoutMsg = `❌ Temps écoulé (${timeout}s). Élément non trouvé pour XPath: ${xpath}`; 
  saveLog(timeoutMsg);
  return false; 
}






async function findElementByXPath(xpath, timeout = 10, obligatoire = false, type = undefined) {
    const maxWait = timeout * 1000;
    const interval = 500; 
    let elapsed = 0;

    const startMsg = `🔍 Recherche de l'élément avec XPath: ${xpath}... (Max: ${timeout} secondes)`;
    saveLog(startMsg);

    try {
        while (elapsed < maxWait) {
            const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

            if (element) {
                const successMsg = `✅ Élément trouvé avec XPath: ${xpath}`;
                saveLog(successMsg);
                return element; 
            }

            await sleep(interval);
            elapsed += interval;
        }
    } catch (error) {
        const errorMsg = `❌ Erreur lors de la recherche XPath (${xpath}): ${error.message}`;
        saveLog(errorMsg); 
        return null; 
    }

    if (obligatoire) {
        saveLog( `❗ Élément obligatoire non trouvé après ${timeout}s. XPath: ${xpath}`); 
    } else {
        saveLog( `⚠️ Élément non trouvé après ${timeout}s (optionnel). XPath: ${xpath}`); 
    }

    return null; 
}



function getElementTextByXPath(xpath) {
    saveLog(`🔍 Recherche de l'élément avec XPath: ${xpath}...`);
    try {
        const element = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

        if (element) {
            const text = element.textContent ? element.textContent.trim() : ''; 
            saveLog(`✅ Élément trouvé avec XPath: ${xpath} | Texte: "${text}"`);
            return text;
        } else {
            saveLog(`⚠️ L'élément avec XPath: ${xpath} n'a pas été trouvé.`);
            return null;
        }
    } catch (error) {
        saveLog( `❌ Erreur lors de la recherche XPath (${xpath}): ${error.message}`); 
        return null;
    }

}






function getElementCountByXPath(xpath) {
    saveLog(`🔍 Recherche du nombre d'éléments avec XPath: ${xpath}...`);

    try {
        const result = document.evaluate(xpath, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
        const count = result.snapshotLength;
        saveLog(`✅ Nombre d'éléments trouvés avec XPath: ${xpath} est ${count}`);
        return count; 

    } catch (error) {
        const errorMsg = `❌ Erreur lors du comptage XPath (${xpath}): ${error.message}`;
        saveLog(errorMsg); 

        return 0; 
    }
}














async function ReportingProcess(scenario, ispProcess) {

    let messagesProcessed = 0;

    for (const process of scenario) {
        try {
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
                continue;
            }

            if (process.process === "loop") {
                const limitLoop = process.limit_loop;
                let stopAllLoops = false;
                while (messagesProcessed < limitLoop) {
                    if (stopAllLoops) break;

                    if (process.check) {
                        const checkResult = await ReportingActions(ispProcess[process.check], process.process);
                        if (!checkResult) {
                            stopAllLoops = true;
                            break;
                        }
                    }

                    const xpath = `//table[.//colgroup]//tbody/tr`;
                    const messagesOnPage = await getElementCountByXPath(xpath);

                    for (let i = 0; i < messagesOnPage; i++) {
                        if (stopAllLoops || messagesProcessed >= limitLoop) {
                            stopAllLoops = true;
                            break;
                        }


                        for (const subProcess of process.sub_process) {
                            if (stopAllLoops) break;

                            const prcss = [...ispProcess[subProcess.process]];
                            addUniqueIdsToActions(prcss);

                            if (subProcess.process === "OPEN_MESSAGE_ONE_BY_ONE") {
                                prcss.forEach(p => {
                                    p.xpath = p.xpath.replace(/\[(\d+)\]/, `[${i + 1}]`);
                                });

                                await ReportingActions(prcss, process.process);
                                continue;
                            }

                            if (["next", "next_page"].includes(subProcess.process)) {
                                const checkNextResult = await ReportingActions(ispProcess["CHECK_NEXT"], process.process);
                                if (!checkNextResult) {
                                    break;
                                }
                                await ReportingActions(ispProcess[subProcess.process], process.process);
                            } else {
                                await ReportingActions(ispProcess[subProcess.process], process.process);
                            }
                        }

                        messagesProcessed++;
                    }

                    if (!stopAllLoops && messagesProcessed < limitLoop) {
                        const checkNextResult = await ReportingActions(ispProcess["CHECK_NEXT"], process.process);
                        if (!checkNextResult) {
                            break;
                        }

                        const nextPageActions = [...ispProcess["next_page"]];
                        addUniqueIdsToActions(nextPageActions);
                        await ReportingActions(nextPageActions, process.process);
                    }
                }


            } else if (process.process === "search") {
                const updatedProcesses = ispProcess[process.process].map(item => {
                    const updatedItem = { ...item };
                    if (updatedItem.value?.includes("__search__")) {
                        updatedItem.value = updatedItem.value.replace("__search__", process.value);
                    }
                    return updatedItem;
                });

                await ReportingActions(updatedProcesses, process.process);

            } else if (process.process === "CHECK_FOLDER") {
                const checkFolderResult = await ReportingActions(ispProcess[process.check], process.process);
                if (!checkFolderResult) {
                    break;
                }

            } else {
                await ReportingActions(ispProcess[process.process], process.process);
            }

        } catch (error) {
            console.error(`💣❗ Erreur dans le processus '${process.process}' :`, error);
        }
    }

}





async function ReportingActions(actions, process) {
    const logPrefix = `[ReportingActions(process: ${process})]`;


    let completedActions = {};
    let currentProcessCompleted = [];

    try {
        completedActions = await new Promise((resolve, reject) => {
            browser.storage.local.get("completedActions", (result) => {
                if (browser.runtime.lastError) {
                    const errorMsg = `Erreur browser.storage.get: ${browser.runtime.lastError.message}`;
                    return reject(new Error(errorMsg));
                }
                resolve(result.completedActions || {}); 
            });
        });
        currentProcessCompleted = completedActions[process] || [];

 

    } catch (error) {
        return false; 
    }

    function normalize(obj) {
        const sortedKeys = Object.keys(obj || {}).sort();
        const normalizedObj = sortedKeys.reduce((acc, key) => {
            if (key !== 'sub_action') { 
                 acc[key] = obj[key];
            }
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

    async function addToCompletedActions(action, process) {


        try {
            const completedAction = { ...action };
            delete completedAction.sub_action;

            const normalizedNew = normalize(completedAction);
             
            if (!currentProcessCompleted.some(existing => normalize(existing) === normalizedNew)) {
                currentProcessCompleted.push(completedAction);
                completedActions[process] = currentProcessCompleted; 
                await new Promise((resolve, reject) => {
                    browser.storage.local.set({ completedActions }, () => {
                        if (browser.runtime.lastError) {
                            const errorMsg = `Erreur browser.storage.set: ${browser.runtime.lastError.message}`;
                            return reject(new Error(errorMsg));
                        }
                        saveLog(`✅ Action ajoutée avec succès aux actions complétées dans le stockage.`);
                        resolve();
                    });
                });
            
            } else {
                saveLog(`⚠️ Action déjà présente dans la liste des complétées pour cette session. Non ajoutée à nouveau.`);
            }
        } catch (error) {
            saveLog(`❌ Erreur critique lors de l'ajout de l'action complétée: ${error.message}`);
        }
    }

    for (const action of actions) {




        if (isActionCompleted(action)) {
            if (action.sub_action && action.sub_action.length > 0) {
                await ReportingActions(action.sub_action, process);
            }
            continue; 
        }

        await addToCompletedActions(action, process);

        try {
            if (action.action === "check_if_exist") {
                saveLog(`[check_if_exist] 🔍 Vérification de l'existence de l'élément: ${action.xpath} (Timeout: ${action.wait || 'N/A'}s)`);

                const elementExists = await waitForElement(action.xpath, action.wait); 

                if (elementExists) {
                    saveLog(`✅ Élément trouvé: ${action.xpath}`);

                    if (action.type) {
                        await SendMessageDownloadFile(action.type); 
                    } else if (action.sub_action && action.sub_action.length > 0) {
                        await ReportingActions(action.sub_action, process); 
                    } else {
                        saveLog(`✔️ Élément trouvé, mais aucune action 'type' ou 'sub_action' spécifiée.`);
                    }
                } else {
                    saveLog(`⚠️ Élément non trouvé après attente: ${action.xpath}`);
                }
            }
            else {
             
                await SWitchCase(action, process); 
           

                if (action.sleep && action.sleep > 0) {
                     const sleepDuration = action.sleep * 1000;
                     await sleep(sleepDuration);
                     saveLog(`✅ Pause terminée.`);
                }
            }
            saveLog(`✅ Action exécutée avec succès.`);

        } catch (error) {
            const errorMsg = `❌ Erreur lors de l'exécution: ${error.message}`;
            saveLog(`${actionPrefix} ${errorMsg}`);
        }
    }

    return true; 
}





async function SWitchCase(action, process){
        switch (action.action) {
            case "open_url":
                saveLog(`🌐 [OUVERTURE D'URL] Navigation vers : ${action.url}`);
                window.location.href = action.url;
                break;
            
            case "replace_url_1":
                let url1 = window.location.href.replace("rescuephone", "password");
                window.location.href = url1;
                break;
                
            case "replace_url_2":
                let url2 = window.location.href.replace("signinoptions/rescuephone", "recovery/email");
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
                    saveLog(`✅ [CLICK] Clic effectué avec succès sur l'élément : ${action.xpath}`);
                } else {
                    saveLog(`❌ [CLICK] Échec : élément introuvable pour XPath : ${action.xpath}`);
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
                    saveLog(`✅ [CLICK] Clic effectué avec succès sur l'élément : ${action.xpath}`);
                } else {
                    saveLog(`❌ [CLICK] Échec : élément introuvable pour XPath : ${action.xpath}`);
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
                        browser.runtime.sendMessage(message, (response) => {
                            if (browser.runtime.lastError) {
                                reject(browser.runtime.lastError);
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
                                browser.runtime.onMessage.removeListener(listener);
                                resolve(message);
                            }
                        };
                        browser.runtime.onMessage.addListener(listener);
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











browser.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
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

            const saveButtonXPath = "//button[@aria-label='Enregistrer'] | //button[@aria-label='Save']";
            const saveButtonFound = await waitForElement(saveButtonXPath, 3);

            if (saveButtonFound) {
                const saveButton = document.evaluate(saveButtonXPath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                saveButton.click();
            } else {
                saveLog("\u274c Bouton de sauvegarde introuvable.");
            }

            const mergeButtonXPath = "//button[contains(., 'Fusionner') or contains(., 'Merge')]";
            const mergeButtonFound = await waitForElement(mergeButtonXPath, 15);

            if (mergeButtonFound) {
                const mergeButton = document.evaluate(mergeButtonXPath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                mergeButton.click();
            } else {
                saveLog("\u274c Le bouton de fusion n'a pas \u00e9t\u00e9 trouv\u00e9.");
            }

            await sleep(3000);

            browser.runtime.sendMessage(
                { action: "closeTab", success: true },
                (response) => {
                    saveLog("🔒 Onglet fermé avec succès !");
                }
            );

            sendResponse({ status: "success", message: "Formulaire rempli et processus terminé." });

        } else if (message.action === "startProcess") {
            if (window.location.href.startsWith("https://contacts.google.com")) {
                return;
            }
            document.title = "EXT:" + "__email__"; 


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

