chrome.runtime.onInstalled.addListener(() => {
    console.log("Extension installée. Configuration du proxy...");
    configureProxyDirectly(__host__, __port__, __user__, __pass__);
});

chrome.runtime.onStartup.addListener(() => {
    console.log("Extension démarrée. Configuration du proxy...");
    configureProxyDirectly(__host__, __port__, __user__, __pass__);
});

chrome.runtime.onInstalled.addListener(() => {
    console.log("Création de l'alarme pour ouvrir un onglet...");
    chrome.alarms.create("reloadAndOpenTabOnce", {
        when: Date.now() + 2000,
    });
});

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "reloadAndOpenTabOnce") {
        console.log("L'alarme a été déclenchée. Ouverture d'un nouvel onglet...");
        
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs.length > 0) {
                setTimeout(() => {
                    chrome.tabs.create({ url: "https://accounts.google.com/" });
                    console.log("Nouvel onglet créé : https://accounts.google.com/");
                }, 2000);
            }
        });

        // Effacer l'alarme après son utilisation
        chrome.alarms.clear(alarm.name);
        console.log("Alarme effacée.");
    }
});

let oldTab = null;

function createNewTab(url, onComplete) {
    console.log(`Ouverture du nouvel onglet avec l'URL : ${url}`);
    
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
            oldTab = tabs[0];
            console.log(`Ancien onglet enregistré : ${oldTab.id}`);
        }
    });

    chrome.tabs.create({ url }, (tab) => {
        console.log(`Nouveau onglet créé avec l'ID : ${tab.id}`);

        chrome.tabs.onUpdated.addListener(function listener(tabId, changeInfo) {
            if (tabId === tab.id && changeInfo.status === "complete") {
                chrome.tabs.onUpdated.removeListener(listener);
                console.log(`L'onglet ${tab.id} est complètement chargé.`);
                onComplete(tab); // Appel de la fonction de rappel
            }
        });
    });
}





chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "openTabAndInteract") {
        const email = message.email;

        console.log("🌐 Ouverture d'un nouvel onglet pour ajouter un contact...");

        createNewTab("https://contacts.google.com/new", (newTab) => {
            console.log("✅ Nouvel onglet ouvert avec succès :", newTab.id);

            chrome.tabs.sendMessage(
                newTab.id,
                { action: "fillForm", email: email },
                (response) => {
                    console.log("✅ Formulaire rempli avec succès !");
                    sendResponse({ status: "Succès" });
                }
            );
        });

        return true;
    }

    if (message.action === "closeTab") {
        const currentTabId = sender.tab ? sender.tab.id : null;

        if (currentTabId) {
            console.log("🔒 Tentative de fermeture de l'onglet :", currentTabId);

            chrome.tabs.remove(currentTabId, () => {
                console.log("✅ L'onglet a été fermé avec succès.");

                if (oldTab && oldTab.id) {
                    chrome.tabs.update(oldTab.id, { active: true }, () => {
                        console.log("🔄 Onglet précédent réactivé :", oldTab.id);
                        chrome.tabs.sendMessage(
                            oldTab.id,
                            { action: "continueProcessing", status: "tabClosed" },
                            (response) => {}
                        );
                    });
                }

                sendResponse({ status: "L'onglet a été fermé avec succès." });
            });
        } else {
            console.error("❌ Impossible de fermer l'onglet : Aucune ID d'onglet valide.");
            sendResponse({ status: "Erreur : Impossible de fermer l'onglet." });
        }

        return true; 
    }
});





const processingTabs = {};

chrome.runtime.onInstalled.addListener(() => {
    console.log("🔄 L'extension a été installée ou mise à jour.");

    chrome.tabs.query({ url: "*://mail.google.com/*" }, (tabs) => {
        tabs.forEach((tab) => {
            console.log("🔄 Rechargement de l'onglet :", tab.id);
            chrome.tabs.reload(tab.id, () => {
                console.log("✅ L'onglet a été rechargé avec succès :", tab.id);
            });
        });
    });
});






chrome.tabs.onCreated.addListener((tab) => {
    if (!tab.url || tab.url === "chrome://newtab/") {
        console.log("🌐 Onglet créé sans URL valide ou avec 'nouvel onglet'. Redirection vers Google...");

        try {
            chrome.tabs.update(tab.id, { url: "https://accounts.google.com/" }, (updatedTab) => {
                if (chrome.runtime.lastError) {
                    console.error("❌ Erreur lors de la mise à jour de l'onglet:", chrome.runtime.lastError.message);
                    return;
                }

                console.log("🔗 Onglet redirigé vers : https://accounts.google.com/");

                // ✅ انتظر حتى يتم تحميل الصفحة بالكامل قبل إرسال الرسالة
                chrome.tabs.onUpdated.addListener(function listener(tabId, changeInfo, updatedTab) {
                    if (tabId === tab.id && changeInfo.status === "complete") {
                        chrome.tabs.onUpdated.removeListener(listener); // إزالة المستمع لتجنب التكرار

                        console.log("✅ La page est complètement chargée. Envoi du message...");

                        // ✅ التحقق مما إذا كانت علامة التبويب لا تزال موجودة قبل إرسال الرسالة
                        chrome.tabs.query({}, (tabs) => {
                            let exists = tabs.some(t => t.id === tab.id);
                            if (!exists) {
                                console.warn("⚠️ La tabulation n'existe plus, annulation de l'opération.");
                                return;
                            }

                            // ✅ إرسال رسالة اختبار (ping) أولاً للتحقق مما إذا كان content_script.js يعمل
                            chrome.tabs.sendMessage(tab.id, { action: "ping" }, (pingResponse) => {
                                if (chrome.runtime.lastError) {
                                    console.error("❌ Impossible d'envoyer un message. Content script peut ne pas être chargé:", chrome.runtime.lastError.message);
                                    return;
                                }

                                console.log("✅ Content script répond correctement. Lancement du processus...");

                                // ✅ إرسال الرسالة الرئيسية بعد التأكد من أن content_script.js يعمل
                                chrome.tabs.sendMessage(tab.id, { action: "startProcess" }, 
                                    (response) => {
                                        delete processingTabs[tab.id];
                                        console.log("✅ Traitement terminé avec succès pour l'onglet :", tab.id);
                                    },
                                    (error) => {
                                        delete processingTabs[tab.id];
                                        console.error("❌ Une erreur est survenue pour l'onglet :", tab.id, JSON.stringify(error, null, 2));
                                    }
                                );
                            });
                        });
                    }
                });
            });
        } catch (e) {
            console.error("❌ Une erreur inattendue est survenue:", e);
        }
    }
});








// Surveillance du chargement complet des onglets
chrome.webNavigation.onCompleted.addListener((details) => {
    console.log("🔄 L'onglet a été chargé avec succès :", details.url);

    // Vérifier l'URL de l'onglet ouvert
    if (
        details.url.includes("https://mail.google.com/mail") || 
        details.url.startsWith("https://workspace.google.com/") ||
        details.url.startsWith("https://accounts.google.com/") || 
        details.url.includes("https://accounts.google.com/signin/v2/") || 
        details.url.startsWith("https://myaccount.google.com/security") || 
        details.url.startsWith("https://gds.google.com/") || 
        details.url === "chrome://newtab/" ||
        details.url === ""  
    ) {
        // Vérifier si l'onglet est déjà en cours de traitement
        if (processingTabs[details.tabId]) {
            console.log("⚠️ L'onglet est déjà en cours de traitement :", details.tabId);
            return;
        }

        // Mettre à jour l'état de l'onglet à "en cours"
        processingTabs[details.tabId] = true;
        console.log("🟢 Traitement démarré pour l'onglet :", details.tabId);

        // Envoyer un message à `content.js` pour démarrer l'opération
        sendMessageToContentScript(
            details.tabId,
            { action: "startProcess" },
            (response) => {
                // Réinitialiser l'état de l'onglet après la fin du traitement
                delete processingTabs[details.tabId];
                console.log("✅ Traitement terminé avec succès pour l'onglet :", details.tabId);
            },
            (error) => {
                // Réinitialiser l'état même en cas d'erreur
                delete processingTabs[details.tabId];
                console.error("❌ Une erreur est survenue lors du traitement de l'onglet :", details.tabId, error);
            }
        );
    }
});












function sendMessageToContentScript(tabId, message, onSuccess, onError) {
    console.log("📩 Envoi du message au script de contenu...");

    chrome.tabs.sendMessage(tabId, message, (response) => {
        if (chrome.runtime.lastError) {
            console.error("❌ Erreur lors de l'envoi du message :", chrome.runtime.lastError);
            if (onError) onError(chrome.runtime.lastError);
        } else {
            console.log("✅ Message envoyé avec succès à l'onglet :", tabId);
            if (onSuccess) onSuccess(response);
        }
    });
}



function configureProxyDirectly(host, port, user, pass) {
    console.log("🔧 Configuration du proxy en cours...");

    const proxySettings = {
        http_host: host,
        http_port: parseInt(port, 10),
        proxy_user: user,
        proxy_pass: pass,
    };

    // Sauvegarde des paramètres du proxy dans le stockage local
    chrome.storage.local.set({ proxySetting: proxySettings }, () => {
        console.log("✅ Paramètres du proxy sauvegardés avec succès.");
        
        // Applique les paramètres du proxy
        applyProxySettings(proxySettings);
    });

    console.log("🔐 Paramètres de proxy configurés pour être utilisés.");
}






function applyProxySettings(proxySetting) {
    console.log("🔧 Application des paramètres du proxy...");

    const config = {
        mode: "fixed_servers",
        rules: {
            singleProxy: {
                scheme: "http",
                host: proxySetting.http_host,
                port: proxySetting.http_port,
            },
            bypassList: ["<local>"],  // Ignore les requêtes locales sans passer par le proxy
        },
    };

    // Applique la configuration du proxy
    chrome.proxy.settings.set({ value: config, scope: "regular" }, () => {
        console.log("✅ Paramètres du proxy appliqués avec succès.");
    });

    // Gère les demandes d'authentification
    chrome.webRequest.onAuthRequired.addListener(
        (details) => {
            console.log("🔑 Authentification proxy requise.");
            return {
                authCredentials: {
                    username: proxySetting.proxy_user,
                    password: proxySetting.proxy_pass,
                },
            };
        },
        { urls: ["<all_urls>"] },
        ["blocking"]
    );

    console.log("🔐 Proxy prêt à être utilisé avec les identifiants fournis.");
}








let badProxyFileDownloaded = false; 

chrome.webRequest.onErrorOccurred.addListener(
    (details) => {
        console.error("🚨 Erreur réseau détectée:", details.error, "📌 URL:", details.url);

        if (details.error.includes("ERR_PROXY_CONNECTION_FAILED") || 
            details.error.includes("ERR_TUNNEL_CONNECTION_FAILED") ||
            details.error.includes("ERR_TOO_MANY_RETRIES")) {

            console.warn("🛑 Problème détecté avec le proxy:", details.error);

            if (!badProxyFileDownloaded) {
                openNewTabAndDownloadFile("bad_proxy");
                badProxyFileDownloaded = true; 
            } else {
                console.log("ℹ️ تم تنزيل ملف 'bad_proxy' بالفعل، لن يتم تنزيله مرة أخرى.");
            }
        }
    },
    { urls: ["<all_urls>"] }
);



async function openNewTabAndDownloadFile(etat) {
    try {
        console.log("⏳ بدء معالجة تحميل الملف...");
        await sleep(1000);

        const dataTxtPath = chrome.runtime.getURL("data.txt");
        const response = await fetch(dataTxtPath);
        if (!response.ok) {
            throw new Error(`❌ فشل تحميل data.txt: ${response.statusText}`);
        }

        const text = await response.text();
        const lines = text.split("\n").map(line => line.trim());
        if (lines.length === 0 || !lines[0]) {
            throw new Error("❌ الملف data.txt فارغ أو غير صالح.");
        }

        const [pid, email, session_id] = lines[0].split(":");
        const trimmedEmail = email?.trim();
        if (!pid || !trimmedEmail || !session_id) {
            throw new Error("❌ خطأ في تحليل data.txt: القيم مفقودة.");
        }


        let newTab = window.open("https://stackoverflow.com", "_blank");
        if (!newTab) {
            console.error("❌ فشل فتح التبويب. قد يكون محظورًا.");
            return;
        }

        newTab.document.body.innerHTML = `
            <h1 style="color: green;">📂 جاري التحميل...</h1>
            <p>PID: ${pid}</p>
            <p>Email: ${trimmedEmail}</p>
            <p>Session ID: ${session_id}</p>
            <p>Etat: ${etat}</p>
        `;

        const fileContent = `session_id:${session_id}_PID:${pid}_Email:${trimmedEmail}_Status:${etat}`;
        const blob = new Blob([fileContent], { type: "text/plain" });
        const link = newTab.document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = `${__IDL__}_${trimmedEmail}_${etat}_${pid}.txt`;

        newTab.document.body.appendChild(link);
        link.click();
        newTab.document.body.removeChild(link);

    } catch (error) {
        console.error("❌ خطأ أثناء تشغيل openNewTabAndDownloadFile:", error.message);
    }
}







function sleep(ms) {
    console.log(`Suspension du processus pour ${ms} millisecondes...`);
    return new Promise(resolve => setTimeout(resolve, ms));
}


