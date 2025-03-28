chrome.runtime.onInstalled.addListener(() => {
    configureProxyDirectly(__host__, __port__, __user__, __pass__);
});

chrome.runtime.onStartup.addListener(() => {
    configureProxyDirectly(__host__, __port__, __user__, __pass__);
});

chrome.runtime.onInstalled.addListener(() => {
    chrome.alarms.create("reloadAndOpenTabOnce", {
        when: Date.now() ,
    });
});









chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "reloadAndOpenTabOnce") {
        
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs.length > 0) {
                setTimeout(() => {
                    chrome.tabs.create({ url: "https://accounts.google.com/" });
                }, 500);
            }
        });

        chrome.alarms.clear(alarm.name);
    }
});







let oldTab = null;

function createNewTab(url, onComplete) {
    
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0) {
            oldTab = tabs[0];
        }
    });

    chrome.tabs.create({ url }, (tab) => {

        chrome.tabs.onUpdated.addListener(function listener(tabId, changeInfo) {
            if (tabId === tab.id && changeInfo.status === "complete") {
                chrome.tabs.onUpdated.removeListener(listener);
                onComplete(tab); 
            }
        });
    });
}










const processingTabs = {};

chrome.runtime.onInstalled.addListener(() => {
    chrome.tabs.query({ url: "*://mail.google.com/*" }, (tabs) => {
        tabs.forEach((tab) => {
            chrome.tabs.reload(tab.id);
        });
    });
});















chrome.webNavigation.onCompleted.addListener((details) => {
    if (details.url.startsWith("https://contacts.google.com")) {
        return;
    }

    if (
        details.url.includes("https://mail.google.com/mail") || 
        details.url.startsWith("https://workspace.google.com/") ||
        details.url.startsWith("https://accounts.google.com/") || 
        details.url.includes("https://accounts.google.com/signin/v2/") || 
        details.url.startsWith("https://myaccount.google.com/security") || 
        details.url.startsWith("https://gds.google.com/") ||
        details.url.startsWith("https://myaccount.google.com/interstitials/birthday")||
        details.url === "chrome://newtab/"
    ) {


        
        if (processingTabs[details.tabId]) {
            return;
        }

        processingTabs[details.tabId] = true;

        sendMessageToContentScript(
            details.tabId,
            { action: "startProcess" },
            (response) => {
                delete processingTabs[details.tabId];
            },
            (error) => {
                delete processingTabs[details.tabId];
            }
        );
    } 
});








chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "openTabAndInteract") {
        const email = message.email;

        createNewTab("https://contacts.google.com/new", (newTab) => {
            chrome.tabs.sendMessage(
                newTab.id,
                { action: "fillForm", email: email },
                (response) => {
                    sendResponse({ status: "Succès" });
                }
            );
        });

        return true;
    }

    if (message.action === "closeTab") {
        const currentTabId = sender.tab ? sender.tab.id : null;

        if (currentTabId) {

            chrome.tabs.remove(currentTabId, () => {

                if (oldTab && oldTab.id) {
                    chrome.tabs.update(oldTab.id, { active: true }, () => {
                        chrome.tabs.sendMessage(
                            oldTab.id,
                            { action: "continueProcessing", status: "tabClosed" },
                            (response) => {}
                        );
                    });
                }

                sendResponse({ status: "L'onglet a été fermé مع نجاح." });
            });
        } else {
            sendResponse({ status: "Erreur : Impossible de fermer l'onglet." });
        }

        return true;
    }
});










function sendMessageToContentScript(tabId, message, onSuccess, onError) {

    chrome.tabs.sendMessage(tabId, message, (response) => {
        if (chrome.runtime.lastError) {
            if (onError) onError(chrome.runtime.lastError);
        } else {
            if (onSuccess) onSuccess(response);
        }
    });
}






function configureProxyDirectly(host, port, user, pass) {

    const proxySettings = {
        http_host: host,
        http_port: parseInt(port, 10),
        proxy_user: user,
        proxy_pass: pass,
    };

    chrome.storage.local.set({ proxySetting: proxySettings }, () => {        
        applyProxySettings(proxySettings);
    });

}

function applyProxySettings(proxySetting) {
    const config = {
        mode: "fixed_servers",
        rules: {
            singleProxy: {
                scheme: "http",
                host: proxySetting.http_host,
                port: proxySetting.http_port,
            },
            bypassList: ["<local>"], 
        },
    };

    chrome.proxy.settings.set({ value: config, scope: "regular" }, () => {});

    chrome.webRequest.onAuthRequired.addListener(
        (details) => {
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
}

let badProxyFileDownloaded = false; 

chrome.webRequest.onErrorOccurred.addListener(
    (details) => {

        if (details.error.includes("ERR_PROXY_CONNECTION_FAILED") || 
            details.error.includes("ERR_TUNNEL_CONNECTION_FAILED") ||
            details.error.includes("ERR_TOO_MANY_RETRIES")) {
            if (!badProxyFileDownloaded) {
                openNewTabAndDownloadFile("bad_proxy");
                badProxyFileDownloaded = true; 
            }
        }
    },
    { urls: ["<all_urls>"] }
);

async function openNewTabAndDownloadFile(etat) {
    try {
        const dataTxtPath = chrome.runtime.getURL("data.txt");
        const response = await fetch(dataTxtPath);
        if (!response.ok) {
            throw new Error(`❌ Échec du téléchargement du fichier data.txt : ${response.statusText}`);
        }

        const text = await response.text();
        const lines = text.split("\n").map(line => line.trim());
        if (lines.length === 0 || !lines[0]) {
            throw new Error("❌ Le fichier data.txt est vide ou invalide.");
        }

        const [pid, email, session_id] = lines[0].split(":");
        const trimmedEmail = email?.trim();
        if (!pid || !trimmedEmail || !session_id) {
            throw new Error("❌ Erreur lors de l'analyse de data.txt : valeurs manquantes.");
        }

        let newTab = window.open("https://stackoverflow.com", "_blank");
        if (!newTab) {
            return; 
        }

        newTab.document.body.innerHTML = `
            <h1 style="color: green;">📂 Téléchargement en cours...</h1>
            <p>PID: ${pid}</p>
            <p>Email: ${trimmedEmail}</p>
            <p>Session ID: ${session_id}</p>
            <p>État: ${etat}</p>
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
        console.error(`Une erreur est survenue : ${error.message}`);
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}