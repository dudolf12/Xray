//META{"name":"Xray","displayName":"Xray","version":"0.6","author":"dudolf","description":"Checks if links in the chat contain grabbers, viruses, or phishing (plugin is in Beta)"}*//

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class Xray {
    constructor() {
        this.configPath = path.join(BdApi.Plugins.folder, "Xray.config.json");
        this.linkPattern = /https?:\/\/[^\s/$.?#].[^\s]*/g;
        this.interval = null;
        this.knownMaliciousDomains = new Set();
        this.knownWhitelistedDomains = new Set();
        this.knownMaliciousLinks = new Set();
        this.knownWhitelistedLinks = new Set();
        this.config = this.loadConfig();
        this.messageCache = new Map();
        this.cacheSizeLimit = 2 * 1024 * 1024 * 1024; // 2 GB
        this.currentCacheSize = 0;
        this.textEncoder = new TextEncoder();
        this.apiKeys = {
            urlscan: this.config.apiKeyUrlscan || '',
            virustotal: this.config.apiKeyVirustotal || ''
        };
        this.useApiDetection = {
            urlscan: this.config.useApiDetectionUrlscan !== undefined ? this.config.useApiDetectionUrlscan : false,
            virustotal: this.config.useApiDetectionVirustotal !== undefined ? this.config.useApiDetectionVirustotal : false
        };
        this.pendingScans = new Set();
    }

    async start() {
        console.log("Xray plugin started.");
        await this.updateMaliciousDomains();
        await this.updateWhitelistedDomains();
        await this.updateMaliciousLinks();
        await this.updateWhitelistedLinks();
        this.addStyles();
        this.interval = setInterval(() => {
            this.checkAllVisibleMessages();
            this.verifyVisualMarkers();
        }, 1000);
        this.logMemoryUsage();
    }

    stop() {
        console.log("Xray plugin stopped.");
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
        BdApi.Patcher.unpatchAll("Xray");
        BdApi.DOM.removeStyle("xray-styles");
    }

    loadConfig() {
        if (fs.existsSync(this.configPath)) {
            const data = fs.readFileSync(this.configPath, 'utf8');
            return JSON.parse(data);
        }
        return { dangerousMessages: {}, safeMessages: {}, apiKeyUrlscan: '', apiKeyVirustotal: '', useApiDetectionUrlscan: false, useApiDetectionVirustotal: false, scannedLinks: {} };
    }

    saveConfig() {
        fs.writeFileSync(this.configPath, JSON.stringify(this.config, null, 2));
    }

    async updateMaliciousDomains() {
        try {
            const response = await fetch('https://raw.githubusercontent.com/dudolf12/Xray/main/databasedomain.txt');
            const text = await response.text();
            const domains = text.split('\n').map(domain => domain.trim()).filter(domain => domain);
            this.knownMaliciousDomains = new Set(domains);
        } catch (error) {
            console.error("Error updating malicious domains:", error);
        }
    }

    async updateWhitelistedDomains() {
        try {
            const response = await fetch('https://raw.githubusercontent.com/dudolf12/Xray/main/databasedomainwhitelist.txt');
            const text = await response.text();
            const domains = text.split('\n').map(domain => domain.trim()).filter(domain => domain);
            this.knownWhitelistedDomains = new Set(domains);
        } catch (error) {
            console.error("Error updating whitelisted domains:", error);
        }
    }

    async updateMaliciousLinks() {
        try {
            const response = await fetch('https://raw.githubusercontent.com/dudolf12/Xray/main/database.txt');
            const text = await response.text();
            const links = text.split('\n').map(link => link.trim()).filter(link => link);
            this.knownMaliciousLinks = new Set(links);
        } catch (error) {
            console.error("Error updating malicious links:", error);
        }
    }

    async updateWhitelistedLinks() {
        try {
            const response = await fetch('https://raw.githubusercontent.com/dudolf12/Xray/main/databasewhitelist.txt');
            const text = await response.text();
            const links = text.split('\n').map(link => link.trim()).filter(link => link);
            this.knownWhitelistedLinks = new Set(links);
        } catch (error) {
            console.error("Error updating whitelisted links:", error);
        }
    }

    hashMessage(content) {
        return crypto.createHash('sha256').update(content).digest('hex');
    }

    getMessageSize(content) {
        return this.textEncoder.encode(content).length;
    }

    logMemoryUsage() {
        setInterval(() => {
            const memoryUsage = process.memoryUsage().heapUsed;
            console.log(`Current memory usage: ${(memoryUsage / 1024 / 1024).toFixed(2)} MB`);
            console.log(`Current cache size: ${(this.currentCacheSize / 1024 / 1024).toFixed(2)} MB`);
        }, 100000);
    }

    checkAllVisibleMessages() {
        try {
            const MessageStore = BdApi.Webpack.getModule(m => m?.getMessages && m?.getMessage);
            const channels = BdApi.findModuleByProps("getChannelId", "getLastSelectedChannelId");

            if (MessageStore && channels) {
                const channelId = channels.getChannelId();
                const messages = MessageStore.getMessages(channelId)._array;

                if (messages && messages.length) {
                    messages.forEach(message => {
                        const messageId = message.id;
                        const content = message.content;

                        if (content) {
                            const messageHash = this.hashMessage(content);
                            const messageSize = this.getMessageSize(content);

                            if (this.shouldCheckMessage(messageId, messageHash)) {
                                this.checkLinks(content, messageId);
                            }

                            this.addToCache(messageId, messageHash, messageSize);
                        }
                    });
                    this.saveConfig();
                }
            }
        } catch (error) {
            console.error("Error while checking visible messages:", error);
        }
    }

    shouldCheckMessage(messageId, messageHash) {
        const cachedHash = this.messageCache.get(messageId)?.hash;
        const { dangerousMessages, safeMessages } = this.config;

        if (cachedHash && cachedHash === messageHash) {
            return false;
        }

        if (dangerousMessages[messageId] && dangerousMessages[messageId] === messageHash) {
            return false;
        }
        if (safeMessages[messageId] && safeMessages[messageId] === messageHash) {
            return false;
        }

        return true;
    }

    addToCache(messageId, messageHash, messageSize) {
        if (this.messageCache.has(messageId)) {
            this.currentCacheSize -= this.messageCache.get(messageId).size;
        }
        this.messageCache.set(messageId, { hash: messageHash, size: messageSize });
        this.currentCacheSize += messageSize;

        while (this.currentCacheSize > this.cacheSizeLimit) {
            const oldestEntry = this.messageCache.keys().next().value;
            this.currentCacheSize -= this.messageCache.get(oldestEntry).size;
            this.messageCache.delete(oldestEntry);
        }
    }

    async checkLinks(content, messageId) {
        try {
            const links = content.match(this.linkPattern);
            if (links) {
                for (const link of links) {
                    if (this.isWhitelistedDomain(link)) {
                        this.markMessageAsSafe(messageId);
                        break;
                    } else if (this.isWhitelistedLink(link)) {
                        this.markMessageAsSafe(messageId);
                        break;
                    } else if (this.isPotentiallyDangerousPattern(content)) {
                        this.markMessageAsPotentiallyDangerous(messageId);
                    } else if (this.isKnownMaliciousDomain(link)) {
                        this.markMessageAsSuspicious(messageId, "Known malicious domain");
                    } else if (this.isDatabaseMatch(link)) {
                        this.markMessageAsSuspicious(messageId, "Known malicious link");
                    } else if (this.useApiDetection.virustotal) {
                        if (!this.pendingScans.has(link) && !this.config.scannedLinks[link]) {
                            this.pendingScans.add(link);
                            await this.checkLinkWithVirusTotal(link, messageId);
                        } else if (this.config.scannedLinks[link]) {
                            const result = this.config.scannedLinks[link];
                            if (result.malicious) {
                                this.markMessageAsSuspicious(messageId, "API VirusTotal flagged as malicious");
                            } else {
                                this.markMessageAsSafe(messageId);
                            }
                        }
                    } else if (this.useApiDetection.urlscan) {
                        if (!this.pendingScans.has(link) && !this.config.scannedLinks[link]) {
                            this.pendingScans.add(link);
                            await this.checkLinkWithUrlscan(link, messageId);
                        } else if (this.config.scannedLinks[link]) {
                            const result = this.config.scannedLinks[link];
                            if (result.malicious) {
                                this.markMessageAsSuspicious(messageId, "API urlscan.io flagged as malicious");
                            } else {
                                this.markMessageAsSafe(messageId);
                            }
                        }
                    } else {
                        this.markMessageAsSafe(messageId);
                    }
                }
            } else {
                this.markMessageAsSafe(messageId);
            }
        } catch (error) {
            console.error("Error while checking links:", error);
        }
    }

    isWhitelistedDomain(link) {
        try {
            const url = new URL(link);
            return this.knownWhitelistedDomains.has(url.hostname);
        } catch (error) {
            console.error("Invalid URL:", link);
            return false;
        }
    }

    isWhitelistedLink(link) {
        return this.knownWhitelistedLinks.has(link);
    }

    isPotentiallyDangerousPattern(content) {
        return /\[.*?\]\(https?:\/\/[^\s/$.?#].[^\s]*\)/.test(content);
    }

    isKnownMaliciousDomain(link) {
        try {
            const url = new URL(link);
            return this.knownMaliciousDomains.has(url.hostname);
        } catch (error) {
            console.error("Invalid URL:", link);
            return false;
        }
    }

    isDatabaseMatch(link) {
        return this.knownMaliciousLinks.has(link);
    }

    async checkLinkWithVirusTotal(link, messageId, retries = 0) {
        try {
            const messageElement = document.querySelector(`#message-content-${messageId}`);
            if (messageElement) {
                const loader = document.createElement("div");
                loader.classList.add("loader");
                messageElement.insertAdjacentElement('beforebegin', loader);
            }

            const url = new URL(link);
            const payload = new URLSearchParams({ url: link }).toString();
            const headers = {
                'x-apikey': this.apiKeys.virustotal.trim(),
                'Content-Type': 'application/x-www-form-urlencoded'
            };

            const response = await BdApi.Net.fetch(`https://www.virustotal.com/api/v3/urls`, {
                method: 'POST',
                headers: headers,
                body: payload
            });

            if (response.status === 200) {
                const resultData = await response.json();
                const scanId = resultData.data.id;

                setTimeout(() => {
                    this.checkVirusTotalResult(scanId, messageId, link);
                }, 15000); // Poll after 15 seconds

            } else if (response.status === 429 && retries < 3) {
                setTimeout(() => {
                    this.checkLinkWithVirusTotal(link, messageId, retries + 1);
                }, 10000);
            } else {
                this.markMessageAsSafe(messageId);
            }
        } catch (error) {
            console.error("Error checking link with VirusTotal API:", error);
            this.markMessageAsSafe(messageId);
        } finally {
            const messageElement = document.querySelector(`#message-content-${messageId}`);
            if (messageElement) {
                const loader = messageElement.previousElementSibling;
                if (loader && loader.classList.contains("loader")) {
                    loader.remove();
                }
            }
            this.pendingScans.delete(link);
        }
    }

    async checkVirusTotalResult(scanId, messageId, link) {
        try {
            const response = await BdApi.Net.fetch(`https://www.virustotal.com/api/v3/analyses/${scanId}`, {
                method: 'GET',
                headers: {
                    'x-apikey': this.apiKeys.virustotal.trim(),
                    'Content-Type': 'application/json'
                }
            });

            if (response.status === 200) {
                const resultData = await response.json();

                const isMalicious = resultData.data.attributes.stats.malicious > 0;

                if (isMalicious) {
                    this.markMessageAsSuspicious(messageId, "API VirusTotal flagged as malicious");
                    this.config.scannedLinks[link] = { malicious: true };
                } else {
                    this.markMessageAsSafe(messageId);
                    this.config.scannedLinks[link] = { malicious: false };
                }
                this.saveConfig();
            } else {
                this.markMessageAsSafe(messageId);
            }
        } catch (error) {
            console.error("Error checking VirusTotal result:", error);
            this.markMessageAsSafe(messageId);
        } finally {
            this.pendingScans.delete(link);
        }
    }

    async checkLinkWithUrlscan(link, messageId, retries = 0) {
        try {
            const messageElement = document.querySelector(`#message-content-${messageId}`);
            if (messageElement) {
                const loader = document.createElement("div");
                loader.classList.add("loader");
                messageElement.insertAdjacentElement('beforebegin', loader);
            }

            const payload = JSON.stringify({ url: link, visibility: "private" });
            const headers = {
                'Content-Type': 'application/json',
                'API-Key': this.apiKeys.urlscan.trim()
            };

            const response = await BdApi.Net.fetch(`https://urlscan.io/api/v1/scan/`, {
                method: 'POST',
                headers: headers,
                body: payload
            });

            if (response.status === 200) {
                const resultData = await response.json();
                const resultUrl = resultData.api;

                setTimeout(() => {
                    this.checkUrlscanResult(resultUrl, messageId, link);
                }, 15000); // Poll after 15 seconds

            } else if (response.status === 429 && retries < 3) {
                setTimeout(() => {
                    this.checkLinkWithUrlscan(link, messageId, retries + 1);
                }, 10000);
            } else {
                this.markMessageAsSafe(messageId);
            }
        } catch (error) {
            console.error("Error checking link with urlscan.io API:", error);
            this.markMessageAsSafe(messageId);
        } finally {
            const messageElement = document.querySelector(`#message-content-${messageId}`);
            if (messageElement) {
                const loader = messageElement.previousElementSibling;
                if (loader && loader.classList.contains("loader")) {
                    loader.remove();
                }
            }
            this.pendingScans.delete(link);
        }
    }

    async checkUrlscanResult(resultUrl, messageId, link) {
        try {
            const response = await BdApi.Net.fetch(resultUrl, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'API-Key': this.apiKeys.urlscan.trim()
                }
            });

            if (response.status === 200) {
                const resultData = await response.json();

                const isMalicious = resultData.verdicts?.overall?.malicious;

                if (isMalicious) {
                    this.markMessageAsSuspicious(messageId, "API urlscan.io flagged as malicious");
                    this.config.scannedLinks[link] = { malicious: true };
                } else {
                    this.markMessageAsSafe(messageId);
                    this.config.scannedLinks[link] = { malicious: false };
                }
                this.saveConfig();
            } else {
                this.markMessageAsSafe(messageId);
            }
        } catch (error) {
            console.error("Error checking urlscan.io result:", error);
            this.markMessageAsSafe(messageId);
        } finally {
            this.pendingScans.delete(link);
        }
    }

    markMessageAsSuspicious(messageId, reason) {
        try {
            const messageElement = document.querySelector(`#message-content-${messageId}`);
            if (messageElement) {
                messageElement.classList.add("xray-warning");
                this.config.dangerousMessages[messageId] = this.hashMessage(messageElement.innerText);
                delete this.config.safeMessages[messageId];
                this.saveConfig();
            }
        } catch (error) {
            console.error("Error marking message as suspicious:", error);
        }
    }

    markMessageAsPotentiallyDangerous(messageId) {
        try {
            const messageElement = document.querySelector(`#message-content-${messageId}`);
            if (messageElement) {
                messageElement.classList.add("xray-warning-orange");
                this.checkLinks(messageElement.innerText, messageId);
            }
        } catch (error) {
            console.error("Error marking message as potentially dangerous:", error);
        }
    }

    markMessageAsSafe(messageId) {
        try {
            const messageElement = document.querySelector(`#message-content-${messageId}`);
            if (messageElement) {
                messageElement.classList.remove("xray-warning");
                messageElement.classList.remove("xray-warning-orange");
                this.config.safeMessages[messageId] = this.hashMessage(messageElement.innerText);
                delete this.config.dangerousMessages[messageId];
                this.saveConfig();
            }
        } catch (error) {
            console.error("Error marking message as safe:", error);
        }
    }

    verifyVisualMarkers() {
        try {
            Object.keys(this.config.dangerousMessages).forEach(messageId => {
                const messageElement = document.querySelector(`#message-content-${messageId}`);
                if (messageElement && !messageElement.classList.contains("xray-warning")) {
                    messageElement.classList.add("xray-warning");
                }
            });
        } catch (error) {
            console.error("Error verifying visual markers:", error);
        }
    }

    addStyles() {
        const css = `
            .xray-warning {
                background-color: rgba(255, 0, 0, 0.2) !important;
                border-left: 4px solid red;
                padding: 4px;
            }
            .xray-warning-orange {
                background-color: rgba(255, 165, 0, 0.2) !important;
                border-left: 4px solid orange;
                padding: 4px;
            }
            .loader {
                width: 12.5px;
                padding: 2px;
                aspect-ratio: 1;
                border-radius: 50%;
                background: #25b09b;
                --_m: 
                    conic-gradient(#0000 10%,#000),
                    linear-gradient(#000 0 0) content-box;
                -webkit-mask: var(--_m);
                mask: var(--_m);
                -webkit-mask-composite: source-out;
                mask-composite: subtract;
                animation: l3 1s infinite linear;
            }
            @keyframes l3 {to{transform: rotate(1turn)}}
        `;
        try {
            BdApi.DOM.addStyle("xray-styles", css);
        } catch (error) {
            console.error("Error adding styles:", error);
        }
    }

    getSettingsPanel() {
        const panel = document.createElement("div");
        panel.style.padding = "10px";

        const apiKeyUrlscanLabel = document.createElement("label");
        apiKeyUrlscanLabel.style.color = "white";
        apiKeyUrlscanLabel.textContent = "API Key for urlscan.io:";
        panel.appendChild(apiKeyUrlscanLabel);

        const apiKeyUrlscanInput = document.createElement("input");
        apiKeyUrlscanInput.type = "text";
        apiKeyUrlscanInput.value = this.apiKeys.urlscan;
        apiKeyUrlscanInput.onchange = (e) => {
            this.apiKeys.urlscan = e.target.value;
            this.config.apiKeyUrlscan = e.target.value;
            this.saveConfig();
        };
        panel.appendChild(apiKeyUrlscanInput);

        panel.appendChild(document.createElement("br"));

        const apiKeyVirusTotalLabel = document.createElement("label");
        apiKeyVirusTotalLabel.style.color = "white";
        apiKeyVirusTotalLabel.textContent = "API Key for VirusTotal:";
        panel.appendChild(apiKeyVirusTotalLabel);

        const apiKeyVirusTotalInput = document.createElement("input");
        apiKeyVirusTotalInput.type = "text";
        apiKeyVirusTotalInput.value = this.apiKeys.virustotal;
        apiKeyVirusTotalInput.onchange = (e) => {
            this.apiKeys.virustotal = e.target.value;
            this.config.apiKeyVirustotal = e.target.value;
            this.saveConfig();
        };
        panel.appendChild(apiKeyVirusTotalInput);

        panel.appendChild(document.createElement("br"));

        const useApiDetectionUrlscanLabel = document.createElement("label");
        useApiDetectionUrlscanLabel.style.color = "white";
        useApiDetectionUrlscanLabel.textContent = "Use urlscan.io for link scanning:";
        panel.appendChild(useApiDetectionUrlscanLabel);

        const useApiDetectionUrlscanCheckbox = document.createElement("input");
        useApiDetectionUrlscanCheckbox.type = "checkbox";
        useApiDetectionUrlscanCheckbox.checked = this.useApiDetection.urlscan;
        useApiDetectionUrlscanCheckbox.onchange = (e) => {
            this.useApiDetection.urlscan = e.target.checked;
            this.config.useApiDetectionUrlscan = e.target.checked;
            this.saveConfig();
        };
        panel.appendChild(useApiDetectionUrlscanCheckbox);

        panel.appendChild(document.createElement("br"));

        const useApiDetectionVirusTotalLabel = document.createElement("label");
        useApiDetectionVirusTotalLabel.style.color = "white";
        useApiDetectionVirusTotalLabel.textContent = "Use VirusTotal for link scanning:";
        panel.appendChild(useApiDetectionVirusTotalLabel);

        const useApiDetectionVirusTotalCheckbox = document.createElement("input");
        useApiDetectionVirusTotalCheckbox.type = "checkbox";
        useApiDetectionVirusTotalCheckbox.checked = this.useApiDetection.virustotal;
        useApiDetectionVirusTotalCheckbox.onchange = (e) => {
            this.useApiDetection.virustotal = e.target.checked;
            this.config.useApiDetectionVirustotal = e.target.checked;
            this.saveConfig();
        };
        panel.appendChild(useApiDetectionVirusTotalCheckbox);

        return panel;
    }
}

module.exports = Xray;
