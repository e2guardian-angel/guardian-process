'use strict'
const os = require('os');
const path = require('path');
const fs = require('fs');
const Config = require('./config');
const Controller = require('./controller');
const KUBECONFIG_PATH = process.env.KUBECONFIG || '/etc/rancher/k3s/k3s.yaml';

function GuardianProcess() {
    if (!process.env.NAMESPACE) {
        process.env.NAMESPACE = 'filter';
    }
    this.user = os.userInfo();
    this.volumePath = path.join(process.env.HOME, '.volumes');
    this.aclVolumePath = path.join(this.volumePath, 'acl');
    this.guardianDbVolumePath = path.join(this.volumePath, 'db');
    this.phraseVolumePath = path.join(this.volumePath, 'phrases');
    this.configPath = path.join(this.volumePath, 'config');
    this.configFile = path.join(this.configPath, 'config.json');
    [this.aclVolumePath, this.guardianDbVolumePath, this.phraseVolumePath, this.configPath].forEach(p => {
        if (!fs.existsSync(p)) {
            fs.mkdirSync(p, {recursive: true});
        }
    });

    // Create default config file if it doesn't exist
    if (!fs.existsSync(this.configFile)) {
        const newConfig = new Config({});
        fs.writeFileSync(this.configFile, JSON.stringify(newConfig, null, 2));
    }

    this.controller = new Controller(KUBECONFIG_PATH, this.user);
}

GuardianProcess.prototype.initFirewall = async function() {
    const config = JSON.parse(fs.readFileSync(this.configFile));
    await this.controller.initFirewall(config);
}

GuardianProcess.prototype.tearDownFirewall = async function() {
    await this.controller.tearDownFirewall();
}

GuardianProcess.prototype.update = async function() {
    /*
     * 1. Check if paths are initialized for volumes and create them if not
     * 2. Check if guardian-db and guardian-angel are running, if not, start them
     * 3. Pull guardian conf. See if it matches the deployment. If not, apply it.
     *    3a. Generate CA and guardian-angel certificates using openssl
     * 4. Check config and apply necessary firewall rules
     */

    await this.controller.getKubeData();
    await this.controller.getNodeName();

    const config = JSON.parse(fs.readFileSync(this.configFile));
    this.controller.setConfig(config);

    await this.controller.initializeSecrets();
    await this.controller.pushConfig();
    await this.controller.pushRedisPassword();
    await this.controller.pushTLS();
    await this.controller.pushDbPassword();

    // Get pods at the beginning so we can know who needs a reload
    const pods = await this.controller.kubeGet(this.controller.paths.kube.pods);

    // Create the auth db
    await this.controller.deployDb(this.guardianDbVolumePath);

    // First deploy redis as other deployments depend on it
    await this.controller.deployRedis();
    await this.controller.pollUntilReady();

    // Create the lookup service
    await this.controller.deployGuardian(this.aclVolumePath, this.phraseVolumePath);

    // Deploy DNS
    await this.controller.deployDNS();
    await this.controller.deployFilter();
    //await this.controller.deployNginx();
    await this.controller.pollUntilReady();

    // reload pods if necessary
    await this.controller.reloadPods(pods.body.items);

    // Create/update firewall rules
    await this.controller.updateFirewall(config);

    // Pull configuration so everything is synced
    await this.controller.getKubeData();

    return 'OK';
}

module.exports = GuardianProcess;