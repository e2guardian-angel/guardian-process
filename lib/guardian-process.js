'use strict'
const os = require('os');
const path = require('path');
const fs = require('fs');
const Request = require('kubernetes-client/backends/request');
const Config = require('./config');
const Controller = require('./controller');
const KUBECONFIG_PATH = process.env.KUBECONFIG || '/etc/rancher/k3s/k3s.yaml';

function GuardianProcess() {
    if (!process.env.NAMESPACE) {
        process.env.NAMESPACE = 'filter';
    }
    this.volumePath = path.join(process.env.HOME, '.volumes');
    this.aclVolumePath = path.join(this.volumePath, 'acl');
    this.authVolumePath = path.join(this.volumePath, 'auth');
    this.phraseVolumePath = path.join(this.volumePath, 'phrases');
    this.configPath = path.join(this.volumePath, 'config');
    this.configFile = path.join(this.configPath, 'config.json');
    // Create default config file if it doesn't exist
    if (!fs.existsSync(this.configFile)) {
        const newConfig = new Config({});
        fs.writeFileSync(this.configFile, JSON.stringify(newConfig));
    }

    this.controller = new Controller(KUBECONFIG_PATH);
}
GuardianProcess.prototype.startup = async function() {
    /*
     * 1. Check if paths are initialized for volumes and create them if not
     * 2. Check if authdb and guardian-angel are running, if not, start them
     * 3. Pull guardian conf. See if it matches the deployment. If not, apply it.
     *    3a. Generate CA and guardian-angel certificates using openssl
     * 4. Check config and apply necessary firewall rules
     */

    await this.controller.getKubeData();

    const config = JSON.parse(fs.readFileSync(this.configFile));
    this.controller.setConfig(config);

    await this.controller.initializeSecrets();
    await this.controller.pushConfig();
    await this.controller.pushRedisPassword();
    await this.controller.pushTLS();

    if (!fs.existsSync(this.aclVolumePath)) {
        fs.mkdirSync(this.aclVolumePath);
    }
    if (!fs.existsSync(this.authVolumePath)) {
        fs.mkdirSync(this.authVolumePath);
    }
    if (!fs.existsSync(this.phraseVolumePath)) {
        fs.mkdirSync(this.phraseVolumePath);
    }

    // Get pods at the beginning so we can know who needs a reload
    const pods = await this.controller.kubeGet(this.controller.paths.kube.pods);

    // Create the auth db
    await this.controller.deployMongo(this.authVolumePath);

    // First deploy redis as other deployments depend on it
    await this.controller.deployRedis();
    await this.controller.pollUntilReady();

    // Create the lookup service
    await this.controller.deployGuardian(this.aclVolumePath);

    // Now deploy the others
    await this.controller.deployDNS();
    await this.controller.deployFilter();
    await this.controller.deployNginx();
    await this.controller.pollUntilReady();

    // reload pods if necessary
    await this.controller.reloadPods(pods.body.items);

    // Pull configuration so everything is synced
    await this.controller.getKubeData();

    // TODO: create/update firewall rules

    return 'OK';
}

GuardianProcess.prototype.poll = async function() {
    /*
     * Poll on config file and apply firewall config changes
     */
}

module.exports = GuardianProcess;