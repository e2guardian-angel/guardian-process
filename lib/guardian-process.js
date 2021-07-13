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
    this.username = os.userInfo().username;
    this.volumePath = path.join(process.env.HOME, '.volumes');
    this.aclVolumePath = path.join(this.volumePath, 'acl');
    this.authVolumePath = path.join(this.volumePath, 'auth');
    this.phraseVolumePath = path.join(this.volumePath, 'phrases');
    this.configPath = path.join(this.volumePath, 'config');

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
    if (!fs.existsSync(this.aclVolumePath)) {
        fs.mkdirSync(this.aclVolumePath);
    }
    if (!fs.existsSync(this.authVolumePath)) {
        fs.mkdirSync(this.authVolumePath);
    }
    if (!fs.existsSync(this.phraseVolumePath)) {
        fs.mkdirSync(this.phraseVolumePath);
    }
    if (!fs.existsSync(this.configPath)) {
        fs.mkdirSync(this.configPath);
        // Create a default config for the first time
        const config = new Config({});
        this.controller.setConfig(config);
    }

    // Create the auth db
    await this.controller.deployMongo(this.authVolumePath);

    // Create the lookup service
    await this.controller.deployGuardian();
}

GuardianProcess.prototype.poll = async function() {
    /*
     * Poll on config file and apply firewall config changes
     */
}

module.exports = GuardianProcess;