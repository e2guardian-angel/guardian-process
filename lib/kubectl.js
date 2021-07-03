'use strict'
const fs = require('fs');
const yaml = require('yaml');
const got = require('got');
const https = require('https');

function base64decode(str) {
    const strBuffer = new Buffer.from(str, 'base64');
    return strBuffer.toString('utf-8');
}

function Kubectl(kubeConfig) {
    this.kubeConfig = yaml.parse(fs.readFileSync(kubeConfig, 'utf-8'));
    let cas = https.globalAgent.options.ca || [];
    cas.push(base64decode(this.kubeConfig.clusters[0].cluster['certificate-authority-data']));
    https.globalAgent.options.ca = cas;
}

Kubectl.prototype.getDefaultOptions = function() {
    return {
        key: base64decode(this.kubeConfig.users[0].user['client-key-data']),
        cert: base64decode(this.kubeConfig.users[0].user['client-certificate-data']),
        https: {
            certificateAuthority: base64decode(this.kubeConfig.clusters[0].cluster['certificate-authority-data'])
        }
    }
}

Kubectl.prototype.get = async function(path) {
    const options = this.getDefaultOptions();
    const result = await got.get(`${this.kubeConfig.clusters[0].cluster.server}/${path}`, options);
    return JSON.parse(result.body);
}

Kubectl.prototype.apply = async function(path, resource) {
    const options = this.getDefaultOptions();
    options.json = resource;

    let fetched;
    await this.get(path).then(resource => {
        fetched = resource;
    }).catch(function() {
        fetched = null;
    });

    let method;
    if (fetched) {
        method = got.put;
    } else {
        method = got.get;
    }
    const result = await method(`${this.kubeConfig.clusters[0].cluster.server}/${path}`, options);
    return result.body;
}

module.exports = Kubectl;