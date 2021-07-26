'use strict'
const fs = require('fs');
const path = require('path');
const yaml = require('yaml');
const https = require('https');
const got = require('got');
const crypto = require('crypto');
const joi = require('joi');
const nconf = require('nconf');
const selfSigned = require('selfsigned');
const { waitFor } = require('poll-until-promise');
const Config = require('./config');

// Local files
const GUARDIAN_CONFIG_FILE = nconf.get('GUARDIAN_ANGEL_CONF_FILE') || '/opt/guardian/guardian.json';

// Local store of all configmaps/secrets
let kubeData = {};
let savedData = {
    deployments: {
        filter: {},
        redis: {},
        dns: {}
    },
    services: {
        filter: {},
        redis: {},
        dns: {}
    }
};

function readResourceFile(filename) {
    return JSON.parse(fs.readFileSync(filename));
}

function readFileContents(path) {
    if (fs.existsSync(path)) {
        return fs.readFileSync(path, 'utf8');
    } else {
        return '';
    }
}

function base64decode(str) {
    const strBuffer = new Buffer.from(str, 'base64');
    return strBuffer.toString('utf-8');
}

function duplicateObject(obj) {
    return JSON.parse(JSON.stringify(obj));
}

function Controller(kubeConfig) {
    nconf.env('__');
    this.namespace = nconf.get('NAMESPACE');

    this.kubeConfig = yaml.parse(fs.readFileSync(kubeConfig, 'utf-8'));
    let cas = https.globalAgent.options.ca || [];
    cas.push(base64decode(this.kubeConfig.clusters[0].cluster['certificate-authority-data']));
    https.globalAgent.options.ca = cas;

    this.generatePaths(this.namespace);
    this.baseUrl =  this.kubeConfig.clusters[0].cluster.server;
    this.resources = {
        loaded: false,
        deployments: {
            webfilter: readResourceFile(`${__dirname}/json/filter-deployment.json`),
            redis: readResourceFile(`${__dirname}/json/redis-deployment.json`),
            dns: readResourceFile(`${__dirname}/json/dns-deployment.json`),
            nginx: readResourceFile(`${__dirname}/json/nginx-deployment.json`),
            mongo: readResourceFile(`${__dirname}/json/mongodb-deployment.json`),
            guardian: readResourceFile(`${__dirname}/json/guardian-deployment.json`)
        },
        services: {
            webfilter: readResourceFile(`${__dirname}/json/filter-service.json`),
            redis: readResourceFile(`${__dirname}/json/redis-service.json`),
            dns: readResourceFile(`${__dirname}/json/dns-service.json`),
            nginx: readResourceFile(`${__dirname}/json/nginx-service.json`),
            mongo: readResourceFile(`${__dirname}/json/mongodb-service.json`),
            guardian: readResourceFile(`${__dirname}/json/guardian-service.json`)
        },
        configmaps: {
            config: readResourceFile(`${__dirname}/json/guardian-conf-configmap.json`)
        },
        secrets: {
            redisPass: readResourceFile(`${__dirname}/json/redis-pass-secret.json`),
            tls: readResourceFile(`${__dirname}/json/tls-secret.json`)
        },
        volumes: {
            acl: readResourceFile(`${__dirname}/json/acl-pv.json`),
            auth: readResourceFile(`${__dirname}/json/auth-pv.json`),
            phrases: readResourceFile(`${__dirname}/json/phrases-pv.json`)
        },
        volumeClaims: {
            acl: readResourceFile(`${__dirname}/json/acl-pvc.json`),
            auth: readResourceFile(`${__dirname}/json/auth-pvc.json`),
            phrases: readResourceFile(`${__dirname}/json/phrases-pvc.json`)
        }
    };
}

Controller.prototype.generatePaths = function(namespace) {
    this.paths = {};
    this.paths.kube = {};
    this.paths.resources = {};
    // Set kube paths
    this.paths.kube.configMaps = `api/v1/namespaces/${namespace}/configmaps`;
    this.paths.kube.secrets = `api/v1/namespaces/${namespace}/secrets`;
    this.paths.kube.deployments = `apis/apps/v1/namespaces/${namespace}/deployments`;
    this.paths.kube.services = `api/v1/namespaces/${namespace}/services`;
    this.paths.kube.pods = `api/v1/namespaces/${namespace}/pods`;
    this.paths.kube.persistentVolumes = 'api/v1/persistentvolumes';
    this.paths.kube.persistentVolumeClaims = `api/v1/namespaces/${namespace}/persistentvolumeclaims`;

    // Set resource paths
    this.paths.resources.configs = {
        config: `${this.paths.kube.configMaps}/guardian-conf`
    };
    this.paths.resources.secrets = {
        tls: `${this.paths.kube.secrets}/guardian-tls`,
        redisPass: `${this.paths.kube.secrets}/redis-pass`
    };
    this.paths.resources.deployments = {
        redis: `${this.paths.kube.deployments}/redis`,
        webfilter: `${this.paths.kube.deployments}/webfilter`,
        dns: `${this.paths.kube.deployments}/dns`,
        nginx: `${this.paths.kube.deployments}/nginx`,
        mongo: `${this.paths.kube.deployments}/auth-db`,
        guardian: `${this.paths.kube.deployments}/guardian-angel`
    };
    this.paths.resources.services = {
        redis: `${this.paths.kube.services}/redis`,
        webfilter: `${this.paths.kube.services}/webfilter`,
        dns: `${this.paths.kube.services}/dns`,
        nginx: `${this.paths.kube.services}/nginx`,
        mongo: `${this.paths.kube.services}/auth-db`,
        guardian: `${this.paths.kube.services}/guardian-angel`
    };
    this.paths.resources.volumes = {
        auth: `${this.paths.kube.persistentVolumes}/auth-db`,
        acl: `${this.paths.kube.persistentVolumes}/acl-db`
    };
    this.paths.resources.volumeClaims = {
        auth: `${this.paths.kube.persistentVolumeClaims}/auth-db-pvc`,
        acl: `${this.paths.kube.persistentVolumeClaims}/acl-db-pvc`
    }
};

/*
 * Kubernetes operations
 */
Controller.prototype.kubeOp = async function(op, path, options) {
    const url = `${this.baseUrl}/${path}`;
    return await op(url, options);
}

Controller.prototype.getDefaultOptions = function() {
    let options = {
        responseType: 'json',
        headers: {
            'Accept': 'application/json',
        },
        https: {
            key: base64decode(this.kubeConfig.users[0].user['client-key-data']),
            certificate: base64decode(this.kubeConfig.users[0].user['client-certificate-data']),
            certificateAuthority: base64decode(this.kubeConfig.clusters[0].cluster['certificate-authority-data'])
        }
    }
    return options;
};

Controller.prototype.kubePost = async function(path, data) {
    let options = this.getDefaultOptions();
    options.json = data;
    return this.kubeOp(got.post, path, options);
};

Controller.prototype.kubePut = async function(path, data) {
    let options = this.getDefaultOptions();
    options.json = data;
    return this.kubeOp(got.put, path, options);
};

Controller.prototype.kubeGet = async function(path) {
    let options = this.getDefaultOptions();
    return this.kubeOp(got.get, path, options);
};

Controller.prototype.kubeDelete = async function(path) {
    let options = this.getDefaultOptions();
    return this.kubeOp(got.delete, path, options);
};

/*
 * kubeApply is the equivalent of "kubectl apply -f" - it checks if the resource exists,
 * and performs either a POST or PUT, respectively
 */
Controller.prototype.kubeApply = async function(kubePath, resourcePath, resource) {
    // Get resource; if it exists, then PUT, else POST
    let fetched;
    await this.kubeGet(resourcePath).then(resource => {
        fetched = resource;
    }).catch(function() {
        fetched = null;
    });
    if (fetched) {
        return (await this.kubePut(resourcePath, resource)).statusCode;
    } else {
        return (await this.kubePost(kubePath, resource)).statusCode;
    }
};

/*
 * kubeApply for services, since we need clusterIP and resourceVersion
 */
Controller.prototype.kubeApplyService = async function(kubePath, resourcePath, resource) {
    // Get resource; if it exists, then PUT, else POST
    let fetched;
    await this.kubeGet(resourcePath).then(resource => {
        fetched = resource;
    }).catch(function() {
        fetched = null;
    });

    if (fetched) {
        resource.metadata.resourceVersion = fetched.body.metadata.resourceVersion
        resource.spec.clusterIP = fetched.body.spec.clusterIP;
        resource.spec.clusterIPs = fetched.body.spec.clusterIPs;
        return (await this.kubePut(resourcePath, resource)).statusCode;
    } else {
        return (await this.kubePost(kubePath, resource)).statusCode;
    }
};

Controller.prototype.kubeDeleteIfExists = async function(path) {
    let fetched;
    await this.kubeGet(path).then(resource => {
        fetched = resource;
    }).catch(function() {
        fetched = null;
    });

    if (fetched) {
        return (await this.kubeDelete(path)).statusCode;
    }
    return 0;
}

/*
 * Guardian config operations
 */
Controller.prototype.setConfig = function(config) {
    kubeData.config = new Config(config);
};

Controller.prototype.getConfig = function() {
    return kubeData.config || new Config({});
};

Controller.prototype.pushConfig = async function() {
    if (!kubeData.config) {
        throw new Error('Config not set');
    }
    try {
        let configResource = duplicateObject(this.resources.configmaps.config);
        configResource.data[path.basename(GUARDIAN_CONFIG_FILE)] = JSON.stringify(kubeData.config);
        return await this.kubeApply(this.paths.kube.configMaps, this.paths.resources.configs.config, configResource);
    } catch (err) {
        const message = `Failed to push guardian config: \n${err.message}`;
        console.error(message);
        throw new Error(message);
    }
};

Controller.prototype.pullConfig = async function() {
    try {
        let response = await this.kubeGet(this.paths.resources.configs.config);
        kubeData.config = JSON.parse(response.body.data[path.basename(GUARDIAN_CONFIG_FILE)]);
        savedData.config = duplicateObject(kubeData.config);
        return kubeData.config;
    } catch (err) {
        console.info('No config in ConfigMap');
        return null;
    }
};

Controller.prototype.writeConfigFile = function() {
    fs.writeFileSync(GUARDIAN_CONFIG_FILE, JSON.stringify(kubeData.config), {flag: 'w'});
};

/*
 * Redis password operations
 */
Controller.prototype.setRedisPassword = function(redisPass) {
    kubeData.redisPass = joi.attempt(redisPass, joi.string().min(40).regex(/^[0-9a-f]+$/));
};

Controller.prototype.getRedisPassword = function() {
    return kubeData.redisPass;
};

Controller.prototype.rotateRedisPassword = function() {
    const newPassword = crypto.randomBytes(20).toString('hex');
    this.setRedisPassword(newPassword);
};

Controller.prototype.pushRedisPassword = async function() {
    if (!kubeData.redisPass) {
        throw new Error('Redis password not set');
    }
    try {
        let passBuffer = new Buffer.from(kubeData.redisPass);
        let secretResource = duplicateObject(this.resources.secrets.redisPass);
        secretResource.data.REDIS_PASS = passBuffer.toString('base64');
        return await this.kubeApply(this.paths.kube.secrets, this.paths.resources.secrets.redisPass, secretResource);
    } catch (err) {
        const message = `Failed to create redis secret: ${err.message}`;
        console.error(message);
        throw new Error(message);
    }
};

Controller.prototype.pullRedisPassword = async function() {
    try {
        const secretResource = await this.kubeGet(this.paths.resources.secrets.redisPass)
        let passBuffer = Buffer.from(secretResource.body.data.REDIS_PASS, 'base64');
        kubeData.redisPass = passBuffer.toString('utf-8')
        savedData.redisPass = kubeData.redisPass;
        return kubeData.redisPass;
    } catch (err) {
        console.info('No redis password stored in secret or env var');
        return null;
    }
};

/*
 * TLS cert/key operations
 */
Controller.prototype.setTLS = function(tlsData) {
    const schema = joi.object({
        cert: joi.string().min(1).required(),
        key: joi.string().min(1).required()
    });
    kubeData.tls = joi.attempt(tlsData, schema);
};

Controller.prototype.getTLS = function() {
    return kubeData.tls;
};

Controller.prototype.pullTLS = async function() {
    try {
        let tlsResource = await this.kubeGet(this.paths.resources.secrets.tls);
        let certBuffer = Buffer.from(tlsResource.body.data['tls.crt'], 'base64');
        kubeData.tls = {};
        kubeData.tls.cert = certBuffer.toString('utf-8');
        // Don't store the key locally since we aren't using it
        savedData.tls = duplicateObject(kubeData.tls);
        return kubeData.tls;
    } catch (err) {
        console.info('No certificate locally or in ConfigMap');
        return null;
    }
};

Controller.prototype.pushTLS = async function() {
    if (!kubeData.tls.key) {
        // only push if the key is set locally
        return null;
    }
    try {
        let certBuffer = new Buffer.from(kubeData.tls.cert);
        let keyBuffer = new Buffer.from(kubeData.tls.key);
        let tlsResource = duplicateObject(this.resources.secrets.tls);
        tlsResource.data['tls.crt'] = certBuffer.toString('base64');
        tlsResource.data['tls.key'] = keyBuffer.toString('base64');
        const result = await this.kubeApply(this.paths.kube.secrets, this.paths.resources.secrets.tls, tlsResource);
        // erase local tls secret
        delete kubeData.tls.key;
        return result;
    } catch(err) {
        const message = `Failed to push TLS data: ${err.message}`
        console.error(message);
        throw new Error(message);
    }
};

Controller.prototype.rotateTLS = async function() {
    const attrs = [
        {name: 'countryName', value: kubeData.config.caInfo.country},
        {name: 'stateOrProvinceName', value: kubeData.config.caInfo.state},
        {name: 'localityName', value: kubeData.config.caInfo.city},
        {name: 'organizationName', value: kubeData.config.caInfo.organization},
        {name: 'organizationalUnitName', value: kubeData.config.caInfo.organizationalUnit},
        {name: 'commonName', value: kubeData.config.caInfo.commonName},
        {name: 'emailAddress', value: kubeData.config.caInfo.email}
    ];
    const pem = selfSigned.generate(attrs, {days: kubeData.config.caInfo.days});
    this.setTLS({
        cert: pem.cert,
        key: pem.private
    });
};

/*
 * Render resources based on the config
 */
Controller.prototype.renderFilterDeployment = function() {
    let filterResource = duplicateObject(this.resources.deployments.webfilter);
    if (!kubeData.config.sslBumpEnabled) {
        let squidContainer = filterResource.spec.template.spec.containers.find(
            container => container.name === 'squid'
        );
        // Delete the guardian tls mount since we aren't using it
        squidContainer.volumeMounts = squidContainer.volumeMounts.filter(
            mount => mount.name !== 'guardian-tls-volume'
        );
        // Remove the e2guardian container since we won't be using it
        filterResource.spec.template.spec.containers = filterResource.spec.template.spec.containers.filter(
            container => container.name !== 'e2guardian'
        );
        // Remove the tls volume since we aren't using it
        filterResource.spec.template.spec.volumes = filterResource.spec.template.spec.volumes.filter(
            volume => volume.name !== 'guardian-tls-volume'
        );
    }
    if (!kubeData.config.transparent) {
        // Remove the transocks container since we won't be using it
        filterResource.spec.template.spec.containers = filterResource.spec.template.spec.containers.filter(
            container => container.name !== 'transocks'
        );
    }
    return filterResource;
};

Controller.prototype.renderFilterService = function() {
    let filterServiceResource = duplicateObject(this.resources.services.webfilter);
    if (!kubeData.config.transparent) {
        // Remove transocks port since we won't be using it
        filterServiceResource.spec.ports = filterServiceResource.spec.ports.filter(
            port => port.name !== 'transocks'
        );
    }
    return filterServiceResource;
};

Controller.prototype.renderNginxDeployment = function() {
    let nginx = duplicateObject(this.resources.deployments.nginx);
    if (!kubeData.config.httpsEnabled) {
        // Remove TLS mount
        nginx.spec.template.spec.containers.forEach(container => {
            container.volumeMounts = container.volumeMounts.filter(mount => mount.name !== 'guardian-tls-volume');
        });
        // Remove TLS volume
        nginx.spec.template.spec.volumes = nginx.spec.template.spec.volumes.filter(
            volume => volume.name !== 'guardian-tls-volume'
        );
    }
    return nginx;
}

Controller.prototype.renderNginxService = function() {
    let nginx = duplicateObject(this.resources.services.nginx);
    if (!kubeData.config.httpsEnabled) {
        nginx.spec.ports = nginx.spec.ports.filter(port => port.name !== 'https');
    }
    return nginx;
}

Controller.prototype.renderAuthVolume = function(path) {
    let authPv = duplicateObject(this.resources.volumes.auth);
    let authPvc = duplicateObject(this.resources.volumeClaims.auth);
    authPv.spec.local.path = path;
    return {
        pv: authPv,
        pvc: authPvc
    };
}

Controller.prototype.renderPhraseVolume = function(path) {
    let phrasePv = duplicateObject(this.resources.volumes.phrases);
    let phrasePvc = duplicateObject(this.resources.volumeClaims.phrases);
    phrasePv.spec.local.path = path;
    return {
        pv: phrasePv,
        pvc: phrasePvc
    };
}

Controller.prototype.renderAclVolume = function(path) {
    let aclPv = duplicateObject(this.resources.volumes.acl);
    let aclPvc = duplicateObject(this.resources.volumeClaims.acl);
    aclPv.spec.local.path = path;
    return {
        pv: aclPv,
        pvc: aclPvc
    };
}

/*
 * Poll until pods are all ready
 */
Controller.prototype.pollUntilReady = async function() {
    let errorMessage = '';
    await waitFor(async () => {
        const pods = await this.kubeGet(this.paths.kube.pods);
        pods.body.items.forEach(pod => {
            pod.status.containerStatuses.forEach(containerStatus => {
                // Don't wait on a container that is never coming up
                if (
                    containerStatus.state.waiting &&
                    containerStatus.state.waiting.reason === 'CrashLoopBackoff'
                ) {
                    errorMessage = 'Error when creating container';
                    return;
                }
            });
            if (!pod.status.phase) {
                throw new Error ('Pod phase is missing');
            }
            if (pod.status.phase !== 'Running') {
                throw new Error('Pods are still coming up');
            }
            if(pod.metadata.deletionTimestamp) {
                throw new Error('Pods are not done deleting');
            }
        });
        return;
    }, {
        interval: 1000,
        timeout: 300000
    });
    if (errorMessage) {
        throw new Error(errorMessage);
    }
};

/*
 * Push deployments and services
 */
Controller.prototype.deployFilter = async function() {
    const deploymentResource = this.renderFilterDeployment();
    const serviceResource = this.renderFilterService();

    try {
        await this.kubeApply(
            this.paths.kube.deployments,
            this.paths.resources.deployments.webfilter,
            deploymentResource
        );
        await this.kubeApplyService(
            this.paths.kube.services,
            this.paths.resources.services.webfilter,
            serviceResource
        );
    } catch (err) {
        throw new Error(`Failed to deploy webfilter deployment: ${err.message}`);
    }

    return 'OK';
}

Controller.prototype.deployRedis = async function() {
    const deploymentResource = this.resources.deployments.redis;
    const serviceResource = this.resources.services.redis;

    if (!kubeData.redisPass) {
        throw new Error('Cannot deploy redis, password not set');
    }

    try {
        await this.kubeApply(this.paths.kube.deployments, this.paths.resources.deployments.redis, deploymentResource);
        await this.kubeApplyService(this.paths.kube.services, this.paths.resources.services.redis, serviceResource);
    } catch (err) {
        throw new Error(`Failed to deploy redis: ${err.message}`);
    }

    return 'OK';
}

Controller.prototype.deployDNS = async function() {
    const deploymentResource = this.resources.deployments.dns;
    const serviceResource = this.resources.services.dns;

    if (!kubeData.redisPass) {
        throw new Error('Cannot deploy DNS, redis password not set');
    }

    try {
        await this.kubeApply(this.paths.kube.deployments, this.paths.resources.deployments.dns, deploymentResource);
        await this.kubeApplyService(this.paths.kube.services, this.paths.resources.services.dns, serviceResource);
    } catch (err) {
        throw new Error(`Failed to deploy DNS: ${err.message}`);
    }

    return 'OK';
}

Controller.prototype.deployNginx = async function() {
    const deploymentResource = this.renderNginxDeployment();
    const serviceResource = this.renderNginxService();

    if(kubeData.config.httpsEnabled && !kubeData.tls) {
        throw new Error('Cannot deploy Nginx, TLS certificate/key not set');
    }

    let step;
    try {
        step = 'deployment';
        await this.kubeApply(this.paths.kube.deployments, this.paths.resources.deployments.nginx, deploymentResource);
        step = 'service';
        await this.kubeApplyService(this.paths.kube.services, this.paths.resources.services.nginx, serviceResource);
    } catch (err) {
        throw new Error(`Failed to deploy nginx ${step}: ${err.message}`);
    }

    return 'OK';
}

Controller.prototype.deployMongo = async function(authVolumePath) {
    const authVol = this.renderAuthVolume(authVolumePath);
    const deploymentResource = this.resources.deployments.mongo;
    const serviceResource = this.resources.services.mongo;

    let step;
    // Create volume if it isn't already created
    await this.kubeGet(this.paths.resources.volumes.auth).catch(async err => {
        try {
            await this.kubeApply(this.paths.kube.persistentVolumes, this.paths.resources.volumes.auth, authVol.pv);
        } catch (err) {
            throw new Error(`Failed to deploy auth-db: ${err.message}`);
        }
    });
    await this.kubeGet(this.paths.resources.volumeClaims.auth).catch(async err => {
        try {
            await this.kubeApply(this.paths.kube.persistentVolumeClaims, this.paths.resources.volumeClaims.auth, authVol.pvc);
        } catch (err) {
            throw new Error(`Failed to deploy auth-db-pv: ${err.message}`);
        }
    });
    try {
        step = 'deployment';
        await this.kubeApply(this.paths.kube.deployments, this.paths.resources.deployments.mongo, deploymentResource);
        step = 'service';
        await this.kubeApplyService(this.paths.kube.services, this.paths.resources.services.mongo, serviceResource);
    } catch (err) {
        throw new Error(`Failed to deploy nginx ${step}: ${err.message}`);
    }

    return 'OK';
}

Controller.prototype.deployGuardian = async function(aclVolumePath, phraseVolumePath) {
    const aclVol = this.renderAclVolume(aclVolumePath);
    const phraseVol = this.renderPhraseVolume(phraseVolumePath);
    const deploymentResource = this.resources.deployments.guardian;
    const serviceResource = this.resources.services.guardian;

    // Create volumes if they aren't already created
    await this.kubeGet(this.paths.resources.volumes.acl).catch(async err => {
        try {
            await this.kubeApply(this.paths.kube.persistentVolumes, this.paths.resources.volumes.acl, aclVol.pv);
        } catch (err) {
            throw new Error(`Failed to deploy acl-db: ${err.message}`);
        }
    });
    await this.kubeGet(this.paths.resources.volumeClaims.acl).catch(async err => {
        try {
            await this.kubeApply(this.paths.kube.persistentVolumeClaims, this.paths.resources.volumeClaims.acl, aclVol.pvc);
        } catch (err) {
            throw new Error(`Failed to deploy acl-db-pv: ${err.message}`);
        }
    });
    await this.kubeGet(this.paths.resources.volumes.phrases).catch(async err => {
        try {
            await this.kubeApply(this.paths.kube.persistentVolumes, this.paths.resources.volumes.phrases, phraseVol.pv);
        } catch (err) {
            throw new Error(`Failed to deploy phrases vol: ${err.message}`);
        }
    });
    await this.kubeGet(this.paths.resources.volumeClaims.phrases).catch(async err => {
        try {
            await this.kubeApply(this.paths.kube.persistentVolumeClaims, this.paths.resources.volumeClaims.phrases, phraseVol.pvc);
        } catch (err) {
            throw new Error(`Failed to deploy phrases pv: ${err.message}`);
        }
    });
    let step;
    try {
        step = 'deployment';
        await this.kubeApply(this.paths.kube.deployments, this.paths.resources.deployments.guardian, deploymentResource);
        step = 'service';
        await this.kubeApplyService(this.paths.kube.services, this.paths.resources.services.guardian, serviceResource);
    } catch (err) {
        throw new Error(`Failed to deploy guardian-angel ${step}: ${err.message}`);
    }

    return 'OK';
}

Controller.prototype.reloadPod = async function(pods, prefix) {
    const targetPods = pods.filter(pod => {
        return pod.metadata.name.startsWith(prefix);
    });
    const promises = targetPods.map(targetPod => {
        const podPath = `${this.paths.kube.pods}/${targetPod.metadata.name}`;
        return this.kubeDeleteIfExists(podPath);
    });
    await Promise.all(promises);
}

/*
 * reload pods that are affected by updates to config and secrets
 */
Controller.prototype.reloadPods = async function(pods) {
    // Reload webfilter on any config change
    const reloadWebFilter = (
        JSON.stringify(kubeData.config) !== JSON.stringify(savedData.config) ||
        JSON.stringify(kubeData.tls) !== JSON.stringify(savedData.tls)
    );
    // Reload redis if the redis password changes
    const reloadRedis = (kubeData.redisPass !== savedData.redisPass);
    // Reload dns on redis password change or safesearch
    const reloadDNS = (
        kubeData.redisPass !== savedData.redisPass ||
        kubeData.config.safeSearchEnforced !== savedData.config.safeSearchEnforced
    );
    // Reload nginx on TLS change or change to httpsEnabled
    const reloadNginx = (
        JSON.stringify(kubeData.tls) !== JSON.stringify(savedData.tls) ||
        kubeData.config.httpsEnabled != savedData.config.httpsEnabled
    );

    let step;
    try {
        step = 'redis';
        if (reloadRedis) {
            await this.reloadPod(pods, 'redis');
        }
        await this.pollUntilReady();

        step = 'webfilter';
        if (reloadWebFilter) {
            await this.reloadPod(pods, 'webfilter');
        }

        step = 'dns';
        if (reloadDNS) {
            await this.reloadPod(pods, 'dns');
        }

        step = 'nginx';
        if (reloadNginx) {
            await this.reloadPod(pods, 'nginx');
        }

        await this.pollUntilReady();
    } catch (err) {
        throw new Error(`Error reloading ${step} pods: ${err.message}`);
    }

}

/*
 * getKubeData is called upon initialization. It fetches all the kubernetes data needed
 * to run guardian, and stores it locally.
 */
Controller.prototype.getKubeData = async function() {
    kubeData.config = await this.pullConfig() || new Config({});
    kubeData.redisPass = await this.pullRedisPassword();
    kubeData.tls = await this.pullTLS();
    try {
        kubeData.nginx = await this.kubeGet(paths.resources.deployments.nginx);
    } catch (err) {
        kubeData.nginx = null;
    }

    Object.assign(savedData, duplicateObject(kubeData))
    return kubeData;
}

Controller.prototype.clearKubeData = async function() {
    delete kubeData.redisPass;
    delete kubeData.tls;
    delete kubeData.config;
};

/*
 * Initialize secrets if they have not been set
 */
Controller.prototype.initializeSecrets = async function() {
    if (!kubeData.config) {
        throw new Error('Configuration not set');
    }
    if (!kubeData.redisPass) {
        this.rotateRedisPassword();
    }
    if (!kubeData.tls) {
        await this.rotateTLS();
    }
};

/*
 * Tear down everything
 */
Controller.prototype.tearDown = async function() {
    await this.kubeDeleteIfExists(this.paths.resources.deployments.webfilter);
    await this.kubeDeleteIfExists(this.paths.resources.services.webfilter);
    await this.kubeDeleteIfExists(this.paths.resources.deployments.dns);
    await this.kubeDeleteIfExists(this.paths.resources.services.dns);
    await this.kubeDeleteIfExists(this.paths.resources.deployments.redis);
    await this.kubeDeleteIfExists(this.paths.resources.services.redis);
    await this.kubeDeleteIfExists(this.paths.resources.deployments.nginx);
    await this.kubeDeleteIfExists(this.paths.resources.services.nginx);
    await this.kubeDeleteIfExists(this.paths.resources.deployments.mongo);
    await this.kubeDeleteIfExists(this.paths.resources.services.mongo);
    await this.kubeDeleteIfExists(this.paths.resources.deployments.guardian);
    await this.kubeDeleteIfExists(this.paths.resources.services.guardian);
};

/*
 * Delete kube data
 */
Controller.prototype.eraseKubeData = async function() {
    await this.kubeDeleteIfExists(this.paths.resources.secrets.redisPass);
    await this.kubeDeleteIfExists(this.paths.resources.secrets.tls);
    await this.kubeDeleteIfExists(this.paths.resources.configs.config);
    await this.kubeDeleteIfExists(this.paths.resources.volumeClaims.auth);
    await this.kubeDeleteIfExists(this.paths.resources.volumeClaims.acl);
    await this.kubeDeleteIfExists(this.paths.resources.volumes.auth);
    await this.kubeDeleteIfExists(this.paths.resources.volumes.acl);
};

module.exports = Controller;