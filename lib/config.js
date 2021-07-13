'use strict'

const joi = require('joi');
const nconf = require('nconf');

function validate(config) {
    const schema = joi.object({
        localNetwork: joi.string().min(1).default('192.168.4.0/24'),
        configured: joi.boolean().default(false),
        namespace: joi.string().min(1).default('default'),
        squidConfigDir: joi.string().min(1).default('/etc/squid'),
        proxyHost: joi.string().min(1).default('squid'),
        proxyPort: joi.number().min(1).max(65535).default(3128),
        e2guardianConfigDir: joi.string().min(1).default('/opt/etc/e2guardian'),
        httpsEnabled: joi.bool().default(false),
        networkConfig: joi.object({
            local: joi.boolean().default(false),
            gateway: joi.boolean().default(false),
            wifi: joi.boolean().default(false),
            vpn: joi.boolean().default(false),
            wan: joi.string().min(1).default('eth0'),
            lan: joi.array().items(joi.string().min(1)).default([])
        }).default(),
        httpPort: joi.number().min(1).max(65536).default(3000),
        httpsPort: joi.number().min(1).max(65536).default(3443),
        transparent: joi.bool().default(false),
        sslBumpEnabled: joi.bool().default(false),
        safeSearchEnforced: joi.bool().default(false),
        aclDatabaseFile: joi.string().min(1).default('/opt/guardian/acl/acls.db'),
        allowRules: joi.array().items(joi.object({
            category: joi.string().min(1).required(),
            allow: joi.boolean().required()
        })).default([{ category: 'all', allow: true }]),
        authDb: joi.object({
            host: joi.string().min(1).default('auth-db')
        }).default(),
        decryptRules: joi.array().items(joi.object({
            category: joi.string().min(1).required(),
            decrypt: joi.boolean().required()
        })).default([{ category: 'all', decrypt: false }]),
        caInfo: joi.object({
            country: joi.string().min(1).default('US'),
            state: joi.string().min(1).default('TX'),
            city: joi.string().min(1).default('Austin'),
            organization: joi.string().min(1).default('GuardianAngel'),
            organizationalUnit: joi.string().min(1).default('RootCerts'),
            commonName: joi.string().min(1).default('guardian.angel'),
            email: joi.string().email().default('guardian.angel@example.com'),
            days: joi.number().min(1).max(36500).default(3650)
        }).default(),
        redisConfig: joi.object({
            host: joi.string().min(1).default('redis'),
            port: joi.number().min(1).max(65535).default(6379),
            family: joi.number().valid(4, 6).optional(),
            password: joi.string().min(1).optional()
        }).default(),
        cacheConfig: joi.object({
            ttl: joi.number().min(1).default(90),
            maxKeys: joi.number().min(100).default(8192)
        }).default(),
        helper: joi.object({
            host: joi.string().min(1).default('guardian-angel'),
            port: joi.number().min(1).max(65535).default(3000)
        }).default(),
        e2guardianConf: joi.object({
            phraseLists: joi.array().items(joi.object({
                listName: joi.string().min(1).required(),
                groups: joi.array().min(1).items(joi.object({
                    groupName: joi.string().min(1).required(),
                    phrases: joi.array().min(1).items(
                        joi.array().min(1).items(joi.string()).required()
                    )
                })).min(1).required()
            })).default([]),
            siteLists: joi.array().items(joi.object({
                listName: joi.string().min(1).required(),
                groups: joi.array().items(joi.object({
                    groupName: joi.string().min(1).required(),
                    sites: joi.array().min(1).items(
                        joi.string().min(1).required()
                    ).min(1).required()
                })).min(1).required()
            })).default([]),
            regexpurllists: joi.array().items(joi.object({
                listName: joi.string().required(),
                groups: joi.array().min(1).items(joi.object({
                    groupName: joi.string().min(1).required(),
                    patterns: joi.array().min(1).items(
                        joi.string().min(1).required()
                    ).min(1).required()
                })).min(1).required()
            })).default([]),
            mimetypelists: joi.array().items(joi.object({
                listName: joi.string().min(1).required(),
                groups: joi.array().items(joi.object({
                    groupName: joi.string().min(1).required(),
                    types: joi.array().min(1).items(
                        joi.string().min(1).required()
                    ).min(1).required()
                })).min(1).required()
            })).default([]),
            extensionslists: joi.array().items(joi.object({
                listName: joi.string().min(1).required(),
                groups: joi.array().items(joi.object({
                    groupName: joi.string().min(1).required(),
                    extensions: joi.array().min(1).items(
                        joi.string().min(1).required()
                    ).min(1).required()
                })).min(1).required()
            })).default([])
        }).default()
    });
    return joi.attempt(config, schema, {allowUnknown: true, stripUnknown: true});
} // end validate

// Resolved config object
function Config(info) {
    // Read environment variables
    nconf.env('__');

    let config = {}
    if (info) {
        config = info;
    } else {
        config.localNetwork = nconf.get('LOCAL_NETWORK');
        config.squidConfigDir = nconf.get('SQUID_CONFIG_DIR');
        config.proxyPort = nconf.get('SQUID_PROXY_PORT');
        config.e2guardianConfigDir = nconf.get('E2GUARDIAN_CONFIG_DIR');
        config.httpsEnabled = nconf.get('HTTPS_ENABLED');
        config.transparent = nconf.get('TRANSPARENT');
        config.sslBumpEnabled = nconf.get('SSL_BUMP_ENABLED');
        config.caInfo = {};
        config.caInfo.country = nconf.get('CERT_COUNTRY_CODE');
        config.caInfo.state = nconf.get('CERT_STATE');
        config.caInfo.city = nconf.get('CERT_CITY');
        config.caInfo.organization = nconf.get('CERT_ORGANIZATION');
        config.caInfo.organizationalUnit = nconf.get('CERT_ORGUNIT');
        config.caInfo.commonName = nconf.get('CERT_CN');
        config.caInfo.email = nconf.get('CERT_EMAIL');
        config.redisConfig = {};
        config.redisConfig.host = nconf.get('REDIS_HOST');
        config.cacheConfig = {};
        config.cacheConfig.ttl = nconf.get('CACHE_CONFIG_TTL');
        config.cacheConfig.maxKeys = nconf.get('CACHE_CONFIG_MAX_KEYS');
    }

    const validatedConfig = validate(config);
	
    Object.assign(this, validatedConfig);
}

module.exports = Config;
