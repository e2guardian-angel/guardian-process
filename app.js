'use strict';

const gProcess = require('./lib/guardian-process');
const watch = require('node-watch');

const p = new gProcess();

let configWatcher = watch(p.configFile);

// Initialize global firewall rules
p.initFirewall();

configWatcher.on('change', async function(evt, name) {
    console.log('Applying new config...');
    await p.update();
    console.log('Done');
});

async function gracefulShutdown() {
    console.info('Shutting down...');
    configWatcher.close();
    console.info('Clearing firewall rules...');
    await p.tearDownFirewall();
    console.info('guardian-process exited.');
    process.exit(0);
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
process.on('SIGHUP', gracefulShutdown);
