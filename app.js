'use strict';

const gProcess = require('./lib/guardian-process');
const watch = require('node-watch');

const p = new gProcess();

let configWatcher = watch(p.configFile);

configWatcher.on('change', async function(evt, name) {
    console.log('Applying new config...');
    await p.update();
    console.log('Done');
});

