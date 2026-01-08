let pkg = null;

try {
    pkg = require('elliptic/package.json');
} catch (e) {
    if (e.code !== 'MODULE_NOT_FOUND') {
        throw e;
    }
}

// If we found the real elliptic (not our shim), block it
if (pkg !== null && pkg.name === 'elliptic' && !pkg.version.startsWith('99')) {
    console.error('\nSECURITY BLOCK');
    console.error('   The unsafe original "elliptic" package was detected.');
    console.error('   @soatok/elliptic-to-noble (powered by @noble/curves) is in use instead.');
    console.error('   This installation has been aborted for security.\n');
    process.exit(1);
}
