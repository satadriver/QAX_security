const { execSync } = require('child_process');

function getProcessIdentity() {
    const uid  = process.getuid();
    const euid = process.geteuid();
    const gid  = process.getgid();
    const egid = process.getegid();
    const groups = process.getgroups();

    let username = 'unknown';
    let homedir  = 'unknown';
    let shell    = 'unknown';
    let groupNames = [];

    try {
        const idOutput = execSync('id', { encoding: 'utf8' });
        const uidMatch = idOutput.match(/uid=(\d+)\(([^)]+)\)/);
        if (uidMatch) username = uidMatch[2];

        const groupsMatch = idOutput.match(/groups=[\d()a-zA-Z,_\s.-]+/);
        if (groupsMatch) {
            groupNames = groupsMatch[0].replace('groups=', '').split(',');
        }
    } catch {}

    return {
        username,
        uid,
        gid,
        euid,
        egid,
        isRoot:          uid === 0,
        isEffectiveRoot: euid === 0,
        groups,
        groupNames,
        homedir,
        shell,
    };
}

const identity = getProcessIdentity();
console.log(JSON.stringify(identity, null, 2));