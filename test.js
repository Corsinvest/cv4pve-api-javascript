const pve = require('./src');

console.log(pve);

async function foo() {
    const client = new pve.PveClient('10.92.90.101', 8006);
    //client.logEnabled = true;
    //client.apiToken = '';

    const login = await client.login('root', process.env.PVE_PASSWORD, 'pam');
    if (login) {
        console.log((await client.get('/version')).response);
        console.log((await client.version.version()).response);

        console.log((await client.get('/nodes')).response);
        console.log((await client.nodes.index()).response);

        console.log((await client.get('/nodes/cv-pve01/qemu')).response);
        console.log((await client.nodes.get('cv-pve01').qemu.vmlist(0)).response);

        console.log((await client.get('/nodes/cv-pve01/qemu/103/config/')).response);
        console.log((await client.nodes.get('cv-pve01').qemu.get(103).config.vmConfig()).response);

        console.log((await client.get('/nodes/cv-pve01/qemu/103/snapshot/')).response);
        console.log((await client.nodes.get('cv-pve01').qemu.get(103).snapshot.snapshotList()).response);
    }
}

foo();