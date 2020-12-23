import { ChildProcess, spawn } from 'child_process';
import * as fs from 'fs';
import fetch from 'node-fetch';
import * as c32check from 'c32check';

async function main() {
    const addresses = fs.readFileSync('check_addrs.txt', { encoding: 'ascii' }).split('\n');
    const accounts: {stxAddr: string, testnetAddr: string; amount: string}[] = [];
    let i = 0;
    for (const line of addresses) {
        const [addr, amount] = line.split('|');
        try {
            const stxAddr = c32check.b58ToC32(addr);
            const testnetAddr = getTestnetAddress(stxAddr);
            console.log(`${stxAddr} / ${testnetAddr}: ${amount}`);
            accounts.push({stxAddr, testnetAddr, amount});
        } catch (error) {
            console.log(`Skipping check for placeholder: ${addr}`);
        }
        i++;
        // Uncomment to limit the amount of address tested during dev.
        // The Stacks 2.0 account queries are very slow, several minutes per 100 account queries.
        /*
        if (i > 50) {
            break;
        }
        */
    }

    console.log('Starting Stacks 1.0 node...');
    const stacksNode1Proc = spawn('blockstack-core', ['start', '--foreground', '--working-dir', '/stacks1.0-chain'], { stdio: 'inherit' });
    const stacksNode1Exit = waitProcessExit(stacksNode1Proc);
    console.log('Waiting for Stacks 1.0 RPC init...');
    await waitHttpGetSuccess('http://localhost:6270/v1/info');
    console.log('Stacks 1.0 RPC online');

    for (const account of accounts) {
        const res: {balance: string} = await (await fetch(`http://localhost:6270/v1/accounts/${account.stxAddr}/STACKS/balance`)).json();
        console.log(`got: ${res.balance}, expected ${account.amount}`);
        if (res.balance !== account.amount) {
            throw new Error(`Unexpected Stacks 1.0 balance for ${account.stxAddr}. Expected ${account.amount} got ${res.balance}`);
        }
        console.log(`Stacks 2.0 has expected balance ${res.balance} for ${account.stxAddr}`);
    }

    console.log('Shutting down Stacks 1.0 node...');
    stacksNode1Proc.kill('SIGKILL');
    await stacksNode1Exit;

    console.log('Starting Stacks 2.0 node...');
    const stacksNode2Proc = spawn('stacks-node', ['mocknet'], { stdio: 'inherit' });
    const stacksNode2Exit = waitProcessExit(stacksNode2Proc);
    console.log('Waiting for Stacks 1.0 RPC init...');
    await waitHttpGetSuccess('http://localhost:20443/v2/info');
    console.log('Stacks 2.0 RPC online');

    while (true) {
        console.log('Checking for Stacks 2.0 node block initialized...')
        const res: {stacks_tip_height: number} = await (await fetch('http://localhost:20443/v2/info')).json();
        if (res.stacks_tip_height > 0) {
            break;
        }
        await timeout(1500);
    }

    for (const account of accounts) {
        const res: {balance: string} = await (await fetch(`http://localhost:20443/v2/accounts/${account.testnetAddr}`)).json();
        const balance = BigInt(res.balance).toString();
        if (balance !== account.amount) {
            throw new Error(`Unexpected Stacks 2.0 balance for ${account.testnetAddr}. Expected ${account.amount} got ${balance}`);
        }
        console.log(`Stacks 2.0 has expected balance ${balance} for ${account.testnetAddr}`);
    }

    console.log('Shutting down Stacks 2.0 node...');
    stacksNode2Proc.kill('SIGKILL');
    await stacksNode2Exit;
}

main().catch(error => {
    console.error(error);
});

function getTestnetAddress(mainnetAddress: string): string {
    const [version, hash160] = c32check.c32addressDecode(mainnetAddress);
    let testnetVersion = 0;
    if (version === c32check.versions.mainnet.p2pkh) {
        testnetVersion = c32check.versions.testnet.p2pkh;
    } else if (version === c32check.versions.mainnet.p2sh) {
        testnetVersion = c32check.versions.testnet.p2sh;
    } else {
        throw new Error(`Unexpected address version: ${version}`);
    }
    return c32check.c32address(testnetVersion, hash160);
}

async function waitProcessExit(proc: ChildProcess): Promise<Error | void> {
    return await new Promise((resolve, reject) => {
        proc.on('exit', (code, signal) => {
            if (code === 0 || signal === 'SIGKILL') {
                resolve();
            } else {
                reject(new Error(`${proc.spawnfile} exited with code ${code} signal ${signal}`));
            }
        });
    });
}

async function timeout(ms: number) {
    await new Promise<void>(res => setTimeout(res, ms));
}

async function waitHttpGetSuccess(endpoint: string, waitTime = 5 * 60 * 1000, retryDelay = 2500) {
    const startTime = Date.now();
    let fetchError: Error | undefined;
    while (Date.now() - startTime < waitTime) {
        try {
            await fetch(endpoint);
            return;
        } catch (error) {
            fetchError = error;
            console.log(`Testing connection to ${endpoint}...`);
            await timeout(retryDelay);
        }
    }
    if (fetchError) {
        throw fetchError;
    } else {
        throw new Error(`Timeout waiting for request to ${endpoint}`);
    }
}