import { ChildProcess, execFile, spawn } from 'child_process';
import fetch from 'node-fetch';

// ## Get account balance [GET /v1/accounts/{address}/{tokenType}/balance]


async function main() {
    console.log('Starting Stacks 1.0 node...');
    const stacksNode1Proc = spawn('blockstack-core', ['start', '--foreground', '--working-dir', '/stacks1.0-chain'], { stdio: 'inherit' });
    const stacksNode1Exit = waitProcessExit(stacksNode1Proc);
    console.log('Waiting for Stacks 1.0 RPC init...');
    await awaitHttpGetSuccess('http://localhost:6270/v1/info');
    console.log('Stacks 1.0 RPC online');

    console.log('Starting Stacks 2.0 node...');
    const stacksNode2Proc = spawn('stacks-node', ['mocknet'], { stdio: 'inherit' });
    const stacksNode2Exit = waitProcessExit(stacksNode2Proc);
    console.log('Waiting for Stacks 1.0 RPC init...');
    await awaitHttpGetSuccess('http://localhost:20443/v2/info');
    console.log('Stacks 2.0 RPC online');

    await Promise.race([stacksNode1Exit, stacksNode2Exit]);
}

main().catch(error => {
    console.error(error);
});

async function waitProcessExit(proc: ChildProcess): Promise<Error | void> {
    return await new Promise((resolve, reject) => {
        proc.on('exit', code => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`${proc.spawnfile} exited with code ${code}`));
            }
        });
    });
}

async function timeout(ms: number) {
    await new Promise<void>(res => setTimeout(res, ms));
}

async function awaitHttpGetSuccess(endpoint: string, waitTime = 5 * 60 * 1000, retryDelay = 2500) {
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