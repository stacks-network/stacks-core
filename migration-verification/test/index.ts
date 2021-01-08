import { ChildProcess, spawn } from 'child_process';
import * as fs from 'fs';
import fetch from 'node-fetch';
import * as c32check from 'c32check';
import * as stxTx from '@stacks/transactions';

interface LockupSchedule {
    stxAddr: string; testnetAddr: string; amount: string; height: number;
}

async function main() {

    // Get the Stacks 1.0 block height of when the export was triggered.
    const exportBlockHeight = parseInt(fs.readFileSync('/stacks1.0/export_block', {encoding: 'ascii'}));
    console.log(`Export block height: ${exportBlockHeight}`);

    // Parse the sample of account lockups from Stacks 1.0.
    const lockups = fs.readFileSync('check_lockups.txt', { encoding: 'ascii'}).split('\n');
    const schedules: LockupSchedule[] = [];
    const lockupMap = new Map<number, LockupSchedule[]>();
    for (const line of lockups) {
        const [addr, amount, block] = line.split('|');
        const blockHeight = parseInt(block);
        if (blockHeight < exportBlockHeight) {
            // Ignore schedules that have unlocked since the export block height.
            continue;
        }
        try {
            const stxAddr = c32check.b58ToC32(addr);
            const testnetAddr = getTestnetAddress(stxAddr);
            // Get the expected Stacks 2.0 block height.
            const stacks2Height = blockHeight - exportBlockHeight;
            const schedule: LockupSchedule = {stxAddr, testnetAddr, amount, height: stacks2Height};
            schedules.push(schedule);
            const blockSchedules = lockupMap.get(stacks2Height) ?? [];
            blockSchedules.push(schedule);
            lockupMap.set(stacks2Height, blockSchedules);
        } catch (error) {
            console.log(`Skipping check for placeholder lockup: ${addr}`);
        }
    }
    console.log(`Validating lockup schedules:\n${JSON.stringify(schedules)}`);

    const expectedHeights = new Set([...schedules].sort((a, b) => a.height - b.height).map(s => s.height));
    console.log(`Checking lockup schedules at heights: ${[...expectedHeights].join(', ')}`);

    // Parse the sample of address balances from Stacks 1.0.
    const addresses = fs.readFileSync('check_addrs.txt', { encoding: 'ascii' }).split('\n');
    const accounts: {stxAddr: string; testnetAddr: string; amount: string}[] = [];
    let i = 0;
    for (const line of addresses) {
        const [addr, amount] = line.split('|');
        try {
            const stxAddr = c32check.b58ToC32(addr);
            const testnetAddr = getTestnetAddress(stxAddr);
            accounts.push({stxAddr, testnetAddr, amount});
        } catch (error) {
            console.log(`Skipping check for placeholder balance: ${addr}`);
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

    // Start the Stacks 2.0 node process
    console.log('Starting Stacks 2.0 node...');
    const stacksNode2Proc = spawn('stacks-node', ['mocknet'], { stdio: 'inherit' });
    const stacksNode2Exit = waitProcessExit(stacksNode2Proc);

    // Wait until the Stacks 2.0 RPC server is responsive.
    console.log('Waiting for Stacks 2.0 RPC init...');
    await waitHttpGetSuccess('http://localhost:20443/v2/info');
    console.log('Stacks 2.0 RPC online');

    // Wait until the Stacks 2.0 node has mined the first block, otherwise RPC queries fail.
    while (true) {
        console.log('Checking for Stacks 2.0 node block initialized...')
        const res: {stacks_tip_height: number} = await (await fetch('http://localhost:20443/v2/info')).json();
        if (res.stacks_tip_height > 0) {
            break;
        }
        await timeout(1500);
    }

    // Query the Stacks 2.0 lockup contract, ensuring the exported Stacks 1.0 lockups match.
    for (let [blockHeight, lockupSchedule] of lockupMap) {
        // Fetch the lockup schedules for the current block height.
        const queryUrl = "http://localhost:20443/v2/map_entry/ST000000000000000000002AMW42H/lockup/lockups?proof=0";
        const clarityCv = stxTx.uintCV(blockHeight);
        const serialized = '0x' + stxTx.serializeCV(clarityCv).toString('hex');
        const res = await fetch(queryUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: `"${serialized}"`
        });
        const resData: {data: string} = await res.json();

        // Deserialize the Clarity value response into regular objects.
        const clarityVal = stxTx.deserializeCV(Buffer.from(resData.data.substr(2), 'hex'));
        if (clarityVal.type !== stxTx.ClarityType.OptionalSome) {
            throw new Error(`Expected lockup schedules at block height ${blockHeight}`)
        }
        const contractSchedules: LockupSchedule[] = [];
        const clarityList = (clarityVal.value as any).list;
        for (const tupleVal of clarityList) {
            const amount = tupleVal.data['amount'].value.toString();
            const recipient = tupleVal.data['recipient'];
            const testnetAddr = c32check.c32address(recipient.address.version, recipient.address.hash160);
            const stxAddr = getMainnetAddress(testnetAddr);
            contractSchedules.push({testnetAddr, stxAddr, amount, height: blockHeight});
        }

        // Ensure each Stacks 1.0 schedule exists in the Stacks 2.0 lookup result.
        for (const stacks1Schedule of lockupSchedule) {
            const found = contractSchedules.find(s => s.amount === stacks1Schedule.amount && s.stxAddr === stacks1Schedule.stxAddr);
            if (!found) {
                throw new Error(`Could not find schedule in Stacks 2.0: ${blockHeight} ${stacks1Schedule.stxAddr} ${stacks1Schedule.amount}`);
            }
        }
        console.log(`Lockups okay at height ${blockHeight} for ${lockupSchedule.length} schedules`);
    }
    console.log(`Stacks 2.0 lockups OKAY`);

    // Query the Stacks 2.0 accounts, ensuring the exported Stacks 1.0 balances match.
    for (const account of accounts) {
        const res: {balance: string} = await (await fetch(`http://localhost:20443/v2/accounts/${account.testnetAddr}?proof=0`)).json();
        const balance = BigInt(res.balance).toString();
        if (balance !== account.amount) {
            throw new Error(`Unexpected Stacks 2.0 balance for ${account.testnetAddr}. Expected ${account.amount} got ${balance}`);
        }
        console.log(`Stacks 2.0 has expected balance ${balance} for ${account.testnetAddr}`);
    }

    // Shutdown the Stacks 2.0 node.
    console.log('Shutting down Stacks 2.0 node...');
    stacksNode2Proc.kill('SIGKILL');
    await stacksNode2Exit;

    // Start the Stacks 1.0 node process.
    console.log('Starting Stacks 1.0 node...');
    const stacksNode1Proc = spawn('blockstack-core', ['start', '--foreground', '--working-dir', '/stacks1.0-chain'], { stdio: 'inherit' });
    const stacksNode1Exit = waitProcessExit(stacksNode1Proc);
    console.log('Waiting for Stacks 1.0 RPC init...');

    // Wait until the Stacks 1.0 RPC server is responsive.
    await waitHttpGetSuccess('http://localhost:6270/v1/info');
    console.log('Stacks 1.0 RPC online');

    // Validate the balance samples previously exported from sqlite match the Stacks 1.0 account view.
    for (const account of accounts) {
        const res: {balance: string} = await (await fetch(`http://localhost:6270/v1/accounts/${account.stxAddr}/STACKS/balance`)).json();
        console.log(`got: ${res.balance}, expected ${account.amount}`);
        if (res.balance !== account.amount) {
            throw new Error(`Unexpected Stacks 1.0 balance for ${account.stxAddr}. Expected ${account.amount} got ${res.balance}`);
        }
        console.log(`Stacks 1.0 has expected balance ${res.balance} for ${account.stxAddr}`);
    }

    // Shutdown the Stacks 1.0 node.
    console.log('Shutting down Stacks 1.0 node...');
    stacksNode1Proc.kill('SIGKILL');
    await stacksNode1Exit;
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});

function getMainnetAddress(testnetAddress: string): string {
    const [version, hash160] = c32check.c32addressDecode(testnetAddress);
    let ver = 0;
    if (version === c32check.versions.testnet.p2pkh) {
        ver = c32check.versions.mainnet.p2pkh;
    } else if (version === c32check.versions.testnet.p2sh) {
        ver = c32check.versions.mainnet.p2sh;
    } else {
        throw new Error(`Unexpected address version: ${version}`);
    }
    return c32check.c32address(ver, hash160);
  }

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