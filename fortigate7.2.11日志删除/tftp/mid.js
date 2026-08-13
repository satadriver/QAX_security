// memfd_load.js

//import ffi from 'node:ffi';
//import fs from 'fs';
//import path from 'path';
//import { fileURLToPath } from 'url';
const ffi = require('node:ffi');
const fs = require('fs');
const path = require('path');
// 因为使用了 CommonJS，可以直接使用 __dirname，不再需要 fileURLToPath
// 所以可以省略 fileURLToPath 的导入

// 如果你在模块中需要 fileURLToPath，可以这样导入：
// const { fileURLToPath } = require('url');
// 但在本场景中，通常用 __dirname 更简单。



function MidInMan(mip,mport,dip,dport){

	//const __dirname = path.dirname(fileURLToPath(import.meta.url));


	// 1. 加载 libc
	const libc = ffi.load('libc.so.6');

	// 2. 声明 memfd_create
	// int memfd_create(const char *name, unsigned int flags);
	const memfd_create = libc.declare('memfd_create', 'int', ['string', 'uint32']);

	// 3. 声明 write
	const write = libc.declare('write', 'ssize_t', ['int', 'pointer', 'size_t']);

	// 4. 常量定义（Linux 4.9 支持的标志）
	const MFD_CLOEXEC = 0x0001;
	const MFD_ALLOW_SEALING = 0x0002;
	// 注意：Linux 4.9 没有 MFD_EXEC，无需指定

	// 5. 读取 .so 文件
	const soPath = path.join(__dirname, 'libmid.so');
	const soData = fs.readFileSync(soPath);

	// 6. 创建 memfd（默认具有执行权限）
	const fd = memfd_create('libMid', MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd === -1) {
		console.error('memfd_create failed');
		process.exit(1);
	}
	console.log(`memfd created with fd: ${fd}`);

	// 7. 写入 so 数据
	const written = write(fd, soData, soData.length);
	if (written !== soData.length) {
		console.error('write failed');
		process.exit(1);
	}

	// 8. 通过 /proc/self/fd/<fd> 路径加载
	const libPath = `/proc/self/fd/${fd}`;
	const lib = ffi.load(libPath);

	// 9. 调用库中的函数
	const MidInMan = lib.declare('MidInMan', 'int', ['string','string','string','string']);
	MidInMan(mip,mport,dip,dport);
}



// readmem.js
function parseArgs(argv) {
  const args = {};
  const flags = []; // 可选：用于记录所有标志名
  
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    
    if (arg.startsWith('--')) {
      // 长选项，后一个参数为值
      const key = arg.slice(2);
      if (i + 1 < argv.length) {
        args[key] = argv[i + 1];
        i++; // 跳过值
      } else {
        // 如果 -- 后面没有值，则视为布尔标志（根据需求可自定义）
        args[key] = true;
      }
    } else if (arg.startsWith('-')) {
      // 短选项，只有名称，无值
      const key = arg.slice(1);
      args[key] = true;
      flags.push(key);
    } else {
      // 其他情况（如不带前缀的独立参数），可根据需要处理
      // 这里忽略或作为位置参数
      console.warn(`Ignored positional argument: ${arg}`);
    }
  }
  
  return args;
}



function main() {
    try {
		console.log("start\r\n");
        const args = parseArgs(process.argv);
        console.log(args);

        if (args.mid) {
            //console.log('disable');
	
			MidInMan(args.mip,args.mport,args.dip,args.dport);
			
        } else if (args.unloadso) {

        }
		else {
            console.error('Usage: ${progName} -disable/-enable --filter:mystring/--unfilter');
            process.exit(1);
        }
    } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }
}



//--experimental-ffi --allow-ffi
main();