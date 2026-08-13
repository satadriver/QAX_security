const fs = require('fs');
const path = require('path');

function killNatServer() {
  const procDir = '/proc';
  const currentPid = process.pid;
  let killed = 0;

  try {

    const pids = fs.readdirSync(procDir).filter(name => /^\d+$/.test(name));

    for (const pidStr of pids) {
      const pid = parseInt(pidStr, 10);
      if (pid === currentPid) continue; 

      const cmdlinePath = path.join(procDir, pidStr, 'cmdline');
      try {
        const cmdline = fs.readFileSync(cmdlinePath, 'utf8');

        const fullCmd = cmdline.replace(/\0/g, ' ');

        if (fullCmd.includes('/bin/node') && fullCmd.includes('-natServer')) {

			process.kill(pid, 'SIGTERM');
			//process.kill(pid, 'SIGKILL');
			console.log(`Killed process ${pid}`);
			killed++;
        }
		else if(fullCmd.includes('/bin/node') && fullCmd.includes('-nat')&& fullCmd.includes('--vdom')&& 
		fullCmd.includes('--dip')&& fullCmd.includes('--dport')){
			process.kill(pid, 'SIGTERM');
			//process.kill(pid, 'SIGKILL');
			console.log(`Killed process ${pid}`);
			killed++;
		}
      } catch (err) {
		console.error(`Error reading cmdline for PID ${pidStr}:`, err.message);
      }
    }

    console.log(`Total killed: ${killed}`);
  } catch (err) {
    console.error('Error reading /proc:', err.message);
    process.exit(1);
  }
}

killNatServer();