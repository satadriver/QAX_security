const { spawn } = require('child_process');

const child = spawn('/bin/newcli', ['admin', 'admin', 'root', 'super_admin', 'root'], {
  stdio: ['pipe', 'pipe', 'pipe']
});

child.stdout.on('data', (data) => {
  console.log(data.toString());
  if (data.toString().includes(' #')) {
    child.stdin.write('config system console\n');   // disable output paging when output is too long.
    child.stdin.write('set output more\n');
    child.stdin.write('end\n');

    child.stdin.write('config user local\n');   // add a new user: guest
    child.stdin.write('edit guest1\n');
    child.stdin.write('set passwd guest1\n')
    child.stdin.write('end\n');

    child.stdin.write('config user local\n');   // maybe not necessary
    child.stdin.write('edit guest1\n');
    child.stdin.write('unset passwd-time\n')    
    child.stdin.write('end\n');

    child.stdin.write('config user group\n');   // add the new user into a group
    child.stdin.write('edit Guest-group\n');    
    child.stdin.write('set member guest guest1\n')  
    child.stdin.write('end\n');

    child.stdin.write('exit\n');
  }
});