const { spawn } = require("child_process");

const child = spawn(
  "/bin/newcli",
  ["admin", "admin", "root", "super_admin", "root"],
  {
    stdio: ["pipe", "pipe", "pipe"],
  },
);

child.stdout.on("data", (data) => {
  console.log(data.toString());
  if (data.toString().includes(" #")) {
    child.stdin.write("execute log filter reset\n");
    child.stdin.write("execute log filter device 0\n");
    child.stdin.write("exit\n");
  }
});
