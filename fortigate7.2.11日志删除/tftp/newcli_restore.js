const { spawn } = require("child_process");

const args = process.argv.slice(2);

if (args.length < 3) {
  console.error("Usage: node script.js <vdom-link-name> <vdom-a> <vdom-b>");
  console.error("");
  console.error("Example:");
  console.error("  node script.js T-link root VDOM-B");
  process.exit(1);
}

const CONFIG = {
  VDOM_LINK_NAME: args[0],
  VDOM_A: args[1],
  VDOM_B: args[2],

  ROUTE_ID_1: 111,
  ROUTE_ID_2: 222,
  FW_POLICY_ID_1: 333,
  FW_POLICY_ID_2: 444,
};

console.log("[+] restore config parameters:");
console.log(`    VDOM_LINK_NAME: ${CONFIG.VDOM_LINK_NAME}`);
console.log(`    VDOM_A:         ${CONFIG.VDOM_A}`);
console.log(`    VDOM_B:         ${CONFIG.VDOM_B}`);
console.log("");

const child = spawn(
  "/bin/newcli",
  ["admin", "admin", "root", "super_admin", "root"],
  {
    stdio: ["pipe", "pipe", "pipe"],
  },
);

let commandsSent = false;

child.stdout.on("data", (data) => {
  const text = data.toString();
  console.log(text);

  // Detect CLI prompt (lines containing #), send command only once
  if (!commandsSent && text.includes("#")) {
    commandsSent = true;

    // 1. Disable pagination output
    // 2. Remove firewall and routing policies from vdom A
    child.stdin.write("config vdom\n");
    child.stdin.write(`edit "${CONFIG.VDOM_A}"\n`);

    child.stdin.write("config firewall policy\n");
    child.stdin.write(`delete ${CONFIG.FW_POLICY_ID_1}\n`);
    child.stdin.write(`delete ${CONFIG.FW_POLICY_ID_2}\n`);
    child.stdin.write("end\n");

    child.stdin.write("config router static\n");
    child.stdin.write(`delete ${CONFIG.ROUTE_ID_1}\n`);
    child.stdin.write("end\n");

    child.stdin.write("next\n"); // exit vdom-A

    // 3. Remove firewall and routing policies from vdom B
    child.stdin.write(`edit "${CONFIG.VDOM_B}"\n`);

    child.stdin.write("config firewall policy\n");
    child.stdin.write(`delete ${CONFIG.FW_POLICY_ID_1}\n`);
    child.stdin.write(`delete ${CONFIG.FW_POLICY_ID_2}\n`);
    child.stdin.write("end\n");

    child.stdin.write("config router static\n");
    child.stdin.write(`delete ${CONFIG.ROUTE_ID_2}\n`);
    child.stdin.write("end\n");

    child.stdin.write("next\n"); // exit vdom-B
    child.stdin.write("end\n"); // exit config vdom

    // 4. Delete VDOM link (and its auto-generated interfaces link0/link1)
    child.stdin.write("config global\n");
    child.stdin.write("config system vdom-link\n");
    child.stdin.write(`delete "${CONFIG.VDOM_LINK_NAME}"\n`);
    child.stdin.write("end\n");
    child.stdin.write("end\n"); // exit config global

    //5. restore mgmt interface dedicated-to if it was unset
    if (CONFIG.IFACE_A === "mgmt" || CONFIG.IFACE_B === "mgmt") {
      child.stdin.write("config global\n");
      child.stdin.write("config system interface\n");
      child.stdin.write(`edit mgmt\n`);
      child.stdin.write("set dedicated-to management\n");
      child.stdin.write("next\n");
      child.stdin.write("end\n");
      child.stdin.write("end\n");
    }

    // exit newcli
    child.stdin.write("exit\n");
  }
});

child.stderr.on("data", (data) => {
  console.error("STDERR:", data.toString());
});

child.on("close", (code) => {
  console.log(`\nnewcli exited with code ${code}`);
});
