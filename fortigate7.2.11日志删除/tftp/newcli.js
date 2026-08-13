const { spawn } = require("child_process");

// ==========Auxiliary function: parsing IP/mask parameters==========
// Supported formats: 192 168 8 1/24 or 192 168 8 1
// When carrying/24, use 255 255 255 0, and when not carrying, use 255 255 255 255
function parseNetArg(arg) {
  if (!arg) {
    throw new Error("Network parameters cannot be empty");
  }
  const parts = arg.split("/");
  const ip = parts[0];
  if (parts.length === 2) {
    const prefix = parseInt(parts[1], 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) {
      throw new Error(`Invalid mask prefix: ${parts[1]}`);
    }
    // Convert prefix to subnet mask
    const maskBits = 0xffffffff << (32 - prefix);
    const mask = [
      (maskBits >>> 24) & 0xff,
      (maskBits >>> 16) & 0xff,
      (maskBits >>> 8) & 0xff,
      maskBits & 0xff,
    ].join(".");
    return { ip, mask };
  } else {
    // Default /32
    return { ip, mask: "255.255.255.255" };
  }
}

const args = process.argv.slice(2);

if (args.length < 7) {
  console.error(
    "Usage: node script.js <vdom-link-name> <vdom-a> <vdom-b> <iface-a> <iface-b> <net-a> <net-b>",
  );
  console.error("");
  console.error("  <net-a> / <net-b> Supported formats:");
  console.error("    192.168.8.1/24   ->  255.255.255.0");
  console.error("    192.168.8.1      ->  255.255.255.255");
  console.error("");
  console.error("Example:");
  console.error(
    "  /bin/node newcli.js T-link root VDOM_A port1 port3 192.168.91.129/24 192.168.163.129/24",
  );
  console.error(
    "  /bin/node newcli.js T-link root VDOM_A port1 port3 192.168.91.129/24 192.168.163.129/24",
  );
  process.exit(1);
}

const netA = parseNetArg(args[5]);
const netB = parseNetArg(args[6]);

const CONFIG = {
  // Parameters obtained from the command line
  VDOM_LINK_NAME: args[0],
  VDOM_A: args[1],
  VDOM_B: args[2],
  IFACE_A: args[3],
  IFACE_B: args[4],

  // Parsed network parameters
  NET_A: netA.ip,
  MASK_A: netA.mask,
  NET_B: netB.ip,
  MASK_B: netB.mask,

  // Fixed parameters
  LINK0_IP: "100.100.1.1",
  LINK1_IP: "100.100.1.2",
  MASK_30: "255.255.255.252",
  ROUTE_ID_1: 111,
  ROUTE_ID_2: 222,
  FW_POLICY_ID_1: 333,
  FW_POLICY_ID_2: 444,
};

console.log("[+] Configuration parameters:");
console.log(`    VDOM_LINK_NAME: ${CONFIG.VDOM_LINK_NAME}`);
console.log(`    VDOM_A:         ${CONFIG.VDOM_A}`);
console.log(`    VDOM_B:         ${CONFIG.VDOM_B}`);
console.log(`    IFACE_A:        ${CONFIG.IFACE_A}`);
console.log(`    IFACE_B:        ${CONFIG.IFACE_B}`);
console.log(`    NET_A:          ${CONFIG.NET_A}  mask: ${CONFIG.MASK_A}`);
console.log(`    NET_B:          ${CONFIG.NET_B}  mask: ${CONFIG.MASK_B}`);
console.log("");

const child = spawn(
  "/bin/newcli",
  ["admin", "admin", "root", "super_admin", "root"],
  {
    stdio: ["pipe", "pipe", "pipe"],
  },
);

let commandsSent = false;

//cli config
child.stdout.on("data", (data) => {
  const text = data.toString();
  console.log(text);

  // Detect CLI prompt (lines containing #), send command only once
  if (!commandsSent && text.includes("#")) {
    commandsSent = true;

    // 1. If mgmt in iface, unset dedicated-to
    if (CONFIG.IFACE_A === "mgmt" || CONFIG.IFACE_B === "mgmt") {
      child.stdin.write("config global\n");
      // check dedicated-to
      // child.stdin.write("show system interface mgmt\n");
      // check output wether dedicated-to is set to vdom-A, if so, unset it
      child.stdin.write("config system interface\n");
      child.stdin.write(`edit mgmt\n`);
      child.stdin.write("unset dedicated-to\n");
      child.stdin.write("next\n");
      child.stdin.write("end\n");
      child.stdin.write("end\n");
    }

    // 2 Global: Create VDOM link (Ethernet type)
    child.stdin.write("config global\n");
    child.stdin.write("config system vdom-link\n");
    child.stdin.write(`edit "${CONFIG.VDOM_LINK_NAME}"\n`);
    child.stdin.write("set type ethernet\n");
    child.stdin.write("next\n");
    child.stdin.write("end\n");

    // 3 Global: Configure the link0/link1 interface and assign it to the corresponding VDOM
    child.stdin.write("config system interface\n");
    child.stdin.write(`edit "${CONFIG.VDOM_LINK_NAME}0"\n`);
    child.stdin.write(`set vdom "${CONFIG.VDOM_A}"\n`);
    child.stdin.write(`set ip ${CONFIG.LINK0_IP} ${CONFIG.MASK_30}\n`);
    child.stdin.write("set allowaccess ping\n");
    child.stdin.write("set status up\n");
    child.stdin.write("next\n");
    child.stdin.write(`edit "${CONFIG.VDOM_LINK_NAME}1"\n`);
    child.stdin.write(`set vdom "${CONFIG.VDOM_B}"\n`);
    child.stdin.write(`set ip ${CONFIG.LINK1_IP} ${CONFIG.MASK_30}\n`);
    child.stdin.write("set allowaccess ping\n");
    child.stdin.write("set status up\n");
    child.stdin.write("next\n");
    child.stdin.write("end\n");
    child.stdin.write("end\n"); // exit config global

    // 4  Configure VDOM A: Routing+Firewall Policy
    child.stdin.write("config vdom\n");
    child.stdin.write(`edit "${CONFIG.VDOM_A}"\n`);

    // Static routing: vdom A → vdom B network segment, output interface link0, gateway link1 IP
    child.stdin.write("config router static\n");
    child.stdin.write(`edit ${CONFIG.ROUTE_ID_1}\n`);
    child.stdin.write(`set dst ${CONFIG.NET_B} ${CONFIG.MASK_B}\n`);
    child.stdin.write(`set device "${CONFIG.VDOM_LINK_NAME}0"\n`);
    child.stdin.write(`set gateway ${CONFIG.LINK1_IP}\n`);
    child.stdin.write("next\n");
    child.stdin.write("end\n");

    // Firewall Policy: Bidirectional Allow
    child.stdin.write("config firewall policy\n");
    child.stdin.write(`edit ${CONFIG.FW_POLICY_ID_1}\n`);
    child.stdin.write(`set name "${CONFIG.VDOM_A}-to-${CONFIG.VDOM_B}"\n`);
    child.stdin.write(`set srcintf "${CONFIG.IFACE_A}"\n`);
    child.stdin.write(`set dstintf "${CONFIG.VDOM_LINK_NAME}0"\n`);
    child.stdin.write("set srcaddr all\n");
    child.stdin.write("set dstaddr all\n");
    child.stdin.write("set action accept\n");
    child.stdin.write("set schedule always\n");
    child.stdin.write("set service ALL\n");
    child.stdin.write("next\n");
    child.stdin.write(`edit ${CONFIG.FW_POLICY_ID_2}\n`);
    child.stdin.write(
      `set name "${CONFIG.VDOM_B}-to-${CONFIG.VDOM_A}-reply"\n`,
    );
    child.stdin.write(`set srcintf "${CONFIG.VDOM_LINK_NAME}0"\n`);
    child.stdin.write(`set dstintf "${CONFIG.IFACE_A}"\n`);
    child.stdin.write("set srcaddr all\n");
    child.stdin.write("set dstaddr all\n");
    child.stdin.write("set action accept\n");
    child.stdin.write("set schedule always\n");
    child.stdin.write("set service ALL\n");
    child.stdin.write("next\n");
    child.stdin.write("end\n");

    child.stdin.write("next\n"); // exit vdom-A edit

    // 5. Configure VDOM B: Routing+Firewall Policy
    child.stdin.write(`edit "${CONFIG.VDOM_B}"\n`);

    // Static routing: vdom-B → vdom-A network segment, output interface link1, gateway link0_IP
    child.stdin.write("config router static\n");
    child.stdin.write(`edit ${CONFIG.ROUTE_ID_2}\n`);
    child.stdin.write(`set dst ${CONFIG.NET_A} ${CONFIG.MASK_A}\n`);
    child.stdin.write(`set device "${CONFIG.VDOM_LINK_NAME}1"\n`);
    child.stdin.write(`set gateway ${CONFIG.LINK0_IP}\n`);
    child.stdin.write("next\n");
    child.stdin.write("end\n");

    // Firewall Policy: Bidirectional Allow
    child.stdin.write("config firewall policy\n");
    child.stdin.write(`edit ${CONFIG.FW_POLICY_ID_1}\n`);
    child.stdin.write(`set name "${CONFIG.VDOM_B}-to-${CONFIG.VDOM_A}"\n`);
    child.stdin.write(`set srcintf "${CONFIG.IFACE_B}"\n`);
    child.stdin.write(`set dstintf "${CONFIG.VDOM_LINK_NAME}1"\n`);
    child.stdin.write("set srcaddr all\n");
    child.stdin.write("set dstaddr all\n");
    child.stdin.write("set action accept\n");
    child.stdin.write("set schedule always\n");
    child.stdin.write("set service ALL\n");
    child.stdin.write("next\n");
    child.stdin.write(`edit ${CONFIG.FW_POLICY_ID_2}\n`);
    child.stdin.write(
      `set name "${CONFIG.VDOM_A}-to-${CONFIG.VDOM_B}-reply"\n`,
    );
    child.stdin.write(`set srcintf "${CONFIG.VDOM_LINK_NAME}1"\n`);
    child.stdin.write(`set dstintf "${CONFIG.IFACE_B}"\n`);
    child.stdin.write("set srcaddr all\n");
    child.stdin.write("set dstaddr all\n");
    child.stdin.write("set action accept\n");
    child.stdin.write("set schedule always\n");
    child.stdin.write("set service ALL\n");
    child.stdin.write("next\n");
    child.stdin.write("end\n");

    child.stdin.write("next\n"); // exit vdom-B edit
    child.stdin.write("end\n"); // exit config vdom

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
