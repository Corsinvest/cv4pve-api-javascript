# Basic Examples

This guide provides common usage patterns and practical examples for getting started with the Proxmox VE API.

## Getting Started

### **Basic Connection**

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

// Create client and authenticate
const client = new PveClient("pve.example.com");
client.apiToken = "user@pve!token=uuid";

// Test connection
const version = await client.version.version();
console.log(`Connected to Proxmox VE ${version.response.data.version}`);
```

### **Client Setup with Error Handling**

```javascript
async function createClient() {
    const client = new PveClient("pve.local");
    client.timeout = 120000; // 2 minutes in milliseconds

    try {
        // Use API token or login
        if (process.env.PVE_TOKEN) {
            client.apiToken = process.env.PVE_TOKEN;
        } else {
            const success = await client.login("root", "password", "pam");
            if (!success) {
                throw new Error("Authentication failed");
            }
        }

        return client;
    } catch (error) {
        console.log(`Failed to create client: ${error.message}`);
        throw error;
    }
}
```

---

## Virtual Machine Operations

### **List Virtual Machines**

```javascript
// Get all VMs in cluster
const resources = await client.cluster.resources.resources();
for (const resource of resources.response.data) {
    if (resource.type === "qemu") {
        console.log(`VM ${resource.vmid}: ${resource.name} on ${resource.node} - ${resource.status}`);
    }
}
```

### **Get VM Configuration**

```javascript
// Get VM configuration
const vmConfig = await client.nodes.get("pve1").qemu.get(100).config.vmConfig();
const config = vmConfig.response.data;
console.log(`VM Name: ${config.name}`);
console.log(`Memory: ${config.memory} MB`);
console.log(`CPU Cores: ${config.cores}`);
console.log(`Boot Order: ${config.boot}`);
```

### **VM Power Management**

```javascript
const vm = client.nodes.get("pve1").qemu.get(100);

// Start VM
await vm.status.start.vmStart();
console.log("VM started successfully");

// Stop VM
await vm.status.stop.vmStop();
console.log("VM stopped successfully");

// Restart VM
await vm.status.reboot.vmReboot();
console.log("VM restarted successfully");

// Get current status
const status = await vm.status.current.vmStatus();
console.log(`VM Status: ${status.response.data.status}`);
console.log(`CPU Usage: ${(status.response.data.cpu * 100).toFixed(2)}%`);
console.log(`Memory: ${(status.response.data.mem / status.response.data.maxmem * 100).toFixed(2)}%`);
```

### **Snapshot Management**

```javascript
const vm = client.nodes.get("pve1").qemu.get(100);

// Create snapshot
await vm.snapshot.snapshot("backup-2024", "Pre-update backup");
console.log("Snapshot created successfully");

// List snapshots
const snapshots = await vm.snapshot.snapshotList();
console.log("Available snapshots:");
for (const snapshot of snapshots.response.data) {
    console.log(`  - ${snapshot.name}: ${snapshot.description} (${snapshot.snaptime})`);
}

// Restore snapshot
await vm.snapshot.get("backup-2024").rollback.rollbackVm();
console.log("Snapshot restored successfully");

// Delete snapshot
await vm.snapshot.get("backup-2024").delSnapshot();
console.log("Snapshot deleted successfully");
```

---

## Container Operations

### **List Containers**

```javascript
// Get all containers
const resources = await client.cluster.resources.resources();
for (const resource of resources.response.data) {
    if (resource.type === "lxc") {
        console.log(`CT ${resource.vmid}: ${resource.name} on ${resource.node} - ${resource.status}`);
    }
}
```

### **Container Management**

```javascript
const container = client.nodes.get("pve1").lxc.get(101);

// Get container configuration
const config = await container.config.vmConfig();
const ctConfig = config.response.data;
console.log(`Container: ${ctConfig.hostname}`);
console.log(`OS Template: ${ctConfig.ostemplate}`);
console.log(`Memory: ${ctConfig.memory} MB`);

// Start container
await container.status.start.vmStart();
console.log("Container started");

// Get container status
const status = await container.status.current.vmStatus();
console.log(`Status: ${status.response.data.status}`);
console.log(`Uptime: ${status.response.data.uptime} seconds`);
```

---

## Cluster Operations

### **Cluster Status**

```javascript
// Get cluster status
const clusterStatus = await client.cluster.status.status();
console.log("Cluster Status:");
for (const item of clusterStatus.response.data) {
    console.log(`  ${item.type}: ${item.name} - ${item.status}`);
}
```

### **Node Information**

```javascript
// Get all nodes
const nodes = await client.nodes.index();
console.log("Available Nodes:");
for (const node of nodes.response.data) {
    console.log(`  ${node.node}: ${node.status}`);
    console.log(`    CPU: ${(node.cpu * 100).toFixed(2)}%`);
    console.log(`    Memory: ${(node.mem / node.maxmem * 100).toFixed(2)}%`);
    console.log(`    Uptime: ${Math.floor(node.uptime / 3600)}h ${Math.floor((node.uptime % 3600) / 60)}m`);
}
```

### **Storage Information**

```javascript
// Get storage for a specific node
const storages = await client.nodes.get("pve1").storage.index();
console.log("Available Storage:");
for (const storage of storages.response.data) {
    const usedPercent = storage.used / storage.total * 100;
    console.log(`  ${storage.storage} (${storage.type}): ${usedPercent.toFixed(1)}% used`);
    console.log(`    Total: ${(storage.total / (1024*1024*1024)).toFixed(2)} GB`);
    console.log(`    Available: ${(storage.avail / (1024*1024*1024)).toFixed(2)} GB`);
}
```

---

## Common Patterns

### **Resource Monitoring**

```javascript
async function monitorResources(client) {
    while (true) {
        const resources = await client.cluster.resources.resources();

        console.clear();  // Note: This may not work in all environments
        console.log(`Proxmox VE Resource Monitor - ${new Date().toLocaleTimeString()}`);
        console.log("=".repeat(50));

        // Group by type
        const nodes = resources.response.data.filter(r => r.type === "node");
        const vms = resources.response.data.filter(r => r.type === "qemu");
        const containers = resources.response.data.filter(r => r.type === "lxc");

        console.log(`Nodes: ${nodes.length}`);
        for (const node of nodes) {
            console.log(`  ${node.node}: CPU ${(node.cpu * 100).toFixed(1)}%, Memory ${((node.mem / node.maxmem) * 100).toFixed(1)}%`);
        }

        console.log(`\nVMs: ${vms.length} (${vms.filter(v => v.status === "running").length} running)`);
        console.log(`Containers: ${containers.length} (${containers.filter(c => c.status === "running").length} running)`);

        await new Promise(resolve => setTimeout(resolve, 5000)); // Update every 5 seconds
    }
}
```

### **Batch Operations**

```javascript
async function batchVmOperation(client, vmIds, operation) {
    const results = [];

    for (const vmId of vmIds) {
        // Find VM location
        const resources = await client.cluster.resources.resources();
        const vm = resources.response.data.find(r => r.type === "qemu" && r.vmid === vmId);

        if (vm) {
            const vmInstance = client.nodes.get(vm.node).qemu.get(vmId);

            let task;
            switch (operation.toLowerCase()) {
                case "start":
                    task = vmInstance.status.start.vmStart();
                    break;
                case "stop":
                    task = vmInstance.status.stop.vmStop();
                    break;
                case "restart":
                    task = vmInstance.status.reboot.vmReboot();
                    break;
                default:
                    throw new Error(`Unknown operation: ${operation}`);
            }

            await task;
            results.push({ vmId, success: true });
        }
    }

    for (const result of results) {
        console.log(`VM ${result.vmId} ${operation}: ${result.success ? "Success" : "Failed"}`);
    }
}
```

### **Performance Monitoring**

```javascript
async function getVmPerformance(client, node, vmId) {
    const vm = client.nodes.get(node).qemu.get(vmId);

    // Get current status
    const status = await vm.status.current.vmStatus();
    const data = status.response.data;

    console.log(`VM ${vmId} Performance:`);
    console.log(`  Status: ${data.status}`);
    console.log(`  CPU Usage: ${(data.cpu * 100).toFixed(2)}%`);
    console.log(`  Memory: ${formatBytes(data.mem)} / ${formatBytes(data.maxmem)} (${((data.mem / data.maxmem) * 100).toFixed(1)}%)`);
    console.log(`  Disk Read: ${formatBytes(data.diskread)}`);
    console.log(`  Disk Write: ${formatBytes(data.diskwrite)}`);
    console.log(`  Network In: ${formatBytes(data.netin)}`);
    console.log(`  Network Out: ${formatBytes(data.netout)}`);
    console.log(`  Uptime: ${Math.floor(data.uptime / 60)}m ${data.uptime % 60}s`);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
```

---

## Best Practices

### **Error Handling**

```javascript
async function safeVmOperation(client, node, vmId, operation) {
    try {
        const vm = client.nodes.get(node).qemu.get(vmId);

        let result;
        switch (operation.toLowerCase()) {
            case "start":
                result = await vm.status.start.vmStart();
                break;
            case "stop":
                result = await vm.status.stop.vmStop();
                break;
            default:
                throw new Error(`Unknown operation: ${operation}`);
        }

        if (result.isSuccessStatusCode) {
            console.log(`VM ${vmId} ${operation} successful`);
            return true;
        } else {
            console.log(`VM ${vmId} ${operation} failed: ${result.reasonPhrase}`);
            return false;
        }
    } catch (error) {
        console.log(`Exception during ${operation} on VM ${vmId}: ${error.message}`);
        return false;
    }
}
```

### **Resource Discovery**

```javascript
async function findVm(client, vmName) {
    const resources = await client.cluster.resources.resources();
    const vm = resources.response.data.find(r =>
        r.type === "qemu" &&
        r.name &&
        r.name.toLowerCase() === vmName.toLowerCase()
    );

    return vm ? { node: vm.node, vmId: vm.vmid } : null;
}

// Usage
const vmLocation = await findVm(client, "web-server");
if (vmLocation) {
    const { node, vmId } = vmLocation;
    const vm = client.nodes.get(node).qemu.get(vmId);
    // ... work with VM
}
```
