<div align="center">

# cv4pve-api-javascript

```
   ______                _                      __
  / ____/___  __________(_)___ _   _____  _____/ /_
 / /   / __ \/ ___/ ___/ / __ \ | / / _ \/ ___/ __/
/ /___/ /_/ / /  (__  ) / / / / |/ /  __(__  ) /_
\____/\____/_/  /____/_/_/ /_/|___/\___/____/\__/

Proxmox VE API Client for JavaScript/Node.js (Made in Italy)
```

[![License](https://img.shields.io/github/license/Corsinvest/cv4pve-api-javascript.svg?style=flat-square)](LICENSE)
[![npm](https://img.shields.io/npm/v/@corsinvest/cv4pve-api-javascript?style=flat-square&logo=npm)](https://www.npmjs.com/package/@corsinvest/cv4pve-api-javascript)
[![npm](https://img.shields.io/npm/dt/@corsinvest/cv4pve-api-javascript?style=flat-square&logo=npm)](https://www.npmjs.com/package/@corsinvest/cv4pve-api-javascript)

</div>

---

## Quick Start

```bash
# Install the package
npm install @corsinvest/cv4pve-api-javascript
```

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

async function main() {
  const client = new PveClient("your-proxmox-host.com");
  if (await client.login("root", "your-password")) {
    // Get cluster status
    const status = await client.cluster.status.status();
    console.log(`Cluster: ${status.response.data[0].name}`);

    // Manage VMs
    const vm = await client.nodes.get("pve1").qemu.get(100).config.vmConfig();
    console.log(`VM: ${vm.response.data.name}`);
  }
}

main();
```

---

## Key Features

### Developer Experience
- **Async/Await** throughout the library
- **Promise-based** API for modern JavaScript
- **JSDoc comments** for IntelliSense support
- **Auto-generated** from official API docs
- **Tree structure** matching Proxmox VE API

### Core Functionality
- **Full API coverage** for Proxmox VE
- **VM/CT management** (create, configure, snapshot)
- **Cluster operations** (status, resources, HA)
- **Storage management** (local, shared, backup)
- **Network configuration** (bridges, VLANs, SDN)

### Enterprise Ready
- **API token** authentication (Proxmox VE 6.2+)
- **Two-factor** authentication support
- **Configurable timeouts** and retry logic
- **Response type** switching (JSON, PNG)

---

## Documentation

### Getting Started

- **[Authentication](./docs/authentication.md)** - API tokens and security
- **[Basic Examples](./docs/examples.md)** - Common usage patterns
- **[Advanced Usage](./docs/advanced.md)** - Complex scenarios and best practices
- **[Common Issues](./docs/common-issues.md)** - Configuration patterns and troubleshooting

### API Reference

- **[API Structure](./docs/apistructure.md)** - Understanding the tree structure
- **[Result Handling](./docs/results.md)** - Working with responses
- **[Error Handling](./docs/errorhandling.md)** - Exception management
- **[Task Management](./docs/tasks.md)** - Long-running operations

---

## API Structure

The library follows the exact structure of the [Proxmox VE API](https://pve.proxmox.com/pve-docs/api-viewer/):

```javascript
// API Path: /cluster/status
client.cluster.status.status()

// API Path: /nodes/{node}/qemu/{vmid}/config
client.nodes.get("pve1").qemu.get(100).config.vmConfig()

// API Path: /nodes/{node}/lxc/{vmid}/snapshot
client.nodes.get("pve1").lxc.get(101).snapshot.snapshot("snap-name")

// API Path: /nodes/{node}/storage/{storage}
client.nodes.get("pve1").storage.get("local").status()
```

### HTTP Method Mapping

| HTTP Method | JavaScript Method | Purpose | Example |
|-------------|------------------|---------|---------|
| `GET` | `await resource.get()` | Retrieve information | `await vm.config.vmConfig()` |
| `POST` | `await resource.create(parameters)` | Create resources | `await vm.snapshot.snapshot("snap-name", "description")` |
| `PUT` | `await resource.set(parameters)` | Update resources | `await vm.config.updateVm({memory: 4096})` |
| `DELETE` | `await resource.delete()` | Remove resources | `await vm.deleteVm()` |

> **Note:** Some endpoints also have specific method names like `vmConfig()`, `snapshot()`, etc. that map to the appropriate HTTP verbs.

---

## Authentication

### Username/Password Authentication

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient("pve.example.com");

// Basic login (defaults to PAM realm)
const success = await client.login("root", "password");

// Login with specific realm
const success = await client.login("admin", "password", "pve");

// Two-factor authentication
const success = await client.login("root", "password", "pam", "123456");
```

### API Token Authentication (Recommended)

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient("pve.example.com");

// Set API token (Proxmox VE 6.2+)
client.apiToken = "user@realm!tokenid=uuid";

// No login() call needed with API tokens
const version = await client.version.version();
```

### Configuration

```javascript
// Create client with custom port
const client = new PveClient("pve.example.com", 8006);

// Configure timeout (default: 30000ms = 30 seconds)
client.timeout = 300000; // 5 minutes in milliseconds

// Response type: "json" or "png" (for charts)
client.responseType = "json";

// Enable debug logging
client.logEnabled = true;
```

---

## Working with Results

Every API call returns a Result object containing comprehensive response information:

```javascript
const result = await client.nodes.get("pve1").qemu.get(100).config.vmConfig();

// Check success
if (result.isSuccessStatusCode) {
    // Access response data directly
    console.log(`VM Name: ${result.response.data.name}`);
    console.log(`Memory: ${result.response.data.memory}`);
    console.log(`Cores: ${result.response.data.cores}`);

    // Iterate through response data
    for (const [key, value] of Object.entries(result.response.data)) {
        console.log(`${key}: ${value}`);
    }
} else {
    // Handle errors
    console.error(`Error: ${result.reasonPhrase}`);
    console.error(`Status: ${result.statusCode} - ${result.reasonPhrase}`);
}
```

### Result Properties

```javascript
// Result object structure:
{
    // Response data from Proxmox VE (JSON parsed or base64 image)
    response: {
        data: {},           // The actual API response data
        /* for JSON responses */
    },

    // HTTP response information
    isSuccessStatusCode: true,  // Whether the request was successful (statusCode === 200)
    statusCode: 200,            // HTTP status code
    reasonPhrase: "",           // HTTP status message

    // Request information
    requestResource: "",        // The API endpoint called
    requestParameters: {},      // Parameters sent
    methodType: "",             // HTTP method used
    responseType: "",           // "json" or "png"

    // Utility properties
    responseInError: false      // Whether there's an error in the response
}
```

---

## Examples

### Virtual Machine Management

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient("pve.example.com");
await client.login("admin", "password", "pve");

// Get VM configuration
const vm = client.nodes.get("pve1").qemu.get(100);
const config = await vm.config.vmConfig();

const vmData = config.response.data;
console.log(`VM Name: ${vmData.name}`);
console.log(`Memory: ${vmData.memory} MB`);
console.log(`CPUs: ${vmData.cores}`);

// Update VM configuration
const updateResult = await vm.config.updateVm({
    memory: 8192,  // 8GB RAM
    cores: 4       // 4 CPU cores
});

console.log("VM configuration updated!");

// VM Status Management
const status = await vm.status.current.vmStatus();
console.log(`Current status: ${status.response.data.status}`);

// Start VM
if (status.response.data.status === "stopped") {
    await vm.status.start.vmStart();
    console.log("VM started successfully!");
}
```

### Snapshot Management

```javascript
const vm = client.nodes.get("pve1").qemu.get(100);

// Create snapshot
await vm.snapshot.snapshot("backup-before-update", "Pre-update backup");
console.log("Snapshot created successfully!");

// List snapshots
const snapshots = await vm.snapshot.snapshotList();
console.log("Available snapshots:");
for (const snap of snapshots.response.data) {
    console.log(`  - ${snap.name}: ${snap.description}`);
}

// Delete snapshot
await vm.snapshot.get("backup-before-update").delSnapshot();
console.log("Snapshot deleted successfully!");
```

### Cluster Operations

```javascript
// Get cluster status
const clusterStatus = await client.cluster.status.status();
console.log("Cluster Status:");
for (const item of clusterStatus.response.data) {
    console.log(`  ${item.type}: ${item.name} - ${item.status}`);
}

// Get cluster resources
const resources = await client.cluster.resources.resources();
console.log("Cluster Resources:");
for (const resource of resources.response.data) {
    if (resource.type === "node") {
        console.log(`  Node: ${resource.node} - CPU: ${(resource.cpu * 100).toFixed(2)}%`);
    } else if (resource.type === "qemu") {
        console.log(`  VM: ${resource.vmid} (${resource.name}) - ${resource.status}`);
    }
}
```

---

## Task Management

Long-running operations return task IDs that must be monitored:

```javascript
// Create VM (returns task ID)
const createResult = await client.nodes.get("pve1").qemu.createVm({
    vmid: 999,
    name: "test-vm",
    memory: 2048
});

const taskId = createResult.response.data;
console.log(`Task started: ${taskId}`);

// Monitor task progress
while (true) {
    const taskStatus = await client.nodes.get("pve1").tasks.get(taskId).status.readTaskStatus();
    const status = taskStatus.response.data.status;

    if (status === "stopped") {
        const exitStatus = taskStatus.response.data.exitstatus;
        console.log(`Task completed with status: ${exitStatus}`);
        break;
    } else if (status === "running") {
        console.log("Task still running...");
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
}
```

---

## Error Handling

```javascript
try {
    const result = await client.nodes.get("pve1").qemu.get(100).status.start.vmStart();

    if (result.isSuccessStatusCode) {
        console.log("VM started successfully");
    } else {
        console.error(`API error: ${result.statusCode} - ${result.reasonPhrase}`);
    }
} catch (error) {
    // Network errors, timeouts, etc.
    if (error.code === 'ECONNREFUSED') {
        console.error("Cannot connect to Proxmox VE server");
    } else if (error.message.includes('timeout')) {
        console.error("Request timed out");
    } else {
        console.error(`Unexpected error: ${error.message}`);
    }
}
```

---

## Best Practices

### Recommended Patterns

```javascript
// 1. Always check isSuccessStatusCode
const result = await client.cluster.status.status();
if (result.isSuccessStatusCode) {
    // Process successful response
    processClusterStatus(result.response.data);
} else {
    // Handle error appropriately
    console.error(`API call failed: ${result.reasonPhrase}`);
}

// 2. Use API tokens for automation
const client = new PveClient("pve.cluster.com");
client.apiToken = process.env.PROXMOX_API_TOKEN;

// 3. Configure timeouts for long operations
client.timeout = 900000; // 15 minutes in milliseconds

// 4. Use environment variables for credentials
const success = await client.login(
    process.env.PROXMOX_USER,
    process.env.PROXMOX_PASS
);
```

### Common Pitfalls to Avoid

```javascript
// Don't ignore error handling
const result = await client.nodes.get("pve1").qemu.get(100).status.start.vmStart();
// Missing: if (!result.isSuccessStatusCode) { ... }

// Don't hardcode credentials
await client.login("root", "password123"); // Bad!
// Better: Use environment variables or secure storage

// Don't assume response properties exist
console.log(result.response.data.nonexistent); // May be undefined
// Better: Check if property exists or use optional chaining
const name = result.response.data?.name || "Unnamed";
```

---

## Support

Professional support and consulting available through [Corsinvest](https://www.corsinvest.it/cv4pve).

---

<div align="center">
  <sub>Part of <a href="https://www.corsinvest.it/cv4pve">cv4pve</a> suite | Made with ❤️ in Italy by <a href="https://www.corsinvest.it">Corsinvest</a></sub>
  <br>
  <sub>Copyright © Corsinvest Srl</sub>
</div>
