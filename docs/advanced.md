# Advanced Usage Guide

This guide covers complex scenarios, best practices, and advanced patterns for experienced developers.

## Enterprise Configuration

### **Client Setup**

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient("pve.company.com");
client.apiToken = process.env.PROXMOX_API_TOKEN;
client.timeout = 600000; // 10 minutes in milliseconds
```

### **Resilient Operations**

```javascript
// Retry policy with exponential backoff
async function withRetry(operation, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await operation();
        } catch (error) {
            if (attempt < maxRetries && isRetriableError(error)) {
                const delay = Math.pow(2, attempt) * 1000;
                console.log(`Attempt ${attempt} failed, retrying in ${delay/1000}s: ${error.message}`);
                await new Promise(resolve => setTimeout(resolve, delay));
            } else if (attempt === maxRetries) {
                throw error; // Re-throw on final attempt
            }
        }
    }
}

function isRetriableError(error) {
    // Network errors that can be retried
    return error.code === 'ECONNRESET' || error.code === 'ECONNREFUSED' ||
           error.code === 'EHOSTUNREACH' || error.message.includes('timeout');
}

// Usage
const result = await withRetry(async () =>
    await client.nodes.get("pve1").qemu.get(100).status.start.vmStart()
);
```

---

## Task and Resource Management

### **Long-Running Operations**

```javascript
// Complete task management with progress
async function executeWithProgress(client, operation, node, description) {
    console.log(`Starting: ${description}`);

    const result = await operation();
    if (!result.isSuccessStatusCode) {
        console.log(`Failed to start ${description}: ${result.reasonPhrase}`);
        return false;
    }

    const taskId = result.response.data;
    return await waitForTaskCompletion(client, node, taskId, description);
}

async function waitForTaskCompletion(client, node, taskId, description) {
    const timeout = 30 * 60 * 1000; // 30 minutes in milliseconds
    const start = Date.now();

    while (Date.now() - start < timeout) {
        const status = await client.nodes.get(node).tasks.get(taskId).status.readTaskStatus();

        if (status.response.data.status === "stopped") {
            const success = status.response.data.exitstatus === "OK";
            console.log(`${description}: ${status.response.data.exitstatus} (${success ? "Success" : "Failed"})`);
            return success;
        }

        await new Promise(resolve => setTimeout(resolve, 2000));
    }

    console.log(`Timeout: ${description} timed out`);
    return false;
}
```

### **Bulk Operations**

```javascript
// Perform operations on multiple VMs with concurrency control
async function bulkVmOperation(client, vmIds, operation, operationName) {
    // Get all resources to find VM locations
    const resources = await client.cluster.resources.resources();
    const vmLocations = {};

    for (const resource of resources.response.data) {
        if (resource.type === "qemu" && vmIds.includes(resource.vmid)) {
            vmLocations[resource.vmid] = resource.node;
        }
    }

    // Create a semaphore to limit concurrent operations
    const maxConcurrent = 5;
    const results = {};

    // Process in batches
    for (let i = 0; i < vmIds.length; i += maxConcurrent) {
        const batch = vmIds.slice(i, i + maxConcurrent);
        const batchPromises = batch.map(async vmId => {
            if (!vmLocations[vmId]) {
                console.log(`VM ${vmId} not found`);
                results[vmId] = false;
                return;
            }

            const node = vmLocations[vmId];
            try {
                await operation(client, node, vmId);
                console.log(`VM ${vmId} ${operationName}: Success`);
                results[vmId] = true;
            } catch (error) {
                console.log(`VM ${vmId} ${operationName}: Failed - ${error.message}`);
                results[vmId] = false;
            }
        });

        await Promise.all(batchPromises);
    }

    return results;
}

// Usage examples
const startResults = await bulkVmOperation(
    client,
    [100, 101, 102],
    async (c, node, vmId) => await c.nodes.get(node).qemu.get(vmId).status.start.vmStart(),
    "start"
);
```

---

## Monitoring and Health Checks

### **Cluster Health Assessment**

```javascript
class ClusterHealthMonitor {
    constructor(client) {
        this.client = client;
    }

    async getHealthReport() {
        const resources = await this.client.cluster.resources.resources();
        const data = resources.response.data;

        const nodes = data.filter(r => r.type === "node");
        const vms = data.filter(r => r.type === "qemu");
        const containers = data.filter(r => r.type === "lxc");

        // Calculate averages - handle potential division by zero
        const avgCpuUsage = nodes.length > 0 ? nodes.reduce((sum, n) => sum + (n.cpu || 0), 0) / nodes.length : 0;
        const avgMemoryUsage = nodes.length > 0 ? nodes.reduce((sum, n) => sum + ((n.mem || 0) / (n.maxmem || 1)), 0) / nodes.length : 0;

        return {
            timestamp: new Date(),
            nodes: {
                total: nodes.length,
                online: nodes.filter(n => n.status === "online").length,
                averageCpuUsage: avgCpuUsage,
                averageMemoryUsage: avgMemoryUsage
            },
            virtualMachines: {
                total: vms.length,
                running: vms.filter(v => v.status === "running").length,
                stopped: vms.filter(v => v.status === "stopped").length,
                highCpuUsage: vms.filter(v => (v.cpu || 0) > 0.8).length
            },
            containers: {
                total: containers.length,
                running: containers.filter(c => c.status === "running").length,
                stopped: containers.filter(c => c.status === "stopped").length
            }
        };
    }

    async checkAlerts() {
        const alerts = [];
        const resources = await this.client.cluster.resources.resources();
        const data = resources.response.data;

        // Check for offline nodes
        const offlineNodes = data.filter(r => r.type === "node" && r.status !== "online");
        for (const node of offlineNodes) {
            alerts.push({
                severity: "critical",
                message: `Node ${node.node} is offline`,
                resource: node.node
            });
        }

        // Check for high resource usage
        const highCpuNodes = data.filter(r => r.type === "node" && (r.cpu || 0) > 0.9);
        for (const node of highCpuNodes) {
            alerts.push({
                severity: "warning",
                message: `Node ${node.node} has high CPU usage: ${(node.cpu * 100).toFixed(1)}%`,
                resource: node.node
            });
        }

        return alerts;
    }
}

// Usage
const monitor = new ClusterHealthMonitor(client);
const health = await monitor.getHealthReport();
const alerts = await monitor.checkAlerts();

console.log(`Cluster Health: ${health.nodes.online}/${health.nodes.total} nodes online`);
console.log(`VMs: ${health.virtualMachines.running}/${health.virtualMachines.total} running`);

for (const alert of alerts.filter(a => a.severity === "critical")) {
    console.log(`CRITICAL: ${alert.message}`);
}
```

---

## Architecture Patterns

### **Repository Pattern**

```javascript
class ProxmoxRepository {
    constructor(client) {
        this.client = client;
    }

    async getVmsAsync(nodeFilter = null) {
        console.log(`Getting VMs for node filter: ${nodeFilter}`);

        const resources = await this.client.cluster.resources.resources();
        let vms = resources.response.data.filter(r => r.type === "qemu");

        if (nodeFilter) {
            vms = vms.filter(vm => vm.node.toLowerCase() === nodeFilter.toLowerCase());
        }

        return vms;
    }

    async getVmConfigAsync(node, vmId) {
        console.log(`Getting config for VM ${vmId} on node ${node}`);

        const result = await this.client.nodes.get(node).qemu.get(vmId).config.vmConfig();
        return result.response.data;
    }

    async startVmAsync(node, vmId) {
        console.log(`Starting VM ${vmId} on node ${node}`);

        await this.client.nodes.get(node).qemu.get(vmId).status.start.vmStart();
        console.log(`Successfully started VM ${vmId}`);
    }

    async createSnapshotAsync(node, vmId, name, description = null) {
        console.log(`Creating snapshot ${name} for VM ${vmId} on node ${node}`);

        await this.client.nodes.get(node).qemu.get(vmId).snapshot.snapshot(name, description);
    }
}
```

---

## Error Handling and Logging

### **Centralized Error Management**

```javascript
class ProxmoxOperations {
    static async safeExecute(operation, operationName, logger = console) {
        try {
            logger.log(`Executing: ${operationName}`);
            const startTime = Date.now();

            const result = await operation();
            const duration = Date.now() - startTime;

            logger.log(`${operationName} completed in ${duration}ms`);

            return result;
        } catch (error) {
            if (error.code === 'ECONNRESET' || error.code === 'ECONNREFUSED') {
                logger.error(`Network error during ${operationName}: ${error.message}`);
                throw error;
            } else if (error.message.includes('timeout')) {
                logger.error(`Timeout during ${operationName}: ${error.message}`);
                throw error;
            } else {
                logger.error(`Unexpected error during ${operationName}: ${error.message}`);
                throw error;
            }
        }
    }
}

// Usage
const result = await ProxmoxOperations.safeExecute(
    async () => await client.nodes.get("pve1").qemu.get(100).status.start.vmStart(),
    "Start VM 100",
    console
);
```

---

## Best Practices Summary

### **Performance**
- Use appropriate timeout settings
- Implement retry policies for resilience
- Limit concurrent operations to avoid overloading the API
- Cache frequently accessed data

### **Security**
- Always use API tokens in production
- Store credentials securely (environment variables)
- Implement proper audit logging

### **Architecture**
- Use repository pattern for testability
- Implement centralized error handling
- Separate concerns with proper abstractions

### **Monitoring**
- Log all operations with appropriate levels
- Implement health checks and alerting
- Monitor task completion and failures
- Track performance metrics
