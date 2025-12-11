# Error Handling Guide

Comprehensive guide to handling errors and exceptions when working with the Proxmox VE API in JavaScript/Node.js.

## Types of Errors

### **Network Errors**
```javascript
try {
    const client = new PveClient("invalid-host.local");
    const result = await client.version.version();
} catch (error) {
    if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED' || error.code === 'EHOSTUNREACH') {
        console.log(`Network error: ${error.message}`);
        // Handle: DNS resolution, connection refused, network unreachable
    } else if (error.message.includes('timeout') || error.code === 'ETIMEDOUT') {
        console.log(`Request timeout: ${error.message}`);
        // Handle: Request took too long
    } else {
        console.log(`Request error: ${error.message}`);
    }
}
```

### **Authentication Errors**
```javascript
try {
    const client = new PveClient("pve.local");
    const success = await client.login("user", "wrong-password", "pam");

    if (!success) {
        console.log("Authentication failed - check credentials");
    }
} catch (error) {
    console.log(`Authentication error: ${error.message}`);
}
```

### **API Response Errors**
```javascript
const result = await client.nodes.get("pve1").qemu.get(999).config.vmConfig();

if (!result.isSuccessStatusCode) {
    switch (result.statusCode) {
        case 404:
            console.log("VM not found");
            break;
        case 403:
            console.log("Permission denied");
            break;
        case 400:
            console.log(`Bad request: ${result.reasonPhrase}`);
            break;
        default:
            console.log(`API error: ${result.statusCode} - ${result.reasonPhrase}`);
            break;
    }
}
```

## Error Handling Patterns

### **Basic Pattern**
```javascript
async function safeVmOperation(client, node, vmId) {
    try {
        const result = await client.nodes.get(node).qemu.get(vmId).status.start.vmStart();

        if (result.isSuccessStatusCode) {
            console.log(`VM ${vmId} started successfully`);
            return true;
        } else {
            console.log(`Failed to start VM ${vmId}: ${result.reasonPhrase}`);
            return false;
        }
    } catch (error) {
        console.log(`Exception starting VM ${vmId}: ${error.message}`);
        return false;
    }
}
```

### **Centralized Error Handler**
```javascript
class ErrorHandler {
    static async safeApiCall(apiCall, operation = "API call") {
        try {
            const result = await apiCall();

            if (!result.isSuccessStatusCode) {
                this.logApiError(result, operation);
            }

            return result;
        } catch (error) {
            if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED' || error.code === 'EHOSTUNREACH') {
                console.log(`Network error during ${operation}: ${error.message}`);
            } else if (error.message.includes('timeout') || error.code === 'ETIMEDOUT') {
                console.log(`Timeout during ${operation}: ${error.message}`);
            } else {
                console.log(`Unexpected error during ${operation}: ${error.message}`);
            }
            throw error;
        }
    }

    static logApiError(result, operation) {
        console.log(`${operation} failed:`);
        console.log(`   Status: ${result.statusCode} - ${result.reasonPhrase}`);

        if (result.response.errors) {
            console.log(`   Details: ${result.response.errors}`);
        }
    }
}

// Usage
const result = await ErrorHandler.safeApiCall(
    () => client.nodes.get("pve1").qemu.get(100).status.start.vmStart(),
    "Starting VM 100"
);
```

### **Retry Logic**
```javascript
async function withRetry(operation, maxRetries = 3, operationName = "operation") {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const result = await operation();

            if (result.isSuccessStatusCode) {
                return result;
            }

            // Don't retry client errors (4xx), only server errors (5xx)
            if (result.statusCode < 500) {
                console.log(`${operationName} failed with client error: ${result.statusCode}`);
                return result;
            }

            if (attempt < maxRetries) {
                console.log(`Warning: ${operationName} failed (attempt ${attempt}/${maxRetries}), retrying...`);
                const delay = Math.pow(2, attempt) * 1000; // Exponential backoff in milliseconds
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        } catch (error) {
            if (attempt < maxRetries) {
                console.log(`Warning: ${operationName} threw exception (attempt ${attempt}/${maxRetries}): ${error.message}`);
                const delay = Math.pow(2, attempt) * 1000;
                await new Promise(resolve => setTimeout(resolve, delay));
            } else {
                // Final attempt - re-throw the error
                throw error;
            }
        }
    }

    // Final attempt without catching exceptions
    return await operation();
}

// Usage
const result = await withRetry(
    () => client.nodes.get("pve1").qemu.get(100).config.vmConfig(),
    3,
    "Get VM config"
);
```

## Common Error Scenarios

### **Permission Issues**
```javascript
function handlePermissionError(result) {
    if (result.statusCode === 403) {
        console.log("Permission denied. Check:");
        console.log("   - User has required permissions");
        console.log("   - API token has correct privileges");
        console.log("   - Resource exists and user has access");
    }
}
```

### **Resource Not Found**
```javascript
async function vmExists(client, node, vmId) {
    try {
        const result = await client.nodes.get(node).qemu.get(vmId).config.vmConfig();
        return result.isSuccessStatusCode;
    } catch (error) {
        return false; // Network error, can't determine
    }
}

// Usage
if (!(await vmExists(client, "pve1", 100))) {
    console.log("VM 100 does not exist on node pve1");
    return;
}
```

### **Timeout Handling**
```javascript
const client = new PveClient("pve.local");
client.timeout = 300000; // Increase timeout for long operations (5 minutes in milliseconds)

try {
    const result = await client.nodes.get("pve1").qemu.get(100).clone.cloneVm({newid: 101});
} catch (error) {
    if (error.message.includes('timeout')) {
        console.log("Operation timed out - try increasing client timeout");
    } else {
        console.log("Operation failed:", error.message);
    }
}
```

## Best Practices

### **Defensive Programming**
```javascript
// Always validate input
async function getVmConfig(client, node, vmId) {
    if (!node || typeof node !== 'string') {
        throw new Error("Node name must be a non-empty string");
    }

    if (typeof vmId !== 'number' || vmId <= 0) {
        throw new Error("VM ID must be a positive number");
    }

    return await client.nodes.get(node).qemu.get(vmId).config.vmConfig();
}

// Check for null responses
const result = await client.cluster.resources.resources();
if (result.isSuccessStatusCode && result.response.data) {
    for (const resource of result.response.data) {
        // Process resource
    }
}
```

### **Graceful Degradation**
```javascript
async function getClusterStatus(client) {
    try {
        const result = await client.cluster.status.status();
        if (result.isSuccessStatusCode) {
            return parseClusterStatus(result.response.data);
        }
    } catch (error) {
        console.log(`Warning: Could not get cluster status: ${error.message}`);
    }

    // Return fallback status
    return { status: "unknown", lastUpdate: new Date() };
}
```

### **Detailed Logging**
```javascript
async function loggedApiCall(apiCall, operation) {
    console.log(`Starting: ${operation}`);
    const startTime = Date.now();

    try {
        const result = await apiCall();
        const duration = Date.now() - startTime;

        if (result.isSuccessStatusCode) {
            console.log(`${operation} completed in ${duration}ms`);
        } else {
            console.log(`${operation} failed after ${duration}ms: ${result.reasonPhrase}`);
        }

        return result;
    } catch (error) {
        const duration = Date.now() - startTime;
        console.log(`${operation} threw exception after ${duration}ms: ${error.message}`);
        throw error;
    }
}
```
