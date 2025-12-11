# Task Management Guide

Understanding and managing long-running operations in Proxmox VE.

## Understanding Tasks

Many Proxmox VE operations are asynchronous and return a task ID instead of immediate results:

```javascript
// Operations that return task IDs
const result = await client.nodes.get("pve1").qemu.get(100).clone.cloneVm({newid: 101});
const taskId = result.response.data; // Returns: "UPID:pve1:..."
console.log(`Task started: ${taskId}`);
```

## Task Status

### **Checking Task Status**
```javascript
async function getTaskStatus(client, node, taskId) {
    const result = await client.nodes.get(node).tasks.get(taskId).status.readTaskStatus();
    const data = result.response.data;
    return {
        status: data.status,        // "running", "stopped"
        exitStatus: data.exitstatus, // "OK" if successful
        startTime: data.starttime,
        endTime: data.endtime,
        progress: data.pct ? parseFloat(data.pct) : null,
        log: data.log
    };
}
```

### **Waiting for Completion**
```javascript
async function waitForTaskCompletion(
    client,
    node,
    taskId,
    timeout = 1800000, // 30 minutes in milliseconds
    progressCallback = null
) {
    const startTime = Date.now();
    let lastStatus = "";

    while (Date.now() - startTime < timeout) {
        const statusResult = await client.nodes.get(node).tasks.get(taskId).status.readTaskStatus();
        const data = statusResult.response.data;
        const currentStatus = data.status;

        // Report progress if status changed
        if (currentStatus !== lastStatus && progressCallback) {
            progressCallback(`Task ${taskId}: ${currentStatus}`);
            lastStatus = currentStatus;
        }

        // Check if task completed
        if (currentStatus === "stopped") {
            const exitStatus = data.exitstatus;
            const success = exitStatus === "OK";

            if (progressCallback) {
                progressCallback(`Task ${taskId} ${success ? "completed" : "failed"}: ${exitStatus}`);
            }
            return success;
        }

        await new Promise(resolve => setTimeout(resolve, 2000)); // Check every 2 seconds
    }

    throw new Error(`Task ${taskId} did not complete within timeout`);
}
```

## Common Task Operations

### **VM Clone with Progress**
```javascript
async function cloneVmWithProgress(
    client,
    node,
    sourceVmId,
    targetVmId,
    newName
) {
    console.log(`Cloning VM ${sourceVmId} to ${targetVmId}...`);

    // Start clone operation
    const cloneResult = await client.nodes.get(node).qemu.get(sourceVmId).clone.cloneVm({
        newid: targetVmId,
        name: newName
    });
    const taskId = cloneResult.response.data;

    // Wait for completion with progress reporting
    const progressCallback = (status) => console.log(`Status: ${status}`);

    try {
        const success = await waitForTaskCompletion(client, node, taskId, 3600000, progressCallback); // 60 minutes

        if (success) {
            console.log(`VM cloned successfully: ${sourceVmId} → ${targetVmId}`);
        } else {
            console.log(`VM clone failed`);
        }

        return success;
    } catch (error) {
        console.log(`Timeout: Clone operation timed out: ${error.message}`);
        return false;
    }
}
```

### **Container Creation**
```javascript
async function createContainer(
    client,
    node,
    vmId,
    template,
    config
) {
    // Start container creation
    const createResult = await client.nodes.get(node).lxc.createVm({
        vmid: vmId,
        ostemplate: template,
        hostname: config.hostname,
        memory: config.memory,
        rootfs: config.rootfs
    });
    const taskId = createResult.response.data;
    console.log(`Creating container ${vmId} (Task: ${taskId})`);

    return await waitForTaskCompletion(client, node, taskId, 600000); // 10 minutes
}
```

## Monitoring Multiple Tasks

### **Parallel Task Monitoring**
```javascript
async function monitorMultipleTasks(
    client,
    tasks // Map: {taskId: node}
) {
    const results = {};
    const activeTasks = {...tasks}; // Clone the object

    console.log(`Monitoring ${Object.keys(activeTasks).length} tasks...`);

    while (Object.keys(activeTasks).length > 0) {
        const completedTasks = [];

        // Check each active task
        for (const [taskId, node] of Object.entries(activeTasks)) {
            try {
                const statusResult = await client.nodes.get(node).tasks.get(taskId).status.readTaskStatus();

                if (statusResult.response.data.status === "stopped") {
                    const success = statusResult.response.data.exitstatus === "OK";
                    results[taskId] = success;
                    completedTasks.push(taskId);

                    console.log(`Task ${taskId}: ${statusResult.response.data.exitstatus} (${success ? "Success" : "Failed"})`);
                }
            } catch (error) {
                console.log(`Error checking task ${taskId}: ${error.message}`);
                results[taskId] = false;
                completedTasks.push(taskId);
            }
        }

        // Remove completed tasks
        for (const taskId of completedTasks) {
            delete activeTasks[taskId];
        }

        if (Object.keys(activeTasks).length > 0) {
            await new Promise(resolve => setTimeout(resolve, 3000)); // Check every 3 seconds
        }
    }

    return results;
}
```

## Task Utilities

### **Task History**
```javascript
async function getRecentTasks(client, node, limit = 10) {
    const result = await client.nodes.get(node).tasks.nodeTasks({limit: limit});
    const tasks = [];

    for (const task of result.response.data) {
        tasks.push({
            id: task.upid,
            type: task.type,
            status: task.status,
            exitStatus: task.exitstatus,
            startTime: new Date(task.starttime * 1000), // Convert Unix timestamp
            endTime: task.endtime ? new Date(task.endtime * 1000) : null,
            user: task.user,
            node: task.node
        });
    }

    return tasks.sort((a, b) => b.startTime - a.startTime);
}
```

### **Task Cleanup**
```javascript
async function stopTask(client, node, taskId) {
    await client.nodes.get(node).tasks.get(taskId).delete();
    console.log(`Task ${taskId} stopped`);
}
```

## Best Practices

### **Timeout Management**
```javascript
// Set appropriate timeouts for different operations
const timeouts = {
    clone: 7200000,        // 2 hours in milliseconds
    backup: 14400000,      // 4 hours in milliseconds
    snapshot: 600000,      // 10 minutes
    start: 300000,         // 5 minutes
    stop: 300000,          // 5 minutes
    create: 1800000        // 30 minutes
};

const timeout = timeouts[operationType] || 1800000; // Default to 30 minutes
await waitForTaskCompletion(client, node, taskId, timeout);
```

### **Error Recovery**
```javascript
async function robustTaskWait(client, node, taskId) {
    const maxRetries = 3;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await waitForTaskCompletion(client, node, taskId);
        } catch (error) {
            if (attempt < maxRetries &&
                (error.code === 'ECONNRESET' || error.code === 'ECONNREFUSED' || error.message.includes('timeout'))) {
                console.log(`Warning: Network error checking task (attempt ${attempt}): ${error.message}`);
                await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
            } else if (attempt === maxRetries) {
                throw error; // Re-throw on final attempt
            }
        }
    }

    // Final attempt (should not be reached due to throw above, but for safety)
    return await waitForTaskCompletion(client, node, taskId);
}
```

### **Batch Operations with Tasks**
```javascript
async function bulkVmClone(
    client,
    node,
    sourceVmId,
    targetVmIds
) {
    const tasks = {}; // taskId -> targetVmId
    const results = {};

    // Start all clone operations
    for (const targetVmId of targetVmIds) {
        try {
            const cloneResult = await client.nodes.get(node).qemu.get(sourceVmId).clone.cloneVm({newid: targetVmId});

            if (cloneResult.isSuccessStatusCode) {
                const taskId = cloneResult.response.data;
                tasks[taskId] = targetVmId;
                console.log(`Started clone to VM ${targetVmId} (Task: ${taskId})`);
            } else {
                console.log(`Failed to start clone to VM ${targetVmId}: ${cloneResult.reasonPhrase}`);
                results[targetVmId] = false;
            }
        } catch (error) {
            console.log(`Exception starting clone to VM ${targetVmId}: ${error.message}`);
            results[targetVmId] = false;
        }
    }

    // Monitor all tasks
    const taskResults = await monitorMultipleTasks(
        client,
        Object.keys(tasks).reduce((obj, taskId) => {
            obj[taskId] = node;
            return obj;
        }, {})
    );

    // Map task results back to VM IDs
    for (const [taskId, success] of Object.entries(taskResults)) {
        if (tasks[taskId] !== undefined) {
            results[tasks[taskId]] = success;
        }
    }

    return results;
}
```
