# Result Handling Guide

Understanding how to work with API responses and the Result class.

## Result Class

Every API call returns a Result object:

```javascript
{
    // Response data from Proxmox VE
    response: {
        data: {},           // The actual API response data
        /* for JSON responses, this contains the Proxmox VE response object */
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

## Checking Success

```javascript
const result = await client.nodes.get("pve1").qemu.get(100).config.vmConfig();

if (result.isSuccessStatusCode) {
    // Success - process the data
    console.log(`VM Name: ${result.response.data.name}`);
}
```

## Accessing Response Data

### **Direct Access**
```javascript
const result = await vm.config.vmConfig();
const data = result.response.data;
console.log(`VM Name: ${data.name}`);
console.log(`Memory: ${data.memory}`);
console.log(`Cores: ${data.cores}`);
```

### **Iterating Through Response**
```javascript
const result = await vm.config.vmConfig();
if (result.isSuccessStatusCode) {
    const data = result.response.data;
    for (const [key, value] of Object.entries(data)) {
        console.log(`${key}: ${value}`);
    }
}
```

## Error Handling

### **Basic Error Checking**
```javascript
const result = await vm.status.start.vmStart();

if (!result.isSuccessStatusCode) {
    console.log(`Failed to start VM: ${result.reasonPhrase}`);
    console.log(`HTTP Status: ${result.statusCode}`);
}
```

### **Detailed Error Information**
```javascript
const result = await vm.config.updateVm({memory: 999999}); // Invalid value

if (!result.isSuccessStatusCode) {
    console.log("Proxmox VE returned an error:");
    console.log(result.reasonPhrase);

    // Check specific status codes
    switch (result.statusCode) {
        case 401:
            console.log("Authentication failed");
            break;
        case 403:
            console.log("Permission denied");
            break;
        case 400:
            console.log("Invalid request parameters");
            break;
        case 500:
            console.log("Server error");
            break;
    }
}
```

## Working with Different Response Types

### **List Responses**
```javascript
const result = await client.cluster.resources.resources();
if (result.isSuccessStatusCode) {
    for (const resource of result.response.data) {
        console.log(`${resource.type}: ${resource.id}`);
    }
}
```

### **Task Responses**
```javascript
// Operations that return task IDs
const result = await vm.snapshot.snapshot("backup-snapshot");
if (result.isSuccessStatusCode) {
    const taskId = result.response.data;
    console.log(`Task started: ${taskId}`);

    // Monitor task progress...
}
```

### **Image Responses**
```javascript
// Change response type for charts
client.responseType = "png";
const chartResult = await client.nodes.get("pve1").rrd.rrd({ds: "cpu", timeframe: "day"});

if (chartResult.isSuccessStatusCode) {
    const base64Image = chartResult.response; // Base64 encoded image with data URI prefix
    console.log(`<img src="${base64Image}" />`);
}

// Switch back to JSON
client.responseType = "json";
```

## Best Practices

### **Always Check Success**
```javascript
// Good practice
const result = await vm.status.start.vmStart();
if (result.isSuccessStatusCode) {
    console.log("VM started successfully");
} else {
    console.log(`Failed to start VM: ${result.reasonPhrase}`);
}

// Don't ignore errors
await vm.status.start.vmStart(); // Missing error handling
```

### **Handle Null Values**
```javascript
const result = await vm.config.vmConfig();
const data = result.response.data;

// Safe access with optional chaining
const vmName = data?.name || "Unnamed VM";
const description = data?.description || "No description";

console.log(`VM: ${vmName} - ${description}`);
```

### **Error Handling with Try-Catch**
```javascript
try {
    const result = await vm.status.start.vmStart();
    if (result.isSuccessStatusCode) {
        console.log("VM started successfully");
    } else {
        console.log(`API error: ${result.reasonPhrase}`);
    }
} catch (error) {
    console.log(`Connection error: ${error.message}`);
}
```

## Response Error Detection

### **Check for Errors in Response**
```javascript
const result = await vm.config.updateVm({memory: 2048});

// Check if response contains errors
if (result.responseInError) {
    console.log("Response contains errors:");
    console.log(result.response.errors);
}
```

## Logging Results

### **Debug Information**
```javascript
// Enable logging to see full request/response details
client.logEnabled = true;

const result = await vm.config.vmConfig();

// The result object has a toString() method
console.log(result.toString());
```
