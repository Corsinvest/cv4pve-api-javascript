# API Structure Guide

Understanding the hierarchical structure of the Proxmox VE API and how it maps to the JavaScript client.

## Tree Structure

The API follows the exact structure of the [Proxmox VE API](https://pve.proxmox.com/pve-docs/api-viewer/):

```javascript
// API Path: /cluster/status
await client.cluster.status.status();

// API Path: /nodes/{node}/qemu/{vmid}/config
await client.nodes.get("pve1").qemu.get(100).config.vmConfig();

// API Path: /nodes/{node}/lxc/{vmid}/snapshot
await client.nodes.get("pve1").lxc.get(101).snapshot.snapshot("snap-name");

// API Path: /nodes/{node}/storage/{storage}
await client.nodes.get("pve1").storage.get("local").status();
```

## HTTP Method Mapping

| HTTP Method | JavaScript Method | Purpose | Example |
|-------------|------------------|---------|---------|
| `GET` | `await resource.get()` | Retrieve information | `await vm.config.vmConfig()` |
| `POST` | `await resource.create(parameters)` | Create resources | `await vm.snapshot.snapshot("snap-name", "description")` |
| `PUT` | `await resource.set(parameters)` | Update resources | `await vm.config.updateVm({memory: 4096})` |
| `DELETE` | `await resource.delete()` | Remove resources | `await vm.deleteVm()` |

## Common Endpoints

### **Cluster Level**
```javascript
await client.cluster.status.status();           // GET /cluster/status
await client.cluster.resources.resources();     // GET /cluster/resources
await client.version.version();                 // GET /version
```

### **Node Level**
```javascript
await client.nodes.index();                     // GET /nodes
await client.nodes.get("pve1").status.status(); // GET /nodes/pve1/status
await client.nodes.get("pve1").storage.index(); // GET /nodes/pve1/storage
```

### **VM Operations**
```javascript
await client.nodes.get("pve1").qemu.get(100).config.vmConfig();        // GET config
await client.nodes.get("pve1").qemu.get(100).status.current.vmStatus(); // GET status
await client.nodes.get("pve1").qemu.get(100).status.start.vmStart();   // POST start
await client.nodes.get("pve1").qemu.get(100).snapshot.snapshotList();  // GET snapshots
```

### **Container Operations**
```javascript
await client.nodes.get("pve1").lxc.get(101).config.vmConfig();         // GET config
await client.nodes.get("pve1").lxc.get(101).status.current.vmStatus(); // GET status
await client.nodes.get("pve1").lxc.get(101).status.start.vmStart();    // POST start
```

## Parameters and Indexers

### **Numeric Indexers**
```javascript
client.nodes.get("pve1").qemu.get(100)     // VM ID 100
client.nodes.get("pve1").lxc.get(101)      // Container ID 101
```

### **String Indexers**
```javascript
client.nodes.get("pve1")                    // Node name
client.nodes.get("pve1").storage.get("local")   // Storage name
client.nodes.get("pve1").qemu.get(100).snapshot.get("snap1") // Snapshot name
```

### **Method Parameters**
```javascript
// Parameters as objects
await vm.config.updateVm({memory: 4096, cores: 2});

// Positional parameters
await vm.snapshot.snapshot("backup", "Description here");
```
