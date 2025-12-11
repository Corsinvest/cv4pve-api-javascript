# Common Issues and Solutions

This guide covers common issues, configuration patterns, and solutions when working with the Proxmox VE API in JavaScript/Node.js.

---

## Indexed Parameters

Many VM/CT configuration methods use indexed parameters represented as objects where the key is the index and the value is the configuration string.

### Understanding Indexed Parameters

Proxmox VE uses indexed parameters for devices that can have multiple instances. In the JavaScript API, indexed parameters are passed as objects with numeric keys and string values.

**Common Parameters:**
- **netN** - Network interfaces
- **scsiN** / **virtioN** / **sataN** / **ideN** - Disk devices
- **ipconfigN** - Cloud-init network configuration
- **hostpciN** / **usbN** - Hardware passthrough
- **mpN** - LXC mount points (containers only)

> **Note:** Proxmox VE supports many other indexed parameters. All use the same object pattern. For a complete list, refer to the [Proxmox VE API Documentation](https://pve.proxmox.com/pve-docs/api-viewer/).

### Basic Usage

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient("pve.example.com");
await client.login("root", "password", "pam");

// Configure network interfaces (indexed as net0, net1, etc.)
const networks = {
    0: "model=virtio,bridge=vmbr0,firewall=1",
    1: "model=e1000,bridge=vmbr1"
};

// Configure disks (indexed as scsi0, scsi1, etc.)
const disks = {
    0: "local-lvm:32,cache=writethrough",
    1: "local-lvm:64,iothread=1"
};

// Note: The actual method parameters may vary - check API documentation
await client.nodes.get("pve1").qemu.get(100).config.updateVm({
    net0: networks[0],
    net1: networks[1],
    scsi0: disks[0],
    scsi1: disks[1]
});
```

---

## Network Configuration (netN)

### Network Interface Syntax

Format: `model=<model>,bridge=<bridge>[,option=value,...]`

### Common Parameters

| Parameter | Description | Example Values |
|-----------|-------------|----------------|
| model | Network card model | virtio, e1000, rtl8139, vmxnet3 |
| bridge | Bridge to connect to | vmbr0, vmbr1 |
| firewall | Enable firewall | 0, 1 |
| link_down | Disconnect interface | 0, 1 |
| macaddr | MAC address | A2:B3:C4:D5:E6:F7 |
| mtu | MTU size | 1500, 9000 |
| queues | Number of queues | 1, 2, 4, 8 |
| rate | Rate limit (MB/s) | 10, 100 |
| tag | VLAN tag | 100, 200 |
| trunks | VLAN trunks | 10;20;30 |

### Examples

```javascript
// Basic VirtIO network
await vm.config.updateVm({
    net0: "model=virtio,bridge=vmbr0"
});

// Network with VLAN and firewall
await vm.config.updateVm({
    net0: "model=virtio,bridge=vmbr0,tag=100,firewall=1"
});

// Multiple networks with different settings
await vm.config.updateVm({
    net0: "model=virtio,bridge=vmbr0,firewall=1",
    net1: "model=e1000,bridge=vmbr1,rate=100",
    net2: "model=virtio,bridge=vmbr0,tag=200,queues=4"
});
```

---

## Disk Configuration

### Disk Syntax

Format: `<storage>:<size>[,option=value,...]`

Or for existing volumes: `<storage>:<volume>[,option=value,...]`

### Storage Types

- **scsiN** - SCSI disks (0-30), most common, supports all features
- **virtioN** - VirtIO disks (0-15), high performance
- **sataN** - SATA disks (0-5), legacy compatibility
- **ideN** - IDE disks (0-3), legacy, often used for CD-ROM
- **efidisk0** - EFI disk for UEFI boot

### Common Disk Parameters

| Parameter | Description | Example Values |
|-----------|-------------|----------------|
| cache | Cache mode | none, writethrough, writeback, directsync, unsafe |
| discard | Enable TRIM/discard | on, ignore |
| iothread | Enable IO thread | 0, 1 |
| ssd | SSD emulation | 0, 1 |
| backup | Include in backup | 0, 1 |
| replicate | Enable replication | 0, 1 |
| media | Media type | disk, cdrom |
| size | Disk size | 32G, 100G, 1T |

### SCSI Disk Examples

```javascript
// Basic SCSI disk - 32GB
await vm.config.updateVm({
    scsi0: "local-lvm:32"
});

// SCSI disk with options
await vm.config.updateVm({
    scsi0: "local-lvm:32,cache=writethrough,iothread=1,discard=on"
});

// Multiple SCSI disks
await vm.config.updateVm({
    scsi0: "local-lvm:32,cache=writethrough,iothread=1",  // OS disk
    scsi1: "local-lvm:100,cache=none,iothread=1,discard=on",  // Data disk
    scsi2: "local-lvm:200,backup=0"  // Temp disk, no backup
});
```

### VirtIO Disk Examples

```javascript
// VirtIO disks for maximum performance
await vm.config.updateVm({
    virtio0: "local-lvm:32,cache=writethrough,discard=on",
    virtio1: "ceph-storage:100,cache=none,iothread=1"
});
```

### SATA/IDE Examples

```javascript
// SATA disk
await vm.config.updateVm({
    sata0: "local-lvm:32"
});

// IDE CD-ROM
await vm.config.updateVm({
    ide2: "local:iso/ubuntu-22.04.iso,media=cdrom"
});
```

### EFI Disk

```javascript
// EFI disk for UEFI boot
await client.nodes.get("pve1").qemu.get(100).config.updateVm({
    bios: "ovmf",
    efidisk0: "local-lvm:1,efitype=4m,pre-enrolled-keys=0"
});
```

---

## Cloud-Init Configuration (ipconfigN)

### IP Configuration Syntax

Format: `ip=<address>,gw=<gateway>[,option=value,...]`

### Examples

```javascript
// DHCP on all interfaces
await vm.config.updateVm({
    ipconfig0: "ip=dhcp"
});

// Static IP configuration
await vm.config.updateVm({
    ipconfig0: "ip=192.168.1.100/24,gw=192.168.1.1"
});

// Multiple interfaces with different configs
await vm.config.updateVm({
    ipconfig0: "ip=192.168.1.100/24,gw=192.168.1.1",  // Management
    ipconfig1: "ip=10.0.0.100/24",  // Internal network
    ipconfig2: "ip=dhcp"  // External network via DHCP
});

// IPv6 with auto-configuration
await vm.config.updateVm({
    ipconfig0: "ip=192.168.1.100/24,gw=192.168.1.1,ip6=auto"
});
```

---

## Complete Example

### Linux VM with VirtIO and Cloud-Init

```javascript
const client = new PveClient("pve.example.com");
await client.login("admin", "password", "pve");

// VM identifiers
const vmid = 101;
const vmName = "ubuntu-server";
const node = "pve1";

// Hardware resources
const memory = 4096;  // 4GB RAM
const cores = 2;
const sockets = 1;

// Create VM with full configuration
const result = await client.nodes.get(node).qemu.createVm({
    vmid: vmid,
    name: vmName,
    memory: memory,
    cores: cores,
    sockets: sockets,
    ostype: "l26",
    scsihw: "virtio-scsi-single",
    boot: "order=virtio0",
    agent: "enabled=1",
    virtio0: "local-lvm:32,cache=writethrough,discard=on",
    net0: "model=virtio,bridge=vmbr0,firewall=1",
    ipconfig0: "ip=192.168.1.100/24,gw=192.168.1.1",
    ciuser: "admin",
    cipassword: "SecurePassword123!",
    sshkeys: "ssh-rsa AAAAB3NzaC1yc2E...",
    nameserver: "8.8.8.8 8.8.4.4",
    searchdomain: "example.com"
});

console.log(`VM ${vmid} created successfully with cloud-init!`);
```

---

## Common Troubleshooting

### VM Won't Start

**Check configuration:**
```javascript
const result = await client.nodes.get("pve1").qemu.get(100).config.vmConfig();
console.log(result.response.data);
```

**Common issues:**
- Missing boot disk: Verify `boot` parameter points to valid disk
- Invalid network bridge: Check bridge exists on node
- Insufficient resources: Verify memory/CPU allocation

### Disk Not Found

Verify storage exists and has space:
```javascript
const storages = await client.nodes.get("pve1").storage.index();
for (const storage of storages.response.data) {
    console.log(`Storage: ${storage.storage}`);
    console.log(`  Type: ${storage.type}`);
    console.log(`  Available: ${storage.avail}`);
}
```

### Network Issues

Verify bridge configuration:
```javascript
const networks = await client.nodes.get("pve1").network.index();
for (const net of networks.response.data) {
    if (net.type === "bridge") {
        console.log(`Bridge: ${net.iface}`);
    }
}
```

---

For more details on specific parameters and options, refer to the [Proxmox VE API Documentation](https://pve.proxmox.com/pve-docs/api-viewer/).
