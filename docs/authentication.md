# Authentication Guide

This guide covers all authentication methods available for connecting to Proxmox VE.

## Authentication Methods

### **API Token (Recommended)**

API tokens are the most secure method for automation and applications.

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient("pve.example.com");

// Set API token (no login() call needed)
client.apiToken = "user@realm!tokenid=uuid";

// Ready to use
const version = await client.version.version();
```

**Format:** `USER@REALM!TOKENID=UUID`

**Example:** `automation@pve!api-token=12345678-1234-1234-1234-123456789abc`

### **Username/Password**

Traditional authentication with username and password.

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient("pve.example.com");

// Basic login (defaults to PAM realm)
const success = await client.login("root", "password");

// Login with specific realm
const success = await client.login("admin", "password", "pve");

// Login with PAM realm explicitly
const success = await client.login("user", "password", "pam");
```

### **Two-Factor Authentication (2FA)**

For accounts with Two-Factor Authentication enabled.

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient("pve.example.com");

// Login with TOTP/OTP code
const success = await client.login("admin", "password", "pve", "123456");

// The fourth parameter is the 6-digit code from your authenticator app
```

---

## Creating API Tokens

### **Via Proxmox VE Web Interface**

1. **Login** to Proxmox VE web interface
2. **Navigate** to Datacenter → Permissions → API Tokens
3. **Click** "Add" button
4. **Configure** token:
   - **User:** Select user (e.g., `root@pam`)
   - **Token ID:** Choose name (e.g., `api-automation`)
   - **Privilege Separation:** Uncheck for full user permissions
   - **Comment:** Optional description
5. **Click** "Add" and **copy the token** (you won't see it again!)

### **Via Command Line**

```bash
# Create API token
pveum user token add root@pam api-automation --privsep=0

# List tokens
pveum user token list root@pam

# Remove token
pveum user token remove root@pam api-automation
```

### **Example Token Creation**

```bash
# Create token for automation user
pveum user add automation@pve --password "secure-password"
pveum user token add automation@pve api-token --privsep=0 --comment "API automation"

# Grant necessary permissions
pveum aclmod / -user automation@pve -role Administrator
```

---

## Security Best Practices

### **DO's**

```javascript
// Use API tokens for automation
client.apiToken = process.env.PROXMOX_API_TOKEN;

// Store credentials securely
const username = process.env.PROXMOX_USER;
const password = process.env.PROXMOX_PASS;

// Use specific user accounts (not root)
await client.login("automation", password, "pve");
```

### **DON'Ts**

```javascript
// Don't hardcode credentials
await client.login("root", "password123"); // Bad!

// Don't use overly permissive tokens
// Create tokens with minimal required permissions
```

---

## Permission Management

### **Creating Dedicated Users**

```bash
# Create user for API access
pveum user add api-user@pve --password "secure-password" --comment "API automation user"

# Create custom role with specific permissions
pveum role add ApiUser -privs "VM.Audit,VM.Config.Disk,VM.Config.Memory,VM.PowerMgmt,VM.Snapshot"

# Assign role to user
pveum aclmod / -user api-user@pve -role ApiUser
```

### **Common Permission Sets**

```bash
# Read-only access
pveum role add ReadOnly -privs "VM.Audit,Datastore.Audit,Sys.Audit"

# VM management
pveum role add VMManager -privs "VM.Audit,VM.Config.Disk,VM.Config.Memory,VM.PowerMgmt,VM.Snapshot,VM.Clone"

# Full administrator (use with caution)
pveum aclmod / -user user@pve -role Administrator
```

---

## Environment Configuration

### **Environment Variables**

```bash
# Set environment variables
export PROXMOX_HOST="pve.example.com"
export PROXMOX_API_TOKEN="user@pve!token=uuid"

# Or for username/password
export PROXMOX_USER="admin@pve"
export PROXMOX_PASS="secure-password"
```

### **Application Configuration**

```javascript
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

// Load configuration from environment
const config = {
    host: process.env.PROXMOX_HOST,
    apiToken: process.env.PROXMOX_API_TOKEN,
    timeout: parseInt(process.env.PROXMOX_TIMEOUT || '30000')
};

const client = new PveClient(config.host);

// Use API token if available
if (config.apiToken) {
    client.apiToken = config.apiToken;
} else {
    // Fallback to username/password
    const username = process.env.PROXMOX_USER;
    const password = process.env.PROXMOX_PASS;
    await client.login(username, password);
}
```

### **Configuration File Example**

```json
{
  "proxmox": {
    "host": "pve.example.com",
    "apiToken": "user@pve!token=uuid",
    "timeout": 30000
  }
}
```

---

## Troubleshooting Authentication

### **Common Issues**

#### **"Authentication Failed"**
```javascript
// Check credentials
try {
    const success = await client.login("user", "password", "pam");
    if (!success) {
        console.log("Invalid credentials");
    }
} catch (error) {
    console.log(`Login error: ${error.message}`);
}
```

#### **"Permission Denied"**
```bash
# Check user permissions
pveum user list
pveum aclmod / -user user@pve -role Administrator
```

#### **"Invalid API Token"**
```javascript
// Verify token format
client.apiToken = "user@realm!tokenid=uuid"; // Correct format

// Check if token exists
// Token format: USER@REALM!TOKENID=SECRET
```

### **Testing Authentication**

```javascript
async function testAuthentication(client) {
    try {
        const version = await client.version.version();
        if (version.isSuccessStatusCode) {
            console.log("Authentication successful");
            console.log(`Connected to Proxmox VE ${version.response.data.version}`);
            return true;
        } else {
            console.log(`Authentication failed: ${version.reasonPhrase}`);
            return false;
        }
    } catch (error) {
        console.log(`Connection error: ${error.message}`);
        return false;
    }
}
```

---

## Authentication Examples

### **Enterprise Setup**

```javascript
// Corporate environment
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient("pve.company.com");
client.timeout = 300000; // 5 minutes in milliseconds

client.apiToken = process.env.PROXMOX_API_TOKEN;
```

### **Home Lab Setup**

```javascript
// Simple home lab setup
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient("192.168.1.100");
client.timeout = 120000; // 2 minutes in milliseconds

await client.login("root", process.env.PVE_PASSWORD, "pam");
```

### **Cloud/Automation Setup**

```javascript
// Automated deployment script
const { PveClient } = require("@corsinvest/cv4pve-api-javascript");

const client = new PveClient(process.env.PROXMOX_HOST);

// Use API token for automation
client.apiToken = process.env.PROXMOX_API_TOKEN;

// Verify connection before proceeding
if (!(await testAuthentication(client))) {
    process.exit(1);
}
```
