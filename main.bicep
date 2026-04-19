// ============================================================
// AZURE CAPSTONE PROJECT — main.bicep
// Deploys: VNet, Subnets, NSGs, 2 VMs + Nginx, Load Balancer,
//          Azure SQL DB (private), Key Vault, Monitor Alert
// ============================================================

// ---------- PARAMETERS ----------
// These are values you can change before deploying

@description('Location for all resources')
param location string = resourceGroup().location

@description('Admin username for the VMs')
param vmAdminUsername string = 'azureuser'

@description('Admin password for the VMs')
@secure()
param vmAdminPassword string

@description('Admin username for SQL Server')
param sqlAdminUsername string = 'sqladmin'

@description('Admin password for SQL Server')
@secure()
param sqlAdminPassword string

@description('Your email for alert notifications')
param alertEmail string

// ---------- VARIABLES ----------
// Reusable name definitions

var vnetName = 'vnet-capstone'
var nsgWebName = 'nsg-web'
var nsgAppName = 'nsg-app'
var nsgDbName = 'nsg-db'
var vm1Name = 'vm-web-01'
var vm2Name = 'vm-web-02'
var lbName = 'lb-capstone'
var lbPipName = 'pip-loadbalancer'
var sqlServerName = 'sql-server-capstone-${uniqueString(resourceGroup().id)}'
var sqlDbName = 'db-capstone'
var keyVaultName = 'kv-cap-${uniqueString(resourceGroup().id)}'
var actionGroupName = 'ag-cpu-alert'
var alertRuleName = 'alert-high-cpu'

// Nginx install script that runs on VM startup
var nginxInstallScript = '''
#!/bin/bash
apt-get update -y
apt-get install nginx -y
systemctl start nginx
systemctl enable nginx
echo "<h1>Hello from $(hostname)</h1>" > /var/www/html/index.html
'''

// ============================================================
// 1. NETWORK SECURITY GROUPS
// ============================================================

// NSG for Web Subnet — allows HTTP and HTTPS from internet
resource nsgWeb 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: nsgWebName
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-HTTP'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
        }
      }
      {
        name: 'Allow-HTTPS'
        properties: {
          priority: 110
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        name: 'Allow-SSH'
        properties: {
          priority: 120
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
    ]
  }
}

// NSG for App Subnet — only allows traffic from Web Subnet
resource nsgApp 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: nsgAppName
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-From-Web'
        properties: {
          priority: 100
          protocol: '*'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '10.0.1.0/24'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// NSG for DB Subnet — only allows SQL port from App Subnet
resource nsgDb 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: nsgDbName
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-SQL-From-App'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '10.0.2.0/24'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '1433'
        }
      }
    ]
  }
}

// ============================================================
// 2. VIRTUAL NETWORK + SUBNETS
// ============================================================

resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
    subnets: [
      {
        name: 'subnet-web'
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: { id: nsgWeb.id }
        }
      }
      {
        name: 'subnet-app'
        properties: {
          addressPrefix: '10.0.2.0/24'
          networkSecurityGroup: { id: nsgApp.id }
        }
      }
      {
        name: 'subnet-db'
        properties: {
          addressPrefix: '10.0.3.0/24'
          networkSecurityGroup: { id: nsgDb.id }
          // Needed for private endpoint
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

// Helper references to individual subnets
var subnetWebId = vnet.properties.subnets[0].id
var subnetDbId  = vnet.properties.subnets[2].id

// ============================================================
// 3. LOAD BALANCER — Public IP + Frontend + Backend + Rule
// ============================================================

resource lbPip 'Microsoft.Network/publicIPAddresses@2023-04-01' = {
  name: lbPipName
  location: location
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource lb 'Microsoft.Network/loadBalancers@2023-04-01' = {
  name: lbName
  location: location
  sku: { name: 'Standard' }
  properties: {
    frontendIPConfigurations: [
      {
        name: 'frontend-ip'
        properties: {
          publicIPAddress: { id: lbPip.id }
        }
      }
    ]
    backendAddressPools: [
      { name: 'backend-pool' }
    ]
    probes: [
      {
        name: 'probe-http'
        properties: {
          protocol: 'Tcp'
          port: 80
          intervalInSeconds: 5
          numberOfProbes: 2
        }
      }
    ]
    loadBalancingRules: [
      {
        name: 'rule-http'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/loadBalancers/frontendIPConfigurations', lbName, 'frontend-ip')
          }
          backendAddressPool: {
            id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', lbName, 'backend-pool')
          }
          probe: {
            id: resourceId('Microsoft.Network/loadBalancers/probes', lbName, 'probe-http')
          }
          protocol: 'Tcp'
          frontendPort: 80
          backendPort: 80
          enableFloatingIP: false
          idleTimeoutInMinutes: 4
        }
      }
    ]
  }
}

// ============================================================
// 4. VIRTUAL MACHINES — NICs + VMs with Nginx auto-install
// ============================================================

// --- VM 1 Network Interface ---
resource nic1 'Microsoft.Network/networkInterfaces@2023-04-01' = {
  name: '${vm1Name}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: subnetWebId }
          privateIPAllocationMethod: 'Dynamic'
          loadBalancerBackendAddressPools: [
            {
              id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', lbName, 'backend-pool')
            }
          ]
        }
      }
    ]
  }
  dependsOn: [lb]
}

// --- VM 2 Network Interface ---
resource nic2 'Microsoft.Network/networkInterfaces@2023-04-01' = {
  name: '${vm2Name}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: subnetWebId }
          privateIPAllocationMethod: 'Dynamic'
          loadBalancerBackendAddressPools: [
            {
              id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', lbName, 'backend-pool')
            }
          ]
        }
      }
    ]
  }
  dependsOn: [lb]
}

// --- Virtual Machine 1 ---
resource vm1 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: vm1Name
  location: location
  properties: {
    hardwareProfile: { vmSize: 'Standard_B1s' }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'Standard_LRS' }
      }
    }
    osProfile: {
      computerName: vm1Name
      adminUsername: vmAdminUsername
      adminPassword: vmAdminPassword
    }
    networkProfile: {
      networkInterfaces: [{ id: nic1.id }]
    }
  }
}

// Auto-install Nginx on VM 1 via Custom Script Extension
resource vm1NginxExt 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {
  parent: vm1
  name: 'install-nginx'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Extensions'
    type: 'CustomScript'
    typeHandlerVersion: '2.1'
    autoUpgradeMinorVersion: true
    settings: {
      script: base64(nginxInstallScript)
    }
  }
}

// --- Virtual Machine 2 ---
resource vm2 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: vm2Name
  location: location
  properties: {
    hardwareProfile: { vmSize: 'Standard_B1s' }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'Standard_LRS' }
      }
    }
    osProfile: {
      computerName: vm2Name
      adminUsername: vmAdminUsername
      adminPassword: vmAdminPassword
    }
    networkProfile: {
      networkInterfaces: [{ id: nic2.id }]
    }
  }
}

// Auto-install Nginx on VM 2
resource vm2NginxExt 'Microsoft.Compute/virtualMachines/extensions@2023-03-01' = {
  parent: vm2
  name: 'install-nginx'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Extensions'
    type: 'CustomScript'
    typeHandlerVersion: '2.1'
    autoUpgradeMinorVersion: true
    settings: {
      script: base64(nginxInstallScript)
    }
  }
}

// ============================================================
// 5. AZURE SQL SERVER + DATABASE (private, no public access)
// ============================================================

resource sqlServer 'Microsoft.Sql/servers@2022-05-01-preview' = {
  name: sqlServerName
  location: location
  properties: {
    administratorLogin: sqlAdminUsername
    administratorLoginPassword: sqlAdminPassword
    publicNetworkAccess: 'Disabled'
  }
}

resource sqlDb 'Microsoft.Sql/servers/databases@2022-05-01-preview' = {
  parent: sqlServer
  name: sqlDbName
  location: location
  sku: {
    name: 'GP_S_Gen5_1'
    tier: 'GeneralPurpose'
    family: 'Gen5'
    capacity: 1
  }
  properties: {
    autoPauseDelay: 60
    minCapacity: '0.5'
  }
}

// Private Endpoint — gives SQL a private IP inside the VNet
resource sqlPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-04-01' = {
  name: 'pe-sql'
  location: location
  properties: {
    subnet: { id: subnetDbId }
    privateLinkServiceConnections: [
      {
        name: 'sql-connection'
        properties: {
          privateLinkServiceId: sqlServer.id
          groupIds: ['sqlServer']
        }
      }
    ]
  }
}

// ============================================================
// 6. KEY VAULT — stores secrets securely
// ============================================================

resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    softDeleteRetentionInDays: 7
    enableSoftDelete: true
  }
}

// Secret: SQL admin username
resource secretSqlUser 'Microsoft.KeyVault/vaults/secrets@2023-02-01' = {
  parent: keyVault
  name: 'sql-admin-username'
  properties: {
    value: sqlAdminUsername
  }
}

// Secret: SQL admin password
resource secretSqlPass 'Microsoft.KeyVault/vaults/secrets@2023-02-01' = {
  parent: keyVault
  name: 'sql-admin-password'
  properties: {
    value: sqlAdminPassword
  }
}

// Secret: SQL connection string
resource secretConnStr 'Microsoft.KeyVault/vaults/secrets@2023-02-01' = {
  parent: keyVault
  name: 'sql-connection-string'
  properties: {
    value: 'Server=tcp:${sqlServer.properties.fullyQualifiedDomainName},1433;Database=${sqlDbName};User ID=${sqlAdminUsername};Password=${sqlAdminPassword};Encrypt=true;'
  }
}

// ============================================================
// 7. MONITORING — Action Group + CPU Alert Rule
// ============================================================

// Action Group: sends an email when alert fires
resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: actionGroupName
  location: 'global'
  properties: {
    groupShortName: 'CPUAlert'
    enabled: true
    emailReceivers: [
      {
        name: 'email-notification'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
  }
}

// Alert Rule: fires when VM 1 CPU > 80%
resource cpuAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: alertRuleName
  location: 'global'
  properties: {
    description: 'Alert when CPU on vm-web-01 exceeds 80%'
    severity: 2
    enabled: true
    scopes: [vm1.id]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'HighCPU'
          metricName: 'Percentage CPU'
          operator: 'GreaterThan'
          threshold: 80
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [
      { actionGroupId: actionGroup.id }
    ]
  }
}

// ============================================================
// OUTPUTS — shown after deployment
// ============================================================

output loadBalancerPublicIP string = lbPip.properties.ipAddress
output sqlServerFQDN string = sqlServer.properties.fullyQualifiedDomainName
output keyVaultName string = keyVault.name
