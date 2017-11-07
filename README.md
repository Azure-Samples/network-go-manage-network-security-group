| services | platforms | author |
|:--------:|:---------:|:------:|
| network  | Go        | marstr |

# Getting Started with Network - Manage Network Security Groups - in Go

## Setting Up Your Machine
### Downloads and Subscriptions
This sample assumes that you have an Azure subscription to target. If you do not already have one, you can get started for free at [azure.microsoft.com](https://azure.microsoft.com/en-us/free/). 

You should also have a machine with [Go 1.9](https://golang.org/dl/) or higher installed.

### System Environment
You will need to have the following environment variables set when executing this sample:
- AZURE_SUBSCRIPTION_ID
- AZURE_TENANT_ID
- AZURE_CLIENT_ID
- AZURE_CLIENT_SECRET

There's a lot of great documentation that can be found on populating those variables, getting starting with Service Principals, and accessing your subscription programaticly. Here are some of the sites that will be best at helping you get started:
- [Azure SDK for Node, Authentication Documentation](https://github.com/Azure/azure-sdk-for-node/blob/master/Documentation/Authentication.md)
- [Azure Portal, ARM Documentation](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal)

## Acquiring & Running
There are a couple of options for acquiring and running this sample.
1. Using `go get...`:
   
   This is fastest and easiest, but will clutter your PATH. Simply run the following command:

   `go get -u github.com/Azure-Samples/network-go-manage-network-security-group`
   
   Once `go get` has finished running, you should be able to execute the command:

   `network-go-manage-network-security-group`

   If you make tweaks to the source code for the sample, you will need to [re-build](https://golang.org/cmd/go/#hdr-Compile_packages_and_dependencies) and optionally [re-install](https://golang.org/cmd/go/#hdr-Compile_and_install_packages_and_dependencies) the sample.
2. Clone & Build:

   Using this option will require using glide, but doesn't add anything into your Go bin directory. For this option, take the following steps:
   - Install [glide](https://github.com/Masterminds/glide) if it's not already present on your machine.
   - `git clone git@github.com:Azure-Samples/network-go-manage-network-security-group.git`
   - `cd network-go-manage-network-security-group`
   - `glide install`
   - `go run ./sample.go

Using either of the above options, your subscription may have restrictions on which Locations are eligible for the operations taken by this sample. If you run into trouble, you can change the region which is targeted by the global variable `sampleLocation`. At the time of this writing, the definition is on [line 47](https://github.com/Azure-Samples/network-go-manage-network-security-group/blob/master/sample.go#L47).

### Execution Flags
For convenience of the ability to test the network security groups that were craeted by this sample, there are a couple of ways to delay cleanup.
- `-pause` waits for human acknowledgement before deleting the resource group that was created.
- `-delay {uint}` waits a specified number of seconds before deleting the resource group that was created.
If you don't care to see the output messages, you can pass the flag `-quiet`.

## What This Sample Does
1. Create a Resource Group to encapsulate everything created by this sample.
2. Create a Virtual Network that will host the subjects of this sample.
3. Create two Security Groups that initially have no rules to enforce.
4. Create two Subnets, and associate them with the previously created Security Groups.
5. Create a set of SecurityRules for each Subnet that hypothetically would give appropriate access.
6. Clean up. Delete all of the items that were created above.