package main

import (
	"errors"
	"fmt"
	"os"

	"net/http"

	"sort"

	"strings"

	"github.com/Azure/azure-sdk-for-go/arm/network"
	"github.com/Azure/azure-sdk-for-go/arm/resources/resources"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/marstr/guid"
)

const (
	sampleSecurityGroupName  string = "samplesecuritygroup"
	sampleSecurityGroupLabel string = "Auto-generated Go-Sample Network Security Group"
)

// Authentication environment variable names.
const (
	azureEnvVarNameSubscriptionID string = "AZURE_SUBSCRIPTION_ID"
	azureEnvVarNameClientID       string = "AZURE_CLIENT_ID"
	azureEnvVarNameClientSecret   string = "AZURE_CLIENT_SECRET"
	azureEnvVarNameTenantID       string = "AZURE_TENANT_ID"
)

// Authentication environment variable values & the
var (
	subscriptionID string
	clientID       string
	clientSecret   string
	tenantID       string
	token          *azure.ServicePrincipalToken
	successfulInit bool
)

// Clients required for sending and receiving Azure requests.
var (
	vNetClient          network.VirtualNetworksClient
	resourceGroupClient resources.GroupsClient
)

var (
	sampleLocation = "westus2"
)

func main() {
	cancel := make(chan struct{})

	resourceGroupClient, resourceGroupName, err := createResourceGroup(cancel)
	if nil == err {
		defer deleteResourceGroup(resourceGroupClient, resourceGroupName, cancel)
	} else {
		return
	}

	vNetParameters := network.VirtualNetwork{
		Location: &sampleLocation,
		VirtualNetworkPropertiesFormat: &network.VirtualNetworkPropertiesFormat{
			AddressSpace: &network.AddressSpace{
				AddressPrefixes: &[]string{"192.168.0.0/16"},
			},
		},
	}
	if response, err := vNetClient.CreateOrUpdate(resourceGroupName, "sampleVirtualNetwork", vNetParameters, cancel); nil == err && http.StatusOK == response.StatusCode {
		fmt.Printf("Finished creating new Azure Virtual Network.\n")
	} else {
		fmt.Fprintf(os.Stderr, "Response Code: %d\nCould not create network because: %v\n", response.StatusCode, err)
	}

	if response, err := vNetClient.Delete("VMsampleResourceGroup", "sampleVirtualNetwork", cancel); nil == err && http.StatusOK == response.StatusCode {
		fmt.Printf("Finished deleting Azure Virtual Network.\n")
	} else {
		fmt.Fprintf(os.Stderr, "Response Code: %d\nCould not delete network because: %v\n", response.StatusCode, err)
	}
}

func init() {
	successfulInit = false
	subscriptionID = os.Getenv(azureEnvVarNameSubscriptionID)
	clientID = os.Getenv(azureEnvVarNameClientID)
	clientSecret = os.Getenv(azureEnvVarNameClientSecret)
	tenantID = os.Getenv(azureEnvVarNameTenantID)

	if errs := validateParameters(); len(errs) > 0 {
		for err := range errs {
			fmt.Fprintf(os.Stderr, "Invalid parameter. Details:\n%v\n", err)
		}
		return
	}

	authConfig, err := azure.PublicCloud.OAuthConfigForTenant(tenantID)
	if nil != err {
		fmt.Fprintf(os.Stderr, "%v", err)
		return
	}

	token, err = azure.NewServicePrincipalToken(*authConfig, clientID, clientSecret, azure.PublicCloud.ResourceManagerEndpoint) //TODO add callback in the event that the authentication token is refreshed.
	if nil != err {
		fmt.Fprintf(os.Stderr, "%v", err)
		return
	}

	vNetClient = network.NewVirtualNetworksClient(subscriptionID)
	vNetClient.Authorizer = token

	successfulInit = true
}

func createResourceGroup(cancel <-chan struct{}) (resources.GroupsClient, string, error) {
	resourceGroupClient = resources.NewGroupsClient(subscriptionID)
	resourceGroupClient.Authorizer = token

	resourceGroupName, err := getResourceGroupName(resourceGroupClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		return resourceGroupClient, resourceGroupName, err
	}

	resourceGroupParameters := resources.ResourceGroup{
		Location: &sampleLocation,
	}
	fmt.Printf("Creating Resource Group '%s'...", resourceGroupName)
	_, err = resourceGroupClient.CreateOrUpdate(resourceGroupName, resourceGroupParameters)
	if nil == err {
		fmt.Println("SUCCESS")
	} else {
		fmt.Println("FAILED")
		fmt.Fprintf(os.Stderr, "Error: %v", err)
	}
	return resourceGroupClient, resourceGroupName, err
}

func deleteResourceGroup(client resources.GroupsClient, name string, cancel <-chan struct{}) error {
	fmt.Fprintf(os.Stdout, "Deleting Resource Group '%s'...", name)

	response, err := resourceGroupClient.Delete(name, cancel)
	if nil == err && http.StatusOK == response.StatusCode {
		fmt.Fprintln(os.Stdout, "SUCCESS")
	} else {
		fmt.Fprintln(os.Stdout, "FAILED")
	}
	return err
}

func validateParameters() []error {
	const preferredGUIDFormat guid.Format = guid.FormatD

	errs := make([]error, 0)

	if "" == tenantID {
		errs = append(errs, newMissingAzureAuthError("Azure Tenant ID", azureEnvVarNameTenantID))
	} else if parsed, err := guid.Parse(tenantID); nil != err {
		errs = append(errs, err)
	} else {
		tenantID, _ = parsed.Stringf(preferredGUIDFormat)
	}

	if "" == subscriptionID {
		errs = append(errs, newMissingAzureAuthError("Azure Subscription ID", azureEnvVarNameSubscriptionID))
	} else if parsed, err := guid.Parse(subscriptionID); nil != err {
		errs = append(errs, err)
	} else {
		subscriptionID, _ = parsed.Stringf(preferredGUIDFormat)
	}

	if "" == clientID {
		errs = append(errs, newMissingAzureAuthError("Azure Client ID", azureEnvVarNameClientID))
	} else if parsed, err := guid.Parse(clientID); nil != err {
		errs = append(errs, err)
	} else {
		clientID, _ = parsed.Stringf(preferredGUIDFormat)
	}

	if "" == clientSecret {
		errs = append(errs, newMissingAzureAuthError("Azure Client Secret", azureEnvVarNameClientSecret))
	}

	//TODO marstr: Finish up formatting here.

	return errs
}

func newMissingAzureAuthError(pretty string, envVarName string) error {
	formatted := fmt.Sprintf("No value was provieded to act as the %s. Set enviroment variable \"%s\"", pretty, envVarName)
	return errors.New(formatted)
}

func getResourceGroupName(client resources.GroupsClient) (string, error) {
	const resourceGroupNamePrefix = "networkSecurityGroupSample"
	groupList, err := client.List("", nil)
	if nil != err {
		return "", err
	}

	if http.StatusOK == groupList.Response.StatusCode {
		any := false
		seen := make([]string, 0)
		for _, rg := range *groupList.Value {
			if strings.HasPrefix(*rg.Name, resourceGroupNamePrefix) {
				any = true
				seen = append(seen, *rg.Name)
			}
		}
		sort.Strings(seen)
		if any && seen[0] == resourceGroupNamePrefix {
			count := len(seen) - 1
			for i := 0; i < count; i++ {
				candidate := fmt.Sprintf("%s%d", resourceGroupNamePrefix, i)
				if seen[i+1] != candidate {
					return candidate, nil
				}
			}
			return fmt.Sprintf("%s%d", resourceGroupNamePrefix, len(seen)-1), nil
		}
		return resourceGroupNamePrefix, nil
	}
	return "", fmt.Errorf("Bad response: %d", groupList.Response.StatusCode) //TODO verify that error could be nil and status code something other than http.StatusOK
}
