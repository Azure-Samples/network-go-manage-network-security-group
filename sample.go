package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/arm/network"
	"github.com/Azure/azure-sdk-for-go/arm/resources/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
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
	token          *adal.ServicePrincipalToken
)

// User adjustable variables to customized execution environment depending on
// Azure Subscription requirements.
var (
	sampleLocation = "westus2"
)

// Capture flow control options as defined by the arguments provided to this program.
var (
	output io.Writer
	pause  bool
	delay  uint
	help   bool
)

// Exit status codes associated with various error cases.
const (
	ExitSuccess = iota
	ExitAuthenticationFailure
	ExitResourceGroupCreationFailure
	ExitVirtualNetworkCreationFailure
	ExitNetworkSecuritryGroupCreationFailure
	ExitSecurityRuleCreationFailure
	ExitSubnetCreationFailure
)

func main() {
	exitStatus := ExitSuccess
	defer func() {
		os.Exit(exitStatus)
	}()

	if help {
		return
	}

	//Ensure authentication is setup correctly before continuing.
	if nil == token {
		fmt.Fprintln(os.Stderr, "Fatal Error: Authentication Failed.")
		exitStatus = ExitAuthenticationFailure
		return
	}

	bearer := autorest.NewBearerAuthorizer(token)

	cancel := make(chan struct{})

	// Make an isolated environment to store assets created for this sample.
	resourceGroupClient, resourceGroupName, err := createResourceGroup(cancel)
	if err != nil {
		exitStatus = ExitResourceGroupCreationFailure
		return
	}
	defer deleteResourceGroup(resourceGroupClient, resourceGroupName, cancel)

	// Create a network that will be the target of network security groups
	_, vNetName, err := createVirtualNetwork(resourceGroupName, cancel)
	if nil != err {
		exitStatus = ExitVirtualNetworkCreationFailure
		return
	}

	// Create two Network Security Groups, one to be used for front-end requests, another for back-end
	nsgClient := network.NewSecurityGroupsClient(subscriptionID)
	nsgClient.Authorizer = bearer

	frontEndNSG, err := createNetworkSecurityGroup(nsgClient, resourceGroupName, "frontend", cancel)
	if nil != err {
		exitStatus = ExitNetworkSecuritryGroupCreationFailure
		return
	}

	backEndNSG, err := createNetworkSecurityGroup(nsgClient, resourceGroupName, "backend", cancel)
	if nil != err {
		exitStatus = ExitNetworkSecuritryGroupCreationFailure
		return
	}

	//Create Subnets to host Virtual Machines which will be protected by the rules above.
	subNetClient := network.NewSubnetsClient(subscriptionID)
	subNetClient.Authorizer = bearer

	frontendAddressPrefix := to.StringPtr("192.168.1.0/24")
	frontendSubnet := network.Subnet{
		Name: to.StringPtr("frontendSubnet"),
		SubnetPropertiesFormat: &network.SubnetPropertiesFormat{
			AddressPrefix:        frontendAddressPrefix,
			NetworkSecurityGroup: &frontEndNSG,
		},
	}

	backendAddressPrefix := to.StringPtr("192.168.2.0/24")
	backendSubnet := network.Subnet{
		Name: to.StringPtr("backendSubnet"),
		SubnetPropertiesFormat: &network.SubnetPropertiesFormat{
			AddressPrefix:        backendAddressPrefix,
			NetworkSecurityGroup: &backEndNSG,
		},
	}

	_, err = executeWithStatus(func() (resp autorest.Response, err error) {
		respChan, errChan := subNetClient.CreateOrUpdate(resourceGroupName, vNetName, *frontendSubnet.Name, frontendSubnet, cancel)
		resp, err = (<-respChan).Response, <-errChan
		return
	}, fmt.Sprintf("Creating Subnet '%s'", *frontendSubnet.Name))
	if err != nil {
		exitStatus = ExitSubnetCreationFailure
		return
	}

	_, err = executeWithStatus(func() (autorest.Response, error) {
		respChan, errChan := subNetClient.CreateOrUpdate(resourceGroupName, vNetName, *backendSubnet.Name, backendSubnet, cancel)
		return (<-respChan).Response, <-errChan
	}, fmt.Sprintf("Creating Subnet '%s'", *backendSubnet.Name))
	if err != nil {
		exitStatus = ExitSubnetCreationFailure
		return
	}

	// Create the security rules that should be enforced, and associate them with their respective security group.
	ruleClient := network.NewSecurityRulesClient(subscriptionID)
	ruleClient.Authorizer = autorest.NewBearerAuthorizer(token)

	anyPortRange := "*"
	anyAddressPrefix := "*"

	sshPortRange := "22"
	sshRuleDesc := "Allow SSH"
	sshRulePriority := int32(100)
	frontendSSHRuleName := "ALLOW-SSH"
	frontendSSHRule := network.SecurityRule{
		Name: &frontendSSHRuleName,
		SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
			Access: network.SecurityRuleAccessAllow,
			DestinationAddressPrefix: &anyAddressPrefix,
			DestinationPortRange:     &sshPortRange,
			Direction:                network.SecurityRuleDirectionInbound,
			Description:              &sshRuleDesc,
			Priority:                 &sshRulePriority,
			Protocol:                 network.SecurityRuleProtocolTCP,
			SourceAddressPrefix:      &anyAddressPrefix,
			SourcePortRange:          &anyPortRange,
		},
	}

	_, err = executeWithStatus(func() (autorest.Response, error) {
		respChan, errChan := ruleClient.CreateOrUpdate(resourceGroupName, *frontEndNSG.Name, frontendSSHRuleName, frontendSSHRule, cancel)
		return (<-respChan).Response, <-errChan
	}, fmt.Sprintf("Creating Security Rule '%s'", *frontendSSHRule.Description))
	if nil != err {
		exitStatus = ExitSecurityRuleCreationFailure
		return
	}

	frontendHTTPRuleName := "ALLOW-HTTP"
	frontendHTTPRule := network.SecurityRule{
		SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
			Access: network.SecurityRuleAccessAllow,
			DestinationAddressPrefix: &anyAddressPrefix,
			DestinationPortRange:     to.StringPtr("80"),
			Direction:                network.SecurityRuleDirectionInbound,
			Description:              to.StringPtr("Allow HTTP"),
			Priority:                 to.Int32Ptr(101),
			Protocol:                 network.SecurityRuleProtocolTCP,
			SourceAddressPrefix:      &anyAddressPrefix,
			SourcePortRange:          &anyPortRange,
		},
	}

	executeWithStatus(func() (autorest.Response, error) {
		respChan, errChan := ruleClient.CreateOrUpdate(resourceGroupName, *frontEndNSG.Name, frontendHTTPRuleName, frontendHTTPRule, cancel)
		return (<-respChan).Response, <-errChan
	}, fmt.Sprintf("Creating Security Rule '%s'", *frontendHTTPRule.Description))

	if nil != err {
		exitStatus = ExitSecurityRuleCreationFailure
		return
	}

	sqlRuleName := "ALLOW-SQL"
	backendSQLRule := network.SecurityRule{
		SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
			Access: network.SecurityRuleAccessAllow,
			DestinationAddressPrefix: &anyAddressPrefix,
			DestinationPortRange:     to.StringPtr("1433"),
			Direction:                network.SecurityRuleDirectionInbound,
			Description:              to.StringPtr("Allow SQL"),
			Priority:                 to.Int32Ptr(100),
			Protocol:                 network.SecurityRuleProtocolTCP,
			SourceAddressPrefix:      frontendAddressPrefix,
			SourcePortRange:          &anyPortRange,
		},
	}

	executeWithStatus(func() (autorest.Response, error) {
		respChan, errChan := ruleClient.CreateOrUpdate(resourceGroupName, *backEndNSG.Name, sqlRuleName, backendSQLRule, cancel)
		return (<-respChan).Response, <-errChan
	}, fmt.Sprintf("Creating Security Rule \"%s\"", sqlRuleName))

	outDenyName := "DENY-OUT"
	backendOutboundRule := network.SecurityRule{
		SecurityRulePropertiesFormat: &network.SecurityRulePropertiesFormat{
			Access: network.SecurityRuleAccessDeny,
			DestinationAddressPrefix: &anyAddressPrefix,
			DestinationPortRange:     &anyPortRange,
			Direction:                network.SecurityRuleDirectionOutbound,
			Description:              to.StringPtr("Deny Outbound traffic"),
			Priority:                 to.Int32Ptr(100),
			Protocol:                 network.SecurityRuleProtocolAsterisk,
			SourceAddressPrefix:      &anyAddressPrefix,
			SourcePortRange:          &anyPortRange,
		},
	}

	executeWithStatus(func() (autorest.Response, error) {
		respChan, errChan := ruleClient.CreateOrUpdate(resourceGroupName, *backEndNSG.Name, outDenyName, backendOutboundRule, cancel)
		return (<-respChan).Response, <-errChan
	}, fmt.Sprintf("Creating Security Rule \"%s\"", outDenyName))

	// Give the user time to go inspect their subscription if they desire.
	if pause {
		fmt.Printf("Press Enter to continue...")
		fmt.Scanln()
	} else if delay > 0 {
		fmt.Fprintf(output, "Delaying %d seconds...", delay)
		time.Sleep(time.Second * time.Duration(delay))
		fmt.Fprintln(output, "DONE")
	}
}

func init() {
	// Setup execution environment
	subscriptionID = os.Getenv(azureEnvVarNameSubscriptionID)
	clientID = os.Getenv(azureEnvVarNameClientID)
	clientSecret = os.Getenv(azureEnvVarNameClientSecret)
	tenantID = os.Getenv(azureEnvVarNameTenantID)

	useQuiet := flag.Bool("quiet", false, "Prevents status messages from being printed to stdout.")
	flag.BoolVar(&pause, "pause", false, "After all sample assets are created, wait for user response before removing all assets created for this sample.")
	flag.UintVar(&delay, "delay", 0, "An alternative to 'pause' which waits the specified number of seconds before removing all assets created for this sample.")
	flag.BoolVar(&help, "help", false, "Instead of executing this sample, enumerates the available flags.")
	flag.Parse()

	if help {
		flag.PrintDefaults()
		return
	}

	if *useQuiet {
		output = ioutil.Discard
	} else {
		output = os.Stdout
	}

	if errs := validateParameters(); len(errs) > 0 {
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "Invalid argument. Details: %v\n", err)
		}
		return
	}

	//Authenticate

	authConfig, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, tenantID)
	if nil != err {
		fmt.Fprint(os.Stderr, err)
		return
	}

	token, err = adal.NewServicePrincipalToken(*authConfig, clientID, clientSecret, azure.PublicCloud.ResourceManagerEndpoint)
	if nil != err {
		fmt.Fprint(os.Stderr, err)
		return
	}
}

func createNetworkSecurityGroup(client network.SecurityGroupsClient, resourceGroupName string, name string, cancel <-chan struct{}) (network.SecurityGroup, error) {
	args := network.SecurityGroup{
		Name:     &name,
		Location: &sampleLocation,
	}
	_, err := executeWithStatus(func() (autorest.Response, error) {
		respChan, errChan := client.CreateOrUpdate(resourceGroupName, name, args, cancel)
		return (<-respChan).Response, <-errChan
	}, fmt.Sprintf("Creating Network Security Group '%s'", name))

	result, err := client.Get(resourceGroupName, *args.Name, "")
	return result, err
}

func createResourceGroup(cancel <-chan struct{}) (resources.GroupsClient, string, error) {
	resourceGroupClient := resources.NewGroupsClient(subscriptionID)
	resourceGroupClient.Authorizer = autorest.NewBearerAuthorizer(token)

	resourceGroupName, err := getUniqueResourceGroupName(resourceGroupClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		return resourceGroupClient, resourceGroupName, err
	}

	resourceGroupParameters := resources.Group{
		Location: &sampleLocation,
	}

	fmt.Fprintf(output, "Creating Resource Group '%s'...", resourceGroupName)
	_, err = resourceGroupClient.CreateOrUpdate(resourceGroupName, resourceGroupParameters)
	if err != nil {
		fmt.Fprintln(output, "FAILED")
		fmt.Fprintf(os.Stderr, "\tError: %v\n", err)
		return resourceGroupClient, "", err
	}
	fmt.Fprintln(output, "SUCCESS")
	return resourceGroupClient, resourceGroupName, err
}

func deleteResourceGroup(client resources.GroupsClient, name string, cancel <-chan struct{}) error {
	_, err := executeWithStatus(func() (autorest.Response, error) {
		respChan, errChan := client.Delete(name, cancel)
		return <-respChan, <-errChan
	}, fmt.Sprintf("Deleting Resource Group '%s'", name))
	return err
}

func createVirtualNetwork(resourceGroupName string, cancel <-chan struct{}) (network.VirtualNetworksClient, string, error) {
	const networkName = "sampleVirtualNetwork"

	vNetParameters := network.VirtualNetwork{
		Location: &sampleLocation,
		VirtualNetworkPropertiesFormat: &network.VirtualNetworkPropertiesFormat{
			AddressSpace: &network.AddressSpace{
				AddressPrefixes: &[]string{"192.168.0.0/16"},
			},
		},
	}

	vNetClient := network.NewVirtualNetworksClient(subscriptionID)
	vNetClient.Authorizer = autorest.NewBearerAuthorizer(token)

	_, err := executeWithStatus(func() (autorest.Response, error) {
		respChan, errChan := vNetClient.CreateOrUpdate(resourceGroupName, networkName, vNetParameters, cancel)
		return (<-respChan).Response, <-errChan
	}, fmt.Sprintf("Creating Virtual Network '%s'", networkName))

	return vNetClient, networkName, err
}

func validateParameters() []error {
	const preferredGUIDFormat guid.Format = guid.FormatD
	const uuidErrTemplate = "argument '%s' was not of type Uuid as expected"

	errs := make([]error, 0)

	if "" == tenantID {
		errs = append(errs, newMissingAzureAuthError("Azure Tenant ID", azureEnvVarNameTenantID))
	} else if parsed, err := guid.Parse(tenantID); nil != err {
		errs = append(errs, fmt.Errorf(uuidErrTemplate, azureEnvVarNameTenantID))
	} else {
		tenantID = parsed.Stringf(preferredGUIDFormat)
	}

	if "" == subscriptionID {
		errs = append(errs, newMissingAzureAuthError("Azure Subscription ID", azureEnvVarNameSubscriptionID))
	} else if parsed, err := guid.Parse(subscriptionID); nil != err {
		errs = append(errs, fmt.Errorf(uuidErrTemplate, azureEnvVarNameSubscriptionID))
	} else {
		subscriptionID = parsed.Stringf(preferredGUIDFormat)
	}

	if "" == clientID {
		errs = append(errs, newMissingAzureAuthError("Azure Client ID", azureEnvVarNameClientID))
	} else if parsed, err := guid.Parse(clientID); nil != err {
		errs = append(errs, fmt.Errorf(uuidErrTemplate, azureEnvVarNameClientID))
	} else {
		clientID = parsed.Stringf(preferredGUIDFormat)
	}

	if "" == clientSecret {
		errs = append(errs, newMissingAzureAuthError("Azure Client Secret", azureEnvVarNameClientSecret))
	}

	return errs
}

func newMissingAzureAuthError(pretty string, envVarName string) error {
	formatted := fmt.Sprintf("No value was provieded to act as the %s. Set enviroment variable \"%s\"", pretty, envVarName)
	return errors.New(formatted)
}

func getUniqueResourceGroupName(client resources.GroupsClient) (string, error) {
	const resourceGroupNamePrefix = "networkSecurityGroupSample"
	groupList, err := client.List("", nil)
	if nil != err {
		return "", err
	}

	if http.StatusOK == groupList.Response.StatusCode {
		any := false
		seen := []string{}
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
	return "", fmt.Errorf("Bad response: %d", groupList.Response.StatusCode)
}

func executeWithStatus(operation func() (autorest.Response, error), message string) (response autorest.Response, err error) {
	fmt.Fprintf(output, "%s...", message)

	response, err = operation()

	if nil == err && http.StatusOK == response.StatusCode {
		fmt.Fprintln(output, "SUCCESS")
	} else {
		fmt.Fprintln(output, "FAILED")
		fmt.Fprint(os.Stderr, getFailureStatus(err, response))
	}
	return
}

func getFailureStatus(err error, response autorest.Response) string {
	retval := ""
	if response.Response != nil {
		retval += fmt.Sprintf("\tStatus Code: %d\n\tStatus: %s\n", response.StatusCode, response.Status)
	}

	if nil != err {
		retval += fmt.Sprintf("\tError: %v\n", err)
	}

	if "" == retval {
		retval = "An unknown error occurred.\n"
	}

	return retval
}
