# SecureAKSDeployment

## Overview

Repo contains an Azure CLI BASH scripts that deploys the below sample environment on Azure:

![Sample Diagram](https://github.com/CodeTheCloud-CA/SecureAKSDeployment/blob/trunk/SampleDiagram.jpg?raw=true)

Additionally there is a BASH scripts to create some test deployments and network policies on the AKS cluster deployed.

The yaml templates required for the deployment are available under ***k8s-templates*** folder.

## Dependencies & Pre-requisites

1. The scripts were tested on Ubuntu WSL with Bash version 4.4.19 installed
2. The *SecureAKSDeployment* script requires "jq" to be installed and it was tested with version 1.5.1
3. The scripts require Azure CLI to be installed and they were tested with version 2.10.0
4. The deployment was tested in Canada Central region, other regions might not have support for all resources and features required (for example Canada East does not have log analytics workspaces)
5. You require a valid Azure subcription with enough permissions (***Owner*** permission is required) and sufficient credits to deploy all components (Did not calculate exactly but if you run the script without editing, it costs around $8 CAD per hour)
6. The [***SecureAKSDeployment***](./scripts/SecureAKSDeployment.sh) script expects the existence of two AAD groups, one called ***aks-admins*** and another ***aks-readers***

## Usage
Simply run the script [***SecureAKSDeployment***](./scripts/SecureAKSDeployment.sh)

If you want to edit any names or variables you can do that before running the script.

And if you want to deploy multiple environment at the same time all you need to do is change the variable ***NAME_PREFIX***

## Post-Deployment Test Scenarios

### 1. Test Deployments to AKS Cluster

You can run the [***SampleDeployment***](./scripts/SampleDeployment.sh) script providing it the required variable values based on the infrastructure that you deployed.

Add an entry to your hosts file which maps the public IP of the Azure Firewall deployed in your environment with the hostname comprised of ${SUBDOMAIN}.${DOMAIN} which you provided to the 

Give it 1 minute for the pods to be ready and you should be able to browse to https://${SUBDOMAIN}.${DOMAIN}/productpage

This test proves that:
1. AKS is able to pull private images from ACR
2. User from approved source (your public IP), AKS cluster components and Istio are able to communicate with API server in the AKS control plane
3. DNAT rule from Azure Firewall PIP to Private frontend of ILB (which is mapped to the istio-ingressgateway) is working
4. Network Policy is allowing the services in the namespace to be exposed through Istio ingress

### 2. Test minimum TLS version set on Istio Gateway

Run the following commands after setting the values of the variables SUBDOMAIN and DOMAIN to what you used in your deployment (e.g.: DOMAIN="codethecloud.ca" SUBDOMAIN="bookinfo"):

```
# Should work
curl -k -v https://${SUBDOMAIN}.${DOMAIN}/productpage --tlsv1.3

# Should work
curl -k -v https://${SUBDOMAIN}.${DOMAIN}/productpage --tlsv1.2

# Should NOT work
curl -k -v https://${SUBDOMAIN}.${DOMAIN}/productpage --tlsv1.1

# Should NOT work
curl -k -v https://${SUBDOMAIN}.${DOMAIN}/productpage --tlsv1.0
```

### 3. Test Istio Service Mesh mTLS

Edit the *ratings-v1* deployment and add the annotation `sidecar.istio.io/inject: "false"` to the pod template and wait for the pod to be recreated without the istio-proxy sidecar.

Exec into the *ratings-v1* pod and curl to the nginx service running in the same namespace, it should **NOT** work.

Remove the annotation from the deployment so you can use the pod again in the next tests.

### 4. Test Network Policies

- Remove the ***allow-ingress-from-istio*** Network Policy and wait for 10-20 seconds then try to browse again to  https://${SUBDOMAIN}.${DOMAIN}/productpage and it should **NOT** work.

- Exec into the *ratings-v1* pod and curl to the nginx service running in the same namespace, it should work. Next, remove the ***allow-inter-namespace*** Network Policy and wait for 10-20 seconds then try to curl to the nginx service again, it should **NOT** work.

- You can also run another deployment creating a different namespace and test connectivity between the two namespaces directly, it should **NOT** work.

### 5. Test AAD Integration and K8s RBAC

Login to Azure with two different users one in the **aks-admins** group and one in the **aks-readers** group, the first one should have full control as cluster admin and second one only has ability to list pods in the default namespace

### 6. Test Azure Firewall Threat Intelligence 

Exec into any pod that has curl in it (for example ratings-v1) and curl to http://testmaliciousdomain.eastus.cloudapp.azure.com, it won't be responsive but it will show up in the Azure Firewall monitoring Workbook on Azure.

### 7. Test DNAT rule for SSH to Jumpbox

SSH to Jumpbox using the command `ssh jbuser@<Azure Firewall PIP> -p 2222` it should work.

Turn on VPN to change your public IP and try again, it should **NOT** work.

### 8. Test outbound access from Jumpbox

SSH to Jumpbox using the command `ssh jbuser@<Azure Firewall PIP> -p 2222`

Run the following commands:

```
# Should NOT work
curl -v https://www.google.com

# Should work
curl -v -k https://<AKS API Server FQDN>

# Should work
curl -v https://dev.azure.com
``` 

## License & Copyright

Created by Ahmad Harb

Copyright 2020, CodeTheCloud distributed under GPLv3 License.

See [LICENSE](LICENSE) for full details.
