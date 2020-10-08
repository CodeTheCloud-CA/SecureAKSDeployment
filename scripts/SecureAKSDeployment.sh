#!/bin/bash

echo "$(date) - Script Starting"
# Set General Variables
NAME_PREFIX="secure"
NAME_PREFIX="${NAME_PREFIX,,}"
LOCATION="canadacentral"
RG_NAME="${NAME_PREFIX}-demo-rg"

# Set Azure Log Analytics Workspace Details
ALA_NAME="${NAME_PREFIX}-ala-workspace"
ALA_RETENTION=90
ALA_SKU=PerGB2018

# Set ACR Variables
ACR_NAME="${NAME_PREFIX}acr$(date +%H%M%S)"
ACR_FQDN="${ACR_NAME}.azurecr.io"
ACR_SKU="Premium" # Should use premium so we can enable resource firewall on ACR
ISTIO_DOCKER_IMAGES=("docker.io/istio/citadel:1.4.10" "docker.io/istio/galley:1.4.10" "docker.io/istio/mixer:1.4.10" \
    "docker.io/istio/node-agent-k8s:1.4.10" "docker.io/istio/pilot:1.4.10" "docker.io/istio/proxyv2:1.4.10" \
    "docker.io/istio/sidecar_injector:1.4.10" "docker.io/jaegertracing/all-in-one:1.14" "docker.io/prom/prometheus:v2.12.0" \
    "docker.io/grafana/grafana:6.4.3" "quay.io/kiali/kiali:v1.15" "docker.io/istio/examples-bookinfo-details-v1:1.15.1" \
    "docker.io/istio/examples-bookinfo-ratings-v1:1.15.1" "docker.io/istio/examples-bookinfo-reviews-v1:1.15.1" \
    "docker.io/istio/examples-bookinfo-productpage-v1:1.15.1" "docker.io/library/nginx:1.14.2")

# Set AKS Variables
AZURE_NETWORK_PLUGIN=azure # Keep it at Azure CNI, this script will not work with Kubenet as it needs a different approach
AZURE_NETWORK_POLICY=calico # Required for the kubernetes network policies
AKS_NAME="${NAME_PREFIX}aks"
AKS_DNS_NAME_PREFIX="${AKS_NAME,,}"
AKS_NODE_SIZE="Standard_D4s_v3"
AKS_NODE_OSDISK_SIZE=256
AKS_MIN_NODE_COUNT=3
AKS_MAX_NODE_COUNT=5
AKS_DOCKER_BRIDGE_CIDR=172.17.0.1/16
AKS_SERVICE_CIDR=10.240.0.0/16
AKS_DNS_SERVICE_IP=$(echo $AKS_SERVICE_CIDR | awk -F"." '{ print $1"."$2"."$3"."10 }')
AKS_ADMINS_AAD_GROUP_NAME="aks-admins"
AKS_READERS_AAD_GROUP_NAME="aks-readers"
# This will not work if you run the script using a service principal 
# because they do not have access to Azure AD by default and you would need to grant them the permission
AKS_ADMINS_AAD_GROUP_OID=$(az ad group show --group "$AKS_ADMINS_AAD_GROUP_NAME" -o tsv --query objectId)
AKS_READERS_AAD_GROUP_OID=$(az ad group show --group "$AKS_READERS_AAD_GROUP_NAME" -o tsv --query objectId)
# Picks up latest GA version of AKS available in the region
AKS_VERSION=$(az aks get-versions -l $LOCATION -o table | awk '{ print $1 }' | tail -n+3 | grep -iv "preview" | head -1)
# Set Grafana and Kiali credentials
GRAFANA_USERNAME=$(echo "grafana" | base64)
GRAFANA_PASSWORD=$(cat /dev/urandom | tr -cd "[:alnum:]" | head -c 16 | base64)
KIALI_USERNAME=$(echo "kiali" | base64)
KIALI_PASSWORD=$(cat /dev/urandom | tr -cd "[:alnum:]" | head -c 16 | base64)

# Set Network and Azure Firewall Variables
NETWORK_RG_NAME="${NAME_PREFIX}-network-rg"
VNET_NAME="${NAME_PREFIX}-vnet"
VNET_CIDR=10.0.0.0/16
AKS_SUBNET_NAME="${NAME_PREFIX}-aks-subnet"
AKS_SUBNET_CIDR=10.0.0.0/20 # Usable Hosts range 10.1.0.4 - 10.1.15.254
JB_SUBNET_NAME="${NAME_PREFIX}-jbox-subnet"
JB_SUBNET_CIDR=10.0.16.0/24 # Usable Hosts range 10.1.16.4 - 10.1.16.254
FW_SUBNET_NAME="AzureFirewallSubnet" # DO NOT CHANGE - This is a requirement for the subnet name of Azure Firewall.
FW_SUBNET_CIDR=10.0.17.0/26 # Azure Firewall requires a maximum subnet size of /26 to support its scaling when required
FW_PIP_NAME="${NAME_PREFIX}-fw-pip"
FW_IPCONFIG_NAME="${NAME_PREFIX}-fw-ipconfig"
FW_RT_NAME="${NAME_PREFIX}-fw-rt"
FW_ROUTE_NAME="${NAME_PREFIX}-fw-route"
FW_INTERNET_ROUTE_NAME="${NAME_PREFIX}-fw-internet-route"
FW_NAME="${NAME_PREFIX}fw"

# Set Jumpbox VM details
JB_VM_NAME=${NAME_PREFIX}jb001
JB_NIC_NAME=${JB_VM_NAME}-nic001
JB_VM_IMAGE="OpenLogic:CentOS:8_2:latest"
JB_VM_SIZE="Standard_D2s_v3"
JB_VM_ADMIN_USERNAME="jbuser"

echo "$(date) - Create Network Resource Group"
az group create --name $NETWORK_RG_NAME --location $LOCATION -o none

echo "$(date) - Create Virtual Network"
az network vnet create --resource-group $NETWORK_RG_NAME --name $VNET_NAME \
    --location $LOCATION --address-prefixes $VNET_CIDR -o none

VNET_ID=$(az network vnet show -g $NETWORK_RG_NAME --name $VNET_NAME --query id -o tsv)

# Get list of all available service endpoints
SERVICE_ENDPOINTS=$(az network vnet list-endpoint-services -l $LOCATION -o table | tail -n+3 | tr '\n' ' ')

# Subnet level NSGs aren't required on the AzureFirewallSubnet, and are disabled to ensure no service interruption
echo "$(date) - Create Azure Firewall Subnet"
az network vnet subnet create --resource-group $NETWORK_RG_NAME --vnet-name $VNET_NAME \
    --name $FW_SUBNET_NAME --address-prefix $FW_SUBNET_CIDR --service-endpoints $SERVICE_ENDPOINTS -o none

# Created with default rules only, advised to be updated with specific rules
echo "$(date) - Create NSG for AKS Subnet"

az network nsg create --name "${AKS_SUBNET_NAME}-nsg" --resource-group $NETWORK_RG_NAME --location $LOCATION -o none

AKS_NSG_ID=$(az network nsg show --name "${AKS_SUBNET_NAME}-nsg" --resource-group $NETWORK_RG_NAME -o tsv --query id)

echo "$(date) - Create AKS Subnet"
az network vnet subnet create --resource-group $NETWORK_RG_NAME --vnet-name $VNET_NAME \
    --name $AKS_SUBNET_NAME --address-prefix $AKS_SUBNET_CIDR --nsg $AKS_NSG_ID -o none

# Created with default rules only, advised to be updated with specific rules
echo "$(date) - Create NSG for Jumpbox Subnet"

az network nsg create --name "${JB_SUBNET_NAME}-nsg" --resource-group $NETWORK_RG_NAME --location $LOCATION -o none

JB_NSG_ID=$(az network nsg show --name "${JB_SUBNET_NAME}-nsg" --resource-group $NETWORK_RG_NAME -o tsv --query id)

echo "$(date) - Create Jumpbox Subnet"
az network vnet subnet create --resource-group $NETWORK_RG_NAME --vnet-name $VNET_NAME \
    --name $JB_SUBNET_NAME --address-prefix $JB_SUBNET_CIDR --nsg $JB_NSG_ID -o none

echo "$(date) - Create Azure Firewall Public IP"
az network public-ip create -g $NETWORK_RG_NAME -n $FW_PIP_NAME -l $LOCATION --sku "Standard" -o none

echo "$(date) - Create Azure Firewall CLI Extension"
az extension add --name azure-firewall

echo "$(date) - Create Azure Firewall"
az network firewall create -g $NETWORK_RG_NAME -n $FW_NAME -l $LOCATION --enable-dns-proxy true -o none

FW_ID=$(az network firewall show -g $NETWORK_RG_NAME -n $FW_NAME -o tsv --query id)

echo "$(date) - Configure Azure Firewall IP Config"
az network firewall ip-config create -g $NETWORK_RG_NAME -f $FW_NAME -n $FW_IPCONFIG_NAME \
  --public-ip-address $FW_PIP_NAME --vnet-name $VNET_NAME -o none

echo "$(date) - Get Azure Firewall Private & Public IPs to use when creating rules"
FW_PUBLIC_IP=$(az network public-ip show -g $NETWORK_RG_NAME -n $FW_PIP_NAME --query "ipAddress" -o tsv)
FW_PRIVATE_IP=$(az network firewall show -g $NETWORK_RG_NAME -n $FW_NAME --query "ipConfigurations[0].privateIpAddress" -o tsv)

echo "$(date) - Create Route Table to add UDRs for routing through Azure Firewall"
az network route-table create -g $NETWORK_RG_NAME -l $LOCATION --name $FW_RT_NAME -o none

echo "$(date) - Create UDR to route everything through Azure Firewall as an NVA"
az network route-table route create -g $NETWORK_RG_NAME --name $FW_ROUTE_NAME \
  --route-table-name $FW_RT_NAME --address-prefix 0.0.0.0/0 --next-hop-type VirtualAppliance \
  --next-hop-ip-address $FW_PRIVATE_IP -o none

# Not applicable to our architecture but would be required if public LB is used for AKS ingress 
# Reference in MS docs about this issue https://docs.microsoft.com/th-th/azure/firewall/integrate-lb#fix-the-routing-issue
echo "$(date) - Create UDR to fix Asymmetric Routing issues"
az network route-table route create -g $NETWORK_RG_NAME --name $FW_INTERNET_ROUTE_NAME \
  --route-table-name $FW_RT_NAME --address-prefix $FW_PUBLIC_IP/32 --next-hop-type Internet -o none

echo "$(date) - Associate Route Table with AKS Subnet"
az network vnet subnet update -g $NETWORK_RG_NAME --vnet-name $VNET_NAME --name $AKS_SUBNET_NAME --route-table $FW_RT_NAME -o none

echo "$(date) - Associate Route Table with Jumpbox Subnet"
az network vnet subnet update -g $NETWORK_RG_NAME --vnet-name $VNET_NAME --name $JB_SUBNET_NAME --route-table $FW_RT_NAME -o none

# Retrieve your Public IP address
MY_CURRENT_PIP=$(curl -s ifconfig.me)

# Retrieve AKS and FW Subnet IDs
AKS_SUBNET_ID=$(az network vnet subnet show -g $NETWORK_RG_NAME --vnet-name $VNET_NAME --name $AKS_SUBNET_NAME --query id -o tsv)
FW_SUBNET_ID=$(az network vnet subnet show -g $NETWORK_RG_NAME --vnet-name $VNET_NAME --name $FW_SUBNET_NAME --query id -o tsv)

# Retrieve AAD Tenant ID and Subscription ID
AAD_TENANT_ID=$(az account show -o tsv --query tenantId)
SUBSCRIPTION_ID=$(az account show -o tsv --query id)

echo "$(date) - Create Demo Resource Group"
az group create --name $RG_NAME --location $LOCATION -o none

echo "$(date) - Create Azure Log Analytics Workspace"

az monitor log-analytics workspace create -g $RG_NAME -n $ALA_NAME -l $LOCATION --sku $ALA_SKU --retention-time $ALA_RETENTION -o none

ALA_ID=$(az monitor log-analytics workspace show -g $RG_NAME -n $ALA_NAME -o tsv --query id)

echo "$(date) - Create ACR"
az acr create --name $ACR_NAME --resource-group $RG_NAME --location $LOCATION --sku $ACR_SKU \
  --admin-enabled false --default-action Deny -o none

ACR_ID=$(az acr show -g $RG_NAME --name $ACR_NAME --query id -o tsv)

echo "$(date) - Enable Dedicated Data Endpoints on ACR"
az acr update --name $ACR_NAME --resource-group $RG_NAME --data-endpoint-enabled -o none

ACR_DATA_ENDPOINT="${ACR_NAME}.${LOCATION}.data.azurecr.io"

echo "$(date) - Allow my public IP Address to access the ACR"
az acr network-rule add --name $ACR_NAME --resource-group $RG_NAME --ip-address ${MY_CURRENT_PIP}/32 -o none

echo "$(date) - Allow Azure Firewall subnet to access the ACR"
az acr network-rule add --name $ACR_NAME --resource-group $RG_NAME --subnet $FW_SUBNET_ID -o none

echo "$(date) - Add Azure Firewall Application Rule required for AKS to access ACR"
az network firewall application-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-ar" \
  -n "aks-access-acr-${ACR_NAME}" --source-addresses $AKS_SUBNET_CIDR --protocols 'http=80' 'https=443' \
  --target-fqdns "${ACR_FQDN}" "${ACR_DATA_ENDPOINT}" --action allow --priority 1000 -o none

echo "$(date) - Create Service Principal for AKS Cluster"
AKS_SP_DETAILS=$(az ad sp create-for-rbac -n "${AKS_NAME}-sp" --skip-assignment)
AKS_SP_APP_ID=$(echo $AKS_SP_DETAILS | jq -r ".appId")
AKS_SP_PASSWORD=$(echo $AKS_SP_DETAILS | jq -r ".password")

sleep 5

echo "$(date) - Assign AKS Cluster Service Principal Network Contributor role on VNET"
az role assignment create --assignee $AKS_SP_APP_ID --scope $VNET_ID --role "Network Contributor" -o none

echo "$(date) - Assign AKS Cluster Service Principal acrpull role on ACR"
az role assignment create --assignee $AKS_SP_APP_ID --scope $ACR_ID --role "acrpull" -o none

echo "$(date) - Import container images required for Istio deployment and demo into ACR"
for IMAGE_NAME in "${ISTIO_DOCKER_IMAGES[@]}"
do
  ACR_IMAGE_NAME=$(echo "${IMAGE_NAME}" | sed 's/^[^\/]*\///g')
  az acr import -n $ACR_NAME -g $RG_NAME --source $IMAGE_NAME --image "${ACR_IMAGE_NAME}" -o none
done

echo "$(date) - Add Azure Firewall Application Rule required for AKS functionality (uses AzureKubernetesService service tag)"

az network firewall application-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-ar" \
  -n 'aks-service-tag' --source-addresses $AKS_SUBNET_CIDR --protocols 'http=80' 'https=443' --fqdn-tags "AzureKubernetesService" -o none
  
echo "$(date) - Create AKS Cluster"
az aks create -g $RG_NAME -n $AKS_NAME -l $LOCATION --dns-name-prefix $AKS_DNS_NAME_PREFIX --no-ssh-key \
  --kubernetes-version $AKS_VERSION --enable-addons monitoring --workspace-resource-id $ALA_ID --node-vm-size $AKS_NODE_SIZE \
  --node-osdisk-size $AKS_NODE_OSDISK_SIZE --vm-set-type VirtualMachineScaleSets --enable-cluster-autoscaler \
  --min-count $AKS_MIN_NODE_COUNT --max-count $AKS_MAX_NODE_COUNT --outbound-type userDefinedRouting \
  --network-plugin $AZURE_NETWORK_PLUGIN --network-policy $AZURE_NETWORK_POLICY --service-cidr $AKS_SERVICE_CIDR \
  --dns-service-ip $AKS_DNS_SERVICE_IP --docker-bridge-address $AKS_DOCKER_BRIDGE_CIDR --attach-acr "$ACR_ID" \
  --vnet-subnet-id $AKS_SUBNET_ID --api-server-authorized-ip-ranges ${FW_PUBLIC_IP}/32,${MY_CURRENT_PIP}/32 \
  --service-principal $AKS_SP_APP_ID --client-secret $AKS_SP_PASSWORD --skip-subnet-role-assignment \
  --enable-aad --aad-admin-group-object-ids $AKS_ADMINS_AAD_GROUP_OID --aad-tenant-id $AAD_TENANT_ID -o none #\ 
  #--uptime-sla #TODO: Enable later - Should be enabled for production workloads

AKS_ID=$(az aks show -g $RG_NAME -n $AKS_NAME -o tsv --query id)

echo "$(date) - Assign AD Groups Azure Kubernetes Service Cluster User Role on AKS"
az role assignment create --assignee-object-id $AKS_ADMINS_AAD_GROUP_OID --scope $AKS_ID \
  --role "Azure Kubernetes Service Cluster User Role" -o none
az role assignment create --assignee-object-id $AKS_READERS_AAD_GROUP_OID --scope $AKS_ID \
  --role "Azure Kubernetes Service Cluster User Role" -o none

echo "$(date) - Enable Diagnostic Logs on AKS cluster"
az monitor diagnostic-settings create --resource $AKS_ID \
--name "aks-ala-diag-logs" --workspace $ALA_ID -o none \
--logs '[
     {
       "category": "kube-audit",
       "enabled": true
     },
     {
       "category": "kube-audit-admin",
       "enabled": true
     },
     {
       "category": "guard",
       "enabled": true
     }
   ]'

echo "$(date) - Enable Diagnostic Logs on Azure Firewall"
az monitor diagnostic-settings create --resource $FW_ID -o none \
--name "aks-ala-diag-logs" --workspace $ALA_ID \
--logs '[
     {
       "category": "AzureFirewallApplicationRule",
       "enabled": true
     },
     {
       "category": "AzureFirewallNetworkRule",
       "enabled": true
     },
     {
       "category": "AzureFirewallDnsProxy",
       "enabled": true
     }
   ]' --metrics '[
     {
       "category": "AllMetrics",
       "enabled": true
     }
   ]'

# Azure Docs regarding Azure Firewall workbook https://docs.microsoft.com/en-us/azure/firewall/firewall-workbook
echo "$(date) - Deploy Azure Firewall Workbook"
az deployment group create -g $NETWORK_RG_NAME -n "$RG_NAME-${RANDOM}-deployment" --template-uri https://raw.githubusercontent.com/Azure/Azure-Network-Security/master/Azure%20Firewall/Azure%20Monitor%20Workbook/Azure%20Firewall_ARM.json \
  --mode Incremental --parameters DiagnosticsWorkspaceName=$ALA_NAME DiagnosticsWorkspaceSubscription=$SUBSCRIPTION_ID \
  DiagnosticsWorkspaceResourceGroup=$RG_NAME -o none

echo "$(date) - Login to AKS Cluster as Cluster-Admin (Bypass AAD for now)"
az aks get-credentials -g $RG_NAME -n $AKS_NAME --admin --overwrite-existing -o none

# Retrieve AKS API Server IP
AKS_API_SERVER_IP=$(kubectl get endpoints -o=jsonpath='{.items[?(@.metadata.name == "kubernetes")].subsets[].addresses[].ip}' -A)

echo "$(date) - Add Azure Firewall Network Rule required for AKS Nodes secure tunnel connection (UDP) to the Control plane"
az network firewall network-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-nr" \
  -n 'aks-control-plane-secure-tunnel-udp' --protocols 'UDP' --source-addresses $AKS_SUBNET_CIDR \
  --destination-addresses "$AKS_API_SERVER_IP" --destination-ports 1194 --action allow --priority 1000 -o none

echo "$(date) - Add Azure Firewall Network Rule required for AKS Nodes secure tunnel connection (TCP) to the Control plane"
az network firewall network-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-nr" \
  -n 'aks-control-plane-secure-tunnel-tcp' --protocols 'TCP' --source-addresses $AKS_SUBNET_CIDR \
  --destination-addresses "$AKS_API_SERVER_IP" --destination-ports 9000 -o none

echo "$(date) - Add Azure Firewall Network Rule required for AKS workloads HTTPS connection the AKS API server"
az network firewall network-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-nr" \
  --n "aks-api-server-https" --protocols 'TCP' --source-addresses $AKS_SUBNET_CIDR $JB_SUBNET_CIDR \
  --destination-addresses "$AKS_API_SERVER_IP" --destination-ports 443 -o none

echo "$(date) - Add Azure Firewall Network Rule required for AKS clusters using Azure Monitor"
az network firewall network-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-nr" \
  -n 'aks-azure-monitor' --protocols 'TCP' --source-addresses $AKS_SUBNET_CIDR --destination-addresses "AzureMonitor" \
  --destination-ports 443 -o none

echo "$(date) - Add Azure Firewall Network Rule required for AKS Ubuntu nodes connection to NTP servers"
az network firewall network-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-nr" \
  -n 'ubuntu-ntp' --protocols 'UDP' --source-addresses $AKS_SUBNET_CIDR --destination-fqdns 'ntp.ubuntu.com' \
  --destination-ports 123 -o none

echo "$(date) - Add Azure Firewall Application Rule required for AKS clusters using Azure Monitor"
az network firewall application-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-ar" \
  -n 'aks-azure-monitor' --source-addresses $AKS_SUBNET_CIDR --protocols 'https=443' \
  --target-fqdns "dc.services.visualstudio.com" "*.ods.opinsights.azure.com" "*.oms.opinsights.azure.com" "*.monitoring.azure.com" -o none

echo "$(date) - Add Azure Firewall Application Rule required for AKS Ubuntu nodes security patches and updates"
az network firewall application-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-ar" \
  -n 'aks-ubuntu-node-patching' --source-addresses $AKS_SUBNET_CIDR --protocols 'http=80' 'https=443' \
  --target-fqdns "security.ubuntu.com" "azure.archive.ubuntu.com" "changelogs.ubuntu.com" -o none

# Note: Other rules would be required if enabling more features in AKS such as Dev Spaces or Azure Policy for AKS

#TODO: Removed rule to allow public endpoints
#echo "$(date) - Add Azure Firewall Application Rule required to allow public container registries"
#az network firewall application-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "aks-public-registries-fw-ar" \
#  -n "allow-public-container-registries" --protocols 'http=80' 'https=443' --source-addresses $AKS_SUBNET_CIDR --action allow \
#  --target-fqdns "*auth.docker.io" "*cloudflare.docker.io" "*cloudflare.docker.com" "*registry-1.docker.io" "*quay.io" \
#  --priority 1010 -o none

echo "$(date) - Create istio-system namespace"

kubectl create ns istio-system

echo "$(date) - Create Kuberentes Secret for Istio's Grafana credentials"

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: grafana
  namespace: istio-system
  labels:
    app: grafana
type: Opaque
data:
  username: $GRAFANA_USERNAME
  passphrase: $GRAFANA_PASSWORD
EOF

echo "$(date) - Create Kuberentes Secret for Istio's Kiali credentials"

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: kiali
  namespace: istio-system
  labels:
    app: kiali
type: Opaque
data:
  username: $KIALI_USERNAME
  passphrase: $KIALI_PASSWORD
EOF

echo "$(date) - Download Istio package"
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.4.10 sh -

echo "$(date) - Deploy Istio in the AKS Cluster with customizations"
istio-1.4.10/bin/istioctl manifest apply -f CustomIstioProfile.yaml --set hub="${ACR_FQDN}/istio"

# Cleanup downloaded istio package
rm -rf istio-1.4.10

echo "$(date) - Patch image references for Istio monitoring stack to use private ACR images"

ACR_KIALI_IMAGE="${ACR_FQDN}/kiali/kiali:v1.15"
ACR_GRAFANA_IMAGE="${ACR_FQDN}/grafana/grafana:6.4.3"
ACR_JAEGER_IMAGE="${ACR_FQDN}/jaegertracing/all-in-one:1.14"
ACR_PROMETHEUS_IMAGE="${ACR_FQDN}/prom/prometheus:v2.12.0"

kubectl get -n istio-system deployments kiali -o json | jq --arg acr_kiali_image "$ACR_KIALI_IMAGE" \
  '.spec.template.spec.containers[0].image = $acr_kiali_image' | kubectl replace -f -

kubectl get -n istio-system deployments grafana -o json | jq --arg acr_grafana_image "$ACR_GRAFANA_IMAGE" \
  '.spec.template.spec.containers[0].image = $acr_grafana_image' | kubectl replace -f -

kubectl get -n istio-system deployments istio-tracing -o json | jq --arg acr_jaeger_image "$ACR_JAEGER_IMAGE" \
  '.spec.template.spec.containers[0].image = $acr_jaeger_image' | kubectl replace -f -

kubectl get -n istio-system deployments prometheus -o json | jq --arg acr_prom_image "$ACR_PROMETHEUS_IMAGE" \
  '.spec.template.spec.containers[0].image = $acr_prom_image' | kubectl replace -f -

echo "$(date) - Add HTTP/HTTPS DNAT Rules to Azure Firewall for AKS Istio Ingress Private Loadbalancer frontend IP"
ISTIO_INGRESS_LB_IP=$(kubectl get svc -n istio-system istio-ingressgateway -o=jsonpath='{.status.loadBalancer.ingress[0].ip}')
while [ -z $ISTIO_INGRESS_LB_IP ]
do
  ISTIO_INGRESS_LB_IP=$(kubectl get svc -n istio-system istio-ingressgateway -o=jsonpath='{.status.loadBalancer.ingress[0].ip}')
  sleep 5
done

az network firewall nat-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-dnat" \
  -n "${AKS_NAME}-istio-ingress-http-dnat-rule"  --destination-addresses $FW_PUBLIC_IP --destination-ports 80 --protocols 'TCP' \
  --source-addresses '*' --action 'Dnat' --priority 1000 --translated-port 80 --translated-address $ISTIO_INGRESS_LB_IP -o none

az network firewall nat-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${AKS_NAME}-fw-dnat" \
  -n "${AKS_NAME}-istio-ingress-https-dnat-rule"  --destination-addresses $FW_PUBLIC_IP --destination-ports 443 --protocols 'TCP' \
  --source-addresses '*' --translated-port 443 --translated-address $ISTIO_INGRESS_LB_IP -o none

echo "$(date) - Create pod-reader role in default namespace of AKS cluster"
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "watch", "list"]
EOF

echo "$(date) - Create pod-reader rolebinding in default namespace of AKS cluster for AKS Readers AAD Group"
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
 name: pod-reader-${AKS_READERS_AAD_GROUP_NAME}
 namespace: default
roleRef:
 apiGroup: rbac.authorization.k8s.io
 kind: Role
 name: pod-reader
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: "$AKS_READERS_AAD_GROUP_OID"
EOF

echo "$(date) - Create Jumpbox"

echo "$(date) - Create Jumpbox NIC"
JB_SUBNET_ID=$(az network vnet subnet show -g $NETWORK_RG_NAME -n $JB_SUBNET_NAME --vnet-name $VNET_NAME -o tsv --query id)
az network nic create -g $RG_NAME -n $JB_NIC_NAME --subnet $JB_SUBNET_ID --location $LOCATION -o none
JB_NIC_ID=$(az network nic show -g $RG_NAME -n $JB_NIC_NAME -o tsv --query id)

echo "$(date) - Create Jumpbox Virtual Machine"
az vm create --location $LOCATION -g $RG_NAME -n $JB_VM_NAME --image $JB_VM_IMAGE \
  --size $JB_VM_SIZE --nics $JB_NIC_ID --admin-username $JB_VM_ADMIN_USERNAME --generate-ssh-keys -o none

echo "$(date) - Add SSH DNAT Rule to Azure Firewall for Jumpbox VM"
JB_VM_IP_ADDRESS=$(az vm show -g $RG_NAME -n $JB_VM_NAME -d --query privateIps -o tsv)

az network firewall nat-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "${JB_VM_NAME}-fw-dnat" \
  -n "${JB_VM_NAME}-ssh-dnat-rule"  --destination-addresses $FW_PUBLIC_IP --destination-ports 2222 --protocols 'TCP' \
  --source-addresses "$MY_CURRENT_PIP" --action 'Dnat' --priority 1010 --translated-port 22 \
  --translated-address $JB_VM_IP_ADDRESS -o none

echo "$(date) - You should be able to SSH to the Jumpbox VM '$JB_VM_NAME' using the address:port '${FW_PUBLIC_IP}:2222'"

echo "$(date) - Add Azure Firewall Application Rule required to allow Jumpbox subnet to reach dev.azure.com"
az network firewall application-rule create -g $NETWORK_RG_NAME -f $FW_NAME --collection-name "jumpbox-fw-ar" \
  -n "allow-azure-devops" --protocols 'http=80' 'https=443' --source-addresses $JB_SUBNET_CIDR --action allow \
  --target-fqdns "dev.azure.com" --priority 1020 -o none

echo "$(date) - Script Complete"