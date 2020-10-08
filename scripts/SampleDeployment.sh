#!/bin/bash

read -p "Enter ACR Name: " ACR_NAME # Name of ACR deployed by the SecureAKSDeployment.sh script
export ACR_FQDN=${ACR_NAME}.azurecr.io

read -p "Enter AKS Resource Group Name: " RG_NAME # Name of RG deployed by the SecureAKSDeployment.sh script
read -p "Enter AKS Name: " AKS_NAME # Name of AKS deployed by the SecureAKSDeployment.sh script
read -p "Enter name of Namespace to use: " NAMESPACE # Name of namespace you want to use for testing, must comply with k8s namespace naming conventions
read -p "Enter name of domain to use: " DOMAIN # Example: codethecloud.ca
read -p "Enter name of subdomain to use: " SUBDOMAIN # Example: bookinfo

export NAMESPACE="${NAMESPACE,,}"
export FQDN="${SUBDOMAIN}.${DOMAIN}"

# Generate TLS Cert
echo "$(date) - Create root certificate and private key to sign your own certs"
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -subj "/O=CodeTheCloud Inc./CN=${DOMAIN}" \
    -keyout ${DOMAIN}.key -out ${DOMAIN}.crt

echo "$(date) - Create a certificate and a private key for ${FQDN}"
openssl req -out ${FQDN}.csr -newkey rsa:2048 -nodes -keyout ${FQDN}.key \
    -subj "/CN=${FQDN}/O=CodeTheCloud Inc."
openssl x509 -req -days 365 -CA ${DOMAIN}.crt -CAkey ${DOMAIN}.key \
    -set_serial 0 -in ${FQDN}.csr -out ${FQDN}.crt

echo "$(date) - Login to AKS cluster"
az aks get-credentials -g $RG_NAME -n $AKS_NAME --overwrite-existing -o none

# Delete secret if it already exists, can add check before deleting it
kubectl delete -n istio-system secret gateway-tls-credential

echo "$(date) - Create tls secret in istio-system namespace"
kubectl create -n istio-system secret tls gateway-tls-credential \
    --key=${FQDN}.key --cert=${FQDN}.crt

# Delete namespace if it already exists, can add check before deleting it
kubectl delete ns $NAMESPACE

echo "$(date) - Create demo namespace"
kubectl create ns $NAMESPACE

echo "$(date) - Label demo namespace for automatic Istio sidecar injection"
kubectl label ns $NAMESPACE istio-injection=enabled

echo "$(date) - Deploy Istio's Sample Bookinfo application in ${NAMESPACE} namespace"
cat ../k8s-templates/SampleDeployment/bookinfo.yaml | envsubst | kubectl apply -n ${NAMESPACE} -f -

echo "$(date) - Create a Secure Istio Gateway in ${NAMESPACE} namespace"
cat ../k8s-templates/SampleDeployment/secure-gateway.yaml | envsubst | kubectl apply -f -

echo "$(date) - Create nginx deployment and service in namespace ${NAMESPACE}"
kubectl create deployment -n $NAMESPACE --image ${ACR_FQDN}/library/nginx:1.14.2 nginx
kubectl expose deployment -n $NAMESPACE nginx --port=80 --type=ClusterIP
# Use Annotation sidecar.istio.io/inject: "false" to disable sidecar injection

echo "$(date) - Apply Network policy to allow ingress from istio-system to demo namespace ${NAMESPACE}"
cat ../k8s-templates/NetworkPolicy/03-allow-ingress-from-istio.yaml | envsubst | kubectl apply -f -
echo "$(date) - Apply Network policy to allow inter-namespace ingress in demo namespace ${NAMESPACE}"
cat ../k8s-templates/NetworkPolicy/02-allow-inter-namespace.yaml | envsubst | kubectl apply -f -
echo "$(date) - Apply Network policy for catch all deny all ingress in demo namespace ${NAMESPACE}"
cat ../k8s-templates/NetworkPolicy/01-catch-all-deny-ingress.yaml | envsubst | kubectl apply -f -

# Test Azure Firewall Intl using testmaliciousdomain.eastus.cloudapp.azure.com

# Cleanup certs and keys created
rm -f *.crt *.key *.csr