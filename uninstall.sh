#!/bin/bash

RED='\033[0;31m'
NC='\033[0m' # No Color

function uninstall() {
  namespace=$1

  echo -e "${RED}Removing finalizers from PolicyServer${NC}"
  kubectl get policyservers.policies.kubewarden.io --no-headers | \
    cut -d " " -f 1 | \
    xargs -n 1 kubectl patch policyservers.policies.kubewarden.io -p '{"metadata":{"finalizers":null}}' --type=merge

  echo -e "${RED}Removing finalizers from ClusterAdmissionPolicy${NC}"
  kubectl get clusteradmissionpolicies.policies.kubewarden.io --no-headers | \
    cut -d " " -f 1 | \
    xargs -n 1 kubectl patch clusteradmissionpolicies.policies.kubewarden.io -p '{"metadata":{"finalizers":null}}' --type=merge

  echo -e "${RED}Removing Validating Webhook Configuration for Kubewarden Controller${NC}"
  kubectl delete validatingwebhookconfigurations.admissionregistration.k8s.io  kubewarden-controller-validating-webhook-configuration

  echo -e "${RED}Removing Mutating Webhook Configuration for Kubewarden Controller${NC}"
  kubectl delete mutatingwebhookconfigurations.admissionregistration.k8s.io kubewarden-controller-mutating-webhook-configuration

  echo -e "${RED}Removing Validating Webhook Configuration created by the Kubewarden Controller${NC}"
  kubectl delete validatingwebhookconfigurations.admissionregistration.k8s.io  -l kubewarden=true

  echo -e "${RED}Removing Mutating Webhook Configuration created by the Kubewarden Controller${NC}"
  kubectl delete mutatingwebhookconfigurations.admissionregistration.k8s.io  -l kubewarden=true

  echo -e "${RED}Removing Kubewarden namespace '$namespace'${NC}"
  kubectl delete namespace $namespace

  echo -e "${RED}Removing Custom Resource Definitions and their instances${NC}"
  kubectl delete customresourcedefinitions.apiextensions.k8s.io policyservers.policies.kubewarden.io
  kubectl delete customresourcedefinitions.apiextensions.k8s.io clusteradmissionpolicies.policies.kubewarden.io
}

function print_help() {
  echo "Last resort script that removes all Kubewarden resources from a cluster."
  echo "The recommended uninstallation method is by using 'helm uninstall'."
  echo ""
  echo "Note well: a working 'kubectl' must be available."
  echo ""
  echo "USAGE:"
  echo "  uninstall.sh [FLAGS]"
  echo ""
  echo "FLAGS:"
  echo "  -h, --help                  Print help information"
  echo "  -n, --namespace <namespace> Specify the namespace where Kubewarden was deployed"
  echo "  -f, --force                 Do not ask for confirmation before performing removals"
}

# getopt handling insipired by https://stackoverflow.com/a/21210966

getopt --test > /dev/null
if [[ $? -ne 4 ]]; then
  echo 'I’m sorry, `getopt --test` failed in this environment.'
  exit 1
fi

OPTIONS=fhn:
LONGOPTS=force,help,namespace:

PARSED=$(getopt --options=$OPTIONS --longoptions=$LONGOPTS --name "$0" -- "$@")
if [[ $? -ne 0 ]]; then
  # e.g. return value is 1
  #  then getopt has complained about wrong arguments to stdout
  exit 2
fi
# read getopt’s output this way to handle the quoting right:
eval set -- "$PARSED"

force=false namespace=kubewarden
while true; do
  case "$1" in
    -n|--namespace)
      namespace="$2"
      shift 2
      ;;
    -f|--force)
      force=true
      shift 1
      ;;
    -h|--help)
      print_help
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Wrong usage"
      exit 3
      ;;
  esac
done

if [ "$force" = false ]; then
  echo -e "${RED}WARNING:${NC} this script will remove all the Kubewarden resources from your cluster"
  read -p "Continue (y/n)? " choice
  case "$choice" in
    y|Y ) force=true;;
    n|N ) exit 0;;
    * ) echo "Invalid option"; exit 1;
  esac
fi

# it means the user either answered "yes" or used the "--force" flag
uninstall $namespace
