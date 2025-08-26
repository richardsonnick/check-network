#!/bin/bash

# A script to build, deploy, and run the OpenShift scanner application.
#
# Usage: ./deploy_and_scan.sh
#
# This script will create the pod_ips.txt file in the current directory.

# --- Configuration ---
APP_NAME="scanner-app"

# --- Functions ---

# Function to print a formatted header
print_header() {
    echo "========================================================================"
    echo "=> $1"
    echo "========================================================================"
}

# Function to check for errors and exit if one occurs
check_error() {
    # $? is the exit code of the last command
    if [ $? -ne 0 ]; then
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        echo "An error occurred during: '$1'"
        echo "Exiting script."
        echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        exit 1
    fi
}

# Function to clean up existing resources before starting
cleanup() {
    print_header "Step 0: Cleaning Up Previous Deployments"
    echo "--> Deleting existing resources for '$APP_NAME' (if they exist)..."
    oc delete deployment "$APP_NAME" --ignore-not-found=true
    oc delete service "$APP_NAME" --ignore-not-found=true
    oc delete buildconfig "$APP_NAME" --ignore-not-found=true
    oc delete imagestream "$APP_NAME" --ignore-not-found=true
    echo "Cleanup complete."
}


# --- Main Script ---

# 0. Clean up any previous runs
cleanup

# 1. Build and Deploy the Scanner
print_header "Step 1: Building and Deploying the Scanner"

echo "--> Creating new build configuration..."
oc new-build --name="$APP_NAME" --strategy=docker --binary
check_error "oc new-build"

echo "--> Starting the build (this may take a few minutes)..."
oc start-build "$APP_NAME" --from-dir=. --follow
check_error "oc start-build"

echo "--> Deploying the new application..."
oc new-app "$APP_NAME"
check_error "oc new-app"

echo "--> Waiting for the deployment to become ready..."
oc wait --for=condition=available --timeout=180s "deployment/$APP_NAME"
check_error "oc wait for deployment"

echo "Scanner pod is now running."

# 2. Prepare and Run the Scan
print_header "Step 2: Preparing and Running the Scan"

echo "--> Getting the current scanner pod name..."
POD_NAME=$(oc get pods -l "deployment=$APP_NAME" -o jsonpath='{.items[0].metadata.name}')
check_error "Get scanner pod name"
echo "    Pod Name: $POD_NAME"

echo "--> Executing the scan in the background inside the pod..."
oc exec "$POD_NAME" -- bash -c "cd /app && nohup ./check-network -j 12 --all-pods --json results.json &"
check_error "oc exec to run scan"

print_header "Scan Started Successfully!"
echo "The scan is now running in the background inside the pod: $POD_NAME"
echo "You can monitor its progress by running:"
echo "oc exec -it $POD_NAME -- tail -f /tmp/nohup.out"
echo ""
echo "When complete, the results will be in '/app/results.json' inside the pod."
echo "You can copy the results back with:"
echo "oc cp ${POD_NAME}:/app/results.json ./results.json"


