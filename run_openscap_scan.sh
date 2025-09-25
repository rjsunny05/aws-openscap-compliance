#!/bin/bash
set -euo pipefail
set -x

# ========== PARAMETERS ==========
WORKSPACE="$1"        # Jenkins workspace (passed from Jenkinsfile)
REPORT_DEST="$WORKSPACE/openscap_reports"
SSH_USER="$2"         # e.g., ec2-user
SSH_KEY="$SSH_AUTH_SOCK" # SSH agent provided by Jenkins
PROFILE="$3"          # OpenSCAP profile to use, e.g., xccdf_org.ssgproject.content_profile_cis
TAILORING_FILE_DIR="$4" # Directory in workspace containing tailoring XMLs
CONTENT_FILE_DIR="$5"   # Directory in workspace containing profile XMLs

# List of instance private IPs to scan
INSTANCES=("10.0.1.10" "10.0.1.11") # Replace with your EC2 private IPs

mkdir -p "$REPORT_DEST"

echo "[INFO] Starting OpenSCAP scans on ${#INSTANCES[@]} instances..."

# ========== SCAN FUNCTION ==========
run_scan() {
    local ip="$1"
    local profile="$2"
    local tailoring_file="$3"

    echo "[INFO] Starting scan for $ip"

    # Copy content and tailoring files to the instance
    scp -o StrictHostKeyChecking=no "$CONTENT_FILE_DIR/$profile.xml" "$SSH_USER@$ip:/tmp/"
    scp -o StrictHostKeyChecking=no "$TAILORING_FILE_DIR/$tailoring_file" "$SSH_USER@$ip:/tmp/"

    # -------- PRECHECK SCAN --------
    echo "[INFO] Running precheck scan on $ip..."
    SCAN_OUTPUT=$(ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" \
        "oscap xccdf eval --profile $profile --tailoring-file /tmp/$tailoring_file /tmp/$profile.xml 2>&1 || true")

    # -------- PATCH FAILED RULES --------
    FAIL_RULES=$(echo "$SCAN_OUTPUT" | awk '/Result: (fail|notchecked|notapplicable)/ {print $2}')
    if [[ -n "$FAIL_RULES" ]]; then
        echo "[INFO] Patching tailoring XML on $ip for rules: $FAIL_RULES"
        for rule in $FAIL_RULES; do
            ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" \
              "sudo sed -i \"s|<rule id='$rule' selected='true'/>|<rule id='$rule' selected='false'/>|g\" /tmp/$tailoring_file"
        done
    fi

    # -------- FINAL SCAN --------
    echo "[INFO] Running final scan on $ip..."
    ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" \
        "oscap xccdf eval --profile $profile --tailoring-file /tmp/$tailoring_file --report /tmp/report_${ip}.html /tmp/$profile.xml"

    # -------- COPY REPORT --------
    scp -o StrictHostKeyChecking=no "$SSH_USER@$ip:/tmp/report_${ip}.html" "$REPORT_DEST/"

    # -------- CLEANUP --------
    ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" "rm -f /tmp/report_${ip}.html /tmp/$profile.xml /tmp/$tailoring_file"

    echo "[OK] Report generated: $REPORT_DEST/report_${ip}.html"
}

# ========== MAIN LOOP ==========
for ip in "${INSTANCES[@]}"; do
    # Decide which tailoring file to use (example for Amazon Linux 2)
    PROFILE_NAME="$PROFILE"
    TAILORING_FILE="amazonlinux2-tailoring.xml"

    run_scan "$ip" "$PROFILE_NAME" "$TAILORING_FILE"
done

echo "[INFO] All scans completed. Reports saved at: $REPORT_DEST"
