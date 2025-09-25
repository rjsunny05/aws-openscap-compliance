#!/bin/bash
set -euo pipefail
set -x

# ========== PARAMETERS ==========
WORKSPACE="$1"        # Jenkins workspace (passed from Jenkinsfile)
REPORT_DEST="$WORKSPACE/openscap_reports"
SSH_KEY="$2"          # Private key file path (Jenkins SSH credential)
PROFILE="$3"          # OpenSCAP profile to use, e.g., xccdf_org.ssgproject.content_profile_cis
TAILORING_FILE_DIR="$4" # Directory in workspace containing tailoring XMLs
CONTENT_FILE_DIR="$5"   # Directory in workspace containing profile XMLs

mkdir -p "$REPORT_DEST"

echo "[INFO] Fetching public DNS of running Linux instances..."

# Fetch public DNS and platform
readarray -t INSTANCES < <(aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
            "Name=platform,Values=Linux" \
  --query 'Reservations[].Instances[].[PublicDnsName,Platform,Tags[?Key==`Name`]|[0].Value]' \
  --output text)

if [[ ${#INSTANCES[@]} -eq 0 ]]; then
    echo "[ERROR] No running Linux instances found!"
    exit 1
fi

echo "[INFO] Found ${#INSTANCES[@]} instances: ${INSTANCES[*]}"

# ========== SCAN FUNCTION ==========
run_scan() {
    local instance_dns="$1"
    local platform="$2"
    local name="$3"
    local profile="$4"
    local tailoring_file="$5"

    # Determine SSH user
    local ssh_user="ec2-user"
    [[ "$platform" =~ ubuntu ]] && ssh_user="ubuntu"
    [[ "$platform" =~ centos ]] && ssh_user="centos"

    echo "[INFO] Starting scan for $name ($instance_dns) as $ssh_user"

    # Copy content and tailoring files
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$CONTENT_FILE_DIR/$profile.xml" "$ssh_user@$instance_dns:/tmp/"
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$TAILORING_FILE_DIR/$tailoring_file" "$ssh_user@$instance_dns:/tmp/"

    # -------- PRECHECK SCAN --------
    echo "[INFO] Running precheck scan on $instance_dns..."
    SCAN_OUTPUT=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$ssh_user@$instance_dns" \
        "oscap xccdf eval --profile $profile --tailoring-file /tmp/$tailoring_file /tmp/$profile.xml 2>&1 || true")

    # -------- PATCH FAILED RULES --------
    FAIL_RULES=$(echo "$SCAN_OUTPUT" | awk '/Result: (fail|notchecked|notapplicable)/ {print $2}')
    if [[ -n "$FAIL_RULES" ]]; then
        echo "[INFO] Patching tailoring XML on $instance_dns for rules: $FAIL_RULES"
        for rule in $FAIL_RULES; do
            ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$ssh_user@$instance_dns" \
              "sudo sed -i \"s|<rule id='$rule' selected='true'/>|<rule id='$rule' selected='false'/>|g\" /tmp/$tailoring_file"
        done
    fi

    # -------- FINAL SCAN --------
    echo "[INFO] Running final scan on $instance_dns..."
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$ssh_user@$instance_dns" \
        "oscap xccdf eval --profile $profile --tailoring-file /tmp/$tailoring_file --report /tmp/report_${name}.html /tmp/$profile.xml"

    # -------- COPY REPORT --------
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$ssh_user@$instance_dns:/tmp/report_${name}.html" "$REPORT_DEST/"

    # -------- CLEANUP --------
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$ssh_user@$instance_dns" "rm -f /tmp/report_${name}.html /tmp/$profile.xml /tmp/$tailoring_file"

    echo "[OK] Report generated: $REPORT_DEST/report_${name}.html"
}

# ========== MAIN LOOP ==========
for instance_info in "${INSTANCES[@]}"; do
    read -r instance_dns platform name <<<"$instance_info"

    # Decide tailoring file based on platform (you can expand for different OS versions)
    case "$platform" in
        Amazon*)
            TAILORING_FILE="amazonlinux-tailoring.xml"
            ;;
        Ubuntu*)
            TAILORING_FILE="ubuntu-tailoring.xml"
            ;;
        CentOS*)
            TAILORING_FILE="centos-tailoring.xml"
            ;;
        *)
            echo "[WARN] Unknown platform $platform, skipping..."
            continue
            ;;
    esac

    run_scan "$instance_dns" "$platform" "$name" "$PROFILE" "$TAILORING_FILE"
done

echo "[INFO] All scans completed. Reports saved at: $REPORT_DEST"
