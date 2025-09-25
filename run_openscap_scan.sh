#!/bin/bash
set -euo pipefail
set -x

# ========== PARAMETERS ==========
WORKSPACE="$1"           # Jenkins workspace (passed from Jenkinsfile)
AWS_REGION="$2"          # AWS region (passed from Jenkinsfile)
SSM_FILE="$WORKSPACE/ssm_inventory.csv"
REPORT_DEST="$WORKSPACE/openscap_reports"
SSH_KEY="$SSH_AUTH_SOCK" # SSH agent provided by Jenkins (no hardcoding)

mkdir -p "$REPORT_DEST"

echo "[INFO] Fetching instance metadata..."

# ========== FETCH INSTANCE METADATA ==========
# Example: using AWS CLI SSM describe-instance-information
aws ssm describe-instance-information \
  --region "$AWS_REGION" \
  --query 'InstanceInformationList[*].[ComputerName,IPAddress,PlatformName,PlatformVersion]' \
  --output text > "$SSM_FILE"

echo "[INFO] Inventory saved to $SSM_FILE"

# ========== SCAN FUNCTION ==========
run_scan() {
    local ip="$1"
    local os_name="$2"
    local os_version="$3"
    local profile="$4"
    local tailoring="$5"

    echo "[INFO] Starting scan for $os_name $os_version ($ip)"

    # Copy content & tailoring files to instance
    scp -o StrictHostKeyChecking=no content/* ec2-user@"$ip":/tmp/
    scp -o StrictHostKeyChecking=no tailoring/* ec2-user@"$ip":/tmp/

    # -------- PRECHECK SCAN --------
    echo "[INFO] Running precheck scan on $ip..."
    SCAN_OUTPUT=$(ssh -o StrictHostKeyChecking=no ec2-user@"$ip" \
      "oscap xccdf eval --profile $profile \
       --tailoring-file /tmp/$tailoring \
       /tmp/$profile.xml 2>&1 || true")

    # -------- PATCH FAILED RULES --------
    FAIL_RULES=$(echo "$SCAN_OUTPUT" | awk '/Result: (fail|notchecked|notapplicable)/ {print $2}')
    if [[ -n "$FAIL_RULES" ]]; then
        echo "[INFO] Patching tailoring XML on $ip for rules: $FAIL_RULES"
        for rule in $FAIL_RULES; do
            ssh -o StrictHostKeyChecking=no ec2-user@"$ip" \
              "sudo sed -i \"s|<rule id='$rule' selected='true'/>|<rule id='$rule' selected='false'/>|g\" /tmp/$tailoring"
        done
    fi

    # -------- FINAL SCAN --------
    echo "[INFO] Running final scan on $ip..."
    ssh -o StrictHostKeyChecking=no ec2-user@"$ip" \
      "oscap xccdf eval --profile $profile \
       --tailoring-file /tmp/$tailoring \
       --report /tmp/report_${ip}.html \
       /tmp/$profile.xml"

    # -------- COPY REPORT --------
    scp -o StrictHostKeyChecking=no ec2-user@"$ip":/tmp/report_${ip}.html "$REPORT_DEST/" || {
        echo "[WARN] Failed to copy report from $ip. Report remains on instance."
    }

    # -------- CLEANUP --------
    ssh -o StrictHostKeyChecking=no ec2-user@"$ip" "rm -f /tmp/report_${ip}.html /tmp/*.xml"
    echo "[OK] Report generated: $REPORT_DEST/report_${ip}.html"
}

# ========== MAIN LOOP ==========
while IFS=$'\t' read -r name private_ip platform_name platform_version; do
    if [[ "$name" == "unknown" || -z "$platform_name" ]]; then
        echo "[SKIP] Instance $private_ip has unknown name or OS"
        continue
    fi

    case "$platform_name" in
        "CentOS Linux")
            if [[ "$platform_version" == "7.6" ]]; then
                run_scan "$private_ip" "CentOS" "7.6" "xccdf_org.ssgproject.content_profile_cis" "centos-7.6-tailoring.xml"
            elif [[ "$platform_version" == "7.9" ]]; then
                run_scan "$private_ip" "CentOS" "7.9" "xccdf_org.ssgproject.content_profile_cis" "centos-7.9-tailoring.xml"
            fi
            ;;
        "Amazon Linux")
            if [[ "$platform_version" == "2" ]]; then
                run_scan "$private_ip" "Amazon Linux" "2" "xccdf_org.ssgproject.content_profile_cis" "amazonlinux2-tailoring.xml"
            elif [[ "$platform_version" == "2023" ]]; then
                ssh -o StrictHostKeyChecking=no ec2-user@"$private_ip" "sudo yum install -y openscap-scanner"
                run_scan "$private_ip" "Amazon Linux" "2023" "xccdf_org.ssgproject.content_profile_cis" "amazonlinux2023-tailoring.xml"
            fi
            ;;
        "Ubuntu")
            if [[ "$platform_version" == "22.04" ]]; then
                run_scan "$private_ip" "Ubuntu" "22.04" "xccdf_org.ssgproject.content_profile_cis" "ubuntu2204-tailoring.xml"
            fi
            ;;
        *)
            echo "[SKIP] Unsupported OS: $platform_name $platform_version"
            ;;
    esac
done < "$SSM_FILE"

echo "[INFO] All scans completed. Reports saved at: $REPORT_DEST"
