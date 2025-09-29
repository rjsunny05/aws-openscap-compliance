#!/bin/bash
set -euo pipefail
set -x

# ========== PARAMETERS ==========
WORKSPACE="$1"          # Jenkins workspace
SSH_KEY="$2"            # Private key file path (Jenkins SSH credential)
PROFILE="$3"            # OpenSCAP profile (e.g. xccdf_org.ssgproject.content_profile_cis)
TAILORING_FILE_DIR="$4" # Directory in workspace containing tailoring XMLs
TARGET_OS="$5"          # OS filter from Jenkins param (AmazonLinux2, Ubuntu22.04, CentOS7.9)
SCAN_ALL_INSTANCES="$6" # true/false
INSTANCE_IDS="$7"       # Comma-separated instance IDs (only if SCAN_ALL_INSTANCES=false)
EXCLUDED_IPS="$8"       # Comma-separated list of IPs to exclude

REPORT_DEST="$WORKSPACE/openscap_reports"
mkdir -p "$REPORT_DEST"

# Convert excluded IPs to array
IFS=',' read -r -a EXCLUDED_ARRAY <<< "$EXCLUDED_IPS"

echo "[INFO] Fetching EC2 instances from AWS..."

if [[ "$SCAN_ALL_INSTANCES" == "true" ]]; then
    # All running instances in region
    readarray -t INSTANCES < <(aws ec2 describe-instances \
      --filters "Name=instance-state-name,Values=running" \
      --query 'Reservations[].Instances[].[InstanceId,PublicDnsName,Tags[?Key==`Name`]|[0].Value,Platform]' \
      --output text)
else
    # Only user-specified instances
    IFS=',' read -r -a IDS <<< "$INSTANCE_IDS"
    INSTANCES=()
    for id in "${IDS[@]}"; do
        info=$(aws ec2 describe-instances \
          --instance-ids "$id" \
          --query 'Reservations[].Instances[].[InstanceId,PublicDnsName,Tags[?Key==`Name`]|[0].Value,Platform]' \
          --output text)
        INSTANCES+=("$info")
    done
fi

if [[ ${#INSTANCES[@]} -eq 0 ]]; then
    echo "[ERROR] No matching instances found!"
    exit 1
fi

echo "[INFO] Found ${#INSTANCES[@]} candidate instances"
printf '%s\n' "${INSTANCES[@]}"

# ========== SCAN FUNCTION ==========
run_scan() {
    local instance_id="$1"
    local instance_dns="$2"
    local name="$3"
    local platform="$4"

    # Default SSH user
    local ssh_user="ec2-user"
    [[ "$platform" =~ Ubuntu ]] && ssh_user="ubuntu"
    [[ "$platform" =~ CentOS ]] && ssh_user="centos"

    echo "[INFO] Starting scan for $name ($instance_dns, $platform) as $ssh_user"

    # -------- INSTALL OPENSCAP + CONTENT --------
    if [[ "$platform" =~ Ubuntu ]]; then
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$ssh_user@$instance_dns" \
            "sudo apt-get update -y && sudo apt-get install -y openscap-utils ssg-base"
        CONTENT_FILE="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
    elif [[ "$platform" =~ CentOS ]]; then
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$ssh_user@$instance_dns" \
            "sudo yum install -y openscap-scanner scap-security-guide"
        CONTENT_FILE="/usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml"
    else
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$ssh_user@$instance_dns" \
            "sudo yum install -y openscap-scanner scap-security-guide"
        CONTENT_FILE="/usr/share/xml/scap/ssg/content/ssg-amazonlinux2-ds.xml"
    fi

    # Pick tailoring file
    local tailoring_file
    case "$platform" in
        Amazon*|AmazonLinux*) tailoring_file="amazonlinux-tailoring.xml" ;;
        Ubuntu*) tailoring_file="ubuntu-tailoring.xml" ;;
        CentOS*) tailoring_file="centos-tailoring.xml" ;;
        *) echo "[WARN] Unknown platform $platform for $instance_dns, skipping..." ; return ;;
    esac

    # Copy tailoring file
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        "$TAILORING_FILE_DIR/$tailoring_file" "$ssh_user@$instance_dns:/tmp/"

    # Run scan
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        "$ssh_user@$instance_dns" \
        "oscap xccdf eval --profile $PROFILE --tailoring-file /tmp/$tailoring_file --report /tmp/report_${name}.html $CONTENT_FILE"

    # Copy back report
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        "$ssh_user@$instance_dns:/tmp/report_${name}.html" "$REPORT_DEST/"

    echo "[OK] Report generated: $REPORT_DEST/report_${name}.html"
}

# ========== MAIN LOOP ==========
for entry in "${INSTANCES[@]}"; do
    read -r instance_id instance_dns name platform <<<"$entry"

    # Normalize platform
    if [[ -z "$platform" || "$platform" == "None" || "$platform" == "null" ]]; then
        platform="AmazonLinux"
    fi

    # Match target OS filter
    case "$TARGET_OS" in
        AmazonLinux2) [[ "$platform" =~ AmazonLinux ]] || continue ;;
        Ubuntu22.04)  [[ "$platform" =~ Ubuntu ]] || continue ;;
        CentOS7.9)    [[ "$platform" =~ CentOS ]] || continue ;;
    esac

    # Skip excluded IPs
    for ip in "${EXCLUDED_ARRAY[@]}"; do
        [[ "$instance_dns" == "$ip" ]] && echo "[INFO] Skipping excluded $instance_dns" && continue 2
    done

    run_scan "$instance_id" "$instance_dns" "$name" "$platform"
done

echo "[INFO] All scans completed. Reports saved at: $REPORT_DEST"
