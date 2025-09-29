#!/bin/bash
set -euo pipefail
set -x

# ================== CHANGE IS HERE ==================
# Jenkins parameters are now read from environment variables, which is more robust.
# Only context-specific values are passed as arguments.

# ========== PARAMETERS from arguments ==========
WORKSPACE="$1"          # Jenkins workspace path
SSH_KEY="$2"            # Private key file path (from Jenkins credentials)
PROFILE="$3"            # OpenSCAP profile name

# ========== PARAMETERS from environment variables (set by Jenkins) ==========
# These are read automatically from the environment, no need to pass them as $4, $5, $6...
# TARGET_OS
# SCAN_ALL_INSTANCES
# INSTANCE_IDS
# EXCLUDED_IPS

# ========== DERIVED PARAMETERS ==========
TAILORING_FILE_DIR="$WORKSPACE/tailoring" # Directory in workspace containing tailoring XMLs
REPORT_DEST="$WORKSPACE/openscap_reports"
# ===================================================

mkdir -p "$REPORT_DEST"

# Convert excluded IPs to array
# Use :-"" to provide a default empty string if EXCLUDED_IPS is not set
IFS=',' read -r -a EXCLUDED_ARRAY <<< "${EXCLUDED_IPS:-""}"

echo "[INFO] Fetching EC2 instances from AWS..."

if [[ "$SCAN_ALL_INSTANCES" == "true" ]]; then
    # All running instances in region
    # Note the check for empty PublicDnsName to avoid scanning instances without a public IP
    readarray -t INSTANCES < <(aws ec2 describe-instances \
      --filters "Name=instance-state-name,Values=running" \
      --query 'Reservations[].Instances[?PublicDnsName != ``].[InstanceId,PublicDnsName,Tags[?Key==`Name`]|[0].Value,PlatformDetails]' \
      --output text)
else
    # Only user-specified instances
    # Using a single AWS call for efficiency
    instance_ids_for_cli=$(echo "$INSTANCE_IDS" | tr ',' ' ')
    readarray -t INSTANCES < <(aws ec2 describe-instances \
      --instance-ids $instance_ids_for_cli \
      --query 'Reservations[].Instances[?PublicDnsName != ``].[InstanceId,PublicDnsName,Tags[?Key==`Name`]|[0].Value,PlatformDetails]' \
      --output text)
fi

if [[ ${#INSTANCES[@]} -eq 0 || -z "${INSTANCES[0]}" ]]; then
    echo "[ERROR] No matching and running instances with public DNS found!"
    exit 1
fi

echo "[INFO] Found ${#INSTANCES[@]} candidate instances"
printf '%s\n' "${INSTANCES[@]}"

# ========== SCAN FUNCTION ==========
run_scan() {
    local instance_id="$1"
    local instance_dns="$2"
    local name="$3"
    # AWS now provides "PlatformDetails" which is more reliable
    local platform="$4" 

    # Default SSH user
    local ssh_user="ec2-user"
    [[ "$platform" == "Ubuntu" ]] && ssh_user="ubuntu"
    [[ "$platform" == "CentOS" ]] && ssh_user="centos"

    echo "[INFO] Starting scan for $name ($instance_dns, $platform) as $ssh_user"

    # -------- INSTALL OPENSCAP + CONTENT --------
    if [[ "$platform" == "Ubuntu" ]]; then
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$ssh_user@$instance_dns" \
            "sudo apt-get update -y && sudo apt-get install -y openscap-utils ssg-base"
        CONTENT_FILE="/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
    elif [[ "$platform" == "CentOS" ]]; then
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$ssh_user@$instance_dns" \
            "sudo yum install -y openscap-scanner scap-security-guide"
        CONTENT_FILE="/usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml"
    else # Default to Amazon Linux
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$ssh_user@$instance_dns" \
            "sudo yum install -y openscap-scanner scap-security-guide"
        CONTENT_FILE="/usr/share/xml/scap/ssg/content/ssg-amazonlinux2-ds.xml"
    fi

    # Pick tailoring file
    local tailoring_file
    case "$platform" in
        "Linux/UNIX") tailoring_file="amazonlinux-tailoring.xml" ;; # Amazon Linux 2
        "Ubuntu") tailoring_file="ubuntu-tailoring.xml" ;;
        "CentOS") tailoring_file="centos-tailoring.xml" ;;
        *) echo "[WARN] Unknown platform '$platform' for $instance_dns, attempting Amazon Linux tailoring..." ; tailoring_file="amazonlinux-tailoring.xml" ;;
    esac

    # Copy tailoring file
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$TAILORING_FILE_DIR/$tailoring_file" "$ssh_user@$instance_dns:/tmp/"

    # Run scan
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$ssh_user@$instance_dns" \
        "sudo oscap xccdf eval --profile $PROFILE --tailoring-file /tmp/$tailoring_file --report /tmp/report_${name}.html $CONTENT_FILE"

    # Copy back report
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$ssh_user@$instance_dns:/tmp/report_${name}.html" "$REPORT_DEST/"

    echo "[OK] Report generated: $REPORT_DEST/report_${name}.html"
}

# ========== MAIN LOOP ==========
for entry in "${INSTANCES[@]}"; do
    read -r instance_id instance_dns name platform <<<"$entry"

    # Normalize platform - default to Amazon Linux if not specified
    if [[ -z "$platform" || "$platform" == "None" ]]; then
        platform="Linux/UNIX" # This is what Amazon Linux 2 often reports as PlatformDetails
    fi

    # Match target OS filter
    case "$TARGET_OS" in
        AmazonLinux2) [[ "$platform" == "Linux/UNIX" ]] || continue ;;
        Ubuntu22.04)  [[ "$platform" == "Ubuntu" ]] || continue ;;
        CentOS7.9)    [[ "$platform" == "CentOS" ]] || continue ;;
    esac

    # Skip excluded IPs
    for ip in "${EXCLUDED_ARRAY[@]}"; do
        if [[ "$instance_dns" == "$ip" ]]; then
            echo "[INFO] Skipping excluded instance $instance_dns"
            continue 2 # Skips to the next instance in the outer loop
        fi
    done

    # Run the scan for the instance. Added error handling.
    run_scan "$instance_id" "$instance_dns" "$name" "$platform" || echo "[ERROR] Scan failed for $name ($instance_dns). Continuing with next instance."
done

echo "[INFO] All scans completed. Reports saved at: $REPORT_DEST"
