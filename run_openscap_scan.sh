#!/bin/bash
set -euo pipefail
set -x

# ========== PARAMETERS from Jenkins ==========
WORKSPACE="$1"
SSH_KEY="$2"
PROFILE="$3"
# The rest (TARGET_OS_FILTER, SCAN_ALL_INSTANCES, etc.) are read from environment variables

# ========== DERIVED PARAMETERS ==========
TAILORING_FILE_DIR="$WORKSPACE/tailoring"
REPORT_DEST="$WORKSPACE/openscap_reports"
mkdir -p "$REPORT_DEST"

# Convert excluded IPs to an array
IFS=',' read -r -a EXCLUDED_ARRAY <<< "${EXCLUDED_IPS:-""}"

# ========== INSTANCE DISCOVERY (UPDATED) ==========
echo "[INFO] Fetching EC2 instances from AWS..."

# Default filter gets all running instances
aws_filter="Name=instance-state-name,Values=running"

# Add an OS-specific filter based on the parameter from Jenkins, if not 'All'
# This works by filtering on the 'Name' tag of the instance.
os_choice="${TARGET_OS_FILTER:-"All"}" # Default to "All" if variable isn't set
if [[ "$os_choice" != "All" ]]; then
    os_tag_value="*${os_choice,,}*" # Convert to lowercase and add wildcards (e.g., *ubuntu*)
    
    # For Amazon Linux, the tag might be 'amazon-linux-server' or similar
    if [[ "$os_choice" == "AmazonLinux" ]]; then
        os_tag_value="*amazon*linux*"
    fi
    
    aws_filter="$aws_filter Name=tag:Name,Values=$os_tag_value"
    echo "[INFO] Filtering for OS type: $os_choice"
fi

if [[ "${SCAN_ALL_INSTANCES:-false}" == "true" ]]; then
    # Get instances based on the constructed filter
    readarray -t INSTANCES < <(aws ec2 describe-instances \
      --filters $aws_filter \
      --query 'Reservations[].Instances[?PublicDnsName != ``].[InstanceId,PublicDnsName,Tags[?Key==`Name`]|[0].Value]' \
      --output text)
else
    # Get only user-specified instances (this logic remains the same)
    instance_ids_for_cli=$(echo "$INSTANCE_IDS" | tr ',' ' ')
    readarray -t INSTANCES < <(aws ec2 describe-instances \
      --instance-ids $instance_ids_for_cli \
      --query 'Reservations[].Instances[?PublicDnsName != ``].[InstanceId,PublicDnsName,Tags[?Key==`Name`]|[0].Value]' \
      --output text)
fi

if [[ ${#INSTANCES[@]} -eq 0 || -z "${INSTANCES[0]}" ]]; then
    echo "[ERROR] No matching and running instances with public DNS found!"
    exit 1
fi

echo "[INFO] Found ${#INSTANCES[@]} candidate instances."

# ========== SCAN FUNCTION ==========
run_scan() {
    local instance_id="$1"
    local instance_dns="$2"
    local name="$3"
    local ssh_user
    local tailoring_file

    # --- INTELLIGENT SSH USER AND TAILORING FILE SELECTION ---
    name_lower=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    if [[ "$name_lower" == *"ubuntu"* ]]; then
        ssh_user="ubuntu"
        tailoring_file="ubuntu-tailoring.xml"
    elif [[ "$name_lower" == *"centos"* ]]; then
        ssh_user="centos"
        tailoring_file="centos-tailoring.xml"
    elif [[ "$name_lower" == *"rhel"* ]]; then
        ssh_user="ec2-user"
        tailoring_file="rhel-tailoring.xml"
    else # Default to Amazon Linux
        ssh_user="ec2-user"
        tailoring_file="amazonlinux-tailoring.xml"
    fi

    echo "[INFO] Starting scan for '$name' ($instance_dns) as '$ssh_user'"

    # --- DYNAMIC CONTENT FILE DISCOVERY ---
    local content_file_path
    echo "[INFO] Finding SCAP content file on remote host..."
    if [[ "$ssh_user" == "ubuntu" ]]; then
        content_file_path=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$ssh_user@$instance_dns" "sudo find /usr/share/xml/scap/ssg/content/ -name '*ssg-ubuntu*ds.xml' | head -n 1")
    else # For Amazon Linux, CentOS, RHEL
        content_file_path=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$ssh_user@$instance_dns" "sudo find /usr/share/xml/scap/ssg/content/ -name '*ssg-al2023*ds.xml' -o -name '*ssg-amzn*ds.xml' -o -name '*ssg-rhel*ds.xml' -o -name '*ssg-centos*ds.xml' | head -n 1")
    fi

    if [[ -z "$content_file_path" ]]; then
        echo "[ERROR] Could not find a valid SCAP content file on '$instance_dns'. Skipping scan."
        return 1
    fi
    echo "[INFO] Found content file on remote: $content_file_path"

    # --- RUN SCAN ---
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$TAILORING_FILE_DIR/$tailoring_file" "$ssh_user@$instance_dns:/tmp/tailoring.xml"

    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$ssh_user@$instance_dns" \
        "sudo oscap xccdf eval --profile $PROFILE --tailoring-file /tmp/tailoring.xml --report /tmp/report_${name}.html $content_file_path"

    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$ssh_user@$instance_dns:/tmp/report_${name}.html" "$REPORT_DEST/"

    echo "[OK] Report for '$name' copied to '$REPORT_DEST/report_${name}.html'"
}

# ========== MAIN LOOP ==========
for entry in "${INSTANCES[@]}"; do
    read -r instance_id instance_dns name <<<"$entry"

    # Skip excluded IPs
    for ip in "${EXCLUDED_ARRAY[@]}"; do
        if [[ "$instance_dns" == "$ip" ]]; then
            echo "[INFO] Skipping excluded instance $instance_dns"
            continue 2 # Skips to the next instance
        fi
    done
    
    # Run the scan for the instance with error handling
    run_scan "$instance_id" "$instance_dns" "$name" || echo "[ERROR] Scan failed for '$name' ($instance_dns). Continuing..."
done

echo "[INFO] All scans completed. Reports are in: $REPORT_DEST"
