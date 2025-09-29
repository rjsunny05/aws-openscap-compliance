#!/bin/bash
set -euo pipefail
set -x

# ========== PARAMETERS from Jenkins ==========
WORKSPACE="$1"
SSH_KEY="$2"
PROFILE="$3"
# The rest (TARGET_OS_FILTER, EXCLUDED_INSTANCE_IDS, etc.) are read from environment variables

# ========== DERIVED PARAMETERS ==========
TAILORING_FILE_DIR="$WORKSPACE/tailoring"
REPORT_DEST="$WORKSPACE/openscap_reports"
mkdir -p "$REPORT_DEST"

IFS=',' read -r -a EXCLUDED_ID_ARRAY <<< "${EXCLUDED_INSTANCE_IDS:-""}"

# ========== INSTANCE DISCOVERY ==========
echo "[INFO] Fetching EC2 instances from AWS..."

# Use a bash array to store filters for robust argument passing.
aws_filter_array=("Name=instance-state-name,Values=running")
os_choice="${TARGET_OS_FILTER:-"All"}"

# Use a case statement to select the best filter for the chosen OS.
case "$os_choice" in
    Rhel | RHEL)
        # Use the Name tag filter for all OS types for consistency.
        aws_filter_array+=("Name=tag:Name,Values=*rhel*")
        echo "[INFO] Filtering for OS type: RHEL (using Name tag)"
        ;;
    Ubuntu | ubuntu)
        aws_filter_array+=("Name=tag:Name,Values=*ubuntu*")
        echo "[INFO] Filtering for OS type: Ubuntu (using Name tag)"
        ;;
    Centos | centos)
        aws_filter_array+=("Name=tag:Name,Values=*centos*")
        echo "[INFO] Filtering for OS type: CentOS (using Name tag)"
        ;;
    AmazonLinux | amazonlinux)
        aws_filter_array+=("Name=tag:Name,Values=*amazon*linux*,*amzn*")
        echo "[INFO] Filtering for OS type: Amazon Linux (using Name tag)"
        ;;
    All)
        echo "[INFO] Scanning all running instances."
        ;;
    *)
        echo "[ERROR] Unknown OS choice from Jenkins parameter: $os_choice"
        exit 1
        ;;
esac

# Pass the filter array to the AWS CLI command.
readarray -t INSTANCES < <(aws ec2 describe-instances \
  --filters "${aws_filter_array[@]}" \
  --query 'Reservations[].Instances[?PublicDnsName != ``].[InstanceId,PublicDnsName,Tags[?Key==`Name`]|[0].Value]' \
  --output text)

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

    is_excluded=false
    for excluded_id in "${EXCLUDED_ID_ARRAY[@]}"; do
        if [[ "$instance_id" == "$excluded_id" ]]; then
            echo "[INFO] Skipping excluded instance ID: $instance_id"
            is_excluded=true
            break
        fi
    done
    if [[ "$is_excluded" == true ]]; then
        continue
    fi
    
    run_scan "$instance_id" "$instance_dns" "$name" || echo "[ERROR] Scan failed for '$name' ($instance_dns). Continuing..."
done

echo "[INFO] All scans completed. Reports are in: $REPORT_DEST"
