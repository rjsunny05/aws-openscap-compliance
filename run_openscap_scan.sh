#!/bin/bash
set -x

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SSM_FILE="${SCRIPT_DIR}/ssm.txt"
FINAL_SSM_FILE="${SCRIPT_DIR}/ssm_final_scan_list.txt"

#
# STEP 1: Always discover all online instances.
#
echo "[INFO] Performing full instance discovery..."
echo "InstanceName,PrivateIP,PlatformName,PlatformVersion" > "$SSM_FILE"

declare -A IP_NAME_MAP
while IFS=$'\t' read -r instance_id name private_ip; do
    if [[ -n "$private_ip" && -n "$name" ]]; then
        IP_NAME_MAP["$private_ip"]="$name"
    fi
done < <(aws ec2 describe-instances \
    --query 'Reservations[].Instances[?State.Name==`running`].[InstanceId,Tags[?Key==`Name`]|[0].Value,PrivateIpAddress]' \
    --output text)

while IFS=$'\t' read -r instance_id platform_name platform_version private_ip; do
    name="${IP_NAME_MAP[$private_ip]:-unknown}"
    if [[ "$name" == "unknown" ]]; then
        echo "[SKIP] Unknown instance ($private_ip) - Name not found"
        continue
    fi

    if [[ -n "$platform_name" && -n "$platform_version" ]]; then
        echo "$name,$private_ip,\"$platform_name\",\"$platform_version\"" >> "$SSM_FILE"
    else
        echo "[SKIP] $name ($private_ip) - Missing platform info"
    fi
done < <(aws ssm describe-instance-information \
    --filters "Key=PingStatus,Values=Online" \
    --query 'InstanceInformationList[*].[InstanceId,PlatformName,PlatformVersion,IPAddress]' \
    --output text | grep -v 'Windows')

echo "[INFO] Full instance list generated in ssm.txt:"
cat "$SSM_FILE"
echo "--------------------------------------------------"

#
# STEP 2: Filter the discovered list based on Jenkins parameters.
#
HEADER=$(head -n 1 "$SSM_FILE")
BODY=$(tail -n +2 "$SSM_FILE")

# OS Filtering
if [[ -n "$OS_TYPE" && "$OS_TYPE" != "All" ]]; then
    echo "[FILTER] Filtering by OS: $OS_TYPE"
    OS_FILTER=""
    case "$OS_TYPE" in
        "Centos") OS_FILTER="CentOS Linux" ;;
        "RHEL") OS_FILTER="Red Hat Enterprise Linux" ;;
        "Ubuntu") OS_FILTER="Ubuntu" ;;
        "Amazon Linux") OS_FILTER="Amazon Linux" ;;
    esac
    BODY=$(echo "$BODY" | grep "$OS_FILTER" || true)
fi

# Version Filtering
VERSION_FILTER=""
if [[ "$OS_TYPE" == "Ubuntu" && -n "$UBUNTU_VERSION" && "$UBUNTU_VERSION" != "N/A" ]]; then
    VERSION_FILTER=$UBUNTU_VERSION
elif [[ "$OS_TYPE" == "Amazon Linux" && -n "$AMAZON_LINUX_VERSION" && "$AMAZON_LINUX_VERSION" != "N/A" ]]; then
    VERSION_FILTER=$AMAZON_LINUX_VERSION
fi

if [[ -n "$VERSION_FILTER" ]]; then
    echo "[FILTER] Filtering by Version: $VERSION_FILTER"
    BODY=$(echo "$BODY" | grep ",\"$VERSION_FILTER\"" || true)
fi

# IP Exclusion Filtering
if [[ -n "$EXCLUDE_IPS" ]]; then
    echo "[FILTER] Excluding IPs:"
    echo "$EXCLUDE_IPS"
    BODY=$(echo "$BODY" | grep -v -F -f <(echo "$EXCLUDE_IPS") || true)
fi

#
# STEP 3: Create the final list for scanning.
#
echo "$HEADER" > "$FINAL_SSM_FILE"
if [[ -n "$BODY" ]]; then
    echo "$BODY" >> "$FINAL_SSM_FILE"
fi

echo "[INFO] Final instance list for scanning is ready:"
cat "$FINAL_SSM_FILE"
echo "====================================================="


#
# STEP 4: Run scans using the FINAL list.
# The rest of your script remains the same, but it now reads from FINAL_SSM_FILE
#

declare -A platform_filters=(
  ["Amazon Linux 2"]="Amazon Linux|2"
  ["Amazon Linux 2023"]="Amazon Linux|2023"
  ["CentOS Linux 7.9.2009"]="CentOS Linux|7.9.2009"
  ["CentOS Linux 7.6.1810"]="CentOS Linux|7.6.1810"
  ["Red Hat Enterprise Linux Server 7.9"]="Red Hat Enterprise Linux Server|7.9"
  ["Ubuntu 22.04"]="Ubuntu|22.04"
)

for label in "${!platform_filters[@]}"; do
  IFS='|' read -r p_name p_version <<< "${platform_filters[$label]}"
  echo "________ $label ________"
  awk -F',' -v name="$p_name" -v version="$p_version" '
    $3 ~ name && $4 ~ version {
      gsub(/"/, "", $0);
      print $1 "," $2 "," $3 "," $4
    }
  ' "$FINAL_SSM_FILE"
  echo ""
done

SSH_KEY="${SSH_KEY_FROM_JENKINS:-/home/khushi.m/key.pem}"
REPORT_DEST="${SCRIPT_DIR}/openscap_reports"
mkdir -p "$REPORT_DEST"
FOLDER_NAME="customCentos7_6_1810"

echo ""
echo "[INFO] Starting OpenSCAP for CentOS Linux 7.6.1810 instances..."

tail -n +2 "$FINAL_SSM_FILE" | while IFS=',' read -r name ip platform version; do
    platform=$(echo "$platform" | tr -d '"')
    version=$(echo "$version" | tr -d '"')

    if [[ "$platform" == "CentOS Linux" && "$version" == "7.6.1810" ]]; then
        echo "[TRY] $name ($ip) - CentOS Linux 7.6.1810"
        
        # --- ADD THE NEW LOGIC BLOCK HERE ---
        if [[ "$platform" == "Ubuntu" ]]; then
            SSH_USER="ubuntu"
        elif [[ "$platform" == "Amazon Linux" || "$platform" == "Red Hat Enterprise Linux" ]]; then
            SSH_USER="ec2-user"
        elif [[ "$platform" == "CentOS Linux" ]]; then
            SSH_USER="centos"
        else
            echo "[WARN] Could not determine SSH user for platform: $platform. Skipping."
            continue
        fi
        # --- END OF LOGIC BLOCK ---

        if ssh -vvv -n -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip" "echo SSH successful"; then
            echo "[OK] SSH successful to $ip as $SSH_USER"

            echo "[COPY] Copying folder $FOLDER_NAME to $ip:/tmp/ ..."
            scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -r "${SCRIPT_DIR}/profiles/$FOLDER_NAME" "$SSH_USER@$ip:/tmp/"

            echo "[INFO] Files in /tmp/$FOLDER_NAME:"
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "ls -1 /tmp/$FOLDER_NAME"

            echo "[SCAN] Running temporary OpenSCAP scan (Precheck)..."
            SCAN_OUTPUT=$(ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" \
            "sudo oscap xccdf eval \
              --profile xccdf_org.ssgproject.content_profile_pci-dss2 \
              --tailoring-file /tmp/$FOLDER_NAME/tailoring-xccdf.xml \
              --tailoring-id xccdf_scap-workbench_tailoring_default \
              --report /tmp/$FOLDER_NAME/precheck_${ip}.html \
              /tmp/$FOLDER_NAME/ssg-centos7-ds-1.2.xml")

            echo "$SCAN_OUTPUT" > "/tmp/oscap_scan_${ip}.log"
            echo "[INFO] Precheck completed for $ip"

            echo "[PARSE] Checking for failed/notchecked/notapplicable rules..."
            FAIL_RULES=$(echo "$SCAN_OUTPUT" | awk '
                /Rule/ {rule=$2}
                /Result/ {
                    if ($2=="fail" || $2=="notchecked" || $2=="notapplicable") {
                        print rule ":" $2
                    }
                }')

            if [[ -n "$FAIL_RULES" ]]; then
                echo "[FAIL] Rules to disable:"
                echo "$FAIL_RULES"
                for entry in $FAIL_RULES; do
                    rule=$(echo "$entry" | cut -d':' -f1)
                    status=$(echo "$entry" | cut -d':' -f2)
                    echo "[PATCH] Disabling $rule ($status)..."
                    ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "
                        sudo sed -i 's/\(idref=\"$rule\" selected=\"\)true\"/\1false\"/g' /tmp/$FOLDER_NAME/ssg-centos7-ds-1.2.xml &&
                        sudo sed -i 's/\(id=\"$rule\" selected=\"\)true\"/\1false\"/g' /tmp/$FOLDER_NAME/tailoring-xccdf.xml"
                done
            else
                echo "[OK] No failed/notchecked/notapplicable rules found."
            fi

            echo "[INFO] Removing old report and generating final report..."
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo rm -f /tmp/$FOLDER_NAME/report_${ip}.html"
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" \
            "sudo oscap xccdf eval \
              --profile xccdf_org.ssgproject.content_profile_pci-dss2 \
              --tailoring-file /tmp/$FOLDER_NAME/tailoring-xccdf.xml \
              --tailoring-id xccdf_scap-workbench_tailoring_default \
              --report /tmp/$FOLDER_NAME/report_${ip}.html \
              /tmp/$FOLDER_NAME/ssg-centos7-ds-1.2.xml"

            echo "[DONE] Final report generated successfully."

            echo "[SCP] Copying report to $REPORT_DEST..."
            scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip:/tmp/$FOLDER_NAME/report_${ip}.html" "$REPORT_DEST/report_${ip}.html"

            echo "[CLEANUP] Removing report from remote server..."
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo rm -f /tmp/$FOLDER_NAME/report_${ip}.html"

            echo "[OK] Completed for $ip"
        else
            echo "[FAIL] SSH failed for $ip"
        fi
    fi
done

SSH_KEY="${SSH_KEY_FROM_JENKINS:-/home/khushi.m/key.pem}"
REPORT_DEST="${SCRIPT_DIR}/openscap_reports"
mkdir -p "$REPORT_DEST"
FOLDER_NAME="customCentos7_9_2009"

echo ""
echo "[INFO] Starting OpenSCAP for CentOS Linux 7.9.2009 instances..."

tail -n +2 "$FINAL_SSM_FILE" | while IFS=',' read -r name ip platform version; do
    platform=$(echo "$platform" | tr -d '"')
    version=$(echo "$version" | tr -d '"')

    if [[ "$platform" == "CentOS Linux" && "$version" == "7.9.2009" ]]; then
        echo "[TRY] $name ($ip) - CentOS Linux 7.9.2009"
         # --- ADD THE NEW LOGIC BLOCK HERE ---
        if [[ "$platform" == "Ubuntu" ]]; then
            SSH_USER="ubuntu"
        elif [[ "$platform" == "Amazon Linux" || "$platform" == "Red Hat Enterprise Linux" ]]; then
            SSH_USER="ec2-user"
        elif [[ "$platform" == "CentOS Linux" ]]; then
            SSH_USER="centos"
        else
            echo "[WARN] Could not determine SSH user for platform: $platform. Skipping."
            continue
        fi
        # --- END OF LOGIC BLOCK ---

        if ssh -vvv -n -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip" "echo SSH successful"; then
            echo "[OK] SSH successful to $ip as $SSH_USER"

            echo "[COPY] Copying folder $FOLDER_NAME to $ip:/tmp/ ..."
            scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -r "${SCRIPT_DIR}/profiles/$FOLDER_NAME" "$SSH_USER@$ip:/tmp/"

            echo "[INFO] Files in /tmp/$FOLDER_NAME:"
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "ls -1 /tmp/$FOLDER_NAME"

            echo "[SCAN] Running temporary OpenSCAP scan (Precheck)..."
            SCAN_OUTPUT=$(ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" \
            "sudo oscap xccdf eval \
              --profile xccdf_org.ssgproject.content_profile_pci-dss2 \
              --tailoring-file /tmp/$FOLDER_NAME/tailoring-xccdf.xml \
              --tailoring-id xccdf_scap-workbench_tailoring_default \
              --report /tmp/$FOLDER_NAME/precheck_${ip}.html \
              /tmp/$FOLDER_NAME/ssg-centos7-ds-1.2.xml")

            echo "$SCAN_OUTPUT" > "/tmp/oscap_scan_${ip}.log"
            echo "[INFO] Precheck completed for $ip"

            echo "[PARSE] Checking for failed/notchecked/notapplicable rules..."
            FAIL_RULES=$(echo "$SCAN_OUTPUT" | awk '
                /Rule/ {rule=$2}
                /Result/ {
                    if ($2=="fail" || $2=="notchecked" || $2=="notapplicable") {
                        print rule ":" $2
                    }
                }')

            if [[ -n "$FAIL_RULES" ]]; then
                echo "[FAIL] Rules to disable:"
                echo "$FAIL_RULES"
                for entry in $FAIL_RULES; do
                    rule=$(echo "$entry" | cut -d':' -f1)
                    status=$(echo "$entry" | cut -d':' -f2)
                    echo "[PATCH] Disabling $rule ($status)..."
                    ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "
                        sudo sed -i 's/\(idref=\"$rule\" selected=\"\)true\"/\1false\"/g' /tmp/$FOLDER_NAME/ssg-centos7-ds-1.2.xml &&
                        sudo sed -i 's/\(id=\"$rule\" selected=\"\)true\"/\1false\"/g' /tmp/$FOLDER_NAME/tailoring-xccdf.xml"
                done
            else
                echo "[OK] No failed/notchecked/notapplicable rules found."
            fi

            echo "[INFO] Removing old report and generating final report..."
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo rm -f /tmp/$FOLDER_NAME/report_${ip}.html"
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" \
            "sudo oscap xccdf eval \
              --profile xccdf_org.ssgproject.content_profile_pci-dss2 \
              --tailoring-file /tmp/$FOLDER_NAME/tailoring-xccdf.xml \
              --tailoring-id xccdf_scap-workbench_tailoring_default \
              --report /tmp/$FOLDER_NAME/report_${ip}.html \
              /tmp/$FOLDER_NAME/ssg-centos7-ds-1.2.xml"

            echo "[DONE] Final report generated successfully."

            echo "[SCP] Copying report to $REPORT_DEST..."
            scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip:/tmp/$FOLDER_NAME/report_${ip}.html" "$REPORT_DEST/report_${ip}.html"

            echo "[CLEANUP] Removing report from remote server..."
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo rm -f /tmp/$FOLDER_NAME/report_${ip}.html"

            echo "[OK] Completed for $ip"
        else
            echo "[FAIL] SSH failed for $ip"
        fi
    fi
done


SSH_KEY="${SSH_KEY_FROM_JENKINS:-/home/khushi.m/key.pem}"
REPORT_DEST="${SCRIPT_DIR}/openscap_reports"
mkdir -p "$REPORT_DEST"
FOLDER_NAME="customAmazon2"

echo ""
echo "[INFO] Processing Amazon Linux 2 instances..."

tail -n +2 "$FINAL_SSM_FILE" | while IFS=',' read -r name ip platform version; do
    platform=$(echo "$platform" | tr -d '"')
    version=$(echo "$version" | tr -d '"')

    if [[ "$platform" == "Amazon Linux" && "$version" == "2" ]]; then
        echo "[TRY] $name ($ip) - Amazon Linux 2"
        
         # --- ADD THE NEW LOGIC BLOCK HERE ---
        if [[ "$platform" == "Ubuntu" ]]; then
            SSH_USER="ubuntu"
        elif [[ "$platform" == "Amazon Linux" || "$platform" == "Red Hat Enterprise Linux" ]]; then
            SSH_USER="ec2-user"
        elif [[ "$platform" == "CentOS Linux" ]]; then
            SSH_USER="centos"
        else
            echo "[WARN] Could not determine SSH user for platform: $platform. Skipping."
            continue
        fi
        # --- END OF LOGIC BLOCK ---

        # SSH Test
        if ssh -vvv -n -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip" "echo SSH successful"; then
            echo "[OK] SSH successful to $ip as $SSH_USER"

            echo "[COPY] Copying $FOLDER_NAME to $ip:/tmp/ ..."
            scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -r "${SCRIPT_DIR}/profiles/$FOLDER_NAME" "$SSH_USER@$ip:/tmp/"

            echo "[INFO] Files in /tmp/$FOLDER_NAME:"
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "ls -1 /tmp/$FOLDER_NAME"

            echo "[SCAN] Running temporary OpenSCAP scan (Precheck)..."
            SCAN_OUTPUT=$(ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" \
            "sudo oscap xccdf eval \
              --profile xccdf_org.ssgproject.content_profile_pci-dss_customized \
              --tailoring-file /tmp/$FOLDER_NAME/tailoring-xccdfamazon2.xml \
              --tailoring-id xccdf_scap-workbench_tailoring_default \
              --report /tmp/$FOLDER_NAME/precheck_${ip}.html \
              /tmp/$FOLDER_NAME/ssg-amzn2-ds.xml")

            echo "$SCAN_OUTPUT" > "/tmp/oscap_scan_${ip}.log"
            echo "[INFO] Precheck completed for $ip"

            echo "[PARSE] Checking for failed/notchecked/notapplicable rules..."
            FAIL_RULES=$(echo "$SCAN_OUTPUT" | awk '
                /Rule/ {rule=$2}
                /Result/ {
                    if ($2=="fail" || $2=="notchecked" || $2=="notapplicable") {
                        print rule ":" $2
                    }
                }')

            if [[ -n "$FAIL_RULES" ]]; then
                echo "[FAIL] Rules to disable:"
                echo "$FAIL_RULES"
                for entry in $FAIL_RULES; do
                    rule=$(echo "$entry" | cut -d':' -f1)
                    status=$(echo "$entry" | cut -d':' -f2)
                    echo "[PATCH] Disabling $rule ($status)..."
                    ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "
                        sudo sed -i 's/\(idref=\"$rule\" selected=\"\)true\"/\1false\"/g' /tmp/$FOLDER_NAME/ssg-amzn2-ds.xml &&
                        sudo sed -i 's/\(id=\"$rule\" selected=\"\)true\"/\1false\"/g' /tmp/$FOLDER_NAME/tailoring-xccdfamazon2.xml"
                done
            else
                echo "[OK] No failed/notchecked/notapplicable rules found."
            fi

            echo "[INFO] Removing old report and generating final report..."
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo rm -f /tmp/$FOLDER_NAME/report_${ip}.html"
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" \
            "sudo oscap xccdf eval \
              --profile xccdf_org.ssgproject.content_profile_pci-dss_customized \
              --tailoring-file /tmp/$FOLDER_NAME/tailoring-xccdfamazon2.xml \
              --tailoring-id xccdf_scap-workbench_tailoring_default \
              --report /tmp/$FOLDER_NAME/report_${ip}.html \
              /tmp/$FOLDER_NAME/ssg-amzn2-ds.xml"

            echo "[DONE] Final report generated successfully."

            echo "[SCP] Copying report to $REPORT_DEST..."
            scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip:/tmp/$FOLDER_NAME/report_${ip}.html" "$REPORT_DEST/report_${ip}.html"

            echo "[CLEANUP] Removing report from remote server..."
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo rm -f /tmp/$FOLDER_NAME/report_${ip}.html"

            echo "[OK] Completed for $ip"
        else
            echo "[FAIL] SSH failed for $ip"
        fi
    fi
done

# Amazon Linux 2023 - OpenSCAP Scan Section
SSH_KEY="${SSH_KEY_FROM_JENKINS:-/home/khushi.m/key.pem}"
REPORT_DEST="${SCRIPT_DIR}/openscap_reports"
mkdir -p "$REPORT_DEST"
FOLDER_NAME="customAmazon2023"

echo ""
echo "[INFO] Starting OpenSCAP for Amazon Linux 2023 instances..."

tail -n +2 "$FINAL_SSM_FILE" | while IFS=, read -r name ip platform version; do
    platform=$(echo "$platform" | tr -d '"')
    version=$(echo "$version" | tr -d '"')

    if [[ "$platform" == "Amazon Linux" && "$version" == "2023" ]]; then
        echo "[TRY] $name ($ip) - Amazon Linux 2023"

         # --- ADD THE NEW LOGIC BLOCK HERE ---
        if [[ "$platform" == "Ubuntu" ]]; then
            SSH_USER="ubuntu"
        elif [[ "$platform" == "Amazon Linux" || "$platform" == "Red Hat Enterprise Linux" ]]; then
            SSH_USER="ec2-user"
        elif [[ "$platform" == "CentOS Linux" ]]; then
            SSH_USER="centos"
        else
            echo "[WARN] Could not determine SSH user for platform: $platform. Skipping."
            continue
        fi
        # --- END OF LOGIC BLOCK ---

        # SSH connectivity check
        if ssh -n -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip" "echo SSH successful"; then
            echo "[OK] SSH successful to $ip as $SSH_USER"
        else
            echo "[ERROR] SSH failed to $ip"
            continue
        fi

        # Ensure OpenSCAP is installed
        echo "[CHECK] Ensuring OpenSCAP is installed on $ip..."
        ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo yum install -y openscap-scanner" >/dev/null 2>&1

        echo "[COPY] Copying folder $FOLDER_NAME to $ip:/tmp/ ..."
        scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -r "${SCRIPT_DIR}/profiles/$FOLDER_NAME" "$SSH_USER@$ip:/tmp/" || {
            echo "[ERROR] Failed to copy files to $ip"
            continue
        }

        echo "[INFO] Files in /tmp/$FOLDER_NAME:"
        ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "ls -1 /tmp/$FOLDER_NAME" || true

        echo "[SCAN] Running temporary OpenSCAP scan (Precheck)..."
        SCAN_OUTPUT=$(ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo oscap xccdf eval \
            --profile xccdf_org.ssgproject.content_profile_standard \
            --tailoring-file /tmp/$FOLDER_NAME/tailoring-file2023.xml \
            --report /tmp/$FOLDER_NAME/precheck_${ip}.html \
            /tmp/$FOLDER_NAME/ssg-al2023-ds.xml" 2>&1)

        echo "[INFO] Precheck completed for $ip"

        echo "[PARSE] Checking for failed/notapplicable rules..."
        FAIL_RULES=$(echo "$SCAN_OUTPUT" | awk '
            /Rule/ {rule=$2}
            /Result/ {if ($2=="fail" || $2=="notapplicable") {print rule ":" $2}}
        ')

        if [[ -z "$FAIL_RULES" ]]; then
            echo "[OK] No failed or notapplicable rules found. Skipping patching."
        else
            echo "[FAILED RULES FOUND]"
            echo "$FAIL_RULES"
            echo "[INFO] Disabling failing rules in BOTH files..."

            for rule in $(echo "$FAIL_RULES" | cut -d':' -f1); do
                echo "[PATCH] Disabling rule: $rule"
                ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo sed -i 's|\(<[^>]*idref=\"$rule\"[^>]*selected=\)\"true\"|\1\"false\"|' /tmp/$FOLDER_NAME/tailoring-file2023.xml"
                ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo sed -i 's|\(<[^>]*idref=\"$rule\"[^>]*selected=\)\"true\"|\1\"false\"|' /tmp/$FOLDER_NAME/ssg-al2023-ds.xml"
                # Verification
                ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "grep \"$rule\" /tmp/$FOLDER_NAME/tailoring-file2023.xml | head -1"
                ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "grep \"$rule\" /tmp/$FOLDER_NAME/ssg-al2023-ds.xml | head -1"
            done

            echo "[INFO] All failed/notapplicable rules disabled in BOTH files."
        fi

        echo "[INFO] Removing old report and generating final report..."
        ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo rm -f /tmp/$FOLDER_NAME/report_${ip}.html"
        
        FINAL_SCAN=$(ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo oscap xccdf eval \
            --profile xccdf_org.ssgproject.content_profile_standard \
            --tailoring-file /tmp/$FOLDER_NAME/tailoring-file2023.xml \
            --report /tmp/$FOLDER_NAME/report_${ip}.html \
            /tmp/$FOLDER_NAME/ssg-al2023-ds.xml" 2>&1)

        echo "[DONE] Final report generated successfully."

        # Check if all rules passed
        FAILED_AFTER=$(echo "$FINAL_SCAN" | awk '/Result/ {if ($2!="pass") print $2}')
        if [[ -z "$FAILED_AFTER" ]]; then
            echo "[SUCCESS] Scan is 100% successful for $ip."
        else
            echo "[ERROR] Scan NOT 100% successful. Check report for details."
        fi

        echo "[SCP] Copying report to $REPORT_DEST..."
        mkdir -p "$REPORT_DEST"
        if scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip:/tmp/$FOLDER_NAME/report_${ip}.html" "$REPORT_DEST/report_${ip}.html"; then
            echo "[CLEANUP] Removing report from remote server..."
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo rm -f /tmp/$FOLDER_NAME/report_${ip}.html"
            echo "[OK] Completed for $ip"
        else
            echo "[ERROR] Failed to copy report for $ip. Remote report retained for debugging."
        fi
        echo "====================================================="
    fi
done

SSH_KEY="${SSH_KEY_FROM_JENKINS:-/home/khushi.m/key.pem}"
REPORT_DEST="${SCRIPT_DIR}/openscap_reports"
mkdir -p "$REPORT_DEST"
FOLDER_NAME="customUbuntu2204"

echo ""
echo "[INFO] Starting OpenSCAP for Ubuntu 22.04 instances..."

tail -n +2 "$FINAL_SSM_FILE" | while IFS=',' read -r name ip platform version; do
    platform=$(echo "$platform" | tr -d '"')
    version=$(echo "$version" | tr -d '"')

    if [[ "$platform" == "Ubuntu" && "$version" == "22.04" ]]; then
        echo "[TRY] $name ($ip) - Ubuntu 22.04"
        
        if [[ "$platform" == "Ubuntu" ]]; then
            SSH_USER="ubuntu"
        elif [[ "$platform" == "Amazon Linux" || "$platform" == "Red Hat Enterprise Linux" ]]; then
            SSH_USER="ec2-user"
        elif [[ "$platform" == "CentOS Linux" ]]; then
            SSH_USER="centos"
        else
            echo "[WARN] Could not determine SSH user for platform: $platform. Skipping."
            continue
        fi
        # --- END OF LOGIC BLOCK ---

        if ssh -vvv -n -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip" "echo SSH successful"; then
            echo "[OK] SSH successful to $ip as $SSH_USER"

            echo "[COPY] Copying folder $FOLDER_NAME to $ip:/tmp/ ..."
            scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -r "${SCRIPT_DIR}/profiles/$FOLDER_NAME" "$SSH_USER@$ip:/tmp/"

            echo "[INFO] Files in /tmp/$FOLDER_NAME:"
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "ls -1 /tmp/$FOLDER_NAME"

            LOOP_COUNT=1
            PREV_FAIL_LOG="/tmp/prev_fail_${ip}.log"
            CURRENT_FAIL_LOG="/tmp/current_fail_${ip}.log"

            > "$PREV_FAIL_LOG"  # clear old log if exists

            while true; do
                echo ""
                echo "[SCAN] Running OpenSCAP Precheck (Iteration $LOOP_COUNT) on $ip..."

                SCAN_OUTPUT=$(ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" \
                "sudo oscap xccdf eval \
                  --profile xccdf_org.ssgproject.content_profile_standard_customized \
                  --tailoring-file /tmp/$FOLDER_NAME/tailoring-xccdf.xml \
                  --tailoring-id xccdf_org.ssgproject.content_tailoring_ubuntu2204_pass_only \
                  --report /tmp/$FOLDER_NAME/precheck_${ip}.html \
                  /tmp/$FOLDER_NAME/ssg-ubuntu2204-ds.xml")

                echo "$SCAN_OUTPUT" > "$CURRENT_FAIL_LOG.raw"

                FAIL_RULES=$(echo "$SCAN_OUTPUT" | awk '
                    /Rule/ {rule=$2}
                    /Result/ {
                        if ($2=="fail" || $2=="notchecked" || $2=="notapplicable") {
                            print rule ":" $2
                        }
                    }')

                if [[ -z "$FAIL_RULES" ]]; then
                    echo "[OK] All rules passed on $ip!"
                    break
                fi

                COUNT=$(echo "$FAIL_RULES" | wc -l)
                echo "[FAIL] Found $COUNT failing/notchecked/notapplicable rules:"
                echo "$FAIL_RULES"

                echo "$FAIL_RULES" > "$CURRENT_FAIL_LOG"

                echo "[PATCH] Applying fixes..."
                for entry in $FAIL_RULES; do
                    rule=$(echo "$entry" | cut -d: -f1)

                    if grep -q "$rule" "$PREV_FAIL_LOG"; then
                        echo "[DELETE] Rule $rule still failing after previous patch. Removing completely..."
                        ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "
                            sudo sed -i '/idref=\"$rule\"/d' /tmp/$FOLDER_NAME/ssg-ubuntu2204-ds.xml &&
                            sudo sed -i '/id=\"$rule\"/d' /tmp/$FOLDER_NAME/tailoring-xccdf.xml
                        "
                    else
                        echo "[PATCH] Disabling $rule (selected=false)..."
                        ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "
                            sudo sed -i 's|\\(idref=\"$rule\" selected=\\\"\\)[^\"]*\\\"|\\1false\\\"|g' /tmp/$FOLDER_NAME/ssg-ubuntu2204-ds.xml &&
                            sudo sed -i 's|\\(idref=\"$rule\" selected=\\\"\\)[^\"]*\\\"|\\1false\\\"|g' /tmp/$FOLDER_NAME/tailoring-xccdf.xml
                        "
                    fi
                done

                cp "$CURRENT_FAIL_LOG" "$PREV_FAIL_LOG"
                LOOP_COUNT=$((LOOP_COUNT + 1))
                sleep 2
            done

            echo "[INFO] Generating final OpenSCAP report for $ip..."
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo rm -f /tmp/$FOLDER_NAME/report_${ip}.html"
            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" \
            "sudo oscap xccdf eval \
              --profile xccdf_org.ssgproject.content_profile_standard_customized \
              --tailoring-file /tmp/$FOLDER_NAME/tailoring-xccdf.xml \
              --tailoring-id xccdf_org.ssgproject.content_tailoring_ubuntu2204_pass_only \
              --report /tmp/$FOLDER_NAME/report_${ip}.html \
              /tmp/$FOLDER_NAME/ssg-ubuntu2204-ds.xml"

            echo "[SCP] Copying final report to $REPORT_DEST..."
            scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$ip:/tmp/$FOLDER_NAME/report_${ip}.html" "$REPORT_DEST/report_${ip}.html"

            ssh -n -i "$SSH_KEY" "$SSH_USER@$ip" "sudo rm -f /tmp/$FOLDER_NAME/report_${ip}.html"
            echo "[OK] Completed for $ip"
        else
            echo "[FAIL] SSH failed for $ip"
        fi
    fi
done
