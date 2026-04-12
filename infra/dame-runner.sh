#!/bin/bash
# Spin up a DAME/PyRIT runner on EC2 — one command, ready in ~3 minutes.
#
# Usage:
#   ./dame-runner.sh start                    # Create instance
#   ./dame-runner.sh ssh                      # SSH in
#   ./dame-runner.sh stop                     # Stop (keep data)
#   ./dame-runner.sh terminate                # Destroy everything
#   ./dame-runner.sh status                   # Check state
#
# Prerequisites:
#   - AWS CLI configured with eu-west-2 access
#   - An SSH key pair in AWS (default: deepcyber-dame)
#   - Local SSH key at ~/.ssh/deepcyber-dame.pem
#
# What it creates:
#   - t3.medium spot instance (~$0.01/hr)
#   - Python 3.11, inspect-ai, pyrit, boto3 pre-installed
#   - DAME and DASE repos cloned
#   - tmux for persistent sessions
#   - Security group allowing SSH only

set -e

INSTANCE_NAME="dame-runner"
REGION="eu-west-2"
INSTANCE_TYPE="t3.medium"
KEY_NAME="${DAME_KEY_NAME:-deepcyber-red}"
AMI="ami-0c76bd4bd302b30ec"  # Amazon Linux 2023 eu-west-2 (update if stale)
SECURITY_GROUP="dame-runner-sg"
TAG="dame-runner"
STATE_FILE="/tmp/dame-runner-instance-id"

# ── User data script (runs on first boot) ─────────────────────────
read -r -d '' USER_DATA << 'BOOTSTRAP' || true
#!/bin/bash
set -e

# System packages
dnf install -y python3.11 python3.11-pip git tmux

# Python alias
alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.11 1

# Install frameworks
pip3 install inspect-ai pyrit boto3 httpx

# Clone repos
mkdir -p /home/ec2-user/dame /home/ec2-user/dase
cd /home/ec2-user
git clone https://github.com/deepcyber-ai/dame.git dame || true
git clone https://github.com/deepcyber-ai/dase.git dase || true

# Install as editable
cd /home/ec2-user/dame && pip3 install -e . 2>/dev/null || true
cd /home/ec2-user/dase && pip3 install -e . 2>/dev/null || true

# Convenience script
cat > /home/ec2-user/run-dame.sh << 'EOF'
#!/bin/bash
# Quick DAME run — edit and execute
# Attacker: Bedrock Qwen 235B
# Target: Gemini 2.5 Flash (or set TARGET_URL for target via tunnel)

cd /home/ec2-user/dame

inspect eval src/dame/task.py@dame \
  --model bedrock/qwen.qwen3-235b-a22b-2507-v1:0 \
  -T dataset_path=datasets/financial_advisor.jsonl \
  -T target_model=google/gemini-2.5-flash \
  -T strategy=crescendo_10 \
  -T judge_model=openai/gpt-4.1 \
  --max-connections 8 \
  --log-dir results/

echo "Done. Results in results/"
EOF
chmod +x /home/ec2-user/run-dame.sh

# Fix ownership
chown -R ec2-user:ec2-user /home/ec2-user

echo "DAME runner ready" > /home/ec2-user/READY
BOOTSTRAP

ensure_security_group() {
    # Create SG if it doesn't exist
    local sg_id
    sg_id=$(aws ec2 describe-security-groups \
        --region "$REGION" \
        --filters "Name=group-name,Values=$SECURITY_GROUP" \
        --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null)

    if [ "$sg_id" = "None" ] || [ -z "$sg_id" ]; then
        echo "Creating security group..." >&2
        sg_id=$(aws ec2 create-security-group \
            --region "$REGION" \
            --group-name "$SECURITY_GROUP" \
            --description "DAME runner - SSH only" \
            --query 'GroupId' --output text)

        aws ec2 authorize-security-group-ingress \
            --region "$REGION" \
            --group-id "$sg_id" \
            --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
        echo "Security group created: $sg_id" >&2
    fi
    echo "$sg_id"
}

get_instance_id() {
    if [ -f "$STATE_FILE" ]; then
        cat "$STATE_FILE"
    else
        aws ec2 describe-instances \
            --region "$REGION" \
            --filters "Name=tag:Name,Values=$TAG" "Name=instance-state-name,Values=running,stopped" \
            --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null
    fi
}

case "${1:-help}" in
    start)
        EXISTING=$(get_instance_id)
        if [ -n "$EXISTING" ] && [ "$EXISTING" != "None" ]; then
            STATE=$(aws ec2 describe-instances --region "$REGION" \
                --instance-ids "$EXISTING" \
                --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)
            if [ "$STATE" = "stopped" ]; then
                echo "Starting existing instance $EXISTING..."
                aws ec2 start-instances --region "$REGION" --instance-ids "$EXISTING" > /dev/null
                aws ec2 wait instance-running --region "$REGION" --instance-ids "$EXISTING"
                IP=$(aws ec2 describe-instances --region "$REGION" \
                    --instance-ids "$EXISTING" \
                    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
                echo "Running at $IP"
                echo "SSH: ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$IP"
                exit 0
            elif [ "$STATE" = "running" ]; then
                IP=$(aws ec2 describe-instances --region "$REGION" \
                    --instance-ids "$EXISTING" \
                    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
                echo "Already running at $IP"
                echo "SSH: ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$IP"
                exit 0
            fi
        fi

        echo "Launching DAME runner..."
        SG_ID=$(ensure_security_group)

        INSTANCE_ID=$(aws ec2 run-instances \
            --region "$REGION" \
            --image-id "$AMI" \
            --instance-type "$INSTANCE_TYPE" \
            --key-name "$KEY_NAME" \
            --security-group-ids "$SG_ID" \
            --instance-market-options '{"MarketType":"spot","SpotOptions":{"SpotInstanceType":"persistent","InstanceInterruptionBehavior":"stop"}}' \
            --user-data "$USER_DATA" \
            --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG}]" \
            --query 'Instances[0].InstanceId' --output text)

        echo "$INSTANCE_ID" > "$STATE_FILE"
        echo "Instance: $INSTANCE_ID"
        echo "Waiting for running state..."

        aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"

        IP=$(aws ec2 describe-instances --region "$REGION" \
            --instance-ids "$INSTANCE_ID" \
            --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

        echo ""
        echo "DAME runner ready at $IP"
        echo "SSH:  ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$IP"
        echo ""
        echo "First time setup (~3 min for packages to install):"
        echo "  1. ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$IP"
        echo "  2. Wait for /home/ec2-user/READY file to appear"
        echo "  3. Set API keys: export OPENAI_API_KEY=... GOOGLE_API_KEY=..."
        echo "  4. tmux new -s dame"
        echo "  5. ./run-dame.sh"
        ;;

    ssh)
        ID=$(get_instance_id)
        IP=$(aws ec2 describe-instances --region "$REGION" \
            --instance-ids "$ID" \
            --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
        exec ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$IP
        ;;

    stop)
        ID=$(get_instance_id)
        echo "Stopping $ID (data preserved)..."
        aws ec2 stop-instances --region "$REGION" --instance-ids "$ID" > /dev/null
        echo "Stopped. Cost: $0 while stopped. Run './dame-runner.sh start' to resume."
        ;;

    terminate)
        ID=$(get_instance_id)
        echo "Terminating $ID..."
        aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" > /dev/null
        rm -f "$STATE_FILE"
        echo "Terminated."
        ;;

    status)
        ID=$(get_instance_id)
        if [ -z "$ID" ] || [ "$ID" = "None" ]; then
            echo "No DAME runner found"
            exit 0
        fi
        aws ec2 describe-instances --region "$REGION" \
            --instance-ids "$ID" \
            --query 'Reservations[0].Instances[0].{State:State.Name,IP:PublicIpAddress,Type:InstanceType,Launch:LaunchTime}' \
            --output table
        ;;

    *)
        echo "Usage: $0 {start|ssh|stop|terminate|status}"
        echo ""
        echo "  start      Launch or resume the DAME runner (~\$0.01/hr spot)"
        echo "  ssh        SSH into the runner"
        echo "  stop       Stop instance (data preserved, zero cost)"
        echo "  terminate  Destroy instance"
        echo "  status     Check instance state"
        ;;
esac
