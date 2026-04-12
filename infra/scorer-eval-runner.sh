#!/bin/bash
# Spin up a scorer evaluation runner on EC2 — DAME + DASE + AIRT Harness.
#
# Usage:
#   ./scorer-eval-runner.sh start               # Create instance
#   ./scorer-eval-runner.sh ssh                 # SSH in
#   ./scorer-eval-runner.sh stop                # Stop (keep data)
#   ./scorer-eval-runner.sh terminate           # Destroy everything
#   ./scorer-eval-runner.sh status              # Check state
#   ./scorer-eval-runner.sh sync-results        # Download results to local
#
# Prerequisites:
#   - AWS CLI configured with eu-west-2 access
#   - Bedrock model access enabled (Sonnet 4.6, Opus 4.6, Llama 3.3 70B)
#   - An SSH key pair in AWS (default: deepcyber-red)
#   - Local SSH key at ~/.ssh/deepcyber-red.pem
#
# What it creates:
#   - t3.medium spot instance (~$0.01/hr) — CPU only, no GPU needed
#   - Python 3.11, inspect-ai, airt-harness, boto3 pre-installed
#   - DAME and DASE repos cloned and installed
#   - All API calls go through Bedrock (ZDR, no data retention)

set -e

S3_BUCKET="${AIRT_S3_BUCKET:-deepcyber-airt-results}"
INSTANCE_NAME="scorer-eval-runner"
REGION="eu-west-2"
INSTANCE_TYPE="t3.medium"
KEY_NAME="${DAME_KEY_NAME:-deepcyber-red}"
AMI="ami-0c76bd4bd302b30ec"  # Amazon Linux 2023 eu-west-2
SECURITY_GROUP="dame-runner-sg"
TAG="scorer-eval-runner"
STATE_FILE="/tmp/scorer-eval-runner-id"

# ── User data script (runs on first boot) ─────────────────────────
read -r -d '' USER_DATA << 'BOOTSTRAP' || true
#!/bin/bash
set -e

# System packages
dnf install -y python3.11 python3.11-pip git tmux docker

# Python alias
alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.11 1

# Start Docker (for airt-harness container)
systemctl enable docker
systemctl start docker
usermod -aG docker ec2-user

# Install frameworks
pip3 install inspect-ai boto3 airt-harness

# Clone repos
cd /home/ec2-user
git clone https://github.com/deepcyber-ai/airt.git deepcyber-airt || true
git clone https://github.com/deepcyber-ai/airt-harness.git airt-harness || true

# Install DAME and DASE as editable
cd /home/ec2-user/deepcyber-airt/dame && pip3 install -e . 2>/dev/null || true
cd /home/ec2-user/deepcyber-airt/dase && pip3 install -e . 2>/dev/null || true

# Pull harness Docker image
docker pull deepcyberx/airt-harness:1.3.0 || true

# Create convenience scripts
cat > /home/ec2-user/run-scorer-eval.sh << 'EOF'
#!/bin/bash
# Full scorer evaluation pipeline
# Edit the variables below before running

set -e

# ── Config ────────────────────────────────────────────────────────
PROFILE="deepvault-agentic"      # or "mediguide"
DATASET="datasets/deepvault_agentic.jsonl"
ATTACKER="bedrock/anthropic.claude-sonnet-4-6"
STRATEGY="crescendo_5"
RESULTS_DIR="results/${PROFILE}"

echo "=== Scorer Evaluation Pipeline ==="
echo "Profile:  $PROFILE"
echo "Dataset:  $DATASET"
echo "Attacker: $ATTACKER"
echo "Strategy: $STRATEGY"
echo

# ── Step 1: Start harness ─────────────────────────────────────────
echo "[Step 1] Starting harness with $PROFILE profile..."
cd ~/airt-harness
export GOOGLE_API_KEY="${GOOGLE_API_KEY:-}"
MOCK_BACKEND=echo airt-launch "$PROFILE"
sleep 5

# ── Step 2: Run DAME ──────────────────────────────────────────────
echo "[Step 2] Running DAME (attacker: $ATTACKER, strategy: $STRATEGY)..."
cd ~/deepcyber-airt/dame
mkdir -p "$RESULTS_DIR"

inspect eval src/dame/task.py \
  --model "$ATTACKER" \
  -T target_model=openai/target \
  -T target_base_url=http://localhost:8000/v1 \
  -T dataset_path="$DATASET" \
  -T strategy="$STRATEGY" \
  --log-dir "$RESULTS_DIR/"

echo "DAME complete. Results in $RESULTS_DIR/"

# ── Step 3: Ingest into DASE format ───────────────────────────────
echo "[Step 3] Ingesting DAME results..."
cd ~/deepcyber-airt/dase

LATEST_EVAL=$(ls -t ~/deepcyber-airt/dame/$RESULTS_DIR/*.eval 2>/dev/null | head -1)
if [ -z "$LATEST_EVAL" ]; then
  echo "ERROR: No .eval files found in dame/$RESULTS_DIR/"
  exit 1
fi

python3 tools/ingest_dame.py \
  --input "$LATEST_EVAL" \
  --output "datasets/${PROFILE}_from_dame.jsonl"

echo "Ingested: datasets/${PROFILE}_from_dame.jsonl"

# ── Step 4: Panel consensus ──────────────────────────────────────
echo "[Step 4] Running panel consensus (Sonnet + Opus + Llama)..."

python3 tools/run_panel.py \
  --input "datasets/${PROFILE}_from_dame.jsonl" \
  --output "datasets/${PROFILE}_panel.jsonl" \
  --delay 2

echo "Panel labels: datasets/${PROFILE}_panel.jsonl"

# ── Step 5: Evaluate scorers ─────────────────────────────────────
echo "[Step 5] Evaluating scorers..."

# Opus (leave-one-out)
echo "  Evaluating Opus 4.6..."
python3 tools/run_panel.py \
  --input "datasets/${PROFILE}_from_dame.jsonl" \
  --output "datasets/${PROFILE}_panel_no_opus.jsonl" \
  --exclude opus-4.6 \
  --delay 2

inspect eval src/dase/task.py \
  --model bedrock/anthropic.claude-opus-4-6-v1 \
  -T dataset_path="datasets/${PROFILE}_panel_no_opus.jsonl" \
  --log-dir "results/${PROFILE}-scorers/"

# Llama (leave-one-out)
echo "  Evaluating Llama 3.3 70B..."
python3 tools/run_panel.py \
  --input "datasets/${PROFILE}_from_dame.jsonl" \
  --output "datasets/${PROFILE}_panel_no_llama.jsonl" \
  --exclude llama-3.3-70b \
  --delay 2

inspect eval src/dase/task.py \
  --model bedrock/meta.llama3-3-70b-instruct-v1:0 \
  -T dataset_path="datasets/${PROFILE}_panel_no_llama.jsonl" \
  --log-dir "results/${PROFILE}-scorers/"

# GPT-5.4 (not a panel member — use full panel)
echo "  Evaluating GPT-5.4..."
inspect eval src/dase/task.py \
  --model openai/gpt-5.4 \
  -T dataset_path="datasets/${PROFILE}_panel.jsonl" \
  --log-dir "results/${PROFILE}-scorers/"

# Gemini Flash (not a panel member)
echo "  Evaluating Gemini 2.5 Flash..."
inspect eval src/dase/task.py \
  --model google/gemini-2.5-flash \
  -T dataset_path="datasets/${PROFILE}_panel.jsonl" \
  --log-dir "results/${PROFILE}-scorers/"

echo
echo "=== Complete ==="

# ── Step 6: Push to S3 ────────────────────────────────────────────
S3_BUCKET="${AIRT_S3_BUCKET:-deepcyber-airt-results}"
RUN_ID="$(date +%Y-%m-%d)-${PROFILE}-$(echo $ATTACKER | tr '/' '-')-${STRATEGY}"

echo "[Step 6] Pushing results to s3://$S3_BUCKET/$RUN_ID/ ..."

# Save run config for reproducibility
cat > "/tmp/run-${RUN_ID}.yaml" << RUNYAML
run_id: "$RUN_ID"
timestamp: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
profile: "$PROFILE"
attacker: "$ATTACKER"
strategy: "$STRATEGY"
dataset: "$DATASET"
harness_commit: "$(cd ~/airt-harness && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
dame_commit: "$(cd ~/deepcyber-airt/dame && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
dase_commit: "$(cd ~/deepcyber-airt/dase && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
RUNYAML

aws s3 cp "/tmp/run-${RUN_ID}.yaml" "s3://$S3_BUCKET/$RUN_ID/run.yaml"
aws s3 sync ~/deepcyber-airt/dame/$RESULTS_DIR/ "s3://$S3_BUCKET/$RUN_ID/dame/" --exclude "*.pyc"
aws s3 sync ~/deepcyber-airt/dase/results/${PROFILE}-scorers/ "s3://$S3_BUCKET/$RUN_ID/dase-scorers/" --exclude "*.pyc" 2>/dev/null || true
aws s3 cp ~/deepcyber-airt/dase/datasets/${PROFILE}_panel.jsonl "s3://$S3_BUCKET/$RUN_ID/panel_labelled.jsonl" 2>/dev/null || true
aws s3 cp ~/deepcyber-airt/dase/datasets/${PROFILE}_from_dame.jsonl "s3://$S3_BUCKET/$RUN_ID/from_dame.jsonl" 2>/dev/null || true

echo "Results archived: s3://$S3_BUCKET/$RUN_ID/"
echo ""
echo "DAME results:  ~/deepcyber-airt/dame/$RESULTS_DIR/"
echo "Panel labels:  ~/deepcyber-airt/dase/datasets/${PROFILE}_panel.jsonl"
echo "Scorer evals:  ~/deepcyber-airt/dase/results/${PROFILE}-scorers/"
echo "S3 archive:    s3://$S3_BUCKET/$RUN_ID/"
echo "View results:  inspect view --log-dir ~/deepcyber-airt/dase/results/${PROFILE}-scorers/"

# Stop harness
airt-stop
EOF
chmod +x /home/ec2-user/run-scorer-eval.sh

# Fix ownership
chown -R ec2-user:ec2-user /home/ec2-user

echo "Scorer eval runner ready" > /home/ec2-user/READY
BOOTSTRAP

ensure_security_group() {
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

get_ip() {
    local id=$1
    aws ec2 describe-instances --region "$REGION" \
        --instance-ids "$id" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text
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
                echo "Running at $(get_ip $EXISTING)"
                echo "SSH: ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$(get_ip $EXISTING)"
                exit 0
            elif [ "$STATE" = "running" ]; then
                echo "Already running at $(get_ip $EXISTING)"
                echo "SSH: ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$(get_ip $EXISTING)"
                exit 0
            fi
        fi

        echo "Launching scorer eval runner..."
        SG_ID=$(ensure_security_group)

        # IAM role for Bedrock access
        INSTANCE_PROFILE="${INSTANCE_PROFILE:-}"
        IAM_ARGS=""
        if [ -n "$INSTANCE_PROFILE" ]; then
            IAM_ARGS="--iam-instance-profile Name=$INSTANCE_PROFILE"
        fi

        INSTANCE_ID=$(aws ec2 run-instances \
            --region "$REGION" \
            --image-id "$AMI" \
            --instance-type "$INSTANCE_TYPE" \
            --key-name "$KEY_NAME" \
            --security-group-ids "$SG_ID" \
            $IAM_ARGS \
            --instance-market-options '{"MarketType":"spot","SpotOptions":{"SpotInstanceType":"persistent","InstanceInterruptionBehavior":"stop"}}' \
            --user-data "$USER_DATA" \
            --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG}]" \
            --query 'Instances[0].InstanceId' --output text)

        echo "$INSTANCE_ID" > "$STATE_FILE"
        echo "Instance: $INSTANCE_ID"
        echo "Waiting for running state..."

        aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"
        IP=$(get_ip "$INSTANCE_ID")

        echo ""
        echo "Scorer eval runner ready at $IP"
        echo "SSH:  ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$IP"
        echo ""
        echo "First time setup (~3 min):"
        echo "  1. ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$IP"
        echo "  2. Wait for READY file: while [ ! -f READY ]; do sleep 5; echo waiting...; done"
        echo "  3. Set API keys:"
        echo "     export OPENAI_API_KEY=..."
        echo "     export GOOGLE_API_KEY=..."
        echo "     (Bedrock uses IAM role — no key needed if instance profile is set)"
        echo "  4. tmux new -s eval"
        echo "  5. ./run-scorer-eval.sh"
        ;;

    ssh)
        ID=$(get_instance_id)
        IP=$(get_ip "$ID")
        exec ssh -i ~/.ssh/${KEY_NAME}.pem ec2-user@$IP
        ;;

    stop)
        ID=$(get_instance_id)
        echo "Stopping $ID (data preserved)..."
        aws ec2 stop-instances --region "$REGION" --instance-ids "$ID" > /dev/null
        echo "Stopped. Cost: \$0 while stopped."
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
            echo "No scorer eval runner found"
            exit 0
        fi
        aws ec2 describe-instances --region "$REGION" \
            --instance-ids "$ID" \
            --query 'Reservations[0].Instances[0].{State:State.Name,IP:PublicIpAddress,Type:InstanceType,Launch:LaunchTime}' \
            --output table
        ;;

    sync-results)
        echo "Syncing results from S3..."
        LOCAL_RESULTS="$HOME/src/deepcyber-airt/airt-workshop/results"
        mkdir -p "$LOCAL_RESULTS"
        aws s3 sync "s3://$S3_BUCKET/" "$LOCAL_RESULTS/" --region "$REGION"
        echo "Results synced to $LOCAL_RESULTS/"
        echo ""
        echo "Browse runs:"
        ls -d "$LOCAL_RESULTS"/20* 2>/dev/null | while read d; do
            basename "$d"
        done
        ;;

    *)
        echo "Usage: $0 {start|ssh|stop|terminate|status|sync-results}"
        echo ""
        echo "  start          Launch or resume (~\$0.01/hr spot)"
        echo "  ssh            SSH into the runner"
        echo "  stop           Stop instance (data preserved, zero cost)"
        echo "  terminate      Destroy instance"
        echo "  status         Check instance state"
        echo "  sync-results   Download DAME/DASE results to local"
        ;;
esac
