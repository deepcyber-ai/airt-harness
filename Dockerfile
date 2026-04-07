FROM python:3.11-slim

WORKDIR /app

# Install harness dependencies (includes gradio for GUI)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy harness package (includes gui.py)
COPY harness/ harness/

# Default profile (Deep Vault Capital -- fictional, works out of the box)
COPY profiles/default/ profiles/default/

# Expose harness, mock, and GUI ports
EXPOSE 7860 8000 8089

# Default profile and backend
ENV PROFILE=profiles/default/profile.yaml
ENV BACKEND=mock

# Startup script: mock + harness in background, GUI in foreground
COPY <<'EOF' /app/start.sh
#!/bin/sh
# Read mock backend from profile if MOCK_BACKEND env not set
if [ -z "$MOCK_BACKEND" ]; then
  MOCK_BACKEND=$(python -c "import yaml; print(yaml.safe_load(open('$PROFILE')).get('mock',{}).get('backend','echo'))" 2>/dev/null || echo "echo")
fi
echo "Starting mock server on :8089 (backend: $MOCK_BACKEND)..."
python -m harness.mock --profile "$PROFILE" --backend "$MOCK_BACKEND" --port 8089 &
sleep 1
echo "Starting harness on :8000..."
uvicorn harness.server:app --host 0.0.0.0 --port 8000 &
sleep 2
echo "Starting GUI on :7860..."
exec python -m harness.gui --url http://localhost:8000 --port 7860
EOF
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
