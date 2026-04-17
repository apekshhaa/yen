# Red-Cell AI Pentester - Local Development Guide

## Running Locally on Mac

### Prerequisites

1. **Docker Desktop** installed and running
2. **Python 3.12+** installed
3. **Temporal Server** running (either locally or accessible)

---

## Option 1: Run with Docker (Recommended)

### Step 1: Build the Docker Image

```bash
cd agents/red-cell

# Build the image
docker build -t red-cell:local .
```

### Step 2: Run the Temporal Worker Container

```bash
# Run with environment variables
docker run -it --rm \
  --name red-cell-worker \
  -p 8000:8000 \
  -e AGENT_NAME="red-cell" \
  -e WORKFLOW_NAME="MajorProjectWorkflow" \
  -e WORKFLOW_TASK_QUEUE="red-cell-queue" \
  -e TEMPORAL_ADDRESS="host.docker.internal:7233" \
  -e TEMPORAL_NAMESPACE="default" \
  -e LITELLM_API_KEY="your-litellm-api-key" \
  -e AGENTEX_BASE_URL="http://host.docker.internal:5003" \
  -e AGENT_API_KEY="your-agent-api-key" \
  -e OPENAI_API_KEY="your-openai-api-key" \
  red-cell:local
```

**Note**: On Mac, use `host.docker.internal` to access services running on your host machine.

### Step 3: Verify the Worker is Running

Check the logs - you should see:
```
Starting Temporal worker...
Worker started successfully
Listening on task queue: red-cell-queue
```

---

## Option 2: Run with Docker Compose (Easiest)

### Create docker-compose.yml

```yaml
version: '3.8'

services:
  red-cell-worker:
    build: .
    container_name: red-cell-worker
    ports:
      - "8000:8000"
    environment:
      - AGENT_NAME=red-cell
      - WORKFLOW_NAME=MajorProjectWorkflow
      - WORKFLOW_TASK_QUEUE=red-cell-queue
      - TEMPORAL_ADDRESS=host.docker.internal:7233
      - TEMPORAL_NAMESPACE=default
      - LITELLM_API_KEY=${LITELLM_API_KEY}
      - AGENTEX_BASE_URL=http://host.docker.internal:5003
      - AGENT_API_KEY=${AGENT_API_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    restart: unless-stopped
```

### Create .env file

```bash
# .env
LITELLM_API_KEY=your-litellm-api-key
AGENT_API_KEY=your-agent-api-key
OPENAI_API_KEY=your-openai-api-key
```

### Run with Docker Compose

```bash
# Start the worker
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the worker
docker-compose down
```

---

## Option 3: Run Directly with Python (Development)

### Step 1: Create Virtual Environment

```bash
cd agents/red-cell

# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # On Mac/Linux
```

### Step 2: Install Dependencies

```bash
# Install the package in development mode
pip install -e .

# Or install from requirements
pip install -r requirements.txt
```

### Step 3: Set Environment Variables

```bash
export AGENT_NAME="red-cell"
export WORKFLOW_NAME="MajorProjectWorkflow"
export WORKFLOW_TASK_QUEUE="red-cell-queue"
export TEMPORAL_ADDRESS="localhost:7233"
export TEMPORAL_NAMESPACE="default"
export LITELLM_API_KEY="your-litellm-api-key"
export AGENTEX_BASE_URL="http://localhost:5003"
export AGENT_API_KEY="your-agent-api-key"
export OPENAI_API_KEY="your-openai-api-key"
```

### Step 4: Run the Worker

```bash
# Run the worker
python -m project.worker
```

---

## Running Temporal Server Locally

If you don't have Temporal running, you can start it with Docker:

```bash
# Run Temporal server
docker run -d \
  --name temporal \
  -p 7233:7233 \
  -p 8233:8233 \
  temporalio/auto-setup:latest

# Run Temporal UI (optional)
docker run -d \
  --name temporal-ui \
  -p 8080:8080 \
  --link temporal:temporal \
  -e TEMPORAL_ADDRESS=temporal:7233 \
  temporalio/ui:latest
```

Access Temporal UI at: http://localhost:8080

---

## Port Forwarding (If Connecting to Remote Cluster)

If you want to connect to a remote Temporal cluster:

```bash
# Port forward Temporal
kubectl port-forward -n agentex svc/agentex-temporal-frontend 7233:7233

# Port forward AgentEx
kubectl port-forward -n agentex svc/agentex 5003:5003
```

Then run the worker with:
```bash
docker run -it --rm \
  --name red-cell-worker \
  -p 8000:8000 \
  -e TEMPORAL_ADDRESS="host.docker.internal:7233" \
  -e AGENTEX_BASE_URL="http://host.docker.internal:5003" \
  # ... other env vars
  red-cell:local
```

---

## Testing the Agent

### 1. Using Temporal UI

1. Navigate to http://localhost:8080 (or your Temporal UI)
2. Go to "Workflows"
3. Click "Start Workflow"
4. Select workflow type: `MajorProjectWorkflow`
5. Task queue: `red-cell-queue`
6. Input:
```json
{
  "task": {
    "id": "test-task-001"
  }
}
```

### 2. Using AgentEx API

```bash
# Create a task
curl -X POST http://localhost:5003/api/tasks \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-agent-api-key" \
  -d '{
    "agent_name": "red-cell",
    "input": {
      "target_scope": {
        "domains": ["example.com"],
        "ip_ranges": [],
        "rules_of_engagement": "Testing only"
      },
      "scan_type": "light"
    }
  }'
```

---

## Development Workflow

### 1. Make Code Changes

Edit files in `agents/red-cell/project/`

### 2. Rebuild Docker Image

```bash
docker build -t red-cell:local .
```

### 3. Restart Container

```bash
# If using docker run
docker stop red-cell-worker
docker run -it --rm ... red-cell:local

# If using docker-compose
docker-compose restart
```

### 4. View Logs

```bash
# Docker run
docker logs -f red-cell-worker

# Docker compose
docker-compose logs -f

# Python direct
# Logs will appear in terminal
```

---

## Debugging

### Enable Debug Logging

Add to environment variables:
```bash
-e LOG_LEVEL="DEBUG"
-e PYTHONUNBUFFERED="1"
```

### Interactive Shell in Container

```bash
# Start container with shell
docker run -it --rm \
  --entrypoint /bin/bash \
  red-cell:local

# Then manually run the worker
python -m project.worker
```

### Check Container Status

```bash
# List running containers
docker ps

# Inspect container
docker inspect red-cell-worker

# Check resource usage
docker stats red-cell-worker
```

---

## Common Issues

### Issue: "Connection refused" to Temporal

**Solution**: Make sure Temporal is running and accessible:
```bash
# Test connection
nc -zv localhost 7233

# Or from inside container
docker exec -it red-cell-worker nc -zv host.docker.internal 7233
```

### Issue: "Module not found" errors

**Solution**: Rebuild the Docker image:
```bash
docker build --no-cache -t red-cell:local .
```

### Issue: Port already in use

**Solution**: Stop the conflicting container:
```bash
docker ps
docker stop <container-id>
```

### Issue: Environment variables not set

**Solution**: Check they're passed correctly:
```bash
docker exec -it red-cell-worker env | grep AGENT_NAME
```

---

## Quick Reference

### Build Image
```bash
docker build -t red-cell:local .
```

### Run Worker (Simple)
```bash
docker run -it --rm \
  --name red-cell-worker \
  -p 8000:8000 \
  -e TEMPORAL_ADDRESS="host.docker.internal:7233" \
  -e OPENAI_API_KEY="your-key" \
  red-cell:local
```

### View Logs
```bash
docker logs -f red-cell-worker
```

### Stop Worker
```bash
docker stop red-cell-worker
```

### Clean Up
```bash
# Remove container
docker rm red-cell-worker

# Remove image
docker rmi red-cell:local

# Remove all stopped containers
docker container prune
```

---

## Next Steps

1. ✅ Get the worker running locally
2. ✅ Test with a simple workflow
3. ✅ Verify agents are working
4. 🔄 Implement remaining workflow states
5. 🔄 Add tool call visualization
6. 🔄 Test end-to-end multi-agent flow

---

## Support

For issues or questions:
1. Check logs: `docker logs -f red-cell-worker`
2. Verify Temporal connection: `nc -zv localhost 7233`
3. Check environment variables: `docker exec red-cell-worker env`
4. Review Temporal UI: http://localhost:8080