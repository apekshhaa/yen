# Major-Project AI Pentester - Build and Deploy Guide

## Prerequisites

1. Docker installed and running
2. AWS CLI configured with ECR access
3. kubectl configured with cluster access
4. Helm 3.x installed

## Step 1: Build Docker Image

### Build locally
```bash
cd agents/major-project

# Build the image
docker build -t major-project:latest .

# Tag for ECR
docker tag major-project:latest 457710302499.dkr.ecr.eu-west-2.amazonaws.com/sre/major-project:latest
docker tag major-project:latest 457710302499.dkr.ecr.eu-west-2.amazonaws.com/sre/major-project:0.0.1
```

### Push to ECR
```bash
# Login to ECR
aws ecr get-login-password --region eu-west-2 | docker login --username AWS --password-stdin 457710302499.dkr.ecr.eu-west-2.amazonaws.com

# Create ECR repository if it doesn't exist
aws ecr create-repository --repository-name sre/major-project --region eu-west-2 || true

# Push images
docker push 457710302499.dkr.ecr.eu-west-2.amazonaws.com/sre/major-project:latest
docker push 457710302499.dkr.ecr.eu-west-2.amazonaws.com/sre/major-project:0.0.1
```

## Step 2: Create Kubernetes Secrets

The agent requires these secrets in the `agentex` namespace:

```bash
# Create namespace if it doesn't exist
kubectl create namespace agentex || true

# Create secrets
kubectl create secret generic agents-major-project \
  --from-literal=LITELLM_API_KEY='your-litellm-api-key' \
  --from-literal=AGENTEX_BASE_URL='http://agentex.agentex.svc.cluster.local:5003' \
  --from-literal=AGENT_API_KEY='your-agent-api-key' \
  --namespace agentex \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Step 3: Deploy with Helm

### Install Helm dependencies
```bash
cd chart/major-project

# Update dependencies
helm dependency update
```

### Deploy to QA
```bash
# Install or upgrade
helm upgrade --install major-project . \
  --namespace agentex \
  --create-namespace \
  --values values.qa.yaml \
  --set global.image.tag=latest \
  --wait \
  --timeout 10m
```

### Deploy to Production
```bash
helm upgrade --install major-project . \
  --namespace agentex \
  --create-namespace \
  --values values.yaml \
  --set global.image.tag=0.0.1 \
  --wait \
  --timeout 10m
```

## Step 4: Verify Deployment

### Check pods
```bash
kubectl get pods -n agentex -l app.kubernetes.io/name=major-project
```

### Check logs
```bash
# Temporal worker logs
kubectl logs -n agentex -l app.kubernetes.io/name=major-project-temporal-worker --tail=100 -f

# Service logs (if ACP server is enabled)
kubectl logs -n agentex -l app.kubernetes.io/name=major-project --tail=100 -f
```

### Check services
```bash
kubectl get svc -n agentex -l app.kubernetes.io/name=major-project
```

## Step 5: Test the Agent

### Using AgentEx UI
1. Navigate to AgentEx UI: http://agentex.dhhmena.com
2. Create a new task for "major-project" agent
3. Send target scope configuration:

```json
{
  "target_scope": {
    "domains": ["example.com"],
    "ip_ranges": [],
    "excluded_hosts": [],
    "authorized_until": "2024-12-31T23:59:59Z",
    "rules_of_engagement": "Testing only, no DoS"
  },
  "scan_type": "light"
}
```

### Using Temporal UI
1. Navigate to Temporal UI: http://temporal.dhhmena.com
2. Check workflow executions in "default" namespace
3. Monitor task queue: "major-project-queue"

## Troubleshooting

### Pod not starting
```bash
# Describe pod
kubectl describe pod -n agentex -l app.kubernetes.io/name=major-project-temporal-worker

# Check events
kubectl get events -n agentex --sort-by='.lastTimestamp'
```

### Image pull errors
```bash
# Verify ECR repository exists
aws ecr describe-repositories --repository-names sre/major-project --region eu-west-2

# Check image exists
aws ecr list-images --repository-name sre/major-project --region eu-west-2
```

### Worker not connecting to Temporal
```bash
# Check Temporal service
kubectl get svc -n agentex agentex-temporal-frontend

# Test connectivity from pod
kubectl exec -it -n agentex <pod-name> -- nc -zv agentex-temporal-frontend 7233
```

### Missing secrets
```bash
# List secrets
kubectl get secrets -n agentex | grep major-project

# Describe secret
kubectl describe secret agents-major-project -n agentex
```

## Configuration

### Environment Variables

The agent uses these environment variables (configured in values.yaml):

- `AGENT_NAME`: "major-project"
- `WORKFLOW_NAME`: "MajorProjectWorkflow"
- `WORKFLOW_TASK_QUEUE`: "major-project-queue"
- `TEMPORAL_ADDRESS`: "agentex-temporal-frontend.agentex.svc.cluster.local:7233"
- `TEMPORAL_NAMESPACE`: "default"
- `LITELLM_API_KEY`: LiteLLM API key (from secret)
- `AGENTEX_BASE_URL`: AgentEx server URL (from secret)
- `AGENT_API_KEY`: Agent API key (from secret)

### Resource Limits

Default resource configuration:
- CPU: 250m request, 500m limit
- Memory: 250Mi request, 1Gi limit

Adjust in values.yaml if needed for your workload.

## Uninstall

```bash
# Uninstall Helm release
helm uninstall major-project --namespace agentex

# Delete secrets (optional)
kubectl delete secret agents-major-project --namespace agentex
```

## Next Steps

After successful deployment:
1. Monitor logs for any errors
2. Test with a simple target scope
3. Review findings in AgentEx UI
4. Implement multi-agent architecture (see IMPLEMENTATION_STATUS.md)
5. Add safety guardrails and approval workflows