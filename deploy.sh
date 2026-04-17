#!/bin/bash
set -e

# Major-Project AI Pentester - Deploy Script
# Usage: ./deploy.sh [environment] [version]

ENVIRONMENT=${1:-qa}
VERSION=${2:-latest}
NAMESPACE="agentex"
RELEASE_NAME="major-project"
CHART_DIR="chart/major-project"

echo "🚀 Deploying Major-Project AI Pentester"
echo "Environment: ${ENVIRONMENT}"
echo "Version: ${VERSION}"
echo "Namespace: ${NAMESPACE}"
echo ""

# Check if chart directory exists
if [ ! -d "${CHART_DIR}" ]; then
    echo "❌ Chart directory not found: ${CHART_DIR}"
    exit 1
fi

cd ${CHART_DIR}

# Update Helm dependencies
echo "📦 Updating Helm dependencies..."
helm dependency update

# Determine values file
if [ "${ENVIRONMENT}" == "prod" ]; then
    VALUES_FILE="values.yaml"
else
    VALUES_FILE="values.qa.yaml"
fi

echo "📋 Using values file: ${VALUES_FILE}"

# Create namespace if it doesn't exist
echo "🏗️  Ensuring namespace exists..."
kubectl create namespace ${NAMESPACE} 2>/dev/null || echo "Namespace already exists"

# Check if secrets exist
echo "🔐 Checking secrets..."
if ! kubectl get secret agents-major-project -n ${NAMESPACE} &>/dev/null; then
    echo "⚠️  Warning: Secret 'agents-major-project' not found in namespace ${NAMESPACE}"
    echo ""
    echo "Please create the secret with:"
    echo "kubectl create secret generic agents-major-project \\"
    echo "  --from-literal=LITELLM_API_KEY='your-key' \\"
    echo "  --from-literal=AGENTEX_BASE_URL='http://agentex.agentex.svc.cluster.local:5003' \\"
    echo "  --from-literal=AGENT_API_KEY='your-key' \\"
    echo "  --namespace ${NAMESPACE}"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Deploy with Helm
echo "🎯 Deploying with Helm..."
helm upgrade --install ${RELEASE_NAME} . \
  --namespace ${NAMESPACE} \
  --values ${VALUES_FILE} \
  --set global.image.tag=${VERSION} \
  --wait \
  --timeout 10m

echo ""
echo "✅ Deployment complete!"
echo ""
echo "Check status:"
echo "  kubectl get pods -n ${NAMESPACE} -l app.kubernetes.io/name=major-project-temporal-worker"
echo ""
echo "View logs:"
echo "  kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/name=major-project-temporal-worker --tail=100 -f"
echo ""
echo "Get services:"
echo "  kubectl get svc -n ${NAMESPACE} -l app.kubernetes.io/name=major-project"
echo ""
echo "Port forward (if needed):"
echo "  kubectl port-forward -n ${NAMESPACE} svc/major-project 8000:8000"