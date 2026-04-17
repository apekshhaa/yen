#!/bin/bash
set -e

# Major-Project AI Pentester - Build and Push Script
# Usage: ./build.sh [version]

VERSION=${1:-latest}
REGION=""
ACCOUNT_ID=""
REPOSITORY="major-project"
ECR_URL="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
IMAGE_NAME="${ECR_URL}/${REPOSITORY}"

echo "🔨 Building Major-Project AI Pentester Docker Image"
echo "Version: ${VERSION}"
echo "Repository: ${IMAGE_NAME}"
echo ""

# Build the image
echo "📦 Building Docker image..."
docker build -t major-project:${VERSION} .

# Tag for ECR
echo "🏷️  Tagging image for ECR..."
docker tag major-project:${VERSION} ${IMAGE_NAME}:${VERSION}

if [ "${VERSION}" != "latest" ]; then
    docker tag major-project:${VERSION} ${IMAGE_NAME}:latest
fi

# Login to ECR
echo "🔐 Logging in to ECR..."
aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${ECR_URL}

# Create repository if it doesn't exist
echo "📁 Ensuring ECR repository exists..."
aws ecr create-repository --repository-name ${REPOSITORY} --region ${REGION} 2>/dev/null || echo "Repository already exists"

# Push to ECR
echo "⬆️  Pushing image to ECR..."
docker push ${IMAGE_NAME}:${VERSION}

if [ "${VERSION}" != "latest" ]; then
    docker push ${IMAGE_NAME}:latest
fi

echo ""
echo "✅ Build and push complete!"
echo ""
echo "Image: ${IMAGE_NAME}:${VERSION}"
echo ""
echo "Next steps:"
echo "1. Deploy with Helm:"
echo "   cd chart/major-project"
echo "   helm upgrade --install major-project . --namespace agentex --values values.qa.yaml --set global.image.tag=${VERSION}"
echo ""
echo "2. Check deployment:"
echo "   kubectl get pods -n agentex -l app.kubernetes.io/name=major-project-temporal-worker"
echo ""
echo "3. View logs:"
echo "   kubectl logs -n agentex -l app.kubernetes.io/name=major-project-temporal-worker --tail=100 -f"
