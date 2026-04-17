#!/bin/bash

echo "🚀 Starting Major Project Demo..."
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Start backend
echo -e "${BLUE}[1/2]${NC} Starting Backend API (port 8000)..."
source venv/bin/activate
python -m uvicorn api:app --reload --port 8000 &
BACKEND_PID=$!

# Wait for backend to start
sleep 3

# Start frontend
echo -e "${BLUE}[2/2]${NC} Starting Frontend Dashboard (port 5173)..."
cd frontend
npm run dev &
FRONTEND_PID=$!

echo ""
echo -e "${GREEN}✅ Both services started!${NC}"
echo ""
echo "📊 Dashboard: http://localhost:5173"
echo "🔌 API: http://localhost:8000"
echo ""
echo "Press Ctrl+C to stop both services"
echo ""

# Wait for both processes
wait $BACKEND_PID $FRONTEND_PID
