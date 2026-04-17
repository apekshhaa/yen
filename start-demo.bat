@echo off
echo.
echo 🚀 Starting Major Project Demo...
echo.

REM Start backend
echo [1/2] Starting Backend API ^(port 8000^)...
call venv\Scripts\Activate.bat
start "Major Project API" cmd /k python -m uvicorn api:app --reload --port 8000

REM Wait for backend to start
timeout /t 3 /nobreak

REM Start frontend
echo [2/2] Starting Frontend Dashboard ^(port 5173^)...
cd frontend
start "Major Project Dashboard" cmd /k npm run dev

echo.
echo.
echo ✅ Both services started in separate windows!
echo.
echo 📊 Dashboard: http://localhost:5173
echo 🔌 API: http://localhost:8000
echo.
echo Close each window to stop the respective service.
echo.
cd ..
