# ODSAF Frontend

Modern React 18 web interface for the ODSAF (Open Data Security Assessment Framework) security assessment platform.

## Features

- **Real-time Assessment Monitoring** - Live progress tracking of security assessments
- **Comprehensive Findings Explorer** - Filter and search security vulnerabilities by severity
- **Compliance Dashboard** - View compliance status against OWASP, NIST, and CIS frameworks
- **Audit Trail** - Complete activity log of all system actions
- **Dark Mode** - Professional dark theme with glassmorphism design  
- **Responsive Design** - Works seamlessly on desktop, tablet, and mobile devices
- **Modern Stack** - Built with React 18, TypeScript, Tailwind CSS, and Vite

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Start Development Server
```bash
npm run dev
```

This opens http://localhost:5173 automatically.

### 3. Connect to Backend
Ensure the ODSAF backend is running on `http://localhost:8000`. The frontend automatically proxies API calls to this address.

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Create production build
- `npm run preview` - Preview production build
- `npm run type-check` - Check TypeScript types

## Project Structure

```
src/
├── components/        # Reusable React components
├── pages/            # Full page views
├── hooks/            # Custom React hooks
├── services/         # API client
└── styles/           # Global CSS
```

## Tech Stack

- React 18 + TypeScript
- Vite (fast bundler)
- Tailwind CSS
- Zustand (state management)
- Axios (HTTP client)

## Environment Variables

Create `.env.local`:
```
VITE_API_BASE=http://localhost:8000/api
```

## Troubleshooting

**API Connection Issues**: Verify backend is running on port 8000
**Port in Use**: Change port in `vite.config.ts`
**Dependencies**: Run `npm install` again

See [FRONTEND_INTEGRATION.md](../FRONTEND_INTEGRATION.md) for complete setup guide.
