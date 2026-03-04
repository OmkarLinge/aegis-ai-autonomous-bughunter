#!/usr/bin/env python3
"""
Aegis AI — Unified Launcher
Starts the FastAPI backend server.
"""
import sys
import os
from pathlib import Path

# Ensure project root is on path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

def check_dependencies():
    """Check that required packages are available."""
    required = {
        'fastapi': 'pip install fastapi',
        'uvicorn': 'pip install uvicorn[standard]',
        'pydantic': 'pip install pydantic',
        'bs4': 'pip install beautifulsoup4',
        'sklearn': 'pip install scikit-learn',
        'numpy': 'pip install numpy',
    }
    missing = []
    for pkg, install in required.items():
        try:
            __import__(pkg)
        except ImportError:
            missing.append(f"  {pkg}  →  {install}")

    if missing:
        print("❌ Missing required packages:")
        print('\n'.join(missing))
        print("\nInstall all at once:")
        print("  pip install -r backend/requirements.txt")
        sys.exit(1)

def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║             AEGIS AI — Autonomous Bug Hunter              ║
║         Agentic Security Research Platform v1.0           ║
╚═══════════════════════════════════════════════════════════╝

⚠️  AUTHORIZED USE ONLY: Only scan systems you own or have
    explicit written permission to test.

""")
    check_dependencies()

    try:
        import uvicorn
        print("🚀 Starting Aegis AI backend on http://localhost:8000")
        print("📊 API docs: http://localhost:8000/api/docs")
        print("🖥️  Frontend: http://localhost:5173 (run separately with npm run dev)")
        print("\nPress Ctrl+C to stop\n")
        uvicorn.run(
            "backend.main:app",
            host="0.0.0.0",
            port=8000,
            reload=False,
            log_level="info",
        )
    except KeyboardInterrupt:
        print("\n\nAegis AI stopped.")

if __name__ == "__main__":
    main()
