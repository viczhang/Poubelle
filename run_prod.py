#!/usr/bin/env python3
"""
Production-ready entry point for Poubelle application.
Supports both development and production modes.
"""

import os
import sys
from app import create_app

def run_development():
    """Run the application in development mode."""
    app = create_app()
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )

def run_production():
    """Run the application in production mode with gunicorn."""
    try:
        import gunicorn
    except ImportError:
        print("Gunicorn not installed. Install with: pip install gunicorn")
        print("Falling back to development server...")
        run_development()
        return
    
    # Gunicorn configuration
    workers = int(os.environ.get('GUNICORN_WORKERS', 4))
    timeout = int(os.environ.get('GUNICORN_TIMEOUT', 120))
    bind = '0.0.0.0:5000'
    
    # Run with gunicorn
    from gunicorn.app.wsgiapp import run
    sys.argv = [
        'gunicorn',
        '--bind', bind,
        '--workers', str(workers),
        '--timeout', str(timeout),
        '--worker-class', 'sync',
        '--access-logfile', '-',
        '--error-logfile', '-',
        '--log-level', 'info',
        'run:app'
    ]
    run()

if __name__ == '__main__':
    # Determine if we should run in production mode
    flask_env = os.environ.get('FLASK_ENV', 'development')
    
    if flask_env == 'production':
        run_production()
    else:
        run_development()