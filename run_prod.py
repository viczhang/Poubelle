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
    app = create_app() # Create the Flask app instance
    
    # Gunicorn expects a string with the module:app_variable
    # Since we have create_app() in app/__init__.py, and run_prod.py is in /app,
    # we need to reference it as 'app:app' after we create the app instance in this module.
    # We will temporarily add 'app' to global scope for Gunicorn to find it.
    import __main__
    __main__.app = app

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
        'wsgi:app' # Reference the 'app' variable in wsgi.py
    ]
    run()

if __name__ == '__main__':
    # Determine if we should run in production mode
    flask_env = os.environ.get('FLASK_ENV', 'development')
    
    if flask_env == 'production':
        run_production()
    else:
        run_development()