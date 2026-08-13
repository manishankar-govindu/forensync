#!/usr/bin/env python3
"""
ForenSync Startup Script
Starts the Flask backend server
"""

import sys
import subprocess
import os

def check_dependencies():
    """Check and install missing dependencies"""
    required = ['flask', 'flask-sqlalchemy', 'flask-cors', 'pillow', 'reportlab', 'piexif', 'python-dotenv']
    missing = []
    
    for package in required:
        try:
            mod_name = package.replace('-', '_')
            __import__(mod_name)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"Installing missing packages: {missing}")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        print("Dependencies installed successfully!")

def main():
    """Main startup function"""
    print("=" * 50)
    print("ForenSync - Digital Forensics Platform")
    print("=" * 50)
    
    # Check dependencies
    check_dependencies()
    
    # Get paths
    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, 'backend')
    
    if not os.path.exists(backend_dir):
        print(f"Error: Backend directory not found at {backend_dir}")
        sys.exit(1)
    
    print(f"\nRoot directory: {root_dir}")
    print(f"Backend directory: {backend_dir}")
    
    # Add both directories to Python path
    sys.path.insert(0, root_dir)
    sys.path.insert(0, backend_dir)
    
    # Change to root directory (NOT backend) to avoid restart issues
    os.chdir(root_dir)
    print(f"Working directory: {os.getcwd()}")
    
    # Set environment variable to tell app where it is
    os.environ['FORENSYNC_ROOT'] = root_dir
    
    # Start the Flask app
    print("\nStarting Flask server...")
    print("Open your browser to: http://127.0.0.1:5000")
    print("Press Ctrl+C to stop the server\n")
    
    try:
        # Import and run from backend directory context
        import importlib.util
        spec = importlib.util.spec_from_file_location("app", os.path.join(backend_dir, "app.py"))
        app_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(app_module)
        
        # Run without reloader to avoid path issues
        app_module.app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
        
    except Exception as e:
        print(f"Error starting server: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()