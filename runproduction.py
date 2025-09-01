#!/usr/bin/env python3
"""
Production WSGI entry point for FinTrace
Handles errors gracefully and ensures the app starts even if there are issues
"""

import os
import sys
import traceback

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db
    
    # Initialize database tables
    with app.app_context():
        try:
            db.create_all()
            print("✅ Database initialized successfully")
        except Exception as e:
            print(f"⚠️ Database initialization warning: {e}")
            print("App will continue without database initialization")
    
    # Create the WSGI application
    application = app
    
    print("✅ FinTrace WSGI application created successfully")
    
except Exception as e:
    print(f"❌ Critical error creating WSGI application: {e}")
    print("Traceback:")
    traceback.print_exc()
    
    # Create a minimal error app
    from flask import Flask
    error_app = Flask(__name__)
    
    @error_app.route('/')
    def error_home():
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>FinTrace - System Error</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #0f1419; color: white;">
            <h1>🚨 FinTrace System Error</h1>
            <p>We're experiencing technical difficulties. Please contact support.</p>
            <p>Error: {error}</p>
        </body>
        </html>
        '''.format(error=str(e)), 500
    
    @error_app.route('/<path:path>')
    def error_catch_all(path):
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>FinTrace - System Error</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #0f1419; color: white;">
            <h1>🚨 FinTrace System Error</h1>
            <p>We're experiencing technical difficulties. Please contact support.</p>
            <p>Error: {error}</p>
        </body>
        </html>
        '''.format(error=str(e)), 500
    
    application = error_app
    print("⚠️ Created minimal error application as fallback")

if __name__ == "__main__":
    try:
        port = int(os.environ.get("PORT", 5000))
        print(f"Starting FinTrace on port {port}")
        application.run(host="0.0.0.0", port=port)
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)
