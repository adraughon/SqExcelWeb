"""
Vercel entry point for SqExcelWeb FastAPI application
This file serves as the entry point for Vercel serverless functions
"""

from main import app

# Vercel expects the app to be available as 'app'
# The main.py file contains the FastAPI app
