"""
Vercel entry point for SqExcelWeb FastAPI application
This file serves as the entry point for Vercel serverless functions
"""

from main import app
from mangum import Mangum

# Create the ASGI handler for Vercel
handler = Mangum(app, lifespan="off")

# Vercel expects the handler to be available as 'handler'