"""
Author: Vishal Rai
Description: Implements JWT and OAuth2-based authentication, role-based
access control, and JWT lifecycle management including
signing, verification, and key rotation.
"""

from fastapi import Depends


from src.app import create_app
import uvicorn

app = create_app()

if __name__ == "__main__":
    # 'app' can be fully async; uvicorn handles it
    uvicorn.run(
        "main:app",         # module:variable
        host="0.0.0.0",     # use 0.0.0.0 if running in docker/k8s
        port=8005,
        reload=True,        # dev only; remove in prod
        log_level="info"
    )
