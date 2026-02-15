from src.core.tracing import request_id_var

def get_request_id() -> str:
    return request_id_var.get()
