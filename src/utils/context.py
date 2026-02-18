from src.core.tracing import request_id_var, client_ip_var

def get_request_id() -> str:
    return request_id_var.get()

def get_client_ip() -> str:
    return client_ip_var.get()
