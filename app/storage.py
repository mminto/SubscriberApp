# storage.py
from azure.storage.blob import BlobServiceClient

def create_blob_service_client(connection_string: str) -> BlobServiceClient:
    return BlobServiceClient.from_connection_string(connection_string)
