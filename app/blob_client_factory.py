# blob_client_factory.py

import os
from azure.storage.blob import BlobServiceClient

def create_blob_service_client():
    if os.getenv("UNIT_TESTING") == "1":
        return None  # Will be mocked in test
    connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    if not connection_string:
        raise ValueError("AZURE_STORAGE_CONNECTION_STRING is not set.")
    return BlobServiceClient.from_connection_string(connection_string)
