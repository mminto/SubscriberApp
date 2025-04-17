# config.py
import os
from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient

load_dotenv()

class AppConfig:
    def __init__(self):
        self.container_name = os.getenv("AZURE_BLOB_CONTAINER_NAME", "bronze")
        self.connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
        if not self.connection_string:
            raise ValueError("AZURE_STORAGE_CONNECTION_STRING is required")
        self.blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)
