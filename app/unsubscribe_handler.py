# --- Standard Library ---
import os
import re
import json
import hashlib
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from urllib.parse import parse_qs

# --- Third-Party Packages ---
import pytz

# --- Azure SDK ---
import azure.functions as func
from azure.storage.blob import BlobServiceClient
from opencensus.ext.azure.log_exporter import AzureLogHandler

# --- App-Specific Imports ---
from app.config import AppConfig

# ✅ Keep shared headers here
headers = {
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains"
}
# Constants
CONTAINER_NAME = os.getenv("AZURE_BLOB_CONTAINER_NAME", "bronze")
SYDNEY_TZ = pytz.timezone('Australia/Sydney')


def validate_event_data(event_data: Dict[str, Any]) -> bool:
    """Validate the structure of the event data."""
    required_keys = {"type", "data", "fired_at"}

    if not isinstance(event_data, dict):
        return False

    # Check for missing keys
    missing_keys = required_keys - event_data.keys()
    if missing_keys:
        return False

    # Optional deeper checks
    if "email" not in event_data["data"] and "merges" not in event_data["data"]:
        return False

    return True


def convert_to_sydney_time(utc_datetime_str: Optional[str]) -> Optional[str]:
    """Convert a UTC datetime string to Sydney time."""
    if not utc_datetime_str:
        return "invalid format"  # Avoid returning None

    datetime_formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S"
    ]

    for fmt in datetime_formats:
        try:
            parsed_datetime = datetime.strptime(utc_datetime_str, fmt)
            if parsed_datetime.tzinfo is None:
                parsed_datetime = parsed_datetime.replace(tzinfo=pytz.UTC)

            sydney_datetime = parsed_datetime.astimezone(SYDNEY_TZ)
            return sydney_datetime.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

    logging.error(f"Error converting datetime '{utc_datetime_str}' with available formats.")
    return "invalid format"  # Explicitly return invalid format

def extract_event_data(req: func.HttpRequest) -> Optional[Dict[str, Any]]:
    content_type = req.headers.get('Content-Type', '').lower()
    logging.info(f"Webhook Content-Type: {content_type}")
    body = None

    try:
        body = req.get_body().decode('utf-8')

        if content_type == 'application/json':
            json_data = req.get_json()
            if not isinstance(json_data, dict) or "type" not in json_data or "data" not in json_data:
                logging.error(f"Invalid JSON structure: {json_data}")
                return None
            logging.info(f"Webhook payload (JSON): {json.dumps(json_data, indent=2)}")
            return json_data

        elif content_type in ['application/x-www-form-urlencoded', '']:
            parsed = parse_qs(body)
            flat_data = {k: v[0] for k, v in parsed.items()}

            event_data = {}
            nested_data = {}
            nested_merges = {}

            for key, value in flat_data.items():
                match = re.match(r"data(?:\[merges])?\[(.*?)\]", key)
                if match:
                    sub_key = match.group(1)
                    if "merges" in key:
                        nested_merges[sub_key] = value
                    else:
                        nested_data[sub_key] = value
                else:
                    event_data[key] = value

            if nested_merges:
                nested_data["merges"] = nested_merges
            if nested_data:
                event_data["data"] = nested_data

            logging.info(f"Webhook payload (Form): {event_data}")
            return event_data

        logging.error(f"Unsupported Content-Type: {content_type}")
        return None

    except Exception as e:
        logging.error(f"Parsing error: {e} | Raw body: {body}")
        return None
        
def handle_unsubscribe_event(event_data: Dict[str, Any], blob_service_client: BlobServiceClient, config: AppConfig) -> None:
    data = event_data.get("data", {})
    email_address = data.get("email")
    phone_number = data.get("merges", {}).get("SMSPHONE")

    if not email_address and not phone_number:
        logging.error("Missing both email and phone in unsubscribe payload.")
        return

    identifier = email_address or phone_number
    hashed_id = hashlib.sha256(identifier.encode('utf-8')).hexdigest()
    blob_name = f"MailChimp/Inbox/unsubscribe_{hashed_id}.json"

    full_name = f"{data.get('merges', {}).get('FNAME', '')} {data.get('merges', {}).get('LNAME', '')}".strip()
    reason = data.get("reason", "unknown reason")
    action = data.get("action", "unknown action")
    fired_at = convert_to_sydney_time(event_data.get("fired_at")) or "unknown"

    payload = {
        "type": event_data.get("type"),
        "email_address": email_address or "N/A",
        "phone_number": phone_number or "N/A",
        "full_name": full_name,
        "reason": reason,
        "action": action,
        "fired_at": fired_at
    }

    try:
        blob_client = blob_service_client.get_blob_client(
            container=config.container_name,
            blob=blob_name
        )
        blob_client.upload_blob(json.dumps(payload, indent=4), overwrite=True, validate_content=True)
        logging.info(f"Stored unsubscribe event: {blob_name}")
    except Exception as e:
        logging.error(f"Upload failed for {identifier} → blob '{blob_name}': {str(e)}")
        raise

def handle_mailchimp_request(
    req: func.HttpRequest,
    blob_service_client: BlobServiceClient,
    config: AppConfig  # Now included for future flexibility
) -> func.HttpResponse:
    logging.info("Processing MailChimp webhook request.")

    try:
        if req.method != "POST":
            return func.HttpResponse("Method not allowed", status_code=405)

        event_data = extract_event_data(req)
        if not event_data:
            logging.warning("Empty or missing payload.")
            return func.HttpResponse("Success", status_code=200)

        if not validate_event_data(event_data):
            logging.warning("Invalid event data.")
            return func.HttpResponse("Invalid event data", status_code=400)

        event_type = event_data.get("type")
        logging.info(f"Received event type: {event_type}")

        if event_type == "unsubscribe" or event_type == "unsub":
            logging.info("Processing unsubscribe event")
            handle_unsubscribe_event(event_data, blob_service_client, config)
            return func.HttpResponse("Success", status_code=200, headers=headers)

        logging.warning(f"Unexpected event type: {event_type}")
        return func.HttpResponse("Unhandled event type", status_code=400, headers=headers)

    except Exception as e:
        logging.exception("Error processing webhook.")
        return func.HttpResponse(
            f"Internal Server Error: {str(e)}",
            status_code=500,
            headers=headers
        )