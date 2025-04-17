import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import azure.functions as func
import logging
from app.config import AppConfig
from app.unsubscribe_handler import handle_mailchimp_request
from dotenv import load_dotenv

# Load .env environment variables
load_dotenv()

# Initialize the Azure Function App instance
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# 💡 Properly initialize config
config = AppConfig()
logging.warning("✅ AppConfig loaded.")

@app.route(route="contact/unsubscribe")
def unsubscribe(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python unsubscribe trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )

@app.function_name(name="MailChimpUnsubscribe")
@app.route(route="contacts/unsubscribe", methods=["GET", "POST"], auth_level=func.AuthLevel.ANONYMOUS)
def unsubscribe_handler(req: func.HttpRequest) -> func.HttpResponse:
    if req.method == "GET":
        logging.info("Mailchimp webhook verification GET request received.")
        return func.HttpResponse("Webhook verification OK", status_code=200)
    elif req.method == "POST":
        # return func.HttpResponse("Webhook verification OK", status_code=200)
        return handle_mailchimp_request(req, config.blob_service_client, config)
    else:
        return func.HttpResponse("Method not allowed", status_code=405)
