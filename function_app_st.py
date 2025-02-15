import logging
import pandas
import urllib3
import datetime
import requests
import os
import azure.functions as func
import azure.durable_functions as adf
from io import StringIO, BytesIO
from azure.storage.blob import BlobServiceClient


app = adf.DFApp()

# Columns in output data
output_data_columns = ["VaultName", "SecretName", "DumpStatus"]

# Final Dump dataframe
all_vault_secrets = pandas.DataFrame(columns = output_data_columns)

# Setup counter to show current progress
total_processed = 0

# Setup total vault number for updating progress
number_of_vaults_in_subscription = 0

urllib3.disable_warnings() # To suppress unverified https request warning


@app.route(route="akv_extract", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
@app.durable_client_input(client_name="client")
async def akv_extract_starter(req: func.HttpRequest, client) -> func.HttpResponse:
    
    request_body = req.get_json()
    instance_id = await client.start_new("orchestrator_function", None, request_body)
    logging.info(f"Started Orchestration with ID = '{instance_id}'.")
    return client.create_check_status_response(req, instance_id)


@app.orchestration_trigger(context_name="context")
def orchestrator_function(context: adf.DurableOrchestrationContext):
    input_data = context.get_input()
    subscription_id = input_data.get("subscriptionId")
    subscription_access_token = input_data.get("subscriptionAccessToken")
    vault_access_token = input_data.get("vaultAccessToken")
    dataDict = {"subscription_id": subscription_id, "subscription_access_token": subscription_access_token, "vault_access_token": vault_access_token}
    result = yield context.call_activity("akv_extractor", dataDict)
    return [f"Orchestration completed with result: {result}"]



@app.activity_trigger(input_name="dataDict")
def akv_extractor(dataDict: dict) -> str:
    
    execution_start = datetime.datetime.now()
    logging.info('Script execution started at: %s',execution_start)

    subscription_id = dataDict.get("subscription_id")
    subscription_access_token = dataDict.get("subscription_access_token")
    vault_access_token = dataDict.get("vault_access_token")
    number_of_threads = 1

    subscription_url = "https://management.azure.com/subscriptions/{}/resources?$filter=resourceType+eq+'Microsoft.KeyVault/vaults'&$top={}&api-version=2015-11-01".format(subscription_id, 1000)
    subscription_headers = {'authorization' : 'Bearer {}'.format(subscription_access_token), 'content-type' : 'application/json'}
    vault_headers = {'authorization' : 'Bearer {}'.format(vault_access_token), 'content-type' : 'application/json'}

    # Get list of vaults in the subscription
    # vaults_in_subscription = get_value_list(subscription_url, subscription_headers)
    vaults_in_subscription = [{"name": "b-prashanthpa-0360e20a94"}, {"name": "p-prashanthpa-0A45FB0F0A"}, {"name": "b-prashanthpa-7DFF462946"}]

    # Load list of vaults in the subscription into thread safe queue
    global number_of_vaults_in_subscription
    number_of_vaults_in_subscription = len(vaults_in_subscription)

    for vault in vaults_in_subscription:
        worker_thread(vault_headers, vault)

    # Write any non written vault/secret details to output file
    if len(all_vault_secrets.index) != 0:
        # all_vault_secrets.to_csv(output_file_path, index=False, header=False, mode='a')
        save_to_csv(all_vault_secrets)

    append_time = datetime.datetime.now().strftime("%d%b%Y_%H%M%S")

    execution_end = datetime.datetime.now()
    logging.info("\nScript execution completed at:", execution_end)
    logging.info("Total time taken for script execution:", (execution_end - execution_start))

    return f"Processed data for {dataDict.get('subscription_id', 'unknown')} successfully"


# Update vault results to final dump
def thread_safe_appender(vault_name, secret_list, status):
    global all_vault_secrets, output_data_columns
    # Dataframe to store secret data for vault
    current_vault_secrets = pandas.DataFrame(columns = output_data_columns)
    if secret_list is None:
        current_vault_secrets.at[0, 'SecretName'] = "Secrets not fetched"
        current_vault_secrets.at[0, 'VaultName'] = vault_name
        current_vault_secrets.at[0, 'DumpStatus'] = status
    else:
        current_vault_secrets['SecretName'] = secret_list
        current_vault_secrets = current_vault_secrets.assign(**{'VaultName': vault_name})
        current_vault_secrets = current_vault_secrets.assign(**{'DumpStatus': status})
    
    all_vault_secrets = pandas.concat([all_vault_secrets, current_vault_secrets], ignore_index=True)
    if len(all_vault_secrets.index) >= 50:  
        try:
            # all_vault_secrets.to_csv(output_file_path, index=False, header=False, mode='a')
            save_to_csv(all_vault_secrets)
            all_vault_secrets = all_vault_secrets[0:0]
        except Exception as e:
            logging.error('thread_safe_appender: Error while saving to file: %s',e.__str__())
            logging.error('thread_safe_appender: DF - %s',all_vault_secrets.to_string())
            logging.error('thread_safe_appender: List of failed writes: %s',all_vault_secrets.to_string())
            all_vault_secrets = all_vault_secrets[0:0]


# Function to show a visual progress bar
def update_progress(progress, message):
    print('\r[ {0}{1} ] {2}% {3}'.format('#' * int(progress/2), ' ' * int(50 - progress/2), progress, message),end="")


# Function to get list of vaults/secrets
def get_value_list(endpoint, headers):
    value_array = []
    while(endpoint is not None):
        try:
            response = requests.get(endpoint, headers=headers, verify=False)
            if response.status_code==200:
                value_array += response.json()["value"]
                endpoint = response.json().get("nextLink")
            else:
                return "api_error_while_fetching_vault/secret_details "+str(response.status_code)+" "+response.text
        except Exception as e:
            logging.error("get_value_list: Error while getting list of vaults/secrets: ",e.__str__())
            return "exception_while_fetching_all_vault/secret_details "+e.__str__()
    return value_array


# Caller function which will be multi-threaded
def worker_thread(vault_headers, current_vault):
    global shared_queue, total_processed, number_of_vaults_in_subscription
    try:

        # Increment counter
        total_processed += 1

        # Update Progress bar
        update_progress( int((total_processed / number_of_vaults_in_subscription)*100) , "Vaults accessed: "+str(total_processed)+"          " )

        vault_url = "https://{}.vault.azure.net/secrets?maxresults={}&api-version=7.4".format(current_vault["name"], "1")
        # Get secrets in vault
        secrets_in_current_vault = get_value_list(vault_url, vault_headers)

        secret_names = ""
        # Get list of secretNames from secret details
        if(isinstance(secrets_in_current_vault, str) or len(secrets_in_current_vault) == 0):
            secret_names = None
        else:
            secret_names = [ secret_id.rsplit('/', 1)[-1] for secret_id in [secret["id"] for secret in secrets_in_current_vault] ]

        # Write found secrets to global dataframe (can be empty list of secrets)
        if(secret_names is None):
            thread_safe_appender(current_vault["name"], secret_names, secrets_in_current_vault)
        else:
            thread_safe_appender(current_vault["name"], secret_names, "Read Secrets Succesful for vault")

    except Exception as e:
        logging.error("worker_thread: Runtime Error in worker_thread: ",e.__str__())


# Function to update azure blob storage hosted output CSV file
def save_to_csv(df_to_append):
    try:
        logging.info("write_to_csv: Trying to update file to blob storage")
        # Read the existing data from the blob

        connection_string = os.environ["AzureWebJobsStorage"]
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_name = "testcontainer"
        input_blob_name = "test.csv"
        output_blob_name = "test.csv"

        existing_df = read_csv_blob(blob_service_client, container_name, input_blob_name)
        output_df = pandas.concat([existing_df, df_to_append], ignore_index=True)
        write_csv_blob(blob_service_client, container_name, output_blob_name, output_df)
    
        logging.info("write_to_csv: Successfully updated file to blob storage")
    except Exception as e:
        logging.error("Runtime Error while updating file in blob storage: ",e.__str__())

# Function to read data from blob storage file
def read_csv_blob(blob_service_client: BlobServiceClient, container_name: str, blob_name: str) -> pandas.DataFrame:
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    blob_data = blob_client.download_blob().readall()
    csv_data = StringIO(blob_data.decode('utf-8'))
    df = pandas.read_csv(csv_data)
    return df

# Function to write data to blob storage files
def write_csv_blob(blob_service_client: BlobServiceClient, container_name: str, blob_name: str, df: pandas.DataFrame):
    csv_buffer = StringIO()
    df.to_csv(csv_buffer, index=False)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    blob_client.upload_blob(csv_buffer.getvalue(), overwrite=True)
