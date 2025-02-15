import json
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
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
import pyodbc

app = adf.DFApp()

# Define the server and database
dbserver = os.getenv("DBServer")
database = os.getenv("Database")
driver = os.getenv("DBDriver")

# Create a connection string for the ESM database
connection_string = f"mssql+pyodbc://@{dbserver}:1433/{database}?driver={driver}&authentication=ActiveDirectoryMsi"


# Create an engine using the managed identity credential
engine = create_engine(connection_string)

# Function to create a new engine
def create_new_engine(connection_string):
    return create_engine(connection_string)

# Function to check if the connection is still valid
def check_connection(engine):
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except OperationalError:
        return False

# Columns in output data
output_data_columns = ["VaultName", "VaultResourceGroup", "SecretName", "DumpStatus"]

# Final Dump dataframe
all_vault_secrets = pandas.DataFrame(columns=output_data_columns)

# Setup counter to show current progress
total_processed = 0

# Setup total vault number for updating progress
number_of_vaults_in_subscription = 0

akv_secrets_names = set()


urllib3.disable_warnings()  # To suppress unverified https request warning

@app.route(route="akvextract", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
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
    update_db_limit = input_data.get("updateDbLimit") or 0
    dataDict = {"subscription_id": subscription_id, "subscription_access_token": subscription_access_token, "vault_access_token": vault_access_token, "update_db_limit": update_db_limit}
    result = yield context.call_activity("akv_extractor", dataDict)
    return [f"Orchestration completed with result: {result}"]

@app.activity_trigger(input_name="dataDict")
def akv_extractor(dataDict: dict) -> str:
    execution_start = datetime.datetime.now()
    logging.info('Script execution started at: %s', execution_start)

    subscription_id = dataDict.get("subscription_id")
    subscription_access_token = dataDict.get("subscription_access_token")
    vault_access_token = dataDict.get("vault_access_token")
    number_of_threads = 1

    subscription_url = "https://management.azure.com/subscriptions/{}/resources?$filter=resourceType+eq+'Microsoft.KeyVault/vaults'&$top={}&api-version=2015-11-01".format(subscription_id, 1000)
    subscription_headers = {'authorization': 'Bearer {}'.format(subscription_access_token), 'content-type': 'application/json'}
    vault_headers = {'authorization': 'Bearer {}'.format(vault_access_token), 'content-type': 'application/json'}

    # Get list of vaults in the subscription
    vaults_in_subscription = get_value_list(subscription_url, subscription_headers)
    global number_of_vaults_in_subscription
    number_of_vaults_in_subscription = len(vaults_in_subscription)

    # Extract secrets from ESM database
    esm_secrets = get_esm_secrets(engine)

    test_secret_name = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
    query = f'SELECT isdeleted FROM Secrets WHERE Name = \'{test_secret_name}\';'
        
    with engine.connect() as connection:
        result = connection.execute(text(query))
        test_results = [row._mapping for row in result.fetchall()]

    logging.info(test_results)

    for vault in vaults_in_subscription:
       worker_thread(vault_headers, vault)

    # Write any non written vault/secret details to output file
    if len(all_vault_secrets.index) != 0:
       save_to_csv(all_vault_secrets)

    update_db_limit = dataDict.get("update_db_limit")
    if update_db_limit != 0:
        # Compare secrets and mark deleted ones in ESM database
        deleted_secrets = compare_secrets(esm_secrets)
        mark_deleted_secrets(engine, deleted_secrets, update_db_limit)

    return f"Processed data for {dataDict.get('subscription_id', 'unknown')} successfully"

# Update vault results to final dump
def thread_safe_appender(vault_name, vault_resource_group, secret_list, status):
    global all_vault_secrets, output_data_columns
    current_vault_secrets = pandas.DataFrame(columns=output_data_columns)
    if secret_list is None:
        current_vault_secrets.at[0, 'SecretName'] = "Secrets not fetched"
        current_vault_secrets.at[0, 'VaultName'] = vault_name
        current_vault_secrets.at[0, 'VaultResourceGroup'] = vault_resource_group
        current_vault_secrets.at[0, 'DumpStatus'] = status
    else:
        current_vault_secrets['SecretName'] = secret_list
        current_vault_secrets = current_vault_secrets.assign(**{'VaultResourceGroup': vault_resource_group})
        current_vault_secrets = current_vault_secrets.assign(**{'VaultName': vault_name})
        current_vault_secrets = current_vault_secrets.assign(**{'DumpStatus': status})

    all_vault_secrets = pandas.concat([all_vault_secrets, current_vault_secrets], ignore_index=True)
    if len(all_vault_secrets.index) >= 50:
        try:
            save_to_csv(all_vault_secrets)
            all_vault_secrets = all_vault_secrets[0:0]
        except Exception as e:
            logging.error('thread_safe_appender: Error while saving to file: %s', e.__str__())
            logging.error('thread_safe_appender: DF - %s', all_vault_secrets.to_string())
            logging.error('thread_safe_appender: List of failed writes: %s', all_vault_secrets.to_string())
            all_vault_secrets = all_vault_secrets[0:0]

# Function to show a visual progress bar
def update_progress(progress, message):
    print('\r[ {0}{1} ] {2}% {3}'.format('#' * int(progress / 2), ' ' * int(50 - progress / 2), progress, message), end="")

# Function to get list of vaults/secrets
def get_value_list(endpoint, headers):
    value_array = []
    while endpoint is not None:
        try:
            response = requests.get(endpoint, headers=headers, verify=False)
            if response.status_code == 200:
                value_array += response.json()["value"]
                endpoint = response.json().get("nextLink")
            else:
                return "api_error_while_fetching_vault/secret_details " + str(response.status_code) + " " + response.text
        except Exception as e:
            logging.error("get_value_list: Error while getting list of vaults/secrets: ", e.__str__())
            return "exception_while_fetching_all_vault/secret_details " + e.__str__()
    return value_array

# Caller function which will be multi-threaded
def worker_thread(vault_headers, current_vault):
    global shared_queue, total_processed, number_of_vaults_in_subscription, akv_secrets_names
    try:
        total_processed += 1
        update_progress(int((total_processed / number_of_vaults_in_subscription) * 100), "Vaults accessed: " + str(total_processed) + "          ")

        vault_url = "https://{}.vault.azure.net/secrets?maxresults={}&api-version=7.4".format(current_vault["name"], "1")
        secrets_in_current_vault = get_value_list(vault_url, vault_headers)

        secret_names = ""
        if isinstance(secrets_in_current_vault, str) or len(secrets_in_current_vault) == 0:
            secret_names = None
        else:
            secret_names = [secret_id.rsplit('/', 1)[-1] for secret_id in [secret["id"] for secret in secrets_in_current_vault]]

        if secret_names is None:
            thread_safe_appender(current_vault["name"], current_vault["id"].split('/')[4], secret_names, secrets_in_current_vault)
        else:
            akv_secrets_names.update(secret_names)
            thread_safe_appender(current_vault["name"], current_vault["id"].split('/')[4], secret_names, "Read Secrets Successful for vault")

    except Exception as e:
        logging.error("worker_thread: Runtime Error in worker_thread: %s", e.__cause__)

# Function to update azure blob storage hosted output CSV file
def save_to_csv(df_to_append):
    try:
        logging.info("write_to_csv: Trying to update file to blob storage")
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
        logging.error("Runtime Error while updating file in blob storage: ", e.__str__())

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

# Function to get secrets from ESM database
def get_esm_secrets(engine):
    query = 'SELECT name as name FROM Secrets where isdeleted=0;'
    with engine.connect() as connection:
        result = connection.execute(text(query))
        # esm_secrets = [dict(row) for row in result.fetchall()]
        esm_secrets = [row._mapping for row in result.fetchall()]
    return esm_secrets

# Function to compare secrets from ESM database and Azure Key Vault
def compare_secrets(esm_secrets):
    global akv_secrets_names
    esm_secret_names = set(secret['name'] for secret in esm_secrets)
    deleted_in_akv = esm_secret_names-akv_secrets_names
    return deleted_in_akv

# Function to get KV names from ESM database
def get_esm_kvs(engine):
    query = 'SELECT name as name FROM vaults where isdeleted=0;'
    with engine.connect() as connection:
        result = connection.execute(text(query))
        # esm_secrets = [dict(row) for row in result.fetchall()]
        esm_kvs = [row._mapping for row in result.fetchall()]
    return esm_kvs

# Function to mark deleted secrets in ESM database
# def mark_deleted_secrets(engine, deleted_secrets, update_db_limit):
#     logging.info("update_db_limit : %d", update_db_limit)
#     logging.info("updating db : %s", str(deleted_secrets))
#     if len(deleted_secrets)>0 :
#         query = 'SELECT name as name FROM Secrets where isdeleted=0 and Name in :deleted_secrets;'
#         with engine.connect() as connection:
#             result = connection.execute(text(query), {'deleted_secrets': tuple(deleted_secrets)})
#             esm_secrets_to_delete = [row._mapping for row in result.fetchall()]
#         esm_secret_names_to_delete = set(secret['name'] for secret in esm_secrets_to_delete)
#         if update_db_limit == 1:
#             esm_secret_names_to_delete = list(esm_secret_names_to_delete)[:1]
#         logging.info("actual updating db : %s", str(esm_secret_names_to_delete))
#         # if len(esm_secret_names_to_delete) > 0 :
#             # update_query = 'UPDATE Secrets SET IsDeleted=1 WHERE Name IN :esm_secret_names_to_delete'
#             # with engine.connect() as connection:
#             #     connection.execute(text(update_query), {'esm_secret_names_to_delete': tuple(esm_secret_names_to_delete)})

# def mark_deleted_secrets(engine, deleted_secrets, update_db_limit):
#     logging.info("update_db_limit : %d", update_db_limit)
#     logging.info("updating db : %s", str(deleted_secrets))
    
#     # Ensure deleted_secrets is a list
#     deleted_secrets = list(deleted_secrets)
    
#     if len(deleted_secrets) > 0:
#         # Dynamically create placeholders for each item in the list
#         placeholders = ', '.join([':param' + str(i) for i in range(len(deleted_secrets))])
#         query = f'SELECT name as name FROM Secrets WHERE isdeleted=0 AND Name IN ({placeholders});'
        
#         # Create a dictionary of parameters
#         params = {f'param{i}': deleted_secrets[i] for i in range(len(deleted_secrets))}
        
#         with engine.connect() as connection:
#             result = connection.execute(text(query), params)
#             esm_secrets_to_delete = [row._mapping for row in result.fetchall()]
        
#         esm_secret_names_to_delete = set(secret['name'] for secret in esm_secrets_to_delete)
#         if update_db_limit == 1:
#             esm_secret_names_to_delete = list(esm_secret_names_to_delete)[:1]
#         logging.info("actual updating db : %s", str(esm_secret_names_to_delete))

def mark_deleted_secrets(engine, deleted_secrets, update_db_limit):
    logging.info("update_db_limit : %d", update_db_limit)
    logging.info("updating db : %s", str(deleted_secrets))
    
    
    if not check_connection(engine):
        logging.info("restablishing db connection")
        engine = create_new_engine(connection_string)

    # Ensure deleted_secrets is a list
    deleted_secrets = list(deleted_secrets)
    
    for secret in deleted_secrets:
        # query = 'SELECT name as name FROM Secrets WHERE isdeleted=0 AND Name = :param;'
        # params = {'param': secret}
        test_secret_name = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
        test_query = f'SELECT isdeleted FROM Secrets WHERE Name = \'{test_secret_name}\';'
        
        with engine.connect() as connection:
            test_result = connection.execute(text(test_query))
            test_results = [row._mapping for row in test_result.fetchall()]

        logging.info(test_results)

        query = f'SELECT name as name FROM Secrets WHERE isdeleted=0 AND Name = \'{secret}\';'
        
        with engine.connect() as connection:
            result = connection.execute(text(query))
            esm_secrets_to_delete = [row._mapping for row in result.fetchall()]
        
        esm_secret_names_to_delete = set(secret['name'] for secret in esm_secrets_to_delete)
        logging.info("actual updating db : %s", str(esm_secret_names_to_delete))

@app.route(route="secrets", methods=["DELETE"], auth_level=func.AuthLevel.ANONYMOUS)
@app.durable_client_input(client_name="client")
async def akv_delete_starter(req: func.HttpRequest, client) -> func.HttpResponse:
    
    request_body = req.get_json()
    instance_id = await client.start_new("delete_orchestrator_function", None, request_body)
    logging.info(f"Started Orchestration with ID = '{instance_id}'.")
    return client.create_check_status_response(req, instance_id)


@app.orchestration_trigger(context_name="context")
def delete_orchestrator_function(context: adf.DurableOrchestrationContext):
    input_data = context.get_input()
    subscription_id = input_data.get("subscriptionId")
    vault_access_token = input_data.get("vaultAccessToken")
    blob_container = input_data.get("blobContainer", "testcontainer")
    input_file_path = input_data.get("inputFile", "azure_secrets_to_delete.csv")
    output_file_path = input_data.get("outputFile", "azure_secrets_deleted_{}.csv".format(datetime.datetime.now().strftime("%d%b%Y_%H%M%S")))
    dataDict = {"subscription_id": subscription_id, "vault_access_token": vault_access_token, "blob_container": blob_container, "input_file_path": input_file_path, "output_file_path": output_file_path}
    result = yield context.call_activity("delete_secrets", dataDict)
    return [f"Orchestration completed with result: {result}"]


@app.activity_trigger(input_name="dataDict")
def delete_secrets(dataDict: dict) -> str:
    
    execution_start = datetime.datetime.now()
    logging.info('Script execution started at: %s', execution_start)

    urllib3.disable_warnings()  # To suppress unverified https request warning

    subscription_id = dataDict.get("subscription_id")
    blob_container = dataDict.get("blob_container")
    input_file_path = dataDict.get("input_file_path")
    output_file_path = dataDict.get("output_file_path")
    output_data_columns = ["VaultName", "VaultResourceGroup", "SecretName", "Result"]
    connection_string = os.environ["AzureWebJobsStorage"]
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)

    credential = ManagedIdentityCredential()
    
    def delete_read_csv_blob(blob_service_client: BlobServiceClient, container_name: str, blob_name: str) -> pandas.DataFrame:
        try:
            blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
            blob_data = blob_client.download_blob().readall()
            csv_data = StringIO(blob_data.decode('utf-8'))
            df = pandas.read_csv(csv_data, header=0, keep_default_na=False)
            logging.info("read_csv_blob: Successfully read input file from blob storage")
            return df
        except Exception as e:
            logging.error("Runtime Error while reading input file from blob storage: %s", e)
            return pandas.DataFrame()

    def delete_write_csv_blob(blob_service_client: BlobServiceClient, container_name: str, blob_name: str, df: pandas.DataFrame):
        try:
            csv_buffer = StringIO()
            df.to_csv(csv_buffer, index=False)
            blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
            blob_client.upload_blob(csv_buffer.getvalue(), overwrite=True)
            logging.info("write_to_csv: Successfully updated file to blob storage")
        except Exception as e:
            logging.error("Runtime Error while updating file in blob storage: %s", e)

    all_secrets_to_delete = delete_read_csv_blob(blob_service_client, blob_container, input_file_path)
    all_deleted_secrets = pandas.DataFrame(columns=output_data_columns)

    for index, row in all_secrets_to_delete.iterrows():
        vault_url = f"https://{row['VaultName']}.vault.azure.net"
        secret_client = SecretClient(vault_url=vault_url, credential=credential)
        try:
            secret_client.begin_delete_secret(row['SecretName']).result()
            result = "Secret Deleted Successfully"
        except Exception as e:
            result = str(e)
        row_result = pandas.DataFrame([{'VaultName': row['VaultName'], 'VaultResourceGroup': row['VaultResourceGroup'], 'SecretName': row['SecretName'], 'Result': result}])
        all_deleted_secrets = pandas.concat([all_deleted_secrets, row_result], ignore_index=True)

    delete_write_csv_blob(blob_service_client, blob_container, output_file_path, all_deleted_secrets)

    execution_end = datetime.datetime.now()
    logging.info("Script execution completed at %s", execution_end)
    logging.info("Total time taken for script execution: %s", (execution_end - execution_start))

    return f"Processed data for {dataDict.get('subscription_id', 'unknown')} successfully"

def get_updated_name(kv_name):
    if not (kv_name.startswith('p-') or kv_name.startswith('b-')):
        return 'PROD-' + kv_name
    else:
        prefix, uname, hex_part = kv_name.split('-')
        incremented_value = int(hex_part, 16) + 1
        incremented_hex = f"{incremented_value:X}"  # Format as uppercase hex without leading zeros
        incremented_hex = incremented_hex.zfill(len(hex_part))  # Ensure the length matches the original hex part
        return f"{prefix}-{uname}-{incremented_hex}"

# ------------------------------------

@app.orchestration_trigger(context_name="context")
def kv_name_update_orchestrator_function(context: adf.DurableOrchestrationContext):
    input_data = context.get_input()
    dataDict = dict()
    result = yield context.call_activity("update_kv_names", dataDict)
    return [f"Orchestration completed with result: {result}"]

@app.activity_trigger(input_name="dataDict")
def update_kv_names(dataDict : dict) -> str:
    global engine
    execution_start = datetime.datetime.now()
    logging.info('Script execution started at: %s', execution_start)

    urllib3.disable_warnings()  # To suppress unverified https request warning
    if not check_connection(engine):
        logging.info("reestablishing db connection")
        engine = create_new_engine(connection_string)

    esm_kvs = get_esm_kvs(engine)

    
    for kv in esm_kvs:
        updated_name = get_updated_name(kv.name)
        query = text('UPDATE vaults SET name = :updated_name WHERE isdeleted=0 AND name = :kv_name')
        try:
            with engine.connect() as connection:
                # connection.execute(query)
                #connection.execute(query, {'updated_name': updated_name, 'kv_name': kv.name})
                #logging.info(f"Query for vault '{kv}' compiled successfully. Updated-name : '{updated_name}'")
                transaction = connection.begin()  # Start a transaction
                connection.execute(query, {'updated_name': updated_name, 'kv_name': kv.name})
                transaction.commit()  # Commit the transaction
                logging.info(f"Query for vault '{kv.name}' compiled successfully. Updated-name: '{updated_name}'")
        except Exception as e:
            logging.error(f"Error compiling query for kv '{kv.name}': {e}")

    execution_end = datetime.datetime.now()
    logging.info('Script execution ended at: %s', execution_end)

@app.route(route="kvnameupdate", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
@app.durable_client_input(client_name="client")
async def kv_name_update_starter(req: func.HttpRequest, client) -> func.HttpResponse:
    request_body = req.get_json()
    instance_id = await client.start_new("kv_name_update_orchestrator_function", None, request_body)
    logging.info(f"Started Orchestration with ID = '{instance_id}'.")
    return client.create_check_status_response(req, instance_id)