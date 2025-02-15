# Azure Durable Function App for Data Integrity Checking

## Overview

This is a Python-based Azure Durable Function App that verifies data about secrets vaulted in multiple Azure Key Vaults across an Azure subscription and compares it to the status of secrets in the application database of the vaulting solution which acts as a UI for Azure key vault architecture.

The app works by first retrieving a list of all Azure Key Vaults within the specified Azure subscription. For each vault, it then retrieves a list of all secrets stored within that vault. These secrets are then compared to those stored in the MSSQL database to ensure consistency and data integrity.

## Need for this Application

Maintaining data integrity between Key vaulting solution and the underlying Azure Key Vaults architectures is important to ensure confidentiality of data and meeting audit requirements or SOX compliance.

The app ensures that the data in the MSSQL database is consistent with the data in the Azure Key Vaults. If there are any discrepancies, they can be identified and resolved, ensuring that the data remains consistent and reliable.

## How the Application Achieves Data Integrity

The application achieves data integrity through a series of steps:

1. **Retrieving Vault List**: The application first retrieves a list of all Azure Key Vaults within the specified Azure subscription.
2. **Retrieving Secret List**: For each vault, the application then retrieves a list of all secrets stored within that vault.
3. **Connecting to DB and comparing secret status on DB**: The retrieved secrets are then compared to those stored in the MSSQL database. Any discrepancies are identified and logged.
4. **Cleanup secrets in DB**: Secrets deleted in Azure Key vaults but still marked active on database are marked as deleted on database
5. **Delete secrets in Azure**: Secrets marked deleted in database to be deleted in azure key vault

The application uses Azure Durable Functions, which allow for long-running orchestrations. This is particularly useful in this case as the process of retrieving and comparing data can take a significant amount of time, especially when dealing with a large number of vaults and secrets.

## Code Structure

The code is organized into several versions:

- **`function_app_st.py`**: This is the single threaded version of the function app code in logging mode. Only logs the discrepancies between vaulting solution database and azure key vaults (not recommended for large number of files).
- **`function_app_mt.py`**: This is the multi threaded version of the function app code in logging mode. Only logs the discrepancies between vaulting solution database and azure key vaults (not recommended for large number of files).
- **`function_app_dep.py`**: This is the multi threaded version of the function app code which also marks secrets as deleted on database and deletes secrets on Azure.
- **`requirements.txt`**: This file lists the required Python packages.

## Usage

### Inputs

Following inputs are required in API request body. Refer code for API parameters:

- **Azure Subscription ID**: REQUIRED The ID of the Azure subscription that contains the Key Vaults you want to check.
- **Subscription Access Token**: REQUIRED The subscription access token for scope 'https://management.azure.com'. NOT Required if using managed identity.
- **Vault Access Token**: REQUIRED The vault access token with vault manager role for scope 'https://vault.azure.net'. NOT Required if using managed identity.
- **Blob container**: OPTIONAL The azure blob storage container where input/output/log files are stored.
- **Input File Path**: OPTIONAL The location on azure blob storage container where to read input file from (when using in logging mode)
- **Output File Path**: OPTIONAL The location on azure blob storage container where to write output file to (when using in logging mode)
- **DB Update Flag**: OPPITONAL The flag specifying the DB update mode (0, -1, 1; 0 is default mode for checking, 1 updates for all discrepancies, -1 for testing)

### Expected Response Time

The response time for this Azure Function App can vary greatly depending on the number of vaults and secrets being checked.

## Prerequisites

- An Azure subscription
- An Azure Key Vault
- An MSSQL database hosted on Azure
- A service principal/Managed identity with access to the subscription and Key Vaults
- Python 3.6 or later
- The required Python packages (listed in the `requirements.txt` file)


## References

- [Azure Durable Functions](https://docs.microsoft.com/en-us/azure/azure-functions/durable-functions-overview)
- [Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/general/overview)
- [MSSQL Database on Azure](https://docs.microsoft.com/en-us/azure/sql-database/sql-database-technical-overview)
