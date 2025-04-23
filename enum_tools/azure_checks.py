"""
Azure-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

import re
import sys
import requests
from enum_tools import utils
from enum_tools import azure_regions

BANNER = '''
++++++++++++++++++++++++++
       azure checks
++++++++++++++++++++++++++
'''

# Known Azure domain names
BLOB_URL = 'blob.core.windows.net'
FILE_URL= 'file.core.windows.net'
QUEUE_URL = 'queue.core.windows.net'
TABLE_URL = 'table.core.windows.net'
MGMT_URL = 'scm.azurewebsites.net'
VAULT_URL = 'vault.azure.net'
WEBAPP_URL = 'azurewebsites.net'
DATABASE_URL = 'database.windows.net'

# Virtual machine DNS names are actually:
#   {whatever}.{region}.cloudapp.azure.com
VM_URL = 'cloudapp.azure.com'


def print_account_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404 or 'The requested URI does not represent' in reply.reason:
        pass
    elif 'Server failed to authenticate the request' in reply.reason:
        data['msg'] = 'Auth-Only Account'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'The specified account is disabled' in reply.reason:
        data['msg'] = 'Disabled Account'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    elif 'Value for one of the query' in reply.reason:
        data['msg'] = 'HTTP-OK Account'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif 'The account being accessed' in reply.reason:
        data['msg'] = 'HTTPS-Only Account'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif 'Unauthorized' in reply.reason:
        data['msg'] = 'Unathorized Account'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    else:
        print("    Unknown status codes being received from " + reply.url +":\n"
              "       "+ str(reply.status_code)+" : "+ reply.reason)

def check_storage_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks storage account names
    """
    print("[+] Checking for Azure Storage Accounts")
    sys.stdout.flush()

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{BLOB_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_file_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks File account names
    """
    print("[+] Checking for Azure File Accounts")
    sys.stdout.flush()

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{FILE_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_queue_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks Queue account names
    """
    print("[+] Checking for Azure Queue Accounts")
    sys.stdout.flush()

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{QUEUE_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_table_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks Table account names
    """
    print("[+] Checking for Azure Table Accounts")
    sys.stdout.flush()

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{TABLE_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_mgmt_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks App Management account names
    """
    print("[+] Checking for Azure App Management Accounts")
    sys.stdout.flush()

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{MGMT_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_vault_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks Key Vault account names
    """
    print("[+] Checking for Azure Key Vault Accounts")
    sys.stdout.flush()

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    # As Azure Storage Accounts can contain only letters and numbers,
    # discard those not matching to save time on the DNS lookups.
    regex = re.compile('[^a-zA-Z0-9]')
    for name in names:
        if not re.search(regex, name):
            candidates.append(f'{name}.{VAULT_URL}')

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(valid_names, use_ssl=False,
                        callback=print_account_response,
                        threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))


def print_container_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    # Stop brute forcing disabled accounts
    if 'The specified account is disabled' in reply.reason:
        print("    [!] Breaking out early, account disabled.")
        sys.stdout.flush()
        return 'breakout'

    # Stop brute forcing accounts without permission
    if ('not authorized to perform this operation' in reply.reason or
            'not have sufficient permissions' in reply.reason or
            'Public access is not permitted' in reply.reason or
            'Server failed to authenticate the request' in reply.reason):
        print("    [!] Breaking out early, auth required.")
        sys.stdout.flush()
        return 'breakout'

    # Stop brute forcing unsupported accounts
    if 'Blob API is not yet supported' in reply.reason:
        print("    [!] Breaking out early, Hierarchical namespace account")
        sys.stdout.flush()
        return 'breakout'

    # Handle other responses
    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN AZURE CONTAINER'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        utils.list_bucket_contents(reply.url)
    elif 'One of the request inputs is out of range' in reply.reason:
        pass
    elif 'The request URI is invalid' in reply.reason:
        pass
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              f"       {reply.status_code}: {reply.reason}")
        sys.stdout.flush()

    return None


def brute_force_containers(storage_accounts, brute_list, threads):
    """
    Attempts to find public Blob Containers in valid Storage Accounts

    Here is the URL format to list Azure Blog Container contents:
    <account>.blob.core.windows.net/<container>/?restype=container&comp=list
    """

    # We have a list of valid DNS names that might not be worth scraping,
    # such as disabled accounts or authentication required. Let's quickly
    # weed those out.
    print(f"[*] Checking {len(storage_accounts)} accounts for status before brute-forcing")
    sys.stdout.flush()
    
    valid_accounts = []
    for account in storage_accounts:
        try:
            reply = requests.get(f'https://{account}/')
            if 'Server failed to authenticate the request' in reply.reason:
                storage_accounts.remove(account)
            elif 'The specified account is disabled' in reply.reason:
                storage_accounts.remove(account)
            else:
                valid_accounts.append(account)
        except requests.exceptions.ConnectionError as error_msg:
            print(f"    [!] Connection error on https://{account}:")
            print(error_msg)
            sys.stdout.flush()

    # Read the brute force file into memory
    clean_names = utils.get_brute(brute_list, mini=3)

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    print(f"[*] Brute-forcing container names in {len(valid_accounts)} storage accounts")
    sys.stdout.flush()
    
    for account in valid_accounts:
        print(f"[*] Brute-forcing {len(clean_names)} container names in {account}")
        sys.stdout.flush()

        # Initialize the list of correctly formatted urls
        candidates = []

        # Take each mutated keyword and craft a url with correct format
        for name in clean_names:
            candidates.append(f'{account}/{name}/?restype=container&comp=list')

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(candidates, use_ssl=True,
                            callback=print_container_response,
                            threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)


def print_website_response(hostname):
    """
    This function is passed into the DNS brute force as a callback,
    so we can get real-time results.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    data['msg'] = 'Registered Azure Website DNS Name'
    data['target'] = hostname
    data['access'] = 'public'
    utils.fmt_output(data)


def check_azure_websites(names, nameserver, threads, nameserverfile=False):
    """
    Checks for Azure Websites (PaaS)
    """
    print("[+] Checking for Azure Websites")
    sys.stdout.flush()

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = [name + '.' + WEBAPP_URL for name in names]

    # Azure Websites use DNS sub-domains. If it resolves, it is registered.
    utils.fast_dns_lookup(candidates, nameserver,
                          nameserverfile,
                          callback=print_website_response,
                          threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)


def print_database_response(hostname):
    """
    This function is passed into the DNS brute force as a callback,
    so we can get real-time results.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    data['msg'] = 'Registered Azure Database DNS Name'
    data['target'] = hostname
    data['access'] = 'public'
    utils.fmt_output(data)


def check_azure_databases(names, nameserver, threads, nameserverfile=False):
    """
    Checks for Azure Databases
    """
    print("[+] Checking for Azure Databases")
    sys.stdout.flush()
    
    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = [name + '.' + DATABASE_URL for name in names]

    # Azure databases use DNS sub-domains. If it resolves, it is registered.
    utils.fast_dns_lookup(candidates, nameserver,
                          nameserverfile,
                          callback=print_database_response,
                          threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)


def print_vm_response(hostname):
    """
    This function is passed into the DNS brute force as a callback,
    so we can get real-time results.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    data['msg'] = 'Registered Azure Virtual Machine DNS Name'
    data['target'] = hostname
    data['access'] = 'public'
    utils.fmt_output(data)


def check_azure_vms(names, nameserver, threads, nameserverfile=False):
    """
    Checks for Azure Virtual Machines
    """
    print("[+] Checking for Azure Virtual Machines")
    sys.stdout.flush()

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Pull the regions from a config file
    regions = azure_regions.REGIONS

    print(f"[*] Testing across {len(regions)} regions defined in the config file")
    sys.stdout.flush()

    for region in regions:

        # Initialize the list of domain names to look up
        candidates = [name + '.' + region + '.' + VM_URL for name in names]

        # Azure VMs use DNS sub-domains. If it resolves, it is registered.
        utils.fast_dns_lookup(candidates, nameserver,
                              nameserverfile,
                              callback=print_vm_response,
                              threads=threads)

    # Stop the timer
    utils.stop_timer(start_time)


def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)
    sys.stdout.flush()

    # Print a guaranteed output line for debugging
    print("[+] Azure checks starting with keyword: " + ', '.join(args.keyword))
    sys.stdout.flush()

    valid_accounts = check_storage_accounts(names, args.threads,
                                            args.nameserver, args.nameserverfile)
    sys.stdout.flush()
    
    if valid_accounts and not args.quickscan:
        brute_force_containers(valid_accounts, args.brute, args.threads)
        sys.stdout.flush()

    check_file_accounts(names, args.threads, args.nameserver, args.nameserverfile)
    sys.stdout.flush()
    
    check_queue_accounts(names, args.threads, args.nameserver, args.nameserverfile)
    sys.stdout.flush()
    
    check_table_accounts(names, args.threads, args.nameserver, args.nameserverfile)
    sys.stdout.flush()
    
    check_mgmt_accounts(names, args.threads, args.nameserver, args.nameserverfile)
    sys.stdout.flush()
    
    check_vault_accounts(names, args.threads, args.nameserver, args.nameserverfile)
    sys.stdout.flush()

    check_azure_websites(names, args.nameserver, args.threads, args.nameserverfile)
    sys.stdout.flush()
    
    check_azure_databases(names, args.nameserver, args.threads, args.nameserverfile)
    sys.stdout.flush()
    
    check_azure_vms(names, args.nameserver, args.threads, args.nameserverfile)
    sys.stdout.flush()
    
    # Print an ending line
    print("[+] Azure checks completed")
    sys.stdout.flush()
