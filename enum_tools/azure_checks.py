"""
Azure-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

import re
import requests
import threading
from enum_tools import utils
from enum_tools import azure_regions

# Add global progress tracking variables
CURRENT_COUNT = 0
TOTAL_COUNT = 0
VALID_COUNT = 0
ERROR_COUNT = 0
PROGRESS_LOCK = threading.Lock()

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


def update_progress(increment_current=True, increment_valid=False, increment_error=False):
    """
    Updates progress counters and displays progress
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    with PROGRESS_LOCK:
        if increment_current:
            CURRENT_COUNT += 1
        if increment_valid:
            VALID_COUNT += 1
        if increment_error:
            ERROR_COUNT += 1
        
        if TOTAL_COUNT > 0:  # Avoid division by zero
            progress_percentage = (CURRENT_COUNT / TOTAL_COUNT) * 100
            
            # Only update display every 25% or if it's the last item
            if progress_percentage % 25 < (1 / TOTAL_COUNT * 100) or CURRENT_COUNT == TOTAL_COUNT:
                print(f'\r        Progress: {progress_percentage:.1f}% ({CURRENT_COUNT}/{TOTAL_COUNT}), Valid: {VALID_COUNT}, Errors: {ERROR_COUNT}\r', end='', flush=True)


def print_account_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'azure', 'msg': '', 'target': '', 'access': ''}

    # Always increment the current count when we receive a response
    update_progress(increment_current=True)

    if reply.status_code == 404 or 'The requested URI does not represent' in reply.reason:
        pass
    elif 'Server failed to authenticate the request' in reply.reason:
        # Found valid but auth-protected resource
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'Auth-Only Account'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'The specified account is disabled' in reply.reason:
        # Found disabled account
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'Disabled Account'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    elif 'Value for one of the query' in reply.reason:
        # Found HTTP-OK account
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'HTTP-OK Account'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif 'The account being accessed' in reply.reason:
        # Found HTTPS-Only account
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'HTTPS-Only Account'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif 'Unauthorized' in reply.reason:
        # Found Unauthorized account
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'Unathorized Account'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    else:
        # Unknown response - increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print("    Unknown status codes being received from " + reply.url +":\n"
              "       "+ str(reply.status_code)+" : "+ reply.reason)

def check_storage_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks storage account names
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Azure Storage Accounts")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

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
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Create a wrapper function to update progress during DNS lookup
    def dns_callback(name, result):
        update_progress(increment_current=True)
        if result:
            update_progress(increment_current=False, increment_valid=True)
            return True
        return False

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads,
                                        callback=dns_callback)

    # Reset counters for HTTP checks
    CURRENT_COUNT = 0
    TOTAL_COUNT = len(valid_names)
    
    # Show initial progress for HTTP checks
    if TOTAL_COUNT > 0:
        print("\n[+] Checking HTTP responses for Azure Storage Accounts")
        update_progress(increment_current=False)
    
        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=print_account_response,
                            threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Azure Storage Accounts check")
    
    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_file_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks File account names
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Azure File Accounts")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

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
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Create a wrapper function to update progress during DNS lookup
    def dns_callback(name, result):
        update_progress(increment_current=True)
        if result:
            update_progress(increment_current=False, increment_valid=True)
            return True
        return False

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads,
                                        callback=dns_callback)

    # Reset counters for HTTP checks
    CURRENT_COUNT = 0
    TOTAL_COUNT = len(valid_names)
    
    # Show initial progress for HTTP checks
    if TOTAL_COUNT > 0:
        print("\n[+] Checking HTTP responses for Azure File Accounts")
        update_progress(increment_current=False)
    
        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=print_account_response,
                            threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Azure File Accounts check")
    
    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_queue_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks Queue account names
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Azure Queue Accounts")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

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
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Create a wrapper function to update progress during DNS lookup
    def dns_callback(name, result):
        update_progress(increment_current=True)
        if result:
            update_progress(increment_current=False, increment_valid=True)
            return True
        return False

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads,
                                        callback=dns_callback)

    # Reset counters for HTTP checks
    CURRENT_COUNT = 0
    TOTAL_COUNT = len(valid_names)
    
    # Show initial progress for HTTP checks
    if TOTAL_COUNT > 0:
        print("\n[+] Checking HTTP responses for Azure Queue Accounts")
        update_progress(increment_current=False)
    
        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=print_account_response,
                            threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Azure Queue Accounts check")
    
    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_table_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks Table account names
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Azure Table Accounts")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

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
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Create a wrapper function to update progress during DNS lookup
    def dns_callback(name, result):
        update_progress(increment_current=True)
        if result:
            update_progress(increment_current=False, increment_valid=True)
            return True
        return False

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads,
                                        callback=dns_callback)

    # Reset counters for HTTP checks
    CURRENT_COUNT = 0
    TOTAL_COUNT = len(valid_names)
    
    # Show initial progress for HTTP checks
    if TOTAL_COUNT > 0:
        print("\n[+] Checking HTTP responses for Azure Table Accounts")
        update_progress(increment_current=False)
    
        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=print_account_response,
                            threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Azure Table Accounts check")
    
    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_mgmt_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks App Management account names
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Azure App Management Accounts")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

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
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Create a wrapper function to update progress during DNS lookup
    def dns_callback(name, result):
        update_progress(increment_current=True)
        if result:
            update_progress(increment_current=False, increment_valid=True)
            return True
        return False

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads,
                                        callback=dns_callback)

    # Reset counters for HTTP checks
    CURRENT_COUNT = 0
    TOTAL_COUNT = len(valid_names)
    
    # Show initial progress for HTTP checks
    if TOTAL_COUNT > 0:
        print("\n[+] Checking HTTP responses for Azure App Management Accounts")
        update_progress(increment_current=False)
    
        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=print_account_response,
                            threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Azure App Management Accounts check")
    
    # Stop the timer
    utils.stop_timer(start_time)

    # de-dupe the results and return
    return list(set(valid_names))

def check_vault_accounts(names, threads, nameserver, nameserverfile=False):
    """
    Checks Key Vault account names
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Azure Key Vault Accounts")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

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
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Create a wrapper function to update progress during DNS lookup
    def dns_callback(name, result):
        update_progress(increment_current=True)
        if result:
            update_progress(increment_current=False, increment_valid=True)
            return True
        return False

    # Azure Storage Accounts use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads,
                                        callback=dns_callback)

    # Reset counters for HTTP checks
    CURRENT_COUNT = 0
    TOTAL_COUNT = len(valid_names)
    
    # Show initial progress for HTTP checks
    if TOTAL_COUNT > 0:
        print("\n[+] Checking HTTP responses for Azure Key Vault Accounts")
        update_progress(increment_current=False)
    
        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(valid_names, use_ssl=False,
                            callback=print_account_response,
                            threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Azure Key Vault Accounts check")
    
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

    # Always increment the current count when we receive a response
    update_progress(increment_current=True)

    # Stop brute forcing disabled accounts
    if 'The specified account is disabled' in reply.reason:
        # Increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print("    [!] Breaking out early, account disabled.")
        return 'breakout'

    # Stop brute forcing accounts without permission
    if ('not authorized to perform this operation' in reply.reason or
            'not have sufficient permissions' in reply.reason or
            'Public access is not permitted' in reply.reason or
            'Server failed to authenticate the request' in reply.reason):
        
        # Increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print("    [!] Breaking out early, auth required.")
        return 'breakout'

    # Stop brute forcing unsupported accounts
    if 'Blob API is not yet supported' in reply.reason:
        # Increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print("    [!] Breaking out early, Hierarchical namespace account")
        return 'breakout'

    # Handle other responses
    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        # Found valid resource - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
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
        # Increment error counter for unknown responses
        update_progress(increment_current=False, increment_error=True)
        
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")

    return None


def brute_force_containers(storage_accounts, brute_list, threads):
    """
    Attempts to find public Blob Containers in valid Storage Accounts

    Here is the URL format to list Azure Blog Container contents:
    <account>.blob.core.windows.net/<container>/?restype=container&comp=list
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

    # We have a list of valid DNS names that might not be worth scraping,
    # such as disabled accounts or authentication required. Let's quickly
    # weed those out.
    print(f"[*] Checking {len(storage_accounts)} accounts for status before brute-forcing")
    valid_accounts = []
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(storage_accounts)
    
    # Show initial progress
    update_progress(increment_current=False)
    
    for account in storage_accounts:
        try:
            reply = requests.get(f'https://{account}/')
            
            # Update progress counter
            update_progress(increment_current=True)
            
            if 'Server failed to authenticate the request' in reply.reason:
                storage_accounts.remove(account)
            elif 'The specified account is disabled' in reply.reason:
                storage_accounts.remove(account)
            else:
                valid_accounts.append(account)
                update_progress(increment_current=False, increment_valid=True)
        except requests.exceptions.ConnectionError as error_msg:
            update_progress(increment_current=False, increment_error=True)
            print(f"    [!] Connection error on https://{account}:")
            print(error_msg)

    # Read the brute force file into memory
    clean_names = utils.get_brute(brute_list, mini=3)

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    print(f"[*] Brute-forcing container names in {len(valid_accounts)} storage accounts")
    for account in valid_accounts:
        print(f"[*] Brute-forcing {len(clean_names)} container names in {account}")

        # Initialize the list of correctly formatted urls
        candidates = []

        # Take each mutated keyword and craft a url with correct format
        for name in clean_names:
            candidates.append(f'{account}/{name}/?restype=container&comp=list')
        
        # Reset counters for HTTP checks per account
        CURRENT_COUNT = 0
        VALID_COUNT = 0
        ERROR_COUNT = 0
        TOTAL_COUNT = len(candidates)
        
        # Show initial progress
        update_progress(increment_current=False)

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(candidates, use_ssl=True,
                            callback=print_container_response,
                            threads=threads)
        
        # Ensure we show 100% at the end of each account
        update_progress(increment_current=False)
        print("\n")

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
    
    # Increment valid counter (current count is incremented by the dns_callback)
    update_progress(increment_current=False, increment_valid=True)
    
    return True


def check_azure_websites(names, nameserver, threads, nameserverfile=False):
    """
    Checks for Azure Websites (PaaS)
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Azure Websites")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = [name + '.' + WEBAPP_URL for name in names]
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Create a wrapper function to update progress during DNS lookup
    def dns_callback(name, result):
        update_progress(increment_current=True)
        if result:
            return print_website_response(name)
        return False

    # Azure Websites use DNS sub-domains. If it resolves, it is registered.
    utils.fast_dns_lookup(candidates, nameserver,
                          nameserverfile,
                          callback=dns_callback,
                          threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Azure Websites check")
    
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
    
    # Increment valid counter (current count is incremented by the dns_callback)
    update_progress(increment_current=False, increment_valid=True)
    
    return True


def check_azure_databases(names, nameserver, threads, nameserverfile=False):
    """
    Checks for Azure Databases
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Azure Databases")
    
    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0
    
    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of domain names to look up
    candidates = [name + '.' + DATABASE_URL for name in names]
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Create a wrapper function to update progress during DNS lookup
    def dns_callback(name, result):
        update_progress(increment_current=True)
        if result:
            return print_database_response(name)
        return False

    # Azure databases use DNS sub-domains. If it resolves, it is registered.
    utils.fast_dns_lookup(candidates, nameserver,
                          nameserverfile,
                          callback=dns_callback,
                          threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Azure Databases check")
    
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
    
    # Increment valid counter (current count is incremented by the dns_callback)
    update_progress(increment_current=False, increment_valid=True)
    
    return True


def check_azure_vms(names, nameserver, threads, nameserverfile=False):
    """
    Checks for Azure Virtual Machines
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Azure Virtual Machines")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Pull the regions from a config file
    regions = azure_regions.REGIONS

    print(f"[*] Testing across {len(regions)} regions defined in the config file")

    # Calculate total candidates across all regions
    total_candidates = 0
    all_candidates = []
    
    for region in regions:
        # Initialize the list of domain names to look up for this region
        candidates = [name + '.' + region + '.' + VM_URL for name in names]
        all_candidates.extend(candidates)
        total_candidates += len(candidates)
    
    # Set total count for progress tracking
    TOTAL_COUNT = total_candidates
    
    # Show initial progress
    update_progress(increment_current=False)
    
    # Process each region separately
    for region in regions:
        # Initialize the list of domain names to look up for this region
        candidates = [name + '.' + region + '.' + VM_URL for name in names]
        
        print(f"\n[*] Checking {len(candidates)} candidates in region {region}")

        # Create a wrapper function to update progress during DNS lookup
        def dns_callback(name, result):
            update_progress(increment_current=True)
            if result:
                return print_vm_response(name)
            return False

        # Azure VMs use DNS sub-domains. If it resolves, it is registered.
        utils.fast_dns_lookup(candidates, nameserver,
                              nameserverfile,
                              callback=dns_callback,
                              threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Azure Virtual Machines check")
    
    # Stop the timer
    utils.stop_timer(start_time)


def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)

    valid_accounts = check_storage_accounts(names, args.threads,
                                            args.nameserver, args.nameserverfile)
    if valid_accounts and not args.quickscan:
        brute_force_containers(valid_accounts, args.brute, args.threads)

    check_file_accounts(names, args.threads, args.nameserver, args.nameserverfile)
    check_queue_accounts(names, args.threads, args.nameserver, args.nameserverfile)
    check_table_accounts(names, args.threads, args.nameserver, args.nameserverfile)
    check_mgmt_accounts(names, args.threads, args.nameserver, args.nameserverfile)
    check_vault_accounts(names, args.threads, args.nameserver, args.nameserverfile)

    check_azure_websites(names, args.nameserver, args.threads, args.nameserverfile)
    check_azure_databases(names, args.nameserver, args.threads, args.nameserverfile)
    check_azure_vms(names, args.nameserver, args.threads, args.nameserverfile)
