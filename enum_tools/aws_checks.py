"""
AWS-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

import threading
from enum_tools import utils

# Add global progress tracking variables
CURRENT_COUNT = 0
TOTAL_COUNT = 0
VALID_COUNT = 0
ERROR_COUNT = 0
PROGRESS_LOCK = threading.Lock()

BANNER = '''
++++++++++++++++++++++++++
      amazon checks
++++++++++++++++++++++++++
'''

# Known S3 domain names
S3_URL = 's3.amazonaws.com'
APPS_URL = 'awsapps.com'

# Known AWS region names. This global will be used unless the user passes
# in a specific region name. (NOT YET IMPLEMENTED)
AWS_REGIONS = ['amazonaws.com',
               'ap-east-1.amazonaws.com',
               'us-east-2.amazonaws.com',
               'us-west-1.amazonaws.com',
               'us-west-2.amazonaws.com',
               'ap-south-1.amazonaws.com',
               'ap-northeast-1.amazonaws.com',
               'ap-northeast-2.amazonaws.com',
               'ap-northeast-3.amazonaws.com',
               'ap-southeast-1.amazonaws.com',
               'ap-southeast-2.amazonaws.com',
               'ca-central-1.amazonaws.com',
               'cn-north-1.amazonaws.com.cn',
               'cn-northwest-1.amazonaws.com.cn',
               'eu-central-1.amazonaws.com',
               'eu-west-1.amazonaws.com',
               'eu-west-2.amazonaws.com',
               'eu-west-3.amazonaws.com',
               'eu-north-1.amazonaws.com',
               'sa-east-1.amazonaws.com']


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
        
        progress_percentage = (CURRENT_COUNT / TOTAL_COUNT) * 100
        
        # Only update display every 25% or if it's the last item
        if progress_percentage % 25 < (1 / TOTAL_COUNT * 100) or CURRENT_COUNT == TOTAL_COUNT:
            print(f'\r        Progress: {progress_percentage:.1f}% ({CURRENT_COUNT}/{TOTAL_COUNT}), Valid: {VALID_COUNT}, Errors: {ERROR_COUNT}\r', end='', flush=True)


def print_s3_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'aws', 'msg': '', 'target': '', 'access': ''}

    # Always increment the current count when we receive a response
    update_progress(increment_current=True)

    if reply.status_code == 404:
        pass
    elif 'Bad Request' in reply.reason:
        pass
    elif reply.status_code == 200:
        # Found valid resource - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'OPEN S3 BUCKET'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        utils.list_bucket_contents(reply.url)
    elif reply.status_code == 403:
        # Found valid but restricted resource - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'Protected S3 Bucket'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif 'Slow Down' in reply.reason:
        # Increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print("[!] You've been rate limited, skipping rest of check...")
        return 'breakout'
    else:
        # Increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")

    return None


def check_s3_buckets(names, threads):
    """
    Checks for open and restricted Amazon S3 buckets
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for S3 buckets")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0
    
    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        candidates.append(f'{name}.{S3_URL}')
        
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_s3_response,
                        threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed S3 bucket check")
    
    # Stop the time
    utils.stop_timer(start_time)


def check_awsapps(names, threads, nameserver, nameserverfile=False):
    """
    Checks for existence of AWS Apps
    (ie. WorkDocs, WorkMail, Connect, etc.)
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    data = {'platform': 'aws', 'msg': 'AWS App Found:', 'target': '', 'access': ''}

    print("\n[+] Checking for AWS Apps")
    
    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

    # Initialize the list of domain names to look up
    candidates = []

    # Initialize the list of valid hostnames
    valid_names = []

    # Take each mutated keyword craft a domain name to lookup.
    for name in names:
        candidates.append(f'{name}.{APPS_URL}')
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Create a wrapper function to update progress during DNS lookup
    def dns_callback(name, result):
        update_progress(increment_current=True)
        if result:
            update_progress(increment_current=False, increment_valid=True)
            return True
        return False

    # AWS Apps use DNS sub-domains. First, see which are valid.
    valid_names = utils.fast_dns_lookup(candidates, nameserver,
                                        nameserverfile, threads=threads,
                                        callback=dns_callback)

    for name in valid_names:
        data['target'] = f'https://{name}'
        data['access'] = 'protected'
        utils.fmt_output(data)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed AWS Apps check")
    
    # Stop the timer
    utils.stop_timer(start_time)


def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)

    # Use user-supplied AWS region if provided
    # if not regions:
    #    regions = AWS_REGIONS
    check_s3_buckets(names, args.threads)
    check_awsapps(names, args.threads, args.nameserver, args.nameserverfile)
