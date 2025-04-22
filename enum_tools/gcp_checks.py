"""
Google-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

import threading
from enum_tools import utils
from enum_tools import gcp_regions

# Add global progress tracking variables
CURRENT_COUNT = 0
TOTAL_COUNT = 0
VALID_COUNT = 0
ERROR_COUNT = 0
PROGRESS_LOCK = threading.Lock()

BANNER = '''
++++++++++++++++++++++++++
      google checks
++++++++++++++++++++++++++
'''

# Known GCP domain names
GCP_URL = 'storage.googleapis.com'
FBRTDB_URL = 'firebaseio.com'
APPSPOT_URL = 'appspot.com'
FUNC_URL = 'cloudfunctions.net'
FBAPP_URL = 'firebaseapp.com'

# Hacky, I know. Used to store project/region combos that report at least
# one cloud function, to brute force later on
HAS_FUNCS = []


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
            
            # Only update display every 5% or if it's the last item
            if progress_percentage % 5 < (1 / TOTAL_COUNT * 100) or CURRENT_COUNT == TOTAL_COUNT:
                print(f'\r        Progress: {progress_percentage:.1f}% ({CURRENT_COUNT}/{TOTAL_COUNT}), Valid: {VALID_COUNT}, Errors: {ERROR_COUNT}\r', end='', flush=True)


def print_bucket_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    # Always increment the current count when we receive a response
    update_progress(increment_current=True)

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        # Found valid resource - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'OPEN GOOGLE BUCKET'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        utils.list_bucket_contents(reply.url + '/')
    elif reply.status_code == 403:
        # Found valid but protected resource - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'Protected Google Bucket'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        # Unknown response - increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_gcp_buckets(names, threads):
    """
    Checks for open and restricted Google Cloud buckets
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Google buckets")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        candidates.append(f'{GCP_URL}/{name}')
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_bucket_response,
                        threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Google buckets check")
    
    # Stop the time
    utils.stop_timer(start_time)


def print_fbrtdb_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    # Always increment the current count when we receive a response
    update_progress(increment_current=True)

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        # Found valid resource - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'OPEN GOOGLE FIREBASE RTDB'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 401:
        # Found valid but protected resource - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'Protected Google Firebase RTDB'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 402:
        # Found valid but payment required resource - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'Payment required on Google Firebase RTDB'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    elif reply.status_code == 423:
        # Found valid but deactivated resource - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'The Firebase database has been deactivated.'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    else:
        # Unknown response - increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_fbrtdb(names, threads):
    """
    Checks for Google Firebase RTDB
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Google Firebase Realtime Databases")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # Firebase RTDB names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append(f'{name}.{FBRTDB_URL}/.json')
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_fbrtdb_response,
                        threads=threads,
                        redir=False)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Google Firebase Realtime Databases check")
    
    # Stop the time
    utils.stop_timer(start_time)
      
      
def print_fbapp_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    # Always increment the current count when we receive a response
    update_progress(increment_current=True)

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        # Found valid resource - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'OPEN GOOGLE FIREBASE APP'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    else:
        # Unknown response - increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")

def check_fbapp(names, threads):
    """
    Checks for Google Firebase Applications
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Google Firebase Applications")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # Firebase App names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append(f'{name}.{FBAPP_URL}')
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_fbapp_response,
                        threads=threads,
                        redir=False)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Google Firebase Applications check")
    
    # Stop the time
    utils.stop_timer(start_time)

def print_appspot_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    # Always increment the current count when we receive a response
    update_progress(increment_current=True)

    if reply.status_code == 404:
        pass
    elif str(reply.status_code)[0] == 5:
        # Found valid resource with error - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'Google App Engine app with a 50x error'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in (200, 302, 404):
        if 'accounts.google.com' in reply.url:
            # Found valid but protected resource - increment valid counter
            update_progress(increment_current=False, increment_valid=True)
            
            data['msg'] = 'Protected Google App Engine app'
            data['target'] = reply.history[0].url
            data['access'] = 'protected'
            utils.fmt_output(data)
        else:
            # Found valid open resource - increment valid counter
            update_progress(increment_current=False, increment_valid=True)
            
            data['msg'] = 'Open Google App Engine app'
            data['target'] = reply.url
            data['access'] = 'public'
            utils.fmt_output(data)
    else:
        # Unknown response - increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_appspot(names, threads):
    """
    Checks for Google App Engine sites running on appspot.com
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT
    
    print("[+] Checking for Google App Engine apps")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # App Engine project names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append(f'{name}.{APPSPOT_URL}')
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_appspot_response,
                        threads=threads)

    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed Google App Engine apps check")
    
    # Stop the time
    utils.stop_timer(start_time)


def print_functions_response1(reply):
    """
    Parses the HTTP reply the initial Cloud Functions check

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    # Always increment the current count when we receive a response
    update_progress(increment_current=True)

    if reply.status_code == 404:
        pass
    elif reply.status_code == 302:
        # Found valid cloud function - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'Contains at least 1 Cloud Function'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        HAS_FUNCS.append(reply.url)
    else:
        # Unknown response - increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def print_functions_response2(reply):
    """
    Parses the HTTP reply from the secondary, brute-force Cloud Functions check

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    # Always increment the current count when we receive a response
    update_progress(increment_current=True)

    if 'accounts.google.com/ServiceLogin' in reply.url:
        pass
    elif reply.status_code in (403, 401):
        # Found valid but protected function - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'Auth required Cloud Function'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 405:
        # Found valid POST-only function - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'UNAUTHENTICATED Cloud Function (POST-Only)'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in (200, 404):
        # Found valid GET-OK function - increment valid counter
        update_progress(increment_current=False, increment_valid=True)
        
        data['msg'] = 'UNAUTHENTICATED Cloud Function (GET-OK)'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    else:
        # Unknown response - increment error counter
        update_progress(increment_current=False, increment_error=True)
        
        print(f"    Unknown status codes being received from {reply.url}:\n"
              "       {reply.status_code}: {reply.reason}")


def check_functions(names, brute_list, quickscan, threads):
    """
    Checks for Google Cloud Functions running on cloudfunctions.net

    This is a two-part process. First, we want to find region/project combos
    that have existing Cloud Functions. The URL for a function looks like this:
    https://[ZONE]-[PROJECT-ID].cloudfunctions.net/[FUNCTION-NAME]

    We look for a 302 in [ZONE]-[PROJECT-ID].cloudfunctions.net. That means
    there are some functions defined in that region. Then, we brute force a list
    of possible function names there.

    See gcp_regions.py to define which regions to check. The tool currently
    defaults to only 1 region, so you should really modify it for best results.
    """
    global CURRENT_COUNT, TOTAL_COUNT, VALID_COUNT, ERROR_COUNT, HAS_FUNCS
    
    # Clear the global HAS_FUNCS for this run
    HAS_FUNCS = []
    
    print("[+] Checking for project/zones with Google Cloud Functions.")

    # Initialize progress counters
    CURRENT_COUNT = 0
    VALID_COUNT = 0
    ERROR_COUNT = 0

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []
      
    # Pull the regions from a config file
    regions = gcp_regions.REGIONS

    print(f"[*] Testing across {len(regions)} regions defined in the config file")

    # Take each mutated keyword craft a url with the correct format
    for region in regions:
        candidates += [region + '-' + name + '.' + FUNC_URL for name in names]
    
    # Set total count for progress tracking
    TOTAL_COUNT = len(candidates)
    
    # Show initial progress
    update_progress(increment_current=False)

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_functions_response1,
                        threads=threads,
                        redir=False)
    
    # Ensure we show 100% at the end
    update_progress(increment_current=False)
    print("\n[+] Completed initial Google Cloud Functions check")

    # Return from function if we have not found any valid combos
    if not HAS_FUNCS:
        utils.stop_timer(start_time)
        return

    # Also bail out if doing a quick scan
    if quickscan:
        return

    # If we did find something, we'll use the brute list. This will allow people
    # to provide a separate fuzzing list if they choose.
    print(f"[*] Brute-forcing function names in {len(HAS_FUNCS)} project/region combos")

    # Load brute list in memory, based on allowed chars/etc
    brute_strings = utils.get_brute(brute_list)

    # The global was built in a previous function. We only want to brute force
    # project/region combos that we know have existing functions defined
    for func in HAS_FUNCS:
        # Initialize progress counters for each function
        CURRENT_COUNT = 0
        VALID_COUNT = 0
        ERROR_COUNT = 0
        
        print(f"[*] Brute-forcing {len(brute_strings)} function names in {func}")
        # Initialize the list of initial URLs to check. Strip out the HTTP
        # protocol first, as that is handled in the utility
        func = func.replace("http://", "")

        # Noticed weird behaviour with functions when a slash is not appended.
        # Works for some, but not others. However, appending a slash seems to
        # get consistent results. Might need further validation.
        candidates = [func + brute + '/' for brute in brute_strings]
        
        # Set total count for progress tracking
        TOTAL_COUNT = len(candidates)
        
        # Show initial progress
        update_progress(increment_current=False)

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(candidates, use_ssl=False,
                            callback=print_functions_response2,
                            threads=threads)
        
        # Ensure we show 100% at the end of each function
        update_progress(increment_current=False)
        print("")

    print("[+] Completed Google Cloud Functions brute-force")
    # Stop the time
    utils.stop_timer(start_time)


def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)

    check_gcp_buckets(names, args.threads)
    check_fbrtdb(names, args.threads)
    check_fbapp(names, args.threads)
    check_appspot(names, args.threads)
    check_functions(names, args.brute, args.quickscan, args.threads)
