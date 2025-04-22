"""
Helper utilities for cloud_enum.
"""

import sys
import json
import time
import datetime
import requests
import concurrent.futures
import dns.resolver

# Set the global flag for the output file
LOGFILE = False
FORMAT = False

def init_logfile(logfile, format_type):
    """
    Set the global logfile variable.
    """
    global LOGFILE
    global FORMAT
    LOGFILE = logfile
    FORMAT = format_type


def start_timer():
    """
    Helper function to return current time - used for countdown timer.
    """
    return time.time()


def stop_timer(start):
    """
    Helper function to calculate and print elapsed time.
    """
    end = time.time()
    minutes, seconds = divmod(int(end-start), 60)
    print(f"\n[+] Elapsed time: {minutes} minutes and {seconds} seconds\n")


def get_url_batch(url_list, use_ssl=False, callback='', threads=5):
    """
    Helper function to run requests on a batch of URLs.
    Will use callback function to print output, etc.
    """
    # This will run a thread pool and collect responses
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # This dict will map each future with its URL
        futures_to_urls = {}

        # Prepare the GET request for each URL
        for url in url_list:
            # Handle http or https requests
            if use_ssl:
                remote_url = "https://" + url
                futures_to_urls[executor.submit(
                    requests.head, remote_url, timeout=3)] = remote_url
            else:
                remote_url = "http://" + url
                futures_to_urls[executor.submit(
                    requests.head, remote_url, timeout=3)] = remote_url

        # Process futures as they complete.
        for future in concurrent.futures.as_completed(futures_to_urls):
            url = futures_to_urls[future]
            try:
                # This gives us the resulting HTTP object from 'get_url'
                reply = future.result()
                # This handles the reply (prints, etc), running the function
                # that the caller passed us
                result = callback(reply)
                if result == 'breakout':
                    break

            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as error:
                # Callback expects a reply object, not a string. Not going
                # to pass it anything here, just going to print to the
                # screen a very simple message
                pass
            except requests.exceptions.InvalidURL as error:
                print("{}: {}".format(url, error))
            except requests.exceptions.TooManyRedirects:
                print("{}: Too many redirects".format(url))

def set_progress_callback(callback):
    """
    This function is a no-op in the current implementation.
    
    It's here for compatibility with the main cloud_enum.py file,
    but the progress tracking is handled directly by each module.
    """
    # In this implementation, each module handles its own progress
    # tracking directly, so we don't need to do anything here.
    pass

def fmt_output(data):
    """
    Standardizes output formatting.
    """
    # Build a timestamp for the record
    time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Set formatting based on platform
    if data['platform'].lower() == 'aws':
        if data['access'].lower() == 'public':
            color = "orange"
            bold = True
        else:
            color = "green"
            bold = False
    elif data['platform'].lower() == 'azure':
        if data['access'].lower() == 'public':
            color = "orange"
            bold = True
        else:
            color = "green"
            bold = False
    elif data['platform'].lower() == 'gcp':
        if data['access'].lower() == 'public':
            color = "orange"
            bold = True
        else:
            color = "green"
            bold = False
    else:
        color = None
        bold = False

    # Handles a text log file
    if LOGFILE and FORMAT == 'text':
        with open(LOGFILE, 'a') as log:
            text_with_time = f"{time} | [{data['platform']}] [+] {data['msg']} {data['target']}"
            log.write(f"{text_with_time}\n")

    # Handles a json log file
    if LOGFILE and FORMAT == 'json':
        with open(LOGFILE, 'a') as log:
            output = {}
            output['timestamp'] = time
            output['platform'] = data['platform']
            output['message'] = data['msg']
            output['target'] = data['target']
            output['access'] = data['access']
            log.write(f"{json.dumps(output)}\n")

    # Handles a csv log file
    if LOGFILE and FORMAT == 'csv':
        with open(LOGFILE, 'a') as log:
            data_fields = [
                time,
                data['platform'],
                data['msg'],
                data['target'],
                data['access']
            ]
            log.write(f"{','.join(data_fields)}\n")

    printc(f"[{data['platform']}] [+] {data['msg']} {data['target']}",
           color=color, bold=bold)


def printc(text, color=None, bold=False):
    """
    Print with color. Accepts a text string, optional color, and bold flag.
    """
    # ANSI escape sequences
    green = '\033[92m'
    orange = '\033[33m'
    red = '\033[31m'
    white = '\033[37m'
    bold_code = '\033[1m'
    end = '\033[0m'

    # Set color flag to a color text or revert to white
    color_flag = white
    if color:
        if color == 'orange':
            color_flag = orange
        elif color == 'green':
            color_flag = green
        elif color == 'red':
            color_flag = red

    # Build the appropriate formatting
    if bold:
        print(f"{bold_code}{color_flag}{text}{end}")
    else:
        print(f"{color_flag}{text}{end}")


def list_bucket_contents(url):
    """
    List open S3 bucket contents
    """
    # This will be called on a URL that's already been confirmed to be open
    try:
        response = requests.get(url, timeout=3)
        if "Error" in response.text:
            return
        if 'ListBucketResult' in response.text:
            domain_name = url.split('/')[2]
            printc("      Listing open bucket contents - {}:".format(domain_name),
                   color='orange', bold=True)
            for line in response.text.splitlines():
                if "<Key>" in line:
                    printc("         {}".format(
                        line.split("<Key>")[1].split("</Key>")[0]),
                           color='red', bold=True)
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout) as error:
        pass


def fast_dns_lookup(names, nameserver, nameserverfile=False, threads=5, callback=None):
    """
    Helper function to resolve DNS names.
    Returns valid DNS names.
    """
    # Pick a single nameserver if multiple are provided
    if nameserverfile:
        with open(nameserverfile, 'r') as input_file:
            nameserver_list = [item.strip() for item in input_file.readlines()]
            nameserver = nameserver_list[0]
    
    valid = []
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = [nameserver]
    
    # This will run a thread pool and collect responses
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Map each future to its name for lookup in the callback
        futures_to_names = {executor.submit(dns_lookup, name): name for name in names}

        # Process futures as they complete.
        for future in concurrent.futures.as_completed(futures_to_names):
            name = futures_to_names[future]
            try:
                # This gives us the result from dns_lookup
                result = future.result()
                
                # If callback is provided, use it for progress tracking
                if callback and callable(callback):
                    if callback(name, result):
                        valid.append(name)
                # Otherwise use the original behavior
                elif result:
                    valid.append(name)
                    
            except Exception as error:
                # If callback is provided for errors too
                if callback and callable(callback):
                    callback(name, False)
                
    return valid


def dns_lookup(name):
    """
    Helper function to resolve a single DNS name.
    Returns True if valid, else False.
    """
    # Restrict lookup object to IPv4 as IPv6 lookups are much slower
    lookup = dns.resolver.Resolver()
    try:
        answer = lookup.resolve(name, 'A')
        if answer:
            return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except dns.exception.Timeout:
        # Try one more time on timeouts
        try:
            answer = lookup.resolve(name, 'A')
            if answer:
                return True
        except:
            pass
    return False
