import requests
import time
import argparse
import os
import logging

# Set commandline arguments
parser = argparse.ArgumentParser(description="Verify if email address has been comprimised")
parser.add_argument("-a", dest="address", help="Single email address to check")
parser.add_argument("-f", dest="filename",
                    help="File to be checked with one email address per line")
args = parser.parse_args()

# Config for logging and output debug logs
logging.basicConfig(filename='hibperror.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
logger=logging.getLogger(__name__)

try:
    1/0
except ZeroDivisionError as err:
    logger.error(err)

# Set rate, server and ssl certification

rate = 1.3 # 1.3 seconds is a safe value
server = "haveibeenpwned.com"
sslVerify = True

# Define arguments

address = str(args.address)
filename = str(args.filename)
lstEmail = ["info@example.com","example@example.com"]

# Set API key:
# API key needs to be stored in environment variable, use hibp-api-key
# export hibp=""

api = os.environ.get("hibp")

headers = {
    "hibp-api-key": api
}

# Run script if input is correct

def main():
    if address != "None":
        checkAddress(address)
    elif filename != "None":
        email = [line.rstrip('\n') for line in open(filename)]
        for email in email:
            checkAddress(email)
    else:
        for email in lstEmail:
            checkAddress(email)

# Check address against database and output results

def checkAddress(email):
    sleep = rate # Reset default acceptable rate
    check = requests.get("https://" + server + "/api/v3/breachedaccount/" + email + "?includeUnverified=true",
                         headers=headers,
                         verify = sslVerify)
    if str(check.status_code) == "404": # The address has not been found.
        print("[i] " + email + " has not been found in a database dump.")
        time.sleep(sleep) # Sleep so that we don't trigger the rate limit
        return False
    elif str(check.status_code) == "200": # The address has been breached!
        print("[!] " + email + " has been found in a database dump.")
        time.sleep(sleep) # Sleep so that we don't trigger the rate limit
        with open("pwned.log", "a") as f:
            f.write("[!] " + email + " has been found in a database dump." + "\n")
        return True
    elif str(check.status_code) == "429": # Rate limit triggered
        print("[!] Rate limit exceeded, server instructed us to retry after " + check.headers['Retry-After'] + " seconds")
        print("    Refer to acceptable use of API: https://haveibeenpwned.com/API/v2#AcceptableUse")
        sleep = float(check.headers['Retry-After'])
        time.sleep(sleep)
        checkAddress(email)
    else:
        print("[!] Something went wrong while checking " + email + "\n please check API or Networking configuration") # Unknown error, perhaps networking
        time.sleep(sleep)
        return True

if __name__ == "__main__":
    main()
