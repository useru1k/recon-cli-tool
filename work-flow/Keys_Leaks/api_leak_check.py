import re
import sys


# Requirement re and sys

patterns = {
    'MongoDB Connection': r'mongodb(?:\+srv)?:\/\/[^\s]+',
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Access Key': r'[A-Za-z0-9/+=]{40}',
    'Google Cloud API Key': r'AIza[0-9A-Za-z-_]{35}',
    'Slack Webhook URL': r'https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+',
    'Slack API Token': r'xox[baprs]-[0-9A-Za-z]{10,48}',
    'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24}',
    'GitHub Token': r'ghp_[A-Za-z0-9_]{36,}',
    'Twilio Account SID': r'AC[a-zA-Z0-9]{32}',
    'Twilio Auth Token': r'[a-f0-9]{32}',
    'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'Azure Storage Key': r'[a-zA-Z0-9+\/]{88}',
    'PayPal/Braintree Access Token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'Square Access Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
    'Mailgun Private API Key': r'key-[0-9a-zA-Z]{32}',
    'SendGrid API Key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    'Dropbox Access Token': r'[A-Za-z0-9_\-]{11,15}\.[A-Za-z0-9_\-]{11,15}\.[A-Za-z0-9_\-]{11,64}'
}

def scan_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            for secret_type, pattern in patterns.items():
                if re.search(pattern, content):
                    print(f"[!] Warning: {secret_type} detected/Found in {file_path}")
                    return True  # Stop on first secret found
    except FileNotFoundError:
        print(f"[!] Error: File {file_path} not found.")
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[$] You are Wrong : Usage : python <secret_scan>.py <file1> <file2> ...")
        sys.exit(1)

    files_to_scan = sys.argv[1:]
    for file in files_to_scan:
        if scan_file(file):
            print(f"[!] Secret found in the {file}. Please remove it.")
        else:
            print(f"[*] No secrets detected in {file}.")
