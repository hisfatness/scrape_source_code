from progress.bar import Bar
import argparse
import requests
import re

# ANSI color codes
GREEN = '\033[92m'
RESET = '\033[0m'

def find_sensitive_data(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        html_content = response.text

        # Define the regular expression patterns and corresponding key types
        patterns = [
            (r'cloudinary://.*', 'Cloudinary'),
            (r'.*firebaseio\.com', 'Firebase URL'),
            (r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})', 'Slack Token'),
            (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA private key'),
            (r'-----BEGIN DSA PRIVATE KEY-----', 'SSH (DSA) private key'),
            (r'-----BEGIN EC PRIVATE KEY-----', 'SSH (EC) private key'),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP private key block'),
            (r'AKIA[0-9A-Z]{16}', 'Amazon AWS Access Key ID'),
            (r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'Amazon MWS Auth Token'),
            (r'AWS API Key: AKIA[0-9A-Z]{16}', 'AWS API Key'),
            (r'EAACEdEose0cBA[0-9A-Za-z]+', 'Facebook Access Token'),
            (r'[fF][aA][cC][eE][bB][oO][oO][kK].*["\'][0-9a-f]{32}["\']', 'Facebook OAuth'),
            (r'[gG][iI][tT][hH][uU][bB].*["\'][0-9a-zA-Z]{35,40}["\']', 'GitHub'),
            (r'[aA][pP][iI][_]?[kK][eE][yY].*["\'][0-9a-zA-Z]{32,45}["\']', 'Generic API Key'),
            (r'[sS][eE][cC][rR][eE][tT].*["\'][0-9a-zA-Z]{32,45}["\']', 'Generic Secret'),
            (r'AIza[0-9A-Za-z\\-_]{35}', 'Google API Key'),
            (r'AIza[0-9A-Za-z\\-_]{35}', 'Google Cloud Platform API Key'),
            (r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com', 'Google Cloud Platform OAuth'),
            (r'AIza[0-9A-Za-z\\-_]{35}', 'Google Drive API Key'),
            (r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com', 'Google Drive OAuth'),
            (r'\"type\": \"service_account\"', 'Google (GCP) Service-account'),
            (r'AIza[0-9A-Za-z\\-_]{35}', 'Google Gmail API Key'),
            (r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com', 'Google Gmail OAuth'),
            (r'ya29\\.[0-9A-Za-z\\-_]+', 'Google OAuth Access Token'),
            (r'AIza[0-9A-Za-z\\-_]{35}', 'Google YouTube API Key'),
            (r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com', 'Google YouTube OAuth'),
            (r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', 'Heroku API Key'),
            (r'[0-9a-f]{32}-us[0-9]{1,2}', 'MailChimp API Key'),
            (r'key-[0-9a-zA-Z]{32}', 'Mailgun API Key'),
            (r'[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}["\'\\s]', 'Password in URL'),
            (r'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}', 'PayPal Braintree Access Token'),
            (r'sk_live_[0-9a-z]{32}', 'Picatic API Key'),
            (r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}', 'Slack Webhook'),
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe API Key'),
            (r'rk_live_[0-9a-zA-Z]{24}', 'Stripe Restricted API Key'),
            (r'sq0atp-[0-9A-Za-z\\-_]{22}', 'Square Access Token'),
            (r'sq0csp-[0-9A-Za-z\\-_]{43}', 'Square OAuth Secret'),
            (r'SK[0-9a-fA-F]{32}', 'Twilio API Key'),
            (r'[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}', 'Twitter Access Token'),
            (r'[tT][wW][iI][tT][tT][eE][rR].*["\'][0-9a-zA-Z]{35,44}["\']', 'Twitter OAuth'),
        ]


        # Search for the patterns in the HTML content
        matches = []
        for pattern, key_type in patterns:
            match = re.search(pattern, html_content)
            if match:
                matches.append((key_type, match.group()))

        # Print the sensitive data found in a readable format
        if matches:
            print(GREEN + f"\nSensitive Data found in {url}:" + RESET)
            for key_type, value in matches:
                print(f"  - {key_type}: {value}")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Find Sensitive Data in the source code of URLs.")
    parser.add_argument("-f", "--file", help="Path to the text file containing URLs", required=True)
    args = parser.parse_args()

    with open(args.file, "r") as file:
        urls = file.read().splitlines()

    # Initialize progress bar
    bar = Bar('Processing URLs', max=len(urls))

    for url in urls:
        find_sensitive_data(url)
        bar.next()

    bar.finish()

if __name__ == "__main__":
    main()
