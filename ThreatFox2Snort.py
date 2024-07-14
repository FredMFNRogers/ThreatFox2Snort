import csv
import requests
import logging
import argparse
import configparser
import re
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to download the data from threatfox.abuse.ch
def download_data(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open('recent.csv', 'wb') as file:
            file.write(response.content)
        logging.info('Data downloaded successfully.')
    except requests.RequestException as e:
        logging.error(f'Error downloading data: {e}')
        raise

# Function to check if a string is a dotted quad (IPv4 address)
def is_dotted_quad_or_url(ioc):
    return re.match(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', ioc) is not None or re.match(r'^https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?(/.*)?$', ioc) is not None

# Function to extract the IOC and malware type fields from the CSV file
def extract_iocs(filename):
    iocs_and_types = []
    with open(filename, 'r') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip the header
        for row in reader:
            if len(row) > 5:
                ioc = row[2].replace('"', '').strip()  # Remove quotes and strip whitespace
                type_ = row[5].replace('"', '').strip()  # Remove quotes and strip whitespace
                if not is_dotted_quad_or_url(ioc):
                    iocs_and_types.append((ioc, type_))
                else:
                    logging.info(f'Skipping dotted quad or URL IOC: {ioc}')
    logging.info('IOCs extracted successfully.')
    return iocs_and_types

# Function to create the Snort rules and write to a file
def create_snort_rules(iocs_and_types, starting_sid, output_file):
    current_sid = starting_sid
    with open('new.txt', 'w') as rules_file:
        for ioc, type_ in iocs_and_types:
            rule = (f'alert tcp any any -> any any '
                    f'(msg: "[THREATFOX] Possible Indicator of Compromise Detected: {type_}"; '
                    f'content:"{ioc}"; '
                    f'reference:url,threatfox.abuse.ch/browse.php?search=malware%3A{type_}; '
                    f'sid:{current_sid}; '
                    f'rev:1;)')
            rules_file.write(rule + '\n')
            current_sid += 1
    # Write the final rules file
    with open('new.txt', 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            outfile.write(line)
    logging.info(f'Snort rules written to {output_file}.')
    # Clean up temporary files
    import os
    os.remove('recent.csv')
    os.remove('new.txt')
    logging.info('Temporary files cleaned up.')

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Generate Snort rules from ThreatFox IOCs.',
        epilog='This script generates Snort rules from ThreatFox IOCs based on URLs and file hashes while excluding entries containing dotted quads.'
    )
    parser.add_argument('--config', type=str, default='config.ini', help='Path to configuration file')
    parser.add_argument('-s', '--sid_start', type=int, help='Starting SID for rules')
    parser.add_argument('-o', '--output', type=str, help='Output file for Snort rules')
    args = parser.parse_args()

    # Load configuration
    config = configparser.ConfigParser()
    config.read(args.config)

    starting_sid = args.sid_start or config.getint('Settings', 'starting_sid')
    output_file = args.output or config.get('Settings', 'output_file')

    # Download data and create Snort rules
    url = 'https://threatfox.abuse.ch/export/csv/recent/'
    download_data(url)
    iocs_and_types = extract_iocs('recent.csv')
    create_snort_rules(iocs_and_types, starting_sid, output_file)

if __name__ == '__main__':
    main()
