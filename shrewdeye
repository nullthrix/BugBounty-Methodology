#!/usr/bin/python3

import os
import sys
import requests
import argparse

def print_message():
    MAGENTA = "\033[35m"
    RESET = "\033[0m"
    print("\n")
    print(f"{MAGENTA}Subdomains collector from shrewdeye.app. Just provide a file with all the domains.{RESET}")
    print("\n")
def download_file(url, filename):
    response = requests.get(url)
    if response.status_code == 200:
        with open(filename, 'wb') as file:
            file.write(response.content)
        print(f"Downloaded: {filename}")
    else:
        print(f"Failed to download {filename}. Status code: {response.status_code}")
def main(domains_file, separate_files, output_file):
    if separate_files:
        output_directory = "shrewdeye_subdomains"
        if not os.path.exists(output_directory):
            os.makedirs(output_directory)
    with open(domains_file, 'r') as file:
        domains = [line.strip() for line in file.readlines()]
    if separate_files:
        for domain in domains:
            if domain:
                url = f"https://shrewdeye.app/domains/{domain}.txt"
                filename = os.path.join(output_directory, f"{domain}.txt")
                download_file(url, filename)
    else:
        with open(output_file, 'wb') as all_file:
            for domain in domains:
                if domain:
                    url = f"https://shrewdeye.app/domains/{domain}.txt"
                    response = requests.get(url)
                    if response.status_code == 200:
                        all_file.write(response.content)
                        print(f"Downloaded: {domain}.txt")
                    else:
                        print(f"Failed to download {domain}.txt. Status code: {response.status_code}")
        print(f"All subdomains compiled into: {output_file}")
if __name__ == "__main__":
    print_message()
    parser = argparse.ArgumentParser(description="Subdomains collector from shrewdeye.app")
    parser.add_argument("domains_file", help="File containing the list of domains")
    parser.add_argument("-s", "--separate", action="store_true", help="Save each domain in a separate file")
    parser.add_argument("-o", "--output", default="shrewdeye_all_domains.txt", help="Specify output file name (default: shrewdeye_all_domains.txt)")
    args = parser.parse_args()

    main(args.domains_file, args.separate, args.output)
