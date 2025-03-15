# -*- coding: utf-8 -*-
"""
Created on on Sat 15 3:41:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Javascript Based Cache Attack Detector")
print(Fore.GREEN+font)

import requests
import time

# Function to send a request and analyze cache headers
def detect_cache_attack(url):
    # Send the first request
    print(f"Sending request to {url}...")
    response_1 = requests.get(url)
    
    if 'Cache-Control' in response_1.headers:
        print(f"Cache-Control Header: {response_1.headers['Cache-Control']}")
    else:
        print("No Cache-Control header found. This could be a security concern.")

    # Check if there's a "Cache-Control" header
    if "no-store" in response_1.headers.get('Cache-Control', ""):
        print("Cache-Control header indicates no caching.")
    else:
        print("Cache-Control header does not prevent caching. Possible vulnerability.")
    
    # Add some delay before making the second request to simulate timing
    time.sleep(2)  # To simulate the passage of time between requests
    
    # Send the second request
    print(f"Sending second request to {url}...")
    response_2 = requests.get(url)
    
    # Compare response times and headers to check for caching issues
    if response_1.status_code == response_2.status_code:
        print("Status codes match, analyzing response times for potential cache differences.")
        response_time_diff = abs(response_2.elapsed.total_seconds() - response_1.elapsed.total_seconds())
        print(f"Difference in response times: {response_time_diff:.4f} seconds")

        if response_time_diff < 0.1:
            print("No significant difference in response times. Likely cached content.")
        else:
            print("Significant difference in response times. Content likely not cached.")
    else:
        print("Status codes differ between requests. This could indicate different responses.")

    # Check if the server uses proper cache headers
    if "ETag" in response_1.headers:
        print(f"ETag Header: {response_1.headers['ETag']}")
    else:
        print("ETag Header missing. This could be an indicator of improper caching mechanisms.")
    
    # Check for Cache-Control headers on the second request
    if 'Cache-Control' in response_2.headers:
        print(f"Cache-Control Header (2nd Request): {response_2.headers['Cache-Control']}")
    else:
        print("No Cache-Control header found in the second request. This could be a vulnerability.")

# Main function to prompt the user for the URL
def main():
    # Prompt the user to enter the URL of the website
    url = input("Enter the URL of the website to check for JavaScript-based cache attack vulnerabilities:").strip()
    
    # Validate if the URL includes http:// or https://
    if not url.startswith("http://") and not url.startswith("https://"):
        print("Invalid URL. Please make sure the URL starts with http:// or https://")
        return
    
    # Start detecting the cache vulnerabilities
    print("\nStarting analysis of cache vulnerabilities...")
    detect_cache_attack(url)

if __name__ == "__main__":
    main()
