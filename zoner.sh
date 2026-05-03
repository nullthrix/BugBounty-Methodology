#!/bin/bash

# Function to perform zone transfer
perform_zone_transfer() {
    local domain=$1

    echo "Fetching authoritative nameservers for $domain..."

    # Get the authoritative nameservers using dig
    NAMESERVERS=$(dig NS $domain +short)

    # If no nameservers are found, exit
    if [ -z "$NAMESERVERS" ]; then
        echo "No nameservers found for $domain"
        return
    fi

    # Try zone transfer with each nameserver
    for NS in $NAMESERVERS; do
        echo "Trying zone transfer with nameserver: $NS"
        
        # Perform a zone transfer with a 5-second timeout
        RESULT=$(timeout 5 host -l $domain $NS 2>&1)
        
        # Check if the timeout occurred or if zone transfer was successful
        if [ $? -eq 124 ]; then
            echo "Zone transfer attempt timed out for $NS"
        elif [[ $RESULT == *"has address"* ]]; then
            echo "Zone transfer successful with $NS"
            echo "$RESULT"
        else
            echo "Zone transfer failed with $NS. Error: $RESULT"
        fi
        echo "--------------------------------------------------"
    done
}

# Parse command-line options
while getopts "d:l:" opt; do
    case $opt in
        d)  # -d for single domain
            DOMAIN=$OPTARG
            perform_zone_transfer $DOMAIN
            ;;
        l)  # -l for file with domains
            FILE=$OPTARG
            if [ ! -f "$FILE" ]; then
                echo "Error: File '$FILE' does not exist."
                exit 1
            fi
            while IFS= read -r DOMAIN; do
                # Skip empty lines and comments
                if [[ -z "$DOMAIN" || "$DOMAIN" =~ ^# ]]; then
                    continue
                fi
                perform_zone_transfer $DOMAIN
            done < "$FILE"
            ;;
        *)
            echo "Usage: $0 -d <domain> | -l <file>"
            exit 1
            ;;
    esac
done

# Check if neither -d nor -l was provided
if [ -z "$DOMAIN" ] && [ -z "$FILE" ]; then
    echo "Usage: $0 -d <domain> | -l <file>"
    exit 1
fi
