#!/bin/bash
#
# Print X.509 certificate (PEM format) fingerprint
#

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <certificate_file.pem>"
    exit 1
fi

CERTIFICATE_FILE=$1
CMD="openssl x509 -noout -fingerprint -sha1 -inform pem -in $CERTIFICATE_FILE"
echo $CMD
eval $CMD
