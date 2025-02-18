#!/bin/bash

if [[ $OSTYPE == msys ]]; then
  echo Detected GitBash/Cygwin on Windows
  # GitBash/Cygwin on Windows requires escaping the starting slash of the the subject DNS
  # Otherwise it gets expanded into a filesystem path.
  DN_PREFIX="//"
else
  DN_PREFIX="/"
fi

mkdir out
HOST=$1
X509_O=$2
X509_L=$3
UZI=$4
URA=$5
AGB=$6

if [[ -z $HOST || -z $X509_O || -z $X509_L || -z $UZI || -z $URA || -z $AGB ]]; then
  echo Usage: $0 HOST X509_O X509_L UZI URA AGB
  exit 1
fi

echo Generating key and certificate for $HOST
openssl genrsa -out out/$HOST.key 2048
openssl req -new -key out/$HOST.key -out $HOST.csr -subj "${DN_PREFIX}CN=${HOST}/O=${X509_O}/L=${X509_L}/serialNumber=${UZI}"

local_openssl_config="
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = otherName:2.5.5.5;UTF8:2.16.528.1.1007.99.2110-1-${UZI}-S-${URA}-00.000-${AGB}
"
cat <<< "$local_openssl_config" > node.ext
openssl x509 -req -in $HOST.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out out/$HOST.pem -days 365 -sha256 \
  -extfile node.ext

cat ca.pem > out/$HOST-chain.pem
cat out/$HOST.pem >> out/$HOST-chain.pem

rm $HOST.csr
rm node.ext