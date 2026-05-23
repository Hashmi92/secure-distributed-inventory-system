# Secure Distributed Inventory System

A Python-based prototype that demonstrates secure record insertion and secure query retrieval in a distributed inventory environment.

The system uses RSA digital signatures, Proof-of-Authority style consensus, Harn-style multi-signature approval, and RSA-encrypted response delivery.

## Features

- RSA-based record signing and verification
- Tamper detection for modified inventory records
- Consensus-based record insertion across four inventory nodes
- Multi-node query result approval using Harn-style multi-signature
- Secure response encryption and recovery for an authorised query user
- JSON-based local storage for inventory records and cryptographic parameters

## Project Structure

```text
record_insertion.py       # secure record signing, verification, and consensus insertion
query_retrieval.py        # secure query approval and encrypted response delivery
*.json                    # inventory records, node keys, and cryptographic parameters
