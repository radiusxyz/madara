#!/usr/bin/env bash

URL="http://localhost:9944"
COUNT=10000

for i in $(seq 0 $COUNT)
do
    NONCE=$(printf "0x%x" $i)
    RANDOM_CHOICE=$((RANDOM % 2))

    if [ $RANDOM_CHOICE -eq 0 ]; then
        # Encrypt and Add Encrypted Invoke Transaction
        ENCRYPT_DATA=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "starknet_encryptInvokeTransaction",
  "params": {
    "invoke_transaction": {
      "sender_address": "0x0000000000000000000000000000000000000000000000000000000000000001",
      "calldata": [
        "0x0000000000000000000000000000000000000000000000000000000000001111",
        "0x36fa6de2810d05c3e1a0ebe23f60b9c2f4629bbead09e5a9704e1c5632630d5",
        "0x0"
      ],
      "type": "INVOKE",
      "max_fee": "0xbc614e",
      "version": "0x1",
      "signature": ["0x0", "0x0"],
      "nonce": "$NONCE",
      "offset_version": "0x0"
    },
    "t": 21
  },
  "id": 1
}
EOF
)

        RESPONSE=$(curl -s -H "Content-Type: application/json" -X POST --data "$ENCRYPT_DATA" $URL)
        echo "Encrypt response: $RESPONSE"

        ENCRYPTED_TRANSACTION=$(echo $RESPONSE | jq -c '.result.encrypted_invoke_transaction')
        echo "Encrypted transaction: $ENCRYPTED_TRANSACTION"

        ADD_ENCRYPTED_DATA=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "starknet_addEncryptedInvokeTransaction",
  "params": {
    "encrypted_invoke_transaction": $ENCRYPTED_TRANSACTION
  },
  "id": 1
}
EOF
)

        ADD_RESPONSE=$(curl -s -H "Content-Type: application/json" -X POST --data "$ADD_ENCRYPTED_DATA" $URL)
        echo "Add encrypted transaction response: $ADD_RESPONSE"
    else
        # Add Invoke Transaction Directly
        INVOKE_DATA=$(cat <<EOF
{
    "jsonrpc": "2.0",
    "method": "starknet_addInvokeTransaction",
    "params": {
        "invoke_transaction": {
            "sender_address":"0x0000000000000000000000000000000000000000000000000000000000000001",
            "calldata": [
                "0x0000000000000000000000000000000000000000000000000000000000001111",
                "0x36fa6de2810d05c3e1a0ebe23f60b9c2f4629bbead09e5a9704e1c5632630d5",
                "0x0"
            ],
            "type": "INVOKE",
            "max_fee": "0xbc614e",
            "version":"0x1",
            "signature":[
                "0x0",
                "0x0"
            ],
            "nonce":"$NONCE",
            "offset_version": "0x0"
        }
    },
    "id": 1
}
EOF
)

        INVOKE_RESPONSE=$(curl -s -H "Content-Type: application/json" -X POST --data "$INVOKE_DATA" $URL)
        echo "Invoke transaction response: $INVOKE_RESPONSE"
    fi
done