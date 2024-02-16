#!/usr/bin/env bash

URL="http://localhost:9944"
COUNT=10000

for i in $(seq 0 $COUNT)
do
  NONCE=$(printf "0x%x" $i)
  INVOKE_TRANSACTION=$(cat <<EOF
{
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
}
EOF
)
  RANDOM_CHOICE=$((RANDOM % 2))

  if [ $RANDOM_CHOICE -eq 0 ]; then
    # Encrypt and Add Encrypted Invoke Transaction
    ENCRYPT_INVOKE_TRANSACTION=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "starknet_encryptInvokeTransaction",
  "params": {
    "invoke_transaction": $INVOKE_TRANSACTION,
    "t": 21
  },
  "id": 1
}
EOF
)

    ENCRYPT_RESPONSE=$(curl -s -H "Content-Type: application/json" -X POST --data "$ENCRYPT_INVOKE_TRANSACTION" $URL)
    echo "Encrypt invoke transaction response:"
    echo $ENCRYPT_RESPONSE | jq .

    ENCRYPTED_TRANSACTION=$(echo $ENCRYPT_RESPONSE | jq -c '.result.encrypted_invoke_transaction')

    ADD_ENCRYPTED_TRANSACTION=$(cat <<EOF
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

    ADD_ENCRYPTED_TRANSACTION_RESPONSE=$(curl -s -H "Content-Type: application/json" -X POST --data "$ADD_ENCRYPTED_TRANSACTION" $URL)
    echo "Add encrypted invoke transaction response:"
    echo $ADD_ENCRYPTED_TRANSACTION_RESPONSE | jq .
  else
    # Add Invoke Transaction
    ADD_TRANSACTION=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method": "starknet_addInvokeTransaction",
  "params": {
    "invoke_transaction": $INVOKE_TRANSACTION
  },
  "id": 1
}
EOF
)

    ADD_TRANSACTION_RESPONSE=$(curl -s -H "Content-Type: application/json" -X POST --data "$ADD_TRANSACTION" $URL)
    echo "Add invoke transaction response:"
    echo $ADD_TRANSACTION_RESPONSE | jq .
  fi

done