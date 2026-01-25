#!/usr/bin/env sh
set -e

# Start Vault server in the background
vault server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200 &

# Wait for Vault to be ready
until vault status > /dev/null 2>&1; do
  echo "Waiting for Vault to start..."
  sleep 1
done

echo "Vault is up, configuring transit engine..."

# Enable transit engine
vault secrets enable transit || echo "Transit engine already enabled"

# Create master key
vault write -f transit/keys/wallet-master-key || echo "Master key already exists"

echo "Vault configured successfully."

# Keep the container running by bringing Vault back to foreground
wait $!
