#!/bin/bash

# Simple script to generate TypeScript types from Go structs
# Uses a more direct approach with go2ts or manual conversion

echo "Generating TypeScript types..."

mkdir -p generated

# Create TypeScript types manually based on the Go structs
cat > generated/types.ts << 'EOF'
/**
 * This file is auto-generated
 * Do not edit manually
 */

// Enums
export enum LibType {
  GG20 = 0,
  DKLS = 1,
}

export enum ReshareType {
  Normal = 0,
  Plugin = 1,
}

// Request/Response Types
export interface VaultCreateRequest {
  name: string;
  session_id: string;
  hex_encryption_key: string;
  hex_chain_code: string;
  local_party_id?: string;
  encryption_password: string;
  email: string;
  lib_type: LibType;
}

export interface VaultCreateResponse {
  name: string;
  session_id: string;
  hex_encryption_key: string;
  hex_chain_code: string;
  keygen_msg: string;
}

export interface VaultGetResponse {
  name: string;
  public_key_ecdsa: string;
  public_key_eddsa: string;
  hex_chain_code: string;
  local_party_id: string;
}

export interface ReshareRequest {
  name: string;
  public_key: string;
  session_id: string;
  hex_encryption_key: string;
  hex_chain_code: string;
  local_party_id: string;
  old_parties: string[];
  encryption_password: string;
  email: string;
  old_reshare_prefix: string;
  lib_type: LibType;
  reshare_type: ReshareType;
}

export interface MigrationRequest {
  public_key: string;
  session_id: string;
  hex_encryption_key: string;
  encryption_password: string;
  email: string;
}

export interface KeysignRequest {
  public_key: string;
  messages: string[];
  session: string;
  hex_encryption_key: string;
  derive_path: string;
  is_ecdsa: boolean;
  vault_password: string;
}

export interface VaultResendRequest {
  public_key_ecdsa: string;
  password: string;
  email: string;
}

export interface EmailRequest {
  email: string;
  file_name: string;
  file_content: string;
  vault_name: string;
  code: string;
}

// Query Parameters
export interface GetDerivedPublicKeyParams {
  publicKey: string;
  hexChainCode: string;
  derivePath: string;
  isEdDSA?: string;
}

// API Response wrapper (if needed)
export interface ApiResponse<T> {
  data?: T;
  error?: string;
  message?: string;
}
EOF

echo "✅ TypeScript types generated in generated/types.ts"