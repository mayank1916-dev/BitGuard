# AWS KMS Key Policy Examples for BitGuard Signer Shim

> [!IMPORTANT]
> **Key Isolation & Least Privilege (Invariant #1):**
> Neither BitGuard Policy Decision Point nor human operators ever hold or access raw private keys.
> Private keys reside exclusively within FIPS 140-2/3 Level 3 Hardware Security Modules (AWS KMS).
> Signing permissions (`kms:Sign`) are granted **exclusively** to the isolated Signer Shim execution role under strict IAM condition keys. **No human principals may sign transactions.**

---

## 1. AWS KMS Asymmetric Key Policy

The following key policy enforces:
1. **Administrative Control:** Dedicated SecOps role can manage the key lifecycle, rotate aliases, and audit access, but is **explicitly denied** `kms:Sign`.
2. **Shim-Only Signing:** The automated Signer Shim IAM role (`BitGuardSignerShimRole`) is the sole principal permitted to invoke `kms:Sign`.
3. **Condition Confinement:** Signing calls must originate from the designated Signer Shim VPC endpoint (`vpc-0123456789abcdef0`) and use `ECDSA_SHA_256` with `DIGEST` message type.
4. **Zero Human Access:** All IAM users and federated human SSO roles are explicitly denied signing capabilities.

*(All AWS Account IDs, VPC IDs, and ARNs below are synthetic placeholders.)*

```json
{
  "Version": "2012-10-17",
  "Id": "BitGuardKmsHotWalletKeyPolicy",
  "Statement": [
    {
      "Sid": "AllowRootAccountAdministration",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowSecOpsKeyManagementWithoutSigning",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/SecOpsSecurityAdminRole"
      },
      "Action": [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:GetPublicKey"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenySecOpsFromSigning",
      "Effect": "Deny",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/SecOpsSecurityAdminRole"
      },
      "Action": [
        "kms:Sign"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowSignerShimRoleExclusiveSigning",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:role/BitGuardSignerShimRole"
      },
      "Action": [
        "kms:Sign",
        "kms:GetPublicKey",
        "kms:DescribeKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "kms:SigningAlgorithm": "ECDSA_SHA_256",
          "kms:MessageType": "DIGEST",
          "aws:sourceVpc": "vpc-0123456789abcdef0"
        }
      }
    },
    {
      "Sid": "ExplicitlyDenyAllHumanPrincipalsFromSigning",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "kms:Sign"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::111122223333:role/BitGuardSignerShimRole"
        }
      }
    }
  ]
}
```

---

## 2. Signer Shim IAM Execution Role Policy

The Signer Shim container or EC2/EKS instance assumes `arn:aws:iam::111122223333:role/BitGuardSignerShimRole`. Its policy grants strictly bounded access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SignerShimKmsSignAccess",
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:GetPublicKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-1234567890ab",
      "Condition": {
        "StringEquals": {
          "kms:SigningAlgorithm": "ECDSA_SHA_256",
          "kms:MessageType": "DIGEST"
        }
      }
    }
  ]
}
```

---

## 3. HashiCorp Vault Transit Engine Least-Privilege Policy

For deployments utilizing HashiCorp Vault Transit, the following ACL policy is attached to the Signer Shim AppRole:

```hcl
# Allow Signer Shim to sign transaction prehashed digests only
path "transit/sign/bitguard-hot-wallet" {
  capabilities = ["update"]
  allowed_parameters = {
    "input" = []
    "prehashed" = ["true"]
    "hash_algorithm" = ["sha2-256"]
  }
}

# Allow reading the public key to compute Ethereum address
path "transit/keys/bitguard-hot-wallet" {
  capabilities = ["read"]
}

# Explicitly deny key export, deletion, or modification
path "transit/keys/bitguard-hot-wallet/*" {
  capabilities = ["deny"]
}
```

---

## 4. Key Security & Operational Checklist

| Control | Implementation | Verification |
| :--- | :--- | :--- |
| **Key Spec** | `ECC_SECG_P256K1` (asymmetric secp256k1) | AWS CLI `describe-key` |
| **Key Usage** | `SIGN_VERIFY` | AWS CLI `describe-key` |
| **Audit Logging** | AWS CloudTrail enabled with data events on KMS keys | SIEM alert on any non-shim `kms:Sign` attempt |
| **Separation of Duties** | Security engineers manage key metadata; only shim role can sign | Deny rule validated in IAM policy simulator |
| **Network Confinement** | KMS endpoint policy inside private VPC with VPC Endpoint | `aws:sourceVpc` condition verified |
