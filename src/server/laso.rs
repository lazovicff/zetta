//! Laso Finance card provider client (docs @ cd53dcba8fc8).
//! The operator wallet pays each order over x402 (EIP-3009 on Base). Dev points
//! LASO_URL at mock-laso (localhost:4100), which accepts the shape without
//! settling on-chain; prod points it at https://laso.finance. Same code path.

use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::signers::Signer;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolValue;
use serde_json::{Value, json};

#[derive(Clone)]
pub struct LasoClient {
    base: String,
    http: reqwest::Client,
    /// Operator wallet — pays every card order.
    signer: PrivateKeySigner,
}

pub struct LasoAuth {
    pub id_token: String,
    pub refresh_token: String,
}

pub struct LasoOrder {
    pub card_id: String,
    pub auth: LasoAuth,
}

impl LasoClient {
    pub fn new(base: &str, signer: PrivateKeySigner) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            signer,
        }
    }

    /// x402 handshake: GET /get-card -> 402 challenge -> sign -> paid replay.
    pub async fn order_card(&self, usd_amount: &str) -> Result<LasoOrder, String> {
        let url = format!("{}/get-card?amount={usd_amount}", self.base);
        let res = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if res.status().as_u16() != 402 {
            return Err(format!(
                "/get-card: expected 402 challenge, got {}",
                res.status()
            ));
        }
        let encoded = res
            .headers()
            .get("payment-required")
            .and_then(|v| v.to_str().ok())
            .ok_or("/get-card: missing PAYMENT-REQUIRED header")?;
        let challenge: Value = serde_json::from_slice(&b64_decode(encoded)?)
            .map_err(|e| format!("/get-card: bad challenge: {e}"))?;
        let accept = challenge["accepts"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["network"] == "eip155:8453"))
            .cloned()
            .ok_or("/get-card: challenge has no Base payment option")?;

        let payment = self.sign_payment(&accept).await?;
        let paid = self
            .http
            .get(&url)
            .header("PAYMENT-SIGNATURE", payment)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !paid.status().is_success() {
            let status = paid.status();
            let body = paid.text().await.unwrap_or_default();
            return Err(format!("/get-card payment rejected ({status}): {body}"));
        }
        let v: Value = paid.json().await.map_err(|e| e.to_string())?;
        Ok(LasoOrder {
            card_id: v["card"]["card_id"]
                .as_str()
                .ok_or("/get-card: no card.card_id in response")?
                .into(),
            auth: parse_auth(&v["auth"])?,
        })
    }

    /// GET /get-card-data; returns (status, body) so the caller drives 401-refresh.
    pub async fn card_data(&self, id_token: &str, card_id: &str) -> Result<(u16, Value), String> {
        let res = self
            .http
            .get(format!("{}/get-card-data?card_id={card_id}", self.base))
            .bearer_auth(id_token)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = res.status().as_u16();
        let body = res.json().await.unwrap_or_else(|_| json!({}));
        Ok((status, body))
    }

    /// POST /auth, grant_type=refresh_token (flat response shape).
    pub async fn refresh(&self, refresh_token: &str) -> Result<LasoAuth, String> {
        let res = self
            .http
            .post(format!("{}/auth", self.base))
            .json(&json!({ "grant_type": "refresh_token", "refresh_token": refresh_token }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !res.status().is_success() {
            return Err(format!("/auth refresh: {}", res.status()));
        }
        parse_auth(&res.json::<Value>().await.map_err(|e| e.to_string())?)
    }

    /// GET /auth with SIGN-IN-WITH-X (CAIP-122), EIP-191 signed by the operator wallet.
    pub async fn auth(&self) -> Result<LasoAuth, String> {
        let address = self.signer.address();
        let host = self
            .base
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let now = unix_ms();
        let message = format!(
            "{host} wants you to sign in with your Ethereum account:\n{address}\n\n\
             Sign in to Laso Finance.\n\nURI: {}\nVersion: 1\nChain ID: 8453\nNonce: {now:x}\nIssued At: {now}",
            self.base
        );
        let sig = self
            .signer
            .sign_message(message.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let envelope = json!({
            "message": message,
            "signature": sig.to_string(),
            "address": address.to_string(),
        });
        let res = self
            .http
            .get(format!("{}/auth", self.base))
            .header(
                "SIGN-IN-WITH-X",
                b64_encode(envelope.to_string().as_bytes()),
            )
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !res.status().is_success() {
            return Err(format!("/auth: {}", res.status()));
        }
        let v: Value = res.json().await.map_err(|e| e.to_string())?;
        parse_auth(&v["auth"])
    }

    /// x402 v2 payment header (base64 JSON) for the Base option of a challenge.
    async fn sign_payment(&self, accept: &Value) -> Result<String, String> {
        let field = |k: &str| {
            accept[k]
                .as_str()
                .ok_or_else(|| format!("accept.{k} missing"))
        };
        let asset: Address = field("asset")?.parse().map_err(|_| "bad accept.asset")?;
        let pay_to: Address = field("payTo")?.parse().map_err(|_| "bad accept.payTo")?;
        let value: U256 = field("amount")?.parse().map_err(|_| "bad accept.amount")?;
        let chain_id: u64 = field("network")?
            .strip_prefix("eip155:")
            .ok_or("accept.network is not eip155")?
            .parse()
            .map_err(|_| "bad accept.network chain id")?;
        let name = accept["extra"]["name"].as_str().unwrap_or("USD Coin");
        let version = accept["extra"]["version"].as_str().unwrap_or("2");

        let now = unix_ms() / 1000;
        let valid_after = U256::ZERO;
        let valid_before = U256::from(now + 3600);
        let nonce = keccak256(format!("laso-{now}-{}", self.base));
        let digest = eip3009_digest(
            name,
            version,
            chain_id,
            asset,
            self.signer.address(),
            pay_to,
            value,
            valid_after,
            valid_before,
            nonce,
        );
        let sig = self
            .signer
            .sign_hash(&digest)
            .await
            .map_err(|e| e.to_string())?;
        let header = json!({
            "x402Version": 2,
            "accepted": accept,
            "payload": {
                "signature": sig.to_string(),
                "authorization": {
                    "from": self.signer.address(),
                    "to": pay_to,
                    "value": value.to_string(),
                    "validAfter": "0",
                    "validBefore": (now + 3600).to_string(),
                    "nonce": nonce,
                },
            },
        });
        Ok(b64_encode(header.to_string().as_bytes()))
    }
}

/// keccak256(0x1901 ‖ domain_separator ‖ struct_hash) for USDC's EIP-3009
/// TransferWithAuthorization.
#[allow(clippy::too_many_arguments)]
fn eip3009_digest(
    domain_name: &str,
    domain_version: &str,
    chain_id: u64,
    asset: Address,
    from: Address,
    to: Address,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
) -> B256 {
    let domain_sep = keccak256(
        (
            keccak256(
                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            ),
            keccak256(domain_name.as_bytes()),
            keccak256(domain_version.as_bytes()),
            U256::from(chain_id),
            asset,
        )
            .abi_encode(),
    );
    let struct_hash = keccak256(
        (
            keccak256(
                "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
            ),
            from,
            to,
            value,
            valid_after,
            valid_before,
            nonce,
        )
            .abi_encode(),
    );
    keccak256(
        [
            b"\x19\x01".as_slice(),
            domain_sep.as_slice(),
            struct_hash.as_slice(),
        ]
        .concat(),
    )
}

/// 18-decimal stablecoin wei -> "25.00" USD string for ?amount=.
pub fn wei_to_usd(v: U256) -> String {
    let e18 = U256::from(10u64).pow(U256::from(18u64));
    let whole = v / e18;
    let cents = (v % e18) / (e18 / U256::from(100u64));
    format!("{whole}.{cents:0>2}")
}

fn parse_auth(v: &Value) -> Result<LasoAuth, String> {
    Ok(LasoAuth {
        id_token: v["id_token"]
            .as_str()
            .ok_or("auth.id_token missing")?
            .into(),
        refresh_token: v["refresh_token"]
            .as_str()
            .ok_or("auth.refresh_token missing")?
            .into(),
    })
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// base64 (no extra deps)
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut table = [255u8; 256];
    for (i, &c) in B64.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut nbits) = (0u32, 0u32);
    for &byte in s.as_bytes() {
        let byte = match byte {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        };
        if byte == b'=' {
            break;
        }
        let v = table[byte as usize];
        if v == 255 {
            return Err("invalid base64 in PAYMENT-REQUIRED".into());
        }
        acc = (acc << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}
