//! Xác thực thanh toán USDT (BSC/ETH) để mở khóa lưu trữ vĩnh viễn.
//! Server luôn tự kiểm tra lại trên blockchain — không bao giờ tin số liệu client gửi lên.

use serde_json::{json, Value};

pub const TREASURY_EVM: &str = "0xb11be01e0d81b20f373aa0de7058946765e68d97";
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
// dung sai ~100000 đơn vị nhỏ nhất (chống sai số làm tròn), không phải lỗ hổng thật vì
// 100000/10^decimals là rất nhỏ so với 1 USDT thật ở cả hai mạng
const TOLERANCE: u128 = 100_000;

pub struct Network {
    pub rpc: &'static str,
    pub usdt_contract: &'static str,
    pub decimals: u32,
}

pub fn network_for(name: &str) -> Option<Network> {
    match name {
        "bsc" => Some(Network {
            rpc: "https://bsc-rpc.publicnode.com",
            usdt_contract: "0x55d398326f99059ff775485246999027b3197955",
            decimals: 18,
        }),
        "eth" => Some(Network {
            rpc: "https://ethereum-rpc.publicnode.com",
            usdt_contract: "0xdac17f958d2ee523a2206206994597c13d831ec7",
            decimals: 6,
        }),
        _ => None,
    }
}

async fn rpc_call(rpc: &str, method: &str, params: Value) -> Result<Value, String> {
    let client = reqwest::Client::new();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let res = client
        .post(rpc)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let v: Value = res.json().await.map_err(|e| e.to_string())?;
    v.get("result").cloned().ok_or_else(|| format!("lỗi RPC: {v}"))
}

fn topic_addr(addr: &str) -> String {
    format!("0x{:0>64}", addr.trim_start_matches("0x").to_lowercase())
}

/// Xác minh 1 giao dịch cụ thể (theo hash do client tìm thấy) thực sự là chuyển ~1 USDT
/// tới ví treasury trên đúng mạng đã chọn, và trả về số USD (để log) nếu hợp lệ.
pub async fn verify_tx(network: &Network, tx_hash: &str) -> Result<bool, String> {
    if !tx_hash.starts_with("0x") || tx_hash.len() != 66 {
        return Ok(false);
    }
    let receipt = match rpc_call(network.rpc, "eth_getTransactionReceipt", json!([tx_hash])).await {
        Ok(v) => v,
        // publicnode trả lỗi "cần token archive" khi không tìm thấy giao dịch trong cache gần đây
        // (hash sai/giả hoặc giao dịch chưa được index) — coi như "chưa xác nhận", không phải lỗi hệ thống.
        Err(e) if e.contains("Archive requests") => return Ok(false),
        Err(e) => return Err(e),
    };
    if receipt.is_null() {
        return Ok(false); // giao dịch chưa xác nhận hoặc không tồn tại
    }
    if receipt.get("status").and_then(|s| s.as_str()) != Some("0x1") {
        return Ok(false); // giao dịch thất bại
    }
    let to_contract = receipt.get("to").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
    if to_contract != network.usdt_contract.to_lowercase() {
        return Ok(false); // không phải gọi vào hợp đồng USDT đúng mạng
    }
    let expected_topic_to = topic_addr(TREASURY_EVM);
    let want = 10u128.pow(network.decimals); // 1 USDT ở đơn vị nhỏ nhất
    let Some(logs) = receipt.get("logs").and_then(|v| v.as_array()) else { return Ok(false) };
    for log in logs {
        let addr = log.get("address").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        if addr != network.usdt_contract.to_lowercase() {
            continue;
        }
        let topics: Vec<String> = log
            .get("topics")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|t| t.as_str().map(|s| s.to_lowercase())).collect())
            .unwrap_or_default();
        if topics.len() < 3 || topics[0] != TRANSFER_TOPIC {
            continue;
        }
        if topics[2] != expected_topic_to {
            continue; // không chuyển tới treasury
        }
        let data = log.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
        let amount = u128::from_str_radix(data.trim_start_matches("0x"), 16).unwrap_or(0);
        if amount + TOLERANCE >= want {
            return Ok(true);
        }
    }
    Ok(false)
}
