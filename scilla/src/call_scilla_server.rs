use serde::Deserialize;
use serde::Serialize;
use tracing::*;
use anyhow::{anyhow, Result};
use std::net::TcpStream;
use jsonrpc_core::Params;
use crate::scilla_tcp_server::ScillaServer;
use serde_json::from_str;
use serde_json::{json, Value, from_value};
use std::io::Write;
use std::io::Read;
use std::str;

struct TcpRawClient {
    pub client: TcpStream,
}

#[derive(Deserialize, Debug)]
pub struct CheckOutput {
    pub contract_info: ContractInfo,
}

#[derive(Deserialize, Debug)]
pub struct ContractInfo {
    pub scilla_major_version: String,
    pub fields: Vec<Param>,
}

#[derive(Deserialize, Debug)]
pub struct Param {
    #[serde(rename = "vname")]
    pub name: String,
    pub depth: u64,
    #[serde(rename = "type")]
    pub ty: String,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcRequest {
    jsonrpc: String,
    pub method: String,
    pub params: Params,
    id: u32,
}

impl JsonRpcRequest {
    fn new(method: &str, params: Params, id: u32) -> Self {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id,
        }
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    id: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcError {
    code: i32,
    message: String,
    data: Option<Value>,
}

fn respond_json(val: Value, mut connection: &TcpStream) {

    let response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: Some(val),
        error: None,
        id: 1,
    };

    let response_str = serde_json::to_string(&response).unwrap();
    let response_str = response_str.to_owned() + "\n";

    connection.write_all(response_str.as_bytes()).unwrap();
}

pub fn call_scilla_server<B: evm::backend::Backend>(method: &str, params: Params, tcp_scilla_server: &mut ScillaServer<B>) -> Result<String> {

    let request = JsonRpcRequest::new(method, params, 1);
    let mut request_str = serde_json::to_string(&request)?;
    let request_str = request_str + "\n";

    let mut stream = TcpStream::connect("127.0.0.1:12345")?;
    let mut stream_backend = TcpStream::connect("127.0.0.1:12346")?;

    stream.write_all(request_str.as_bytes())?;

    stream.set_nonblocking(true)?;
    stream_backend.set_nonblocking(true)?;

    let mut response = [0; 10000];
    let mut response_backend = [0; 10000];
    let mut bytes_read = 0;
    let mut bytes_read_backend = 0;

    loop {
        let bytes_read_tcp = stream_backend.read(&mut response_backend[bytes_read..]);

        match bytes_read_tcp {
            Ok(bytes_read) => {
                bytes_read_backend += bytes_read;
            }
            Err(e) => {
                debug!("Scilla backend error: {:?}", e);
            }
        }

        if bytes_read_backend > 0 {
            if response_backend[bytes_read_backend-1] == '\n' as u8 {

                let not_filtered = response_backend[0..bytes_read_backend-1].to_vec();

                let mut request: Result<JsonRpcRequest, serde_json::Error> = from_str(&String::from_utf8(not_filtered.to_vec())?);

                let backend_resp = tcp_scilla_server.handle_request(request.expect("Deser of server request failed"));

                debug!("Scilla backend response: {:?}", backend_resp);

                // Reset read pointer
                bytes_read_backend = 0;

                respond_json(backend_resp?, &stream_backend);
            } else {
                debug!("Scilla response so farX: {:?}", String::from_utf8(response.to_vec())?);
            }
        }

        let bytes_r = stream.read(&mut response[bytes_read..]);

        match bytes_r {
            Ok(bytes_r) => {
                bytes_read += bytes_r;
            }
            Err(e) => {
                debug!("Scilla read error: {:?}", e);
            }
        }

        if bytes_read == 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }

        if response[bytes_read-1] == '\n' as u8 {
            let filtered = filter_this(response[0..bytes_read-1].to_vec());
            return Ok(String::from_utf8(filtered)?);
        } else {
            debug!("Scilla response so farYY: {:?}", String::from_utf8(response.to_vec())?);
        }

        if bytes_read >= 10000 {
            return Err(anyhow!("Response from Scilla server too large!"));
        }
    }
}

fn filter_this(data: Vec<u8>) -> Vec<u8> {
    let mut filtered_data = Vec::new();
    let mut skip_next = false;

    for (i, &byte) in data.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }

        if byte == b'\\' && i + 1 < data.len() && data[i + 1] == b'"' {
            continue;
        }

        if byte == b'\\' && i + 1 < data.len() && data[i + 1] == b'n' {
            skip_next = true; // Skip the next character, which is a quotation mark
            continue;
        }
        filtered_data.push(byte);
    }
    filtered_data
}
