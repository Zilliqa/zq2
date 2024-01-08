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
    //pub params: serde_json::Value,
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

    debug!("Responding to the backend with: {:?}", response_str);

    connection.write_all(response_str.as_bytes()).unwrap();
}
pub fn call_scilla_server<B: evm::backend::Backend>(method: &str, params: Params, tcp_scilla_server: &mut ScillaServer<B>) -> Result<String> {

    let request = JsonRpcRequest::new(method, params, 1);
    let mut request_str = serde_json::to_string(&request)?;
    let request_str = request_str + "\n";

    debug!("Calling Scilla server with request: {:?}", request_str);

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
                //if bytes_read > 0 {
                //    debug!("Scilla backend response so far: {:?}", str::from_utf8(&response_backend));
                //}

                bytes_read_backend += bytes_read;
            }
            Err(e) => {
                //debug!("Scilla backend response so far: {:?}", str::from_utf8(&response_backend));
                //debug!("Scilla backend error: {:?}", e);
            }
        }

        if bytes_read_backend > 0 {
            if response_backend[bytes_read_backend-1] == '\n' as u8 {

                let not_filtered = response_backend[0..bytes_read_backend-1].to_vec();

                debug!("Deser the request...");
                let mut request: Result<JsonRpcRequest, serde_json::Error> = from_str(&String::from_utf8(not_filtered.to_vec())?);
                debug!("Deser the request... {:?}", request);

                let aa = tcp_scilla_server.handle_request(request.expect("Deser of server request failed"));

                //let aa =

                debug!("Scilla backend response: {:?}", aa);

                // Reset read pointer
                bytes_read_backend = 0;

                respond_json(aa?, &stream_backend);

                //return Ok(String::from_utf8(filtered)?);
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
                //debug!("Scilla read error: {:?}", e);
            }
        }


        //if bytes_read > 0 {
        //    debug!("Scilla response so farBk: {:?}", String::from_utf8(response.to_vec())?);
        //}

        if bytes_read == 0 {
            // sleep 1 sec
            std::thread::sleep(std::time::Duration::from_secs(1));

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

        // sleep 1 sec
        std::thread::sleep(std::time::Duration::from_secs(1));
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
            //skip_next = true; // Skip the next character, which is a quotation mark
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
