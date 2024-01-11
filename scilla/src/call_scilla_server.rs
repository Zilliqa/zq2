use std::{
    io::{Read, Write},
    net::TcpStream,
    str,
};

use anyhow::{anyhow, Result};
use jsonrpc_core::Params;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, Value};
use tracing::*;

use crate::scilla_tcp_server::ScillaServer;

/// Collection of functions to call the Scilla server and decode the result.
/// The communications are over TCP currently.
/// The scilla server is unusual in that it sometimes responds with a string as the 'result' which
/// then has to be further parsed.
/// There are two tcp connections required. The first is for the request (such as a 'run' command),
/// and the second is for the backend queries (the server reading and writing to the state).

/// Response from the 'check' command
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

fn respond_json(val: Value, mut connection: &TcpStream, id: u32) {
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

pub fn call_scilla_server<B: evm::backend::Backend>(
    method: &str,
    params: Params,
    tcp_scilla_server: &mut ScillaServer<B>,
) -> Result<String> {
    let request = JsonRpcRequest::new(method, params, 1);
    let request_str = serde_json::to_string(&request)?;
    let request_str = request_str + "\n"; // This is required to complete the request

    trace!("Connecting to scilla server...");
    let mut stream = TcpStream::connect("127.0.0.1:12345")?;
    let mut stream_backend = TcpStream::connect("127.0.0.1:12346")?;

    trace!("Sending request to scilla server: {:?}", request_str);
    stream.write_all(request_str.as_bytes())?;

    // Set non-blocking so that we can check and respond to both connections (and timeout).
    stream.set_nonblocking(true)?;
    stream_backend.set_nonblocking(true)?;

    let mut response = vec![];
    let mut response_backend = vec![];

    let mut bytes_read = 0;
    let mut bytes_read_backend = 0;

    loop {

        // Bump up the buffers we are reading into if we are at the end (exponential growth)
        if bytes_read >= response.len() {
            response.resize((response.len() + 1)*2, 0);
        }

        if bytes_read_backend >= response_backend.len() {
            response_backend.resize((response_backend.len() + 1)*2, 0);
        }

        // Read backend request
        let bytes_read_ch2 = stream_backend.read(&mut response_backend[bytes_read_backend..]);

        match bytes_read_ch2 {
            Ok(bytes_read) => {
                bytes_read_backend += bytes_read;
            }
            // It is valid if there is no data to read for either connection because it can still be
            // processing the request.
            Err(_) => {
                //debug!("Scilla backend error: {:?}", e);
            }
        }

        // Check if final character read was a newline, which indicates the end of the response
        if bytes_read_backend > 0 {
            if response_backend[bytes_read_backend - 1] == b'\n' {
                let possible_response = &response_backend[0..bytes_read_backend - 1];

                let request: Result<JsonRpcRequest, serde_json::Error> =
                    from_str(&String::from_utf8(possible_response.to_vec())?);

                match request {
                    Ok(request) => {
                        debug!("Scilla backend request: {:?}", request);
                        let backend_resp = tcp_scilla_server.handle_request(&request);

                        // Reset read pointer
                        bytes_read_backend = 0;

                        respond_json(backend_resp?, &stream_backend, request.id);
                    }
                    Err(e) => {
                        // This could be caused by a newline in the response itself,
                        // so we just continue on and will try to handle the full request later
                        debug!("Scilla backend request deser error: {:?}", e);
                    }
                }
            }
        }

        let bytes_read_ch1 = stream.read(&mut response[bytes_read..]);

        match bytes_read_ch1 {
            Ok(bytes_r) => {
                bytes_read += bytes_r;
            }
            Err(_) => {
                //debug!("Scilla read error: {:?}", e);
            }
        }

        // Nothing read on either channel, so sleep for a bit
        if bytes_read_ch1.is_err() && bytes_read_ch2.is_err() || bytes_read == 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }

        // Attempt to deserialize the response and return
        if response[bytes_read - 1] == b'\n' {
            let filtered = filter_out_escape_chars(response[0..bytes_read - 1].to_vec());
            return Ok(String::from_utf8(filtered)?);
        }
    }
}

/// Filter out the escape characters from the response
fn filter_out_escape_chars(data: Vec<u8>) -> Vec<u8> {
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
