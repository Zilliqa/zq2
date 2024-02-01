use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
    str,
};

use anyhow::{anyhow, Result};
use jsonrpc_core::Params;
use serde_json::{from_str, Value};
use tracing::*;

use crate::{
    scilla_server_run::{
        SCILLA_SERVER_INIT_PATH, SCILLA_SERVER_INPUT_PATH, SCILLA_SERVER_MESSAGE_PATH,
    },
    scilla_tcp_server::ScillaServer,
    types::{JsonRpcRequest, JsonRpcResponse},
};
fn get_scilla_write_port() -> String {
    env::var("SCILLA_WRITE_PORT").unwrap_or_else(|_| "127.0.0.1:12345".to_string())
}

fn get_scilla_read_port() -> String {
    env::var("SCILLA_READ_PORT").unwrap_or_else(|_| "127.0.0.1:12346".to_string())
}
fn get_scilla_file_port() -> String {
    env::var("SCILLA_FILE_PORT").unwrap_or_else(|_| "127.0.0.1:12347".to_string())
}

/// Collection of functions to call the Scilla server and decode the result.
/// The communications are over TCP currently.
/// The scilla server is unusual in that it sometimes responds with a string as the 'result' which
/// then has to be further parsed.
/// There are two tcp connections required. The first is for the request (such as a 'run' command),
/// and the second is for the backend queries (the server reading and writing to the state).

fn respond_json(val: Value, mut connection: &TcpStream, id: u32) {
    let response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: Some(val),
        error: None,
        id,
    };

    let response_str = serde_json::to_string(&response).unwrap();
    let response_str = response_str.to_owned() + "\n";

    connection.write_all(response_str.as_bytes()).unwrap();
}

pub fn call_scilla_server<B: evm::backend::Backend>(
    method: &str,
    params: Params,
    tcp_scilla_server: &mut ScillaServer<B>,
) -> Result<JsonRpcResponse> {
    let request = JsonRpcRequest::new(method, params, 1);
    let request_str = serde_json::to_string(&request)?;
    let request_str = request_str + "\n"; // This is required to complete the request

    trace!("Connecting to scilla server...");
    let mut stream = TcpStream::connect(get_scilla_write_port())?;
    let mut stream_backend = TcpStream::connect(get_scilla_read_port())?;

    trace!("Sending request to scilla server: {:?}", request_str);
    stream.write_all(request_str.as_bytes())?;

    // Set non-blocking so that we can check and respond to both connections (and timeout).
    stream.set_nonblocking(true)?;
    stream_backend.set_nonblocking(true)?;

    let mut response = vec![];
    let mut response_backend = vec![];

    let mut bytes_read = 0;
    let mut bytes_read_backend = 0;

    let now = std::time::Instant::now();

    loop {
        if now.elapsed().as_millis() > 5000 {
            return Err(anyhow!("Timeout waiting for response from scilla server"));
        }

        // Bump up the buffers we are reading into if we are at the end (exponential growth)
        if bytes_read >= response.len() {
            response.resize((response.len() + 1) * 2, 0);
        }

        if bytes_read_backend >= response_backend.len() {
            response_backend.resize((response_backend.len() + 1) * 2, 0);
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
        if bytes_read_backend > 0 && response_backend[bytes_read_backend - 1] == b'\n' {
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

            let deser: Result<JsonRpcResponse, serde_json::Error> = from_str(&filtered);

            match deser {
                Ok(response) => {
                    return Ok(response);
                }
                Err(e) => {
                    // This could be caused by a newline in the response itself,
                    // so we just continue on and will try to handle the full request later
                    debug!(
                        "Scilla request deser error: {:?} Text: {:?} Bytes: {:?}",
                        e,
                        String::from_utf8(response.clone()).unwrap_or("not a string".to_string()),
                        response
                    );
                }
            }
        }
    }
}

/// Filter out the escape characters from the response
fn filter_out_escape_chars(data: Vec<u8>) -> String {
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
    let filtered_data: String = String::from_utf8(filtered_data).unwrap();

    filtered_data.replace("\"{", "{").replace("}\"", "}")
}

/// Ensure that the files are set up correctly for the scilla server to read them.
pub fn ensure_setup_correct(
    init_data: Option<serde_json::Value>,
    input_data: Option<Vec<u8>>,
    message: Option<Value>,
) {
    if let Some(init_data) = init_data {
        let mut stream = TcpStream::connect(get_scilla_file_port())
            .expect("unable to connect to scilla server for file setup!");
        stream
            .write_all(SCILLA_SERVER_INIT_PATH.as_bytes())
            .unwrap();
        stream
            .write_all(serde_json::to_string(&init_data).unwrap().as_bytes())
            .unwrap();
    }

    if let Some(input_data) = input_data {
        let mut stream = TcpStream::connect(get_scilla_file_port())
            .expect("unable to connect to scilla server for file setup!");
        stream
            .write_all(SCILLA_SERVER_INPUT_PATH.as_bytes())
            .unwrap();
        stream.write_all(&input_data).unwrap();
    }

    if let Some(message) = message {
        let mut stream = TcpStream::connect(get_scilla_file_port())
            .expect("unable to connect to scilla server for file setup!");
        stream
            .write_all(SCILLA_SERVER_MESSAGE_PATH.as_bytes())
            .unwrap();
        stream
            .write_all(serde_json::to_string(&message).unwrap().as_bytes())
            .unwrap();
    }
}
