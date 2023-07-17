use eyre::Result;
use futures::future::JoinAll;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use crate::setup::Setup;

pub struct Process {
    pub index: usize,
    pub join_handle: Option<JoinAll<tokio::task::JoinHandle<()>>>,
}

pub struct OutputData {
    pub index: usize,
    pub line: String,
}

pub struct ExitValue {
    pub index: usize,
    pub status: std::process::ExitStatus,
}

pub enum Message {
    Exited(ExitValue),
    OutputData(OutputData),
}

impl Process {
    pub async fn spawn(
        index: usize,
        key: &str,
        rpc: bool,
        channel: &mpsc::Sender<Message>,
    ) -> Result<Process> {
        let mut cmd = Command::new("target/debug/zilliqa");
        cmd.arg(key);
        cmd.arg("--config-file");
        cmd.arg(Setup::config_path(index));
        if !rpc {
            cmd.arg("--no-jsonrpc");
        }
        cmd.stdout(Stdio::piped());
        let mut child = cmd
            .spawn()
            .expect("Failed to spawn - have you built zilliqa?");
        let stdout = child.stdout.take().expect("No handle to stdout");
        let mut stdout_reader = BufReader::new(stdout).lines();
        let tx_1 = channel.clone();
        let join_handle = tokio::spawn(async move {
            let status = child.wait().await.expect("Child errored");
            // @TODO not sure there is much we can do if this fails ..
            let _ = tx_1
                .send(Message::Exited(ExitValue { index, status }))
                .await;
            println!("Child status {status}");
        });
        let tx_2 = channel.clone();
        let output_waiter = tokio::spawn(async move {
            while let Some(line) = stdout_reader.next_line().await.expect("Boo!") {
                // @todo Not sure if there is much we can do if this fails - rrw 2023-02-22
                let _ = tx_2
                    .send(Message::OutputData(OutputData {
                        index,
                        line: line.to_string(),
                    }))
                    .await;
                // println!("Stdout says {line}");
            }
        });
        let joiner = futures::future::join_all(vec![join_handle, output_waiter]);
        Ok(Process {
            index,
            join_handle: Some(joiner),
        })
    }

    pub async fn await_termination(&mut self) {
        if let Some(handle) = self.join_handle.take() {
            handle.await;
        }
    }
}
