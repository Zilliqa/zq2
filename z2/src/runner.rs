use std::process::Stdio;

use eyre::Result;
use futures::future::JoinAll;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc,
};

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
    ErrorData(OutputData),
}

impl Process {
    pub async fn spawn(
        index: usize,
        key: &str,
        config_file: &str,
        channel: &mpsc::Sender<Message>,
    ) -> Result<Process> {
        let mut cmd = Command::new("target/debug/zilliqa");
        cmd.arg(key);
        cmd.arg("--config-file");
        cmd.arg(config_file);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .expect("Failed to spawn - have you built zilliqa?");
        let stdout = child.stdout.take().expect("No handle to stdout");
        let stderr = child.stderr.take().expect("No handle to stderr");
        let mut stdout_reader = BufReader::new(stdout).lines();
        let mut stderr_reader = BufReader::new(stderr).lines();
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
            }
        });

        let tx_3 = channel.clone();
        let error_waiter = tokio::spawn(async move {
            while let Some(line) = stderr_reader.next_line().await.expect("Boo!") {
                // @todo Not sure if there is much we can do if this fails - rrw 2023-02-22
                let _ = tx_3
                    .send(Message::ErrorData(OutputData {
                        index,
                        line: line.to_string(),
                    }))
                    .await;
            }
        });

        let joiner = futures::future::join_all(vec![join_handle, output_waiter, error_waiter]);
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
