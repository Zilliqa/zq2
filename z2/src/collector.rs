use std::fmt;

use anyhow::{Context as _, Result};
use colored::{self, Colorize as _};
use futures::future::JoinAll;
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::mpsc,
    task::JoinHandle,
};
use zilliqa::crypto::SecretKey;

use crate::{
    components::{Component, Requirements},
    docs, mitmweb, otterscan, spout, zq2,
};

type Tx = mpsc::Sender<Message>;

// Not too many or we will end up with buffer bloat.
const MSG_CHANNEL_BUFFER: usize = 64;

#[derive(Clone, PartialEq)]
pub enum Program {
    Zq2,
    Otterscan,
    Spout,
    Mitmweb,
    Docs,
}

#[derive(PartialEq, Clone)]
pub struct Legend {
    pub component: Component,
    pub index: usize,
}

impl fmt::Display for Legend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{0}{1}", self.component, self.index)
    }
}

impl Legend {
    pub fn new(component: Component, index: usize) -> Result<Self> {
        Ok(Self { component, index })
    }

    pub fn get_color(&self) -> colored::Color {
        match self.index % 5 {
            0 => colored::Color::Green,
            1 => colored::Color::Yellow,
            2 => colored::Color::Blue,
            3 => colored::Color::Magenta,
            4 => colored::Color::Cyan,
            // Will never happen, but rust doesn't know this.
            _ => colored::Color::White,
        }
    }
}

pub trait Runner {
    fn take_join_handles(&mut self) -> Result<Option<JoinAll<tokio::task::JoinHandle<()>>>>;
}

pub struct ExitValue {
    pub legend: Legend,
    pub status: std::process::ExitStatus,
}

pub struct OutputData {
    pub legend: Legend,
    pub line: String,
}

pub enum Message {
    Exited(ExitValue),
    OutputData(OutputData),
    ErrorData(OutputData),
}

pub struct Collector {
    pub runners: Vec<Box<dyn Runner>>,
    pub reader: Option<tokio::task::JoinHandle<()>>,
    pub nr_nodes: usize,
    pub tx: Tx,
    pub log_spec: String,
    pub base_dir: String,
    pub log_file: Option<String>,
}

impl Collector {
    pub fn color_log(legend: &Legend, kind: &str, rest: &str) -> String {
        let colored = format!("{kind}#{legend}: ").color(legend.get_color());
        format!("{colored} {rest}")
    }

    pub async fn new(log_spec: &str, base_dir: &str, log_file: &Option<String>) -> Result<Self> {
        let (tx, mut rx) = mpsc::channel(MSG_CHANNEL_BUFFER);
        let log_file_for_reader = log_file.clone();
        let reader = Some(tokio::spawn(async move {
            let mut log_lines: Vec<String> = Vec::new();
            // Now, output here is already colored, so just color the legends.
            while let Some(msg) = rx.recv().await {
                match msg {
                    Message::Exited(st) => {
                        println!(
                            "{}",
                            Self::color_log(
                                &st.legend,
                                "Exited",
                                &format!("return code {:?}", st.status.code())
                            )
                        );
                        log_lines.push(format!(
                            "{0}#Exited: return code {1:?}",
                            st.legend,
                            st.status.code()
                        ));
                    }
                    Message::OutputData(od) => {
                        println!("{}", Self::color_log(&od.legend, "Rx", &od.line));
                        log_lines.push(format!("{0}#Rx: {1}", &od.legend, &od.line));
                    }
                    Message::ErrorData(od) => {
                        println!("{}", Self::color_log(&od.legend, "Rx!", &od.line));
                        log_lines.push(format!("{0}#Rx!: {1}", &od.legend, &od.line));
                    }
                }
                if let Some(ref val) = log_file_for_reader {
                    if !log_lines.is_empty() {
                        let result = fs::File::options()
                            .append(true)
                            .create(true)
                            .open(val)
                            .await;
                        match result {
                            Ok(mut file) => {
                                let write_result =
                                    file.write_all(log_lines.join("\n").as_bytes()).await;
                                if let Err(x) = write_result {
                                    println!(
                                        "{0}",
                                        format!("Can't write to log {val} - {:?}", x)
                                            .color(colored::Color::Red)
                                    );
                                }
                            }
                            // @todo maybe don't output this every single time?
                            Err(x) => {
                                println!(
                                    "{0}",
                                    format!("Can't write to log {val} - {:?}", x)
                                        .color(colored::Color::Red)
                                )
                            }
                        }
                    }
                }
            }
            println!("Printing done!");
        }));
        Ok(Collector {
            runners: Vec::new(),
            reader,
            nr_nodes: 0,
            tx,
            log_spec: log_spec.to_string(),
            base_dir: base_dir.to_string(),
            log_file: log_file.clone(),
        })
    }

    // Some question as to where this should go, but Program is notionally logic-free, so here for now.
    pub async fn fetch_requirements(p: &Program) -> Result<Requirements> {
        let r = match p {
            Program::Zq2 => zq2::Runner::requirements().await?,
            Program::Otterscan => otterscan::Runner::requirements().await?,
            Program::Spout => spout::Runner::requirements().await?,
            Program::Mitmweb => mitmweb::Runner::requirements().await?,
            Program::Docs => docs::Runner::requirements().await?,
        };
        Ok(r)
    }

    pub async fn start_zq2_node(
        &mut self,
        base_dir: &str,
        idx: usize,
        key: &SecretKey,
        config_file: &str,
    ) -> Result<()> {
        self.runners.push(Box::new(
            zq2::Runner::spawn(
                base_dir,
                idx,
                &key.to_hex(),
                config_file,
                &Some(self.log_spec.clone()),
                &self.tx,
            )
            .await?,
        ));
        Ok(())
    }

    pub async fn start_otterscan(
        &mut self,
        base_dir: &str,
        chain_url: &str,
        port: u16,
    ) -> Result<()> {
        self.runners.push(Box::new(
            otterscan::Runner::spawn_otter(base_dir, chain_url, port, &self.tx).await?,
        ));
        Ok(())
    }

    pub async fn start_spout(
        &mut self,
        base_dir: &str,
        chain_url: &str,
        explorer_url: &str,
        priv_key: &str,
        port: u16,
    ) -> Result<()> {
        self.runners.push(Box::new(
            spout::Runner::spawn_spout(base_dir, chain_url, explorer_url, priv_key, port, &self.tx)
                .await?,
        ));
        Ok(())
    }

    pub async fn start_mitmweb(
        &mut self,
        base_dir: &str,
        index: usize,
        from_port: u16,
        to_port: u16,
        mgmt_port: u16,
    ) -> Result<()> {
        self.runners.push(Box::new(
            mitmweb::Runner::spawn_mitmproxy(
                base_dir, index, from_port, to_port, mgmt_port, &self.tx,
            )
            .await?,
        ));
        Ok(())
    }

    pub async fn start_docs(&mut self, base_dir: &str, listen_hostport: &str) -> Result<()> {
        self.runners.push(Box::new(
            docs::Runner::spawn_docs(base_dir, listen_hostport, &self.tx).await?,
        ));
        Ok(())
    }

    pub async fn complete(&mut self) -> Result<()> {
        futures::future::join_all(
            self.runners
                .iter_mut()
                .filter_map(|x| x.take_join_handles().unwrap())
                .collect::<Vec<JoinAll<tokio::task::JoinHandle<()>>>>(),
        )
        .await;
        self.reader.as_mut().unwrap().await?;
        Ok(())
    }
}

pub async fn spawn(
    cmd: &mut Command,
    desc: &str,
    legend: &Legend,
    channel: Tx,
) -> Result<JoinAll<JoinHandle<()>>> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().context(format!("Failed to spawn {desc}"))?;
    let stdout = child.stdout.take().context("no handle to stdout")?;
    let stderr = child.stderr.take().context("no handle to stderr")?;
    let mut stdout_reader = BufReader::new(stdout).lines();
    let mut stderr_reader = BufReader::new(stderr).lines();
    let tx_1 = channel.clone();
    let legend_1 = legend.clone();
    let join_handle_1 = tokio::spawn(async move {
        let status = child.wait().await.expect("Child returned with an error");
        let _ = tx_1
            .send(Message::Exited(ExitValue {
                legend: legend_1,
                status,
            }))
            .await;
        println!("Child status {status}");
    });
    let tx_2 = channel.clone();
    let legend_2 = legend.clone();
    let join_handle_2 = tokio::spawn(async move {
        while let Some(line) = stdout_reader
            .next_line()
            .await
            .expect("Failed to read from stdout")
        {
            let _ = tx_2
                .send(Message::OutputData(OutputData {
                    legend: legend_2.clone(),
                    line: line.to_string(),
                }))
                .await;
        }
    });
    let tx_3 = channel.clone();
    let legend_3 = legend.clone();
    let join_handle_3 = tokio::spawn(async move {
        while let Some(line) = stderr_reader
            .next_line()
            .await
            .expect("Failed to read from stdout")
        {
            let _ = tx_3
                .send(Message::ErrorData(OutputData {
                    legend: legend_3.clone(),
                    line: line.to_string(),
                }))
                .await;
        }
    });
    let joiner = futures::future::join_all(vec![join_handle_1, join_handle_2, join_handle_3]);
    Ok(joiner)
}
