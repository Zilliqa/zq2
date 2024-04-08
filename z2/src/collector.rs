use colored::{self, Colorize as _};
use eyre::Result;
use futures::future::JoinAll;
use tokio::sync::mpsc;
use zilliqa::crypto::SecretKey;

use crate::runner;

pub struct Collector {
    pub runners: Vec<runner::Process>,
    pub reader: Option<tokio::task::JoinHandle<()>>,
    pub nr_nodes: usize,
}

impl Collector {
    pub fn color_log(idx: usize, legend: &str, rest: &str) -> String {
        let colored = format!("{legend}{idx}: ").color(Self::color_from_index(idx));
        format!("{colored} {rest}")
    }

    pub fn color_from_index(idx: usize) -> colored::Color {
        match idx % 5 {
            0 => colored::Color::Green,
            1 => colored::Color::Yellow,
            2 => colored::Color::Blue,
            3 => colored::Color::Magenta,
            4 => colored::Color::Cyan,
            // Will never happen, but rust doesn't know this.
            _ => colored::Color::White,
        }
    }

    pub async fn new(
        keys: &[SecretKey],
        config_files: &Vec<String>,
        log_spec: &str,
    ) -> Result<Collector> {
        let mut runners = Vec::new();
        let (tx, mut rx) = mpsc::channel(32);
        let nr = keys.len();
        // Fire everything up.
        for (i, (key, config_file)) in keys.iter().zip(config_files.iter()).enumerate() {
            runners.push(
                runner::Process::spawn(
                    i,
                    &key.to_hex(),
                    config_file,
                    &Some(log_spec.to_string()),
                    &tx,
                )
                .await?,
            );
        }
        let reader = tokio::spawn(async move {
            // Now, output here is already colored, so just color the legends.
            while let Some(msg) = rx.recv().await {
                match msg {
                    runner::Message::Exited(st) => {
                        let index = st.index;
                        println!("{}", Self::color_log(index, "Exited", ""));
                    }
                    runner::Message::OutputData(od) => {
                        let data = od.line;
                        let index = od.index;
                        println!("{}", Self::color_log(index, "Rx", &data));
                    }
                    runner::Message::ErrorData(od) => {
                        let data = od.line;
                        let index = od.index;
                        println!("{}", Self::color_log(index, "Rx!", &data));
                    }
                }
            }
            println!("Printing done!");
        });
        Ok(Collector {
            runners,
            reader: Some(reader),
            nr_nodes: nr,
        })
    }

    pub async fn complete(&mut self) -> Result<()> {
        futures::future::join_all(
            self.runners
                .iter_mut()
                .filter_map(|x| x.join_handle.take())
                .collect::<Vec<JoinAll<tokio::task::JoinHandle<()>>>>(),
        )
        .await;
        if let Some(val) = self.reader.take() {
            val.await?;
        }
        Ok(())
    }
}
