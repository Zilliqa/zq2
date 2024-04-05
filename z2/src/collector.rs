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
    pub async fn new(keys: &[SecretKey], config_files: &Vec<String>) -> Result<Collector> {
        let mut runners = Vec::new();
        let (tx, mut rx) = mpsc::channel(32);
        let nr = keys.len();
        // Fire everything up.
        for (i, (key, config_file)) in keys.iter().zip(config_files.iter()).enumerate() {
            runners.push(runner::Process::spawn(i, &key.to_hex(), config_file, &tx).await?);
        }
        let reader = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    runner::Message::Exited(st) => {
                        let index = st.index;
                        println!("Exited#{index}");
                    }
                    runner::Message::OutputData(od) => {
                        let data = od.line;
                        let index = od.index;
                        println!("Rx#{index}: {data}");
                    }
                    runner::Message::ErrorData(od) => {
                        let data = od.line;
                        let index = od.index;
                        println!("Rx!#{index}: {data}");
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
