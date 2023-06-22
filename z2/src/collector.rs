use crate::runner;
use eyre::Result;
use futures::future::JoinAll;
use std::vec::Vec;
use tokio::sync::mpsc;

pub struct Collector {
    pub runners: Vec<runner::Process>,
    pub reader: Option<tokio::task::JoinHandle<()>>,
    pub nr_nodes: usize,
}

impl Collector {
    pub async fn new(keys: &Vec<String>) -> Result<Collector> {
        let mut runners = Vec::new();
        let (tx, mut rx) = mpsc::channel(32);
        let nr = keys.len();
        // Fire everything up.
        let mut do_rpc = true;
        for (i, key) in keys.iter().enumerate() {
            runners.push(runner::Process::spawn(i, key, do_rpc, &tx).await?);
            do_rpc = false; // only launch RPC server in first node. TODO: better config on nodes
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
                .filter_map(|x| {
                    if let Some(handle) = x.join_handle.take() {
                        Some(handle)
                    } else {
                        None
                    }
                })
                .collect::<Vec<JoinAll<tokio::task::JoinHandle<()>>>>(),
        )
        .await;
        if let Some(val) = self.reader.take() {
            val.await?;
        }
        Ok(())
    }
}
