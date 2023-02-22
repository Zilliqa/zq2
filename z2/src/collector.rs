use crate::runner;
use eyre::Result;
use futures::future::JoinAll;
use std::vec::Vec;
use tokio::sync::mpsc;

pub struct Collector {
    runners: Vec<runner::Process>,
    reader: Option<tokio::task::JoinHandle<()>>,
    nr_nodes: u32,
}

impl Collector {
    pub async fn new(nr: u32) -> Result<Collector> {
        let mut runners = Vec::new();
        let (tx, mut rx) = mpsc::channel(32);
        // Fire everything up.
        for i in 0..nr - 1 {
            runners.push(runner::Process::spawn(i, &tx).await?)
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

    pub async fn complete(&mut self) {
        futures::future::join_all(
            self.runners
                .iter_mut()
                .filter_map(|x| {
                    if let Some(handle) = x.join_handle.take() {
                        println!("X");
                        Some(handle)
                    } else {
                        None
                    }
                })
                .collect::<Vec<JoinAll<tokio::task::JoinHandle<()>>>>(),
        )
        .await;
        if let Some(val) = self.reader.take() {
            val.await;
        }
        // .collect::Vec<JoinAll<tokio::task::JoinHandle<()>>>::(),
    }
}
