// Code to stress-test z2 networks.
#![allow(unused_imports)]

use crate::{node_spec, setup::Setup};
use anyhow::{anyhow, Error, Result};
use jsonrpsee::core::{client::ClientT, params::ArrayParams};
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use std::cmp::{Ordering, PartialOrd};
use std::collections::{BinaryHeap, HashSet};
use tokio::time::{self, Duration, Instant};
use tower_http::trace::TraceLayer;

// This is inherently reversed, since BinaryHeap is a max-heap

// Not very artistic, but it'll do .
#[derive(Debug)]
pub struct PartitionEntry {
    pub nodes_to_talk_to: HashSet<u64>,
    pub nodes_to_tell: HashSet<u64>,
    pub start_ms: u64,
    pub end_ms: u64,
}

/// A partition test, specified by a list of sets of nodes and time ranges during which we
/// use the admin interface to whitelist nodes to communicate only with other nodes within
/// their partition.
/// It would've been nice to add some view constraints too, but since many of the views will
/// be identical this would be harder to specify than I want for this code.
#[derive(Debug)]
pub struct Partition {
    entries: Vec<PartitionEntry>,
}

#[derive(Debug, Eq, PartialEq)]
struct HeapEntry {
    idx: usize,
    is_start: bool,
    when_ms: u64,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Backwards because BinaryHeap is a max-heap.
        if self.when_ms > other.when_ms {
            Ordering::Less
        } else if self.when_ms < other.when_ms {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn nodes_from_spec(spec: &str, setup: &Setup) -> Result<HashSet<u64>> {
    Ok(if spec == "all" {
        setup
            .config
            .node_data
            .keys()
            .cloned()
            .collect::<HashSet<u64>>()
    } else {
        node_spec::indices_from_string(spec)?
    })
}

impl Partition {
    pub fn from_args(args: &[String], setup: &Setup) -> Result<Partition> {
        let mut entries: Vec<PartitionEntry> = Vec::new();
        for arg in args {
            // Partitions are specified as a comma-separated range of nodes, followed by ':', followed by nodes to talk to (equal if only one :), followed by a start millisecond, followed by '/', followed by an end millisecond
            // eg. 0-1:400/500
            // The special value "all" means all of them.
            let fields = arg.split(':').collect::<Vec<&str>>();
            if fields.len() != 2 && fields.len() != 3 {
                return Err(anyhow!(
                    "Arg '{arg}' has the wrong number of ':'-separated fields - {0} - should be 2",
                    fields.len()
                ));
            }
            let has_nodes_to_tell = fields.len() == 3;
            let nodes_to_talk_to = nodes_from_spec(fields[0], setup)?;
            let nodes_to_tell = if has_nodes_to_tell {
                nodes_from_spec(fields[1], setup)?
            } else {
                nodes_to_talk_to.clone()
            };
            let times = (if has_nodes_to_tell {
                fields[2]
            } else {
                fields[1]
            })
            .split('/')
            .collect::<Vec<&str>>();
            if times.len() != 2 {
                return Err(anyhow!("Arg '{arg}' - there must be two times, separated by a '/' after the ':' - found {0}", times.len()));
            }
            let start_ms = u64::from_str_radix(times[0], 10)?;
            let end_ms = u64::from_str_radix(times[1], 10)?;
            entries.push(PartitionEntry {
                nodes_to_talk_to,
                nodes_to_tell,
                start_ms,
                end_ms,
            });
        }

        Ok(Partition { entries })
    }

    pub async fn run_with(&self, setup: &mut Setup) -> Result<()> {
        println!("🦒 Running partition test ... ");
        // This is fairly easily done with a pair of pqueues of indices (indices because the rust priority queue impl wants
        // an equality relation on items).
        // I = (index, is_start)
        let mut tasks: BinaryHeap<HeapEntry> = BinaryHeap::new();

        self.entries.iter().enumerate().for_each(|(idx, val)| {
            tasks.push(HeapEntry {
                idx,
                is_start: true,
                when_ms: val.start_ms,
            });
            tasks.push(HeapEntry {
                idx,
                is_start: false,
                when_ms: val.end_ms,
            });
        });

        let start_time = Instant::now();
        loop {
            let now = Instant::now();
            if let Some(heap_entry) = tasks.pop() {
                let event_happens_at = start_time + Duration::from_millis(heap_entry.when_ms);
                if event_happens_at > now {
                    let to_sleep: Duration = event_happens_at - now;
                    println!(
                        "🦒🦒 Waiting {:?} for next event (idx = {}, is_start = {})",
                        to_sleep, heap_entry.idx, heap_entry.is_start
                    );
                    tokio::time::sleep(to_sleep).await;
                }
                let mut peer_ids: ArrayParams = ArrayParams::new();
                let mut peer_vec: Vec<String> = Vec::new();
                let entry = &self.entries[heap_entry.idx];

                if heap_entry.is_start {
                    // List the peer ids of the elements
                    for peer in entry.nodes_to_talk_to.iter() {
                        let id = setup.peer_id_for_idx(*peer)?;
                        peer_ids.insert(id.to_string())?;
                        peer_vec.push(id);
                    }
                }
                // Otherwise, leave empty and we'll remove the partition.
                for peer in entry.nodes_to_tell.iter() {
                    println!("🦩 admin_whitelist to {peer} for {peer_vec:?}");
                    let client = HttpClientBuilder::default()
                        .build(setup.get_json_rpc_url_for_node(*peer)?)?;

                    client
                        .request::<(), ArrayParams>("admin_whitelist", peer_ids.clone())
                        .await?;
                }
            } else {
                println!("🐌 All done");
                break;
            }
        }
        Ok(())
    }
}
