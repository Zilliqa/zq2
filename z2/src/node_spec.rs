use std::{
    collections::{HashMap, HashSet},
    default::Default,
    fmt,
};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use zilliqa::range_map::RangeMap;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodeDesc {
    pub is_validator: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Composition {
    pub nodes: HashMap<u64, NodeDesc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodeSpec {
    pub configured: Composition,
    pub start: Composition,
}

impl fmt::Display for Composition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut map: RangeMap = RangeMap::new();
        self.nodes
            .iter()
            .filter_map(|(x, y)| if y.is_validator { Some(x) } else { None })
            .for_each(|x| {
                map.with_elem(*x);
            });
        write!(f, "{}", map)
    }
}

fn indices_from_string(input: &str) -> Result<HashSet<u64>> {
    // We support a-b and a,b,c .
    let components = input.split(',');
    let mut result = RangeMap::new();
    // Now, each component is either a-b or a number
    for c in components {
        if let Ok(val) = c.trim().parse::<u64>() {
            result.with_elem(val);
        } else {
            let ranges = c.split('-').collect::<Vec<&str>>();
            if ranges.len() != 2 {
                return Err(anyhow!(
                    "Composition element {c} is neither a number nor a range"
                ));
            }
            let left = ranges[0].trim().parse::<u64>()?;
            let right = ranges[1].trim().parse::<u64>()?;
            result.with_closed_tuple((left, right));
        }
    }
    Ok(result.iter_values().collect::<HashSet<u64>>())
}

impl Composition {
    pub fn parse(from: &str) -> Result<Self> {
        let mut components = from.split('/');
        let mut nodes = HashMap::new();
        if let Some(val) = components.next() {
            for v in indices_from_string(val)? {
                nodes.insert(v, NodeDesc { is_validator: true });
            }
        }
        Ok(Self { nodes })
    }

    pub fn small_network() -> Self {
        let mut nodes = HashMap::new();
        for i in 0..4 {
            nodes.insert(i, NodeDesc { is_validator: true });
        }
        Self { nodes }
    }

    /// If we were to ask to start 'other' in a network of 'self',
    /// would it work? Returns a descriptive error if not.
    pub fn check_compatible(&self, other: &Self) -> Result<()> {
        for (k, v) in &other.nodes {
            if let Some(def) = self.nodes.get(k) {
                if def.is_validator != v.is_validator {
                    return Err(anyhow!(
                        "Node {k} is_validator mismatch - network {0}, spec {1}",
                        def.is_validator,
                        v.is_validator
                    ));
                }
            } else {
                return Err(anyhow!("Cannot start non-existent node {k}"));
            }
        }
        Ok(())
    }
}

impl fmt::Display for NodeSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.configured, self.start)
    }
}

impl NodeSpec {
    pub fn small_network() -> Self {
        Self {
            configured: Composition::small_network(),
            start: Composition::small_network(),
        }
    }

    pub fn parse(from: &str) -> Result<Option<Self>> {
        let mut components = from.split('/');
        if let Some(config) = components.next() {
            let configured = Composition::parse(config)?;
            if let Some(start_str) = components.next() {
                let start = Composition::parse(start_str)?;
                Ok(Some(Self { configured, start }))
            } else {
                Ok(Some(Self {
                    configured: configured.clone(),
                    start: configured,
                }))
            }
        } else {
            Ok(None)
        }
    }
}
