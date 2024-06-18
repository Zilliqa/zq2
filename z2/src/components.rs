// Components of z2
use std::{collections::HashSet, fmt};

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum Component {
    ZQ2,
    Otterscan,
    Otel,
    Spout,
    Mitmweb,
    Docs,
    Scilla,
}

#[derive(Default, Clone)]
pub struct Requirements {
    /// Human readable requirements.
    pub software: Vec<String>,
    /// This is a list of zilliqa repositories.
    pub repos: Vec<String>,
}

impl Component {
    pub fn in_dependency_order() -> Vec<Component> {
        vec![
            Component::Otel,
            Component::Scilla,
            Component::ZQ2,
            Component::Mitmweb,
            Component::Otterscan,
            Component::Spout,
            Component::Docs,
        ]
    }

    pub fn all() -> HashSet<Component> {
        // These must be listed in dependency order!
        HashSet::from([
            Component::Otel,
            Component::Scilla,
            Component::ZQ2,
            Component::Mitmweb,
            Component::Otterscan,
            Component::Spout,
            Component::Docs,
        ])
    }
}

// Used as a legend for log output.
impl fmt::Display for Component {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Component::ZQ2 => write!(f, "zq2"),
            Component::Otterscan => write!(f, "otterscan"),
            Component::Spout => write!(f, "spout"),
            Component::Mitmweb => write!(f, "mitmweb"),
            Component::Docs => write!(f, "docs"),
            Component::Otel => write!(f, "otel"),
            Component::Scilla => write!(f, "scilla"),
        }
    }
}

impl fmt::Display for Requirements {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for r in &self.software {
            writeln!(f, "- program:   {r}")?;
        }
        for repo in &self.repos {
            writeln!(f, "- repo   :  {repo}")?;
        }
        Ok(())
    }
}
