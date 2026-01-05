// Code to generate documentation from .tera.md files.

use std::{
    cmp::{Ord, Ordering, PartialOrd},
    collections::HashMap,
    convert::TryFrom,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicUsize},
};

use anyhow::{Context as _, Result, anyhow};
use arc_swap::ArcSwap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tera::Tera;
use tokio::fs;
use zilliqa::{cfg::NodeConfig, crypto::SecretKey, sync::SyncPeers};

const SUPPORTED_APIS_PATH_NAME: &str = "index";

#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub enum PageStatus {
    Implemented,
    NotYetImplemented,
    NeverImplemented,
    PartiallyImplemented,
    NotYetDocumented,
}

impl fmt::Display for PageStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let val = match self {
            Self::Implemented => "Implemented",
            Self::NotYetImplemented => "NotYetImplemented",
            Self::NeverImplemented => "NeverImplemented",
            Self::PartiallyImplemented => "PartiallyImplemented",
            Self::NotYetDocumented => "NotYetDocumented",
        };
        write!(f, "{val}")
    }
}

impl TryFrom<&str> for PageStatus {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self> {
        // From docs/docgen.md
        Ok(match s {
            "Implemented" => Self::Implemented,
            "NotYetImplemented" => Self::NotYetImplemented,
            "NeverImplemented" => Self::NeverImplemented,
            "PartiallyImplemented" => Self::PartiallyImplemented,
            "NotYetDocumented" => Self::NotYetDocumented,
            _ => Self::PartiallyImplemented,
        })
    }
}

pub struct GeneratedFile {
    /// What is the filename we should give in the nav entry in mkdocs?
    pub mkdocs_filename: String,
    /// Components of the id for the nav entry in mkdocs.
    pub id_components: Vec<String>,
    /// Name of the API for our list.
    pub api_name: ApiMethod,
    /// Page status.
    pub page_status: PageStatus,
}

// Mostly so I don't have to retype the hashtable everywhere, but also
// useful in future for collecting fields related to macros.
pub struct Macros {
    pub macros: HashMap<String, String>,
}

pub struct Docs {
    // Where do we render to?
    pub target_dir: String,
    // Where do we render from?
    pub source_dir: String,
    // What should we prefix the id with, if anything?
    pub id_prefix: Option<String>,
    // Where should we write the index file?
    pub index_file: Option<String>,
    // At what key should we start?
    pub index_file_key_prefix: String,
    // What is the API url ?
    pub api_url: String,
    // What APIs are actually implemented?
    pub implemented: HashMap<ApiMethod, PageStatus>,
}

#[derive(Debug)]
struct ParsedInput {
    sections: HashMap<String, String>,
    rest: String,
}

fn split_into_components(prefix: &str) -> Result<Vec<String>> {
    Ok(prefix.split('/').map(|x| x.to_string()).collect::<Vec<_>>())
}

// Removes the first element of the sequence named by components
fn replace_first_string_element_of(
    val: &serde_yaml::Value,
    components: &Vec<String>,
    idx: usize,
    to_insert: &str,
) -> Option<serde_yaml::Value> {
    match val {
        serde_yaml::Value::Mapping(map) => {
            if idx >= components.len() {
                return Some(val.clone());
            }
            // Insert all.
            let component = &components[idx];
            let mut new_map = serde_yaml::Mapping::new();
            for (k, v) in map {
                if let serde_yaml::Value::String(k_s) = k {
                    if k_s == component {
                        let to_insert =
                            replace_first_string_element_of(v, components, idx + 1, to_insert);
                        if let Some(v) = to_insert {
                            new_map.insert(k.clone(), v);
                        }
                    } else {
                        new_map.insert(k.clone(), v.clone());
                    }
                }
            }
            // Implicitly remove empty maps.
            if new_map.is_empty() {
                None
            } else {
                Some(serde_yaml::Value::Mapping(new_map))
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            match idx.cmp(&components.len()) {
                std::cmp::Ordering::Less => {
                    // Move on.
                    let mut new_seq = serde_yaml::Sequence::new();
                    for s in seq.iter() {
                        if let Some(v) =
                            replace_first_string_element_of(s, components, idx, to_insert)
                        {
                            new_seq.push(v);
                        }
                    }
                    if new_seq.is_empty() {
                        None
                    } else {
                        Some(serde_yaml::Value::Sequence(new_seq))
                    }
                }
                std::cmp::Ordering::Equal => {
                    // Remove the first non-mapping element.
                    let mut new_seq = serde_yaml::Sequence::new();
                    new_seq.push(serde_yaml::Value::String(to_insert.to_string()));
                    let mut got_one = false;
                    for s in seq.iter() {
                        if !got_one {
                            match s {
                                serde_yaml::Value::String(_) => (),
                                _ => new_seq.push(s.clone()),
                            }
                            got_one = true;
                        } else {
                            new_seq.push(s.clone());
                        }
                    }
                    Some(serde_yaml::Value::Sequence(new_seq))
                }
                _ => Some(val.clone()),
            }
        }
        // Ignore tags for now!
        _ => Some(val.clone()),
    }
}

// Mutating trees is just as painful in rust as it is in ML :-(
fn remove_key(
    val: &serde_yaml::Value,
    components: &Vec<String>,
    idx: usize,
) -> Option<serde_yaml::Value> {
    if idx >= components.len() {
        return Some(val.clone());
    }
    let component = &components[idx];
    match val {
        serde_yaml::Value::Mapping(map) => {
            // Insert all but
            let mut new_map = serde_yaml::Mapping::new();
            for (k, v) in map {
                if let serde_yaml::Value::String(k_s) = k
                    && !(idx == components.len() - 1 && k_s == component)
                {
                    let to_insert = remove_key(v, components, idx + 1);
                    if let Some(v) = to_insert {
                        new_map.insert(k.clone(), v);
                    }
                }
            }
            // Implicitly remove empty maps.
            if new_map.is_empty() {
                None
            } else {
                Some(serde_yaml::Value::Mapping(new_map))
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            let mut new_seq = serde_yaml::Sequence::new();
            for s in seq.iter() {
                if let Some(v) = remove_key(s, components, idx) {
                    new_seq.push(v);
                }
            }
            if new_seq.is_empty() {
                None
            } else {
                Some(serde_yaml::Value::Sequence(new_seq))
            }
        }
        // Ignore tags for now!
        _ => Some(val.clone()),
    }
}

pub enum Position {
    Beginning,
    End,
}

fn insert_key(
    val: &mut serde_yaml::Value,
    components: &Vec<String>,
    idx: usize,
    value: &str,
    position: &Option<Position>,
) {
    let k = &components[idx];
    if idx == components.len() - 1 {
        // We're here .
        match val {
            serde_yaml::Value::Mapping(map) => {
                map.insert(
                    serde_yaml::Value::String(k.clone().to_string()),
                    serde_yaml::Value::String(value.to_string()),
                );
            }
            serde_yaml::Value::Sequence(seq) => {
                let mut new_map = serde_yaml::Mapping::new();
                new_map.insert(
                    serde_yaml::Value::String(k.clone()),
                    serde_yaml::Value::String(value.to_string()),
                );
                match position.as_ref().unwrap_or(&Position::End) {
                    Position::Beginning => seq.insert(0, serde_yaml::Value::Mapping(new_map)),
                    Position::End => seq.push(serde_yaml::Value::Mapping(new_map)),
                }
            }
            _ => (),
        }
    } else {
        // Not yere het.
        match val {
            serde_yaml::Value::Mapping(map) => match map.get_mut(k) {
                Some(ref mut seq) => {
                    insert_key(seq, components, idx + 1, value, position);
                }
                None => {
                    let mut seq = serde_yaml::Value::Sequence(serde_yaml::Sequence::new());
                    insert_key(&mut seq, components, idx + 1, value, position);
                    map.insert(serde_yaml::Value::String(k.clone()), seq);
                }
            },
            serde_yaml::Value::Sequence(seq) => {
                // Find the right map, if there is one, otherwise add one.
                let mut found = false;
                for s in seq.iter_mut() {
                    if let serde_yaml::Value::Mapping(map) = s {
                        match map.get_mut(k) {
                            None => (),
                            Some(v) => {
                                insert_key(v, components, idx + 1, value, position);
                                found = true;
                            }
                        }
                    }
                }
                if !found {
                    let mut map = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
                    insert_key(&mut map, components, idx, value, position);
                    seq.push(map);
                }
            }
            _ => (),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, Serialize, Deserialize)]
pub enum ApiMethod {
    JsonRpc { name: String },
    Rest { uri: String },
}

impl PartialOrd for ApiMethod {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ApiMethod {
    fn cmp(&self, other: &Self) -> Ordering {
        fn cmp_prefix(s1: &str, s2: &str) -> Ordering {
            // This implements a heuristic order: if there is a prefix (xxx_), then this is a non-ZIL API and comes first.
            // non-prefixed APIs are ZIL APIs and are all ordered second.
            match (s1.contains('_'), s2.contains('_')) {
                (true, true) | (false, false) => s1.cmp(s2),
                (true, false) => Ordering::Less,
                _ => Ordering::Greater,
            }
        }

        // All JsonRpc comes before all Rest
        match (self, other) {
            (Self::JsonRpc { name: _ }, Self::Rest { uri: _ }) => Ordering::Less,
            (Self::Rest { uri: _ }, Self::JsonRpc { name: _ }) => Ordering::Greater,
            (Self::JsonRpc { name: n1 }, Self::JsonRpc { name: n2 }) => cmp_prefix(n1, n2),
            (Self::Rest { uri: n1 }, Self::Rest { uri: n2 }) => cmp_prefix(n1, n2),
        }
    }
}

/// Used when we want to construct an ordered list of API call status.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ApiCallStatus {
    pub method: ApiMethod,
    pub status: PageStatus,
}

pub fn get_implemented_jsonrpc_methods() -> Result<HashMap<ApiMethod, PageStatus>> {
    let mut methods = HashMap::new();

    // Construct an empty node so we can check for the existence of RPC methods without constructing a full node.
    let config = NodeConfig::default();
    let secret_key = SecretKey::new()?;
    let (s1, _) = tokio::sync::mpsc::unbounded_channel();
    let (s2, _) = tokio::sync::mpsc::unbounded_channel();
    let (s3, _) = tokio::sync::mpsc::unbounded_channel();
    let (s4, _) = tokio::sync::mpsc::unbounded_channel();
    let peers_count = Arc::new(AtomicUsize::new(0));

    let peer_id = secret_key.to_libp2p_keypair().public().to_peer_id();
    let sync_peers = Arc::new(SyncPeers::new(peer_id));
    let swarm_peers = Arc::new(ArcSwap::from_pointee(Vec::new()));

    let my_node = Arc::new(zilliqa::node::Node::new(
        config,
        secret_key,
        s1,
        s2,
        s3,
        s4,
        peers_count,
        sync_peers,
        swarm_peers,
    )?);
    let module = zilliqa::api::rpc_module(my_node.clone(), &[]);
    for m in module.method_names() {
        methods.insert(
            ApiMethod::JsonRpc {
                name: m.to_string(),
            },
            PageStatus::Implemented,
        );
    }
    // @todo we don't document the admin_ entrypoints for now.
    Ok(methods)
}

impl Macros {
    pub fn inject_into(&self, context: &mut tera::Context) -> Result<()> {
        for (k, v) in self.macros.iter() {
            context.insert(format!("macro_{k}"), v);
        }
        Ok(())
    }
}

impl Docs {
    pub fn new(
        source_dir: &str,
        target_dir: &str,
        id_prefix: &Option<String>,
        index_file: &Option<String>,
        index_file_key_prefix: &str,
        api_url: &str,
        implemented: &HashMap<ApiMethod, PageStatus>,
    ) -> Result<Self> {
        Ok(Self {
            target_dir: target_dir.to_string(),
            source_dir: source_dir.to_string(),
            id_prefix: id_prefix.clone(),
            index_file: index_file.clone(),
            index_file_key_prefix: index_file_key_prefix.to_string(),
            api_url: api_url.to_string(),
            implemented: implemented.clone(),
        })
    }

    pub async fn read_macros(&self) -> Result<Macros> {
        let macro_source = include_str!("../resources/api_macros.tera.md");
        let parsed = self.parse_input_sections(macro_source).await?;
        Ok(Macros {
            macros: parsed.sections,
        })
    }

    pub async fn generate_all(&self) -> Result<HashMap<ApiMethod, PageStatus>> {
        let macros = self.read_macros().await?;
        let result = self
            .generate_dir(&PathBuf::from(&self.source_dir), &macros)
            .await?;
        Ok(result)
    }

    pub async fn get_base_mkdocs_key(&self) -> Result<Vec<String>> {
        let key_prefix_components = split_into_components(&self.index_file_key_prefix)?;

        // We now need to zap the prefix ..
        let key_to_remove = if let Some(ref v) = self.id_prefix {
            let id_components = split_into_components(v)?;
            key_prefix_components
                .iter()
                .chain(id_components.iter())
                .map(|x| x.to_string())
                .collect()
        } else {
            key_prefix_components.clone()
        };
        Ok(key_to_remove)
    }

    // Recursively generate documentation.
    // Because of the weird rules around recursive async, this is done iteratively.
    // @return A vector of the APIs documented
    pub async fn generate_dir(
        &self,
        dir: &Path,
        macros: &Macros,
    ) -> Result<HashMap<ApiMethod, PageStatus>> {
        #[derive(PartialEq, Debug, Clone)]
        struct Entry {
            abs: PathBuf,
            rel: PathBuf,
        }
        let mut stack: Vec<Entry> = Vec::new();
        let mut to_generate: Vec<Entry> = Vec::new();
        let mut documented_apis = HashMap::new();
        stack.push(Entry {
            abs: PathBuf::from(dir),
            rel: PathBuf::from(""),
        });
        let mut contents_map: serde_yaml::Value = if let Some(val) = &self.index_file {
            serde_yaml::from_str(&fs::read_to_string(val).await?)?
        } else {
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
        };
        let base_key = self.get_base_mkdocs_key().await?;
        let key_prefix_components = split_into_components(&self.index_file_key_prefix)?;
        contents_map = remove_key(&contents_map, &base_key, 0)
            .unwrap_or(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));

        while let Some(ref path_entry) = stack.pop() {
            let md = fs::metadata(&path_entry.abs)
                .await
                .context(format!("Cannot find {0:?}", path_entry.abs))?;
            if md.is_dir() {
                let mut entries = fs::read_dir(&path_entry.abs).await?;
                loop {
                    let Some(entry) = entries.next_entry().await? else {
                        break;
                    };
                    let mut rel = PathBuf::from(&path_entry.rel);
                    rel.push(entry.file_name());
                    stack.push(Entry {
                        abs: entry.path(),
                        rel,
                    });
                }
            } else if md.is_file() {
                // It's a file. does it end `.doc.md`? If so, it's a candidate for documentation.
                let name = path_entry
                    .abs
                    .file_name()
                    .ok_or(anyhow!("{0:?} has no file name", path_entry.abs))?
                    .to_str()
                    .ok_or(anyhow!(
                        "{0:?} is not representable as a string",
                        path_entry.abs
                    ))?;
                let components = name.split('.').collect::<Vec<&str>>();
                if components.len() >= 2
                    && components[components.len() - 1] == "md"
                    && components[components.len() - 2] == "doc"
                {
                    // Push onto the "files" list - we'll sort it in a bit
                    to_generate.push(path_entry.clone());
                }
            }
        }

        // Now sort the list of files to generate.
        to_generate.sort_by(|a, b| a.rel.cmp(&b.rel));
        for path_entry in to_generate.iter() {
            let generated = self
                .generate_file(&path_entry.abs, &path_entry.rel, macros)
                .await?;
            let the_iter = key_prefix_components.iter().chain(
                generated
                    .id_components
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, v)| {
                        if idx == 1 && v == "api" {
                            None
                        } else {
                            Some(v)
                        }
                    }),
            );
            // Flatten "api" back to the root directory, per #1434
            insert_key(
                &mut contents_map,
                &the_iter.map(|m| m.to_string()).collect(),
                0,
                &generated.mkdocs_filename,
                &Some(Position::End),
            );
            documented_apis.insert(generated.api_name, generated.page_status);
        }

        if let Some(val) = &self.index_file {
            // Save the index file back out again.
            fs::write(val, &serde_yaml::to_string(&contents_map)?).await?;
        }
        Ok(documented_apis)
    }

    pub async fn generate_api_table(
        &self,
        documented_apis: &HashMap<ApiMethod, PageStatus>,
        implemented_apis: &HashMap<ApiMethod, PageStatus>,
    ) -> Result<Vec<ApiCallStatus>> {
        // Documented APIs will have had their page status set properly (to NotImplemented if necessary) already
        // Implemented APIs that are not documented need to get it set to NotYetDocumented.
        // I am turning into JH...
        let mut all_apis: Vec<ApiCallStatus> = documented_apis
            .iter()
            .chain(
                implemented_apis
                    .iter()
                    .filter(|(k, _)| !documented_apis.contains_key(k))
                    .map(|(k, _)| (k, &PageStatus::NotYetDocumented)),
            )
            .map(|(k, v)| ApiCallStatus {
                method: k.clone(),
                status: v.clone(),
            })
            .collect::<Vec<ApiCallStatus>>();
        all_apis.sort_by(|a, b| a.method.cmp(&b.method));
        let mut list_tera: Tera = Default::default();
        let mut context = tera::Context::new();

        let macros = self.read_macros().await?;

        // Find some paths for later ..
        let mut desc_path: PathBuf = PathBuf::new();
        desc_path.push(&self.target_dir);
        if let Some(ref v) = self.id_prefix {
            desc_path.push(v.to_lowercase());
        }
        let supported_api_filename = format!("{SUPPORTED_APIS_PATH_NAME}.md");
        desc_path.push(&supported_api_filename);

        let mut out_path = PathBuf::new();
        out_path.push(&self.target_dir);
        if let Some(ref v) = self.id_prefix {
            out_path.push(v.to_lowercase());
        }
        out_path.push(&supported_api_filename);
        let mut mkdocs_path = PathBuf::new();
        if let Some(ref v) = self.id_prefix {
            mkdocs_path.push(v.to_lowercase());
        }
        mkdocs_path.push(format!("{SUPPORTED_APIS_PATH_NAME}.md"));
        let mut id_path = PathBuf::new();
        if let Some(ref v) = self.id_prefix {
            id_path.push(v);
        }
        id_path.push(SUPPORTED_APIS_PATH_NAME);

        context.insert("apis", &all_apis);
        context.insert("_id", &id_path);
        macros.inject_into(&mut context)?;

        list_tera.add_raw_template(
            "api_calls",
            include_str!("../resources/supported_apis.tera.md"),
        )?;
        let list_page = list_tera
            .render("api_calls", &context)
            .context("Whilst rendering api call list")?;

        self.write_file(&list_page, &desc_path).await?;

        if let Some(val) = &self.index_file {
            // Now write out...
            let contents_map = serde_yaml::from_str(&fs::read_to_string(val).await?)?;
            let base_key = self.get_base_mkdocs_key().await?;
            let contents_map = replace_first_string_element_of(
                &contents_map,
                &base_key,
                0,
                mkdocs_path.to_str().unwrap(),
            )
            .unwrap_or(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
            fs::write(val, &serde_yaml::to_string(&contents_map)?).await?;
        }
        Ok(all_apis)
    }

    // Old-style parser. You can probably do better (you can certainly do more elegant!)
    // For convenience, we trim() sections as we parse them.
    async fn parse_input_sections(&self, input_text: &str) -> Result<ParsedInput> {
        let lines = input_text.split('\n');
        let is_heading = Regex::new(r"^#\s+(.*)$")?;
        let mut current_heading: Option<String> = None;
        let mut current_text: String = String::new();
        // Text outside a heading - either ignored or an error, depending how you feel today.
        let mut rest: String = String::new();
        let mut sections: HashMap<String, String> = HashMap::new();
        fn push_line(into: &mut String, l: &str) {
            into.push_str(l);
            into.push('\n');
        }

        for l in lines {
            let cap = is_heading.captures(l);
            if let Some(c) = cap {
                if let Some(val) = current_heading {
                    sections.insert(val.clone(), current_text.trim().to_string());
                }
                current_text = String::new();
                current_heading = Some(c[1].trim().to_lowercase().to_string());
            } else {
                match current_heading {
                    None => push_line(&mut rest, l),
                    Some(_) => push_line(&mut current_text, l),
                }
            }
        }
        // .. and anything we were working on.
        if let Some(v) = current_heading {
            sections.insert(v.clone(), current_text.trim().to_string());
        }
        let rest = rest.trim().to_string();
        Ok(ParsedInput { sections, rest })
    }

    pub async fn write_file(&self, contents: &str, rel: &Path) -> Result<()> {
        let output_path = PathBuf::from(&self.target_dir).join(rel);
        println!("📙 writing {output_path:?}");
        if let Some(v) = output_path.parent() {
            fs::create_dir_all(v).await?;
        }
        fs::write(&output_path, contents).await?;
        Ok(())
    }

    // OK. The cunning plan here is that each section of an API doc is specified in the
    // .md - we have a very simple parser which just checks for ^# <section_name>.
    // We then substitute the sections with some Tera that we had to hand for style, etc.
    // (this should not be necessary, really, but just in case .. )
    // Then we make those sections the elements of a Tera dictionary and substitute a template
    // which tells us how to generate the documentation - this is a resource for now, but
    // one day it might be programmable.
    // @return A vector of the components we will use to index this page in mkdocs.yaml
    pub async fn generate_file(
        &self,
        src: &Path,
        rel: &Path,
        macros: &Macros,
    ) -> Result<GeneratedFile> {
        fn indent4(
            v: &tera::Value,
            _args: &HashMap<String, tera::Value>,
        ) -> tera::Result<tera::Value> {
            // no-op if this is not a string
            match v {
                tera::Value::String(in_str) => Ok(tera::Value::String(
                    in_str
                        .split('\n')
                        .map(|x| {
                            if !x.is_empty() {
                                format!("    {x}")
                            } else {
                                String::new()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                )),
                _ => Ok(v.clone()),
            }
        }

        // First, let's read the input
        let src_contents = fs::read_to_string(src).await?;
        let parsed = self.parse_input_sections(&src_contents).await?;
        // If there is "rest" text, complain.
        if !parsed.rest.is_empty() {
            return Err(anyhow!(
                "{src:?} contains text outside a section: '{0}' - please fix!",
                &parsed.rest
            ));
        }
        // otherwise, each section gets Tera-substituted with the library. We can do this all at once ..
        let mut section_tera: Tera = Default::default();
        let mut context = tera::Context::new();
        context.insert("_api_url", &self.api_url);
        macros.inject_into(&mut context)?;

        // Add context keys here when we have some.
        let mut page_status = PageStatus::Implemented;
        for (k, v) in &parsed.sections {
            section_tera.add_raw_template(k, v)?;
        }

        let mut final_context = tera::Context::new();
        println!("---------------------------");
        for k in parsed.sections.keys() {
            let rendered = section_tera.render(k, &context)?;
            if k == "status" {
                page_status = rendered.trim().try_into()?;
            } else {
                final_context.insert(k, &rendered);
            }
        }

        // OK. Grab the template
        let mut page_tera: Tera = Default::default();
        page_tera.add_raw_template("api", include_str!("../resources/api.tera.md"))?;

        let Some(page_title) = parsed.sections.get("title") else {
            return Err(anyhow!(
                "Page {src:?} does not contain a title section - needed to build the mkdocs index"
            ));
        };
        let api_name = ApiMethod::JsonRpc {
            name: page_title.to_string(),
        };
        // If the API is not implemented, and it is supposed to be ..
        if !self.implemented.contains_key(&api_name) && page_status != PageStatus::NeverImplemented
        {
            // ... set the status to not implemented
            page_status = PageStatus::NotYetImplemented;
        }
        final_context.insert("status", &page_status.to_string());
        macros.inject_into(&mut final_context)?;
        let mut nearly_id: Vec<String> = PathBuf::from(rel)
            .iter()
            .map(|x| x.to_str().unwrap_or("").to_string())
            .collect();
        nearly_id.pop();

        // Where should we write the output?
        let mut desc_path: PathBuf = PathBuf::new();
        desc_path.push(&self.target_dir);
        if let Some(ref v) = self.id_prefix {
            desc_path.push(v.to_lowercase());
        }
        for p in &nearly_id {
            desc_path.push(p);
        }
        desc_path.push(format!("{page_title}.md"));

        // Where do we tell mkdocs the file is?
        let mut mkdocs_path = PathBuf::new();
        if let Some(ref v) = self.id_prefix {
            mkdocs_path.push(v.to_lowercase());
        }
        for p in &nearly_id {
            mkdocs_path.push(p);
        }
        mkdocs_path.push(format!("{page_title}.md"));

        // What is the id?
        let mut id_path = PathBuf::new();
        if let Some(ref v) = self.id_prefix {
            id_path.push(v);
        }
        for p in &nearly_id {
            id_path.push(p);
        }
        id_path.push(page_title);

        // That is also the mkdocs id of this file.
        final_context.insert("_id", &id_path);
        // Because we need to indent every line in a section by exactly 4
        // spaces or tabs don't work . Grr!
        page_tera.register_filter("indent4", indent4);
        let final_page = page_tera
            .render("api", &final_context)
            .context(format!("Whilst rendering {src:?}"))?;

        // OK. Now we have some data, let's write it.
        self.write_file(&final_page, &desc_path).await?;

        let id_components = id_path
            .iter()
            .map(|x| x.to_str().unwrap_or("").to_string())
            .collect();

        Ok(GeneratedFile {
            mkdocs_filename: mkdocs_path.into_os_string().into_string().unwrap(),
            id_components,
            api_name,
            page_status,
        })
    }
}
