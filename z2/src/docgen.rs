// Code to generate documentation from .tera.md files.
#![allow(unused_imports)]

use std::{
    cmp::{Ord, Ordering, PartialOrd},
    collections::{HashMap, HashSet},
    convert::TryFrom,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use alloy_primitives::{address, Address};
use anyhow::{anyhow, Context as _, Result};
use libp2p::PeerId;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tera::Tera;
use tokio::{
    fs,
    sync::{broadcast, mpsc::UnboundedSender},
};
use zilliqa::{
    cfg::{ConsensusConfig, NodeConfig},
    crypto::SecretKey,
    node::{MessageSender, Node},
};
use zqutils::utils;

const SUPPORTED_APIS_PATH_NAME: &str = "supported_apis";
const SUPPORTED_APIS_PAGE_NAME: &str = "Supported APIs";

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
        write!(f, "{}", val)
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
                if let serde_yaml::Value::String(k_s) = k {
                    if !(idx == components.len() - 1 && k_s == component) {
                        let to_insert = remove_key(v, components, idx + 1);
                        if let Some(v) = to_insert {
                            new_map.insert(k.clone(), v);
                        }
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

fn insert_key(val: &mut serde_yaml::Value, components: &Vec<String>, idx: usize, value: &str) {
    let k = &components[idx];
    if idx == components.len() - 1 {
        // We're here .
        match val {
            serde_yaml::Value::Mapping(ref mut map) => {
                map.insert(
                    serde_yaml::Value::String(k.clone().to_string()),
                    serde_yaml::Value::String(value.to_string()),
                );
            }
            serde_yaml::Value::Sequence(ref mut seq) => {
                let mut new_map = serde_yaml::Mapping::new();
                new_map.insert(
                    serde_yaml::Value::String(k.clone()),
                    serde_yaml::Value::String(value.to_string()),
                );
                seq.push(serde_yaml::Value::Mapping(new_map));
            }
            _ => (),
        }
    } else {
        // Not yere het.
        match val {
            serde_yaml::Value::Mapping(ref mut map) => match map.get_mut(k) {
                Some(ref mut seq) => {
                    insert_key(seq, components, idx + 1, value);
                }
                None => {
                    let mut seq = serde_yaml::Value::Sequence(serde_yaml::Sequence::new());
                    insert_key(&mut seq, components, idx + 1, value);
                    map.insert(serde_yaml::Value::String(k.clone()), seq);
                }
            },
            serde_yaml::Value::Sequence(ref mut seq) => {
                // Find the right map, if there is one, otherwise add one.
                let mut found = false;
                for s in seq.iter_mut() {
                    if let serde_yaml::Value::Mapping(ref mut map) = s {
                        match map.get_mut(k) {
                            None => (),
                            Some(v) => {
                                insert_key(v, components, idx + 1, value);
                                found = true;
                            }
                        }
                    }
                }
                if !found {
                    let mut map = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
                    insert_key(&mut map, components, idx, value);
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
    let genesis_accounts: Vec<(Address, String)> = vec![
        (
            address!("7E5F4552091A69125d5DfCb7b8C2659029395Bdf"),
            "5000000000000000000000".to_string(),
        ),
        // privkey db11cfa086b92497c8ed5a4cc6edb3a5bfe3a640c43ffb9fc6aa0873c56f2ee3
        (
            address!("cb57ec3f064a16cadb36c7c712f4c9fa62b77415"),
            "5000000000000000000000".to_string(),
        ),
    ];

    let config = NodeConfig {
        consensus: ConsensusConfig {
            genesis_accounts,
            ..Default::default()
        },
        ..Default::default()
    };
    let secret_key = SecretKey::new()?;
    let (s1, _) = tokio::sync::mpsc::unbounded_channel();
    let (s2, _) = tokio::sync::mpsc::unbounded_channel();
    let (s3, _) = tokio::sync::mpsc::unbounded_channel();

    let my_node = Arc::new(Mutex::new(zilliqa::node::Node::new(
        config, secret_key, s1, s2, s3,
    )?));
    let module = zilliqa::api::rpc_module(my_node.clone());
    for m in module.method_names() {
        methods.insert(
            ApiMethod::JsonRpc {
                name: m.to_string(),
            },
            PageStatus::Implemented,
        );
    }
    Ok(methods)
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

    pub async fn generate_all(&self) -> Result<HashMap<ApiMethod, PageStatus>> {
        let result = self.generate_dir(&PathBuf::from(&self.source_dir)).await?;
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
    pub async fn generate_dir(&self, dir: &Path) -> Result<HashMap<ApiMethod, PageStatus>> {
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

        println!("After remove {0}", serde_yaml::to_string(&contents_map)?);

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
            println!("File: {:?} rel {:?}", &path_entry.abs, &path_entry.rel);
            let generated = self.generate_file(&path_entry.abs, &path_entry.rel).await?;
            let the_iter = key_prefix_components
                .iter()
                .chain(generated.id_components.iter());
            insert_key(
                &mut contents_map,
                &the_iter.map(|m| m.to_string()).collect(),
                0,
                &generated.mkdocs_filename,
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

        // Find some paths for later ..
        let mut desc_path: PathBuf = PathBuf::new();
        desc_path.push(&self.target_dir);
        if let Some(ref v) = self.id_prefix {
            desc_path.push(v.to_lowercase());
        }
        let supported_api_filename = format!("{0}.md", SUPPORTED_APIS_PATH_NAME);
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
        mkdocs_path.push(format!("{0}.md", SUPPORTED_APIS_PATH_NAME));
        let mut id_path = PathBuf::new();
        if let Some(ref v) = self.id_prefix {
            id_path.push(v);
        }
        id_path.push(SUPPORTED_APIS_PATH_NAME);
        let mkdocs_filename = zqutils::utils::string_from_path(&mkdocs_path)?;

        context.insert("apis", &all_apis);
        let prefixed_id = zqutils::utils::string_from_path(&id_path)?;
        context.insert("_id", &prefixed_id);

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
            let mut base_key = self.get_base_mkdocs_key().await?;
            base_key.push(SUPPORTED_APIS_PAGE_NAME.to_string());
            let mut contents_map = remove_key(&contents_map, &base_key, 0)
                .unwrap_or(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
            insert_key(&mut contents_map, &base_key, 0, &mkdocs_filename);
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
    pub async fn generate_file(&self, src: &Path, rel: &Path) -> Result<GeneratedFile> {
        fn indent4(
            v: &tera::Value,
            _args: &HashMap<String, tera::Value>,
        ) -> tera::Result<tera::Value> {
            // no-op if this is not a string
            match v {
                tera::Value::String(ref in_str) => Ok(tera::Value::String(
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
        let src_file = zqutils::utils::string_from_path(src)?;
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
        // Keep rust happy.
        context.insert("_api_url", &self.api_url);
        // Add context keys here when we have some.
        let mut page_status = PageStatus::Implemented;
        for (k, v) in &parsed.sections {
            section_tera.add_raw_template(k, v)?;
        }

        let mut final_context = tera::Context::new();
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
                "Page {0} does not contain a title section - needed to build the mkdocs index",
                src_file
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
        let prefixed_id = zqutils::utils::string_from_path(&id_path)?;
        final_context.insert("_id", &prefixed_id);
        // Because we need to indent every line in a section by exactly 4
        // spaces or tabs don't work . Grr!
        page_tera.register_filter("indent4", indent4);
        let final_page = page_tera
            .render("api", &final_context)
            .context(format!("Whilst rendering {0:?}", src_file))?;

        // OK. Now we have some data, let's write it.
        self.write_file(&final_page, &desc_path).await?;

        let mkdocs_filename = zqutils::utils::string_from_path(&mkdocs_path)?;

        println!("prefixed_id is {prefixed_id}");
        println!("mkdocs_filename is {mkdocs_filename}");

        let id_components = id_path
            .iter()
            .map(|x| x.to_str().unwrap_or("").to_string())
            .collect();

        Ok(GeneratedFile {
            mkdocs_filename,
            id_components,
            api_name,
            page_status,
        })
    }
}
