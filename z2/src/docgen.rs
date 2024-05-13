// Code to generate documentation from .tera.md files.
#![allow(unused_imports)]

use anyhow::{anyhow, Context as _, Result};
use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tera::Tera;
use tokio::fs;
use zqutils::utils;

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
}

#[derive(Debug)]
struct ParsedInput {
    sections: HashMap<String, String>,
    rest: String,
}

fn split_into_components(prefix: &str) -> Result<Vec<String>> {
    Ok(prefix.split("/").map(|x| x.to_string()).collect::<Vec<_>>())
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
                println!("k = {k:?}");
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
                    match s {
                        serde_yaml::Value::Mapping(ref mut map) => match map.get_mut(k) {
                            None => (),
                            Some(mut v) => {
                                insert_key(v, components, idx + 1, value);
                                found = true;
                            }
                        },
                        _ => (),
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

impl Docs {
    pub fn new(
        source_dir: &str,
        target_dir: &str,
        id_prefix: &Option<String>,
        index_file: &Option<String>,
        index_file_key_prefix: &str,
    ) -> Result<Self> {
        Ok(Self {
            target_dir: target_dir.to_string(),
            source_dir: source_dir.to_string(),
            id_prefix: id_prefix.clone(),
            index_file: index_file.clone(),
            index_file_key_prefix: index_file_key_prefix.to_string(),
        })
    }

    pub async fn generate_all(&self) -> Result<()> {
        self.generate_dir(&PathBuf::from(&self.source_dir)).await?;
        Ok(())
    }

    // Recursively generate documentation.
    // Because of the weird rules around recursive async, this is done iteratively.
    pub async fn generate_dir(&self, dir: &Path) -> Result<()> {
        struct Entry {
            abs: PathBuf,
            rel: PathBuf,
        }
        let mut stack: Vec<Entry> = Vec::new();
        stack.push(Entry {
            abs: PathBuf::from(dir),
            rel: PathBuf::from(""),
        });
        let mut contents_map: serde_yaml::Value = if let Some(val) = &self.index_file {
            serde_yaml::from_str(&fs::read_to_string(val).await?)?
        } else {
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
        };
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
        contents_map = remove_key(&contents_map, &key_to_remove, 0)
            .unwrap_or(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));

        println!("After remove {0}", serde_yaml::to_string(&contents_map)?);

        while let Some(ref path_entry) = stack.pop() {
            let md = fs::metadata(&path_entry.abs).await?;
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
                // It's a file. does it end `.md`? If so, it's a candidate for documentation.
                if let Some(v) = path_entry.abs.extension() {
                    if v.to_str()
                        .ok_or(anyhow!("Can't convert extension"))?
                        .to_string()
                        == "md"
                    {
                        println!("File: {:?} rel {:?}", &path_entry.abs, &path_entry.rel);
                        let (output_filename, prefixed_id) =
                            self.generate_file(&path_entry.abs, &path_entry.rel).await?;
                        let the_iter = key_prefix_components.iter().chain(prefixed_id.iter());
                        //let key = the_iter.next_back().ok_or(anyhow!(
                        //    "API file {0:?} has empty description path!",
                        //   &path_entry.abs
                        //))?;

                        insert_key(
                            &mut contents_map,
                            &the_iter.map(|m| m.to_string()).collect(),
                            0,
                            &output_filename,
                        );
                    }
                }
            }
        }
        if let Some(val) = &self.index_file {
            // Save the index file back out again.
            fs::write(val, &serde_yaml::to_string(&contents_map)?).await?;
        }
        Ok(())
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
    pub async fn generate_file(&self, src: &Path, rel: &Path) -> Result<(String, Vec<String>)> {
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
        context.insert("_test", "test");
        // Add context keys here when we have some.
        for (k, v) in &parsed.sections {
            section_tera.add_raw_template(k, v)?;
        }

        let mut final_context = tera::Context::new();
        for k in parsed.sections.keys() {
            let rendered = section_tera.render(k, &context)?;
            final_context.insert(k, &rendered);
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
        // By convention, for ids, we drop the "src" from the start of rel.
        let mut nearly_id: Vec<String> = PathBuf::from(rel)
            .iter()
            .skip(1)
            .map(|x| x.to_str().unwrap_or("").to_string())
            .collect();
        nearly_id.pop();

        // Where should we write the output?
        let mut desc_path: PathBuf = PathBuf::new();
        desc_path.push(&self.target_dir);
        for p in &nearly_id {
            desc_path.push(&p);
        }
        desc_path.push(format!("{page_title}.md"));

        // Where do we tell mkdocs the file is?
        let mut mkdocs_path = PathBuf::new();
        if let Some(ref v) = self.id_prefix {
            mkdocs_path.push(v);
        }
        for p in &nearly_id {
            mkdocs_path.push(&p);
        }
        mkdocs_path.push(format!("{page_title}.md"));

        // What is the id?
        let mut id_path = PathBuf::new();
        if let Some(ref v) = self.id_prefix {
            id_path.push(v);
        }
        for p in &nearly_id {
            id_path.push(&p);
        }
        id_path.push(format!("{page_title}"));

        // That is also the mkdocs id of this file.
        let prefixed_id = zqutils::utils::string_from_path(&id_path)?;
        final_context.insert("_id", &prefixed_id);
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

        Ok((mkdocs_filename, id_components))
    }
}
