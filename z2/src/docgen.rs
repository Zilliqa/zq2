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
        let key_prefix_components = self
            .index_file_key_prefix
            .split("/")
            .map(|x| x.to_string())
            .collect::<Vec<_>>();

        // We now need to zap the prefix ..
        if !key_prefix_components.is_empty() {
            let mut insert_at: Option<&mut serde_yaml::Value> = Some(&mut contents_map);
            let mut found = true;
            for component in key_prefix_components
                .iter()
                .take(key_prefix_components.len() - 1)
            {
                if let Some(serde_yaml::Value::Mapping(ref mut map)) = insert_at {
                    if map.contains_key(component) {
                        insert_at = Some(map.get_mut(component).ok_or(anyhow!("Foo"))?);
                    } else {
                        found = false;
                        insert_at = None;
                        break;
                    }
                } else {
                    found = false;
                    insert_at = None;
                    break;
                }
            }
            if found {
                let Some(serde_yaml::Value::Mapping(ref mut map)) = insert_at else {
                    return Err(anyhow!("Internal error #5"));
                };
                map.remove(
                    key_prefix_components
                        .last()
                        .ok_or(anyhow!("Empty key prefix"))?,
                );
            }
        }

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
                        let (desc_path, prefixed_id) =
                            self.generate_file(&path_entry.abs, &path_entry.rel).await?;
                        let mut the_iter = key_prefix_components.iter().chain(desc_path.iter());
                        let key = the_iter.next_back().ok_or(anyhow!(
                            "API file {0:?} has empty description path!",
                            &path_entry.abs
                        ))?;
                        let mut insert_at: &mut serde_yaml::Value = &mut contents_map;
                        for component in the_iter {
                            let serde_yaml::Value::Mapping(ref mut map) = insert_at else {
                                return Err(anyhow!("Internal error!"));
                            };
                            if !map.contains_key(component) {
                                map.insert(
                                    serde_yaml::Value::String(component.to_string()),
                                    serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
                                );
                            }
                            insert_at =
                                map.get_mut(component).ok_or(anyhow!("Internal error 3"))?;
                        }
                        let serde_yaml::Value::Mapping(ref mut map) = insert_at else {
                            return Err(anyhow!("Internal error 2"));
                        };
                        map.insert(
                            serde_yaml::Value::String(key.to_string()),
                            serde_yaml::Value::String(prefixed_id),
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
    pub async fn generate_file(&self, src: &Path, rel: &Path) -> Result<(Vec<String>, String)> {
        // First, let's read the input
        let src_contents = fs::read_to_string(src).await?;
        let src_file = zqutils::utils::string_from_path(src)?;
        // By convention, for ids, we drop the "src" from the start of rel.
        let id: PathBuf = PathBuf::from(rel).iter().skip(1).collect();
        let rel_file = zqutils::utils::string_from_path(&id)?;
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
        let mut desc_path: Vec<String> = Vec::new();
        let prefixed_id = if let Some(ref v) = self.id_prefix {
            desc_path.push(v.to_string());
            format!("{0}{1}", v, &rel_file)
        } else {
            rel_file.to_string()
        };
        desc_path.append(
            &mut id
                .clone()
                .iter()
                .map(|x| x.to_str().map_or(String::new(), |x| x.to_string()))
                .collect::<Vec<String>>(),
        );
        final_context.insert("_id", &prefixed_id);
        let final_page = page_tera
            .render("api", &final_context)
            .context(format!("Whilst rendering {0:?}", src_file))?;

        // OK. Now we have some data, let's write it.
        self.write_file(&final_page, &id).await?;

        // Now, desc_path's last component should be the page title.
        let Some(page_title) = parsed.sections.get("title") else {
            return Err(anyhow!(
                "Page {0} does not contain a title section - needed to build the mkdocs index",
                src_file
            ));
        };
        let out_path = desc_path
            .iter()
            .take(desc_path.len() - 1)
            .chain(std::iter::once(page_title))
            .map(|x| x.to_string())
            .collect::<Vec<_>>();

        Ok((out_path, prefixed_id))
    }
}
