use crate::utils;
use anyhow::{anyhow, Result};
use colored::{Color, Colorize};
use libc;
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

/// Wrapper in case we later want to add stuff to it.
pub struct ChildProcess {
    pub child: Child,
}

// Reap on termination and return the id.
pub fn reap_on_termination(child: ChildProcess) -> Result<u32> {
    let id = child
        .child
        .id()
        .ok_or(anyhow!("Could not get child process id"))?;
    tokio::spawn(async move { child.child.wait_with_output().await });
    Ok(id)
}

pub struct CommandOutput {
    pub success: bool,
    pub status_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    pub fn fake(ok: bool) -> Self {
        Self {
            status_code: if ok { 0 } else { 1 },
            success: ok,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    pub fn success_or(&self, err: &str) -> Result<&Self> {
        if self.success {
            Ok(self)
        } else {
            // TODO - make this part of the error!
            self.print();
            Err(anyhow!("{0}", err))
        }
    }
    pub fn print(&self) {
        let output = &utils::string_or_empty_from_u8(&self.stdout);
        let error = &utils::string_or_empty_from_u8(&self.stderr);
        println!("---------\n{output}\n{error}\n---------\n");
    }
    pub fn sanitise_stdout(&self) -> Result<String> {
        self.sanitise_to_string(&self.stdout)
    }

    pub fn sanitise_stderr(&self) -> Result<String> {
        self.sanitise_to_string(&self.stderr)
    }

    pub fn sanitise_to_string(&self, input: &[u8]) -> Result<String> {
        let result = utils::string_or_empty_from_u8(input);
        Ok(result.trim().to_string())
    }
}

#[derive(Debug, Clone)]
pub struct CommandBuilder {
    cmd: Option<String>,
    args: Option<Vec<String>>,
    env: Option<HashMap<String, String>>,
    cwd: Option<String>,
    throw_on_failure: bool,
    display_command: bool,
    display_str: Option<String>,
    /// Should this command create a new session?.
    create_new_session: bool,
    /// Should we log the output, or return it?
    logged: bool,
    color: Option<Color>,
}

impl Default for CommandBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Second cut at running commands, because the option list was getting waay too long.
impl CommandBuilder {
    pub fn new() -> Self {
        CommandBuilder {
            cmd: None,
            args: None,
            env: None,
            cwd: None,
            throw_on_failure: true,
            display_command: true,
            display_str: None,
            create_new_session: false,
            logged: false,
            color: None,
        }
    }

    pub fn log_output(&mut self) -> &mut Self {
        self.logged = true;
        self
    }

    pub fn display(&mut self, what: &str) -> &mut Self {
        self.display_str = Some(what.to_string());
        self
    }

    pub fn color(&mut self, what: Color) -> &mut Self {
        self.color = Some(what);
        self
    }

    pub fn ignore_failures(&mut self) -> &mut Self {
        self.throw_on_failure = false;
        self
    }

    pub fn throw_on_failure(&mut self) -> &mut Self {
        self.throw_on_failure = true;
        self
    }

    pub fn set_throw_on_failure(&mut self, throw_on_failure: bool) -> &mut Self {
        self.throw_on_failure = throw_on_failure;
        self
    }

    pub fn silent(&mut self) -> &mut Self {
        self.display_command = false;
        self
    }

    pub fn create_new_session(&mut self) -> &mut Self {
        self.create_new_session = true;
        self
    }

    pub fn cmd(&mut self, cmd: &str, args: &[&str]) -> &mut Self {
        self.cmd = Some(cmd.to_string());
        self.args = Some(args.iter().map(|x| x.to_string()).collect());
        self
    }

    pub fn more_args(&mut self, args: &[&str]) -> &mut Self {
        let converted_args: Vec<String> = args.iter().map(|x| x.to_string()).collect();
        match &mut self.args {
            None => self.args = Some(converted_args),
            Some(val) => val.extend(converted_args),
        };
        self
    }

    pub fn env_var(&mut self, name: &str, value: &str) -> &mut Self {
        if let Some(e) = &mut self.env {
            e.insert(name.to_string(), value.to_string());
        } else {
            let mut map = HashMap::<String, String>::new();
            map.insert(name.to_string(), value.to_string());
            self.env = Some(map);
        }
        self
    }

    pub fn env(&mut self, env: &HashMap<String, String>) -> &mut Self {
        self.env = Some(env.clone());
        self
    }

    pub fn cwd(&mut self, cwd: &str) -> &mut Self {
        self.cwd = Some(cwd.to_string());
        self
    }

    pub fn describe_command(&self) -> Result<String> {
        let cmd_name = self
            .cmd
            .as_ref()
            .ok_or(anyhow!("No command specified"))?
            .clone();
        let cwd_str = self.cwd.as_ref().map_or("", |x| x.as_str());
        let mut result = String::new();
        if let Some(val) = &self.display_str {
            result.push_str(&format!("[{cwd_str}]$ {val}"));
        } else {
            let space_args = if let Some(args) = &self.args {
                args.join(" ")
            } else {
                "".to_string()
            };
            result.push_str(&format!("[{cwd_str}]$ {0} {space_args}", &cmd_name));
        }
        Ok(result)
    }
    /// Common bits of starting a new process.
    fn make_command(&self) -> Result<Command> {
        let cmd_name = self
            .cmd
            .as_ref()
            .ok_or(anyhow!("No command specified"))?
            .clone();
        let mut cmd = Command::new(cmd_name);
        if self.display_command {
            println!("{0}", self.describe_command()?)
        }
        if let Some(args) = &self.args {
            cmd.args(args);
        }
        if let Some(env) = &self.env {
            cmd.envs(env);
        }
        if let Some(cwd) = &self.cwd {
            cmd.current_dir(cwd);
        }
        if self.create_new_session {
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
        }
        Ok(cmd)
    }

    pub async fn spawn(&self) -> Result<ChildProcess> {
        let mut cmd = self.make_command()?;
        let child = cmd.spawn()?;
        Ok(ChildProcess { child })
    }

    pub async fn spawn_logged(&self) -> Result<ChildProcess> {
        self.spawn_logged_with_input(None).await
    }

    pub async fn spawn_logged_with_input(&self, input: Option<&str>) -> Result<ChildProcess> {
        let mut cmd = self.make_command()?;
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        if input.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        let mut child = cmd.spawn()?;
        let output = child
            .stdout
            .take()
            .ok_or(anyhow!("Cannot get process output"))?;
        let err = child
            .stderr
            .take()
            .ok_or(anyhow!("Cannot get process error"))?;
        let current_color = self.color;
        tokio::spawn(async move {
            let mut out_reader = BufReader::new(output).lines();
            while let Some(line) = out_reader.next_line().await.unwrap_or(None) {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let mut real_line = String::new();
                    real_line.push('\r');
                    real_line.push('\n');
                    real_line.push('>');
                    real_line.push_str(trimmed);
                    if let Some(color) = current_color {
                        print!("{}", real_line.color(color));
                    } else {
                        let _ = tokio::io::stdout().write_all(real_line.as_bytes()).await;
                    }
                }
            }
        });
        tokio::spawn(async move {
            let mut err_reader = BufReader::new(err).lines();
            while let Some(line) = err_reader.next_line().await.unwrap_or(None) {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let mut real_line = String::new();
                    real_line.push('\r');
                    real_line.push('\n');
                    real_line.push('!');
                    real_line.push_str(trimmed);
                    if let Some(color) = current_color {
                        print!("{}", real_line.color(color));
                    } else {
                        let _ = tokio::io::stdout().write_all(real_line.as_bytes()).await;
                    }
                }
            }
        });
        if let Some(val) = input {
            let mut input = child
                .stdin
                .take()
                .ok_or(anyhow!("Cannot get process input"))?;
            let val_copy = val.to_string();
            tokio::spawn(async move {
                if let Err(errval) = input.write_all(val_copy.as_bytes()).await {
                    println!("Couldn't write stdin - {0:?}", errval);
                }
            });
        }

        Ok(ChildProcess { child })
    }

    pub async fn run_logged(&self) -> Result<CommandOutput> {
        let mut child = self.spawn_logged().await?;
        let result = child.child.wait().await?;
        let code = result.code().unwrap_or(-1);
        if self.throw_on_failure && !result.success() {
            return Err(anyhow!("Command failed  - {0}", code));
        }
        Ok(CommandOutput {
            success: result.success(),
            status_code: code,
            stdout: vec![],
            stderr: vec![],
        })
    }

    pub async fn run(&self) -> Result<CommandOutput> {
        if self.logged {
            self.run_logged().await
        } else {
            self.run_for_output().await
        }
    }

    pub async fn run_logged_with_input(&self, indata: &str) -> Result<()> {
        let mut proc = self.spawn_logged_with_input(Some(indata)).await?;
        proc.child.wait().await?;
        Ok(())
    }

    pub async fn run_for_output(&self) -> Result<CommandOutput> {
        let mut cmd = self.make_command()?;
        let out = cmd.output().await?;
        let result_code = if let Some(val) = out.status.code() {
            val
        } else {
            -1
        };
        if self.throw_on_failure && !out.status.success() {
            let output = &utils::string_or_empty_from_u8(&out.stdout);
            let error = &utils::string_or_empty_from_u8(&out.stderr);
            return Err(anyhow!("Command failed - {result_code}\n{output}\n{error}"));
        }
        Ok(CommandOutput {
            success: out.status.success(),
            status_code: result_code,
            stdout: out.stdout,
            stderr: out.stderr,
        })
    }
}

#[derive(Debug)]
pub struct BackgroundCommand {
    pub running: Child,
}

impl BackgroundCommand {
    pub fn new(cmd: &str, args: Vec<&str>, env: Option<&HashMap<String, String>>) -> Result<Self> {
        let result: Child;
        if let Some(env_tbl) = env {
            result = Command::new(cmd).args(args).envs(env_tbl).spawn()?;
        } else {
            result = Command::new(cmd).args(args).spawn()?;
        }
        Ok(BackgroundCommand { running: result })
    }
}
