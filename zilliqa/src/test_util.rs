use std::{
    collections::HashMap,
    fs::DirBuilder,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use alloy::{json_abi::JsonAbi, primitives::Bytes};
use foundry_compilers::{
    artifacts::{EvmVersion, Optimizer, Settings, SolcInput, Source},
    solc::{Solc, SolcLanguage},
};
use rand::{Rng, SeedableRng, distributions::Alphanumeric, rngs::StdRng};
use serde::Deserialize;

pub fn compile_contract(path: &str, contract: &str) -> (JsonAbi, Bytes) {
    let path: PathBuf = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path).into();

    let solc_input = SolcInput::new(
        SolcLanguage::Solidity,
        Source::read_all_files(vec![path.clone()]).unwrap(),
        Settings {
            remappings: vec![
                format!(
                    "@openzeppelin/contracts={}/../vendor/openzeppelin-contracts/contracts",
                    env!("CARGO_MANIFEST_DIR")
                )
                .parse()
                .unwrap(),
            ],
            optimizer: Optimizer {
                enabled: Some(true),
                runs: Some(2usize.pow(32) - 1),
                details: None,
            },
            ..Default::default()
        },
    )
    .evm_version(EvmVersion::Shanghai); // ensure compatible with EVM version in exec.rs

    let mut solc = Solc::find_or_install(&semver::Version::new(0, 8, 28)).unwrap();
    solc.allow_paths
        .insert(PathBuf::from("../vendor/openzeppelin-contracts"));
    let mut output = solc.compile_exact(&solc_input).unwrap();

    if output.has_error() {
        for error in output.errors {
            eprintln!("{error}");
        }
        panic!("failed to compile contract");
    }

    let contract = output
        .contracts
        .remove(&path)
        .unwrap()
        .remove(contract)
        .unwrap();
    let evm = contract.evm.unwrap();

    (
        contract.abi.unwrap(),
        evm.bytecode.unwrap().into_bytes().unwrap(),
    )
}

pub struct ScillaServer {
    pub addr: String,
    pub temp_dir: String,
    container_name: String,
    child: Child,
}

impl Default for ScillaServer {
    fn default() -> ScillaServer {
        let mut container_name = "scilla-server-".to_owned();
        let rng = StdRng::from_entropy();
        container_name.extend(rng.sample_iter(&Alphanumeric).map(char::from).take(8));

        let temp_dir = std::env::var_os("ZQ_TEST_TEMP_DIR")
            .map(|s| s.into_string())
            .transpose()
            .unwrap()
            .unwrap_or_else(|| "/tmp".to_owned());

        DirBuilder::new()
            .recursive(true)
            .mode(0o777)
            .create(format!("{temp_dir}/scilla_ext_libs"))
            .unwrap();
        DirBuilder::new()
            .recursive(true)
            .mode(0o777)
            .create(format!("{temp_dir}/scilla-sockets"))
            .unwrap();

        let child = Command::new("docker")
            .arg("run")
            .arg("--platform")
            .arg("linux/amd64")
            .arg("--name")
            .arg(&container_name)
            // Let Docker auto-assign a free port on the host. The scilla-server listens on port 3000.
            .arg("--publish")
            .arg("3000/tcp")
            .arg("--init")
            .arg("--rm")
            .arg("--mount")
            .arg(format!(
                "type=bind,src={temp_dir}/scilla_ext_libs,dst={temp_dir}/scilla_ext_libs"
            ))
            .arg("--mount")
            .arg(format!(
                "type=bind,src={temp_dir}/scilla-sockets,dst={temp_dir}/scilla-sockets"
            ))
            .arg(
                "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/scilla:abdb24b1",
            )
            .arg("/scilla/0/bin/scilla-server-http")
            .spawn()
            .unwrap();

        // Wait for the container to be running.
        for i in 0.. {
            let status_output = Command::new("docker")
                .arg("inspect")
                .arg("-f")
                .arg("{{.State.Status}}")
                .arg(&container_name)
                .output()
                .unwrap();
            let status = String::from_utf8(status_output.stdout).unwrap();
            if status.trim() == "running" {
                break;
            }
            if i >= 1200 {
                panic!("container is still not running");
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Find the port that Docker selected on the host.
        let inspect = Command::new("docker")
            .arg("inspect")
            .arg("--format")
            .arg("{{json .NetworkSettings.Ports}}")
            .arg(&container_name)
            .output()
            .unwrap();
        #[derive(Deserialize, Copy, Clone)]
        struct Addr {
            #[serde(rename = "HostIp")]
            ip: IpAddr,
            #[serde(rename = "HostPort", with = "crate::serde_util::num_as_str")]
            port: u16,
        }
        let inspect: HashMap<String, Vec<Addr>> = serde_json::from_slice(&inspect.stdout).unwrap();
        let addrs: Vec<SocketAddr> = inspect["3000/tcp"]
            .iter()
            .copied()
            .filter(|a| a.ip.is_ipv4())
            .map(|a| (IpAddr::V4(Ipv4Addr::LOCALHOST), a.port).into())
            .collect();
        let addr = *addrs.first().unwrap();

        ScillaServer {
            addr: format!("http://{addr}"),
            temp_dir,
            container_name,
            child,
        }
    }
}

impl Drop for ScillaServer {
    fn drop(&mut self) {
        let mut stop_child = Command::new("docker")
            .arg("stop")
            .arg("--signal")
            .arg("SIGKILL")
            .arg(&self.container_name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _ = self.child.wait();
        let _ = stop_child.wait();
    }
}
