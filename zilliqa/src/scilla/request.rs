use anyhow::Result;
use jsonrpsee::core::params::ObjectParams;
use serde_json::Value;

use crate::transaction::{ScillaGas, ZilAmount};

#[derive(PartialEq, Debug)]
pub(super) enum ScillaServerRequestType {
    Check,
    Run,
}

#[derive(Debug)]
pub(super) struct ScillaServerRequestBuilder {
    request_type: ScillaServerRequestType,
    init: Option<String>,
    message: Option<String>,
    lib_dirs: Option<Vec<String>>,
    code: Option<String>,
    gas_limit: Option<String>,
    ipc_address: Option<String>,
    balance: Option<String>,
    is_library: bool,
    contract_info: bool,
    json_errors: bool,
    pplit: bool,
}

impl ScillaServerRequestBuilder {
    pub(super) fn new(request_type: ScillaServerRequestType) -> Self {
        Self {
            request_type,
            init: None,
            lib_dirs: None,
            code: None,
            message: None,
            gas_limit: None,
            balance: None,
            ipc_address: None,
            is_library: false,
            contract_info: false,
            json_errors: false,
            pplit: false,
        }
    }

    pub(super) fn init(mut self, init: String) -> Self {
        self.init = Some(init);
        self
    }

    pub(super) fn message(mut self, msg: &Value) -> Result<Self> {
        self.message = Some(serde_json::to_string(&msg)?);
        Ok(self)
    }

    pub(super) fn lib_dirs(mut self, lib_dirs: Vec<String>) -> Self {
        self.lib_dirs = Some(lib_dirs);
        self
    }

    pub(super) fn code(mut self, code: String) -> Self {
        self.code = Some(code);
        self
    }

    pub(super) fn ipc_address(mut self, ipc_address: String) -> Self {
        self.ipc_address = Some(ipc_address);
        self
    }

    pub(super) fn gas_limit(mut self, gas_limit: ScillaGas) -> Self {
        self.gas_limit = Some(gas_limit.to_string());
        self
    }

    pub(super) fn balance(mut self, balance: ZilAmount) -> Self {
        self.balance = Some(balance.to_string());
        self
    }

    pub(super) fn pplit(mut self, pplit: bool) -> Self {
        self.pplit = pplit;
        self
    }

    #[allow(clippy::wrong_self_convention)]
    pub(super) fn is_library(mut self, is_library: bool) -> Self {
        self.is_library = is_library;
        self
    }

    pub(super) fn contract_info(mut self, contract_info: bool) -> Self {
        self.contract_info = contract_info;
        self
    }

    pub(super) fn json_errors(mut self, json_errors: bool) -> Self {
        self.json_errors = json_errors;
        self
    }

    pub(super) fn build(self) -> Result<(&'static str, ObjectParams)> {
        let mut args = vec![];

        if let Some(init) = self.init {
            args.extend(["-init".to_owned(), init]);
        }

        if let Some(lib_dirs) = self.lib_dirs {
            args.extend(["-libdir".to_owned(), lib_dirs.join(":")]);
        }

        if let Some(ipc_address) = self.ipc_address {
            args.extend(["-ipcaddress".to_owned(), ipc_address])
        }

        if let Some(balance) = self.balance {
            args.extend(["-balance".to_owned(), balance]);
        }

        if let Some(message) = self.message {
            args.extend(["-imessage".to_owned(), message]);
        }

        if let Some(code) = self.code {
            if self.request_type == ScillaServerRequestType::Run {
                args.push("-i".to_owned());
            }
            args.push(code);
        }

        if let Some(gas_limit) = self.gas_limit {
            args.extend(vec!["-gaslimit".to_owned(), gas_limit.to_string()]);
        }

        if self.contract_info {
            args.push("-contractinfo".to_owned());
        }

        if self.json_errors {
            args.push("-jsonerrors".to_owned());
        }

        if self.is_library {
            args.push("-islibrary".to_owned());
            if self.request_type == ScillaServerRequestType::Run {
                args.push("true".to_owned());
            }
        }
        if self.pplit {
            args.extend(vec!["-pplit".to_owned(), "true".to_owned()]);
        }

        let request_type = match self.request_type {
            ScillaServerRequestType::Check => "check",
            ScillaServerRequestType::Run => "run",
        };

        let mut params = ObjectParams::new();
        params.insert("argv", args)?;

        Ok((request_type, params))
    }
}
