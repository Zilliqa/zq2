export * from "./Config";
export * from "./Account";
export * from "./Results";

import fs from "fs";
import path from "path";

export const getContractAbi = (contractName: string) => {
  try {
    const contractPath = path.resolve(process.cwd(), `artifacts/contracts/${contractName}.sol/${contractName}.json`);
    const file = fs.readFileSync(contractPath, "utf8");
    const json = JSON.parse(file);
    return json.abi;
  } catch (e) {
    console.log(`e`, e);
    return undefined;
  }
};
