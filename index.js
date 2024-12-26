import axios from "axios";
import { program } from "commander";

program
  .name("VirusTotal API")
  .description("Example: node index.js --apikey xxxxxx --ip 185.220.101.149")
  .requiredOption("-k, --apikey <key>", "VirusTotal API Key")
  .option("-a, --hash <SHA256|SHA1|MD5>", "Get file report by hash value")
  .option("-i, --ip <ip_address>", "Get IP address report")
  .option("-d, --domain <domain>", "Get domain report")
  .helpOption("-h, --help", "Display help")
  .showHelpAfterError();

program.parse(process.argv);

if (process.argv.length <= 2) {
  program.help();
}

async function apiRequest(apikey, path, data) {
  const BASE_URL = "https://www.virustotal.com/api/v3";
  try {
    const url = `${BASE_URL}/${path}/${data}`;
    const headers = { "x-apikey": apikey, accept: "application/json" };
    const response = await axios.get(url, { headers });
    console.log(
      `Result For: ${hash}: ${JSON.stringify(response.data, null, 4)}`
    );
  } catch (error) {
    console.error(error.response?.data || error);
  }
}

async function scanHash(apikey, hash) {
  return await apiRequest(apikey, "files", hash);
}

async function scanUrl(apikey, domain) {
  return await apiRequest(apikey, "domains", domain);
}

async function ipAddressReport(apikey, ip) {
  return await apiRequest(apikey, "ip_addresses", ip);
}

async function handleArg(apikey, hash, ip, domain) {
  const argsCount = [hash, ip, domain].filter(Boolean).length;

  if (argsCount > 1) {
    const msg =
      "[Error] Provide the api key with only one of the options (-a, -i)";
    console.error(msg);
    process.exit(1);
  }

  if (hash) return scanHash(apikey, hash);
  else if (ip) return ipAddressReport(apikey, ip);
  else if (domain) return scanUrl(apikey, domain);
  else return;
}

const { apikey, hash, ip, domain } = program.opts();

handleArg(apikey, hash, ip, domain);

// TBD