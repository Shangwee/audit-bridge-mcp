/**
 * Unhardens the system by removing all hardening measures.
 * This function is used to remove an existing hardening system for nessus scans.
 */

import { NodeSSH } from 'node-ssh';
import dayjs from 'dayjs';

const ssh = new NodeSSH();

/**
 * Manual check guides for system unhardening.
 */
const manualCheckGuides: Record<"local" | "services" | "network", string> = {
  local: `[Local Group Policy Check Guide]
  -------------------------------------------------------------------------------------------------------------
  Remember to check that these group policies are set properly to ensure that your nessus results are accurate
  -------------------------------------------------------------------------------------------------------------
  To start, Enter "Edit Group Policy" to access the group policy window (gpedit.msc)

  [Path] User Configuration/Administrative/Templates/System
  [Policy] Prevent Access to registry editing tools
  [Security Settings] Disabled

  [Path] Computer Configuration/Windows Settings/Security Settings/Local Policies/User Rights Assignment/Deny access to this computer from the network
  [Policy] Deny access to this computer from the network
  [Security Settings] Ensure the account used is not in the list
  [Futher information] If the account that is provided as credentials is in this list, Nessus will not work properly

  [Path] Computer Configuration/Windows Settings/Security Settings/Local Policies/User Rights Assignment/Access this computer from the network
  [Policy] Access this computer from the network
  [Security Settings] Ensure the account used is added in the list
  [Futher information] If the account that is provided as credentials is not in this list, Nessus will not work properly

  [Path] Computer Configuration/Windows Settings/Security Settings/Local Policies/Security Options
  [Policy] Microsoft network server: Server SPN target name validation level
  [Security Settings] Off

  [Path] Computer Configuration/Windows Settings/Security Settings/Windows Firewall with Advanced Security/Windows Firewall with Advanced Security
  [Security Settings] Disabled all Firewall Or Add new rule to allow incoming and outgoing traffic from Tester to Host`,
  
  services: `[Services]
  -------------------------------------------------------------------------------------------------------------
  If the following options are different, please take note of the configurations and amend them back to the original
  settings after the audit.
  -------------------------------------------------------------------------------------------------------------

  Using services.msc, Ensure that "RemoteRegistry" is set to Automatic.

  [Special Cases to take note]
  If the following cases exists, please ensure they are set to Automatic as well.
  Netlogon - Only if host is in a domain
  Server - For Windows10 with Nessus Authentication Error
  Security Account Manager - For Windows 10 with Nessus authentication Error`,

  network: `[Network Adapter]
  ------------------------------------------------------------------------------------------------------------------
  If the following options are different, please take note of the configurations and amend them back to the original
  settings.
  ------------------------------------------------------------------------------------------------------------------
  1.Right Click on the Local Area Connection used and click Properties
  2.Ensure the following are ticked:
  - QoS Packet Schedulers
  - Internet Protocol Version 4 (TCP/IPV4)
  - Clients for Microsoft Networks
  - File and printer sharing for Microsoft Networks`
};

/**
 * Logs a command execution and runs it via SSH.
 * @param logFile - The file to log the command output.
 * @param label - A label for the command being executed.
 * @param rawCommand - The raw command to execute.
 * @returns The result of the SSH command execution.
 */
const logAndRun = async (logFile:string, label: string, rawCommand: string) => {
    const escapedCmd = rawCommand.replace(/"/g, '`"'); // Escape quotes in cmd
    const powershellCommand = `
      Add-Content -Path '${logFile}' '[${label}]';
      Add-Content -Path '${logFile}' 'Command: ${rawCommand.replace(/'/g, "''")}';
      ${escapedCmd} | Out-File -Append -FilePath '${logFile}' -Encoding UTF8;
    `.trim();

    const encoded = powershellCommand.replace(/\n/g, " ");
    return ssh.execCommand(`powershell -NoProfile -Command "${encoded}"`);
};

/**
 * Returns a Nessus manual check guide string based on type.
 * @param type - "local", "services", or "network"
 * @returns A formatted Nessus manual check guide
 */
export const listManualChecks = async (
  type: "local" | "services" | "network"
): Promise<string> => {
  return manualCheckGuides[type];
};

/**
 * Checks if a given user has administrator rights via SSH on a remote Windows machine.
 * @param host IP or hostname of the remote machine.
 * @param username SSH username.
 * @param password SSH password.
 * @returns Promise that resolves to true if the user has admin rights, false otherwise.
 */
export async function checkAdminRightsViaSSH(
  host: string,
  username: string,
  password: string
): Promise<boolean> {
  try {
    await ssh.connect({
      host,
      username,
      password,
      tryKeyboard: true,
    });

    // PowerShell command to check if the user is in the Administrators group
    const result = await ssh.execCommand(
        'powershell -Command "$id=[System.Security.Principal.WindowsIdentity]::GetCurrent();$p=New-Object System.Security.Principal.WindowsPrincipal($id);$p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)"'
    );

    if (result.stderr) {
      throw new Error(`SSH Error: ${result.stderr}`);
    }

    const output = result.stdout.trim().toLowerCase();

    // exit from the remote session
    await ssh.execCommand(`powershell -Command "exit"`);

    return output === 'true';
  } catch (err) {
    throw new Error(`Connection or command failed: ${(err as Error).message}`);
  } finally {
    // Ensure the SSH connection is closed
    ssh.dispose();
  }
}

/**
 * Runs a remote audit setup on a Windows machine via SSH.
 * @param host - The IP address or hostname of the remote machine.
 * @param username - The SSH username to authenticate with.
 * @param password - The SSH password to authenticate with.
 * @returns A promise that resolves to the audit results.
 */
export async function runRemoteAuditSetup(
  host: string,
  username: string,
  password: string
): Promise<object> {
  const timestamp = dayjs().toISOString();
  const logDir = `C:\\AuditLogs\\${dayjs().format("YYYYMMDD")}`;
  const logFile = `${logDir}\\audit-log.txt`;

  const result: any = {
    host,
    timestamp,
    registry_exports: {},
    registry_values: {},
    services: {},
    firewall: {},
    network: {},
    notes: [],
    logDir: logDir,
    logFile: logFile,
  };

  const registryExportCmds = {
    Parameters: `reg export HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters ${logDir}\\Parameters.reg /y`,
    System: `reg export HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System ${logDir}\\System.reg /y`
  };

  const registryQueryCmds = {
    SMB1: `reg query "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v SMB1`,
    AutoShareWks: `reg query "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v AutoShareWks`,
    AutoShareServer: `reg query "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v AutoShareServer`,
    LocalAccountTokenFilterPolicy: `reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v LocalAccountTokenFilterPolicy`
  };

  try {
    await ssh.connect({ host, username, password });

    await ssh.execCommand(`powershell -Command "New-Item -ItemType Directory -Path '${logDir}' -Force"`);

    await logAndRun(logFile, "Audit Start", `Get-Date`);

    // Registry exports
    for (const [key, cmd] of Object.entries(registryExportCmds)) {
      await logAndRun(logFile, `Exporting ${key}`, cmd);
      result.registry_exports[key] = `${logDir}\\${key}.reg`;
    }

    // Registry queries
    for (const [key, regQuery] of Object.entries(registryQueryCmds)) {
      const queryResult = await ssh.execCommand(`powershell -Command "${regQuery}"`);
      await logAndRun(logFile, `Query ${key}`, regQuery);

      if (
        queryResult.stderr.includes("unable to find") ||
        queryResult.stdout.includes("ERROR")
      ) {
        result.registry_values[key] = "not found";
      } else {
        const match = queryResult.stdout.match(/REG_DWORD\s+0x([0-9a-fA-F]+)/);
        result.registry_values[key] = match
          ? parseInt(match[1], 16).toString()
          : "unknown";
      }
    }

    // Symantec service
    const sepStatus = await ssh.execCommand(`powershell -Command "sc query SepMasterService"`);
    await logAndRun(logFile, "Symantec Service Check", "sc query SepMasterService");
    const state = sepStatus.stdout.match(/STATE\s+:\s+\d+\s+(\w+)/);
    result.services["SepMasterService"] = state ? state[1] : "Not found";

    // Firewall
    const fwOutput = await ssh.execCommand(`netsh advfirewall show allprofiles state`);
    await logAndRun(logFile, "Firewall Profiles", "netsh advfirewall show allprofiles state");

    const profileStates = {
      DomainProfile: "unknown",
      PrivateProfile: "unknown",
      PublicProfile: "unknown"
    };

    const lines = fwOutput.stdout.split(/\r?\n/);
    let currentProfile: keyof typeof profileStates | null = null;

    for (const line of lines) {
      if (line.includes("Domain Profile Settings")) currentProfile = "DomainProfile";
      else if (line.includes("Private Profile Settings")) currentProfile = "PrivateProfile";
      else if (line.includes("Public Profile Settings")) currentProfile = "PublicProfile";
      else if (/^\s*State\s*:?/i.test(line) && currentProfile) {
        const match = line.match(/State\s*:?\s*(\w+)/i);
        if (match) profileStates[currentProfile] = match[1].toUpperCase();
        currentProfile = null;
      }
    }

    result.firewall = profileStates;

    // IP address
    const ipCmd = `(Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -notlike '169.*' }).IPAddress`;
    await logAndRun(logFile, "IP Address", ipCmd);
    const ipOut = await ssh.execCommand(`powershell -Command "${ipCmd}"`);
    result.network.IPv4Addresses = ipOut.stdout.trim().split(/\r?\n/).filter(Boolean);

    result.notes.push(
      "Ensure the Auditor checks the real-time state of Symantec",
      "Verify firewall rules manually if unexpected results occur"
    );

    // exit from the remote session
    await ssh.execCommand(`powershell -Command "exit"`);

    return result;
  } catch (err) {
    return {
      host,
      timestamp,
      error: `Audit failed: ${(err as Error).message}`
    };
  } finally {
    ssh.dispose();
  }
}

/**
 * check all registry keys that are required for nessus to work properly.
 * @param host - The IP address or hostname of the remote machine.
 * @param username - The SSH username to authenticate with.
 * @param password - The SSH password to authenticate with.
 * @returns A promise that resolves to the audit results.
 */
export async function checkRegistryKeys(
  host: string,
  username: string,
  password: string,
){
  const logFile = `C:\\AuditLogs\\${dayjs().format("YYYYMMDD")}\\audit-log.txt`;

 const registryQueryCmds = {
    SMB1: `reg query "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v SMB1`,
    AutoShareWks: `reg query "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v AutoShareWks`,
    AutoShareServer: `reg query "HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v AutoShareServer`,
    LocalAccountTokenFilterPolicy: `reg query "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v LocalAccountTokenFilterPolicy`
  };

  const results: any = {
    host,
    registry_values: {},
    logFile: logFile,
  };

  try {
    await ssh.connect({ host, username, password });

    await logAndRun(logFile, "Check for registry keys", `Get-Date`);

    // Registry queries
    for (const [key, regQuery] of Object.entries(registryQueryCmds)) {
      const queryResult = await ssh.execCommand(`powershell -Command "${regQuery}"`);
      await logAndRun(logFile, `Query ${key}`, regQuery);

      if (
        queryResult.stderr.includes("unable to find") ||
        queryResult.stdout.includes("ERROR")
      ) {
        results.registry_values[key] = "not found";
      } else {
        const match = queryResult.stdout.match(/REG_DWORD\s+0x([0-9a-fA-F]+)/);
        results.registry_values[key] = match
          ? parseInt(match[1], 16).toString()
          : "unknown";
      }
    }

    await logAndRun(logFile, "Check for registry keys complete", `Get-Date`);

    // exit from the remote session
    await ssh.execCommand(`powershell -Command "exit"`);

    return results;
  } catch (err) {
    throw new Error(`Registry check failed: ${(err as Error).message}`);
  } finally {
    ssh.dispose();
  }
}

/**
 * Adds or updates registry keys on a remote Windows machine via SSH.
 * @param host - IP or hostname of the target machine.
 * @param username - SSH username with admin rights.
 * @param password - SSH password.
 * @returns A Promise with execution results.
 */
export async function addRegistryKeys(
  host: string,
  username: string,
  password: string
): Promise<object | string> {
  const timestamp = dayjs().toISOString();
  const logDir = `C:\\AuditLogs\\${dayjs().format("YYYYMMDD")}`;
  const logFile = `${logDir}\\audit-log.txt`;

  const results: any = {
    host,
    timestamp,
    logDir: logDir,
    logFile: logFile,
    output: "",
  };

  try {
    await ssh.connect({ host, username, password });

    const addRegistryKeysBat = `C:\\tools\\add-registry-keys.bat`;

    // Run the .bat file from C:\tools
    const result = await ssh.execCommand(
      `cmd.exe /c  ${addRegistryKeysBat}`
    );

    await logAndRun(logFile, "Add Registry Keys", `cmd.exe /c  ${addRegistryKeysBat}`);

    if (result.stderr) {
      return `Error: ${result.stderr}`;
    }
  
    if (result.stdout) {
      results.output = result.stdout.trim();
    }

    // exit from the remote session
    await ssh.execCommand(`powershell -Command "exit"`);
    
    return results;
  } catch (err) {
    return `SSH execution failed: ${(err as Error).message}`;
  } finally {
    ssh.dispose();
  }
}

/**
 * Delete all registry keys added
 * @param host - The IP address or hostname of the remote machine.
 * @param username - The SSH username to authenticate with.
 * @param password - The SSH password to authenticate with.
 * @returns A promise that resolves to the audit results.
 */
export async function deleteRegistryKeys(
  host: string,
  username: string,
  password: string
): Promise<object | string> {
  const timestamp = dayjs().toISOString();
  const logDir = `C:\\AuditLogs\\${dayjs().format("YYYYMMDD")}`;
  const logFile = `${logDir}\\audit-log.txt`;

  const results: any = {
    host,
    timestamp,
    logDir: logDir,
    logFile: logFile,
    output: "",
  };

  try {
    await ssh.connect({ host, username, password });

    const addRegistryKeysBat = `C:\\tools\\delete-registry-keys.bat`;

    // Run the .bat file from C:\tools
    const result = await ssh.execCommand(
      `cmd.exe /c  ${addRegistryKeysBat}`
    );

    await logAndRun(logFile, "Delete Registry Keys", `cmd.exe /c  ${addRegistryKeysBat}`);

    if (result.stderr) {
      return `Error: ${result.stderr}`;
    }
  
    if (result.stdout) {
      results.output = result.stdout.trim();
    }
    
    // exit from the remote session
    await ssh.execCommand(`powershell -Command "exit"`);

    return results;
  } catch (err) {
    return `SSH execution failed: ${(err as Error).message}`;
  } finally {
    ssh.dispose();
  }
}


