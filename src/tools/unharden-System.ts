/**
 * Unhardens the system by removing all hardening measures.
 * This function is used to remove an existing hardening system for nessus scans.
 */

import { NodeSSH } from 'node-ssh';

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
    return output === 'true';
  } catch (err) {
    throw new Error(`Connection or command failed: ${(err as Error).message}`);
  } finally {
    ssh.dispose();
  }
}

