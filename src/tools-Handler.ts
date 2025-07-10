import { z } from 'zod';

import {
    listManualChecks,
    checkAdminRightsViaSSH,
    runRemoteAuditSetup,
    checkRegistryKeys,
    addRegistryKeys,
    deleteRegistryKeys,
    remoteImportBatFile,
    revertRegistryKeys,
    checkFirewallStatus,
    enablefirewall,
    disablefirewall
} from './tools/commands.js';

import { handleUnhardeningError } from './utils/error-handling.js';

/**
 * Handler for listing manual checks based on the type specified.
 */

export const ManualCheckSchema = {
    name: 'list_manual_checks',
    description: 'List manual checks for system hardening based on the type specified.',
    inputSchema: {
        type: 'object',
        properties: {
            type: {
                type: 'string',
                enum: ['local', 'services', 'network'],
                description: 'The type of manual checks to list. Can be "local", "services", or "network".'
            }
        },
        required: ['type']
    }
}

export const handleListManualChecks = async (args: Record<string, unknown>) => {
    try {
        // Validate input arguments
        const validatedArgs = z.object({
            type: z.enum(['local', 'services', 'network'])
        }).parse(args);

        // get manual checks based on the type
        const manualChecks = await listManualChecks(validatedArgs.type);

        return {
            content: [
                {
                    type: 'text',
                    text: manualChecks
                }
            ]
        };
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
}

/* 
** This function is used to check if the user has admin rights on a remote system.
** It returns a boolean indicating whether the user has admin rights or not.
*/

export const AdminRightsSchema = {
    name: 'check_admin_rights_remote',
    description: 'Check if the user has admin rights on a remote system.',
    inputSchema: {
        type: 'object',
        properties: {
            host: {
                type: 'string',
                description: 'The hostname or IP address of the remote system.'
            },
            username: {
                type: 'string',
                description: 'The username to check for admin rights.'
            },
            password: {
                type: 'string',
                description: 'The password for the username, provided as plaintext.'
            }
        },
        required: ['host', 'username', 'password']
    }
}

export const handleCheckAdminRightsRemote = async (args: Record<string, unknown>) => {
    try {
        // Validate input arguments
        const validatedArgs = z.object({
            host: z.string(),
            username: z.string(),
            password: z.string()
        }).parse(args);

        // Check admin rights on the remote system
        const hasAdminRights = await checkAdminRightsViaSSH(
            validatedArgs.host,
            validatedArgs.username,
            validatedArgs.password
        );

        if (hasAdminRights === true) {
            return {
                content: [
                    {
                        type: 'text',
                        text: `User ${validatedArgs.username} has admin rights on ${validatedArgs.host}.`
                    }
                ]
            };

        } else if (hasAdminRights === false) {
            return {
                content: [
                    {
                        type: 'text',
                        text: `User ${validatedArgs.username} does not have admin rights on ${validatedArgs.host}.`
                    }
                ]
            };
        }
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
}

/**
 * Handler for running a remote audit setup on a Windows machine via SSH.
 */
export const RemoteAuditSetupSchema = {
    name: 'run_remote_audit_setup',
    description: 'Run a remote audit setup on a Windows machine via SSH.',
    inputSchema: {
        type: 'object',
        properties: {
            host: {
                type: 'string',
                description: 'The IP address or hostname of the remote machine.'
            },
            username: {
                type: 'string',
                description: 'The SSH username to authenticate with.'
            },
            password: {
                type: 'string',
                description: 'The SSH password to authenticate with.'
            }
        },
        required: ['host', 'username', 'password']
    }
};

export const handleRunRemoteAuditSetup = async (args: Record<string, unknown>) => {
    try {
        // Validate input arguments
        const validatedArgs = z.object({
            host: z.string(),
            username: z.string(),
            password: z.string()
        }).parse(args);

        // Run remote audit setup
        const auditResults = await runRemoteAuditSetup(
            validatedArgs.host,
            validatedArgs.username,
            validatedArgs.password
        );

        return {
            content: [
                {
                    type: 'text',
                    text: `Remote audit setup completed successfully on ${validatedArgs.host}.`
                },
                {
                    type: 'json',
                    data: auditResults
                }
            ]
        };
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
}

/**
 * handler for checking registry key settings on a remote Windows machine via SSH.
 */
export const RegistryKeySchema = {
    name: 'check_registry_key',
    description: 'Check all registry key settings.',
    inputSchema: {          
        type: 'object',
        properties: {
            host: {
                type: 'string',
                description: 'The IP address or hostname of the remote machine.'
            },
            username: {
                type: 'string',
                description: 'The SSH username to authenticate with.'
            },
            password: {
                type: 'string',
                description: 'The SSH password to authenticate with.'
            }
        },
        required: ['host', 'username', 'password']
    }
};

export const handleCheckRegistryKey = async (args: Record<string, unknown>) => {
    try {
        // Validate input arguments
        const validatedArgs = z.object({
            host: z.string(),
            username: z.string(),
            password: z.string(),
        }).parse(args);

        // Run registry key check
        const checkResults = await checkRegistryKeys(
            validatedArgs.host,
            validatedArgs.username,
            validatedArgs.password,
        );

        return {
            content: [
                {
                    type: 'text',
                    text: `Registry key check completed successfully on ${validatedArgs.host}.`
                },
                {
                    type: 'json',
                    data: checkResults
                }
            ]
        };
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
}

/**
 *  handler for importing a .bat file to a remote Windows machine via SSH.
 */
export const ImportBatFileSchema = {
    name: 'import_bat_file',
    description: 'Import bat files to a remote Windows machine via SSH.',
    inputSchema: {
        type: 'object',
        properties: {
            host: {
                type: 'string',
                description: 'The IP address or hostname of the remote machine.'
            },
            username: {
                type: 'string',
                description: 'The SSH username to authenticate with.'
            },
            password: {
                type: 'string',
                description: 'The SSH password to authenticate with.'
            }
        },
        required: ['host', 'username', 'password']
    }
};

export const handleImportBatFile = async (args: Record<string, unknown>) => {
    try {
        // Validate input arguments
        const validatedArgs = z.object({
            host: z.string(),
            username: z.string(),
            password: z.string(),
        }).parse(args);

        // Import .bat file to remote machine
        const importResults = await remoteImportBatFile(
            validatedArgs.host,
            validatedArgs.username,
            validatedArgs.password,
        );

        return {
            content: [
                {
                    type: 'text',
                    text: `Batch file imported successfully on ${validatedArgs.host}.`
                },
                {
                    type: 'json',
                    data: importResults
                }
            ]
        };
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
};

/**
 * Handler for adding registry keys on a remote Windows machine via SSH.
 */
export const AddRegistryKeysSchema = {
    name: 'add_registry_keys',
    description: 'Add registry keys on a remote Windows machine via SSH.',
    inputSchema: {
        type: 'object',
        properties: {
            host: {
                type: 'string',
                description: 'The IP address or hostname of the remote machine.'
            },
            username: {
                type: 'string',
                description: 'The SSH username to authenticate with.'
            },
            password: {
                type: 'string',
                description: 'The SSH password to authenticate with.'
            },
        },
        required: ['host', 'username', 'password']
    }
};

export const handleAddRegistryKeys = async (args: Record<string, unknown>) => {
    try {
         // Validate input arguments
        const validatedArgs = z.object({
            host: z.string(),
            username: z.string(),
            password: z.string(),
        }).parse(args);

        // Run registry key addition
        const addResults = await addRegistryKeys(
            validatedArgs.host,
            validatedArgs.username,
            validatedArgs.password,
        );

        return {
            content: [
                {
                    type: 'text',
                    text: `Registry keys added successfully on ${validatedArgs.host}.`
                },
                {
                    type: 'json',
                    data: addResults
                }
            ]
        };
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
};

/**
 * Handler for deleting registry keys on a remote Windows machine via SSH.
 */
export const DeleteRegistryKeysSchema = {
    name: 'delete_registry_keys',
    description: 'Delete registry keys on a remote Windows machine via SSH.',
    inputSchema: {
        type: 'object',
        properties: {
            host: {
                type: 'string',
                description: 'The IP address or hostname of the remote machine.'
            },
            username: {
                type: 'string',
                description: 'The SSH username to authenticate with.'
            },
            password: {
                type: 'string',
                description: 'The SSH password to authenticate with.'
            },
        },
        required: ['host', 'username', 'password']
    }
};

export const handleDeleteRegistryKeys = async (args: Record<string, unknown>) => {
    try {
        // Validate input arguments
        const validatedArgs = z.object({
            host: z.string(),
            username: z.string(),
            password: z.string(),
        }).parse(args);

        // Delete registry keys
        const deleteResults = await deleteRegistryKeys(
            validatedArgs.host,
            validatedArgs.username,
            validatedArgs.password,
        );

        return {
            content: [
                {
                    type: 'text',
                    text: `Registry keys deleted successfully on ${validatedArgs.host}.`
                },
                {
                    type: 'json',
                    data: deleteResults
                }
            ]
        };
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
};

/** 
 * Handlers for revert keys and import original keys
 */
export const RevertKeysSchema = {
    name: 'revert_keys',
    description: 'Delete all registry keys changes and revert to original settings on a remote Windows machine via SSH.',
    inputSchema: {
        type: 'object',
        properties: {
            host: {
                type: 'string',
                description: 'The IP address or hostname of the remote machine.'
            },
            username: {
                type: 'string',
                description: 'The SSH username to authenticate with.'
            },
            password: {
                type: 'string',
                description: 'The SSH password to authenticate with.'
            }
        },
        required: ['host', 'username', 'password']
    }
};

export const handleRevertKeys = async (args: Record<string, unknown>) => {
    try {
        // Validate input arguments
        const validatedArgs = z.object({
            host: z.string(),
            username: z.string(),
            password: z.string(),
        }).parse(args);

        // Revert registry keys
        const revertResults = await revertRegistryKeys(
            validatedArgs.host,
            validatedArgs.username,
            validatedArgs.password,
        );

        return {
            content: [
                {
                    type: 'text',
                    text: `Registry keys reverted successfully on ${validatedArgs.host}.`
                },
                {
                    type: 'json',
                    data: revertResults
                }
            ]
        };
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
};

/**
 * Handler for checking the firewall status on a remote Windows machine via SSH.
 */
export const FirewallStatusSchema = {
    name: 'check_firewall_status',
    description: 'Check the firewall status on a remote Windows machine via SSH.',
    inputSchema: {
        type: 'object',
        properties: {
            host: {
                type: 'string',
                description: 'The IP address or hostname of the remote machine.'
            },
            username: {
                type: 'string',
                description: 'The SSH username to authenticate with.'
            },
            password: {
                type: 'string',
                description: 'The SSH password to authenticate with.'
            }
        },
        required: ['host', 'username', 'password']
    }
};

export const handleCheckFirewallStatus = async (args: Record<string, unknown>) => {
    try {
        // Validate input arguments
        const validatedArgs = z.object({
            host: z.string(),
            username: z.string(),
            password: z.string(),
        }).parse(args);

        // Check firewall status
        const firewallStatus = await checkFirewallStatus(
            validatedArgs.host,
            validatedArgs.username,
            validatedArgs.password,
        );

        return {
            content: [
                {
                    type: 'text',
                    text: `Firewall status checked successfully on ${validatedArgs.host}.`
                },
                {
                    type: 'json',
                    data: firewallStatus
                }
            ]
        };
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
};

/**
 * Handler for enabling the firewall on a remote Windows machine via SSH.
 */
export const EnableFirewallSchema = {
    name: 'enable_firewall',
    description: 'Enable the firewall on a remote Windows machine via SSH.',
    inputSchema: {
        type: 'object',
        properties: {
            host: {
                type: 'string',
                description: 'The IP address or hostname of the remote machine.'
            },
            username: {
                type: 'string',
                description: 'The SSH username to authenticate with.'
            },
            password: {
                type: 'string',
                description: 'The SSH password to authenticate with.'
            }
        },
        required: ['host', 'username', 'password']
    }
};

export const handleEnableFirewall = async (args: Record<string, unknown>) => {
    try {
        // Validate input arguments
        const validatedArgs = z.object({
            host: z.string(),
            username: z.string(),
            password: z.string(),
        }).parse(args);

        // Enable firewall
        const enableResults = await enablefirewall(
            validatedArgs.host,
            validatedArgs.username,
            validatedArgs.password,
        );

        return {
            content: [
                {
                    type: 'text',
                    text: `Firewall enabled successfully on ${validatedArgs.host}.`
                },
                {
                    type: 'json',
                    data: enableResults
                }
            ]
        };
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
};

/**
 * Handler for disabling the firewall on a remote Windows machine via SSH.
 */
export const DisableFirewallSchema = {
    name: 'disable_firewall',
    description: 'Disable the firewall on a remote Windows machine via SSH.',
    inputSchema: {
        type: 'object',
        properties: {
            host: {
                type: 'string',
                description: 'The IP address or hostname of the remote machine.'
            },
            username: {
                type: 'string',
                description: 'The SSH username to authenticate with.'
            },
            password: {
                type: 'string',
                description: 'The SSH password to authenticate with.'
            }
        },
        required: ['host', 'username', 'password']
    }
};

export const handleDisableFirewall = async (args: Record<string, unknown>) => {
    try {
        // Validate input arguments
        const validatedArgs = z.object({
            host: z.string(),
            username: z.string(),
            password: z.string(),
        }).parse(args);

        // Disable firewall
        const disableResults = await disablefirewall(
            validatedArgs.host,
            validatedArgs.username,
            validatedArgs.password,
        );

        return {
            content: [
                {
                    type: 'text',
                    text: `Firewall disabled successfully on ${validatedArgs.host}.`
                },
                {
                    type: 'json',
                    data: disableResults
                }
            ]
        };
    } catch (error) {
        const mcpError = handleUnhardeningError(error);
        return {
            content: [
                {
                    type: 'text',
                    text: `Error: ${mcpError.message}`
                }
            ],
            isError: true
        }
    }
};