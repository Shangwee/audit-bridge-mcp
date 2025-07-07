/**
 * audit bridge MCP - Model Context Protocol Server
 * This server implements the Model Context Protocol (MCP) for managing and executing tools.
 * It supports listing available tools and calling them with specific parameters.
 * 
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { handleUnhardeningError } from './utils/error-handling.js';

import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

//import handlers
import { 
    ManualCheckSchema,
    handleListManualChecks,
    AdminRightsSchema,
    handleCheckAdminRightsRemote,
    RemoteAuditSetupSchema,
    handleRunRemoteAuditSetup,
    RegistryKeySchema,
    handleCheckRegistryKey,
    AddRegistryKeysSchema,
    handleAddRegistryKeys,
    DeleteRegistryKeysSchema,
    handleDeleteRegistryKeys,
    ImportBatFileSchema,
    handleImportBatFile,
    RevertKeysSchema,
    handleRevertKeys
} from './tools-Handler.js';

// Create and configure the MCP server
const createServer = () => {
  // Create the server instance
  const server = new Server(
    {
      name: 'Audit-Bridge-server',
      version: '1.0.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // Register tools list handler
  server.setRequestHandler(
    ListToolsRequestSchema,
    async () => {
      return {
        tools: [
            ManualCheckSchema,
            AdminRightsSchema,
            RemoteAuditSetupSchema,
            RegistryKeySchema,
            AddRegistryKeysSchema,
            DeleteRegistryKeysSchema,
            ImportBatFileSchema,
            RevertKeysSchema
        ]
      };
    }
  );

  // Register tool call handler
  server.setRequestHandler(
    CallToolRequestSchema,
    async (request, extra) => {
      try {
        const { name, arguments: args = {} } = request.params;

        // Route to the appropriate tool handler
        switch (name) {
          case 'list_manual_checks':
            return await handleListManualChecks(args) || {};
          case 'check_admin_rights_remote':
            return await handleCheckAdminRightsRemote(args) || {};
          case 'run_remote_audit_setup':
            return await handleRunRemoteAuditSetup(args) || {};
          case 'check_registry_key':
            return await handleCheckRegistryKey(args) || {};
          case 'add_registry_keys':
            return await handleAddRegistryKeys(args) || {};
          case 'delete_registry_keys':
            return await handleDeleteRegistryKeys(args) || {};
          case 'import_bat_file':
            return await handleImportBatFile(args) || {};
          case 'revert_keys':
            return await handleRevertKeys(args) || {};
          default:
            return {
              content: [
                {
                  type: 'text',
                  text: `Error: Unknown tool "${name}"`
                }
              ],
              isError: true
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
        };
      }
    }
  );

  return server;
};

// Main function
async function main() {
  try {

    // Create the server
    const server = createServer();

    // Create the transport
    const transport = new StdioServerTransport();

    // Connect the server to the transport
    await server.connect(transport);

    console.error('audit bridge MCP Server running on stdio');

    // Handle process termination
    process.on('SIGINT', async () => {
      console.error('Shutting down audit bridge MCP Server...');
      await server.close();
      process.exit(0);
    });
  } catch (error) {
    console.error('Fatal error starting audit bridge MCP Server:', error);
    process.exit(1);
  }
}

// Run the server
main().catch((error) => {
  console.error('Unhandled error in audit bridge MCP Server:', error);
  process.exit(1);
});
