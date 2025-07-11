# Audit Bridge MCP

Audit Bridge MCP is a Model Context Protocol (MCP) server built with TypeScript for orchestrating and managing Windows system auditing tools. It supports various system checks, configuration adjustments, and security operations through a standardized tool interface.

## Purpose

Audit Bridge MCP streamlines Windows system audits by exposing multiple tools and operations behind a unified MCP interface. It is designed for integration with MCP clients and automation workflows related to security, compliance, and administration.

## Requirements

- [Node.js](https://nodejs.org/) (recommended: latest LTS version)
- Remote computer(s) must have **SSH enabled**
- The user account used for SSH must have **administrative rights** on the remote computer

## File Structure

The project follows a modular structure for easy maintenance and scalability:

- **src/test**: Contains test scripts.
- **src/tools**: Implements command interfaces for MCP tools.
- **src/utils**: Provides utility functions and middleware.
    - **error-handling.ts**: Utility for error management across the project.
    - **tools-Handler.ts**: Middleware that communicates with the command interface in `tools`, orchestrating requests and responses between MCP and various audit tools.
    - **index.ts**: Main entry point for utility functions.
- **.gitignore**: Specifies files to ignore in version control.
- **package.json / package-lock.json**: Project dependencies and metadata.
- **tsconfig.json**: TypeScript configuration.
- **README.md**: Project documentation.

## Features

- 🧰 Exposes multiple tools via the Model Context Protocol (MCP):
  - Symantec status checker
  - Manual security guides
  - Admin rights verification
  - Firewall control (enable/disable/status)
  - Registry key audit and modifications
  - Remote audit setup (e.g., via `.bat` files)

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Shangwee/audit-bridge-mcp.git
cd audit-bridge-mcp
npm install
```

## Usage

Build the project:

```bash
npm run build
```

Integrate with your MCP client by referencing the built server:

```json
{
  "mcpServers": {
    "audit-bridge-mcp": {
      "command": "node",
      "args": ["/path/to/audit-bridge-mcp/build/index.js"]
    }
  }
}
```

Replace `/path/to/audit-bridge-mcp/build/index.js` with the actual path to your built server.

## Troubleshooting

If the chat or tool response is stuck for too long, stop the tool in the MCP client and restart it.  
For example, use the stop (🗑️) and start (▶️) controls in your MCP client interface, or use the **Refresh** button as shown below (it should be similar for other MCP client as image below is using chatMCP client):

![image2](/img/refresh.png)

This will often resolve stuck or unresponsive tool sessions.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, open an issue on [GitHub](https://github.com/Shangwee/audit-bridge-mcp/issues).