/**
 * Error handling utilities for the audit bridge MCP server
 */

import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';

/**
 * Handle errors from powershell and convert them to MCP errors
 * @param error Error from the unhardening process
 */
export const handleUnhardeningError = (error: unknown): McpError => {
    if (error instanceof McpError) {
        return error;
    }

    if (error instanceof Error) {
        return {
            name: error.name || 'McpError',
            code: ErrorCode.InternalError,
            message: error.message,
            data: {
                stack: error.stack  // Include stack trace for debugging
            }
        };
    }
    
    // Default case for unknown error types
    return {
        name: 'McpError',
        code: ErrorCode.InternalError,
        message: String(error) || 'Unknown error occurred',
        data: { originalError: error }
    };
};