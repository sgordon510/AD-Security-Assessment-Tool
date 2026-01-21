// Microsoft Graph API Client for CA Policy Analyzer
// Handles authentication and policy fetching

import type {
  ConditionalAccessPolicy,
  NamedLocation,
  DirectoryRole,
  User,
  Group,
} from '../types';

export interface GraphClientConfig {
  accessToken?: string;
  tenantId?: string;
}

export interface GraphResponse<T> {
  value: T[];
  '@odata.nextLink'?: string;
}

const GRAPH_BASE_URL = 'https://graph.microsoft.com/v1.0';
const GRAPH_BETA_URL = 'https://graph.microsoft.com/beta';

export class GraphClient {
  private accessToken: string;

  constructor(config: GraphClientConfig) {
    if (!config.accessToken) {
      throw new Error('Access token is required');
    }
    this.accessToken = config.accessToken;
  }

  private async fetch<T>(endpoint: string, useBeta = false): Promise<T> {
    const baseUrl = useBeta ? GRAPH_BETA_URL : GRAPH_BASE_URL;
    const url = endpoint.startsWith('http') ? endpoint : `${baseUrl}${endpoint}`;

    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Graph API error (${response.status}): ${error}`);
    }

    return response.json();
  }

  private async fetchAll<T>(endpoint: string, useBeta = false): Promise<T[]> {
    const results: T[] = [];
    let nextLink: string | undefined = endpoint;

    while (nextLink) {
      const response = await this.fetch<GraphResponse<T>>(nextLink, useBeta);
      results.push(...response.value);
      nextLink = response['@odata.nextLink'];
    }

    return results;
  }

  async getConditionalAccessPolicies(): Promise<ConditionalAccessPolicy[]> {
    return this.fetchAll<ConditionalAccessPolicy>(
      '/identity/conditionalAccess/policies'
    );
  }

  async getNamedLocations(): Promise<NamedLocation[]> {
    return this.fetchAll<NamedLocation>(
      '/identity/conditionalAccess/namedLocations'
    );
  }

  async getDirectoryRoles(): Promise<DirectoryRole[]> {
    return this.fetchAll<DirectoryRole>('/directoryRoles');
  }

  async getDirectoryRoleTemplates(): Promise<DirectoryRole[]> {
    return this.fetchAll<DirectoryRole>('/directoryRoleTemplates');
  }

  async getUsers(select?: string[]): Promise<User[]> {
    const selectParam = select ? `?$select=${select.join(',')}` : '';
    return this.fetchAll<User>(`/users${selectParam}`);
  }

  async getGroups(select?: string[]): Promise<Group[]> {
    const selectParam = select ? `?$select=${select.join(',')}` : '';
    return this.fetchAll<Group>(`/groups${selectParam}`);
  }

  async getUser(userId: string): Promise<User> {
    return this.fetch<User>(`/users/${userId}`);
  }

  async getGroup(groupId: string): Promise<Group> {
    return this.fetch<Group>(`/groups/${groupId}`);
  }

  async getTenantDetails(): Promise<{ id: string; displayName: string }> {
    const response = await this.fetch<{
      value: Array<{ id: string; displayName: string }>;
    }>('/organization');
    return response.value[0];
  }
}

// Helper to validate access token format
export function isValidAccessToken(token: string): boolean {
  if (!token || typeof token !== 'string') {
    return false;
  }

  // JWT tokens have 3 parts separated by dots
  const parts = token.split('.');
  if (parts.length !== 3) {
    return false;
  }

  // Try to decode the payload to check expiration
  try {
    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64').toString('utf-8')
    );
    const exp = payload.exp;
    if (exp && exp * 1000 < Date.now()) {
      return false; // Token expired
    }
    return true;
  } catch {
    return false;
  }
}

// Helper function to get token from Azure CLI
export async function getTokenFromAzureCli(): Promise<string | null> {
  try {
    const proc = Bun.spawn(['az', 'account', 'get-access-token', '--resource', 'https://graph.microsoft.com', '--query', 'accessToken', '-o', 'tsv'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    const output = await new Response(proc.stdout).text();
    const error = await new Response(proc.stderr).text();

    await proc.exited;

    if (proc.exitCode !== 0) {
      console.error('Azure CLI error:', error);
      return null;
    }

    return output.trim();
  } catch (error) {
    console.error('Failed to get token from Azure CLI:', error);
    return null;
  }
}

// Check if Azure CLI is installed and logged in
export async function checkAzureCliAuth(): Promise<boolean> {
  try {
    const proc = Bun.spawn(['az', 'account', 'show'], {
      stdout: 'pipe',
      stderr: 'pipe',
    });

    await proc.exited;
    return proc.exitCode === 0;
  } catch {
    return false;
  }
}
