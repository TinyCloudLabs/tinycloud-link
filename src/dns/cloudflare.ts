import type { DnsProvider } from "./provider.js";

const CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4";

export interface CloudflareDnsProviderOptions {
  apiToken: string;
  zoneId: string;
  ttl?: number;
}

interface CloudflareResponse<T> {
  success: boolean;
  errors: unknown[];
  result: T;
}

interface CloudflareDnsRecord {
  id: string;
}

/** Production DNS provider for the zone that owns *.local.tinycloud.link. */
export class CloudflareDnsProvider implements DnsProvider {
  constructor(private readonly opts: CloudflareDnsProviderOptions) {}

  async upsertAddressRecords(fqdn: string, ips: string[]): Promise<void> {
    await this.deleteAddressRecords(fqdn);
    for (const ip of ips) {
      const type = ip.includes(":") ? "AAAA" : "A";
      await this.createRecord({ type, name: fqdn, content: ip, ttl: this.opts.ttl ?? 60 });
    }
  }

  async deleteAddressRecords(fqdn: string): Promise<void> {
    for (const type of ["A", "AAAA"]) {
      const records = await this.listRecords(type, fqdn);
      for (const record of records) {
        await this.deleteRecord(record.id);
      }
    }
  }

  async createTxtRecord(fqdn: string, value: string): Promise<{ id: string }> {
    const record = await this.createRecord({
      type: "TXT",
      name: fqdn,
      content: `"${value}"`,
      ttl: 60,
    });
    return { id: record.id };
  }

  async deleteTxtRecord(_fqdn: string, id: string): Promise<void> {
    await this.deleteRecord(id);
  }

  private async listRecords(type: string, name: string): Promise<CloudflareDnsRecord[]> {
    const response = await this.request<CloudflareDnsRecord[]>(
      `/zones/${this.opts.zoneId}/dns_records?type=${type}&name=${encodeURIComponent(name)}`,
      { method: "GET" }
    );
    return response.result;
  }

  private async createRecord(input: {
    type: string;
    name: string;
    content: string;
    ttl: number;
  }): Promise<CloudflareDnsRecord> {
    const response = await this.request<CloudflareDnsRecord>(
      `/zones/${this.opts.zoneId}/dns_records`,
      { method: "POST", body: JSON.stringify(input) }
    );
    return response.result;
  }

  private async deleteRecord(id: string): Promise<void> {
    await this.request(`/zones/${this.opts.zoneId}/dns_records/${id}`, { method: "DELETE" });
  }

  private async request<T>(path: string, init: RequestInit): Promise<CloudflareResponse<T>> {
    const response = await fetch(`${CLOUDFLARE_API_BASE}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${this.opts.apiToken}`,
        "Content-Type": "application/json",
      },
    });
    const body = (await response.json()) as CloudflareResponse<T>;
    if (!response.ok || !body.success) {
      throw new Error(`Cloudflare API error: ${JSON.stringify(body.errors)}`);
    }
    return body;
  }
}
