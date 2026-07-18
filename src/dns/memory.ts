import type { DnsProvider } from "./provider.js";

/** In-memory fake used by tests; never talks to a real DNS API. */
export class InMemoryDnsProvider implements DnsProvider {
  readonly addressRecords = new Map<string, string[]>();
  readonly txtRecords = new Map<string, { fqdn: string; value: string }>();
  private nextId = 1;

  async upsertAddressRecords(fqdn: string, ips: string[]): Promise<void> {
    this.addressRecords.set(fqdn, [...ips]);
  }

  async deleteAddressRecords(fqdn: string): Promise<void> {
    this.addressRecords.delete(fqdn);
  }

  async createTxtRecord(fqdn: string, value: string): Promise<{ id: string }> {
    const id = String(this.nextId++);
    this.txtRecords.set(id, { fqdn, value });
    return { id };
  }

  async deleteTxtRecord(_fqdn: string, id: string): Promise<void> {
    this.txtRecords.delete(id);
  }
}
