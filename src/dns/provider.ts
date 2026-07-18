/**
 * Abstraction over the DNS zone that owns *.local.tinycloud.link, so the
 * production Cloudflare implementation and the in-memory test fake are
 * interchangeable everywhere names/certs are issued.
 */
export interface DnsProvider {
  upsertAddressRecords(fqdn: string, ips: string[]): Promise<void>;
  deleteAddressRecords(fqdn: string): Promise<void>;
  createTxtRecord(fqdn: string, value: string): Promise<{ id: string }>;
  deleteTxtRecord(fqdn: string, id: string): Promise<void>;
}
