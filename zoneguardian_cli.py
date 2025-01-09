import argparse
from zoneguardian.utils.logger import appLogger
from zoneguardian.zoneguardian import ZoneGuardian

def main():
    parser = argparse.ArgumentParser(description="ZoneGuardian: DNS Inspection & Vulnerability Analysis Tool")
    parser.add_argument('--domains', type=str, required=True, help="Comma-separated list of domains to scan (e.g., example.com,example2.com).")
    parser.add_argument('--threads', type=int, default=10, help="Number of threads to use for scanning (default: 10).")
    
    args = parser.parse_args()
    domains = [domain.strip() for domain in args.domains.split(',')]
    dns_tool = ZoneGuardian()
    appLogger.info(f"🚀 Starting DNS inspection for {len(domains)} domains...")

    try:
        results = dns_tool.analyze_domains(domains)

        appLogger.info("\n📊 Resolved DNS Records:")
        for domain, records in results.items():
            appLogger.info(f"\n🛡️ Domain: {domain}")
            for record_type, data in records.items():
                appLogger.info(f"{record_type}: {data}")

        appLogger.info("\n✅ Inspection process completed.")

    except Exception as e:
        appLogger.error(f"❌ An error occurred while analyzing the domains: {e}")


if __name__ == "__main__":
    main()
