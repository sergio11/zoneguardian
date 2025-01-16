import argparse
from zoneguardian.utils.logger import appLogger
from zoneguardian.zoneguardian import ZoneGuardian

def main():
    parser = argparse.ArgumentParser(description="ZoneGuardian: DNS Inspection & Vulnerability Analysis Tool")
    parser.add_argument('--domains', type=str, required=True, help="Comma-separated list of domains to scan (e.g., example.com,example2.com).")
    parser.add_argument('--threads', type=int, default=10, help="Number of threads to use for scanning (default: 10).")
    parser.add_argument('--output-json', type=str, default="zoneguardian_results.json", help="Path to save the JSON output (default: zoneguardian_results.json).")
    parser.add_argument('--output-pdf', type=str, default="zoneguardian_report.pdf", help="Path to save the PDF report (default: zoneguardian_report.pdf).")
    
    args = parser.parse_args()
    domains = [domain.strip() for domain in args.domains.split(',')]
    dns_tool = ZoneGuardian()
    appLogger.info(f"🚀 Starting DNS inspection for {len(domains)} domains using {args.threads} threads...")

    try:
        results = dns_tool.analyze_domains(
            domains, 
            threads=args.threads,
            json_output_file=args.output_json,
            pdf_output_file=args.output_pdf
        )

        for domain, records in results.items():
            total_records = sum(1 for record_type, data in records.items() if isinstance(data, list) and data != "NoAnswer" and data != "NXDOMAIN (Domain does not exist)")
            appLogger.info(f"\n🛡️ Domain: {domain}")
            appLogger.info(f"  ✅ {total_records} DNS records successfully recovered.")

        appLogger.info("\n✅ Inspection process completed.")
        appLogger.info(f"📂 Vulnerability analysis report saved to: {args.output_pdf}")
        appLogger.info(f"📄 Detailed JSON results saved to: {args.output_json}")

    except Exception as e:
        appLogger.error(f"❌ An error occurred while analyzing the domains: {e}")

if __name__ == "__main__":
    main()