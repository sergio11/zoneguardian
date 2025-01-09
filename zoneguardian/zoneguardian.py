import dns.resolver
import dns.exception
from zoneguardian.utils.logger import appLogger

class ZoneGuardian:
    """
    ZoneGuardian: A professional tool for inspecting and analyzing DNS records 
    to identify potential vulnerabilities or misconfigurations.
    """

    def __init__(self, domain):
        """
        Initializes the ZoneGuardian class with the target domain.

        Args:
            domain (str): The domain to analyze.
        """
        self.domain = domain
        self._record_types = [
            "A", "AAAA", "AFSDB", "CAA", "CNAME", "MX", "NS", "SOA", "TXT",
            "PTR", "SRV", "SSHFP", "TLSA", "DS", "DNSKEY", "NSEC", "NSEC3"
        ]
        self.resolver = dns.resolver.Resolver()

    def _resolve_records(self):
        """
        Resolves DNS records for the domain using predefined record types.

        Returns:
            dict: A dictionary containing resolved records or error messages.
        """
        appLogger.info(f"🔍 Scanning DNS records for: {self.domain}")
        results = {}

        for record_type in self._record_types:
            try:
                appLogger.info(f"🔎 Resolving: {record_type}")
                answers = self.resolver.resolve(self.domain, record_type)
                results[record_type] = [str(data) for data in answers]
                appLogger.info(f"✅ {record_type} records resolved: {results[record_type]}")
            except dns.resolver.NoAnswer:
                appLogger.warning(f"⚠️ No answer for {record_type} records.")
                results[record_type] = "NoAnswer"
            except dns.resolver.NXDOMAIN:
                appLogger.error(f"❌ Domain {self.domain} does not exist (NXDOMAIN).")
                results[record_type] = "NXDOMAIN (Domain does not exist)"
            except dns.resolver.Timeout:
                appLogger.warning(f"⏳ Timeout while resolving {record_type} records.")
                results[record_type] = "Timeout (Query timed out)"
            except dns.exception.DNSException as e:
                appLogger.error(f"❌ Error resolving {record_type}: {str(e)}")
                results[record_type] = f"Error: {str(e)}"

        return results

    def _analyze_results(self, results):
        """
        Analyzes the resolved DNS records for potential misconfigurations or vulnerabilities.

        Args:
            results (dict): Resolved DNS records.

        Returns:
            list: A list of warnings or recommendations based on the analysis.
        """
        appLogger.info("🧠 Analyzing DNS records...")
        warnings = []

        if "MX" in results and results["MX"] == "NoAnswer":
            warnings.append("No MX records found. The domain may not be able to receive emails.")
            appLogger.warning("⚠️ Potential issue: Missing MX records.")

        if "TXT" in results and results["TXT"] == "NoAnswer":
            warnings.append("No TXT records found. Missing SPF, DKIM, or DMARC configurations.")
            appLogger.warning("⚠️ Potential issue: Missing TXT records.")

        if "A" in results and results["A"] == "NoAnswer" and "AAAA" in results and results["AAAA"] == "NoAnswer":
            warnings.append("No A or AAAA records found. The domain may not be accessible via IPv4 or IPv6.")
            appLogger.warning("⚠️ Potential issue: Missing A/AAAA records.")

        if "SOA" in results and results["SOA"] == "NoAnswer":
            warnings.append("No SOA record found. This could indicate zone configuration issues.")
            appLogger.warning("⚠️ Potential issue: Missing SOA record.")

        # Add more checks for other record types as needed.

        if not warnings:
            appLogger.info("🎉 No issues found during DNS analysis.")

        return warnings

    def run(self):
        """
        Executes the ZoneGuardian inspection process: resolving records and analyzing results.

        Returns:
            dict: Contains resolved records and analysis warnings.
        """
        appLogger.info(f"🚀 ZoneGuardian is inspecting DNS records for: {self.domain}")
        results = self._resolve_records()

        appLogger.info("📊 Performing analysis...")
        warnings = self._analyze_results(results)

        appLogger.info("✅ Inspection process completed.")
        return {"records": results, "warnings": warnings}


if __name__ == "__main__":
    appLogger.info("💻 Welcome to ZoneGuardian: Your DNS inspection and auditing tool\n")

    # Input the target domain
    target_domain = input("🌐 Enter the target domain: ").strip()

    # Initialize the ZoneGuardian class and run the inspection
    dns_tool = ZoneGuardian(target_domain)
    output = dns_tool.run()

    # Display resolved records
    appLogger.info("\n📂 Resolved DNS Records:")
    for record_type, data in output["records"].items():
        appLogger.info(f"📌 {record_type}: {data}")

    # Display analysis warnings
    appLogger.info("\n⚠️ Analysis Warnings:")
    if output["warnings"]:
        for warning in output["warnings"]:
            appLogger.warning(f"🔴 {warning}")
    else:
        appLogger.info("✅ No warnings found. The DNS configuration appears to be correct.")

    appLogger.info("\n🏁 Inspection completed. Thank you for using ZoneGuardian!")