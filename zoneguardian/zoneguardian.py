import dns.resolver
import dns.exception
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from zoneguardian.utils.logger import appLogger

class ZoneGuardian:
    """
    ZoneGuardian: A professional tool for inspecting and analyzing DNS records
    to identify potential vulnerabilities or misconfigurations.
    """

    def __init__(self):
        """
        Initializes the ZoneGuardian class for DNS inspection.
        """
        self._record_types = [
            "A", "AAAA", "AFSDB", "CAA", "CNAME", "MX", "NS", "SOA", "TXT",
            "PTR", "SRV", "SSHFP", "TLSA", "DS", "DNSKEY", "NSEC", "NSEC3"
        ]
        self.resolver = dns.resolver.Resolver()

    def _resolve_records(self, domain):
        """
        Resolves DNS records for a single domain using predefined record types.
        """
        results = {}
        for record_type in self._record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                results[record_type] = [str(data) for data in answers]
            except dns.resolver.NoAnswer:
                results[record_type] = "NoAnswer"
            except dns.resolver.NXDOMAIN:
                results[record_type] = "NXDOMAIN (Domain does not exist)"
            except dns.resolver.Timeout:
                results[record_type] = "Timeout (Query timed out)"
            except dns.exception.DNSException as e:
                results[record_type] = f"Error: {str(e)}"
        return domain, results

    def _perform_zone_transfer(self, domain):
        """
        Attempts to perform a zone transfer (AXFR) using dnsrecon for a given domain.
        """
        try:
            # Use dnsrecon's AXFR functionality through subprocess
            command = f"dnsrecon -d {domain} -t axfr"
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                return result.stdout
            else:
                return None
        except Exception as e:
            return None

    def analyze_domains(self, domains, json_output_file="zoneguardian_results.json"):
        """
        Analyzes the DNS records for the provided list of domains in parallel and saves the results to a JSON file.
        """
        appLogger.info("🚀 Starting ZoneGuardian inspection for multiple domains in parallel.")
        all_results = {}

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._resolve_records, domain): domain for domain in domains}
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="Resolving Domains", ncols=100):
                domain, results = future.result()
                
                zone_data = self._perform_zone_transfer(domain)
                if zone_data:
                    results['zone_data'] = zone_data
                all_results[domain] = results

        with open(json_output_file, "w") as json_file:
            json.dump(all_results, json_file, indent=4)
        
        appLogger.info(f"✅ Inspection process completed. Results saved to {json_output_file}")
        return all_results