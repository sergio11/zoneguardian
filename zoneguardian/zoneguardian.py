import dns.resolver
import dns.exception
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from zoneguardian.core.security_analyzer import DNSVulnerabilityAnalyzer
from zoneguardian.utils.logger import appLogger
import whois
from zoneguardian import __version__

class ZoneGuardian:
    """
    The ZoneGuardian class is responsible for inspecting and analyzing DNS records to identify potential vulnerabilities.
    
    This class supports a variety of DNS record types and integrates with the `DNSVulnerabilityAnalyzer` class to perform security analysis on the DNS records it retrieves.

    Attributes:
        _record_types (list): A list of DNS record types that will be inspected during the analysis.
        resolver (dns.resolver.Resolver): The DNS resolver used to query DNS records from different domains.
        analyzer (DNSVulnerabilityAnalyzer): An instance of the DNSVulnerabilityAnalyzer class used for analyzing vulnerabilities in the DNS data.
    """

    def __init__(self):
        """
        Initializes the ZoneGuardian class for DNS inspection.

        This constructor sets up the following:
        - Defines the list of DNS record types that are subject to inspection.
        - Initializes the DNS resolver for querying DNS records.
        - Initializes the DNSVulnerabilityAnalyzer for analyzing DNS vulnerabilities.

        The constructor does the following:
        - Sets up the `_record_types` attribute, which includes a predefined list of DNS record types to inspect.
        - Initializes the `dns.resolver.Resolver()` object for performing DNS lookups.
        - Creates an instance of `DNSVulnerabilityAnalyzer` to analyze any vulnerabilities in the retrieved DNS records.

        Attributes initialized:
            - `_record_types`: List of supported DNS record types.
            - `resolver`: Instance of `dns.resolver.Resolver` for performing DNS lookups.
            - `analyzer`: Instance of the `DNSVulnerabilityAnalyzer` class for vulnerability analysis.
        """
        self._print_banner()
        self._record_types = [
            "A", "AAAA", "AFSDB", "CAA", "CNAME", "MX", "NS", "SOA", "TXT",
            "PTR", "SRV", "SSHFP", "TLSA", "DS", "DNSKEY", "NSEC", "NSEC3"
        ]
        self.resolver = dns.resolver.Resolver()
        self.analyzer = DNSVulnerabilityAnalyzer()


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
        
    def _get_whois_information(self, domain):
        """
        Retrieves and returns the WHOIS information for a specified domain.

        Args:
            domain (str): The domain name for which WHOIS information is requested.

        Returns:
            whois.parser.WhoisEntry: Object containing the WHOIS information of the domain.
        
        Raises:
            whois.exceptions.WhoisCommandFailed: If the WHOIS query fails.
            ValueError: If the domain name is invalid or empty.
        """
        if not domain:
            raise ValueError("Domain name cannot be empty.")

        try:
            # Perform the WHOIS query
            response = whois.whois(domain)
            return response
        except Exception as e:
            appLogger.error(f"Error retrieving WHOIS information for domain {domain}: {e}")
            raise

    def analyze_domains(self, domains, threads=10, json_output_file="zoneguardian_results.json", pdf_output_file="zoneguardian_report.pdf"):
        """
        Analyzes the DNS records for the provided list of domains in parallel and generates a security report.
        """
        appLogger.info("🚀 Starting ZoneGuardian inspection for multiple domains in parallel.")
        all_results = {}

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._resolve_records, domain): domain for domain in domains}
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="Resolving Domains", ncols=100):
                domain, results = future.result()
                
                # Perform zone transfer if possible
                zone_data = self._perform_zone_transfer(domain)
                if zone_data:
                    results['zone_data'] = zone_data.splitlines()
                
                whois_info = self._get_whois_information(domain)
                if whois_info:
                    results['WHOIS'] = whois_info
                all_results[domain] = results

        appLogger.info("🔍 Analyzing vulnerabilities based on DNS scan results...")
        self.analyzer.generate_report(scan_results=all_results, pdf_path=pdf_output_file, json_path=json_output_file)

        appLogger.info(f"✅ Inspection process completed. Results saved to {json_output_file} and report generated as {pdf_output_file}")
        return all_results
    
    def _print_banner(self):
        """
        Prints a welcome banner at the start of the program for Zoneguardian.
        """
        banner = f"""
        ███████╗ ██████╗ ███╗   ██╗███████╗                            
        ╚══███╔╝██╔═══██╗████╗  ██║██╔════╝                            
        ███╔╝ ██║   ██║██╔██╗ ██║█████╗                              
        ███╔╝  ██║   ██║██║╚██╗██║██╔══╝                              
        ███████╗╚██████╔╝██║ ╚████║███████╗                            
        ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝                            
                                                                        
        ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
        ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
        ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
        ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
        ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
        ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                                              
        ZoneGuardian: Your First Line of Defense in DNS Security. (Version: {__version__})
        """
        print(banner)