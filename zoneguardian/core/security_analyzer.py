import json
import os
from dotenv import load_dotenv
from fpdf import FPDF
from langchain_groq import ChatGroq
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.text_splitter import CharacterTextSplitter
from zoneguardian.utils.logger import appLogger

class DNSVulnerabilityAnalyzer:
    """
    This class is designed to analyze DNS vulnerability data, leveraging AI models and other tools to provide actionable insights into potential security risks.
    
    It uses a Groq AI model for detailed analysis and HuggingFace embeddings for vector-based search. The class integrates with Langchain for effective document retrieval and information extraction from DNS scan results.

    Attributes:
        model (ChatGroq): Groq AI model used for processing the DNS vulnerability scan data.
        embeddings (HuggingFaceEmbeddings): Embedding model from HuggingFace used to convert text data into vector representations.
    """

    def __init__(self):
        """
        Initializes the DNSVulnerabilityAnalyzer class by loading environment variables from a .env file,
        setting up the Groq AI model for DNS vulnerability analysis, and preparing the necessary embedding model.

        This constructor performs the following actions:
        - Loads environment variables from the .env file using `load_dotenv()`.
        - Retrieves the Groq API key and Model ID from the environment variables.
        - Initializes the Groq AI model using the retrieved credentials.
        - Initializes the HuggingFaceEmbeddings model for text vectorization.
        - Logs successful initialization with a logger.

        Raises:
            ValueError: If the required environment variables (GROQ_API_KEY and MODEL_ID) are not found.
        """
        load_dotenv()

        groq_api_key = os.getenv("GROQ_API_KEY")
        model_id = os.getenv("MODEL_ID")

        if not groq_api_key or not model_id:
            raise ValueError("GROQ API key and Model ID are required. Ensure they are defined in the .env file.")

        self.model = ChatGroq(model=model_id, temperature=1, api_key=groq_api_key)
        self.embeddings = HuggingFaceEmbeddings()
        appLogger.info("🔥 Groq model initialized successfully! Ready to roll. 💻")

    def generate_report(self, scan_results: dict, pdf_path="dns_security_report.pdf", json_path="dns_security_report.json"):
        """
        Generates a professional security audit report based on DNS scan results.
        
        Args:
            scan_results (dict): The DNS scan results obtained.
            pdf_path (str, optional): Path where the PDF report will be saved.
            json_path (str, optional): Path where the JSON report will be saved.
        """
        try:
            appLogger.info("🔍 Analyzing DNS results...")

            # Convert scan results into text for Langchain processing
            report_content = self._format_report(scan_results)
            chunks = self._split_log_into_chunks(report_content)

            # Create a FAISS vector store to facilitate document retrieval
            vector_store = FAISS.from_documents(chunks, self.embeddings)
            retriever = vector_store.as_retriever()

            # Create the Langchain QA chain to generate the final report
            chain = RetrievalQA.from_chain_type(self.model, retriever=retriever)

            # Generate the analysis prompt to guide the LLM's vulnerability assessment
            prompt = self._generate_report_prompt()

            # Invoke the model to analyze the scan results and generate a detailed report
            appLogger.info("🤖 Running the analysis with retrieval chain...")
            result = chain.invoke(prompt).get("result", "")

            # Generate the reports in PDF and JSON formats
            self._generate_pdf_report(result, pdf_path)
            self._generate_json_report(result, json_path)

            appLogger.info("✅ DNS security report generated successfully!")
            return "Report generation complete. PDF and JSON reports have been saved."
        
        except Exception as e:
            appLogger.error(f"🚨 Error during report generation: {e}")
            return f"Error during report generation: {e}"

    def _format_report(self, scan_results: dict):
        """
        Formats the DNS scan results into a structured report for Langchain processing.

        Args:
            scan_results (dict): The DNS scan results obtained.

        Returns:
            str: A formatted text report ready to be included in the PDF.
        """
        report = []
        report.append("DNS Vulnerability Audit Report\n")
        report.append("====================================\n")

        for domain, records in scan_results.items():
            report.append(f"\nDomain: {domain}\n")
            
            for record_type, record_value in records.items():
                if record_type == "zone_data":
                    report.append(f"  {record_type}:\n")
                    for line in record_value:
                        report.append(f"    - {line}")
                else:
                    report.append(f"  {record_type}: {record_value}\n")
            
            formatted_report = "\n".join(report)
        return formatted_report

    def _split_log_into_chunks(self, content: str):
        """
        Splits the log content into smaller chunks for Langchain processing.

        Args:
            content (str): The report content to be split into chunks.

        Returns:
            list: A list of documents (chunks) ready for Langchain processing.
        """
        chunk_size = 4500
        text_splitter = CharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=0)
        return text_splitter.create_documents([content])

    def _generate_report_prompt(self):
        """
        Generates the prompt to guide the model's analysis of DNS scan results.

        Returns:
            str: The prompt for the LLM to analyze the scan results.
        """
        return (
            "You are an AI-powered cybersecurity expert, tasked with analyzing DNS records from multiple domains. "
            "Your goal is to generate a **highly focused, actionable security report** by identifying **critical security risks** and vulnerabilities in the DNS zone files. "
            "Pay close attention to information that may expose sensitive infrastructure details such as internal domain names, server configurations, or other confidential data that could be leveraged by attackers. "
            "You should classify vulnerabilities as **critical vulnerabilities**, **warnings**, or **informational notes**, but focus mainly on **serious risks** that could lead to severe attacks or system exposure. "
            "Your analysis should prioritize issues that require immediate attention and that could directly impact the security of the organization's systems.\n\n"
            
            "The report should include the following sections:\n\n"
            
            "**1. Executive Summary:**\n"
            "   - Provide a concise overview of the most critical vulnerabilities found in the DNS zone files, focusing on risks that could expose sensitive infrastructure or provide attackers with valuable information.\n"
            "   - Highlight any **urgent vulnerabilities** or configurations that could be exploited to breach the system.\n\n"
            
            "**2. Vulnerability Analysis:**\n"
            "   - For each domain, carefully review and analyze any **sensitive information** revealed in the DNS zone files, such as internal server names, internal network infrastructure, or improperly exposed DNS records. "
            "   - Classify vulnerabilities into the following categories:\n"
            "     1. **Critical Vulnerabilities**: Immediate threats that expose sensitive infrastructure details or could lead to a significant compromise.\n"
            "     2. **Warnings**: Issues that are less severe but still relevant, such as the exposure of non-sensitive, but still relevant, internal DNS records.\n"
            "     3. **Informational Notes**: Low-priority findings, such as standard DNS configurations that don’t pose a direct security risk but could be useful for attackers if combined with other vulnerabilities.\n"
            "   - For each identified issue, provide a **clear description**, its **potential impact** on the organization (especially with regard to internal infrastructure exposure), and specific steps on how to **mitigate** the risk.\n\n"
            
            "**3. Recommendations:**\n"
            "   - Provide **specific and actionable remediation steps** for each identified vulnerability. Focus on high-priority fixes, especially those that would close off potential attack vectors from exposed internal data or misconfigurations.\n"
            "   - Ensure the recommendations focus on reducing the exposure of internal systems or sensitive infrastructure.\n\n"
            
            "**4. Conclusion:**\n"
            "   - Summarize the security posture based on the DNS zone analysis, identifying the most pressing vulnerabilities and areas requiring further investigation or monitoring.\n"
            "   - Focus on any exposed internal infrastructure that could be targeted by attackers or used to gain access to more critical systems.\n\n"
            
            "Throughout the report, ensure that the language is **clear, professional, and actionable**. Emphasize actionable steps to mitigate the **high-priority vulnerabilities** while excluding irrelevant or low-priority findings."
        )


    def _generate_pdf_report(self, content: str, file_path="dns_security_report.pdf"):
        """
        Generates a PDF report based on the provided content.

        Args:
            content (str): The content to include in the PDF report.
            file_path (str): Path where the PDF will be saved.
        """
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(200, 10, txt="DNS Security Audit Report", ln=True, align='C')
            pdf.ln(10)
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, txt=content)
            pdf.output(file_path)
            appLogger.info(f"📄 PDF report generated: {file_path}")
        except Exception as e:
            appLogger.error(f"⚠️ Error generating PDF report: {e}")

    def _generate_json_report(self, content: str, file_path="dns_security_report.json"):
        """
        Generates a JSON report containing the vulnerabilities found.

        Args:
            content (str): The vulnerabilities and warnings content.
            file_path (str): Path where the JSON file will be saved.
        """
        try:
            with open(file_path, 'w') as json_file:
                json.dump({"report": content}, json_file, indent=4)
            appLogger.info(f"📂 JSON report generated: {file_path}")
        except Exception as e:
            appLogger.error(f"⚠️ Error generating JSON report: {e}")