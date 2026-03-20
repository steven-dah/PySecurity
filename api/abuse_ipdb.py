from api.config.api_config import Configuration
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
from tkinter.messagebox import (
    
    showinfo,
    showwarning

    )

import requests
import time
import os

class AbuseIPDB(Configuration):

    def __init__(self):
        
        super().__init__("ips")
        self.ai_ips = self.config_path

    class Threats:

        def threats(self, ai_json, null):

            threats_list = []

            data = ai_json.get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            if score > 0:

                threats_list.append(f"Confidence score (Abuse) : {score}%")
            
            if data.get("isTor"):

                threats_list.append("Tor")

            plural = ""

            if len(threats_list) > 1:

                plural = "s"
                formatted_threats = "\n".join(threats_list)

            elif len(threats_list) == 1:

                formatted_threats = threats_list[0]

            else:

                formatted_threats = null

            return formatted_threats, plural

    class Results:

        def results(self, ai_json, threats_data, plural, null):

            ai_informations = []
            
            data = ai_json.get("data", {})

            report_data = (
                
                f"IP Address : {data.get('ipAddress') or null}\n\n"
                f"Whitelisted : {data.get('isWhitelisted')}\n"
                f"Usage  : {data.get('usageType') or null}\n"
                f"ISP : {data.get('isp') or null}\n\n"
                f"Domain : {data.get('domain') or null}\n"
                f"Country : {data.get('countryCode') or null}\n\n"
                f"Reports : {data.get('totalReports') or 0}\n\n"
                "Verdict on the danger of the IP :\n\n"
                f"- Confidence score (Abuse) : {data.get('abuseConfidenceScore') or 0}%\n"
                f"- Users reporting : {data.get('numDistinctUsers') or 0}\n"
                f"- Last reported : {data.get('lastReportedAt') or null}"
                
                )

            ai_informations.append(report_data)

            report_data = "\n".join(ai_informations)

            ai_results = (

                f"AbuseIPDB - Results :\n\n"
                f"{report_data}\n\n"
                f"AbuseIPDB - IP classification{plural} :\n\n"
                f"{threats_data}"
            
                )

            return ai_results.strip()

    class Threads:

        def threads(self, executor, threats, ai_json, null):
            
            future_threats = executor.submit(
                
                threats.threats, 
                ai_json, 
                null
                
                )
                
            return future_threats.result()

    class Analyze:

        def ai_analyze(self, parent):

            threats = parent.Threats()
            threads = parent.Threads()
            results = parent.Results()

            load_dotenv(parent.api_keys)
            
            ai_key = os.getenv("ABUSE_IPDB")  
            null = "N/A"

            first_result = True
            ips_values = parent.load_keys()

            if ips_values:

                for ip_value in ips_values:

                    ai_url = "https://api.abuseipdb.com/api/v2/check"
                    ai_headers = {
            
                        "Key": ai_key,
                        "Accept": "application/json"
                            
                        }
                    
                    params = {

                        "ipAddress": ip_value,
                        "maxAgeInDays": "90"
                
                        }
                    
                    try:

                        ai_request = requests.get(

                            ai_url,
                            params=params,
                            headers=ai_headers,
                            timeout=15
                        
                            )
                        
                        if ai_request.status_code == 200:

                            ai_json = ai_request.json()

                            with ThreadPoolExecutor() as executor:

                                threats_data, plural = threads.threads(

                                    executor, 
                                    threats, 
                                    ai_json, 
                                    null
                                
                                    )

                            output = results.results(
                                
                                ip_value, 
                                ai_json, 
                                threats_data, 
                                plural, 
                                null
                                
                                )

                            if not first_result:

                                yield "\n\n" + output

                            else:

                                yield output
                                first_result = False

                            time.sleep(1)

                        elif ai_request.status_code == 429:

                            ai_exceeded = (

                                "You have exceeded the quota allowed by AbuseIPDB !\n"
                                "Please check your plan limits and try again later."

                                )
                            
                            showwarning(title=parent.title, message=ai_exceeded)
                            yield ai_exceeded

                    except Exception:

                        yield f"An error occurred while communicating with the AbuseIPDB API for {ip_value} !\n\n"

                ai_completed = (
                    
                    "The analysis of the IP addresses via the AbuseIPDB API has just been completed !\n\n"
                    "If you would like to copy the results, please left-click in the text box."

                    )

                showinfo(title=parent.title, message=ai_completed)

            else:

                ai_requirement = "To use the AbuseIPDB API, please create a text file containing the IP addresses to be analyzed in the api\ips subdirectory !"
                showwarning(title=parent.title, message=ai_requirement)

                yield ""