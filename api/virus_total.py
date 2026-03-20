from api.config.api_config import Configuration
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor
from tkinter.messagebox import (
    
    showwarning, 
    showinfo
    
    )

import os
import requests
import time

class VirusTotal(Configuration):

    def __init__(self):
        
        super().__init__("vt_hashes")
        self.vt_hashes = self.config_path

    class Threats:

        def threats(self, threat_categories, null):

            threats_list = []

            for category in threat_categories:

                value = str(category.get("value"))
                value = value.capitalize()

                count = category.get("count")
                threats_list.append(

                    f"{value} - "
                    f"{count} %"
                    
                    )

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

        def results(self, hash_value, last_analysis, plural, threats_data, null):

            report_list = []

            for engine in last_analysis.values():

                name = engine.get("engine_name")
                category = engine.get("category")
                result = engine.get("result")

                if not result:

                    result = null

                report_list.append(

                    f"{name} - "
                    f"{category} - "
                    f"{result}"
                
                    )

            report_data = "\n".join(report_list) if report_list else null

            vt_results = (

                f"VirusTotal - Results :\n\n"
                f"HASH - {hash_value} :\n\n"
                f"{report_data}\n\n"
                f"VirusTotal - Binary classification{plural} :\n\n"
                f"{threats_data}"
            
                )

            return vt_results.strip()

    class Threads:

        def threads(self, executor, threats, threat_categories, null):
            
            future_threats = executor.submit(
                
                threats.threats, 
                threat_categories, 
                null
                
                )
                
            return future_threats.result()

    class Analyze:

        def vt_analyze(self, parent):

            threats = parent.Threats()
            threads = parent.Threads()
            results = parent.Results()

            load_dotenv(parent.api_keys)
            
            vt_key = os.getenv("VIRUS_TOTAL")  
            null = "N/A"
            
            first_result = True
            hashes_values = parent.load_keys()

            if hashes_values:

                for hash_value in hashes_values:

                    vt_url = "https://www.virustotal.com/api/v3/files/" + hash_value
                    vt_headers = {
                        
                        "accept": "application/json",
                        "x-apikey": vt_key
                                
                        }
                        
                    try:

                        vt_request = requests.get(

                                vt_url,
                                headers=vt_headers,
                                timeout=10
                            
                                )

                        if vt_request.status_code == 429:

                            vt_error = (

                                f"The digital signature {hash_value} could not be verified due to a quota exceeded.\n\n"
                                "Please wait 60 seconds before trying again."

                                )

                            yield vt_error
                            break
                        
                        if vt_request.status_code == 200:

                            vt_json = vt_request.json()
                            data = vt_json.get("data", {})

                            attributes = data.get("attributes", {})
                            last_analysis = attributes.get("last_analysis_results", {})
                                
                            threat_classification = attributes.get("popular_threat_classification", {})
                            threat_categories = threat_classification.get("popular_threat_category", [])

                            with ThreadPoolExecutor() as executor:

                                threats_data, plural = threads.threads(

                                    executor, 
                                    threats, 
                                    threat_categories, 
                                    null
                                
                                    )

                            output = results.results(
                                
                                hash_value, 
                                last_analysis, 
                                plural, 
                                threats_data,
                                null
                                
                                )

                            if not first_result:

                                yield "\n\n" + output

                            else:

                                yield output
                                first_result = False

                            time.sleep(15)

                    except requests.ConnectionError:

                        yield "An error occurred while communicating with the VirusTotal API.\n\n"

                vt_completed = (
                    
                    "The analysis of the digital signatures via the VirusTotal API has just been completed !\n\n"
                    "If you would like to copy the results, please left-click in the text box."

                    )

                showinfo(title=parent.title, message=vt_completed)

            else:

                vt_requirement = r"To use the VirusTotal API, please create a text file containing the digital signatures to be analyzed in the api\vt_hashes subdirectory !"
                showwarning(title=parent.title, message=vt_requirement)

                yield ""