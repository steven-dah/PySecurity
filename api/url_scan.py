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

class URLScan(Configuration):

    def __init__(self):
        
        super().__init__("urls")
        self.url_keys = self.config_path

    class Threats:

        def threats(self, verdicts):

            is_malicious = verdicts.get("malicious", False)
            severity = "Malicious" if is_malicious else "Clean"

            return severity

    class Results:

        def results(self, url, url_json, severity, null):

            page = url_json.get("page", {})
            task = url_json.get("task", {})

            domain = page.get("domain")
            ip = page.get("ip")

            if not domain:

                domain = null

            if not ip:

                ip = null

            url_results = (

                f"URLScan - Results :\n\n"
                f"URL - {url} :\n\n"
                f"Domain : {domain}\n"
                f"Server IP address : {ip}\n\n"
                f"URLScan - Threat classification :\n\n"
                f"Severity : {severity}\n\n"
                f"Screenshot : {task.get('screenshotURL', null)}\n"
                f"Full report : {task.get('reportURL', null)}"
            
                )

            return url_results.strip()

    class Threads:

        def threads(self, executor, threats, verdicts):

            future_threats = executor.submit(

                threats.threats, 
                verdicts

                )

            return future_threats.result()

    class Analyze:

        def url_analyze(self, parent):

            threats = parent.Threats()
            threads = parent.Threads()
            results = parent.Results()

            load_dotenv(parent.api_keys)
            
            url_key = os.getenv("URL_SCAN")  
            null = "N/A"
            
            first_result = True
            urls = parent.load_keys()

            if urls:

                for url in urls:

                    submit_api = "https://urlscan.io/api/v1/scan/"
                    
                    submit_headers = {

                        "Content-Type": "application/json",
                        "API-Key": url_key

                        }
                    
                    submit_data = {"url": url, "visibility": "public"}
                        
                    try:

                        submit_request = requests.post(

                            submit_api, 
                            headers=submit_headers, 
                            json=submit_data, 
                            timeout=10

                            )

                        if submit_request.status_code == 200:

                            uuid = submit_request.json().get("uuid")
                            
                            url_api = "https://urlscan.io/api/v1/result/" + uuid + "/"
                            
                            url_headers = {
                                
                                "API-Key": url_key

                                }

                            max_attempts = 10
                            attempt = 0
                            url_json = None

                            while attempt < max_attempts:

                                attempt += 1
                                
                                time.sleep(10)

                                url_request = requests.get(

                                    url_api,
                                    headers=url_headers,
                                    timeout=10

                                    )

                                if url_request.status_code == 200:

                                    url_json = url_request.json()
                                    break

                                elif url_request.status_code != 404:

                                    break

                            if url_json:

                                verdicts = url_json.get("verdicts", {}).get("overall", {})

                                with ThreadPoolExecutor() as executor:

                                    severity = threads.threads(
                                        
                                        executor, 
                                        threats, 
                                        verdicts
                                        
                                        )
                                    
                                output = results.results(
                                    
                                    url, 
                                    url_json, 
                                    severity, 
                                    null
                                    
                                    )

                                if not first_result:

                                    yield "\n\n" + output

                                else:

                                    yield output
                                    first_result = False

                                time.sleep(2)

                        else:

                            wait_time = submit_request.headers.get("X-Rate-Limit-Reset-After", "N/A")
                            
                            quota_message = (

                                f"The URL {url} could not be analyzed due to a quota exceeded !\n\n"
                                f"Please wait {wait_time} before trying again."
                            
                                )
                            
                            if not first_result:

                                yield "\n\n" + quota_message

                            else:

                                yield quota_message
                                first_result = False

                    except requests.ConnectionError:

                        yield f"An error occurred while communicating with the URLScan API for {url} !"

                url_completed = (
                    
                    "The analysis of the URLs via the URLScan API has just been completed !\n\n"
                    "If you would like to copy the results, please left-click in the text box."

                    )

                showinfo(title=parent.title, message=url_completed)

            else:

                url_requirement = "To use the URLScan API, please create a text file containing the URLs to be scanned in the api/urls subdirectory !"
                showwarning(title=parent.title, message=url_requirement)

                yield ""