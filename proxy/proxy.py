import sys
import os
from pathlib import Path

parent = str(Path(__file__).resolve().parent.parent)

if parent not in sys.path:
    
    sys.path.insert(0, parent)

from config.config import (
    
    path_exists,
    title,
    path_join,
    proxy, 
    denied

    )

from mitmproxy import http
from tkinter.messagebox import (
    
    askyesno,
    showwarning, 
    showinfo

    )

import subprocess

def request(flow: http.HTTPFlow):

    if path_exists(proxy):
        
        with open(proxy, "r", encoding="utf-8") as blacklist:

            hosts = []

            for line in blacklist:

                line_content = line.strip()

                if line_content:

                    hosts.append(line_content)

            unique_domains = set(hosts)
            current_host = flow.request.pretty_host

            is_blocked = False

            for host in unique_domains:

                if host in current_host:

                    is_blocked = True

                    break

            if is_blocked:

                if path_exists(denied):

                    with open(denied, "rb") as denied_file:

                        flow.response = http.Response.make(

                            403,
                            denied_file.read(),
                            {"Content-Type": "text/html"}
                    
                            )

def mitm_proxy():

    if not path_exists(proxy):

        blacklist_missing = (

            "PySecurity has detected that the text file “proxy.txt” does not exist !\n\n"
            "Would you like to create one ?"
        
            )

        create_blacklist = askyesno(title=title, message=blacklist_missing)

        if create_blacklist:
            
            try:
                        
                with open(proxy, "w", encoding="utf-8"):
                            
                    pass

                transmit_domains = (

                    "The text document has just been created ; it serves as a blacklist !\n\n"
                    "Would you like to transmit domains ?"
                        
                    )
                        
                if askyesno(title=title, message=transmit_domains):

                    subprocess.run(["notepad.exe", proxy])

            except Exception:

                showwarning(title=title, message="The text document intended to serve as a blacklist could not be created !")
                
                return

    proxy_dir = path_join(parent, "proxy")
    proxy_script = path_join(proxy_dir, "proxy.py")

    env = os.environ.copy()
    
    ignored_list = [

        "virustotal.com",
        "abuse.ch",
        "urlscan.io",
        "abuseipdb.com",
        "google.com"
        
        ]
    
    env["NO_PROXY"] = ",".join(ignored_list)
    
    ignore_regex = "^(.+\\.(virustotal\\.com|abuse\\.ch|urlscan\\.io|abuseipdb\\.com|google\\.com))"

    subprocess.Popen([
        
        "mitmproxy", "-s",
        proxy_script, "--listen-port", "8080",
        "--ignore-hosts", ignore_regex
        
        ],
        creationflags=subprocess.CREATE_NO_WINDOW,
        cwd=proxy_dir,
        env=env
        
        )
    
    showinfo(title=title, message="The proxy server is listening on port 8080 !")
    
if __name__ == "__main__":

    mitm_proxy()