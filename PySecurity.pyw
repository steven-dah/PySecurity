from config.config import (
    
    title,
    path_join,
    parent 
    
    )

from PIL import Image
from pathlib import Path
from tkinter.messagebox import showwarning
from functools import partial
from api.virus_total import VirusTotal
from api.malware_bazaar import MalwareBazaar
from api.url_scan import URLScan
from api.abuse_ipdb import AbuseIPDB
from proxy.proxy import mitm_proxy

import customtkinter as ctk
import threading
import requests 

class PySecurity:

    def __init__(self):

        self.calibri = ("Calibri", 18, "bold")
        self.fg_color = "#565B5E"
        self.hover_color="#C5A059"

    def main(self):

        ctk.set_appearance_mode("dark")

        root = ctk.CTk()
        root.title(title)
        
        width = 940
        height = 400

        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        
        position_x = (screen_width // 2) - (width // 2)
        position_y = (screen_height // 2) - (height // 2)
        
        root.geometry(f"{width}x{height}+{position_x}+{position_y}")
        root.resizable(False, False)

        self.results = Result(root)

        self.menu = Menu(root)
        self.menu.place(x=0, y=0)
        
        icons = Icons()
        icons.icons(self.menu)
        
        labels = Labels(self.menu, self.calibri)
        
        buttons = Buttons(
            
            self.menu, 
            self.calibri, 
            self.fg_color, 
            self.hover_color,
            self.results
            
            )

        timer = Timer(root, title, self.calibri, self.results, buttons)

        labels.labels("Malwares :", 10)
        buttons.vt_button(timer)
        buttons.mb_button(timer)
        
        labels.labels("URLs :", 140)
        buttons.url_button(timer)
        
        labels.labels("IPs :", 225)
        buttons.ip_button(timer)
        
        labels.labels("Proxy :", 310)
        buttons.proxy_button(timer)
        
        root.mainloop()

class Icons:

    def icons(self, menu):

        if menu.icons_directory.exists():

            for icon in menu.icons_directory.iterdir():

                if icon.suffix.lower() == ".ico":

                    name = icon.stem
                    img = Image.open(icon)

                    menu.icons[name] = ctk.CTkImage(
                        
                        light_image=img,
                        dark_image=img,
                        size=(24, 24)

                        )

class Menu(ctk.CTkFrame):

    def __init__(self, master):
    
        super().__init__(
            
            master, 
            fg_color="transparent", 
            width=260, 
            height=490
            
            )
        
        self.icons_directory = Path(path_join(parent)) / "icons"
        self.icons = {}

class Labels(ctk.CTkLabel):

    def __init__(self, master, font):

        self.master = master
        self.font = font

    def labels(self, text, y_position):

        ctk.CTkLabel(
            
            master=self.master, 
            text=text, 
            font=self.font
            
            ).place(x=10, y=y_position)

class Buttons:

    def __init__(self, master, font, fg_color, hover_color, results):
      
        self.master = master
        self.font = font
        self.fg_color = fg_color
        self.hover_color = hover_color
        self.results = results
        self.button_list = []
        
        self.api_malware = API.Malware(self.results, self)
        self.api_url = API.URL(self.results, self)
        self.api_ip = API.IP(self.results, self)
        self.proxy = API.Proxy(self.results, self)

    def buttons(self, text, icon_name, y_position, analysis, timer):

        button = ctk.CTkButton(

            master=self.master,
            text=text,
            width=230,
            height=40,
            font=self.font,
            corner_radius=20,
            image=self.master.icons.get(icon_name),
            fg_color=self.fg_color,
            hover_color=self.hover_color,
            compound="right",
            command=lambda: timer.get_duration(analysis)
        
            )

        button.place(x=15, y=y_position)
        self.button_list.append(button)

    def vt_button(self, timer):

        self.buttons(
            
            "VirusTotal -", 
            "virus_total", 
            45, 
            self.api_malware.virus_total,
            timer
            
            )
    
    def mb_button(self, timer):

        self.buttons(
            
            "MalwareBazaar -", 
            "malware_bazaar", 
            95, 
            self.api_malware.malware_bazaar,
            timer
            
            )

    def url_button(self, timer):

        self.buttons(
            
            "URLScan -", 
            "url_scan", 
            175, 
            self.api_url.url_scan,
            timer
            
            )

    def ip_button(self, timer):

        self.buttons(
            
            "AbuseIPDB -", 
            "abuse_ipdb", 
            260, 
            self.api_ip.abuse_ipdb,
            timer
                
            )

    def proxy_button(self, timer):

        button = ctk.CTkButton(

            master=self.master,
            text="MITMProxy -",
            width=230,
            height=40,
            font=self.font,
            corner_radius=20,
            image=self.master.icons.get("mitm_proxy"),
            fg_color=self.fg_color,
            hover_color=self.hover_color,
            compound="right",
            command=self.proxy.proxy
        
            )

        button.place(x=15, y=345)
        self.button_list.append(button)

    def toggle_state(self, state):

        for button in self.button_list:

            button.configure(state=state)

class Timer:

    def __init__(self, master, title, font, results, buttons):

        self.master = master
        self.title = title
        self.font = font
        self.results = results
        self.buttons = buttons

    def validate_duration(self, input):

        return (input == "" or input.isdigit()) and len(input) <= 3

    def submit_duration(self, timer_entry, timer_frame, analysis):

        value = timer_entry.get()

        if value and value.isdigit() and 1 <= len(value) <= 3:

            self.results.display_duration = int(value) * 1000
            timer_frame.destroy()
            self.buttons.toggle_state("normal")

            if analysis:
                
                analysis()

    def get_duration(self, analysis):

        self.buttons.toggle_state("disabled")

        timer_frame = ctk.CTkFrame(
            
            self.master, 
            width=400, 
            height=190, 
            fg_color="#242424", 
            border_width=2, 
            border_color="#C5A059",
            corner_radius=20
            
            )
        
        timer_frame.place(relx=0.64, rely=0.5, anchor="center")
        timer_frame.pack_propagate(False)

        ctk.CTkLabel(
            
            timer_frame, 
            text=self.title, 
            font=self.font
            
            ).pack(pady=(15, 0))
        
        ctk.CTkLabel(
            
            timer_frame, 
            text="How long do you want the results\nto remain displayed ?",
            justify="center"
            
            ).pack(pady=5)

        validation = (self.master.register(self.validate_duration), "%P")
        
        timer_entry = ctk.CTkEntry(
            
            timer_frame, 
            validate="key", 
            validatecommand=validation,
            justify="center"
            
            )
       
        timer_entry.pack(pady=5)
        timer_entry.focus_set()

        ctk.CTkButton(

            timer_frame, 
            text="OK", 
            command=partial(self.submit_duration, timer_entry, timer_frame, analysis), 
            corner_radius=15
            
            ).pack(pady=10)

class API:

    def scan(results, scan_method, scanner_instance, buttons):

        def run():

            buttons.toggle_state("disabled")
            results.insert("")

            for data in scan_method(scanner_instance):

                results.insert(data, append=True)
            
            def cleanup():

                results.insert("")
                buttons.toggle_state("normal")

            results.app.after(results.display_duration, cleanup)

        threading.Thread(target=run, daemon=True).start()

    class Malware:

        def __init__(self, results, buttons):

            self.results = results
            self.buttons = buttons

            self.vt_scanner = VirusTotal()
            self.vt_analyzer = VirusTotal.Analyze()

            self.mb_scanner = MalwareBazaar()
            self.mb_analyzer = MalwareBazaar.Analyze()

        def virus_total(self):

            API.scan(
                
                self.results, 
                self.vt_analyzer.vt_analyze, 
                self.vt_scanner, 
                self.buttons
                
                )

        def malware_bazaar(self):

            API.scan(
                
                self.results, 
                self.mb_analyzer.mb_analyze, 
                self.mb_scanner, 
                self.buttons
                
                )

    class URL:

        def __init__(self, results, buttons):

            self.results = results
            self.buttons = buttons

            self.url_scanner = URLScan()
            self.url_analyzer = URLScan.Analyze()

        def url_scan(self):

            API.scan(

                self.results,
                self.url_analyzer.url_analyze,
                self.url_scanner,
                self.buttons

                )

    class IP:

        def __init__(self, results, buttons):

            self.results = results
            self.buttons = buttons
            self.ai_scanner = AbuseIPDB()
            self.ai_analyzer = AbuseIPDB.Analyze()

        def abuse_ipdb(self):

            API.scan(

                self.results,
                self.ai_analyzer.ai_analyze,
                self.ai_scanner,
                self.buttons

                )

    class Proxy:

        def __init__(self, results, buttons):

            self.results = results
            self.buttons = buttons

        def proxy(self):

            threading.Thread(target=mitm_proxy, daemon=True).start()

class Result:

    def __init__(self, app):
        
        self.app = app
        self.display_duration = 0
        self.textbox = ctk.CTkTextbox(

            master=app,
            width=660,
            height=380,
            corner_radius=25,
            border_width=5,
            state="disabled"

            )
        
        self.textbox.place(x=270, y=10)

        self.textbox.bind("<Button-1>", self.clipboard)
        self.app.focus_set()

    def insert(self, data, append=False):

        def update():

            self.textbox.configure(state="normal")

            if not append:

                self.textbox.delete("1.0", "end")

            self.textbox.insert("end", str(data))
            self.textbox.yview_moveto(0)
            self.textbox.configure(state="disabled")

        self.app.after(0, update)

    def clipboard(self, event):

        content = self.textbox.get("1.0", "end-1c")

        if content.strip():

            self.app.clipboard_clear()
            self.app.clipboard_append(content)

if __name__ == "__main__":

    try:

        ping_connection = requests.get("https://google.com", timeout=5)

        if ping_connection.status_code == 200:

            app = PySecurity()
            app.main()

    except requests.ConnectionError:

        showwarning(title=title, message="To use PySecurity, you must have an Internet connection !")