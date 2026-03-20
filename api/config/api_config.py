from pathlib import Path

import yaml

parent = Path(__file__).resolve().parent

class Configuration:

    def __init__(self, key):
        
        api_folder = parent.parent
        config_path = api_folder.parent / "config" / "config.yaml"
        
        with open(config_path, "r") as config_yaml:
            
            config = yaml.safe_load(config_yaml)

            self.title = config["project"]["title"]
            self.api_keys = api_folder / "keys" / "api_keys.env"
            
            relative_path = config["path"][key]
            self.config_path = api_folder.parent / relative_path

    def load_keys(self):

        if self.config_path.exists():
            
            with open(self.config_path, "r") as key_file:
                
                content = key_file.read()
                
                lines = content.splitlines()
                
                keys_list = []
                
                for line in lines:
                    
                    clean_key = line.strip()
                    
                    if clean_key:
                        
                        keys_list.append(clean_key)
                        
                return keys_list
        
        return []