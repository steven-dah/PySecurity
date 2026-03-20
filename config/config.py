import yaml
from pathlib import Path

parent = Path(__file__).resolve().parent
path_join = lambda *args: str(Path(*args))
path_exists = lambda path: Path(path).exists()

with open(parent / "config.yaml", "r", encoding="utf-8") as config:

    config_data = yaml.safe_load(config)

title = config_data["project"]["title"]

proxy = str(parent.parent / "proxy" / "proxy.txt")
denied = str(parent.parent / "proxy" / "denied.html")