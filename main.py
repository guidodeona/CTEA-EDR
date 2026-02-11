import logging
from dashboard.cli import run_cli

if __name__ == "__main__":
    run_cli()
    

logging.basicConfig(
    filename="logs/ctea.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
