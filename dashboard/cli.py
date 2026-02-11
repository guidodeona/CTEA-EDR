import argparse
from Core.engine import CTEAEngine

def run_cli():
    parser = argparse.ArgumentParser(
        prog="CTEA",
        description="Cyber Threat Exposure Analyzer"
    )

    parser.add_argument(
        "command",
        choices=["scan", "daemon", "status", "version"],
        help="Comando a ejecutar"
    )

    args = parser.parse_args()
    engine = CTEAEngine()

    if args.command == "scan":
        severity, score, events = engine.run()
        print(f"\nResultado del escaneo:")
        print(f"Severidad: {severity}")
        print(f"Score: {score}")
        print(f"Eventos detectados: {len(events)}")

    elif args.command == "daemon":
        engine.run_daemon()

    elif args.command == "status":
        print("CTEA está listo para ejecutarse.")

    elif args.command == "version":
        print("CTEA v1.0 – Behavioral Threat Detection")

