class ThreatAnalyzer:

    def __init__(self, rules):
        self.rules = rules
        self.events = []

    def add_events(self, events):
        self.events.extend(events)

    def calculate_risk(self):
        total_risk = sum(event.get("risk", 0) for event in self.events)
        return total_risk

    def evaluate(self):
        score = self.calculate_risk()

        if score >= self.rules['risk_thresholds']['high']:
            return "HIGH", score
        elif score >= self.rules['risk_thresholds']['medium']:
            return "MEDIUM", score
        else:
            return "LOW", score
