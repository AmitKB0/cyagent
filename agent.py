import socket
import subprocess
import time


class CyberSecurityAgent:

    def __init__(self):
        self.target = None
        self.results = {}

    def understand_request(self, request):

        print("\n[AGENT] Understanding your request...")

        words = request.split()

        if len(words) == 0:
            return None

        self.target = words[-1]

        print(f"[AGENT] Target identified: {self.target}")

        return self.target

    def decide_actions(self, request):

        print("\n[AGENT] Deciding what actions are required...")

        request = request.lower()

        actions = []

        if "dns" in request:
            actions.append("dns")

        if "ping" in request:
            actions.append("ping")

        if "port" in request:
            actions.append("ports")

        if "analyze" in request:
            actions = [
                "dns",
                "ping",
                "ports"
            ]

        if len(actions) == 0:
            actions = [
                "dns",
                "ping",
                "ports"
            ]

        print("[AGENT] I have decided to use:")

        for action in actions:
            print(f"        -> {action}")

        return actions

    def dns_lookup(self):

        print("\n[TOOL] Running DNS lookup...")

        try:

            ip = socket.gethostbyname(self.target)

            self.results["ip"] = ip

            print(f"[TOOL] IP address: {ip}")

        except socket.gaierror:

            self.results["ip"] = None

            print("[TOOL] DNS lookup failed.")

    def ping_test(self):

        print("\n[TOOL] Testing connectivity...")

        try:

            start_time = time.time()

            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", self.target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            end_time = time.time()

            if result.returncode == 0:

                latency = round(
                    (end_time - start_time) * 1000,
                    2
                )

                self.results["reachable"] = True
                self.results["latency"] = latency

                print("[TOOL] Host is reachable.")
                print(f"[TOOL] Approx latency: {latency} ms")

            else:

                self.results["reachable"] = False

                print("[TOOL] Host did not respond.")

        except Exception as error:

            self.results["reachable"] = False

            print(f"[TOOL] Ping error: {error}")

    def port_check(self):

        print("\n[TOOL] Checking common ports...")

        ports = {
            22: "SSH",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL"
        }

        open_ports = []

        ip = self.results.get("ip")

        if ip is None:

            print("[TOOL] No IP address available.")

            return

        for port, service in ports.items():

            try:

                sock = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                )

                sock.settimeout(0.5)

                result = sock.connect_ex(
                    (ip, port)
                )

                sock.close()

                if result == 0:

                    print(
                        f"[TOOL] Port {port} OPEN ({service})"
                    )

                    open_ports.append(
                        (port, service)
                    )

            except Exception:

                pass

        self.results["open_ports"] = open_ports

    def analyze_results(self):

        print("\n[AGENT] Analyzing results...")

        findings = []

        if self.results.get("ip"):

            findings.append(
                "DNS resolution successful."
            )

        else:

            findings.append(
                "DNS resolution failed."
            )

        if self.results.get("reachable"):

            latency = self.results.get(
                "latency",
                0
            )

            if latency > 200:

                findings.append(
                    "Host is reachable but latency is high."
                )

            else:

                findings.append(
                    "Host is reachable."
                )

        else:

            findings.append(
                "Host did not respond to ping."
            )

        open_ports = self.results.get(
            "open_ports",
            []
        )

        if len(open_ports) == 0:

            findings.append(
                "No tested ports were found open."
            )

        else:

            for port, service in open_ports:

                findings.append(
                    f"{service} detected on port {port}."
                )

        self.results["findings"] = findings

    def generate_report(self):

        print("\n")
        print("=" * 50)
        print("       CYBERSECURITY AGENT REPORT")
        print("=" * 50)

        print(f"\nTarget: {self.target}")

        print("\n--- NETWORK INFORMATION ---")

        if self.results.get("ip"):

            print(
                f"IP Address: {self.results['ip']}"
            )

        else:

            print("IP address unavailable.")

        print("\n--- CONNECTIVITY ---")

        if self.results.get("reachable"):

            print("Status: Reachable")
            print(
                f"Latency: {self.results['latency']} ms"
            )

        else:

            print("Status: No response")

        print("\n--- OPEN PORTS ---")

        open_ports = self.results.get(
            "open_ports",
            []
        )

        if open_ports:

            for port, service in open_ports:

                print(
                    f"Port {port} -> {service}"
                )

        else:

            print("No tested ports are open.")

        print("\n--- AGENT FINDINGS ---")

        for finding in self.results.get(
            "findings",
            []
        ):

            print(f"* {finding}")

        print("\n" + "=" * 50)

    def run(self, request):

        print("\n" + "=" * 50)

        target = self.understand_request(request)

        if target is None:

            print("[AGENT] I could not understand the request.")

            return

        actions = self.decide_actions(request)

        for action in actions:

            if action == "dns":

                self.dns_lookup()

            elif action == "ping":

                self.ping_test()

            elif action == "ports":

                self.port_check()

        self.analyze_results()

        self.generate_report()


def main():

    agent = CyberSecurityAgent()

    print("\n===================================")
    print("     CYBERSECURITY ASSISTANT")
    print("===================================")

    print("\nExamples:")
    print("Analyze example.com")
    print("Check DNS example.com")
    print("Check ping example.com")
    print("Check ports example.com")

    while True:

        request = input(
            "\nCyberSec Agent > "
        )

        if request.lower() in [
            "exit",
            "quit"
        ]:

            print("\nAgent shutting down...")
            break

        if request.strip() == "":
            continue

        agent.run(request)


if __name__ == "__main__":
    main()