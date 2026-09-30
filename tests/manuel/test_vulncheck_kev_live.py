from sentinel.enrichers.vulncheck_kev.client import VulnCheckKEVClient


def main() -> None:
    client = VulnCheckKEVClient()

    try:
        catalog = client.load()

        print(f"VulnCheck KEV chargé : {len(catalog)} CVE")

        if not catalog:
            print("ATTENTION : le catalogue est vide.")
            return

        first_cve, vulnerability = next(
            iter(catalog.items()),
        )

        print()
        print(f"CVE testé              : {first_cve}")
        print(f"Vendor                 : {vulnerability.vendor}")
        print(f"Product                : {vulnerability.product}")
        print(
            f"Vulnerability name     : {vulnerability.vulnerability_name}",
        )
        print(
            f"Known ransomware       : {vulnerability.known_ransomware}",
        )
        print(
            "Reported by canaries   : "
            f"{vulnerability.reported_exploited_by_canaries}",
        )
        print(
            f"Date added             : {vulnerability.date_added}",
        )

    finally:
        client.close()


if __name__ == "__main__":
    main()
