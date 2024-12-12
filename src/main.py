import argparse


def run():
    # Parsing
    parser = argparse.ArgumentParser(
        description="This script executes a defensive script is executed to intercept scan SYN, DDOS and brute force attack on the honeypot.")
    parser.add_argument('--mail', "-mail",nargs='?', type=str,
                        help='On which email to send the report', required=True)
    parser.add_argument('--key', "-key",nargs='?', type=str,
                        help='Key to encrypt the mail', required=True)
    args = parser.parse_args()
    print(f"Mail: {args.mail}")
    print(f"Key: {args.key}")


if __name__ == "__main__":
    run()
