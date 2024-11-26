import argparse


def run():
    # Parsing
    parser = argparse.ArgumentParser(
        description="This script executes a defensive script is executed to intercept scan SYN, DDOS and brute force attack on the honeypot.")
    parser.add_argument('--mail', "-mail",nargs='?', type=str,
                        help='On which email to send the report', required=True)
    args = parser.parse_args()
    print(args.mail)


if __name__ == "__main__":
    run()
