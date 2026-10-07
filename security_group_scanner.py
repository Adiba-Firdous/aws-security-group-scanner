import argparse
import boto3

MOCK_GROUPS = [
    {
        "GroupId": "sg-demo-web",
        "GroupName": "web-server-sg",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
        ],
    },
    {
        "GroupId": "sg-demo-db",
        "GroupName": "database-sg",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "IpRanges": [{"CidrIp": "10.0.1.0/24"}],
            }
        ],
    },
]


def scan_security_groups(groups):
    findings = []

    for group in groups:
        for permission in group.get("IpPermissions", []):
            for ip_range in permission.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    findings.append({
                        "group_id": group["GroupId"],
                        "group_name": group["GroupName"],
                        "protocol": permission.get("IpProtocol"),
                        "from_port": permission.get("FromPort"),
                        "to_port": permission.get("ToPort"),
                        "cidr": "0.0.0.0/0",
                    })

    return findings


def print_findings(findings):
    if not findings:
        print("No overly permissive rules found.")
        return

    print(f"Found {len(findings)} overly permissive rule(s).")
    print()

    for finding in findings:
        print(f"Security Group : {finding['group_name']}")
        print(f"Group ID       : {finding['group_id']}")
        print(f"Protocol       : {finding['protocol']}")
        print(f"Ports          : {finding['from_port']}-{finding['to_port']}")
        print(f"CIDR           : {finding['cidr']}")
        print("Risk           : Open to the entire IPv4 internet")
        print("Recommendation : Restrict access to a trusted IP or private CIDR.")
        print("-" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="AWS Security Group Scanner"
    )

    parser.add_argument(
        "--mock",
        action="store_true",
        help="Run without AWS credentials using sample data",
    )

    parser.add_argument(
        "--region",
        default="ap-south-1",
        help="AWS region",
    )

    args = parser.parse_args()

    if args.mock:
        print("AWS Security Group Scanner - MOCK MODE")
        print("=" * 60)
        findings = scan_security_groups(MOCK_GROUPS)
        print_findings(findings)
        return

    ec2 = boto3.client("ec2", region_name=args.region)
    response = ec2.describe_security_groups()

    findings = scan_security_groups(
        response.get("SecurityGroups", [])
    )

    print_findings(findings)


if __name__ == "__main__":
    main()