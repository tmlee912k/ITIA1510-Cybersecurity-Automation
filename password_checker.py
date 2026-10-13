# Password Strength Analyzer - Week 07
# ITIA 1510 - Cybersecurity Automation


# Policy stays outside the main block so the tests can import it.
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True
}


def check_length(password, policy):
    """Check password length and return whether it meets policy and its verdict."""
    password_length = len(password)

    # Read thresholds from policy so the rules can be changed in one place.
    if password_length < policy["min_length"]:
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length < policy["strong_length"] - 3:
        length_verdict = (
            "MODERATE -- meets minimum but falls short of NIST recommendations"
        )
    elif password_length < policy["strong_length"]:
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_verdict = (
            "STRONG -- meets NIST SP 800-63B recommendations"
        )

    length_ok = password_length >= policy["strong_length"]
    return length_ok, length_verdict


def check_digit(password):
    """Return True if the password contains at least one digit."""
    has_digit = False

    # A for loop checks each character in the password.
    for char in password:
        if char in "0123456789":
            has_digit = True

    return has_digit


def check_username(password, username):
    """Return True if the password differs from the username."""
    # A password should not be identical to its username.
    not_username = password != username
    return not_username


def check_rotation(rotation_interval, policy):
    """Return whether the rotation interval passes policy and its verdict."""
    if rotation_interval > policy["max_rotation_months"]:
        rotation_verdict = (
            "WARNING -- rotation interval exceeds recommended maximum of "
            f"{policy['max_rotation_months']} months"
        )
    elif rotation_interval >= policy["good_rotation_months"]:
        rotation_verdict = (
            "ACCEPTABLE -- rotation interval within recommended range"
        )
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    rotation_ok = rotation_interval <= policy["max_rotation_months"]
    return rotation_ok, rotation_verdict


def check_breach(password, known_breached):
    """Return True if the password is not in the breach list."""
    # The in operator checks whether the complete password matches an item.
    not_breached = password not in known_breached
    return not_breached


def load_breached(filepath):
    """Read breached passwords from a file and return a list of strings."""
    known_breached = []

    # with automatically closes the file, even if an error occurs.
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Skip blank lines because they are not passwords.
            if line != "":
                known_breached.append(line)

    return known_breached


def load_credentials(filepath):
    """Read credentials and return a list of four-key dictionaries."""
    credentials = []

    # with closes the file automatically when the block ends.
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()

            # Skip empty lines because they do not contain account records.
            if line == "":
                continue

            fields = line.split(",")

            credentials.append({
                "account": fields[0],
                "username": fields[1],
                "password": fields[2],
                "rotation_interval": int(fields[3])
            })

    return credentials


def write_report(report_lines, filepath):
    """Write each report string to a file on its own line."""
    # Write mode creates the file or replaces its previous contents.
    with open(filepath, "w") as f:
        for line in report_lines:
            f.write(line + "\n")


def audit_password(
    account,
    username,
    password,
    rotation_interval,
    known_breached,
    policy,
    report_lines
):
    """Audit one password, append its report, and return pass/fail/critical flags."""

    password_length = len(password)
    length_score = password_length * 10
    rotations_3yr = 36 // rotation_interval

    # Run the existing Week 06 checks with the current policy.
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    not_breached = check_breach(password, known_breached)

    digit_ok = has_digit or not policy["require_digit"]
    breach_ok = not_breached or not policy["check_breach_list"]

    # A password passes only when all required checks pass.
    overall_pass = (
        length_ok
        and digit_ok
        and not_username
        and breach_ok
    )

    passed = 0
    failed = 0
    critical = 0

    # Collect report lines instead of printing them immediately.
    report_lines.append("========================================")
    report_lines.append(
        f"   PASSWORD AUDIT REPORT  "
        f"({audit_password.count + 1} of {audit_password.batch_size})"
    )
    report_lines.append("========================================")
    report_lines.append(f"Account:           {account}")
    report_lines.append(f"Username:          {username}")
    report_lines.append(f"Password length:   {password_length} characters")
    report_lines.append(f"Length score:      {length_score} points")
    report_lines.append(f"Rotation interval: {rotation_interval} months")
    report_lines.append(f"Rotations (3 yr):  {rotations_3yr}")
    report_lines.append("----------------------------------------")
    report_lines.append(f"Length verdict:    {length_verdict}")
    report_lines.append(f"Digit found:       {'YES' if has_digit else 'NO'}")
    report_lines.append(f"Username match:    {'NO' if not_username else 'YES'}")

    if not_breached:
        report_lines.append(
            "Breach check:      PASS -- password not found in known breach list"
        )
    else:
        report_lines.append(
            "Breach check:      CRITICAL -- password found in known breach list"
        )

    report_lines.append(f"Rotation verdict:  {rotation_verdict}")

    # A matching username or breached password is a critical finding.
    if not_username is False or not_breached is False:
        critical = 1

    report_lines.append("----------------------------------------")

    if overall_pass:
        report_lines.append(
            "OVERALL: PASS -- password meets all checked criteria"
        )
        passed = 1
    else:
        report_lines.append("OVERALL: FAIL -- see findings above")
        failed = 1

    report_lines.append("========================================")
    report_lines.append("")

    return passed, failed, critical


# This main guard prevents the audit from running when tests import functions.
if __name__ == "__main__":

    # Load both input files instead of hardcoding their contents.
    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")
    report_lines = []

    # Keep the Week 06 summary structure.
    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    # Audit every account loaded from credentials.txt.
    for cred in credentials:
        summary["total"] += 1

        audit_password.count = summary["total"] - 1
        audit_password.batch_size = len(credentials)

        passed, failed, critical = audit_password(
            cred["account"],
            cred["username"],
            cred["password"],
            cred["rotation_interval"],
            known_breached,
            policy,
            report_lines
        )

        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        if failed == 1:
            summary["failed_accounts"].append(cred["account"])

        if critical == 1:
            summary["critical_accounts"].append(cred["account"])

    # Append the batch summary to the same list as the account reports.
    report_lines.append("========================================")
    report_lines.append("   BATCH AUDIT SUMMARY")
    report_lines.append("========================================")
    report_lines.append(f"Credentials audited: {summary['total']}")
    report_lines.append(f"Passed:              {summary['passed']}")
    report_lines.append(f"Failed:              {summary['failed']}")
    report_lines.append("----------------------------------------")
    report_lines.append(
        f"Failed accounts:     {', '.join(summary['failed_accounts'])}"
    )
    report_lines.append(f"Critical flags:      {summary['critical']}")
    report_lines.append(
        f"Critical accounts:   {', '.join(summary['critical_accounts'])}"
    )
    report_lines.append("========================================")

    # Print and save the exact same report lines.
    for line in report_lines:
        print(line)

    write_report(report_lines, "report.txt")
