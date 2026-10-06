# Password Strength Analyzer - Week 06
# ITIA 1510 - Cybersecurity Automation


# This list is outside the main block so the functions and test file
# can both access it.
known_breached = [
    "password",
    "password123",
    "123456",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "sunshine"
]


# Policy is outside the main block so the functions and test file
# can both access the same rules.
policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True
}


def check_length(password, policy):
    """
    Checks the password length and returns whether it passes
    and the correct length classification.
    """

    password_length = len(password)

    # Reading the limit from policy means one change updates every
    # function instead of having the same number written multiple times.
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

    # The password must meet the strong length policy.
    length_ok = password_length >= policy["strong_length"]

    return length_ok, length_verdict


def check_digit(password):
    """
    Checks whether the password contains at least one number.
    Returns True if a digit is found, otherwise False.
    """

    # Start with False before checking each character.
    has_digit = False

    # A for loop walks through every character one at a time.
    for char in password:
        if char in "0123456789":
            has_digit = True

    return has_digit


def check_username(password, username):
    """
    Checks that the password does not match the username.
    Returns True when the password and username are different.
    """

    # A password should never be the same as the username.
    not_username = password != username

    return not_username


def check_rotation(rotation_interval, policy):
    """
    Checks the password rotation interval.
    Returns whether the interval passes and its classification.
    """

    # The maximum is read from policy so the rule can be changed in one place.
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
    """
    Checks whether the password appears in the known breach list.
    Returns True when the password is not breached.
    """

    # Using "in" checks the entire list for a matching item.
    not_breached = password not in known_breached

    return not_breached


def audit_password(
    account,
    username,
    password,
    rotation_interval,
    known_breached,
    policy
):
    """
    Audits one password using the checking functions.
    Prints the report and returns pass, fail, and critical results.
    """

    password_length = len(password)
    length_score = password_length * 10
    rotations_3yr = 36 // rotation_interval

    # Call the checking functions using the current security policy.
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    not_breached = check_breach(password, known_breached)

    # Use the policy to decide whether the digit check is required.
    digit_ok = has_digit or not policy["require_digit"]

    # Use the policy to decide whether the breach list should be checked.
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

    print("========================================")
    print(
        f"   PASSWORD AUDIT REPORT  "
        f"({audit_password.count + 1} of {audit_password.batch_size})"
    )
    print("========================================")
    print(f"Account:           {account}")
    print(f"Username:          {username}")
    print(f"Password length:   {password_length} characters")
    print(f"Length score:      {length_score} points")
    print(f"Rotation interval: {rotation_interval} months")
    print(f"Rotations (3 yr):  {rotations_3yr}")
    print("----------------------------------------")
    print(f"Length verdict:    {length_verdict}")
    print(f"Digit found:       {'YES' if has_digit else 'NO'}")
    print(f"Username match:    {'NO' if not_username else 'YES'}")

    if not_breached:
        print("Breach check:      PASS -- password not found in known breach list")
    else:
        print(
            "Breach check:      "
            "CRITICAL -- password found in known breach list"
        )

    print(f"Rotation verdict:  {rotation_verdict}")

    # A matching username or breached password is a critical finding.
    if not_username is False or not_breached is False:
        critical = 1

    print("----------------------------------------")

    if overall_pass:
        print("OVERALL: PASS -- password meets all checked criteria")
        passed = 1
    else:
        print("OVERALL: FAIL -- see findings above")
        failed = 1

    print("========================================")
    print()

    return passed, failed, critical


# The main guard prevents the credential list and audit from running during testing.
if __name__ == "__main__":

    # Each dictionary stores the credential values using descriptive field names.
    credentials = [
        {
            "account": "Gmail",
            "username": "jsmith",
            "password": "password123",
            "rotation_interval": 12
        },
        {
            "account": "SSH Server",
            "username": "jsmith",
            "password": "jsmith",
            "rotation_interval": 24
        },
        {
            "account": "VPN",
            "username": "jsmith",
            "password": "Tr0ub4dor&3correct",
            "rotation_interval": 3
        },
        {
            "account": "Company Email",
            "username": "jsmith",
            "password": "summer2024!",
            "rotation_interval": 6
        },
        {
            "account": "GitHub",
            "username": "jsmith",
            "password": "Blue-Harbor-72-Lantern",
            "rotation_interval": 6
        }
    ]

    # One summary dictionary replaces the separate pass, fail, and critical counters.
    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": []
    }

    # Loop through each credential dictionary.
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
            policy
        )

        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical

        # Store failed account names for the final report.
        if failed == 1:
            summary["failed_accounts"].append(cred["account"])

        # Store critical account names for the final report.
        if critical == 1:
            summary["critical_accounts"].append(cred["account"])

    print("========================================")
    print("   BATCH AUDIT SUMMARY")
    print("========================================")
    print(f"Credentials audited: {summary.get('total', 0)}")
    print(f"Passed:              {summary.get('passed', 0)}")
    print(f"Failed:              {summary.get('failed', 0)}")
    print("----------------------------------------")
    print(
        f"Failed accounts:     "
        f"{', '.join(summary.get('failed_accounts', []))}"
    )
    print(f"Critical flags:      {summary.get('critical', 0)}")
    print(
        f"Critical accounts:   "
        f"{', '.join(summary.get('critical_accounts', []))}"
    )
    print("----------------------------------------")
    print(
        "NOTE: Credentials and breach list are hardcoded -- "
        "file reading coming in Week 07."
    )
    print("========================================")
```
