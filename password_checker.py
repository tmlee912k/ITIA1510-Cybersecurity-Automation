# Password Strength Analyzer - Week 05
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


def check_length(password):
    """
    Checks the password length and returns whether it passes
    and the correct length classification.
    """

    password_length = len(password)

    # Classify the password based on its length.
    if password_length < 8:
        length_verdict = "WEAK -- does not meet minimum length requirements"
    elif password_length <= 11:
        length_verdict = (
            "MODERATE -- meets minimum but falls short of NIST recommendations"
        )
    elif password_length <= 14:
        length_verdict = "GOOD -- acceptable length for most systems"
    else:
        length_verdict = (
            "STRONG -- meets NIST SP 800-63B recommendations"
        )

    # The password must be at least 15 characters long.
    length_ok = password_length >= 15

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


def check_rotation(rotation_interval):
    """
    Checks the password rotation interval.
    Returns whether the interval passes and its classification.
    """

    # Rotation intervals longer than 12 months receive a warning.
    if rotation_interval > 12:
        rotation_verdict = (
            "WARNING -- rotation interval exceeds recommended maximum of 12 months"
        )
    elif rotation_interval >= 6:
        rotation_verdict = (
            "ACCEPTABLE -- rotation interval within recommended range"
        )
    else:
        rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

    rotation_ok = rotation_interval <= 12

    return rotation_ok, rotation_verdict


def check_breach(password, known_breached):
    """
    Checks whether the password appears in the known breach list.
    Returns True when the password is not breached.
    """

    # Using "in" checks the entire list for a matching item without
    # manually walking through it with a for loop.
    not_breached = password not in known_breached

    return not_breached


def audit_password(
    account,
    username,
    password,
    rotation_interval,
    known_breached
):
    """
    Audits one password using the checking functions.
    Prints the report and returns pass, fail, and critical results.
    """

    password_length = len(password)
    length_score = password_length * 10
    rotations_3yr = 36 // rotation_interval

    # Call the checking functions.
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)
    not_breached = check_breach(password, known_breached)

    # A password passes only when all required checks pass.
    overall_pass = (
        length_ok
        and has_digit
        and not_username
        and not_breached
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


# The main guard prevents the credential list from running during testing.
if __name__ == "__main__":

    # Each inner list stores account, username, password, and rotation interval.
    credentials = [
        ["Gmail", "jsmith", "password123", 12],
        ["SSH Server", "jsmith", "jsmith", 24],
        ["VPN", "jsmith", "Tr0ub4dor&3correct", 3],
        ["Company Email", "jsmith", "summer2024!", 6],
        ["GitHub", "jsmith", "Blue-Harbor-72-Lantern", 6],
    ]

    total_pass = 0
    total_fail = 0
    critical_count = 0

    failed_accounts = []
    critical_accounts = []

    # Loop through each credential record in the list.
    for count in range(len(credentials)):

        credential = credentials[count]

        account = credential[0]
        username = credential[1]
        password = credential[2]
        rotation_interval = credential[3]

        audit_password.count = count
        audit_password.batch_size = len(credentials)

        passed, failed, critical = audit_password(
            account,
            username,
            password,
            rotation_interval,
            known_breached
        )

        total_pass += passed
        total_fail += failed
        critical_count += critical

        # Store account names so they can be printed in the final summary.
        if failed == 1:
            failed_accounts.append(account)

        if critical == 1:
            critical_accounts.append(account)

    print("========================================")
    print("   BATCH AUDIT SUMMARY")
    print("========================================")
    print(f"Credentials audited: {len(credentials)}")
    print(f"Passed:              {total_pass}")
    print(f"Failed:              {len(failed_accounts)}")
    print("----------------------------------------")
    print(f"Failed accounts:     {', '.join(failed_accounts)}")
    print(f"Critical flags:      {len(critical_accounts)}")
    print(f"Critical accounts:   {', '.join(critical_accounts)}")
    print("----------------------------------------")
    print(
        "NOTE: Breach list and credentials are hardcoded -- "
        "file reading coming in Week 08."
    )
    print("========================================")
