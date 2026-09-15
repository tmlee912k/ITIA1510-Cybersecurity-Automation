# Password Strength Analyzer
# ITIA 1510 - Cybersecurity Automation
# Week 04 - Functions and Unit Testing


def check_length(password):
    """Checks password length against NIST thresholds.
    Takes a password string.
    Returns (length_ok: bool, length_verdict: str).
    """

    password_length = len(password)

    # Check the password length and classify it.
    if password_length < 8:
        length_ok = False
        length_verdict = "Too Short"
    elif password_length < 16:
        length_ok = True
        length_verdict = "Acceptable"
    else:
        length_ok = True
        length_verdict = "Strong"

    return length_ok, length_verdict


def check_digit(password):
    """Checks whether a password contains a digit.
    Takes a password string.
    Returns has_digit as a Boolean.
    """

    has_digit = False

    # Loop through each character to look for a digit.
    for char in password:
        if char in "0123456789":
            has_digit = True
            break

    return has_digit


def check_username(password, username):
    """Checks whether the password differs from the username.
    Takes a password and username string.
    Returns not_username as a Boolean.
    """

    # Passwords should not be the same as the username.
    not_username = password != username

    return not_username


def check_rotation(rotation_interval):
    """Checks the password rotation interval.
    Takes rotation_interval as an integer in months.
    Returns (rotation_ok: bool, rotation_verdict: str).
    """

    # A rotation interval of 12 months or fewer passes.
    if rotation_interval <= 12:
        rotation_ok = True
        rotation_verdict = "Acceptable"
    else:
        rotation_ok = False
        rotation_verdict = "Too Long"

    return rotation_ok, rotation_verdict


def audit_password(account, username, password, rotation_interval):
    """Audits one password using the four checking functions.
    Takes account, username, password, and rotation_interval.
    Returns (passed, failed, critical) as 1 or 0 counters.
    """

    # Call each function to check the password.
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)

    password_length = len(password)

    # Determine the number of failed checks.
    failed_checks = 0

    if not length_ok:
        failed_checks += 1

    if not has_digit:
        failed_checks += 1

    if not not_username:
        failed_checks += 1

    if not rotation_ok:
        failed_checks += 1

    # Determine the overall result.
    if failed_checks == 0:
        passed = 1
        failed = 0
        critical = 0
        overall = "PASS"
    else:
        passed = 0
        failed = 1
        critical = 0
        overall = "FAIL"

    # Print the password audit report.
    print("----------------------------------------")
    print("Password Strength Report")
    print("----------------------------------------")
    print(f"Account: {account}")
    print(f"Username: {username}")
    print(f"Password Length: {password_length}")
    print(f"Length Verdict: {length_verdict}")
    print(f"Contains Digit: {has_digit}")
    print(f"Differs From Username: {not_username}")
    print(f"Rotation Interval: {rotation_interval} months")
    print(f"Rotation Verdict: {rotation_verdict}")
    print(f"Overall Result: {overall}")
    print("----------------------------------------")

    return passed, failed, critical


if __name__ == "__main__":
    # This block keeps the main loop from running when imported by tests.
    total_pass = 0
    total_fail = 0
    critical_count = 0

    while True:
        account = input("Enter account name (or 'quit' to exit): ")

        if account.lower() == "quit":
            break

        username = input("Enter username: ")
        password = input("Enter password: ")
        rotation_interval = int(
            input("Enter password rotation interval in months: ")
        )

        # Run the audit and accumulate the returned counters.
        passed, failed, critical = audit_password(
            account, username, password, rotation_interval
        )

        total_pass += passed
        total_fail += failed
        critical_count += critical

    # Display the batch summary.
    print("----------------------------------------")
    print("Batch Summary")
    print("----------------------------------------")
    print(f"Total Passed: {total_pass}")
    print(f"Total Failed: {total_fail}")
    print(f"Critical Count: {critical_count}")
    print("NOTE: Passwords were not stored.")
