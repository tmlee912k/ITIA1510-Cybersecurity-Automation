# Password Strength Analyzer - Week 04
# ITIA 1510 - Cybersecurity Automation


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


def audit_password(account, username, password, rotation_interval):
    """
    Audits one password using the four checking functions.
    Prints the report and returns pass, fail, and critical results.
    """

    password_length = len(password)
    length_score = password_length * 10
    rotations_3yr = 36 // rotation_interval

    # Call the four checking functions.
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)

    # A password passes only when all checks pass.
    overall_pass = (
        length_ok
        and has_digit
        and not_username
        and rotation_ok
    )

    passed = 0
    failed = 0
    critical = 0

    print("========================================")
    print(f"   PASSWORD AUDIT REPORT  ({audit_password.count + 1} of {audit_password.batch_size})")
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
    print(f"Rotation verdict:  {rotation_verdict}")

    # A matching username and password is a critical finding.
    if not_username is False:
        print("CRITICAL -- password must not match username.")
        critical = 1

    print("----------------------------------------")

    if overall_pass:
        print("OVERALL: PASS -- password meets all checked criteria")
        passed = 1
    else:
        print("OVERALL: FAIL -- see findings above")
        failed = 1

    print("========================================")

    return passed, failed, critical


# The main guard prevents the input loop from running during testing.
if __name__ == "__main__":

    batch_size = 3
    count = 0

    total_pass = 0
    total_fail = 0
    critical_count = 0

    # Process each password until the batch size is reached.
    while count < batch_size:

        account = input("Enter the account or system: ")
        username = input("Enter the username: ")
        password = input("Enter the password: ")
        rotation_interval = int(
            input("Enter the password rotation interval in months: ")
        )

        # Pass the password information to the audit function.
        audit_password.count = count
        audit_password.batch_size = batch_size

        passed, failed, critical = audit_password(
            account,
            username,
            password,
            rotation_interval
        )

        # Add the returned results to the batch counters.
        total_pass += passed
        total_fail += failed
        critical_count += critical

        count += 1

    print("========================================")
    print("   BATCH AUDIT SUMMARY")
    print("========================================")
    print(f"Passwords audited: {batch_size}")
    print(f"Passed:            {total_pass}")
    print(f"Failed:            {total_fail}")
    print(f"Critical flags:    {critical_count}")
    print("----------------------------------------")
    print(
        "NOTE: Input is still hardcoded -- file reading coming in Week 08."
    )
    print("========================================")
