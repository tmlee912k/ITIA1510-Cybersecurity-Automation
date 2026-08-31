# Password Strength Analyzer - Week 02
# ITIA 1510 - Cybersecurity Automation

# Collect information about the account and password.
account = input("Enter the account or system: ")

# Username is collected now because it will be used for checks in Week 02.
username = input("Enter the username: ")

# Collect the password that will be analyzed.
password = input("Enter the password: ")

# Collect the rotation interval as a string, then convert it to an integer.
rotation_interval = int(input("Enter the password rotation interval in months: "))

# Calculate the password length.
password_length = len(password)

# Calculate a simple length score.
length_score = password_length * 10

# Calculate the number of password rotations over three years.
rotations_3yr = (36 // rotation_interval)

# Classify the password based on its length.
if password_length < 8:
    length_verdict = "WEAK -- does not meet minimum length requirements"
elif password_length <= 11:
    length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
elif password_length <= 14:
    length_verdict = "GOOD -- acceptable length for most systems"
else:
    length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

# Check whether the password contains at least one digit.
has_digit = '0' in password or '1' in password or '2' in password or '3' in password or '4' in password or '5' in password or '6' in password or '7' in password or '8' in password or '9' in password

# Check that the password does not match the username.
not_username = password != username

# Classify the password rotation frequency.
if rotation_interval > 12:
    rotation_verdict = "WARNING -- rotation interval exceeds recommended maximum of 12 months"
elif rotation_interval >= 6:
    rotation_verdict = "ACCEPTABLE -- rotation interval within recommended range"
else:
    rotation_verdict = "EXCELLENT -- frequent rotation policy detected"

# A password passes only when it is long enough, has a digit,
# and does not match the username.
length_ok = password_length >= 15
overall_pass = length_ok and has_digit and not_username

# Display the password audit report.
print("========================================")
print("   PASSWORD AUDIT REPORT")
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

# Display a critical warning if the password matches the username.
if not_username is False:
    print("CRITICAL -- password must not match username.")

print("----------------------------------------")

# Display PASS only when all three Boolean checks are true.
if overall_pass:
    print("OVERALL: PASS -- password meets all checked criteria")
else:
    print("OVERALL: FAIL -- see findings above")

print("========================================")
