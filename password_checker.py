# Password Strength Analyzer - Week 03

# ITIA 1510 - Cybersecurity Automation

# Set the number of passwords to audit in this batch.

batch_size = 3
count = 0

# These counters are initialized before the loop so they can track

# results across all passwords instead of resetting for each password.

total_pass = 0
total_fail = 0
critical_count = 0

# Process each password until the batch size has been reached.

while count < batch_size:

```
# Collect information about the account and password.
account = input("Enter the account or system: ")

# Username is collected for the username-match security check.
username = input("Enter the username: ")

# Collect the password that will be analyzed.
password = input("Enter the password: ")

# Collect the rotation interval and convert it to an integer.
rotation_interval = int(input("Enter the password rotation interval in months: "))

# Calculate the password length.
password_length = len(password)

# Calculate a simple length score.
length_score = password_length * 10

# Calculate the number of password rotations over three years.
rotations_3yr = 36 // rotation_interval

# Classify the password based on its length.
if password_length < 8:
    length_verdict = "WEAK -- does not meet minimum length requirements"
elif password_length <= 11:
    length_verdict = "MODERATE -- meets minimum but falls short of NIST recommendations"
elif password_length <= 14:
    length_verdict = "GOOD -- acceptable length for most systems"
else:
    length_verdict = "STRONG -- meets NIST SP 800-63B recommendations"

# Start with False, then use a for loop to check each character for a digit.
# This is better than the Week 02 version because it checks all digits
# without needing nine separate or operators.
has_digit = False
for char in password:
    if char in '0123456789':
        has_digit = True

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

# Display the password audit report for the current password.
print("========================================")
print(f"   PASSWORD AUDIT REPORT  ({count + 1} of {batch_size})")
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

# Track passwords that match their username as CRITICAL findings.
if not_username is False:
    print("CRITICAL -- password must not match username.")
    critical_count += 1

print("----------------------------------------")

# Update the batch PASS or FAIL counter.
if overall_pass:
    print("OVERALL: PASS -- password meets all checked criteria")
    total_pass += 1
else:
    print("OVERALL: FAIL -- see findings above")
    total_fail += 1

print("========================================")

# Increase the count so the while loop eventually reaches the batch size.
count += 1
```

# Display the summary after all passwords have been processed.

print("========================================")
print("   BATCH AUDIT SUMMARY")
print("========================================")
print(f"Passwords audited: {batch_size}")
print(f"Passed:            {total_pass}")
print(f"Failed:            {total_fail}")
print(f"Critical flags:    {critical_count}")
print("----------------------------------------")
print("NOTE: Input is still hardcoded -- file reading coming in Week 08.")
print("========================================")
