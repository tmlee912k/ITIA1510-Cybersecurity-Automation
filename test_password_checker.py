# Week 06 Unit Tests
# ITIA 1510 - Cybersecurity Automation

from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    known_breached,
    policy
)


# Test check_length with a weak password.
length_ok, length_verdict = check_length("abcd", policy)
assert length_ok == False
print(
    "PASS: check_length correctly identified weak password "
    "(length_ok = False)"
)


# Test check_length with a strong password.
length_ok, length_verdict = check_length("abcdefghijklmnop", policy)
assert length_ok == True
print(
    "PASS: check_length correctly identified strong password "
    "(length_ok = True)"
)


# Test check_digit with no digits.
has_digit = check_digit("password")
assert has_digit == False
print(
    "PASS: check_digit correctly returned False "
    "for password with no digits"
)


# Test check_digit with a digit.
has_digit = check_digit("password1")
assert has_digit == True
print(
    "PASS: check_digit correctly returned True "
    "for password containing a digit"
)


# Test check_username when password matches username.
not_username = check_username("dylan", "dylan")
assert not_username == False
print(
    "PASS: check_username correctly returned False "
    "when password matches username"
)


# Test check_username when password differs.
not_username = check_username("password123", "dylan")
assert not_username == True
print(
    "PASS: check_username correctly returned True "
    "when password differs from username"
)


# Test check_rotation with an 18-month interval.
rotation_ok, rotation_verdict = check_rotation(18, policy)
assert rotation_ok == False
print(
    "PASS: check_rotation correctly returned False "
    "for 18-month interval"
)


# Test check_rotation with a 6-month interval.
rotation_ok, rotation_verdict = check_rotation(6, policy)
assert rotation_ok == True
print(
    "PASS: check_rotation correctly returned True "
    "for 6-month interval"
)


# Test the strong password length policy.
assert policy["strong_length"] == 15
print(
    "PASS: policy correctly sets strong_length to 15"
)


# Test that the digit requirement exists in the policy.
assert "require_digit" in policy
print(
    "PASS: policy contains the require_digit setting"
)


# Test check_breach with a known breached password.
not_breached = check_breach("password123", known_breached)
assert not_breached == False
print(
    "PASS: check_breach correctly identified a breached password"
)


# Test check_breach with a password not in the breach list.
not_breached = check_breach("Blue-Harbor-72-Lantern", known_breached)
assert not_breached == True
print(
    "PASS: check_breach correctly accepted a password "
    "not in the breach list"
)


print("----------------------------------------")
print("All 12 tests passed.")
```
