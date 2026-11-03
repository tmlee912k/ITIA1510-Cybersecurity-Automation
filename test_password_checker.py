# Week 11 Unit Tests
# ITIA 1510 - Cybersecurity Automation

import json
import os
import tempfile

from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    breach_verdicts,
    load_breached,
    load_credentials,
    policy,
    load_history,
    add_to_history,
    save_history
)

# Load the breach list and credentials for the tests.
known_breached = load_breached("breached.txt")


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


# Shared sample summary for the history tests.
sample = {
    "passed": 2,
    "failed": 3,
    "critical_accounts": ["Gmail", "SSH Server"]
}


# Test load_history when the file does not exist.
with tempfile.TemporaryDirectory() as folder:
    missing_filepath = os.path.join(folder, "missing_history.json")
    assert load_history(missing_filepath) == []
print("PASS: load_history returns an empty list for a missing file")


# Test that the first history entry is numbered 1.
history = add_to_history([], sample, 3)
assert len(history) == 1
assert history[0]["run"] == 1
assert history[0]["passed"] == 2
assert history[0]["failed"] == 3
assert history[0]["critical_accounts"] == ["Gmail", "SSH Server"]
print("PASS: add_to_history records the first run")


# Test that only the newest two runs are kept.
history = []
for i in range(3):
    history = add_to_history(history, sample, 2)
assert [entry["run"] for entry in history] == [2, 3]
print("PASS: add_to_history kept only the newest 2 runs")


# Test that saved history can be loaded back unchanged.
with tempfile.TemporaryDirectory() as folder:
    history_filepath = os.path.join(folder, "history.json")
    history = add_to_history([], sample, 3)
    save_history(history, history_filepath)
    loaded_history = load_history(history_filepath)
    assert loaded_history == history
print("PASS: save_history and load_history returned the original history")


# Week 11 Test 1: Gmail password is on the breach list.
credentials = load_credentials("credentials.txt")

result = breach_verdicts(
    "jsmith",
    credentials,
    known_breached
)

assert result["accounts"][0] == {
    "account": "Gmail",
    "on_breach_list": True
}

print(
    "PASS: breach_verdicts marked the Gmail password "
    "as on the breach list"
)


# Week 11 Test 2: Username with no accounts returns an empty list.
result = breach_verdicts(
    "nobody",
    credentials,
    known_breached
)

assert result["accounts"] == []

print(
    "PASS: breach_verdicts returned an empty accounts list "
    "for a username with no accounts"
)


# Week 11 Test 3: No passwords appear in the verdict JSON.
credentials = load_credentials("credentials.txt")

result = breach_verdicts(
    "jsmith",
    credentials,
    known_breached
)

result_json = json.dumps(result)

for credential in credentials:
    if credential["username"] == "jsmith":

        # SSH Server password equals the username, which is in the result.
        if credential["account"] != "SSH Server":
            assert credential["password"] not in result_json

print(
    "PASS: breach_verdicts does not include passwords "
    "in its JSON result"
)


print("----------------------------------------")
print("All Week 10 and Week 11 tests passed.")
