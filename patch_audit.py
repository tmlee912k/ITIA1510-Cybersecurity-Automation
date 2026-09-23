"""
Week 06 INDIVIDUAL ASSIGNMENT -- Patch Compliance Audit
ITIA 1510 Cybersecurity Automation

Topic: lists, from Week 05, and everything before them. if / elif / else,
for loops, functions that return values, and debugging. No dictionaries.

This program reads the patch inventory, gives every host a status against the
patch policy, and reports how much of the network is inside that policy.

THE POLICY
   Criticality 3 (domain controllers, databases)   patch within 14 days
   Criticality 2 (servers)                          patch within 30 days
   Criticality 1 (workstations, kiosks, printers)   patch within 60 days

   COMPLIANT   days since patch is no more than the limit
   OVERDUE     past the limit, but no more than twice the limit
   CRITICAL    more than twice the limit
   EXEMPT      the host is on the signed exception list, whatever its numbers say
   INVALID     the record cannot be trusted: days below 0, or a criticality
               that is not 1, 2 or 3

The inventory and the section headings are already written. Work through the
15 numbered TODOs in order. Two of the functions are finished and wrong, and
fixing them is part of the job.

Run the file before changing anything. It works, but every answer is wrong,
because every function still returns a placeholder.

The host names are invented.
"""

# The inventory is three PARALLEL LISTS. Position 0 in each list describes the
# same host, position 1 the next host, and so on.
HOSTS = [
    "dc-01", "dc-02", "web-01", "web-02", "db-01", "mail-01", "file-01",
    "hr-laptop-07", "kiosk-03", "lab-sandbox-01", "lab-sandbox-02",
    "print-01", "vpn-01",
]
DAYS_SINCE_PATCH = [9, 31, 12, 45, 95, 30, 61, 130, 58, 400, -1, -1, 20]
CRITICALITY = [3, 3, 2, 2, 3, 2, 1, 1, 1, 1, 1, 1, 0]

# Hosts with a signed exception. They are left out of the compliance rate.
EXEMPT = ["lab-sandbox-01", "lab-sandbox-02"]

# The order the summary prints in.
STATUS_ORDER = ["COMPLIANT", "OVERDUE", "CRITICAL", "EXEMPT", "INVALID"]


# ---------------------------------------------------------------------------
# One host at a time
# ---------------------------------------------------------------------------

def patch_limit(criticality):
    """Return the number of days the policy allows: 14, 30 or 60."""
    # TODO 1
    #   Criticality 3 gets 14 days, criticality 2 gets 30, anything else 60.
    if criticality == 3:
        return 14
    elif criticality == 2:
        return 30
    return 60


def is_valid_record(days, criticality):
    """True when days is 0 or more AND criticality is 1, 2 or 3."""
    # TODO 2
    #   One return statement. Say the rule in English before writing it, and
    #   decide where it needs and, and where it needs or.

    if days >= 0 and criticality in [1,2,3]:
        return True
    else:
        return False


def patch_status(host, days, criticality, exempt):
    """Return 'EXEMPT', 'INVALID', 'COMPLIANT', 'OVERDUE' or 'CRITICAL'."""
    # TODO 3
    #   Build this out of is_valid_record and patch_limit. It should not
    #   contain the numbers 14, 30 or 60.
    #   The order of the branches matters. lab-sandbox-02 has a broken record
    #   AND a signed exception. The policy says which one wins.

    if host in exempt:
        return 'EXEMPT'
    
    isValid = is_valid_record(days,criticality)
    if isValid == False:
        return "INVALID"

    theLimit = patch_limit(criticality)
    if theLimit <= theLimit:
        return 'COMPLIANT'
    elif theLimit <= theLimit * 2:
        return 'OVERDUE'

    return 'CRITICAL'


def days_overdue(days, criticality):
    """Return how many days past the limit a host is, or 0 when it is not."""
    # TODO 4
    #   Never return a negative number.

    overdue = days - patch_limit(criticality)

    if overdue > 0:
        return overdue
    else:
        return  0


# ---------------------------------------------------------------------------
# The whole inventory
# ---------------------------------------------------------------------------

def build_statuses(hosts, days, crits, exempt):
    """Return a new list holding the status of every host, in the same order."""
    # TODO 5
    #   The three lists are parallel, so loop over the POSITIONS with
    #   range(len(hosts)) and use the position to reach into all three.
    #   Append each status to a new list and return the list.
    #   Remember what append() returns before writing  x = x.append(y).

    statuses = []

    for i in range(len(host
    return []


def count_status(statuses, wanted):
    """Return how many entries in statuses equal wanted."""
    # TODO 6
    #   Write the loop and the counter. Do not use the .count() method.
    return 0


def hosts_with_status(hosts, statuses, wanted):
    """Return a list of the host names whose status equals wanted."""
    # TODO 7
    #   hosts and statuses are parallel lists, the same way the inventory is.
    return []


def remove_exempt(hosts, exempt):
    """Return a copy of hosts with every exempt host taken out."""
    # TODO 8 -- DEBUG
    #   This function is finished and it is wrong. The inventory holds 13
    #   hosts and 2 are exempt, so it should return 11. It returns 12.
    #   Set a breakpoint, step through the loop and watch remaining and host.
    #   Find out which host survives and why, then fix the function.
    remaining = hosts[:]
    for host in remaining:
        if host in exempt:
            remaining.remove(host)
    return remaining


def average_days(days, statuses):
    """Return the average days since patch, leaving out EXEMPT and INVALID
    hosts, rounded to 1 decimal place."""
    # TODO 9 -- DEBUG
    #   This function is finished and it is wrong in TWO places. The right
    #   answer for this inventory is 52.3. Work the average out by hand for
    #   the first three hosts, then step through and find where the function
    #   disagrees with you. It cannot be tested until TODO 5 is done.
    total = 0
    for i in range(1, len(statuses)):
        if statuses[i] != "EXEMPT" and statuses[i] != "INVALID":
            total = total + days[i]
    return round(total / len(days), 1)


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------

# The report runs only when this file is run directly, so the test file can
# import the functions above without the report printing.
if __name__ == "__main__":
    statuses = build_statuses(HOSTS, DAYS_SINCE_PATCH, CRITICALITY, EXEMPT)

    print("=" * 66)
    print("PATCH COMPLIANCE AUDIT")
    print("=" * 66)
    print("Hosts in the inventory:   " + str(len(HOSTS)))
    print("Hosts that are audited:   " + str(len(remove_exempt(HOSTS, EXEMPT))))

    print()
    print("-" * 66)
    print("HOST".ljust(18) + "CRIT".ljust(6) + "DAYS".ljust(7) + "STATUS".ljust(11) + "OVERDUE")
    print("-" * 66)
    # TODO 10
    #   Print one line for every host, lined up under the headings above, using
    #   the same .ljust() widths the heading line uses. Numbers need str()
    #   first. The last column is days_overdue for that host.

    print()
    print("-" * 66)
    print("SUMMARY")
    print("-" * 66)
    # TODO 11
    #   Walk STATUS_ORDER and print each status with its count from
    #   count_status, so the summary always prints in the same order and a
    #   status nobody has still shows 0. Use .ljust(12) on the status.

    # TODO 12
    #   The compliance rate is the COMPLIANT hosts as a percentage of the hosts
    #   that can be judged: every host that is not EXEMPT and not INVALID.
    #   Round it to 1 decimal place.
    rate = 0.0

    # TODO 13
    #   The verdict is PASS at a rate of 90 or above, AT RISK at 70 or above,
    #   and FAIL below that. The order the branches are tested in matters.
    verdict = "UNKNOWN"

    print()
    print("Compliance rate:          " + str(rate) + "%")
    print("Audit verdict:            " + verdict)
    print("Average days since patch: " + str(average_days(DAYS_SINCE_PATCH, statuses)))

    print()
    print("-" * 66)
    print("ESCALATION QUEUE")
    print("-" * 66)
    # TODO 14
    #   Build one list named queue: the CRITICAL hosts in sorted order,
    #   followed by the OVERDUE hosts in sorted order. Use hosts_with_status
    #   and sorted(), and join the two lists with +.
    queue = []

    # TODO 15
    #   The patch team takes 3 tickets a day. Print the first 3 hosts in queue
    #   under TODAY and whatever is left under TOMORROW, each host indented
    #   3 spaces. Use slices. Do not write a loop that counts to 3.
    print("TODAY")
    print("TOMORROW")

    print("=" * 66)
