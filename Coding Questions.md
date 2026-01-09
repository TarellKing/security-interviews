# Python Coding Practice - Log Analysis

Practice Python coding for security/log analysis interviews. Each section has a dataset and questions to answer. Try solving them before checking the solutions.

**Key Skills:** Dictionary counting, sets for uniqueness, `.get()` method, nested JSON access, looping through nested arrays, filtering data.

---

## Dataset 1: Authentication Logs

```python
auth_logs = [
    {"user": "alice", "action": "login", "status": "success", "src_ip": "192.168.1.10"},
    {"user": "bob", "action": "login", "status": "failed", "src_ip": "10.0.5.22"},
    {"user": "alice", "action": "login", "status": "success", "src_ip": "192.168.1.10"},
    {"user": "bob", "action": "login", "status": "failed", "src_ip": "10.0.5.22"},
    {"user": "bob", "action": "login", "status": "failed", "src_ip": "10.0.5.22"},
    {"user": "", "action": "login", "status": "failed", "src_ip": "203.0.113.5"},
    {"user": "charlie", "action": "login", "status": "success", "src_ip": None},
]
```

### Q1: Count login attempts per user
**Task:** Print each user and their total login attempt count. Skip empty usernames.

**Expected Output:**
```
alice 2
bob 3
charlie 1
```

<details>
<summary>Click for solution</summary>

```python
def count_logins(auth_logs):
    login_counts = {}

    for log in auth_logs:
        user = log.get("user")
        action = log.get("action")

        if not user:  # Skip empty users
            continue

        if action != "login":  # Only count logins
            continue

        login_counts[user] = login_counts.get(user, 0) + 1

    for user, count in login_counts.items():
        print(user, count)

count_logins(auth_logs)
```

**Key concepts:** Dict for counting, `.get()` with default, filtering
</details>

---

### Q2: Find users with 3+ failed logins
**Task:** Print users who had 3 or more failed login attempts and their count.

**Expected Output:**
```
bob 3
```

<details>
<summary>Click for solution</summary>

```python
def failed_logins(auth_logs):
    failed_counts = {}

    for log in auth_logs:
        user = log.get("user")

        if not user:
            continue

        if log.get("action") == "login" and log.get("status") == "failed":
            failed_counts[user] = failed_counts.get(user, 0) + 1

    for user, count in failed_counts.items():
        if count >= 3:
            print(user, count)

failed_logins(auth_logs)
```

**Key concepts:** Multiple conditions, filtering by status
</details>

---

### Q3: Count missing or invalid data
**Task:** Count how many events have missing critical data (empty user OR None src_ip).

**Expected Output:**
```
2
```

<details>
<summary>Click for solution</summary>

```python
def missing_data(auth_logs):
    missing_count = 0

    for log in auth_logs:
        user = log.get("user")
        src_ip = log.get("src_ip")

        if not user or not src_ip:
            missing_count += 1

    print(missing_count)

missing_data(auth_logs)
```

**Key concepts:** Counting with OR condition, None vs empty string
</details>

---

## Dataset 2: Network Alerts

```python
network_alerts = [
    {"src_ip": "10.1.2.3", "dest_ip": "8.8.8.8", "protocol": "DNS", "severity": "low", "country": "US"},
    {"src_ip": "10.1.2.5", "dest_ip": "185.220.101.45", "protocol": "TLS", "severity": "high", "country": "RU"},
    {"src_ip": "10.1.2.3", "dest_ip": "1.1.1.1", "protocol": "DNS", "severity": "low", "country": "US"},
    {"src_ip": "10.1.2.9", "dest_ip": "185.220.101.45", "protocol": "HTTP", "severity": "high", "country": "RU"},
    {"src_ip": "10.1.2.5", "dest_ip": "185.220.101.67", "protocol": "TLS", "severity": "high", "country": "RU"},
    {"src_ip": "10.1.2.10", "dest_ip": "", "protocol": "ICMP", "severity": "medium", "country": None},
]
```

### Q4: Count alerts per country
**Task:** Count total alerts by country. Skip None countries.

**Expected Output:**
```
US 2
RU 3
```

<details>
<summary>Click for solution</summary>

```python
def alerts_by_country(network_alerts):
    country_counts = {}

    for alert in network_alerts:
        country = alert.get("country")

        if not country:  # Skip None
            continue

        country_counts[country] = country_counts.get(country, 0) + 1

    for country, count in country_counts.items():
        print(country, count)

alerts_by_country(network_alerts)
```

**Key concepts:** Dict counting, filtering None
</details>

---

### Q5: Unique IPs with high severity alerts
**Task:** Find all unique source IPs that triggered "high" severity alerts.

**Expected Output:**
```
{'10.1.2.5', '10.1.2.9'}
```

<details>
<summary>Click for solution</summary>

```python
def high_severity_ips(network_alerts):
    unique_ips = set()

    for alert in network_alerts:
        src_ip = alert.get("src_ip")
        severity = alert.get("severity")

        if not src_ip:
            continue

        if severity == "high":
            unique_ips.add(src_ip)

    print(unique_ips)

high_severity_ips(network_alerts)
```

**Key concepts:** Set for uniqueness, filtering by field value
</details>

---

### Q6: Most common protocol
**Task:** Find which protocol appears most frequently and print its count.

**Expected Output:**
```
DNS 2
```

<details>
<summary>Click for solution</summary>

```python
def most_common_protocol(network_alerts):
    protocol_counts = {}

    for alert in network_alerts:
        protocol = alert.get("protocol")
        if not protocol:
            continue

        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    max_protocol = None
    max_count = 0

    for protocol, count in protocol_counts.items():
        if count > max_count:
            max_count = count
            max_protocol = protocol

    print(max_protocol, max_count)

most_common_protocol(network_alerts)
```

**Key concepts:** Finding max value in dict
</details>

---

## Dataset 3: Cloud Activity Logs

```python
cloud_activity = [
    {"user": "admin@corp.com", "action": "CreateInstance", "region": "us-east-1", "bytes_out": 1024},
    {"user": "admin@corp.com", "action": "ModifySecurityGroup", "region": "us-east-1", "bytes_out": 512},
    {"user": "dev@corp.com", "action": "DeleteBucket", "region": "us-west-2", "bytes_out": 0},
    {"user": "attacker@evil.com", "action": "ListBuckets", "region": "eu-central-1", "bytes_out": 204800},
    {"user": "attacker@evil.com", "action": "GetObject", "region": "eu-central-1", "bytes_out": 524288},
    {"user": "attacker@evil.com", "action": "GetObject", "region": "eu-central-1", "bytes_out": 1048576},
    {"user": "admin@corp.com", "action": "CreateInstance", "region": "us-east-1", "bytes_out": None},
]
```

### Q7: Total bytes transferred per user
**Task:** Calculate total bytes_out for each user. Skip None values.

**Expected Output:**
```
admin@corp.com 1536
dev@corp.com 0
attacker@evil.com 1777664
```

<details>
<summary>Click for solution</summary>

```python
def bytes_per_user(cloud_activity):
    user_bytes = {}

    for event in cloud_activity:
        user = event.get("user")
        bytes_out = event.get("bytes_out")

        if not user or bytes_out is None:
            continue

        user_bytes[user] = user_bytes.get(user, 0) + bytes_out

    for user, total in user_bytes.items():
        print(user, total)

bytes_per_user(cloud_activity)
```

**Key concepts:** Summing values, checking `is None` vs `if not`
</details>

---

### Q8: Users with more than 2 actions
**Task:** Find users who performed more than 2 actions. Print user and count.

**Expected Output:**
```
admin@corp.com 3
attacker@evil.com 3
```

<details>
<summary>Click for solution</summary>

```python
def active_users(cloud_activity):
    user_actions = {}

    for event in cloud_activity:
        user = event.get("user")
        if not user:
            continue

        user_actions[user] = user_actions.get(user, 0) + 1

    for user, count in user_actions.items():
        if count > 2:
            print(user, count)

active_users(cloud_activity)
```

**Key concepts:** Counting, filtering results
</details>

---

### Q9: Region with highest data transfer
**Task:** Find which region had the most total bytes_out. Skip None values.

**Expected Output:**
```
eu-central-1 1777664
```

<details>
<summary>Click for solution</summary>

```python
def top_region(cloud_activity):
    region_bytes = {}

    for event in cloud_activity:
        region = event.get("region")
        bytes_out = event.get("bytes_out")

        if not region or bytes_out is None:
            continue

        region_bytes[region] = region_bytes.get(region, 0) + bytes_out

    max_region = None
    max_bytes = 0

    for region, total in region_bytes.items():
        if total > max_bytes:
            max_bytes = total
            max_region = region

    print(max_region, max_bytes)

top_region(cloud_activity)
```

**Key concepts:** Grouping and summing, finding max
</details>

---

## Dataset 4: Process Events (Nested Data)

```python
process_events = [
    {"host": "laptop-001", "process": "chrome.exe", "user": "alice", "children": ["gpu-process.exe", "renderer.exe"], "suspicious": False},
    {"host": "server-prod", "process": "powershell.exe", "user": "SYSTEM", "children": ["cmd.exe", "net.exe", "whoami.exe"], "suspicious": True},
    {"host": "laptop-002", "process": "outlook.exe", "user": "bob", "children": [], "suspicious": False},
    {"host": "server-prod", "process": "svchost.exe", "user": "SYSTEM", "children": ["powershell.exe"], "suspicious": True},
    {"host": "server-dev", "process": "bash", "user": "root", "children": ["curl", "wget", "nc"], "suspicious": True},
    {"host": "laptop-003", "process": None, "user": "charlie", "children": [], "suspicious": False},
]
```

### Q10: Count suspicious processes per host
**Task:** Count how many suspicious processes each host ran.

**Expected Output:**
```
server-prod 2
server-dev 1
```

<details>
<summary>Click for solution</summary>

```python
def suspicious_per_host(process_events):
    host_counts = {}

    for event in process_events:
        host = event.get("host")
        suspicious = event.get("suspicious")

        if not host or not suspicious:
            continue

        host_counts[host] = host_counts.get(host, 0) + 1

    for host, count in host_counts.items():
        print(host, count)

suspicious_per_host(process_events)
```

**Key concepts:** Boolean filtering, counting
</details>

---

### Q11: Total child processes from suspicious events
**Task:** Count total number of child processes spawned by ALL suspicious processes.

**Expected Output:**
```
7
```

<details>
<summary>Click for solution</summary>

```python
def total_suspicious_children(process_events):
    total = 0

    for event in process_events:
        suspicious = event.get("suspicious")
        children = event.get("children", [])

        if not suspicious:
            continue

        if not children:  # Skip None or empty list
            continue

        total += len(children)

    print(total)

total_suspicious_children(process_events)
```

**Key concepts:** Nested arrays, len() on lists, summing
</details>

---

### Q12: All unique child processes from suspicious events
**Task:** Find all unique child process names spawned by suspicious processes.

**Expected Output:**
```
{'cmd.exe', 'net.exe', 'whoami.exe', 'powershell.exe', 'curl', 'wget', 'nc'}
```

<details>
<summary>Click for solution</summary>

```python
def unique_suspicious_children(process_events):
    unique_children = set()

    for event in process_events:
        suspicious = event.get("suspicious")
        children = event.get("children", [])

        if not suspicious or not children:
            continue

        for child in children:
            unique_children.add(child)

    print(unique_children)

unique_suspicious_children(process_events)
```

**Key concepts:** Nested loops, sets for deduplication
</details>

---

## Dataset 5: CloudTrail Logs (Nested JSON)

```python
cloudtrail_records = [
    {
        "eventName": "CreateInstance",
        "userIdentity": {"userName": "alice", "accountId": "12345"},
        "sourceIPAddress": "192.168.1.10"
    },
    {
        "eventName": "DeleteBucket",
        "userIdentity": {"accountId": "67890"},
        "sourceIPAddress": "10.0.5.22"
    },
    {
        "eventName": "ListBuckets",
        "userIdentity": None,
        "sourceIPAddress": "203.0.113.5"
    },
    {
        "eventName": "ModifySecurityGroup",
        "userIdentity": {"userName": "bob", "accountId": "12345"},
        "sourceIPAddress": "192.168.1.10"
    },
]
```

### Q13: Extract user info safely
**Task:** For each record, print: `eventName userName accountId`. Use "Unknown" for missing userName, "None" for missing accountId.

**Expected Output:**
```
CreateInstance alice 12345
DeleteBucket Unknown 67890
ListBuckets Unknown None
ModifySecurityGroup bob 12345
```

<details>
<summary>Click for solution</summary>

```python
def extract_user_info(cloudtrail_records):
    for record in cloudtrail_records:
        event_name = record.get("eventName", "Unknown")

        # Safe nested access
        user_identity = record.get("userIdentity", {})
        user_name = user_identity.get("userName", "Unknown")
        account_id = user_identity.get("accountId", "None")

        print(event_name, user_name, account_id)

extract_user_info(cloudtrail_records)
```

**Alternative with chained .get():**
```python
def extract_user_info_v2(cloudtrail_records):
    for record in cloudtrail_records:
        event_name = record.get("eventName", "Unknown")
        user_name = record.get("userIdentity", {}).get("userName", "Unknown")
        account_id = record.get("userIdentity", {}).get("accountId", "None")

        print(event_name, user_name, account_id)
```

**Key concepts:** Nested JSON, default to {}, chained .get()
</details>

---

### Q14: Count events per account
**Task:** Count how many events happened per accountId. Skip records with no accountId.

**Expected Output:**
```
12345 2
67890 1
```

<details>
<summary>Click for solution</summary>

```python
def events_per_account(cloudtrail_records):
    account_counts = {}

    for record in cloudtrail_records:
        # Safe nested access
        account_id = record.get("userIdentity", {}).get("accountId")

        if not account_id:
            continue

        account_counts[account_id] = account_counts.get(account_id, 0) + 1

    for account, count in account_counts.items():
        print(account, count)

events_per_account(cloudtrail_records)
```

**Key concepts:** Chained .get(), counting nested values
</details>

---

## Dataset 6: Complex Grouping Challenge

```python
cloud_activity = [
    {"user": "admin@corp.com", "action": "CreateInstance", "region": "us-east-1"},
    {"user": "admin@corp.com", "action": "ModifySecurityGroup", "region": "us-east-1"},
    {"user": "admin@corp.com", "action": "CreateInstance", "region": "us-west-2"},
    {"user": "dev@corp.com", "action": "DeleteBucket", "region": "us-west-2"},
    {"user": "attacker@evil.com", "action": "ListBuckets", "region": "eu-central-1"},
    {"user": "attacker@evil.com", "action": "GetObject", "region": "eu-central-1"},
    {"user": "attacker@evil.com", "action": "GetObject", "region": "eu-central-1"},
    {"user": "", "action": "CreateInstance", "region": "us-east-1"},
]
```

### Q15: Group by user → region → unique actions
**Task:** Create nested structure: user → region → set of unique actions. Skip empty users.

**Expected Output:**
```
admin@corp.com:
  us-east-1: {'CreateInstance', 'ModifySecurityGroup'}
  us-west-2: {'CreateInstance'}
dev@corp.com:
  us-west-2: {'DeleteBucket'}
attacker@evil.com:
  eu-central-1: {'GetObject', 'ListBuckets'}
```

<details>
<summary>Click for solution</summary>

```python
def group_user_region_actions(cloud_activity):
    user_activity = {}

    for event in cloud_activity:
        user = event.get("user")
        region = event.get("region")
        action = event.get("action")

        if not user or not region or not action:
            continue

        # Initialize user dict if needed
        if user not in user_activity:
            user_activity[user] = {}

        # Initialize region set if needed
        if region not in user_activity[user]:
            user_activity[user][region] = set()

        # Add action (auto-deduplicates)
        user_activity[user][region].add(action)

    # Print results
    for user, regions in user_activity.items():
        print(f"{user}:")
        for region, actions in regions.items():
            print(f"  {region}: {actions}")

group_user_region_actions(cloud_activity)
```

**Key concepts:** Nested dicts, checking existence, dict of dict of set
</details>

---

## Quick Reference

### Data Structures
```python
# Counting → Dict
counts[key] = counts.get(key, 0) + 1

# Unique values → Set
unique_ips.add(ip)

# Nested grouping → Dict of Dict
if user not in groups:
    groups[user] = {}
```

### Safe Access
```python
# Single level
user = log.get("user", "Unknown")

# Nested
user_name = record.get("userIdentity", {}).get("userName", "Unknown")
```

### Filtering
```python
# Skip bad data
if not user:
    continue

# Check specific value
if status != "failed":
    continue
```

### Nested Arrays
```python
children = event.get("children", [])  # Default to []

if not children:  # Skip None or empty
    continue

for child in children:
    process(child)
```
