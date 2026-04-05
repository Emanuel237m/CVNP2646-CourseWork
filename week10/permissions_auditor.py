import json
import csv
from datetime import datetime
from collections import defaultdict, Counter

# =================================================
# STEP 1: LOAD DATA
# =================================================

def load_json(filepath):
    """
    Load a JSON file and return a list of records.
    """
    with open(filepath, 'r', encoding='utf-8') as file:
        data = json.load(file)

        if not isinstance(data, list):
            raise ValueError("JSON file must contain a list")

        return data


# =================================================
# STEP 2: BUILD LOOKUP STRUCTURES
# =================================================

def build_user_lookup(users_data):
    """
    Create a fast lookup dictionary using user_id.
    """
    lookup = {}
    for user in users_data:
        lookup[user['user_id']] = user
    return lookup


def group_roles_by_user(roles_data):
    """
    Group all roles under each user_id.
    """
    grouped = defaultdict(list)
    for role in roles_data:
        grouped[role['user_id']].append(role['role'])
    return dict(grouped)


# =================================================
# STEP 3: REQUIRED VIOLATION RULES
# =================================================

def check_disabled_with_roles(users_dict, roles_data):
    violations = []
    users_with_roles = {r['user_id'] for r in roles_data}
    grouped_roles = group_roles_by_user(roles_data)

    for user_id, user in users_dict.items():
        if user['status'] == 'disabled' and user_id in users_with_roles:
            roles = grouped_roles.get(user_id, [])
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'disabled_with_roles',
                'severity': 'CRITICAL',
                'details': f"Disabled account has {len(roles)} roles: {', '.join(roles)}"
            })

    return violations


def check_unauthorized_admins(users_dict, roles_data, authorized_depts={'IT', 'Security'}):
    violations = []

    for role in roles_data:
        if 'admin' in role['role'].lower():
            user_id = role['user_id']
            if user_id not in users_dict:
                continue

            user = users_dict[user_id]
            if user['department'] not in authorized_depts:
                violations.append({
                    'user_id': user_id,
                    'username': user['username'],
                    'violation_type': 'unauthorized_admin',
                    'severity': 'HIGH',
                    'details': f"{user['department']} user has admin role {role['role']}"
                })

    return violations


def check_stale_accounts(users_dict, stale_days=90):
    violations = []
    today = datetime.now()

    for user_id, user in users_dict.items():
        if user['status'] != 'active':
            continue

        last_login = user.get('last_login')
        if not last_login:
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'stale_account',
                'severity': 'MEDIUM',
                'details': "No last login date"
            })
            continue

        days_inactive = (today - datetime.strptime(last_login, '%Y-%m-%d')).days
        if days_inactive > stale_days:
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'stale_account',
                'severity': 'MEDIUM',
                'details': f"Last login was {days_inactive} days ago"
            })

    return violations


# =================================================
# STEP 4: AI-ENHANCED RULES
# =================================================

def check_conflicting_roles(users_dict, roles_data):
    violations = []
    conflicts = [{'admin', 'auditor'}, {'billing_admin', 'audit_viewer'}]
    grouped_roles = group_roles_by_user(roles_data)

    for user_id, roles in grouped_roles.items():
        if user_id not in users_dict:
            continue

        role_set = set(roles)
        for pair in conflicts:
            if pair.issubset(role_set):
                violations.append({
                    'user_id': user_id,
                    'username': users_dict[user_id]['username'],
                    'violation_type': 'conflicting_roles',
                    'severity': 'CRITICAL',
                    'details': f"Conflicting roles detected: {', '.join(pair)}"
                })

    return violations


def check_excessive_permissions(users_dict, roles_data, max_roles=5):
    violations = []
    grouped_roles = group_roles_by_user(roles_data)

    for user_id, roles in grouped_roles.items():
        if user_id in users_dict and len(roles) > max_roles:
            violations.append({
                'user_id': user_id,
                'username': users_dict[user_id]['username'],
                'violation_type': 'excessive_permissions',
                'severity': 'MEDIUM',
                'details': f"User has {len(roles)} roles"
            })

    return violations


def check_orphaned_roles(users_dict, roles_data):
    violations = []
    for role in roles_data:
        if role['user_id'] not in users_dict:
            violations.append({
                'user_id': role['user_id'],
                'username': 'UNKNOWN',
                'violation_type': 'orphaned_role',
                'severity': 'HIGH',
                'details': f"Role assigned to missing user: {role['role']}"
            })
    return violations


# =================================================
# EXTRA FEATURE 1: USER RISK SCORING
# =================================================

def calculate_risk_scores(violations):
    """
    Add up risk points per user.
    """
    points = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 3, 'LOW': 1}
    scores = defaultdict(int)

    for v in violations:
        scores[v['user_id']] += points.get(v['severity'], 0)

    return dict(scores)


# =================================================
# EXTRA FEATURE 2: TOP RISK USERS
# =================================================

def print_top_risk_users(risk_scores, users_dict, top_n=5):
    print("\nTOP RISK USERS")
    print("-" * 40)

    for user_id, score in sorted(risk_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        print(f"{users_dict[user_id]['username']} ({user_id}) - Risk Score: {score}")


# =================================================
# EXTRA FEATURE 3: DEPARTMENT RISK
# =================================================

def calculate_department_risk(violations, users_dict):
    points = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 3, 'LOW': 1}
    dept_scores = defaultdict(int)

    for v in violations:
        user = users_dict.get(v['user_id'])
        if user:
            dept_scores[user['department']] += points.get(v['severity'], 0)

    return dict(dept_scores)


def print_department_risk(dept_scores):
    print("\nDEPARTMENT RISK SUMMARY")
    print("-" * 40)

    for dept, score in sorted(dept_scores.items(), key=lambda x: x[1], reverse=True):
        print(f"{dept}: Risk Score {score}")


# =================================================
# EXTRA FEATURE 4: CSV EXPORT
# =================================================

def export_violations_csv(violations, filename='audit_report.csv'):
    with open(filename, 'w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(
            file,
            fieldnames=['user_id', 'username', 'violation_type', 'severity', 'details']
        )
        writer.writeheader()
        for v in violations:
            writer.writerow(v)


# =================================================
# STEP 5: REPORT GENERATION
# =================================================

def generate_json_report(violations, users_dict, roles_data):
    return {
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_users_audited": len(users_dict),
            "total_roles_reviewed": len(roles_data),
            "total_violations": len(violations),
            "auditor": "IAM Audit System v1.0"
        },
        "violation_summary": {
            "by_severity": dict(Counter(v['severity'] for v in violations)),
            "by_type": dict(Counter(v['violation_type'] for v in violations))
        },
        "all_violations": violations
    }


def generate_text_report(violations):
    lines = []
    lines.append("=" * 80)
    lines.append("USER ACCOUNT & PERMISSIONS AUDIT REPORT")
    lines.append("=" * 80)

    for v in violations:
        lines.append(f"{v['severity']} | {v['username']} | {v['details']}")

    return "\n".join(lines)


# =================================================
# STEP 6: MAIN ORCHESTRATION
# =================================================

def main():
    print("Starting IAM Audit...\n")

    users = load_json('users.json')
    roles = load_json('roles.json')

    users_dict = build_user_lookup(users)

    violations = []
    violations += check_disabled_with_roles(users_dict, roles)
    violations += check_unauthorized_admins(users_dict, roles)
    violations += check_stale_accounts(users_dict)
    violations += check_conflicting_roles(users_dict, roles)
    violations += check_excessive_permissions(users_dict, roles)
    violations += check_orphaned_roles(users_dict, roles)

    risk_scores = calculate_risk_scores(violations)
    dept_risk = calculate_department_risk(violations, users_dict)

    with open('audit_report.json', 'w') as f:
        json.dump(generate_json_report(violations, users_dict, roles), f, indent=2)

    with open('audit_report.txt', 'w') as f:
        f.write(generate_text_report(violations))

    export_violations_csv(violations)

    print("IAM Audit Complete!\n")
    print(f"Violations Found: {len(violations)}")
    print("Reports Generated:")
    print("- audit_report.json")
    print("- audit_report.txt")
    print("- audit_report.csv")

    print_top_risk_users(risk_scores, users_dict)
    print_department_risk(dept_risk)


if __name__ == '__main__':
    main()