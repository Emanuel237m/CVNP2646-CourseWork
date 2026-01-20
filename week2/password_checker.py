#!/usr/bin/env python3
# password_checker.py
# Validates password strength.


def check_password_strength(password: str) -> str:
    """
    Evaluates password strength based on multiple criteria.
    """
    score = 0
    feedback = []

    # Check the length of the password
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short (minimum 8 characters)")

    # Checks the number of uppercase letters in password
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    # Checks the number of lowercase letters in password
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    # Check the amount of digits in password
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add numbers")

    # Check the number of special characters
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if any(c in special_chars for c in password):
        score += 1
    else:
        feedback.append("Add special characters")

    # Rates password strength
    if score <= 2:
        rating = "WEAK ❌"
    elif score <= 4:
        rating = "MEDIUM ⚠️"
    else:
        rating = "STRONG ✅"

    if feedback:
        return f"{rating} - Issues: {', '.join(feedback)}"
    else:
        return f"{rating} - Excellent password!"


if __name__ == "__main__":
    test_passwords = [
        "weak",
        "Password1",
        "Pass123!",
        "VeryStr0ng!Pass",
        "12345678",
    ]

    print("Password Strength Checker")
    print("=" * 60)

    for pwd in test_passwords:
        result = check_password_strength(pwd)
        print(f"'{pwd}' → {result}")

    print()
    user_password = input("Enter a password to check its strength: ")
    strength_result = check_password_strength(user_password)
    print(f"Result: {strength_result}")
