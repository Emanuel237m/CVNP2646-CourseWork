#!/usr/bin/env python3
# ip_validator.py
# Validates IPv4 addresses.


"""
Python Basics Demonstration
CVNP2646 - Week 2
This script demonstrates fundamental Python concepts.
"""

print("=" * 50)
print("PYTHON BASICS DEMONSTRATION")
print("=" * 50)
print()

# ========== SECTION 1: VARIABLES & DATA TYPES ==========
print("SECTION 1: Variables & Data Types")
print("-" * 50)

# Prints out a String variable
course_name = "CVNP2646 - Python and JSON"
print(f"String: {course_name}")

# Prints oyut an Integer variable
student_count = 25
print(f"Integer: {student_count} students")

# Calculates a Float variable
pass_rate = 94.5
print(f"Float: {pass_rate}% pass rate")

# Boolean variable makes a statement true or false
is_online = True
print(f"Boolean: Course is online: {is_online}")

# List variable
programming_languages = ["Python", "JavaScript", "Java", "C++"]
print(f"List: {programming_languages}")
print()

# ========== SECTION 2: CONDITIONAL STATEMENTS ==========
print("SECTION 2: Conditional Logic")
print("-" * 50)

# Check pass rate
if pass_rate >= 90:
    print("✅ Excellent pass rate!")
elif pass_rate >= 70:
    print("⚠️ Good pass rate")
else:
    print("❌ Needs improvement")

# Check if Python is in the list
if "Python" in programming_languages:
    print("✅ Python is on the list!")
print()

# ========== SECTION 3: LOOPS ==========
print("SECTION 3: Loops")
print("-" * 50)

# For loop - iterate through list
print("Popular programming languages:")
for i, lang in enumerate(programming_languages, 1):
    print(f" {i}. {lang}")

print()

# Performs a countdown loop from 5 down to 1, then prints a final message.
print("Countdown to course start:")
countdown = 5
while countdown > 0:
    print(f" {countdown}...")
    countdown -= 1

print(" 🚀 Let's begin!")
print()

# ========== SECTION 4: STRING MANIPULATION ==========
print("SECTION 4: String Manipulation")
print("-" * 50)

# String methods
sample_text = " Python Programming "
print(f"Original: '{sample_text}'")
print(f"Stripped: '{sample_text.strip()}'")
print(f"Uppercase: '{sample_text.upper()}'")
print(f"Lowercase: '{sample_text.lower()}'")
print(f"Replaced: '{sample_text.replace('Python', 'Advanced Python')}'")
print()

# ========== SECTION 5: BASIC MATH OPERATIONS ==========
print("SECTION 5: Math Operations")
print("-" * 50)

num1 = 10
num2 = 3

print(f"Addition: {num1} + {num2} = {num1 + num2}")
print(f"Subtraction: {num1} - {num2} = {num1 - num2}")
print(f"Multiplication: {num1} * {num2} = {num1 * num2}")
print(f"Division: {num1} / {num2} = {num1 / num2}")
print(f"Floor Division: {num1} // {num2} = {num1 // num2}")
print(f"Modulus: {num1} % {num2} = {num1 % num2}")
print(f"Exponent: {num1} ** {num2} = {num1 ** num2}")
print()

# ========== CONCLUSION ==========
print("=" * 50)
print("✅ Python Basics Demonstration Complete!")
print("=" * 50)
