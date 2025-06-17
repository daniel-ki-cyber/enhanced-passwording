import string
import re

# common weak passwords examples
COMMON_PASSWORDS = {"password", "123456", "qwerty", "letmein", "admin", "welcome"}

def check_password_strength(password):
    score = 0
    feedback = []

    # check length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("🔸 Use at least 12 characters.")
    
    # check for different character types
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("🔸 Add uppercase letters.")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("🔸 Add lowercase letters.")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("🔸 Add numbers.")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    else:
        feedback.append("🔸 Add special characters.")

    # check if it's a common password
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("❗ This is a very common password!")
        score = 0

    # score rating
    if score >= 6:
        strength = "🔒 Strong"
    elif score >= 4:
        strength = "🟡 Medium"
    else:
        strength = "🔓 Weak"

    return strength, feedback
