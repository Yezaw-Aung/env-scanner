"""
Sample project #4 — Comment skipping edge case.
Contains a secret inside a comment (should be skipped) and the same secret
in a real assignment (should be flagged).

env-guard should report exactly 2 findings: the commented-out secret on
line 13 AND the real assignment on line 16. A secret in a comment is still
committed to version control and is equally dangerous.
"""

import os

# Bug: AWS secret key was hardcoded here before, now commented out
# AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# But the developer left a real one in the code below:
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_aws_client():
    print(f"Using key: {AWS_SECRET_ACCESS_KEY}")
