# utils/prompt_helper.py

def generate_ai_analysis(purpose_text):
    """
    Placeholder function to simulate AI interaction for analyzing access purpose.
    In a real application, this would call an external AI API (e.g., Google Gemini, OpenAI GPT).

    Args:
        purpose_text (str): The text description of the access purpose.

    Returns:
        str: A simulated AI analysis or a placeholder message.
    """
    if "audit" in purpose_text.lower() or "compliance" in purpose_text.lower():
        return "AI Note: This purpose suggests potential audit or compliance relevance. Further review may be warranted."
    elif "sensitive" in purpose_text.lower() or "personal" in purpose_text.lower():
        return "AI Note: Access to potentially sensitive or personal data indicated. Ensure data handling policies are followed."
    else:
        return "AI Note: Basic analysis completed. No immediate flags based on keywords."

# You could potentially add more specific helper functions here
# For example:
# def check_for_data_policy_violation(access_log_entry):
#     # ... AI logic to check against internal policies ...
#     return "Policy check: OK"