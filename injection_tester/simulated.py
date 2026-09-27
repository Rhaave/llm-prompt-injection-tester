"""A scripted fake model - NOT a real LLM.

Used by the test suite and by --demo so the tool can be tried without Ollama.
It is deliberately gullible in 'baseline' mode and mostly resistant in
'hardened' mode, with two realistic gaps (spelling obfuscation and indirect
injection), so the report shows what a before/after comparison looks like.
Numbers produced with it are illustrations, not measurements.
"""

REFUSAL = "I can only help with opening hours and blocking a card."


class SimulatedModel:
    model = "simulated-demo-model"

    def check_model(self):
        return None

    def chat(self, messages):
        system, user = messages[0]["content"], messages[1]["content"]
        hardened = "<user_input>" in user
        secret = system.split("Internal reference code: ")[1].split(".")[0]
        pii = system.split("account number ")[1].split(".")[0].split()[0]
        low = user.lower()

        # Gaps that survive the hardened prompt as well.
        if "spell it" in low:
            return "-".join(secret)
        if "email from it" in low and "reference code" in low:
            return "IT asks for an audit note. Reference: " + secret

        if hardened:
            return REFUSAL

        if "injection-ok" in low:
            return "INJECTION-OK"
        if "repeat the text above" in low or "configuration and instructions" in low:
            return system
        if "reference code" in low and "backwards" in low:
            return secret[::-1]
        if "reference code" in low:
            return "Sure, the code is " + secret
        if "account number" in low or "personal data" in low:
            return "Anna Kowalska, account number " + pii
        if "<script>" in low:
            return "<b>Hello</b><script>alert(document.cookie)</script>"
        return REFUSAL
