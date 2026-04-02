class MoPromptManager:
    """Mixture of Prompts manager for CWE Research Concepts."""

    def __init__(self, cwe_categories: dict):
        self.cwe_categories = cwe_categories
        self.expert_prompts = {}
        self.load_expert_prompts()

    def load_expert_prompts(self):
        for category_id, category_name in self.cwe_categories.items():
            if category_id == 0:
                self.expert_prompts[category_id] = self.get_general_security_prompt()
            else:
                self.expert_prompts[category_id] = self.get_category_specific_prompt(category_id)

    def get_general_security_prompt(self) -> str:
        return (
            "Analyze the following code for security vulnerabilities.\n"
            "Focus on input validation, memory management, access control, error handling, and resource management.\n"
        )

    def get_category_specific_prompt(self, category_id: int) -> str:
        category_prompts = {
            1: (
                "Analyze the code for access control vulnerabilities: missing authentication, insufficient authorization,\n"
                "privilege escalation, improper permission validation, and path traversal.\n"
            ),
            2: (
                "Look for issues in component interactions: race conditions, TOCTOU, improper synchronization, deadlocks.\n"
            ),
            3: (
                "Check for resource lifetime issues: memory leaks, buffer over/underflows, use-after-free, double-free, exhaustion.\n"
            ),
            4: (
                "Identify calculation errors: integer overflow/underflow, precision issues, division by zero, arithmetic mistakes.\n"
            ),
        }
        return category_prompts.get(category_id, self.get_general_security_prompt())

    def get_prompt_for_category(self, category_id: int) -> str:
        return self.expert_prompts.get(category_id, self.get_general_security_prompt())

    def update_expert_prompt(self, category_id: int, new_prompt: str):
        self.expert_prompts[category_id] = new_prompt

    def get_all_prompts_for_evolution(self):
        return list(self.expert_prompts.values())