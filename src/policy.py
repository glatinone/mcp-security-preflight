class Policy:
    def __init__(self): self.blocked={"shell.run","files.export","search.query"}
    def decision(self, tool, approved=False):
        if tool in self.blocked: return "deny"
        if tool=="documents.archive" and not approved: return "approval-required"
        return "allow"
