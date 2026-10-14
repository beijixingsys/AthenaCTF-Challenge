"""Base domain error shared by every recreated challenge."""


class Problem(Exception):
    def __init__(self, message, status=400):
        Exception.__init__(self, message)
        self.message = str(message)
        self.status = int(status)


class PlatformProblem(Problem):
    pass
