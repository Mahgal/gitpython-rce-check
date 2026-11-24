# NOTE: SAFE FIXTURE -- benign demo code for the static scanner.
# Every Remote.pull() / Head.checkout() call here passes a constant
# string, so there is nothing untrusted to flag. Fixture for
# `gitpython-rce-check --demo`.
#
# Simulated environment: GitPython 3.2.0 (>= 3.2.0, fixed for
# CVE-2026-110858 and CVE-2026-110859).

"""Deploy helper, fixed version (fixture)."""


def deploy(repo):
    """Pull the pinned refspec only."""
    remote = repo.remotes.origin
    remote.pull("main")


def switch_branch(repo):
    """Check out the pinned branch only."""
    head = repo.head
    head.checkout("main")
