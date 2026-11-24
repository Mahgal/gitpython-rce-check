# NOTE: SIMULATION ONLY -- benign demo code for the static scanner.
# It models the *shape* of a dangerous call: an untrusted variable
# passed to Remote.pull() / Head.checkout(). It performs no git
# operation, contains no exploit, and is never executed as a deploy
# script. Fixture for `gitpython-rce-check --demo`.
#
# Simulated environment: GitPython 3.1.30 (< 3.2.0, vulnerable to
# CVE-2026-110858 command injection and CVE-2026-110859 arbitrary
# file read). The fix is GitPython >= 3.2.0.

"""Deploy helper (fixture)."""

import sys


def deploy(repo, user_input):
    """Pull whatever refspec the caller supplies.

    In the vulnerable version the refspec reaches Remote.pull()
    unchecked, so an option-shaped value can inject git options
    (CVE-2026-110858). The scanner must flag this call because
    `user_input` is a function parameter whose name marks it as
    untrusted input.

    Why this matters in real code: deploy scripts, CI helpers and
    webhook handlers routinely take a branch or refspec from a
    user, a webhook payload, or a queue message and hand it to
    GitPython. With GitPython < 3.2.0 that value is passed to the
    git command line without a `--` separator and without an
    unsafe-option check on the positional argument, so an
    option-shaped value is parsed as a git option. The guard that
    was supposed to stop this only inspected keyword arguments --
    the positional refspec was never checked, which is exactly the
    hole CVE-2026-110858 describes. Local-path and SSH transports
    are the affected paths.

    The call below is the one the demo highlights. It is only
    reached when this fixture is imported and called -- the demo
    never executes it; the scanner only reads the source.
    """
    remote = repo.remotes.origin
    remote.pull(user_input)


def switch_branch(repo, branch_name):
    """Check out whatever branch name the caller supplies.

    In the vulnerable version the branch name reaches
    Head.checkout() unchecked, so an option-shaped value can make
    git read arbitrary files (CVE-2026-110859). The scanner must
    flag this call because `branch_name` comes from the caller.
    A hostile repository can name its default branch after a git
    option, and a consumer that checks out the active branch
    leaks file contents through the error message.
    """
    head = repo.head
    head.checkout(branch_name)


def pull_main(repo):
    """Safe example: a constant refspec is never reported."""
    remote = repo.remotes.origin
    remote.pull("main")


def deploy_from_cli(repo):
    """Safe-looking but still dangerous: sys.argv is external input."""
    refspec = sys.argv[1]
    remote = repo.remotes.origin
    remote.pull(refspec)
