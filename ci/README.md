# CI

`SERVER_REF` is the commit of `sovtech/grasp-p` that the end-to-end job builds
and tests against. It is a full SHA, never a branch name, so a server change
cannot alter what a client pipeline proves. Bump it in its own merge request
when the client must follow a server change.

It currently points at `legacy/v1.2-grasp-p`, the last server line before the
port onto upstream ngit-grasp v3.
