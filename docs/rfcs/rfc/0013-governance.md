|              |                                  |
| :----------- | :------------------------------- |
| Feature Name | Governance                       |
| Start Date   | 2022-11-14                       |
| Category     | Document                         |
| RFC PR       | https://github.com/kubewarden/rfc/pull/14  |
| State        | **ACCEPTED**                     |


# Summary
[summary]: #summary

This document defines the project governance for Kubewarden.

# Code of conduct

The Code of Conduct document can be found at:
https://github.com/kubewarden/.github/blob/main/CODE_OF_CONDUCT.md

# Roles

### Contributors

Community members who contribute in concrete ways to the project. Anyone can
contribute to the project and become a contributor, regardless of their
skillset. There is no expectation of commitment to the project, no specific
skill requirements, and no selection process. There are many ways to contribute
to the project, for example:
- Reporting or fixing bugs.
- Identifying requirements, strengths, and weaknesses.
- Improving the Kubewarden website.
- Improving the documentation.
- Joining discussions on our Slack channels (#kubewarden), social networks (e.g:
  Twitter), or at community meetings.
- Evangelizing about the project (e.g. a link on a website or word-of-mouth
  awareness raising).

As one continues to contribute to the project and engage with the community,
they may at some point become eligible and desire to be a Maintainer.

### Maintainers

Maintainers are first and foremost, committers that have shown they are committed
to the long term success of the project. They are the planners and designers of
the Kubewarden project. Maintainership is about building trust with the current
maintainers of the project and being a person that they can depend on to make
decisions in the best interest of the project in a consistent manner.

A list of active maintainers can be seen at
https://github.com/orgs/kubewarden/teams/maintainers.

Committers wanting to become maintainers are expected to:
- Collaborate well.
- Demonstrate a deep and comprehensive understanding of Kubewarden's
  architecture, technical goals, and directions.
- Actively engage with major Kubewarden feature proposals and implementations.
- Enable adoptions or ecosystems.
- Perform day-to-day work: review PRs, triage issues, create releases, own
  project infrastructure, represent Kubewarden, and involve themselves in
  CNCF-related activities.

A new Maintainer must be publicly nominated by an existing maintainer (by
opening a PR to update the maintainers list). Upon a supermajority (2/3) of
votes from active maintainers, it is approved and becomes active.

If a Maintainer is no longer able to perform the maintainer duties listed above,
they should volunteer to be moved to emeritus status. In extreme cases,
maintainers can also be removed from the active maintainers list by a
supermajority (2/3) of votes of existing maintainers.

Maintainers are defined in the CODEOWNERS file of the specific repositories by
their GitHub user handles.

# Governance

- The Kubewarden community believes that the best decisions are reached through
  Consensus https://en.wikipedia.org/wiki/Consensus_decision-making.
- Most decisions, and day-to-day project maintenance is done following the Lazy
  Consensus process: https://communitymgt.wikia.com/wiki/Lazy_consensus.
  If an objection is raised through the Lazy Consensus process, Deciders work
  together to seek an agreeable solution.
- Major changes that touch several parts of the Kubewarden stack are proposed by
  an RFC document, or amending an existing one. See RFC repository:
  https://github.com/kubewarden/rfc
- Community or project level decisions, such as creating a new project,
  maintainer promotion, major updates on GOVERNANCE, or major changes that touch
  several parts of the stack, must be brought to broader awareness of the
  community via community meetings, GitHub discussions, and slack channels. A
  supermajority (2/3) approval from Maintainers is required for such approvals.

In general, we prefer that technical issues and maintainer membership are
amicably worked out between the persons involved. If a dispute cannot be decided
independently, the maintainers can be called in to resolve the issue by voting.
A specific statement of what is being voted on should be added to the relevant
github issue or PR. Maintainers should indicate their yes/no vote on that issue
or PR, and after a suitable period of time, the votes will be tallied and the
outcome noted.

# Changing the governance documents

As with other agreements in the project, changes to the governance documents are
submitted via a GitHub pull request to the Project's governance document (this
one). The pull request is then refined in response to public comment and review,
with the goal being consensus in the community.
