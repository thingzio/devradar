# Account Menu Identity Labels

## Goal

Make the account menu distinguish the selected account from the signed-in user
when both values happen to be the same email address.

## Display Contract

With an active account, render the header in this order:

```text
Account: <account name>
User: <user email> (<membership role>)
```

Membership roles use the exact user-facing labels `Admin`, `Editor`, and
`Reader`.

Without an active account, render only:

```text
User: <user email>
```

The template continues to escape account names and user emails. Existing menu
layout, permissions, links, keyboard behavior, and responsive styling remain
unchanged.

## Scope

This change affects only the account-menu identity header. It does not rename
Account settings, Members, API tokens, or the Tokens & settings page, and it
does not add a personal User settings page.

## Validation

Template regressions must cover all three title-cased roles, account-first
ordering, and the no-selected-account fallback. Existing capability and
navigation tests must remain green.
