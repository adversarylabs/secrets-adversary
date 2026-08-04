# security/secrets — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `secrets`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Any text with secrets

## Mission

Find high-confidence committed credentials and private keys in repository text.

## In scope (fair miss if humans raised it and we did not)

- API keys, tokens, private keys committed in tree
- High-confidence secret material in files

## Out of scope (not a miss for this adversary)

- Design-level auth architecture (go-security)
- Workflow secret *wiring* without committed values (github-actions)

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
