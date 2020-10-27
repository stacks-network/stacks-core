Use the following template to create your pull request

## Description

Describe the changes that where made in this pull request. When possible start with a user story - short, simple descriptions of a feature told from the perspective of the person who desires the new capability. Be sure to also include the following information:

1. Motivation for change
2. What was changed
3. How does this impact application developers
4. Link to relevant issues and documentation
5. Provide examples of use cases with code samples and applicable acceptance criteria

Example:
As a Blockstack developer, I would like to encrypt files using the app private key. This is needed because storing unencrypted files is unacceptable. This pull request adds the `encryptContent` function which will take a string and encrypt it using the app private key.

```
encryptContent('my data')

// Running the above should result in the following encrypted data object
{"iv":"c91...","ephemeralPK":"031...","cipherText":"d61...","mac":"e73..."}
```

For details refer to issue #123

## Type of Change
- [ ] New feature
- [ ] Bug fix
- [ ] API reference/documentation update
- [ ] Other

## Does this introduce a breaking change?
List the APIs or describe the functionality that this PR breaks.
Workarounds for or expected timeline for deprecation

## Are documentation updates required?
<!-- 
  DOCUMENTATION
  Consider if this PR makes changes that require documentation updates:
    - API changes
    - Renamed methods
    - Change in instructions inside tutorials/guides
    - etc...

   The best way to find these is by searching inside the docs at https://github.com/blockstack/docs
-->
- [ ] Link to documentation updates: 

## Testing information

Provide context on how tests should be performed.

1. Is testing required for this change?
2. If it’s a bug fix, list steps to reproduce the bug
3. Briefly mention affected code paths
4. List other affected projects if possible
5. Things to watch out for when testing

## Checklist
- [ ] Code is commented where needed
- [ ] Unit test coverage for new or modified code paths
- [ ] `cargo test` passes
- [ ] Changelog is updated
- [ ] Tag @kantai and @jcnelson for review
