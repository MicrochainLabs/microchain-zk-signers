## Description

<!-- Briefly describe what this PR does and why. Link the related issue if applicable. -->

Closes #

## Type of Change

- [ ] Bug fix
- [ ] New feature / verifier adapter
- [ ] Circuit change (Noir `.nr` files modified)
- [ ] Refactor / code cleanup
- [ ] Documentation
- [ ] Dependency update
- [ ] Other: ___

## Checklist

### General

- [ ] I have read [CONTRIBUTING.md](CONTRIBUTING.md)
- [ ] My branch is up to date with `main`
- [ ] My changes do not introduce new linting or compiler warnings

### Solidity

- [ ] Hardhat tests pass (`npx hardhat test`)
- [ ] Foundry tests pass (`forge test`)
- [ ] New functionality has corresponding test coverage

### Noir Circuits (if `.nr` files were modified)

- [ ] Circuits compile without errors (`nargo compile`)
- [ ] Circuit tests pass (`nargo test`)
- [ ] Solidity verifiers have been **regenerated** using `bb write_vk` + `bb write_solidity_verifier` and are included in this PR
- [ ] Breaking changes to public inputs are documented and discussed in a linked issue

### Documentation

- [ ] README updated (if user-facing behaviour changed)
- [ ] Inline comments added for non-obvious logic

## Testing Notes

<!-- Describe how you tested these changes. Include relevant commands, test names, or screenshots. -->

## Additional Notes

<!-- Anything else reviewers should know. -->
