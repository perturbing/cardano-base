# Description

<!-- Add your description here, if this PR fixes a particular issue please provide a
[link](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword=)
to the issue. -->

# Checklist

- [ ] Commit sequence broadly makes sense and commits have useful messages
- [ ] New tests are added if needed and existing tests are updated
- [ ] All visible changes are prepended to the latest section of a `CHANGELOG.md` for the affected packages.
      **_New section is never added with the code changes._** (See [RELEASING.md](https://github.com/intersectmbo/cardano-base/blob/master/RELEASING.md#changelogmd))
- [ ] When applicable, versions are updated in `.cabal` and `CHANGELOG.md` files according to the
      [versioning process](https://github.com/intersectmbo/cardano-base/blob/master/RELEASING.md#versioning-process).
- [ ] The version bounds in `.cabal` files for all affected packages are updated.
      **_If you change the bounds in a cabal file, that package itself must have a version increase._** (See [RELEASING.md](https://github.com/intersectmbo/cardano-base/blob/master/RELEASING.md#versioning-process))
- [ ] Commits that only contain large amounts of formatting changes were added to `.git-blame-ignore-revs`
- [ ] Self-reviewed the diff
