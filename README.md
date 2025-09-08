# npm-package-template

Fully Automated NPM package release
- Automated semantic-release based on Angular Commit Message Conventions
- Manual release
- NPM release
- GitHub release
- GitHub Tags
- Changelog generation

[![Version](https://img.shields.io/npm/v/@netcentric/npm-package-template.svg)](https://npmjs.org/package/@netcentric/npm-package-template)
[![Build Status](https://github.com/netcentric/npm-package-template/workflows/CI/badge.svg?branch=main)](https://github.com/netcentric/npm-package-template/actions)
[![CodeQL Analysis](https://github.com/netcentric/npm-package-template/workflows/CodeQL/badge.svg?branch=main)](https://github.com/netcentric/npm-package-template/actions)
[![semver: semantic-release](https://img.shields.io/badge/semver-semantic--release-blue.svg)](https://github.com/semantic-release/semantic-release)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## TLDR;

1. Create a new repo from this Template
   [![Template repo](https://docs.github.com/assets/images/help/repository/use-this-template-button.png)](https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/creating-a-repository-from-a-template)
2. Update the Readme
    - replace `@netcentric/npm-package-template`  with the new package_name
3. Update package.json
    - replace "name" `@netcentric/npm-package-template`  with the new package_name
    - replace "repository.url" `https://github.com/netcentric/npm-package-template`  with the new repository url
    - Add description, and other fields if needed
4. Update LICENSE
    - Update `[COMPANY]` name
    - Update year `[yyyy]`
5. Update docs/CODE_OF_CONDUCT.md
    - Update `[COMPANY]` name
6. Activate automatic release
    - disable `dry_run` in Release step in .github/workflows/release.yml.

## Content

### Docs
  - LICENSE
  - docs/CODE_OF_CONDUCT.md
  - docs/CONTRIBUTING.md
  - docs/CHANGELOG.md --> dynamically updated

### Issue template
  - .github/ISSUE_TEMPLATE.md

### PR template
  - .github/PULL_REQUEST_TEMPLATE.md --> automatically closes connected issue

### Workflows
  - CI --> npm ci, test and build
  - CodeQL --> Perform CodeQL Analysis (Security, etc.)
  - Release --> semantic-release:
    * Creates release notes
    * Updates CHANGELOG
    * Updates package.json version
    * Creates Git tag/release
    * Publish package to NPM
  - Manual Release --> same as Release, but can be triggered manually in Actions tab

### Release
  - based on Angular Commit Message Conventions in commits -
    https://github.com/angular/angular/blob/master/CONTRIBUTING.md#commit-message-header
  - Commit message format is used to build:
    * Release notes
    * Changelog updates
    * NPM package semver

### Commit message Convention

```
<type>(<scope>): <short summary>
│       │             │
│       │             └─⫸ Summary in present tense. Not capitalized. No period at the end.
│       │
│       └─⫸ Commit Scope (optional): project|based|list
│
└─⫸ Commit Type: build|ci|docs|feat|fix|perf|refactor|test
```


#### Major Version Release:

In order to trigger Major Version upgrade, `BREAKING CHANGE:` needs to be in the footer of a commit message:

```
<type>(<scope>): <short summary>
<BLANK LINE>
BREAKING CHANGE: <breaking change summary>
```
