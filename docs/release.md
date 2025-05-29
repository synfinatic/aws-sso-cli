# Release instructions

1. Update the `CHANGELOG.md`
    * Ensure the top level version is set and the date is correct
    * At the bottom is the list of changes, add the new version
1. Update `Makefile`
    * Update the `PROJECT_VERSION`
1. Commit `CHANGELOG.md` and `Makefile` & merge to `main`
1. Run `make release-tag` to create an annotated/signed tag
1. Visit [github.com](https://github.com/synfinatic/aws-sso-cli) and create the release.
1. Wait for the github actions to create the binaries and attach them to the release
1. Run `make release-brew` to create PR against [Homebrew/core](https://github.com/Homebrew/homebrew-core)
    * Note, if this command does not work, it's most likely because
    your homebrew dev environment is not setup.  Follow
    [the instructions here](https://docs.brew.sh/How-To-Open-a-Homebrew-Pull-Request#formulae-related-pull-request).
