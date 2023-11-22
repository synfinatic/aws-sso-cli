# V2 Design 

## Goals

 1. Completely rework the [sso](../sso) code
    1. The AWS SSO code should be in its own module
    1. The configuration and caching should be in a different module
 1. The configuration and caching (C&C) should provide a unified interface
    1. All access to the underlying data needs to be done via a defined interface
    1. `~/.aws-sso/config.yaml` and `~/.aws-sso/cache.json` need to be loaded
        and proceesed via a single API call.
        1. Users can override the location of these files on command line
    1. Other than the `login`, `logout`, and `cache` commands, there should 
        be _no need_ to specify the `--sso` flag.
    1. `cache` command would of course update the cache for a single SSO instance.
    1. Any action operating on a specific IAM Role should only require
        the SSO instance to be provided if there are role collisions.
        1. `aws-sso setup aws-config` would require the necessary `ProfileFormat`
            setting or manual configuration of the account/role `Profile` tag
            to avoid duplicates.
        1. Yes, if users are using `--account` and `--role` they _may_ need to
            use `--sso` to disambiguate duplicates.
