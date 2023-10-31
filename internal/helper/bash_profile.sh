__aws_sso_profile_complete() {
    COMPREPLY=()
    local _args=${AWS_SSO_HELPER_ARGS:- -L error}
    local cur
    _get_comp_words_by_ref -n : cur

    COMPREPLY=($(compgen -W '$({{ .Executable }} $_args list --csv -P "Profile=$cur" Profile)' -- ""))

    __ltrim_colon_completions "$cur"
}

aws-sso-profile() {
    local _args=${AWS_SSO_HELPER_ARGS:- -L error}
    if [ -n "$AWS_PROFILE" ]; then
        echo "Unable to assume a role while AWS_PROFILE is set"
        return 1
    fi
    eval $({{ .Executable }} $_args eval -p "$1")
    if [ "$AWS_SSO_PROFILE" != "$1" ]; then
        return 1
    fi
}

aws-sso-clear() {
    local _args=${AWS_SSO_HELPER_ARGS:- -L error}
    if [ -z "$AWS_SSO_PROFILE" ]; then
        echo "AWS_SSO_PROFILE is not set"
        return 1
    fi
    eval $(aws-sso eval $_args -c)
}

complete -F __aws_sso_profile_complete aws-sso-profile
complete -C {{ .Executable }} aws-sso
