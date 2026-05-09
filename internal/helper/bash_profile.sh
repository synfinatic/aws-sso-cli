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
    local _sso=""
    local _profile=""
    
    if [ -n "$AWS_PROFILE" ]; then
        echo "Unable to assume a role while AWS_PROFILE is set"
        return 1
    fi

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            -S|--sso)
                shift
                if [ -z "$1" ]; then
                    echo "Error: -S/--sso requires an argument"
                    return 1
                fi
                _sso="$1"
                shift
                ;;
            -*)
                echo "Unknown option: $1"
                echo "Usage: aws-sso-profile [-S|--sso <sso-instance>] <profile>"
                return 1
                ;;
            *)
                if [ -z "$_profile" ]; then
                    _profile="$1"
                else
                    echo "Error: Multiple profiles specified"
                    return 1
                fi
                shift
                ;;
        esac
    done

    if [ -z "$_profile" ]; then
        echo "Usage: aws-sso-profile [-S|--sso <sso-instance>] <profile>"
        return 1
    fi

    # Build and execute the eval command with optional SSO flag
    if [ -n "$_sso" ]; then
        eval $({{ .Executable }} $_args -S "$_sso" eval -p "$_profile")
    else
        eval $({{ .Executable }} $_args eval -p "$_profile")
    fi
    
    if [ "$AWS_SSO_PROFILE" != "$_profile" ]; then
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
