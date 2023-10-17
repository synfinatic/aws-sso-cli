function __complete_aws-sso
    set -lx COMP_LINE (commandline -cp)
    test -z (commandline -ct)
    and set COMP_LINE "$COMP_LINE "
    {{ .Executable }}
end
complete -f -c aws-sso -a "(__complete_aws-sso)"
