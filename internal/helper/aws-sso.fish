function __complete_aws-sso
    set -lx COMP_LINE (commandline -cp)
    test -z (commandline -ct)
    and set COMP_LINE "$COMP_LINE "
    {{ .Executable }}
end
complete -f -c aws-sso -a "(__complete_aws-sso)"

function aws-sso-profile
  set --local _args (string split -- ' ' $AWS_SSO_HELPER_ARGS)
  set -q AWS_SSO_HELPER_ARGS; or set --local _args -L error --no-config-check
  if [ -n "$AWS_PROFILE" ]
      echo "Unable to assume a role while AWS_PROFILE is set"
      return 1
  end
  eval $({{ .Executable }} $_args eval -p $argv[1])
  if [ "$AWS_SSO_PROFILE" != "$1" ]
      return 1
  end
end

function __aws_sso_profile_complete
  set --local _args (string split -- ' ' $AWS_SSO_HELPER_ARGS)
  set -q AWS_SSO_HELPER_ARGS; or set --local _args -L error --no-config-check
  set -l cur (commandline -t)

  set -l cmd "aws-sso list $_args --csv -P Profile=$cur Profile"
  for completion in (eval $cmd)
    printf "%s\n" $completion
  end
end
complete -f -c aws-sso-profile -f -a '(__aws_sso_profile_complete)'

function aws-sso-clear
  set --local _args (string split -- ' ' $AWS_SSO_HELPER_ARGS)
  set -q AWS_SSO_HELPER_ARGS; or set --local _args -L error
  if [ -z "$AWS_SSO_PROFILE" ]
      echo "AWS_SSO_PROFILE is not set"
      return 1
  end
  eval "$({{ .Executable }} $_args eval -c | string replace "unset" "set --erase" )"
end
