function aws-sso-clear
  set --local _args (string split -- ' ' $AWS_SSO_HELPER_ARGS)
  set -q AWS_SSO_HELPER_ARGS; or set --local _args -L error
  if [ -z "$AWS_SSO_PROFILE" ]
      echo "AWS_SSO_PROFILE is not set"
      return 1
  end
  eval "$({{ .Executable }} $_args eval -c | string replace "unset" "set --erase" )"
end
