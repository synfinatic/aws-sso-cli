function __complete_aws-sso
    set -lx COMP_LINE (commandline -cp)
    test -z (commandline -ct)
    and set COMP_LINE "$COMP_LINE "
    export __NO_ESCAPE_COLONS=1
    {{ .Executable }}
end
complete -f -c aws-sso -a "(__complete_aws-sso)"

function aws-sso-profile
  set --local _args (string split -- ' ' $AWS_SSO_HELPER_ARGS)
  set -q AWS_SSO_HELPER_ARGS; or set --local _args -L error
  set --local _sso ""
  set --local _profile ""
  set --local _remaining_args
  
  if [ -n "$AWS_PROFILE" ]
      echo "Unable to assume a role while AWS_PROFILE is set"
      return 1
  end

  # Parse arguments
  set --local i 1
  while [ $i -le (count $argv) ]
      switch $argv[$i]
          case -S --sso
              set i (math $i + 1)
              if [ $i -gt (count $argv) ]
                  echo "Error: -S/--sso requires an argument"
                  return 1
              end
              set _sso $argv[$i]
          case '-*'
              echo "Unknown option: $argv[$i]"
              echo "Usage: aws-sso-profile [-S|--sso <sso-instance>] <profile>"
              return 1
          case '*'
              if [ -z "$_profile" ]
                  set _profile $argv[$i]
              else
                  echo "Error: Multiple profiles specified"
                  return 1
              end
      end
      set i (math $i + 1)
  end

  if [ -z "$_profile" ]
      echo "Usage: aws-sso-profile [-S|--sso <sso-instance>] <profile>"
      return 1
  end

  # Build and execute the eval command with optional SSO flag
  if [ -n "$_sso" ]
      eval $({{ .Executable }} $_args -S $_sso eval -p $_profile)
  else
      eval $({{ .Executable }} $_args eval -p $_profile)
  end
  
  if [ "$AWS_SSO_PROFILE" != "$_profile" ]
      return 1
  end
end

function __aws_sso_profile_complete
  set --local _args (string split -- ' ' $AWS_SSO_HELPER_ARGS)
  set -q AWS_SSO_HELPER_ARGS; or set --local _args -L error
  set -l cur (commandline -t)

  set -l cmd "{{ .Executable }} list $_args --csv -P Profile=$cur Profile"
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
