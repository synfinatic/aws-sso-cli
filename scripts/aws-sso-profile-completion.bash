#!/usr/bin/env bash

# these scripts/aliases run against your DefaultSSO.  If you 
# want to use a different SSO instance, be sure to set:
# AWS_SSO=<Alternate SSO>

# Grab a list of the profiles
_aws_sso_profile_complete(){
    local words
    for i in $(aws-sso -L error list Profile | tail +5 | sed -Ee 's|:|\\\\:|g') ; do 
        words="${words} ${i}"
    done
    COMPREPLY=($(compgen -W "${words}" "${COMP_WORDS[1]}"))
}

complete -F _aws_sso_profile_complete aws-sso-profile

# alias aws-sso-profile='source /usr/local/bin/helper-aws-sso-profile'
# alias aws-sso-clear='eval $(aws-sso -L error eval -c)'
