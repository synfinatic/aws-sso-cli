function __aws_sso_profile_complete
    if test -n $AWS_SSO_HELPER_ARGS 
        set -l _args "$AWS_SSO_HELPER_ARGS" 
    else
        set -l _args ' --no-config-check --level=error '
    end
    set -l cur (commandline -t)

    set -l cmd "aws-sso list $_args --csv -P Profile=$cur Profile"
    for completion in (eval $cmd)
        printf "%s\n" $completion
    end
end

function aws-sso-profile
    if test -n $AWS_SSO_PROFILE 
        set -l _args "$AWS_SSO_HELPER_ARGS" 
    else
        set -l _args ' --no-config-check --level=error '
    end
    if test -n "$AWS_PROFILE"
        echo "Unable to assume a role while AWS_PROFILE is set"
        return 1
    end

    eval (aws-sso $_args eval -p "$argv[1]")

    if test "$AWS_SSO_PROFILE" != "$argv[1]"
        return 1
    end

end

function aws-sso-clear
    if test -n $AWS_SSO_HELPER_ARGS 
        set -l _args "$AWS_SSO_HELPER_ARGS" 
    else
        set -l _args ' --no-config-check --level=error '
    end
    if test -z "$AWS_SSO_PROFILE"
        echo "AWS_SSO_PROFILE is not set"
        return 1
    end

    aws-sso eval $_args -c | sed 's/unset //g' | while read LINE;
        eval (set --erase $LINE)
    end
    rm -rf ~/.aws/credentials
end

complete -f -c aws-sso-profile -f -a '(__aws_sso_profile_complete)'

complete -f -c aws-sso -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -l lines -d 'Print line number in logs'
complete -c aws-sso -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -c aws-sso -s b -l browser -d 'Path to browser to open URLs with ($AWS_SSO_BROWSER)'
complete -c aws-sso -l config -d 'Config file ($AWS_SSO_CONFIG)'
complete -c aws-sso -s L -l level -d 'Logging level [error|warn|info|debug|trace] (default: warn)'
complete -c aws-sso -s u -l url-action -d 'How to handle URLs [clip|exec|open|print|printurl|granted-containers|open-url-in-container] (default: open)'
complete -c aws-sso -s S -l sso -d 'Override default AWS SSO Instance ($AWS_SSO)'
complete -c aws-sso -l sts-refresh  -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -l threads -d 'Override number of threads for talking to AWS'

complete -c aws-sso -n __fish_use_subcommand -a console -d 'Open AWS Console using specificed AWS role/profile'
complete -c aws-sso -n '__fish_seen_subcommand_from console' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from console' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from console' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from console' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -c aws-sso -n '__fish_seen_subcommand_from console' -s P -l prompt -d 'Force interactive prompt to select role'
complete -f -c aws-sso -n __fish_use_subcommand -a eval -d 'Print AWS environment vars for use with eval $(aws-sso eval ...)'
complete -c aws-sso -n '__fish_seen_subcommand_from eval' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from eval' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from eval' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from eval' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -c aws-sso -n '__fish_seen_subcommand_from eval' -s c -l clear -d 'Generate "unset XXXX" commands to clear environment'
complete -c aws-sso -n '__fish_seen_subcommand_from eval' -s n -l no-region -d 'Do not set/clear AWS_DEFAULT_REGION from'
complete -c aws-sso -n '__fish_seen_subcommand_from eval' -s r -l refresh -d 'Refresh current IAM credentials'
complete -f -c aws-sso -n __fish_use_subcommand -a exec -d '[<command> [<args> ...]]  Execute command using specified IAM role in a new shell'
complete -c aws-sso -n '__fish_seen_subcommand_from exec' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from exec' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from exec' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from exec' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -c aws-sso -n '__fish_seen_subcommand_from exec' -s n -l no-region -d 'Do not set AWS_DEFAULT_REGION from config.yaml'
complete -f -c aws-sso -n __fish_use_subcommand -a flush -d 'Flush AWS SSO/STS credentials from cache'
complete -c aws-sso -n '__fish_seen_subcommand_from flush' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from flush' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from flush' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from flush' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -f -c aws-sso -n __fish_use_subcommand -a list -d '[<fields> ...]  List all accounts / roles (default command)'
complete -c aws-sso -n '__fish_seen_subcommand_from list' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from list' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from list' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from list' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -c aws-sso -n '__fish_seen_subcommand_from list' -s f -l list-fields -d 'List available fields'
complete -c aws-sso -n '__fish_seen_subcommand_from list' -l csv -d 'Generate CSV instead of a table'
complete -f -c aws-sso -n __fish_use_subcommand -a process -d 'Generate JSON for credential_process in ~/.aws/config'
complete -c aws-sso -n '__fish_seen_subcommand_from process' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from process' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from process' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from process' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -f -c aws-sso -n __fish_use_subcommand -a tags -d 'List tags'
complete -c aws-sso -n '__fish_seen_subcommand_from tags' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from tags' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from tags' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from tags' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -c aws-sso -n '__fish_seen_subcommand_from tags' -l force-update -d 'Force account/role cache update'
complete -f -c aws-sso -n __fish_use_subcommand -a time -d 'Print how much time before current STS Token expires'
complete -c aws-sso -n '__fish_seen_subcommand_from time' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from time' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from time' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from time' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -f -c aws-sso -n __fish_use_subcommand -a completions -d 'Manage shell completions'
complete -c aws-sso -n '__fish_seen_subcommand_from completions' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from completions' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from completions' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from completions' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -c aws-sso -n '__fish_seen_subcommand_from completions' -s I -l install -d 'Install shell completions'
complete -c aws-sso -n '__fish_seen_subcommand_from completions' -s U -l uninstall -d 'Uninstall shell completions'
complete -c aws-sso -n '__fish_seen_subcommand_from completions' -l uninstall-pre-19 -d 'Uninstall pre-v1.9 shell completion integration'
complete -f -c aws-sso -n __fish_use_subcommand -a config-profiles -d 'Update ~/.aws/config with AWS SSO profiles from the cache'
complete -c aws-sso -n '__fish_seen_subcommand_from config-profiles' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from config-profiles' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from config-profiles' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from config-profiles' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -c aws-sso -n '__fish_seen_subcommand_from config-profiles' -l diff -d 'Print a diff of changes to the config file instead'
complete -c aws-sso -n '__fish_seen_subcommand_from config-profiles' -l force -d 'Write a new config file without prompting'
complete -c aws-sso -n '__fish_seen_subcommand_from config-profiles' -l print -d 'Print profile entries instead of modifying config'
complete -f -c aws-sso -n __fish_use_subcommand -a config -d 'Run the configuration wizard'
complete -c aws-sso -n '__fish_seen_subcommand_from config' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from config' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from config' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from config' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
complete -f -c aws-sso -n __fish_use_subcommand -a version -d 'Print version and exit'
complete -c aws-sso -n '__fish_seen_subcommand_from version' -s h -l help -d 'Show context-sensitive help.'
complete -c aws-sso -n '__fish_seen_subcommand_from version' -l lines -d 'Print line number in logs'
complete -c aws-sso -n '__fish_seen_subcommand_from version' -l sts-refresh -d 'Force refresh of STS Token Credentials'
complete -c aws-sso -n '__fish_seen_subcommand_from version' -l no-config-check -d 'Disable automatic ~/.aws/config updates'
