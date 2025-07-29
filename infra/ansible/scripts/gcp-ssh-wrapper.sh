#!/bin/bash
# This is a wrapper script allowing to use GCP's IAP SSH option to connect
# to our servers.

# Ansible passes a large number of SSH parameters along with the hostname as the
# second to last argument and the command as the last. We will pop the last two
# arguments off of the list and then pass all of the other SSH flags through
# without modification:
selfLink="${@: -2: 1}"
cmd="${@: -1: 1}"

# Unfortunately ansible has hardcoded ssh options, so we need to filter these out
# It's an ugly hack, but for now we'll only accept the options starting with '--'
declare -a opts
for ssh_arg in "${@: 1: $# -3}" ; do
        if [[ "${ssh_arg}" == --* ]] ; then
                opts+="${ssh_arg} "
        fi
done

# Parse self link to get the project and the selfLink
project=$(echo "${selfLink}" | cut -d '/' -f7)
host=$(echo "${selfLink}" | cut -d '/' -f11)

exec gcloud --project "${project}" compute ssh --strict-host-key-checking=no \
        --ssh-flag="-o ControlPersist=15m" \
        --ssh-flag="-o ControlMaster=auto" \
        --ssh-flag="-o ControlPath=~/.ssh/gcp-%r@%h:%p" \
        --ssh-flag="-o ServerAliveInterval=60" \
        --ssh-flag="-o StrictHostKeyChecking=no" \
        --ssh-flag="-o UserKnownHostsFile=/dev/null" \
        $opts "${host}" -- -C "${cmd}"
