#!/bin/bash
# This is a wrapper script allowing to use GCP's IAP option to connect
# to our servers.

# Ansible passes a large number of SSH parameters along with the hostname as the
# second to last argument and the command as the last. We will pop the last two
# arguments off of the list and then pass all of the other SSH flags through
# without modification:
selfLink="${@: -1: 1}"
src="${@: -2: 1}"

# Unfortunately ansible has hardcoded scp options, so we need to filter these out
# It's an ugly hack, but for now we'll only accept the options starting with '--'
declare -a opts
for scp_arg in "${@: 1: $# -3}" ; do
        if [[ "${scp_arg}" == --* ]] ; then
                opts+="${scp_arg} "
        fi
done

# Parse self link to get the project and the selfLink
project=$(echo "${selfLink}" | tr -d [] | cut -d '/' -f7)
host=$(echo "${selfLink}" | tr -d [:] | cut -d '/' -f11)
dest=$(echo "${selfLink}" | cut -d ':' -f3 | tr -d [:])

#echo "gcloud --project ${project} compute scp $opts ${src} ${host}:${dest}"
exec gcloud --project "${project}" compute scp $opts "${src}" "${host}:${dest}"