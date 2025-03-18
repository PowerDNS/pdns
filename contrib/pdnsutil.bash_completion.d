# simple & stupid implementation of bash completion for pdnsutil
#
# (C) 2016 Joerg Jungermann
#
# License: GPLv2
#
#   put it into /etc/bash_completion.d/
#
# pdnsutil <TAB>           - expands to known operations given as $1
# pdnsutil YOUNAMEIT <TAB> - completes to available zones, might be expensive with many (>10000) zones
#

which pdnsutil >/dev/null 2>&1

if [ "${?}" -eq 0 ]
then
  _pdnsutil_helper_local_() {
    local cur prev cmd

    local _PDNSUTIL_ALL_CMDS="activate-tsig-key activate-zone-key add-record add-autoprimary remove-autoprimary list-autoprimaries add-zone-key backend-cmd b2b-migrate bench-db
                              check-zone check-all-zones clear-zone create-bind-db create-secondary-zone change-secondary-zone-primary create-zone deactivate-tsig-key
                              deactivate-zone-key delete-rrset delete-tsig-key delete-zone disable-dnssec edit-zone export-zone-dnskey export-zone-ds export-zone-key
                              export-zone-key-pem generate-tsig-key generate-zone-key get-meta hash-password hash-zone-record hsm hsm increase-serial import-tsig-key
                              import-zone-key import-zone-key-pem ipdecrypt ipencrypt load-zone list-algorithms list-keys list-zone list-all-zones list-member-zones
                              list-tsig-keys publish-zone-key rectify-zone rectify-all-zones remove-zone-key replace-rrset secure-all-zones secure-zone set-kind set-options-json
                              set-option set-catalog set-account set-nsec3 set-presigned set-publish-cdnskey set-publish-cds add-meta set-meta show-zone unpublish-zone-key
                              unset-nsec3 unset-presigned unset-publish-cdnskey unset-publish-cds test-schema raw-lua-from-content zonemd-verify-file lmdb-get-backend-version"
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    case "$prev" in
      pdnsutil )
        COMPREPLY=( $(compgen -W "$_PDNSUTIL_ALL_CMDS" -- $cur) )
        return 0
        ;;
    esac
    case "$_PDNSUTIL_ALL_CMDS" in
      "$prev "* | *" $prev "* | *" $prev" )
        prevprev="${COMP_WORDS[COMP_CWORD-2]}"
        COMPREPLY=( $(compgen -W "$($prevprev list-all-zones | head -n -1 )" -- $cur) )
        return 0
        ;;
    esac
  }

  complete -o default -F _pdnsutil_helper_local_ pdnsutil
fi
