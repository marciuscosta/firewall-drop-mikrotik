#!/bin/bash
#
# Script que cria e deleta regras de firewall no Mikrotik. Usado pelo active-response do Wazuh.
#
# Por Marcius em 16/08/2022

LOG_AR=/var/ossec/logs/active-responses.log

# Verifica se o 'jq' esta instalado no SO
if [[ `which jq ; echo $? ` -ne 0 ]]; then
        echo "`date` - O 'jq' precisa estar instalado no sistema operacional. Script finalizado." >> $LOG_AR
        exit 1
fi

# Captura o alerta passado pelo Wazuh em formato json e salva na variavel ALERTA
read -r ALERTA

ACAO=`echo $ALERTA | jq '.command' | tr -d "\""`
ALERTA_ID=`echo $ALERTA | jq '.parameters.alert.id' | tr -d "\""`
IP=`echo $ALERTA | jq '.parameters.alert.data.srcip' | tr -d "\""`
SSH_KEY=/var/ossec/ssh_keys/mikrotik_wazuh.rsa
SSH_USER=wazuh-ar
IP_MIKROTIK=10.0.1.253

# Logando
echo "`date` $0 $ALERTA" >> $LOG_AR

if [[ $ACAO == "add" ]]; then
        # Send control message to execd
        printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":["$IP"]}}\n'

        read RESPONSE
        COMMAND2=$(echo $RESPONSE | jq -r .command)
        if [ ${COMMAND2} != "continue" ]; then
                echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $ALERTA" >> ${LOG_AR}
                exit 0;
        fi
        ssh -i $SSH_KEY -l $SSH_USER $IP_MIKROTIK /ip firewall filter add action=drop chain=input src-address=$IP comment=$ALERTA_ID
elif [[ $ACAO == "delete" ]]; then
        ssh -i $SSH_KEY -l $SSH_USER $IP_MIKROTIK /ip firewall filter remove [find comment=$ALERTA_ID]
else
        echo "`date` $0 'Erro ao executar o script - '$ALERTA" >> $LOG_AR
fi
