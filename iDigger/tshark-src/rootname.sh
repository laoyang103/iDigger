#!/bin/bash

files=`ls . | grep packet..*c$`

for f in $files:
do 
    line=`cat $f | sed -n '/proto_register_protocol..*$/p'`
    pname="\""`cat $f | grep '#define PNAME' | awk -F '\"' '{print $2}'`"\""
    if [ -n "$pname" ]; then
        line=`echo $line | sed "s/PNAME/$pname/g"`
    fi
    if [ -n "$line" ]; then
        name="\""`echo $f | awk -F '.' '{print $1}' | cut -d '-' -f 2- | tr 'a-z' 'A-Z'`
        desc=`echo $line | awk -F '\"' '{print $2}'`"\""
        echo "laotao-"$name" - "$desc >> /root/iDigger/dissectors/$f".bak"
    fi

#    sed -i 's/proto_register_protocol(\t\t*/proto_register_protocol(/g' $f
#    sed -i ':a;N;$!ba;s/proto_register_protocol (\n/proto_register_protocol(/g' $f

done
