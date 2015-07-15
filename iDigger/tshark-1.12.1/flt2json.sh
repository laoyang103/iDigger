#!/bin/bash

files=`ls . | grep packet..*bak$`
for f in $files:
do
    root=`cat $f | grep laotao | cut -d '-' -f 2-`
    if [ -z "$root" ]; then
        root=`echo $f | cut -d '-' -f 2 | cut -d '.' -f 1 | tr 'a-z' 'A-Z'`
    fi
    echo "$root: {"
    cat $f | grep -v '\.\"' | grep -v '\. ' | grep '\.' | awk -F '"' '{print "    \""$4"\""": ""\""$2"\","}'
    echo "}, "
done
#sed -i 's/\",\n/\",/g' $f
#cat $f | sed -n '/hf_register_info /,/\};/p' > $f".bak"

