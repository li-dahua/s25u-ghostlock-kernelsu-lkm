#!/system/bin/sh
ui_print "- roothelper: uid=$(id -u) ctx=$(cat /proc/self/attr/current 2>/dev/null)"
setenforce 0 2>/dev/null
getenforce > /data/local/tmp/rootprobe.txt 2>&1
id >> /data/local/tmp/rootprobe.txt
chmod 666 /data/local/tmp/rootprobe.txt 2>/dev/null
ui_print "- roothelper: $(cat /data/local/tmp/rootprobe.txt | tr '\n' ' ')"
