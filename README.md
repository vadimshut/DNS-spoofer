# DNS-spoofer
Simple dns spoofer from Kali Linux

Start internal web server
    
    service apache2 start

Redirect input and output packet to queue

    iptables -I OUTPUT -j NFQUEUE --queue-num 0

    iptables -I INPUT -j NFQUEUE --queue-num 0

Return to default setting iptables

    iptables --flush