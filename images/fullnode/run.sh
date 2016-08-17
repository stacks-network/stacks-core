echo "Starting namecoind ..."
/srv/namecoin/src/namecoind --daemon &

while true;
do
    out=$(/srv/namecoin/src/namecoind getinfo)

    if [[ $out == *"block"* ]];
    then
        echo "Namecoind is live"
        break
    else
        echo "Namecoind is loading, wait ..."
        sleep 1
    fi
done

echo "Starting Apache2 ..."
/usr/sbin/apache2ctl start
echo "Starting memcached ..."
memcached -unobody &
echo "Warming up cache ..."
python -m tools.warmup_cache
echo "Synching cache with blockchain ..."
python -m tools.sync_cache --foreground
