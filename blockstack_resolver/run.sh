echo "Starting Apache2 ..."
/usr/sbin/apache2ctl start
echo "Starting memcached ..."
memcached -unobody &
echo "Warming up cache ..."
python -m tools.warmup_cache
echo "Synching cache with blockchain ..."
python -m tools.sync_cache --foreground
