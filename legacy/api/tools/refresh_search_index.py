#!/bin/bash

while true; do
        sudo echo "starting refresh" 
        python search/substring_search.py --create_index
        sudo service apache2 restart
        echo "-------------------------";
        sleep 21600;
done
