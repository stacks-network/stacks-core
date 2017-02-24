sudo apt-get update && sudo apt-get install -y python-pip python-dev libssl-dev libffi-dev rng-tools libgmp3-dev
sudo pip install git+https://github.com/blockstack/virtualchain.git@rc-0.14.1 --upgrade
sudo pip install git+https://github.com/blockstack/dns-zone-file-py.git@rc-0.14.1 --upgrade
sudo pip install git+https://github.com/blockstack/blockstack-profiles-py.git@rc-0.14.1 --upgrade
sudo pip install fastecdsa
sudo pip install git+https://github.com/blockstack/blockstack-core.git@rc-0.14.1b --upgrade