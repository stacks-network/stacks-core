DEBIAN BUILD NOTES
====================
Some notes on how to build Namecoin daemon on Debian. Ubuntu should work similar to Debian as well.  

Get the Namecoin source
---------------------

	sudo apt-get update
	sudo apt-get install git
	git clone https://github.com/namecoin/namecoin.git

Get the required packages
---------------------

	sudo apt-get install -y build-essential
	sudo apt-get install -y libssl-dev
	sudo apt-get install -y libboost-all-dev
	sudo apt-get install -y libminiupnpc-dev
	sudo apt-get install -y libglib2.0-dev libglibmm-2.4-dev
	
Install LibDB
---------------------

Debian 7 (Wheezy) and later have packages for libdb5.1-dev and libdb5.1++-dev, but using these will break binary wallet compatibility, and is not recommended. The oldstable repository contains db4.8 packages. Add the following line to /etc/apt/sources.list, can use any official debian mirror.

	sudo vi /etc/apt/sources.list
	deb http://ftp.us.debian.org/debian/ oldstable main
        
To enable the change run

	sudo apt-get update
	
And now you can install the libdb4.8 packages

	sudo apt-get install -y libdb4.8-dev libdb4.8++-dev
	
Compile the source
---------------------

You can now compile namecoind

	cd namecoin/src
	make namecoind 

Starting Namecoind
---------------------

Run namecoind once, so that it initializes the files in ~/.namecoin directory 

	./namecoind 
	
Now create the namecoin.conf file

	touch ~/.namecoin/namecoin.conf
	chmod 600 ~/.namecoin/namecoin.conf
	
Open the namecoin.conf file and enter values for rpcuser and rpcpassword

	vi ~/.namecoin/namecoin.conf
	rpcuser=<type_here>
	rpcpassword=<type_strong_passwd_here>

You should now be able to run namecoind  

	./namecoind -daemon
	
Get basic stats to confirm that your installation was successful (it takes a few minutes for namecoind to start)

	./namecoind getinfo
