## Intructions

Requirement:
  Debian VM
  Tor
  Nginx

Run it in a virtual machine:
```
# create /var/www/onion and copy index.html to it
sudo mkdir /var/www/onion
sudo cp index.html /var/www/onion
sudo chmod +r /var/www/onion/index.html

# install nginx, tor, openssh-server if required
sudo apt udate
sudo apt install nginx tor ssh openssh-server
# IF you get 'sshd: no hostkeys available -- exiting'
sudo ssh-keygen -A
# IF you receive 'Missing privilege separation directory: /run/sshd'
sudo install -d -o root -g root -m 0755 /run/sshd

# set all config files
cd ft_onion
sudo nginx -c /absolute_path/nginx.conf
sudo tor -f /absolute_path/torrc
sudo sshd -f /absolute_path/sshd_config

# check if all uses the correct config
pgrep -a nginx

# restart service if required
sudo service tor restart

# check all services and ports listening are correct (matches config)
sudo ss -lntp

# find onion address in /var/lib/tor/hidden_service/hostaname
curl --socks5-hostname http://127.0.0.1:9050 https:://onion_address.onion

```

## Notes

Tor -> guard relay -> middle relay -> exit relay -> website

By default, Onion Services publish a “Hidden Service Descriptor” to the Tor network’s distributed Hidden Service Directory (HDir) (every few hours?).

HDir is tor relay assigned to store and serve these descriptors.

The Hidden Service Descriptor returned by the HDir contains the metadata necessary for a client to connect to the Onion Service.

Run tor from cli in linux
```
cd tor-browser
./start-tor-browser.desktop

# to use tor browser without tor network (for testing)
./start-tor-browser.desktop --no-tor
# launch in safe-mode
./start-tor-browser.desktop --safe-mode
```

check.torproject.org

```
sudo apt install tor
man tor
sudo nano /etc/tor/torrc # uncomment the 2 lines
sudo service tor stop
sudo service tor start
sudo service tor status
sudo cat /var/lib/tor/hidden_service/hostname # see your onion hostname

curl ifconfig.me #compare your ip with tor with command below
torify curl ifconfig.me 2>/dev/null

sudo apt install nginx
sudo service nginx start
sudo service nginx status
sudo nano /etc/nginx/nginx.conf # uncomment server_tokens off, server_name_in_redirect off and add port_in_redirect off
sudo service nginx restart
```

vanity prefixes: 56-character onion link starts with something like “facebook,” “bbcnews,” or “ciadotgov.” 
[mkp224o](https://github.com/cathugger/mkp224o) vanity address generator for ed25519 onion services
dark web directories like [Hidden Wiki](https://thehiddenwiki.org/)


## Resources

[How to install Tor](https://support.torproject.org/little-t-tor/getting-started/installing/)
[Set up Your Onion Service](https://community.torproject.org/onion-services/setup/)
[NetWorkChuck video: i put a DARK WEB website on a Raspberry Pi!!](https://www.youtube.com/watch?v=bllS9tkCkaM) - intro to tor network