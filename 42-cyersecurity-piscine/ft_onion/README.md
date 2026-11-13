


## Notes

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