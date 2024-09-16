# Ready_to_hunt
A handy tool for setting up a server for bug hunting.




## Installation
1. ``` git clone https://github.com/Compact-Blue/Ready_to_hunt.git && cd Ready_to_hunt ```
2. ``` chmod +x setup.sh && ./setup.sh ```

## What does Ready_to_hunt do?

### Installs all the packages and programs you might need: 
  - vim
  - curl
  - zsh
  - git
  - gcc
  - net-tools
  - ruby
  - ruby-dev
  - tmux
  - build-essential
  - postgresql
  - make
  - python3-apt
  - bind9
  - certbot
  - python3-certbot-nginx
  - libssl-dev
  - zip
  - unzip
  - jq
  - nginx
  - pkg-config
  - mysql-server
  - php php-curl
  - php-fpm php-mysql
  - dnsutils
  - whois
  - python3-pip
  - ca-certificates
  - gnupg
  - tmux
  - nmap
  - libpcap-dev

### Installs all the tools you need for bug hunting:
  #### Wide Recon Tools
  - subfinder
  - asnmap
  - mapcidr
  - cut-cdn
  - sns
  - puredns
  - shuffledns
  - uncover
  - naabu
  - httpx
  - dnsx
  - wpscan
  - alterx

  #### Narrow Recon Tools
  - waybackurls
  - ffuf
  - gau
  - fallparams
  - katana
  - x8
  - gospider
  - kiterunner
  - grpcurl
  - jsluice
  - wroxy

  #### Vulnerability Discovery Tools
  - dalfox
  - sqlmap
  - nuclei
  - gobuster
  - cookiemonster

  #### Easier Hunting Tools
  - anew
  - unfurl
  - cent
  - notify
  - cook

### Adds helpful bash commands for hunting to your .bashrc:
`Note`: You can run any command by calling it and providing inputs if needed.
  - get_certificate
  - get_certificate_nuclei
  - httpx_full
  - dns_brute_full
  - get_ptr
  - get_ip_prefix
  - get_asn_details
  - get_ip_asn
  - nice_katana
  - whois_search
  - param_maker
  - wlist_maker

`Note`: If your server is using zsh, switch to bash.  
`Note`: If bash commands don’t work, try running this command: `source .bashrc`
