#!/bin/bash

### Server setup script ###

# Define color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Updating befor
sudo apt update

install_packages_ubuntu() {
    echo -e "${GREEN}Installing Packages on Ubuntu...${NC}"
    
    sudo apt install -y vim curl zsh git gcc net-tools ruby ruby-dev tmux build-essential postgresql make python3-apt bind9 certbot python3-certbot-nginx libssl-dev zip unzip jq nginx pkg-config mysql-server php php-curl php-fpm php-mysql dnsutils whois python3-pip ca-certificates gnupg tmux nmap libpcap-dev
}

install_rust() {
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
}

install_tool() {

    local repo=$1
    local post_install_cmds=$2
    local tool_name=$(basename "$repo" .git)
       
    if [[ "$tool_name" == "recollapse" ]]; then
      
        python3 -m venv recollapse_venv
        source recollapse_venv/bin/activate

        git clone "$repo"
        cd "$tool_name"
        
        eval "$post_install_cmds"

        if [[ $? -eq 0 ]]; then
            echo -e "[+] Successfully installed $tool_name"
        else
            echo -e "[-] Failed to install $tool_name"
        fi
        
        cd -
        
     
        deactivate
    else

        git clone "$repo"
        cd "$tool_name"
        eval "$post_install_cmds"
        if [[ $? -eq 0 ]]; then
            echo -e "[+] Successfully installed $tool_name"
        else
            echo -e "[-] Failed to install $tool_name"
        fi
        cd -

   fi
 }

install_dnsgen() {
    
    python3 -m venv dnsgen_venv
    source dnsgen_venv/bin/activate

    python3 -m pip install dnsgen

    if [[ $? -eq 0 ]]; then
        echo -e "[+] Successfully installed dnsgen"
    else
        echo -e "[-] Failed to install dnsgen"
    fi
    
    cd -
    
   
    deactivate
}

install_tools_from_source() {
    echo -e "${GREEN}[+] Installing Tools from source...${NC}"
    mkdir -p Tools && cd Tools

    install_tool https://github.com/blechschmidt/massdns.git "make && sudo make install"
    install_tool https://github.com/robertdavidgraham/masscan.git "make && sudo make install"
    install_tool https://github.com/sqlmapproject/sqlmap.git ""
    install_tool https://github.com/phor3nsic/favicon_hash_shodan.git "sudo python3 setup.py install"
    # To use recollapse 1.cd Tools 2.source recollapse_venv/bin/activate
    install_tool https://github.com/0xacb/recollapse.git "pip3 install --upgrade -r requirements.txt && chmod +x install.sh && ./install.sh"
    install_tool https://github.com/jim3ma/crunch.git "make && sudo make install"
    install_tool https://github.com/Khode4li/wroxy-rotate "chmod +x run_wroxy"

    # To use recollapse 1.source dnsgen_venv/bin/activate
    install_dnsgen
    cargo install x8
    cargo install ripgen
    gem install wpscan

# param_maker file
    echo 'param_maker () {
            filename="$1"
            value="$2"
            counter=0
            query_string="?"
            while IFS= read -r keyword
            do
                if [ -n "$keyword" ]
                then
                    counter=$((counter+1))
                    query_string="${query_string}${keyword}=${value}${counter}&"
                fi
                if [ $counter -eq 25 ]
                then
                    echo "${query_string%?}"
                    query_string="?"
                    counter=0
                fi
            done < "$filename"
            if [ $counter -gt 0 ]
            then
                echo "${query_string%?}"
            fi
        }' >> nice_passive.py 

}

install_go() {
    get_latest_go_version() {
        curl -s https://go.dev/dl/ | grep -oP 'go[0-9]+\.[0-9]+\.[0-9]' | sort -uV | tail -1
    }

    GO_VERSION=$(get_latest_go_version)

    if [[ -z "$GO_VERSION" ]]; then
        echo -e "${RED}Failed to fetch the latest Go version. Aborting.${NC}"
        exit 1
    fi

    GO_BINARY_URL="https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz"
    INSTALL_DIR="/usr/local"

    curl -OL "$GO_BINARY_URL"
    sudo tar -C "$INSTALL_DIR" -xzf "${GO_VERSION}.linux-amd64.tar.gz"

    echo "export PATH=\$PATH:$INSTALL_DIR/go/bin" >> "$HOME/.bashrc"
    source "$HOME/.bashrc"

    rm "${GO_VERSION}.linux-amd64.tar.gz"

    if go version &> /dev/null; then
        echo -e "[+] Installing go tools..."
        install_go_package() {
            package=$1
            if go install $package &> /dev/null; then
                echo -e "${GREEN}[+] Successfully installed $package${NC}"
            else
                echo -e "${RED}[-] Failed to install $package${NC}"
            fi
        }

        install_go_package github.com/tomnomnom/waybackurls@latest
        #install_go_package github.com/projectdiscovery/alterx/cmd/alterx@latest
        install_go_package github.com/projectdiscovery/dnsx/cmd/dnsx@latest
        #install_go_package github.com/projectdiscovery/tlsx/cmd/tlsx@latest
        install_go_package github.com/tomnomnom/anew@latest
        #install_go_package github.com/glebarez/cero@latest
        install_go_package github.com/iangcarroll/cookiemonster/cmd/cookiemonster@latest
        install_go_package github.com/ffuf/ffuf/v2@latest
        install_go_package github.com/lc/gau/v2/cmd/gau@latest
        install_go_package github.com/jaeles-project/gospider@latest
        install_go_package github.com/projectdiscovery/httpx/cmd/httpx@latest
        install_go_package github.com/hahwul/dalfox/v2@latest
        install_go_package github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
        install_go_package github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
        install_go_package github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
        install_go_package github.com/tomnomnom/unfurl@latest
        install_go_package github.com/projectdiscovery/asnmap/cmd/asnmap@latest
        #install_go_package github.com/xm1k3/cent@latest
        #install_go_package github.com/projectdiscovery/chaos-client/cmd/chaos@latest
        install_go_package github.com/OJ/gobuster/v3@latest
        install_go_package github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
        install_go_package github.com/projectdiscovery/katana/cmd/katana@latest
        install_go_package github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
        install_go_package github.com/projectdiscovery/notify/cmd/notify@latest
        install_go_package github.com/d3mondev/puredns/v2@latest
        install_go_package github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        #install_go_package github.com/projectdiscovery/uncover/cmd/uncover@latest
        install_go_package github.com/ImAyrix/cut-cdn@latest
        install_go_package github.com/sw33tLie/sns@latest
        install_go_package github.com/BishopFox/jsluice/cmd/jsluice@latest
        install_go_package github.com/ImAyrix/fallparams@latest
        install_go_package github.com/glitchedgitz/cook/v2/cmd/cook@latest
        install_go_package github.com/BishopFox/sj@latest
        install_go_package github.com/sw33tLie/sns@latest
        install_tool https://github.com/assetnote/kiterunner.git "make build && ln -s $(pwd)/Tools/kiterunner/dist/kr /usr/local/bin/kr" 
    fi
}

install_packages_ubuntu
install_rust
install_tools_from_source
install_go

# Setting up Go environment
if ! grep -q "export PATH=\$PATH:/usr/local/go/bin" ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    echo "Go environment configured in .bashrc."
    
else
    echo "Go environment already configured in .bashrc."
fi

# .bashrc config
{
    if ! grep -q 'alias nice_passive=' ~/.bashrc; then
        echo 'alias nice_passive="~/Tools/nice_passive.py"'
    fi

    if ! grep -q 'get_certificate' ~/.bashrc; then
        echo 'get_certificate () {
            openssl s_client -showcerts -servername $1 -connect $1:443 2> /dev/null | openssl x509 -inform pem -noout -text
        }'
    fi

    if ! grep -q 'httpx_full' ~/.bashrc; then
        echo 'httpx_full() {
            httpx -silent -follow-host-redirects -title -status-code -cdn -tech-detect \
            -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" \
            -H "Referer: https://llegit.com" -threads 1
        }'
    fi

    if ! grep -q 'dns_brute_full' ~/.bashrc; then
        echo 'dns_brute_full () {
            echo "cleaning..."
            rm -f "$1.wordlist $1.dns_brute $1.dns_gen"
            echo "making static wordlist..."
            awk -v domain="$1" "{print \$0\".\"domain}" "$WL_PATH./subdomains-assetnote-merged.txt" >> "$1.wordlist"
            echo "making 4 chars wordlist..."
            awk -v domain="$1" "{print \$0\".\"domain}" "$WL_PATH./4-lower.txt" >> "$1.wordlist"
            echo "shuffledns static brute-force..."
            shuffledns -list $1.wordlist -d $1 -r ~/.resolvers -m $(which massdns) -mode resolve -t 30 -silent | tee $1.dns_brute 2>&1 > /dev/null
            echo "[+] finished, total $(wc -l $1.dns_brute) resolved..."
            echo "running subfinder..."
            subfinder -d $1 -all | dnsx -silent | anew $1.dns_brute 2>&1 > /dev/null
            echo "[+] finished, total $(wc -l $1.dns_brute) resolved..."
            echo "running DNSGen..."
            cat $1.dns_brute | dnsgen -w $WL_PATH/subdomains/words.txt - > $1.dns_gen 2>&1 > /dev/null
            echo "finished with $(wc -l $1.dns_gen) words..."
            echo "shuffledns dynamic brute-force on dnsgen results..."
            shuffledns -list $1.dns_gen -d $1 -r ~/.resolvers -m $(which massdns) -mode resolve -t 30 -silent | anew $1.dns_brute 2>&1 > /dev/null
            echo "[+] finished, total $(wc -l $1.dns_brute) resolved..."
        }'
    fi

    if ! grep -q 'get_ptr' ~/.bashrc; then
        echo 'get_ptr () {
            input=""
            while read line && [[ "$line" != "END_OF_INPUT" ]]
            do
                input="$input$line\n"
            done
            echo $input | dnsx -silent -resp-only -ptr
        }'
    fi

    if ! grep -q 'get_ip_prefix' ~/.bashrc; then
        echo 'get_ip_prefix () {
            input=""
            while read line
            do
                curl -s https://api.bgpview.io/ip/$line | jq -r ".data.prefixes[0].asn.prefix"
            done < "${1:-/dev/stdin}"
        }'
    fi

    if ! grep -q 'get_asn_details' ~/.bashrc; then
        echo 'get_asn_details () {
            input=""
            while read line
            do
                curl -s https://api.bgpview.io/asn/$line | jq -r ".data | {asn: .asn, name: .name, des: .description_short, email: .email_contacts}"
            done < "${1:-/dev/stdin}"
        }'
    fi

    if ! grep -q 'get_ip_asn' ~/.bashrc; then
        echo 'get_ip_asn () {
            input=""
            while read line
            do
                curl -s https://api.bgpview.io/ip/$line | jq -r ".data.prefixes[0].asn.asn"
            done < "${1:-/dev/stdin}"
        }'
    fi

    if ! grep -q 'get_certificate_nuclei' ~/.bashrc; then
        echo 'get_certificate_nuclei() {
            cat "${1:-/dev/stdin}" | nuclei -t ~/hunt-server/wide_recon/ssl.yaml -silent -j | jq -r ".["extracted-results"][]"
        }'
    fi

    if ! grep -q 'function whois_search' ~/.bashrc; then
        echo 'function whois_search() {
            while read line; do
                $(whois $line > whois_search_temp)
                result=$(cat whois_search_temp | grep OrgName | grep -i $1)
                cidr=$(cat whois_search_temp | grep -i cidr)
                if [[ -n "$result" ]]; then
                    echo $line
                    echo $result
                    echo $cidr
                fi
            done
        }'

    fi

    if ! grep -q 'function nice_katana' ~/.bashrc; then 
        echo 'function nice_katana () {
            while read line
            do
                host=$(echo $line | unfurl format %d)
                echo "$line" | katana -js-crawl -jsluice -known-files all -automatic-form-fill -silent -crawl-scope $host -extension-filter json,js,fnt,ogg,css,jpg,jpeg,png,svg,img,gif,exe,mp4,flv,pdf,doc,ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,ml,ip | tee ${host}.katana
            done < "${1:-/dev/stdin}"
        }'
    fi

    if ! grep -q 'wlist_maker' ~/.bashrc; then
        echo 'param_maker () {
                filename="$1"
                value="$2"
                counter=0
                query_string="?"
                while IFS= read -r keyword
                do
                    if [ -n "$keyword" ]
                    then
                        counter=$((counter+1))
                        query_string="${query_string}${keyword}=${value}${counter}&"
                    fi
                    if [ $counter -eq 25 ]
                    then
                        echo "${query_string%?}"
                        query_string="?"
                        counter=0
                    fi
                done < "$filename"
                if [ $counter -gt 0 ]
                then
                    echo "${query_string%?}"
                fi
            }'
    fi

    if ! grep -q 'wlist_maker' ~/.bashrc; then
        echo 'wlist_maker () {
                seq 1 100 > list.tmp
                echo $1 >> list.tmp
                seq 101 300 >> list.tmp
                echo $1 >> list.tmp
                seq 301 600 >> list.tmp
        }'
    fi

} >> ~/.bashrc

source ~/.bashrc

echo ".bashrc configuration updated."

echo -e "${GREEN}[*_*] Server is ready for hunting${NC}"





