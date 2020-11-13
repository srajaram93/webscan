#!/usr/bin/bash

apt update
apt install python3-pip -y
apt install golang-go -y
apt-get install jq -y
apt-get install cargo -y
pip install colored
pip3 install colored
pip install tldextract
pip3 install tldextract

#Building Directories and Adding Files

if [ ! -d "/root/webscan/Tools/GitHubTool/github-endpoints.py"]
then
  git clone https://github.com/gwen001/github-search.git /root/webscan/Tools/GitHubTool/
elif [ ! -d "/root/webscan"]
then	
  mkdir /root/webscan
elif [ ! -d "/root/webscan/domains.txt"]
then
	touch /root/webscan/domains.txt
elif [ ! -d "/root/webscan/Targets"]
then
  mkdir /root/webscan/Targets
elif [ ! -d "/root/webscan/Tools/"]
then
  mkdir /root/webscan/Tools/
elif [ ! -d "/root/webscan/Tools/GitHubTool"]
then
  mkdir /root/webscan/Tools/GitHubTool
elif [ ! -d "/root/wordlists"]
then
  mkdir /root/wordlists
elif [ ! -d "/root/githubkey/"]
then
  mkdir /root/githubkey/
fi 

wget https://gist.githubusercontent.com/nullenc0de/96fb9e934fc16415fbda2f83f08b28e7/raw/146f367110973250785ced348455dc5173842ee4/content_discovery_nullenc0de.txt -O /root/wordlists/endpoints.txt
wget https://gist.githubusercontent.com/srajaram93/5f2e20027702b5e96f3c1074878cce06/raw/c97c8f8d07a8aa23f718da1960bdb17b0a647d18/10k-subdomains.txt -O /root/wordlists/subdomains.txt
wget https://raw.githubusercontent.com/OWASP/Amass/master/examples/config.ini -O /root/config.ini
echo 71356b8cfdadd4e051ac44776aac88321be31d19 > /root/githubkey/key.txt

#Installing Required Tools

export GOPATH=/opt/amass
go get -v -u github.com/OWASP/Amass
ln -s /opt/amass/bin/amass /usr/bin/amass


#FFUF
export GOPATH=/opt/ffuf
go get -u github.com/ffuf/ffuf
ln -s /opt/ffuf/bin/ffuf /usr/bin/ffuf

#FINDOMAIN
git clone https://github.com/Edu4rdSHL/findomain.git
cd findomain
cargo build --release
cp target/release/findomain /usr/bin/
cd /root/

# ASSETFINDER
export GOPATH=/opt/assetfinder
go get -u github.com/tomnomnom/assetfinder
ln -s /opt/assetfinder/bin/assetfinder /usr/bin/assetfinder

#HTTProbe
export GOPATH=/opt/httprobe
go get -u github.com/tomnomnom/httprobe
ln -s /opt/httprobe/bin/httprobe /usr/local/bin/httprobe

#FPROBE
export GOPATH=/opt/fprobe
go get -u github.com/theblackturtle/fprobe
ln -s /opt/fprobe/bin/fprobe /usr/bin/fprobe


#SUBFINDER
export GOPATH=/opt/subfinder
go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
ln -s /opt/subfinder/bin/subfinder /usr/bin/subfinder


#FILTER-RESOLVED
export GOPATH=/opt/filter-resolved
go get -u github.com/tomnomnom/hacks/filter-resolved
ln -s /opt/filter-resolved/bin/filter-resolved /usr/bin/filter-resolved


#WILDCHECK
export GOPATH=/opt/wildcheck
go get -u github.com/theblackturtle/wildcheck
ln -s /opt/wildcheck/bin/wildcheck /usr/bin/wildcheck


#QSREPLACE
export GOPATH=/opt/qsreplace
go get -u github.com/tomnomnom/qsreplace
ln -s /opt/qsreplace/bin/qsreplace /usr/bin/qsreplace


#GOSPIDER
export GOPATH=/opt/gospider
go get -u github.com/jaeles-project/gospider
ln -s /opt/gospider/bin/gospider /usr/bin/gospider


#KXSS
export GOPATH=/opt/kxss
go get -u github.com/tomnomnom/hacks/kxss
ln -s /opt/kxss/bin/kxss /usr/bin/kxss


#NUCLEI
export GOPATH=/opt/nuclei
go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
ln -s /opt/nuclei/bin/nuclei /usr/bin/nuclei


#WAYBACKURLS
export GOPATH=/opt/waybackurls
go get -u github.com/tomnomnom/waybackurls
ln -s /opt/waybackurls/bin/waybackurls /usr/bin/waybackurls


#GETALLURLS
export GOPATH=/opt/gau
go get -u github.com/lc/gau
ln -s /opt/gau/bin/gau /usr/bin/gau


apt-get install npm
npm install uniq
