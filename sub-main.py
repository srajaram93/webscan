#!/usr/bin/python
import os
import sys
import time

print "{: ^203s}".format("USAGE: python sub-main.py domain.txt OR python sub-main.py domain.com \n")
 

#Build Necessary Directories
if not os.path.isdir("/root/webscan"):
	os.mkdir("/root/webscan")
if not os.path.exists("/root/webscan/domains.txt"):
	os.system("touch /root/webscan/domains.txt")
if not os.path.isdir("/root/webscan/Targets"):
	os.mkdir("/root/webscan/Targets")
if not os.path.isdir("/root/webscan/Tools/"):
	os.mkdir("/root/webscan/Tools/")
if not os.path.isdir("/root/webscan/Tools/GitHubTool"):
	os.mkdir("/root/webscan/Tools/GitHubTool")
if not os.path.exists("/root/webscan/Tools/GitHubTool/github-endpoints.py"):
	os.system("git clone https://github.com/gwen001/github-search.git /root/webscan/Tools/GitHubTool/")
	
##Main Function
	
def scanner(b,d_str,key):
        if not os.path.isdir("/root/webscan/Targets/"+b):
                os.mkdir("/root/webscan/Targets/"+b)
        if not os.path.isdir("/root/webscan/Targets/"+b+"/Hosts"):
                os.mkdir("/root/webscan/Targets/"+b+"/Hosts")
        if not os.path.isdir("/root/webscan/Targets/"+b+"/NotScanned"):
                os.mkdir("/root/webscan/Targets/"+b+"/NotScanned")
        if not os.path.isdir("/root/webscan/Targets/"+b+"/Gobuster"):
                os.mkdir("/root/webscan/Targets/"+b+"/Gobuster")
        if not os.path.exists("/root/webscan/Targets/"+b+"/"+b+".root.txt"):
                os.system("echo "+b+" > /root/webscan/Targets/"+b+"/"+b+".root.txt")
        if not os.path.isdir("/root/webscan-output"):
        	os.mkdir("/root/webscan-output")
        if not os.path.isdir("/root/webscan-output/"+b):
        	os.mkdir("/root/webscan-output/"+b)
        if not os.path.isdir("/root/webscan-output/all"):
        	os.mkdir("/root/webscan-output/all")
        os.system("cat /root/webscan/Targets/"+b+"/"+b+".root.txt | grep -Po '[\w\s]+(?=\.)' >> /root/webscan/Targets/"+b+"/"+b+".domain.txt")
        os.chdir("/root/webscan/Targets/"+b)
        os.system("echo '\e[31m[STARTING "+d_str.upper()+"]\e[0m'\n")

                                                                                       #SUB DOMAIN DISCOVERY

        #LAUNCH ACTIVE AMASS
        os.system("echo '\nRUNNING \e[31m[AMASS ACTIVE]\e[0m'\n")
        os.system("amass enum -config /root/config.ini -min-for-recursive 3 -brute --max-dns-queries 25000 -d "+d_str+" -o /root/webscan/Targets/"+b+"/"+b+".amassactive.txt")
   #  d = sum(1 for line in open('/root/webscan/Targets/"+b+"/"+b+".amassactive.txt')) 
    #    if d == 0:
     #          sys.exit('Nothing Found')

        #LAUNCH ASSETFINDER
        os.system("echo '\nRUNNING  \e[31m[ASSETFINDER]\e[0m'\n")
        os.system("assetfinder -subs-only "+d_str+" > /root/webscan/Targets/"+b+"/"+b+".assetfinder.txt")
        os.system("echo 'ASSETFINDER \e[32mFINISHED\e[0m'\n")

        ## LAUNCH FINDOMAIN
        os.system("echo '\nRUNNING \e[31m[FINDOMAIN]\e[0m'\n")
        os.system("findomain -t "+d_str+" -o ")
        os.system ("echo 'RUNNING FINDOMAIN \e[32mFINISH\e[0m'\n")

        ## LAUNCH DNSBUFFER
        os.system("echo -e '\nRUNNING \e[31m[DNSBUFFEROVER]\e[0m'\n")
        os.system("curl -s https://dns.bufferover.run/dns?q=."+d_str+" | jq -r .FDNS_A[]|cut -d',' -f2 > /root/webscan/Targets/"+b+"/"+b+".dnsbuffer.txt")
        os.system("echo 'DNSBUFFER \e[32mFINISHED\e[0m'\n")
        
        ## LAUNCH CRTSH JUST IN CASE
        os.system("echo -e '\nRUNNING \e[31m[CRT.SH]\e[0m'\n")
        os.system("curl -s https://crt.sh/?q=%.d_str > /tmp/curl.out")
	os.system("cat /tmp/curl.out | grep "+d_str+" | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | httprobe  | sort -u > /root/webscan/Targets/"+b+"/"+b+".crtsh.txt")
	os.system("cat /root/webscan/Targets/"+b+"/"+b+".crtsh.txt")
	os.system("echo 'CRT.SH \e[32mFINISHED\e[0m'\n")

        ## LAUNCH SUBFINDER
        os.system("echo '\nRUNNING \e[31m[SUBFINDER]\e[0m'\n")
        os.system("subfinder -d "+d_str+" -o /root/webscan/Targets/"+b+"/"+b+".subfinder.txt")
        os.system("echo 'SUBFINDER \e[32mFINISHED\e[0m'\n")
        
        ## LAUNCH SUBDOMAIN BRUTEFORCE
        os.system("echo '\nRUNNING \e[31m[SUBDOMAIN BRUTEFORCE]\e[0m'\n")
        os.system("ffuf -w /root/wordlists/subdomains.txt -u https://FUZZ."+d_str+" -H https://FUZZ."+d_str+" -H http://FUZZ."+d_str+" -t 100 -mc 200 -o /root/webscan-output/Targets/"+b+"/"+b+".brutesubdomains.csv -of csv")
        if not os.path.exists("/root/webscan-output/Targets/"+b+"/"+b+".brutesubdomains.csv"):
        	print("No Subdomain found during Bruteforce")
        else:
        	os.system("cat /root/webscan-output/Targets/"+b+"/"+b+".brutesubdomains.csv |cut -d , -f3|qsreplace -a >> /root/webscan/Target/"+b+"/"+b+".brutesubdomains.txt")
        os.system("echo 'SUBDOMAIN BRUTEFORCE \e[32mFINISHED\e[0m'\n")

        ## REMOVING DUPLICATES
        os.system("echo '\nREMOVING \e[31m[DUPLICATES]\e[0m'\n")
        os.system("sort /root/webscan/Targets/"+b+"/*.txt | uniq > /root/webscan/Targets/"+b+"/"+b+".alldomains.txt")
        os.system("echo 'REMOVING DUPLICATES \e[32mFINISH\e[0m'\n")
    #   os.system("wildcheck -i /root/webscan/Targets/"+b+"/"+b+".alldomains.txt -t 100 -p |grep 'non-wildcard' |cut -d ' ' -f3 > /root/webscan/Targets/"+b+"/"+b+".resolved_no_wildcard.txt")


        ## LAUNCH LIVEHOSTS
        os.system("echo '\nRUNNING \e[31m[LIVEHOSTS]\e[0m'\n")
        os.system("cat /root/webscan/Targets/"+b+"/"+b+".alldomains.txt > /root/webscan/Targets/"+b+"/"+b+".resolved.txt")
        os.system("mv /root/webscan/Targets/"+b+"/"+b+".resolved.txt /root/webscan/Targets/"+b+"/Hosts/")
        os.system("rm /root/webscan/Targets/"+b+"/*.txt")
        os.system("sed 's/http:\/\///g; s/https:\/\///g; s/nwww\.//g; s/www\.//g; s/\*\.//g' /root/webscan/Targets/"+b+"/Hosts/"+b+".resolved.txt | sort -u > /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:81 -p https:300 -p https:591 -p https:593 -p https:832 -p https:981 -c 50 > /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:1010 -p https:1311 -p https:2082 -p https:2087 -p https:2095 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:2096 -p https:2480 -p https:3000 -p https:3128 -p https:3333 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:4243 -p https:4567 -p https:4711 -p https:4712 -p https:4993 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:5000 -p https:5104 -p https:5108 -p https:5800 -p https:6543 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:7000 -p https:7396 -p https:7474 -p https:8000 -p https:8001 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:8008 -p https:8014 -p https:8042 -p https:8069 -p https:8080 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:8081 -p https:8083 -p https:8088 -p https:8090 -p https:8091 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:8118 -p https:8123 -p https:8172 -p https:8222 -p https:8243 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:8280 -p https:8281 -p https:8333 -p https:8443 -p https:8500 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:8834 -p https:8880 -p https:8888 -p https:8983 -p https:9000 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:9043 -p https:9060 -p https:9080 -p https:9090 -p https:9091 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:9200 -p https:9443 -p https:9800 -p https:9981 -p https:12443 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".stripped_all_resolved.txt | fprobe -p https:16080 -p https:18091 -p https:18092 -p https:20720 -p https:28017 -c 50 -s >> /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".80_443_web.txt | sort -u > /root/webscan/Targets/"+b+"/Hosts/"+b+".new_80_443_web.txt")
	os.system("cp /root/webscan/Targets/"+b+"/Hosts/"+b+".new_80_443_web.txt /root/webscan-output/"+b+"/")
	os.system("cat /root/webscan/Targets/"+b+"/Hosts/"+b+".new_80_443_web.txt")

d_str =""

with open('/root/githubkey/key.txt','r') as gikey:
        v = gikey.read()
        key = v.strip()
a = sys.argv[1:]
for element in a:
        d_str += element

if d_str == '':
        sys.exit('ERROR: PLEASE PROVIDE A PARAMETER! Eg python webscan.py domain.com or domain.txt \n')

if d_str[-3:] == 'txt':
        with open('/root/webscan/domains.txt','r') as d_file:
                file_contents = d_file.readlines()
                if len(file_contents) == 0:
                	sys.exit('ERROR: PLEASE ADD DOMAINS TO /ROOT/WEBSCAN/DOMAINS.TXT \n')
                for line in file_contents:
                        d = line.strip()
                        b = d.replace(d[-4:],'')
                        scanner(b,d,key)
                        time.sleep(1)
                        continue
elif d_str[-3:] == 'com':
        b = d_str.replace('.com','')
        scanner(b,d_str,key)
        time.sleep(1)


#Compile list of all resolved domains
os.system("echo '\nCREATING \e[31m[RESOLVED LIST W/ PREFIX]\e[0m'\n")
if os.path.exists("/root/webscan-output/all/all_resolved.txt"):
	os.system("mv /root/webscan-output/all/all_resolved.txt /root/webscan-output/all/old_all_resolved.txt")
if os.path.exists("/root/webscan-output/all/stripped_all_resolved.txt"):
	os.system("mv /root/webscan-output/all/stripped_all_resolved.txt /root/webscan-output/all/old_stripped_all_resolved.txt")
os.system("find /root/webscan/Targets/ . -name '*.new_80_443_web.txt' -exec cat {} \; | sort -u > /root/webscan-output/all/all_resolved.txt")
os.system("echo 'LIST W/ PREFIX \e[32mFINISHED\e[0m'\n")


#Compile list of Stripped all resolved domains
os.system("echo '\nCREATING \e[31m[RESOLVED LIST WITHOUT PREFIX]\e[0m'\n")
os.system("sed 's/http:\/\///g; s/https:\/\///g; s/www\.//g; s/\*\.//g' /root/webscan-output/all/all_resolved.txt | sort -u > /root/webscan-output/all/stripped_all_resolved.txt")
os.system("echo 'LIST WITHOUT PREFIX \e[32mFINISHED\e[0m'\n")

#Compile list of of difference between previous scan and current
os.system("echo '\nSEARCHING\e[31m[DIFFERENCES BETWEEN CURRENT SUBDOMAINS AND PREVIOUS SUBDOMAINS]\e[0m'\n")
if os.path.exists("/root/webscan-output/subdomains_diff.txt"):
	os.remove("/root/webscan-output/subdomains_diff.txt")
os.system("diff /root/webscan-output/all/stripped_all_resolved.txt /root/webscan-output/all/old_stripped_all_resolved.txt | sed 's/<//g; s/>//g' | sort -u >> /root/webscan-output/subdomains_diff.txt")
os.system("cat /root/webscan-output/subdomains_diff.txt >> /root/webscan-output/all/all_subdomains_diff.txt")

diff_sub = os.stat("/root/webscan-output/subdomains_diff.txt").st_size == 0
if diff_sub == False:
	print("DIFFERENCE FOUND in SUBDOMAINS when compared to previous scan! \n")
else:
	print("NO DIFFERENCE in SUBDOMAINS when compared to previous scan :( \n")
	
os.system("echo 'SUBDOMAIN DIFFERENCE \e[32mFINISHED\e[0m'\n")

##SCANNING WITH NUCLEI
#nuc = raw_input("Would you like to run a Nuclei Scan? y or n \n")
#if nuc == 'y':
os.system("nuclei -update-templates")
with open('/root/webscan-output/all/stripped_all_resolved.txt','r') as s_file:
	strip_contents = s_file.readlines()
	for sline in strip_contents:
		i = sline.strip()
		c = i.replace(i[-4:],'')
		if not os.path.isdir("/root/webscan-output/"+c):
			os.mkdir("/root/webscan-output/"+c)
					
		#Nuclei CVE
		os.system("nuclei -target https://"+i+" -t /root/nuclei-templates/cves/ -o /root/webscan-output/"+c+"/cves.txt -silent")

		#Nuclei Vulnerabilites
		os.system("nuclei -target https://"+i+" -t /root/nuclei-templates/vulnerabilities/ -o /root/webscan-output/"+c+"/vulnerabilites.txt -silent")

		#Nuclei Generic Detections
		os.system("nuclei -target https://"+i+" -t /root/nuclei-templates/generic-detections/ -o /root/webscan-output/"+c+"/generic-detections.txt -silent")

		#Nuclei Tokens
		os.system("nuclei -target https://"+i+" -t /root/nuclei-templates/tokens/ -o /root/webscan-output/"+c+"/tokens.txt -silent")

		#Nuclei Files
		os.system("nuclei -target https://"+i+" -t /root/nuclei-templates/files/ -o /root/webscan-output/"+c+"/files.txt -silent")

		#Nuclei Security-Misconfigurations
		os.system("nuclei -target https://"+i+" -t /root/nuclei-templates/security-misconfiguration/ -o /root/webscan-output/"+c+"/security-misconfigurations.txt -silent")

		#Nuclei Subdomain-takeover
		os.system("nuclei -target https://"+i+" -t /root/nuclei-templates/subdomain-takeover/ -o /root/webscan-output/"+c+"/subdomain-takeover.txt -silent")

		#Nuclei Default Credentials
		os.system("nuclei -target https://"+i+" -t /root/nuclei-templates/default-credentials/ -o /root/webscan-output/"+c+"/default-credentials.txt -silent")
				
#elif nuc == 'n':
#	print("Continuing without scanning with Nuclei\n")

#else:
#	print("Please enter either 'y' or 'n'\n")

#Compile list of all Nuclei findings
os.system("echo '\nCREATING \e[31m[NUCLEI FINDINGS LIST]\e[0m'\n")
if os.path.exists("/root/webscan-output/all/all_nuclei-findings.txt"):
	os.system("mv /root/webscan-output/all/all_nuclei-findings.txt /root/webscan-output/all/old_all_nuclei-findings.txt")
os.system("find /root/webscan-output/ . -name 'cves.txt' -exec cat {} \; | sort -u > /root/webscan-output/all/all_nuclei-findings.txt")
os.system("find /root/webscan-output/ . -name 'vulnerabilites.txt' -exec cat {} \; | sort -u >> /root/webscan-output/all/all_nuclei-findings.txt")
os.system("find /root/webscan-output/ . -name 'generic-detections.txt' -exec cat {} \; | sort -u >> /root/webscan-output/all/all_nuclei-findings.txt")
os.system("find /root/webscan-output/ . -name 'tokens.txt' -exec cat {} \; | sort -u >> /root/webscan-output/all/all_nuclei-findings.txt")
os.system("find /root/webscan-output/ . -name 'files.txt' -exec cat {} \; | sort -u >> /root/webscan-output/all/all_nuclei-findings.txt")
os.system("find /root/webscan-output/ . -name 'security-misconfigurations.txt' -exec cat {} \; | sort -u >> /root/webscan-output/all/all_nuclei-findings.txt")
os.system("find /root/webscan-output/ . -name 'subdomain-takeover.txt' -exec cat {} \; | sort -u >> /root/webscan-output/all/all_nuclei-findings.txt")
os.system("find /root/webscan-output/ . -name 'default-credentials.txt' -exec cat {} \; | sort -u >> /root/webscan-output/all/all_nuclei-findings.txt")

os.system("echo 'NUCLEI FINDINGS LIST \e[32mFINISHED\e[0m'\n")

#Compile list of of difference between previous scan and current
os.system("echo '\n SEARCHING FOR DIFFERENCES BETWEEN \e[31m[CURRENT NUCLEI FINDINGS AND PREVIOUS NUCLEI FINDINGS]\e[0m'\n")
os.system("diff /root/webscan-output/all/all_nuclei-findings.txt /root/webscan-output/all/old_all_nuclei-findings.txt | sed 's/<//g; s/>//g' | sort -u -o /root/webscan-output/nuclei_diff.txt")
os.system("cat /root/webscan-output/nuclei_diff.txt |sort -u >> /root/webscan-output/all/all_nuclei_diff.txt")
os.system("sort -u /root/webscan-output/all/all_nuclei_diff.txt -o /root/webscan-output/all/all_nuclei_diff.txt")

diff_sub = os.stat("/root/webscan-output/nuclei_diff.txt").st_size == 0
if diff_sub == False:
	print("DIFFERENCE FOUND in NUCLEI FINDINGS when compared to previous scan! \n")
else:
	print("NO DIFFERENCE in NUCLEI FINDINGS when compared to previous scan :( \n")
os.system("echo 'NUCLEI FINDINGS DIFFERENCE \e[32mFINISHED\e[0m'\n")

os.system("echo '\n\n\n\e[32m ---------------------------------------------------------------------------------------- ALL SCAN DATA CAN BE FOUND IN /ROOT/WEBSCAN-OUTPUT/ ------------------------------------------------------------------------\e[0m'")
os.system("echo '\n\n\n\e[32m ---------------------------------------------------------------------------------------- SUBDOMAIN ENUMERATION WITH VULNERABILITY SCAN FINISHED. HAPPY HACKING! ------------------------------------------------------------------------\e[0m'")
