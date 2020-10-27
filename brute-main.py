#!/usr/bin/python
import os
import sys
import time

def scanner(b,d_str,key):
        if not os.path.isdir("/root/webscan"):
                os.mkdir("/root/webscan")
        if not os.path.isdir("/root/webscan/Targets"):
                os.mkdir("/root/webscan/Targets")
        if not os.path.isdir("/root/webscan/Tools/"):
                os.mkdir("/root/webscan/Tools/")
        if not os.path.isdir("/root/webscan/Tools/GitHubTool"):
                os.mkdir("/root/webscan/Tools/GitHubTool")
        if not os.path.exists("/root/webscan/Tools/GitHubTool/github-endpoints.py"):
                os.system("git clone https://github.com/gwen001/github-search.git /root/webscan/Tools/GitHubTool/")
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
        if not os.path.isdir("/root/webscan-output/"+b+"/all"):
        	os.mkdir("/root/webscan-output/"+b+"/all")
        os.system("cat /root/webscan/Targets/"+b+"/"+b+".root.txt | grep -Po '[\w\s]+(?=\.)' >> /root/webscan/Targets/"+b+"/"+b+".domain.txt")
        os.chdir("/root/webscan/Targets/"+b)
        os.system("echo '\e[31m[STARTING "+d_str.upper()+"]\e[0m'\n")
        
        ##SCRAPING WEB FOR ENDPOINTS
       
                                                                                  
        ## LAUNCH GIT-Endpoints
        os.system("echo '\nRUNNING \e[31m[GIT-Endpoints]\e[0m'")
        os.system("python3 /root/webscan/Tools/GitHubTool/github-endpoints.py -t "+key+" -d "+d_str+" -s -r |grep 'http' | grep '"+d_str+"' |sort -u > /root/webscan/Targets/"+b+"/"+b+".200urls.txt")
        os.system("echo 'GIT-Endpoints \e[32mFINISHED\e[0m'")

        ## LAUNCH Directory Bruteforce
        os.system("echo '\nRUNNING \e[31m[Directory Bruteforce]\e[0m'")
        os.system("ffuf -w /root/webscan/Targets/"+b+"/Hosts/"+b+".new_80_443_web.txt:DOMAIN -w /root/webscan/endpoints.txt -u DOMAIN/FUZZ -t 100 -mc 200 -o /root/webscan/Targets/"+b+"/"+b+".bruteurls.csv -of csv")
        os.system("cat /root/webscan/Targets/"+b+"/"+b+".bruteurls.csv |cut -d , -f3|qsreplace -a >> /root/webscan/Targets/"+b+"/Hosts/"+b+".dirbrute_80_443_web.txt")
        os.system("cp /root/webscan/Targets/"+b+"/Hosts/"+b+".dirbrute_80_443_web.txt /root/webscan-output/"+b+"/")
        os.system("echo 'Directory Bruteforce \e[32mFINISH\e[0m'")

        ## LAUNCH goSpider
        os.system("echo '\nRUNNING \e[31m[GOSPIDER]\e[0m'")
        os.system("gospider -S /root/webscan/Targets/"+b+"/Hosts/"+b+".dirbrute_80_443_web.txt --depth 15 -a --no-redirect -t 50 -c 3 -o /root/webscan/Targets/"+b+"/Crawldata/")
        os.system("cat /root/webscan/Targets/"+b+"/Crawldata/* |grep 'form]' | cut -d ' ' -f3 |qsreplace -a >> /root/webscan/Targets/"+b+"/"+b+".200urls.txt")
        os.system("cat /root/webscan/Targets/"+b+"/Crawldata/* |grep 'code-200]' | cut -d ' ' -f5 |qsreplace -a >> /root/webscan/Targets/"+b+"/"+b+".200urls.txt")
        os.system("cat /root/webscan/Targets/"+b+"/Crawldata/* |grep -v 'linkfinder]' | grep 'javascript' |grep '"+b+"' | cut -d ' ' -f3 |sort -u >> /root/webscan/Targets/"+b+"/"+b+".200urls.txt")
        os.system("cat /root/webscan/Targets/"+b+"/Crawldata/* |grep 'linkfinder' |cut -d ' ' -f6 |grep '"+b+"' |sort -u >> /root/webscan/Targets/"+b+"/"+b+".200urls.txt")
        os.system("cat /root/webscan/Targets/"+b+"/"+b+".200urls.txt |qsreplace -a >> /root/webscan/Targets/"+b+"/"+b+".200urls.tmp")
        os.system("mv /root/webscan/Targets/"+b+"/"+b+".200urls.tmp /root/webscan/Targets/"+b+"/"+b+".200urls.txt")
        os.system("cp /root/webscan/Targets/"+b+"/"+b+".200urls.txt /root/webscan-output/"+b+"/")
        print ("FOUND ENDPOINTS")
        #g = ("cat /root/webscan/Targets/"+b+"/"+b+".200urls.txt | wc -l")
        os.system("echo 'GOSPIDER \e[32mFINISHED\e[0m'")

        ##Find XSS
        os.system("echo '\nRUNNING \e[31m[KXSS]\e[0m'")
        os.system("cat /root/webscan/Targets/"+b+"/"+b+".200urls.txt | kxss | tee /root/webscan/Targets/"+b+"/"+b+".kxss_finds.txt")
        os.system("cat /root/webscan/Targets/"+b+"/"+b+".kxss_finds.txt |cut -d '/' -f2 | sort -u > /root/webscan/Targets/"+b+"/"+b+".KXSS.txt")
        os.system("cp /root/webscan/Targets/"+b+"/"+b+".KXSS.txt /root/webscan-output/"+b+"/")
        os.system("echo 'KXSS \e[32mFINISHED\e[0m'")


d_str =""

with open('/root/githubkey/key.txt','r') as gikey:
        v = gikey.read()
        key = v.strip()

a = sys.argv[1:]
for element in a:
        d_str += element
        
if d_str == '':
        sys.exit('ERROR: PLEASE PROVIDE A PARAMETER! Eg ./brute-main.py domain.com or domain.txt \n')

if d_str[-3:] == 'txt':
        with open('/root/webscan-output/all/all_resolved.txt','r') as d_file:
                file_contents = d_file.readlines()
                for line in file_contents:
                        d = line.strip()
                        b = d.replace(d[-4:],'')
                        scanner(b,d,key)
                        time.sleep(1)
                        continue
elif d_str[-3:] == 'com':
        b = d_str.replace('.com','')
        print(d_str)
        scanner(b,d_str,key)

#Compile list of all Directories Bruteforced
os.system("echo '\nCREATING \e[31m[DIRECTORY BRUTEFORCED LIST]\e[0m'\n")
os.system("find /root/webscan/Targets/ . -name '*.dirbrute_80_443_web.txt' -exec cat {} \; | sort -u > /root/webscan-output/all/all_dirbrute.txt")
os.system("echo 'DIRECTORY BRUTEFORCED LIST \e[32mFINISHED\e[0m'\n")

#Compile list of all Spidered Paths
os.system("echo '\nCREATING \e[31m[SPIDERED PATHS LIST]\e[0m'\n")
os.system("find /root/webscan/Targets/ . -name '*.200urls.txt' -exec cat {} \; | sort -u > /root/webscan-output/all/all_200urls.txt")
os.system("echo 'SPIDERED PATHS LIST \e[32mFINISHED\e[0m'\n")

#Compile list of all Cross-Site Scripting with KXSS
os.system("echo '\nCREATING \e[31m[XSS LIST]\e[0m'\n")
os.system("find /root/webscan/Targets/ . -name '*.KXSS.txt' -exec cat {} \; | sort -u > /root/webscan-output/all/all_KXSS.txt")
os.system("echo 'XSS LIST \e[32mFINISHED\e[0m'\n")
