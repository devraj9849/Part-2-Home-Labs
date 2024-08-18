<h1>Part 5: Configure Zeek and Suricata</h1>

For Zeek and Suricata virtual machine, I will install an ubuntu machine with its name zeekandsuricata.
Opening Zeek and Suricata from our virtual machine. 
IP Address of zeek_suricata = 192.168.132.138
![image](https://github.com/user-attachments/assets/9b0a445b-a777-4c04-8fd9-55869b274982)

 
After this opening the system in putty or mobaxterm.
![image](https://github.com/user-attachments/assets/14f96370-60d3-4873-8eea-37cb7107a14c)

 
After this we are going to install zeek. Our ubuntu version is 22.0.4. Go to the website and select your ubuntu version and install it.

    https://github.com/zeek/zeek/wiki/Binary-Packages
Mine is 22.04
  
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    sudo apt update
    sudo apt install [zeek, zeek-6.0, or zeek-nightly]

![image](https://github.com/user-attachments/assets/37cf0f93-2ed7-4a3b-950f-6d50565463ef)

 
Zeek is located under the following directory
cd /opt/zeek/bin
To customize zeek it uses the configuration file that is located under the above directory.

    sudo vi /opt/zeek/share/zeek/site/local.zeek

![image](https://github.com/user-attachments/assets/b20e34d6-5d50-43ae-9227-a5cfec12e1a9)

Add these two lines in the bottom of the page
![image](https://github.com/user-attachments/assets/00c55b3b-d11d-4078-a9fc-6e9ddcd2d58a)

After this our configuration file should be updated with our ja3 and ja4 hashes. 
Now we are going to install JA3 and JA4 for zeek.
Setup JA3 for zeek:
sudo apt install zkg
zkg install ja3
Edit the local.zeek config in /opt/zeek/share/zeek/site/local.zeek and add in @load ja3
![image](https://github.com/user-attachments/assets/85aceca5-d6b0-4cdb-9acd-56c1455475c0)

 
Setup JA4 for zeek:
zkg install zeek/foxio/ja4
![image](https://github.com/user-attachments/assets/2838b3e5-8130-4360-8bb2-dae8d0997d20)

Change the local.zeek config in /opt/zeek/share/zeek/site/local.zeek and add in @load ja4plus
![image](https://github.com/user-attachments/assets/4916eb6e-f2b0-4613-988b-22e17cb920ac)

This is the main file for the installation of zeek in the virtual machine.
Now we are going to install Suricata which is the IDS Intrusion Detection System.

Add Silver C2 rules for Suricata

    sudo apt -y install libnetfilter-queue-dev libnetfilter-queue1 libnfnetlink-dev libnfnetlink0 jq
    sudo add-apt-repository ppa:oisf/suricata-stable
    sudo apt install suricata
    sudo systemctl enable suricata.service
    sudo systemctl stop suricata.service

We want to configure yaml file for its configuration file on Suricata. And this is located under the directory. And make sure that the community-id is set to true.

    sudo vi /etc/suricata/suricata.yaml 
![image](https://github.com/user-attachments/assets/70101659-3076-48a3-83a1-8d679d8a0584)
 
Suricata Rules
   
    sudo suricata-update
    sudo suricata-update - Update Rules
    sudo suricata-update list-sources
    sudo suricata-update enable-source tgreen/hunting
    sudo suricata-update enable-source et/open
    sudo suricata-update - Update Rules
    sudo systemctl start suricata.service
    sudo suricata -T -c /etc/suricata/suricata.yaml -v - Validating Suricata
    /var/lib/suricata/rules/ - Rule Location
    
![image](https://github.com/user-attachments/assets/2fba3991-70d0-45b5-a676-32970788fb23)
 
Immersive Labs

    wget https://raw.githubusercontent.com/Immersive-Labs-Sec/SliverC2-Forensics/main/Rules/sliver.snort
After all this process completed, type
  
    ip a
 ![image](https://github.com/user-attachments/assets/855a140c-662c-4808-898a-449ae61454c6)

We know that this is not in our detection lab network. So, we are assigning a static IP Address.
 
    sudo vi /etc/netplan/00-installer-config.yaml 
                   sudo netplan apply

 ![image](https://github.com/user-attachments/assets/9afbeede-2c2c-4cdf-a644-4b87d3560244)

After this we can ping to our splunk server and we can ping it perfect.
![image](https://github.com/user-attachments/assets/18b60494-d067-4db2-a8eb-e3e3a1da7a25)
 
Go to the splunk website and copy wget link for universal forwarder for sending data from zeek_suricata to the splunk.
 ![image](https://github.com/user-attachments/assets/526d573e-74bb-499f-98d6-e2df78a68867)

Since the URL is too long we can use it a service called tinyurl. Just copy the link in tinyurl and shorten URL there.
![image](https://github.com/user-attachments/assets/88b888d3-b7dc-4ecd-a2c0-88ca4923f0f7)
 
Then in our virtual machine we can write:

    sudo wget https://tinyurl.com/mydfir-detect12
 ![image](https://github.com/user-attachments/assets/c10cec4b-85d6-438f-9700-dde7cebc5f5e)

After this we are going to install the deb file.

    sudo dpkg -i mydfir-detect321
 ![image](https://github.com/user-attachments/assets/ea8ce9aa-3e27-4ec2-aaac-1a862cf964df)
![image](https://github.com/user-attachments/assets/b2b3caa4-64c3-4843-bd9b-e61da09992c3)

 
Here looking at the above screenshot we know it is owned by username splunkfwd. We are going to change into it.

    sudo -u splunkfwd bash
    ./splunk start
![image](https://github.com/user-attachments/assets/64c88822-cdd4-4de5-8fdd-5507bdb67a0b)
 
It will tell you to enter username and password. And make sure that your splunk is enabled.
![image](https://github.com/user-attachments/assets/c5c991b0-d158-4fba-8169-abb5b9911d15)
 
Now we have to point our zeek-suricata server to splunk server. For this

    sudo ./splunk add forward-server 192.168.1.20:9997
    sudo ./splunk list forward-server
![image](https://github.com/user-attachments/assets/03696a22-4730-4dfd-bff8-d0f8fa5b8f79)
 
The second command is used in order to make sure the changes we made using above command is working or not. Now we can go into the user splunkfwd and start the splunk. However we have active forwards to none.

    sudo -u splunkfwd bash
    ./splunk start
 ![image](https://github.com/user-attachments/assets/81e49ddd-cc39-406d-954b-b81923862e3f)

we can see active forwards changed after writing the command below:

    ./splunk list forward-server
 ![image](https://github.com/user-attachments/assets/a2dce259-07b3-419d-bd05-44e3b9069b6b)

This is how we configure Splunk on our zeek-server to point our data over to the Splunk server. Now we need to configure our inputs.conf file, which will be responsible for sending all of the Zeek logs over to our Splunk and to do that first I will exit out and create an inputs.conf file under the etc/system/local for Splunk. So, writing the command:

    sudo vi /opt/splunkforwarder/etc/system/local/
 ![image](https://github.com/user-attachments/assets/4fc668b7-123b-42e3-856e-c9915e6e8826)

Now we need to got to 
cd /opt/zeek
cd logs 
however, we get permission denied.
So changing the user to root.

    sudo su
 ![image](https://github.com/user-attachments/assets/398a44ab-c7cb-4caa-a355-e86e9ada286d)

After this finally we can go to the logs directory.
![image](https://github.com/user-attachments/assets/ae285bc5-294e-40cd-9eed-690ff498445a)
 
Furthermore, I need to change my network to promiscuous mode. In promiscuous mode, the NIC allows all frames through, so even frames intended for all other machines or network devices can be read. We recall that Zeek and Suricata is there to listen in on traffic, so that is why we need to have our network adapter or network interface card set to promiscuous mode.

    sudo ip link set ens33 promisc on
![image](https://github.com/user-attachments/assets/d1ae62dd-4099-4434-af19-2dd478641a2b)
 
After all these configurations we made, we want to make sure that Zeek and Suricata are running properly. 
 ![image](https://github.com/user-attachments/assets/7200f4eb-6896-4049-b4ae-1cb3f8af4d2f)

We make changes to the host=192.168.1.30 and interface=ens33
 ![image](https://github.com/user-attachments/assets/13c990bd-5592-4b7a-8f80-90c85650bcf1)

After we make these changes we are going to deploy it by using the command:

    sudo /opt/zeek/bin/zeekctl deploy
 ![image](https://github.com/user-attachments/assets/2639f835-36eb-4cc9-ba8e-2dec9c57dc30)

![image](https://github.com/user-attachments/assets/42381d82-a102-4d82-840c-5ab693384185)
 

 
Inside of current folder we can see a lot of logs like conn.log, ssl.log, known_hosts.log and many more.
 ![image](https://github.com/user-attachments/assets/9b8374bf-b7c4-4c46-97ab-2b424bea94e0)

Now zeek is good to go. Shifting towards Suricata, its logs are found in 
 
    cd /etc/Suricata
    sudo vi Suricata.yaml
![image](https://github.com/user-attachments/assets/c550c698-1da6-4cec-8c0a-bde1aa82207d)
      
 Here in the suricata.yaml file change the eth0 to ens33. There are 3 interfaces having eth0. So change it to ens33.
 ![image](https://github.com/user-attachments/assets/e2170a0c-c74b-4500-843c-81418f69cd6a)

After this run
        
      systemctl restart suricata.service
 ![image](https://github.com/user-attachments/assets/9520873a-f3ca-4bc4-9512-b6ad728de68f)

In Suricata logs are stored in /var/log/suricata/
![image](https://github.com/user-attachments/assets/b53ea6ee-2ca1-4a3a-8cbc-eddd55220bb9)
 
Running the command and making changes to inputs.conf file.
![image](https://github.com/user-attachments/assets/cee3ff35-8981-4db8-a534-47092a33c69a)
![image](https://github.com/user-attachments/assets/a2bd846f-c832-4ca0-bb4b-74cc8f1a5456)

 
We are gonna make changes in the local.zeek file in order to making sure that the sourcetype file we get will be in json format.
![image](https://github.com/user-attachments/assets/a5cdbd9a-c7a4-4405-a73b-1c28cc84df99)
![image](https://github.com/user-attachments/assets/15e25b22-dc7a-472f-8e58-1f3ba03fd44c)
 
 
After that we run the command

    sudo /opt/zeek/bin/zeekctl deploy
 ![image](https://github.com/user-attachments/assets/38dfd03b-f6eb-4c86-8f6d-8a39b67ff55c)

Now zeek should start outputting its logs in json format. Now we have successfully configured our zeek and making changes for Suricata. Going to inputs.conf file again.
 ![image](https://github.com/user-attachments/assets/7687a767-ff36-4a5d-a5ca-c8cf56bad4db)

After this 
     
    Sudo -u splunkfwd bash
    cd /opt/splunkforwarder/bin
    ./splunk stop
    ./splunk start
Now when we head to the windows machine we should be able to see some logs of zeek.
![image](https://github.com/user-attachments/assets/1f8a28d7-a79b-4085-8d5c-dcd1d28c65e4)
 
<h1>Part6: Configure PFSense</h1>
For pfsense, opening the pfsense in the windows 10 in browser.
![image](https://github.com/user-attachments/assets/690eb758-0ef6-4f8d-8827-55bcc3260f71)
 
Default username and password for pfsense is admin and pfsense respectively.
Click on Next.
Make sure this is checked off.
![image](https://github.com/user-attachments/assets/8829d988-11e3-40a9-ba65-f8b2951dac6c)
 
What I want to do with pfsense is that sending syslog over to our Splunk server and install SquidProxy. That way we can take a look at any proxy logs and then forward those proxy logs over to our Splunk server.
First I want to install SquidProxy before sending syslog over to our Splunk server. To install our proxy, go to System>Package Manager > Available Packages and search squid.
![image](https://github.com/user-attachments/assets/1cf41056-9128-48b1-a50f-19963b028a65)
![image](https://github.com/user-attachments/assets/9f21bd4f-c4cf-4008-945d-a3a2c81247a7)
 
 
Then going to pfsense in virtual machine. Enter 8 to shell. Here we are installing Splunk universal forwarder similar to what we did into the windows machine. Going to Splunk universal forwarder and copying the URL. For pfsense it uses Free BSD.
![image](https://github.com/user-attachments/assets/1c2cb909-a824-4eca-9f60-a2e181a969bf)
 
Then going to tinyurl.com and shortening the URL.
 ![image](https://github.com/user-attachments/assets/a42e96b0-288a-4509-af1e-34ac0faae995)

Pfsense uses fetch instead of wget.
fetch https://tinyurl.com/mydfir-detect2
![image](https://github.com/user-attachments/assets/ccf90248-2825-48cd-85b5-87f7f11fcefb)
 
Then we are going to extract the file using the command below which will create a folder splunkforwarder.
tar xvzf mydfir-detect2
 
![image](https://github.com/user-attachments/assets/2c69fae2-64bd-455c-bd4a-123c07e49e57)
 
![image](https://github.com/user-attachments/assets/3602bf82-d1ca-4f46-ab3e-ce8709a122cb)

![image](https://github.com/user-attachments/assets/16504e66-07ef-4165-9173-9cd7f7a5a82b)

 
Let’s create an inputs.conf file

    cd ..
    cd /etc/system/local
    ls
    vi inputs.conf
 
![image](https://github.com/user-attachments/assets/f553d714-97b2-436e-83b4-86c50ad23669)

![image](https://github.com/user-attachments/assets/c3d944f2-5fef-4d4d-9796-7127ade529f0)

 
Now we need to restart our splunk

    cd ../../../bin
    ./splunk stop
    ./splunk start
After this we can see logs of pfsense in the Splunk. Here we can see logs of pfsense are not parsed properly. For that we can install an application called ta-pfcents.
 
![image](https://github.com/user-attachments/assets/a5b80f0f-d3c1-4086-a9f0-944469398c9b)


<h1>Part7: Generating Telemetry</h1>
Installing the kali linux in the vmware workstation. 

    https://www.kali.org/get-kali/#kali-virtual-machines
![image](https://github.com/user-attachments/assets/3f65def4-099c-4296-b00b-637e33fedb53)

 
The IP address is not in the range of our lab. So we are going to change the IP Address to static.
Go to Settings>Advanced Network Configuration>Wired Connection 1> IPV4 settings and set the method to manual.
![image](https://github.com/user-attachments/assets/e0634f8f-99cc-41e3-a230-607f35e40046)

 
Now the IP is changed to 192.168.1.250
![image](https://github.com/user-attachments/assets/813f1b1a-31d7-47cf-9ed3-81f0615f7db4)
 
So now I am going to create a basic malware to allow my windows machine to execute it, which will then establish a C2 connection back to my kali machine. For that I will be using msvenom.
 ![image](https://github.com/user-attachments/assets/7153ed95-6685-48f3-97b1-e175240313fc)

The only reason we are doing this so that we can additional telemetry on the windows 10 machine, so that we can see that it in Splunk. Now opening msfconsole which is the Metasploit Framework console.
 ![image](https://github.com/user-attachments/assets/1b72a62c-2a2f-495d-80ee-901d927eedeb)
![image](https://github.com/user-attachments/assets/967f8158-ff22-42b1-ad1c-4d16a670df48)

 
Then type exploit and here we are listening to that port
![image](https://github.com/user-attachments/assets/306d9472-0118-4b02-b577-187c9afbc19f)
 
Opening the another tab on terminal.

    python -m http.server 9999
Now going to windows 10 machine and typing 192.168.1.250:9999 in browser we get Invoices.docx.exe file. Make sure to disable windows defender. Now download the file.
 ![image](https://github.com/user-attachments/assets/554c6608-1c81-4b5d-af07-d959c18d0d41)

Download this file and run it and head back to the kali machine. Meterpreter session is started.
![image](https://github.com/user-attachments/assets/c5e45321-2af9-4f6c-8405-38a84e590304)
 
Now we can do anything as we have full control of windows 10 machine. For this I am going to download desktop.ini file in Desktop of Kali from windows 10.
 ![image](https://github.com/user-attachments/assets/7f787eb3-da58-430f-9c8f-f96f8b864ed3)

Furthermore performing nmap scan to create more telemetry.
 ![image](https://github.com/user-attachments/assets/5212c47d-fd46-4dc4-bd19-283ee29ea8b2)

Now when seeing in our splunk we can see every event that happened.
![image](https://github.com/user-attachments/assets/64e2e12b-fb24-487d-b289-7c2f18ea6ead)
