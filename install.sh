
# Update OS
sudo apt update
sudo apt upgrade -y

# Install dependencies Cuckoo
sudo apt install python python-pip python-dev libffi-dev libssl-dev libfuzzy-dev -y
sudo apt install python-virtualenv python-setuptools -y
sudo apt install libjpeg-dev zlib1g-dev swig -y
sudo -H pip install -U pip

# Install Virtualbox and dependencies
cd /opt
sudo sh -c 'echo "deb http://download.virtualbox.org/virtualbox/debian xenial contrib" >> /etc/apt/sources.list.d/virtualbox.list'
sudo wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
sudo apt update && sudo apt install virtualbox-5.2 -y
VBOX_LATEST_VERSION=$(curl http://download.virtualbox.org/virtualbox/LATEST.TXT)
sudo wget http://download.virtualbox.org/virtualbox/${VBOX_LATEST_VERSION}/Oracle_VM_VirtualBox_Extension_Pack-${VBOX_LATEST_VERSION}.vbox-extpack
sudo vboxmanage extpack install Oracle_VM_VirtualBox_Extension_Pack-${VBOX_LATEST_VERSION}.vbox-extpack

# Create environment for Cuckoo Sandbox
sudo adduser cuckoo
sudo usermod -a -G vboxusers cuckoo
cd /home/cuckoo
su cuckoo
virtualenv cuckoo
. /home/cuckoo/cuckoo/bin/activate
pip install -U pip setuptools psycopg2 yara-python weasyprint pycrypto pydeep
easy_install distribute
pip install -U cuckoo
pip install weasyprint==0.36
pip install m2crypto==0.24.0
cuckoo
cuckoo community
deactivate
sudo apt install python-m2crypto
exit

# Install Java for Elasticsearch
sudo add-apt-repository ppa:webupd8team/java
sudo apt update && sudo apt install oracle-java8-installer -y
sudo bash -c "echo 'JAVA_HOME=\"/usr/lib/jvm/java-8-openjdk-amd64\"' >> /etc/environment"
source /etc/environment

# Install mongodb and create DB
sudo apt install mongodb -y
sudo apt install postgresql libpq-dev -y
sudo pip install psycopg2
# Generate random password
db_passwd=$(date +%s | sha256sum | base64 | head -c 32 ; echo)
echo "CREATE USER cuckoo WITH PASSWORD '$db_passwd';" | sudo -u postgres psql
echo "CREATE DATABASE cuckoo;" | sudo -u postgres psql
echo "GRANT ALL PRIVILEGES ON DATABASE cuckoo to cuckoo;" | sudo -u postgres psql
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
sudo apt update && sudo apt install elasticsearch -y
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo service elasticsearch stop
cd /home/cuckoo/
sudo mkdir /home/cuckoo/ESData
sudo chown root:elasticsearch ESData
sudo chmod 777 /home/cuckoo/ESData
sudo usermod -a -G elasticsearch cuckoo
sudo bash -c "cat >> /etc/elasticsearch/elasticsearch.yml <<DELIM
cluster.name: es-cuckoo
node.name: es-node-n1
node.master: true
node.data: true
bootstrap.mlockall: true
path.data: /home/cuckoo/ESData
network.bind_host: 0.0.0.0
DELIM"
sudo service elasticsearch start
sudo curl -X PUT -d @'/home/cuckoo/.cuckoo/elasticsearch/template.json' 'http://localhost:9200/_template/cuckoo'

# Install Yara + rules
cd /opt
sudo apt install dh-autoreconf flex bison libjansson-dev libmagic-dev -y
sudo wget https://github.com/VirusTotal/yara/archive/v3.7.1.tar.gz
sudo tar -zxf v3.7.1.tar.gz
cd yara-3.6.3/
sudo ./bootstrap.sh
sudo ./configure --with-crypto --enable-cuckoo --enable-magic
sudo make
sudo make install
sudo -H pip install -U yara-python
cd /home/cuckoo/.cuckoo/yara/
su cuckoo
sudo git clone https://github.com/lehuff/cuckoo-yara-rules.git
sudo cp cuckoo-yara-rules/cuckoo-yara-rules.py .
sudo rm -rf cuckoo-yara-rules
sudo python cuckoo-yara-rules.py
sudo chown -R cuckoo:cuckoo /home/cuckoo/.cuckoo/

# Install SSDeep
cd /opt
sudo -H pip install -U ssdeep
sudo git clone https://github.com/bunzen/pySSDeep.git
cd pySSDeep
sudo python setup.py build
sudo python setup.py install
cd -

# Install Volatility
sudo apt install pcregrep libpcre++-dev -y
sudo -H pip install -U git+https://github.com/kbandla/pydeep.git
sudo apt install volatility -y
cp -r /usr/lib/python2.7/dist-packages/volatility* /home/cuckoo/cuckoo/lib/python2.7/site-packages
sudo chown cuckoo:cuckoo /home/cuckoo/cuckoo/lib/python2.7/site-packages/*
mv /home/cuckoo/.cuckoo/signatures/windows/volatility_sig.py /home/cuckoo/.cuckoo/signatures/windows/volatility_sig.py.deactivate

# Install TCPDump
sudo apt install tcpdump apparmor-utils -y
sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo chmod +s /usr/sbin/tcpdump

# Install Teserract
sudo apt install tesseract-ocr -y
sudo -H pip install -U cairocffi
sudo apt install wkhtmltopdf xvfb xfonts-100dpi -y

# Install Fonts for PDF
sudo -H pip install -U cairocffi
sudo apt install wkhtmltopdf xvfb xfonts-100dpi -y

# Install MitMproxy
sudo apt install libarchive13 libxml2-dev libxslt1-dev -y
sudo -H pip install -U mitmproxy==0.18.2
su cuckoo
cd ~
mitmproxy + ctrl-c
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.p12 /home/cuckoo/.cuckoo/analyzer/windows/bin/cert.p12
sudo chown cuckoo:cuckoo /home/cuckoo/.cuckoo/analyzer/windows/bin/cert.p12
exit

# Install Tor
sudo apt install tor -y
sudo sh -c 'echo TransPort 192.168.56.1:9040 >> /etc/tor/torrc'
sudo sh -c 'echo DNSPort 192.168.56.1:5353 >> /etc/tor/torrc'

# Install Suricata
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install suricata -y
echo "alert http any any -> any any (msg:\"FILE store all\"; filestore; noalert; sid:15; rev:1;)"  | sudo tee /etc/suricata/rules/cuckoo.rules
# sudo touch /etc/suricata/suricata-cuckoo.yaml
sudo wget -O /etc/suricata/suricata-cuckoo.yaml https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/suricata-cuckoo.yaml 

# Change reles for Suricata
sudo mkdir /var/run/suricata
sudo chown cuckoo:cuckoo /var/run/suricata
sudo chown -R cuckoo:cuckoo /etc/suricata
sudo chown -R cuckoo:cuckoo /var/log/suricata
sudo touch /etc/suricata/threshold.config

# Install ETupdate
cd /opt
sudo git clone https://github.com/seanthegeek/etupdate.git
sudo cp etupdate/etupdate /usr/sbin
sudo /usr/sbin/etupdate -V
sudo crontab -e
0 0 * * * /usr/sbin/etupdate -V

# Install Snort
sudo apt install snort -y
sudo chown -R cuckoo:cuckoo /etc/snort/
sudo chown -R cuckoo:cuckoo /var/log/snort/

# Install VMcloak and Windows 7 SP1 X64
cd /opt
sudo apt install libyaml-dev libpython2.7-dev genisoimage -y
sudo git clone -b vrde https://github.com/tweemeterjop/vmcloak.git
cd vmcloak/
sudo cp /home/cuckoo/.cuckoo/agent/agent.py vmcloak/data/bootstrap/
sudo -H pip install -r requirements.txt
sudo python setup.py install
cd ..
sudo mkdir -p /mnt/win7
sudo mount -o loop,ro ~/en_windows_7_enterprise_with_sp1_x64_dvd_u_677651.iso /mnt/win7/
sudo vmcloak-vboxnet0
sudo vmcloak-iptables 192.168.56.0/24 ens160
cd /home/cuckoo
su cuckoo
vmcloak init --vrde --resolution 1280x1024 --ramsize 4096 --win7_x64 --product professional --cpus 2 win7x64
vmcloak install --vrde win7_x64 python27 pillow adobepdf chrome cuteftp dotnet40 flash java silverlight vcredist wic
vmcloak modify --vrde win7_x64

# Setup Windows 7
vmcloak modify --vrde win7_x64

# Add VM to Cuckoo
vmcloak snapshot win7_x64 win7_x64node1 192.168.56.101
. /home/cuckoo/cuckoo/bin/activate
cuckoo machine --add win7x64node1 192.168.56.101 --platform windows --snapshot vmcloak
cuckoo machine --delete cuckoo1
deactivate

# Install Moloch
sudo apt install libjson-perl -y
cd /opt
sudo wget https://files.molo.ch/builds/ubuntu-16.04/moloch_0.20.2-2_amd64.deb
sudo dpkg -i moloch_0.20.2-2_amd64.deb
sudo /data/moloch/bin/Configure

sudo /data/moloch/db/db.pl http://localhost:9200 init
sudo /data/moloch/bin/moloch_add_user.sh cuckoo cuckoo cuckoosandbox --admin

# Install InetSim
sudo su
echo "deb http://www.inetsim.org/debian/ binary/" > /etc/apt/sources.list.d/inetsim.list
wget -O - http://www.inetsim.org/inetsim-archive-signing-key.asc | apt-key add -
apt update
apt install inetsim
exit

# Install HoneyD
cd /opt/
sudo git clone https://github.com/Bifrozt/honeyd-ansible.git
cd honeyd-ansible/
sudo ansible-playbook honeyd.yml
# sudo touch /usr/share/honeyd/config.conf
sudo wget -O /usr/share/honeyd/config.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/honeyd_config.conf

# Install Nginx
sudo add-apt-repository ppa:nginx/development
sudo apt update
sudo apt install nginx -y
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
sudo mkdir /etc/nginx/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt
sudo -H pip install -U uwsgi
cd /home/cuckoo/
sudo mkdir /var/log/uwsgi/
sudo mkdir /etc/uwsgi
sudo chown cuckoo:cuckoo /var/log/uwsgi/
sudo chown cuckoo:cuckoo /etc/uwsgi/
su cuckoo

# /etc/uwsgi/cuckoo.ini
sudo wget -O /etc/uwsgi/cuckoo.ini https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/uwsgi_cuckoo.ini
# /etc/nginx/sites-available/cuckoo-web
sudo wget -O /etc/nginx/sites-available/cuckoo-web https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/sites_available_cuckoo-web

sudo adduser www-data cuckoo
sudo ln -s /etc/nginx/sites-available/cuckoo-web /etc/nginx/sites-enabled/
sudo systemctl reload nginx

# Change config cuckoo
# /home/cuckoo/.cuckoo/conf/auxiliary.conf
sudo wget -O /home/cuckoo/.cuckoo/conf/auxiliary.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/conf/auxiliary.conf
# /home/cuckoo/.cuckoo/conf/cuckoo.conf
sudo wget -O /home/cuckoo/.cuckoo/conf/cuckoo.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/conf/cuckoo.conf
# /home/cuckoo/.cuckoo/conf/memory.conf
sudo wget -O /home/cuckoo/.cuckoo/conf/memory.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/conf/memory.conf
# /home/cuckoo/.cuckoo/conf/processing.conf
sudo wget -O /home/cuckoo/.cuckoo/conf/processing.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/conf/processing.conf
# /home/cuckoo/.cuckoo/conf/reporting.conf
sudo wget -O /home/cuckoo/.cuckoo/conf/reporting.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/conf/reporting.conf
# /home/cuckoo/.cuckoo/conf/routing.conf
sudo wget -O/home/cuckoo/.cuckoo/conf/routing.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/conf/routing.conf
# /home/cuckoo/.cuckoo/conf/virtualbox.conf
sudo wget -O /home/cuckoo/.cuckoo/conf/virtualbox.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/conf/virtualbox.conf

#Install supervisor and sutup autoload cuckoo
sudo apt install supervisor -y
sudo systemctl stop supervisor
# /etc/supervisor/conf.d/vmcloak-internet.conf
sudo wget -O /etc/supervisor/conf.d/vmcloak-internet.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/supervisor/vmcloak-internet.conf
# /etc/supervisor/conf.d/cuckoo.conf
sudo wget -O /etc/supervisor/conf.d/cuckoo.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/supervisor/cuckoo.conf
# /etc/supervisor/conf.d/uwsgi.conf
sudo wget -O /etc/supervisor/conf.d/uwsgi.conf https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/supervisor/uwsgi.conf

sudo systemctl restart supervisor
sudo supervisorctl -c /etc/supervisor/supervisord.conf reload

# Create script for startup
# /opt/serv.sh
sudo wget -O /opt/serv.sh https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/serv.sh

sudo chmod +x serv.sh
sudo crontab -e 
@reboot /bin/sh /opt/serv.sh
