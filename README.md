# install_cuckoo

URL: https://habr.com/ru/articles/350392/

# Сборка
Итак, теоретическая часть позади, приступаем к практике!

# Обновление ОС
Обновляем системные пакеты.
```bash
sudo apt update
sudo apt upgrade -y
```

# Зависимости Cuckoo
Устанавливаем зависимости Cuckoo.

```bash
sudo apt install libjpeg-dev zlib1g-dev swig libffi-dev libssl-dev libfuzzy-dev -y
sudo apt install python python-pip python-dev python-virtualenv python-setuptools -y
sudo apt git -y
sudo -H pip install -U pip==20.3.4
```

# Virtualbox
Устанавливаем Virtualbox вместе с extpack.

```bash
cd /opt
sudo sh -c 'echo "deb http://download.virtualbox.org/virtualbox/debian xenial contrib" >> /etc/apt/sources.list.d/virtualbox.list'
sudo wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
sudo apt update && sudo apt install virtualbox-5.2 -y
sudo wget http://download.virtualbox.org/virtualbox/5.2.44/Oracle_VM_VirtualBox_Extension_Pack-5.2.44.vbox-extpack
sudo vboxmanage extpack install Oracle_VM_VirtualBox_Extension_Pack-5.2.44.vbox-extpack
```

# Cuckoo Sandbox
Устанавливаем Venv, активируем и ставим Cuckoo через PIP.

```bash
sudo adduser cuckoo
sudo usermod -aG vboxusers cuckoo
sudo usermod -aG sudo cuckoo
cd /home/cuckoo
su cuckoo
sudo apt install python-m2crypto
virtualenv cuckoo
. /home/cuckoo/cuckoo/bin/activate
pip install -U pip==20.3.4 setuptools==44.1.1 pycrypto==2.6.1 pydeep==0.4 easy_install=66.0.2 distribute==0.7.3 cuckoo==2.0.7 weasyprint==0.36 m2crypto==0.24.0 yara-python==3.6.3 psycopg2-binary==2.8.6
cuckoo
cuckoo community
deactivate
exit
```

# Java для Elasticsearch
Elastic написан на Java, поэтому нам нужно установить Java.

```bash
sudo add-apt-repository ppa:webupd8team/java
sudo apt update && sudo apt -y install openjdk-8-jdk -y
sudo bash -c "echo 'JAVA_HOME=\"/usr/lib/jvm/java-8-openjdk-amd64\"' >> /etc/environment"
source /etc/environment
```

# БД
Тут устанавливаем и настраиваем все БД, обратите внимание, переменная "db_passwd" генерирует рандомный пароль к базе Postgres, если хотите задать свой — не забудьте установить его.    
Cuckoo использует *морально устаревший `Elastic 2`-й версии*, обратите на это внимание и не установите случайно 5.x+ версию.

```bash
sudo apt install mongodb -y
sudo apt install postgresql libpq-dev -y
sudo pip install psycopg2 -y
```

```bash
db_passwd=$(date +%s | sha256sum | base64 | head -c 32 ; echo)
echo "CREATE USER cuckoo WITH PASSWORD '$db_passwd';" | sudo -u postgres psql
echo "CREATE DATABASE cuckoo;" | sudo -u postgres psql
echo "GRANT ALL PRIVILEGES ON DATABASE cuckoo to cuckoo;" | sudo -u postgres psql
```

Нужен VPN или Proxy

```bash
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
```

```bash
echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
sudo apt update && sudo apt install elasticsearch -y
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo service elasticsearch stop
```

```bash
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
```

# Yara + rules
Установим последнюю версию Yara и добавим правила Yara в Cuckoo.

```bash
cd /opt
sudo apt install dh-autoreconf flex bison libjansson-dev libmagic-dev -y
sudo wget https://github.com/VirusTotal/yara/archive/v3.6.3.tar.gz
sudo tar -zxf v3.6.3.tar.gz
cd yara-3.6.3/
sudo ./bootstrap.sh
sudo pip install -U yara-python==3.6.3
cd /home/cuckoo/.cuckoo/yara/
su cuckoo
sudo git clone https://github.com/lehuff/cuckoo-yara-rules.git
sudo cp cuckoo-yara-rules/cuckoo-yara-rules.py .
sudo rm -rf cuckoo-yara-rules
sudo python cuckoo-yara-rules.py
sudo chown -R cuckoo:cuckoo /home/cuckoo/.cuckoo/
```

# SSDeep
Устанавливаем SSDeep.

```bash
cd /opt
sudo pip install -U pytest-runner six cffi
sudo pip install -U ssdeep
cd pySSDeep
sudo python setup.py build
sudo python setup.py install
cd -
```

# Volatility
Установить Volatility просто, но заставить Cuckoo из venv его увидеть — не очень, ставить — же в venv вместе с Cuckoo — тоже не вариант, он зависимостями меняет версии библиотек Cuckoo. С третей строчки костыль, решающий эту проблему, если у кого есть идея, как это подружить более верным способом — напишите.

```bash
sudo apt install pcregrep libpcre++-dev -y
sudo -H pip install -U git+https://github.com/kbandla/pydeep.git
sudo apt install volatility -y
cp -r /usr/lib/python2.7/dist-packages/volatility* /home/cuckoo/cuckoo/lib/python2.7/site-packages
sudo chown cuckoo:cuckoo /home/cuckoo/cuckoo/lib/python2.7/site-packages/*
mv /home/cuckoo/.cuckoo/signatures/windows/volatility_sig.py /home/cuckoo/.cuckoo/signatures/windows/volatility_sig.py.deactivate
```

# TCPDump
Дошли до TCP dump.

```bash
sudo apt install tcpdump apparmor-utils -y
sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo chmod +s /usr/sbin/tcpdump
```

# Teserract
Ставится просто, подключается тоже, однако прелести в работе OCR я не заметил.

```bash
sudo apt install tesseract-ocr -y
```

# Fonts for PDF
Без этой магии PDF отчёты генерироваться не будут.

```bash
sudo -H pip install -U cairocffi
sudo apt install wkhtmltopdf xvfb xfonts-100dpi -y
```

# MitMproxy
Очень полезная библиотека, позволяющая подглядывать в SSL трафик. Обратите внимание, Cuckoo понимает только пакет версии 0.18.2.

```bash
sudo apt install libarchive13 libxml2-dev libxslt1-dev -y
sudo -H pip install -U mitmproxy==0.18.2
su cuckoo
cd ~
mitmproxy + ctrl-c
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.p12 /home/cuckoo/.cuckoo/analyzer/windows/bin/cert.p12
sudo chown cuckoo:cuckoo /home/cuckoo/.cuckoo/analyzer/windows/bin/cert.p12
exit
```

# Tor
Тут всё достаточно просто.

```bash
sudo apt install tor -y
```

Не понятные пока IP адресса. Нужно уточнить кому они пренадлежат.
```bash
sudo sh -c 'echo TransPort 192.168.56.1:9040 >> /etc/tor/torrc'
sudo sh -c 'echo DNSPort 192.168.56.1:5353 >> /etc/tor/torrc'
```

# Suricata
Изначально я хотел написать что и где в конфиге надо править, но к моменту, когда я смог побороть Suricata и убрать все огрехи работы, правок в конфиг было внесено немало, а задокументировано — 0, поэтому публикую конфиг целиком. Тем более оригинальный файл с правилами останется нетронутым.

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install suricata -y
echo "alert http any any -> any any (msg:\"FILE store all\"; filestore; noalert; sid:15; rev:1;)"  | sudo tee /etc/suricata/rules/cuckoo.rules

sudo mv /etc/suricata/suricata-cuckoo.yalm /etc/suricata/suricata-cuckoo.yalm.original
sudo wget -O /etc/suricata/suricata-cuckoo.yaml https://raw.githubusercontent.com/GnuriaN/install_cuckoo/main/suricata-cuckoo.yaml 
```
И напоследок, поправим права.
```bash
sudo mkdir /var/run/suricata
sudo chown cuckoo:cuckoo /var/run/suricata
sudo chown -R cuckoo:cuckoo /etc/suricata
sudo chown -R cuckoo:cuckoo /var/log/suricata
sudo touch /etc/suricata/threshold.config
```
**ИНФО:** возможно директория `/var/run/suricata` уже создана.

# ETupdate
Настраиваем автообновление Community сигнатур Suricata.

```bash
cd /opt
sudo git clone https://github.com/seanthegeek/etupdate.git
sudo cp etupdate/etupdate /usr/sbin
sudo /usr/sbin/etupdate -V
sudo crontab -e
```
Добавляем запись: `0 0 * * * /usr/sbin/etupdate -V` сохраняем и выходим.

# Snort
Добавлять правила в него не стал, так как больше доверяю Suricata.

При конфигурации указываем дефолтный интерфейс и подсеть 192.168.0.0/16.
Как его посмотреть:
```bash
ifconfig
```
или
```bash
ip -br link show
```
или
```bash
nmcli device status
```
Установка:

```bash
sudo apt install snort -y
```
Меняем права:
```bash
sudo chown -R cuckoo:cuckoo /etc/snort/
sudo chown -R cuckoo:cuckoo /var/log/snort/
```

# VMcloak и Windows 7 SP1 X64
Удобнейшая программа для автоматического развёртывания ВМ Cuckoo.    
Существенно сокрашает время, однако автор переписывал её логику работы и конечно-же не обновил документацию. Советую посмотреть либо код утилиты на [GitHub](https://github.com/hatching/vmcloak) либо почитать [старую документацию](https://vmcloak.readthedocs.io/en/latest/), чтобы понять все прелести работы с VMcloak и разобраться с тем, что мы будем делать дальше.    
Самый внимательный хабражитель заметит, что официальный репозиторий проекта https://github.com/jbremer/vmcloak отличается от того, что использован ниже в скрипте https://github.com/tweemeterjop/vmcloak. По отношению к форку, оригинал не умел включать vRDE — реализацию RDP протокола в настраиваемой гостевой ВМ.    
Наверное правильным будет вариант — взять оригинальный код и допилить в него vRDE, однако если форк не так далеко ушёл от отригинала — можно использовать форк, как делаю я ниже. На момент настройки репозиторий и его форк практически не имели отличий.    
По опыту своему скажу — vRDE нужен, бывают use cases, когда документ целевой атаки защищён паролем Word и пароль надо ввести, чтобы вирус отработал в песочнице, либо вирус склеен с установщиком, который надо проинсталлить. Без vRDE это сделать проблематично. Да и для дальнейшей настройки ОС vRDE нам тоже понадобится.

```bash
cd /opt
sudo apt install libyaml-dev libpython2.7-dev genisoimage -y
sudo git clone -b vrde https://github.com/tweemeterjop/vmcloak.git
cd vmcloak/
sudo cp /home/cuckoo/.cuckoo/agent/agent.py vmcloak/data/bootstrap/
sudo -H pip install -r requirements.txt
```
Далее немного магии.
```bash
sudo -H pip install -U requests==2.7.0 sqlalchemy==1.0.8 pyyaml==3.12 click==6.6 ndg-httpsclient==0.5.1
```
Продолжаем:
```bash
sudo python setup.py install
cd ..
```
Внимание, после этого может умереть PIP
```bash
cd usr/lib/python2.7/dist-packages
```
удалить куками пакеты `pip-8.1.1`

После всех танцев унас останеться конфликт библиотек:
```
Warning!!! Possibly conflicting dependencies found:
* mitmproxy==0.18.2
 - requests [required: >=2.9.1,<2.12, installed: 2.7.0]
* VMCloak==0.4.3a2
 - pyyaml [required: ==3.12, installed: 3.11]
```

Продолжаем...
Нужно поместить образ 

```bash
cd /opt
```
