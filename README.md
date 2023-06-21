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
