sleep 30
sudo systemctl start molochcapture.service
sudo systemctl start molochviewer.service
sudo inetsim
cd /opt/irma/ansible/
sudo vagrant up
sudo honeyd -f /usr/share/honeyd/config.conf -i vboxnet0
