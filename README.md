### Prerequisites
* install ubuntu server 20.04 on VM
![install-ubuntu-on-VM](https://user-images.githubusercontent.com/38042656/200448074-63632f1c-6b7f-4524-b750-a8140d19c0f7.png)


### 1. Install Java and Nginx
  - Update system packages > ```sudo apt update```
  - Install required package > ```sudo apt install curl wget```
  - To run Elasticsearch, you require Java. Install Java > ``` sudo apt install openjdk-11-jdk ```
  - Verify the installation > ``` java -version ```
  - Kibana dashboard uses Nginx as a reverse proxy. Install Nginx webserver > ``` sudo apt install nginx ```

### 2. Install and Configure Elasticsearch & Kibana
  - Install required packages > ``` $ sudo apt install apt-transport-https ```
  - Import the Elasticsearch PGP signing key > ``` wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - ```
  - Add Elasticsearch APT repository > ``` echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list && apt update ```
  - Install Elasticsearch & Kibana > ``` sudo apt install elasticsearch=8.2.0 && sudo apt install kibana=8.2.0 ```
  - Edit Elasticsearch configuration file > ``` sudo vim /etc/elasticsearch/elasticsearch.yml ```
    ```
    network.host: localhost
    http.port: 9200
    xpack.security.enrollment.enabled: false
    xpack.security.enabled: true
    ```    
    - reload deamon & start the service ``` sudo systemctl daemon-reload && sudo systemctl start elasticsearch ```
    - Test it > ``` curl localhost:9200 -u elastic:elastic-password ``` **you need elastic default password here**
    - you should see this message > 
    
    ```yml
      {
    "name" : "ubuntu-elk",
    "cluster_name" : "elasticsearch",
    "cluster_uuid" : "8K2kc7leQxOJAd27co1Kvw",
    "version" : {
      "number" : "8.2.0",
      "build_flavor" : "default",
      "build_type" : "deb",
      "build_hash" : "b174af62e8dd9f4ac4d25875e9381ffe2b9282c5",
      "build_date" : "2022-04-20T10:35:10.180408517Z",
      "build_snapshot" : false,
      "lucene_version" : "9.1.0",
      "minimum_wire_compatibility_version" : "7.17.0",
      "minimum_index_compatibility_version" : "7.0.0"
    },
    "tagline" : "You Know, for Search"
    }
    ```
    - Generate an enrollment token for Kibana >  ``` ./usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana ```
    - Generate Kibana Encryption keys > ``` ./usr/share/kibana/bin/kibana-encryption-keys generate ```
    - Edit Kibana configuration file > ``` sudo vim /etc/kibana/kibana.yml ```
    ```
    server.port: 5601
    server.host: "0.0.0.0"
    xpack.encryptedSavedObjects.encryptionKey: 12f746c01ac10190095ccc0fa710735c
    xpack.reporting.encryptionKey: 223019dd8b4b45ccbfcb64d331403460
    xpack.security.encryptionKey: 9588a38d34bdbea68faf4d8abcd29185

    ```
    ### 3. Install Nginx and configure the reverse proxy
      - ``` sudo apt-get install nginx && sudo apt-get install apache2-utils```
      - ``` sudo vim /etc/nginx/conf.d/kibana.conf ```
      ```
        server {
      listen 8888 default_server;
      listen [::]:8888 default_server;

      location / {
          proxy_pass http://192.168.1.35:5601;
      }

      location /test {
          proxy_pass http://localhost:5601;
      }
    }
    ```
    - Role (Safee) assign to use (test)
    ![role-assigned-to-user](https://user-images.githubusercontent.com/38042656/200447966-4491c55b-ad41-4e55-a5fd-9c285e1dcb95.png)

    - install Logstash & start > ``` sudo apt install logstash && sudo systemctl start logstash ```
    ### 4. Install Metricbeat and configure it
    - ``` sudo apt install metricbeat=8.2.0 ```
    - Edit Metricbeat configuration file > ``` sudo vim /etc/metricbeat/metricbeat.yml ```
    ```
    host: "localhost:5601"
    output.elasticsearch:
    hosts: ["localhost:9200"]
    username: "elastic"
    password: "b5pJ6A+6ylmJ7s1HMmLk"
    ```
    - enable nginx module ``` metricbeat modules enable nginx```
    - Then, we can customize the metrics we want to track by modifying ```sudo vim /etc/metricbeat/modules.d/system.yml```
    - then start it ``` sudo service metricbeat start && metricbeat setup -e``` > **see the result in dashboard**
    
  ### 5. Install Filebeat and configure it
  - install Filebeat ``` sudo apt install filebeat ``` 
  - ```filebeat modules enable system``` **you have to enable syslog and audit filesets in the file ```modules.d/system.yml```**
  - Configure it > ``` vim /etc/filebeat/filebeat.yml ```
  ```
  output.elasticsearch:
  hosts: ["localhost:9200"]
  username: "elastic"
  password: "b5pJ6A+6ylmJ7s1HMmLk"
  allow_older_versions: true # because we use ELK 8.2.0 V
  ```
  - finally run it > ```sudo service filebeat start && filebeat setup -e ```
  ![filebeat](https://user-images.githubusercontent.com/38042656/200447478-b38821e3-4afd-4a7a-ba6d-8f67995e2117.png)
  ### . Install Heartbeat and configure it
  - ``` sudo apt install heartbeat-elastic ``` then configure it ``` vim /etc/heartbeat/heartbeat.yml ```
  ```
  heartbeat.monitors:
- type: http
  # Set enabled to true (or delete the following line) to enable this example monitor
  enabled: true
  # ID used to uniquely identify this monitor in elasticsearch even if the config changes
  id: my-monitor
  # Human readable display name for this service in Uptime UI and elsewhere
  name: My Monitor
  # List or urls to query
  urls: ["http://localhost:9200"]
  # Configure task schedule
  schedule: '@every 10s'
  # Total test connection and data exchange timeout
  #timeout: 16s
  # Name of corresponding APM service, if Elastic APM is in use for the monitored service.
  #service.name: my-apm-service-name
- type: icmp
  schedule: '*/5 * * * * * *'
  hosts: ["192.168.1.35:9200"]
  id: my-icmp-service
  name: My ICMP Service
- type: tcp
  schedule: '@every 5s'
  hosts: ["192.168.1.35:12345"]
  mode: any
  id: my-tcp-service
  # Kibana
  setup.kibana:
  host: "localhost:5601"
  # Elasticsearch
  output.elasticsearch:
  # Array of hosts to connect to.
  hosts: ["localhost:9200"]
  username: "elastic"
  password: "b5pJ6A+6ylmJ7s1HMmLk"
  allow_older_versions: true
  ```
  - Finally run it > ``` sudo service metricbeat start && heartbeat-elastic -e ```
   ![heartbeat](https://user-images.githubusercontent.com/38042656/200447700-4b12fb17-7bd8-4f6f-a599-d731818ee61b.png)

  ### 6. Dashboard 1
  ![ssh-dashboard](https://user-images.githubusercontent.com/38042656/200446446-b327be83-dc7d-48ee-b562-1d7e10b00658.png)
  ### 7. Dashboard 2
  ![dashboard2](https://user-images.githubusercontent.com/38042656/200446492-8dfb3e0c-1664-478c-972e-3dfbb1cbad83.png)
  ### 8. Alerting purposes (elastaert2 with Docker-Compose) to be continue...
  - docker-compose.yml
  - make sure to run this command before run compose to fix problems when run kibana``` sudo sysctl -w vm.max_map_count=262144 ``` 
  - ``` docker-compose up -d ``` 
  ```
  version: '2.2'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.1.1
    container_name: elasticsearch
    environment:
      - node.name=elasticsearch
      - discovery.seed_hosts=elasticsearch
      - cluster.initial_master_nodes=elasticsearch
      - cluster.name=docker-cluster
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - esdata1:/usr/share/elasticsearch/data
    ports:
      - 9200:9200

  kibana:
    image: docker.elastic.co/kibana/kibana:7.1.1
    container_name: kibana
    environment:
      ELASTICSEARCH_URL: "http://elasticsearch:9200"
    ports:
      - 5601:5601
    depends_on:
      - elasticsearch

volumes:
  esdata1:
    driver: local
  ```
  - Configure Filebeat and enable system module ``` sudo vi /etc/filebeat/filebeat.yml ``` (edit kibana and elasticsearch url to your host)
  ### Install and setup elastalert
  - 
    ```
    sudo apt-get install -y python
    sudo apt-get install -y python-pip python-dev libffi-dev libssl-dev
    git clone https://github.com/Yelp/elastalert.git
    cd elastalert
    sudo pip install "setuptools>=11.3"
    sudo pip install pyOpenSSL
    sudo python setup.py install
    sudo pip install "elasticsearch>=5.0.0"
    cp config.example.yaml config.yaml
    ```
  ### Alert rule to send an email when the VM CPU average is higher than 50% for the last 5 min.
  - ```
      name: CPU spike
      type: spike
      index: logstash-*
      threshold: 1
      timeframe:
          minutes: 5
      spike_height: 2
      spike_type: "up"

          filter:
          - range:
              cpuLoad:
                  from: 3.0
                  to: 55.0

          alert:
          - "email"
          email:
          - "eslam.adel.me@gmail.com.com"          
          from_addr: "test@task.com"
          alert_subject: "CPU - ERROR detected greater than 50%."
          alert_subject_args:
          - "@timestamp"
          alert_text: "Hello Team, ERROR event(s) detected in last 5 minutes."
          alert_text_type: alert_text_only 
    ```
   - Postfix Gmail SMTP
   - install postfix ``` sudo apt-get install postfix mailutils libsasl2-2 ca-certificates libsasl2-modules```
   - Postfix configuration to add
   ```
    relayhost = [smtp.gmail.com]:587
    smtp_sasl_auth_enable = yes
    smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
    smtp_sasl_security_options = noanonymous
    smtp_tls_CApath = /etc/ssl/certs
    smtpd_tls_CApath = /etc/ssl/certs
    smtp_use_tls = yes
   ```
   - Add sasl_passwd
   ``` 
   [smtp.gmail.com]:587	eslam.adel.me@gmail.com:password_generated_from_2fa_app
   ```
   ```
  sudo chmod 400 /etc/postfix/sasl_passwd
  sudo postmap /etc/postfix/sasl_passwd
  sudo systemctl restart postfix
   ``` 
   ### send an email when any heartbeat monitor failed once in the last 5 mins.
   ```
   name: Sites Down
description: Site pings returned down more than once in lat 5 minutes.
type: frequency
index: heartbeat-*
num_events: 2
timeframe:
  minutes: 5
filter:
- query:
    query_string:
      query: "(monitor.status: down) AND !(monitor.name: http)"    
realert: 
  hours: 1
exponential_realert:
  hours: 8

alert:
- "email"
email:
- "eslam.adel.me@gmail.com.com"          
from_addr: "test@task.com"
alert_subject: "Site down"
alert_subject_args:
- "@timestamp"
alert_text: "Hello Team, ERROR event(s) detected in last 5 minutes."
alert_text_type: alert_text_only
   ```
