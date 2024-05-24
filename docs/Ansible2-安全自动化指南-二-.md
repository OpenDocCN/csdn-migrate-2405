# Ansible2 安全自动化指南（二）

> 原文：[`zh.annas-archive.org/md5/CFD4FC07D470F8B8541AAD40C25E807E`](https://zh.annas-archive.org/md5/CFD4FC07D470F8B8541AAD40C25E807E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：日志监控和无服务器自动防御（AWS 中的 Elastic Stack）

日志监控是考虑安全自动化的理想场所。要使监视有效，需要发生一些事情。我们应该能够将来自不同设备的日志移动到一个中心位置。我们应该能够理解什么是常规日志条目，以及可能是攻击的内容。我们应该能够存储日志，并对其进行诸如聚合、标准化以及最终分析等操作。

但是，在深入设置堆栈并使用 Elastic Stack 构建集中式日志记录和监控之前，我们需要了解一些关于为什么需要使用和自动设置来防御接近实时攻击的原因。成为万事通是困难的。传统的日志记录系统发现很难为所有应用程序、系统和设备记录日志。各种时间格式、日志输出格式等等使得这项任务变得非常复杂。

最大的障碍是找到一种方法能够集中日志。这妨碍了能够有效地实时或接近实时处理日志条目。

以下是一些问题点：

+   访问通常很困难

+   需要高度专业的挖掘数据技能

+   日志很难找到

+   日志数据庞大

在本章中，我们将讨论以下主题：

+   安装 Elastic Stack 进行日志监控

+   在服务器上安装 Beats

+   设置和配置警报

+   设置 AWS Lambda 终端点以进行自动化防御

# Elastic Stack 简介

Elastic Stack 是 Elastic 公司推出的一组开源产品。它可以从任何类型的来源和任何格式的数据中提取数据，并实时搜索、分析和可视化该数据。它由四个主要组件组成，如下：

+   Elasticsearch

+   Logstash

+   Kibana

+   节拍

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/07737655-ba15-4f81-8526-9cf1d3c9aa88.png)

Elastic Stack 架构概述（图片来源：https://www.elastic.co/blog/beats-1-0-0）

它帮助用户/管理员以（接近）实时的方式收集、分析和可视化数据。每个模块根据您的用例和环境进行调整。

# Elasticsearch

Elasticsearch 是一个分布式的、RESTful 的搜索和分析引擎，能够解决越来越多的使用案例。作为 Elastic Stack 的核心，它集中存储您的数据，以便您可以发现预期的内容并发现意外情况

Elastic Stack 的主要优点：

+   分布式和高可用搜索引擎，用 Java 编写，使用 Groovy

+   基于 Lucene 构建

+   多租户，具有多种类型和一组 API

+   面向文档的，提供（接近）实时搜索

# Logstash

Logstash 是一个开源的、服务器端的数据处理管道，它从多种来源摄取数据，同时对其进行转换，然后将其发送到您喜欢的 *stash*。

只是强调 Logstash 是：

+   一个用 Ruby 编写的管理事件和日志的工具

+   所有类型日志的集中式数据处理

+   包括以下三个主要组件：

    +   **输入**：传递日志以将其处理为机器可理解的格式

    +   **过滤器**：一组条件，用于对事件执行特定操作

    +   **输出**：已处理事件/日志的决策者

# Kibana

Kibana 让你可以可视化你的 Elasticsearch 数据并导航 Elastic Stack，这样你就可以做任何事情，从了解为什么在凌晨 2 点会被叫醒到理解雨水可能对你的季度数据造成的影响。

Kibana 的功能列表：

+   强大的前端仪表板是用 JavaScript 编写的

+   基于浏览器的 Elasticsearch 分析和搜索仪表板

+   一个灵活的分析和可视化平台

+   实时以图表、图形、计数、地图等形式提供数据

# Beats

Beats 是单一用途数据船的平台。它们安装为轻量级代理，并将数据从数百或数千台机器发送到 Logstash 或 Elasticsearch。

Beats 是：

+   为 Elasticsearch 和 Logstash 提供轻量级船员

+   捕获各种运营数据，比如日志或网络数据包

+   它们可以将日志发送到 Elasticsearch 或 Logstash

不同类型的 Beats 如下所示：

+   **Libbeat**：用于创建新 Beats 的 Go 框架

+   **Packetbeat**：窥探您的线路数据

+   **Filebeat**：轻量级日志转发器到 Logstash 和 Elasticsearch

+   **Winlogbeat**：发送 Windows 事件日志，以及许多其他由社区提供的 Beats

# 为什么我们应该使用 Elastic Stack 进行安全监控和警报？

Elastic Stack 解决了我们之前讨论过的大部分问题，比如：

+   能够存储大量数据

+   能够理解和读取各种日志格式

+   能够将日志信息从各种设备以近乎实时的方式发送到一个中央位置

+   日志分析的可视化仪表板

# 设置 Elastic Stack 的先决条件

让我们从先决条件开始。在这里，我们使用 `debconf` 来为交互式输入添加值。然后我们安装 Java、nginx 和其他必需的软件包：

```
- name: install python 2
  raw: test -e /usr/bin/python || (apt -y update && apt install -y python-minimal)

- name: accepting oracle java license agreement
  debconf:
    name: 'oracle-java8-installer'
    question: 'shared/accepted-oracle-license-v1-1'
    value: 'true'
    vtype: 'select'

- name: adding ppa repo for oracle java by webupd8team
  apt_repository:
    repo: 'ppa:webupd8team/java'
    state: present
    update_cache: yes

- name: installing java nginx apache2-utils and git
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - python-software-properties
    - oracle-java8-installer
    - nginx
    - apache2-utils
    - python-pip
    - python-passlib
```

# 设置 Elastic Stack

栈是以下组合：

+   Elasticsearch 服务

+   Logstash 服务

+   Kibana 服务

+   所有设备上的 Beats 服务

这个 Elastic Stack 可以以不同的方式设置。在本章中，我们将在单台机器上设置 Elasticsearch、Logstash 和 Kibana。

这是主要的日志收集机器：

+   它至少需要 4 GB 的 RAM，因为我们在一台机器上为三个服务（Elasticsearch、Logstash 和 Kibana）提供服务

+   它需要至少 20 GB 的磁盘空间，并根据您的日志大小增加磁盘空间

# Logstash 集成

Logstash 为以下内容提供了非常大量的集成支持：

+   **输入**：输入插件使得 Logstash 能够读取特定事件源。输入插件有文件、lumberjack、s3、Beats、stdin 等等。

+   **过滤器**：过滤器插件对事件进行中间处理。根据事件的特征，通常会有条件地应用过滤器。

+   **输出**：输出插件将事件数据发送到特定目的地。输出是事件管道中的最后阶段。输出插件包括 Elasticsearch、电子邮件、标准输出、s3、文件、HTTP 等等。

# Kibana

Kibana 默认具有不同类型的插件和集成，以及社区提供的插件，可在[`www.elastic.co/guide/en/kibana/current/known-plugins.html`](https://www.elastic.co/guide/en/kibana/current/known-plugins.html)找到。

# ElastAlert

ElastAlert 是一个 Python 工具，还捆绑了不同类型的集成，用于支持警报和通知。其中一些包括命令、电子邮件、JIRA、OpsGenie、AWS SNS、HipChat、Slack、Telegram 等。它还提供了一种模块化的方法来创建我们自己的集成。

# 安装 Elasticsearch

从存储库安装 Elasticsearch，并将其添加到启动程序：

```
- name: adding elastic gpg key for elasticsearch
  apt_key:
    url: "https://artifacts.elastic.co/GPG-KEY-elasticsearch"
    state: present

- name: adding the elastic repository
  apt_repository:
    repo: "deb https://artifacts.elastic.co/packages/5.x/apt stable main"
    state: present

- name: installing elasticsearch
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - elasticsearch

- name: adding elasticsearch to the startup programs
  service:
    name: elasticsearch
    enabled: yes

  notify:
    - start elasticsearch
```

配置 Elasticsearch 集群所需的设置。另外，为 Elasticsearch 集群备份和快照创建一个备份目录。为 Elasticsearch 集群设置 JVM 选项。 

```
- name: creating elasticsearch backup repo directory at {{ elasticsearch_backups_repo_path }}
  file:
    path: "{{ elasticsearch_backups_repo_path }}"
    state: directory
    mode: 0755
    owner: elasticsearch
    group: elasticsearch

- name: configuring elasticsearch.yml file
  template:
    src: "{{ item.src }}"
    dest: /etc/elasticsearch/"{{ item.dst }}"

  with_items:
    - { src: 'elasticsearch.yml.j2', dst: 'elasticsearch.yml' }
    - { src: 'jvm.options.j2', dst: 'jvm.options' }

  notify:
    - restart elasticsearch
```

通知部分将触发 `重启 elasticsearch` 处理程序，处理程序文件如下所示。一旦在处理程序目录中创建了处理程序，我们可以在任务中的任何地方使用处理程序：

```
- name: start elasticsearch
  service:
    name: elasticsearch
    state: started

- name: restart elasticsearch
  service:
    name: elasticsearch
    state: restarted
```

# 安装 Logstash

从存储库安装 Logstash，并将其添加到启动程序：

```
- name: adding elastic gpg key for logstash
  apt_key:
    url: "https://artifacts.elastic.co/GPG-KEY-elasticsearch"
    state: present

- name: adding the elastic repository
  apt_repository:
    repo: "deb https://artifacts.elastic.co/packages/5.x/apt stable main"
    state: present

- name: installing logstash
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - logstash

- name: adding logstash to the startup programs
  service:
    name: logstash
    enabled: yes

  notify:
    - start logstash
```

配置 Logstash 服务的输入、输出和过滤器设置。这使得可以接收日志、处理日志并将日志发送到 Elasticsearch 集群：

```
- name: logstash configuration files
  template:
    src: "{{ item.src }}"
    dest: /etc/logstash/conf.d/"{{ item.dst }}"

  with_items:
    - { src: '02-beats-input.conf.j2', dst: '02-beats-input.conf' }
    - { src: '10-sshlog-filter.conf.j2', dst: '10-sshlog-filter.conf' }
    - { src: '11-weblog-filter.conf.j2', dst: '11-weblog-filter.conf' }
    - { src: '30-elasticsearch-output.conf.j2', dst: '10-elasticsearch-output.conf' }

  notify:
    - restart logstash
```

# Logstash 配置

为了从不同系统接收日志，我们使用 Elastic 的 Beats 服务。以下配置用于将来自不同服务器的日志发送到 Logstash 服务器。Logstash 运行在端口 `5044` 上，我们可以使用 SSL 证书来确保日志通过加密通道传输：

```
# 02-beats-input.conf.j2
input {
    beats {
        port => 5044
        ssl => true
        ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
        ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
    }
}
```

以下配置用于使用 `grok` 过滤器解析系统 SSH 服务日志（`auth.log`）。同时还应用了 `geoip` 等过滤器，提供额外的国家、地点、经度、纬度等信息：

```
#10-sshlog-filter.conf.j2
filter {
    if [type] == "sshlog" {
        grok {
            match => [ "message", "%{SYSLOGTIMESTAMP:syslog_date} %{SYSLOGHOST:syslog_host} %{DATA:syslog_program}(?:\[%{POSINT}\])?: %{WORD:login} password for %{USERNAME:username} from %{IP:ip} %{GREEDYDATA}",
            "message", "%{SYSLOGTIMESTAMP:syslog_date} %{SYSLOGHOST:syslog_host} %{DATA:syslog_program}(?:\[%{POSINT}\])?: message repeated 2 times: \[ %{WORD:login} password for %{USERNAME:username} from %{IP:ip} %{GREEDYDATA}",
            "message", "%{SYSLOGTIMESTAMP:syslog_date} %{SYSLOGHOST:syslog_host} %{DATA:syslog_program}(?:\[%{POSINT}\])?: %{WORD:login} password for invalid user %{USERNAME:username} from %{IP:ip} %{GREEDYDATA}",
            "message", "%{SYSLOGTIMESTAMP:syslog_date} %{SYSLOGHOST:syslog_host} %{DATA:syslog_program}(?:\[%{POSINT}\])?: %{WORD:login} %{WORD:auth_method} for %{USERNAME:username} from %{IP:ip} %{GREEDYDATA}" ]
        }

        date {
            match => [ "timestamp", "dd/MMM/YYYY:HH:mm:ss Z" ]
            locale => en
        }

        geoip {
            source => "ip"
        }
    }
}
```

以下配置用于解析 Web 服务器日志（`nginx`、`apache2`）。还将应用 `geoip` 和 `useragent` 过滤器。`useragent` 过滤器可帮助我们获取有关代理、操作系统类型、版本信息等的信息：

```
#11-weblog-filter.conf.j2
filter {
    if [type] == "weblog" {
        grok {
        match => { "message" => '%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "%{WORD:verb} %{DATA:request} HTTP/%{NUMBER:httpversion}" %{NUMBER:response:int} (?:-|%{NUMBER:bytes:int}) %{QS:referrer} %{QS:agent}' }
        }

        date {
        match => [ "timestamp", "dd/MMM/YYYY:HH:mm:ss Z" ]
        locale => en
        }

        geoip {
            source => "clientip"
        }

        useragent {
            source => "agent"
            target => "useragent"
        }
    }
}
```

以下配置将日志输出发送到 Elasticsearch 集群，并采用每日索引格式：

```
#30-elasticsearch-output.conf.j2
output {
    elasticsearch {
        hosts => ["localhost:9200"]
        manage_template => false
        index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
        document_type => "%{[@metadata][type]}"
    }
}
```

# 安装 Kibana

以下 Playbook 将安装 Kibana。默认情况下，我们不会对 Kibana 进行任何更改，因为它与 Elasticsearch 相配合：

```
- name: adding elastic gpg key for kibana
  apt_key:
    url: "https://artifacts.elastic.co/GPG-KEY-elasticsearch"
    state: present

- name: adding the elastic repository
  apt_repository:
    repo: "deb https://artifacts.elastic.co/packages/5.x/apt stable main"
    state: present

- name: installing kibana
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - kibana

- name: adding kibana to the startup programs
  service:
    name: kibana
    enabled: yes

  notify:
    - start kibana
```

默认情况下，Kibana 没有任何身份验证，X-Pack 是 Elastic 提供的商业插件，用于 RBAC（基于角色的访问控制）和安全性。此外，一些开源选项包括 [`readonlyrest.com/`](https://readonlyrest.com/) 和 Search Guard ([`floragunn.com`](https://floragunn.com)) 用于与 Elasticsearch 交互。强烈建议使用 TLS/SSL 和自定义身份验证和授权。一些开源选项包括 OAuth2 Proxy ([`github.com/bitly/oauth2_proxy`](https://github.com/bitly/oauth2_proxy)) 和 Auth0 等。

# 配置 nginx 反向代理

以下配置是使用 `nginx` 反向代理启用 Kibana 的基本身份验证：

```
server {
    listen 80;
    server_name localhost;
    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;
    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

设置和配置 nginx 服务如下所示：

```
#command: htpasswd -c /etc/nginx/htpasswd.users
- name: htpasswd generation
  htpasswd:
    path: "/etc/nginx/htpasswd.users"
    name: "{{ basic_auth_username }}"
    password: "{{ basic_auth_password }}"
    owner: root
    group: root
    mode: 0644

- name: nginx virtualhost configuration
  template:
    src: "templates/nginxdefault.j2"
    dest: "/etc/nginx/sites-available/default"

  notify:
    - restart nginx
```

# 安装 Beats 以将日志发送到 Elastic Stack

正如我们讨论的那样，Beats 有不同类型。在下面的 playbook 中，我们将安装 Filebeat，以将 SSH 和 web 服务器日志发送到 Elastic Stack：

```
- name: adding elastic gpg key for filebeat
  apt_key:
    url: "https://artifacts.elastic.co/GPG-KEY-elasticsearch"
    state: present

- name: adding the elastic repository
  apt_repository:
    repo: "deb https://artifacts.elastic.co/packages/5.x/apt stable main"
    state: present

- name: installing filebeat
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - apt-transport-https
    - filebeat

- name: adding filebeat to the startup programs
  service:
    name: filebeat
    enabled: yes

  notify:
    - start filebeat
```

现在我们可以配置 Filebeat，将 SSH 和 web 服务器日志发送到 Elastic Stack，以便实时处理和索引：

```
filebeat:
  prospectors:
    -
      paths:
        - /var/log/auth.log
        # - /var/log/syslog
        # - /var/log/*.log
      document_type: sshlog
    -
      paths:
        - /var/log/nginx/access.log
      document_type: weblog

  registry_file: /var/lib/filebeat/registry

output:
 logstash:
   hosts: ["{{ logstash_server_ip }}:5044"]
   bulk_max_size: 1024
   ssl:
    certificate_authorities: ["/etc/pki/tls/certs/logstash-forwarder.crt"]

logging:
 files:
   rotateeverybytes: 10485760 # = 10MB
```

# 用于警报的 ElastAlert

首先，我们需要安装设置 ElastAlert 的先决条件。然后我们将添加配置文件以根据规则执行警报：

```
- name: installing pre requisuites for elastalert
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - python-pip
    - python-dev
    - libffi-dev
    - libssl-dev
    - python-setuptools
    - build-essential

- name: installing elastalert
  pip:
    name: elastalert

- name: creating elastalert directories
  file: 
    path: "{{ item }}"
    state: directory
    mode: 0755

  with_items:
    - /opt/elastalert/rules
    - /opt/elastalert/config

- name: creating elastalert configuration
  template:
    src: "{{ item.src }}"
    dest: "{{ item.dst }}"

  with_items:
    - { src: 'elastalert-config.j2', dst: '/opt/elastalert/config/config.yml' }
    - { src: 'elastalert-service.j2', dst: '/lib/systemd/system/elastalert.service' }
    - { src: 'elastalert-sshrule.j2', dst: '/opt/elastalert/rules/ssh-bruteforce.yml' }

- name: enable elastalert service
  service:
    name: elastalert
    state: started
    enabled: yes

```

我们还将创建一个简单的启动脚本，以便将 ElastAlert 用作系统服务：

```
[Unit]
Description=elastalert
After=multi-user.target

[Service]
Type=simple
WorkingDirectory=/opt/elastalert
ExecStart=/usr/local/bin/elastalert --config /opt/elastalert/config/config.yml

[Install]
WantedBy=multi-user.target
```

# 配置 Let's Encrypt 服务

我们可以使用 Let's Encrypt 提供的命令行工具以开放、自动化的方式获取免费的 SSL/TLS 证书。

该工具能够读取并理解 nginx 虚拟主机文件，并完全自动生成相关证书，无需任何手动干预：

```
- name: adding certbot ppa
  apt_repository:
    repo: "ppa:certbot/certbot"

- name: install certbot
  apt:
    name: "{{ item }}"
    update_cache: yes
    state: present

  with_items:
    - python-certbot-nginx

- name: check if we have generated a cert already
  stat:
    path: "/etc/letsencrypt/live/{{ website_domain_name }}/fullchain.pem"
    register: cert_stats

- name: run certbot to generate the certificates
  shell: "certbot certonly --standalone -d {{ website_domain_name }} --email {{ service_admin_email }} --non-interactive --agree-tos"
  when: cert_stats.stat.exists == False

- name: configuring site files
  template:
    src: website.conf
    dest: "/etc/nginx/sites-available/{{ website_domain_name }}"

- name: restart nginx
  service:
    name: nginx
    state: restarted
```

# ElastAlert 规则配置

假设您已经安装了 Elastic Stack 并记录了 SSH 日志，请使用以下 ElastAlert 规则触发 SSH 攻击 IP 黑名单：

```
es_host: localhost
es_port: 9200
name: "SSH Bruteforce attack alert"
type: frequency
index: filebeat-*
num_events: 20
timeframe:
  minutes: 1
# For more info: http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/query-dsl.html

filter:
- query:
    query_string:
      query: '_type:sshlog AND login:failed AND (username: "ubuntu" OR username: "root")'

alert:
  - slack:
      slack_webhook_url: "https://hooks.slack.com/services/xxxxx"
      slack_username_override: "attack-bot"
      slack_emoji_override: "robot_face"
  - command: ["/usr/bin/curl", "https://xxxxxxxxxxx.execute-api.us-east-1.amazonaws.com/dev/zzzzzzzzzzzzzz/ip/inframonitor/%(ip)s"]

realert:
  minutes: 0
```

在上述示例规则中，大多数参数都是可配置的，根据使用情况而定。

欲了解更多参考，请访问 [`elastalert.readthedocs.io/en/latest/running_elastalert.html`](https://elastalert.readthedocs.io/en/latest/running_elastalert.html)。

# Kibana 仪表板

我们可以将现有的仪表板文件（JSON 格式）导入到 Kibana 中，通过上传 JSON 文件来查看不同的模式。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/e6a3bd97-e0b8-489c-8923-7cb7604497e0.png)

在 Kibana 仪表板中创建索引

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/c9600d4f-2e98-4357-81ca-44952ffbbbe7.png)

将现有的仪表板和可视化内容导入到 Kibana 仪表板

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/7ff55bec-6f91-41a5-8cec-700f4de02ab9.png)

来自 SSH 和 web 服务器日志的攻击仪表板

# 自动化防御？

如果我们能够收到攻击的通知，我们可以进行以下设置和操作：

+   调用 AWS Lambda 函数

+   将攻击者的 IP 地址信息发送到此 AWS Lambda 函数端点

+   使用部署在 Lambda 函数中的代码调用 VPC 网络访问列表 API，并阻止攻击者的 IP 地址

为了确保我们不会用攻击者的 IP 填满 ACL，我们可以将这种方法与 AWS DynamoDB 结合使用，将此信息存储一段时间并从阻止列表中删除。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/3bc96a8d-e7d8-4319-bda8-232f46135565.png)

# 在设置中使用的 AWS 服务

一旦检测到攻击，警报器会通过 HTTPS 请求将 IP 发送到黑名单 Lambda 端点。使用网络 ACL 阻止 IP，并在 DynamoDB 中维护其记录。如果 IP 已被阻止，则在 DynamoDB 中将为该规则的过期时间延长。

定期触发一个到期处理程序函数，从 DynamoDB 和 ACL 中相应地删除过期的规则。

# DynamoDB

DynamoDB 是规则映射到其相应 ACL ID 的中央数据库。通过适当的 Lambda 函数将 IP 地址的规则添加到`blacklist_ip`表中，并从中删除。

# 黑名单 Lambda 函数

黑名单函数是设置的唯一暴露的端点。需要通过 HTTPS 请求将需要列入黑名单的任何 IP 提供给此函数。

# HandleExpiry Lambda 函数

HandleExpiry 函数每分钟触发一次，并根据`expirymin`字段从 ACL 和 DynamoDB 中删除过期规则。

# 云监控

云监控定期触发 HandleExpiry Lambda 函数。默认情况下，该函数每分钟触发一次。

# VPC 网络 ACL

VPC 网络 ACL 是 ACL 规则添加和删除的地方。在设置时必须配置 ACL ID。

# 设置

设置涉及以下步骤：

+   获取 IAM 凭证

+   在 DynamoDB 中创建一个表

+   根据需求配置 Lambda 函数

+   将代码部署到 AWS Lambda

+   配置云监控定期调用

整个设置是自动化的，除了获取 IAM 凭证并根据需求配置函数之外。

# 配置

在部署之前可配置以下参数：

+   `region`：部署的 AWS 区域。这需要与 VPC 网络所在的区域相同。

+   `accessToken`：用于对黑名单端点进行身份验证的 accessToken。

+   `aclLimit`：ACL 可处理的规则数的最大限制。AWS 中默认的最大限制是 20。

+   `ruleStartId`：ACL 中规则的起始 ID。

+   `aclID`：规则将应用的网络的 ACL ID。

+   `tableName`：为每个要防御的 VPC 创建的唯一表名称。

+   `ruleValidity`：规则有效的持续时间，之后 IP 将被解除阻止。

在`config.js`文件中配置以下内容：

```
module.exports = {
    region: "us-east-1",                                        // AWS Region to deploy in
    accessToken: "YOUR_R4NDOM_S3CR3T_ACCESS_TOKEN_GOES_HERE",   // Accesstoken to make requests to blacklist
    aclLimit: 20,                                               // Maximum number of acl rules
    ruleStartId: 10,                                            // Starting id for acl entries
    aclId: "YOUR_ACL_ID",                                       // AclId that you want to be managed
    tableName: "blacklist_ip",                                  // DynamoDB table that will be created
    ruleValidity: 5                                             // Validity of Blacklist rule in minutes 
}
```

确保至少根据您的设置修改`aclId`、`accessToken`和`region`。要修改 Lambda 部署配置，请使用`serverless.yml`文件：

```
...

functions:
  blacklist:
    handler: handler.blacklistip
    events:
     - http:
         path: blacklistip
         method: get

  handleexpiry:
    handler: handler.handleexpiry
    events:
     - schedule: rate(1 minute)

...
```

例如，可以使用 YML 文件修改到期函数触发的速率以及黑名单函数的端点 URL。但默认值已经是最佳的。

播放手册如下：

```
- name: installing node run time and npm
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - nodejs
    - npm

- name: installing serverless package
  npm:
    name: "{{ item }}"
    global: yes
    state: present

  with_items:
    - serverless
    - aws-sdk

- name: copy the setup files
  template:
    src: "{{ item.src }}"
    dest: "{{ item.dst }}"

  with_items:
    - { src: 'config.js.j2', dst: '/opt/serverless/config.js' }
    - { src: 'handler.js.j2', dst: '/opt/serverless/handler.js' }
    - { src: 'iamRoleStatements.json.j2', dst: '/opt/serverless/iamRoleStatements.json' }
    - { src: 'initDb.js.j2', dst: '/opt/serverless/initDb.js' }
    - { src: 'serverless.yml.j2', dst: '/opt/serverless/serverless.yml' }
    - { src: 'aws-credentials.j2', dst: '~/.aws/credentials' }

- name: create dynamo db table
  command: node initDb.js
  args:
    chdir: /opt/serverless/

- name: deploy the serverless
  command: serverless deploy
  args:
    chdir: /opt/serverless/
```

目前 AWS Lambda 的设置是针对网络 ACL 封锁 IP 地址。这可以在其他 API 端点上重用，比如防火墙动态封锁列表和其他安全设备。

根据 AWS 文档，VPC 网络 ACL 规则限制设置为 20：[`docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html#vpc-limits-nacls`](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html#vpc-limits-nacls)

# 使用方法 - 封锁 IP 地址

黑名单端点负责封锁 IP 地址。

# 请求

URL 看起来像以下内容：`https://lambda_url/blacklistipaccessToken=ACCESS_TOKEN&ip=IP_ADDRESS`

查询参数如下：

+   `IP_ADDRESS`：要封锁的 IP 地址

+   `ACCESS_TOKEN`：用于验证请求的`accessToken`

# 响应

响应是标准的 HTTP 状态码，如下所述：

| **状态码** | **主体** | **解释** |
| --- | --- | --- |
| `200` | 已封锁 | 该 IP 已添加到黑名单 |
| `200` | 延长到期 | 黑名单规则的有效期已延长 |
| `400` | 错误请求 | 缺少必填字段 |
| `401` | 未经授权 | accessToken 无效或丢失 |
| `500` | 规则限制已达到 | 已达到 ACL 规则限制 |

# 自动化防御 lambda 在行动

当 ElastAlert 检测到 SSH 暴力攻击时，它将触发对 lambda 端点的请求，提供攻击者的 IP 地址。然后我们的自动化防御平台将触发网络 ACL 封锁列表规则。这可以配置为阻止多长时间。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/bf231e4a-6b2a-44db-8f58-c18ca8739187.png)

# 摘要

这是很多信息需要消化的。此外，我们对场景做出了很多假设。但是，如果这激发了您考虑将设备和服务器的各种日志组合到一个中央位置并启用自动警报和防御措施，那我们的工作就做得很好。

正如本章所示，安全自动化有点像管道工作。只要我们能够理解如何让一堆不同的系统相互通信，我们就可以将它们添加到我们的 playbooks 中。在许多情况下，Ansible 已经为我们提供了可用于使用和启动的模块。

现在我们已经激发了您对日志记录和攻击检测的兴趣，在下一章中，让我们深入了解设置自动化网络安全测试的所需。我们将选择功能强大且多才多艺的 OWASP ZAP 扫描仪和拦截代理，并使用它扫描和测试网站和 API。


# 第五章：使用 OWASP ZAP 进行自动化 Web 应用程序安全测试

OWASP **Zed Attack Proxy**（通常称为**ZAP**）是最受欢迎的网络应用安全测试工具之一。它具有许多功能，使其可用于手动安全测试；在一些调整和配置后，它也很好地适用于**持续集成/持续交付**（**CI/CD**）环境。

有关该项目的更多详细信息可以在[`www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project`](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)找到。

**开放式网络应用安全项目**（**OWASP**）是一个致力于改善软件安全性的全球性非营利慈善组织。在[`www.owasp.org`](https://www.owasp.org)了解更多关于 OWASP 项目和资源的信息。

OWASP ZAP 在一个包中包含许多不同的工具和功能。对于负责对 Web 应用程序进行安全测试的渗透测试员，以下功能至关重要：

| **功能** | **用例** |
| --- | --- |
| 拦截代理 | 这允许我们拦截浏览器中的请求和响应 |
| 主动扫描器 | 自动运行针对目标的网络安全扫描 |
| 被动扫描器 | 从使用蜘蛛工具下载的页面中获取有关安全问题的信息 |
| 蜘蛛 | 在 ZAP 可以攻击应用程序之前，它通过遍历所有可能的网页来创建应用程序的站点地图 |
| REST API | 允许 ZAP 在无头模式下运行，并控制运行自动扫描器、蜘蛛和获取结果 |

正如你可能已经猜到的，在本章中，为了进行安全自动化，我们将以无头模式调用 ZAP，并使用其提供的 API 接口来进行扫描和安全测试。

ZAP 是基于 Java 的软件。使用它的典型方式将涉及以下内容：

+   **Java 运行时环境**（**JRE**）7 或更高版本安装在您选择的操作系统中（macOS、Windows、Linux）

+   使用官方下载页面的软件包管理器、安装程序安装 ZAP

你可以在此处找到最新的更新稳定链接：[`github.com/zaproxy/zaproxy/wiki/Downloads`](https://github.com/zaproxy/zaproxy/wiki/Downloads)。

虽然我们可以构建一个执行此操作的操作手册，但开发者世界正在向 CI/CD 和持续安全的概念发展。一个可以在需要时引导稳定版本的 ZAP 的方法将是理想的。

实现这一目标的最佳方法是将 OWASP ZAP 用作容器。事实上，这是 Mozilla 在 CI/CD 管道中使用 ZAP 来验证每个发布的基线安全控制的设置方式。

如果您想知道 Mozilla 和 OWASP ZAP 之间的联系，Simon Bennetts 领导了 OWASP ZAP 项目并在 Mozilla 工作。 阅读他关于 ZAP 基线扫描的博客文章：[`blog.mozilla.org/security/2017/01/25/setting-a-baseline-for-web-security-controls/`](https://blog.mozilla.org/security/2017/01/25/setting-a-baseline-for-web-security-controls/)。

# 安装 OWASP ZAP

在本章中，我们将使用 OWASP ZAP 作为一个容器，这需要在主机操作系统中运行容器运行时。 OWASP ZAP 团队每周通过 Docker Hub 发布 ZAP Docker 镜像。 根据标签拉取 Docker 镜像的方法在现代 DevOps 环境中很受欢迎，因此我们谈论与其相关的自动化是有意义的。

官方 ZAP 现在通过 Docker Hub 的 Docker 容器提供稳定版和每周发布版本：[`github.com/zaproxy/zaproxy/wiki/Docker`](https://github.com/zaproxy/zaproxy/wiki/Docker)。

# 安装 Docker 运行时

**Docker** 是供开发人员和系统管理员构建、发布和运行分布式应用程序的开放平台，无论是在笔记本电脑、数据中心虚拟机还是云中。 要了解有关 Docker 的更多信息，请参阅 [`www.docker.com/what-docker`](https://www.docker.com/what-docker)。

以下 Playbook 将在 Ubuntu 16.04 中安装 Docker Community Edition 软件：

```
- name: installing docker on ubuntu
  hosts: zap
  remote_user: "{{ remote_user_name }}"
  gather_facts: no
  become: yes
  vars:
    remote_user_name: ubuntu
    apt_repo_data: "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable"
    apt_gpg_key: https://download.docker.com/linux/ubuntu/gpg

  tasks:
    - name: adding docker gpg key
      apt_key:
        url: "{{ apt_gpg_key }}"
        state: present

    - name: add docker repository
      apt_repository:
        repo: "{{ apt_repo_data }}"
        state: present

    - name: installing docker-ce
      apt:
        name: docker-ce
        state: present
        update_cache: yes
    - name: install python-pip
      apt:
        name: python-pip
        state: present
    - name: install docker-py
      pip:
        name: "{{ item }}"
        state: present

      with_items:
        - docker-py

```

Docker 需要 64 位版本的操作系统和 Linux 内核版本大于或等于 3.10。 Docker 运行时也适用于 Windows 和 macOS。 对于本章的目的，我们将使用基于 Linux 的容器。 因此运行时可以在 Windows 上，但在其中运行的容器将是基于 Linux 的。 这些是可用于使用的标准 OWASP ZAP 容器。

# OWASP ZAP Docker 容器设置

我们将在这里使用的两个新模块来处理 Docker 容器是 `docker_image` 和 `docker_container`。

这些模块要求您使用 2.1 及更高版本的 Ansible。现在是检查您的 Ansible 版本的好时机，可以使用 `—version` 标志。

如果您需要使用 `pip` 获取最新稳定版本，请运行以下命令：

```
pip install ansible --upgrade 
```

由于需要从互联网下载约 1GB 的数据，以下操作可能需要一些时间才能完成：

```
- name: setting up owasp zap container
  hosts: zap
  remote_user: "{{ remote_user_name }}"
  gather_facts: no
  become: yes
  vars:
    remote_user_name: ubuntu
    owasp_zap_image_name: owasp/zap2docker-weekly

  tasks:
    - name: pulling {{ owasp_zap_image_name }} container
      docker_image:
        name: "{{ owasp_zap_image_name }}"

    - name: running owasp zap container
      docker_container:
        name: owasp-zap
        image: "{{ owasp_zap_image_name }}"
        interactive: yes
        state: started
        user: zap
        command: zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
        ports:
          - "8090:8090"
</span>
```

在以下配置中，我们说 `api.disablekey=true`，这意味着我们不使用任何 API 密钥。 这可以通过给定特定的 API 密钥来覆盖。 `api.addrs.addr.name=.*` 和 `api.addrs.addr.regex=true` 将允许所有 IP 地址连接到 ZAP API。 有关 ZAP API 密钥设置的更多信息，请参阅 [`github.com/zaproxy/zaproxy/wiki/FAQapikey`](https://github.com/zaproxy/zaproxy/wiki/FAQapikey)。

您可以通过导航到 `http://ZAPSERVERIPADDRESS:8090` 来访问 ZAP API 界面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/cd7413f7-b766-41af-b24f-9d79ce0dbc07.png)

OWASP ZAP API Web UI

# 用于处理容器的专用工具 - Ansible Container

目前，我们正在使用 Docker 模块执行容器操作。新工具 `ansible-container` 提供了一个 Ansible 中心化的工作流程，用于构建、运行、测试和部署容器。

这使我们能够使用现有的播放构建、推送和运行容器。Dockerfiles 就像编写 shell 脚本一样，因此，`ansible-container` 将允许我们将这些 Dockerfiles 编码化，并使用现有的播放构建它们，而不是编写复杂的脚本。

`ansible-container` 支持各种编排工具，如 Kubernetes 和 OpenShift。它还可以用于将构建的映像推送到私有注册表，如 Google Container Registry 和 Docker Hub。

在[`docs.ansible.com/ansible-container/`](https://docs.ansible.com/ansible-container/)了解更多关于`ansible-container`的信息。

# 配置 ZAP 基线扫描

ZAP 基线扫描是在 ZAP Docker 镜像中可用的脚本。

更多关于 OWASP ZAP 基线扫描的详细信息可以在[`github.com/zaproxy/zaproxy/wiki/ZAP-Baseline-Scan`](https://github.com/zaproxy/zaproxy/wiki/ZAP-Baseline-Scan)找到。

此脚本的功能如下：

+   对指定目标运行 ZAP 蜘蛛一分钟，然后执行被动扫描

+   默认情况下，将所有警报报告为警告

+   此脚本旨在在 CI/CD 环境中运行，甚至针对生产站点也是理想的。

在设置和运行 ZAP 基线扫描之前，我们希望运行一个简单易受攻击的应用程序，以便所有使用 ZAP 的扫描和测试都针对该应用程序运行，而不是针对真实世界的应用程序运行扫描，这是未经许可的。

# 运行一个易受攻击的应用容器

我们将使用**Damn Vulnerable Web Services**（**DVWS**）应用程序（更多信息，请访问[`github.com/snoopysecurity/dvws`](https://github.com/snoopysecurity/dvws)）。它是一个带有多个易受攻击的 Web 服务组件的不安全 Web 应用程序，可用于学习真实世界的 Web 服务漏洞。

以下播放将设置运行 DVWS 应用程序的 Docker 容器：

```
- name: setting up DVWS container
  hosts: dvws
  remote_user: "{{ remote_user_name }}"
  gather_facts: no
  become: yes
  vars:
    remote_user_name: ubuntu
    dvws_image_name: cyrivs89/web-dvws

  tasks:
    - name: pulling {{ dvws_image_name }} container
      docker_image:
        name: "{{ dvws_image_name }}"

    - name: running dvws container
      docker_container:
        name: dvws
        image: "{{ dvws_image_name }}"
        interactive: yes
        state: started
        ports:
          - "80:80"

```

一旦播放成功执行，我们可以导航到 `http://DVWSSERVERIP`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/938c0a0d-3b89-43b5-9fa4-88a534cf121d.png)

DVWS 应用首页

现在，我们已经准备好对 DVWS 应用程序执行我们的 OWASP ZAP 基线扫描，通过运行基线扫描播放。

# 运行 OWASP ZAP 基线扫描

以下播放会针对给定的网站 URL 运行 Docker 基线扫描。它还将基线扫描的输出存储在主机系统中，以 HTML、Markdown 和 XML 格式进行存储：

```
- name: Running OWASP ZAP Baseline Scan
  hosts: zap
  remote_user: "{{ remote_user_name }}"
  gather_facts: no
  become: yes
  vars:
    remote_user_name: ubuntu
    owasp_zap_image_name: owasp/zap2docker-weekly
    website_url: {{ website_url }}
    reports_location: /zapdata/
    scan_name: owasp-zap-base-line-scan-dvws

  tasks:
    - name: adding write permissions to reports directory
      file:
        path: "{{ reports_location }}"
        state: directory
        owner: root
        group: root
        recurse: yes
        mode: 0770

    - name: running owasp zap baseline scan container against "{{ website_url }}"
      docker_container:
        name: "{{ scan_name }}"
        image: "{{ owasp_zap_image_name }}"
        interactive: yes
        auto_remove: yes
        state: started
        volumes: "{{ reports_location }}:/zap/wrk:rw"
        command: "zap-baseline.py -t {{ website_url }} -r {{ scan_name }}_report.html"

    - name: getting raw output of the scan
      command: "docker logs -f {{ scan_name }}"
      register: scan_output

    - debug:
        msg: "{{ scan_output }}"

```

让我们探索前面播放的参数：

+   `website_url` 是要执行基线扫描的域名（或）URL，我们可以通过 `--extra-vars "website_url: http://192.168.33.111"` 从 `ansible-playbook` 命令传递这个参数

+   `reports_location` 是 ZAP 主机的路径，报告存储在其中。

下面的截图是来自 OWASP ZAP 的扫描报告输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/576c1909-a7c7-43a8-90e3-93ced983ca3c.png)

OWASP ZAP 基线扫描 HTML 报告

要生成 Markdown 和 XML 格式的报告，请分别添加`-w report.md`和`-x report.xml`到命令。

# 针对 Web 应用程序和网站进行安全测试

到目前为止，我们已经看到了如何使用 OWASP ZAP 容器运行基线扫描。现在我们将看到如何对 Web 应用程序执行主动扫描。主动扫描可能导致应用程序中的漏洞被利用。此外，这种类型的扫描需要额外的配置，包括身份验证和敏感功能。

# 对 DVWS 运行 ZAP 全面扫描

下面的 playbook 将针对 DVWS 应用程序运行全面扫描。现在我们可以看到 playbook 看起来几乎相似，只是发送给命令的标志不同：

```
- name: Running OWASP ZAP Full Scan
  hosts: zap
  remote_user: "{{ remote_user_name }}"
  gather_facts: no
  become: yes
  vars:
    remote_user_name: ubuntu
    owasp_zap_image_name: owasp/zap2docker-weekly
    website_url: {{ website_url }}
    reports_location: /zapdata/
    scan_name: owasp-zap-full-scan-dvws

  tasks:
    - name: adding write permissions to reports directory
      file:

        path: "{{ reports_location }}"
        state: directory
        owner: root
        group: root
        recurse: yes
        mode: 0777

    - name: running owasp zap full scan container against "{{ website_url }}"
      docker_container:
        name: "{{ scan_name }}"
        image: "{{ owasp_zap_image_name }}"
        interactive: yes
        auto_remove: yes
        state: started
        volumes: "{{ reports_location }}:/zap/wrk:rw"
        command: "zap-full-scan.py -t {{ website_url }} -r {{ scan_name }}_report.html"

    - name: getting raw output of the scan
      raw: "docker logs -f {{ scan_name }}"
      register: scan_output

    - debug:
        msg: "{{ scan_output }}"
```

OWASP ZAP 全面扫描检查了许多漏洞，其中包括 OWASP TOP 10（有关更多信息，请访问[`www.owasp.org/index.php/Category:OWASP_Top_Ten_Project`](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)）和许多其他漏洞。这可能对应用程序造成干扰，并向应用程序发送主动请求。它可能会基于应用程序中存在的漏洞对功能造成损害：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/f1f77783-9cb8-4c72-9f58-15f022c2e90c.png)

DVWS 应用程序的 OWASP ZAP 全面扫描报告

上面的截图是 OWASP ZAP 针对 DVWS 应用程序的全面扫描报告。我们可以清楚地看到基线扫描和全面扫描之间的差异，这是基于漏洞数量、不同类型的漏洞和风险评级。

# 测试 Web API

与 ZAP 基线扫描类似，ZAP 背后的可爱人士们提供了一个脚本作为他们的实时和每周 Docker 镜像的一部分。我们可以使用它来对由 OpenAPI 规范或**简单对象访问协议**（**SOAP**）定义的 API 端点运行扫描。

脚本可以理解 API 规范并导入所有定义。基于此，它对找到的所有 URL 运行主动扫描：

```
- name: Running OWASP ZAP API Scan
  hosts: zap
  remote_user: "{{ remote_user_name }}"
  gather_facts: no
  become: yes
  vars:
    remote_user_name: ubuntu
    owasp_zap_image_name: owasp/zap2docker-weekly
    website_url: {{ website_url }}
    reports_location: /zapdata/
    scan_name: owasp-zap-api-scan-dvws
    api_type: openapi
>
  tasks:
    - name: adding write permissions to reports directory
      file:
        path: "{{ reports_location }}"
        state: directory
        owner: root
        group: root
        recurse: yes
        mode: 0777

    - name: running owasp zap api scan container against "{{ website_url }}"
      docker_container:
        name: "{{ scan_name }}"
        image: "{{ owasp_zap_image_name }}"
        interactive: yes
        auto_remove: yes
        state: started
        volumes: "{{ reports_location }}:/zap/wrk:rw"
        command: "zap-api-scan.py -t {{ website_url }} -f {{ api_type }} -r {{ scan_name }}_report.html"

    - name: getting raw output of the scan
      raw: "docker logs -f {{ scan_name }}"
      register: scan_output

    - debug:
        msg: "{{ scan_output }}"
```

# 使用 ZAP 和 Jenkins 进行持续扫描工作流

Jenkins 是一个开源自动化服务器。它在 CI/CD 流水线中被广泛使用。这些流水线通常指一系列基于触发器发生的自动化步骤，例如提交代码到版本控制软件或创建新版本。

我们已经看到了 ZAP 基线扫描作为 Mozilla 发布周期的一部分的示例。我们可以将 ZAP 与 Jenkins 集成。虽然我们可以有许多方式来实现这一点，但一组有用的步骤将是以下内容：

1.  基于触发器，一个新的 ZAP 实例已经准备好进行扫描

1.  ZAP 实例针对自动部署的应用程序运行

1.  扫描结果以某种格式捕获和存储

1.  如果我们选择，结果也可以在诸如 Atlassian Jira 的缺陷跟踪系统中创建票证

为此，我们将首先设置我们的流水线基础设施：

1.  使用 playbook 设置 Jenkins

1.  添加官方 OWASP ZAP Jenkins 插件

1.  使用另一个 playbook 触发工作流程

官方 OWASP ZAP Jenkins 插件可以在 [`wiki.jenkins.io/display/JENKINS/zap+plugin`](https://wiki.jenkins.io/display/JENKINS/zap+plugin) 找到。

# 设置 Jenkins

在服务器上设置 Jenkins 用作 OWASP ZAP 的 CI/CD 平台。 这将返回 Jenkins 管理员密码，一旦完成，我们就可以安装 Ansible 插件：

```
- name: installing jenkins in ubuntu 16.04
  hosts: jenkins
  remote_user: {{ remote_user_name }}
  gather_facts: False
  become: yes
  vars:
    remote_user_name: ubuntu

  tasks:
    - name: adding jenkins gpg key
      apt_key:
        url: 'https://pkg.jenkins.io/debian/jenkins-ci.org.key'
        state: present

    - name: jeknins repository to system
      apt_repository:
        repo: 'deb http://pkg.jenkins.io/debian-stable binary/'
        state: present
    - name: installing jenkins
      apt:
        name: jenkins
        state: present
        update_cache: yes

    - name: adding jenkins to startup
      service:
        name: jenkins
        state: started
        enabled: yes

    - name: printing jenkins default administration password
      command: cat "/var/lib/jenkins/secrets/initialAdminPassword"
      register: jenkins_default_admin_password

    - debug: 
        msg: "{{ jenkins_default_admin_password.stdout }}"

```

然后，我们可以将 playbook 添加到项目中。 当 Jenkins 构建中发生新的触发时，playbook 将开始扫描网站以执行基线扫描：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/5f4b742a-1eb2-48e3-bc56-962db8f2ad5b.png)

一旦 playbooks 触发，它将针对 URL 执行 playbooks 并返回 ZAP 基线扫描输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/0530335e-2a45-4cf4-9d97-14eb53e6e209.png)

# 设置 OWASP ZAP Jenkins 插件

OWASP ZAP 与 Jenkins 配合工作是一个相当常见的设置。我们已经知道如何设置 Jenkins。我们可以使用我们的 playbook 安装官方 ZAP Jenkins 插件。

一旦 playbook 准备就绪，需要进行一些手动配置。 我们在我们的 playbook 安装了 Jenkins 并重新启动服务器后开始，以便插件可用于我们的构建作业。

让我们创建一个新的构建作业，并将其命名为 `ZAP-Jenkins`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/532650b3-2529-4ef8-baf2-c5271b1626dc.png)

对我们来说，这将是一个自由风格的项目。 现在我们将向其中添加 ZAP 的魔力：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/c01a9481-e741-4a27-a5f7-81fe43a0427f.png)

我们正在按照 Jenkins 页面上官方插件的说明进行操作： [`wiki.jenkins.io/display/JENKINS/zap+plugin`](https://wiki.jenkins.io/display/JENKINS/zap+plugin)。

# 需要一些组装

指定接口的 IP 地址和 ZAP 应监听的端口号。 通常，此端口为 `8080`，但由于 Jenkins 正在监听该端口，我们选择 `8090`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/730cfcc9-281b-48be-afb8-c5a4b7b6b73a.png)

对于 JDK，我们选择唯一可用的选项，即从作业继承：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/9f243189-aa25-4418-8fae-a1833c4c4153.png)

对于安装方法，我们选择已经安装在 `/usr/share/owasp-zap` 上的 ZAP。 我们将此值添加到 `/etc/environment` 中的 `ZAPROXY_HOME` 环境变量中。

这样做，我们确保环境变量值在系统重新启动时也能存活：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/4eccf484-5cca-4f5f-b724-4804d0f95444.png)

我们为超时设置了相当小的值，以确保万一出现问题，我们不必等待太久才能看到构建失败或 ZAP 无响应。

我们还指定了一个命令行选项，告诉 Jenkins ZAP 的安装目录是什么。

您可能需要单击“高级”按钮才能查看这些选项。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/590e44b0-85bf-4458-b085-843093366d5a.png)

我们指定了 ZAP 主目录的路径：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/7ca7ac48-5b26-44b3-829a-db3204f326b2.png)

然后我们配置从哪里加载 ZAP 会话：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/af32082a-c625-49a8-b04f-6df0f587185d.png)

这里显示了上下文名称、范围和排除项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/0e38dc8c-b8a3-4846-95cd-5d4052862e9b.png)

这是要测试的 URL 的起始点。我们计划执行的测试类型是爬虫扫描，默认为主动扫描：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/4480cb66-d930-4888-827e-5930f8108cb9.png)

最后，我们指定将生成的报告的文件名。我们添加`BUILD_ID`变量以确保我们无需担心覆盖报告。

# 触发构建（ZAP 扫描）

作业配置完成后，我们就可以触发构建了。当然，您也可以手动点击立即构建然后开始。

但我们将配置构建作业以远程触发，并同时传递必要的目标信息。

在常规下勾选此项目是参数化的：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/97119a78-d832-4e6e-8063-b7a9e494be69.png)

在其中，我们添加一个带有默认值的`TARGET`参数。

在构建触发器下，我们指定一个身份验证令牌，以便在远程触发构建时作为参数传递：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/0fe9b5c7-ca95-4b00-a6e3-c38d88445237.png)

请尽量确保此令牌足够长且随机，并且不是我们用作示例的简单单词。

在 Linux/macOS 中生成足够随机的字符串的一个好方法是使用 OpenSSL 命令。对于`hex`输出（`20`是输出的长度），使用`**openssl rand -hex 20**`。对于`base64`输出（`24`是输出的长度），使用`**openssl rand -base64 24**`。

在此时，我们所要做的就是注意已登录用户的 API 令牌（从`http://JENKINS-URL/user/admin/configure`）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/f484ebee-c98d-4148-baba-a06dbcb14ad7.png)

单击“显示 API 令牌”将显示令牌：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/d828b98f-18ee-4aac-8e5a-7c704816525d.png)

我们现在可以使用命令行工具，比如`curl`，来查看是否正常工作。

链接的格式是`curl "http://username:API-TOKEN@JENKINS-URL/job/ZAP-Jenkins/buildWithParameters?TARGET=http://demo.testfire.net&token=ansible2security"`。

这将触发构建，应用程序将被扫描以查找安全问题。

# 使用自动化进行的操作指南

要执行前述触发器，我们可以使用以下 Ansible playbook。这也可以在我们的 Ansible Tower 中使用来安排扫描。

以下操作指南可以使用 Ansible Vault 存储 API 令牌密钥，该功能用于以加密格式存储 playbooks 中的机密数据。我们将在第十一章中学习有关 Ansible Vault 用法的更多信息，*Ansible 安全最佳实践、参考资料和进一步阅读*。

要创建 Ansible Vault 加密变量，请运行以下命令。当它提示输入密码时，给出一个密码以加密此变量，执行 playbook 时需要。

```
echo 'YOURTOKENGOESHERE' | ansible-vault encrypt_string --stdin-name 'jenkins_api_token'
```

执行后，它会返回加密变量，我们可以直接在 playbook 中使用它作为变量：

```
- name: jenkins build job trigger
  hosts: localhost
  connection: local
  vars:
    jenkins_username: username
    jenkins_api_token: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          36636563313932313366313030623232623338333638363465343339636362353534363536366161
          3062666536613764396439326534663237653438616335640a613564643366623462666361633763
          31326161303666653366343931366265333238383937656435663061363665643431336638353436
          3532646434376533390a646332646639653161343165363832616233333232323130623034313032
          66643537336634633263346363313437666262323064386539616333646132353336
    jenkins_host: 192.168.11.111
    jenkins_target_url: 'http://demo.testfire.net'
    jenkins_token: ansible2security
>
  tasks:
    - name: trigger jenkins build
      uri:
        url: "http://{{ jenkins_username }}:{{ jenkins_api_token }}@{{ jenkins_host }}/job/ZAP-Jenkins/buildWithParameters?TARGET={{ jenkins_target_url }}&token={{ jenkins_token }}"
        method: GET
      register: results
    - debug:
        msg: "{{ results.stdout }}"
```

在执行 playbook 时执行 `ansible-vault` 解密，playbook 执行命令如下：

```
$ ansible-playbook --ask-vault-pass main.yml
```

# ZAP Docker 和 Jenkins

Mozilla 的一群人撰写了一篇关于如何配置 ZAP Docker 与 Jenkins 的出色博客系列。与其重复他们的内容，我们觉得把你指向该系列的第一篇文章更有意义。

欲了解更多信息，请查看有趣的博客 *Docker 化，OWASP-ZAP 安全扫描，在 Jenkins 中，第一部分*，链接在：[`blog.mozilla.org/webqa/2016/05/11/docker-owasp-zap-part-one/`](https://blog.mozilla.org/webqa/2016/05/11/docker-owasp-zap-part-one/)。

# 摘要

OWASP ZAP 是任何安全团队工具库中的绝佳选择。它在我们如何使用以及如何将其融入我们的设置中提供了完全的灵活性。通过将 ZAP 与 Jenkins 结合使用，我们可以快速建立一个体面的、适合生产的持续扫描工作流，并围绕它对我们的流程进行调整。Ansible 允许我们使用 playbooks 安装和配置所有这些优秀的工具。这很棒，因为这主要是一次性的努力，然后我们就可以开始看到 ZAP 的结果和报告。

现在我们正在自动化安全工具的过程中，接下来我们将看到最流行的漏洞评估工具 Nessus，以及我们如何为软件和网络的漏洞评估构建类似的工作流程。


# 第六章：使用 Nessus 进行漏洞扫描

漏洞扫描是安全团队在其计算机上进行的最为了解的定期活动之一。对于定期对计算机、网络、操作系统软件和应用软件进行漏洞扫描，都有充分记录的策略和最佳实践：

+   基本网络扫描

+   凭证补丁审核

+   将系统信息与已知漏洞相关联

对于网络系统，这种类型的扫描通常是从具有适当权限的连接主机执行的，以便扫描安全问题。

最流行的漏洞扫描工具之一是 Nessus。Nessus 最初是一个网络漏洞扫描工具，但现在还包括以下功能：

+   端口扫描

+   网络漏洞扫描

+   Web 应用程序特定扫描

+   基于主机的漏洞扫描

# Nessus 简介

Nessus 拥有的漏洞数据库是其主要优势。虽然我们知道了理解哪个服务正在运行以及正在运行该服务的软件版本的技术，但回答“此服务是否有已知漏洞”这个问题是重要的。除了定期更新的漏洞数据库外，Nessus 还具有有关应用程序中发现的默认凭据、默认路径和位置的信息。所有这些都在易于使用的 CLI 或基于 Web 的工具中进行了优化。

在深入研究我们将如何设置 Nessus 来执行对基础架构进行漏洞扫描和网络扫描之前，让我们看看为什么我们必须设置它以及它将给我们带来什么回报。

在本章中，我们将专注于使用 Nessus 进行漏洞扫描。我们将尝试执行所需的标准活动，并查看使用 Ansible 自动化这些活动需要哪些步骤：

1.  使用 playbook 安装 Nessus。

1.  配置 Nessus。

1.  运行扫描。

1.  使用 AutoNessus 运行扫描。

1.  安装 Nessus REST API Python 客户端。

1.  使用 API 下载报告。

# 为漏洞评估安装 Nessus

首先，获取从 [`www.tenable.com/products/nessus/select-your-operating-system`](https://www.tenable.com/products/nessus/select-your-operating-system) 下载 Nessus 的 URL，然后选择 Ubuntu 操作系统，然后对要设置 Nessus 的服务器运行以下 playbook 角色：

```
- name: installing nessus server
  hosts: nessus
  remote_user: "{{ remote_user_name }}"
  gather_facts: no
  vars:
    remote_user_name: ubuntu
    nessus_download_url: "http://downloads.nessus.org/nessus3dl.php?file=Nessus-6.11.2-ubuntu1110_amd64.deb&licence_accept=yes&t=84ed6ee87f926f3d17a218b2e52b61f0"

  tasks:
    - name: install python 2
      raw: test -e /usr/bin/python || (apt -y update && apt install -y python-minimal)

    - name: downloading the package and installing
      apt:
        deb: "{{ nessus_download_url }}"

    - name: start the nessus daemon
      service:
        name: "nessusd"
        enabled: yes
        state: started
```

# 配置 Nessus 进行漏洞扫描

执行以下步骤配置 Nessus 进行漏洞扫描：

1.  我们必须导航至 `https://NESSUSSERVERIP:8834` 以确认并启动服务：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/58f0611c-b54f-47c9-b416-201868d9f18d.png)

1.  如我们所见，它返回一个 SSL 错误，我们需要接受 SSL 错误并确认安全异常，并继续安装：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/9e9d232d-e5e2-48f8-8060-25eeefe4f598.png)

1.  单击确认安全异常并继续执行安装步骤：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/05f639e6-42e8-4e60-8814-bce45662c200.png)

1.  点击继续并提供用户详细信息，该用户具有完整的管理员访问权限：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/39159020-7ba3-45c3-8cbb-a0e3d9774fa9.png)

1.  最后，我们必须提供注册码（激活码），这可以从注册页面获取：[`www.tenable.com/products/nessus-home`](https://www.tenable.com/products/nessus-home)：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/1c521cde-a718-4cc2-86bb-f428947ceb38.png)

1.  现在，它将安装所需的插件。安装需要一段时间，一旦完成，我们就可以登录使用应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/950ca2ed-e42c-424e-8391-569a9769336c.png)

1.  现在，我们已成功设置了 Nessus 漏洞扫描器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/5c30874c-1cea-4cf6-bdbb-a7ee1a91710a.png)

# 对网络执行扫描

现在，是时候使用 Nessus 执行一些漏洞扫描了。

# 基本网络扫描

Nessus 有各种各样的扫描，其中一些是免费的，一些只在付费版本中才可用。因此，我们也可以根据需要定制扫描。

下面是当前可用模板的列表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/7c0480ef-e84c-4cc9-acd5-5b320d09c298.png)

1.  我们可以从基本网络扫描开始，以查看网络中发生了什么。此扫描将为给定的主机执行基本的全系统扫描：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/409b6465-6b43-4954-8b7c-1c3486b04318.png)

1.  正如您在前面的截图中所看到的，我们必须提到扫描名称和目标。目标只是我们想要的主机。

目标可以以不同格式给出，例如`192.168.33.1`表示单个主机，`192.168.33.1-10`表示主机范围，我们还可以从计算机上载入目标文件。

选择 New Scan / Basic Network Scan 以使用 Nessus 进行分析：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/9f4d07b9-7b4d-42f4-b7a1-1bb418bf6ba2.png)

1.  我们也可以定制扫描类型。例如，我们可以执行常用端口扫描，该扫描将扫描已知端口，如果需要，我们还可以执行完整端口扫描：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/cc73d7c7-efc2-416a-98e9-4e3a3a5d681a.png)

1.  然后，类似地，我们可以指定执行不同类型的 Web 应用程序扫描，如前所述：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/dd3d24d9-5e2c-4092-b5e2-42089281c460.png)

1.  报告也可以根据要求使用可用选项进行定制：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/6e06cc24-e150-4017-9425-5261b0d4bdf1.png)

1.  在扫描关键基础设施时，前述选项非常重要。这些选项旨在确保我们不会在目标网络中产生大量流量和网络带宽。Nessus 允许我们根据使用情况和需求进行定制：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/f7701c34-6ddb-4b4c-b14a-b782f56aa34e.png)

1.  前面的截图表示我们是否已经为任何服务拥有现有凭据，以及如果需要扫描，我们可以在此处提及它们。 Nessus 在扫描时将使用这些凭据进行身份验证，这样可以获得更好的结果。 Nessus 支持多种类型的身份验证服务！[](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/29a03e0e-e307-4f19-bea6-4171f3bd1250.png)

1.  如果需要，可以安排扫描，或者根据需要提供。 我们可以点击“启动”按钮（播放图标）以使用给定的配置参数开始扫描：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/e7c5a15d-2c0a-43dd-ac42-e17770097d3d.png)

1.  扫描结果可以通过基于主机、漏洞、严重程度等的仪表板进行查看：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/5551dcfc-62c8-4065-9bce-ecfab5adf708.png)

1.  上述截图显示了 Nessus 将如何生成现有漏洞的详细结果，包括样本**概念证明**（**POC**）或命令输出。 它还提供了修复、漏洞和参考的详细摘要。

# 使用 AutoNessus 运行扫描

使用 AutoNessus 脚本，我们可以执行以下操作：

+   列出扫描

+   列出扫描策略

+   对扫描执行操作，如启动、停止、暂停和恢复

AutoNessus 的最佳部分在于，由于这是一个命令行工具，因此可以轻松地成为定期任务和其他自动化工作流的一部分。

从[`github.com/redteamsecurity/AutoNessus`](https://github.com/redteamsecurity/AutoNessus)下载 AutoNessus。

# 设置 AutoNessus

以下代码是用于设置 AutoNessus 并配置其使用凭据的 Ansible playbook 片段。 此 playbook 将允许在路径中设置`autoNessus`工具，并且我们可以将其用作简单的系统工具：

```
- name: installing python-pip
  apt:
    name: python-pip
    update_cache: yes
    state: present

- name: install python requests
  pip:
    name: requests

- name: setting up autonessus
  get_url:
    url: "https://github.com/redteamsecurity/AutoNessus/raw/master/autoNessus.py"
    dest: /usr/bin/autoNessus
    mode: 0755

- name: updating the credentials
  replace:
    path: /usr/bin/autoNessus
    regexp: "{{ item.src }}"
    replace: "{{ item.dst }}"
    backup: yes
  no_log: True

  with_items:
    - { src: "token = ''", dst: "token = '{{ nessus_user_token }}'" }
    - { src: "url = 'https://localhost:8834'", dst: "url = '{{ nessus_url }}'" } 
    - { src: "username = 'xxxxx'", dst: "username = '{{ nessus_user_name }}'" }
    - { src: "password = 'xxxxx'", dst: "password = '{{ nessus_user_password }}'" }
```

`no_log: True`将在 Ansible 输出的日志控制台中对输出进行审查。 当我们在 playbooks 中使用密码和密钥时，这将非常有用。

# 使用 AutoNessus 运行扫描

以下的 playbook 代码片段可用于按需执行扫描以及定期执行的扫描。 这也可以在 Ansible Tower、Jenkins 或 Rundeck 中使用。

在使用 AutoNessus 进行自动化扫描之前，我们必须在 Nessus 门户中创建所需的自定义扫描，并且我们可以使用这些自动化 playbook 来执行任务。

# 列出当前可用的扫描和 ID

以下代码片段将返回当前可用的扫描并返回带有信息的 ID：

```
- name: list current scans and IDs using autoNessus
  command: "autoNessus -l"
  register: list_scans_output

- debug:
    msg: "{{ list_scans_output.stdout_lines }}"
```

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/338129f1-3b05-4a74-a585-7da56724ac9f.png)

Ansible 输出返回可用扫描和 ID 信息的列表

# 使用扫描 ID 启动指定的扫描

以下代码片段将基于`scan_id`启动指定的扫描并返回状态信息：

```
- name: starting nessus scan "{{ scan_id }}" using autoNessus
  command: "autoNessus -sS {{ scan_id }}"
  register: start_scan_output

- debug:
    msg: "{{ start_scan_output.stdout_lines }}"
```

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/b61ac39e-739b-412d-b327-f8b79a6386f0.png)

启动后，Ansible 输出返回扫描状态

同样，我们可以执行暂停、恢复、停止、列出策略等操作。 使用 AutoNessus 程序，这些 playbook 是可用的。 这可以通过改进 Nessus API 脚本来改进。

# 存储结果

我们还可以获取与漏洞相关的详细信息、解决方案和风险信息：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/464e437d-420b-4252-acfb-d12eb22e96b9.png)

整个报告可以导出为多种格式，如 HTML、CSV 和 Nessus。 这有助于提供更详细的漏洞结构，带有风险评级的解决方案以及其他参考资料：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/1394cf57-2ed3-46d2-9eb7-d56c14a12b9e.png)

根据受众可以定制输出报告，如果发送给技术团队，我们可以列出所有漏洞和补救措施。例如，如果管理层想要报告，我们可以只得到问题的执行摘要。

报告也可以通过 Nessus 配置中的通知选项通过电子邮件发送。

以下截图是最近基本网络扫描的导出 HTML 格式的详细报告。这可以用来分析和修复基于主机的漏洞：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/fcb0d48c-a86a-482b-9cbf-8faeefa42019.png)

我们可以看到之前按主机分类的漏洞。我们可以在以下截图中详细查看每个漏洞：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/bc0712be-d4ce-45ce-a0e1-4e5b095aa853.png)

# 安装 Nessus REST API Python 客户端

官方 API 文档可以通过连接到您的 Nessus 服务器下的 `8834/nessus6-api.html` 获取。

要使用 Nessus REST API 执行任何操作，我们必须从门户获取 API 密钥。这可以在用户设置中找到。请务必保存这些密钥：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/40071468-ac97-4b5f-9882-1c83c8be5799.png)

# 使用 Nessus REST API 下载报告

以下 playbook 将使用 Nessus REST API 执行对给定 `scan_id` 报告的导出请求。它将使用一个简单的 playbook 自动化整个过程。这将返回报告的 HTML 输出：

```
- name: working with nessus rest api
  connection: local
  hosts: localhost
  gather_facts: no
  vars:
    scan_id: 17
    nessus_access_key: 620fe4ffaed47e9fe429ed749207967ecd7a77471105d8
    nessus_secret_key: 295414e22dc9a56abc7a89dab713487bd397cf860751a2
    nessus_url: https://192.168.33.109:8834
    nessus_report_format: html

  tasks:
    - name: export the report for given scan "{{ scan_id }}"
      uri:
        url: "{{ nessus_url }}/scans/{{ scan_id }}/export"
        method: POST
        validate_certs: no
        headers:
            X-ApiKeys: "accessKey={{ nessus_access_key }}; secretKey={{ nessus_secret_key }}"
        body: "format={{ nessus_report_format }}&chapters=vuln_by_host;remediations"
      register: export_request

    - debug:
        msg: "File id is {{ export_request.json.file }} and scan id is {{ scan_id }}"

    - name: check the report status for "{{ export_request.json.file }}"
      uri:
        url: "{{ nessus_url }}/scans/{{ scan_id }}/export/{{ export_request.json.file }}/status"
        method: GET
        validate_certs: no
        headers:
            X-ApiKeys: "accessKey={{ nessus_access_key }}; secretKey={{ nessus_secret_key }}"
      register: report_status

    - debug:
        msg: "Report status is {{ report_status.json.status }}"

    - name: downloading the report locally
      uri:
        url: "{{ nessus_url }}/scans/{{ scan_id }}/export/{{ export_request.json.file }}/download"
        method: GET
        validate_certs: no
        headers:
          X-ApiKeys: "accessKey={{ nessus_access_key }}; secretKey={{ nessus_secret_key }}"
        return_content: yes
        dest: "./{{ scan_id }}_{{ export_request.json.file }}.{{ nessus_report_format }}"
      register: report_output

    - debug:
      msg: "Report can be found at ./{{ scan_id }}_{{ export_request.json.file }}.{{ nessus_report_format }}"
```

在 Nessus REST API  [`cloud.tenable.com/api#/overview`](https://cloud.tenable.com/api#/overview) 阅读更多。

使用 Nessus REST API 进行自动报告生成的 Ansible playbook：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/204f4904-7160-4058-89f6-8156a1173196.png)

使用 Nessus REST API 进行自动报告生成和导出的 Ansible playbook

# Nessus 配置

Nessus 允许我们创建具有基于角色的认证的不同用户来执行扫描和以不同访问级别审查：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/f4d85881-e0fa-4b97-bbc4-2b36ea92f5a5.png)

下图显示了如何创建一个具有执行 Nessus 活动权限的新用户的过程：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/4ede2d78-3967-4f06-b2c3-1720b479f9d3.png)

# 摘要

安全团队和 IT 团队依赖工具进行漏洞扫描、管理、补救和持续安全流程。由于 Nessus 是最流行和最有用的工具之一，它是作者尝试自动化的自动选择。

在本章中，我们看了漏洞扫描的主要活动，如能够安装和部署工具，启动扫描和下载报告。

在下一章中，我们将深入探讨系统安全和加固。我们将研究各种开放的安全倡议和基准项目，如 STIG、OpenSCAP 和**互联网安全中心**（**CIS**）。我们将学习如何将它们与我们的 playbooks 和自动化工具，如 Tower 和 Jenkins，集成起来。这一章关于漏洞扫描，以及下一章关于网络和应用程序安全加固，为探索更多关于安全自动化和保持系统安全和加固的思路奠定了坚实基础。


# 第七章：应用程序和网络的安全加固

安全加固是任何注重安全的努力中最明显的任务。通过保护系统、应用程序和网络，可以实现多个安全目标，如下所述：

+   确保应用程序和网络没有受到威胁（有时）

+   使威胁难以长期隐藏

+   默认情况下进行安全加固，确保网络的一部分遭受威胁时不会进一步传播和蔓延

Ansible 在围绕安全自动化方面的思考方式非常适合用于自动化安全加固。在本章中，我们将介绍可以用于构建 playbook 的安全基准和框架，这些 playbook 将允许我们做以下事情：

+   确保我们的主镜像安全，以便应用程序和系统一旦成为网络的一部分，它们就提供了合适的安全性

+   执行审计过程，以便我们可以周期性地验证和测量应用程序、系统和网络是否符合组织所需的安全策略

这绝不是一个新的想法。在这个领域已经进行了大量工作。我们将看一些项目，如 dev-sec.io ([`dev-sec.io/`](http://dev-sec.io/)), 它们使我们可以简单地开始对应用程序和网络进行安全加固。

本章将涵盖的主题如下：

+   使用 CIS、STIG 和 NIST 等基准进行安全加固

+   使用 Ansible 自动化进行网络设备的安全审计检查

+   使用 Ansible 自动化进行应用程序的安全审计检查

+   使用 Ansible 进行自动打补丁的方法

# 使用 CIS、STIG 和 NIST 等基准进行安全加固

基准为任何人提供了获得其个人安全努力保证的好方法。这些基准由全球安全专家创建，或由安全成熟的政府部门如 NIST 领导，涵盖了各种系统、配置、软件等。

安全加固主要归结为以下几点：

1.  达成一致，确定最小配置集合何时符合安全配置的定义。通常将其定义为加固基准或框架。

1.  对受到此类配置影响的系统的所有方面进行更改。

1.  定期测量应用程序和系统是否仍与配置一致，或是否存在任何偏差。

1.  如果发现任何偏差，立即采取纠正措施修复它。

1.  如果没有发现任何偏差，记录下来。

1.  由于软件始终在升级，跟踪最新的配置指南和基准非常重要。

我们讨论的三个重要的基准/框架是：

+   CIS 基准

+   STIG 指南

+   NIST 的**国家检查清单计划**(**NCP**)

这些 CIS 基准通常以 PDF 文档的形式表达，任何想了解他们的系统与 CIS 专家对其安全性的看法相比有多安全的人都可以获得。

CIS 是一个非营利性组织，为互联网安全制定了非营利性标准，并被认可为全球标准和最佳实践，用于保护 IT 系统和数据免受攻击。CIS 基准是唯一由政府、企业、行业和学术界开发并接受的基于共识的最佳实践安全配置指南。更多信息，请访问 [`www.cisecurity.org/cis-benchmarks`](https://www.cisecurity.org/cis-benchmarks)。

STIG 与美国政府部门**DISA**的信息系统配置相关。

STIGs 包含了技术指导，用于**锁定**可能易受恶意计算机攻击影响的信息系统/软件。更多信息，请访问 [`iase.disa.mil/stigs/Pages/index.aspx`](https://iase.disa.mil/stigs/Pages/index.aspx)。

NIST 维护一个以符合**安全内容自动化协议**（**SCAP**）的文件形式表达的检查表程序。软件工具可以读取这些文件以自动化配置更改和审计运行配置。

SCAP 使得验证过的安全工具可以使用 SCAP 表达的 NCP 检查表来自动执行配置检查。更多信息请访问 [`www.nist.gov/programs-projects/national-checklist-program`](https://www.nist.gov/programs-projects/national-checklist-program)。

# 使用 Ansible 剧本对基线进行操作系统加固

到目前为止，我们已经创建了多个剧本来执行某些操作。现在，我们将看到如何使用社区提供的现有剧本（**Ansible Galaxy**）。

Hardening Framework 是德国电信的一个项目，用于管理成千上万台服务器的安全性、合规性和维护。该项目的目标是创建一个通用的层，以便轻松地加固操作系统和服务。

如果你的组织使用 chef 或 puppet 工具作为配置管理工具，那么这些概念完全相同。你可以在 [`dev-sec.io`](http://dev-sec.io) 找到相关的菜谱和详细信息。

以下的剧本提供了多种安全配置、标准以及保护操作系统免受不同攻击和安全漏洞的方法。

它将执行的一些任务包括以下内容：

+   配置软件包管理，例如，只允许签名软件包

+   删除已知问题的软件包

+   配置 `pam` 和 `pam_limits` 模块

+   Shadow 密码套件配置

+   配置系统路径权限

+   通过软限制禁用核心转储

+   限制 root 登录到系统控制台

+   设置 SUIDs

+   通过 `sysctl` 配置内核参数

从 galaxy 下载和执行 Ansible 剧本就像下面这样简单：

```
$ ansible-galaxy install dev-sec.os-hardening
- hosts: localhost
  become: yes
  roles:
    - dev-sec.os-hardening

```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/5028b574-37de-4f45-aa1b-185c6ec6f696.png)

在执行中的 dev-sec.os-hardening 剧本

前面的 playbook 将检测操作系统，并根据不同的指南执行加固步骤。可以通过更新默认变量值来配置此内容。有关 playbook 的更多详细信息，请参阅 [`github.com/dev-sec/ansible-os-hardening`](https://github.com/dev-sec/ansible-os-hardening)。

# 用于 Linux 主机的自动化安全加固的 STIGs Ansible 角色

OpenStack 有一个名为 **ansible-hardening** 的令人敬畏的项目（[`github.com/openstack/ansible-hardening`](https://github.com/openstack/ansible-hardening)），它根据 STIGs 标准应用安全配置更改。有关 Unix/Linux 操作系统的 STIGs 基准的更多详细信息，请访问 [`iase.disa.mil/stigs/os/unix-linux/Pages/index.aspx`](https://iase.disa.mil/stigs/os/unix-linux/Pages/index.aspx)。

它为以下领域执行安全强化：

+   `accounts`: 用户帐户安全控制

+   `aide`: 高级入侵检测环境

+   `auditd`: 审计守护程序

+   `auth`: 认证

+   `file_perms`: 文件系统权限

+   `graphical`: 图形化登录安全控制

+   `kernel`: 内核参数

+   `lsm`: Linux 安全模块

+   `misc`: 杂项安全控制

+   `packages`: 软件包管理器

+   `sshd`: SSH 守护程序

`ansible-hardening` playbook 支持多个 Linux 操作系统

+   CentOS 7

+   Debian jessie

+   Fedora 26

+   openSUSE Leap 42.2 和 42.3

+   Red Hat Enterprise Linux 7

+   SUSE Linux Enterprise 12（实验性）

+   Ubuntu 16.04

有关项目和文档的更多详细信息，请参阅 [`docs.openstack.org/ansible-hardening/latest`](https://docs.openstack.org/ansible-hardening/latest)。

使用 `ansible-galaxy` 从 GitHub 存储库本身下载角色，如下所示：

```
$ ansible-galaxy install git+https://github.com/openstack/ansible-hardening

```

playbook 如下所示。与以前的 playbook 类似，可以通过更改默认变量值来配置它所需的内容：

```
- name: STIGs ansible-hardening for automated security hardening
  hosts: servers
  become: yes
  remote_user: "{{ remote_user_name }}"
  vars:
    remote_user_name: vagrant
    security_ntp_servers:
      - time.nist.gov
      - time.google.com

  roles:
    - ansible-hardening
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/4b142365-4106-401d-9773-a6f0b7908a38.png)

一个在 CentOS-7 上执行的 Ansible-hardening playbook 用于 STIGs checklist

前面的 playbook 在 CentOS-7 服务器上执行，用于执行 STIG checklist。

# 使用 Ansible Tower 进行 OpenSCAP 的持续安全扫描和报告

OpenSCAP 是一组安全工具、策略和标准，通过遵循 SCAP 对系统执行安全合规性检查。SCAP 是由 NIST 维护的美国标准。

SCAP 扫描器应用程序读取 SCAP 安全策略，并检查系统是否符合该策略。它逐个检查策略中定义的所有规则，并报告每个规则是否得到满足。如果所有检查都通过，则系统符合安全策略。

OpenSCAP 按照以下步骤对系统进行扫描：

+   安装 SCAP Workbench 或 OpenSCAP Base（有关更多信息，请访问 [`www.open-scap.org`](https://www.open-scap.org)）

+   选择一个策略

+   调整您的设置

+   评估系统

以下 playbook 将安装 `openscap-scanner` 和 `scap-security-guide` 软件来执行检查。然后，它将根据给定的配置文件和策略使用 `oscap` 工具执行扫描。

正如您所见，变量 `oscap_profile` 是从可用配置文件列表中选择配置文件，`oscap_policy` 是选择用于扫描系统的特定策略：

```
- hosts: all
  become: yes
  vars:
    oscap_profile: xccdf_org.ssgproject.content_profile_pci-dss
    oscap_policy: ssg-rhel7-ds

  tasks:
  - name: install openscap scanner
    package:
      name: "{{ item }}"
      state: latest
    with_items:
    - openscap-scanner
    - scap-security-guide

  - block:
    - name: run openscap
      command: >
        oscap xccdf eval
        --profile {{ oscap_profile }}
        --results-arf /tmp/oscap-arf.xml
        --report /tmp/oscap-report.html
        --fetch-remote-resources
        /usr/share/xml/scap/ssg/content/{{ oscap_policy }}.xml

    always:
    - name: download report
      fetch:
        src: /tmp/oscap-report.html
        dest: ./{{ inventory_hostname }}.html
        flat: yes
```

在[`medium.com/@jackprice/ansible-openscap-for-compliance-automation-14200fe70663`](https://medium.com/@jackprice/ansible-openscap-for-compliance-automation-14200fe70663)查看 playbooks 参考。

现在，我们可以使用此 playbook 使用 Ansible Tower 进行持续自动化检查：

1.  首先，我们需要在 Ansible Tower 服务器上创建一个目录，以便使用 `awx` 用户权限存储此 playbook 以添加自定义 playbook。

1.  在 Ansible Tower 中创建一个新项目，执行 OpenSCAP 设置并针对检查进行扫描：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/a162a353-3ae4-45be-8493-86a077e7512a.png)

1.  然后，我们必须创建一个新作业来执行此 playbook。在这里，我们可以包含主机列表、登录凭据和执行所需的其他详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/b1981d8b-aaf2-474f-8a52-4dc4ad876ea9.png)

1.  可以定期安排执行此审核。在这里，您可以看到我们每天都安排，这可以根据合规性频率进行修改（安全合规性要求经常执行这些类型的审核）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/b4f3cd4d-9e54-4460-b46c-92aa55eda502.png)

1.  我们也可以根据需要随时启动此作业。playbook 的执行如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/d292f00e-d1b8-459d-baa9-b2e57a7f4459.png)

1.  playbook 的输出将生成 OpenSCAP 报告，并将其获取到 Ansible Tower。我们可以在 `/tmp/` 位置访问此 playbook。此外，如果需要，我们还可以将此报告发送到其他集中式报告服务器。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/6eb62327-0390-411d-bfa3-9308485458b8.png)

1.  我们还可以根据 playbook 执行结果设置通知。通过这样做，我们可以将此通知发送到相应的渠道，如电子邮件、slack 和消息。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/228a2418-68c1-416e-875e-5960af935706.png)

# CIS 基准

CIS 为不同类型的操作系统、软件和服务制定了基准。以下是一些高级分类：

+   桌面和网络浏览器

+   移动设备

+   网络设备

+   安全指标

+   服务器 – 操作系统

+   服务器 – 其他

+   虚拟化平台、云和其他

了解有关 CIS 基准的更多信息，请访问[`www.cisecurity.org`](https://www.cisecurity.org)。

# Ubuntu CIS 基准（服务器级别）

CIS 基准 Ubuntu 提供了为运行在 x86 和 x64 平台上的 Ubuntu Linux 系统建立安全配置姿态的指导方针。此基准适用于系统和应用程序管理员、安全专家、审计员、帮助台和计划开发、部署、评估或保护包含 Linux 平台的解决方案的平台部署人员。

这是 CIS Ubuntu 16.04 LTS 基准的六个高级域的概述:

+   初始设置:

    +   文件系统配置

    +   配置软件更新

    +   文件系统完整性检查

    +   安全引导设置

    +   附加进程强化

    +   强制访问控制

    +   警告横幅

+   服务:

    +   Inted 服务

    +   专用服务

    +   服务客户端

+   网络配置:

    +   网络参数（仅主机）

    +   网络参数（主机和路由器）

    +   IPv6

    +   TCP 包装器

    +   不常见的网络协议

+   日志和审计:

    +   配置系统会计（`auditd`）

    +   配置日志记录

+   访问、身份验证和授权:

    +   配置 cron

    +   SSH 服务器配置

    +   配置 PAM

    +   用户帐户和环境

+   系统维护:

    +   系统文件权限

    +   用户和组设置

这是分别用于 14.04 LTS 和 16.04 LTS 的 Ansible Playbooks:

+   [`github.com/oguya/cis-ubuntu-14-ansible`](https://github.com/oguya/cis-ubuntu-14-ansible)

+   [`github.com/grupoversia/cis-ubuntu-ansible`](https://github.com/grupoversia/cis-ubuntu-ansible)

```
$ git clone https://github.com/oguya/cis-ubuntu-14-ansible.git
$ cd cis-ubuntu-14-ansible
```

然后，更新变量和清单，并使用以下命令执行 playbook。除非我们想要根据组织自定义基准，否则大多数情况下不需要变量：

```
$ ansible-playbook -i inventory cis.yml
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/6cb09ea9-82e5-4608-adf9-a14ca11464ff.png)

CIS Ubuntu 基准 Ansible playbook 执行

前述 playbook 将针对 Ubuntu 服务器执行 CIS 安全基准，并执行 CIS 指南中列出的所有检查。

# AWS 基准（云提供商级别）

AWS CIS 基准提供了针对 AWS 子集的安全选项配置的指导方针，重点是基础、可测试和与架构无关的设置。适用于计划在 AWS 中开发、部署、评估或保护解决方案的系统和应用程序管理员、安全专家、审计员、帮助台、平台部署和/或 DevOps 人员。

这是 AWS CIS 基准的高级域:

+   身份和访问管理

+   日志记录

+   监控

+   网络

+   额外

目前，有一个名为**prowler**的工具（[`github.com/Alfresco/prowler`](https://github.com/Alfresco/prowler)），它基于 AWS-CLI 命令用于 AWS 帐户安全评估和加固。

这些工具遵循 CIS Amazon Web Services Foundations Benchmark 1.1 的准则

在运行 playbook 之前，我们必须提供 AWS API 密钥以执行安全审核。这可以使用 AWS 服务中的 IAM 角色创建。如果您已经有一个具有所需权限的现有帐户，则可以跳过这些步骤：

1.  在您的 AWS 帐户中创建一个具有编程访问权限的新用户:

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/165b0bb6-95ec-4c62-a86f-3bcbcd519697.png)

1.  为用户从 IAM 控制台中的现有策略应用 SecurityAudit 策略：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/134883fc-1d97-411a-a9ce-1e3d297d8daa.png)

1.  然后，按照步骤创建新用户。确保安全保存访问密钥 ID 和秘密访问密钥以供以后使用：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/da2e9f77-aac7-4a7e-b128-ea5bfa1ce836.png)

1.  这是使用 prowler 工具设置和执行检查的简单 playbook。从前面的步骤提供访问密钥和秘密密钥。

1.  以下 playbook 假定您已经在本地系统中安装了`python`和`pip`：

```
        - name: AWS CIS Benchmarks playbook
          hosts: localhost
          become: yes
          vars:
            aws_access_key: XXXXXXXX
            aws_secret_key: XXXXXXXX

          tasks:
            - name: installing aws cli and ansi2html
              pip:
                name: "{{ item }}"

            with_items:
              - awscli
              - ansi2html

            - name: downloading and setting up prowler
              get_url:
                url:         https://raw.githubusercontent.com/Alfresco/prowler/master
        /prowler
                dest: /usr/bin/prowler
                mode: 0755

            - name: running prowler full scan
              shell: "prowler | ansi2html -la > ./aws-cis-report-{{         ansible_date_time.epoch }}.html"
              environment:
                AWS_ACCESS_KEY_ID: "{{ aws_access_key }}"
                AWS_SECRET_ACCESS_KEY: "{{ aws_secret_key }}"

            - name: AWS CIS Benchmarks report downloaded
              debug:
                msg: "Report can be found at ./aws-cis-report-{{         ansible_date_time.epoch }}.html"
```

1.  该 playbook 将使用 prowler 工具触发 AWS CIS 基准的设置和安全审计扫描：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/a5f1b4b6-efcd-4012-a609-d68756119a38.png)

1.  Prowler 生成的 HTML 报告如下，报告可以按需下载为不同格式，并且扫描检查可以根据需要配置：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/bf620722-2f7a-4d3f-9603-d319ffcd9e80.png)

有关该工具的更多参考资料可以在[`github.com/Alfresco/prowler`](https://github.com/Alfresco/prowler)找到。

# Lynis - 用于 Unix/Linux 系统的开源安全审计工具

Lynis 是一个开源安全审计工具。被系统管理员、安全专业人员和审计员使用，评估他们的 Linux 和基于 Unix 的系统的安全防御。它在主机上运行，因此执行的安全扫描比漏洞扫描器更加广泛。

支持的操作系统：Lynis 几乎可以在所有基于 Unix 的系统和版本上运行，包括以下系统：

+   AIX

+   FreeBSD

+   HP-UX

+   Linux

+   macOS

+   NetBSD

+   OpenBSD

+   Solaris 和其他系统

如[`cisofy.com/lynis`](https://cisofy.com/lynis)所述：

"甚至可以在像树莓派或 QNAP 存储设备等系统上运行。"

该 playbook 如下所示：

```
- name: Lynis security audit playbook
  hosts: lynis
  remote_user: ubuntu
  become: yes
  vars:
    # refer to https://packages.cisofy.com/community
    code_name: xenial

  tasks:
    - name: adding lynis repo key
      apt_key:
        keyserver: keyserver.ubuntu.com
        id: C80E383C3DE9F082E01391A0366C67DE91CA5D5F
        state: present

    - name: installing apt-transport-https
      apt:
        name: apt-transport-https
        state: present

    - name: adding repo
      apt_repository:
        repo: "deb https://packages.cisofy.com/community/lynis/deb/ {{ code_name }} main"
        state: present
        filename: "cisofy-lynis"

    - name: installing lynis
      apt:
        name: lynis
        update_cache: yes
        state: present

    - name: audit scan the system
      shell: lynis audit system > /tmp/lynis-output.log

    - name: downloading report locally
      fetch:
        src: /tmp/lynis-output.log
        dest: ./{{ inventory_hostname }}-lynis-report-{{ ansible_date_time.date }}.log
        flat: yes

    - name: report location
      debug:
        msg: "Report can be found at ./{{ inventory_hostname }}-lynis-report-{{ ansible_date_time.date }}.log"
```

上述 playbook 将设置 Lynis，对其进行系统审计扫描，最后在本地获取报告：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/7f105908-dfa3-4d2b-866d-5612f4925dfc.png)

Lynis 系统审计扫描 playbook 正在执行

以下屏幕截图是最近审计扫描的报告：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/bc364635-9f04-4a74-8824-647fa167ce9a.png)

Lynis 系统审计扫描报告

可以通过 Ansible Tower 和其他自动化工具运行此项，以执行使用 Lynis 进行审计扫描的系统的周期性检查。

# Lynis 命令和高级选项

Lynis 具有多个选项和命令，可用于执行不同的选项。例如，我们可以使用`audit dockerfile <filename>`来执行 Dockerfiles 的分析，使用`--pentest`选项来执行与渗透测试相关的扫描。

>![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/38be2079-174e-47e5-bdc7-690e696d6cda.png)

# 使用 Ansible playbooks 进行 Windows 服务器审计

大多数企业使用 Windows 通过 Active Directory 类型的功能集中管理其政策和更新，这也是保护组织并检查安全问题的非常关键的资产。我们知道 Ansible 支持使用 WinRM 执行配置更改的 Windows 操作系统。让我们看一些示例，通过 Ansible playbooks 为您的 Windows 服务器添加安全性。

# Windows 安全更新 playbook

下面的 playbook 是从 Ansible 文档中简单引用的参考，网址为 [`docs.ansible.com/ansible/devel/windows_usage.html#installing-updates`](https://docs.ansible.com/ansible/devel/windows_usage.html#installing-updates)：

```
- name: Windows Security Updates
  hosts: winblows

  tasks:
    - name: install all critical and security updates
      win_updates:
        category_names:
        - CriticalUpdates
        - SecurityUpdates
        state: installed
      register: update_result

    - name: reboot host if required
      win_reboot:
      when: update_result.reboot_required
```

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/c1555722-c3c5-4ce8-bc9f-0fd24ae1a05b.png)

Windows 更新 playbook 正在运行

前面的 playbook 将自动执行临界严重性的 Windows 安全更新，并在需要时重新启动计算机以应用更新后的更改。

# Windows 工作站和服务器审计

下面的 Ansible playbook 是基于 [`github.com/alanrenouf/Windows-Workstation-and-Server-Audit,`](https://github.com/alanrenouf/Windows-Workstation-and-Server-Audit) 创建的，它将对系统进行审计并生成详细的 HTML 报告。这是一个我们可以使用 PowerShell 脚本执行审计的示例。可以通过添加更多检查和其他安全审计脚本来扩展此功能。

Playbook 如下所示：

```
- name: Windows Audit Playbook
  hosts: winblows

  tasks:
    - name: download audit script
      win_get_url:
        url: https://raw.githubusercontent.com/alanrenouf/Windows-Workstation-and-Server-Audit/master/Audit.ps1
        dest: C:\Audit.ps1

    - name: running windows audit script
      win_shell: C:\Audit.ps1
      args:
        chdir: C:\
```

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/dbf33878-3877-4c36-91b8-6594fb70458e.png)

Windows 审计 playbook 正在运

一旦 playbook 执行完成，我们可以在 HTML 格式的输出报告中看到有关运行服务、安全补丁、事件、日志记录和其他配置详细信息。

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/653549cd-8640-415f-9a18-9408661e37bf.png)

# 使用 Ansible 自动化进行网络设备的安全审计检查

我们已经看到 Ansible 很适合与各种工具一起使用，我们可以利用它来进行网络设备的安全审计检查。

# Nmap 扫描和 NSE

**网络映射器**（**Nmap**）是一个免费的开源软件，用于进行网络发现、扫描、审计等。它具有各种功能，如操作系统检测、系统指纹识别、防火墙检测等。**Nmap 脚本引擎**（**Nmap NSE**）提供了高级功能，如扫描特定的漏洞和攻击。我们还可以编写和扩展自己的自定义脚本来使用 Nmap。Nmap 是渗透测试人员（安全测试人员）和网络安全团队的瑞士军刀。

在 [`nmap.org`](https://nmap.org) 上了解更多关于 Nmap 的信息。Ansible 还有一个模块可以使用 Nmap 执行清单 [`github.com/ansible/ansible/pull/32857/files`](https://github.com/ansible/ansible/pull/32857/files)。

下面的 playbook 将在必要时安装 Nmap 并使用指定的标志执行基本网络端口扫描：

```
- name: Basic NMAP Scan Playbook
  hosts: localhost
  gather_facts: false
  vars:
    top_ports: 1000
    network_hosts:
      - 192.168.1.1
      - scanme.nmap.org
      - 127.0.0.1
      - 192.168.11.0/24

  tasks:
    - name: check if nmap installed and install
      apt:
        name: nmap
        update_cache: yes
        state: present
      become: yes

    - name: top ports scan
      shell: "nmap --top-ports {{ top_ports }} -Pn -oA nmap-scan-%Y-%m-%d {{ network_hosts|join(' ') }}"
```

+   `{{ network_hosts|join(' ') }}` 是一个名为 **filter arguments** 的 Jinja2 功能，用于通过空格分隔解析给定的 `network_hosts`

+   `network_hosts` 变量保存要使用 Nmap 扫描的 IP 列表、网络范围（CIDR）、主机等。

+   `top_ports` 是一个范围从 `0` 到 `65535` 的数字。Nmap 默认选择常见的顶级端口

+   `-Pn` 指定如果 ping（ICMP）不起作用，则扫描主机

+   `-oA` 将输出格式设置为所有格式，其中包括 gnmap（可 greppable 格式）、Nmap 和 XML

+   更多关于 nmap 的选项和文档信息可以在[`nmap.org/book/man.html`](https://nmap.org/book/man.html)找到。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/4df18006-8ab5-47eb-88a0-a1cc62216722.png)

Nmap 基本端口扫描 playbook 执行

运行基本 Nmap 扫描的 playbook 的输出为：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/989d0d43-98ad-47c5-ae25-b416d93178d2.png)

图：playbook 以三种不同的格式进行扫描输出

执行 playbook 后，生成了 Nmap 支持的三种格式的报告：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/df624100-27d6-491f-b672-156233fac84e.png)

图：nmap 格式的 playbook 扫描输出

通过查看`.nmap`文件的输出，我们可以轻松地看到 Nmap 扫描发现了什么。

# Nmap NSE 扫描 playbook

以下 playbook 将使用 Nmap 脚本执行对常用 Web 应用和服务器使用的目录进行枚举，并使用 Nmap 脚本查找 HTTP 服务器支持的选项。

更多关于 Nmap NSE 的信息可以在[`nmap.org/book/nse.html`](https://nmap.org/book/nse.html)找到。

以下的 playbook 将对`scanme.nmap.org`的端口`80`和`443`进行`http-enum`和`http-methods`扫描：

```
- name: Advanced NMAP Scan using NSE
  hosts: localhost
  vars:
    ports:
      - 80
      - 443
    scan_host: scanme.nmap.org 

  tasks:
    - name: Running Nmap NSE scan
      shell: "nmap -Pn -p {{ ports|join(',') }} --script {{ item }} -oA nmap-{{ item }}-results-%Y-%m-%d {{ scan_host }}"

      with_items:
        - http-methods
        - http-enum
```

以下的 playbook 将使用 Ansible playbook 执行 Nmap NSE 脚本进行 HTTP 枚举和方法检查：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/67c6aaed-144e-4da1-8d9e-375f137206e8.png)

执行 Nmap NSE playbook

运行简单的 NSE 脚本时，playbook 的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/5c7335fd-6631-409d-b556-4b70fd465b0c.png)

Nmap NSE 扫描的.nmap 格式输出

`http-enum`脚本在检测到网络端口上有 Web 服务器时会运行额外的测试。在前面的截图中，我们可以看到脚本发现了两个文件夹，并且还枚举了所有支持的 HTTP 方法。

# 使用 Scout2 进行 AWS 安全审计

Scout2 是一款开源的 AWS 安全审计工具，它使用 AWS Python API 来评估 AWS 环境的安全状况。扫描输出将以 JSON 格式存储，并且 Scout2 的最终结果将以简单的 HTML 网站的形式呈现，其中包含了关于 AWS 云安全状况的详细信息。它根据现有的规则集和测试用例执行扫描和审核，并且可以根据我们的自定义脚本和场景进行扩展。

更多关于该工具的详细信息可以在[`github.com/nccgroup/Scout2`](https://github.com/nccgroup/Scout2)找到。此工具需要 AWS IAM 凭证来执行扫描；请参考[`github.com/nccgroup/AWS-recipes/blob/master/IAM-Policies/Scout2-Default.json`](https://github.com/nccgroup/AWS-recipes/blob/master/IAM-Policies/Scout2-Default.json)以创建用户策略。

使用以下 playbook 安装 AWS Scout2 非常简单：

```
- name: AWS Security Audit using Scout2
  hosts: localhost
  become: yes

  tasks:
    - name: installing python and pip
      apt:
        name: "{{ item }}"
        state: present
        update_cache: yes

      with_items:
        - python
        - python-pip

    - name: install aws scout2
      pip:
        name: awsscout2
```

配置了多个规则来进行审核，以下代码片段是 IAM 密码策略规则的示例：

```
# https://raw.githubusercontent.com/nccgroup/Scout2/master/tests/data/rule-configs/iam-password-policy.json
{
    "aws_account_id": "123456789012",
    "services": {
        "iam": {
            "password_policy": {
                "ExpirePasswords": false,
                "MinimumPasswordLength": "1",
                "PasswordReusePrevention": false,
                "RequireLowercaseCharacters": false,
                "RequireNumbers": false,
                "RequireSymbols": false,
                "RequireUppercaseCharacters": false
            }
        }
    }
}
```

以下的 playbook 会执行 AWS Scout2 扫描，并以 HTML 格式返回报告：

```
- name: AWS Security Audit using Scout2
  hosts: localhost
  vars:
    aws_access_key: XXXXXXXX
    aws_secret_key: XXXXXXXX

  tasks:
    - name: running scout2 scan
      # If you are performing from less memory system add --thread-config 1 to below command
      command: "Scout2"
      environment:
        AWS_ACCESS_KEY_ID: "{{ aws_access_key }}"
        AWS_SECRET_ACCESS_KEY: "{{ aws_secret_key }}"

    - name: AWS Scout2 report downloaded
      debug:
        msg: "Report can be found at ./report.html"
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/60a83305-4ff1-438f-822a-74f940a6fb42.png)

AWS Scout2 报告高级概览

上述屏幕截图是高级报告，详细报告如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/53cb544d-e62c-451b-a7fc-f18b511df56f.png)

AWS Scout2 报告 IAM 部分的详细结果

# 使用 Ansible 对应用程序进行自动化安全审计检查

现代应用程序很快就会变得非常复杂。拥有运行自动化执行安全任务的能力几乎是一个强制性要求。

我们可以进行的不同类型的应用程序安全扫描包括以下内容：

1.  对源代码运行 CI/CD 扫描（例如，RIPS 和 brakeman）。

1.  依赖项检查扫描器（例如，OWASP 依赖项检查器和 snyk.io ([`snyk.io/`](https://snyk.io/))）。

1.  一旦部署，然后运行 Web 应用程序扫描器（例如，Nikto、Arachni 和 w3af）。

1.  针对特定框架的安全扫描器（例如，WPScan 和 Droopscan）以及许多其他。

# 源代码分析扫描器

这是在应用程序即将投入生产时最早和常见的减少安全风险的方式之一。源代码分析扫描器，也称为**静态应用程序安全测试**（**SAST**），将通过分析应用程序的源代码来帮助发现安全问题。这种工具和测试方法允许开发人员在**持续集成/持续交付**（**CI/CD**）的过程中反复自动地扫描其代码以查找安全漏洞。

我们可以引入这些工具的多个阶段来有效地识别安全漏洞，比如与 IDE 集成（诸如 Eclipse、Visual Studio Code 等代码编辑器）以及与 CI/CD 过程工具集成（Jenkins、Travis CI 等）。

源代码分析是一种白盒测试，它查看代码。这种测试方法可能无法发现 100% 的安全漏洞覆盖率，而且还需要手动测试。例如，要找到逻辑漏洞，需要某种用户交互，如动态功能。

在市场上有许多开源和商业工具可用于执行静态代码分析。此外，一些工具是针对您使用的技术和框架的。例如，如果您正在扫描 PHP 代码，则使用 RIPS ([`rips-scanner.sourceforge.net/`](http://rips-scanner.sourceforge.net/))；如果是 Ruby on Rails 代码，则使用 Brakeman ([`brakemanscanner.org/`](https://brakemanscanner.org/))；如果是 Python，则使用 Bandit ([`wiki.openstack.org/wiki/Security/Projects/Bandit`](https://wiki.openstack.org/wiki/Security/Projects/Bandit))；依此类推。

更多参考，请访问 [`www.owasp.org/index.php/Source_Code_Analysis_Tools`](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)。

# Brakeman 扫描器 - Rails 安全扫描器

Brakeman 是一个开源工具，用于对 Ruby on Rails 应用程序进行静态安全分析。 这可以应用于开发和部署流程的任何阶段，包括分期、QA、生产等。

用于执行 Brakeman 对我们应用程序的简单 playbook 如下：

```
- name: Brakeman Scanning Playbook
  hosts: scanner
  remote_user: ubuntu
  become: yes
  gather_facts: false
  vars:
    repo_url: https://github.com/OWASP/railsgoat.git
    output_dir: /tmp/railsgoat/
    report_name: report.html

  tasks:
    - name: installing ruby and git
      apt:
        name: "{{ item }}"
        update_cache: yes
        state: present

      with_items:
        - ruby-full
        - git

    - name: installing brakeman gem
      gem:
        name: brakeman
        state: present

    - name: cloning the {{ repo_url }}
      git:
        repo: "{{ repo_url }}"
        dest: "{{ output_dir }}"

    - name: Brakeman scanning in action
      # Output available in text, html, tabs, json, markdown and csv formats
      command: "brakeman -p {{ output_dir }} -o {{ output_dir }}report.html"
      # Error handling for brakeman output
      failed_when: result.rc != 3
      register: result

    - name: Downloading the report
      fetch:
        src: "{{ output_dir }}/report.html"
        dest: "{{ report_name }}"
        flat: yes

    - debug:
        msg: "Report can be found at {{ report_name }}"
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/2865649a-ab00-4757-910c-a2e05334a084.png)

Brakeman Playbook 在 Rails goat 项目中的操作

Brakeman 报告的概述是：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/003978d9-edb3-4a74-aa8a-f5bedb3839c9.png)

Brakeman 报告的高级概述

这是 Brakeman 报告的详细情况：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/dced611e-8391-495e-be04-8d2da8b55735.png)

这是一个包含代码和问题级别的详细报告。

有关 Brakeman 工具和选项的参考信息可在 [`brakemanscanner.org`](https://brakemanscanner.org) 找到。

# 依赖检查扫描器

大多数开发人员在开发应用程序时使用第三方库，使用开源插件和模块在其代码中非常常见。 许多开源项目可能容易受到已知攻击的影响，如跨站脚本和 SQL 注入。 如果开发人员不知道所使用库中存在的漏洞，那么他们的整个应用程序就会因为使用了糟糕的库而变得容易受到攻击。

因此，依赖性检查将允许我们通过扫描库来查找应用程序代码中存在的已知漏洞（OWASP A9）问题，并与 CVE 和 NIST 漏洞数据库进行比较。

市场上有多个项目可用于执行这些检查，其中一些包括以下内容：

+   OWASP Dependency-Check

+   Snyk.io ([`snyk.io/`](https://snyk.io/))

+   Retire.js

+   [:] SourceClear 以及许多其他

# OWASP Dependency-Check

OWASP Dependency-Check 是一个开源工具，主要用于检查 Java 和 .NET 应用程序中已知的漏洞。 它还支持其他平台，如 Node.js 和 Python 作为实验分析器。 这也可能产生误报，并可以根据需要进行配置以调整扫描。

这个工具也可以以多种方式运行，比如 CLI、构建工具（Ant、Gradle、Maven 等）和 CI/CD（Jenkins）流程。

有关项目的更多详细信息，请访问 [`www.owasp.org/index.php/OWASP_Dependency_Check`](https://www.owasp.org/index.php/OWASP_Dependency_Check)。

以下代码片段用于在易受攻击的 Java 项目上设置和使用 OWASP Dependency-Check 工具进行扫描：

```
- name: OWASP Dependency Check Playbook
  hosts: scanner
  remote_user: ubuntu
  become: yes
  vars:
    repo_url: https://github.com/psiinon/bodgeit.git
    output_dir: /tmp/bodgeit/
    project_name: bodgeit
    report_name: report.html

  tasks:
    - name: installing pre requisuites
      apt:
        name: "{{ item }}"
        state: present
        update_cache: yes

      with_items:
        - git
        - unzip
        - mono-runtime
        - mono-devel
        - default-jre

    - name: downloading owasp dependency-check
      unarchive:
        src: http://dl.bintray.com/jeremy-long/owasp/dependency-check-3.0.2-release.zip
        dest: /usr/share/
        remote_src: yes

    - name: adding symlink to the system
      file:
        src: /usr/share/dependency-check/bin/dependency-check.sh
        dest: /usr/bin/dependency-check
        mode: 0755
        state: link

    - name: cloning the {{ repo_url }}
      git:
        repo: "{{ repo_url }}"
        dest: "{{ output_dir }}"

    - name: updating CVE database
      command: "dependency-check --updateonly"

    - name: OWASP dependency-check scanning in action
      # Output available in XML, HTML, CSV, JSON, VULN, ALL formats
      command: "dependency-check --project {{ project_name }} --scan {{ output_dir }} -o {{ output_dir }}{{ project_name }}-report.html"

    - name: Downloading the report
      fetch:
        src: "{{ output_dir }}{{ project_name }}-report.html"
        dest: "{{ report_name }}"
        flat: yes

    - debug:
        msg: "Report can be found at {{ report_name }}" 
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/e4476850-3332-45ce-9ee3-3c272a573afa.png)

使用 Ansible playbook 对 Bodgeit 项目执行 OWASP Dependency-Check 扫描

高级 OWASP Dependency-Check 报告：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/26012f79-ee08-4889-a214-e1fb44da9902.png)

OWASP Dependency-Check 工具的高级报告

这是一个包含漏洞、修复措施和参考资料的详细报告：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/f31ce711-3c95-44a5-bb3c-2c0d5686a704.png)

包含漏洞、修复措施和参考资料的详细报告

高级报告格式如下：

+   **依赖项**：扫描的依赖项的文件名

+   **CPE**：发现的任何通用平台枚举标识符

+   **GAV**: Maven 组、Artifact 和版本（GAV）

+   **最高严重性**：任何相关 CVE 的最高严重性

+   **CVE 数量**：相关 CVE 的数量

+   **CPE 确信度**：Dependency-check 确定已正确识别 CPE 的可信度排名

+   **证据数量**：从用于识别 CPE 的依赖项中提取的数据量

可以在[`jeremylong.github.io/DependencyCheck`](https://jeremylong.github.io/DependencyCheck)找到更详细的文档。

# 运行 Web 应用程序安全扫描器

这是应用程序上线到 QA、阶段（或）生产环境的阶段。然后，我们希望像攻击者一样执行安全扫描（黑盒视图）。在此阶段，应用程序将应用所有动态功能和服务器配置。

这些扫描器的结果告诉我们服务器配置得有多好以及在将复制品发布到生产环境之前是否存在任何其他应用程序安全问题。

在这个阶段，大多数扫描器只能在某个特定水平上工作。我们需要通过人脑进行一些手动测试，以发现逻辑漏洞和其他安全漏洞，这些漏洞无法被安全扫描器和工具检测到。

正如我们在其他部分中所看到的，市场上有许多工具可以代替您执行这些工作，无论是开源还是商业。其中一些包括以下内容：

+   Nikto

+   Arachni

+   w3af

+   Acunetix 和许多其他工具

# Nikto - web 服务器扫描器

Nikto 是一个用 Perl 编写的开源 Web 服务器评估工具，用于执行安全配置检查和 Web 服务器和应用程序扫描，使用其要扫描的条目清单。

Nikto 进行的一些检查包括以下内容：

+   服务器和软件配置错误

+   默认文件和程序

+   不安全的文件和程序

+   过时的服务器和程序

Nikto 设置和执行 Ansible playbook 如下所示：

```
- name: Nikto Playbook
  hosts: scanner
  remote_user: ubuntu
  become: yes
  vars:
    domain_name: idontexistdomainnamewebsite.com # Add the domain to scan
    report_name: report.html

  tasks:
    - name: installing pre requisuites
      apt:
        name: "{{ item }}"
        state: present
        update_cache: yes

      with_items:
        - git
        - perl
        - libnet-ssleay-perl
        - openssl
        - libauthen-pam-perl
        - libio-pty-perl
        - libmd-dev

    - name: downloading nikto
      git:
        repo: https://github.com/sullo/nikto.git
        dest: /usr/share/nikto/

    - name: Nikto scanning in action
      # Output available in csv, html, msf+, nbe, txt, xml formats
      command: "/usr/share/nikto/program/nikto.pl -h {{ domain_name }} -o /tmp/{{ domain_name }}-report.html"

    - name: downloading the report
      fetch:
        src: "/tmp/{{ domain_name }}-report.html"
        dest: "{{ report_name }}"
        flat: yes

    - debug:
        msg: "Report can be found at {{ report_name }}"
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/d482f296-8b37-4235-9a8a-36009a47f6ed.png)

Nikto Playbook 实例

用于下载、安装和运行带有报告输出的 Nikto 的 Playbook 如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/621f521f-71d4-4152-accf-fd3095f16a92.png)

Nikto HTML 扫描报告

了解更多关于 Nikto 选项和文档的信息：[`cirt.net/Nikto2.`](https://cirt.net/Nikto2)

# 特定框架的安全扫描器

这种类型的检查和扫描是针对特定的框架、CMS 和平台进行的。它允许通过对多个安全测试案例和检查进行验证来获得更详细的结果。同样，在开源和商业世界中有多种工具和扫描器可用。

一些示例包括以下内容：

+   使用 WPScan 对 WordPress CMS 进行扫描：[`github.com/wpscanteam/wpscan`](https://github.com/wpscanteam/wpscan)

+   使用 Retire.js 对 JavaScript 库进行扫描：[`retirejs.github.io/retire.js`](https://retirejs.github.io/retire.js)

+   使用 Droopescan 扫描针对 Drupal CMS - [`github.com/droope/droopescan`](https://github.com/droope/droopescan) 和其他许多工具

# WordPress 漏洞扫描器 – WPScan

WPScan 是一个用 Ruby 编写的黑盒 WordPress 漏洞扫描器，用于针对 WordPress CMS 使用 WPScan 漏洞数据库 ([`wpvulndb.com`](https://wpvulndb.com)) 进行安全扫描和漏洞检查。

它执行的一些检查包括但不限于以下内容：

+   WordPress 核心

+   WordPress 插件和主题

+   已知的旧软件漏洞

+   用户名，附件枚举

+   暴力破解攻击

+   安全配置错误等等

以下 Playbook 将根据给定的域执行 WPScan，并生成带有问题列表和参考信息的扫描报告。

根据需要更新 Playbook 中的`domain_name`和`output_dir`值。此外，以下 Playbook 假定您已在系统中安装了 Docker：

```
- name: WPScan Playbook
  hosts: localhost
  vars:
    domain_name: www.idontexistdomainnamewebsite.com # Specify the domain to scan
    wpscan_container: wpscanteam/wpscan
    scan_name: wpscan
    output_dir: /tmp # Specify the output directory to store results

  tasks:
    # This playbook assumes docker already installed
    - name: Downloading {{ wpscan_container }} docker container
      docker_image:
        name: "{{ wpscan_container }}"

    - name: creating output report file
      file:
        path: "{{output_dir }}/{{ domain_name }}.txt"
        state: touch

    - name: Scanning {{ domain_name }} website using WPScan
      docker_container:
        name: "{{ scan_name }}"
        image: "{{ wpscan_container }}"
        interactive: yes
        auto_remove: yes
        state: started
        volumes: "/tmp/{{ domain_name }}.txt:/wpscan/data/output.txt"
        command: ["--update", "--follow-redirection", "--url", "{{ domain_name }}", "--log", "/wpscan/data/output.txt"]

    - name: WPScan report downloaded
      debug:
        msg: "The report can be found at /tmp/{{ domain_name }}.txt"
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/3207c05c-05d2-4aac-bc3b-19c3f926a006.png)

WPScan Ansible playbook 执行

下载、执行和存储 WPScan 扫描结果的 Playbook 输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/dc1ae916-dded-4e76-8f3a-6396427b5ccf.png)

带有问题详情和参考信息的 WPScan 输出报告

这些扫描可以集成到我们的 CI/CD 管道中，并在部署完成后执行以验证安全检查和配置检查。此外，根据需要可以根据 WPScan 定制此扫描；有关更多参考，请参阅 WPScan 文档 [`github.com/wpscanteam/wpscan`](https://github.com/wpscanteam/wpscan)。

# 使用 Ansible 的自动修补方法

补丁和更新是每个必须管理生产系统的人都必须处理的任务。我们将看到的两种方法如下：

+   滚动更新

+   蓝绿部署

# 滚动更新

想象一下我们在负载均衡器后面有五台 web 服务器。我们想要做的是对我们的 Web 应用进行零停机升级。使用 Ansible 中提供的某些关键字，我们可以实现这一点。

在我们的示例中，我们希望实现以下目标：

+   告诉负载均衡器 web 服务器节点已经宕机

+   将该节点上的 web 服务器关闭

+   将更新后的应用程序文件复制到该节点

+   在该节点上启动 web 服务器

我们首先要查看的关键字是`serial`。让我们从 Ansible 文档中看一个例子：

```
- name: test play
  hosts: webservers
  serial: 1
```

该示例来自 [`docs.ansible.com/ansible/latest/playbooks_delegation.html#rolling-update-batch-size`](http://docs.ansible.com/ansible/latest/playbooks_delegation.html#rolling-update-batch-size)。

这确保了 Playbook 的执行是串行而不是并行进行的。因此，我们先前列出的步骤可以逐个节点完成。负载均衡器将流量分发到正在运行的节点上的网站，并且我们实现了滚动更新。

除了给 serial 一个数字之外，我们还可以使用百分比。因此，示例变为以下形式：

```
- name: test play
  hosts: webservers
  serial: "20%"
```

示例来自 [`docs.ansible.com/ansible/latest/playbooks_delegation.html#rolling-update-batch-size`](http://docs.ansible.com/ansible/latest/playbooks_delegation.html#rolling-update-batch-size)。

我们可以选择为 serial 提供百分比值或数字值。在这种情况下，play 将针对 1 个节点运行，然后是剩余节点的 20%，最后是所有剩余节点。

```
# The batch sizes can be a list as well
- name: test play
  hosts: webservers
  serial:
    - "1"
    - "20%"
    - "100%"
```

示例来自 [`docs.ansible.com/ansible/latest/playbooks_delegation.html#rolling-update-batch-size`](http://docs.ansible.com/ansible/latest/playbooks_delegation.html#rolling-update-batch-size)。

这种更新方式的一个很好的示例在下面的链接中给出

*第 47 集 - 使用 Ansible 进行零停机部署*：[`sysadmincasts.com/episodes/47-zero-downtime-deployments-with-ansible-part-4-4`](https://sysadmincasts.com/episodes/47-zero-downtime-deployments-with-ansible-part-4-4)

# 蓝绿部署

蓝绿的概念归功于马丁·福勒。一个很好的参考是这篇文章 [`martinfowler.com/bliki/BlueGreenDeployment.html`](http://martinfowler.com/bliki/BlueGreenDeployment.html)。其想法是将我们当前的生产工作负载视为蓝色。现在我们想要做的是升级应用程序。因此，在相同的负载均衡器后面启动蓝色的副本。基础设施的副本具有更新的应用程序。

一旦它启动并运行，负载均衡器配置将从当前的蓝色切换到指向绿色。蓝色保持运行，以防有任何操作问题。一旦我们对进展满意，就可以关闭旧主机。下面的 playbook 以非常简单的方式演示了这一点：

+   第一个 playbook 启动三个主机。两个运行 nginx 的 Web 服务器在负载均衡器后面

+   第二个 playbook 将当前正在运行的内容（蓝色）切换为绿色

# 蓝绿部署设置 playbook

以下 playbook 将设置三个节点，包括负载均衡器和两个 Web 服务器节点。请参阅 [`www.upcloud.com/support/haproxy-load-balancer-ubuntu`](https://www.upcloud.com/support/haproxy-load-balancer-ubuntu) 创建一个 playbook。

下面的代码片段是 `inventory` 文件：

```
[proxyserver]
proxy ansible_host=192.168.100.100 ansible_user=ubuntu ansible_password=passwordgoeshere

[blue]
blueserver ansible_host=192.168.100.10 ansible_user=ubuntu ansible_password=passwordgoeshere

[green]
greenserver ansible_host=192.168.100.20 ansible_user=ubuntu ansible_password=passwordgoeshere

[webservers:children]
blue
green

[prod:children]
webservers
proxyserver
```

然后，`main.yml` playbook 文件如下所示，描述了在哪些节点上执行哪些角色和流程：

```
- name: running common role
  hosts: prod
  gather_facts: false
  become: yes
  serial: 100%
  roles:
    - common

- name: running haproxy role
  hosts: proxyserver
  become: yes 
  roles:
    - haproxy

- name: running webserver role
  hosts: webservers
  become: yes 
  serial: 100% 
  roles:
    - nginx

- name: updating blue code
  hosts: blue
  become: yes 
  roles:
    - bluecode

- name: updating green code
  hosts: green
  become: yes 
  roles:
    - greencode
```

每个角色都有其自己的功能要执行；以下是在所有节点上执行的常见角色：

```
- name: installing python if not installed
  raw: test -e /usr/bin/python || (apt -y update && apt install -y python-minimal)

- name: updating and installing git, curl
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - git
    - curl

# Also we can include common any monitoring and security hardening tasks
```

然后，代理服务器角色如下所示，用于设置和配置 `haproxy` 服务器：

```
- name: adding haproxy repo
  apt_repository:
    repo: ppa:vbernat/haproxy-1.7

- name: updating and installing haproxy
  apt:
    name: haproxy
    state: present
    update_cache: yes

- name: updating the haproxy configuration
  template:
    src: haproxy.cfg.j2
    dest: /etc/haproxy/haproxy.cfg

- name: starting the haproxy service
  service:
    name: haproxy
    state: started
    enabled: yes
```

`haproxy.cfg.j2` 如下所示，其中包含执行设置所需的所有配置。根据我们想要添加（或）移除的配置，可以进行改进，如 SSL/TLS 证书和暴露 `haproxy` 统计信息等：

```
global
  log /dev/log local0
  log /dev/log local1 notice
  chroot /var/lib/haproxy
  stats socket /run/haproxy/admin.sock mode 660 level admin
  stats timeout 30s
  user haproxy
  group haproxy
  daemon

  # Default SSL material locations
  ca-base /etc/ssl/certs
  crt-base /etc/ssl/private

  # Default ciphers to use on SSL-enabled listening sockets.
  # For more information, see ciphers(1SSL). This list is from:
  # https://hynek.me/articles/hardening-your-web-servers-ssl-ciphers/
  # An alternative list with additional directives can be obtained from
  # https://mozilla.github.io/server-side-tls/ssl-config-generator/?server=haproxy
  ssl-default-bind-ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS
  ssl-default-bind-options no-sslv3

defaults
  log global
  mode http
  option httplog
  option dontlognull
        timeout connect 5000
        timeout client 50000
        timeout server 50000
  errorfile 400 /etc/haproxy/errors/400.http
  errorfile 403 /etc/haproxy/errors/403.http
  errorfile 408 /etc/haproxy/errors/408.http
  errorfile 500 /etc/haproxy/errors/500.http
  errorfile 502 /etc/haproxy/errors/502.http
  errorfile 503 /etc/haproxy/errors/503.http
  errorfile 504 /etc/haproxy/errors/504.http

frontend http_front
   bind *:80
   stats uri /haproxy?stats
   default_backend http_back

backend http_back
   balance roundrobin
   server {{ hostvars.blueserver.ansible_host }} {{ hostvars.blueserver.ansible_host }}:80 check
   #server {{ hostvars.greenserver.ansible_host }} {{ hostvars.greenserver.ansible_host }}:80 check
```

下面的代码片段将服务器添加为负载均衡器的一部分，并在用户请求时提供服务。我们也可以添加多个服务器。`haproxy`还支持 L7 和 L4 负载平衡：

```
server {{ hostvars.blueserver.ansible_host }} {{ hostvars.blueserver.ansible_host }}:80 check
```

Web 服务器是非常简单的 nginx 服务器设置，用于安装并将服务添加到启动过程中：

```
- name: installing nginx
  apt:
    name: nginx
    state: present
    update_cache: yes

- name: starting the nginx service
  service:
    name: nginx
    state: started
    enabled: yes
```

最后，以下代码片段分别是`blue`和`green`服务器的代码：

```
<html>
    <body bgcolor="blue">
       <h1 align="center">Welcome to Blue Deployment</h1>
    </body>
</html>
<html>
    <body bgcolor="green">
        <h1 align="center">Welcome to Green Deployment</h1>
    </body>
</html>
```

以下是整个设置的 playbook 执行的参考截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/20124216-1607-4579-8648-cb4427a6716c.png)

一旦 playbook 完成，我们就可以在负载均衡器 IP 地址上检查生产站点，查看蓝色部署：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/16ae76c4-6cda-480d-85b3-e17b0d2a0748.png)

# BlueGreen 部署更新 playbook

现在，开发人员已经更新了代码（或者）服务器已经修补了一些安全漏洞。我们希望使用绿色部署部署生产站点的新版本。

playbook 看起来非常简单，如下所示，它将更新配置并重新加载 `haproxy` 服务以服务新的生产部署：

```
- name: Updating to GREEN deployment
  hosts: proxyserver
  become: yes 

  tasks:
    - name: updating proxy configuration
      template:
        src: haproxy.cfg.j2
        dest: /etc/haproxy/haproxy.cfg

    - name: updating the service
      service:
        name: haproxy
        state: reloaded

    - debug:
        msg: "GREEN deployment successful. Please check your server :)"
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/419d233e-30b5-4776-9c71-f330f26771f9.png)

然后，我们可以再次检查我们的生产站点，通过导航到负载均衡器 IP 地址来查看更新的部署：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/b323f803-2c55-43cc-be61-d81a8179856b.png)

现在，我们可以看到我们的生产站点正在运行新的更新部署。HAProxy 中有多个高级选项可用于执行不同类型的更新，并且可以根据需要进行配置。

# 摘要

本章涉及了应用程序和网络安全的各种用例。通过将各种工具与 Ansible playbook 的强大功能相结合，我们在这个领域创建了强大的安全自动化工作流程。根据需求，您可以使用基准来启用安全默认值或定期检查合规性并满足审计要求。我们研究了允许我们对 AWS 云执行相同操作的工具。从应用程序安全扫描器到以安全配置驱动的软件更新和补丁方法，我们尝试涵盖一系列任务，这些任务通过 Ansible 自动化变得强大。

在下一章中，我们将专注于 IT 和运维中最激动人心的新兴领域之一，即容器。Docker 作为容器的代名词，已经成为开发人员、系统管理员广泛部署的技术，也是现代软件开发和部署流程的核心组成部分。让我们探索 Ansible 与 Docker 容器配合使用的秘密。
