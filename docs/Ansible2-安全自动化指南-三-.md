# Ansible2 安全自动化指南（三）

> 原文：[`zh.annas-archive.org/md5/CFD4FC07D470F8B8541AAD40C25E807E`](https://zh.annas-archive.org/md5/CFD4FC07D470F8B8541AAD40C25E807E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：Docker 容器的持续安全扫描

Docker 容器是开发人员打包应用程序的新方法。容器最好的特性是它们包含了代码、运行时、系统库以及应用程序工作所需的所有设置。由于易于使用和部署，越来越多的应用程序正在以容器形式部署用于生产。

由于有这么多的活动部分，我们迫切需要有能力持续扫描 Docker 容器以寻找安全问题。在本章中，我们将看到各种做到这一点的方法。从使用 Ansible 调用的熟悉的 CIS 基准脚本开始，我们将转向 clair-scanner，这是一个用于扫描现有漏洞并与现有的 CI/CD 工作流程很好地集成的工具，如果需要的话。

在本章中，我们将详细探讨以下主题：

+   理解持续安全的概念

+   使用 Ansible 自动化 Docker 容器的漏洞评估

+   使用 Ansible Tower 对 Docker 安全进行定期扫描

+   使用 Ansible Tower 对操作系统和内核安全进行定期扫描

+   使用 Ansible 进行文件完整性检查和主机级监控的定期扫描，以满足各种合规性要求

# 理解持续安全的概念

DevOps 中出现的一个关键方法是不可变基础设施的概念。这意味着每当需要进行运行时更改，无论是应用程序代码还是配置，都会重新构建和部署容器，并且会销毁现有的运行容器。

由于这样可以实现可预测性、弹性，并简化运行时的部署选择，因此毫无疑问，许多运维团队正在朝着这个方向发展。伴随而来的问题是这些容器应该何时进行安全和合规性测试。通过接受本章讨论的持续安全扫描和监控的流程，您可以自动化各种工作负载和工作流程。

# 使用 Ansible 自动化 Docker 容器的漏洞评估

容器无处不在。让我们看一些使用 Ansible 进行扫描和评估 Docker 容器和环境的技术和工具。

评估容器安全有许多不同的方法。在本章中，我们将看一些方法以及它们如何与 Ansible 结合使用：

| **工具** | **描述** |
| --- | --- |
| Docker Bench | 基于 CIS 进行检查的安全 Shell 脚本 |
| Clair | 基于 CVE 数据库进行漏洞分析的工具 |
| Anchore | 用于执行安全评估并做出运行时策略决策的工具 |
| `vuls` | 一种无需代理的漏洞扫描器，具有 CVE、OVAL 数据库 |
| `osquery` | 用于进行 OS 分析的 OS 仪表化框架，以执行 HIDS 类型的活动 |

# Docker 安全检查

**Docker 安全工作台**是一个 shell 脚本，用于对 Docker 容器环境进行多项检查。它将根据 CIS 基准提供更详细的安全配置视图。由于它是基于符合 POSIX 2004 标准构建的，所以该脚本支持大多数 Unix 操作系统。

有关工具信息的更多详细信息，请访问[`github.com/docker/docker-bench-security`](https://github.com/docker/docker-bench-security)。

以下是此脚本将执行的检查的高级区域：

+   主机

+   Docker 守护程序配置和文件

+   Docker 容器映像

+   Docker 运行时

+   Docker 安全操作

+   Docker 集群配置

以下 Playbook 将针对 Docker 环境执行 Docker 安全检查，并返回详细的报告：

```
- name: Docker bench security playbook
  hosts: docker
  remote_user: ubuntu
  become: yes

  tasks:
    - name: make sure git installed
      apt:
        name: git
        state: present

    - name: download the docker bench security
      git:
        repo: https://github.com/docker/docker-bench-security.git
        dest: /opt/docker-bench-security

    - name: running docker-bench-security scan
      command: docker-bench-security.sh -l /tmp/output.log
      args:
        chdir: /opt/docker-bench-security/

    - name: downloading report locally
      fetch:
        src: /tmp/output.log
        dest: "{{ playbook_dir }}/{{ inventory_hostname }}-docker-report-{{ ansible_date_time.date }}.log"
        flat: yes

    - name: report location
      debug:
        msg: "Report can be found at {{ playbook_dir }}/{{ inventory_hostname }}-docker-report-{{ ansible_date_time.date }}.log"</mark>
```

Docker 安全检查 Ansible Playbook 的执行：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/66d4e4e4-d03c-4e8d-add9-ab0a391a6fd0.png)

Docker 安全检查 Ansible Playbook 的执行

Playbook 的输出将下载并扫描基于 CIS 基准的容器，并将结果存储在`log`文件中，其输出可以在此处看到：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/85657f30-7178-4c75-91ac-c19f140c2278.png)

详细的 Docker 安全检查分析报告

# Clair

Clair 允许我们通过与现有漏洞数据库进行检查来对容器执行静态漏洞分析。它允许我们使用 Clair 数据库对我们的 Docker 容器映像执行漏洞分析检查。有关 Clair 的更多详细信息，请访问[`github.com/coreos/clair`](https://github.com/coreos/clair)。

设置 Clair 本身真的很困难，并且使用 Docker 映像的 API 进行扫描会使得情况更加复杂。这就是 clair-scanner 的用武之地，它使得通过 REST API 进行设置和执行扫描变得非常简单。

请在[`github.com/arminc/clair-scanner`](https://github.com/arminc/clair-scanner)中阅读更多关于 clair-scanner 的信息。

Clair-scanner 可以根据某些事件触发对容器进行简单扫描，以检查现有的漏洞。此外，该报告可以转发给负责修复等工作的团队。

以下 Playbook 将设置所需的 Docker 容器和配置以执行 clair-scanning。它假设目标系统已安装了 Docker 和所需的库：

```
- name: Clair Scanner Server Setup
  hosts: docker
  remote_user: ubuntu
  become: yes

  tasks:
    - name: setting up clair-db
      docker_container:
        name: clair_db
        image: arminc/clair-db
        exposed_ports:
          - 5432

    - name: setting up clair-local-scan
      docker_container:
        name: clair
        image: arminc/clair-local-scan:v2.0.1
        ports:
          - "6060:6060"
        links:
          - "clair_db:postgres"
```

以下截图展示了使用 Ansible 设置 clair-scanner 与 Docker 容器的执行。

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/95c063eb-a6c0-476b-be4a-243423ab9cf1.png)

使用 Ansible 设置 clair-scanner 与 Docker 容器

在执行 Playbook 后，下载和设置 CVE 数据库将需要一段时间。

以下 Playbook 将用于运行 clair-scanner，通过向服务器发出 API 请求对容器进行分析：

```
- name: Scanning containers using clair-scanner
  hosts: docker
  remote_user: ubuntu
  become: yes
  vars:
    image_to_scan: "debian:sid"   #container to scan for vulnerabilities
    clair_server: "http://192.168.1.10:6060"    #clair server api endpoint

  tasks:
    - name: downloading and setting up clair-scanner binary
      get_url:
        url: https://github.com/arminc/clair-scanner/releases/download/v6/clair-scanner_linux_amd64
        dest: /usr/local/bin/clair-scanner
        mode: 0755

    - name: scanning {{ image_to_scan }} container for vulnerabilities
      command: clair-scanner -r /tmp/{{ image_to_scan }}-scan-report.json -c {{ clair_server }} --ip 0.0.0.0 {{ image_to_scan }}
      register: scan_output
      ignore_errors: yes

    - name: downloading the report locally
      fetch:
        src: /tmp/{{ image_to_scan }}-scan-report.json
        dest: {{ playbook_dir }}/{{ image_to_scan }}-scan-report.json
        flat: yes
```

以下截图展示了针对请求的 Docker 映像执行 clair-scanner 的情况。正如您所看到的致命错误，所以当它发现 Docker 映像存在任何问题时，它会返回错误，我们可以使用`ignore_errors`来处理它。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/20f95437-597d-406e-adcb-317ba4134f1e.png)

Clair-scanner 执行过程

这是运行 clair-scanner 的 playbook 输出以及 JSON 格式的报告输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/604c7d53-1ed1-47e0-af85-ae15e4f5b234.png)

报告的输出包括漏洞 CVE 和严重程度

# 使用 Ansible Tower 进行定期扫描 Docker 安全性

持续安全性流程涉及计划、执行、测量和行动的循环：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/d055e059-aaaf-4d38-a2f1-11c37f25eebb.png)

来自维基共享的 Deming 循环

通过遵循标准的检查表和基准，并使用 Ansible 在容器上执行它们，我们可以检查安全问题并对其采取行动。Anchore 是一个用于容器的分析和检查平台。

# Anchore - 开放式容器合规性平台

Anchore 是执行容器镜像分析、检查和认证的最流行的工具和服务之一。它提供多个服务和平台进行设置，最稳定和强大的方式是使用 Anchore Engine 设置本地服务，可以通过 REST API 访问。在以下文档中，我们将看到如何使用 Anchore Engine 设置服务以及如何使用这个 REST API 执行 Docker 容器的持续安全扫描和分析。

以下是 Anchore 可执行的高级操作：

+   策略评估操作

+   图像操作

+   策略操作

+   注册操作

+   订阅操作

+   系统操作

在[`github.com/anchore/anchore-engine`](https://github.com/anchore/anchore-engine)了解更多关于 Anchore 引擎服务的信息。

# 设置 Anchore 引擎服务

以下 playbook 将设置 Anchore 引擎服务，其中包含引擎容器以及用于存储数据库信息的 `postgres`。`admin_password` 变量是访问 Anchore REST API 的管理员用户密码：

```
- name: anchore server setup
  hosts: anchore
  become: yes
  vars:
    db_password: changeme
    admin_password: secretpassword

  tasks:
    - name: creating volumes
      file:
        path: "{{ item }}"
        recurse: yes
        state: directory

      with_items:
        - /root/aevolume/db
        - /root/aevolume/config

    - name: copying anchore-engine configuration
      template:
        src: config.yaml.j2
        dest: /root/aevolume/config/config.yaml

    - name: starting anchore-db container
      docker_container:
        name: anchore-db
        image: postgres:9
        volumes:
          - "/root/aevolume/db/:/var/lib/postgresql/data/pgdata/"
        env:
          POSTGRES_PASSWORD: "{{ db_password }}"
          PGDATA: "/var/lib/postgresql/data/pgdata/"

    - name: starting anchore-engine container
      docker_container:
        name: anchore-engine
        image: anchore/anchore-engine
        ports:
          - 8228:8228
          - 8338:8338
        volumes:
          - "/root/aevolume/config/config.yaml:/config/config.yaml:ro"
          - "/var/run/docker.sock:/var/run/docker.sock:ro"
        links:
          - anchore-db:anchore-db
```

以下截图是执行 Anchore 引擎服务设置的 Ansible playbook 执行过程：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/3f6352ba-e5ba-4be6-b7c1-b026e4dcb6b8.png)

使用 Ansible playbook 设置 Anchore 引擎服务

# Anchore CLI 扫描器

现在我们已经拥有了 Anchore 引擎服务的 REST API 访问详情，我们可以利用这一点在任何主机上执行容器镜像的扫描。以下步骤是配置 Ansible Tower 来执行持续的容器镜像漏洞扫描。

用于扫描容器镜像的 playbook 如下所示：

```
- name: anchore-cli scan
  hosts: anchore
  become: yes
  vars:
    scan_image_name: "docker.io/library/ubuntu:latest"
    anchore_vars:
      ANCHORE_CLI_URL: http://localhost:8228/v1
      ANCHORE_CLI_USER: admin
      ANCHORE_CLI_PASS: secretpassword

  tasks:
    - name: installing anchore-cli
      pip:
        name: "{{ item }}"

      with_items:
        - anchorecli
        - pyyaml

    - name: downloading image
      docker_image: 
        name: "{{ scan_image_name }}"

    - name: adding image for analysis
      command: "anchore-cli image add {{ scan_image_name }}"
      environment: "{{anchore_vars}}"

    - name: wait for analysis to compelte
      command: "anchore-cli image content {{ scan_image_name }} os"
      register: analysis
      until: analysis.rc != 1
      retries: 10
      delay: 30
      ignore_errors: yes
      environment: "{{anchore_vars}}"

    - name: vulnerabilities results
      command: "anchore-cli image vuln {{ scan_image_name }} os"
      register: vuln_output
      environment: "{{anchore_vars}}"

    - name: "vulnerabilities in {{ scan_image_name }}"
      debug:
        msg: "{{ vuln_output.stdout_lines }}"
```

可以根据需要自定义执行 `anchore-cli` 的选项，请参阅[`github.com/anchore/anchore-cli`](https://github.com/anchore/anchore-cli)的文档。

现在，我们必须在 Ansible Tower 中创建新项目以添加 playbook。然后我们可以从版本控制中选择 playbook 源，或者提供详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/454e5c03-dfb4-4682-841d-0ef7042430b0.png)

我们也可以通过 Ansible Tower UI 传递变量。正如您所见，我们正在传递一些秘密，我们将看到如何利用 Ansible Vault 安全存储和使用它们：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/e8279541-428b-42f8-9679-85fbbfa0dde3.png)

我们还可以按需安排此 Playbook 每周或每月运行，根据需要进行设置。还请注意，这可以根据用例进行定制：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/9e26ee66-df77-4747-8c18-dea06decca55.png)

然后，我们还可以通过启动作业执行按需扫描。以下截图是关于 `ubuntu:latest` Docker 镜像漏洞的参考，其中包含 CVE 详细信息和易受攻击的软件包列表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/56b8d6fb-affd-4517-92e1-a1fe9d2b1596.png)

# 使用 Ansible Tower 定期扫描操作系统和内核安全

持续的安全扫描要求我们在类似 Ansible Tower 的软件中进行管理。虽然大多数讨论的工具都可用于扫描和维护安全基准，但我们应考虑事故响应和威胁检测工作流程的整个过程：

1.  准备工作

1.  检测和分析

1.  遏制、根除和恢复

1.  事后活动

设置所有这些扫描器是我们的准备工作。使用这些扫描器的输出使我们能够进行检测和分析。遏制和恢复都超出了这些工具的范围。对于恢复和事后活动的流程，您可能需要考虑可以销毁当前基础架构并按原样重新创建的 Playbook。

作为准备的一部分，熟悉以下术语可能很有用，因为您会在漏洞扫描器和漏洞管理工具的世界中反复看到它们的使用：

| **术语** | **全称（如果有）** | **术语描述** |
| --- | --- | --- |
| CVE | 通用漏洞和暴露 | 这是一个网络安全漏洞标识符列表。通常使用 CVE ID。 |
| OVAL | 开放式漏洞和评估语言 | 用于发现和命名计算机系统中的漏洞和配置问题的语言。 |
| CWE | 通用弱点枚举 | 软件安全弱点的通用列表。 |
| NVD | 国家漏洞数据库 | 美国政府的漏洞管理数据库，以 XML 格式公开供公众使用。 |

# Vuls - 漏洞扫描器

**Vuls** 是一个用 golang 编写的无代理扫描器。它支持各种不同的 Linux 操作系统。它执行完整的端到端安全系统管理任务，如扫描安全漏洞和安全软件更新。它根据 CVE 分数对系统进行所需的安全漏洞分析，通过 Slack 和电子邮件发送通知，并提供具有历史数据的简单 Web 报告。

在 [`github.com/future-architect/vuls`](https://github.com/future-architect/vuls) 了解更多关于 vuls 的信息。

# Vuls 设置 Playbook

以下 playbook 用于在 Ubuntu 16.04 系统上使用 Docker 容器设置`vuls`。 以下 playbook 假定您已经安装了 docker 和所需的软件包。

playbook 主要有两个角色，用于使用 Docker 容器设置`vuls`。

+   `vuls_containers_download`

+   `vuls_database_download`

```
- name: setting up vuls using docker containers
  hosts: vuls
  become: yes

  roles:
    - vuls_containers_download
    - vuls_database_download
```

使用`docker_image`模块在本地拉取 Docker 容器：

```
- name: pulling containers locally
  docker_image:
    name: "{{ item }}"
    pull: yes

  with_items:
    - vuls/go-cve-dictionary
    - vuls/goval-dictionary
    - vuls/vuls
```

然后下载所需操作系统和分发版本的 CVE 和 OVAL 数据库：

```
- name: fetching NVD database locally
  docker_container:
    name: "cve-{{ item }}"
    image: vuls/go-cve-dictionary
    auto_remove: yes
    interactive: yes
    state: started
    command: fetchnvd -years "{{ item }}"
    volumes:
      - "{{ vuls_data_directory }}:/vuls"
      - "{{ vuls_data_directory }}/go-cve-dictionary-log:/var/log/vuls"
  with_sequence: start=2002 end="{{ nvd_database_years }}"

- name: fetching redhat oval data
  docker_container:
    name: "redhat-oval-{{ item }}"
    image: vuls/goval-dictionary
    auto_remove: yes
    interactive: yes
    state: started
    command: fetch-redhat "{{ item }}"
    volumes:
      - "{{ vuls_data_directory }}:/vuls"
      - "{{ vuls_data_directory }}/goval-dictionary-log:/var/log/vuls"
  with_items: "{{ redhat_oval_versions }}"

- name: fetching ubuntu oval data
  docker_container:
    name: "ubuntu-oval-{{ item }}"
    image: vuls/goval-dictionary
    auto_remove: yes
    interactive: yes
    state: started
    command: "fetch-ubuntu {{ item }}"
    volumes:
      - "{{ vuls_data_directory }}:/vuls"
      - "{{ vuls_data_directory }}/goval-dictionary-log:/var/log/vuls"
  with_items: "{{ ubuntu_oval_versions }}"
```

全局变量文件如下所示。 我们可以添加更多`redhat_oval_versions`，例如`5`。 `nvd_database_years`将下载 CVE 数据库直到 2017 年底：

```
vuls_data_directory: "/vuls_data"
nvd_database_years: 2017
redhat_oval_versions:
  - 6
  - 7
ubuntu_oval_versions:
  - 12
  - 14
  - 16
```

以下屏幕截图是用于 vuls 设置的 Ansible playbook 执行示例：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/a8393a43-938e-4c3f-af12-0711aef5cb8b.png)

Vuls 设置 playbook 生效

# Vuls 扫描 playbook

现在，是时候使用`vuls` Docker 容器执行扫描和报告了。 以下 playbook 包含了执行针对虚拟机和容器的`vuls`扫描以及将报告发送到 slack 和 web 的简单步骤：

```
- name: scanning and reporting using vuls
  hosts: vuls
  become: yes
  vars:
    vuls_data_directory: "/vuls_data"
    slack_web_hook_url: https://hooks.slack.com/services/XXXXXXX/XXXXXXXXXXXXXXXXXXXXX
    slack_channel: "#vuls"
    slack_emoji: ":ghost:"
    server_to_scan: 192.168.33.80
    server_username: vagrant
    server_key_file_name: 192-168-33-80

  tasks:
    - name: copying configuraiton file and ssh keys
      template:
        src: "{{ item.src }}"
        dest: "{{ item.dst }}"
        mode: 0400

      with_items:
         - { src: 'config.toml', dst: '/root/config.toml' }
         - { src: '192-168-33-80', dst: '/root/.ssh/192-168-33-80' } 

    - name: running config test
      docker_container:
        name: configtest
        image: vuls/vuls
        auto_remove: yes
        interactive: yes
        state: started
        command: configtest -config=/root/config.toml
        volumes:
          - "/root/.ssh:/root/.ssh:ro"
          - "{{ vuls_data_directory }}:/vuls"
          - "{{ vuls_data_directory }}/vuls-log:/var/log/vuls"
          - "/root/config.toml:/root/config.toml:ro"

    - name: running vuls scanner
      docker_container:
        name: vulsscan
        image: vuls/vuls
        auto_remove: yes
        interactive: yes
        state: started
        command: scan -config=/root/config.toml
        volumes:
          - "/root/.ssh:/root/.ssh:ro"
          - "{{ vuls_data_directory }}:/vuls"
          - "{{ vuls_data_directory }}/vuls-log:/var/log/vuls"
          - "/root/config.toml:/root/config.toml:ro"
          - "/etc/localtime:/etc/localtime:ro"
        env:
          TZ: "Asia/Kolkata"

    - name: sending slack report
      docker_container:
        name: vulsreport
        image: vuls/vuls
        auto_remove: yes
        interactive: yes
        state: started
        command: report -cvedb-path=/vuls/cve.sqlite3 -ovaldb-path=/vuls/oval.sqlite3 --to-slack -config=/root/config.toml
        volumes:
          - "/root/.ssh:/root/.ssh:ro"
          - "{{ vuls_data_directory }}:/vuls"
          - "{{ vuls_data_directory }}/vuls-log:/var/log/vuls"
          - "/root/config.toml:/root/config.toml:ro"
          - "/etc/localtime:/etc/localtime:ro"

    - name: vuls webui report
      docker_container:
        name: vulswebui
        image: vuls/vulsrepo
        interactive: yes
        volumes:
          - "{{ vuls_data_directory }}:/vuls"
        ports:
          - "80:5111"
```

以下文件是`vuls`执行扫描的配置文件。 这保存了 slack 警报的配置以及执行扫描的服务器。 可以根据`vuls`文档非常有效地进行配置：

```
[slack]
hookURL = "{{ slack_web_hook_url}}"
channel = "{{ slack_channel }}"
iconEmoji = "{{ slack_emoji }}"

[servers]

[servers.{{ server_key_file_name }}]
host = "{{ server_to_scan }}"
user = "{{ server_username }}"
keyPath = "/root/.ssh/{{ server_key_file_name }}"
```

以下屏幕截图是用于 vuls 扫描的 Ansible playbook 执行示例：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/b9ee7989-87b9-49d2-80a1-7682070bfaa7.png)

Vuls 扫描 playbook 生效

一旦报告容器执行完毕，根据配置选项，`vuls`将问题通知到相应的 slack 频道：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/0bc2665a-9572-4911-93ec-7eac35721b0e.png)

我们还可以访问`vuls`服务器 IP 地址的 Web UI 界面，以查看表格和便携格式的详细结果。 这对于管理大量服务器和规模化补丁非常有用：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/9a9e5c82-cfb7-4b9a-828e-5dceda00315c.png)

我们还可以通过报告深入了解问题、严重性、操作系统等：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/80fa4ebb-c50f-408a-b00c-31b1b8d6eadf.png)

这可以作为基础架构代码的 CI/CD 生命周期的一部分，然后我们可以使用 Ansible Tower 或 Jenkins 作为计划扫描运行它。

# 为各种合规性倡议进行文件完整性检查和主机级监视的计划扫描

使用 Ansible 在主机上执行命令的许多优点之一是能够获取内部系统信息，例如：

+   文件哈希值

+   网络连接

+   正在运行的进程列表

它可以作为轻量级**主机入侵检测系统**（**HIDS**）。虽然在许多情况下这可能不能完全替代专门设计的 HIDS，但我们可以使用像 Facebook 的`osquery`这样的工具与 Ansible 一起执行相同类型的安全任务。

# osquery

`osquery`是 Facebook 开发的操作系统仪表化框架，用 C++编写，支持 Windows、Linux、OS X（macOS）和其他操作系统。它提供了使用类似 SQL 语法的接口来查询操作系统的功能。通过使用这个，我们可以执行诸如运行进程、内核配置、网络连接和文件完整性检查等低级活动。总的来说，它就像一个**主机入侵检测系统**（**HIDS**）端点安全。它提供`osquery`作为服务、系统交互 shell 等。因此我们可以使用它来执行集中监控和安全管理解决方案。更多关于`osquery`的信息请访问[`osquery.io`](https://osquery.io)。

这里是对`osquery`的高层次概述：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/5343db14-1311-45d2-8872-0baac58e339c.png)

使用 SQL 查询获取用户列表及其组和其他信息的`osquery`

以下操作手册是为了在 Linux 服务器上设置和配置`osquery`代理，以监视和查找漏洞、文件完整性监控和许多其他合规性活动，然后将它们记录下来发送到集中日志监控系统：

```
- name: setting up osquery
  hosts: linuxservers
  become: yes

  tasks:
    - name: installing osquery
      apt:
        deb: https://pkg.osquery.io/deb/osquery_2.10.2_1.linux.amd64.deb
        update_cache: yes

    - name: adding osquery configuration
      template:
        src: "{{ item.src }}"
        dest: "{{ item.dst }}"

      with_items:
        - { src: fim.conf, dst: /usr/share/osquery/packs/fim.conf }
        - { src: osquery.conf, dst: /etc/osquery/osquery.conf }

    - name: starting and enabling osquery service
      service:
        name: osqueryd
        state: started
        enabled: yes
```

以下`fim.conf`代码片段是用于文件完整性监控的包，它每 300 秒监视`/home`、`/etc`和`/tmp`目录中的文件事件。它使用**安全哈希算法**（**SHA**）校验来验证更改。这可用于查找攻击者是否添加了自己的 SSH 密钥或对系统配置更改进行合规性和其他活动的审核日志更改：

```
{
  "queries": {
    "file_events": {
      "query": "select * from file_events;",
      "removed": false,
      "interval": 300
    }
  },
  "file_paths": {
    "homes": [
      "/root/.ssh/%%",
      "/home/%/.ssh/%%"
    ],
      "etc": [
      "/etc/%%"
    ],
      "home": [
      "/home/%%"
    ],
      "tmp": [
      "/tmp/%%"
    ]
  }
}
```

以下配置由`osquery`守护程序使用，以基于指定选项、包和自定义查询执行检查和监控。我们还使用不同的包（包含多个查询）来查找不同的监控和配置检查。

默认情况下，`osquery`具有多个包，用于事件响应、漏洞管理、合规性、rootkit、硬件监控等。更多详情请访问[`osquery.io/schema/packs`](https://osquery.io/schema/packs)。

以下代码片段是`osquery`服务配置。根据需要可以进行修改以监视和记录`osquery`服务：

```
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "log_result_events": "true",
    "schedule_splay_percent": "10",
    "pidfile": "/var/osquery/osquery.pidfile",
    "events_expiry": "3600",
    "database_path": "/var/osquery/osquery.db",
    "verbose": "false",
    "worker_threads": "2",
    "enable_monitor": "true",
    "disable_events": "false",
    "disable_audit": "false",
    "audit_allow_config": "true",
    "host_identifier": "hostname",
    "enable_syslog": "true",
    "audit_allow_sockets": "true",
    "schedule_default_interval": "3600" 
  },
  "schedule": {
    "crontab": {
      "query": "SELECT * FROM crontab;",
      "interval": 300
    },
    "system_profile": {
      "query": "SELECT * FROM osquery_schedule;"
    }, 
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    }
  },
  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
      "SELECT user AS username FROM logged_in_users ORDER BY time DESC LIMIT 1;"
    ]
  },
  "packs": {
     "fim": "/usr/share/osquery/packs/fim.conf",
     "osquery-monitoring": "/usr/share/osquery/packs/osquery-monitoring.conf",
     "incident-response": "/usr/share/osquery/packs/incident-response.conf",
     "it-compliance": "/usr/share/osquery/packs/it-compliance.conf",
     "vuln-management": "/usr/share/osquery/packs/vuln-management.conf"
  }
}
```

参考教程可在[`www.digitalocean.com/community/tutorials/how-to-monitor-your-system-security-with-osquery-on-ubuntu-16-04`](https://www.digitalocean.com/community/tutorials/how-to-monitor-your-system-security-with-osquery-on-ubuntu-16-04)处查看。

可以执行该操作手册来设置 Linux 服务器上的`osquery`配置，以设置和记录`osquery`代理生成的事件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/b665501d-8b25-4672-9a83-7c54ce7211b5.png)

`osquery`设置操作手册在执行中

目标不仅仅是设置`osquery`，我们可以使用日志来构建一个使用我们的 Elastic 堆栈的集中式实时监控系统。我们可以使用 Filebeat 代理将这些日志转发到我们的 Elastic 堆栈，然后我们可以查看它们并构建一个用于警报和监控的集中式仪表板。

以下是`osquery`生成的日志的示例，我们可以看到`authorized_keys`文件在 2017 年 11 月 22 日 23:59:21.000 被 Ubuntu 用户修改：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/2cde3ca0-ebbd-4e3b-9ff0-b7fe54a3a8f5.png)

这个想法可以通过利用自动化 Ansible playbooks 对已知行动采取行动来构建一些自动化防御措施。

世界正在向容器迈进，这种监控方法可以让我们看到诸如内核安全检查和主机级文件完整性检查等底层事物。当攻击者试图绕过容器并访问主机以提升权限时，我们可以使用这种设置来检测并防御它们。

# 总结

容器正在迅速改变开发人员和运维团队的世界。变化的速度正在加快，在这个新世界中，安全自动化将起到重要作用。通过利用我们使用 Ansible 编写逐条命令的知识以及优秀的工具，如 Archore 和`osquery`，我们可以测量、分析和基准我们的容器的安全性。这使我们能够构建端到端的自动化流程，以确保、扫描和修复容器。

在下一章中，我们将探讨安全自动化的专用用例。我们将研究如何通过自动化部分任务来改进恶意软件分析。我们将特别关注集成了 Cuckoo 沙箱的轻量级动态分析工作流程，Cuckoo 沙箱是当前最流行的恶意软件分析工具之一。


# 第九章：自动化取证收集和恶意软件分析的实验室设置

恶意软件是安全社区面临的最大挑战之一。它影响着所有与信息系统互动的人。尽管在保护操作系统免受恶意软件侵害方面需要付出大量努力，但在恶意软件防御方面的大部分工作都是关于理解它们的来源和能力。

这是 Ansible 可以用于自动化和启用恶意软件分析专家的部分。在本章中，我们将研究各种工作流程，这些工作流程都是为了使用像 Cuckoo Sandbox 等工具对恶意软件进行分类和分析。此外，我们还将研究为隔离环境创建 Ansible Playbooks 的各种用途，以及用于收集和存储取证工件的安全备份。

# 为隔离环境创建 Ansible Playbooks

我们将从使用 VirusTotal 开始，并转向具有 Windows 虚拟机的隔离网络中的 Cuckoo。恶意软件分析的另一个重要方面是能够使用**恶意软件信息共享平台**（**MISP**）共享威胁。我们还设置了 Viper（二进制管理和分析框架）来执行分析。

# 收集文件和域名恶意软件识别和分类

恶意软件分析的最初阶段之一是识别和分类。最流行的来源之一是使用 VirusTotal 进行扫描并获取恶意软件样本、域名信息等的结果。它拥有非常丰富的 API，并且许多人编写了利用该 API 进行自动扫描的自定义应用程序，使用 API 密钥来识别恶意软件类型。以下示例是在系统中设置 VirusTotal 工具、针对 VirusTotal API 扫描恶意软件样本，并识别其是否真的是恶意软件。它通常使用 60 多个杀毒扫描器和工具进行检查，并提供详细信息。

# 设置 VirusTotal API 工具

以下 playbook 将设置 VirusTotal API 工具（[`github.com/doomedraven/VirusTotalApi`](https://github.com/doomedraven/VirusTotalApi)），它在 VirusTotal 页面本身得到了官方支持：

```
- name: setting up VirusTotal
  hosts: malware
  remote_user: ubuntu
  become: yes

  tasks:
    - name: installing pip
      apt:
        name: "{{ item }}"

      with_items:
        - python-pip
        - unzip

    - name: checking if vt already exists
      stat:
        path: /usr/local/bin/vt
      register: vt_status

    - name: downloading VirusTotal api tool repo
      unarchive:
        src: "https://github.com/doomedraven/VirusTotalApi/archive/master.zip"
        dest: /tmp/
        remote_src: yes
      when: vt_status.stat.exists == False 

    - name: installing the dependencies
      pip:
        requirements: /tmp/VirusTotalApi-master/requirements.txt
      when: vt_status.stat.exists == False 

    - name: installing vt
      command: python /tmp/VirusTotalApi-master/setup.py install
      when: vt_status.stat.exists == False
```

Playbook 的执行将下载存储库并设置 VirusTotal API 工具，这将使我们准备好扫描恶意软件样本：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/8ac588de-ea81-47b6-bc36-ca873f7ea3bb.png)

# 用于恶意软件样本的 VirusTotal API 扫描

一旦我们准备好设置，使用 Ansible playbook 运行扫描一系列恶意软件样本就像使用 Ansible playbook 一样简单。以下 playbook 将查找并将本地恶意软件样本复制到远程系统，并对其进行递归扫描并返回结果。完成扫描后，它将从远程系统中删除样本：

```
- name: scanning file in VirusTotal
  hosts: malware
  remote_user: ubuntu
  vars:
    vt_api_key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX #use Ansible-vault
    vt_api_type: public # public/private
    vt_intelligence_access: False # True/False
    files_in_local_system: /tmp/samples/
    files_in_remote_system: /tmp/sample-file/

  tasks:
    - name: creating samples directory
      file:
        path: "{{ files_in_remote_system }}"
        state: directory

    - name: copying file to remote system
      copy:
        src: "{{ files_in_local_system }}"
        dest: "{{ files_in_remote_system }}"
        directory_mode: yes

    - name: copying configuration
      template:
        src: config.j2
        dest: "{{ files_in_remote_system }}/.vtapi"

    - name: running VirusTotal scan
      command: "vt -fr {{ files_in_remote_system }}"
      args:
        chdir: "{{ files_in_remote_system }}"
      register: vt_scan

    - name: removing the samples
      file:
        path: "{{ files_in_remote_system }}"
        state: absent

    - name: VirusTotal scan results
      debug:
        msg: "{{ vt_scan.stdout_lines }}"
```

使用 VirusTotal API 对恶意软件样本进行扫描的结果如下。它返回恶意软件扫描报告的哈希值和指针，以获取详细结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/2aa46276-21d0-4017-becf-af14138a51ea.png)

# 部署布谷鸟沙箱环境

**布谷鸟沙箱**是最流行的开源自动化恶意软件分析系统之一。它有很多集成来执行可疑文件的恶意软件分析。其设置要求包括依赖项和其他软件，如 VirtualBox、yara、ssdeep 和 volatility。此外，VM 分析是 Windows，需要一些先决条件才能进行分析。

阅读更多有关布谷鸟沙箱的信息，请访问[`cuckoosandbox.org`](https://cuckoosandbox.org)。

# 设置 Cuckoo 主机

以下 Ansible Playbook 将设置主机操作系统和 Cuckoo Sandbox 工作所需的依赖关系。这有不同的角色以安装 Ubuntu 操作系统中的所有必需软件包。

以下角色包括设置主机系统：

```
- name: setting up cuckoo
  hosts: cuckoo
  remote_user: ubuntu
  become: yes

  roles:
    - dependencies
    - virtualbox
    - yara
    - cuckoo
    - start-cukcoo
```

依赖关系角色具有很多必须安装的`apt`软件包以执行其他安装。然后，我们将为`tcpdump`软件包设置功能，以便 Cuckoo 可以访问它们进行分析：

```
- name: installing pre requirements
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - python
    - python-pip
    - python-dev
    - libffi-dev
    - libssl-dev
    - python-virtualenv
    - python-setuptools
    - libjpeg-dev
    - zlib1g-dev
    - swig
    - tcpdump
    - apparmor-utils
    - mongodb
    - unzip
    - git
    - volatility
    - autoconf
    - libtool
    - libjansson-dev
    - libmagic-dev
    - postgresql
    - volatility
    - volatility-tools
    - automake
    - make
    - gcc
    - flex
    - bison

- name: setting capabilitites to tcpdump
  capabilities:
    path: /usr/sbin/tcpdump
    capability: "{{ item }}+eip"
    state: present

  with_items:
    - cap_net_raw
    - cap_net_admin
```

然后我们将安装 VirtualBox，以便 VM 分析可以安装在 VirtualBox 中。Cuckoo 使用 VirtualBox API 与 VM 分析进行交互以执行操作：

```
- name: adding virtualbox apt source
  apt_repository:
    repo: "deb http://download.virtualbox.org/virtualbox/debian xenial contrib"
    filename: 'virtualbox'
    state: present

- name: adding virtualbox apt key
  apt_key:
    url: "https://www.virtualbox.org/download/oracle_vbox_2016.asc"
    state: present

- name: install virtualbox
  apt:
    name: virtualbox-5.1
    state: present
    update_cache: yes
```

之后，我们将安装一些额外的软件包和工具供 Cuckoo 在分析中使用：

```
- name: copying the setup scripts
  template:
    src: "{{ item.src }}"
    dest: "{{ item.dest }}"
    mode: 0755

  with_items:
    - { src: "yara.sh", dest: "/tmp/yara.sh" }
    - { src: "ssdeep.sh", dest: "/tmp/ssdeep.sh" }

- name: downloading ssdeep and yara releases
  unarchive:
    src: "{{ item }}"
    dest: /tmp/
    remote_src: yes

  with_items:
    - https://github.com/plusvic/yara/archive/v3.4.0.tar.gz
    - https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz

- name: installing yara and ssdeep
  shell: "{{ item }}"
  ignore_errors: yes

  with_items:
    - /tmp/yara.sh
    - /tmp/ssdeep.sh

- name: installing M2Crypto
  pip:
    name: m2crypto
    version: 0.24.0
```

自定义脚本具有安装`yara`和`ssdeep`软件包的构建脚本：

```
# yara script
#!/bin/bash

cd /tmp/yara-3.4.0
./bootstrap
./configure --with-crypto --enable-cuckoo --enable-magic
make
make install
cd yara-python
python setup.py build
python setup.py install

# ssdeep script
#!/bin/bash

cd /tmp/ssdeep-2.14.1
./configure
./bootstrap
make
make install
```

最后，我们将安装 Cuckoo 和其他必需的设置，例如将用户创建到`vboxusers`组。配置文件取自模板，因此这些将根据 VM 分析环境进行修改：

```
  - name: adding cuckoo to vboxusers
    group:
      name: cuckoo
      state: present

  - name: creating new user and add to groups
    user:
      name: cuckoo
      shell: /bin/bash
      groups: vboxusers, cuckoo
      state: present
      append: yes

  - name: upgrading pip, setuptools and cuckoo
    pip:
      name: "{{ item }}"
      state: latest

    with_items:
      - pip
      - setuptools
      - pydeep
      - cuckoo
      - openpyxl
      - ujson
      - pycrypto
      - distorm3
      - pytz
      - weasyprint

  - name: creating cuckoo home direcotry
    command: "cuckoo"
    ignore_errors: yes

  - name: adding cuckoo as owner
    file:
      path: "/root/.cuckoo"
      owner: cuckoo
      group: cuckoo
      recurse: yes
```

以下 playbook 将复制配置并启动 Cuckoo 和 Web 服务器以执行 Cuckoo 分析：

```
- name: copying the configurationss
  template:
    src: "{{ item.src }}"
    dest: /root/.cuckoo/conf/{{ item.dest }}

  with_items:
    - { src: "cuckoo.conf", dest: "cuckoo.conf"}
    - { src: "auxiliary.conf", dest: "auxiliary.conf"}
    - { src: "virtualbox.conf", dest: "virtualbox.conf"}
    - { src: "reporting.conf", dest: "reporting.conf"}

- name: starting cuckoo server
  command: cuckoo -d
  ignore_errors: yes

- name: starting cuckoo webserver
  command: "cuckoo web runserver 0.0.0.0:8000"
    args:
      chdir: "/root/.cuckoo/web"
  ignore_errors: yes
```

# 设置 Cuckoo Guest

大多数设置将需要在 Windows 操作系统中执行。以下指南将帮助您为 Cuckoo 分析设置 Windows Guest VM。请参阅[`cuckoo.sh/docs/installation/guest/index.html`](https://cuckoo.sh/docs/installation/guest/index.html)。

以下截图是参考，第一个适配器是 Host-only 适配器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/23aa5335-c165-4eb2-8df1-fb25cac7e27d.png)

第二个适配器是 NAT：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/4589cb15-147a-4cdb-8dd6-f7ae6b67bea9.png)

一旦 Windows VM 启动，我们需要安装 VirtualBox Guest Addition 工具。这允许 Cuckoo 使用名为 VBoxManage 的命令行实用程序执行分析：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/d669e0d8-d604-4501-ba2f-41363b6bf086.png)

接下来，我们必须在本地安装 Python 以启动本地 Cuckoo 代理，我们可以从官方 Python 网站安装 Python：[`www.python.org/downloads/release/python-2714`](https://www.python.org/downloads/release/python-2714)。

现在从布谷鸟主机下载代理，在 Cuckoo 工作目录中的`agent`文件夹中可用。我们需要将其保留在 Windows VM 中，以便 Cuckoo 服务器与之交互：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/84ad3515-6fee-42d1-b791-ee43d3e4de9e.png)

然后，我们必须使用`regedit`命令将 Python 文件路径添加到系统启动项中。这可以通过导航到`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Current\Version\Run`来完成。然后，在注册表编辑器的右侧添加新的字符串，名称为 Cuckoo，并在值部分中提供`agent.py`文件的完整路径： 

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/42a0f513-4974-44d3-a3c2-9cc746144a44.png)

现在，我们可以拍摄快照并更新 Cuckoo 主机中的配置。完成后，我们准备启动 Cuckoo 服务器和 Web 服务器。

以下截图是 Cuckoo Web 服务器的首页。一旦我们提交了恶意软件样本，我们就可以点击“分析”开始：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/5d4f710c-39ff-4224-bed2-61bb91846267.png)

然后，将花费一些时间使用 VirtualBox Windows 虚拟机执行分析。这将根据您选择的选项执行分析：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/e1912ee3-c858-4672-8df9-7ff6e3a1c45e.png)

然后，它将提供有关样本的完整详细信息。其中包括已提交文件的校验和、Cuckoo 执行分析时的运行时执行截图和其他信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/fed7a78b-f2a3-4678-9838-091acf127c6f.png)

下面的截图是恶意软件样本的行为分析，其中包括进程树的详细分析。左侧菜单包含不同的选项，如放置文件、内存转储分析和数据包分析：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/f00c00b8-c0ca-482e-bd63-c7464dddbcfb.png)

在 Cuckoo 文档中了解更多有关 Cuckoo 使用的信息：[`docs.cuckoosandbox.org/en/latest/usage`](http://docs.cuckoosandbox.org/en/latest/usage)。

# 使用 Ansible playbook 提交样本和报告

以下 playbook 将在本地系统路径中执行给定恶意软件样本文件的分析，并将报告返回给 使用 Ansible playbook：

```
- name: Cuckoo malware sample analysis
  hosts: cuckoo
  vars:
    local_binaries_path: /tmp/binaries

  tasks:
    - name: copying malware sample to cuckoo for analysis
      copy:
        src: "{{ local_binaries_path }}"
        dest: "/tmp/binaries/{{ Ansible_hostname }}"

    - name: submitting the files to cuckoo for analysis
      command: "cuckoo submit /tmp/binaries/{{ Ansible_hostname }}"
      ignore_errors: yes
```

下面的截图将恶意样本复制到 Cuckoo 分析系统，并使用 Ansible playbook 将这些文件提交进行自动化分析：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/a0985b27-d3e9-4a7d-aef7-1d311eace559.png)

上面的截图将本地二进制文件复制到远程 Cuckoo 主机，并使用 Cuckoo 提交功能提交它们进行分析：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/b942741d-1183-457c-b81e-c7ee688627a1.png)

上述截图是我们的 Cuckoo 扫描提交使用 Ansible Playbook 提交的分析报告。

# 使用 Docker 容器设置 Cuckoo

这将允许我们使用 Docker 容器简化 Cuckoo 的设置。以下命令将允许我们使用 Docker 容器设置 Cuckoo 沙箱：

```
$ git clone https://github.com/blacktop/docker-cuckoo
$ cd docker-cuckoo
$ docker-compose up -d
```

下载 Docker 容器并配置它们以协同工作需要一些时间。安装完成后，我们可以使用`http://localhost`访问 Cuckoo：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/3956ed3e-db8d-40a1-a9cb-bc7b01e43ea9.png)

现在，我们可以将恶意软件样本或可疑文件提交给 Cuckoo 进行分析，使用工具集进行分析，它将返回详细的分析结果。在提交样本之前，我们还可以通过选择配置选项来选择进行哪些分析。

# 设置 MISP 和威胁共享

**恶意软件信息共享平台（MISP）**是一个开源的威胁共享平台（[`www.misp-project.org`](http://www.misp-project.org)）。它允许我们在已知的社区和组织内交换关于**高级持续威胁（APT）**和有针对性攻击的**威胁指标（IOCs）**。通过这样做，我们可以更多地了解不同的攻击和威胁，组织可以更容易地防御这些攻击。

使用**卢森堡计算机事件响应中心**（**CIRCL**）定制的虚拟机是开始使用这个平台的最简单方法，其中包括完整设置的最新版本。这个虚拟机经过定制，适用于不同的环境。

VM 和培训材料可在 [`www.circl.lu/services/misp-training-materials`](https://www.circl.lu/services/misp-training-materials) 找到。

# 使用 Ansible playbook 设置 MISP

我们也可以使用 Ansible playbooks 进行设置。根据我们的定制使用，社区中有多个可用的 playbooks：

+   [`github.com/juju4/Ansible-MISP`](https://github.com/juju4/Ansible-MISP)

+   [`github.com/StamusNetworks/Ansible-misp`](https://github.com/StamusNetworks/Ansible-misp)

使用现有的 Ansible playbooks 设置 MISP 就像克隆存储库并更新所需更改和配置的变量一样简单。在执行 playbook 之前，请确保更新变量：

```
$ git clone https://github.com/StamusNetworks/Ansible-misp.git
$ cd Ansible-misp
$ Ansible-playbook -i hosts misp.yaml
```

# MISP Web 用户界面

以下是 MISP 虚拟机的 Web 界面。以下是 MISP 虚拟机的默认凭据：

```
For the MISP web interface -> admin@admin.test:admin
For the system -> misp:Password1234
```

以下截图是**恶意软件信息共享平台**（**MISP**）的主页，带有登录面板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/e83ca3e2-9b9f-4e7e-8266-2f15311fbee6.png)

以下截图是 MISP 平台网页界面的主界面，包含了共享 IOCs、添加组织和执行访问控制等功能选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/724103e4-ddba-4dfc-8195-08e1fc8da6bf.png)

通过阅读 MISP 的文档了解不同的功能，可在 [`www.circl.lu/doc/misp/`](https://www.circl.lu/doc/misp/) 找到更多信息。

# 设置 Viper - 二进制管理和分析框架

**Viper**（[`viper.li`](http://viper.li)）是一个专为恶意软件和漏洞研究人员设计的框架。它提供了一个简单的解决方案，可以轻松地组织恶意软件和漏洞样本的集合。它为研究人员提供了 CLI 和 Web 界面，用于对二进制文件和恶意软件样本进行分析。

以下 playbook 将设置整个 Viper 框架。 它有两个角色，一个是设置运行 Viper 框架所需的依赖项，另一个是主要设置：

```
- name: Setting up Viper - binary management and analysis framework
  hosts: viper
  remote_user: ubuntu
  become: yes

  roles:
    - dependencies
    - setup
```

以下代码片段是用于设置依赖项和其他所需软件包的：

```
- name: installing required packages
  apt:
    name: "{{ item }}"
    state: present
    update_cache: yes

  with_items:
    - gcc
    - python-dev
    - python-pip
    - libssl-dev
    - swig

- name: downloading ssdeep release
  unarchive:
    src: https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz
    dest: /tmp/
    remote_src: yes

- name: copy ssdeep setup script
  template:
    src: ssdeep.sh
    dest: /tmp/ssdeep.sh
    mode: 0755

- name: installing ssdeep
  shell: /tmp/ssdeep.sh
  ignore_errors: yes

- name: installing core dependencies
  pip:
    name: "{{ item }}"
    state: present

  with_items:
    - SQLAlchemy
    - PrettyTable
    - python-magic
    - pydeep
```

在这里，我们正在使用自定义 shell 脚本来设置`ssdeep`，它必须执行编译和构建：

```
#!/bin/bash

cd /tmp/ssdeep-2.14.1
./configure
./bootstrap
make
make install
```

设置角色将安装 Viper 软件包，所需的依赖项，并将启动 web 服务器以访问 Viper web 用户界面：

```
- name: downloading the release
  unarchive:
    src: https://github.com/viper-framework/viper/archive/v1.2.tar.gz
    dest: /opt/
    remote_src: yes

- name: installing pip dependencies
  pip:
    requirements: /opt/viper-1.2/requirements.txt

- name: starting viper webinterface
  shell: nohup /usr/bin/python /opt/viper-1.2/web.py -H 0.0.0.0 &
  ignore_errors: yes

- debug:
    msg: "Viper web interface is running at http://{{ inventory_hostname }}:9090"
```

以下截图指的是 Viper 框架设置的 playbook 执行。并返回 web 界面 URL 以进行访问：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/8fa9f79e-ba57-4e72-b49f-506b86b25e3c.png)

如果我们导航到`http://192.18.33.22:9090`，我们可以看到具有许多选项的 web 界面以使用此框架：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/daa31818-eebe-4a20-85e3-941154de6423.png)

以下截图是我们分析的示例恶意软件的输出。此 Viper 框架还具有 YARA 规则集，VirusTotal API 和其他模块的模块支持，可以根据用例执行深度分析：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/2808eb26-b1dd-42fc-92de-906acba6584e.png)

# 为收集和存储创建 Ansible playbook，同时安全备份取证工件

Ansible 是各种 bash 脚本的合适替代品。通常，对于大多数需要分析的活动，我们遵循一套固定模式：

1.  收集正在运行的进程的日志到已知路径的文件中

1.  定期将这些日志文件的内容复制到本地安全存储区或通过 SSH 或网络文件共享远程访问

1.  成功复制后，旋转日志

由于涉及一些网络活动，我们的 bash 脚本通常编写为在网络连接方面具有容错性并很快变得复杂。 Ansible playbook 可以用于执行所有这些操作，同时对每个人都很容易阅读。

# 收集用于事件响应的日志工件

事件响应中的关键阶段是**日志分析**。以下 playbook 将收集所有主机的日志并将其存储到本地。这使得响应者可以进行进一步分析：

```
# Reference https://www.Ansible.com/security-automation-with-Ansible

- name: Gather log files
  hosts: servers
  become: yes

  tasks:
    - name: List files to grab
      find:
        paths:
          - /var/log
        patterns:
          - '*.log*'
        recurse: yes
      register: log_files

    - name: Grab files
      fetch:
        src: "{{ item.path }}"
        dest: "/tmp/LOGS_{{ Ansible_fqdn }}/"
      with_items: "{{ log_files.files }}"
```

以下 playbook 执行将使用 Ansible 模块在远程主机中的指定位置收集日志列表，并将其存储在本地系统中。 playbook 的日志输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/009d900e-d9dd-456e-8c0d-3ad27595a725.png)

# 数据收集的安全备份

当从服务器中收集多组数据时，将其安全地存储并进行加密备份至关重要。这可以通过将数据备份到 S3 等存储服务来实现。

以下 Ansible playbook 允许我们安装并将收集的数据复制到启用了加密的 AWS S3 服务中：

```
- name: backing up the log data
  hosts: localhost
  gather_facts: false
  become: yes
  vars:
    s3_access_key: XXXXXXX # Use Ansible-vault to encrypt
    s3_access_secret: XXXXXXX # Use Ansible-vault to encrypt
    localfolder: /tmp/LOGS/ # Trailing slash is important
    remotebucket: secretforensicsdatausingAnsible # This should be unique in s3

  tasks:
    - name: installing s3cmd if not installed
      apt:
        name: "{{ item }}"
        state: present
        update_cache: yes

      with_items:
        - python-magic
        - python-dateutil
        - s3cmd

    - name: create s3cmd config file
      template:
        src: s3cmd.j2
        dest: /root/.s3cfg
        owner: root
        group: root
        mode: 0640

    - name: make sure "{{ remotebucket }}" is avilable
      command: "s3cmd mb s3://{{ remotebucket }}/ -c /root/.s3cfg"

    - name: running the s3 backup to "{{ remotebucket }}"
      command: "s3cmd sync {{ localfolder }} --preserve s3://{{ remotebucket }}/ -c /root/.s3cfg"
```

`s3cmd`配置的配置文件如下所示：

```
[default]
access_key = {{ s3_access_key }}
secret_key = {{ s3_access_secret }}
host_base = s3.amazonaws.com
host_bucket = %(bucket)s.s3.amazonaws.com
website_endpoint = http://%(bucket)s.s3-website-%(location)s.amazonaws.com/
use_https = True
signature_v2 = True
```

以下截图是上传数据到 S3 存储桶的 Ansible playbook 执行：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/ea83bd32-edb8-4955-b8e5-888bc36e5f1c.png)

前面的屏幕截图显示了 Ansible 播放书安装`S3cmd`，创建了名为`secretforensicsdatausingAnsible`的新桶，并将本地日志数据复制到远程 S3 存储桶。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/11e06805-87c5-4129-a36d-942dfb4d18e0.png)

前面的屏幕截图是播放书的结果。我们可以看到日志已成功上传到 AWS S3 中的`secretforensicsdatausingAnsible` S3 存储桶中。

# 摘要

能够自动化用于恶意软件分析的各种工作流程，使我们能够扩展分析恶意软件的数量以及进行此类大规模分析所需的资源。这是解决每天在互联网上释放的恶意软件洪流并创建有用的防御措施的一种方式。

在下一章中，我们将继续创建一个用于安全测试的 Ansible 模块。我们将从理解基础知识开始，逐步学习创建模块，并利用 OWASP ZAP 的 API 来扫描网站。到本章结束时，您将拥有一个完整的模块，可用于 Ansible CLI 或 Ansible 播放书。


# 第十章：为安全测试编写 Ansible 模块

Ansible 主要通过将小块代码推送到其连接的节点来工作。这些代码/程序就是我们所知的 Ansible 模块。通常在 Linux 主机的情况下，这些代码通过 SSH 复制，执行，然后从节点中删除。

正如 Ansible 开发人员指南中所述（这是所有与 Ansible 相关事物的最佳资源）：

"Ansible 模块可以用任何可以返回 JSON 的语言编写。"

模块可以由 Ansible 命令行，在 playbook 中或通过 Ansible API 使用。Ansible 版本 2.4.x 已经内置了数百个模块。

查看 Ansible 文档网站上的模块索引：[`docs.ansible.com/ansible/latest/modules_by_category.html`](http://docs.ansible.com/ansible/latest/modules_by_category.html)。

目前，模块有 20 多个类别，包括云、存储、远程管理和 Windows 等类别。

有时候，尽管有了所有这些模块，您可能仍然需要编写自己的模块。本章将带您编写一个可以与 Ansible playbook 一起使用的模块。

Ansible 有一个非常详细的开发指南（[`docs.ansible.com/ansible/latest/dev_guide/index.html`](http://docs.ansible.com/ansible/latest/dev_guide/index.html)），如果您计划贡献您的模块以与 Ansible 一起发布，这是开始的最佳位置。

本章完全不打算取代它。考虑到，如果您计划为内部使用编写模块，并且您不介意分发它们，那么本章为您提供了一个简单易行的路径，我们最终将获得一个可用的模块，用于启用安全自动化，这一直是我们的目标。

我们将研究以下内容：

+   如何设置开发环境

+   编写一个 Ansible hello world 模块以了解基础知识

+   寻求进一步帮助的地方

+   定义一个安全问题陈述

+   通过编写我们自己的模块来解决这个问题

除此之外，我们将尝试理解并试图回答以下问题：

+   模块的良好使用案例是什么？

+   何时使用角色才有意义？

+   模块与插件有何不同？

让我们从一个简单的 hello world 模块开始。

# 开始使用一个简单的 hello world Ansible 模块

我们将向自定义模块传递一个参数，并根据此参数的执行情况显示模块执行成功或失败。

由于这一切对我们来说都是新的，我们将查看以下内容：

+   hello world 模块的源代码

+   该模块的成功和失败输出

+   我们将用来调用它的命令

在我们开始之前，所有这些都基于 Ansible 开发人员指南！以下代码是用 Python 编写的。

# 代码

我们在许多脚本任务中使用 Python，但我们并不是专家。但我们相信这段代码足够简单易懂：

```
from ansible.module_utils.basic import AnsibleModule

module = AnsibleModule(
    argument_spec=dict(
        answer=dict(choices=['yes', 'no'], default='yes'),
    )
)

answer = module.params['answer']
if answer == 'no':
    module.fail_json(changed=True, msg='Failure! We failed because we answered no.')

module.exit_json(changed=True, msg='Success! We passed because we answered yes.')
```

1.  我们正在导入一些模块。

1.  第二部分只是我们需要声明模块将接受的参数。

1.  在我们的代码中，我们可以引用参数的方式就像我们取得了 `answer` 变量的值一样。

1.  基于答案，如果是 `no`，我们表示失败。

1.  如果答案是 `yes`，我们表示成功。

让我们看看如果我们提供答案为 `yes` 时的输出是什么样子：

```
$ ANSIBLE_LIBRARY=. ansible -m ansible_module_hello_world.py -a answer=yes localhost

 [WARNING]: provided hosts list is empty, only localhost is available

localhost | SUCCESS => {
    "changed": true,
    "msg": "Success! We passed because we answered yes."
}
```

如果答案是 `no`：

```
$ ANSIBLE_LIBRARY=. ansible -m ansible_module_hello_world -a answer=no localhost

 [WARNING]: provided hosts list is empty, only localhost is available

localhost | FAILED! => {
    "changed": true,
    "failed": true,
    "msg": "Failure! We failed because we answered no."
}
```

输出中的主要区别是指示的 `SUCCESS` 或 `FAILED` 状态以及我们提供的消息。

由于到目前为止我们还没有设置开发环境，所以我们为此命令设置了一个环境变量：

+   `ANSIBLE_LIBRARY=.` 表示在当前目录中搜索要执行的模块

+   使用 `-m`，我们调用我们的模块

+   使用 `-a`，我们传递模块参数，在这种情况下是可能值为 `yes` 或 `no`

+   我们以我们要在其上运行模块的主机结束，对于此示例，它是本地的

尽管 Ansible 是用 Python 编写的，请注意模块可以用任何能够返回 JSON 消息的语言编写。对于 Ruby 程序员来说，一个很好的起点是 Github 上的 Ansible for Rubyists ([`github.com/ansible/ansible-for-rubyists`](https://github.com/ansible/ansible-for-rubyists)) 仓库。Packt 出版的《Learning Ansible》第五章也涵盖了这一点。

# 设置开发环境

Ansible 2.4 的主要要求是 Python 2.6 或更高版本和 Python 3.5 或更高版本。如果你安装了其中之一，我们可以按照简单的步骤进行开发环境设置。

来自 Ansible 开发者指南：

1.  克隆 Ansible 仓库：`$ git clone https://github.com/ansible/ansible.git`

1.  切换到仓库根目录：`$ cd ansible`

1.  创建虚拟环境：`$ python3 -m venv venv`（或对于 Python 2 `$ virtualenv venv`

1.  注意，这需要你安装 `virtualenv` 包：`$ pip install virtualenv`

1.  激活虚拟环境：`$ . venv/bin/activate`

1.  安装开发要求：`$ pip install -r requirements.txt`

1.  对每个新的 dev shell 进程运行环境设置脚本：`$ . hacking/env-setup`

此时你应该得到一个 `venv` 提示符。以下是设置开发环境的一个简单 Playbook。

以下 Playbook 将通过安装和设置虚拟环境来设置开发环境：

```
- name: Setting Developer Environment
  hosts: dev
  remote_user: madhu
  become: yes
  vars:
    ansible_code_path: "/home/madhu/ansible-code"

  tasks:
    - name: installing prerequirements if not installed
      apt:
        name: "{{ item }}"
        state: present
        update_cache: yes

      with_items:
        - git
        - virtualenv
        - python-pip

    - name: downloading ansible repo locally
      git:
        repo: https://github.com/ansible/ansible.git
        dest: "{{ ansible_code_path }}/venv"

    - name: creating virtual environment
      pip:
        virtualenv: "{{ ansible_code_path }}"
        virtualenv_command: virtualenv
        requirements: "{{ ansible_code_path }}/venv/requirements.txt"
```

以下屏幕截图显示了使用 Python 虚拟环境编写自己的 Ansible 模块设置开发环境的 Playbook 执行：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/af498854-8518-42d4-a369-b6ce26748db6.png)

# 计划和需要注意的事项

Ansible 开发者指南中有一个关于如何开发模块的部分 ([`docs.ansible.com/ansible/latest/dev_guide/developing_modules.html#should-you-develop-a-module`](http://docs.ansible.com/ansible/latest/dev_guide/developing_modules.html#should-you-develop-a-module)).

在该部分中，他们有多个关于继续开发模块前需要注意的要点。

是否已经存在类似的模块？检查当前的模块是否已经做了你计划构建的事情总是一个好主意。好消息是，到目前为止还没有人建立一个**开放式 Web 应用程序安全项目**（**OWASP**）**Zed Attack Proxy**（**ZAP**）模块。

是否有人已经在类似的 *Pull Request* 上工作？再次强调，也许这个模块还没有发布，但这并不意味着人们还没有在上面工作。文档提供了三个方便的链接，以检查是否已经有类似的 PR 存在。

另外，它询问是否应该查看一个动作插件或角色，而不是一个模块。我们认为开发模块对我们来说是有道理的主要原因是它将在节点上运行。如果 ZAP 已经在运行，ZAP 提供了一个 API 端点，我们打算让我们的模块可以方便地在托管的 ZAP 实例上运行 ZAP 扫描。

所以，现在的计划是：

1.  创建一个模块，将连接到托管的 ZAP 实例。

1.  为模块提供两个主要信息：

    +   托管 ZAP 的 IP 地址

    +   扫描目标 URL

1.  通过调用该模块，我们将有一个任务来扫描目标应用程序。

# OWASP ZAP 模块

OWASP ZAP 有一个我们可以使用的 API。此外，有一个用于消费 API 的 Python 模块。我们将尝试使用它来学习如何编写自己的 Ansible 模块。

# 使用 Docker 创建 ZAP

对于我们的开发，让我们使用一个 Docker 容器来启动 ZAP。由于我们计划使用 API，我们将在无头模式下运行容器：

```
$ docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
```

命令的解释

+   当我们进行开发时，我们可以禁用 API 密钥：`-config api.disablekey=true`

+   允许从任何 IP 访问 API：`-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true`

+   监听端口 `8080`

如果一切正常，你将看到以下输出：

**![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/0d732a52-b810-4d6a-8556-1d7b093f9cb6.png)**

# 创建一个易受攻击的应用程序

对于一个易受攻击的应用程序，我们可以托管一个自己的，但让我们使用同一个在线易受攻击的应用程序，我们在 第五章 中用于 OWASP ZAP + Jenkins 集成的：*自动化* *Web 应用程序安全测试使用 OWASP ZAP - *[`testphp.vulnweb.com/`](http://testphp.vulnweb.com/)

# Ansible 模块模板

我们将使用模块开发指南中给出的示例代码来开始：[`docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html#new-module-development`](http://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html#new-module-development)。

这个模板有一个注释齐全的代码，写得让我们很容易开始。代码分为以下几部分：

+   元数据

+   文档化模块

+   我们将要使用的函数

# 元数据

这个部分包含有关模块的信息：

```
ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}
```

这个模块没有官方支持，因此使用了 `community`。

# 文档化模块

模块文档是从模块代码本身生成的。 现在创建的模块必须有 `DOCUMENTATION` 文档字符串。

开始的最简单方法是查看此示例：[`github.com/ansible/ansible/blob/devel/examples/DOCUMENTATION.yml`](https://github.com/ansible/ansible/blob/devel/examples/DOCUMENTATION.yml)。

此处所需的字段清单为：

+   `module`：模块名称

+   `short_description`：简短描述

+   `description`：描述

+   `version_added`：由 `X.Y` 指示

+   `author`：您的姓名和 Twitter/GitHub 用户名

+   `options`：模块支持的每个选项

+   `notes`：模块用户应该注意的任何其他事项

+   `requirements`：我们列出额外的包要求

有关字段的更多详细信息，请访问[`docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#fields`](http://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#fields)。

# 源代码模板

这里有一些我们将用来编写模块的源代码片段。我们已经讨论了元数据和文档部分。我们还需要为示例和模块将返回的内容编写文档字符串。

我们的导入模块 - 我们可以在这里导入构建模块所需的所有模块：

```
from ansible.module_utils.basic import AnsibleModule
```

主要代码块 - 在函数 `run_module` 中，我们进行以下工作：

1.  定义模块正常工作所需的所有参数。

1.  初始化结果字典。

1.  创建 `AnsibleModule` 对象并传递可能需要的公共属性：

```
def run_module():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        name=dict(type='str', required=True),
        new=dict(type='bool', required=False, default=False)
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
```

1.  处理异常和结果：

```
 # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    if module.params['name'] == 'fail me':
        module.fail_json(msg='You requested this to fail', **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)
```

只需记住以下几点：

+   如果遇到任何错误或异常，我们调用 `AnsibleModule` 对象的 `fail_json` 函数

+   如果一切顺利，我们调用相同对象的 `exit_json` 函数

调用我们的功能完成代码：

```
def main():
    run_module()

if __name__ == '__main__':
    main()
```

目前，我们已经准备好了以下工作，并准备进行下一步：

| 模块代码模板 | 就绪 |
| --- | --- |
| 我们需要扫描的易受攻击应用程序（目标） | 就绪 |
| 启用 API 并在无头模式下运行的 OWASP ZAP 代理（主机和端口） | 就绪 |
| 我们可以参考的 OWASP ZAP Python API 代码 | 待定 |

我们希望专注于编写 Ansible 模块，而不是花时间学习完整的 OWASP ZAP API。虽然我们建议您这样做，但等到模块正常工作后再学习也可以。

# OWASP ZAP Python API 示例脚本

OWASP ZAP Python API 包带有一个非常实用的脚本，完整涵盖了对 Web 应用程序进行爬行和主动扫描的代码。

从[`github.com/zaproxy/zaproxy/wiki/ApiPython#an-example-python-script`](https://github.com/zaproxy/zaproxy/wiki/ApiPython#an-example-python-script)下载代码进行学习。

这里有一些我们目前感兴趣的样本代码片段。 导入用于 OWASP ZAP 的 Python API 客户端。 这通过 `pip install python-owasp-zap-v2.4` 安装：

```
from zapv2 import ZAPv2
```

现在，我们连接到 ZAP 实例 API 端点。我们可以将主机和端口提供给我们模块的 OWASP ZAP 实例作为参数：

```
zap = ZAPv2(apikey=apikey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})
```

提供我们想要扫描的网站的主机/IP 地址：

```
zap.urlopen(target)
# Give the sites tree a chance to get updated
time.sleep(2)

print 'Spidering target %s' % target
scanid = zap.spider.scan(target)

# Give the Spider a chance to start
time.sleep(2)
while (int(zap.spider.status(scanid)) < 100):
    print 'Spider progress %: ' + zap.spider.status(scanid)
    time.sleep(2)

print 'Spider completed'
# Give the passive scanner a chance to finish
time.sleep(5)

print 'Scanning target %s' % target
scanid = zap.ascan.scan(target)
while (int(zap.ascan.status(scanid)) < 100):
    print 'Scan progress %: ' + zap.ascan.status(scanid)
    time.sleep(5)

print 'Scan completed'

# Report the results

print 'Hosts: ' + ', '.join(zap.core.hosts)
print 'Alerts: '
pprint (zap.core.alerts())
```

此代码是我们在模块中使用的一个很好的起始模板。

在这里，我们准备好了可以参考的 OWASP ZAP Python API 代码。

连接到 ZAP 实例。此时，我们复制了代码的重要部分，即：

1.  连接到目标。

1.  启动爬虫和主动安全扫描。

但是我们很快遇到了一个错误。在异常期间我们返回了一个字符串，这显然不符合 Ansible 所需的 JSON 格式。

这导致了一个错误，我们没有足够的信息来采取行动

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/e219ede6-f722-42bf-8e27-51d241f642c9.png)

Ansible 模块应该只返回 JSON，否则您可能会看到像上面那样的难以理解的错误

在[`docs.ansible.com/ansible/latest/dev_guide/developing_modules_best_practices.html#conventions-best-practices-and-pitfalls`](http://docs.ansible.com/ansible/latest/dev_guide/developing_modules_best_practices.html#conventions-best-practices-and-pitfalls)中快速阅读惯例、最佳实践和陷阱为我们解释了问题。

如果您在编写模块过程中遇到任何问题，我们强烈建议您阅读本指南：[`docs.ansible.com/ansible/latest/dev_guide/developing_modules_best_practices.html#conventions-best-practices-and-pitfalls`](http://docs.ansible.com/ansible/latest/dev_guide/developing_modules_best_practices.html#conventions-best-practices-and-pitfalls)。

使用 OWASP ZAP API 文档来了解更多信息：[`github.com/zaproxy/zaproxy/wiki/ApiGen_Index`](https://github.com/zaproxy/zaproxy/wiki/ApiGen_Index)。

# 完整的代码清单

此代码也可以在 GitHub 上找到（[`github.com/appsecco/ansible-module-owasp-zap`](https://github.com/appsecco/ansible-module-owasp-zap)）。所有注释、元数据和文档字符串都已从此列表中删除：

```
try: 
    from zapv2 import ZAPv2
    HAS_ZAPv2 = True
except ImportError:
    HAS_ZAPv2 = False 

from ansible.module_utils.basic import AnsibleModule
import time
def run_module():
    module_args = dict(
        host=dict(type='str', required=True),
        target=dict(type='str', required=True)
    )

    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if not HAS_ZAPv2:
        module.fail_json(msg = 'OWASP python-owasp-zap-v2.4 required. pip install python-owasp-zap-v2.4')

if module.check_mode:
    return result
host = module.params['host']
target = module.params['target']
apikey = None
zap = ZAPv2(apikey=apikey, proxies={'http':host,'https':host})
zap.urlopen(target)
try:
    scanid = zap.spider.scan(target)
    time.sleep(2)
    while (int(zap.spider.status(scanid)) < 100):
        time.sleep(2)
except:
    module.fail_json(msg='Spidering failed')
time.sleep(5)

try:
    scanid = zap.ascan.scan(target)
    while (int(zap.ascan.status(scanid)) < 100):
        time.sleep(5)
except:
    module.fail_json(msg='Scanning failed')

result['output'] = zap.core.alerts()
result['target'] = module.params['target']
result['host'] = module.params['host']
module.exit_json(**result)

def main():
    run_module()
if __name__ == '__main__':
    main()
```

根据被爬取和扫描的网站不同，这可能需要一些时间来完成。在执行结束时，您将在`results['output']`中获得扫描结果。

# 运行模块

我们运行模块的选择如下：

1.  我们将其复制到 Ansible 库的标准路径。

1.  每当我们有我们的模块文件时，我们都会提供一个路径到 Ansible 库。

1.  通过 playbook 运行此文件。

以下命令将调用我们的模块以供我们测试并查看结果：

```
ansible -m owasp_zap_test_module localhost -a "host=http://172.16.1.102:8080 target=http://testphp.vulnweb.com" -vvv
```

命令的解释

+   `ansible`命令行

+   `-m`用于提供模块名称，即`owasp_zap_test_module`

+   它将在`localhost`上运行

+   `-a`允许我们传递`host`和`target`模块参数

+   `-vvv` 用于输出的详细程度。

# 模块的 playbook

这是一个简单的 playbook，用于测试一切是否正常运行：

```
- name: Testing OWASP ZAP Test Module
  connection: local
  hosts: localhost
  tasks:
  - name: Scan a website
    owasp_zap_test_module:
      host: "http://172.16.1.102:8080"
      target: "http://testphp.vulnweb.com"
```

使用此命令执行 playbook：

```
ansible-playbook owasp-zap-site-scan-module-playbook.yml
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/sec-auto-asb2/img/260d3644-61a1-49df-8b52-50b8310868ba.png)

重要的一点要记住的是，仅仅因为我们有一个可用的模块，并不意味着 Ansible 的优秀工程师们会自动接受我们的模块并将其随软件的下一个版本一起发布。我们的模块要能够被所有人使用，还需要进行大量的额外工作。

通常，最好的指南是本章前面提到的开发人员指南。

我们的模块中可以添加的一个简单的功能是能够将 API 密钥作为参数发送。大多数用于常规扫描的 ZAP 实例已经配置了这个。此外，当在 playbook 中存储时，此密钥可以由 Ansible vault 保护。

# 添加 API 密钥作为参数

只需做出以下更改，我们就能够将`apikey`添加为一个参数：

+   首先，我们将其添加到第 76-78 行的`module_args`字典中：`apikey=dict(type='str',required=False,default=None)`

+   然后，我们检查 `module.params['apikey']` 是否设置为`None`的值

+   如果不是，将其设置为 `apikey = module.params['apikey']`

+   现在，如果模块与 Ansible 命令行工具一起使用，请将其与 `target` 和 `host` 一起传递，如果在 playbook 中使用，请在那里传递

# 将扫描类型添加为参数

如果你迄今为止一直在跟进，你可能意识到我们运行的扫描是一个主动扫描。扫描器会对目标发送攻击流量进行主动扫描。

由于这个事实，有时如果网站很大，完成可能需要很长时间。

有关主动扫描的更多信息，请访问[`github.com/zaproxy/zap-core-help/wiki/HelpStartConceptsAscan`](https://github.com/zaproxy/zap-core-help/wiki/HelpStartConceptsAscan)。

我们希望添加一个参数，以便能够提供要运行的扫描类型。到目前为止，我们有两种类型：

+   **主动**：发送攻击流量

+   **被动扫描**：在蜘蛛爬取阶段下载的所有站点文件都会被解析

我们首先将其作为`module_args`的一部分添加：

```
module_args = dict(
    host=dict(type='str', required=True),
    target=dict(type='str', required=True),
    apikey=dict(type='str',required=False,default=None),
    scantype=dict(default='passive', choices=['passive','active'])
)
```

新添加的行已加粗以突出显示更改。请注意，我们现在定义了默认值，并且当前只允许这个参数有两个选择。因此，如果未设置任何值，则执行更快、更少侵入性的被动扫描。

我们需要将模块参数的值放入名为`scantype`的变量中：

```
scantype = module.params['scantype']
```

现在逻辑改变以适应两个可能的值：

```
if scantype == 'active':
    try:
        scanid = zap.ascan.scan(target)
        while (int(zap.ascan.status(scanid)) < 100):
            time.sleep(5)
    except:
        module.fail_json(msg='Active Scan Failed')
else:
    try:
        while (int(zap.pscan.records_to_scan) > 0):
            time.sleep(2)
    except:
        module.fail_json(msg='Passive Scan Failed')
```

如果`scantype`已设置且值为`active`，那么它才会进行主动扫描。这个改进使我们的模块更加灵活：

```
Using the new and improved module in our playbook
- name: Testing OWASP ZAP Test Module
  connection: local
  hosts: localhost
  tasks:
  - name: Scan a website
    owasp_zap_test_module:
      host: "http://172.16.1.102:8080"
      target: "http://testphp.vulnweb.com"
      scantype: passive
    register: output
  - name: Print version
    debug:
      msg: "Scan Report: {{ output }}"
```

# 使用 Ansible 作为 Python 模块

直接在您的 Python 代码中使用 Ansible 是一种与其交互的强大方式。请注意，使用 Ansible 2.0 及更高版本时，这并不是最简单的方法。

在继续之前，我们应该告诉你核心 Ansible 团队对直接使用 Python API 的看法

从 http://docs.ansible.com/ansible/latest/dev_guide/developing_api.html

请注意，虽然我们提供了此 API，但它不适用于直接使用，它在这里是为了支持 Ansible 命令行工具。我们尽量不会进行破坏性更改，但如果对 Ansible 工具集有意义，我们保留随时进行更改的权利。

以下文档提供给那些仍然希望直接使用 API 的人，但请注意，这不是 Ansible 团队支持的内容。

以下代码来自 Ansible 开发者指南文档：[`docs.ansible.com/ansible/latest/dev_guide/developing_api.html`](http://docs.ansible.com/ansible/latest/dev_guide/developing_api.html)：

```
import json
from collections import namedtuple
from ansible.parsing.dataloader import DataLoader
from ansible.vars.manager import VariableManager
from ansible.inventory.manager import InventoryManager
from ansible.playbook.play import Play
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.plugins.callback import CallbackBase
```

一旦所有的初始工作都完成了，任务将会这样执行：

```
try</span>:
    tqm = TaskQueueManager(
              inventory=inventory,
              variable_manager=variable_manager,
              loader=loader,
              options=options,
              passwords=passwords,
              stdout_callback=results_callback,  # Use our custom callback instead of the ``default`` callback plugin
          )
    result = tqm.run(play)
```

在 Ansible 2.0 之前，整个过程要简单得多。但是这段代码现在不再适用了：

```
import ansible.runner

runner = ansible.runner.Runner(
   module_name='ping',
   module_args='',
   pattern='web*',
   forks=10
)
datastructure = runner.run()
```

# 总结

在这一章中，我们创建了一个用于安全自动化的工作中的 Ansible 模块。我们首先创建了一个类似于 hello world 的模块，虽然功能不多，但帮助我们理解了一个模块文件可能是什么样子的布局。我们按照 Ansible 开发者指南的说明设置了一个能够进行模块开发的环境。我们阐述了我们对模块的需求，并选择了 OWASP ZAP 作为创建模块的可能候选者。

使用开发者文档中的模板等辅助工具，我们创建了该模块，并学习了如何使用 Ansible CLI 或 playbook 使用它。我们在原始代码中添加了几个选项，以使模块更加实用和灵活。现在我们有了一个能够连接到任何允许使用 API 密钥访问并在目标上执行被动或主动扫描的 OWASP ZAP Ansible 模块。

这是本书的倒数第二章。在下一章中，我们将查看额外的参考资料，使用 Ansible Vault 保护我们的机密信息，以及一些已经使用 Ansible 实现的世界级安全自动化的参考资料。
