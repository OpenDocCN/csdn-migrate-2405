# Ansible 学习手册（六）

> 原文：[`zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5`](https://zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：使用 Ansible 和 OpenSCAP 加固您的服务器

使用像 Ansible 这样的编排和配置工具的优势之一是，它可以用于在许多主机上生成和部署一组复杂的配置，以便重复执行。在本章中，我们将看一下一个实际上为您生成配置然后应用的工具。

在本章中，我们将学习如何使用 Ansible 和 OpenSCAP 加固基于 Red Hat 的 CentOS 7.5.1804 主机。

# 技术要求

我们将针对运行 CentOS Linux 发行版 7.5.1804 的 Vagrant 虚拟机进行操作；我们使用这个虚拟机是因为它配备了最新版本的 OpenSCAP。最终 playbooks 的副本可以在本书附带的存储库中找到；存储库位于[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter13/scap`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter13/scap)。

# OpenSCAP

我们将研究由 Red Hat 维护的一组工具之一，名为 OpenSCAP。在继续之前，我觉得我应该警告您，下一节将包含大量缩写，从 SCAP 开始。

那么，什么是 SCAP？**安全内容自动化协议**（**SCAP**）是一个开放标准，包括几个组件，所有这些组件本身都是开放标准，用于构建一个框架，允许您自动评估和纠正您的主机针对**国家标准与技术研究所**（**NIST**）特刊 800-53。

这本出版物是一个控制目录，适用于所有美国联邦 IT 系统，除了由**国家安全局**（**NSA**）维护的系统。这些控制措施已经被制定，以帮助在美国联邦部门实施 2002 年**联邦信息安全管理法**（**FISMA**）。

SCAP 由以下组件组成：

+   **资产识别**（**AID**）是用于资产识别的数据模型。

+   **资产报告格式**（**ARF**）是一个供应商中立和技术不可知的数据模型，用于在不同的报告应用程序和服务之间传输资产信息。

+   **常见配置枚举**（**CCE**）是一个标准数据库，用于常见软件的推荐配置。每个建议都有一个唯一的标识符。在撰写本文时，该数据库自 2013 年以来尚未更新。

+   **常见配置评分系统**（**CCSS**）是 CCE 的延续。它用于为各种软件和硬件配置生成得分，涵盖所有类型的部署。

+   **常见平台枚举**（**CPE**）是一种识别组织基础设施中的硬件资产、操作系统和软件的方法。一旦识别，这些数据可以用于搜索其他数据库以评估资产的威胁。

+   **常见弱点枚举**（**CWE**）是一种处理和讨论系统架构、设计和代码中可能导致漏洞的弱点原因的通用语言。

+   **常见漏洞和暴露**（**CVE**）是一个公开承认的漏洞数据库。大多数系统管理员和 IT 专业人员在某个时候都会遇到 CVE 数据库。每个漏洞都有一个唯一的 ID；例如，大多数人都会知道 CVE-2014-0160，也被称为**心脏出血**。

+   **常见漏洞评分系统**（**CVSS**）是一种帮助捕捉漏洞特征以产生标准化数值评分的方法，然后可以用于描述漏洞的影响，例如低、中、高和关键。

+   **可扩展配置清单描述格式**（**XCCDF**）是一种描述安全清单的 XML 格式。它也可以用于配置和基准，并为 SCAP 的所有部分提供一个通用语言。

+   **开放式清单交互语言**（**OCIL**）是一个用于向最终用户提出问题以及以标准化方式处理响应程序的框架。

+   **开放式漏洞评估语言**（**OVAL**）以 XML 形式定义，旨在标准化 NIST、MITRE 公司、**美国计算机紧急应对小组**（**US-CERT**）和美国**国土安全部**（**DHS**）提供的所有工具和服务之间的安全内容传输。

+   **安全自动化数据信任模型**（**TMSAD**）是一个旨在定义一个通用信任模型的 XML 文档，可应用于构成 SCAP 的所有组件交换的数据。

您可以想象，SCAP 及其基础组件的开发已经耗费了数千人年。其中一些项目自 90 年代中期以来一直存在，因此它们已经得到了很好的建立，并被认为是安全最佳实践的事实标准；但是，我相信您会认为这一切听起来非常复杂——毕竟，这些是由学者、安全专业人员和政府部门定义和维护的标准。

这就是 OpenSCAP 的用武之地。由 Red Hat 维护的 OpenSCAP 项目还获得了 NIST 对其支持 SCAP 1.2 标准的认证，它允许您使用命令行客户端应用我们讨论的所有最佳实践。

与许多 Red Hat 项目一样，OpenSCAP 正在获得对 Ansible 的支持，当前版本引入了自动生成 Ansible playbook 以修复 OpenSCAP 扫描中发现的不符合规范的支持。

当前版本的 OpenSCAP 中的自动修复脚本还在不断改进中，存在已知问题，我们将在本章末解决这些问题。因此，您的输出可能与本章中介绍的内容有所不同。

在接下来的章节中，我们将启动一个 CentOS 7.5.1804 Vagrant box，对其进行扫描，并生成修复 playbook。由于 playbook 支持刚刚被引入，因此修复的覆盖率还不到 100%，因此我们将再次扫描主机，然后使用 Ansible 生成修复的 bash 脚本，并在主机上执行它，然后再次执行扫描，以便比较所有三次扫描的结果。

# 准备主机

在开始扫描之前，我们需要一个目标主机，因此让我们快速创建文件夹结构和`Vagrantfile`。要创建结构，请运行以下命令：

```
$ mkdir scap scap/group_vars scap/roles
$ touch scap/Vagrantfile scap/production scap/site.yml scap/group_vars/common.yml
```

我们创建的`scap/Vagrantfile`应该包含以下代码：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
BOX_NAME = "russmckendrick/centos75"
BOX_IP = "10.20.30.40"
DOMAIN = "nip.io"
PRIVATE_KEY = "~/.ssh/id_rsa"
PUBLIC_KEY = '~/.ssh/id_rsa.pub'

Vagrant.configure(API_VERSION) do |config|
  config.vm.box = BOX_NAME
  config.vm.network "private_network", ip: BOX_IP
  config.vm.host_name = BOX_IP + '.' + DOMAIN
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.ssh.insert_key = false
  config.ssh.private_key_path = [PRIVATE_KEY, "~/.vagrant.d/insecure_private_key"]
  config.vm.provision "file", source: PUBLIC_KEY, destination: "~/.ssh/authorized_keys"

  config.vm.provider "virtualbox" do |v|
    v.memory = "2024"
    v.cpus = "2"
  end

  config.vm.provider "vmware_fusion" do |v|
    v.vmx["memsize"] = "2024"
    v.vmx["numvcpus"] = "2"
  end

end
```

这意味着主机清单文件`scap/production`应包含以下内容：

```
box1 ansible_host=10.20.30.40.nip.io

[scap]
box1

[scap:vars]
ansible_connection=ssh
ansible_user=vagrant
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False 
```

我们可以使用以下命令之一启动 Vagrant box：

```
$ vagrant up
$ vagrant up --provider=vmware_fusion
```

现在我们的目标主机已准备就绪，我们可以执行初始扫描了。

# playbook

我们将把 playbook 拆分成几个不同的角色。与以往的章节不同，我们将使其中一些角色可重用，并在执行它们时传递参数。我们的第一个角色是一个简单的角色，安装我们运行 OpenSCAP 扫描所需的软件包。

# 安装角色

如前所述，这个第一个角色是一个简单的角色，安装我们运行扫描所需的软件包：

```
$ ansible-galaxy init roles/install
```

我们需要在`roles/install/defaults/main.yml`中设置一些默认值；这些是：

```
install:
  packages:
    - "openscap-scanner"
    - "scap-security-guide"
```

`roles/install/tasks/main.yml`中有一个任务，安装软件包并执行`yum`更新：

```
- name: update all of the installed packages
  yum:
    name: "*"
    state: "latest"
    update_cache: "yes"

- name: install the packages needed
  package:
    name: "{{ item }}"
    state: latest
  with_items: "{{ install.packages }}"
```

这就是这个角色的全部内容；我们将在每次运行扫描时调用它，以确保我们安装了正确的软件包来运行扫描本身。

# 扫描角色

现在我们已经安装了 OpenSCAP 软件包，我们可以创建一个执行扫描的角色：

```
$ ansible-galaxy init roles/scan
```

如前所述，我们将在整个手册中重复使用这个角色，这给我们带来了一个很容易解决的问题。默认情况下，即使你多次定义了角色，Ansible 在手册运行期间也只会执行一次角色。为了允许角色执行多次，我们需要在`roles/scan/meta/main.yml`文件的顶部添加以下行：

```
allow_duplicates: true
```

这指示 Ansible 在手册运行期间多次执行这个角色。接下来，我们需要向`group_vars/common.yml`文件添加一些变量。这些关键值将在我们手册中使用的所有角色之间共享。

```
oscap:
  profile: "xccdf_org.ssgproject.content_profile_pci-dss"
  policy: "ssg-centos7-ds.xml"
  policy_path: "/usr/share/xml/scap/ssg/content/"
```

这些定义了我们想要使用的配置文件和我们想要应用的策略。默认情况下，OpenSCAP 不附带任何策略；这些是通过`scap-security-guide`软件包安装的。该软件包提供了几个策略，所有这些策略都可以在`/usr/share/xml/scap/ssg/content/`中找到；以下终端截图显示了该文件夹的目录列表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/7d4643a7-32c1-4165-a75a-7a56b5158c46.png)

对于我们的手册，我们将使用`ssg-centos7-ds.xml`策略，或者给它一个适当的标题，`PCI-DSS v3 Control Baseline for CentOS Linux 7`。

**支付卡行业数据安全标准**（**PCI-DSS**）是所有主要信用卡运营商都同意的一个标准，任何处理持卡人数据的人都必须遵守该标准。该标准是一组安全控制，由外部审计员或通过自我评估问卷进行审核，具体取决于您处理的交易数量。

以下一组嵌套变量定义了我们将存储扫描生成的各种文件的位置：

```
report:
  report_remote_path: "/tmp/{{ inventory_hostname }}_report_{{ report_name }}.html"
  report_local_path: "generated/{{ inventory_hostname }}_report_{{ report_name }}.html"
  results: "/tmp/{{ inventory_hostname }}_results_{{ report_name }}.xml" 
```

如你所见，我们有 HTML 报告的远程和本地路径。这是因为我们将在手册运行过程中将报告复制到我们的 Ansible 控制器。

现在我们有了共享变量，我们需要在`roles/scan/defaults/main.yml`文件中添加一个单个默认变量：

```
scan_command: >
  oscap xccdf eval --profile {{ oscap.profile }}
    --fetch-remote-resources
    --results-arf {{ report.results }}
    --report {{ report.report_remote_path }}
    {{ oscap.policy_path }}{{ oscap.policy }}
```

这是我们将运行以启动扫描的命令。在撰写本文时，没有任何 OpenSCAP 模块，因此我们需要使用`command`模块执行`oscap`命令。值得注意的是，我已经将命令分成多行放在变量中，以便阅读。

因为我使用了`>`，当应用变量到任务时，Ansible 实际上会将命令呈现为单行，这意味着我们不必像在命令行上运行多行命令时那样在每行末尾添加`\`。

角色的最后部分是任务本身。我们将把所有任务放在`roles/scan/tasks/main.yml`文件中，从执行我们定义的命令的任务开始。

```
- name: run the openscap scan
  command: "{{ scan_command }}"
  args:
    creates: "{{ report.report_remote_path }}"
  ignore_errors: yes
```

`ignore_errors`在这里非常重要。就 Ansible 而言，除非我们从扫描中获得 100%的干净健康报告，否则这个任务将始终运行。下一个任务是将扫描生成的 HTML 报告从目标主机复制到我们的 Ansible 控制器：

```
- name: download the html report
  fetch:
    src: "{{ report.report_remote_path }}"
    dest: "{{ report.report_local_path }}"
    flat: yes
```

现在我们有了两个角色，我们可以开始运行我们的第一个扫描。

# 运行初始扫描

现在我们已经完成了安装和扫描角色，我们可以运行我们的第一个扫描。我们还没有涵盖的唯一文件是`site.yml`；这个文件看起来与我们在其他章节中使用的文件略有不同：

```
---

- hosts: scap
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - { role: install, tags: [ "scan" ] }
    - { role: scan, tags: [ "scan" ], report_name: "01-initial-scan" }
```

如你所见，我们正在为角色打标签，并在运行扫描时传递一个参数。现在，我们只是运行手册而不使用任何标签。要运行手册，请发出以下命令：

```
$ ansible-playbook -i production site.yml
```

这将给我们以下结果：

```
PLAY [scap] ****************************************************************************************

TASK [Gathering Facts] *****************************************************************************
ok: [box1]

TASK [install : install the packages needed] *******************************************************
changed: [box1] => (item=openscap-scanner)
changed: [box1] => (item=scap-security-guide)

```

```
TASK [scan : run the openscap scan] ****************************************************************
fatal: [box1]: FAILED! => {"changed": true, "cmd": ["oscap", "xccdf", "eval", "--profile", "xccdf_org.ssgproject.content_profile_pci-dss", "--fetch-remote-resources", "--results-arf", "/tmp/box1_results_01-initial-scan.xml", "--report", "/tmp/box1_report_01-initial-scan.html", "/usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml"], "delta": "0:01:03.459407", "end": "2018-05-16 08:17:50.970321", "msg": "non-zero return code", "rc": 2, "start": "2018-05-16 08:16:47.510914", "stderr": "Downloading: https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml.bz2 ... ok", "stderr_lines": ["Downloading: https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml.bz2 ... ok"], "stdout": "Title\r\tEnsure Red Hat GPG Key Installed\nRule\r\txccdf_org.ssgproject.content_rule_ensure_redhat_gpgkey_installed\nResult\r\tpass\n\nTitle\r\tEnsure gpgcheck Enabled In Main Yum "\txccdf_org.ssgproject.content_rule_chronyd_or_ntpd_specify_multiple_servers", "Result", "\tpass"]}
...ignoring

TASK [scan : download the html report] *************************************************************
changed: [box1]

PLAY RECAP *****************************************************************************************
box1 : ok=4 changed=3 unreachable=0 failed=0
```

我已经在此输出中截断了扫描结果，但当你运行它时，你会看到一个大部分失败的输出被标记为红色。如前所述，这是可以预料到的，不用担心。

我们初始扫描的 HTML 报告的副本现在应该在您的 Ansible 控制器上；您可以使用以下命令在浏览器中打开它：

```
$ open generated/box1_report_01-initial-scan.html
```

或者，打开`generated`文件夹，双击`box1_report_01-initial-scan.html`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/e5ebc9c4-a064-48d6-b4f0-767d9402f75b.png)

如您从示例中所见，我们的主机在 OpenSCAP 运行的 94 个检查中有 51 个失败。让我们看看如何解决这些失败的检查。

# 生成补救的 Ansible playbook

在我们继续之前，我必须首先提醒您报告给出了以下警告：

在没有在非运行环境中进行测试的情况下，请不要尝试实施本指南中的任何设置。本指南的创建者对其他方使用本指南不承担任何责任，并且对其质量、可靠性或任何其他特性不作任何明示或暗示的保证。

虽然我们这里只针对一个测试主机，如果您喜欢并决定查看针对其他工作负载实施 OpenSCAP，请确保您慢慢进行测试，然后再运行，即使只是由开发人员使用，我们即将进行的补救可能会对目标主机的运行产生严重后果。

既然我们已经解决了这个警告，我们可以继续看如何使用自动生成的 Ansible playbook 来保护我们的主机：

```
$ ansible-galaxy init roles/fix-ansible
```

对于这个角色，我们需要一些默认值，定义我们生成的 playbook 将被排序的位置，再次需要定义需要运行的命令。这些值可以在`roles/fix-ansible/defaults/main.yml`中找到。

第一个块处理我们将要生成的文件在目标主机和本地存储的位置：

```
playbook_file:
  remote: "/tmp/{{ inventory_hostname }}_ansible.yml"
  local: "generated/{{ inventory_hostname }}_ansible.yml"
  log: "generated/{{ inventory_hostname }}_ansible.log"
```

接下来，我们有需要执行的命令来生成 playbook 文件：

```
ansible_fix_command: >
  oscap xccdf generate fix
    --profile {{ oscap.profile }}
    --template urn:xccdf:fix:script:ansible
    --output {{ playbook_file.remote }}
    {{ report.results }}
```

然后，我们有一些文件夹和文件的位置需要在运行 playbook 之前放在那里；否则，将导致错误和失败：

```
missing_folders:
  - "/etc/dconf/db/local.d/locks/"

missing_files:
  - "/etc/dconf/db/local.d/locks/00-security-settings-lock"
  - "/etc/sysconfig/prelink"
```

既然我们已经有了默认的变量，我们可以开始向`roles/fix-ansible/tasks/main.yml`添加任务，首先使用`file`模块放置缺失的文件夹和文件：

```
- name: fix missing folders
  file:
    path: "{{ item }}"
    state: "directory"
  with_items: "{{ missing_folders }}"

- name: fix missing files
  file:
    path: "{{ item }}"
    state: "touch"
  with_items: "{{ missing_files }}"
```

接下来，我们将添加一个检查，看看目标机器上的 playbook 文件是否已经存在：

```
- name: do we already have the playbook?
  stat:
    path: "{{ playbook_file.remote }}"
  register: playbook_check
```

我们这样做是为了有一种跳过运行已生成的 playbook 的方法。接下来，我们运行命令来生成 playbook：

```
- name: generate the ansible playbook with the fixes
  command: "{{ ansible_fix_command }}"
  args:
    creates: "{{ playbook_file.remote }}" 
  ignore_errors: yes
```

如您从示例中所见，我们正在传递参数告诉 Ansible 创建 playbook 文件的命令；如果文件存在，则命令将不会再次执行。现在我们在机器上有了 playbook，我们需要将其复制到我们的 Ansible 控制器上。在这里，我们再次使用`fetch`模块：

```
- name: download the ansible playbook
  fetch:
    src: "{{ playbook_file.remote }}"
    dest: "{{ playbook_file.local }}"
    flat: yes
  when: playbook_check.stat.exists == False
```

如您所见，我们正在使用`when`，以便任务仅在角色运行开始时 playbook 文件不存在时才运行。现在我们在本地有了 playbook 的副本，我们可以运行它。为此，我们将使用`local_action`模块与`command`模块结合在 Ansible 中运行 Ansible：

```
- name: run the ansible playbook locally
  local_action:
    module: "command ansible-playbook -i production --become --become-method sudo {{ playbook_file.local }}"
  become: no
  register: playbook_run
  when: playbook_check.stat.exists == False
```

这里发生了一些不同的事情，所以让我们更详细地分解一下，从我们正在运行的命令开始，这个命令的翻译是：

```
$ ansible-playbook -i production --become --become-method sudo generated/box1_ansible.yml
```

如您所见，我们必须传递使用`become`与`sudo`方法作为命令的一部分的指令。这是因为生成的 Ansible playbook 没有考虑到您使用 root 以外的用户进行外部连接。

这个角色的最后一个任务将上一个任务的结果写入我们的 Ansible 控制器上的一个文件：

```
- name: write the results to a log file
  local_action:
    module: "copy content={{ playbook_run.stdout }} dest={{ playbook_file.log }}"
  become: no
  when: playbook_check.stat.exists == False
```

这样就完成了角色。我们可以再次运行 playbook 来应用修复和补救措施，然后运行另一个扫描，以便我们可以更新`site.yml`文件，使其读取：

```
---

- hosts: scap
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - { role: install, tags: [ "scan" ] }
    - { role: scan, tags: [ "scan" ], report_name: "01-initial-scan" }
    - { role: fix-ansible, report_name: "01-initial-scan" }
    - { role: scan, report_name: "02-post-ansible-fix" }
```

如您所见，我们已经删除了`fix-ansible`角色的标记，并且还更新了第二次扫描的报告名称。我们可以通过运行以下命令来启动 playbook：

```
$ ansible-playbook -i production site.yml
```

这将给我们以下输出：

```
PLAY [scap] *************************************************************************************

TASK [Gathering Facts] **************************************************************************
ok: [box1]

TASK [install : update all of the installed packages] *******************************************
ok: [box1]

TASK [install : install the packages needed] ****************************************************
ok: [box1] => (item=openscap-scanner)
ok: [box1] => (item=scap-security-guide)

TASK [scan : run the openscap scan] *************************************************************
ok: [box1]

TASK [scan : download the html report] **********************************************************
ok: [box1]

TASK [fix-ansible : fix missing folders] ********************************************************
changed: [box1] => (item=/etc/dconf/db/local.d/locks/)

TASK [fix-ansible : fix missing files] **********************************************************
changed: [box1] => (item=/etc/dconf/db/local.d/locks/00-security-settings-lock)
changed: [box1] => (item=/etc/sysconfig/prelink)

TASK [fix-ansible : do we already have the playbook?] *******************************************
ok: [box1]

TASK [fix-ansible : generate the ansible playbook with the fixes] *******************************
changed: [box1]

TASK [fix-ansible : download the ansible playbook] **********************************************
changed: [box1]

TASK [fix-ansible : run the ansible playbook locally] *******************************************
changed: [box1 -> localhost]

TASK [fix-ansible : write the results to a log file] ********************************************
changed: [box1 -> localhost]

TASK [scan : run the openscap scan] *************************************************************
fatal: [box1]: FAILED! => 
...ignoring

TASK [scan : download the html report] **********************************************************
changed: [box1]

PLAY RECAP **************************************************************************************
box1 : ok=14 changed=8 unreachable=0 failed=0
```

让我们看一下报告，看看运行 Ansible playbook 有什么不同：

```
$ open generated/box1_report_02-post-ansible-fix.html
```

输出如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/c5936eb5-8d14-42be-afa3-3a92e03deeef.png)

现在比以前好一点了；然而，我们仍然有 25 条规则失败了—为什么呢？嗯，正如已经提到的，仍在进行将所有修复规则迁移到 Ansible 的工作；例如，如果你打开原始扫描结果并滚动到底部，你应该会看到设置 SSH 空闲超时间隔检查失败。

点击它将向您显示 OpenSCAP 正在检查的信息，为什么他们正在检查，以及为什么应该修复。最后，在底部，您将注意到有显示 shell 和 Ansible 修复解决方案的选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/30f04aed-e541-4b71-8a17-5e0c2a58075a.png)

现在，点击第二份报告中剩下的失败之一。你应该注意到只有使用 shell 脚本进行修复的选项。我们将在下一个角色中生成这个，但在我们继续之前，让我们快速看一下生成的 playbook。

我在撰写时生成的 playbook 包含超过 3200 行的代码，所以我不打算在这里覆盖它们所有，但正如我们已经提到的设置 SSH 空闲超时间隔检查，让我们看一下 playbook 中应用修复的任务：

```
    - name: Set SSH Idle Timeout Interval
      lineinfile:
        create: yes
        dest: /etc/ssh/sshd_config
        regexp: ^ClientAliveInterval
        line: "ClientAliveInterval {{ sshd_idle_timeout_value }}"
        validate: sshd -t -f %s
      #notify: restart sshd
      tags:
        - sshd_set_idle_timeout
        - low_severity
        - restrict_strategy
        - low_complexity
        - low_disruption
        - CCE-27433-2
        - NIST-800-53-AC-2(5)
        - NIST-800-53-SA-8(i)
        - NIST-800-53-AC-12
        - NIST-800-171-3.1.11
        - PCI-DSS-Req-8.1.8
        - CJIS-5.5.6
        - DISA-STIG-RHEL-07-040320
```

如您所见，它使用 lineinfile 模块来应用在 playbook 顶部定义的变量。此外，每个任务都带有关于修复所属的标准的许多信息，以及严重程度。这意味着我们可以对 playbook 运行的部分进行非常细致的控制；例如，您可以通过使用以下命令仅运行低干扰更改：

```
$ ansible-playbook -i production --become --become-method sudo --tags "low_disruption" generated/box1_ansible.yml
```

最后，在`box1_ansible.log`文件的底部，我们可以看到 playbook 运行做出了以下更改：

```
PLAY RECAP **************************************************************************************
box1 : ok=151 changed=85 unreachable=0 failed=0 
```

# 生成修复的 bash 脚本

为了纠正剩下的问题，我们应该生成并执行 bash 脚本：

```
$ ansible-galaxy init roles/fix-bash
```

由于这是一个很好的功能，我不打算详细介绍我们在这里添加的内容的各个方面。`roles/fix-bash/defaults/main.yml`的内容与`fix-ansible`角色中的内容类似：

```
bash_file:
  remote: "/tmp/{{ inventory_hostname }}_bash.sh"
  log: "generated/{{ inventory_hostname }}_bash.log"

bash_fix_command: >
  oscap xccdf generate fix
    --profile {{ oscap.profile }}
    --output {{ bash_file.remote }}
    {{ report.results }}
```

`roles/fix-bash/tasks/main.yml`中的任务也是类似的，不需要任何解释：

```
- name: do we already have the bash script?
  stat:
    path: "{{ bash_file.remote }}"
  register: bash_script_check

- name: generate the bash script
  command: "{{ bash_fix_command }}"
  args:
    creates: "{{ bash_file.remote }}" 
  ignore_errors: yes

- name: run the bash script
  command: "bash {{ bash_file.remote }}"
  ignore_errors: yes
  register: bash_run
  when: bash_script_check.stat.exists == False

- name: write the results to a log file
  local_action:
    module: "copy content={{ bash_run.stdout }} dest={{ bash_file.log }}"
  become: no
  when: bash_script_check.stat.exists == False
```

更新`site.yml`文件，使其读取：

```
- hosts: scap
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - { role: install, tags: [ "scan" ] }
    - { role: scan, tags: [ "scan" ], report_name: "01-initial-scan" }
    - { role: fix-ansible, report_name: "01-initial-scan" }
    - { role: scan, report_name: "02-post-ansible-fix" }
    - { role: fix-bash, report_name: "02-post-ansible-fix" }
    - { role: scan, report_name: "03-post-bash-fix" }
```

这意味着我们可以拿到在应用 Ansible 修复后运行的扫描结果，生成包含剩余修复的 bash 脚本；然后我们进行最后一次扫描。要应用最终的一批修复，运行以下命令：

```
$ ansible-playbook -i production site.yml
```

这会产生以下输出：

```
PLAY [scap] *************************************************************************************

TASK [Gathering Facts] **************************************************************************
ok: [box1]

TASK [install : update all of the installed packages] *******************************************
ok: [box1]

TASK [install : install the packages needed] ****************************************************
ok: [box1] => (item=openscap-scanner)
ok: [box1] => (item=scap-security-guide)

TASK [scan : run the openscap scan] *************************************************************
ok: [box1]

TASK [scan : download the html report] **********************************************************
ok: [box1]

TASK [fix-ansible : fix missing folders] ********************************************************
ok: [box1] => (item=/etc/dconf/db/local.d/locks/)

TASK [fix-ansible : fix missing files] **********************************************************
changed: [box1] => (item=/etc/dconf/db/local.d/locks/00-security-settings-lock)
changed: [box1] => (item=/etc/sysconfig/prelink)

TASK [fix-ansible : do we already have the playbook?] *******************************************
ok: [box1]

TASK [fix-ansible : generate the ansible playbook with the fixes] *******************************
skipping: [box1]

TASK [fix-ansible : download the ansible playbook] **********************************************
skipping: [box1]

TASK [fix-ansible : run the ansible playbook locally] *******************************************
skipping: [box1]

TASK [fix-ansible : write the results to a log file] ********************************************
skipping: [box1]

TASK [scan : run the openscap scan] *************************************************************
ok: [box1]

TASK [scan : download the html report] **********************************************************
ok: [box1]

TASK [fix-bash : do we already have the bash script?] *******************************************
ok: [box1]

TASK [fix-bash : generate the bash script] ******************************************************
changed: [box1]

TASK [fix-bash : run the bash script] ***********************************************************
changed: [box1]

TASK [fix-bash : write the results to a log file] ***********************************************
changed: [box1 -> localhost]

TASK [scan : run the openscap scan] *************************************************************
fatal: [box1]: FAILED! =>
...ignoring

TASK [scan : download the html report] **********************************************************
changed: [box1]

PLAY RECAP **************************************************************************************
box1 : ok=16 changed=6 unreachable=0 failed=0
```

通过运行检查最终报告：

```
$ open generated/box1_report_03-post-bash-fix.html
```

这应该显示总共失败检查的数量已经减少到只有五个：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/f65a56a1-ee6e-4d15-aeda-298f3ce3782f.png)

# 运行独立扫描

当我们创建扫描角色时，提到角色应该是可重用的。当我们在`site.yml`文件中定义角色时，我们还为角色添加了标记。让我们快速看一下我们如何可以仅运行扫描而不是完整的 playbook 运行。要启动扫描，请运行以下命令：

```
$ ansible-playbook -i production --tags "scan" --extra-vars "report_name=scan-only" site.yml
```

这将只运行标记为`scan`的 playbook 部分，并且我们还覆盖了`report_name`变量，这是我们在`site.yml`文件中调用角色时设置的，以调用我们的`report box1_report_scan-only.html`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/d25ced72-4024-45a0-9642-f66b12df3583.png)

# 修复剩下的失败检查

到目前为止，我们还没有不得不采取任何硬编码的修复措施来解决扫描中发现的任何问题。我们不得不创建一些文件和文件夹来允许应用修复，但这更多是为了让自动修复工作，而不是修复。

在撰写本文时，我们已知有两个当前显示在我的扫描中的五个问题存在问题；它们是：

+   `xccdf_org.ssgproject.content_rule_audit_rules_privileged_commands`

+   `xccdf_org.ssgproject.content_rule_audit_rules_login_events`

正在进行修复。你可以在 Red Hat 的 Bugzilla 上找到它们：

+   [`bugzilla.redhat.com/show_bug.cgi?id=1570802`](https://bugzilla.redhat.com/show_bug.cgi?id=1570802)

+   [`bugzilla.redhat.com/show_bug.cgi?id=1574586`](https://bugzilla.redhat.com/show_bug.cgi?id=1574586)

因此，将这两个放在一边，现在有三个我可以修复。为了做到这一点，我将创建一个单独的角色和 playbook，因为在你阅读这篇文章的时候，以下的修复可能已经不再需要：

```
$ ansible-galaxy init roles/final-fixes
```

直接跳转到`roles/final-fixes/tasks/main.yml`，我们的第一个修复是将日志每天而不是每周进行轮转，这是默认设置。为了做到这一点，我们将使用`lineinfile`模块将`weekly`替换为`daily`：

```
- name: sort out the logrotate
  lineinfile:
    path: "/etc/logrotate.conf"
    regexp: "^weekly"
    line: "daily"
```

下一个任务添加了一个修复，应该在某个时候通过`scap-security-guide`软件包实现：

```
- name: add the missing line to the modules.rules
  lineinfile:
    path: "/etc/audit/rules.d/modules.rules"
    line: "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules"
```

正如你在这里所看到的，我们再次使用`lineinfile`模块。这一次，如果`/etc/audit/rules.d/modules.rules`中不存在，我们将添加一行。这将添加一个规则，考虑到 32 位内核以及已经配置好的 64 位内核的修复脚本。

接下来，我们为应该在 bash 脚本执行期间执行的脚本添加了一个修复。首先，我们需要使用`file`模块创建一个文件：

```
- name: add file for content_rule_file_permissions_var_log_audit
  file:
    path: "/var/log/audit/audit.log.fix"
    state: "touch"
```

然后我们需要复制并执行在我们第一次运行时失败的 bash 脚本的部分：

```
- name: copy the content_rule_file_permissions_var_log_audit.sh script
  copy:
    src: "content_rule_file_permissions_var_log_audit.sh"
    dest: "/tmp/content_rule_file_permissions_var_log_audit.sh"

- name: run the content_rule_file_permissions_var_log_audit.sh script 
  command: "bash /tmp/content_rule_file_permissions_var_log_audit.sh"
```

bash 脚本本身可以在`roles/final-fixes/files/content_rule_file_permissions_var_log_audit.sh`中找到，它看起来是这样的：

```
if `grep -q ^log_group /etc/audit/auditd.conf` ; then
  GROUP=$(awk -F "=" '/log_group/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
  if ! [ "${GROUP}" == 'root' ] ; then
    chmod 0640 /var/log/audit/audit.log
    chmod 0440 /var/log/audit/audit.log.*
  else
    chmod 0600 /var/log/audit/audit.log
    chmod 0400 /var/log/audit/audit.log.*
  fi

  chmod 0640 /etc/audit/audit*
  chmod 0640 /etc/audit/rules.d/*
else
  chmod 0600 /var/log/audit/audit.log
  chmod 0400 /var/log/audit/audit.log.*
  chmod 0640 /etc/audit/audit*
  chmod 0640 /etc/audit/rules.d/*
fi
```

最后，我们需要创建一个名为`final-fixes.yml`的 playbook 文件。这应该运行我们刚刚创建的角色，然后运行最终扫描：

```
---

- hosts: scap
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - { role: final-fixes }
    - { role: scan, report_name: "04-final-fixes" }
```

要运行 playbook，请使用以下命令：

```
$ ansible-playbook -i production final-fixes.yml
```

这将产生以下结果：

```
PLAY [scap] *************************************************************************************

TASK [Gathering Facts] **************************************************************************
ok: [box1]

TASK [final-fixes : sort out the logrotate] *****************************************************
changed: [box1]

TASK [final-fixes : add the missing line to the modules.rules] **********************************
changed: [box1]

TASK [final-fixes : add file for content_rule_file_permissions_var_log_audit] *******************
changed: [box1]

TASK [final-fixes : copy the content_rule_file_permissions_var_log_audit.sh script] *************
changed: [box1]

TASK [final-fixes : run the content_rule_file_permissions_var_log_audit.sh script] **************
changed: [box1]

TASK [scan : run the openscap scan] *************************************************************
fatal: [box1]: FAILED! => 
...ignoring

TASK [scan : download the html report] **********************************************************
changed: [box1]

PLAY RECAP **************************************************************************************
box1 : ok=8 changed=7 unreachable=0 failed=0
```

打开使用以下命令生成的报告：

```
$ open generated/box1_report_04-final-fixes.html
```

这告诉我们，仍然有两个中等检查存在已知问题，仍然失败：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/c78e226b-f378-44e9-a908-fdb0584971e6.png)

希望在你阅读本文时，你的主机将得到一个干净的健康证明，这最后一部分将不再需要，这就是为什么我将它从主`site.yml` playbook 中分离出来的原因。

# 销毁 Vagrant box

完成后不要忘记销毁 Vagrant box；你不希望在主机上运行一个空闲的虚拟机。要做到这一点，请运行：

```
$ vagrant destroy
```

一旦 box 消失，我建议在干净的安装上多次运行扫描和修复，以了解如何在新主机上实现这一点。

# 总结

在本章中，我们创建了一个 playbook，生成了一个 playbook，用于在扫描期间发现 PCI-DSS 不符合错误的修复。除了非常酷外，如果你想象一下你正在运行几十台需要符合标准的服务器，并且它们都需要完整的审计历史记录，这也是非常实用的。

现在你已经有了一个 playbook 的基础，可以每天用来定位这些主机，对它们进行审计，并将结果存储在主机之外，但是根据你的配置，你也有一种自动解决扫描期间发现的任何不符合标准的方法。

我们在本章中进行的扫描都是基于主机的；在下一章中，我们将看看如何远程扫描主机。

# 问题

1.  将`>`添加到多行变量会产生什么影响？

1.  正确或错误：OpenSCAP 已经获得 NIST 认证。

1.  为什么我们告诉 Ansible 在`scan`命令标记为失败时继续运行？

1.  解释为什么我们对某些角色使用标签。

1.  正确或错误：我们使用`copy`命令将 HTML 报告从远程主机复制到 Ansible 控制器。

# 进一步阅读

您可以在以下链接找到本章涵盖的技术和组织的更多信息：

+   OpenSCAP：[`www.open-scap.org/`](https://www.open-scap.org/)

+   安全内容自动化协议（SCAP）：[`scap.nist.gov/`](https://scap.nist.gov/)

+   NIST：[`www.nist.gov/`](https://www.nist.gov/)

+   麻省理工学院：[`www.mitre.org/`](https://www.mitre.org/)

+   资产识别（AID）：[`csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/aid`](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/aid)

+   资产报告格式（ARF）：[`csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/arf`](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/arf)

+   通用配置标识（CCE）：[`cce.mitre.org`](https://cce.mitre.org)

+   通用配置评分系统（CCSS）：[`www.nist.gov/publications/common-configuration-scoring-system-ccss-metrics-software-security-configuration`](https://www.nist.gov/publications/common-configuration-scoring-system-ccss-metrics-software-security-configuration)

+   通用平台标识（CPE）：[`nvd.nist.gov/products/cpe`](https://nvd.nist.gov/products/cpe)

+   通用弱点枚举（CWE）：[`cwe.mitre.org/`](https://cwe.mitre.org/)

+   通用漏洞和暴露（CVE）：[`cve.mitre.org`](https://cve.mitre.org)

+   通用漏洞评分系统（CVSS）：[`www.first.org/cvss/`](https://www.first.org/cvss/)

+   可扩展配置清单描述格式（XCCDF）：[`csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/xccdf`](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/xccdf)

+   开放清单交互语言（OCIL）：[`csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/ocil`](https://csrc.nist.gov/Projects/Security-Content-Automation-Protocol/Specifications/ocil)

+   开放漏洞和评估语言（OVAL）：[`oval.mitre.org`](https://oval.mitre.org)

+   安全自动化数据信任模型（TMSAD）：[`www.nist.gov/publications/trust-model-security-automation-data-10-tmsad`](https://www.nist.gov/publications/trust-model-security-automation-data-10-tmsad)


# 第十四章：部署 WPScan 和 OWASP ZAP

在本章中，我们将介绍创建一个 playbook，部署和运行两个安全工具 WPScan 和 OWASP ZAP。然后，使用之前章节的 playbooks，我们将启动一个 WordPress 安装供我们扫描。

与其他章节一样，我们将使用 Vagrant 和我们已经下载的框之一。您可以在[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter14`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter14)找到完整的 playbook 副本。

# 准备框

在本章中，我们将启动两个 Vagrant 框，第一个将用于安装扫描工具。此主机将安装了 Docker，并且我们将使用 Docker Ansible 模块与该软件进行交互。第二个框将包含或托管 WordPress 安装，扫描工具将针对其进行扫描。

创建一个包含以下内容的`Vagrantfile`：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
BOX_NAME = "centos/7"
BOX_IP_SCAN = "10.20.30.40"
BOX_IP_WP = "10.20.30.41"
DOMAIN = "nip.io"
PRIVATE_KEY = "~/.ssh/id_rsa"
PUBLIC_KEY = '~/.ssh/id_rsa.pub'

```

```
Vagrant.configure(API_VERSION) do |config|

  config.vm.define :scan do |scan| 
    scan.vm.box = BOX_NAME
    scan.vm.network "private_network", ip: BOX_IP_SCAN
    scan.vm.host_name = BOX_IP_SCAN + '.' + DOMAIN
    scan.ssh.insert_key = false
    scan.ssh.private_key_path = [PRIVATE_KEY, "~/.vagrant.d/insecure_private_key"]
    scan.vm.provision "file", source: PUBLIC_KEY, destination: "~/.ssh/authorized_keys"
  end

  config.vm.define :wp do |wp| 
    wp.vm.box = BOX_NAME
    wp.vm.network "private_network", ip: BOX_IP_WP
    wp.vm.host_name = BOX_IP_WP + '.' + DOMAIN
    wp.ssh.insert_key = false
    wp.ssh.private_key_path = [PRIVATE_KEY, "~/.vagrant.d/insecure_private_key"]
    wp.vm.provision "file", source: PUBLIC_KEY, destination: "~/.ssh/authorized_keys"
  end

  config.vm.provider "virtualbox" do |v|
    v.memory = "2024"
    v.cpus = "2"
  end

  config.vm.provider "vmware_fusion" do |v|
    v.vmx["memsize"] = "2024"
    v.vmx["numvcpus"] = "2"
  end

end
```

如您所见，我们将启动两个 CentOS 7 框，一个标记为`scan`，其主机名为`10.20.30.40.nip.io`，另一个为`wp`，其主机名为`10.20.30.41.nip.io`。

主机清单文件，通常称为 production，包含以下内容：

```
box1 ansible_host=10.20.30.40.nip.io
box2 ansible_host=10.20.30.41.nip.io

[scan]
box1

[wordpress]
box2

[boxes]
box1
box2

[boxes:vars]
ansible_connection=ssh
ansible_user=vagrant
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

如您所见，我们定义了三个主机组；第一组名为`scan`，包括我们将用于运行扫描工具的单个主机。第二组`wordpress`，虽然只包含一个主机，但可以列出多个主机，并且扫描应该针对它们所有。第三组名为`boxes`，已被定义为将连接配置应用于我们在 playbook 中添加的所有主机的一种方式。

您可以使用以下两个命令之一启动这两个框：

```
$ vagrant up
$ vagrant up --provider=vmware_fusion
```

现在我们的 Vagrant 框已经启动并运行，我们可以看一下我们的 playbook 是什么样子的。

# WordPress playbook

正如您已经猜到的那样，这将非常简单，因为我们已经编写了一个在 CentOS 7 主机上部署 WordPress 的 playbook。实际上，我们唯一需要做的就是从存储库的`Chapter05/lemp`文件夹中复制`group_vars`、`roles`文件夹及其内容，以及`site.yml`文件，然后我们就完成了。

这是使用 Ansible 这样的工具的一个巨大优势：写一次，多次使用；我们唯一要做的更改是在添加部署软件的 plays 时更改`site.yml`文件。

# 扫描 playbook

如前所述，我们将使用 Docker 来运行 WPScan 和 OWASP ZAP。这样做的原因是，如果我们直接在主机上安装这两个软件包，我们将最终部署相当多的支持软件。虽然这不是问题，但使用诸如 Docker 这样的工具可以简化安装过程，并给我们一个借口来介绍 Docker Ansible 模块。

# Docker 角色

与我们迄今为止创建的所有角色一样，我们将使用`ansible-galaxy`命令来生成我们角色的结构：

```
$ ansible-galaxy init roles/docker
```

对于我们的 Docker 安装，我们将使用 Docker 自己提供的`yum`存储库；这意味着在安装 Docker 之前，需要启用存储库。一旦启用，我们将能够安装最新的稳定版本。让我们首先在`roles/docker/defaults/main.yml`中填充一些默认值：

```
docker:
  gpg_key: "https://download.docker.com/linux/centos/gpg"
  repo_url: "https://download.docker.com/linux/centos/docker-ce.repo"
  repo_path: "/etc/yum.repos.d/docker-ce.repo"
  packages:
    - "docker-ce"
    - "device-mapper-persistent-data"
    - "lvm2"
    - "python-setuptools"
    - "libselinux-python"
  pip:
    - "docker"
```

正如你所看到的，我们正在定义存储库的 GPG 密钥的 URL，存储库文件的 URL，以及存储库文件应该被复制到主机的位置。我们还列出了需要安装的软件包列表，以使 Docker 正常运行。最后，我们有用于 Docker 的 Python 软件包，这将允许 Ansible 与我们的 Vagrant box 上的 Docker API 进行交互。

在使用任何已定义的变量之前，我们需要确保我们运行的主机的软件包是最新的，因此`roles/docker/tasks/main.yml`中的第一个任务应该执行`yum update`：

```
- name: update all of the installed packages
  yum:
    name: "*"
    state: "latest"
    update_cache: "yes"
```

现在我们的主机已经更新，我们可以添加 GPG 密钥；对此，我们将使用`rpm_key`模块，我们只需提供要安装的密钥的 URL 或文件路径：

```
- name: add the gpg key for the docker repo
  rpm_key:
    key: "{{ docker.gpg_key }}"
    state: "present"
```

现在我们已经安装了 GPG 密钥，我们可以从 Docker 下载`docker-ce.repo`文件，并将其存储在`yum`在下次执行时会使用的位置：

```
- name: add docker repo from the remote url
  get_url:
    url: "{{ docker.repo_url }}"
    dest: "{{ docker.repo_path }}"
    mode: "0644"
```

如您所见，我们使用`get_url`模块下载文件并将其放置在主机机器上的`/etc/yum.repos.d/`中；我们还设置了文件的读、写和执行权限为`0644`。

现在我们已经配置了 Docker 存储库，我们可以通过添加以下任务来安装我们定义的软件包：

```
- name: install the docker packages
  yum:
    name: "{{ item }}"
    state: "installed"
    update_cache: "yes"
  with_items: "{{ docker.packages }}"
```

我们添加了`update_cache`选项，因为我们刚刚添加了一个新的存储库，并希望确保它被识别。接下来，我们必须使用`pip`安装 Docker Python 包；默认情况下，`pip`未安装，因此我们需要确保它首先可用，方法是使用`easy_install`，而`easy_install`又是由先前的任务安装的`python-setuptools`软件包安装的。有一个`easy_install`模块，因此这个任务很简单：

```
- name: install pip
  easy_install:
    name: pip
    state: latest
```

现在 pip 可用，我们可以使用`pip`模块来安装 Docker Python 库：

```
- name: install the python packages
  pip:
    name: "{{ item }}"
  with_items: "{{ docker.pip }}"
```

倒数第二个任务是在 Vagrant 虚拟机上禁用 SELinux：

```
- name: put selinux into permissive mode
  selinux:
    policy: targeted
    state: permissive
```

默认情况下，由 Docker 提供的 Docker 版本不会自动在 CentOS/Red Hat 服务器上启动，因此这个角色的最后一个任务是启动 Docker 服务，并确保它配置为在启动时启动：

```
- name: start docker and configure to start on boot
  service:
    name: "docker"
    state: "started"
    enabled: "yes"
```

我们在 playbook 运行的这一部分完成之前完成了这个步骤，而不是使用处理程序，因为 playbook 需要在完成之前与 Docker 交互。由于处理程序只在 playbook 运行结束时调用，这意味着我们的 playbook 的下一部分将失败。在开始下载和运行容器之前，让我们快速运行 playbook。

# 测试 playbook

由于我们已经有了所有基本角色，我们可以尝试运行 playbook；在这样做之前，我们需要更新`site.yml`以包括我们扫描主机的操作：

```
---

- hosts: scan
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/docker

- hosts: wordpress
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/stack-install
    - roles/stack-config
    - roles/wordpress
```

更新后，我们可以使用以下代码运行我们的 playbook：

```
$ ansible-playbook -i production site.yml
```

这应该给我们类似以下的输出：

```
PLAY [scan] *************************************************************************************

TASK [Gathering Facts] **************************************************************************
ok: [box1]

TASK [roles/docker : update all of the installed packages] **************************************
changed: [box1]

TASK [roles/docker : add the gpg key for the docker repo] ***************************************
changed: [box1]

TASK [roles/docker : add docker repo from the remote url] ***************************************
changed: [box1]

TASK [roles/docker : install the docker packages] ***********************************************
changed: [box1] => (item=[u'docker-ce', u'device-mapper-persistent-data', u'lvm2', u'python-setuptools', u'libselinux-python'])

TASK [roles/docker : install pip] ***************************************************************
changed: [box1]

TASK [roles/docker : install the python packages] ***********************************************
changed: [box1] => (item=docker)

TASK [roles/docker : put selinux into permissive mode] ******************************************
changed: [box1]

TASK [roles/docker : start docker and configure to start on boot] *******************************
changed: [box1]

PLAY [wordpress] ********************************************************************************

TASK [Gathering Facts] **************************************************************************
ok: [box2]

TASK [roles/stack-install : install the repo packages] ******************************************
changed: [box2] => (item=[u'epel-release', u'https://centos7.iuscommunity.org/ius-release.rpm'])

TASK [roles/stack-install : add the NGINX mainline repo] ****************************************
changed: [box2]

TASK [roles/stack-install : update all of the installed packages] *******************************
changed: [box2]

TASK [roles/stack-install : remove the packages so that they can be replaced] *******************
changed: [box2] => (item=[u'mariadb-libs.x86_64'])

TASK [roles/stack-install : install the stack packages] *****************************************
changed: [box2] => (item=[u'postfix', u'MySQL-python', u'policycoreutils-python', u'nginx', u'mariadb101u', u'mariadb101u-server', u'mariadb101u-config', u'mariadb101u-common', u'mariadb101u-libs', u'php72u', u'php72u-bcmath', u'php72u-cli', u'php72u-common', u'php72u-dba', u'php72u-fpm', u'php72u-fpm-nginx', u'php72u-gd', u'php72u-intl', u'php72u-json', u'php72u-mbstring', u'php72u-mysqlnd', u'php72u-process', u'php72u-snmp', u'php72u-soap', u'php72u-xml', u'php72u-xmlrpc', u'vim-enhanced', u'git', u'unzip'])

TASK [roles/stack-config : add the wordpress user] **********************************************
changed: [box2]

TASK [roles/stack-config : copy the nginx.conf to /etc/nginx/] **********************************
changed: [box2]

TASK [roles/stack-config : create the global directory in /etc/nginx/] **************************
changed: [box2]

TASK [roles/stack-config : copy the restrictions.conf to /etc/nginx/global/] ********************
changed: [box2]

TASK [roles/stack-config : copy the wordpress_shared.conf to /etc/nginx/global/] ****************
changed: [box2]

TASK [roles/stack-config : copy the default.conf to /etc/nginx/conf.d/] *************************
changed: [box2]

TASK [roles/stack-config : copy the www.conf to /etc/php-fpm.d/] ********************************
changed: [box2]

TASK [roles/stack-config : configure php.ini] ***************************************************
changed: [box2] => (item={u'regexp': u'^;date.timezone =', u'replace': u'date.timezone = Europe/London'})
changed: [box2] => (item={u'regexp': u'^expose_php = On', u'replace': u'expose_php = Off'})
changed: [box2] => (item={u'regexp': u'^upload_max_filesize = 2M', u'replace': u'upload_max_filesize = 20M'})

TASK [roles/stack-config : start php-fpm] *******************************************************
changed: [box2]

TASK [roles/stack-config : start nginx] *********************************************************
changed: [box2]

TASK [roles/stack-config : configure the mariadb bind address] **********************************
changed: [box2]

TASK [roles/stack-config : start mariadb] *******************************************************
changed: [box2]

TASK [roles/stack-config : change mysql root password] ******************************************
changed: [box2] => (item=127.0.0.1)
changed: [box2] => (item=::1)
changed: [box2] => (item=10.20.30.41.nip.io)
changed: [box2] => (item=localhost)

TASK [roles/stack-config : set up .my.cnf file] *************************************************
changed: [box2]

TASK [roles/stack-config : delete anonymous MySQL user] *****************************************
ok: [box2] => (item=127.0.0.1)
ok: [box2] => (item=::1)
changed: [box2] => (item=10.20.30.41.nip.io)
changed: [box2] => (item=localhost)

TASK [roles/stack-config : remove the MySQL test database] **************************************
changed: [box2]

TASK [roles/stack-config : set the selinux allowing httpd_t to be permissive is required] *******
changed: [box2]

TASK [roles/wordpress : download wp-cli] ********************************************************
changed: [box2]

TASK [roles/wordpress : update permissions of wp-cli to allow anyone to execute it] *************
changed: [box2]

TASK [roles/wordpress : create the wordpress database] ******************************************
changed: [box2]

TASK [roles/wordpress : create the user for the wordpress database] *****************************
changed: [box2] => (item=127.0.0.1)
ok: [box2] => (item=::1)
ok: [box2] => (item=10.20.30.41.nip.io)
ok: [box2] => (item=localhost)

TASK [roles/wordpress : are the wordpress files already there?] *********************************
ok: [box2]

TASK [roles/wordpress : download wordpresss] ****************************************************
changed: [box2]

TASK [roles/wordpress : set the correct permissions on the homedir] *****************************
changed: [box2]

TASK [roles/wordpress : is wordpress already configured?] ***************************************
ok: [box2]

TASK [roles/wordpress : configure wordpress] ****************************************************
changed: [box2]

TASK [roles/wordpress : do we need to install wordpress?] ***************************************
fatal: [box2]: FAILED! =>
...ignoring

TASK [roles/wordpress : install wordpress if needed] ********************************************
changed: [box2]

TASK [roles/wordpress : do we need to install the plugins?] *************************************
failed: [box2] (item=jetpack) =>
failed: [box2] (item=wp-super-cache) =>
failed: [box2] (item=wordpress-seo) =>
failed: [box2] (item=wordfence) =>
failed: [box2] (item=nginx-helper) =>
...ignoring

TASK [roles/wordpress : set a fact if we don't need to install the plugins] *********************
skipping: [box2]

TASK [roles/wordpress : set a fact if we need to install the plugins] ***************************
ok: [box2]

TASK [roles/wordpress : install the plugins if we need to or ignore if not] *********************
changed: [box2] => (item=jetpack)
changed: [box2] => (item=wp-super-cache)
changed: [box2] => (item=wordpress-seo)
changed: [box2] => (item=wordfence)
changed: [box2] => (item=nginx-helper)

TASK [roles/wordpress : do we need to install the theme?] ***************************************
fatal: [box2]: FAILED! =>
...ignoring

TASK [roles/wordpress : set a fact if we don't need to install the theme] ***********************
skipping: [box2]

TASK [roles/wordpress : set a fact if we need to install the theme] *****************************
ok: [box2]

TASK [roles/wordpress : install the theme if we need to or ignore if not] ***********************
changed: [box2]

RUNNING HANDLER [roles/stack-config : restart nginx] ********************************************
changed: [box2]

RUNNING HANDLER [roles/stack-config : restart php-fpm] ******************************************
changed: [box2]

PLAY RECAP **************************************************************************************
box1 : ok=9 changed=8 unreachable=0 failed=0
box2 : ok=42 changed=37 unreachable=0 failed=0
```

如您所见，这已经执行了完整的 Docker 和 WordPress 安装；打开`http://10.20.30.41.nip.io/`将带您进入 WordPress 站点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/ad0c912f-5f54-4698-b797-30b830ddbcd8.png)

现在我们的 WordPress 站点已经运行起来了，我们可以开始执行扫描站点的角色。

# WPScan 角色

我们要创建的第一个角色是运行 WPScan 的角色。WPScan 是一个执行 WordPress 站点扫描的工具；它尝试确定正在运行的 WordPress 版本，并检查是否有已知漏洞的插件。它还可以尝试暴力破解管理员用户帐户；但是，我们将跳过这一步。

与往常一样，我们可以使用以下命令引导角色：

```
$ ansible-galaxy init roles/wpscan
```

文件放置好后，我们需要将以下内容添加到`roles/wpscan/defaults/main.yml`中：

```
image: "wpscanteam/wpscan"
log:
  remote_folder: /tmp/wpscan/
  local_folder: "generated/"
  file: "{{ ansible_date_time.date }}-{{ ansible_date_time.hour }}-{{ ansible_date_time.minute }}.txt"
```

这设置了我们想要从 Docker Hub 下载的镜像；在这种情况下，它是来自 WPScan 团队的官方 WPScan 镜像。然后，我们设置了我们希望用于日志的变量；您可能注意到我们正在为日志定义一个文件夹和文件名。

接下来，我们需要将任务添加到`roles/wpscan/tasks/main.yml`中，其中第一个任务使用`docker_image`模块来拉取`wpscanteam/wpscan`镜像的副本：

```
- name: pull the image
  docker_image:
    name: "{{ image }}"
```

接下来，我们需要创建一个文件夹，用于将日志写入我们的 Vagrant 虚拟机：

```
- name: create the folder which we will mount inside the container
  file:
    path: "{{ log.remote_folder }}"
    state: "directory"
    mode: "0777"
```

我们这样做的原因是，我们将在下一个任务中启动的容器内挂载此文件夹。由于日志是我们希望保留的每次扫描中的唯一数据，因此我们将它们写入挂载的文件夹，这意味着一旦容器退出并删除，我们就可以将日志复制到我们的 Ansible 控制器上。

在我们看下一个任务之前，让我们快速看一下如果我们直接在命令行上使用 Docker 来启动扫描，我们需要运行的命令：

```
$ docker container run -it --rm --name wpscan -v /tmp/wpscan/:/tmp/wpscan/ wpscanteam/wpscan \
 -u http://10.20.30.41.nip.io/ --update --enumerate --log /tmp/wpscan/10.20.30.41.nip.io-2018-05-19-12-16.txt
```

命令的第一行是 Docker 逻辑发生的地方；我们要求 Docker 做的是在前台(`-it`)启动(`run`)一个名为 wpscan 的容器(`--name`)，将主机上的`/tmp/wpscan/`挂载到容器内的`/tmp/wpscan/`(`-v`)，使用指定的镜像(`wpscanteam/wpscan`)。一旦进程退出，我们就移除容器(`--rm`)。

第二行的所有内容都传递给容器的默认入口点，在`wpscanteam/wpscan`镜像的情况下，入口点是`/wpscan/wpscan.rb`，这意味着我们在容器内运行扫描的命令实际上是这样的：

```
$ /wpscan/wpscan.rb -u http://10.20.30.41.nip.io/ --update --enumerate --log /tmp/wpscan/10.20.30.41.nip.io-2018-05-19-12-16.txt
```

现在我们知道了使用 Docker 运行命令的想法，我们可以看看在我们的任务中它会是什么样子：

```
- name: run the scan
  docker_container:
    detach: false
    auto_remove: true
    name: "wpscan"
    volumes: "{{ log.remote_folder }}:{{ log.remote_folder }}"
    image: "{{ image }}"
    command: "--url http://{{ hostvars[item]['ansible_host'] }} --update --enumerate --log {{ log.remote_folder }}{{ hostvars[item]['ansible_host'] }}-{{ log.file }}"
  register: docker_scan
  failed_when: docker_scan.rc == 0 or docker_scan.rc >= 2
  with_items: "{{ groups['wordpress'] }}"
```

任务中的选项的顺序与 Docker 命令中编写的顺序相同：

+   `detach: false`类似于传递`-it`，它将在前台运行容器；默认情况下，`docker_container`模块在后台运行容器。这引入了一些挑战，我们很快会讨论。

+   `auto_remove: true`与`--rm`相同。

+   `name: "wpscan"`与运行`--name wpscan`完全相同。

+   `volumes:"{{ log.remote_folder }}:{{ log.remote_folder }}"`与在 Docker 中使用`-v`标志传递的内容相同。

+   `image: "{{ image }}"`相当于只传递镜像名称，例如`wpscanteam/wpscan`。

+   最后，`command`包含了我们想要传递给入口点的所有内容；正如你所看到的，我们在这里传递了一些动态变量。

如前所述，默认情况下，`docker_container`模块在后台运行容器；在大多数情况下，这通常是很好的；然而，由于我们只是将容器作为一次性任务来执行我们的扫描，所以我们需要在前台运行它。

这样做实际上会导致错误，因为我们指示 Ansible 保持连接到一个容器，然后一旦扫描过程完成，容器就会终止并被移除。为了解决这个问题，我们正在注册任务的结果，而不是使用`ignore_errors`，我们告诉任务在返回代码(`rc`)等于`0`或等于或大于`2`时失败(`failed_when`)，因为我们的任务应该始终有一个返回代码为`1`。

那么为什么不让容器在后台运行呢？因为下一个任务会将日志文件从 Vagrant 框复制到 Ansible 控制器，如果我们让容器在后台运行，Ansible 将立即转移到下一个任务并复制一个部分写入的文件。

连接到容器并等待其退出意味着我们正在等待扫描完成，然后再进行下一个任务，看起来像这样：

```
- name: download the html report
  fetch:
    src: "{{ log.remote_folder }}{{ hostvars[item]['ansible_host'] }}-{{ log.file }}"
    dest: "{{ log.local_folder }}{{ hostvars[item]['ansible_host'] }}-{{ log.file }}"
    flat: yes
  with_items: "{{ groups['wordpress'] }}"
```

现在我们已经编写了我们的任务，我们可以尝试运行我们的角色。

# 运行 WPScan

要运行扫描，更新`site.yml`文件，使其看起来像下面的代码：

```
- hosts: wordpress
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

```

```
  roles:
    - roles/stack-install
    - roles/stack-config
    - roles/wordpress

- hosts: scan
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/docker
    - roles/wpscan
```

然后运行以下命令：

```
$ ansible-playbook -i production site.yml
```

这应该给你以下结果（截图只显示了扫描而不是完整的 playbook 运行，你应该看到）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/ba811144-905c-42ef-8c2d-89fc0c83b686.png)

此外，你应该在生成的文件夹中找到一个日志文件；其中包含了 WPScan 运行的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/7654170f-9851-4ca8-b3e1-9f829b5f8bef.png)

正如你所看到的，这里有相当多的信息；然而，由于我们是从头开始部署 WordPress 安装，我们应该有一个干净的健康状况。

# OWASP ZAP 角色

既然我们已经介绍了如何在 WPScan 角色中使用 Ansible 运行容器的基础知识，那么创建运行 OWASP ZAP 的角色应该很简单；我们只需使用这个命令：

```
$ ansible-galaxy init roles/zap
```

**Open Web Application Security Project Zed Attack Proxy**或**OWASP ZAP**，是一个开源的 Web 应用安全扫描器。

`roles/zap/defaults/main.yml`中角色的默认值应包含此代码：

```
image: "owasp/zap2docker-stable"
log:
  remote_folder: /tmp/zap/
  local_folder: "generated/"
  file: "{{ ansible_date_time.date }}-{{ ansible_date_time.hour }}-{{ ansible_date_time.minute }}.html"
```

正如您所看到的，我们使用`owasp/zap2docker-stable`镜像，同时我们还在 Vagrant 框中使用`/tmp/zap/`文件夹来存储报告文件。

继续进行`roles/zap/tasks/main.yml`中的任务，我们正在拉取镜像并创建文件夹，就像我们在 WPScan 角色中所做的那样：

```
- name: pull the image
  docker_image:
    name: "{{ image }}"

- name: create the folder which we will mount inside the container
  file:
    path: "{{ log.remote_folder }}"
    state: "directory"
    mode: "0777"
```

让我们看看我们将要运行的`docker`命令，以找出我们需要在下一个任务中放入什么：

```
$ docker container run -it --rm --name zap -v /tmp/zap/:/zap/wrk/ owasp/zap2docker-stable \
 zap-baseline.py -t http://10.20.30.41.nip.io/ -g gen.conf -r 10.20.30.41.nip.io-2018-05-19-14-26.html
```

正如您所看到的，该命令使用了我们之前使用的所有选项；在我们将文件夹挂载到容器中的位置上有所不同，因为 OWASP ZAP 希望我们将要保存的任何文件写入`/zap/wrk/`。这意味着当给出报告名称时，我们不必提供完整的文件系统路径，因为应用程序将默认写入`/zap/wrk/`。

这意味着启动容器的任务应该如下代码所示：

```
- name: run the scan
  docker_container:
    detach: false
    auto_remove: true
    name: "zap"
    volumes: "{{ log.remote_folder }}:/zap/wrk/"
    image: "{{ image }}"
    command: "zap-baseline.py -t http://{{ hostvars[item]['ansible_host'] }} -g gen.conf -r {{ hostvars[item]['ansible_host'] }}-{{ log.file }}"
  register: docker_scan
  failed_when: docker_scan.rc == 0 or docker_scan.rc >= 2
  with_items: "{{ groups['wordpress'] }}"
```

然后我们使用以下任务下载报告：

```
- name: download the html report
  fetch:
    src: "{{ log.remote_folder }}{{ hostvars[item]['ansible_host'] }}-{{ log.file }}"
    dest: "{{ log.local_folder }}{{ hostvars[item]['ansible_host'] }}-{{ log.file }}"
    flat: yes
  with_items: "{{ groups['wordpress'] }}"
```

现在我们已经安排好了任务，我们可以运行该角色。

# 运行 OWASP ZAP

要运行扫描，我们只需将该角色附加到我们的`site.yml`文件的末尾。添加后，运行以下命令：

```
$ ansible-playbook -i production site.yml
```

这将运行 playbook；输出的摘要副本可以在此处找到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/6c6c75df-7b91-46c2-b011-059277d5a7eb.png)

然后将 HTML 文件复制到生成的文件夹中；文件应该类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/1bdfb5fa-4590-4aad-b525-223bd83caf0b.png)

现在，您可以使用以下命令删除 Vagrant 框：

```
$ vagrant destroy
```

然后重新启动框并完整运行 playbook。

# 摘要

在本章中，我们已经看到如何将 Ansible 与 Docker 结合使用，以启动两种不同的工具，对我们使用 Ansible playbook 启动的 WordPress 安装进行外部漏洞扫描。这显示了我们如何可以启动一些相当复杂的工具，而无需担心直接在我们的主机上编写 playbook 来安装、配置和管理它们。

在下一章中，我们将离开命令行，看一下由红帽提供的 Ansible 的两个基于 Web 的界面。

# 问题

1.  为什么我们使用 Docker 而不是直接在我们的 Vagrant 框上安装 WPScan 和 OWASP ZAP？

1.  真或假：`pip`默认安装在我们的 Vagrant 框中。

1.  我们需要安装哪个 Python 模块才能使 Ansible Docker 模块正常运行的模块名称是什么？

1.  更新`Vagrantfile`和`production`文件，以启动第二个 WordPress Vagrant 框并扫描它们。

# 进一步阅读

有关本章中使用的工具的更多信息，请参阅以下链接：

+   **Docker**：[`docker.com`](https://docker.com)

+   **WPScan**：[`wpscan.org`](https://wpscan.org)

+   **OWASP ZAP**：[`www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project`](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)


# 第十五章：介绍 Ansible Tower 和 Ansible AWX

在本章中，我们将研究 Ansible 的两个图形界面，商业版的 Ansible Tower 和开源版的 Ansible AWX。我们将讨论如何安装它们，它们的区别，以及为什么您需要使用它们。毕竟，我们现在已经进行了 15 章的 Ansible 之旅，但还没有需要使用图形界面。

在本章结束时，我们将有：

+   安装了 Ansible Tower 和 Ansible AWX

+   配置了两个工具

+   使用 Ansible Tower 部署了我们的高可用云应用

# 技术要求

我们将使用 Vagrant box 在本地查看使用 Ansible Tower 和 Ansible AWX；我们还将使用我们在第十章中涵盖的 playbook，*高可用云部署*。最终的 playbook 可以在 GitHub 存储库[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter15`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter15)中找到。

# 基于 Web 的 Ansible

在我们查看安装工具之前，我们应该先花时间讨论为什么我们需要它们以及它们之间的区别。

我相信您已经开始注意到我们迄今为止所涵盖的所有 playbook 之间的共同点——在可能的情况下，我们允许我们运行的角色使用尽可能多的参数。这使得我们可以轻松地更改 playbook 运行的输出，而无需直接重写或编辑角色。因此，我们也应该很容易开始使用 Red Hat 提供的两个基于 Web 的工具之一来管理您的 Ansible 部署。

Ansible Tower 是一个商业许可的基于 Web 的图形界面，用于 Ansible。正如前面提到的，您可能很难看到其中的价值。想象一下，将 Ansible 连接到公司的活动目录，并让开发人员等用户使用 Ansible Tower 根据您的 playbook 部署自己的环境，为您提供一种受控的方式来在整个系统中保持一致性，同时允许自助服务。

当 Red Hat 在 2015 年 10 月宣布收购 Ansible 时，发布的 FAQ 中提出的一个问题是：*Red Hat 是否会开源 Ansible 的所有技术？*之所以提出这个问题，是因为 Red Hat 在多年来收购的其他技术中，几乎已经开源了它们的所有方面，不仅邀请社区贡献，还测试和构建新功能，最终使其进入了 Red Hat 的商业支持版本。

其中一个例子是 Fedora 项目。该项目是 Red Hat 企业 Linux 功能的开源上游，包括 Fedora 用户现在正在利用的 DNF，这是 YUM 的替代品。自 2015 年以来，这一直是 Fedora 的默认软件包管理器，如果一切顺利，它应该会进入 Red Hat 企业 Linux 8。

Red Hat 开源其技术的其他示例包括 WildFly，这是 JBoss 的上游，以及由 Red Hat 赞助的 ManageIQ，它是 Red Hat CloudForms 的基础。

2017 年 9 月，Red Hat 宣布将发布 Ansible AWX，这是 Ansible Tower 的开源上游。该项目将与 AWX 团队一起进行每两周的发布，使某些发布版本*稳定*，尽管在这种情况下，稳定并不意味着项目已经准备投入生产，因为该项目仍处于初始开发周期中。

# Ansible Tower

我们将从查看 Ansible Tower 开始。正如您可能还记得的那样，这是商业软件，所以我们需要许可证；幸运的是，Red Hat 提供了试用许可证。您可以通过点击[`www.ansible.com/`](https://www.ansible.com/)上的“尝试 Tower 免费”按钮来请求。

请注意，您必须使用一个商业地址，Ansible 不会接受来自`me.com`、`icloud.com`、`gmail.com`、`hotmain.com`等邮箱地址的请求。

过一会儿，您将收到一封类似以下内容的电子邮件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/fae164f6-44f2-43ba-828d-cfa0dc7d9d48.png)

点击“立即下载塔（.TAR）”按钮；这将打开您的浏览器并下载一个包含我们将用来部署 Ansible Tower 的 playbooks 的 TAR 文件。接下来，我们需要一个服务器来托管我们的 Ansible Tower 安装。让我们使用我们在其他章节中使用过的`Vagrantfile`：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
BOX_NAME = "centos/7"
BOX_IP = "10.20.30.40"
DOMAIN = "nip.io"
PRIVATE_KEY = "~/.ssh/id_rsa"
PUBLIC_KEY = '~/.ssh/id_rsa.pub'

Vagrant.configure(API_VERSION) do |config|
  config.vm.box = BOX_NAME
  config.vm.network "private_network", ip: BOX_IP
  config.vm.host_name = BOX_IP + '.' + DOMAIN
  config.ssh.insert_key = false
  config.ssh.private_key_path = [PRIVATE_KEY, "~/.vagrant.d/insecure_private_key"]
  config.vm.provision "file", source: PUBLIC_KEY, destination: "~/.ssh/authorized_keys"

  config.vm.provider "virtualbox" do |v|
    v.memory = "2024"
    v.cpus = "2"
  end

  config.vm.provider "vmware_fusion" do |v|
    v.vmx["memsize"] = "2024"
    v.vmx["numvcpus"] = "2"
  end

end
```

一旦`Vagrantfile`就位，您可以使用以下命令之一启动 Vagrant 框：

```
$ vagrant up
$ vagrant up --provider=vmware_fusion
```

一旦您的 Vagrant 框已经启动运行，您可以查看需要对清单进行的更改，这些更改包含在我们下载的 TAR 文件中。

# 更新清单文件

在未解压的文件夹的顶层提供了几个文件，要解压文件夹，请双击 TAR 文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/92ca865e-46d5-4d3a-bb4b-654efca1ce0a.png)

我们只需要担心`inventory`文件；在文本编辑器中打开文件并更新它，使其看起来像以下内容：

```
[tower]
10.20.30.40.nip.io ansible_connection=ssh ansible_user=vagrant ansible_private_key_file=~/.ssh/id_rsa host_key_checking=False

[database]

[all:vars]
admin_password='password'

pg_host=''
pg_port=''

pg_database='awx'
pg_username='awx'
pg_password='iHpkiPEAHpGeR8paCoVhwLPH'

rabbitmq_port=5672
rabbitmq_vhost=tower
rabbitmq_username=tower
rabbitmq_password='WUwTLJK2AtdxCfopcXFQoVYs'
rabbitmq_cookie=cookiemonster

# Needs to be true for fqdns and ip addresses
rabbitmq_use_long_name=true

# Isolated Tower nodes automatically generate an RSA key for authentication;
# To disable this behavior, set this value to false
# isolated_key_generation=true
```

正如您所看到的，我们已经更新了`[tower]`组下列出的主机，以包括我们的 Vagrant 框的详细信息和配置；我们还为`admin_password`、`pg_password`和`rabbitmq_password`参数添加了密码。显然，您可以设置自己的密码，而不是使用这里列出的密码。

文件的最终更改是将`rabbitmq_use_long_name`从`false`更新为`true`。如果不这样做，将导致 RabbitMQ 服务无法启动。

# 运行 playbook

现在我们已经更新了`inventory`文件，我们可以运行`install.yml` playbook 来启动 Ansible Tower 的安装。要做到这一点，请运行以下命令：

```
$ ansible-playbook -i inventory --become install.yml
```

playbook 中内置了检查，以查看 playbook 是否作为 root 用户运行。在典型的安装中，playbook 期望您在要安装 Ansible Tower 的机器上以 root 用户身份运行 playbook。然而，我们正在稍微不同的方式进行，因此我们需要使用`--become`标志。

安装过程大约需要 20 分钟，正如您从以下输出中所看到的，安装程序会执行许多任务：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/789e806f-e002-4216-b6b5-92944d9b3012.png)

# 请求许可

现在我们已经安装了 Ansible Tower，还有一些步骤需要完成安装。第一步是登录；要做到这一点，请在浏览器中输入以下 URL：`https://10.20.30.40.nip.io/`。当您首次打开 Tower 时，将会收到有关 SSL 证书的警告；这是因为在部署期间安装的证书是自签名的。可以安全地继续。

现在您应该看到一个登录页面；将用户名输入为`admin`，密码输入为`password`，这是我们之前在`inventory`文件中设置的：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/4e12c388-4b18-42c3-a3f3-fd39ce22da43.png)

然后点击“登录”按钮；这将带您到一个页面，指示您输入许可文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/af0bc969-d4be-4aea-afd5-fd236f80442c.png)

点击“请求许可”按钮将带您到[`www.ansible.com/license/`](https://www.ansible.com/license/)；在这里，您可以选择为您的安装请求两种类型的许可。我们将请求免费的 Ansible Tower 试用版 - 有限功能最多支持 10 个节点的许可。选择许可类型，填写表格，并按提示提交。

过一会儿，您应该会收到几封电子邮件，其中一封欢迎您使用 Ansible Tower。另一封电子邮件包含许可文件。复制附加的许可文件，并在 Tower 许可页面上使用 BROWSE 按钮上传它。还要审查并同意最终用户协议。上传许可文件并同意最终用户许可协议后，点击提交。

几秒钟后，您将首次看到 Ansible Tower 的外观：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/41ca39b4-0dbe-4c1d-a16f-7398de59637c.png)

现在我们已经安装了 Ansible Tower，我们可以开始运行我们的第一个 playbook。

# hello world 演示项目

如您所见，我们已经配置了一个项目；这是一个非常基本的项目，它从[`github.com/ansible/ansible-tower-samples/`](https://github.com/ansible/ansible-tower-samples/)下载示例 playbook，并显示消息 Hello World。在运行 playbook 之前，我们首先需要从 GitHub 下载一个副本；要做到这一点，请点击顶部菜单中的 PROJECTS。

您将能够看到列出的 Demo Project。将鼠标悬停在操作下的图标上将为您提供单击时每个图标将执行的描述；我们要点击的是第一个图标，即启动 SCM 更新。不久后，您应该看到 REVISION 和**LAST UPDATED**都已填充：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/ed0bb817-c5fb-4151-a62d-301e52c1a3b8.png)

这意味着 Ansible Tower 现在已从 GitHub 下载了演示 playbook；我们现在可以运行 playbook。要做到这一点，请点击顶部菜单中的 TEMPLATES。

同样，您应该看到有一个名为 Demo Job Template 的模板，并且在该行的右侧有几个图标。我们要点击的是看起来像火箭的图标。点击使用此模板启动作业将运行演示作业；您将被带到一个屏幕，您可以在其中监视作业的进度。

完成后，您应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/37ebd7b4-0675-4c1a-bb65-b0779b2ea23e.png)

如您所见，在左侧，您可以看到工作本身的概述；这告诉您状态，开始和结束的时间，以及哪个用户请求执行该工作。页面右侧的部分显示了 playbook 的输出，这与我们从命令行执行 playbook 时看到的完全相同。

让我们来运行一些更复杂的东西。

# 启动 AWS playbook

在第十章中，*高可用云部署*，我们通过一个 playbook 来运行 WordPress 的 AWS 核心 Ansible 模块来启动一个集群；在 GitHub 上托管了`aws-wordpress` playbook 的独立版本，网址为[`github.com/russmckendrick/aws-wordpress/`](https://github.com/russmckendrick/aws-wordpress/)。让我们使用这个来使用 Ansible Tower 部署我们的 AWS 集群。

在配置 Ansible Tower 中的 playbook 之前，我们需要对作为 Ansible Tower 安装的一部分部署的一些 Python 模块的版本进行一些清理。这是因为我们的 playbook 的某些部分需要更高版本的 Boto 模块。

为了做到这一点，我们需要通过运行以下命令 SSH 到我们的 Ansible Tower 主机：

```
$ vagrant ssh
```

现在我们以 Vagrant 用户登录，我们可以使用以下命令更改 root：

```
$ sudo -i
```

接下来，我们切换到与 Ansible Tower 使用相同的 Python 环境；为此，我们运行以下命令：

```
$ source /var/lib/awx/venv/ansible/bin/activate
```

现在我们正在使用正确的环境，我们需要使用以下命令升级`boto`库：

```
$ pip install boto boto3 botocore --upgrade
```

更新后，我们可以通过运行退出 Ansible Tower Python 环境：

```
$ deactivate
```

然后，我们使用`exit`命令退出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/93972b61-5047-4b28-bed5-eb3433ac515b.png)

现在我们的环境已更新，我们可以继续添加一个新项目。

# 添加一个新项目

我们需要做的第一件事是添加一个新项目；这是我们让 Ansible Tower 知道我们的 playbook 存储库的地方。如前所述，我们将使用一个 GitHub 存储库来存放代码。要添加新项目，点击顶部菜单中的项目，然后点击右侧的+添加按钮，该按钮可以在顶部菜单的图标行下方找到。

在这里，您将被要求输入一些信息；输入以下内容：

+   名称：`AWS 项目`

+   描述：`AWS WordPress 集群`

+   组织：`默认`

+   SCM 类型：GIT

选择 SCM 类型时，将出现第二部分，要求输入源代码存放的详细信息：

+   SCM URL：`https://github.com/russmckendrick/aws-wordpress.git`

+   SCM 分支/标签/提交：主

+   SCM 凭据：留空，因为这是一个公开可访问的存储库

+   清除：打勾

+   更新时删除：打勾

+   启动时更新：打勾

+   缓存超时（秒）：保持为零

输入详细信息后，点击保存。如果现在返回到项目页面，您应该会看到 Ansible 已经下载了 playbook 的源代码：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/24a65a34-ffd8-4f41-b8b4-7125c23be058.png)

# 添加凭据

接下来，我们需要让 Ansible Tower 知道在访问我们的 AWS 账户时要使用的凭据；要添加这些凭据，点击顶部菜单中的设置图标（顶部菜单中的齿轮图标），您将被带到一个看起来像以下内容的屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/511cdd09-30d8-4e89-9dcc-f401feb5cc36.png)

正如您所看到的，这里有很多不同的选项。您可能已经猜到，我们感兴趣的选项是凭据。点击它将带您到一个页面，该页面会给您一个现有凭据的概述；我们想要添加一些新的凭据，所以点击+添加按钮。

这将带您到一个页面，布局类似于我们添加项目的页面。填写以下信息：

+   名称：`AWS API 凭据`

+   描述：`AWS API 凭据`

+   组织：`默认`

+   凭据类型：点击放大镜图标，选择 Amazon Web Services

选择凭据类型后，将添加第二部分；在这里，您可以输入以下内容：

+   访问密钥：添加您在之前的 AWS 章节中的访问密钥，例如，`AKIAI5KECPOTNTTVM3EDA`

+   秘钥：添加您在之前的 AWS 章节中的秘钥，例如，`Y4B7FFiSWl0Am3VIFc07lgnc/TAtK5+RpxzIGTr`

+   STS 令牌：留空

表单填写完成后，点击保存。保存后，您会注意到密钥被标记为加密：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/b6cf5b66-48ca-40fa-bbb6-ab7ae358c6c8.png)

当您在 Ansible Tower 中保存敏感信息时，它会被加密，您只能选择替换或恢复它。在任何时候，您都不能再查看这些信息。

# 添加库存

现在我们已经有了凭据，我们需要在 Ansible Tower 中重新创建名为`production`的库存文件的内容。作为提醒，文件看起来像下面这样：

```
# Register all of the host groups we will be creating in the playbooks
[ec2_instance]
[already_running]

# Put all the groups into into a single group so we can easily apply one config to it for overriding things like the ssh user and key location
[aws:children]
ec2_instance
already_running

# Finally, configure some bits to allow us access to the instances before we deploy our credentials using Ansible
[aws:vars]
ansible_ssh_user=centos
ansible_ssh_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

要添加库存，点击顶部菜单中的库存，然后点击+添加按钮。您会注意到+添加按钮现在会弹出一个下拉列表；从该列表中，我们要添加一个库存。

在打开的表单中，输入以下内容：

+   名称：`AWS 库存`

+   描述：`AWS 库存`

+   组织：`默认`

+   洞察凭据：留空

+   洞察组：留空

+   变量：输入以下列出的值：

```
ansible_ssh_user: "centos"
ansible_ssh_private_key_file: "~/.ssh/id_rsa"
host_key_checking: "False"
```

输入后，点击保存；这将创建库存，现在我们可以添加我们需要的两个组。要做到这一点，点击组，可以在表单上方的按钮行中找到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/6abeb18c-4611-4245-84f4-8c73e6cfd01f.png)

点击**+添加组**，然后输入以下详细信息：

+   名称：`ec2_instance`

+   描述：`ec2_instance`

+   变量：留空

然后点击保存，重复该过程，并使用以下详细信息添加第二个组：

+   名称：`already_running`

+   描述：`already_running`

+   变量：留空

再次点击保存；现在应该列出两个组：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/653abd86-9d9f-4828-ac8a-6f6cbf23fa19.png)

现在我们已经有了我们的项目、库存和一些用于访问我们的 AWS 的凭据，我们只需要添加模板，一个用于启动和配置集群，另一个用于终止它。

# 添加模板

点击顶部菜单中的 TEMPLATES，然后在+ADD 按钮的下拉菜单中选择作业模板。这是我们迄今为止遇到的最大表单；但是，当我们开始填写详细信息时，其中的部分将自动填充。让我们开始吧：

+   名称：`AWS - 启动`

+   描述：启动和部署 WordPress 实例

+   工作类型：保持为运行

+   库存：点击图标并选择 AWS 库存

+   项目：点击图标并选择`AWS 项目`

+   游戏规则：从下拉列表中选择`site.yml`

+   凭据：选择 Amazon Web Services 的凭据类型，然后选择 AWS API 凭据；还为 MACHINE 选择演示凭据

+   分叉：保持默认

+   限制：留空

+   详细程度：保持为`0`（正常）

+   实例组、作业标签、跳过标签、标签：留空

+   显示更改：关闭

+   选项和额外变量：保持默认值

点击保存，您可以添加第二个模板来删除集群。要做到这一点，点击+ADD 按钮并再次选择作业模板；这次使用以下信息：

+   名称：`AWS - 删除`

+   描述：移除 WordPress 集群

+   工作类型：保持为运行

+   库存：点击图标并选择 AWS 库存

+   项目：点击图标并选择`AWS 项目`

+   游戏规则：从下拉列表中选择`remove.yml`

+   凭据：选择 Amazon Web Services 的凭据类型，然后选择 AWS API 凭据；还为 MACHINE 选择演示凭据

+   分叉：保持默认

+   限制：留空

+   详细程度：保持为`0`（正常）

+   实例组、作业标签、跳过标签、标签：留空

+   显示更改：关闭

+   选项和额外变量：保持默认值

# 运行剧本

现在我们的剧本已经准备好运行，我们可以通过点击顶部菜单中的 TEMPLATES，然后点击`AWS -Launch`旁边的运行图标，来运行它。这将花费与我们从命令行执行时一样多的时间来运行：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/51ab538f-b42d-480d-ba33-a0257a04bbdd.png)

正如您从前面的截图中所看到的，一切都按预期构建和运行，这意味着当我们转到弹性负载均衡器 URL 时，我们将能够看到我们的 WordPress 网站：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/d97f6a4b-b560-46b3-a8b9-2ea9b55111ec.png)

# 删除集群

现在我们已经启动了集群，我们可以运行第二个剧本，将其删除。要做到这一点，点击顶部菜单中的 TEMPLATES，然后点击运行图标，即`AWS -Remove`旁边的火箭图标。这将启动剧本，删除我们刚刚启动的一切。同样，运行所有任务需要一点时间。

需要指出的是，为了使`remove.yml`剧本能够通过 Ansible Tower 成功执行，您必须更新`roles/remove/tasks/main.yml`中的一个任务。如果您还记得，我们在那里有以下几行：

```
- name: prompt
  pause:
    prompt: "Make sure the elastic load balancer has been terminated before proceeding"
```

如果此任务存在，那么我们的剧本执行将在此任务处停顿，而不会继续进行，因为 Ansible Tower 剧本运行不是交互式的。该任务已被以下内容替换：

```
- name: wait for 2 minutes before continuing
  pause:
    minutes: 2
```

这是我们的剧本能够在 Ansible Tower 上运行所需的唯一更改；其他一切保持不变。

# Tower 摘要

虽然我们只有时间运行了一个基本的剧本，但我相信您已经开始看到使用 Ansible Tower 为所有用户运行剧本的优势了。您可以使用许多功能。但是，目前有三个不同版本的 Ansible Tower 可用。以下表格提供了每个版本中可用功能的快速概述：

| **功能** | **自助支持** | **标准** | **高级** |
| --- | --- | --- | --- |
| 仪表板：获取 Ansible Tower 状态的概述 | 是 | 是 | 是 |
| 实时作业输出：实时查看作业的输出 | 是 | 是 | 是 |
| 作业调度：按计划执行作业；还可以设置重复运行，例如，每个工作日上午 9 点运行部署开发实例的作业 | 是 | 是 | 是 |
| 从源代码控制中拉取：将您的 playbooks 托管在源代码控制中，比如 Git 或 SVN | 是 | 是 | 是 |
| 工作流程：在一个作业中链接多个 playbooks | 否 | 是 | 是 |
| 基于角色的访问：对用户及其访问权限进行精细控制 | 是 | 是 | 是 |
| 与第三方身份验证集成：将您的 Tower 安装连接到 Active Directory 或 LDAP 身份验证服务器 | 否 | 是 | 是 |
| 调查：为用户构建表单，作为作业运行的一部分填写；这允许用户提供信息，而无需编写任何 YAML | 否 | 是 | 是 |
| 来自红帽的 8x5 支持 | 否 | 是 | 是 |
| 来自红帽的 24x7 支持 | 否 | 否 | 是 |

Ansible Tower 的当前许可成本如下：

+   **自助支持最多 10 个节点**：免费；这是我们应用于我们的安装的许可证

+   **自助支持最多 100 个节点**：每年 5,000 美元

+   **自助支持最多 250 个节点**：每年 10,000 美元

+   **标准最多 100 个节点**：每年 10,000 美元

+   **标准超过 100 个节点**：自定义定价，请联系 Ansible

+   **高级最多 100 个节点**：每年 14,000 美元

+   **高级超过 100 个节点**：自定义定价，请联系 Ansible

这些价格不包括由红帽支持的 Ansible Engine；如果您想要受支持的 Ansible 引擎，除了这里列出的费用之外，还有额外的费用。

因此，虽然 Ansible Tower 非常好，但可能不在每个人的预算范围内，这就是 Ansible AWX 的用武之地。

# Ansible AWX

让我们直接开始安装 Ansible AWX；我们将需要一个 Vagrant box，在 Vagrant box 上安装 Docker，最后是 AWX 源的副本。

# 准备 playbook

对于我们的安装，我们将使用 Ansible 来准备我们的 Vagrant box 并安装 Ansible AWX。要为 playbook 创建结构，请运行以下命令：

```
$ mkdir awx awx/group_vars awx/roles
$ touch awx/production awx/site.yml awx/group_vars/common.yml awx/Vagrantfile
```

我们将使用的`Vagrantfile`可以在这里找到：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
BOX_NAME = "centos/7"
BOX_IP = "10.20.30.50"
DOMAIN = "nip.io"
PRIVATE_KEY = "~/.ssh/id_rsa"
PUBLIC_KEY = '~/.ssh/id_rsa.pub'

Vagrant.configure(API_VERSION) do |config|
  config.vm.box = BOX_NAME
  config.vm.network "private_network", ip: BOX_IP
  config.vm.host_name = BOX_IP + '.' + DOMAIN
  config.ssh.insert_key = false
  config.ssh.private_key_path = [PRIVATE_KEY, "~/.vagrant.d/insecure_private_key"]
  config.vm.provision "file", source: PUBLIC_KEY, destination: "~/.ssh/authorized_keys"

  config.vm.provider "virtualbox" do |v|
    v.memory = "2024"
    v.cpus = "2"
  end

  config.vm.provider "vmware_fusion" do |v|
    v.vmx["memsize"] = "2024"
    v.vmx["numvcpus"] = "2"
  end

end
```

我们要创建的第一个角色是我们已经涵盖过的角色；它是来自第十四章的 Docker 角色，*部署 WPScan 和 OWASP ZAP*。

# docker 角色

我不打算详细介绍任务，因为这些已经涵盖过了。我们可以通过运行以下命令来引导角色：

```
$ ansible-galaxy init roles/docker
```

现在我们已经放置了文件，我们可以使用以下内容更新`roles/docker/defaults/main.yml`文件：

```
docker:
  gpg_key: "https://download.docker.com/linux/centos/gpg"
  repo_url: "https://download.docker.com/linux/centos/docker-ce.repo"
  repo_path: "/etc/yum.repos.d/docker-ce.repo"
  packages:
    - "docker-ce"
    - "device-mapper-persistent-data"
    - "lvm2"
    - "python-setuptools"
    - "libselinux-python"
  pip:
    - "docker"
```

`roles/docker/tasks/main.yml`的内容应该是：

```
- name: update all of the installed packages
  yum:
    name: "*"
    state: "latest"
    update_cache: "yes"

- name: add the gpg key for the docker repo
  rpm_key:
    key: "{{ docker.gpg_key }}"
    state: "present"

- name: add docker repo from the remote url
  get_url:
    url: "{{ docker.repo_url }}"
    dest: "{{ docker.repo_path }}"
    mode: "0644"

- name: install the docker packages
  yum:
    name: "{{ item }}"
    state: "installed"
    update_cache: "yes"
  with_items: "{{ docker.packages }}"

- name: install pip
  easy_install:
    name: pip
    state: latest

- name: install the python packages
  pip:
    name: "{{ item }}"
  with_items: "{{ docker.pip }}"

- name: put selinux into permissive mode
  selinux:
    policy: targeted
    state: permissive

- name: start docker and configure to start on boot
  service:
    name: "docker"
    state: "started"
    enabled: "yes"
```

这应该安装 AWX 安装的 Docker 部分，并允许我们转移到下一个角色。

# awx 角色

我们的 AWX 安装的下一个（有点）最终角色可以通过运行以下命令创建：

```
$ ansible-galaxy init roles/awx
```

`roles/awx/defaults/main.yml`中的默认变量格式与`docker`角色中的变量类似：

```
awx:
  repo_url: "https://github.com/ansible/awx.git"
  logo_url: "https://github.com/ansible/awx-logos.git"
  repo_path: "~/awx/"
  packages:
    - "git"
  pip:
    - "ansible"
    - "boto"
    - "boto3"
    - "botocore"
  install_command: 'ansible-playbook -i inventory --extra-vars "awx_official=true" install.yml'
```

从头开始，我们有两个不同的 GitHub 存储库 URL。第一个`awx.repo_url`是主 AWX 存储库，第二个`awx.logo_url`是官方标志包。接下来，我们有路径`awx.repo_path`，我们也想检出代码。在这种情况下，它是`~/awx`，因为我们使用`become`，它将是`/root/awx/`。

要从 GitHub 检出代码，我们需要确保已安装 Git。`awx.packages`是我们需要使用`yum`安装的唯一附加软件包。接下来，我们需要安装 Ansible 本身以及我们将使用 PIP（`awx.pip`）安装的其他一些 Python 软件包。

最后，我们有一个命令（`awx.install_command`），我们需要运行以安装 Ansible AWX。如您所见，我们正在使用作为我们正在检查的代码的一部分提供的 Ansible playbook；命令本身正在通过传递`awx_official=true`作为额外变量来覆盖使用官方 AWX 标志的选项。

现在我们已经讨论了我们需要定义的变量，我们可以将任务添加到`roles/awx/tasks/main.yml`中，从安装 Yum 和 Pip 软件包的任务开始：

```
- name: install the awx packages
  yum:
    name: "{{ item }}"
    state: "installed"
    update_cache: "yes"
  with_items: "{{ awx.packages }}"

- name: install the python packages
  pip:
    name: "{{ item }}"
  with_items: "{{ awx.pip }}"
```

接下来，我们有检出两个 AWX 存储库的任务来自 GitHub：

```
- name: check out the awx repo
  git:
    repo: "{{ awx.repo_url }}"
    dest: "{{ awx.repo_path }}"
    clone: "yes"
    update: "yes"

- name: check out the awx logos repo
  git:
    repo: "{{ awx.logo_url }}"
    dest: "{{ awx.repo_path }}"
    clone: "yes"
    update: "yes"
```

如您所见，两个存储库都将移动到 Vagrant 盒子上的相同位置。最后一个任务运行了下载、配置和启动 Ansible AWX Docker 容器的 playbook：

```
- name: install awx
  command: "{{ awx.install_command }}"
  args:
    chdir: "{{ awx.repo_path }}installer"
```

# 运行 playbook

现在我们已经准备好了我们的 playbook，我们可以将我们的主机清单信息添加到`production`文件中：

```
box ansible_host=10.20.30.50.nip.io

[awx]
box

[awx:vars]
ansible_connection=ssh
ansible_user=vagrant
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

最后，我们可以将以下内容添加到`site.yml`文件中，然后我们就可以运行我们的安装了：

```
---

- hosts: awx
  gather_facts: true
  become: yes
  become_method: sudo

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/docker
    - roles/awx
```

为了让 Ansible AWX 运行起来，我们需要执行以下命令中的一个来启动 Vagrant 盒子：

```
$ vagrant up
$ vagrant up --provider=vmware_fusion
```

然后，以下命令将运行 playbook：

```
$ ansible-playbook -i production site.yml
```

运行 playbook 需要几分钟时间；完成后，您应该会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/978a3929-0a39-4176-9ab7-9a3904f7fe65.png)

打开浏览器并转到`http://10.20.30.50.nip.io/`应该会显示以下消息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/15b0a5e1-cdcf-472c-89b7-5dd3bde9e0f2.png)

保持页面打开，几分钟后，您应该会看到一个登录提示。

# 使用 Ansible AWX

您应该会看到登录提示。用户名和密码是`admin`/`password`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/ce021ce4-f26e-4c3b-8f72-b176feee04e3.png)

当您首次登录时，您可能会注意到外观和感觉与 Ansible Tower 相似，尽管有一些差异：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/36b9751c-cc82-4d13-b008-cb2cac6a3148.png)

如您所见，菜单已从顶部移至左侧，并且还有更多选项。在左侧菜单中点击 PROJECTS 将带您到页面，您可以获取我们在 Ansible Tower 中首次运行的 hello-world 示例的最新 SVM 修订版。点击云图标进行下载。

一旦项目同步完成，点击左侧菜单中的 TEMPLATES；您应该会看到一个空列表。点击+按钮并从下拉列表中选择作业模板。

这将带你到一个页面，与我们在 Ansible Tower 中添加模板时看到的相同。填写以下细节：

+   名称：`Demo Template`

+   描述：`运行 hello-world 示例`

+   作业类型：保持为运行

+   清单：点击图标并选择`Demo Inventory`

+   **PROJECT**：点击图标并选择`Demo Project`

+   **PLAYBOOK**：从下拉列表中选择`hello-world.yml`

+   **CREDENTIAL**：点击图标并从列表中选择**Demo Credential**

+   **FORKS**：保持默认

+   **LIMIT**：留空

+   **VERBOSITY**：保持为`0`（正常）

+   **INSTANCE GROUPS**，**JOB TAGS**，**SKIP TAGS**，**LABELS**：留空

+   **显示更改**：保持关闭

+   **OPTIONS**和**EXTRA VARIABLES**：保持默认值

填写完毕后，点击表单底部的**保存**按钮。现在点击左侧菜单中的 TEMPLATES 将显示`Demo Template`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/2315d6be-97ba-4765-ac5c-5bca300f6dba.png)

点击火箭图标，或者**使用此模板启动作业**，将运行 hello world playbook：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/5850f7c3-e70f-4bf8-bff2-e59346fcffdb.png)

所以我们已经对 Ansible AWX 进行了一个非常快速的概述，正如我已经提到的，它与 Ansible Tower 并没有太大的不同。

# AWX 摘要

让我们现在解决这个问题。在撰写本文时，红帽不建议在生产环境中使用 Ansible AWX。就我个人而言，我发现它相当稳定，尤其是对于不断发展的软件。当然，在升级时可能会出现一些问题，但大多数情况下这些问题都很小。

由于 Ansible AWX 是 Ansible Tower 的上游，因此具有一些功能，例如能够使用第三方身份验证服务和工作流程，这些功能在自支持版本的 Ansible Tower 中不存在。您可以管理的主机数量也没有限制。这使得 Ansible AWX 成为 Ansible Tower 的一个非常有吸引力的替代品；但是，您需要考虑其开发周期以及升级可能如何影响您的 AWX 安装的日常运行。

# 总结

在本章中，我们已经通过安装和使用两种不同的 Web 前端来运行您的 Ansible playbooks。我们还讨论了前端各个版本之间的成本、功能和稳定性差异。

我相信您会同意，使用诸如 Ansible Tower 或 Ansible AWX 这样的工具将允许您的用户、同事和最终用户以受支持和一致的方式使用您编写的 playbooks。

在下一章中，我们将更详细地了解`ansible-galaxy`命令和服务。

# 问题

1.  阐明 Ansible Tower 和 Ansible AWX 之间的区别并解释。

1.  使用 Ansible AWX，配置并运行 AWS WordPress playbook，就像我们在 Ansible Tower 中所做的那样。

# 进一步阅读

有关这两个软件的更多详细信息，请参阅以下网址：

+   **Ansible Tower 概述**: [`www.ansible.com/products/tower/`](https://www.ansible.com/products/tower/)

+   **Ansible Tower 完整功能列表**: [`www.ansible.com/products/tower/editions/`](https://www.ansible.com/products/tower/editions/)

+   **Ansible AWX 公告**: [`www.redhat.com/en/about/press-releases/red-hat-advances-enterprise-and-network-automation-new-ansible-offerings/`](https://www.redhat.com/en/about/press-releases/red-hat-advances-enterprise-and-network-automation-new-ansible-offerings/)

+   **Ansible AWX 常见问题**: [`www.ansible.com/products/awx-project/faq/`](https://www.ansible.com/products/awx-project/faq/)

+   **Ansible AWX GitHub 存储库**: [`github.com/ansible/awx/`](https://github.com/ansible/awx/)
