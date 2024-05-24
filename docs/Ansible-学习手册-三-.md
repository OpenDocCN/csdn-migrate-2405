# Ansible 学习手册（三）

> 原文：[`zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5`](https://zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：核心网络模块

在本章中，我们将介绍随 Ansible 一起提供的核心网络模块。由于这些模块的要求，我们只会简要介绍这些模块提供的功能，并提供一些用例和示例。

本章将涵盖以下主题：

+   核心网络模块

+   与服务器本地防火墙交互

+   与网络设备交互

# 技术要求

在本章中，我们将启动一个运行软件防火墙的 Vagrant 虚拟机。您需要安装 Vagrant 并访问互联网；Vagrant 虚拟机大小约为 400MB。我们将在本章中使用的完整版本 playbook 可以在[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter07/vyos`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter07/vyos)上找到。

# 制造商和设备支持

到目前为止，我们一直在查看与服务器交互的模块。在我们的情况下，它们都在本地运行。在后面的章节中，我们将与远程托管的服务器进行通信。在开始与远程服务器交互之前，我们应该先了解核心网络模块。

这些模块都被设计用来与各种网络设备交互和管理配置，从传统的顶部交换机和完全虚拟化的网络基础设施到防火墙和负载均衡器。Ansible 支持许多非常不同的设备，从开源虚拟设备到根据配置可能成本超过 50 万美元的解决方案。

# 模块

我在这里列出了每个设备和操作系统。对于每个设备，都有一个加粗显示的简称。每个简称都是模块的前缀。例如，在第一个设备中，有一个名为**a10_server**的模块，用于使用 aXAPIv2 API 管理**服务器负载均衡器**（**SLB**）对象。

# A10 Networks

**A10**模块支持 A10 Networks AX、SoftAX、Thunder 和 vThunder 设备。这些都是应用交付平台，提供负载均衡。除其他功能外，这几个模块允许您在物理和虚拟设备上管理负载平衡和虚拟主机。

# 思科应用中心基础设施（ACI）

50 多个**ACI**模块用于管理思科的 ACI 的所有方面，这是可以预期的，因为这是思科的下一代 API 驱动的网络堆栈。

# 思科 AireOS

两个**AireOS**模块允许您与运行 AireOS 的思科无线局域网控制器进行交互。其中一个模块允许您直接在设备上运行命令，另一个用于管理配置。

# Apstra 操作系统（AOS）

大约十几个**AOS**模块都标记为已弃用，因为它们不支持 AOS 2.1 或更高版本。这些模块将在即将发布的 Ansible 版本 2.9 之前被替换，确切地说。

# Aruba 移动控制器

只有两个**Aruba**模块。这些允许您管理惠普的 Aruba 移动控制器的配置并执行命令。

# 思科自适应安全设备（ASA）

有三个**ASA**模块，您可以管理访问列表，并运行命令和管理物理和虚拟的思科 ASA 设备的配置。

# Avi Networks

在撰写本文时，有 65 个**Avi**模块，允许您与 Avi 应用服务平台的所有方面进行交互，包括负载均衡和**Web 应用防火墙**（**WAF**）功能。

# Big Switch Networks

有三个 Big Switch Network 模块。其中一个**Big Cloud Fabric**（**BCF**）允许您创建和删除 BCF 交换机。另外两个模块允许您创建**Big Monitoring Fabric**（**Big Mon**）服务链和策略。

# Citrix Netscaler

目前有一个已弃用的**Netscaler**模块。它将在 Ansible 2.8 中被移除。这给了您足够的时间转移到新模块。单一模块已被 14 个其他模块取代，这些模块允许您管理负载均衡器和 Citrix 安全设备中更多的功能。

# 华为 CloudEngine（CE）

有 65 多个**CE**模块，可以让您管理华为的这些强大交换机的所有方面，包括 BGP、访问控制列表、MTU、静态路由、VXLAN，甚至 SNMP 配置。

# Arista CloudVision（CV）

有一个单一模块，可以让您使用配置文件配置 Arista **CV**服务器端口。

# Lenovo CNOS

有 15 多个模块，可以让您管理运行联想**CNOS**操作系统的设备；它们允许您管理从 BGP 和端口聚合到 VLAG、VLAN，甚至工厂重置设备的所有内容。

# Cumulus Linux（CL）

在八个**CL**中，有七个已被弃用，取而代之的是一个模块，使用**网络命令行实用程序**（**NCLU**）与您的 Cumulus Linux 设备进行通信。

# Dell 操作系统 10（DellOS10）

**DellOS10**有三个模块，可以让您在运行戴尔网络操作系统的设备上执行命令，管理配置并收集信息。还有**Dell 操作系统 6**（**DellOS6**）和**Dell 操作系统 9**（**DellOS9**）的模块。

# Ubiquiti EdgeOS

有适用于**EdgeOS**的模块，可以让您管理配置，执行临时命令，并收集运行 EdgeOS 的设备（如 Ubiquiti EdgeRouter）的信息。

# 联想企业网络操作系统（ENOS）

有三个模块适用于联想**ENOS**。与其他设备一样，这些模块允许您收集信息，执行命令并管理配置。

# Arista EOS

有 16 个模块，可以让您管理运行**EOS**的设备。这些模块允许您配置接口、VLAN、VRF、用户、链路聚合、静态路由，甚至日志记录。还有一个模块，可以让您从每个设备中收集信息。

# F5 BIG-IP

有 65 个模块，所有这些模块都以**BIG-IP**为前缀，可以让您管理 F5 BIG-IP 应用交付控制器的所有方面。

# FortiGate FortiManager

有一个单一模块，可以让您使用**FortiManager**（**fmgr**）添加、编辑、删除和执行脚本，针对您的 FortiGate 设备。

# FortiGate FortiOS

作为核心网络模块的一部分，有三个模块可以让您管理 FortiGate **FortiOS**设备上的地址、配置和 IPv4 策略对象。

# illumos

**illumos**是 OpenSolaris 操作系统的一个分支。它具有几个强大的网络功能，使其成为部署自建路由器或防火墙的理想选择。使用了三个前缀：`dladm`、`flowadm`和`ipadm`。这些模块允许您管理接口、NetFlow 和隧道。此外，由于 illumos 是 OpenSolaris 的一个分支，您的 playbook 应该适用于基于 OpenSolaris 的操作系统。

# Cisco IOS 和 IOS XR

有大约 25 个模块，可以让您管理您的 Cisco **IOS**和**IOS XR**设备。使用它们，您可以收集设备信息，以及配置用户、接口、日志记录、横幅等。

# Brocade IronWare

有三个通常的模块，可以帮助您管理您的 Brocade **IronWare**设备；您可以配置、运行临时命令和收集信息。

# Juniper Junos

有 20 个模块，可以让您在 playbooks 中与运行**Junos**的 Juniper 设备进行交互。这些模块包括标准命令、配置和信息收集模块，以及允许您安装软件包并将文件复制到设备的模块。

# Nokia NetAct

有一个单一模块，可以让您上传并应用您的 Nokia **NetAct**驱动的核心和无线电网络。

# Pluribus Networks Netvisor OS

有超过十个模块允许您管理您的**Pluribus Networks**（**PN**）Netvisor OS 设备，从创建集群和路由器到在白盒交换机上运行命令。

# Cisco Network Services Orchestrator (NSO)

有少数模块允许您与您的 Cisco **NSO**管理的设备进行交互。您可以执行 NSO 操作，从您的安装中查询数据，并在服务同步和配置方面验证您的配置。

# Nokia Nuage Networks Virtualized Services Platform (VSP)

有一个单一模块允许您管理您的 Nokia **Nuage** Networks VSP 上的企业。

# Cisco NX-OS (NXOS)

可以想象，有很多模块用于管理运行 Cisco **NXOS**的设备——超过 70 个。其中一些正在被弃用。有这么多模块，您可以获得这个强大网络操作系统所有功能的广泛覆盖。

# Mellanox ONYX

有超过十几个模块允许您与 Mellanox 的交换机操作系统**ONYX**进行交互。您可以管理 BGP、L2 和 L3 接口，以及 LDAP。

# Ordnance

有两个模块用于**Ordnance** Router as a Service；它们允许您应用配置更改并收集信息。

# Open vSwitch (OVS)

有三个模块允许您管理**OVS**虚拟交换机上的桥接、端口和数据库。

# Palo Alto Networks PAN-OS

有超过 20 个模块可以让您配置、管理和审计运行 PAN-OS（**panos**）的 Palo Alto Networks 设备。目前有一些模块正在被弃用；它们将在 Ansible 2.5 中停止作为核心模块分发。

# Radware

最近推出的少量模块允许您通过**vDirect**服务器管理您的 Radware 设备。

# Nokia Networks Service Router Operating System (SROS)

有三个模块允许您对 Nokia Networks 的**SROS**设备运行命令、配置和回滚更改。

# VyOS

有十几个模块允许您管理**VyOS**开源 Linux 路由器和防火墙的大多数方面。我们将在下一节中看一下 VyOS。

# 系统

还有一些通用的**net**模块，允许您管理基于 Linux 的网络设备上的接口、Layer2 和 Layer3 配置、NETCONF、路由，以及 LLDP 服务。

# 与网络设备交互

正如在本章开头已经提到的，我们将使用 Vagrant 启动一个网络设备，然后运行一个 playbook 来应用基本配置。我们将要启动的设备是 VyOS。虽然设备将是完整的 VyOS 安装，但我们将只应用一个测试配置，以便让您了解我们在上一节提到的模块如何使用。

在附带本标题的 GitHub 存储库中有这个 playbook 的完整副本。

# 启动网络设备

为了做到这一点，我们将使用一个 VyOS Vagrant box。如果您在跟随，我们首先需要创建一个名为`vyos`的文件夹。这将保存我们的 playbook 和`Vagrantfile`。要创建所需的文件夹结构和空白文件，运行以下命令：

```
$ mkdir vyos vyos/group_vars vyos/roles
$ ansible-galaxy init vyos/roles/vyos-firewall
$ touch vyos/Vagrantfile
$ touch vyos/production
$ touch vyos/site.yml
$ touch vyos/group_vars/common.yml
$ touch vyos/roles/vyos-firewall/templates/firewall.j2 
```

将以下代码复制到我们创建的空白`Vagrantfile`中：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
BOX_NAME    = "russmckendrick/vyos"
BOX_IP      = "192.168.50.10"
DOMAIN      = "nip.io"
PRIVATE_KEY = "~/.ssh/id_rsa"
PUBLIC_KEY  = '~/.ssh/id_rsa.pub'

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
```

```
    v.vmx["numvcpus"] = "2"
  end

end
```

正如您所看到的，`Vagrantfile`看起来与我们在以前章节中使用的并没有太大不同。现在让我们来看一下`vyos_firewall`角色。在执行和编写角色时有一些不同之处，我们在启动之前应该讨论一下。

# VyOS 角色

在我们进入任务之前，让我们先看一下我们将要使用的变量。首先是`roles/vyos-firewall/defaults/main.yml`的内容：

```
---

motd_asciiart: |
  -----------------------------

  VyOS Ansible Managed Firewall 

  -----------------------------

vyos_nameservers:
  - 8.8.8.8
  - 8.8.4.4
```

在这里，我们只设置了两个关键值。第一个`motd_asciiart`是一个多行横幅，每当我们登录到 VyOS 设备时都会显示。我们使用`|`来声明关键字后，将变量设置为多行。下一个关键字`vyos_nameservers`是要使用的 DNS 解析器列表。在这里，我们使用 Google 的公共 DNS 解析器。

playbook 中还使用了一些其他变量；这些可以在`group_vars/common.yml`中找到，如下所示：

```
---

vyos:
  host: "192.168.50.10.nip.io"
  username: "vagrant"
  backup: "yes"
  inside:
    interface: "172.16.20.1/24"
    subnet: "172.16.20.0/24"

whitelist_ips:
  - 172.16.20.2

rules:
    - { action: 'set', source_address: '0.0.0.0/0', source_port: '80', destination_port: '80', destination_address: '172.16.20.11', protocol: 'tcp', description: 'NAT port 80 to 172.16.10.11', rule_number: '10' }
    - { action: 'set', source_address: '0.0.0.0/0', source_port: '443', destination_port: '443', destination_address: '172.16.20.11', protocol: 'tcp', description: 'NAT port 443 to 172.16.10.11', rule_number: '20' }
    - { action: 'set', source_address: '123.123.123.123/32', source_port: '222', destination_port: '22', destination_address: '172.16.20.11', protocol: 'tcp', description: 'NAT port 443 to 172.16.10.11', rule_number: '30' }
```

正如你所看到的，这些是可能根据我们的 playbook 运行位置而改变的大部分变量。首先，我们在一个名为`vyos`的嵌套变量中设置了我们设备的详细信息和基本配置。你可能已经注意到，我们在这里传递了我们 VyOS 设备的 IP 地址和用户名的详细信息，而不是我们的主机清单文件。

实际上，我们的主机清单文件名为`production`，应该只包含以下代码行：

```
localhost
```

这意味着当我们的 playbook 被执行时，它不会针对我们的 VyOS 设备执行。相反，playbook 将针对我们的 Ansible 控制器，并且模块将会针对 VyOS 设备。这种方法在所有核心网络模块中都很常见。正如我们已经讨论过的，Ansible 是一个无代理平台；默认情况下只需要 SSH 或 WinRM 连接。

然而，并非每个网络设备都具有 SSH 或 WinRM 访问权限；有些可能只有基于 Web 的 API，而其他一些可能使用专有的访问方法。另外，像 VyOS 这样的设备可能看起来具有 SSH 访问权限；但是，你实际上是在一个专门设计仅运行少量防火墙命令的自定义 shell 中进行 SSH。因此，大多数核心网络模块都会将它们的连接和通信管理远离主机清单文件。

`group_vars/common.yml`文件中的其余变量设置了一些基本防火墙规则，我们很快会看到。

可以在`roles/vyos-firewall/tasks/main.yml`中找到该角色的任务，它包含四个部分。首先，我们使用`vyos_config`模块来设置主机名。看一下这段代码：

```
- name: set the hostname correctly
  vyos_config:
    provider:
      host: "{{ vyos.host }}"
      username: "{{ vyos.username }}"
    lines:
      - "set system host-name {{ vyos.host }}"
```

正如你所看到的，我们使用`provider`选项传递了 VyOS 设备的详细信息；然后我们传递了一个`vyos`命令来设置主机名。`vyos_config`模块还接受模板文件，我们将在下一步中使用它来完全配置我们的设备。

下一个任务使用`vyos_system`模块配置 DNS 解析器。看一下这段代码：

```
- name: configure name servers
  vyos_system:
    provider:
      host: "{{ vyos.host }}"
      username: "{{ vyos.username }}"
    name_server: "{{ item }}"
  with_items: "{{ vyos_nameservers }}"
```

接下来，我们将使用`vyos_banner`模块设置**每日消息**（**MOTD**）。看一下这段代码：

```
- name: configure the motd
  vyos_banner:
    provider:
      host: "{{ vyos.host }}"
      username: "{{ vyos.username }}"
    banner: "post-login"
    state: "present"
    text: "{{ motd_asciiart }}"
```

最后，我们将使用以下任务应用我们的主防火墙配置：

```
- name: backup and load from file
  vyos_config:
    provider:
      host: "{{ vyos.host }}"
      username: "{{ vyos.username }}"
    src: "firewall.j2"
    backup: "{{ vyos.backup }}"
    save: "yes"
```

与其使用`lines`提供命令，这次我们使用`src`来提供模板文件的名称。我们还指示模块备份当前配置；这将存储在`roles/vyos-firewall/backup`文件夹中，在 playbook 运行时创建。

模板可以在`roles/vyos-firewall/templates/firewall.j2`中找到。该模板包含以下代码：

```
set firewall all-ping 'enable'
set firewall broadcast-ping 'disable'
set firewall ipv6-receive-redirects 'disable'
set firewall ipv6-src-route 'disable'
set firewall ip-src-route 'disable'
set firewall log-martians 'enable'
set firewall receive-redirects 'disable'
set firewall send-redirects 'enable'
set firewall source-validation 'disable'
set firewall state-policy established action 'accept'
set firewall state-policy related action 'accept'
set firewall syn-cookies 'enable'
set firewall name OUTSIDE-IN default-action 'drop'
set firewall name OUTSIDE-IN description 'deny traffic from internet'
{% for item in whitelist_ips %}
set firewall group address-group SSH-ACCESS address {{ item }}
{% endfor %}
set firewall name OUTSIDE-LOCAL rule 310 source group address-group SSH-ACCESS
set firewall name OUTSIDE-LOCAL default-action 'drop'
set firewall name OUTSIDE-LOCAL rule 310 action 'accept'
set firewall name OUTSIDE-LOCAL rule 310 destination port '22'
set firewall name OUTSIDE-LOCAL rule 310 protocol 'tcp'
set firewall name OUTSIDE-LOCAL rule 900 action 'accept'
set firewall name OUTSIDE-LOCAL rule 900 description 'allow icmp'
set firewall name OUTSIDE-LOCAL rule 900 protocol 'icmp'
set firewall receive-redirects 'disable'
set firewall send-redirects 'enable'
set firewall source-validation 'disable'
set firewall state-policy established action 'accept'
set firewall state-policy related action 'accept'
set firewall syn-cookies 'enable'
set interfaces ethernet eth0 firewall in name 'OUTSIDE-IN'
set interfaces ethernet eth0 firewall local name 'OUTSIDE-LOCAL'
set interfaces ethernet eth1 address '{{ vyos.inside.interface }}'
set interfaces ethernet eth1 description 'INSIDE'
set interfaces ethernet eth1 duplex 'auto'
set interfaces ethernet eth1 speed 'auto'
set nat source rule 100 outbound-interface 'eth0'
set nat source rule 100 source address '{{ vyos.inside.subnet }}'
set nat source rule 100 translation address 'masquerade'
{% for item in rules if item.action == "set" %}
{{ item.action }} nat destination rule {{ item.rule_number }} description '{{ item.description }}'
{{ item.action }} nat destination rule {{ item.rule_number }} destination port '{{ item.source_port }}'
{{ item.action }} nat destination rule {{ item.rule_number }} translation port '{{ item.destination_port }}'
{{ item.action }} nat destination rule {{ item.rule_number }} inbound-interface 'eth0'
{{ item.action }} nat destination rule {{ item.rule_number }} protocol '{{ item.protocol }}'
{{ item.action }} nat destination rule {{ item.rule_number }} translation address '{{ item.destination_address }}'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} action 'accept'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} source address '{{ item.source_address }}'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} destination address '{{ item.destination_address }}'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} destination port '{{ item.destination_port }}'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} protocol '{{ item.protocol }}'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} state new 'enable'
{% endfor %}
{% for item in rules if item.action == "delete" %}
{{ item.action }} nat destination rule {{ item.rule_number }}
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }}
{% endfor %}
```

模板中有很多命令，其中大部分只是在设备上应用一些基本设置。我们感兴趣的是三个`for`循环。第一个循环如下：

```
{% for item in whitelist_ips %}
set firewall group address-group SSH-ACCESS address {{ item }}
{% endfor %}
```

这将简单地循环遍历我们在`whitelist_ips`变量中提供的每个 IP 地址，类似于我们在之前的 playbook 中使用`with_items`的方式。下一个循环更好地演示了这一点，它从`firewall`变量中获取变量，并创建 NAT 和防火墙规则。看一下这段代码：

```
{% for item in rules if item.action == "set" %}
{{ item.action }} nat destination rule {{ item.rule_number }} description '{{ item.description }}'
{{ item.action }} nat destination rule {{ item.rule_number }} destination port '{{ item.source_port }}'
{{ item.action }} nat destination rule {{ item.rule_number }} translation port '{{ item.destination_port }}'
{{ item.action }} nat destination rule {{ item.rule_number }} inbound-interface 'eth0'
{{ item.action }} nat destination rule {{ item.rule_number }} protocol '{{ item.protocol }}'
{{ item.action }} nat destination rule {{ item.rule_number }} translation address '{{ item.destination_address }}'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} action 'accept'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} source address '{{ item.source_address }}'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} destination address '{{ item.destination_address }}'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} destination port '{{ item.destination_port }}'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} protocol '{{ item.protocol }}'
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }} state new 'enable'
{% endfor %}
```

正如你所看到的，只有在我们将变量中的`action`设置为`set`时，才会包含该规则；最后一个循环处理任何将`action`设置为`delete`的规则，如下所示：

```
{% for item in rules if item.action == "delete" %}
{{ item.action }} nat destination rule {{ item.rule_number }}
{{ item.action }} firewall name OUTSIDE-IN rule {{ item.rule_number }}
{% endfor %}
```

如果您一直在跟进，那么除了`site.yml`文件之外，我们最初创建的所有文件中应该都包含内容。这个文件应该包含以下代码：

```
---

- hosts: localhost
  connection: local
  gather_facts: false

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/vyos-firewall
```

现在我们已经将 playbook 的所有部分准备好，我们可以启动 VyOS Vagrant box 并运行 playbook。

# 运行 playbook

要启动 Vagrant box，请确保您在我们在本章节开始时创建的`vyos`文件夹中，并运行以下两个命令中的一个来使用您选择的 hypervisor 启动 box：

```
$ vagrant up
$ vagrant up --provider=vmware_fusion
```

一旦您的 Vagrant box 启动，您可以使用以下命令运行 playbook：

```
$ ansible-playbook -i production site.yml
```

此 playbook 运行的输出应该类似于以下内容：

```
PLAY [localhost] ***********************************************************************************

TASK [roles/vyos-firewall : set the hostname correctly] ********************************************
changed: [localhost]

TASK [roles/vyos-firewall : configure name servers] ************************************************
changed: [localhost] => (item=8.8.8.8)
changed: [localhost] => (item=8.8.4.4)

TASK [roles/vyos-firewall : configure the motd] ****************************************************
changed: [localhost]

TASK [roles/vyos-firewall : backup and load from file] *********************************************
changed: [localhost]

PLAY RECAP *****************************************************************************************
localhost : ok=4 changed=4 unreachable=0 failed=0
```

完成后，您应该能够通过运行以下代码 SSH 到您的 VyOS 设备：

```
$ vagrant ssh
```

您应该能够看到登录横幅已更新为我们定义的横幅，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/2a2c0127-ca93-4a8a-a093-e690236f322e.png)

在登录状态下，您可以通过运行以下命令查看 VyOS 配置：

```
$ show config
```

您应该能够在 playbook 运行中看到我们所做的所有更改，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/afa4ed4f-cbf4-4710-8702-fae627fc826c.png)

要停止查看配置，请按*Q*。您可以输入`exit`来离开 SSH 会话。您可以通过运行以下命令删除 VyOS Vagrant box：

```
$ vagrant destroy
```

正如本章节开头提到的，这个练习并不是关于使用 Ansible 配置一个完全功能的 VyOS 安装；相反，它提供了一个实际的例子，说明您可以如何使用 Ansible 模块配置网络设备，这些模块既能产生变化，又能使用模板应用配置。

# 总结

在本章中，我们简要介绍了作为 Ansible 核心模块一部分提供的各种网络模块。我们还将配置应用到虚拟的 VyOS 设备上，以了解网络模块与我们在之前章节中介绍的模块有何不同。

在下一章中，我们将学习如何使用 Ansible 启动基于云的服务器实例，然后将一些 playbooks 应用到它们上。

# 问题

1.  真或假：您必须在模板中的`for`循环中使用`with_items`。

1.  哪个字符用于将您的变量分成多行？

1.  真或假：在使用 VyOS 模块时，我们不需要在主机清单文件中传递设备的详细信息。

1.  您能否将 VyOS 配置回滚到您存储的最早备份？

# 进一步阅读

每个设备和技术的详细信息，目前都由核心网络模块支持，都可以在以下链接中找到：

+   **A10 Networks**: [`www.a10networks.com/`](https://www.a10networks.com/)

+   **Cisco ACI**: [`www.cisco.com/c/en_uk/solutions/data-center-virtualization/application-centric-infrastructure/index.html`](https://www.cisco.com/c/en_uk/solutions/data-center-virtualization/application-centric-infrastructure/index.html)

+   **Cisco AireOS**: [`www.cisco.com/c/en/us/products/wireless/wireless-lan-controller/index.html`](https://www.cisco.com/c/en/us/products/wireless/wireless-lan-controller/index.html)

+   **AOS**: [`www.apstra.com/products/aos/`](http://www.apstra.com/products/aos/)

+   **Aruba Mobility Controller**: [`www.arubanetworks.com/en-gb/products/networking/controllers/`](http://www.arubanetworks.com/en-gb/products/networking/controllers/)

+   **Cisco ASA**: [`www.cisco.com/c/en/us/products/security/adaptive-security-appliance-asa-software/index.html`](https://www.cisco.com/c/en/us/products/security/adaptive-security-appliance-asa-software/index.html)

+   **Avi Networks**: [`avinetworks.com/`](https://avinetworks.com/)

+   **Big Switch Networks**: [`www.bigswitch.com`](https://www.bigswitch.com)

+   **Citrix Netscaler**: [`www.citrix.com/products/netscaler-adc/`](https://www.citrix.com/products/netscaler-adc/)

+   华为 CloudEngine：[`e.huawei.com/uk/products/enterprise-networking/switches/data-center-switches`](http://e.huawei.com/uk/products/enterprise-networking/switches/data-center-switches)

+   阿里斯塔 CloudVision：[`www.arista.com/en/products/eos/eos-cloudvision`](https://www.arista.com/en/products/eos/eos-cloudvision)

+   联想 CNOS 和 ENOS：[`www3.lenovo.com/gb/en/data-center/networking/-software/c/networking-software/`](https://www3.lenovo.com/gb/en/data-center/networking/-software/c/networking-software/)

+   Cumulus Linux：[`cumulusnetworks.com/products/cumulus-linux/`](https://cumulusnetworks.com/products/cumulus-linux/)

+   戴尔操作系统 10：[`www.dell.com/en-us/work/shop/povw/open-platform-software/`](http://www.dell.com/en-us/work/shop/povw/open-platform-software/)

+   Ubiquiti EdgeOS：[`www.ubnt.com/edgemax/edgerouter/`](https://www.ubnt.com/edgemax/edgerouter/)

+   阿里斯塔 EOS：[`www.arista.com/en/products/eos`](https://www.arista.com/en/products/eos)

+   F5 BIG-IP：[`f5.com/products/big-ip`](https://f5.com/products/big-ip)

+   FortiGate FortiManager：[`www.fortinet.com/products/management/fortimanager.html`](https://www.fortinet.com/products/management/fortimanager.html)

+   FortiGate FortiOS：[`www.fortinet.com/products/fortigate/fortios.html`](https://www.fortinet.com/products/fortigate/fortios.html)

+   illumos：[`www.illumos.org/`](http://www.illumos.org/)

+   思科 IOS：[`www.cisco.com/c/en/us/products/ios-nx-os-software/ios-software-releases-listing.html`](https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-software-releases-listing.html)

+   思科 IOS XR：[`www.cisco.com/c/en/us/products/ios-nx-os-software/ios-xr-software/index.html`](https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-xr-software/index.html)

+   博科铁路：[`www.broadcom.com/`](https://www.broadcom.com/)

+   瞻博 Junos：[`www.juniper.net/uk/en/products-services/nos/junos/`](https://www.juniper.net/uk/en/products-services/nos/junos/)

+   诺基亚 NetAct：[`networks.nokia.com/solutions/netact`](https://networks.nokia.com/solutions/netact)

+   Pluribus Networks Netvisor OS：[`www.pluribusnetworks.com/products/white-box-os/`](https://www.pluribusnetworks.com/products/white-box-os/)

+   思科 NSO：[`www.cisco.com/c/en/us/solutions/service-provider/solutions-cloud-providers/network-services-orchestrator-solutions.html`](https://www.cisco.com/c/en/us/solutions/service-provider/solutions-cloud-providers/network-services-orchestrator-solutions.html)

+   诺基亚 Nuage Networks VSP：[`www.nuagenetworks.net/products/virtualized-services-platform/`](http://www.nuagenetworks.net/products/virtualized-services-platform/)

+   思科 NX-OS：[`www.cisco.com/c/en/us/products/ios-nx-os-software/nx-os/index.htm`](https://www.cisco.com/c/en/us/products/ios-nx-os-software/nx-os/index.htm)l

+   Mellanox ONYX：[`www.mellanox.com/page/mlnx_onyx?mtag=onyx_software`](http://www.mellanox.com/page/mlnx_onyx?mtag=onyx_software)

+   军火库：[`ordnance.co/`](https://ordnance.co/)

+   Open vSwitch：[`www.openvswitch.org/`](https://www.openvswitch.org/)

+   Palo Alto Networks PAN-OS：[`www.paloaltonetworks.com/documentation/80/pan-os`](https://www.paloaltonetworks.com/documentation/80/pan-os)

+   Radware：[`www.radware.com`](https://www.radware.com)

+   诺基亚网络服务路由器操作系统：[`networks.nokia.com/products/sros`](https://networks.nokia.com/products/sros)

+   VyOS：[`vyos.io/`](https://vyos.io/)


# 第八章：转移到云端

在本章中，我们将从使用本地虚拟机转移到使用 Ansible 在公共云提供商中启动实例。在本章中，我们将使用 DigitalOcean，我们选择这个提供商是因为它允许我们简单地启动虚拟机并与其交互，而不需要太多的配置开销。

然后，我们将研究如何调整我们的 WordPress playbook，以便与新启动的实例进行交互。

在本章中，我们将涵盖以下主题：

+   DigitalOcean 的简要介绍

+   在 DigitalOcean 中启动实例

+   如何在本地和远程之间切换运行 Ansible，以便我们可以部署 WordPress

# 技术要求

在本章中，我们将在公共云中启动实例，因此如果您正在跟随操作，您将需要一个 DigitalOcean 账户。与其他章节一样，playbook 的完整版本可以在[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter08`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter08)的`Chapter08`文件夹中找到。

# 与 DigitalOcean 交互

DigitalOcean 成立于 2011 年，从一个典型的虚拟专用服务器主机发展成为一个拥有全球数据中心的开发者友好的云服务提供商。Netcraft 指出，2012 年 12 月，DigitalOcean 托管了大约 100 个面向 Web 的服务器；到 2018 年 3 月，这个数字超过了 400,000 个，使 DigitalOcean 成为第三大面向 Web 的实例主机。

除了价格之外，DigitalOcean 之所以受到开发者的欢迎，还在于其性能；DigitalOcean 是最早提供全固态硬盘（SSD）实例存储的托管公司之一。它有易于使用的基于 Web 的控制面板，可以从命令行界面启动实例，还有强大的 API，允许您从应用程序内启动实例（DigitalOcean 称之为 Droplets），以及诸如 Ansible 之类的工具。

您可以在[`www.digitalocean.com/`](https://www.digitalocean.com/)注册账户。注册后，在进行其他操作之前，我建议您首先在您的账户上配置双因素认证。

双因素认证（2FA）或多因素认证（MFA）为您的账户增加了额外的认证级别。通常，这是通过向与您的账户关联的设备发送短信验证码来实现的，或者将账户链接到第三方认证应用程序（如 Google 或 Microsoft Authenticator）来实现，该应用程序运行在您的智能手机上。与这些服务相关的账户通常需要您输入一个每 30 秒轮换一次的六位数字。

您可以通过转到 DigitalOcean 控制面板中的设置，然后点击左侧菜单中的安全来配置 2FA；一旦进入，按照屏幕上的说明启用您账户上的 2FA。

# 生成个人访问令牌

为了使我们的 playbook 能够在我们的 DigitalOcean 账户中启动 Droplet，我们需要生成一个个人访问令牌以与 DigitalOcean API 进行交互。要做到这一点，请点击 DigitalOcean 基于 Web 的控制面板顶部菜单中的 API 链接。

点击“生成新令牌”按钮将打开以下对话框：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/0f0b015c-341f-4a89-ab40-c643a369d2f1.png)

如您所见，我已将我的令牌命名为`Ansible`，以便轻松识别。点击“生成令牌”按钮将创建一个令牌；它只会显示一次，所以请确保您记下来。

任何拥有您个人访问令牌副本的人都可以在您的 DigitalOcean 账户中启动资源；请确保将其保存在安全的地方，不要在任何地方发布您的令牌。

我已经在以下截图中模糊处理了我的令牌，但这应该让您了解在生成个人访问令牌后会看到什么：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/d2666137-b386-49fe-aa7a-cbd70a521bdb.png)

现在我们有了令牌，但在开始 playbook 之前，我们还需要配置另一件事。

# 安装 dopy

我们将使用的一个模块需要一个名为`dopy`的 Python 模块；它是 DigitalOcean API 的包装器，可以使用以下`pip`命令进行安装：

```
$ sudo pip install dopy
```

安装了`dopy`之后，我们可以开始编写 playbook。

# 启动 Droplet

根据我们之前编写的 playbooks，您可以通过运行以下命令来创建骨架结构：

```
$ mkdir digitalocean digitalocean/group_vars digitalocean/roles
$ ansible-galaxy init digitalocean/roles/droplet
$ touch digitalocean/production digitalocean/site.yml digitalocean/group_vars/common.yml
```

我们需要完成两个任务来启动我们的 Droplet；首先，我们需要确保我们的公共 SSH 密钥的副本已上传到 DigitalOcean，以便我们可以在第二个任务期间将其注入到我们启动的 Droplet 中。

在我们继续查看启动 Droplet 的角色之前，我们应该弄清楚 playbook 需要访问 DigitalOcean API 的个人访问令牌要做什么。为此，我们将使用 Ansible Vault 对令牌进行编码；运行以下命令，确保用您自己的令牌替换`encrypt_string`的内容：

```
ansible-vault \
 encrypt_string 'pLgVbM2hswiLFWbemyD4Nru3a2yYwAKm2xbL6WmPBtzqvnMTrVTXYuabWbp7vArQ' \
 --name 'do_token'
```

本章中使用的令牌是随机生成的；请确保您用自己的替换它们。

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/41bf40bd-a56d-498d-9271-392ab015a599.png)

如您所见，这返回了加密令牌，因此将加密令牌放入`group_vars/common.yml`文件中。在我们填充变量的同时，让我们看看`roles/droplet/defaults/main.yml`的内容应该是什么样的：

```
---
# defaults file for digitalocean/roles/droplet

key:
  name: "Ansible"
  path: "~/.ssh/id_rsa.pub"

droplet:
  name: "AnsibleDroplet"
  region: "lon1"
  size: "s-1vcpu-2gb"
  image: "centos-7-x64"
  timeout: "500"
```

有两个密钥值集合；第一个处理 SSH 密钥，playbook 将上传它，第二个包含启动 Droplet 的信息。我们初始 playbook 运行的默认设置将在 DigitalOcean 伦敦数据中心启动一个 1-CPU 核心、2 GB RAM、50 GB HDD 的 CentOS 7 Droplet。

启动 Droplet 的任务应该在`roles/droplet/tasks/main.yml`中包含两个独立的部分；第一部分处理上传 SSH 密钥，这是必须的，以便我们可以使用它来启动 Droplet：

```
- name: "upload SSH key to DigitalOcean"
  digital_ocean_sshkey:
    oauth_token: "{{ do_token }}"
    name: "{{ key.name }}"
    ssh_pub_key: "{{ item }}"
    state: present
  with_file: "{{ key.path }}"
```

如您所见，此任务使用了我们用 Ansible Vault 加密的令牌；我们还使用了`with_file`指令来复制密钥文件的内容，即`~/.ssh/id_rsa.pub`。根据您在 DigitalOcean 帐户中已有的内容，此任务将执行三种操作中的一种：

+   如果密钥不存在，它将上传它

+   如果一个密钥与`~/.ssh/id_rsa.pub`的指纹匹配但名称不同，那么它将重命名该密钥

+   如果密钥和名称匹配，将不会上传或更改任何内容

现在我们知道我们已经上传了我们的密钥，我们需要知道它的唯一 ID。为了找出这一点，我们应该通过运行以下任务来收集我们在 DigitalOcean 帐户中配置的所有密钥的事实：

```
- name: "gather facts on all of the SSH keys in DigitalOcean"
  digital_ocean_sshkey_facts:
    oauth_token: "{{ do_token }}"
```

这将返回一个名为`ssh_keys`的 JSON 数组，其中包含密钥的名称，密钥的指纹，密钥本身的内容，以及密钥的唯一 ID；这些信息对于我们在 DigitalOcean 帐户中配置的每个密钥都会返回。由于我们只需要知道这些密钥中的一个 ID，我们需要操作结果以将列表过滤为我们上传的单个密钥，然后将 ID 设置为变量。

我们知道，我们有一个存储在`ssh_keys`值中的潜在密钥的 JSON 数组；对我来说，看起来像这样：

```
{
    "fingerprint": "9e:ad:42:e9:86:01:3c:5f:de:11:60:11:e0:11:9e:11",
    "id": 2663259,
    "name": "Work",
    "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAv2cUTYCHnGcwHYjVh3vu09T6UwLEyXEKDnv3039KStLpQV3H7PvhOIpAbY7Gvxi1t2KyqkOvuBdIat5fdQKzGQMEFZiwlcgWDVQGJBKuMH02w+ceMqNYaD8sZqUO+bQQwkUDt3PuDKoyNRzhcDLsc//Dp6wAwJsw75Voe9bQecI3cWqjT54n+oareqADilQ/nO2cdFdmCEfVJP4CqOmL1QLJQNe46yQoGJWLNa9VPC8/ffmUPnwJRWa9AZRPAQ2vGbDF6meSsFwVUfhtxkn+0bof7PFxrcaycGa3zqt6m1y6o3BDh29eFN94TZf9lUK/nQrXuby2/FhrMBrRcgWE4gQ== russ@work"
},
{
    "fingerprint": "7d:ce:56:5f:af:45:71:ab:af:fe:77:c2:9f:90:bc:cf",
    "id": 19646265,
    "name": "Ansible",
    "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmuoFR01i/Yf3HATl9c3sufJvghTFgYzK/Zt29JiTqWlSQhmXhNNTh6iI6nXuPVhQGQaciWbqya6buncQ3vecISx6+EwsAmY3Mwpz1a/eMiXOgO/zn6Uf79dXcMN2JwpLFoON1f9PR0/DTpEkjwqb+eNLw9ThjH0J994+Pev+m8OrqgReFW36a/kviUYKsHxkXmkgxtPJgwKU90STNab4qyfKEGhi2w/NzECgseeQYs1H3klORaHQybhpXkoCIMmgy9gnzSH7oa2mJqKilVed27xoirkXzWPaAQlfiEE1iup+2xMqWY6Jl9qb8tJHRS+l8UcxTMNaWsQkTysLTgBAZ russ@mckendrick.io"
}
```

您可能已经注意到，我已经执行了 playbook 并上传了我的密钥，以便我可以与您一起完成这个任务。现在我们需要找到名为`key.name`的密钥，对我们来说是`Ansible`，然后返回 ID。为此，我们将添加以下任务：

```
- name: "set the SSH key ID as a fact"
  set_fact:
    pubkey: "{{ item.id }}"
  with_items: "{{ ssh_keys | json_query(key_query) }}"
  vars:
    key_query: "[?name=='{{ key.name }}']"
```

正如你所看到的，我们正在使用`set_fact`模块创建一个名为`pubkey`的键值对；我们正在使用一个项目的 ID，并确保我们返回的只是一个项目，我们正在对我们的数组应用 JSON 查询。这个查询确保只返回包含`key.name`的 JSON 在`with_items`列表中；从这里我们可以取得单个项目的`id`，这使我们可以继续进行第二部分，即启动 Droplet。

现在我们知道要使用的 SSH 密钥的 ID，我们可以继续进行角色的第二部分。以下任务启动 Droplet：

```
- name: "launch the droplet"
  digital_ocean:
    state: "present"
    command: "droplet"
    name: "{{ droplet.name }}"
    unique_name: "yes"
    api_token: "{{ do_token }}"
    size_id: "{{ droplet.size }}"
    region_id: "{{ droplet.region }}"
    image_id: "{{ droplet.image }}"
    ssh_key_ids: [ "{{ pubkey }}" ]
    wait_timeout: "{{ droplet.timeout }}"
  register: droplet
```

使用`digital_ocean`模块启动 Droplet。大多数项目都是不言自明的；然而，有一个重要的选项我们必须设置一个值，那就是`unique_name`。默认情况下，`unique_name`设置为`no`，这意味着如果我们第二次运行我们的 playbook，将创建一个具有与我们启动的第一个 Droplet 完全相同细节的新 Droplet；第三次运行将创建第三个 Droplet。将`unique_name`设置为`yes`将意味着只有一个具有`droplet.name`值的 Droplet 在任一时间处于活动状态。

正如你所看到的，我们正在将任务的输出注册为一个值。关于 Droplet 的一些细节将作为任务执行的一部分返回；Droplet 的 IP 地址就是其中之一，因此我们可以使用它来设置一个事实，然后打印一个带有 IP 地址的消息：

```
- name: "set the droplet IP address as a fact"
  set_fact:
    droplet_ip: "{{ droplet.droplet.ip_address }}"

- name: "print the IP address of the droplet" 
  debug:
    msg: "The IP of the droplet is {{ droplet_ip }}"
```

这完成了基本的 playbook，一旦我们更新了`site.yml`文件，我们就可以运行它。这应该包含以下内容：

```
---

- hosts: localhost
  connection: local
  gather_facts: false

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/droplet
```

正如你所看到的，我们只是使用本地主机，因此不需要调用主机清单文件。

# 运行 playbook

由于我们有一个使用 Vault 加密的值，我们需要运行以下命令来运行 playbook：

```
$ ansible-playbook --vault-id @prompt site.yml
```

这将提示输入你设置的加密 Vault 的密码。一旦输入了密码，play 将运行：

```
PLAY [localhost] *****************************************************************************************************************************

TASK [roles/droplet : upload SSH key to DigitalOcean] ****************************************************************************************
changed: [localhost] => (item=ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmuoFR01i/Yf3HATl9c3sufJvghTFgYzK/Zt29JiTqWlSQhmXhNNTh6iI6nXuPVhQGQaciWbqya6buncQ3vecISx6+EwsAmY3Mwpz1a/eMiXOgO/zn6Uf79dXcMN2JwpLFoON1f9PR0/DTpEkjwqb+eNLw9ThjH0J994+Pev+m8OrqgReFW36a/kviUYKsHxkXmkgxtPJgwKU90STNab4qyfKEGhi2w/NzECgseeQYs1H3klORaHQybhpXkoCIMmgy9gnzSH7oa2mJqKilVed27xoirkXzWPaAQlfiEE1iup+2xMqWY6Jl9qb8tJHRS+l8UcxTMNaWsQkTysLTgBAZ russ@mckendrick.io)

TASK [roles/droplet : gather facts on all of the SSH keys in DigitalOcean] *******************************************************************
ok: [localhost]

TASK [roles/droplet : set the SSH key ID as a fact] ******************************************************************************************
ok: [localhost] => (item={u'public_key': u'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmuoFR01i/Yf3HATl9c3sufJvghTFgYzK/Zt29JiTqWlSQhmXhNNTh6iI6nXuPVhQGQaciWbqya6buncQ3vecISx6+EwsAmY3Mwpz1a/eMiXOgO/zn6Uf79dXcMN2JwpLFoON1f9PR0/DTpEkjwqb+eNLw9ThjH0J994+Pev+m8OrqgReFW36a/kviUYKsHxkXmkgxtPJgwKU90STNab4qyfKEGhi2w/NzECgseeQYs1H3klORaHQybhpXkoCIMmgy9gnzSH7oa2mJqKilVed27xoirkXzWPaAQlfiEE1iup+2xMqWY6Jl9qb8tJHRS+l8UcxTMNaWsQkTysLTgBAZ russ@mckendrick.io', u'fingerprint': u'7d:ce:56:5f:af:45:71:ab:af:fe:77:c2:9f:90:bc:cf', u'id': 19646265, u'name': u'Ansible'})

TASK [roles/droplet : launch the droplet] ****************************************************************************************************
changed: [localhost]

TASK [roles/droplet : set the droplet IP address as a fact] **********************************************************************************
ok: [localhost]

TASK [roles/droplet : print the IP address of the droplet] ***********************************************************************************
ok: [localhost] => {
 "msg": "The IP of the droplet is 159.65.27.87"
}

PLAY RECAP ***********************************************************************************************************************************
localhost : ok=6 changed=2 unreachable=0 failed=0
```

正如你所看到的，这上传了我的密钥并启动了一个具有 IP 地址`159.65.27.87`的 Droplet（此 IP 现在不再被此 Droplet 使用）。这反映在 DigitalOcean 控制面板中，我们可以看到已添加的密钥：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/182babfc-1dc7-49fc-81d6-2cf586983380.png)

你还可以在 Droplets 页面上看到 Droplet：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/b49cc2b2-be4a-4ef1-9d4d-43b6cea742c6.png)

此外，你可以使用`root`用户名 SSH 登录 Droplet：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/c75163c1-61f0-49bf-8398-f2923e1ddb4d.png)

正如你所看到的，启动和与 DigitalOcean 交互是相对简单的。在继续下一部分之前，在 DigitalOcean 控制面板内销毁你的实例。

# DigitalOcean 上的 WordPress

现在我们有一个启动 Droplet 的 playbook，我们将稍作调整，并在我们启动的 Droplet 上安装 WordPress。为此，复制刚才运行的 playbook 所在的文件夹，并将其命名为`digitalocean-wordpress`。从`Chapter06/lemp-multi/roles`文件夹中复制三个角色，`stack-install`、`stack-config`和`wordpress`。

# 主机清单

我们要更改的第一个文件是名为 production 的主机清单文件；这需要更新为以下内容：

```
[droplets]

[digitalocean:children]
droplets

[digitalocean:vars]
ansible_ssh_user=root
ansible_ssh_private_key_file=~/.ssh/id_rsa
host_key_checking=False
ansible_python_interpreter=/usr/bin/python
```

这里有一个名为`droplets`的空主机组，然后我们为要启动的 Droplet 设置了一些全局变量。暂时不用担心添加实际的主机；我们将在运行 playbook 期间添加它。

# 变量

我们将要覆盖一些默认变量。为此，更新`group_vars/common.yml`文件，确保它读起来像这样，确保你更新`do_token`值以反映你自己的值：

```
do_token: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63376236316336633631353131313363666463363834524609643522613230653265373236353664
          36653763373961313433373138633933663939452257345733336238353862383432373831393839
          32316262653963333836613332366639333039393066343739303066663262323337613937623533
          3461626330663363330a303538393836613835313166383030636134623530323932303266373134
          35616339376138636530346632345734563457326532376233323930383535303563323634336162
          31386635646636363334393664383633346636616664386539393162333062343964326561343861
          33613265616632656465643664376536653334653532336335306230363834523454245337626631
          33323730636562616631

droplet:
  name: "WordPress"
  region: "lon1"
  size: "s-1vcpu-2gb"
  image: "centos-7-x64"
  timeout: "500"

wordpress:
  domain: "http://{{ hostvars['localhost'].droplet_ip }}/"
  title: "WordPress installed by Ansible on {{ os_family }} host in DigitalOcean"
  username: "ansible"
  password: "AnsiblePasswordForDigitalOcean"
  email: "test@example.com"
  theme: "sydney"
  plugins:
    - "jetpack"
    - "wp-super-cache"
    - "wordpress-seo"
    - "wordfence"
    - "nginx-helper"
```

正如你所看到的，大多数值都是它们的默认值；我们正在更改的四个值是：

+   `droplet.name`：这是对名称的简单更新，这样我们就可以在 DigitalOcean 控制面板中轻松找到我们的实例。

+   `wordpress.domain`：这里的重要变化。正如您所看到的，我们使用了我们在 Ansible 控制器上设置的`droplet_ip`变量。为了使变量对我们的 WordPress 主机可用，我们告诉 Ansible 从 localhost 使用变量。如果我们没有这样做，那么变量就不会被设置；我们将在下一节中看到原因。

+   `wordpress.title`：对我们的 WordPress 站点配置的标题进行了轻微调整，以反映它所托管的位置。

+   `wordpress.password`：更改密码使其更复杂，因为我们在公开可用的 IP 地址上启动。

# playbook

我们接下来要更改的文件是`site.yml`。这个文件需要更新以在本地和我们启动的 Droplet 上运行角色：

```
---

- name: Launch the droplet in DigitalOcean
  hosts: localhost
  connection: local
  gather_facts: True

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/droplet

- name: Install WordPress on the droplet
  hosts: digitalocean
  gather_facts: true

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/stack-install
    - roles/stack-config
    - roles/wordpress
```

我们更新的`site.yml`文件包含两个不同的 play：第一个在我们的 Ansible 控制器上运行，并与 DigitalOcean API 交互以启动 Droplet，第二个 play 然后连接到`digitalocean`组中的主机以安装 WordPress。那么 Ansible 如何知道要连接的主机的 IP 地址呢？

# droplet 角色

我们需要做一个改变，`droplet`角色，可以在`roles/droplet/tasks/main.yml`中找到；这个改变将获取动态分配的 IP 地址，并将其添加到我们的`droplets`主机组中。为此，请替换以下任务：

```
- name: "print the IP address of the droplet" 
  debug:
    msg: "The IP of the droplet is {{ droplet_ip }}"
```

用以下任务替换它：

```
- name: add our droplet to a host group for use in the next step
  add_host:
    name: "{{ droplet_ip }}"
    ansible_ssh_host: "{{ droplet_ip }}"
    groups: "droplets"
```

正如你所看到的，这个任务使用`droplet_ip`变量，并使用`add_host`模块将主机添加到组中。

# 运行 playbook

现在我们已经将 playbook 的所有部分放在一起，我们可以通过运行以下命令启动 Droplet 并安装 WordPress：

```
$ ansible-playbook -i production --vault-id @prompt site.yml
```

启动 Droplet 并执行安装需要一些时间；在最后，您应该在 play 概述中列出 IP 地址，因为 IP 地址用作我们 Droplet 主机的名称。这是我的 playbook 运行的结尾：

```
RUNNING HANDLER [roles/stack-config : restart nginx] *****************************************************************************************
changed: [165.227.228.104]

RUNNING HANDLER [roles/stack-config : restart php-fpm] ***************************************************************************************
changed: [165.227.228.104]

PLAY RECAP ***********************************************************************************************************************************
165.227.228.104 : ok=47 changed=37 unreachable=0 failed=0
localhost : ok=7 changed=1 unreachable=0 failed=0
```

在浏览器中输入 IP 地址应该会呈现出类似以下页面的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/2d73f5a8-dbd7-4817-967e-66706e827aa8.png)

您应该能够使用我们在`common.yml`文件中设置的新密码登录。尝试安装 WordPress；当您准备好时，从 DigitalOcean 控制面板内销毁 Droplet。但请记住：保持 Droplet 运行将产生费用。

# 总结

在本章中，我们使用了 Ansible 云模块之一在公共云中启动了我们的第一个实例；正如您所看到的，这个过程相对简单，我们成功在云中启动了计算资源，然后安装了 WordPress，而没有对我们在第五章中涵盖的角色进行任何更改，*部署 WordPress*。

在下一章中，我们将扩展本章涵盖的一些技术，并返回到网络，但与上一章不同，我们在上一章中涵盖了网络设备，我们将研究公共云中的网络。

# 问题

1.  我们需要安装哪个 Python 模块来支持`digital_ocean`模块？

1.  正确还是错误：您应该始终加密诸如 DigitalOcean 个人访问令牌之类的敏感值。

1.  我们使用哪个过滤器来查找我们需要使用的 SSH 密钥的 ID？

1.  解释为什么我们在`digital_ocean`任务中使用了`unique_name`选项。

1.  从另一个 Ansible 主机访问变量的正确语法是什么？

1.  正确还是错误：`add_server`模块用于将我们的 Droplet 添加到主机组。

1.  尝试在 Ubuntu Droplet 上安装 WordPress；要使用的镜像 ID 是`ubuntu-16-04-x64`，不要忘记更改`ansible_python_interpreter`的值。

# 进一步阅读

您可以在[`trends.netcraft.com/www.digitalocean.com/`](http://trends.netcraft.com/www.digitalocean.com/)上阅读有关 DigitalOcean 的 Netcraft 统计的更多详细信息。


# 第九章：构建云网络

现在我们已经在 DigitalOcean 上启动了服务器，我们将继续开始研究在 Amazon Web Services（AWS）内启动服务。

在启动实例之前，我们需要为它们创建一个网络。这称为 VPC，我们需要在 playbook 中汇集一些不同的元素来创建一个 VPC，然后我们就可以用于我们的实例。

在本章中，我们将：

+   介绍 AWS

+   介绍我们试图实现的目标和原因

+   创建 VPC、子网和路由-网络和路由

+   创建安全组-防火墙

+   创建弹性负载均衡（ELB）-负载均衡器

# 技术要求

在本章中，我们将使用 AWS；您需要管理员访问权限才能创建所需的角色，以允许 Ansible 与您的帐户进行交互。与其他章节一样，您可以在附带的 GitHub 存储库的`Chapter09`文件夹中找到完整的 playbooks，网址为[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter09/vpc`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter09/vpc)。

# AWS 简介

AWS 自 2002 年以来一直存在；它开始提供了一些毫不相关的服务，直到 2006 年初才重新推出。重新推出的 AWS 汇集了三项服务：

+   亚马逊弹性计算云（Amazon EC2）：这是 AWS 的计算服务

+   亚马逊简单存储服务（Amazon S3）：亚马逊的可扩展对象存储可访问服务

+   亚马逊简单队列服务（Amazon SQS）：该服务主要为 Web 应用程序提供消息队列

自 2006 年以来，它已经从三项独特的服务发展到了 160 多项，涵盖了 15 个主要领域，例如：

+   计算

+   存储

+   数据库

+   网络和内容传递

+   机器学习

+   分析

+   安全、身份和合规性

+   物联网

在 2018 年 2 月的财报电话会议上，透露出 AWS 在 2017 年的收入为 174.6 亿美元，占亚马逊总收入的 10%；对于一个最初只提供空闲计算时间共享的服务来说，这并不差。

在撰写本文时，AWS 覆盖了 18 个地理区域，总共拥有 54 个可用区域：[`aws.amazon.com/about-aws/global-infrastructure/`](https://aws.amazon.com/about-aws/global-infrastructure/)。

那么 AWS 的成功之处在哪里？不仅在于其覆盖范围，还在于其推出服务的方式。AWS 首席执行官 Andy Jassy 曾经说过：

“我们的使命是使任何开发人员或任何公司都能够在我们的基础设施技术平台上构建他们所有的技术应用。”

作为个人，您可以访问与大型跨国公司和亚马逊自身消费其服务相同的 API、服务、区域、工具和定价模型。这确实使您有自由从小规模开始并大规模扩展。例如，亚马逊 EC2 实例的价格从每月约 4.50 美元的 t2.nano（1 vCPU，0.5G）开始，一直到每月超过 19,000 美元的 x1e.32xlarge（128 vCPU，3,904 GB RAM，两个 1920 GB SSD 存储）-可以看出，有适用于各种工作负载的实例类型。

这两个实例和大多数服务都按照按使用计费，例如 EC2 实例按秒计费，存储按每月每 GB 计费。

# 亚马逊虚拟私有云概述

在本章中，我们将集中讨论启动 Amazon Virtual Private Cloud（Amazon VPC）；这是将容纳我们将在下一章中启动的计算和其他 Amazon 服务的网络层。

我们即将启动的 VPC 概述如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/3cc7aae7-3f58-4999-bffc-621d0535095e.png)

正如您所看到的，我们将在**EU-West #1**（爱尔兰）地区启动我们的 VPC；我们将跨越我们的 EC2 实例和**应用弹性负载均衡器**的所有三个可用区。我们将仅使用两个可用区来启动我们的 Amazon **关系数据库服务**（**RDS**）实例，以及两个区域用于**亚马逊弹性文件系统**（**Amazon EFS**）卷。

这意味着我们的 Ansible playbook 需要创建/配置以下内容：

+   一个亚马逊 VPC

+   EC2 实例的三个子网

+   两个用于 Amazon RDS 实例的子网

+   用于 Amazon EFS 卷的两个子网

+   应用负载均衡器的三个子网

+   一个互联网网关

我们还需要配置以下内容：

+   一条允许通过互联网网关访问的路由

+   一个安全组，允许每个人访问应用负载均衡器上的端口`80`（HTTP）和`443`（HTTPS）

+   一个安全组，允许 EC2 实例上的端口`22`（SSH）的受信任来源访问

+   一个安全组，允许应用负载均衡器从 EC2 实例访问端口`80`（HTTP）

+   一个安全组，允许 EC2 实例从 Amazon RDS 实例访问端口`3306`（MySQL）

+   一个安全组，允许 EC2 实例从 Amazon EFS 卷访问端口`2049`（NGF）

这将为我们提供基本网络，允许对除了我们希望公开的应用负载均衡器之外的所有内容进行限制性访问。在我们开始创建部署网络的 Ansible playbook 之前，我们需要获取 AWS API 访问密钥和密钥。

# 创建访问密钥和秘密

为您自己的 AWS 用户创建访问密钥和秘密密钥，以便为 Ansible 提供对您的 AWS 帐户的完全访问权限是完全可能的。

因此，我们将尝试为 Ansible 创建一个用户，该用户只有权限访问我们知道 Ansible 将需要与本章涵盖的任务进行交互的 AWS 部分。我们将为 Ansible 提供以下服务的完全访问权限：

+   亚马逊 VPC

+   亚马逊 EC2

+   亚马逊 RDS

+   亚马逊 EFS

要做到这一点，请登录到 AWS 控制台，该控制台可以在[`console.aws.amazon.com/`](https://console.aws.amazon.com/)找到。登录后，单击顶部菜单中的“服务”。在打开的菜单中，输入`IAM`到搜索框中，然后单击应该是唯一结果的 IAM 管理用户访问和加密密钥。这将带您到一个类似以下内容的页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/b5d44c52-1d83-43b8-87a8-749837229570.png)

在 IAM 页面上，单击左侧菜单中的“组”；我们将创建一个具有分配权限的组，然后我们将创建一个用户并将其分配给我们的组。

一旦您进入组页面，单击“创建新组”按钮。此过程有三个主要步骤，第一个是设置组名。在提供的空间中，输入组名`Ansible`，然后单击“下一步”按钮。

下一步是我们附加策略的步骤；我们将使用亚马逊提供的策略。选择 AmazonEC2FullAccess，AmazonVPCFullAccess，AmazonRDSFullAccess 和 AmazonElasticFileSystemFullAccess；一旦选择了所有四个，单击“下一步”按钮。

您现在应该在一个页面上，该页面向您概述了您选择的选项；它应该看起来类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/ab3872af-5311-4a14-80ee-b2ff16b83a6e.png)

当您对您的选择感到满意时，请单击“创建组”按钮，然后单击左侧菜单中的“用户”。

一旦进入用户页面，单击“添加用户”，这将带您到一个页面，您可以在其中配置所需的用户名以及您想要的用户类型。输入以下信息：

+   用户名：在此处输入`Ansible`

+   AWS 访问类型：勾选“程序化访问”旁边的复选框；我们的`Ansible`用户不需要 AWS 管理控制台访问权限，所以不要勾选该选项

现在您应该能够点击“下一步：权限”按钮；这将带您到设置用户权限的页面。由于我们已经创建了组，请从列表中选择`Ansible`组，然后点击“下一步：审阅”，这将带您到您输入的选项的概述页面。如果您对它们满意，然后点击“创建用户”按钮。

这将带您到一个看起来像以下内容的页面（我已经故意模糊了访问密钥 ID）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/6ed3ccc4-4fd1-468d-8e81-f34d65bd0dc1.png)

如您所见，成功消息告诉您这是您最后一次能够下载凭据，这意味着您将无法再次看到秘密访问密钥。要么点击“显示”按钮并记下密钥，要么点击“下载 .csv”按钮；您将无法恢复秘密访问密钥，只能让其过期并生成一个新的。

现在我们有了一个具有我们需要启动 VPC 的权限的用户的访问密钥 ID 和秘密访问密钥，我们可以开始编写 playbook。

# VPC playbook

首先，我们需要讨论的是如何以安全的方式将访问密钥 ID 和秘密访问密钥传递给 Ansible。由于我将在 GitHub 上的公共存储库中分享最终的 playbook，我不想与世界分享我的 AWS 密钥，因为那可能会很昂贵！通常情况下，如果是私有存储库，我会使用 Ansible Vault 加密密钥，并将其与其他可能敏感的数据（如部署密钥等）一起包含在其中。

在这种情况下，我不想在存储库中包含任何加密信息，因为这意味着人们需要解密它，编辑值，然后重新加密它。幸运的是，Ansible 提供的 AWS 模块允许您在 Ansible 控制器上设置两个环境变量；这些变量将作为 playbook 执行的一部分读取。

要设置变量，请运行以下命令，确保您用自己的访问密钥和秘密替换内容（以下列出的信息仅为占位符值）：

```
$ export AWS_ACCESS_KEY=AKIAI5KECPOTNTTVM3EDA $ export AWS_SECRET_KEY=Y4B7FFiSWl0Am3VIFc07lgnc/TAtK5+RpxzIGTr
```

设置好后，您可以通过运行以下命令查看内容：

```
$ echo $AWS_ACCESS_KEY
```

如您所见，这将显示`AWS_ACCESS_KEY`变量的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/2fae39d3-2fab-490c-a908-82b2e8bc720d.png)

现在我们有了一种将凭据传递给 Ansible 的方法，我们可以通过运行以下命令创建 playbook 结构：

```
$ mkdir vpc vpc/group_vars vpc/roles $ touch vpc/production vpc/site.yml vpc/group_vars/common.yml
$ cd vpc
```

现在我们已经有了基本的设置，我们可以开始创建角色；与以前的章节不同，我们将在添加每个角色后运行 playbook，以便我们可以更详细地讨论发生了什么。

# VPC 角色

我们要创建的第一个角色是创建 VPC 本身的角色。我们将在接下来的角色中配置/创建的所有内容都需要托管在一个 VPC 中，因此需要先创建它，然后我们需要收集一些关于它的信息，以便我们可以继续进行 playbook 的其余部分。

要引导角色，请从您的工作文件夹中运行以下命令：

```
$ ansible-galaxy init roles/vpc
```

现在我们有了角色的文件，打开`roles/vpc/tasks/main.yml`并输入以下内容：

```
- name: ensure that the VPC is present
  ec2_vpc_net:
    region: "{{ ec2_region }}"
    name: "{{ environment_name }}"
    state: present
    cidr_block: "{{ vpc_cidr_block }}"
    resource_tags: { "Name" : "{{ environment_name }}", "Environment" : "{{ environment_name }}" }
  register: vpc_info

# - name: print the information we have registered
#   debug:
#     msg: "{{ vpc_info }}"
```

如您所见，我们使用了一个名为`ec2_vpc_net`的 Ansible 模块；这个模块替换了一个名为`ec2_vpc`的模块，后者在 Ansible 2.5 中已被弃用和移除。

我们在任务中使用了三个变量；前两个变量`ec2_region`和`environment_name`应该放在`group_vars/common.yml`中，因为我们将在大多数我们将创建的角色中使用它们：

```
environment_name: "my-vpc"
ec2_region: "eu-west-1"
```

这两个变量都是不言自明的：第一个是我们将用来引用我们将在 AWS 中启动的各种元素的名称，第二个让 Ansible 知道我们想要在哪里创建 VPC。

第三个变量`vpc_cidr_block`应该放在`roles/vpc/defaults/main.yml`文件中：

```
vpc_cidr_block: "10.0.0.0/16"
```

这定义了我们想要使用的 CIDR；`10.0.0.0/16`表示我们想要保留 10.0.0.1 到 10.0.255.254，这给了我们大约 65,534 个可用的 IP 地址范围，这应该足够我们的测试了。

在第一个任务结束时，我们使用注册标志来获取在创建 VPC 过程中捕获的所有内容，并将其注册为一个变量。然后我们使用 debug 模块将这些内容打印到屏幕上。

现在我们有了第一个角色，我们可以在`site.yml`文件中添加一些内容：

```
- name: Create and configure an Amazon VPC
  hosts: localhost
  connection: local
  gather_facts: True

  vars_files:
    - group_vars/common.yml
    - group_vars/firewall.yml
    - group_vars/secrets.yml
    - group_vars/words.yml
    - group_vars/keys.yml

  roles:
    - roles/vpc
```

然后使用以下命令运行 playbook：

```
$ ansible-playbook site.yml
```

这应该给你一个类似下面的输出：

```
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit
localhost does not match 'all'

PLAY [Create and configure an Amazon VPC] *******************************************************

TASK [Gathering Facts] **************************************************************************
ok: [localhost]

TASK [roles/vpc : ensure that the VPC is present] ***********************************************
changed: [localhost]

TASK [roles/vpc : print the information we have registered] *************************************
ok: [localhost] => {
 "msg": {
 "changed": true,
 "failed": false,
 "vpc": {
 "cidr_block": "10.0.0.0/16",
 "cidr_block_association_set": [
 {
 "association_id": "vpc-cidr-assoc-1eee5575",
 "cidr_block": "10.0.0.0/16",
 "cidr_block_state": {
 "state": "associated"
 }
 }
 ],
 "classic_link_enabled": false,
 "dhcp_options_id": "dopt-44851321",
 "id": "vpc-ccef75aa",
 "instance_tenancy": "default",
 "is_default": false,
 "state": "available",
 "tags": {
 "Environment": "my-vpc",
 "Name": "my-vpc"
 }
 }
 }
}

PLAY RECAP **************************************************************************************
localhost : ok=3 changed=1 unreachable=0 failed=0
```

检查 AWS 控制台的 VPC 部分应该会显示 VPC 已经创建，并且信息应该与 Ansible 捕获的信息匹配：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/03e9bc2f-fa70-4e2d-82e2-f5111b81b5ab.png)

如果重新运行 playbook，你会注意到，Ansible 不会再次创建 VPC，而是会认识到已经有一个名为`my-vpc`的 VPC，并且会发现已经存在的 VPC 的信息，并填充`vpc_info`变量。这是有用的，因为我们将在下一个角色中使用收集到的信息。

# 子网角色

现在我们有了 VPC，我们可以开始填充它。我们要配置的第一件事是 10 个子网。如果你还记得，我们需要以下内容：

+   三个 EC2 实例

+   三个 ELB 实例

+   两个 RDS 实例

+   两个 EFS 实例

通过从你的工作目录运行以下命令来创建角色：

```
$ ansible-galaxy init roles/subnets
```

现在，在`roles/subnets/defaults/main.yml`中输入以下内容：

```
the_subnets:
  - { use: 'ec2', az: 'a', subnet: '10.0.10.0/24' }
  - { use: 'ec2', az: 'b', subnet: '10.0.11.0/24' }
  - { use: 'ec2', az: 'c', subnet: '10.0.12.0/24' }
  - { use: 'elb', az: 'a', subnet: '10.0.20.0/24' }
  - { use: 'elb', az: 'b', subnet: '10.0.21.0/24' }
  - { use: 'elb', az: 'c', subnet: '10.0.22.0/24' }
  - { use: 'rds', az: 'a', subnet: '10.0.30.0/24' }
  - { use: 'rds', az: 'b', subnet: '10.0.31.0/24' }
  - { use: 'efs', az: 'b', subnet: '10.0.40.0/24' }
  - { use: 'efs', az: 'c', subnet: '10.0.41.0/24' }
```

正如你所看到的，我们有一个包含子网用途（`ec2`、`elb`、`rds`或`efs`）、子网应该创建在哪个可用区（`a`、`b`或`c`）以及子网本身的变量列表。在这里，我们为每个可用区使用了/24。

像这样分组子网应该消除一些在创建子网时的重复。然而，它并没有完全消除，因为我们可以从`roles/subnets/tasks/main.yml`的内容中看到：

```
- name: ensure that the subnets are present
  ec2_vpc_subnet:
    region: "{{ ec2_region }}"
    state: present
    vpc_id: "{{ vpc_info.vpc.id }}"
    cidr: "{{ item.subnet }}"
    az: "{{ ec2_region }}{{ item.az }}"
    resource_tags: 
      "Name" : "{{ environment_name }}_{{ item.use }}_{{ ec2_region }}{{ item.az }}"
      "Environment" : "{{ environment_name }}"
      "Use" : "{{ item.use }}"
  with_items: "{{ the_subnets }}"
```

任务开始时非常简单：在这里，我们使用`ec2_vpc_subnet`模块通过循环`the_subnets`变量来创建子网。正如你所看到的，我们使用了在上一个角色中注册的变量来正确地将子网部署到我们的 VPC 中；这就是`vpc_info.vpc.id`。

你可能已经注意到，我们没有注册这个任务的结果；这是因为，如果我们这样做了，我们将会得到所有十个子网的信息。相反，我们希望根据子网的用途来分解这些信息。要找出这些信息，我们可以使用`ec2_vpc_subnet_facts`模块来根据我们在创建子网时设置的`Environment`和`Use`标签进行过滤来收集信息：

```
- name: gather information about the ec2 subnets
  ec2_vpc_subnet_facts:
    region: "{{ ec2_region }}"
    filters:
      "tag:Use": "ec2"
      "tag:Environment": "{{ environment_name }}"
  register: subnets_ec2

- name: gather information about the elb subnets
  ec2_vpc_subnet_facts:
    region: "{{ ec2_region }}"
    filters:
      "tag:Use": "elb"
      "tag:Environment": "{{ environment_name }}"
  register: subnets_elb

- name: gather information about the rds subnets
  ec2_vpc_subnet_facts:
    region: "{{ ec2_region }}"
    filters:
      "tag:Use": "rds"
      "tag:Environment": "{{ environment_name }}"
  register: subnets_rds

- name: gather information about the efs subnets
  ec2_vpc_subnet_facts:
    region: "{{ ec2_region }}"
    filters:
      "tag:Use": "efs"
      "tag:Environment": "{{ environment_name }}"
  register: subnets_efs
```

正如你所看到的，这里我们正在过滤使用和注册四组不同的信息：`subnets_ec2`、`subnets_elb`、`subnets_rds`和`subnets_efs`。然而，我们还没有完成，因为我们只想知道子网 ID 而不是关于每个子网的所有信息。

为了做到这一点，我们需要使用`set_fact`模块和一些 Jinja2 过滤：

```
- name: register just the IDs for each of the subnets
  set_fact:
    subnet_ec2_ids: "{{ subnets_ec2.subnets | map(attribute='id') | list  }}"
    subnet_elb_ids: "{{ subnets_elb.subnets | map(attribute='id') | list  }}"
    subnet_rds_ids: "{{ subnets_rds.subnets | map(attribute='id') | list  }}"
    subnet_efs_ids: "{{ subnets_efs.subnets | map(attribute='id') | list  }}"
```

最后，我们可以通过将变量连接在一起来将所有的 ID 打印到屏幕上：

```
# - name: print all the ids we have registered
#   debug:
#     msg: "{{ subnet_ec2_ids + subnet_elb_ids + subnet_rds_ids
      + subnet_efs_ids }}"
```

现在我们已经把角色的所有部分准备好了，让我们运行它。更新`site.yml`文件，使其看起来像下面这样：

```
- name: Create and configure an Amazon VPC
  hosts: localhost
  connection: local
  gather_facts: True

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/vpc
    - roles/subnets
```

然后使用以下命令运行 playbook：

```
$ ansible-playbook site.yml
```

在运行 playbook 之前，我在 VPC 角色中注释掉了`debug`任务。你的输出应该看起来像接下来的输出；你可能已经注意到，VPC 角色返回了一个`ok`，因为我们的 VPC 已经存在：

```
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [Create and configure an Amazon VPC] *******************************************************

TASK [Gathering Facts] **************************************************************************
ok: [localhost]

TASK [roles/vpc : ensure that the VPC is present] ***********************************************
ok: [localhost]

TASK [roles/subnets : ensure that the subnets are present] **************************************
changed: [localhost] => (item={u'subnet': u'10.0.10.0/24', u'use': u'ec2', u'az': u'a'})
changed: [localhost] => (item={u'subnet': u'10.0.11.0/24', u'use': u'ec2', u'az': u'b'})
changed: [localhost] => (item={u'subnet': u'10.0.12.0/24', u'use': u'ec2', u'az': u'c'})
changed: [localhost] => (item={u'subnet': u'10.0.20.0/24', u'use': u'elb', u'az': u'a'})
changed: [localhost] => (item={u'subnet': u'10.0.21.0/24', u'use': u'elb', u'az': u'b'})
changed: [localhost] => (item={u'subnet': u'10.0.22.0/24', u'use': u'elb', u'az': u'c'})
changed: [localhost] => (item={u'subnet': u'10.0.30.0/24', u'use': u'rds', u'az': u'a'})
changed: [localhost] => (item={u'subnet': u'10.0.31.0/24', u'use': u'rds', u'az': u'b'})
changed: [localhost] => (item={u'subnet': u'10.0.40.0/24', u'use': u'efs', u'az': u'b'})
changed: [localhost] => (item={u'subnet': u'10.0.41.0/24', u'use': u'efs', u'az': u'c'})

```

```
TASK [roles/subnets : gather information about the ec2 subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the elb subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the rds subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the efs subnets] *********************************
ok: [localhost]

TASK [roles/subnets : register just the IDs for each of the subnets] ****************************
ok: [localhost]

TASK [roles/subnets : print all the ids we have registered] *************************************
ok: [localhost] => {
 "msg": [
 "subnet-2951e761",
 "subnet-24ea4a42",
 "subnet-fce80ba6",
 "subnet-6744f22f",
 "subnet-64eb083e",
 "subnet-51f15137",
 "subnet-154ef85d",
 "subnet-19e9497f",
 "subnet-4340f60b",
 "subnet-5aea0900"
 ]
}

PLAY RECAP **************************************************************************************
localhost : ok=9 changed=1 unreachable=0 failed=0
```

唯一记录的更改是子网的添加；如果我们再次运行它，那么这也会返回一个`ok`，因为子网已经存在。正如你也可以看到的，我们返回了十个子网 ID，这也反映在 AWS 控制台中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/c64f7a9f-9ec7-4c01-b840-f5e5e7367277.png)

现在我们有了子网，我们需要确保 EC2 实例可以连接到互联网。

# 互联网网关角色

虽然互联网网关角色只会使用我们在`common.yml`中定义的变量，并通过收集之前任务中的信息，我们应该继续像之前一样继续引导`roles`文件夹：

```
$ ansible-galaxy init roles/gateway
```

在这个角色中，我们将使用两个模块；第一个模块`ec2_vpc_igw`创建互联网网关并对其进行标记：

```
- name: ensure that there is an internet gateway
  ec2_vpc_igw:
    region: "{{ ec2_region }}"
    vpc_id: "{{ vpc_info.vpc.id }}"
    state: present
    tags:
      "Name": "{{ environment_name }}_internet_gateway"
      "Environment": "{{ environment_name }}"
      "Use": "gateway"
  register: igw_info
```

然后我们将已注册的关于互联网网关的信息打印到屏幕上：

```
# - name: print the information we have registered
#   debug:
#     msg: "{{ igw_info }}"
```

在最终使用第二个模块`ec2_vpc_route_table`之前，我们创建一个路由，将所有目的地为`0.0.0.0/0`的流量发送到新创建的互联网网关，只针对 EC2 子网使用我们在之前角色中创建的 ID 列表：

```
- name: check that we can route through internet gateway
  ec2_vpc_route_table:
    region: "{{ ec2_region }}"
    vpc_id: "{{ vpc_info.vpc.id }}"
    subnets: "{{ subnet_ec2_ids + subnet_elb_ids }}"
    routes:
      - dest: 0.0.0.0/0
        gateway_id: "{{ igw_info.gateway_id }}"
    resource_tags:
      "Name": "{{ environment_name }}_outbound"
      "Environment": "{{ environment_name }}"
```

将角色添加到`site.yml`文件中：

```
- name: Create and configure an Amazon VPC
  hosts: localhost
  connection: local
  gather_facts: True

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/vpc
    - roles/subnets
    - roles/gateway
```

然后运行 playbook：

```
$ ansible-playbook site.yml
```

此时，由于我们已经运行了 playbook 三次，我应该快速提到`警告`。这是因为我们没有使用清单文件，而是在我们的`site.yml`文件的顶部定义了`localhost`。你应该收到类似以下输出的内容；我已经注释掉了之前角色中的调试任务：

```
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [Create and configure an Amazon VPC] *******************************************************

TASK [Gathering Facts] **************************************************************************
ok: [localhost]

TASK [roles/vpc : ensure that the VPC is present] ***********************************************
ok: [localhost]

TASK [roles/subnets : ensure that the subnets are present] **************************************
ok: [localhost] => (item={u'subnet': u'10.0.10.0/24', u'use': u'ec2', u'az': u'a'})
ok: [localhost] => (item={u'subnet': u'10.0.11.0/24', u'use': u'ec2', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.12.0/24', u'use': u'ec2', u'az': u'c'})
ok: [localhost] => (item={u'subnet': u'10.0.20.0/24', u'use': u'elb', u'az': u'a'})
ok: [localhost] => (item={u'subnet': u'10.0.21.0/24', u'use': u'elb', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.22.0/24', u'use': u'elb', u'az': u'c'})
ok: [localhost] => (item={u'subnet': u'10.0.30.0/24', u'use': u'rds', u'az': u'a'})
ok: [localhost] => (item={u'subnet': u'10.0.31.0/24', u'use': u'rds', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.40.0/24', u'use': u'efs', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.41.0/24', u'use': u'efs', u'az': u'c'})

TASK [roles/subnets : gather information about the ec2 subnets] *********************************
ok: [localhost]

```

```
TASK [roles/subnets : gather information about the elb subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the rds subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the efs subnets] *********************************
ok: [localhost]

TASK [roles/subnets : register just the IDs for each of the subnets] ****************************
ok: [localhost]

TASK [roles/gateway : ensure that there is an internet gateway] *********************************
changed: [localhost]

TASK [roles/gateway : print the information we have registered] *********************************
ok: [localhost] => {
 "msg": {
 "changed": true,
 "failed": false,
 "gateway_id": "igw-a74235c0",
 "tags": {
 "Environment": "my-vpc",
 "Name": "my-vpc_internet_gateway",
 "Use": "gateway"
 },
 "vpc_id": "vpc-ccef75aa"
 }
}

TASK [roles/gateway : check that we can route through internet gateway] *************************
changed: [localhost]

PLAY RECAP **************************************************************************************
localhost : ok=11 changed=2 unreachable=0 failed=0
```

回到 AWS 控制台。你应该能够查看到互联网网关：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/2b3f505c-0ec7-4212-b931-dcbdd76896e6.png)

在上面的截图中，你可以看到默认的 VPC 互联网网关，以及我们使用 Ansible 创建的互联网网关。你还可以看到我们创建的路由表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/3d308540-a5d0-491b-8912-58b35cbb716d.png)

在这里，你可以看到 Ansible 配置的路由，以及我们创建 VPC 时创建的默认路由。这个默认路由被设置为主要路由，并允许在我们之前添加的所有子网之间进行路由。

接下来，我们需要向我们的 VPC 添加一些安全组。

# 安全组角色

我们在这个角色中有一些不同的目标。第一个目标很简单：创建一个安全组，将端口`80`和`443`对外开放，或者在 IP 术语中是`0.0.0.0/0`。第二个目标是创建一个允许 SSH 访问的规则，但只允许我们访问，第三个目标是确保只有我们的 EC2 实例可以连接到 RDS 和 EFS。

第一个目标很容易，因为`0.0.0.0/0`是一个已知的数量，其他的就不那么容易了。我们的 IP 地址经常会变化，所以我们不想硬编码它。而且，我们还没有启动任何 EC2 实例，所以我们不知道它们的 IP 地址。

让我们引导这个角色并创建第一组规则：

```
$ ansible-galaxy init roles/securitygroups
```

我们将使用`ec2_group`模块在`roles/securitygroups/tasks/main.yml`中创建我们的第一个组：

```
- name: provision elb security group
  ec2_group:
    region: "{{ ec2_region }}"
    vpc_id: "{{ vpc_info.vpc.id }}"
    name: "{{ environment_name }}-elb"
    description: "opens port 80 and 443 to the world"
    tags:
      "Name": "{{ environment_name }}-elb"
      "Environment": "{{ environment_name }}"
    rules:
      - proto: "tcp"
        from_port: "80"
        to_port: "80"
        cidr_ip: "0.0.0.0/0"
        rule_desc: "allow all on port 80"
      - proto: "tcp"
        from_port: "443"
        to_port: "443"
        cidr_ip: "0.0.0.0/0"
        rule_desc: "allow all on port 443"
  register: sg_elb
```

在这里，我们创建了一个名为`my-vpc-elb`的规则，对其进行标记，然后将端口`80`和`443`对`0.0.0.0/0`开放。正如你所看到的，当你知道源 IP 地址很直接的时候，添加规则就很容易。现在让我们来看看为 EC2 实例添加规则；这个有点不同。

首先，我们不想让每个人都能访问我们实例上的 SSH，所以我们需要知道我们 Ansible 控制器的 IP 地址。为了做到这一点，我们将使用`ipify_facts`模块。

ipify 是一个免费的 web API，简单地返回你用来查询 API 的设备的当前公共 IP 地址。

正如接下来的任务所示，我们正在调用 ipify 的 API，然后设置一个包含 IP 地址的事实，然后将 IP 地址打印到屏幕上：

```
- name: find out your current public IP address using https://ipify.org/
  ipify_facts:
  register: public_ip

- name: set your public ip as a fact
  set_fact:
    your_public_ip: "{{ public_ip.ansible_facts.ipify_public_ip }}/32"

# - name: print your public ip address
#   debug:
#     msg: "Your public IP address is {{ your_public_ip }}"
```

现在我们知道要允许访问端口`22`的 IP 地址，我们可以创建一个名为`my-vpc-ec2`的规则：

```
- name: provision ec2 security group
  ec2_group:
    region: "{{ ec2_region }}"
    vpc_id: "{{ vpc_info.vpc.id }}"
    name: "{{ environment_name }}-ec2"
    description: "opens port 22 to a trusted IP and port 80 to the elb group"
    tags:
      "Name": "{{ environment_name }}-ec2"
      "Environment": "{{ environment_name }}"
    rules:
      - proto: "tcp"
        from_port: "22"
        to_port: "22"
        cidr_ip: "{{ your_public_ip }}"
        rule_desc: "allow {{ your_public_ip }} access to port 22"
      - proto: "tcp"
        from_port: "80"
        to_port: "80"
        group_id: "{{ sg_elb.group_id }}"
        rule_desc: "allow {{ sg_elb.group_id }} access to port 80"
  register: sg_ec2
```

在`my-vpc-ec2`安全组中还有第二个规则；这个规则允许来自具有`my-vpc-elb`安全组附加的任何源的端口`80`的访问，而在我们的情况下，这将只是 ELB。这意味着任何人访问我们的 EC2 实例上的端口`80`的唯一方式是通过 ELB。

我们将使用相同的原则来创建 RDS 和 EFS 组，这次只允许访问端口`3306`和`2049`的实例在`my-vpc-ec2`安全组中：

```
- name: provision rds security group
  ec2_group:
    region: "{{ ec2_region }}"
    vpc_id: "{{ vpc_info.vpc.id }}"
    name: "{{ environment_name }}-rds"
    description: "opens port 3306 to the ec2 instances"
    tags:
      "Name": "{{ environment_name }}-rds"
      "Environment": "{{ environment_name }}"
    rules:
      - proto: "tcp"
        from_port: "3306"
        to_port: "3306"
        group_id: "{{ sg_ec2.group_id }}"
        rule_desc: "allow {{ sg_ec2.group_id }} access to port 3306"
  register: sg_rds

- name: provision efs security group
  ec2_group:
    region: "{{ ec2_region }}"
    vpc_id: "{{ vpc_info.vpc.id }}"
    name: "{{ environment_name }}-efs"
    description: "opens port 2049 to the ec2 instances"
    tags:
      "Name": "{{ environment_name }}-efs"
      "Environment": "{{ environment_name }}"
    rules:
      - proto: "tcp"
        from_port: "2049"
        to_port: "2049"
        group_id: "{{ sg_ec2.group_id }}"
        rule_desc: "allow {{ sg_ec2.group_id }} access to port 2049"
  register: sg_efs
```

现在我们已经创建了我们的主要组，让我们添加一个`debug`任务，将安全组 ID 打印到屏幕上：

```
# - name: print all the ids we have registered
#   debug:
#     msg: "ELB = {{ sg_elb.group_id }}, EC2 = {{ sg_ec2.group_id }}, RDS = {{ sg_rds.group_id }} and EFS = {{ sg_efs.group_id }}"
```

现在我们有了完整的角色，我们可以运行 playbook。记得在`site.yml`文件中添加`- roles/securitygroups`：

```
$ ansible-playbook site.yml
```

同样，我已经注释掉了`securitygroups`角色之外的`debug`模块的任何输出：

```
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [Create and configure an Amazon VPC] *******************************************************

TASK [Gathering Facts] **************************************************************************
ok: [localhost]

TASK [roles/vpc : ensure that the VPC is present] ***********************************************
ok: [localhost]

TASK [roles/subnets : ensure that the subnets are present] **************************************
ok: [localhost] => (item={u'subnet': u'10.0.10.0/24', u'use': u'ec2', u'az': u'a'})
ok: [localhost] => (item={u'subnet': u'10.0.11.0/24', u'use': u'ec2', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.12.0/24', u'use': u'ec2', u'az': u'c'})
ok: [localhost] => (item={u'subnet': u'10.0.20.0/24', u'use': u'elb', u'az': u'a'})
ok: [localhost] => (item={u'subnet': u'10.0.21.0/24', u'use': u'elb', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.22.0/24', u'use': u'elb', u'az': u'c'})
ok: [localhost] => (item={u'subnet': u'10.0.30.0/24', u'use': u'rds', u'az': u'a'})
ok: [localhost] => (item={u'subnet': u'10.0.31.0/24', u'use': u'rds', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.40.0/24', u'use': u'efs', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.41.0/24', u'use': u'efs', u'az': u'c'})

TASK [roles/subnets : gather information about the ec2 subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the elb subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the rds subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the efs subnets] *********************************
ok: [localhost]

TASK [roles/subnets : register just the IDs for each of the subnets] ****************************
ok: [localhost]

TASK [roles/gateway : ensure that there is an internet gateway] *********************************
ok: [localhost]

TASK [roles/gateway : check that we can route through internet gateway] *************************
ok: [localhost]

TASK [roles/securitygroups : provision elb security group] **************************************
changed: [localhost]

TASK [roles/securitygroups : find out your current public IP address using https://ipify.org/] **
ok: [localhost]

```

```
TASK [roles/securitygroups : set your public ip as a fact] **************************************
ok: [localhost]

TASK [roles/securitygroups : print your public ip address] **************************************
ok: [localhost] => {
 "msg": "Your public IP address is 109.153.155.197/32"
}

TASK [roles/securitygroups : provision ec2 security group] **************************************
changed: [localhost]

TASK [roles/securitygroups : provision rds security group] **************************************
changed: [localhost]

TASK [roles/securitygroups : provision efs security group] **************************************
changed: [localhost]

TASK [roles/securitygroups : print all the ids we have registered] ******************************
ok: [localhost] => {
 "msg": "ELB = sg-97778eea, EC2 = sg-fa778e87, RDS = sg-8e7089f3 and EFS = sg-7b718806"
}

PLAY RECAP **************************************************************************************
localhost : ok=18 changed=4 unreachable=0 failed=0
```

您可以在 AWS 控制台中查看 Ansible 创建的组。在下面的截图中，您可以看到`my-vpc-ec2`安全组：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/2a7aa377-4181-4b69-96a2-390834eb4deb.png)

现在我们已经配置了基本的 VPC，我们可以开始在其中启动服务，首先是 Application Load Balancer。

# ELB 角色

在本章中，我们将要查看的最后一个角色是启动 Application Load Balancer 的角色。嗯，它创建了一个目标组，然后将其附加到 Application Load Balancer 上。我们将使用这个角色创建的负载均衡器很基本；在后面的章节中，我们将会更详细地介绍。

与其他角色一样，我们首先需要引导文件：

```
$ ansible-galaxy init roles/elb
```

现在打开`roles/elb/tasks/main.yml`并使用`elb_target_group`模块创建目标组：

```
- name: provision the target group
  elb_target_group:
    name: "{{ environment_name }}-target-group"
    region: "{{ ec2_region }}"
    protocol: "http"
    port: "80"
    deregistration_delay_timeout: "15"
    vpc_id: "{{ vpc_info.vpc.id }}"
    state: "present"
    modify_targets: "false"
```

正如你所看到的，我们正在在我们的 VPC 中创建目标组，并将其命名为`my-vpc-target-group`。现在我们有了目标组，我们可以使用`elb_application_lb`模块启动 Application Elastic Balancer：

```
- name: provision an application elastic load balancer
  elb_application_lb:
    region: "{{ ec2_region }}"
    name: "{{ environment_name }}-elb"
    security_groups: "{{ sg_elb.group_id }}"
    subnets: "{{ subnet_elb_ids }}"
    listeners:
      - Protocol: "HTTP" 
        Port: "80"
        DefaultActions:
          - Type: "forward" 
            TargetGroupName: "{{ environment_name }}-target-group"
    state: present
  register: loadbalancer
```

在这里，我们正在为我们的 VPC 中的 Application Load Balancer 创建一个名为`my-vpc-elb`的负载均衡器；我们正在传递我们使用`subnet_elb_ids`创建的 ELB 子网的 ID。我们还使用`sg_elb.group_id`将 ELB 安全组添加到负载均衡器，并在端口`80`上配置一个侦听器，将流量转发到`my-vpc-target-group`。

任务的最后部分打印了我们关于 ELB 的信息：

```
# - name: print the information on the load balancer we have registered
#   debug:
#     msg: "{{ loadbalancer }}"
```

这完成了我们的最终角色；更新`site.yml`文件，使其如下所示：

```
- name: Create and configure an Amazon VPC
  hosts: localhost
  connection: local
  gather_facts: True

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/vpc
    - roles/subnets
    - roles/gateway
    - roles/securitygroups
    - roles/elb
```

我们现在可以通过运行以下命令最后一次运行我们的 playbook：

```
$ ansible-playbook site.yml
```

你可能猜到了 playbook 运行的输出将如下所示：

```
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [Create and configure an Amazon VPC] *******************************************************

TASK [Gathering Facts] **************************************************************************
ok: [localhost]

TASK [roles/vpc : ensure that the VPC is present] ***********************************************
ok: [localhost]

TASK [roles/subnets : ensure that the subnets are present] **************************************
ok: [localhost] => (item={u'subnet': u'10.0.10.0/24', u'use': u'ec2', u'az': u'a'})
ok: [localhost] => (item={u'subnet': u'10.0.11.0/24', u'use': u'ec2', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.12.0/24', u'use': u'ec2', u'az': u'c'})
ok: [localhost] => (item={u'subnet': u'10.0.20.0/24', u'use': u'elb', u'az': u'a'})
ok: [localhost] => (item={u'subnet': u'10.0.21.0/24', u'use': u'elb', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.22.0/24', u'use': u'elb', u'az': u'c'})
ok: [localhost] => (item={u'subnet': u'10.0.30.0/24', u'use': u'rds', u'az': u'a'})
ok: [localhost] => (item={u'subnet': u'10.0.31.0/24', u'use': u'rds', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.40.0/24', u'use': u'efs', u'az': u'b'})
ok: [localhost] => (item={u'subnet': u'10.0.41.0/24', u'use': u'efs', u'az': u'c'})

TASK [roles/subnets : gather information about the ec2 subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the elb subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the rds subnets] *********************************
ok: [localhost]

TASK [roles/subnets : gather information about the efs subnets] *********************************
ok: [localhost]

TASK [roles/subnets : register just the IDs for each of the subnets] ****************************
ok: [localhost]

TASK [roles/gateway : ensure that there is an internet gateway] *********************************
ok: [localhost]

TASK [roles/gateway : check that we can route through internet gateway] *************************
ok: [localhost]

TASK [roles/securitygroups : provision elb security group] **************************************
ok: [localhost]

TASK [roles/securitygroups : find out your current public IP address using https://ipify.org/] **
ok: [localhost]

TASK [roles/securitygroups : set your public ip as a fact] **************************************
ok: [localhost]

TASK [roles/securitygroups : provision ec2 security group] **************************************
ok: [localhost]

TASK [roles/securitygroups : provision rds security group] **************************************
ok: [localhost]

TASK [roles/securitygroups : provision efs security group] **************************************
ok: [localhost]

TASK [roles/elb : provision the target group] ***************************************************
changed: [localhost]

TASK [roles/elb : provision an application elastic load balancer] *******************************
changed: [localhost]

TASK [roles/elb : print the information on the load balancer we have registered] ****************
ok: [localhost] => {
 "msg": {
 "access_logs_s3_bucket": "",
 "access_logs_s3_enabled": "false",
 "access_logs_s3_prefix": "",
 "attempts": 1,
 "availability_zones": [
 {
 "subnet_id": "subnet-51f15137",
 "zone_name": "eu-west-1a"
 },
 {
 "subnet_id": "subnet-64eb083e",
 "zone_name": "eu-west-1c"
 },
 {
 "subnet_id": "subnet-6744f22f",
 "zone_name": "eu-west-1b"
 }
 ],
 "canonical_hosted_zone_id": "Z32O12XQLNTSW2",
 "changed": true,
 "created_time": "2018-04-22T16:12:31.780000+00:00",
 "deletion_protection_enabled": "false",
 "dns_name": "my-vpc-elb-374523105.eu-west-1.elb.amazonaws.com",
 "failed": false,
 "idle_timeout_timeout_seconds": "60",
 "ip_address_type": "ipv4",
 "listeners": [
 {
 "default_actions": [
 {
 "target_group_arn": "arn:aws:elasticloadbalancing:eu-west-1:687011238589:targetgroup/my-vpc-target-group/d5bab5efb2d314a8",
 "type": "forward"
 }
 ],
 "listener_arn": "arn:aws:elasticloadbalancing:eu-west-1:687011238589:listener/app/my-vpc-elb/98dd881c7a931ab3/3f4be2b480657bf9",
 "load_balancer_arn": "arn:aws:elasticloadbalancing:eu-west-1:687011238589:loadbalancer/app/my-vpc-elb/98dd881c7a931ab3",
 "port": 80,
 "protocol": "HTTP",
 "rules": [
 {
 "actions": [
 {
 "target_group_arn": "arn:aws:elasticloadbalancing:eu-west-1:687011238589:targetgroup/my-vpc-target-group/d5bab5efb2d314a8",
 "type": "forward"
 }
 ],
 "conditions": [],
 "is_default": true,
 "priority": "default",
 "rule_arn": "arn:aws:elasticloadbalancing:eu-west-1:687011238589:listener-rule/app/my-vpc-elb/98dd881c7a931ab3/3f4be2b480657bf9/c70feab5b31460c2"
 }
 ]
 }
 ],
 "load_balancer_arn": "arn:aws:elasticloadbalancing:eu-west-1:687011238589:loadbalancer/app/my-vpc-elb/98dd881c7a931ab3",
 "load_balancer_name": "my-vpc-elb",
 "routing_http2_enabled": "true",
 "scheme": "internet-facing",
 "security_groups": [
 "sg-97778eea"
 ],
 "state": {
 "code": "provisioning"
 },
 "tags": {},
 "type": "application",
 "vpc_id": "vpc-ccef75aa"
 }
}

```

```
PLAY RECAP ******************************************************************************************************************************
localhost : ok=19 changed=2 unreachable=0 failed=0
```

现在您应该能够在 AWS 控制台的 EC2 部分看到 ELB：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/65e6ad53-1d4f-401b-82d1-5e2e63cc0e69.png)虽然 VPC 不会产生任何费用，但 ELB 会；请确保在完成测试后立即删除任何未使用的资源。

这结束了关于 VPC playbook 的本章；我们将在下一章中使用其中的元素，在那里我们将使用 VPC 作为我们安装的基础，将我们的 WordPress 安装部署到 AWS。

# 总结

在本章中，我们已经迈出了使用 Ansible 在公共云中启动资源的下一步。我们通过创建 VPC，设置我们应用程序所需的子网，配置互联网网关，并设置我们的实例通过它路由其出站流量，为自动化一个相当复杂的环境奠定了基础。

我们还配置了四个安全组，其中三个包含动态内容，以在最终在我们的 VPC 中为我们的服务提供安全保障之前，最终配置了一个 ELB。

在下一章中，我们将在本章奠定的基础上构建，并启动一组更复杂的服务。

# 问题

1.  AWS 模块用来读取您的访问 ID 和密钥的两个环境变量是什么？

1.  真或假：每次运行 playbook，您都会得到一个新的 VPC。

1.  说明为什么我们不费心注册创建子网的结果。

1.  在定义安全组规则时，使用`cidr_ip`和`group_id`有什么区别？

1.  真或假：在使用定义了`group_id`的规则时，添加安全组的顺序并不重要。

1.  在现有 VPC 旁边创建第二个 VPC，给它一个不同的名称，并且也让它使用 10.1.0.0/24。

# 进一步阅读

您可以在本章中使用的 AWS 技术的以下链接找到更多详细信息：

+   **AWS**: [`aws.amazon.com/`](https://aws.amazon.com/)

+   **AWS Management Console**: [`aws.amazon.com/console/`](https://aws.amazon.com/console/)

+   **AWS IAM**: [`aws.amazon.com/iam/`](https://aws.amazon.com/iam/)

+   **Amazon VPC**: [`aws.amazon.com/vpc/`](https://aws.amazon.com/vpc/)

+   **ELB**: [`aws.amazon.com/elasticloadbalancing/`](https://aws.amazon.com/elasticloadbalancing/)
