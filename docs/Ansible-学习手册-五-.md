# Ansible 学习手册（五）

> 原文：[`zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5`](https://zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：构建 VMware 部署

现在我们知道如何在 AWS 中启动网络和服务，我们现在将讨论在 VMware 环境中部署类似设置，并讨论核心 VMware 模块。

在本章中，我们将：

+   快速介绍 VMware

+   审查 Ansible VMware 模块

+   通过一个示例 playbook 来启动几个虚拟机

# 技术要求

在本章中，我们将讨论 VMware 产品系列的各种组件，以及如何使用 Ansible 与它们进行交互。虽然本章中有一个示例 playbook，但它可能不容易转移到您的安装中。因此，建议您在更新之前不要使用本章中的任何示例。

# VMware 简介

VMware 有近 20 年的历史，从一个隐秘的初创公司到被戴尔拥有并被 EMC 收购，收入达 79.2 亿美元。VMware 产品组合目前有大约 30 种产品；最常见的是其 hypervisors，其中有两种不同的类型。

第一个 hypervisor，VMware ESXi，是一种直接在硬件上运行的类型 1，使用大多数现代 64 位英特尔和 AMD CPU 中找到的指令集。其原始的类型 2 hypervisor 不需要 CPU 中存在虚拟化指令，就像它们需要在类型 1 中一样。它以前被称为 GSX；这个 hypervisor 早于类型 1 hypervisor，这意味着它可以支持更旧的 CPU。

VMware 在大多数企业中非常普遍；它允许管理员快速在许多标准的基于 x86 的硬件配置和类型上部署虚拟机。

# VMware 模块

如前所述，VMware 范围内大约有 30 种产品；这些产品涵盖了从 hypervisors 到虚拟交换机、虚拟存储以及与基于 VMware 的主机和虚拟机进行交互的几个接口。在本节中，我们将介绍随 Ansible 一起提供的核心模块，以管理您的 VMware 资产的所有方面。

我尝试将它们分成逻辑组，并且对于每个组，都会简要解释模块所针对的产品。

# 要求

所有模块都有一个共同点：它们都需要安装一个名为`PyVmomi`的 Python 模块。要安装它，请运行以下`pip`命令：

```
$ sudo pip install PyVmomi
```

该模块包含了 VMware vSphere API Python 绑定，没有它，我们将在本章中要讨论的模块无法与您的 VMware 安装进行交互。

虽然本章中的模块已经在 vSphere 5.5 到 6.5 上进行了测试，但您可能会发现一些旧模块在较新版本的 vSphere 上存在一些问题。

# vCloud Air

vCloud Air 是 VMware 的**基础设施即服务**（**IaaS**）产品，我说*是*因为 vCloud Air 业务部门和负责该服务的团队于 2017 年中被法国托管和云公司 OVH 从 VMware 收购。有三个 Ansible 模块直接支持 vCloud Air，以及**VMware vCloud Hybrid Service**（**vCHS**）和**VMware vCloud Director**（**vCD**）。

# vca_fw 模块

该模块使您能够从 vCloud Air 网关中添加和删除防火墙规则。以下示例向您展示了如何添加一个允许 SSH 流量的规则：

```
- name: example fireware rule
  vca_fw:
   instance_id: "abcdef123456-1234-abcd-1234-abcdef123456"
   vdc_name: "my_vcd"
   service_type: "vca"
   state: "present"
   fw_rules:
     - description: "Allow SSH"
       source_ip: "10.20.30.40"
       source_port: "Any"
       dest_port: "22"
       dest_ip: "192.0.10.20"
       is_enable: "true"
       enable_logging: "false"
       protocol: "Tcp"
       policy: "allow"
```

注意我们传递了一个`service_type`；这可以是`vca`、`vcd`或`vchs`。

# vca_nat 模块

该模块允许您管理**网络地址转换**（**NAT**）规则。在下面的示例中，我们要求所有命中公共 IP 地址`123.123.123.123`上的端口`2222`的流量被转发到 IP 地址为`192.0.10.20`的虚拟机上的端口`22`：

```
- name: example nat rule
  vca_nat:
   instance_id: "abcdef123456-1234-abcd-1234-abcdef123456"
   vdc_name: "my_vcd"
   service_type: "vca"
   state: "present"
   nat_rules:
      - rule_type: "DNAT"
        original_ip: "123.123.123.123"
        original_port: "2222"
        translated_ip: "192.0.10.20"
        translated_port: "22"
```

这意味着要从我们的外部网络访问虚拟机`192.0.10.20`上的 SSH，我们需要运行类似以下命令：

```
$ ssh username@123.123.123.123 -p2222
```

假设我们已经设置了正确的防火墙规则，我们应该通过`192.0.10.20`虚拟机进行路由。

# vca_vapp 模块

该模块用于创建和管理 vApps。vApp 是一个或多个虚拟机的组合，用于提供一个应用程序：

```
- name: example vApp
  vca_vapp:
    vapp_name: "Example"
    vdc_name: "my_vcd"
    state: "present"
    operation: "poweron"
    template_name: "CentOS7 x86_64 1804"
```

上一个示例是使用`vca_vapp`模块的一个非常基本的示例，以确保存在名为`Example`的 vApp 并且处于开启状态。

# VMware vSphere

VMware vSphere 是由 VMware 组件组成的软件套件。这就是 VMware 可能会让人有点困惑的地方，因为 VMware vSphere 由 VMware vCentre 和 VMware ESXi 组成，它们各自也有自己的 Ansible 模块，并且在表面上，它们似乎完成了类似的任务。

# vmware_cluster 模块

该模块允许您管理您的 VMware vSphere 集群。VMware vSphere 集群是一组主机，当它们被集群在一起时，它们共享资源，允许您添加**高可用性**（**HA**），并且还可以启动**分布式资源调度器**（**DRS**），它管理集群中工作负载的放置：

```
- name: Create a cluster
  vmware_cluster:
    hostname: "{{ item.ip }}"
    datacenter_name: "my_datacenter"
    cluster_name: "cluster"
    enable_ha: "yes"
    enable_drs: "yes"
    enable_vsan: "yes"
    username: "{{ item.username }}"
    password: "{{ item.password }}"
  with_items: "{{ vsphere_hosts }}"
```

前面的代码将循环遍历主机、用户名和密码列表以创建一个集群。

# vmware_datacenter 模块

VMware vSphere 数据中心是指支持您的集群的物理资源、主机、存储和网络的集合的名称：

```
- name: Create a datacenter
  vmware_datacenter:
    hostname: "{{ item.ip }}"
    username: "{{ item.username }}"
    password: "{{ item.password }}"
    datacenter_name: "my_datacenter"
    state: present
  with_items: "{{ vsphere_hosts }}"
```

上一个示例将`vsphere_hosts`中列出的主机添加到`my_datacenter` VMware vSphere 数据中心。

# vmware_vm_facts 模块

该模块可用于收集运行在您的 VMware vSphere 集群中的虚拟机或模板的信息：

```
- name: Gather facts on all VMs in the cluster
  vmware_vm_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    vm_type: "vm"
  delegate_to: "localhost"
  register: vm_facts
```

上一个示例仅收集了在我们的集群中创建的虚拟机的信息，并将结果注册为`vm_facts`变量。如果我们想要找到有关模板的信息，我们可以将`vm_type`更新为 template，或者我们可以通过将`vm_type`更新为 all 来列出所有虚拟机和模板。

# vmware_vm_shell 模块

该模块可用于连接到使用 VMware 的虚拟机并运行 shell 命令。在任何时候，Ansible 都不需要使用诸如 SSH 之类的基于网络的服务连接到虚拟机，这对于在虚拟机上线之前配置 VM 非常有用：

```
- name: Shell example
  vmware_vm_shell:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    datacenter: "my_datacenter"
    folder: "/my_vms"
    vm_id: "example_vm"
    vm_username: "root"
    vm_password: "supersecretpassword"
    vm_shell: "/bin/cat"
    vm_shell_args: " results_file "
    vm_shell_env:
      - "PATH=/bin"
      - "VAR=test"
    vm_shell_cwd: "/tmp"
  delegate_to: "localhost"
  register: shell_results
```

上一个示例连接到名为`example_vm`的 VM，该 VM 存储在`my_datacenter`数据中心根目录下的`my_vms`文件夹中。一旦使用我们提供的用户名和密码连接后，它将运行以下命令：

```
$ /bin/cat results_file
```

在 VM 的`/tmp`文件夹中，运行命令的输出被注册为`shell_results`，以便我们以后可以使用它。

# vmware_vm_vm_drs_rule 模块

使用此模块，您可以配置 VMware DRS 亲和性规则。这允许您控制集群中虚拟机的放置：

```
- name: Create DRS Affinity Rule for VM-VM
  vmware_vm_vm_drs_rule:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    cluster_name: "cluster"
    vms: "{{ item }}"
    drs_rule_name: ""
    enabled: "True"
    mandatory: "True"
    affinity_rule: "True"
  with_items:
    - "example_vm"
    - "another_example_vm"
```

在上一个示例中，我们正在创建一个规则，使得 VMs `example_vm`和`another_example_vm`永远不会在同一台物理主机上运行。

# vmware_vm_vss_dvs_migrate 模块

该模块将指定的虚拟机从标准 vSwitch 迁移到分布式 vSwitch，后者可在整个集群中使用。

```
- name: migrate vm to dvs
  vmware_vm_vss_dvs_migrate"
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
```

```
    password: "{{ vsphere_password }}"
    vm_name: "example_vm"
    dvportgroup_name: "example_portgroup"
  delegate_to: localhost
```

正如你所看到的，我们正在将`example_vm`从标准 vSwitch 移动到名为`example_portgroup`的分布式 vSwitch。

# vsphere_copy 模块

该模块有一个单一的目的——将本地文件复制到远程数据存储：

```
- name: copy file to datastore
  vsphere_copy:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    src: "/path/to/local/file"
    datacenter: "my_datacenter"
    datastore: "my_datastore"
    path: "path/to/remove/file"
  transport: local
```

正如你所看到的，我们正在将文件从`/path/to/local/file`复制到`my_datacenter`数据中心中托管的`my_datastore`数据存储中的`path/to/remove/file`。

# vsphere_guest 模块

该模块已被弃用，并将在 Ansible 2.9 中删除；建议您改用`vmware_guest`模块。

# VMware vCentre

VMware vCentre 是 VMware vSphere 套件的重要组件；它使诸如 vMotion、VMware 分布式资源调度器和 VMware 高可用性等功能进行集群化。

# vcenter_folder 模块

此模块使 vCenter 文件夹管理成为可能。例如，以下示例为您的虚拟机创建一个文件夹：

```
- name: Create a vm folder
  vcenter_folder:
    hostname: "{{ item.ip }}"
    username: "{{ item.username }}"
    password: "{{ item.password }}"
    datacenter_name: "my_datacenter"
    folder_name: "virtual_machines"
    folder_type: "vm"
    state: "present"
```

以下是为您的主机创建文件夹的示例：

```
- name: Create a host folder
  vcenter_folder:
    hostname: "{{ item.ip }}"
    username: "{{ item.username }}"
    password: "{{ item.password }}"
    datacenter_name: "my_datacenter"
    folder_name: "hosts"
    folder_type: "host"
    state: "present"
```

# vcenter_license 模块

此模块允许您添加和删除 VMware vCenter 许可证：

```
- name: Add a license
  vcenter_license:
    hostname: "{{ item.ip }}"
    username: "{{ item.username }}"
    password: "{{ item.password }}"
    license: "123abc-456def-abc456-def123"
    state: "present"
  delegate_to: localhost
```

# vmware_guest 模块

此模块允许您在 VMware 集群中启动和管理虚拟机；以下示例显示了如何使用模板启动 VM：

```
- name: Create a VM from a template
  vmware_guest:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my-datacenter"
    folder: "/vms"
    name: "yet_another_example_vm"
    state: "poweredon"
    template: "centos7-x86_64-1804"
    disk:
      - size_gb: "40"
        type: "thin"
        datastore: "my_datastore"
    hardware:
      memory_mb: "4048"
      num_cpus: "4"
      max_connections: "3"
      hotadd_cpu: "True"
      hotremove_cpu: "True"
      hotadd_memory: "True"
    networks:
      - name: "VM Network"
        ip: "192.168.1.100"
        netmask: "255.255.255.0"
        gateway: "192.168.1.254"
        dns_servers:
          - "192.168.1.1"
          - "192.168.1.2"
    wait_for_ip_address: "yes"
  delegate_to: "localhost"
  register: deploy
```

正如您所看到的，我们对 VM 及其配置有相当多的控制权。硬件、网络和存储配置有单独的部分；我们将在本章末稍微详细地看一下这个模块。

# vmware_guest_facts 模块

此模块收集有关已创建的 VM 的信息：

```
- name: Gather facts on the yet_another_example_vm vm
  vmware_guest_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my-datacenter"
    folder: "/vms"
    name: "yet_another_example_vm"
  delegate_to: localhost
  register: facts
```

前面的示例收集了我们在上一节中定义的机器的大量信息，并将信息注册为变量，以便我们可以在 playbook 运行的其他地方使用它。

# vmware_guest_file_operation 模块

此模块是在 Ansible 2.5 中引入的；它允许您在 VM 上添加和获取文件，而无需 VM 连接到网络。它还允许您在 VM 内创建文件夹。以下示例在 VM 内创建一个目录：

```
- name: create a directory on a vm
  vmware_guest_file_operation:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my-datacenter"
    vm_id: "yet_another_example_vm"
    vm_username: "root"
    vm_password: "supersecretpassword"
    directory:
      path: "/tmp/imported/files"
      operation: "create"
      recurse: "yes"
  delegate_to: localhost
```

以下示例将名为`config.zip`的文件从我们的 Ansible 主机复制到先前创建的目录中：

```
- name: copy file to vm
  vmware_guest_file_operation:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my-datacenter"
    vm_id: "yet_another_example_vm"
    vm_username: "root"
    vm_password: "supersecretpassword"
    copy:
        src: "files/config.zip"
        dest: "/tmp/imported/files/config.zip"
        overwrite: "False"
  delegate_to: localhost
```

# vmware_guest_find 模块

我们知道 VM 运行的文件夹的名称。如果我们不知道，或者由于任何原因发生了更改，我们可以使用`vmware_guest_find`模块动态发现位置：

```
- name: Find vm folder location
  vmware_guest_find:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    name: "yet_another_example_vm"
  register: vm_folder
```

文件夹的名称将注册为`vm_folder`。

# vmware_guest_powerstate 模块

这个模块很容易理解；它用于管理 VM 的电源状态。以下示例重新启动了一个 VM：

```
- name: Powercycle a vm
  vmware_guest_powerstate:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    folder: "/vms"
    name: "yet_another_example_vm"
    state: "reboot-guest"
  delegate_to: localhost
```

您还可以安排对电源状态的更改。以下示例在 2019 年 4 月 1 日上午 9 点关闭 VM：

```
- name: April fools
  vmware_guest_powerstate:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    folder: "/vms"
    name: "yet_another_example_vm"
    state: "powered-off"
    scheduled_at: "01/04/2019 09:00"
  delegate_to: localhost
```

并不是我会做这样的事情！

# vmware_guest_snapshot 模块

此模块允许您管理 VM 快照；例如，以下创建了一个快照：

```
- name: Create a snapshot
  vmware_guest_snapshot:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my-datacenter"
    folder: "/vms"
    name: "yet_another_example_vm"
    snapshot_name: "pre-patching"
    description: "snapshot made before patching"
    state: "present"
  delegate_to: localhost
```

从前面的示例中可以看出，这个快照是因为我们即将对 VM 进行打补丁。如果打补丁顺利进行，那么我们可以运行以下任务：

```
- name: Remove a snapshot
  vmware_guest_snapshot:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my-datacenter"
    folder: "/vms"
    name: "yet_another_example_vm"
    snapshot_name: "pre-patching"
    state: "remove"
  delegate_to: localhost
```

如果一切不如预期那样进行，打补丁破坏了我们的 VM，那么不用担心，我们有一个可以恢复的快照：

```
- name: Revert to a snapshot
  vmware_guest_snapshot:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my-datacenter"
    folder: "/vms"
    name: "yet_another_example_vm"
    snapshot_name: "pre-patching"
    state: "revert"
  delegate_to: localhost
```

祈祷您永远不必恢复快照（除非计划中）。

# vmware_guest_tools_wait 模块

本节的最后一个模块是另一个很容易理解的模块；它只是等待 VMware tools 可用，然后收集有关该机器的信息：

```
- name: Wait for VMware tools to become available by name
  vmware_guest_tools_wait:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    folder: "/vms"
    name: "yet_another_example_vm"
  delegate_to: localhost
  register: facts
```

VMware tools 是在 VM 内部运行的应用程序。一旦启动，它允许 VMware 与 VM 进行交互，从而使诸如`vmware_guest_file_operation`和`vmware_vm_shell`等模块能够正常运行。

# VMware ESXi

在大多数 VMware 安装的核心是一些 VMware ESXi 主机。VMware ESXi 是一种类型 1 的 hypervisor，可以使 VM 运行。Ansible 提供了几个模块，允许您配置和与您的 VMware ESXi 主机进行交互。

# vmware_dns_config 模块

此模块允许您管理 ESXi 主机的 DNS 方面；它允许您设置主机名、域和 DNS 解析器：

```
- name: Configure the hostname and dns servers
  local_action
    module: vmware_dns_config:
    hostname: "{{ exsi_host }}"
    username: "{{ exsi_username }}"
    password: "{{ exsi_password }}"
    validate_certs: "no"
    change_hostname_to: "esxi-host-01"
    domainname: "my-domain.com"
    dns_servers:
        - "8.8.8.8"
        - "8.8.4.4"
```

在前面的示例中，我们将主机的 FQDN 设置为`esxi-host-01.my-domain.com`，并配置主机使用 Google 公共 DNS 解析器。

# vmware_host_dns_facts 模块

一个简单的模块，用于收集您的 VMware ESXi 主机的 DNS 配置信息：

```
- name: gather facts on dns config
  vmware_host_dns_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
```

# vmware_host 模块

您可以使用此模块将您的 ESXi 主机附加到 vCenter：

```
- name: add an esxi host to vcenter
  vmware_host:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    datacenter_name: "my-datacenter"
    cluster_name: "my_cluster"
    esxi_hostname: "{{ exsi_host }}"
    esxi_username: "{{ exsi_username }}"
    esxi_password: "{{ exsi_password }}"
    state: present
```

您还可以使用该模块重新连接主机到您的 vCenter 集群：

```
- name: reattach an esxi host to vcenter
  vmware_host:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    datacenter_name: "my-datacenter"
    cluster_name: "my_cluster"
    esxi_hostname: "{{ exsi_host }}"
    esxi_username: "{{ exsi_username }}"
    esxi_password: "{{ exsi_password }}"
    state: reconnect
```

您还可以从 vCenter 集群中删除主机：

```
- name: remove an esxi host to vcenter
  vmware_host:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    datacenter_name: "my-datacenter"
    cluster_name: "my_cluster"
    esxi_hostname: "{{ exsi_host }}"
    esxi_username: "{{ exsi_username }}"
    esxi_password: "{{ exsi_password }}"
    state: absent
```

# vmware_host_facts 模块

正如您可能已经猜到的那样，此模块收集有关您的 vSphere 或 vCenter 集群中的 VMware ESXi 主机的信息：

```
- name: Find out facts on the esxi hosts
  vmware_host_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
  register: host_facts
  delegate_to: localhost
```

# vmware_host_acceptance 模块

使用此模块，您可以管理 VMware ESXi 主机的接受级别。VMware 支持四个接受级别，它们是：

+   VMwareCertified

+   VMwareAccepted

+   PartnerSupported

+   CommunitySupported

这些级别控制着可以安装在 ESXi 主机上的 VIB；VIB 是 ESXi 软件包。这通常决定了您将从 VMware 或 VMware 合作伙伴那里获得的支持水平。以下任务将为指定集群中的所有 ESXi 主机设置接受级别为 CommunitySupported：

```
- name: Set acceptance level for all esxi hosts in the cluster
  vmware_host_acceptance:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
    acceptance_level: "community"
    state: present
  register: cluster_acceptance_level
```

# vmware_host_config_manager 模块

使用此模块，您可以在各个 VMware ESXi 主机上设置配置选项，例如：

```
- name: Set some options on our esxi host
  vmware_host_config_manager:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ exsi_host }}"
    options:
        "Config.HostAgent.log.level": "verbose"
        "Annotations.WelcomeMessage": "Welcome to my awesome Ansible managed ESXi host"
        "Config.HostAgent.plugins.solo.enableMob": "false"
```

Ansible 将从您的 VMware 主机映射高级配置选项，因此有关可用选项的更多信息，请参阅您的文档。

# vmware_host_datastore 模块

此模块使您能够在 VMware ESXi 主机上挂载和卸载数据存储；在以下示例中，我们正在在清单中的所有 VMware ESXi 主机上挂载三个数据存储：

```
- name: Mount datastores on our cluster
  vmware_host_datastore:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter_name: "my-datacenter"
    datastore_name: "{{ item.name }}"
    datastore_type: "{{ item.type }}"
    nfs_server: "{{ item.server }}"
    nfs_path: "{{ item.path }}"
    nfs_ro: "no"
    esxi_hostname: "{{ inventory_hostname }}"
    state: present
  delegate_to: localhost
  with_items:
      - { "name": "ds_vol01", "server": "nas", "path": "/mnt/ds_vol01", 'type': "nfs"} 
      - { "name": "ds_vol02", "server": "nas", "path": "/mnt/ds_vol02", 'type': "nfs"} 
      - { "name": "ds_vol03", "server": "nas", "path": "/mnt/ds_vol03", 'type': "nfs"} 
```

# vmware_host_firewall_manager 模块

此模块允许您配置 VMware ESXi 主机上的防火墙规则：

```
- name: set some firewall rules on the esxi hosts
  vmware_host_firewall_manager:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ inventory_hostname }}"
    rules:
      - name: "vvold"
        enabled: "True"
      - name: "CIMHttpServer"
        enabled: "False"
```

上一个示例在主机清单中的每个 VMware ESXi 主机上启用了`vvold`并禁用了`CIMHttpServer`。

# vmware_host_firewall_facts 模块

正如您可能已经猜到的那样，此模块与其他事实模块一样，用于收集我们集群中所有主机的防火墙配置的信息：

```
- name: Get facts on all cluster hosts
  vmware_host_firewall_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
```

它也可以仅收集单个主机的信息：

```
- name: Get facts on a single host
  vmware_host_firewall_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ exsi_host }}"
```

# vmware_host_lockdown 模块

此模块带有一个警告，内容为：此模块具有破坏性，因为管理员权限是使用 API 管理的，请仔细阅读选项并继续。

您可以使用以下代码锁定主机：

```
- name: Lockdown an ESXi host
  vmware_host_lockdown:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ exsi_host }}"
    state: "present"
```

您可以使用以下方法将主机解除锁定：

```
- name: Remove the lockdown on an ESXi host
  vmware_host_lockdown:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ exsi_host }}"
    state: "absent"
```

如先前提到的，此模块可能会产生一些意想不到的副作用，因此您可能希望逐个主机执行此操作，而不是使用以下选项，该选项将使指定集群中的所有主机进入锁定状态：

```
- name: Lockdown all the ESXi hosts
  vmware_host_lockdown:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
    state: "present"
```

# vmware_host_ntp 模块

使用此模块，您可以管理每个 VMware ESXi 主机的 NTP 设置。以下示例配置所有主机使用相同的 NTP 服务器：

```
- name: Set NTP servers for all hosts
  vmware_host_ntp:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
    state: present
    ntp_servers:
        - 0.pool.ntp.org
        - 1.pool.ntp.org
        - 2.pool.ntp.org
```

# vmware_host_package_facts 模块

此模块可用于收集有关您集群中所有 VMware ESXi 主机的信息：

```
- name: Find out facts about the packages on all the ESXi hosts
  vmware_host_package_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
  register: cluster_packages
```

与其他事实模块一样，它也可以仅收集单个主机的信息：

```
- name: Find out facts about the packages on a single ESXi host
  vmware_host_package_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ exsi_host }}"
  register: host_packages
```

# vmware_host_service_manager 模块

此模块可让您管理集群成员或单个主机上的 ESXi 服务器：

```
- name: Start the ntp service on all esxi hosts
  vmware_host_service_manager:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
    service_name: "ntpd"
    service_policy: "automatic"
    state: "present"
```

在此示例中，我们正在启动集群中所有主机的 NTP 服务（`service_name`）；由于我们将`service_policy`定义为`automatic`，因此只有在配置了与防火墙规则相对应的服务时，服务才会启动。如果我们希望服务无论防火墙规则如何都启动，那么我们可以将`service_policy`设置为`on`，或者如果希望停止服务，则应将`service_policy`设置为`off`。

# vmware_host_service_facts 模块

使用此模块，您可以查找集群中每个 VMware ESXi 主机上配置的服务的信息：

```
- name: Find out facts about the services on all the ESXi hosts
  vmware_host_service_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
  register: cluster_services
```

# vmware_datastore_facts 模块

这是一个旧式事实模块，可用于收集数据中心中配置的数据存储的信息：

```
- name: Find out facts about the datastores
  vmware_datastore_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my_datacenter"
  delegate_to: localhost
  register: datastore_facts
```

您可能会注意到这个和之前的事实模块之间的语法有一点不同。

# vmware_host_vmnic_facts 模块

从旧式事实模块返回到新模块，此模块可用于收集有关 VMware ESXi 主机上物理网络接口的信息：

```
- name: Find out facts about the vmnics on all the ESXi hosts
  vmware_host_vmnic_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my_datacenter"
  register: cluster_vmnics
```

对于单个 ESXi 主机，我们可以使用以下任务：

```
- name: Find out facts about the vmnics on a single ESXi host
  vmware_host_vmnic_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ exsi_host }}"
  register: host_vmnics
```

# vmware_local_role_manager 模块

使用此模块，您可以在集群上配置角色；这些角色可用于分配特权。在以下示例中，我们正在为`vmware_qa`角色分配一些特权：

```
- name: Add a local role
  vmware_local_role_manager:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
  local_role_name: "vmware_qa"
  local_privilege_ids: [ "Folder.Create", "Folder.Delete"]
  state: "present"
```

# vmware_local_user_manager 模块

使用此模块，您可以通过添加用户并设置其密码来管理本地用户：

```
- name: Add local user to ESXi
  vmware_local_user_manager:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    local_user_name: "myuser"
    local_user_password: "my-super-secret-password"
    local_user_description: "An example user added by Ansible"
  delegate_to: "localhost"
```

# vmware_cfg_backup 模块

使用此模块，您可以创建 VMware ESXi 主机配置的备份：

```
- name: Create an esxi host configuration backup
  vmware_cfg_backup:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    state: "saved"
    dest: "/tmp/"
    esxi_hostname: "{{ exsi_host }}"
  delegate_to: "localhost"
  register: cfg_backup
```

请注意，此模块将自动将主机置于维护状态，然后保存配置。在前面的示例中，您可以使用`fetch`模块使用`/tmp`中注册的信息来获取备份的副本。

您还可以使用此模块恢复配置：

```
- name: Restore an esxi host configuration backup
  vmware_cfg_backup:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
```

```
    validate_certs: "no"
    state: "loaded"
    dest: "/tmp/my-host-backup.tar.gz"
    esxi_hostname: "{{ exsi_host }}"
  delegate_to: "localhost"
```

最后，您还可以通过运行以下代码将主机配置重置为默认设置：

```
- name: Reset a host configuration to the default values
  vmware_cfg_backup:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    state: "absent"
    esxi_hostname: "{{ exsi_host }}"
  delegate_to: "localhost"
```

# vmware_vmkernel 模块

此模块允许您在主机上添加 VMkernel 接口，也称为虚拟 NIC：

```
- name: Add management port with a static ip
   vmware_vmkernel:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ exsi_host }}"
  vswitch_name: "my_vSwitch"
  portgroup_name: "my_portgroup"
  vlan_id: "the_vlan_id"
  network:
    type: "static"
    ip_address: "192.168.127.10"
    subnet_mask: "255.255.255.0"
  state: "present"
  enable_mgmt: "True"
```

在前面的示例中，我们添加了一个管理接口；还有以下选项：

+   `enable_ft`：启用容错流量的接口

+   `enable_mgmt`：启用管理流量的接口

+   `enable_vmotion`：启用 VMotion 流量的接口

+   `enable_vsan`：启用 VSAN 流量的接口

# vmware_vmkernel_facts 模块

另一个事实模块，这是一个新式模块；您可能已经猜到任务的样子：

```
- name: Find out facts about the vmkernel on all the ESXi hosts
  vmware_vmkernel_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
  register: cluster_vmks

- name: Find out facts about the vmkernel on a single ESXi host
  vmware_vmkernel_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ exsi_host }}"
  register: host_vmks
```

# vmware_target_canonical_facts 模块

使用此模块，您可以找出 SCSI 目标的规范名称；您只需要知道目标设备的 ID：

```
- name: Get Canonical name of SCSI device
  vmware_target_canonical_facts"
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    target_id: "6"
   register: canonical_name
```

# vmware_vmotion 模块

您可以使用此模块执行虚拟机从一个 VMware ESXi 主机迁移到另一个主机的 vMotion：

```
- name: Perform vMotion of VM
  vmware_vmotion
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    vm_name: "example_vm"
    destination_host: "esxi-host-02"
  delegate_to: "localhost"
  register: vmotion_results
```

# vmware_vsan_cluster 模块

您可以使用此模块注册 VSAN 集群；此模块的工作方式与本章中的其他模块略有不同，您首先需要在单个主机上生成集群 UUID，然后再使用生成的 UUID 在其余主机上部署 VSAN。

以下任务假定您有一个名为`esxi_hosts`的主机组，其中包含多个主机。第一个任务将 VSAN 分配给组中的第一个主机，然后注册结果：

```
- name: Configure VSAN on first host in the group
  vmware_vsan_cluster:
    hostname: "{{ groups['esxi_hosts'][0] }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
  register: vsan_cluster
```

作为`vsan_cluster`注册的结果包含我们将需要在组中其余主机上使用的 VSAN 集群 UUID。以下代码配置了其余主机上的集群，跳过原始主机：

```
- name: Configure VSAN on the remaining hosts in the group
  vmware_vsan_cluster:
    hostname: "{{ item }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    cluster_uuid: "{{ vsan_cluster.cluster_uuid }}"
  with_items: "{{ groups['esxi_hosts'][1:] }}"
```

# vmware_vswitch 模块

使用此模块，您可以向 ESXi 主机添加或删除**VMware 标准交换机**（**vSwitch**）：

```
- name: Add a vSwitch
  vmware_vswitch:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    switch: "vswitch_name"
    nics:
      - "vmnic1"
      - "vmnic2"
    mtu: "9000"
  delegate_to: "localhost"
```

在此示例中，我们添加了一个连接到多个 vmnic 的 vSwitch。

# vmware_drs_rule_facts 模块

您可以使用此模块收集整个集群或单个数据中心中配置的 DRS 的事实：

```
- name: Find out facts about drs on all the hosts in the cluster
  vmware_drs_rule_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
  delegate_to: "localhost"
  register: cluster_drs

- name: Find out facts about drs in a single data center
  vmware_drs_rule_facts:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my_datacenter"
  delegate_to: "localhost"
  register: datacenter_drs
```

# vmware_dvswitch 模块

此模块允许您创建和删除分布式 vSwitches：

```
- name: Create dvswitch
  vmware_dvswitch:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my_datacenter"
    switch_name: "my_dvSwitch"
    switch_version: "6.0.0"
    mtu: "9000"
    uplink_quantity: "2"
    discovery_proto: "lldp"
    discovery_operation: "both"
    state: present
  delegate_to: "localhost"
```

# vmware_dvs_host 模块

使用此模块，您可以向分布式虚拟交换机添加或删除主机：

```
- name: Add host to dvs
  vmware_dvs_host:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ exsi_host }}"
    switch_name: "my_dvSwitch"
    vmnics:
      - "vmnic1"
      - "vmnic2"
    state: "present"
  delegate_to: "localhost"
```

# vmware_dvs_portgroup 模块

使用此模块，您可以管理您的 DVS 端口组：

```
- name: Create a portgroup with vlan 
  vmware_dvs_portgroup:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    portgroup_name: "my_portgroup_vlan123"
    switch_name: "my_dvSwitch"
    vlan_id: "123"
    num_ports: "120"
    portgroup_type: "earlyBinding"
    state: "present"
  delegate_to: "localhost"
```

# vmware_maintenancemode 模块

使用此模块，您可以将主机置于维护模式。以下示例向您展示了如何在 VSAN 上保持对象可用性的同时将主机置于维护模式：

```
- name: Put host into maintenance mode
  vmware_maintenancemode:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    esxi_hostname: "{{ exsi_host }}"
    vsan: "ensureObjectAccessibility"
    evacuate: "yes"
    timeout: "3600"
    state: "present"
  delegate_to: "localhost"
```

# vmware_portgroup 模块

此模块允许您在给定集群中的主机上创建 VMware 端口组：

```
- name: Create a portgroup with vlan
  vmware_portgroup:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    cluster_name: "my_cluster"
    switch_name: "my_switch"
    portgroup_name: "my_portgroup_vlan123"
    vlan_id: "123"
  delegate_to: "localhost"
```

# vmware_resource_pool 模块

使用这个，我们要看的最后一个模块，您可以创建一个资源池。以下是如何执行此操作的示例：

```
- name: Add resource pool
  vmware_resource_pool:
    hostname: "{{ vsphere_host }}"
    username: "{{ vsphere_username }}"
    password: "{{ vsphere_password }}"
    validate_certs: "no"
    datacenter: "my_datacenter"
    cluster: "my_new_cluster"
    resource_pool: "my_resource_pool"
    mem_shares: "normal"
    mem_limit: "-1"
    mem_reservation: "0"
    mem_expandable_reservations: "True"
    cpu_shares: "normal"
    cpu_limit: "-1"
    cpu_reservation: "0"
    cpu_expandable_reservations: "True"
    state: present
  delegate_to: "localhost"
```

# 一个示例 playbook

在完成本章之前，我将分享一个我为在 VMware 集群中部署少量虚拟机编写的示例 playbook。该项目的想法是将七台虚拟机启动到客户的网络中，如下所示：

+   一个 Linux 跳板主机

+   一个 NTP 服务器

+   一个负载均衡器

+   两个 Web 服务器

+   两个数据库服务器

所有 VM 都必须从现有模板构建；不幸的是，这个模板是使用`/etc/sysconfig/network`文件中硬编码的网关 IP 地址`192.168.1.254`构建的。这意味着为了让这些机器正确出现在网络上，我必须在每台虚拟机启动后进行更改。

我首先在我的`group_vars`文件夹中设置了一个名为`vmware.yml`的文件；其中包含了连接到我的 VMware 安装所需的信息，以及 VM 的默认凭据：

```
vcenter:
  host: "cluster.cloud.local"
  username: "svc_ansible@cloud.local"
  password: "mymegasecretpassword"

wait_for_ip_address: "yes"
machine_state: "poweredon"

deploy:
  datacenter: "Cloud DC4"
  folder: "/vm/Ansible"
  resource_pool: "/Resources/"

vm_shell:
  username: "root"
  password: "hushdonttell"
  cwd: "/tmp"
  cmd: "/bin/sed"
  args: "-i 's/GATEWAY=192.168.1.254/GATEWAY={{ item.gateway }}/g' /etc/sysconfig/network"
```

我将使用两个角色中定义的变量。接下来是`group_vars/vms.yml`文件；其中包含了在我的 VMware 环境中启动虚拟机所需的所有信息：

```
vm:
  - name: "NTPSERVER01"
    machine_name: "ntpserver01"
    machine_template: "RHEL6_TEMPLATE"
    guest_id: "rhel6_64Guest"
    host: "compute-host-01.cloud.local"
    cpu: "1"
    ram: "1024"
    networks: 
      - name: "CLOUD-CUST|Customer|MANGMENT"
        ip: "192.168.99.10"
        netmask: "255.255.255.0"
        device_type: "vmxnet3"
    gateway: "192.168.99.254"
    disk:
      - size_gb: "30"
        type: "thin"
        datastore: "cust_sas_esx_nfs_01"
  - name: "JUMPHOST01"
    machine_name: "jumphost01"
    machine_template: "RHEL6_TEMPLATE"
    guest_id: "rhel6_64Guest"
    host: "compute-host-02.cloud.local"
    cpu: "1"
    ram: "1024"
    networks: 
      - name: "CLOUD-CUST|Customer|MANGMENT"
        ip: "192.168.99.20"
        netmask: "255.255.255.0"
        device_type: "vmxnet3"
    gateway: "192.168.99.254"
    disk:
      - size_gb: "30"
        type: "thin"
        datastore: "cust_sas_esx_nfs_01"
  - name: "LOADBALANCER01"
    machine_name: "loadbalancer01"
    machine_template: "LB_TEMPLATE"
    guest_id: "rhel6_64Guest"
    host: "compute-host-03.cloud.local"
    cpu: "4"
    ram: "4048"
    networks: 
      - name: "CLOUD-CUST|Customer|DMZ"
        ip: "192.168.98.100"
        netmask: "255.255.255.0"
        device_type: "vmxnet3"
    gateway: "192.168.99.254"
    disk:
      - size_gb: "30"
        type: "thin"
        datastore: "cust_sas_esx_nfs_02"    
  - name: "WEBSERVER01"
    machine_name: "webserver01"
    machine_template: "RHEL6_TEMPLATE"
    guest_id: "rhel6_64Guest"
    host: "compute-host-01.cloud.local"
    cpu: "1"
    ram: "1024"
    networks: 
      - name: "CLOUD-CUST|Customer|APP"
        ip: "192.168.100.10"
        netmask: "255.255.255.0"
        device_type: "vmxnet3"
    gateway: "192.168.100.254"
    disk:
      - size_gb: "30"
        type: "thin"
        datastore: "cust_sas_esx_nfs_01"
  - name: "WEBSERVER02"
    machine_name: "webserver02"
    machine_template: "RHEL6_TEMPLATE"
    guest_id: "rhel6_64Guest"
    host: "compute-host-02.cloud.local"
    cpu: "1"
    ram: "1024"
    networks: 
      - name: "CLOUD-CUST|Customer|APP"
        ip: "192.168.100.20"
        netmask: "255.255.255.0"
        device_type: "vmxnet3"
    gateway: "192.168.100.254"
    disk:
      - size_gb: "30"
        type: "thin"
        datastore: "cust_sas_esx_nfs_02"      
  - name: "DBSERVER01"
    machine_name: "dbserver01"
    machine_template: "RHEL6_TEMPLATE"
    guest_id: "rhel6_64Guest"
    host: "compute-host-10.cloud.local"
    cpu: "8"
    ram: "32000"
    networks: 
      - name: "CLOUD-CUST|Customer|DB"
        ip: "192.168.101.10"
        netmask: "255.255.255.0"
        device_type: "vmxnet3"
    gateway: "192.168.101.254"
    disk:
      - size_gb: "30"
        type: "thin"
        datastore: "cust_sas_esx_nfs_01"
      - size_gb: "250"
        type: "thick"
        datastore: "cust_ssd_esx_nfs_01" 
      - size_gb: "250"
        type: "thick"
        datastore: "cust_ssd_esx_nfs_01" 
      - size_gb: "250"
        type: "thick"
        datastore: "cust_ssd_esx_nfs_01" 
  - name: "DBSERVER02"
    machine_name: "dbserver02"
    machine_template: "RHEL6_TEMPLATE"
    guest_id: "rhel6_64Guest"
    host: "compute-host-11.cloud.local"
    cpu: "8"
    ram: "32000"
    networks: 
      - name: "CLOUD-CUST|Customer|DB"
        ip: "192.168.101.11"
        netmask: "255.255.255.0"
        device_type: "vmxnet3"
    gateway: "192.168.101.254"
    disk:
      - size_gb: "30"
        type: "thin"
        datastore: "cust_sas_esx_nfs_02"
      - size_gb: "250"
        type: "thick"
        datastore: "cust_ssd_esx_nfs_02" 
      - size_gb: "250"
        type: "thick"
        datastore: "cust_ssd_esx_nfs_02" 
      - size_gb: "250"
        type: "thick"
        datastore: "cust_ssd_esx_nfs_02"
```

正如你所看到的，我正在为所有七台 VM 定义规格、网络和存储；在可能的情况下，我正在进行存储的薄配置，并确保在一个角色中有多个虚拟机时，我正在使用不同的存储池。

现在我已经拥有了我虚拟机所需的所有细节，我可以创建角色了。首先是`roles/vmware/tasks/main.yml`：

```
- name: Launch the VMs
  vmware_guest:
    hostname: "{{vcenter.host}}"
    username: "{{ vcenter.username }}"
    password: "{{ vcenter.password }}"
    validate_certs: no
    datacenter: "{{ deploy.datacenter }}"
    folder: "{{ deploy.folder }}"
    name: "{{ item.machine_name | upper }}"
    state: "{{ machine_state }}"
    guest_id: "{{ item.guest_id }}"
    esxi_hostname: "{{ item.host }}"
    hardware:
      memory_mb: "{{ item.ram }}"
      num_cpus: "{{ item.cpu }}"
    networks: "{{ item.networks }}"
    disk: "{{ item.disk }}"
    template: "{{ item.machine_template }}"
    wait_for_ip_address: "{{ wait_for_ip_address }}"
    customization:
      hostname: "{{ item.machine_name | lower }}"
  with_items: "{{ vm }}"
```

正如你所看到的，这个任务循环遍历`vm`变量中的项目；一旦虚拟机启动，它将等待我分配的 IP 地址在 VMware 中可用。这确保了在启动下一个虚拟机或继续下一个角色之前，虚拟机已经正确启动。

下一个角色解决了在虚拟机模板中硬编码为`192.168.1.254`的网关的问题；它可以在`roles/fix/tasks/main.yml`中找到。该角色中有两个任务；第一个任务将网关更新为虚拟机所在网络的正确网关：

```
- name: Sort out the wrong IP address in the /etc/sysconfig/network file on the vms
  vmware_vm_shell:
    hostname: "{{vcenter.host}}"
    username: "{{ vcenter.username }}"
    password: "{{ vcenter.password }}"
    validate_certs: no
    vm_id: "{{ item.machine_name | upper }}"
    vm_username: "{{ vm_shell.username }}"
    vm_password: "{{ vm_shell.password }}"
    vm_shell: "{{ vm_shell.cmd }}"
    vm_shell_args: " {{ vm_shell.args }} "
    vm_shell_cwd: "{{ vm_shell.cwd }}"
  with_items: "{{ vm }}"
```

正如你所看到的，这个任务循环遍历定义为`vm`的虚拟机列表，并执行我们在`group_vars/vmware.yml`文件中定义的`sed`命令。一旦这个任务运行完毕，我们需要再运行一个任务。这个任务重新启动所有虚拟机上的网络，以便网关的更改被接受：

```
- name: Restart networking on all VMs
  vmware_vm_shell:
    hostname: "{{vcenter.host}}"
    username: "{{ vcenter.username }}"
    password: "{{ vcenter.password }}"
    validate_certs: no
    vm_id: "{{ item.machine_name | upper }}"
    vm_username: "{{ vm_shell.username }}"
    vm_password: "{{ vm_shell.password }}"
    vm_shell: "/sbin/service"
    vm_shell_args: "network restart"
  with_items: "{{ vm }}"
```

当我运行 playbook 时，大约需要 30 分钟才能运行完，但最终我启动了七台虚拟机，并且可以使用，所以我随后能够运行一系列的 playbooks，对环境进行引导，以便我可以将它们交给客户，让他们部署他们的应用程序。

# 总结

正如你从非常长的模块列表中所看到的，你可以使用 Ansible 来完成大部分作为 VMware 管理员的常见任务。再加上我们在第七章中所看到的*核心网络模块*，用于管理网络设备，以及支持 NetApp 存储设备的模块，你可以构建一些跨物理设备、VMware 元素甚至在虚拟化基础设施中运行的虚拟机的复杂 playbooks。

在下一章中，我们将看到如何使用 Vagrant 在本地构建我们的 Windows 服务器，然后将我们的 playbooks 移到公共云。

# 问题

1.  你需要在你的 Ansible 控制器上安装哪个 Python 模块才能与 vSphere 进行交互？

1.  真或假：`vmware_dns_config`只允许你在你的 ESXi 主机上设置 DNS 解析器。

1.  列举我们已经涵盖的两个可以用来启动虚拟机的模块的名称；有三个，但其中一个已被弃用。

1.  我们已经查看的模块中，你会使用哪一个来确保虚拟机在进行与 VMware 交互的任务之前完全可用？

1.  真或假：使用 Ansible 可以安排更改电源状态。

# 进一步阅读

关于 VMware vSphere 的一个很好的概述，我推荐观看以下视频：[`www.youtube.com/watch?v=3OvrKZYnzjM`](https://www.youtube.com/watch?v=3OvrKZYnzjM)。


# 第十二章：Ansible Windows 模块

到目前为止，我们一直在针对 Linux 服务器进行操作。在本章中，我们将看一下支持和与基于 Windows 的服务器进行交互的核心 Ansible 模块的不断增长的集合。就个人而言，来自几乎完全是 macOS 和 Linux 背景，使用一个在 Windows 上没有本地支持的工具来管理 Windows 感觉有点奇怪。

然而，我相信在本章结束时，您会同意，它的开发人员已经尽可能地使将 Windows 工作负载引入到您的 playbook 中的过程变得无缝和熟悉。

在本章中，我们将学习如何使用 Vagrant 在本地构建我们的 Windows 服务器，然后将我们的 playbooks 移到公共云。我们将涵盖：

+   在 Windows 中启用功能

+   在 AWS 中启动 Windows 实例

+   创建用户

+   使用 Chocolatey 安装第三方软件包

# 技术要求

与上一章一样，我们将使用 Vagrant 和 AWS。我们将使用的 Vagrant box 包含 Windows 2016 的评估副本。我们将在 AWS 中启动的 Windows EC2 实例将是完全许可的，因此将在 EC2 资源成本之上产生额外的费用。与往常一样，您可以在附带的存储库中找到完整的 playbooks，网址为[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter12`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter12)。

# 启动和运行

对于本节，我们将使用 Vagrant 来启动一个 Windows 2016 服务器，就像我们在第二章中所做的那样，*安装和运行 Ansible*。让我们首先看一下我们将使用来启动我们主机的 Vagrantfile。

# Vagrantfile

这个`Vagrantfile`看起来与我们用来启动 Linux 主机的文件并没有太大的不同：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION  = "2"
BOX_NAME     = "StefanScherer/windows_2016"
COMMUNICATOR = "winrm"
USERNAME     = "vagrant"
PASSWORD     = "vagrant"

Vagrant.configure(API_VERSION) do |config|
  config.vm.define "vagrant-windows-2016"
  config.vm.box = BOX_NAME
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.network "forwarded_port", guest: 80, host: 8080
  config.vm.communicator = COMMUNICATOR
  config.winrm.username = USERNAME
  config.winrm.password = PASSWORD

  config.vm.provider "virtualbox" do |v|
    v.memory = "4048"
    v.cpus = "4"
    v.gui = true
  end

  config.vm.provider "vmware_fusion" do |v|
    v.vmx["memsize"] = "4048"
    v.vmx["numvcpus"] = "4"
  end

end
```

正如您所看到的，我们正在替换对 SSH Vagrant 的引用。我们将使用**Windows 远程管理**（**WinRM**）协议以及 Ansible 与虚拟机进行交互。默认情况下，`config.vm.communicator`是 SSH，因此用`winrm`覆盖这个意味着我们必须提供`config.winrm.username`和`config.winrm.password`。

此外，我们指示 Vagrant 不要尝试在虚拟机上挂载我们的本地文件系统，也不要添加任何额外的 IP 地址或网络接口；相反，它应该只是将本地主机的端口转发到主机。

最后，我们将本地机器上的端口`8080`映射到 Windows 主机上的端口`80`；本章后面会详细介绍。

我们可以使用以下命令之一启动主机：

```
$ vagrant up
```

这将使用 VirtualBox，或者我们可以通过运行以下命令使用 VMWare：

```
$ vagrant up --provider=vmware_fusion
```

我们使用的 Vagrant box 大小为几个 GB，因此下载需要一些时间，但一旦下载完成，您应该会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/e80b27cd-f789-4c08-be32-e6ac32f2a108.png)

一旦机器启动，您会发现您的虚拟机已经打开了一个窗口，Windows 桌面是可访问的，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/4a8f7e70-8323-4dd5-bfcd-6492d589b261.png)

现在暂时最小化这个窗口，因为我们将不直接与 Windows 交互。关闭窗口可能会暂停并关闭虚拟机。

现在我们的 Windows 主机已经启动运行，我们需要安装一些支持 Python 模块，以便让 Ansible 与其进行交互。

# Ansible 准备

如前所述，Ansible 将使用 WinRM 与我们的 Windows 主机进行交互。

WinRM 提供对称为 WS-Management 的类似 SOAP 的协议的访问。与提供用户交互式 shell 以管理主机的 SSH 不同，WinRM 接受执行的脚本，然后将结果传递回给您。

为了能够使用 WinRM，Ansible 要求我们安装一些不同的 Python 模块，Linux 用户可以使用以下命令来安装它们：

```
$ sudo pip install pywinrm[credssp]
```

如果 macOS 用户在更新时出现关于无法更新`pyOpenSSL`的错误，那么可能需要执行以下命令，因为它是核心操作系统的一部分：

```
$ sudo pip install pywinrm[credssp] --ignore-installed pyOpenSSL
```

安装完成后，我们现在应该能够与我们的 Windows 主机进行交互，一旦我们配置了主机清单文件。该文件名为`production`，看起来像下面这样：

```
box1 ansible_host=localhost

[windows]
box1

[windows:vars]
ansible_connection=winrm
ansible_user=vagrant
ansible_password=vagrant
ansible_port=55985
ansible_winrm_scheme=http
ansible_winrm_server_cert_validation=ignore
```

正如你所看到的，我们已经删除了所有关于 SSH 的引用，并用 WinRM (`ansible_connection`)替换了它们。同样，我们必须提供用户名(`ansible_user`)和密码(`ansible_password`)。由于我们使用的 Vagrant box 是如何构建的，我们没有使用默认的 HTTPS 方案，而是使用了 HTTP 方案(`ansible_winrm_scheme`)。这意味着我们必须使用端口`55985`(`ansible_port`)，而不是端口`99586`。这两个端口都是从我们的 Ansible 控制器映射到 Windows 主机上的端口`9585`和`5986`。

现在我们已经让 Windows 运行起来并配置了 Ansible，我们可以开始与它进行交互了。

# ping 模块

并非所有的 Ansible 模块都适用于 Windows 主机，其中 ping 就是其中之一。为 Windows 提供了一个名为`win_ping`的模块，我们将在这里使用它。

我们需要运行的命令如下；正如你所看到的，除了模块名称之外，它与我们针对 Linux 主机执行的方式完全相同：

```
$ ansible windows -i production -m win_ping
```

如果你是 macOS 用户，并且收到了这样的错误，那么不用担心；有一个解决方法：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/a12d7ab9-b466-4a78-bd25-e0fe996cedca.png)

这个错误是 Ansible 团队正在解决的一个已知问题。与此同时，运行以下命令，或将其添加到你的`~/.bash_profile`文件中：

```
$ export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

一旦你运行了该命令，你应该会看到以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/bcbfd9e5-a54d-4ca2-af5a-d44526f2ab6d.png)

我们接下来要运行的下一个模块是专为 Windows 或 Linux 主机设计的。

# setup 模块

正如我们在第二章中发现的，*安装和运行 Ansible*，setup 模块在我们的目标主机上收集事实；如果我们使用`ansible`命令直接调用该模块，事实将直接打印在屏幕上。要调用该模块，我们需要运行以下命令：

```
$ ansible windows -i production -m setup
```

正如你从下面的屏幕中看到的，显示的信息几乎与我们针对 Linux 主机运行模块时的情况完全相同：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/772fbc5a-3412-4f17-b8fd-0fa181aca54b.png)

我们可以使用第二章中的一个 playbook，*安装和运行 Ansible*，来查看这一点。在`playbook01.yml`中，我们使用了 Ansible 首次连接到主机时收集的事实来显示一条消息。让我们更新该 playbook 以与我们的 Windows 主机交互：

```
---

- hosts: windows
  gather_facts: true

  tasks:
    - debug:
        msg: "I am connecting to {{ ansible_nodename }} which is running {{ ansible_distribution }} {{ ansible_distribution_version }}"
```

正如你所看到的，我们已经更新了主机组，使用`windows`而不是`boxes`，并且我们还删除了`become`和`become_method`选项，因为我们将连接的用户有足够的权限来运行我们需要的任务。

我们可以使用以下命令运行 playbook：

```
$ ansible-playbook -i production playbook01.yml
```

下面的屏幕显示了预期的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/9c195618-d125-488d-a092-1ea2f3a863ef.png)

现在我们已经快速地介绍了基础知识，我们可以考虑做一些有用的事情，安装一些不同的软件包。

# 安装 web 服务器

当我们让我们的 Linux 主机运行起来时，我们做的第一件事之一就是安装 web 服务器，所以让我们通过在我们的 Windows 主机上安装和启用**Internet Information Services** (**IIS**)来重复这个过程。

IIS 是随 Windows Server 一起提供的默认 web 服务器，它支持以下协议：HTTP、HTTPS 和 HTTP/2，以及 FTP、FTPS、SMTP 和 NNTP。它是 22 年前作为 Windows NT 的一部分首次发布的。

就像我们迄今为止所涵盖的所有 playbook 一样，让我们通过运行以下命令创建基本的框架：

```
$ mkdir web web/group_vars web/roles
$ touch web/production web/site.yml web/group_vars/common.yml
```

现在我们可以开始编写我们的 playbook 了。

# IIS 角色

我们要看的第一个角色安装和配置 IIS，然后，与我们之前的剧本一样，使用模板由 Ansible 生成并上传 HTML 文件。首先，切换到`web`文件夹，并通过运行以下命令创建角色：

```
$ cd web
$ ansible-galaxy init roles/iis
```

从`roles/iis/defaults/main.yml`中的默认变量开始，我们可以看到我们的角色将与我们设置 LAMP 堆栈时创建的 Apache 角色非常相似：

```
---
# defaults file for web/roles/iis

document_root: 'C:\inetpub\wwwroot\'
html_file: ansible.html

html_heading: "Success !!!"
html_body: |
  This HTML page has been deployed using Ansible to a <b>{{ ansible_distribution }}</b> host.<br><br>
  The weboot is <b>{{ document_root }}</b> this file is called <b>{{ html_file }}</b>.<br>
```

如您所见，我们提供了文档根目录的路径，我们的 HTML 文件的名称，以及我们 HTML 文件的一些内容，模板可以在`roles/iis/templates/index.html.j2`中找到：

```
<!--{{ ansible_managed }}-->
<!doctype html>
<title>{{ html_heading }}</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px; margin: 0 auto; }
</style>
<article>
    <h1>{{ html_heading }}</h1>
    <div>
        <p>{{ html_body }}</p>
    </div>
</article>
```

这是我们之前在 Apache 角色中使用的确切模板。部署 IIS 非常简单，我们只需要在`roles/iis/tasks/main.yml`中完成两个任务。我们的第一个任务可以在这里找到：

```
- name: enable IIS
  win_feature:
    name: 
      - "Web-Server"
      - "Web-Common-Http"
    state: "present"
```

这使用`win_feature`模块来启用和启动`Web-Server`和`Web-Common-Http`功能。下一个和最后一个任务使用`win_template`模块部署我们的 HTML 页面：

```
- name: create an html file from a template
  win_template:
    src: "index.html.j2"
    dest: "{{ document_root }}{{ html_file }}"
```

如您所见，语法与标准的`template`模块几乎相同。现在我们的角色已经完成，我们可以运行剧本，将主机清单文件的内容复制到我们在上一节中使用的`production`文件中，并更新`site.yml`，使其包含以下内容：

```
---

- hosts: windows
  gather_facts: true

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/iis
```

然后，您可以使用以下命令运行剧本：

```
$ ansible-playbook -i production site.yml
```

剧本运行的输出应该类似于以下终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/9a44a6c6-53ec-4d84-ae30-40ee1bf3f1d7.png)

完成后，您应该能够在本地计算机上打开 Web 浏览器并转到`http://localhost:8080/`，这应该会显示默认的 IIS 页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/174387ff-ba12-4aad-b513-0686c5c10365.png)

打开`http://localhost:8080/ansible.html`将显示我们上传的页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/55b8632c-0a21-4987-81f4-b90d0beea36a.png)

# ASP.NET 角色

现在我们已经启动了 IIS，让我们看看如何启用 ASP.NET 支持。同样，让我们首先创建角色：

```
$ ansible-galaxy init roles/asp
```

从`roles/asp/defaults/main.yml`中的变量开始，您可以看到它们看起来与 HTML 变量类似，只是我们已经用`.aspx`作为前缀，这样它们就不会与`iis`角色的变量冲突：

```
aspx_document_root: 'C:\inetpub\wwwroot\ansible\'
aspx_file: default.aspx

aspx_heading: "Success !!!"
aspx_body: |
  This HTML page has been deployed using Ansible to a <b>{{ ansible_distribution }}</b> host.<br><br>
  The weboot is <b>{{ aspx_document_root }}</b> this file is called <b>{{ aspx_file }}</b>.<br><br>
  The output below is from ASP.NET<br><br>
  Hello from <%= Environment.MachineName %> at <%= DateTime.UtcNow %><br><br>
```

从页面底部可以看出，我们包含了一个打印机器名称的函数，这在我们的情况下应该是 Vagrant，还有日期和时间。

接下来，我们在`roles/asp/templates/default.aspx.j2`中有模板。除了更新的变量和文件名外，内容基本上与在`iis`角色中使用的内容相同：

```
<!--{{ ansible_managed }}-->
<!doctype html>
<title>{{ html_heading }}</title>
<style>
  body { text-align: center; padding: 150px; }
  h1 { font-size: 50px; }
  body { font: 20px Helvetica, sans-serif; color: #333; }
  article { display: block; text-align: left; width: 650px; margin: 0 auto; }
</style>
<article>
    <h1>{{ aspx_heading }}</h1>
    <div>
        <p>{{ aspx_body }}</p>
    </div>
</article>
```

接下来，我们有应放置在`roles/asp/tasks/main.yml`中的任务。首先，我们使用`win_feature`模块来启用所需的组件，以便让我们的基本页面运行起来：

```
- name: enable .net
  win_feature:
    name: 
      - "Net-Framework-Features"
      - "Web-Asp-Net45"
      - "Web-Net-Ext45"
    state: "present"
  notify: restart iis
```

接下来，我们需要创建一个文件夹来提供我们的页面，并复制渲染的模板：

```
- name: create the folder for our asp.net app
  win_file:
    path: "{{ aspx_document_root }}"
    state: "directory"

- name: create an aspx file from a template
  win_template:
    src: "default.aspx.j2"
    dest: "{{ aspx_document_root }}{{ aspx_file }}"
```

如您所见，我们再次使用了`win_template`模块。除了使用`win_file`模块外，文件模块的语法与我们在其他章节中使用的`file`模块非常接近。最后一个任务检查了 IIS 中站点的配置是否正确：

```
- name: ensure the default web application exists
  win_iis_webapplication:
    name: "Default"
    state: "present"
    physical_path: "{{ aspx_document_root }}"
    application_pool: "DefaultAppPool"
    site: "Default Web Site"
```

`win_iis_webapplication`模块用于配置 IIS 中的 Web 应用程序，正如其名称所示。这在我们的示例中并不是严格要求的，但它可以让你了解可能的操作。

您可能已经注意到，当我们启用了附加功能时，我们发送了一个重新启动 IIS 的通知。这意味着我们必须在`roles/asp/handlers/main.yml`文件中添加一个任务。此任务使用`win_service`模块重新启动 Web 服务器：

```
- name: restart iis
  win_service:
    name: w3svc
    state: restarted
```

现在我们已经完成了角色，我们可以再次运行剧本。首先，我们需要将新角色添加到`site.yml`文件中：

```
---

- hosts: windows
  gather_facts: true

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/iis
    - roles/asp
```

然后，您可以使用以下命令运行剧本：

```
$ ansible-playbook -i production site.yml
```

这应该会给你以下输出的某种形式：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/0007233a-c7c0-42db-926b-db2729691502.png)

打开浏览器并转到`http://localhost:8080/ansible/`应该会显示类似以下网页的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/97b229ab-ce2f-480d-bcba-b18f526dee35.png)

让我们删除 Vagrant 框并查看更多模块。要删除框，请运行：

```
$ vagrant destroy
```

现在我们可以使用 Ansible 创建用户，并在 AWS 中的服务器主机上安装一些桌面应用程序。

# 与 AWS Windows 实例交互

当我们与本地 Windows Vagrant 框进行交互时，它并未使用安全连接；让我们看看如何在 AWS 实例中启动 Windows EC2 实例，然后像我们在第十章中与 CentOS 7 实例进行交互一样与其交互。

首先，我们需要为新的 playbook 创建文件夹结构：

```
$ mkdir cloud cloud/group_vars cloud/roles
$ touch cloud/production cloud/site.yml cloud/group_vars/common.yml
```

一旦我们有了结构，我们需要创建四个角色，首先是 AWS 角色。

# AWS 角色

我们的第一个角色将创建 VPC 并启动 EC2 实例。要启动角色更改，请转到 cloud 文件夹并运行：

```
$ cd cloud
$ ansible-galaxy init roles/aws
```

让我们首先从`roles/aws/defaults/main.yml`的内容开始：

```
vpc_cidr_block: "10.0.0.0/16"
the_subnets:
  - { use: 'ec2', az: 'a', subnet: '10.0.10.0/24' }

ec2:
  instance_type: "t2.large"
  wait_port: "5986"

image:
  base: Windows_Server-2016-English-Full-Base-*
  owner: amazon
  architecture: x86_64
  root_device: ebs

win_initial_password: "{{ lookup('password', 'group_vars/generated_administrator chars=ascii_letters,digits length=30') }}"
```

如您所见，我们只会使用一个子网，并且在 playbook 运行期间将寻找 Windows Server 2016 AMI。最后，我们正在设置一个名为`win_initial_password`的变量，该变量将用于在 playbook 运行期间稍后设置我们的管理员密码。

`roles/aws/tasks/main.yml`中的大多数任务都如您所期望的那样。首先，我们设置 VPC，创建子网，并找出用于安全组的当前 IP 地址：

```
- name: ensure that the VPC is present
  ec2_vpc_net:
    region: "{{ ec2_region }}"
    name: "{{ environment_name }}"
    state: present
    cidr_block: "{{ vpc_cidr_block }}"
    resource_tags: { "Name" : "{{ environment_name }}", "Environment" : "{{ environment_name }}" }
  register: vpc_info

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

- name: gather information about the ec2 subnets
  ec2_vpc_subnet_facts:
    region: "{{ ec2_region }}"
    filters:
      "tag:Use": "ec2"
      "tag:Environment": "{{ environment_name }}"
  register: subnets_ec2

- name: register just the IDs for each of the subnets
  set_fact:
    subnet_ec2_ids: "{{ subnets_ec2.subnets | map(attribute='id') | list }}"

- name: find out your current public IP address using https://ipify.org/
  ipify_facts:
  register: public_ip

- name: set your public ip as a fact
  set_fact:
    your_public_ip: "{{ public_ip.ansible_facts.ipify_public_ip }}/32"
```

安全组已更新，因此我们不再打开端口 22，而是打开远程桌面（端口`3389`）和 WinRM（端口`5985`和`5986`）的端口：

```
- name: provision ec2 security group
  ec2_group:
    region: "{{ ec2_region }}"
    vpc_id: "{{ vpc_info.vpc.id }}"
    name: "{{ environment_name }}-ec2"
    description: "Opens the RDP and WinRM ports to a trusted IP"
    tags:
      "Name": "{{ environment_name }}-ec2"
      "Environment": "{{ environment_name }}"
    rules:
      - proto: "tcp"
        from_port: "3389"
        to_port: "3389"
        cidr_ip: "{{ your_public_ip }}"
        rule_desc: "allow {{ your_public_ip }} access to port RDP"
      - proto: "tcp"
        from_port: "5985"
        to_port: "5985"
        cidr_ip: "{{ your_public_ip }}"
        rule_desc: "allow {{ your_public_ip }} access to WinRM"
      - proto: "tcp"
        from_port: "5986"
        to_port: "5986"
        cidr_ip: "{{ your_public_ip }}"
        rule_desc: "allow {{ your_public_ip }} access to WinRM"
  register: sg_ec2
```

然后，我们继续通过添加互联网网关和路由来构建我们的网络，然后找到要使用的正确 AMI ID：

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

- name: check that we can route through internet gateway
  ec2_vpc_route_table:
    region: "{{ ec2_region }}"
    vpc_id: "{{ vpc_info.vpc.id }}"
    subnets: "{{ subnet_ec2_ids }}"
    routes:
      - dest: 0.0.0.0/0
        gateway_id: "{{ igw_info.gateway_id }}"
    resource_tags:
      "Name": "{{ environment_name }}_outbound"
      "Environment": "{{ environment_name }}"

- name: search for all of the AMIs in the defined region which match our selection
  ec2_ami_facts:
    region: "{{ ec2_region }}"
    owners: "{{ image.owner }}"
    filters:
      name: "{{ image.base }}"
      architecture: "{{ image.architecture }}"
      root-device-type: "{{ image.root_device }}" 
  register: amiFind

- name: filter the list of AMIs to find the latest one with an EBS backed volume
  set_fact:
    amiSortFilter: "{{ amiFind.images | sort(attribute='creation_date') | last }}"

- name: finally grab AMI ID of the most recent result which matches our base image which is backed by an EBS volume
  set_fact:
    our_ami_id: "{{ amiSortFilter.image_id }}"
```

现在是时候启动 EC2 实例了；您可能已经注意到，我们不需要上传密钥或任何凭据。这是因为我们实际上将注入一个 PowerShell 脚本，该脚本在实例首次启动时执行。此脚本将设置管理员密码并配置实例，以便 Ansible 可以针对其运行：

```
- name: launch an instance
  ec2_instance:
    region: "{{ ec2_region }}"
    state: "present"
    instance_type: "{{ ec2.instance_type }}"
    image_id: "{{ our_ami_id }}"
    wait: yes
    security_groups: [ "{{ sg_ec2.group_id }}" ]
    network: 
      assign_public_ip: true
    filters:
      instance-state-name: "running"
      "tag:Name": "{{ environment_name }}"
      "tag:environment": "{{ environment_name }}"
    vpc_subnet_id: "{{ subnet_ec2_ids[0] }}"
    user_data: "{{ lookup('template', 'userdata.j2') }}"
    tags:
      Name: "{{ environment_name }}"
      environment: "{{ environment_name }}"
```

脚本是一个名为`userdata.j2`的模板，它使用`user_data`键在实例启动时注入。我们将在一会儿看一下模板；在此角色中剩下的就是将实例添加到主机组，然后等待 WinRM 可访问：

```
- name: gather facts on the instance we just launched using the AWS API
  ec2_instance_facts:
    region: "{{ ec2_region }}"
    filters:
      instance-state-name: "running"
      "tag:Name": "{{ environment_name }}"
      "tag:environment": "{{ environment_name }}"
  register: singleinstance

- name: add our temporary instance to a host group for use in the next step
  add_host:
    name: "{{ item.public_dns_name }}"
    ansible_ssh_host: "{{ item.public_dns_name }}"
    groups: "ec2_instance"
  with_items: "{{ singleinstance.instances }}"

- name: wait until WinRM is available before moving onto the next step
  wait_for:
    host: "{{ item.public_dns_name }}"
    port: "{{ ec2.wait_port }}"
    delay: 2
    timeout: 320
    state: "started"
  with_items: "{{ singleinstance.instances }}"
```

`roles/aws/templates/`中的`userdata.j2`模板如下所示：

```
<powershell>
$admin = adsi
$admin.PSBase.Invoke("SetPassword", "{{ win_initial_password }}")
Invoke-Expression ((New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1'))
</powershell>
```

脚本的第一部分设置了管理员用户的密码（`win_initial_password`）；然后，脚本直接从 Ansible 的 GitHub 存储库下载并执行 PowerShell 脚本。此脚本对目标实例上的当前 WinRM 配置进行检查，然后进行所需的更改，以便 Ansible 能够安全连接。脚本还配置了对实例事件日志的所有操作进行记录。

# 用户角色

接下来，我们有用户角色，可以运行以下命令来创建：

```
$ ansible-galaxy init roles/user
```

此角色为我们创建了一个用户，以便我们连接到我们的实例。`roles/user/defaults/main.yml`中可以找到的默认值如下：

```
ansible:
  username: "ansible"
  password: "{{ lookup('password', 'group_vars/generated_ansible chars=ascii_letters,digits length=30') }}"
  groups:
    - "Users"
    - "Administrators"
```

如您所见，这里我们定义了一个名为`ansible`的用户，该用户具有 30 个字符的随机密码。`ansible`用户将成为`Users`和`Administrators`组的成员。`roles/user/tasks/main.yml`中有一个使用`win_user`模块的单个任务，看起来像：

```
- name: ensure that the ansible created users are present
  win_user:
    name: "{{ ansible.username }}"
    fullname: "{{ ansible.username | capitalize }}"
    password: "{{ ansible.password }}"
    state: "present"
    groups: "{{ ansible.groups }}"
```

与所有 Windows 模块一样，语法与 Linux 等效模块相似，因此您应该对每个键的含义有一个很好的了解。从前一个任务中可以看出，我们使用了 Jinja2 转换来大写`ansible.username`变量的第一个字母。

# Chocolatey 角色

下一个角色使用 Chocolatey 在计算机上安装一些软件。

Chocolatey 是 Windows 的软件包管理器，原理和功能类似于我们在早期章节中使用的 Homebrew，在 macOS 上使用单个命令安装所需软件。Chocolatey 通过将大多数常见 Windows 安装程序的安装过程包装成一组常见的 PowerShell 命令，简化了命令行上的软件包安装过程，非常适合像 Ansible 这样的编排工具。

要添加角色所需的文件，请运行以下命令：

```
$ ansible-galaxy init roles/choc
```

在`roles/choc/defaults/main.yml`中，我们有一个要安装的软件包列表：

```
apps:
  - "notepadplusplus.install"
  - "putty.install"
  - "googlechrome"
```

如您所见，我们想要安装 Notepad++、PuTTY 和 Google Chrome。需要添加到`roles/choc/tasks/main.yml`的任务本身如下所示：

```
- name: install software using chocolatey
  win_chocolatey:
    name: "{{ item }}"
    state: "present"
  with_items: "{{ apps }}"
```

再次强调，`win_chocolatey`模块在针对基于 Linux 的主机时，与我们在之前章节中使用的软件包管理器模块接受类似的输入。

# 信息角色

我们正在创建的最终角色称为`info`，它的唯一目的是输出有关我们新启动和配置的 Windows Server 2016 EC2 实例的信息。正如您可能已经猜到的那样，我们需要运行以下命令：

```
$ ansible-galaxy init roles/info
```

一旦我们有了这些文件，将以下任务添加到`roles/info/tasks/main.yml`中：

```
- name: print out information on the host
  debug:
    msg: "You can connect to '{{ inventory_hostname }}' using the username of '{{ ansible.username }}' with a password of '{{ ansible.password }}'."
```

如您所见，这将为我们提供要连接的主机，以及用户名和密码。

# 运行 playbook

在运行 playbook 之前，我们需要将以下内容添加到`group_vars/common.yml`中：

```
environment_name: "windows_example"
ec2_region: "eu-west-1"
```

名为`production`的主机清单文件应包含以下内容：

```
[ec2_instance]

[ec2_instance:vars]
ansible_connection=winrm
ansible_user="Administrator"
ansible_password="{{ lookup('password', 'group_vars/generated_administrator chars=ascii_letters,digits length=30') }}"
ansible_winrm_server_cert_validation=ignore
```

如您所见，我们使用 WinRM 连接器使用管理员用户名和在启动实例时运行用户数据脚本时设置的密码连接到我们的 Windows 实例。`site.yml`文件应该有以下内容：

```
---

- name: Create the AWS environment and launch an EC2 instance
  hosts: localhost
  connection: local
  gather_facts: True

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/aws

- name: Bootstrap the EC2 instance
  hosts: ec2_instance
  gather_facts: true

  vars_files:
    - group_vars/common.yml

  roles:
    - roles/user
    - roles/choc
    - roles/info 
```

在首先导出 AWS 凭据后，我们可以使用以下命令运行 playbook：

```
$ export AWS_ACCESS_KEY=AKIAI5KECPOTNTTVM3EDA
$ export AWS_SECRET_KEY=Y4B7FFiSWl0Am3VIFc07lgnc/TAtK5+RpxzIGTr
$ ansible-playbook -i production site.yml
```

playbook 运行的略有编辑的输出如下：

```
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit
localhost does not match 'all'

PLAY [Create the AWS environment and launch an EC2 instance] ************************************

TASK [Gathering Facts] **************************************************************************
ok: [localhost]

TASK [roles/aws : ensure that the VPC is present] ***********************************************
changed: [localhost]

TASK [roles/aws : ensure that the subnets are present] ******************************************
changed: [localhost] => (item={u'subnet': u'10.0.10.0/24', u'use': u'ec2', u'az': u'a'})

TASK [roles/aws : gather information about the ec2 subnets] *************************************
ok: [localhost]

TASK [roles/aws : register just the IDs for each of the subnets] ********************************
ok: [localhost]

TASK [roles/aws : find out your current public IP address using https://ipify.org/] *************
ok: [localhost]

TASK [roles/aws : set your public ip as a fact] *************************************************
ok: [localhost]

TASK [roles/aws : provision ec2 security group] *************************************************
changed: [localhost]

TASK [roles/aws : ensure that there is an internet gateway] *************************************
changed: [localhost]

TASK [roles/aws : check that we can route through internet gateway] *****************************
changed: [localhost]

TASK [roles/aws : search for all of the AMIs in the defined region which match our selection] ***
ok: [localhost]

TASK [roles/aws : filter the list of AMIs to find the latest one with an EBS backed volume] *****
ok: [localhost]

TASK [roles/aws : finally grab AMI ID of the most recent result which matches our base image which is backed by an EBS volume] ***************************************************************
ok: [localhost]

TASK [roles/aws : launch an instance] ***********************************************************
changed: [localhost]

TASK [roles/aws : gather facts on the instance we just launched using the AWS API] **************
ok: [localhost]

TASK [roles/aws : add our temporary instance to a host group for use in the next step] **********
changed: [localhost] => 

TASK [roles/aws : wait until WinRM is available before moving onto the next step] ***************
ok: [localhost] => 

PLAY [Bootstrap the EC2 instance] ***************************************************************

TASK [Gathering Facts] **************************************************************************
ok: [ec2-34-245-2-119.eu-west-1.compute.amazonaws.com]

TASK [roles/user : ensure that the ansible created users are present] **************************
changed: [ec2-34-245-2-119.eu-west-1.compute.amazonaws.com]

TASK [roles/choc : install software using chocolatey] *******************************************
changed: [ec2-34-245-2-119.eu-west-1.compute.amazonaws.com] => (item=notepadplusplus.install)
changed: [ec2-34-245-2-119.eu-west-1.compute.amazonaws.com] => (item=putty.install)
changed: [ec2-34-245-2-119.eu-west-1.compute.amazonaws.com] => (item=googlechrome)
 [WARNING]: Chocolatey was missing from this system, so it was installed during this task run.

TASK [roles/info : print out informaton on the host] ********************************************
ok: [ec2-34-245-2-119.eu-west-1.compute.amazonaws.com] => {
 "msg": "You can connect to 'ec2-34-245-2-119.eu-west-1.compute.amazonaws.com' using the username of 'ansible' with a password of 'Qb9LVPkUeZFRx5HLFgVllFrkqK7HHN'."
}

PLAY RECAP **************************************************************************************
ec2-34-245-2-119.eu-west-1.compute.amazonaws.com : ok=4 changed=2 unreachable=0 failed=0
localhost : ok=17 changed=7 unreachable=0 failed=0
```

从输出中可以看出，我的 EC2 实例的主机名是`ec2-34-245-2-119.eu-west-1.compute.amazonaws.com`，`ansible`用户的密码是`Qb9LVPkUeZFRx5HLFgVllFrkqK7HHN`。我可以使用这些详细信息连接到实例，使用 Microsoft RDP（记住它被锁定到您的 IP 地址）。如下截图所示，我以 Ansible 用户身份连接，并打开了 PuTTY 和 Notepad ++；您还可以看到桌面上的 Google Chrome 的快捷方式：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/0918ae5d-a6ea-4a31-96d2-8a95026cf543.png)

您可能注意到的另一件事是，我们从未安装过 Chocolatey。正如在 playbook 运行期间所述，如果`win_chocolatey`在目标机器上找不到 Chocolatey 安装，它将自动安装和配置它。

在 GitHub 存储库的`Chapter12/cloud`文件夹中有一个 playbook，用于删除我们在此处创建的资源。要运行此 playbook，请使用以下命令：

```
$ ansible-playbook -i production remove.yml
```

确保您仔细检查了一切是否按预期被移除，以确保您不会收到任何意外的账单。

# 总结

正如在本章开头提到的，使用诸如 Ansible 这样的传统 Linux 工具在 Windows 上总是感觉有点奇怪。然而，我相信您会同意，体验尽可能接近 Linux。当我第一次尝试使用 Windows 模块时，我惊讶地发现我成功启动了一个 EC2 Windows Server 实例，并成功部署了一个简单的 Web 应用程序，而无需远程桌面连接到目标实例。

随着每个新版本的发布，Ansible 对基于 Windows 的主机的支持越来越多，从您的 playbook 轻松管理混合工作负载。

在下一章中，我们将回到更熟悉的领域，至少对我来说是这样，并看看我们如何加固我们的 Linux 安装。

# 问题

1.  以下两个模块中哪一个可以在 Windows 和 Linux 主机上使用，setup 还是 file？

1.  真或假：您可以使用 SSH 访问您的 Windows 目标。

1.  解释 WinRM 使用的接口类型。

1.  你需要安装哪个 Python 模块才能在 macOS 和 Linux 上与 WinRM 进行交互？

1.  真或假：您可以在使用`win_chocolatey`模块之前有一个单独的任务来安装 Chocolatey。

1.  更新 playbook 以安装额外的软件包。

# 进一步阅读

您可以在[`chocolatey.org/`](http://chocolatey.org/)找到有关优秀的 Chocolatey 的更多信息。
