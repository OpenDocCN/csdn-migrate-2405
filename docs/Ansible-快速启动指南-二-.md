# Ansible 快速启动指南（二）

> 原文：[`zh.annas-archive.org/md5/5ed89b17596e56ef11e7d3cab54e2924`](https://zh.annas-archive.org/md5/5ed89b17596e56ef11e7d3cab54e2924)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Ansible 自动化基础设施

我们已经介绍了如何编写 playbooks 以及如何使用一些方便的模块填充它们。现在让我们把所有东西混合在一起，构建真实的日常基础设施管理情况。本章将提供一系列示例，我们将使用 Ansible playbooks，并借助一些 Linux 工具来自动化日常任务和其他非工作时间发生的任务。这些 playbooks 将有多个任务按顺序工作，以使您能够有效地计划工作。

本章将涵盖以下主题：

+   Linux 系统和应用程序自动化

+   Windows 系统和应用程序自动化

+   容器配置管理

+   网络配置自动化

+   虚拟和云基础设施自动化

# Linux 基础设施自动化

我们将首先看一些涉及 Linux 管理的用例。在这一部分，我们将确定通常需要手动完成的任务，并尝试尽可能自动化。在出现错误或配置错误的情况下，仍可能需要管理员。

我们将把以下用例分成子类别，以更好地确定它们在一般情况下的作用。在每种情况下，我们将查看几个 Ansible 任务。这些任务要么遵循一个 playbook 序列，要么在满足某些条件时执行，要么在循环内执行。

# 系统管理自动化

在这个小节中，我们将展示一些涉及系统管理任务的用例，这些任务可以使用 Ansible playbooks 进行自动化。我们将首先描述任务和执行任务的环境，然后编写一个格式良好且命名规范的 playbook，以说明如何使用 Ansible。

# 用例 1 - 系统更新自动化

这个用例旨在更新和清理基于 Linux 的主机，主要分为 Debian 和 Red Hat 两大家族。任务应该能够更新软件列表索引，安装任何可用的更新，删除不必要的软件包，清理软件包管理器缓存，并在需要时重新启动主机。这个 playbook 可以用于可访问 Ansible 管理服务器的物理或虚拟 Linux 主机。

这个 playbook 的代码如下：

```
---
- name: Update and clean up Linux OS 
  hosts: Linux
  become: yes
  gather_facts: yes
  tasks:
    - name: Update Debian Linux packages with Index 
      updated
      apt: 
        upgrade: dist
        update_cache: yes
      when: ansible_os_family == "Debian"

    - name: Update Red Hat Linux packages with Index 
      updated
      yum: 
        name: "*"
        state: latest
        update_cache: yes
      when: ansible_os_family == "RedHat"

    - name: Clean up Debian Linux from cache and unused 
      packages
      apt: 
        autoremove: yes 
        autoclean: yes
      when: ansible_os_family == "Debian"

    - name: Clean up Red Hat Linux from cache and unused 
      packages
      shell: yum clean all; yum autoremove
      when: ansible_os_family == "RedHat"
      ignore_errors: yes

   - name: Check if Debian system requires a reboot
     shell: "[ -f /var/run/reboot-required ]"
     failed_when: False
     register: reboot_required
     changed_when: reboot_required.rc == 0
     notify: reboot
     when: ansible_os_family == "Debian"
     ignore_errors: yes

   - name: Check if Red Hat system requires a reboot
     shell: "[ $(rpm -q kernel|tail -n 1) != 
     kernel-$(uname -r) ]"
     failed_when: False
     register: reboot_required
     changed_when: reboot_required.rc == 0
     notify: reboot
     when: ansible_os_family == "RedHat" 
     ignore_errors: yes

  handlers:
   - name: reboot
     command: shutdown -r 1 "A system reboot triggered 
     after and Ansible automated system update"
     async: 0
     poll: 0
     ignore_errors: true
```

然后可以安排执行这个 playbook，使用`crontab`作业在周末或深夜系统空闲时执行。或者，可以安排在系统全天候活动的维护期间运行。为了适应冗余主机，用户可以在定义任务之前，在 playbook 头部添加一个批处理大小和最大失败百分比参数。以下代码行可用于启用一定程度的保护：

```
---
- name: Update and clean up Linux OS 
  hosts: Linux
  max_fail_percentage: 20
  serial: 5
  become: yes
  become_user: setup
  gather_facts: yes
  tasks: ...
```

这允许您一次处理五个主机。如果总主机数量的 20%失败，playbook 将停止。

# 用例 2 - 创建一个新用户及其所有设置

这个用例允许您自动添加新用户到系统中。基本上，我们将在所有 Linux 主机上创建一个新用户，并设置好密码。我们还将创建一个 SSH 密钥，以便可以远程访问，并添加一些`sudo`配置以便更容易管理。这在以下代码中实现：

```
---
- name: Create a dedicated remote management user 
  hosts: Linux
  become: yes
  gather_facts: yes
  tasks:
    - name: Create a now basic user
      user: 
         name: 'ansuser' 
         password: 
   $6$C2rcmXJPhMAxLLEM$N.XOWkuukX7Rms7QlvclhWIOz6.MoQd/
   jekgWRgDaDH5oU2OexNtRYPTWwQ2lcFRYYevM83wIqrK76sgnVqOX. 
         # A hash for generic password.
         append: yes
         groups: sudo
         shell: /bin/bash
         state: present

    - name: Create the user folder to host the SSH key
      file: 
         path: /home/ansuser/.ssh
         state: directory
         mode: 0700
         owner: ansuser

    - name: Copy server public SSH key to the newly 
      created folder
      copy: 
         src: /home/admin/.ssh/ansible_rsa
         dest: /home/ansuser/.ssh/id_rsa
         mode: 0600
         owner: ansuser

    - name: Configure the sudo group to work without a 
       password
      lineinfile: 
         dest: /etc/sudoers
         regexp: '^%sudo\s'
         line: "%sudo ALL=(ALL) NOPASSWD{{':'}} ALL" 
         validate: 'visudo -cf %s'
         state: present

    - name: Install favourite text editor for Debian 
      family
      apt: 
         name: nano
         state: latest
         update_cache: yes
      when: ansible_os_family == "Debian"

    - name: Install favourite text editor for Red Hat 
      family
      yum: 
         name: nano
         state: latest
      when: ansible_os_family == "RedHat"

    - name: remove old editor configuration file
      file: 
         path: /home/ansuser/.selected_editor
         state: absent
      ignore_errors: yes

    - name: Create a new configuration file with the 
      favorite text editor
      lineinfile: 
         dest: /home/ansuser/.selected_editor
         line: "SELECTED_EDITOR='/usr/bin/nano'" 
         state: present
         create: yes

    - name: Make the user a system user to hide it from 
      login interface
      blockinfile: 
         path: /var/lib/AccountsService/users/ansuser
         state: present
         create: yes
         block: |
             [User]
             SystemAccount=true
```

在正确的清单配置上执行时，这个 playbook 应该能够取代通常需要访问多个主机来配置单个用户的数小时工作。通过一些调整，可以向任何 playbook 添加额外的功能。在这种情况下，我们可以将任何用户配置添加到管道中。

# 用例 3 - 服务（systemd）管理

在这个用例中，我们将使用 Ansible 手册自动设置和配置多个主机上的一些系统服务。以下代码显示了如何确保安装服务，然后如何进行配置检查以确保其配置良好。最后，我们启动服务并启用它在系统启动时启动：

```
---
- name: Setup and configured recommended Linux services
  hosts: Linux
  become: yes
  gather_facts: yes
  tasks:
    - name: Install a list of services on Linux hosts
      package: 
         name: '{{ item }}'
         state: latest
      with_items:
         - ntp
         - tzdate
         - autofs

    - name: Fix time zone on Red Hat 6
      lineinfile: 
         path: /etc/sysconfig/clock
         line: "ZONE='Europe/London'"
         state: present
         create: yes
      when: ansible_os_family == 'RedHat' and 
      ansible_distribution_version.split('.')[0] == '6'

    - name: Setup time zone on all local hosts
      timezone: 
         name: "Europe/London"

    - name: Fix time zone on Red Hat 6
      blockinfile:
         path: /etc/ntp.conf
         block: |
            server time.nist.gov iburst
            server 0.uk.pool.ntp.org iburst
            server 1.uk.pool.ntp.org iburst
         insertafter: "# Specify one or more NTP 
         servers."
         state: present
      when: ansible_os_family == 'RedHat'
- name: Restart NTP service to apply change and enable    
   it on Debian
  systemd:
  name: ntp
  enabled: True
  state: restarted
  when: ansible_os_family == 'Debian'

 - name: Restart NTP service to apply change and enable 
  it on Red Hat
  systemd:
  name: ntpd
  enabled: True
  state: restarted
  when: ansible_os_family == 'RedHat'

 - name: Add NFS and SMB support to automount
  blockinfile: 
  path: /etc/auto.master
  block: |
  /nfs /etc/auto.nfs
  /cifs /etc/auto.cifs 
  state: present

 - name: create the NFS and SMB AutoFS configuration    
   files
  file: 
  name: '{{ item }}'
  state: touch
  with_items:
  - '/etc/auto.nfs'
  - '/etc/auto.cifs'

 - name: Restart AutoFS service to apply a change and 
   enable it
  systemd:
  name: autofs
  enabled: True
  state: restarted 
```

这本手册可以作为配置任务的一部分由另一个手册调用，以在构建后配置主机。还可以添加额外的功能来启用更大的 Ansible 角色的方面。

# 用例 4 - 自动网络驱动器挂载（NFS，SMB）

现在我们将设置一些远程主机作为 NFS 和 SMB 客户端。我们还将配置一些驱动器以使用`AutoFS`自动连接，这是在之前的用例中安装的。以下代码安装依赖项，配置客户端，然后启动服务。这本手册适用于 Debian 和 Red Hat Linux 系列：

```
---
- name: Setup and connect network shared folders
  hosts: Linux
  become: yes
  gather_facts: yes
  tasks:
    - name: Install the dependencies to enable NFS and 
      SMB clients on Linux Debian family
      apt: 
         name: '{{ item }}'
         state: latest
      with_items:
         - nfs-common
         - rpcbind
         - cifs-utils
         - autofs
      when: ansible_os_family == 'Debian'

    - name: Install the dependencies to enable NFS and 
      SMB clients on Linux Red Hat family
      yum: 
         name: '{{ item }}'
         state: latest
      with_items:
         - nfs-common
         - rpcbind
         - cifs-utils
         - nfs-utils
         - nfs-utils-lib
         - autofs
      when: ansible_os_family == 'RedHat'

    - name: Block none authorised NFS servers using 
      rpcbind
      lineinfile: 
         path: /etc/hosts.deny
         line: "rpcbind: ALL"
         state: present
         create: yes

    - name: Allow the target NFS servers using rpcbind
      lineinfile: 
         path: /etc/hosts.allow
         line: "rpcbind: 192.168.10.20"
         state: present
         create: yes

    - name: Configure NFS share on Fstab
      mount: 
         name: nfs shared
         path: /nfs/shared
         src: "192.168.10.20:/media/shared"
         fstype: nfs
         opts: defaults
         state: present

    - name: Create the shared drive directories
      file:
         name: '{{ item }}'
         state: directory
         with_items:
         - '/nfs/shared'
         - '/cifs/winshared'

    - name: Configure NFS share on AutoFS
      lineinfile: 
         path: /etc/auto.nfs
         line: "shared -fstype=nfs,rw, 
         192.168.10.20:/media/shared”
         state: present

    - name: Configure SMB share on AutoFS
      lineinfile: 
         path: /etc/auto.cifs
         line: "winshared 
         -fstype=cifs,rw,noperm,credentials=/etc/crd.txt 
          ://192.168.11.20/winshared”
         state: present

    - name: Restart AutoFS service to apply NFS and SMB 
      changes
      systemd:
         name: autofs
         state: restarted
```

这本手册可以个性化，就像任何手册一样。例如，它可以安排在负责设置共享驱动器服务器的手册之后运行。

# 用例 5 - 重要文档的自动备份

在这个用例中，我们试图构建一个备份解决方案，它不会使用太多的带宽，通过归档需要备份的所有内容。我们基本上将选择一个要压缩并移动到安全主机的文件夹。以下代码确保安装了所有必要的依赖项，准备备份文件夹，压缩它，然后发送它。我们将使用一个称为同步的模块，它基本上是`rsync`的包装器，这个著名的数据同步工具。它经常用于提供快速备份解决方案：

```
---
- name: Setup and connect network shared folders
  hosts: Linux
  become: yes
  gather_facts: yes
  tasks:
    - name: Install the dependencies to for archiving the 
      backup
      package: 
         name: '{{ item }}'
         state: latest
      with_items:
         - zip
         - unzip
         - gunzip
         - gzip
         - bzip2
         - rsync

    - name: Backup the client folder to the vault 
      datastore server
      synchronize:
         mode: push 
         src: /home/client1
         dest: client@vault.lab.edu:/media/vault1/client1
         archive: yes
         copy_links: yes
         delete: no
         compress: yes
         recursive: yes
         checksum: yes
         links: yes
         owner: yes
         perms: yes
         times: yes
         set_remote_user: yes
         private_key: /home/admin/users_SSH_Keys/id_rsa
      delegate_to: "{{ inventory_hostname }}"
```

这本手册可以添加到`crontab`作业中，以安排定期备份到特定文件夹。

# 应用程序和服务的自动化

这个小节与上一个小节并没有太大不同，但它侧重于系统向外部世界提供的应用程序和服务，而不是与主机内部系统管理相关的内容。在这里，我们将介绍一些处理与应用程序或服务相关的任务的用例。

# 用例 1 - 设置具有一些预安装工具的 Linux 桌面环境

Linux 管理不仅限于管理服务器。如今，由于新的科学研究和其他复杂工具的出现，Linux GUI 用户正在增加。这些工具中有些需要使用终端，但也有一些需要 GUI 界面，例如显示 3D 渲染的分子结构。在这个第一个用例中，我们将制作一个手册，确保 Linux 主机具有特定用途所需的所有必要工具。这个脚本将安装一个简单的 Linux 图形界面，Openbox。这个脚本只兼容 Debian 系列的 Linux 系统，但也可以很容易地转换为支持 Red Hat 系列。

以下手册代码包括在 Linux 环境中设置应用程序的多种方式：

```
---
- name: Setup and connect network shared folders
  hosts: Linux
  become: yes
  gather_facts: yes
  tasks:
    - name: Install OpenBox graphical interface
      apt: 
         name: '{{ item }}'
         state: latest
         update_cache: yes
      with_items:
         - openbox
         - nitrogen
         - pnmixer
         - conky
         - obconf
         - xcompmgr
         - tint2

    - name: Install basic tools for desktop Linux usage 
     and application build
      apt: 
         name: '{{ item }}'
         state: latest
         update_cache: yes
      with_items:
         - htop
         - screen
         - libreoffice-base
         - libreoffice-calc
         - libreoffice-impress
         - libreoffice-writer
         - gnome-tweak-tool
         - firefox
         - thunderbird
         - nautilus
         - build-essential
         - automake
         - autoconf
         - unzip
         - python-pip
         - default-jre
         - cmake
         - git
         - wget
         - cpanminus
         - r-base
         - r-base-core
         - python3-dev
         - python3-pip
         - libgsl0-dev

    - name: Install tools using Perl CPAN
      cpanm:
          name: '{{ item }}'
      with_items:
         - Data::Dumper
         - File::Path
         - Cwd

    - name: Install tools using Python PyPip
      shell: pip3 install -U '{{ item }}'
      with_items:
         - numpy 
         - cython
         - scipy
         - biopython
         - pandas

    - name: Install tools on R CRAN using Bioconductor as 
      source 
      shell: Rscript --vanilla -e   
       "source('https://bioconductor.org/biocLite.R'); 
        biocLite(c('ggplots2', 'edgeR','optparse'), 
        ask=FALSE);"

    - name: Download a tool to be compiled on each host
      get_url: 
          url: http://cegg.unige.ch/pub/newick-utils-1.6-
          Linux-x86_64-enabled-extra.tar.gz 
          dest: /usr/local/newick.tar.gz
          mode: 0755

    - name: Unarchive the downloaded tool on each host
      unarchive: 
          src: /usr/local/newick.tar.gz
          dest: /usr/local/
          remote_src: yes
          mode: 0755

    - name: Configure the tool before to the host before 
      building
      command: ./configure chdir="/usr/local/newick-
      utils-1.6"

    - name: Build the tool on the hosts
      make:
          chdir: /usr/local/newick-utils-1.6
          target: install

    - name: Create Symlink to the tool’s binary to be 
      executable from anywhere in the system 
      shell: ln -s -f /usr/local/newick-utils-1.6/src
          /nw_display /usr/local/bin/nw_display

    - name: Installing another tool located into a github 
      repo
      git: 
          repo: https://github.com/chrisquince/DESMAN.git
          dest: /usr/local/DESMAN
          clone: yes

    - name: Setup the application using python compiler
      command: cd /usr/local/DESMAN; python3 setup.py install
```

这本手册可以在部署了几台主机后执行，可以在第一个脚本完成后调用它，也可以设置一个监视脚本来等待特定主机可用以启动这本手册。

# 用例 2 - LAMP 服务器设置和配置

这个用例自动化了通常由系统管理员手动执行的任务。使用以下手册，我们将设置一个 LAMP 服务器，基本上是一个 Web 服务器，Apache2；一个内容管理器 PHP；和一个数据库管理器，MySQL 服务器。我们还将添加一些插件和配置，符合最佳实践标准。以下脚本仅适用于 Debian Linux 系列：

```
---
- name: Install a LAMP on Linux hosts
  hosts: webservers
  become: yes
  gather_facts: yes
  tasks:
    - name: Install Lamp packages
      apt: 
         name: '{{ item }}'
         state: latest
         update_cache: yes
      with_items:
         - apache2
         - mysql-server
         - php
         - libapache2-mod-php
         - python-mysqldb

    - name: Create the Apache2 web folder
      file: 
         dest: "/var/www"
         state: directory
         mode: 0700
         owner: "www-data"
         group: "www-data"   

    - name: Setup Apache2 modules
      command: a2enmod {{ item }} creates=/etc/apache2
      /mods-enabled/{{ item }}.load
      with_items:
         - deflate
         - expires
         - headers
         - macro
         - rewrite
         - ssl

    - name: Setup PHP modules
      apt: 
         name: '{{ item }}'
         state: latest
         update_cache: yes
      with_items:
         - php-ssh2
         - php-apcu
         - php-pear
         - php-curl
         - php-gd
         - php-imagick
         - php-mcrypt
         - php-mysql
         - php-json

    - name: Remove MySQL test database
      mysql_db:  db=test state=absent login_user=root 
      login_password="DBp@55w0rd"

    - name: Restart mysql server
      service: 
         name: mysql
         state: restarted

    - name: Restart Apache2
      service: 
         name: apache2
         state: restarted
```

通过修改一些配置文件并填充 Apache2 网页文件夹，可以个性化此操作手册。

# Windows 基础设施自动化

使用 Ansible 操作手册，自动化 Windows 基础设施和自动化 Linux 基础设施一样容易。在本节中，我们将探讨一些自动化一些 Windows 管理任务的用例。

这些用例在 Windows 10 上进行了测试。可能需要额外的配置才能在 Windows 7 或 8 上运行。

# 系统管理自动化

在本小节中，我们将重点关注与 Windows 系统管理相关的用例。

# 用例 1-系统更新自动化

这个用例解决了 Windows 主机系统和一些应用程序更新的自动化。我们将通过禁用自动更新并仅更新允许的类别，使更新受到操作手册的限制：

```
---
- name: Windows updates management
  hosts: windows
  gather_facts: yes
  tasks:
   - name: Create the registry path for Windows Updates
     win_regedit:
       path: HKLM:\SOFTWARE\Policies\Microsoft\Windows
      \WindowsUpdate\AU
       state: present
     ignore_errors: yes

   - name: Add register key to disable Windows AutoUpdate
     win_regedit:
       path: HKLM:\SOFTWARE\Policies\Microsoft\Windows
      \WindowsUpdate\AU
       name: NoAutoUpdate
       data: 1
       type: dword
     ignore_errors: yes

    - name: Make sure that the Windows update service is 
      running
      win_service:
        name: wuauserv
        start_mode: auto
        state: started
      ignore_errors: yes

    - name: Executing Windows Updates on selected 
      categories
      win_updates:
        category_names:
          - Connectors
          - SecurityUpdates
          - CriticalUpdates
          - UpdateRollups
          - DefinitionUpdates
          - FeaturePacks
          - Application
          - ServicePacks
          - Tools
          - Updates
          - Guidance
        state: installed
        reboot: yes
      become: yes
      become_method: runas
      become_user: SYSTEM
      ignore_errors: yes
      register: update_result

    - name: Restart Windows hosts in case of update 
      failure 
      win_reboot:
      when: update_result.failed
```

可以安排此操作手册在非工作时间或计划维护期间执行。重新启动模块用于处理需要系统重新启动的 Windows 更新，因为它们需要系统重新启动而无法通过更新模块完成。通常，大多数更新将触发`require_reboot`的返回值，该值在安装更新后启动机器的重新启动。

# 用例 2-自动化 Windows 优化

这个模块在某种程度上是对系统的清理和组织。它主要针对桌面 Windows 主机，但是一些任务也可以用于服务器。

此操作手册将首先展示如何远程启动已关闭的 Windows 主机。然后等待直到它正常开机以进行磁盘碎片整理。之后，我们执行一些注册表优化任务，并最后将主机加入域：

```
---
- name: Windows system configuration and optimisation
  hosts: windows
  gather_facts: yes
  vars:
     macaddress: "{{ 
     (ansible_interfaces|first).macaddress|default
     (mac|default('')) }}"
      tasks:
   - name: Send magic Wake-On-Lan packet to turn on    
     individual systems
     win_wakeonlan:
       mac: '{{ macaddress }}'
       broadcast: 192.168.11.255

   - name: Wait for the host to start it WinRM service
     wait_for_connection:
       timeout: 20

   - name: start a defragmentation of the C drive
     win_defrag:
       include_volumes: C
       freespace_consolidation: yes

   - name: Setup some registry optimization
     win_regedit:
       path: '{{ item.path }}'
       name: '{{ item.name }}'
       data: '{{ item.data|default(None) }}'
       type: '{{ item.type|default("dword") }}'
       state: '{{ item.state|default("present") }}'
     with_items:

    # Set primary keyboard layout to English (UK)
    - path: HKU:\.DEFAULT\Keyboard Layout\Preload
      name: '1'
      data: 00000809
      type: string

    # Show files extensions on Explorer
    - path: HKCU:\Software\Microsoft\Windows
      \CurrentVersion\Explorer\Advanced
      name: HideFileExt
      data: 0

    # Make files and folders search faster on the 
      explorer
    - path: HKCU:\Software\Microsoft\Windows
     \CurrentVersion\Explorer\Advanced
      name: Start_SearchFiles
      data: 1

  - name: Add Windows hosts to local domain
    win_domain_membership:
      hostname: '{{ inventory_hostname_short }}'
      dns_domain_name: lab.edu
      domain_ou_path: lab.edu
      domain_admin_user: 'admin'
      domain_admin_password: '@dm1nP@55'
      state: domain
```

# 应用程序和服务自动化

在本小节中，我们将重点关注与 Chocolatey 存储库上可用的 Windows 应用程序相关的用例，以及出于各种原因我们希望传统安装的其他应用程序。

# 用例 1-自动化 Windows 应用程序管理

由于 Windows 一直缺乏软件包管理器，因此在 Windows 机器上管理应用程序可能会有些混乱。Chocolatey 是可以帮助解决此问题的解决方案之一。以下操作手册代码确保安装了 Chocolatey 的所有要求，然后检查由 Chocolatey 安装的所有应用程序的更新。最后，它安装新应用程序的最新版本。

建议在桌面型 Windows 主机上使用此用例，而不是服务器。但是也可以在服务器上使用，因为大多数 Windows 服务器现在也有图形界面。

以下操作手册代码显示了如何执行前述操作：

```
---
- name: Application management on Windows hosts
  hosts: windows
  gather_facts: yes
  tasks:
   - name: Install latest updated PowerShell for 
    optimized Chocolatey commands
     win_chocolatey:
       name: powershell
       state: latest

   - name: Update Chocolatey to its latest version
     win_chocolatey:
       name: chocolatey
       state: latest

   - name: Install a list of applications via Chocolatey
     win_chocolatey:
       name: "{{ item }}"
       state: latest
     with_items:
         - javaruntime
         - flashplayeractivex
         - 7zip
         - firefox
         - googlechrome
         - atom
         - notepadplusplus
         - vlc
         - adblockplus-firefox
         - adblockplus-chrome
         - adobereader
      ignore_errors: yes
```

在 Chocolatey 软件包索引网页（[`chocolatey.org/packages`](https://chocolatey.org/packages)）上提供了更多应用程序的列表。

此操作手册可用于为经常使用一些特定应用程序的特定用户设置通用镜像。

# 用例 2-设置 NSclient Nagios 客户端

我们总是向特定环境引入新设备。设置新主机的一个必要任务是将其链接到监控系统。对于这个用例，我们将展示如何在 Windows 主机上设置 Nagios 代理并从示例配置文件中进行配置：

```
---
- name: Setup Nagios agent on Windows hosts
  hosts: windows
  gather_facts: yes
  tasks:
   - name: Copy the MSI file for the NSClient to the 
     windows host
     win_copy:
       src: ~/win_apps/NSCP-0.5.0.62-x64.msi
       dest: C:\NSCP-0.5.0.62-x64.msi

   - name: Install an NSClient with the appropriate 
     arguments
     win_msi:
       path: C:\NSCP-0.5.0.62-x64.msi
       extra_args: ADDLOCAL=FirewallConfig,LuaScript,DotNetPluginSupport,Documentation,CheckPlugins,NRPEPlugins,NSCPlugins,NSCAPlugin,PythonScript,ExtraClientPlugin,SampleScripts ALLOWED_HOSTS=127.0.0.1,192.168.10.10 CONF_NSCLIENT=1 CONF_NRPE=1 CONF_NSCA=1 CONF_CHECKS=1 CONF_NSCLIENT=1 CONF_SCHEDULER=1 CONF_CAN_CHANGE=1 MONITORING_TOOL=none NSCLIENT_PWD=”N@g10sP@55w0rd”
        wait: true

   - name: Copying NSClient personalised configuration 
     file
     win_copy:
       src: ~/win_apps/conf_files/nsclient.ini
       dest: C:\Program Files\NSClient++\nsclient.ini

   - name: Change execution policy to allow the NSClient script remote Nagios execution
     raw: Start-Process powershell -verb RunAs -ArgumentList 'Set-ExecutionPolicy RemoteSigned -Force'

   - name: Restart the NSclient service to apply the 
     configuration change
     win_service:
       name: nscp
       start_mode: auto
       state: restarted

   - name: Delete the MSI file
     win_file: path=C:\NSCP-0.5.0.62-x64.msi state=absent
```

此操作手册可应用于使用 MSI 文件安装的大量应用程序。

# 网络自动化

就像计算机一样，如果网络设备运行某种远程服务，最好是 SSH，Ansible 可以用来自动化网络设备的管理。在本节中，我们将探讨一些关于思科网络设备的用例。我们将研究一些手动操作时耗时的各种任务。

# 用例 1-网络设备的自动打补丁

我们将按照升级网络设备的推荐方法进行操作。我们需要确保备份运行和启动配置。然后，我们将使用串行选项逐个设备进行打补丁：

```
---
- name: Patch CISCO network devices 
  hosts: ciscoswitches
  remote_user: admin
  strategy: debug
  connection: ssh
  serial: 1
  gather_facts: yes
  tasks:
    - name: Backup the running-config and the startup-
      config to the local machine
      ntc_save_config:
         local_file: "images/{{ inventory_hostname 
         }}.cfg"
         platform: 'cisco_ios_ssh'
         username: admin
         password: "P@55w0rd"
         secret: "5ecretP@55"
         host: "{{ inventory_hostname }}"

    - name: Upload binary file to the CISCO devices
      ntc_file_copy:
         local_file: " images/ios.bin'"
         remote_file: 'cXXXX-adventerprisek9sna.bin'
         platform: 'cisco_ios_ssh'
         username: admin
         password: "P@55w0rd"
         secret: "5ecretP@55"
         host: "{{ inventory_hostname }}"

    - name: Reload CISCO device to apply new patch
      ios_command:
         commands:
           - "reload in 5\ny"
         platform: 'cisco_ios_ssh'
         username: admin
         password: "P@55w0rd"
         secret: "5ecretP@55"
         host: "{{ inventory_hostname }}"
```

您可以创建一个名为 `provider` 的事实变量，其中包含有关要用于运行命令的设备的所有凭据和信息。定义变量可以最小化可以放入 playbook 中的代码量。

# 用例 2 - 在网络设备中添加新配置

在这个用例中，我们将更改 Cisco 设备上的一些通用配置。我们将更改主机名，创建横幅，升级 SSH 到版本 2，更改 Cisco VTP 模式，并配置 DNS 服务器和 NTP 服务器：

```
---
- name: Patch CISCO network devices 
  hosts: ciscoswitches
  become: yes
  become_method: enable
  ansible_connection: network_cli
  ansible_ssh_pass=admin
  ansible_become_pass=”P@55w0rd”
  ansible_network_os=ios
  strategy: debug
  connection: ssh
  serial: 1
  gather_facts: yes
  tasks:
    - name: Update network device hostname to match the 
      one used in the inventory
      ios_config:
         authorize: yes
         lines: ['hostname {{ inventory_hostname }}'] 
         force: yes

    - name: Change the CISCO devices login banner
      ios_config:
         authorize: yes
         lines:
            - banner motd ^This device is controlled via 
             Ansible. Please refrain from doing any 
             manual modification^

    - name: upgrade SSh service to version2
      ios_config:
         authorize: yes
         lines:
            - ip ssh version 2

    - name: Configure VTP to use transparent mode
      ios_config:
         authorize: yes
         lines:
            - vtp mode transparent

    - name: Change DNS servers to point to the Google DNS
      ios_config:
         authorize: yes
         lines:
            - ip name-server 8.8.8.8
            - ip name-server 8.8.4.4

    - name: Configure some realisable NTP servers
      ios_config:
         authorize: yes
         lines:
            - ntp server time.nist.gov
            - ntp server 0.uk.pool.ntp.org
```

建议在停机时间或计划维护窗口期间使用这些 playbook。一个设备的配置可能出错，但对其他设备来说完全正常。Ansible 摘要始终具有详细的执行状态，可以跟踪有问题的设备和任务。

# 云和容器基础设施的自动化

这一部分与资源管理更相关，而不是主机本身。之前的任何用例都可以用于本地或云上的裸机或虚拟主机。

在云或虚拟环境中，远程唤醒模块的用处较小。更容易使用专用模块来管理虚拟主机和实例。

# VMware 自动化

在这一小节中，我们将看一些 VMware 环境中主机管理的用例，包括管理它们周围的基础设施。

# 用例 1 - 从模板创建虚拟机

这个用例展示了如何从预定义模板创建虚拟机。之后，我们确保所有虚拟机都已根据正确的参数添加到清单中：

```
---
- name: Create a virtual machine from a template
  hosts: localhost
  gather_facts: False
  tasks:
    - name: Create a virtual machine
       vmware_guest:
          hostname: 'vcenter.edu.lab'
          username: 'vmadmin@lab.edu'
          password: 'VMp@55w0rd'
          datecenter: 'vcenter.edu.lab'
          validate_certs: no
          esxi_hostname: 'esxi1.lab.edu'
          template: ubuntu1404Temp
          folder: '/DeployedVMs'
          name: '{{ item.hostname }}'
          state: poweredon
          disk:
            - size_gb: 50
               type: thin
               datastore: 'datastore1'
          networks:
            - name: 'LabNetwork'
                ip: '{{ item.ip }}'
                netmask: '255.255.255.0'
                gateway: '192.168.13.1'
                dns_servers:
                  - '8.8.8.8'
                  - '8.8.4.4'
          hardware:
              memory_mb: '1024'
              num_cpus: '2'
          wait_for_ip_address: yes
        delegate_to: localhost
        with_items:
            - { hostname: vm1, ip: 192.168.13.10 }
            - { hostname: vm2, ip: 192.168.13.11 }
            - { hostname: vm3, ip: 192.168.13.12 }

    - name: add newly created VMs to the Ansible 
      inventory
       add_host:
          hostname: "{{ item.hostname }}"
          ansible_host: "{{ item.ip }}"
          ansible_ssh_user: setup
          ansible_ssh_pass: "L1nuxP@55w0rd"
          ansible_connection: ssh
          groupname: Linux
       with_items:
            - { hostname: vm1, ip: 192.168.13.10 }
            - { hostname: vm2, ip: 192.168.13.11 }
            - { hostname: vm3, ip: 192.168.13.12 }
```

此 playbook 中的项目可以通过使用预定义变量进行更改。

# 用例 2 - ESXi 主机和集群管理

我们现在将尝试进行一些更高级的基础设施管理。我们将尝试创建一个 VMware 集群并将一个 ESXi 主机添加到其中：

```
---
- name: Create a VMware cluster and populate it
  hosts: localhost
  gather_facts: False
  tasks:
    - name: Create a VMware virtual cluster
      vmware_cluster:
          hostname: 'vcenter.edu.lab'
          username: 'vmadmin@lab.edu'
          password: 'VMp@55w0rd'
          datecenter: 'vcenter.edu.lab'
          validate_certs: no
          cluster_name: "LabCluster"
          state: present
          enable_ha: yes 
          enable_drs: yes
          enable_vsan: no 

    - name: Add a VMware ESXi host to the newly created 
      Cluster
      vmware_host:
          hostname: 'vcenter.edu.lab'
          username: 'vmadmin@lab.edu'
          password: 'VMp@55w0rd'
          datecenter: 'vcenter.edu.lab'
          validate_certs: no
          cluster_name: " LabCluster "
          esxi_hostname: "esxi1.lab.edu"
          esxi_username: "root"
          esxi_password: "E5X1P@55w0rd"
          state: present
```

这些 playbook 可以替代用于管理 VCenter 的 PowerCLI 命令，也可以替代手动访问 Windows 客户端或 Web 界面来管理主机和集群的过程。

# 总结

在本章中，我们涵盖了许多有趣的用例，任何系统管理员在某个时候都需要运行。许多其他任务也可以执行，就像我们使用自定义 playbook 一样。但并非每个脚本都被认为是良好的自动化；重要的是正确的节点在较短的时间内从状态 A 转换到状态 B，没有错误。在 第六章 *Ansible 配置管理编码* 中，我们将学习一些基于最佳实践的高级脚本优化技术，以便充分利用 Ansible 自动化。

# 参考

Ansible 文档：[`docs.ansible.com/ansible/latest/`](https://docs.ansible.com/ansible/latest/)

Ansible GitHub 项目：[`github.com/ansible`](https://github.com/ansible)

Chocolatey 软件包索引：[`chocolatey.org/packages`](https://chocolatey.org/packages)


# 第六章：Ansible 配置管理的编码

学习 Ansible 编码的主要方法是编写自己的 Ansible playbook，无论是为了乐趣还是解决自己的基础设施挑战。然而，在某个时候，事情可能开始变得复杂。您的代码可能有效，但是如何知道它是否真的以正确的方式执行任务？它是否有效？它将有多可扩展？使用有意义的名称使您更容易理解您的代码。还可能出现与脚本组织有关的问题：即使它们彼此无关，也很容易出现一个文件夹中充满了几个脚本的情况。

在本章中，我们将讨论编写 Ansible playbook 的标准和最佳实践。我们的目标是通过加快任务、提高安全性、为内置基础设施冗余系统提供住宿、优化任务以及减少代码重复来改进我们的 playbook，以生成具有相同功能的更小的 playbook。最后，我们将介绍 Ansible 角色，这是 Ansible 中的终极任务优化工具。

本章将涵盖以下主题：

+   编写 Ansible playbook 的标准

+   编写 YAML playbook 的最佳实践

+   优化 Ansible 任务和 playbook

+   Ansible 角色

+   使用 Ansible 角色的示例

# Ansible 配置管理编码标准

在本节中，我们将列出几条规则和方法，以帮助编写符合 Ansible 规范的漂亮和干净的 playbook。这不是严格的指令，而是 Ansible 开发人员和维护人员认为应该使用的表示。遵循这些规范不仅可以更轻松地使用 playbook，还可以帮助使其标准化，并且可以被社区成员理解，从而实现更好的团队协作。

这些标准基于 Ansible 用户和维护者的经验。任何个人用户可能以需要不同的规则使用 Ansible。

# Playbook 和任务命名

制作 playbook 时，使用`name:`字段是可选的。如果您编写一个没有名称的 playbook，它将完全正常工作。以下是一个没有名称的 playbook 的示例：

```
---
- hosts: servers
  become: yes
  gather_facts: false
  tasks:
    - apt: update_cache=yes
    - apt:
       name: mc
    - file:
       path: /usr/local/projects
       mode: 1777
       state: directory
```

这个 playbook 可能有以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/e3e7ca33-b2dc-4a90-9d71-d8f5cf229152.png)

playbook 已经按我们的要求执行了，但是如果我们在一个 playbook 中有很多任务，它没有名称可能会带来问题，因为我们将无法轻松监视每个作业的状态。遵循 Ansible 的标准，编写一个对其每个任务有更好描述的 playbook 可以帮助很多。具有清晰任务描述的好处有助于个人或团队任务监控，为同事和社区用户提供更好的管道解释。一个更具描述性的 playbook 示例可能如下所示：

```
---
- name: Setup users projects workspace with a file manager
  hosts: servers
  become: yes
  gather_facts: false
  tasks:
    - name: Update Package manager repo index
      apt: update_cache=yes
    - name: Install Midnight commander as a terminal file manager
      apt:
       name: mc
    - name: Create the projects workspace folder with sticky bit
      file:
       path: /usr/local/projects
       mode: 1777
       state: directory
```

这样，我们可以得到更具描述性的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-qk-st-gd/img/e354fd3c-8cbc-4e76-a9c1-9d1ea4e1f642.png)

由您决定要编写什么以及任务的哪些方面被描述，只要对用户（包括您自己、您的团队或社区）有意义。我们建议使用简单的措辞来简要解释任务。

# 用于 playbook 的 YAML 语法使用

由于 playbook 是用 YAML 编写的，因此在引入任务参数时，您对代码的外观有一些余地。同样，尽管 Ansible 将接受代码并执行任务，但很容易出现代码行过长的情况，即使是一个平均复杂的任务。这是一个单行 Ansible 任务的样子：

```
- name: Copy user configuration
copy: src=/home/admin/setup.conf dest=/usr/local/projects/ owner=setup group=dev mode=0677 backup=yes
```

与此相反，我们可以遵循一个整洁和更有组织的 YAML 结构，通过在每个任务参数前添加空格。Playbook 应该如下所示：

```
 - name: Copy user configuration
copy: 
src: /home/admin/setup.conf
dest: /usr/local/projects/
owner: setup
group: dev
mode: 0677
backup: yes
```

然而，一些任务或命令可能有很长的字符串，无论是文件的绝对路径还是用于任务的长文本。Ansible 确实提供了一种使用`>`字符来组织具有长字符串的任务的方法，以便将单行字符串写成多行而不带回车。

```
   - name: Fill in sample text file
     lineinfile:
       path: /usr/local/projects/setup.conf
       line: >
            This is the configuration file for the user
            Setup. Please do not edit make any change 
            to it if you are not and administrator.
```

Ansible 提供了一个选项来检查 playbook 的语法，以查看它是否符合 YAML 语法。要使用这个选项，将`--syntax-check`选项添加到 Ansible 命令中。

# become 功能

许多任务需要由特定用户执行，无论是访问受限资源还是启用特定用户服务。虽然有一些 Shell 或 Powershell 命令可以实现这一点，但它们可能会产生非常长和复杂的命令。Ansible 的`become`或`become_user`功能允许更容易为每个特定用户定制的任务。这个功能被认为是 Ansible 配置管理编码的标准，因为它提供了简化复杂命令的任务优化水平，使这个功能不仅仅是 playbook 个性化，还是任务特定的。以下是使用此功能的 playbook 示例：

```
---
- name: Organize users projects folders
  hosts: servers
  become: yes
  remote_user: setup
  gather_facts: false
  tasks:
    - name: create folder for user1
      command: mkdir /usr/local/projects/user1
       become_user: user1

   - name: Create test space for setup
      file:
       path: /usr/local/projects/setup/test
       mode: 1777
       state: directory
---
```

# 组织

主机组织使得可以根据角色、地理位置或数据中心位置将主机组织成组。在父子结构中，可以设置父组变量并使子组继承它们。要覆盖父组变量，个别主机或子组可以有自己的独特自定义变量。这种做法更多的是 Ansible 库存管理功能，而不是 playbook 编码，但对于多架构配置管理非常重要。

如前几章所述，主机变量可以在库存文件或 playbook 本身中定义。但是，当组织在库存文件中作为`group_vars`和`hosts_vars`时，更容易管理。

以下是一个库存文件的示例，展示了如何定义父组和子组变量：

```
/etc/ansible/hosts:
[linuxservers:children]
webservers
loadbalancers

[linuxservers:vars]
remote_user: setup
ntpserver: 0.uk.pool.ntp.org
become: yes

[webservers]
node0
node1
node2

[webservers:vars]
remote_user: devadmin
ansible_connection: ssh

[loadbalancers]
node3
node4

[loadbalancers:vars]
ntpserver: 0.us.pool.ntp.org
ansible_connection: docker
```

这不是唯一可以用来定义组的结构。库存文件只能保存组的结构，然后每个组可以有自己的库存文件来保存它们的变量。相同的规则适用于子变量覆盖父变量。

# 使用处理程序

Ansible 建议使用处理程序进行任务流水线处理，因为处理程序是在被通知时执行的编程任务。处理程序将为报告更改状态的任务触发。它们通常用于在配置更改后进行服务管理。这确保了流畅的配置管理，因为每当主机发生变化时，涉及的服务都应该重新启动以应用更改。

Ansible 还具有一项功能，可以在 playbook 中启用处理程序的大规模刷新。这个功能允许您通过控制任务中所有处理程序的执行来控制何时可以应用更改。使用`meta`，任务处理程序可以从 playbook 中的任何位置刷新：

```
---
- name: Change service settings and apply it
  hosts: servers
  become: yes
  remote_user: setup
  gather_facts: false
  tasks:
    - name: Flush the playbook handlers
      meta: flush_handlers

    - name: Change ntp service config
      lineinfile:
       path: /etc/ntp.conf
       line: "server 0.us.pool.ntp.org"

    - name: Flush the playbook handlers
      meta: flush_handlers

  handlers:
    - name: restart ntp service
      service:
       name: ntp
       state: restarted
```

# playbook 中的密码使用

许多任务需要您输入密码来访问数据库或使用 CLI 或访问第三方终端。在 playbook 上公开写入密码或其他敏感信息是不可取的。有多种方法可以保护这些信息。最常见的两个例子是将它们存储在另一个受保护的 playbook 中，或者使用 Ansible Vault。

在本节中，我们将主要介绍将密码和敏感变量存储在其他更受保护的文件中。Ansible Vault 将在后面的章节中进行全面介绍。

这个想法是创建一个包含多个敏感变量的 playbook，并将其存储在受限制的权限下的安全位置。然后，playbook 在 play 级别（任务所在的位置）使用`include`选项调用其变量：

```
---
- name: usage of sensative variable
  hosts: servers
  include: passwords_playbook.yml
  tasks:
    - name: add a MySQL user
      mysql_user:
        name: user1
        password: {{ mysql_user1_password }}
        priv: '*.*:ALL'
        state: present 
```

```

This method is very easy to use and manage, but it is not the best in terms of security. Ansible Vault will provide better protection for sensitive information in playbooks.

Ansible Vault is not the only tool that allows you to secure variables in Ansible. There are other third-party tools that allow you to secure passwords and critical information by preventing them from being typed as clear text.

# Playbook version control

It is highly recommended to use a version control service, such as GitHub, SubVersion, or Mercurial, to manage your Ansible playbooks. Besides the countless benefits of using version control for any coding, Ansible playbooks can use GitHub projects as an input to enable frameworks that allow continuous deployment and integration. By updating your code in the repository, it gets updated on all the systems it is used in.

# Making Ansible roles where possible

The best way to optimize a task is to make it an Ansible role, or preferably multiple roles if it has multiple goals. A task that has been transformed into a role is ready to be used with multiple situations, and it can be shared to be used by other users. Roles can be included in multiple playbooks to avoid writing the same lines of code twice or more. Ansible has a role-sharing platform called Galaxy, where the community shares their roles with other users. We will cover this in more detail in the next chapter.

# Ansible coding best practices

After exploring the standards that should be followed by Ansible developers, let's now have a look at what Ansible daily users recommend as best practice for good configuration management using Ansible.

These methods may suit some setups more than others. Not every method is a good option for your environment; they may cause more trouble than benefits if they are applied inappropriately. We have collected the methods that we believe are common and useful most of the time.

# Using comments in playbooks

Earlier in this chapter, we discussed naming plays or tasks in the playbook to provide a better description for the reader. However, when performing unusual tasks or running commands that form part of a bigger picture, having a descriptive name is not always enough information.

You can use comments either at the start of each playbook, explaining its overall role, or in the pipelines included within the playbook. You can also offer some information about the author, including contact details when the playbook gets shared within the community. Having comments in the code you write is a good idea for any coding you do, especially if you are planning to share it. It makes any script user-friendly. Even though YAML is an easy coding language, it is not always obvious when reading the work of others. This example playbook shows a way to get more detailed information about a playbook:

```

---

####################################

#

# 这个 playbook 的目标是在管道中实现多个任务

# 配置多个 Linux 主机进行协作项目。它首先

# 设置所需的工具和服务，然后将它们配置为

# 标准，然后准备共享空间，并分配用户和组。

#

# 作者: ***** ***** 电子邮件: *********@****

#

####################################

- 名称: 主机配置 playbook

主机: linuxservers

成为: 是的

remote_user: setup

gather_facts: false

任务:

- 名称: 安装午夜指挥官

# 这是一个基于终端的文件管理器，不需要 GUI 界面

apt:

名称: mc

…

```

# Playbook files and folder naming

This is a best practice that should be followed in life, not just for scripting and playbooks! Whenever you create a file in your computer, on the cloud, or within an application, always make sure to give it a name that reveals what it is. You can also organize your files into subfolders with descriptive names. Although it might take longer for a user to navigate through the folders to get to the playbook, everything will be well explained and clear.

# Avoiding the use of command modules

Ansible offers a few modules that allow you to run commands to be executed as they are in the remote hosts. This is handy when the Ansible modules do not cover the task that is intended to be performed, which is especially the case when there are complex tasks.

The issue with command modules is that they do not know whether the task has been properly executed since they can execute any command running any tool, service, and system. The return values for a command can easily be misunderstood and sometimes do not reflect what really happened after the command execution. It is recommended that you use the `changed_when` option in the task in the playbook, so it looks as follows:

```

- 名称: 执行 Windows 写过滤器启用命令并确定是否进行了更改

win_shell: ewfm.exe -conf enable

register: output

changed_when: "output.stdout == '等待下次启动应用更改。'"

```

There are multiple methods for collecting command changes; this is one of the ones that was most recommended in the community. File and service status modules can be used to check changes in the data via tasks or handlers, but these may cause extra tasks to be sent to the remote hosts.

# Avoiding ignoring module errors

Ansible offers the option of ignoring some task errors when they are reported. This is because Ansible by default halts a playbook if one of its tasks has failed. Sometimes, if a task is used to execute an optional job or to test a particular aspect of the system, the task isn't important enough to cause the entire playbook to halt. We tend to add the `ignore_errors: yes` option at the end of these tasks, but this is a very bad habit that may cause damage to your hosts, especially in pipelined tasks.

The best way to deal with optional tasks or those that return an error even when they have executed what is needed is to use the `failed_when` and `changed_when` options to define when a task has failed or performed its job.

# Using Ansible conditions

We can use the information collected by Ansible about the hosts it manages to personalize tasks to a specific system using Ansible conditions. Not all modules work with every OS. To make a playbook universal, we can add in some settings where some tasks test the facts of the remote host before executing the task. This also helps with reducing the number of playbook scripts by creating scripts that adapt themselves to the system that they are being executed on. As an example, let's try to install the same package with two different names in Debian and Red Hat Linux OS:

```

---- 名称: 在 Linux 主机上安装 python 开发包

主机: linuxservers

成为: 是的

remote_user: setup

gather_facts: true

任务:

- 名称: 在 Debian 系统上安装 python 开发

apt:

名称: python-dev

当: ansible_os_family == "Debian"

- 名称: 在 Red Hat 系统上安装 python 开发

yum:

名称: python-devel

当: ansible_os_family == "RedHat"

```

# Using Ansible loops

Ansible loops offer several possibilities. One of the most common uses is to reduce the amount of code when running the same module multiple times on different inputs. The idea is to define a variable or an object variable that has its own variables, then populate the list with the different entries.

The following playbook shows a good use of Ansible loops to copy several configuration files with different sources, destinations, and ACL settings:

```

---

- 名称: 将用户配置文件复制到其项目目录

主机: linuxservers

成为: 是的

remote_user: setup

gather_facts: true

任务:

- 名称: 复制用户配置文件

复制:

src: '{{ item.src }}'

dest: '{{ item.dest }}'

模式: '{{ item.mode | default("0744") }}'

owner: '{{ item.owner | default("nobody") }}'

when_items:

- { src: "/media/share/config/user1.conf",

dest: "/usr/local/projetsfolder/user1",

模式: "0774", owner: "user1" }}

- { src: "/media/share/config/user2.conf",

dest: "/usr/local/projetsfolder/user2",

模式: "0700", owner: "user2" }}

- { src: "/media/share/samples/users.conf",

dest: "/usr/local/projetsfolder/", mode: "0777" }}

```

The default option takes cares of empty entries by replacing them with what has been entered as the default value.

# Using template files

It is recommended that you use modules that edit configuration files, such as `lineinfile` or `blockinfile`. These can help significantly with setting up standard configurations or updating old settings. However, when these files are automated, they cannot handle the small changes that can be identified easily when modifying manually, leading to unpredictable changes. There is no simple way of telling whether a configuration change will go as expected, especially for a large infrastructure. For this reason, it is recommended to use template files to act as base configuration files, scripts, or web pages. Still, we can use `lineinfile` or `blockinfile` as a backup plan. In these, the user knows exactly what to set up, what to edit, and what to leave for each host. This method helps to control the unpredictability of tasks.

Using the `template` module, we can generate configuration files that are specific to the hosts from a `Jinja` file. The example `.j2` template file gets filled in with predefined variables, as follows:

```

db.conf.j2:

mysql_db_hosts = '{{ db_serv_hostname }}'

mysql_db_name = '{{ db_name }}'

mysql_db_user = '{{ db_username }}'

mysql_db_pass = '{{ db_password }}'

```

These variables can then be defined in the same playbook or another YAML file, included at the play level:

```

---

- 名称: 复制数据库配置文件

主机: linux    servers

成为: 是的

remote_user: setup

gather_facts: true

任务:

- 名称: 从另一个 YAML 导入变量

include_vars: /home/admin/variables/database2.yml

- 名称: 复制 db 配置文件

模板:

src: /home/admin/template/db.conf.j2

dest: /etc/mysql/db.conf

owner: bin

组: wheel

模式: 0600

```

The `Jinja2` files offer a level of control over the variable structure. You can introduce loops and conditional statements with some predefined functions to alter the input to match the structure of the configuration file input.

# Stating task status

When creating files, setting up configuration, or managing services, an Ansible user should always state the status of the object of the task, even when the change is aimed at its default value. Even though this will add an extra line to most of your tasks, it is a good habit to have. It is one of those practices that some people think is useless, but for debugging purposes, or for anyone reading your script, seeing the status of each task provides a better view of what each task has done. Naming the task indicates what you want it to do, but it does not necessarily mean that the task has done that action. Using the `state` option, however, gives a much clearer indication in this respect:

```

任务:

- 名称: 创建一个新文件

文件:

路径: /usr/local/projects/vars.txt

状态: 现有

- 名称: 从文件中删除行

lineinfile:

路径: /usr/local/projects/conf.txt

行: "adminuser = user0"

状态: 不存在

```

# Shared storage space for data tasks

The Ansible management server is doing a lot more in the background than simply sending tasks and managing remote machines. Adding the extra task of managing file transfers and running them on its interface may cause a considerable performance degradation. We always recommend using shared storage space either on an FTP server, an NFS or Samba filesystem, or on a web server to be downloaded by the remote hosts. This practice ensures that the remote hosts carry out the transfer with another dedicated and optimized server.

It is always a good practice to have all tools archived and their sample configuration files stored in a network file system. Remote hosts can easily access the drives either temporarily for a data transfer or permanently if they are in constant need.

The following playbook task shows an example of the code for this use:

```

任务:

- 名称: 将工具存档复制到远程主机

复制:

src: /media/nfshsare/Tools/tool1.tar.gz

dest: /usr/local/tools/

模式: 0755

```

# Ansible roles

This is the section in which we discover Ansible roles and what we can do with them to optimize our automation scripting.

# What are Ansible roles?

The ultimate configuration management scripts optimization is to convert simple playbooks into Ansible roles. This gives you the ability to make a set of configuration management tasks modular and reusable, with multiple configurations. It also means that they can be easily shared when required. Ansible roles allow several related tasks, with their variables and dependencies, to be contained in a portable framework. This framework represents the breakdown of a complex playbook into multiple simple files.

An Ansible role is composed of multiple folders, each of which contain several YAML files. By default, they have a `main.yml` file, but they can have more than one when needed. This is a standardized structure for all Ansible roles, which allows Ansible playbooks to automatically load predefined variables, tasks, handlers, templates, and default values located in separate YAML files. Each Ansible role should contain at least one of the following directories, if not all of them.

# The tasks folder

This is the controller folder. It contains the main YAML files. The code within those files executes the main role tasks by calling all the other defined elements of the role. Usually, it has the `main.yml` file with some YAML files that are OS-specific that ensure certain tasks are executed when the role is run on specific systems. It may also contain other tasks to set up, configure, or ensure the existence of certain tools, services, configuration folders, or packages that failed a test run by the main script and triggered the execution of a task to fix them. The following is a sample task code written on the `main.yml` file in the `tasks` folder:

```

任务/main.yml:

---

- 名称: 检查 NTP 是否已安装

stat:

路径: /etc/init.d/ntpd

register: tool_status

- 包括任务: debian.yml

当: tool_status.stat.exists

- 名称: 将 NTP 配置复制到远程主机

模板:

src: /template/ntp.conf.j2

dest: /etc/ntpd/ntpd.conf

模式: 0400

通知:

- 重新启动 ntp

tasks/debian.yml:

---

- 名称: 将 NTP 配置复制到远程主机

apt:

名称: ntp

状态: 最新

```

# The handlers folder

This folder usually contains the main file with multiple handler tasks that are waiting to be triggered by other tasks, either with the role or from other playbooks or roles. It is mainly used for service management to apply a configuration change performed by another task. Here is an example of a handler script:

```

handlers/main.yml:

---

- 名称: 重新启动 ntp

服务:

名称: ntp

状态: 重新启动

```

# The vars folder

This is where the role variables get stored. Usually, it is used for a permanent variable that does not require any changes between environments. Here is an example of a variables file:

```

vars/main.yml:

---

ntpserv1: 0.uk.pool.ntp.org

ntpserv2: 1.uk.pool.ntp.org

```

# The templates folder

This folder contains the template files used by the role to create the actual configuration files. These are then deployed by the role to the remote hosts. They are `Jinja2` template engine scripts that enable loops and other features. Here is an example of a template file:

```

template/ntp.conf.j2:

driftfile /var/lib/ntp/ntp.drift

filegen loopstats file loopstats type day enable

filegen peerstats file peerstats type day enable

filegen clockstats file clockstats type day enable

循环{{ ntpserv1 }}

循环{{ ntpserv2 }}

池 ntp.ubuntu.com

限制-4 默认 kod notrap nomodify nopeer noquery limited

限制-6 默认 kod notrap nomodify nopeer noquery limited

限制 127.0.0.1

限制::1

限制源 notrap nomodify noquery

```

# The defaults folder

This folder contains the default values for the non-defined variables in the role when they are used. It is a way of organizing variable inputs in the role and is one of the highly recommended options when writing a playbook. It allows for a centralized management of the default values of the variable of the role. Default values are always vulnerable because they change a lot depending on the needs and policies of the user. Having this solution allows one file to change all the values. Here is an example of a `defaults` folder:

```

```
defaults/main.yml:
---
timout: 2000
ID_key: "None"
```

```

# The files folder

This folder holds all extra files that are required to achieve the role task. These files usually get dispatched to remote hosts as part of certain tasks. They are usually static, and they do not contain any variables to change, be copied, extracted, or compressed to the remote host.

# The meta folder

This folder contains machine-readable information about the role. These folders contain the role metadata, which includes information about authors, licenses, compatibilities, and dependencies. The main use for this option is to declare dependencies, more specifically, roles. If the current role relies on another role, that gets declared in a `meta` folder. The following example shows how `meta` folders are used:

```

```
meta/main.yml:
---
galaxy_info:
  author: medalibi
  description: NTP client installn
  company: Packt
  license: license (GPLv3, BSD)
  min_ansible_version: 2.4
  platforms:
    - name: Ubuntu
      version:
        - 16.04
        - 18.04
  galaxy_tags:
    - networking
    - system

dependencies: []
```

```

# The test folder

This folder contains a test environment with an inventory file and a playbook script to test the role. It is usually used by the developers to test any new changes that have happened to the role. It also serves as a sample configuration for new users to follow the running of the role. The playbook script within the `test` folder looks as follows:

```

```
tests/test.yml:
---
- hosts: servers
  remote_user: setup
  become: yes
  roles:
    - ntpclient.lab.edu
```

```

# The README folder/file

This is a folder that can be replaced by a simple markdown `README.md` file. It is an optional feature but it is highly recommended when you are planning to share your roles. It acts as a documentation for the role: it can contain anything that might be useful for first-time users of the role from a simple description of the task delivered by the role, to instructions and requirements to set up this role on their environment. It might also contain some best practices and information about the author and contributors if it is built by a team.

Ansible roles are used for replacing the same function that the option `include` carry out when adding extra parameters and functions to a playbook. Roles are much more organized and allow easier sharing, either on a personal GitHub project or on the Ansible Galaxy. This will be our subject for the next chapter.Make sure to use descriptive names for your roles. Like playbooks, this helps the users of your role to have an idea of what your role should do. Your description should be brief, usually just one or two words. You can always add more detail and description in the `README` file.

Roles tend to be very specific: they do one job and one job only. It is not advisable to have tasks within a role that have nothing to do with the job. Let's create some example Ansible roles that deliver a few jobs to use as template roles that follow all best practices.

# Creating Ansible roles

Let's now create an Ansible role from scratch. This role is a Samba file server setup on either of the big families of Linux. It serves a folder that is accessible via a shared user.

First, let's create our role folder using the `ansible-galaxy` command line. Before running the command, we need to change the Terminal workspace to the location in which we would like to store our Ansible roles:

```

cd ~/Roles/

ansible-galaxy init samba.lab.edu

```

We should see the following output:

```

- 成功创建 samba.lab.edu

```

We then create a folder with the name of the role, with the following structure of subfolders and files:

```

samba.lab.edu

└── README.md

├── 默认值

│ └── main.yml

├── 文件

│

├── 处理程序

│ └── main.yml

├── 元

│ └── main.yml

├── 任务

│ └── main.yml

├── 模板

│

├── 测试

│ ├── 库存

│ └── test.yml

└── 变量

└── main.yml

```

Let's now populate our folder and files with the appropriate code for the role. First, we are going to populate the dependencies and requirements for the role to work. For this, we will be working on the `meta`, `template`, `files`, `vars`, and `defaults` folders, and the OS-specific scripts in the `tasks` folder.

We will start by populating the `template` folder with a `Jinga2` template file for the configuration of the SMB service:

```

template/smb.conf.j2:

#========= 全局设置 =========

# Samba 服务器配置:

[全局]

工作组 = {{ wrk_grp | upper }} ## upper convert any input to uppercase.

服务器字符串 = Samba 服务器%v

netbios 名称 = {{ os_name }}

安全 = 用户

映射到访客=坏用户

dns 代理 = 否

#=========共享定义=========

# Samba 共享文件夹:

[{{ smb_share_name }}]

路径 = {{ smb_share_path }}

有效用户 = @{{ smb_grp }}

访客 ok = 否

只读 = 否

可浏览 = 是

可写 = 是

强制用户 = 无

创建掩码 = {{ add_mod }}

目录掩码 = {{ dir_mod }}

```

We are then going to put a text file in the `files` folder that contains the rules and policies of using the shared folder:

```

文件/Fileserver_rules.txt:

此共享驱动器供指定团队使用。

任何分散的使用都将导致事件的后续跟进。

请不要更改任何团队成员的文件夹或删除任何未分配给您管理的内容。

如有任何疑问，请联系 admin@edu.lab

```

After that, we edit the main file in the `meta` folder with some role information: author, description, support, and tags. This will look as follows:

```

meta/main.yml

---

依赖关系: []

galaxy_info:

作者: medalibi

描述: "Linux OS（Debian/Red Hat）上的 Samba 服务器设置和配置"

许可证: "许可证（GPLv3，BSD）"

min_ansible_version: 2.5

平台:

- 名称: Debian

版本:

- 8

- 9

- 名称: Ubuntu

版本:

- 14.04

- 16.04

- 18.04

- 名称: EL

版本:

- 6

- 7

galaxy_tags:

- 系统

- 网络

- 文件服务器

- 窗户

```

Once this is done, we move on to defining the role variables. For this role, we are going to have all the variables stored in one file, including the OS-specific variable:

```

vars/main.yml

---

debian_smb_pkgs:

- samba

- samba-client

- samba-common

- python-glade2

- system-config-samba

redhat_smb_pkgs:

- 桑巴

- samba-client

- samba-common

- cifs-utils

smb_selinux_pkg:

- libsemanage-python

smb_selinux_bln:

- samba_enable_home_dirs

- samba_export_all_rw

samba_config_path: /etc/samba/smb.conf

debian_smb_services:

- smbd

- nmbd

redhat_smb_services:

- smb

- nmb

```

To set our default values, we fill in the `defaults` main folder with the following file:

```

defaults/main.yml:

---

wrk_grp: 工作组

os_name: debian

smb_share_name: 共享工作空间

smb_share_path: /usr/local/share

add_mod: 0700

dir_mod: 0700

smb_grp: smbgrp

smb_user: 'shareduser1'

smb_pass: '5h@redP@55w0rd'

```

We now create the OS-specific tasks for setting up the service:

```

tasks/Debian_OS.yml:

---

- 名称: 在 Debian 家族 Linux 上安装 Samba 软件包

apt:

名称: "{{ item }}"

状态: 最新

update_cache: 是

with_items: "{{ debian_smb_pkgs }}"

tasks/RedHat_OS.yml:

---

- 名称: 在 Red Hat 家族 Linux 上安装 Samba 软件包

yum:

名称: "{{ item }}"

状态: 最新

update_cache: 是

with_items: "{{ redhat_smb_pkgs }}"

- 名称: 为 Red Hat 安装 SELinux 软件包

yum:

名称: "{{ item }}"

状态: 现有

with_items: "{{ smb_selinux_pkg }}"

- 名称: 配置 Red Hat SELinux 布尔值

seboolean:

名称: "{{ item }}"

状态: 真

persistent: true

with_items: "{{ smb_selinux_bln }}"

```

Let's now finish by adding the main task and the handlers for it:

```

tasks/main.yml:

---

- 名称: 根据主机操作系统设置 Samba

include_tasks: "{{ ansible_os_family }}_OS.yml"

- 名称: 创建 Samba 共享访问组

组:

名称: "{{ smb_grp }}"

状态: 现有

- 名称: 创建 Samba 访问用户

用户:

名称: "{{ smb_user }}"

组: "{{ smb_grp }}"

追加: 是

- 名称: 在 Samba 中定义用户密码

shell: "(echo {{ smb_pass }}; echo {{ smb_pass }}) |

smbpasswd -s -a {{ smb_user }}"

- 名称: 检查共享目录是否存在

stat:

路径: "{{ smb_share_path }}"

register: share_dir

- 名称: 确保共享目录存在

文件:

状态: 目录

路径: "{{ smb_share_path }}"

所有者: "{{ smb_user }}"

组: "{{ smb_grp }}"

模式: '0777'

递归: 是

当: share_dir.stat.exists == False

- 名称: 部署 Samba 配置文件

模板:

dest: "{{ samba_config_path }}"

src: smb.conf.j2

validate: 'testparm -s %s'

备份: 是

通知:

- 重新启动 Samba

- 名称: 在 Debian 家族上启用和启动 Samba 服务

服务:

名称: "{{ item }}"

状态: 已启动

已启用: 是

with_items: "{{ debian_smb_services }}"

当: ansible_os_family == 'Debian'

- 名称: 在 RedHat 家族上启用和启动 Samba 服务

服务:

名称: "{{ item }}"

状态: 已启动

已启用: 是

with_items: "{{ redhat_smb_services }}"

when: ansible_os_family == 'RedHat'

```

We finish by defining the handlers for service management:

```

/handlers/main.yml:

---

- 名称: 重新启动 Samba

服务:

名称: "{{ item }}"

状态: 重新启动

with_items: "{{ debian_smb_services }}"

当: ansible_os_family == 'Debian'

- 重新启动 Samba

服务:

名称: "{{ item }}"

状态: 重新启动

with_items: "{{ redhat_smb_services }}"  when: ansible_os_family == 'RedHat'

```

# Using Ansible roles

For this section, we are going to use the `test` folder to test the new role. First, we need to set up the inventory to match our test environment:

```

tests/inventory：

[linuxserver]

节点 0

节点 1

节点 2

```

Then, we edit the `test.yml` file for the test:

```

tests/test,yml：

- 主机：linuxserver

远程用户：设置

变得：是

角色:

- samba.lab.edu

```

When executing the `test.yml` playbook, we need to add to the `ansible-playbook` command line the `-i` option and specify the `tests/inventory` inventory file we filled earlier. The command line should look like the following:

```

ansible-playbook tests/test.yml -i tests/inventory

```

`README.md`文件可以包含有关角色变量的一些信息，以帮助用户将其个性化到自己的设置中。在构建大量角色时，测试它们的最佳方法是使用具有不同基本系统的容器。

# 摘要

在本章中，我们列出了在使用 Ansible 和其他自动化工具时优化配置管理编码的几种方便的技术。我们介绍了 Ansible 角色，包括如何制作它们以及如何使用它们。在第七章 *Ansible Galaxy 和社区角色*中，我们将探讨 Ansible Galaxy 上的社区角色。我们将下载并使用评分最高的角色，并展示如何在 Ansible Galaxy 上添加一个角色。

# 参考资料

Ansible 文档：[`docs.ansible.com/ansible/latest`](https://docs.ansible.com/ansible/latest)
