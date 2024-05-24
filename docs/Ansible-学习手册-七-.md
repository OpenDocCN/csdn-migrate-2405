# Ansible 学习手册（七）

> 原文：[`zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5`](https://zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：Ansible Galaxy

在之前的章节中，我们一直在使用`ansible-galaxy`命令。在本章中，我们将看看该命令提供的更多功能。Ansible Galaxy 是一个社区贡献角色的在线存储库；我们将发现一些最好的可用角色，如何使用它们，以及如何创建自己的角色并将其托管在 Ansible Galaxy 上。

到本章结束时，我们将完成以下工作：

+   对 Ansible Galaxy 的介绍

+   如何在自己的 playbooks 中使用 Ansible Galaxy 的角色

+   如何编写和提交您自己的角色到 Ansible Galaxy

# 技术要求

在本章中，我们将再次使用本地 Vagrant 框；所使用的 playbooks 可以在附带的存储库中找到[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter16`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter16)。您还需要访问 GitHub 账户——一个免费账户就可以——您可以在[`github.com/`](http://github.com/)注册一个。

# 对 Ansible Galaxy 的介绍

Ansible Galaxy 是许多东西：首先，它是一个网站，可以在[`galaxy.ansible.com/`](https://galaxy.ansible.com/)找到。该网站是社区贡献的角色和模块的家园：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/58107dd3-0605-47d0-a3d8-c62f67ec530c.png)

到目前为止，我们一直在编写我们自己的角色，这些角色与 Ansible Core 模块进行交互，用于我们的 playbook。我们可以使用 Ansible Galaxy 上发布的 15,000 多个角色中的一个，而不是编写我们自己的角色。这些角色涵盖了多种任务，并且几乎支持 Ansible 支持的所有操作系统。

`ansible-galaxy`命令是一种从自己的命令行舒适地与 Ansible Galaxy 网站交互的方式，同时还能够引导角色。就像我们在之前的章节中使用它一样，我们也可以使用它来下载、搜索和发布我们自己的角色到 Ansible Galaxy。

最后，Red Hat 已经开源了 Ansible Galaxy 的代码，这意味着您也可以在需要在防火墙后分发自己的角色时运行自己的网站。

# Jenkins playbook

让我们直接开始创建一个 playbook，只使用从 Ansible Galaxy 下载的角色来安装 Jenkins。

Jenkins，以前是 Hudson 项目，是一个用 Java 编写的开源持续集成和持续交付服务器。它可以使用插件进行扩展，并且已经远远超出了最初编译 Java 应用程序的目的。

首先，我们需要一些文件；现在通过运行以下命令来创建这些文件：

```
$ mkdir jenkins
$ cd jenkins
$ touch production requirements.yml site.yml Vagrantfile
```

正如您所看到的，我们并没有像在之前的章节中那样创建`roles`或`group_vars`文件夹。相反，我们正在创建一个`requirements.yml`文件。这将包含我们想要从 Ansible Galaxy 下载的角色列表。

在我们的情况下，我们将使用以下两个角色：

+   **Java**：[`galaxy.ansible.com/geerlingguy/java/`](https://galaxy.ansible.com/geerlingguy/java/)

+   **Jenkins**：[`galaxy.ansible.com/geerlingguy/jenkins/`](https://galaxy.ansible.com/geerlingguy/jenkins/)

第一个角色`geerlingguy.java`管理主机上 Java 的安装，然后第二个角色`geerlingguy.jenkins`管理 Jenkins 本身的安装和配置。要安装这些角色，我们需要将以下行添加到我们的`requirements.yml`文件中：

```
- src: "geerlingguy.java"
- src: "geerlingguy.jenkins"
```

添加后，我们可以通过运行以下命令下载角色：

```
$ ansible-galaxy install -r requirements.yml
```

您应该看到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/51f97450-f925-4434-ba8b-96e37d916be1.png)

从终端输出中可以看到，这两个角色已从 GitHub 项目的`roles`文件夹中下载，并放置在`~/.ansible/roles/`文件夹中。

在 macOS 和 Linux 上使用`~`表示当前用户的主目录。

您可以忽略警告；它只是让我们知道`geerlingguy.jenkins`角色想要安装`geerlingguy.java`角色的旧版本。在我们的情况下，这不会造成任何问题。

现在我们已经下载了两个角色，我们可以编写`site.yml`文件来启动 Jenkins。应该如下所示：

```
---

- hosts: jenkins
  gather_facts: true
  become: yes
  become_method: sudo

  vars:
    java_packages: "java-1.8.0-openjdk"
    jenkins_hostname: "10.20.30.60.nip.io"
    jenkins_admin_username: "ansible"
    jenkins_admin_password: "Pa55w0rD"

  roles:
    - geerlingguy.java
    - geerlingguy.jenkins
```

请注意，我们只是提供了角色的名称。默认情况下，如果在 playbook 的本地`roles`文件夹中找不到角色，Ansible 将在`~/.ansible/roles/`文件夹中搜索角色。

我们还传递了四个变量：

+   `java_packages`：这是我们希望角色安装的`geerlingguy.java`角色的名称；由于 Jenkins 需要 Java 8，而我们正在运行 CentOS 7 主机，包名称是`java-1.8.0-openjdk`。

剩下的三个变量影响`geerlingguy.jenkins`角色的配置：

+   `jenkins_hostname`：这是我们希望在其上访问 Jenkins 的 URL；与之前的章节一样，我们使用`nip.io`服务为我们的 Vagrant box 提供可解析的主机名

+   `jenkins_admin_username`：这是我们要配置以访问 Jenkins 的管理员用户名

+   `jenkins_admin_password`：这是用户的密码

接下来，我们有`production`主机的清单文件：

```
box ansible_host=10.20.30.60.nip.io

[jenkins]
box

[jenkins:vars]
ansible_connection=ssh
ansible_user=vagrant
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

最后，`Vagrantfile`的内容如下：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
BOX_NAME = "centos/7"
BOX_IP = "10.20.30.60"
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

现在我们已经将所有需要的文件放置并填充了正确的代码，我们可以启动我们的 Jenkins 服务器了。首先，我们需要创建 Vagrant box：

```
$ vagrant up
$ vagrant up --provider=vmware_fusion
```

一旦 Vagrant box 启动运行，我们可以使用以下命令运行 playbook：

```
$ ansible-playbook -i production site.yml
```

安装和配置 Java 和 Jenkins 需要几分钟；您可以在这里查看 playbook 运行的输出：

```
PLAY [jenkins] **********************************************************************************

TASK [Gathering Facts] **************************************************************************
ok: [box]

TASK [geerlingguy.java : Include OS-specific variables.] ****************************************
ok: [box]

TASK [geerlingguy.java : Include OS-specific variables for Fedora.] *****************************
skipping: [box]

TASK [geerlingguy.java : Include version-specific variables for Debian.] ************************
skipping: [box]

TASK [geerlingguy.java : Define java_packages.] *************************************************
skipping: [box]

TASK [geerlingguy.java : include_tasks] *********************************************************
included: /Users/russ/.ansible/roles/geerlingguy.java/tasks/setup-RedHat.yml for box

TASK [geerlingguy.java : Ensure Java is installed.] *********************************************
changed: [box] => (item=java-1.8.0-openjdk)

TASK [geerlingguy.java : include_tasks] *********************************************************
skipping: [box]

TASK [geerlingguy.java : include_tasks] *********************************************************
skipping: [box]

TASK [geerlingguy.java : Set JAVA_HOME if configured.] ******************************************
skipping: [box]

TASK [geerlingguy.jenkins : Include OS-Specific variables] **************************************
ok: [box]

TASK [geerlingguy.jenkins : Define jenkins_repo_url] ********************************************
ok: [box]

TASK [geerlingguy.jenkins : Define jenkins_repo_key_url] ****************************************
ok: [box]

TASK [geerlingguy.jenkins : Define jenkins_pkg_url] *********************************************
ok: [box]

TASK [geerlingguy.jenkins : include_tasks] ******************************************************
included: /Users/russ/.ansible/roles/geerlingguy.jenkins/tasks/setup-RedHat.yml for box

TASK [geerlingguy.jenkins : Ensure dependencies are installed.] *********************************
ok: [box]

TASK [geerlingguy.jenkins : Ensure Jenkins repo is installed.] **********************************
changed: [box]

TASK [geerlingguy.jenkins : Add Jenkins repo GPG key.] ******************************************
changed: [box]

TASK [geerlingguy.jenkins : Download specific Jenkins version.] *********************************
skipping: [box]

TASK [geerlingguy.jenkins : Check if we downloaded a specific version of Jenkins.] **************
skipping: [box]

TASK [geerlingguy.jenkins : Install our specific version of Jenkins.] ***************************
skipping: [box]

TASK [geerlingguy.jenkins : Ensure Jenkins is installed.] ***************************************
changed: [box]

TASK [geerlingguy.jenkins : include_tasks] ******************************************************
skipping: [box]

TASK [geerlingguy.jenkins : include_tasks] ******************************************************
included: /Users/russ/.ansible/roles/geerlingguy.jenkins/tasks/settings.yml for box

TASK [geerlingguy.jenkins : Modify variables in init file] **************************************
changed: [box] => (item={u'option': u'JENKINS_ARGS', u'value': u'--prefix='})
changed: [box] => (item={u'option': u'JENKINS_JAVA_OPTIONS', u'value': u'-Djenkins.install.runSetupWizard=false'})

TASK [geerlingguy.jenkins : Set the Jenkins home directory] *************************************
changed: [box]

TASK [geerlingguy.jenkins : Immediately restart Jenkins on init config changes.] ****************
changed: [box]

TASK [geerlingguy.jenkins : Set HTTP port in Jenkins config.] ***********************************
changed: [box]

TASK [geerlingguy.jenkins : Ensure jenkins_home /var/lib/jenkins exists] ************************
ok: [box]

TASK [geerlingguy.jenkins : Create custom init scripts directory.] ******************************
changed: [box]

RUNNING HANDLER [geerlingguy.jenkins : configure default users] *********************************
changed: [box]

TASK [geerlingguy.jenkins : Immediately restart Jenkins on http or user changes.] ***************
changed: [box]

TASK [geerlingguy.jenkins : Ensure Jenkins is started and runs on startup.] *********************
ok: [box]

TASK [geerlingguy.jenkins : Wait for Jenkins to start up before proceeding.] ********************
FAILED - RETRYING: Wait for Jenkins to start up before proceeding. (60 retries left).
 [WARNING]: Consider using the get_url or uri module rather than running curl. If you need to use
command because get_url or uri is insufficient you can add warn=False to this command task or set
command_warnings=False in ansible.cfg to get rid of this message.

ok: [box]

TASK [geerlingguy.jenkins : Get the jenkins-cli jarfile from the Jenkins server.] ***************
changed: [box]

TASK [geerlingguy.jenkins : Remove Jenkins security init scripts after first startup.] **********
changed: [box]

TASK [geerlingguy.jenkins : include_tasks] ******************************************************
included: /Users/russ/.ansible/roles/geerlingguy.jenkins/tasks/plugins.yml for box

TASK [geerlingguy.jenkins : Get Jenkins admin password from file.] ******************************
skipping: [box]

TASK [geerlingguy.jenkins : Set Jenkins admin password fact.] ***********************************
ok: [box]

TASK [geerlingguy.jenkins : Get Jenkins admin token from file.] *********************************
skipping: [box]

TASK [geerlingguy.jenkins : Set Jenkins admin token fact.] **************************************
ok: [box]

TASK [geerlingguy.jenkins : Create update directory] ********************************************
ok: [box]

TASK [geerlingguy.jenkins : Download current plugin updates from Jenkins update site] ***********
changed: [box]

TASK [geerlingguy.jenkins : Remove first and last line from json file] **************************
ok: [box]

TASK [geerlingguy.jenkins : Install Jenkins plugins using password.] ****************************

TASK [geerlingguy.jenkins : Install Jenkins plugins using token.] *******************************

PLAY RECAP **************************************************************************************
box : ok=32 changed=14 unreachable=0 failed=0
```

一旦 playbook 完成，您应该能够在`http://10.20.30.60.nip.io:8080/`访问您新安装的 Jenkins，并使用我们在`site.yml`文件中定义的管理员用户名和密码登录：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/f20b6569-1aa7-4202-97b8-ff01b27ccaa3.png)

如您所见，使用预定义的社区角色部署我们的 Jenkins 安装比编写我们自己的角色要简单得多。在几分钟内，我们就能够编写一个 playbook 并部署应用程序，而且只需要基本的安装应用程序的理解。事实上，只需要快速浏览一下 Ansible Galaxy 上两个角色的 readme 文件就足够了。

# 发布角色

现在我们知道了下载角色有多么容易，让我们看看如何通过创建角色向社区做出贡献。在过去的几章中，我们一直在使用 Ansible 来安装 Docker。因此，让我们以此为基础，扩展角色以支持 Ubuntu，并安装 Docker CE Edge 版本，而不是稳定版本。

# 创建 docker 角色

首先，我们需要基本文件；要获取这些文件，请在通常存储代码的位置运行以下命令：

```
$ ansible-galaxy init ansible-role-docker
```

这将为我们提供我们新角色所需的目录和文件结构；现在我们可以开始创建角色了。

# 变量

我们将从`vars`文件夹中的文件开始；我们将保持`vars/main.yml`文件为空，并添加两个以`vars/RedHat.yml`开头的新文件：

```
---
# vars file for ansible-role-docker

docker:
  gpg_key: "https://download.docker.com/linux/centos/gpg"
  repo_url: "https://download.docker.com/linux/centos/docker-ce.repo"
  repo_path: "/etc/yum.repos.d/docker-ce.repo"
  edge: "docker-ce-edge"
  packages:
    - "docker-ce"
    - "device-mapper-persistent-data"
    - "lvm2"
    - "python-setuptools"
    - "libselinux-python"
  pip:
    - "docker"
```

要添加的下一个文件是`vars/Debian.yml`：

```
---
# vars file for ansible-role-docker

docker:
  gpg_key: "https://download.docker.com/linux/ubuntu/gpg"
  repo: "deb [arch=amd64] https://download.docker.com/linux/{{ ansible_distribution | lower }} {{ ansible_distribution_release | lower }} edge"
  system_packages:
    - "apt-transport-https"
    - "ca-certificates"
    - "curl"
    - "software-properties-common"
    - "python3-pip"
  packages:
    - "docker-ce"
  pip:
    - "docker"
```

这两个文件包含了我们安装 Docker CE 所需的所有信息。

# 任务

由于我们针对两个不同的操作系统，我们的`tasks/main.yml`文件需要如下所示：

```
---
# tasks file for ansible-role-docker

- name: include the operating system specific variables
  include_vars: "{{ ansible_os_family }}.yml"

- name: install the stack on centos
  import_tasks: install-redhat.yml
  when: ansible_os_family == 'RedHat'

- name: install the stack on ubuntu
  import_tasks: install-ubuntu.yml
  when: ansible_os_family == 'Debian'
```

正如您所看到的，在第六章中在两个操作系统上安装 LEMP Stack 时一样，`tasks/install-redhat.yml`文件看起来与我们在之前章节中用于安装 Docker 的任务非常相似：

```
---
# tasks file for ansible-role-docker

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
    enablerepo: "{{ docker.edge }}"
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

唯一的区别是在安装软件包时启用了 Docker CE Edge 存储库，并且在安装 Docker 时我们没有运行`yum update`。我们之所以不这样做，是因为更新服务器不是我们角色的决定，当其他人运行角色时，我们的角色只应该安装 Docker。

最终的任务文件是`tasks/install-ubuntu.yml`。正如你已经猜到的那样，其中包含了在 Ubuntu 主机上安装 Docker 的任务：

```
---
# tasks file for ansible-role-docker

- name: install the system packages
  apt:
    name: "{{ item }}"
    state: "present"
    update_cache: "yes"
  with_items: "{{ docker.system_packages }}"

- name: add the apt keys from a key server
  apt_key:
    url: "{{ docker.gpg_key }}"
    state: present

- name: add the apt repo
  apt_repository:
    repo: "{{ docker.repo }}"
    state: present

- name: install the docker package
  apt:
    name: "{{ item }}"
    state: "present"
    update_cache: "yes"
    force: "yes"
  with_items: "{{ docker.packages }}"

- name: install the python packages
  pip:
    name: "{{ item }}"
  with_items: "{{ docker.pip }}"

- name: start docker and configure to start on boot
  service:
    name: "docker"
    state: "started"
    enabled: "yes"
```

这就结束了我们在两种不同操作系统上安装 Docker 所需的所有任务和变量。在以前的章节中，这已经足够让我们将角色添加到我们的 playbook 并运行任务了。然而，由于我们将在 Ansible Galaxy 上发布这个角色，我们需要添加一些关于角色的更多信息。

# Metadata

当你浏览 Ansible Galaxy 时，你可能已经看到，每个上传的角色都有关于作者、适用对象、许可证、支持的 Ansible 版本等信息。这些信息都来自于`meta/main.yml`文件。我们发布的文件看起来像下面这样：

```
---

galaxy_info:
  author: "Russ McKendrick"
  description: "Role to install the Docker CE Edge release on either an Enterprise Linux or Ubuntu host"
  license: "license (BSD)"
  min_ansible_version: 2.4
  platforms:
    - name: EL
      versions:
      - 6
      - 7
    - name: Ubuntu
      versions:
      - bionic
      - artful
      - xenial
  galaxy_tags:
    - docker

dependencies: []
```

正如你所看到的，我们在一个 YAML 文件中提供了信息，当我们发布角色时，Ansible Galaxy 将读取这些信息。文件中的大部分信息都是不言自明的，所以我在这里不会详细介绍：

+   `author`: 这是你的名字或选择的别名。

+   `description`: 添加你的角色描述；这将出现在命令行和 web 界面的搜索结果中，所以保持简短，不要添加任何标记。

+   `license`: 你发布角色的许可证；默认是 BSD。

+   `min_ansible_version`: 你的角色将使用的 Ansible 版本。记住，如果你使用了新功能，那么你必须使用该功能发布的版本。说你使用 Ansible 1.9，但使用了来自 Ansible 2.4 的模块，这只会让用户感到沮丧。

+   `platforms`: 这个支持的操作系统和版本列表在显示角色信息时使用，它将在用户选择使用你的角色时发挥作用。确保这是准确的，因为我们不想让用户感到沮丧。

+   `galaxy_tags`: 这些标签被 Ansible Galaxy 用来帮助识别你的角色做了什么。

在我们发布它之前，还有一个角色的最后部分需要看一看：`README.md`文件。

# README

我们需要完成的角色的最后部分是`README.md`文件；这个文件包含了在 Ansible Galaxy 网站上显示的信息。当我们使用`ansible-galaxy`初始化我们的角色时，它创建了一个带有基本结构的`README.md`文件。我们的角色的文件看起来像下面这样：

```
Ansible Docker Role
=========
This role installs the current Edge build Docker CE using the official repo, for more information on Docker CE see the official site at [`www.docker.com/community-edition`](https://www.docker.com/community-edition).

Requirements
------------
Apart from requiring root access via `become: yes` this role has no special requirements.

Role Variables
--------------
All of the variables can be found in the `vars` folder.

Dependencies
------------
None.

Example Playbook
----------------
An example playbook can be found below;

```

- hosts: docker

gather_facts: true

become: yes

become_method: sudo

roles:

- russmckendrick.docker

```

License
-------
BSD

Author Information
------------------
This role is published by [Russ McKendrick](http://russ.mckendrick.io/).
```

现在我们已经准备好了所有需要的文件，我们可以开始将我们的角色提交到 GitHub，并从那里发布到 Ansible Galaxy。

# 提交代码并发布

现在我们已经完成了我们的角色，我们需要将其推送到一个公共的 GitHub 存储库。有几个原因需要将其发布到公共存储库，其中最重要的是任何潜在用户都需要下载你的角色。此外，Ansible Galaxy 链接到存储库，允许用户在选择将其作为 playbook 的一部分执行之前审查你的角色。

在所有 GitHub 页面上，当你登录时，右上角有一个+图标；点击它会弹出一个菜单，其中包含创建新存储库和导入存储库的选项，以及 gists 和组织。从菜单中选择 New repository，你将看到一个如下所示的屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/e7543009-d77e-4ab8-89ec-6a58557ba66e.png)

命名存储库并输入描述；重要的是您将您的存储库命名为 `ansible-role-your-role-name`。在 Ansible Galaxy 中，角色的名称将取决于您在 `ansible-role` 之后给出的名称，因此，在上一个示例中，我们的角色将被称为 `your-role-name`，对于我们将要发布的角色，它将被称为 `docker`。

现在我们有了我们的存储库，我们需要为我们的角色添加文件。回到包含您的角色的文件夹，并在命令行上运行以下命令来在本地初始化 Git 存储库。将其推送到 GitHub，确保用您自己存储库的 URL 替换存储库 URL：

```
$ git init
$ git add -A .
$ git commit -m "first commit"
$ git remote add origin git@github.com:russmckendrick/ansible-role-docker.git
$ git push -u origin master
```

现在您应该已经上传了文件，您的存储库看起来与以下内容并没有太大不同：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/9a583521-a34f-4bb7-9be2-38bb873506f7.png)如果您在推送代码时遇到任何问题，我建议您阅读 GitHub 提供的关于设置 Git ([`help.github.com/articles/set-up-git/`](https://help.github.com/articles/set-up-git/)) 和推送您的第一个文件 ([`help.github.com/articles/create-a-repo/`](https://help.github.com/articles/create-a-repo/)) 的出色文档。

现在我们已经上传并可用了文件，我们可以使用我们的 GitHub 凭据登录到 Ansible Galaxy，然后导入我们的角色。转到 Ansible Galaxy 主页 [`galaxy.ansible.com/`](https://galaxy.ansible.com/)，然后单击“使用 GitHub 登录”链接；这将带您到 GitHub 并要求您确认您同意让 Ansible Galaxy 访问您的帐户上的信息。按照提示进行，您将返回到 Ansible Galaxy。

单击顶部菜单中的“我的内容”链接将带您到一个页面，您可以从 GitHub 导入内容；如果您没有看到您的存储库列出，请单击搜索框旁边的刷新图标：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/36d875f0-9990-44aa-8ba7-e9993171bbcb.png)

当您看到您的存储库列出时，单击角色旁边的开关，就可以了。您的角色现在已导入。单击顶部菜单中的用户名将显示一个下拉列表；从该列表中，选择“我的导入”。这将为您提供导入的日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/0e9472b9-2161-4bbc-928e-73a79ee09378.png)

现在您的角色已发布；您可以通过单击顶部的链接查看您的角色，链接上写着 `russmckendrick/ansible-role-docker`。这将带您到您新添加的角色的 Ansible Galaxy 页面，例如 [`galaxy.ansible.com/russmckendrick/docker/`](https://galaxy.ansible.com/russmckendrick/docker/)：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/08f01e98-0a81-4f21-833f-b8599f59c62a.png)

如您所见，我们添加的所有元数据都显示在列表中，包括查看从 GitHub 导入的 README 文件的链接，以及指向 GitHub 本身的链接。

# 测试角色

现在我们有了我们的角色，我们可以测试它。为此，我们将需要一个 playbook、清单和一个要求文件，以及一个 CentOS 和 Ubuntu 服务器。运行以下命令来创建您需要的文件：

```
$ mkdir docker
$ cd docker
$ touch production requirements.yml site.yml Vagrantfile
```

清单文件 production 应该如下所示：

```
centos ansible_host=10.20.30.10.nip.io 
ubuntu ansible_host=10.20.30.20.nip.io ansible_python_interpreter=/usr/bin/python3

[docker]
centos
ubuntu

[docker:vars]
ansible_connection=ssh
ansible_user=vagrant
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

我们的 `requirements.yml` 文件只包含我们的 Docker 角色：

```
- src: "russmckendrick.docker"
```

我们的 playbook，`site.yml` 文件，应该只调用我们的角色：

```
---

- hosts: docker
  gather_facts: true
  become: yes
  become_method: sudo

  roles:
    - russmckendrick.docker
```

最后，`Vagrantfile` 应该如下所示：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
DOMAIN = "nip.io"
PRIVATE_KEY = "~/.ssh/id_rsa"
PUBLIC_KEY = '~/.ssh/id_rsa.pub'
CENTOS_IP = '10.20.30.10'
CENTOS_BOX = 'centos/7'
UBUNTU_IP = '10.20.30.20'
UBUNTU_BOX = 'generic/ubuntu1804'

Vagrant.configure(API_VERSION) do |config|

  config.vm.define "centos" do |centos|
      centos.vm.box = CENTOS_BOX
      centos.vm.network "private_network", ip: CENTOS_IP
      centos.vm.host_name = CENTOS_IP + '.' + DOMAIN
      centos.ssh.insert_key = false
      centos.ssh.private_key_path = [PRIVATE_KEY, "~/.vagrant.d/insecure_private_key"]
      centos.vm.provision "file", source: PUBLIC_KEY, destination: "~/.ssh/authorized_keys"

      centos.vm.provider "virtualbox" do |v|
        v.memory = "2024"
        v.cpus = "2"
      end

      centos.vm.provider "vmware_fusion" do |v|
        v.vmx["memsize"] = "2024"
        v.vmx["numvcpus"] = "2"
      end
  end

  config.vm.define "ubuntu" do |ubuntu|
      ubuntu.vm.box = UBUNTU_BOX
      ubuntu.vm.network "private_network", ip: UBUNTU_IP
      ubuntu.vm.host_name = UBUNTU_IP + '.' + DOMAIN
      ubuntu.ssh.insert_key = false
      ubuntu.ssh.private_key_path = [PRIVATE_KEY, "~/.vagrant.d/insecure_private_key"]
      ubuntu.vm.provision "file", source: PUBLIC_KEY, destination: "~/.ssh/authorized_keys"

      ubuntu.vm.provider "virtualbox" do |v|
        v.memory = "2024"
        v.cpus = "2"
      end

      ubuntu.vm.provider "vmware_fusion" do |v|
        v.vmx["memsize"] = "2024"
        v.vmx["numvcpus"] = "2"
      end
  end

end
```

现在我们已经把所有文件放在了正确的位置，我们可以通过运行以下命令来下载我们的角色：

```
$ ansible-galaxy install -r requirements.yml
```

如您从以下输出中所见，这将把我们的角色下载到 `~/.ansible/roles/` 文件夹中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/65c29af9-204a-4bfc-b20e-c8a92b8f7d91.png)

接下来，通过运行以下任一命令来启动两个 Vagrant boxes：

```
$ vagrant up
$ vagrant up --provider=vmware_fusion
```

一旦 boxes 运行起来，我们可以通过以下方式运行 playbook：

```
$ ansible-playbook -i production site.yml 
```

如您从以下输出中所见，一切都按计划进行，角色在两个 boxes 上都安装了 Docker：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/305ac1e3-d03f-4664-acc2-ce6c24e555c5.png)

# Ansible Galaxy 命令

在我们结束本章之前，让我们快速看一下`ansible-galaxy`命令的一些其他功能，首先是登录。

# 登录

可以通过命令行登录到 Ansible Galaxy；你可以通过以下方式实现：

```
$ ansible-galaxy login
```

这将要求你的 GitHub 用户名和密码；如果你的 GitHub 账户启用了双因素身份验证，那么这种方法将无法工作。相反，你需要提供个人访问令牌。你可以在以下网址生成个人访问令牌：[`github.com/settings/tokens/`](https://github.com/settings/tokens/)。一旦你有了令牌，你可以使用以下命令，将令牌替换为你自己的：

```
$ ansible-galaxy login --github-token 0aa7c253044609b98425865wbf6z679a94613bae89 
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/ae72ea57-dac3-4195-8d0b-5318b1781e5d.png)个人访问令牌将给任何拥有它的人完全访问你的 GitHub 账户；请将它们安全地存储，并且如果可能的话定期更换。

# 导入

一旦登录，如果你对角色进行了更改并希望将这些更改导入到 Ansible Galaxy 中，你可以运行以下命令：

```
$ ansible-galaxy import russmckendrick ansible-role-docker
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/d246faed-3afd-4c10-b531-ccca5be6406e.png)

我们传递给命令的两个信息是 GitHub 用户名，在我的情况下是`russmckendrick`，以及我们想要导入的仓库的名称——所以对于我们在上一节中发布的 Docker 角色，我使用的是`ansible-role-docker`。

# 搜索

你可以使用`ansible-galaxy`命令搜索角色。例如，运行以下命令目前返回 725 个角色：

```
$ ansible-galaxy search docker
```

如果你想按作者搜索角色，可以使用以下命令：

```
$ ansible-galaxy search --author=russmckendrick docker
```

从截图中的输出可以看出，这只返回了我们发布的角色：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/3fbaf17e-5659-4337-8f48-94da578320a3.png)

这很有用，因为你不必在终端和浏览器之间来回切换。

# 信息

我们要看的最后一个命令是`info`；这个命令将打印出你提供的任何角色的信息。例如，运行以下命令将为你提供关于我们发布的角色的大量信息：

```
$ ansible-galaxy info russmckendrick.docker
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/575b2ae1-697c-4e59-8983-7e811819d80a.png)

正如你所看到的，网站上可以获取的所有信息在命令行上也是可以获取的，这意味着在与 Ansible Galaxy 交互时你可以有选择。

# 总结

在本章中，我们深入了解了 Ansible Galaxy，包括网站和命令行工具。我相信你会同意，Ansible Galaxy 提供了有价值的社区服务，它允许 Ansible 用户共享常见任务的角色，同时也为用户提供了一种通过发布自己的角色来为 Ansible 社区做出贡献的方式。

但是要小心。在将 Ansible Galaxy 的角色用于生产环境之前，请记得仔细检查代码并阅读错误跟踪器；毕竟，这些角色中的许多需要提升的权限才能成功执行它们的任务。

在下一章，我们将看一些将 Ansible 集成到你的日常工作流程中的方法。

# 问题

本章只有一个任务。拿出我们之前创建的其他角色之一，使其适用于多个操作系统，并在 Ansible Galaxy 上发布。

# 进一步阅读

本章开始时使用的两个角色都是由 Jeff Geerling 发布的；你可以在[`www.jeffgeerling.com/`](https://www.jeffgeerling.com/)找到更多关于 Jeff 和他的项目的信息。


# 第十七章：下一步使用 Ansible

在本章中，我们将讨论如何将 Ansible 集成到您的日常工作流程中，从持续集成工具到监控工具和故障排除。我们将讨论以下主题：

+   如何将 Ansible 与 Slack 等服务集成

+   您如何可以使用 Ansible 来解决问题

+   一些真实世界的例子

让我们直接深入研究如何将我们的 playbooks 连接到第三方服务。

# 与第三方服务集成

尽管您可能是运行 playbooks 的人，但您可能会保留 playbook 运行的日志，或者让您团队的其他成员，甚至其他部门了解 playbook 运行的结果。Ansible 附带了几个核心模块，允许您与第三方服务一起工作，以提供实时通知。

# Slack

Slack 已经迅速成为各个 IT 服务部门团队协作服务的首选选择。它不仅通过其应用程序目录支持第三方应用程序，而且还具有强大的 API，您可以使用该 API 将您的工具带入 Slack 提供的聊天室。

我们将在本节中查看示例，完整的 playbook 可以在 GitHub 存储库的`Chapter17/slack`文件夹中找到。我已经从第九章中的 playbook 中获取了 playbook，*构建云网络*，在那里我们在 AWS 中创建了一个 VPC，并且我已经改编它以使用`slack` Ansible 模块。

# 生成令牌

在我们的 Playbook 中使用 Slack 模块之前，我们需要一个访问令牌来请求一个登录到您的 Slack 工作区；如果您还没有工作区，您可以免费注册一个工作区[`slack.com/`](https://slack.com/)。

一旦您登录到您的工作区，无论是使用 Web 客户端还是桌面应用程序，都可以从管理应用选项中选择管理应用选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/e1f3b335-5823-4712-bdea-36fa6db8418b.png)

这将打开您的浏览器，并将您带到您工作区的应用程序目录；从这里，搜索`传入 WebHooks`，然后点击添加配置。

配置的第一部分是选择您希望传入 Webhook 发布消息的频道。我选择了通用频道——一旦选择，您将被带到一个页面，该页面会给您一个 Webhook URL；确保您记下这个 URL，因为我们很快就会需要它。在页面底部，您可以选择自定义您的 Webhook。

在页面底部的集成设置中，我输入了以下信息：

+   发布到频道：我将其留在#general

+   Webhook URL：这是为您预填充的；您还可以选择在此重新生成 URL

+   描述性标签：我在这里输入了`Ansible`

+   自定义名称：我也在这里输入了`Ansible`

+   自定义图标：我将其保留为原样

填写完前面的细节后，我点击了保存设置按钮；这让我得到了一个传入的 Webhook：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/76ce0142-b8e1-4210-bfe2-85b7d536d0d8.png)

如前所述，我还记录了 Webhook URL；对我来说，它是：

`https://hooks.slack.com/services/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`

现在我们已经准备好了一切，我们需要在 Slack 端进行配置，以便开始使用 Ansible 向我们的用户发送消息。

# Ansible playbook

我只会在这里介绍单个角色任务的更新，这是创建 VPC 的角色。我做的第一个更改是在`group_vars/common.yml`文件中添加了几行：

```
---

environment_name: "VPC-Slack"
ec2_region: "eu-west-1"

slack:
  token: "TBCRVDMGA/BBCPTPNH1/tyudQIccviG7gh4JnfeoPScc"
  username: "Ansible"
  icon: "https://upload.wikimedia.org/wikipedia/commons/thumb/0/05/Robot_icon.svg/200px-Robot_icon.svg.png"
```

正如您所看到的，我添加了以下三个嵌套变量：

+   `令牌`：这是从 Webhook URL 中获取的；如您所见，我输入了`https://hooks.slack.com/services/`后的所有内容

+   `用户名`：我们可以通过它来覆盖将发布更新的用户名，我只是将其保留为 Ansible

+   `图标`：这是我们发布的一部分将显示的头像

如果您还记得之前的 VPC 角色，您会记得它包含一个使用`ec2_vpc_net`模块创建 VPC 的单个任务。现在，我们想引入 Slack 通知，并能够向用户提供反馈。因此，首先，让我们发送通知，说我们正在检查 VPC 是否存在：

```
- name: Send notification message via Slack all options
  slack:
    token: "{{ slack.token }}"
    msg: "Checking for VPC called '{{ environment_name }}'"
    username: "{{ slack.username }}"
    icon_url: "{{ slack.icon }}"
    link_names: 0
    parse: 'full'
```

从前面的任务中可以看到，我们正在发送一条消息，在我们的情况下，它将读取`Checking for VPC called 'VPC-Slack'`，以及`token`、`username`和`icon`。角色中的下一个任务是原始角色中的任务：

```
- name: ensure that the VPC is present
  ec2_vpc_net:
    region: "{{ ec2_region }}"
    name: "{{ environment_name }}"
    state: present
    cidr_block: "{{ vpc_cidr_block }}"
    resource_tags: { "Name" : "{{ environment_name }}", "Environment" : "{{ environment_name }}" }
  register: vpc_info
```

现在，可能发生了两种情况：一个名为`VPC-Slack`的 VPC 已经创建，或者 Ansible 已经收集了关于名为`VPC-Slack`的现有 VPC 的信息。当我们向用户发送消息时，它应该根据 Ansible 的操作而改变。以下任务发送一条消息，通知我们的用户已经创建了一个新的 VPC：

```
- name: Send notification message via Slack all options
  slack:
    token: "{{ slack.token }}"
    msg: "VPC called '{{ environment_name }}' created with an ID of '{{ vpc_info.vpc.id }}'"
    username: "{{ slack.username }}"
    icon_url: "{{ slack.icon }}"
    link_names: 0
    parse: 'full'
  when: vpc_info.changed
```

请注意，只有在我注册的`vpc_info`变量标记为更改时，我才运行此任务。此外，我将 VPC 的 ID 作为消息的一部分传递。如果`vpc_info`没有注册任何更改，那么前面的任务将被跳过；而后面的任务将会运行：

```
- name: Send notification message via Slack all options
  slack:
    token: "{{ slack.token }}"
    msg: "Found a VPC called '{{ environment_name }}' which has an ID of '{{ vpc_info.vpc.id }}'"
    username: "{{ slack.username }}"
    icon_url: "{{ slack.icon }}"
    link_names: 0
    parse: 'full'
  when: vpc_info.changed == false and vpc_info.failed == false
```

请注意我如何改变措辞，以及它仅在没有更改时才被调用。我浏览了其他角色，添加了使用与前面代码相同逻辑的任务，向 Slack 发送通知；如前所述，您可以在存储库的`Chapter17/slack`文件夹中找到所有添加。

# 运行 playbook

运行 playbook 时，请使用以下命令：

```
$ export AWS_ACCESS_KEY=AKIAI5KECPOTNTTVM3EDA
$ export AWS_SECRET_KEY=Y4B7FFiSWl0Am3VIFc07lgnc/TAtK5+RpxzIGTr
$ ansible-playbook -i production site.yml
```

我从 Slack 收到了以下通知：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/0367dde3-92bd-456f-a67c-c06edc828a1e.png)

正如您所看到的，许多消息都是关于在 VPC 中创建的服务。立即重新运行 playbook 后，返回以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/b0174ed9-8e7a-4925-928f-f7c13b3d1277.png)

这一次，消息是关于查找现有服务并返回 ID。Slack 只是一个服务。现在让我们简要地看一下您可以从 Ansible playbook 与之交互的其他一些服务。

# 其他服务

Slack 不是 Ansible 可以与之交互的唯一服务；以下是您可能希望在 playbook 中使用的其他一些服务。

# Campfire

Campfire 是内置在 Basecamp 中的聊天服务；您可以使用此模块直接从 Ansible 向项目利益相关者发送更新，例如：

```
- name: Send a message to Campfire
  campfire:
    subscription: "my_subscription"
    token: "my_subscription"
    room: "Demo"
    notify: "loggins"
    msg: "The task has completed and all is well"
```

# Cisco Webex Teams（Cisco Spark）

Cisco Webex Teams，或者正式称为 Cisco Spark，是 Cisco 提供的协作服务，为您的团队提供虚拟会议空间、消息和视频通话。此外，它还具有丰富的 API，可以配置 Ansible 与之交互：

```
- name: Send a message to Cisco Spark
  cisco_spark:
    recipient_type: "roomId"
    recipient_id: "{{ spark.room_id }}"
    message_type: "markdown"
    personal_token: "{{ spark.token }}"
    message: "The task has **completed** and all is well"
```

# CA Flowdock

CA Flowdock 是一个消息服务，从头开始设计，以与面向开发人员的服务集成，如 GitHub、Bitbucket、Jira、Jenkins 和 Ansible：

```
- name: Send a message to a Flowdock inbox
  flowdock:
    type: "inbox"
    token: "{{ flowdock.token }}"
    from_address: "{{ flowdock.email }}"
    source: "{{ flowdock.source }}"
    msg: "The task has completed and all is well"
    subject: "Task Success"
```

# Hipchat

Hipchat 是由 Atlassian 提供的群组消息服务；它与 Atlassian 产品系列的其他产品紧密集成：

```
- name: Send a message to a Hipchat room
  hipchat:
    api: "https://api.hipchat.com/v2/"
    token: "{{ hipchat.token }}"
    room: "{{ hipchat.room }}"
    msg: "The task has completed and all is well"
```

# Mail

这项服务不需要任何介绍；可以配置 Ansible 使用各种配置发送电子邮件。以下示例显示了通过外部 SMTP 服务器发送电子邮件：

```
- name: Send an email using external mail servers
  mail:
    host: "{{ mail.smtp_host }}"
    port: "{{ mail.smtp_port }}"
    username: "{{ mail.smtp_username }}"
    password: "{{ mail.smtp_password }}"
    to: "Russ McKendrick <russ@mckendrick.io>"
    subject: "Task Success"
    body: "The task has completed and all is well"
  delegate_to: localhost
```

# Mattermost

Mattermost 是专有服务的开源替代品，类似于我们在列表中其他地方介绍的服务（例如 Slack、Cisco Webex Teams 和 Hipchat）：

```
- name: Send a message to a Mattermost channel
  mattermost:
    url: "{{ mattermost.url }}"
    api_key: "{{ mattermost.api_key }}"
    text: "The task has completed and all is well"
    channel: "{{ mattermost.channel }}"
    username: "{{ mattermost.username }}"
    icon_url: "{{ mattermost.icon_url }}"
```

# Say

大多数现代计算机都内置了一定程度的语音合成；使用此模块，您可以让 Ansible 口头通知您 playbook 运行的状态：

```
- name: Say a message on your Ansible host
  say:
    msg: "The task has completed and all is well"
    voice: "Daniel"
  delegate_to: localhost
```

# ServiceNow

ServiceNow 是 ServiceNow, Inc.提供的企业级 IT 服务管理软件即服务产品。使用`snow_record`模块，您的 playbook 可以在 ServiceNow 安装中打开事件：

```
- name: Create an incident in ServiceNow
  snow_record:
    username: "{{ snow.username }}"
    password: "{{ snow.password }}"
    instance: "{{ snow.instance }}"
    state: "present"
    data:
      short_description: "The task has completed and all is well"
      severity: "3"
      priority: "3"
  register: snow_incident
```

# Syslog

如果您从主机发送日志文件，则可能希望将 playbook 运行的结果发送到主机 syslog，以便将其发送到您的中央日志服务：

```
- name: Send a message to the hosts syslog
  syslogger:
    msg: "The task has completed and all is well"
    priority: "info"
    facility: "daemon"
    log_pid: "true"
```

# Twilio

使用您的 Twilio 帐户直接从您的 Ansible playbook 发送短信消息，如下所示：

```
- name: Send an SMS message using Twilio
  twilio:
    msg: "The task has completed and all is well"
    account_sid: "{{ twilio.account }}"
    auth_token: "{{ twilio.auth }}"
    from_number: "{{ twilio.from_mumber }}"
    to_number: "+44 7911 123456"
  delegate_to: localhost
```

# 第三方服务摘要

我希望您从这本书中得到的一个要点是自动化很棒——它不仅可以节省时间，而且使用我们在上一章中介绍的工具，如 Ansible Tower 和 Ansible AWX，可以让非系统管理员或开发人员从友好的 Web 界面执行他们的 playbook。

我们在本节中涵盖的模块不仅允许您记录结果，还可以在播放过程中自动进行一些清理工作，并让它自己通知您的用户，从而使您的自动化水平提升到一个新的高度。

例如，假设您需要将新配置部署到服务器。您的服务台为您提出更改，以便您在 ServiceNow 安装中执行工作。您的 playbook 可以这样编写，在执行更改之前，它使用`fetch`模块将配置文件复制到您的 Ansible Controller。然后 playbook 可以使用`snow_record`模块将现有配置文件的副本附加到更改请求，继续进行更改，然后自动更新更改请求的结果。

您可以在本章中提到的服务的以下 URL 中找到详细信息：

+   **Slack**：[`slack.com/`](https://slack.com/)

+   **Campfire**：[`basecamp.com/`](https://basecamp.com/)

+   思科 Webex 团队（思科 Spark）：[`www.webex.com/products/teams/`](https://www.webex.com/products/teams/)

+   **CA Flowdock**：[`www.flowdock.com/`](https://www.flowdock.com/)

+   **Mattermost**：[`mattermost.com/`](https://mattermost.com/)

+   **ServiceNow**：[`www.servicenow.com/`](https://www.servicenow.com/)

+   **Twilio**：[`twilio.com/`](https://twilio.com/)

# Ansible playbook 调试器

Ansible 内置了调试器。让我们看看如何通过创建一个带有错误的简单 playbook 将其构建到您的 playbook 中。正如我们刚才提到的，我们将编写一个使用`say`模块的 playbook。playbook 本身如下所示：

```
---

- hosts: localhost
  gather_facts: false
  debugger: "on_failed"

  vars:
    message: "The task has completed and all is well"
    voice: "Daniel"

  tasks:
    - name: Say a message on your Ansible host
      say:
        msg: "{{ massage }}"
        voice: "{{ voice }}"
```

有两件事需要指出：第一是错误。正如您所看到的，我们正在定义一个名为`message`的变量，但是当我们使用它时，我输错了，输入了`massage`。幸运的是，因为我正在开发 playbook，每当任务失败时，我都指示 Ansible 进入交互式调试器。

# 调试任务

让我们运行 playbook，看看会发生什么：

```
$ ansible-playbook playbook.yml
```

第一个问题是我们没有传递主机清单文件，因此将会收到警告，只有本地主机可用；这没关系，因为我们只想在我们的 Ansible Controller 上运行`say`模块：

```
[WARNING]: Unable to parse /etc/ansible/hosts as an inventory source
[WARNING]: No inventory was parsed, only implicit localhost is available
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit
localhost does not match 'all'
```

接下来，Ansible 运行 play 本身；这应该会导致致命错误：

```
PLAY [localhost] ***********************************************************************************

TASK [Say a message on your Ansible host] **********************************************************
fatal: [localhost]: FAILED! => {"msg": "The task includes an option with an undefined variable. The error was: 'massage' is undefined\n\nThe error appears to have been in '/Users/russ/Documents/Code/learn-ansible-fundamentals-of-ansible-2x/chapter17/say/playbook.yml': line 12, column 7, but may\nbe elsewhere in the file depending on the exact syntax problem.\n\nThe offending line appears to be:\n\n tasks:\n - name: Say a message on your Ansible host\n ^ here\n"}
```

通常，playbook 运行将停止，并且您将返回到您的 shell；但是，因为我们已经指示 Ansible 进入交互式调试器，现在我们看到以下提示：

```
[localhost] TASK: Say a message on your Ansible host (debug)>
```

从这里开始，我们可以更仔细地研究问题；例如，我们可以通过输入以下命令来查看错误：

```
p result._result
```

一旦您按下*Enter*键，失败任务的结果将返回：

```
[localhost] TASK: Say a message on your Ansible host (debug)> p result._result
{'failed': True,
 'msg': u"The task includes an option with an undefined variable. The error was: 'massage' is undefined\n\nThe error appears to have been in '/Users/russ/Documents/Code/learn-ansible-fundamentals-of-ansible-2x/chapter17/say/playbook.yml': line 12, column 7, but may\nbe elsewhere in the file depending on the exact syntax problem.\n\nThe offending line appears to be:\n\n tasks:\n - name: Say a message on your Ansible host\n ^ here\n"}
[localhost] TASK: Say a message on your Ansible host (debug)>
```

通过输入以下内容，让我们更仔细地查看任务中使用的变量：

```
p task.args
```

这将返回我们在任务中使用的两个参数：

```
[localhost] TASK: Say a message on your Ansible host (debug)> p task.args
{u'msg': u'{{ massage }}', u'voice': u'{{ voice }}'}
[localhost] TASK: Say a message on your Ansible host (debug)>
```

现在，让我们通过以下方式查看任务可用的变量：

```
p task_vars
```

您可能已经注意到，我们指示 Ansible 在 playbook 运行中执行 setup 模块；这是为了将可用变量列表保持在最小范围内：

```
[localhost] TASK: Say a message on your Ansible host (debug)> p task_vars
{'ansible_check_mode': False,
 'ansible_connection': 'local',
 'ansible_current_hosts': [u'localhost'],
 'ansible_diff_mode': False,
 'ansible_facts': {},
 'ansible_failed_hosts': [],
 'ansible_forks': 5,
 'ansible_inventory_sources': [u'/etc/ansible/hosts'],
 'ansible_play_batch': [],
 'ansible_play_hosts': [u'localhost'],
 'ansible_play_hosts_all': [u'localhost'],
 'ansible_playbook_python': '/usr/bin/python',
 'ansible_python_interpreter': '/usr/bin/python',
 'ansible_run_tags': [u'all'],
 'ansible_skip_tags': [],
 'ansible_version': {'full': '2.5.5',
 'major': 2,
 'minor': 5,
 'revision': 5,
 'string': '2.5.5'},
 'environment': [],
 'group_names': [],
 'groups': {'all': [], 'ungrouped': []},
 'hostvars': {},
 'inventory_hostname': u'localhost',
 'inventory_hostname_short': u'localhost',
 u'message': u'The task has completed and all is well',
 'omit': '__omit_place_holder__0529a2749315462e1ae1a0d261987dedea3bfdad',
 'play_hosts': [],
 'playbook_dir': u'/Users/russ/Documents/Code/learn-ansible-fundamentals-of-ansible-2x/chapter17/say',
 u'voice': u'Daniel'}
[localhost] TASK: Say a message on your Ansible host (debug)>
```

正如您从前面的输出中所看到的，关于我们的 playbook 正在执行的环境有很多信息。在变量列表中，您会注意到其中两个变量以`u`为前缀：它们是`voice`和`message`。我们可以通过运行以下命令来了解更多信息：

```
p task_vars['message']
p task_vars['voice']
```

这将显示变量的内容：

```
[localhost] TASK: Say a message on your Ansible host (debug)> p task_vars['message']
u'The task has completed and all is well'
[localhost] TASK: Say a message on your Ansible host (debug)> p task_vars['voice']
u'Daniel'
[localhost] TASK: Say a message on your Ansible host (debug)>
```

我们知道我们正在将一个拼写错误的变量传递给`msg`参数，因此我们可以即时进行一些更改并继续 playbook 运行。为此，我们将运行以下命令：

```
task.args['msg'] = '{{ message }}'
```

这将更新参数以使用正确的变量意思，这样我们可以通过运行以下命令重新运行任务：

```
redo
```

这将立即使用正确的参数重新运行任务，并且幸运的话，您应该会听到*任务已完成，一切正常*：

```
[localhost] TASK: Say a message on your Ansible host (debug)> task.args['msg'] = '{{ message }}'
[localhost] TASK: Say a message on your Ansible host (debug)> redo
changed: [localhost]

```

```
PLAY RECAP ************************************************************************************************************************************
localhost : ok=1 changed=1 unreachable=0 failed=0
```

如您从前面的输出中所看到的，因为我们只有一个任务，playbook 已经完成。如果我们有更多任务，那么它将从离开的地方继续。现在您可以使用正确的拼写更新您的 playbook，并继续您的一天。

此外，如果我们愿意，我们可以输入`continue`或`quit`来分别继续或停止。

# Ansible 调试器摘要

当您正在创建大型 playbook 时，启用 Ansible 调试器是一个非常有用的选项——例如，想象一下，您有一个大约需要运行 20 分钟的 playbook，但是在结束时出现了一个错误，比如在您第一次运行 playbook 后的 15 分钟。

让 Ansible 进入交互式调试器 shell 不仅意味着您可以准确地看到定义和未定义的内容，而且还意味着您不必盲目地对 playbook 进行更改，然后等待另外 15 分钟以查看这些更改是否解决了导致致命错误的问题。

# 真实世界的例子

在我们结束本章，也结束本书之前，我想给出一些我如何使用 Ansible 和与 Ansible 交互的例子：第一个是使用聊天与 Ansible 交互。

# 聊天示例

几个月前，我需要设置一个演示来展示自动化工作，但是，我需要能够在我的笔记本电脑或手机上展示演示，这意味着我不能假设我可以访问命令行。

我想出的演示最终使用了 Slack 和其他一些我们在这本书中没有涵盖的工具，即 Hubot 和 Jenkins；在我详细介绍之前，让我们快速看一下演示运行的输出：

！[](assets/d7fb0ae5-d86c-4d81-a9b2-b64a66d6dcad.png)

如前面的输出所示，我在 Slack 频道中提出了以下问题：

*@bot 给我一个 Linux 服务器*

然后触发了一个 Ansible playbook 运行，该运行在 AWS 中启动了一个实例，并在 playbook 确认服务器在网络上可用后返回实例的信息。我还配置它通过询问以下内容来删除所有正在运行的实例：

*@bot 终止所有服务器*

如您所见，这运行了另一个 playbook，并且这次，在实例被删除后返回了一个动画 GIF：

！[](assets/2171890b-ee00-4138-adee-d95714316cab.png)

那么，我用什么做到这一点呢？正如前面提到的，首先，我使用了 Hubot。Hubot 是 GitHub 开发的一个开源可扩展的聊天机器人。它是在我的 Slack 频道中使用`hubot-slack`插件进行配置的，并且它会监听任何给定的命令。

我使用`hubot-alias`插件来定义一个别名，将*@bot 给我一个 Linux 服务器*翻译成*build awslaunch OS=linux*；这使用了`hubot-yardmaster`插件来触发我的 Jenkins 安装中的构建。

Jenkins 是一个开源的自动化服务器，主要用于持续集成和持续交付，它也有一个插件架构。使用 Jenkins Ansible 插件和 Jenkins Git 插件，我能够将用于启动 AWS 实例的 playbook 和角色拉到我的 Jenkins 服务器上，然后让 Jenkins 为我运行 playbook——playbook 本身与我们在第九章和第十章中讨论的 playbook 并没有太大不同，分别是*构建云网络*和*高可用云部署*。

playbook 中内置了一些逻辑，限制了可以启动的实例数量，随机化了要启动的实例的名称，并从几个选项中显示了一个随机的 GIF 图像——所有这些信息，以及实例和 AMI 的详细信息，都通过 Ansible Slack 模块传递给用户，给人一种 playbook 实际上做了更多事情的印象。

在前面的两个例子中，机器人用户是 Hubot，而 Jenkins 实际上是 playbook 运行的反馈。

# 自动化部署

另一个例子——我最近与几位开发人员合作，他们需要一种自动将代码部署到开发和分级服务器的方法。使用 Docker、GitHub、Jenkins 和 Ansible AWX 的组合，我能够为开发人员提供一个工作流程，每当他们将代码推送到 GitHub 存储库的开发或分级分支时都会触发。

为了实现这一点，我在他们自己的 Jenkins 服务器上部署了代码，使用 Ansible 在容器中部署了 Jenkins，并在同一台服务器上使用 Docker 部署了 AWX。然后，使用**Jenkins GitHub**插件，我将 Jenkins 项目连接到 GitHub 以创建触发构建所需的 Webhooks。然后使用**Jenkins Ansible Tower**插件，我让 Jenkins 触发 AWX 中的 playbook 运行。

我这样做是因为目前，AWX 与 GitHub Webhooks 的连接并不那么容易，而**Jenkins**和**Jenkins GitHub**插件具有很高的兼容性——我想随着 AWX 的开发速度，这个小问题很快就会得到解决。

AWX 允许您根据角色授予 playbooks 的访问权限，我给了开发经理和运维工程师运行生产 playbook 的权限，开发人员只有只读权限，以便他们可以查看 playbook 运行的结果。

这意味着部署到生产环境也能够自动化，只要有正确权限的人手动触发 playbook 运行。

AWX 允许我们控制谁可以触发部署，这与我们现有的部署策略相吻合，该策略规定开发人员不应该有权限部署他们编写的代码到生产系统。

# 总结

现在我们不仅结束了这一章，也结束了我们的书。我一直在努力想出一个总结 Ansible 的方法，我在 Ansible 的创建者 Michael DeHaan 的一条推特中找到了答案([`twitter.com/laserllama/status/976135074117808129`](https://twitter.com/laserllama/status/976135074117808129))，他在回复一位技术招聘人员时说：

"使用 Ansible 几个月的人和使用 Ansible 三年的人一样好。这是一个故意简单的工具。"

这完美地总结了我的 Ansible 经验，希望也适用于你。一旦掌握了基础知识，就可以很容易地快速进展，开始构建更加复杂的 playbooks，这些 playbooks 不仅可以帮助部署基本的代码和应用程序，还可以帮助部署复杂的云和甚至物理架构。

不仅能够重用自己的角色，而且可以通过 Ansible Galaxy 访问大量社区贡献的角色，意味着你有许多示例或快速起点用于下一个项目。因此，你可以更快地投入工作，比起其他工具可能更快。此外，如果 Ansible 无法做某事，那么很可能有一个可以集成的工具来提供缺失的功能。

回到我们在第一章讨论过的内容，《Ansible 简介》，能够以可重复和可共享的方式以代码定义基础架构和部署，鼓励他人贡献到你的 playbooks 中，这应该是引入 Ansible 到日常工作流程中的最终目标。我希望通过这本书，你已经开始考虑 Ansible 可以帮助你节省时间的日常任务。

# 更多阅读材料

本章提到的工具的更多信息可以在以下网址找到：

+   **Hubot**: [`hubot.github.com`](https://hubot.github.com)

+   **Hubot Slack**: [`github.com/slackapi/hubot-slack`](https://github.com/slackapi/hubot-slack)

+   **Hubot Alias**: [`github.com/dtaniwaki/hubot-alias`](https://github.com/dtaniwaki/hubot-alias)

+   **Hubot Yardmaster**: [`github.com/hacklanta/hubot-yardmaster`](https://github.com/hacklanta/hubot-yardmaster)

+   **Jenkins Git**: [`plugins.jenkins.io/git`](https://plugins.jenkins.io/git)

+   **Jenkins Ansible**: [`plugins.jenkins.io/ansible`](https://plugins.jenkins.io/ansible)

+   **Jenkins GitHub**: [`plugins.jenkins.io/github`](https://plugins.jenkins.io/github)

+   **Jenkins Ansible Tower**: [`plugins.jenkins.io/ansible-tower`](https://plugins.jenkins.io/ansible-tower)


# 第十八章：评估

# 第二章，安装和运行 Ansible

1.  安装 Ansible 使用 pip 的命令是什么？

`sudo -H pip install ansible`

1.  真或假：在使用 Homebrew 时，您可以选择要安装或回滚到的确切 Ansible 版本。

假

1.  真或假：Windows 子系统在虚拟机中运行。

假

1.  列出三个 Vagrant 支持的虚拟化程序。

VirtualBox，VMware 和 Hyper-V

1.  状态并解释主机清单是什么。

主机清单是一个主机列表，以及用于访问它们的选项，Ansible 将针对它们

1.  真或假：YAML 文件中的缩进对于它们的执行非常重要，而不仅仅是装饰性的。

真

# 第三章，Ansible 命令

1.  在本章中提供有关主机清单的信息的命令中，哪个是默认与 Ansible 一起提供的？

`ansible-inventory`命令

1.  真或假：使用 Ansible Vault 加密字符串的变量文件将与低于 2.4 版本的 Ansible 一起使用。

假

1.  您将运行什么命令来获取如何调用`yum`模块作为任务的示例？

您将使用`ansible-doc`命令

1.  解释为什么您希望针对清单中的主机运行单个模块。

如果您想要使用 Ansible 以受控的方式针对多个主机运行临时命令，您将使用单个模块。

# 第四章，部署 LAMP 堆栈

1.  您会使用哪个 Ansible 模块来下载和解压缩 zip 文件？

该模块称为`unarchive`

1.  真或假：在**`roles/rolename/default/`**文件夹中找到的变量会覆盖同一变量的所有其他引用。

假

1.  解释如何向我们的 playbook 添加第二个用户？

通过向用户变量添加第二行，例如：`{ name: "user2", group: "lamp", state: "present", key: "{{ lookup('file', '~/.ssh/id_rsa.pub') }}" }`

1.  真或假：您只能从一个任务中调用一个处理程序。

假

# 第五章，部署 WordPress

1.  在`setup`模块执行期间收集的哪个事实可以告诉我们的 playbook 目标主机有多少处理器？

事实是`ansible_processor_count`

1.  真或假：在`lineinfile`模块中使用`backref`可以确保如果正则表达式不匹配，则不会应用任何更改。

真

1.  解释为什么我们希望在 playbook 中构建逻辑来检查 WordPress 是否已经安装。

这样我们可以在下次运行 playbook 时跳过下载和安装 WordPress 的任务。

1.  我们使用哪个模块来定义作为 playbook 运行的一部分的变量？

`set_fact`模块

1.  我们传递哪个参数给`shell`模块，以便在我们选择的目录中执行我们想要运行的命令？

参数是`chdir`

1.  真或假：将 MariaDB 绑定到`127.0.0.1`将允许我们从外部访问它。

假

# 第六章，针对多个发行版

1.  真或假：我们需要仔细检查 playbook 中的每个任务，以便它可以在两个操作系统上运行。

真

1.  哪个配置选项允许我们定义 Python 的路径，Ansible 将使用？

选项是`ansible_python_interpreter`

1.  解释为什么我们需要对配置并与 PHP-FPM 服务交互的任务进行更改。

配置文件的路径不同，而且在 Ubuntu 上 PHP-FPM 默认在不同的组下运行

1.  真或假：每个操作系统的软件包名称完全对应。

假

# 第七章，核心网络模块

1.  真或假：您必须在模板中使用`with_items`与`for`循环。

假

1.  哪个字符用于将您的变量分成多行？

您将使用`|`字符

1.  真或假：使用 VyOS 模块时，我们不需要在主机清单文件中传递设备的详细信息。

真

# 第八章，转向云端

1.  我们需要安装哪个 Python 模块来支持`digital_ocean`模块？

该模块称为`dopy`

1.  真或假：您应该始终加密诸如 DigitalOcean 个人访问令牌之类的敏感值。

真

1.  我们使用哪个过滤器来查找我们需要使用的 SSH 密钥的 ID 来启动我们的 Droplet？

过滤器将是`[?name=='Ansible']`

1.  陈述并解释为什么我们在`digital_ocean`任务中使用了`unique_name`选项。

确保我们不会在每个 playbook 运行时启动具有相同名称的多个 droplets。

1.  从另一个 Ansible 主机访问变量的正确语法是什么？

使用`hostvars`，例如使用`{{ hostvars['localhost'].droplet_ip }}`，这已在 Ansible 控制器上注册。

1.  真或假：`add_server`模块用于将我们的 Droplet 添加到主机组。

错误

# 第九章，构建云网络

1.  哪两个环境变量被 AWS 模块用来读取您的访问 ID 和秘密？

它们是`AWS_ACCESS_KEY`和`AWS_SECRET_KEY`

1.  真或假：每次运行 playbook 时，您都会获得一个新的 VPC。

错误

1.  陈述并解释为什么我们不费心注册创建子网的结果。

这样我们可以通过我们稍后在 playbook 运行中分配给它们的角色将子网 ID 列表分组在一起

1.  在定义安全组规则时，使用`cidr_ip`和`group_id`有什么区别？

`cidr_ip`创建一个规则，将提供的端口锁定到特定 IP 地址，而`group_id`将端口锁定到您提供的`group_id`中的所有主机

1.  真或假：在使用具有`group_id`定义的规则时，添加安全组的顺序并不重要。

错误

# 第十章，高可用云部署

1.  使用`gather_facts`选项注册的变量的名称是什么，其中包含我们执行 playbook 的日期和时间？

这是`ansible_date_time`事实

1.  真或假：Ansible 自动找出需要执行的任务，这意味着我们不必自己定义任何逻辑。

错误

1.  解释为什么我们必须使用`local_action`模块。

因为我们不想从我们使用 Ansible 的主机与 AWS API 进行交互； 相反，我们希望所有 AWS API 交互都发生在我们的 Ansible 控制器上

1.  我们在`ansible-playbook`命令之前添加哪个命令来记录我们的命令执行花费了多长时间？

`time`命令

1.  真或假：在使用自动扩展时，您必须手动启动 EC2 实例。

错误

# 第十一章，构建 VMware 部署

1.  您需要在 Ansible 控制器上安装哪个 Python 模块才能与 vSphere 进行交互？

该模块称为 PyVmomi

1.  真或假：`vmware_dns_config`只允许您在 ESXi 主机上设置 DNS 解析器。

错误

1.  列举我们已经介绍的两个可以用于启动虚拟机的模块名称；有三个，但一个已被弃用。

`vca_vapp`和`vmware_guest`模块；已弃用`vsphere_guest`模块

1.  我们已经查看的模块中，您将使用哪个模块来确保在进行与 VMware 通过 VMware 交互的任务之前，虚拟机完全可用？

`vmware_guest_tools_wait`模块

1.  真或假：可以安排使用 Ansible 更改电源状态。

真

# 第十二章，Ansible Windows 模块

1.  以下两个模块中哪一个可以在 Windows 和 Linux 主机上使用：setup 或 file？

`setup`模块

1.  真或假：您可以使用 SSH 访问您的 Windows 目标。

错误

1.  解释 WinRM 使用的接口类型。

WinRM 使用 SOAP 接口而不是交互式 shell

1.  您需要安装哪个 Python 模块才能与 macOS 和 Linux 上的 WinRM 进行交互？

`pywinrm`模块

1.  真或假：您可以在使用`win_chocolatey`模块之前单独安装 Chocolatey 的任务。

错误

# 第十三章，使用 Ansible 和 OpenSCAP 加固您的服务器

1.  将`>`添加到多行变量会产生什么影响？

当 Ansible 将其插入 playbook 运行时，该变量将呈现为单行

1.  真或假：OpenSCAP 获得了 NIST 的认证。

真

1.  为什么我们告诉 Ansible 如果`scan`命令标记为失败就继续？

因为如果得不到 100%的分数，任务将总是失败

1.  解释为什么我们对某些角色使用标签。

这样我们就可以在使用`--tags`标志时运行 playbook 的某些部分

1.  真或假：我们使用`copy`命令将 HTML 报告从远程主机复制到 Ansible 控制器。

假

# 第十四章，部署 WPScan 和 OWASP ZAP

1.  为什么我们使用 Docker 而不是直接在我们的 Vagrant box 上安装 WPScan 和 OWASP ZAP？

简化部署过程；部署两个容器比安装两个工具的支持软件堆栈更容易

1.  真或假：`pip`默认安装在我们的 Vagrant box 上。

假

1.  我们需要安装哪个 Python 模块才能使 Ansible Docker 模块正常工作？

`docker`模块

# 第十五章，介绍 Ansible Tower 和 Ansible AWX

1.  阐述 Ansible Tower 和 Ansible AWX 之间的区别并解释。

Ansible Tower 是由 Red Hat 提供的商业支持的企业级软件。Ansible AWX 是未来版本的 Ansible Tower 的开源上游；它经常更新并按原样提供。
