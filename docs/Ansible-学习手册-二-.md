# Ansible 学习手册（二）

> 原文：[`zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5`](https://zh.annas-archive.org/md5/9B9E8543F5B9586A00B5C40E5C135DD5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：部署 WordPress

在上一章中，我们致力于构建一个安装和配置基本 LAMP 堆栈的 playbook。在本章中，我们将在那里使用的技术基础上构建一个安装 LEMP 堆栈和 WordPress 的 playbook。

我们将涵盖以下主题：

+   准备我们的初始 playbook

+   下载并安装 WordPress CLI

+   安装和配置 WordPress

+   登录到您的 WordPress 安装

在开始之前，我们应该快速了解一下 WordPress 是什么。很可能在过去的 48 小时内，您已经访问过由 WordPress 提供支持的网站。它是一个由 PHP 和 MySQL 提供支持的开源**内容管理系统**（**CMS**），根据 BuiltWith 提供的 CMS 使用统计数据，它被约 19,545,516 个网站使用。

# 技术要求

在前几章中启动的 CentOS 7 Vagrant box 的新副本将被使用。这意味着软件包需要重新下载，以及 WordPress。您可以在[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter05/lemp`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter05/lemp)找到 playbook 的完整副本。

# 预安装任务

如前一章所述，LEMP 堆栈由以下元素组成：

+   **Linux**：在我们的情况下，这将再次是 CentOS 7

+   **NGINX**：如果您记得，它的发音是*engine-x*，并且在我们的堆栈中替代了 Apache

+   **MariaDB**：正如我们所看到的，这将是数据库组件

+   **PHP**：我们将再次使用 PHP 7.2

在安装 WordPress 之前，我们需要安装和配置这些组件。此外，由于这个 playbook 最终将被执行在公开可用的云服务器上，我们需要考虑一些关于 NGINX 配置的最佳实践。

让我们从设置 playbook 的初始结构开始：

```
$ mkdir lemp lemp/group_vars
$ touch lemp/group_vars/common.yml lemp/production lemp/site.yml lemp/Vagrantfile lemp/.gitignore
$ cd lemp
```

既然我们有了基本布局，我们需要在`Vagrantfile`和`.gitignore`文件中放一些内容。`Vagrantfile`包含以下内容，与前几章类似：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
BOX_NAME    = "centos/7"
BOX_IP      = "192.168.50.5"
DOMAIN      = "nip.io"
PRIVATE_KEY = "~/.ssh/id_rsa"
PUBLIC_KEY  = '~/.ssh/id_rsa.pub'

Vagrant.configure(API_VERSION) do |config|
  config.vm.box = BOX_NAME
  config.vm.network "private_network", ip: BOX_IP
  config.vm.host_name = BOX_IP + '.' + DOMAIN
  config.ssh.insert_key = false
  config.ssh.private_key_path = [PRIVATE_KEY,
  "~/.vagrant.d/insecure_private_key"]
  config.vm.provision "file", source: PUBLIC_KEY, destination:
  "~/.ssh/authorized_keys"

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

正如您可能已经注意到的那样，我们为这个 Vagrant box 使用了不同的 IP 地址；`.gitignore`文件应该包含一行：

```
.vagrant
```

现在我们已经配置好了基本内容，我们可以开始编写 playbook 来部署和配置我们的初始软件堆栈。

# stack-install 命令

我们将从使用`ansible-galaxy init`创建一个名为`stack-install`的角色开始：

```
$ ansible-galaxy init roles/stack-install
```

这将安装我们的初始软件堆栈。安装完成后，我们将交给第二个角色，然后配置软件堆栈，然后第三个角色开始安装 WordPress。

那么我们需要哪些软件包呢？WordPress 有以下要求：

+   PHP 7.2 或更高版本

+   MariaDB 10.0 或更高版本，或者 MySQL 5.6 或更高版本

+   带有`mod_rewrite`模块的 NGINX 或 Apache

+   HTTPS 支持

我们知道从上一章，IUS 仓库可以提供 PHP 7.2 和 MariaDB 10.1，所以我们将使用它作为这些软件包的来源，但 NGINX 呢？EPEL 仓库中有 NGINX 软件包。但是，我们将使用主要的 NGINX 仓库，以便获取最新和最好的版本。

# 启用仓库

让我们通过启用我们安装软件堆栈所需的三个仓库来开始我们的 playbook，然后，一旦这些仓库被启用，我们应该执行`yum update`来确保基本操作系统是最新的。

`roles/stack-install/defaults/main.yml`文件需要以下内容才能实现这一点。首先，我们有启用 EPEL 和 IUS 的 RPM 软件包的位置：

```
repo_packages:
  - "epel-release"
  - "https://centos7.iuscommunity.org/ius-release.rpm"
```

之后，我们有以下嵌套变量，其中包含我们使用`yum_repository`模块创建 NGINX 仓库的`.repo`文件所需的所有信息：

```
nginx_repo:
  name: "nginx"
  description: "The mainline NGINX repo"
  baseurl: "http://nginx.org/packages/mainline/centos/7/$basearch/"
  gpgcheck: "no"
  enabled: "yes"
```

现在我们已经有了默认设置，我们可以将任务添加到`roles/stack-install/tasks/main.yml`文件中；具体如下，第一个任务已经很熟悉，因为它只是安装我们的两个软件包：

```
- name: install the repo packages
  yum:
    name: "{{ item }}"
    state: "installed"
  with_items: "{{ repo_packages }}"
```

接下来的任务是在`/etc/yum.repos.d/`中创建一个名为`nginx.repo`的存储库文件：

```
- name: add the NGINX mainline repo
  yum_repository:
    name: "{{ nginx_repo.name }}"
    description: "{{ nginx_repo.description }}"
    baseurl: "{{ nginx_repo.baseurl }}"
    gpgcheck: "{{ nginx_repo.gpgcheck }}"
    enabled: "{{ nginx_repo.enabled }}"
```

从以下终端输出可以看出，文件的内容指向了 NGINX 存储库，我们可以通过运行以下命令获取有关 NGINX 软件包的更多信息：

```
$ yum info nginx
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/0acb7dd0-336e-4be1-9d47-664069f25d1c.png)

下面的任务也应该看起来很熟悉，因为我们在上一章中使用它来更新已安装的软件包：

```
- name: update all of the installed packages
  yum:
    name: "*"
    state: "latest"
    update_cache: "yes"
```

现在我们已经设置好了源存储库并更新了已安装的软件包，我们可以继续进行其余的软件包安装。

# 安装软件包

我们将创建四个软件包列表；这些在`roles/stack-install/defaults/main.yml`文件中。与上一章一样，我们首先需要卸载预安装的 MariaDB 软件包，因此我们的第一个列表包括要删除的软件包：

```
packages_remove:
  - "mariadb-libs.x86_64"
```

接下来，我们需要安装一些软件包，以允许 Ansible 与诸如 SELinux 和 MariaDB 之类的服务进行交互，以及安装 Postfix 软件包，我们知道上次已经删除了：

```
system_packages:
  - "postfix"
  - "MySQL-python"
  - "policycoreutils-python"
```

然后，我们有组成核心软件堆栈的所有软件包：

```
stack_packages:
  - "nginx"
  - "mariadb101u"
  - "mariadb101u-server"
  - "mariadb101u-config"
  - "mariadb101u-common"
  - "mariadb101u-libs"
  - "php72u"
  - "php72u-bcmath"
  - "php72u-cli"
  - "php72u-common"
  - "php72u-dba"
  - "php72u-fpm"
  - "php72u-fpm-nginx"
  - "php72u-gd"
  - "php72u-intl"
  - "php72u-json"
  - "php72u-mbstring"
  - "php72u-mysqlnd"
  - "php72u-process"
  - "php72u-snmp"
  - "php72u-soap"
  - "php72u-xml"
  - "php72u-xmlrpc"
```

最后，我们还有一些不错的功能：

```
extra_packages:
  - "vim-enhanced"
  - "git"
  - "unzip"
```

删除软件包然后安装它们的任务应该放在`roles/stack-install/tasks/main.yml`文件中，从删除软件包的任务开始：

```
- name: remove the packages so that they can be replaced
  yum:
    name: "{{ item }}"
    state: "absent"
  with_items: "{{ packages_remove }}"
```

然后，我们可以使用以下任务一次性安装所有软件包：

```
- name: install the stack packages
  yum:
    name: "{{ item }}"
    state: "installed"
  with_items: "{{ system_packages + stack_packages + extra_packages }}"
```

请注意，我们正在将剩下的三个软件包列表合并为一个变量。我们这样做是为了尽量减少重复使用`yum`任务。这也允许我们在剧本的其他地方覆盖，比如只覆盖`extra_packages`，而不必重复整个堆栈其他部分所需的软件包列表。

# stack-config 角色

接下来的角色将配置我们刚刚安装的软件堆栈，所以让我们创建这个角色：

```
$ ansible-galaxy init roles/stack-config
```

现在我们已经有了角色所需的文件，我们可以开始计划需要配置的内容。我们需要做以下事情：

+   为我们的 WordPress 创建一个用户

+   按照 WordPress Codex 上的最佳实践配置 NGINX

+   将 PHP-FPM 配置为以 WordPress 用户身份运行

+   为 SELinux 进行初始配置

让我们从创建 WordPress 用户开始。

# WordPress 系统用户

WordPress 系统用户的默认设置，应该放在`roles/stack-config/defaults/main.yml`中，如下所示：

```
wordpress_system:
  user: "wordpress"
  group: "php-fpm"
  comment: "wordpress system user"
  home: "/var/www/wordpress"
  state: "present"
```

我们将这称为系统用户，因为我们将在本章后面创建一个 WordPress 用户。这个用户的详细信息也将在 Ansible 中定义，所以我们不想混淆两个不同的用户。

使用这些变量的任务应该在`roles/stack-config/tasks/main.yml`中，看起来像这样：

```
- name: add the wordpress user
  user: 
    name: "{{ wordpress_system.user }}"
    group: "{{ wordpress_system.group }}"
    comment: "{{ wordpress_system.comment }}"
    home: "{{ wordpress_system.home }}"
    state: "{{ wordpress_system.state }}"
```

如你所见，这次我们没有向用户添加密钥，因为我们不想登录到用户帐户来开始操作文件和其他操作。这应该全部在 WordPress 内部完成，或者通过使用 Ansible 完成。

# NGINX 配置

我们将使用几个模板文件来配置我们的 NGINX。第一个模板名为`roles/stack-config/templates/nginx-nginx.conf.j2`，它将替换软件包安装部署的主要 NGINX 配置：

```
# {{ ansible_managed }}
user nginx;
worker_processes {{ ansible_processor_count }};
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
    access_log /var/log/nginx/access.log main;
    sendfile on;
    keepalive_timeout 65;
    client_max_body_size 20m;
    include /etc/nginx/conf.d/*.conf;
}
```

文件本身的内容基本上与初始文件相同，只是我们正在更新`worker_processes`，以便它使用 Ansible 运行`setup`模块时检测到的处理器数量，而不是硬编码的值。

部署配置文件的任务就像你期望的那样，应该放在`roles/stack-config/tasks/main.yml`中：

```
- name: copy the nginx.conf to /etc/nginx/
  template:
    src: "nginx-nginx.conf.j2"
    dest: "/etc/nginx/nginx.conf"
  notify: "restart nginx"
```

如您所见，我们正在通知`restart nginx`处理程序，它存储在以下`roles/stack-config/handlers/main.yml`文件中：

```
- name: "restart nginx"
  service:
    name: "nginx"
    state: "restarted"
    enabled: "yes"
```

接下来，我们有默认站点模板，`roles/stack-config/templates/nginx-confd-default.conf.j2`：

```
# {{ ansible_managed }}

upstream {{ php.upstream }} {
        server {{ php.ip }}:{{ php.port }};
}

server {
    listen 80;
  server_name {{ ansible_nodename }};
  root {{ wordpress_system.home }};
  index index.php index.html index.htm;

    include global/restrictions.conf;
    include global/wordpress_shared.conf;

}
```

为了帮助识别模板文件将放置在目标主机上的位置，我将它们命名，以便文件名中包含完整路径。在这种情况下，文件名是`nginx-confd-default.conf.j2`，它将部署到`/etc/nginx/conf.d/..`。

我们要部署的下两个模板将进入一个不存在的文件夹。因此，我们首先需要创建目标文件夹。为此，我们需要将以下内容添加到`roles/stack-config/tasks/main.yml`中：

```
- name: create the global directory in /etc/nginx/
  file:
    dest: "/etc/nginx/global/"
    state: "directory"
    mode: "0644"
```

然后，以下命令将文件复制到`global`文件夹中：

```
- name: copy the restrictions.conf to /etc/nginx/global/
  copy:
    src: "nginx-global-restrictions.conf"
    dest: "/etc/nginx/global/restrictions.conf"
  notify: "restart nginx"

- name: copy the wordpress_shared.conf to /etc/nginx/global/
  template:
    src: "nginx-global-wordpress_shared.conf.j2"
    dest: "/etc/nginx/global/wordpress_shared.conf"
  notify: "restart nginx"
```

由于我们在`nginx-global-restrictions.conf`文件中没有进行任何替换，所以我们在这里使用`copy`模块而不是`template`；文件存储在`roles/stack-config/files/`中，内容如下：

```
   # Do not log robots.txt
        location = /robots.txt {
            log_not_found off;
            access_log off;
        }

    # If no favicon exists return a 204 (no content error)
        location ~* /favicon\.ico$ {
            try_files $uri =204;
            expires max;
            log_not_found off;
            access_log off;
        }

  # Deny access to htaccess files
        location ~ /\. {
            deny all;
        }

  # Deny access to some bits wordpress leaves hanging around 
        location ~* /(wp-config.php|readme.html|license.txt|nginx.conf) {
            deny all;
        }

    # Deny access to .php files in the /wp-content/ directory (including sub-folders)
        location ~* ^/wp-content/.*.(php|phps)$ {
            deny all;
        }

    # Allow only internal access to .php files inside wp-includes directory
        location ~* ^/wp-includes/.*\.(php|phps)$ {
            internal;
        }

    # Deny access to specific files in the /wp-content/ directory (including sub-folders)
        location ~* ^/wp-content/.*.(txt|md|exe)$ {
            deny all;
        }

    # hide content of sensitive files
        location ~* \\.(conf|engine|inc|info|install|make|module|profile|test|po|sh|.*sql|theme|tpl(\\.php)?|xtmpl)\$|^(\\..*|Entries.*|Repository|Root|Tag|Template)\$|\\.php_ {
            deny all;
        }

    # don't allow other executable file types
        location ~* \\.(pl|cgi|py|sh|lua)\$ {
            deny all;
        }

    # hide the wordfence firewall
        location ~ ^/\.user\.ini {
            deny all;
        }
```

由于我们将`php.upstream`设置为变量，我们使用`template`模块来确保我们的配置包含正确的值，文件`roles/stack-config/templates/nginx-global-wordpress_shared.conf.j2`包含以下内容：

```
    # http://wiki.nginx.org/WordPress
    # This is cool because no php is touched for static content. 
    # Include the "?$args" part so non-default permalinks doesn't break when using query string
        location / {
            try_files $uri $uri/ /index.php?$args;
        }

        # Set the X-Frame-Options
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Xss-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;

    # Do not log + cache images, css, js, etc
        location ~* \.(ico|css|js|gif|jpeg|jpg|png|woff|ttf|otf|svg|woff2|eot)$ {
            expires max;
            log_not_found off;
            access_log off;
         # Send the all shebang in one fell swoop
            tcp_nodelay off;
        # Set the OS file cache
            open_file_cache max=1000 inactive=120s;
            open_file_cache_valid 45s;
            open_file_cache_min_uses 2;
            open_file_cache_errors off;
        }

    # Handle .php files
        location ~ \.php$ {
            try_files $uri =404;
            fastcgi_split_path_info ^(.+\.php)(/.+)$;
            include /etc/nginx/fastcgi_params;
            fastcgi_connect_timeout 180s;
            fastcgi_send_timeout 180s;
            fastcgi_read_timeout 180s;
            fastcgi_intercept_errors on;
            fastcgi_max_temp_file_size 0;
            fastcgi_pass {{ php.upstream }};
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_index index.php;
        }

    # Rewrite rules for WordPress SEO by Yoast
        rewrite ^/sitemap_index\.xml$ /index.php?sitemap=1 last;
        rewrite ^/([^/]+?)-sitemap([0-9]+)?\.xml$ /index.php?sitemap=$1&sitemap_n=$2 last;

    # Add trailing slash to */wp-admin requests
        rewrite /wp-admin$ $scheme://$host$uri/ permanent;
```

NGINX 配置的最后一部分是复制 WordPress 站点的主配置。`roles/stack-config/tasks/main.yml`中的任务如下所示：

```
- name: copy the default.conf to /etc/nginx/conf.d/
  template:
    src: "nginx-confd-default.conf.j2"
    dest: "/etc/nginx/conf.d/default.conf"
  notify: "restart nginx"
```

由于我们设置了一些变量，比如路径和域名，我们有以下模板文件：

```
# {{ ansible_managed }}

upstream php {
        server {{ php.ip }}:{{ php.port }};
}

server {
    listen 80;
  server_name {{ ansible_nodename }};
  root {{ wordpress_system.home }};
  index index.php;
  include global/restrictions.conf;
  include global/wordpress_shared.conf;
}
```

如您所见，我们正在使用一些尚未定义的变量，`php.ip`和`php.port`。我们将在接下来看如何配置 PHP-FPM。

# PHP 和 PHP-FPM 配置

正如我们在上一节中看到的，`roles/stack-config/defaults/main.yml`中为 PHP 定义了一些变量，它们是：

```
php:
  ip: "127.0.0.1"
  port: "9000"
  upstream: "php"
  ini:
    - { regexp: '^;date.timezone =', replace: 'date.timezone = Europe/London' }
    - { regexp: '^expose_php = On', replace: 'expose_php = Off' }
    - { regexp: '^upload_max_filesize = 2M', replace: 'upload_max_filesize = 20M' }
```

第一个配置任务是部署 PHP-FPM 配置；模板如下所示：

```
; {{ ansible_managed }}

[{{ wordpress_system.user }}]
user = {{ wordpress_system.user }}
group = {{ wordpress_system.group }}
listen = {{ php.ip }}:{{ php.port }}
listen.allowed_clients = {{ php.ip }}
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35
php_admin_value[error_log] = /var/log/php-fpm/{{ wordpress_system.user }}-error.log
php_admin_flag[log_errors] = on
php_value[session.save_handler] = files
php_value[session.save_path] = /var/lib/php/fpm/session
php_value[soap.wsdl_cache_dir] = /var/lib/php/fpm/wsdlcache
```

如您所见，我们在这个文件中进行了一些替换。从方括号之间开始，我们定义了 PHP-FPM 池名称；我们使用`wordpress_system.user`的内容。接下来，我们有我们希望池运行的用户和组；在这里，我们使用`wordpress_system.user`和`wordpress_system.group`。最后，我们通过使用`php.ip`和`php.port`变量来设置我们希望 PHP-FPM 池监听的 IP 地址和端口。

部署模板的`roles/stack-config/tasks/main.yml`任务如下所示：

```
- name: copy the www.conf to /etc/php-fpm.d/
  template:
    src: "php-fpmd-www.conf.j2"
    dest: "/etc/php-fpm.d/www.conf"
  notify: "restart php-fpm"
```

在**`roles/stack-config/handlers/main.yml`**中重新启动 PHP-FPM 的处理程序只是：

```
- name: "restart php-fpm"
  service:
    name: "php-fpm"
    state: "restarted"
    enabled: "yes"
```

`roles/stack-config/tasks/main.yml`中的下一个任务使用`lineinfile`模块：

```
- name: configure php.ini
  lineinfile: 
    dest: "/etc/php.ini"
    regexp: "{{ item.regexp }}"
    line: "{{ item.replace }}"
    backup: "yes"
    backrefs: "yes"
  with_items: "{{ php.ini }}"
  notify: "restart php-fpm"
```

我们在这里做的是获取`php.ini`的内容，并通过查找`regexp`键来循环遍历它。一旦找到值，我们就用`replace`键的内容替换它。如果文件有更改，我们首先进行`backup`，以防万一。此外，我们使用`backrefs`来确保如果文件中没有匹配的正则表达式，它将保持不变；如果我们不使用它们，那么每次运行 playbook 时都会调用`restart php-fpm`处理程序，而我们不希望在没有理由的情况下重新启动 PHP-FPM。

# 启动 NGINX 和 PHP-FPM

现在我们已经安装和配置了我们的堆栈，我们需要启动两个服务，而不是等到 playbook 运行结束。如果现在不这样做，我们即将安装 WordPress 的角色将失败。`roles/stack-config/tasks/main.yml`中的两个任务是：

```
- name: start php-fpm
  service:
    name: "php-fpm"
    state: "started"

- name: start nginx
  service:
    name: "nginx"
    state: "started"
```

# MariaDB 配置

MariaDB 配置将与上一章的配置非常相似，减去一些步骤，所以我不打算详细介绍。

该角色在`roles/stack-config/defaults/main.yml`中的默认变量为：

```
mariadb:
  bind: "127.0.0.1"
  server_config: "/etc/my.cnf.d/mariadb-server.cnf"
  username: "root"
  password: "Pa55W0rd123"
  hosts:
    - "127.0.0.1"
    - "::1"
    - "{{ ansible_nodename }}"
    - "localhost"
```

正如你所看到的，我们现在正在使用嵌套变量，并且已经在`roles/stack-config/tasks/main.yml`的任务的第一部分中删除了主机通配符`%`的根访问权限，将 MariaDB 绑定到本地主机：

```
- name: configure the mariadb bind address
  lineinfile: 
    dest: "{{ mariadb.server_config }}"
    regexp: "#bind-address=0.0.0.0"
    line: "bind-address={{ mariadb.bind }}"
    backup: "yes"
    backrefs: "yes"
```

从那里，我们开始 MariaDB，设置根密码，配置`~/.my.cnf`文件，然后删除匿名用户和测试数据库：

```
- name: start mariadb
  service:
    name: "mariadb"
    state: "started"
    enabled: "yes"

- name: change mysql root password
  mysql_user:
    name: "{{ mariadb.username }}" 
    host: "{{ item }}" 
    password: "{{ mariadb.password }}"
    check_implicit_admin: "yes"
    priv: "*.*:ALL,GRANT"
  with_items: "{{ mariadb.hosts }}"

- name: set up .my.cnf file
  template:
    src: "my.cnf.j2"
    dest: "~/.my.cnf"

- name: delete anonymous MySQL user
  mysql_user:
    user: ""
    host: "{{ item }}"
    state: "absent"
  with_items: "{{ mariadb.hosts }}"

- name: remove the MySQL test database
  mysql_db:
    db: "test" 
    state: "absent"
```

`.my.cnf`文件的模板，可以在`roles/stack-config/templates/my.cnf.j2`中找到，现在如下所示：

```
# {{ ansible_managed }}
[client]
password='{{ mariadb.password }}'
```

这意味着我们将不需要在每个与数据库相关的任务中传递根用户名和密码，从我们复制`.my.cnf`文件的地方开始。

# SELinux 配置

角色的最后一个任务是将 SELinux 中的 HTTP 设置为宽松模式；为了做到这一点，我们在`roles/stack-config/defaults/main.yml`中有以下变量：

```
selinux:
  http_permissive: true
```

`roles/stack-config/tasks/main.yml`中的任务有一个条件，如果`selinux.http_permissive`等于`true`，则运行：

```
- name: set the selinux allowing httpd_t to be permissive is required
  selinux_permissive:
    name: httpd_t
    permissive: true
  when: selinux.http_permissive == true
```

我们将在后面的章节更多地关注 SELinux；目前，我们只允许所有的 HTTP 请求。

# WordPress 安装任务

现在我们已经完成了准备目标 Vagrant 盒子的角色，我们可以继续进行实际的 WordPress 安装；这将分为几个不同的部分，首先是下载`wp_cli`和设置数据库。

在我们继续之前，我们应该创建角色：

```
$ ansible-galaxy init roles/wordpress
```

# WordPress CLI 安装

**WordPress CLI**（**WP-CLI**）是一个用于管理 WordPress 安装的命令行工具；我们将在整个角色中使用它，所以我们角色应该首先下载它。为了做到这一点，我们需要在`roles/wordpress/defaults/main.yml`中下载以下变量：

```
wp_cli:
  download: "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
  path: "/usr/local/bin/wp"
```

正如你可能从这两个变量中了解到的，我们将从`wp_cli.download`下载文件，并将其复制到`wp_cli.path`。在`roles/wordpress/tasks/main.yml`中执行此操作的任务如下：

```
- name: download wp-cli
  get_url:
    url: "{{ wp_cli.download }}"
    dest: "{{ wp_cli.path }}"

- name: update permissions of wp-cli to allow anyone to execute it
  file:
    path: "{{ wp_cli.path }}"
    mode: "0755"
```

正如你所看到的，我们正在下载`.phar`文件，移动它，然后设置权限，以便任何登录到服务器的人都可以执行它——这很重要，因为我们将以`wordpress`用户的身份运行许多安装命令。

# 创建 WordPress 数据库

角色的下一部分是创建我们的 WordPress 安装将使用的数据库；与本章其他任务一样，它使用了一个可以在`roles/wordpress/defaults/main.yml`中找到的嵌套变量：

```
wp_database:
  name: "wordpress"
  username: "wordpress"
  password: "W04DPr3S5"
```

在`roles/wordpress/tasks/main.yml`中创建数据库和用户的任务如下：

```
- name: create the wordpress database
  mysql_db:
    db: "{{ wp_database.name }}" 
    state: "present"

- name: create the user for the wordpress database
  mysql_user:
    name: "{{ wp_database.username }}"
    password: "{{ wp_database.password }}"
    priv: "{{ wp_database.name }}.*:ALL"
    state: "present"
  with_items: "{{ mariadb.hosts }}"
```

请注意我们正在使用前一个角色中的`mariadb.hosts`变量。现在我们已经创建了数据库，我们可以开始下载和安装 WordPress 了。

# 下载、配置和安装 WordPress

现在我们已经准备好安装 WordPress，我们可以开始了，首先在`roles/wordpress/defaults/main.yml`中设置一些默认变量：

```
wordpress:
  domain: "http://{{ ansible_nodename }}/"
  title: "WordPress installed by Ansible"
  username: "ansible"
  password: "password"
  email: "test@example.com"
  theme: "sydney"
  plugins:
    - "jetpack"
    - "wp-super-cache"
    - "wordpress-seo"
    - "wordfence"
    - "nginx-helper"
```

现在我们有了变量，如果需要，我们可以开始下载：

```
- name: are the wordpress files already there?
  stat:
    path: "{{ wordpress_system.home }}/index.php"
  register: wp_installed

- name: download wordpresss
  shell: "{{ wp_cli.path }} core download"
  args:
    chdir: "{{ wordpress_system.home }}"
  become_user: "{{ wordpress_system.user }}"
  become: true
  when: wp_installed.stat.exists == False
```

正如你所看到的，第一个任务使用`stat`模块来检查系统用户的主目录（也是 webroot）中是否存在`index.php`。第二个任务使用`shell`模块来执行`wp core download`命令。

在继续下一个任务之前，我们应该处理一些参数。这些是：

+   `args`和`chdir`：您可以使用`args`向`shell`模块传递额外的参数。在这里，我们传递`chdir`，它指示 Ansible 在运行我们提供的`shell`命令之前切换到我们指定的目录。

+   `become_user`：我们希望以哪个用户的身份运行命令。如果我们不使用这个，命令将以 root 用户的身份运行。

+   `become`：这指示 Ansible 以定义的用户身份执行任务。

剧本中的下一个任务设置了用户主目录的正确权限：

```
- name: set the correct permissions on the homedir
  file:
    path: "{{ wordpress_system.home }}"
    mode: "0755"
  when: wp_installed.stat.exists == False
```

现在 WordPress 已经下载，我们可以开始安装。首先，我们需要检查是否已经完成了这一步：

```
- name: is wordpress already configured?
  stat:
    path: "{{ wordpress_system.home }}/wp-config.php"
  register: wp_configured
```

如果没有`wp-config.php`文件，那么将执行以下任务：

```
- name: configure wordpress
  shell: "{{ wp_cli.path }} core config --dbhost={{ mariadb.bind }} --dbname={{ wp_database.name }} --dbuser={{ wp_database.username }} --dbpass={{ wp_database.password }}"
  args:
    chdir: "{{ wordpress_system.home }}"
  become_user: "{{ wordpress_system.user }}"
  become: true
  when: wp_configured.stat.exists == False
```

现在我们已经创建了`wp-config.php`文件，并且数据库凭据已经就位，我们可以安装 WordPress 了。首先，我们需要检查 WordPress 是否已经安装：

```
- name: do we need to install wordpress?
  shell: "{{ wp_cli.path }} core is-installed"
  args:
    chdir: "{{ wordpress_system.home }}"
  become_user: "{{ wordpress_system.user }}"
  become: true
  ignore_errors: yes
  register: wp_installed
```

正如你从`ignore_errors`选项的存在可以看出，如果 WordPress 未安装，这个命令将给我们一个错误。然后我们利用这一点来注册结果，正如你从下面的任务中可以看到的：

```
- name: install wordpress if needed
  shell: "{{ wp_cli.path }} core install --url='{{ wordpress.domain }}' --title='{{ wordpress.title }}' --admin_user={{ wordpress.username }} --admin_password={{ wordpress.password }} --admin_email={{ wordpress.email }}"
  args:
    chdir: "{{ wordpress_system.home }}"
  become_user: "{{ wordpress_system.user }}"
  become: true
  when: wp_installed.rc == 1
```

现在我们已经安装了一个基本的 WordPress 网站，我们可以继续安装插件和主题文件。

# WordPress 插件和主题安装

我们 WordPress 安装的最后一部分是下载和安装我们在`wordpress.plugins`和`wordpress.theme`变量中定义的插件和主题文件。

让我们从安装插件的任务开始，这样我们就不会重新运行安装插件的任务。当需要时，我们将在任务中构建一些逻辑。首先，我们运行一个任务来查看所有插件是否已经安装：

```
- name: do we need to install the plugins?
  shell: "{{ wp_cli.path }} plugin is-installed {{ item }}"
  args:
    chdir: "{{ wordpress_system.home }}"
  become_user: "{{ wordpress_system.user }}"
  become: true
  with_items: "{{ wordpress.plugins }}"
  ignore_errors: yes
  register: wp_plugin_installed
```

如果插件未安装，则此任务应该失败，这就是为什么我们在其中使用`ignore_errors`的原因。正如你所看到的，我们正在注册整个任务的结果，因为如果你记得，我们正在安装几个插件，作为`wp_plugin_installed`。接下来的两个任务获取`wp_plugin_installed`的结果，并使用`setfact`模块设置一个事实：

```
- name: set a fact if we don't need to install the plugins
  set_fact:
    wp_plugin_installed_skip: true
  when: wp_plugin_installed.failed is undefined

- name: set a fact if we need to install the plugins
  set_fact:
    wp_plugin_installed_skip: false
  when: wp_plugin_installed.failed is defined
```

正如你所看到的，我们将`wp_theme_installed_skip`设置为`true`或`false`：如果事实设置为`false`，那么接下来的任务将循环安装插件：

```
- name: install the plugins if we need to or ignore if not
  shell: "{{ wp_cli.path }} plugin install {{ item }} --activate"
  args:
    chdir: "{{ wordpress_system.home }}"
  become_user: "{{ wordpress_system.user }}"
  become: true
  with_items: "{{ wordpress.plugins }}"
  when: wp_plugin_installed_skip == false
```

如果我们将另一个插件添加到列表中，但保留其他插件不变，它将显示一个错误，导致插件被安装。我们将使用相同的逻辑来判断我们是否需要安装我们定义为`wordpress.theme`的主题文件：

```
- name: do we need to install the theme?
  shell: "{{ wp_cli.path }} theme is-installed {{ wordpress.theme }}"
  args:
    chdir: "{{ wordpress_system.home }}"
  become_user: "{{ wordpress_system.user }}"
  become: true
  ignore_errors: yes
  register: wp_theme_installed

- name: set a fact if we don't need to install the theme
  set_fact:
    wp_theme_installed_skip: true
  when: wp_theme_installed.failed == false

- name: set a fact if we need to install the theme
  set_fact:
    wp_theme_installed_skip: false
  when: wp_theme_installed.failed == true

- name: install the theme if we need to or ignore if not
  shell: "{{ wp_cli.path }} theme install {{ wordpress.theme }} --activate"
  args:
    chdir: "{{ wordpress_system.home }}"
  become_user: "{{ wordpress_system.user }}"
  become: true
  when: wp_theme_installed_skip == false
```

现在我们已经安装了插件和主题，可以尝试运行我们的 playbook 了。

# 运行 WordPress playbook

要运行 playbook 并安装 WordPress，我们需要一些东西，首先是名为`production`的清单文件：

```
box1 ansible_host=192.168.50.5.nip.io

[wordpress]
box1

[wordpress:vars]
ansible_connection=ssh
ansible_user=vagrant
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

正如你所看到的，它考虑了我们在本章开头定义的 Vagrant box 的更新后 IP 地址。另外，我们需要 playbook 本身；`site.yml`应该如下所示：

```
---

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

现在，通过运行以下两个命令之一来启动 Vagrant box：

```
$ vagrant up
$ vagrant up --provider=vmware_fusion
```

一旦你的 Vagrant box 启动并运行，我们可以使用以下命令开始 playbook 运行：

```
$ ansible-playbook -i production site.yml
```

当首次执行 playbook 时，你应该看到类似以下结果的内容：

```
PLAY [wordpress] ***********************************************************************************

TASK [Gathering Facts] *****************************************************************************
ok: [box1]

TASK [roles/stack-install : install the repo packages] *********************************************
changed: [box1] => (item=[u'epel-release', u'https://centos7.iuscommunity.org/ius-release.rpm'])

TASK [roles/stack-install : add the NGINX mainline repo] *******************************************
changed: [box1]

TASK [roles/stack-install : update all of the installed packages] **********************************
changed: [box1]

TASK [roles/stack-install : remove the packages so that they can be replaced] **********************
changed: [box1] => (item=[u'mariadb-libs.x86_64'])

TASK [roles/stack-install : install the stack packages] ********************************************
changed: [box1] => (item=[u'postfix', u'MySQL-python', u'policycoreutils-python', u'nginx', u'mariadb101u', u'mariadb101u-server', u'mariadb101u-config', u'mariadb101u-common', u'mariadb101u-libs', u'php72u', u'php72u-bcmath', u'php72u-cli', u'php72u-common', u'php72u-dba', u'php72u-fpm', u'php72u-fpm-nginx', u'php72u-gd', u'php72u-intl', u'php72u-json', u'php72u-mbstring', u'php72u-mysqlnd', u'php72u-process', u'php72u-snmp', u'php72u-soap', u'php72u-xml', u'php72u-xmlrpc', u'vim-enhanced', u'git', u'unzip'])

TASK [roles/stack-config : add the wordpress user] *************************************************
changed: [box1]

TASK [roles/stack-config : copy the nginx.conf to /etc/nginx/] *************************************
changed: [box1]

TASK [roles/stack-config : create the global directory in /etc/nginx/] *****************************
changed: [box1]

TASK [roles/stack-config : copy the restrictions.conf to /etc/nginx/global/] ***********************
changed: [box1]

TASK [roles/stack-config : copy the wordpress_shared.conf to /etc/nginx/global/] *******************
changed: [box1]

TASK [roles/stack-config : copy the default.conf to /etc/nginx/conf.d/] ****************************
changed: [box1]

TASK [roles/stack-config : copy the www.conf to /etc/php-fpm.d/] ***********************************
changed: [box1]

TASK [roles/stack-config : configure php.ini] ******************************************************
changed: [box1] => (item={u'regexp': u'^;date.timezone =', u'replace': u'date.timezone = Europe/London'})
changed: [box1] => (item={u'regexp': u'^expose_php = On', u'replace': u'expose_php = Off'})
changed: [box1] => (item={u'regexp': u'^upload_max_filesize = 2M', u'replace': u'upload_max_filesize = 20M'})

TASK [roles/stack-config : start php-fpm] **********************************************************
changed: [box1]

TASK [roles/stack-config : start nginx] ************************************************************
changed: [box1]

TASK [roles/stack-config : configure the mariadb bind address] *************************************
changed: [box1]

TASK [roles/stack-config : start mariadb] **********************************************************
changed: [box1]

TASK [roles/stack-config : change mysql root password] *********************************************
changed: [box1] => (item=127.0.0.1)
changed: [box1] => (item=::1)
changed: [box1] => (item=192.168.50.5.nip.io)
changed: [box1] => (item=localhost)

TASK [roles/stack-config : set up .my.cnf file] ****************************************************
changed: [box1]

TASK [roles/stack-config : delete anonymous MySQL user] ********************************************
ok: [box1] => (item=127.0.0.1)
ok: [box1] => (item=::1)
changed: [box1] => (item=192.168.50.5.nip.io)
changed: [box1] => (item=localhost)

TASK [roles/stack-config : remove the MySQL test database] *****************************************
changed: [box1]

TASK [roles/stack-config : set the selinux allowing httpd_t to be permissive is required] **********
changed: [box1]

TASK [roles/wordpress : download wp-cli] ***********************************************************
changed: [box1]

TASK [roles/wordpress : update permissions of wp-cli to allow anyone to execute it] ****************
changed: [box1]

TASK [roles/wordpress : create the wordpress database] *********************************************
changed: [box1]

TASK [roles/wordpress : create the user for the wordpress database] ********************************
changed: [box1] => (item=127.0.0.1)
ok: [box1] => (item=::1)
ok: [box1] => (item=192.168.50.5.nip.io)
ok: [box1] => (item=localhost)

TASK [roles/wordpress : are the wordpress files already there?] ************************************
ok: [box1]

TASK [roles/wordpress : download wordpresss] *******************************************************
changed: [box1]

TASK [roles/wordpress : set the correct permissions on the homedir] ********************************
changed: [box1]

TASK [roles/wordpress : is wordpress already configured?] ******************************************
ok: [box1]

TASK [roles/wordpress : configure wordpress] *******************************************************
changed: [box1]

TASK [roles/wordpress : do we need to install wordpress?] ******************************************
fatal: [box1]: FAILED! => {"changed": true, "cmd": "/usr/local/bin/wp core is-installed", "delta": "0:00:00.364987", "end": "2018-03-04 20:22:16.659411", "msg": "non-zero return code", "rc": 1, "start": "2018-03-04 20:22:16.294424", "stderr": "", "stderr_lines": [], "stdout": "", "stdout_lines": []}
...ignoring

TASK [roles/wordpress : install wordpress if needed] ***********************************************
changed: [box1]

TASK [roles/wordpress : do we need to install the plugins?] ****************************************
failed: [box1] (item=jetpack) => {"changed": true, "cmd": "/usr/local/bin/wp plugin is-installed jetpack", "delta": "0:00:01.366121", "end": "2018-03-04 20:22:20.175418", "item": "jetpack", "msg": "non-zero return code", "rc": 1, "start": "2018-03-04 20:22:18.809297", "stderr": "", "stderr_lines": [], "stdout": "", "stdout_lines": []}
failed: [box1] (item=wp-super-cache) => {"changed": true, "cmd": "/usr/local/bin/wp plugin is-installed wp-super-cache", "delta": "0:00:00.380384", "end": "2018-03-04 20:22:21.035274", "item": "wp-super-cache", "msg": "non-zero return code", "rc": 1, "start": "2018-03-04 20:22:20.654890", "stderr": "", "stderr_lines": [], "stdout": "", "stdout_lines": []}
failed: [box1] (item=wordpress-seo) => {"changed": true, "cmd": "/usr/local/bin/wp plugin is-installed wordpress-seo", "delta": "0:00:00.354021", "end": "2018-03-04 20:22:21.852955", "item": "wordpress-seo", "msg": "non-zero return code", "rc": 1, "start": "2018-03-04 20:22:21.498934", "stderr": "", "stderr_lines": [], "stdout": "", "stdout_lines": []}
failed: [box1] (item=wordfence) => {"changed": true, "cmd": "/usr/local/bin/wp plugin is-installed wordfence", "delta": "0:00:00.357012", "end": "2018-03-04 20:22:22.673549", "item": "wordfence", "msg": "non-zero return code", "rc": 1, "start": "2018-03-04 20:22:22.316537", "stderr": "", "stderr_lines": [], "stdout": "", "stdout_lines": []}
failed: [box1] (item=nginx-helper) => {"changed": true, "cmd": "/usr/local/bin/wp plugin is-installed nginx-helper", "delta": "0:00:00.346194", "end": "2018-03-04 20:22:23.389176", "item": "nginx-helper", "msg": "non-zero return code", "rc": 1, "start": "2018-03-04 20:22:23.042982", "stderr": "", "stderr_lines": [], "stdout": "", "stdout_lines": []}
...ignoring

TASK [roles/wordpress : set a fact if we don't need to install the plugins] ************************
skipping: [box1]

TASK [roles/wordpress : set a fact if we need to install the plugins] ******************************
ok: [box1]

TASK [roles/wordpress : install the plugins if we need to or ignore if not] ************************
changed: [box1] => (item=jetpack)
changed: [box1] => (item=wp-super-cache)
changed: [box1] => (item=wordpress-seo)
changed: [box1] => (item=wordfence)
changed: [box1] => (item=nginx-helper)

TASK [roles/wordpress : do we need to install the theme?] ******************************************
fatal: [box1]: FAILED! => {"changed": true, "cmd": "/usr/local/bin/wp theme is-installed sydney", "delta": "0:00:01.451018", "end": "2018-03-04 20:23:02.227557", "msg": "non-zero return code", "rc": 1, "start": "2018-03-04 20:23:00.776539", "stderr": "", "stderr_lines": [], "stdout": "", "stdout_lines": []}
...ignoring

TASK [roles/wordpress : set a fact if we don't need to install the theme] **************************
skipping: [box1]

TASK [roles/wordpress : set a fact if we need to install the theme] ********************************
ok: [box1]

TASK [roles/wordpress : install the theme if we need to or ignore if not] **************************
changed: [box1]

RUNNING HANDLER [roles/stack-config : restart nginx] ***********************************************
changed: [box1]

RUNNING HANDLER [roles/stack-config : restart php-fpm] *********************************************
changed: [box1]

PLAY RECAP *****************************************************************************************
box1 : ok=42 changed=37 unreachable=0 failed=0
```

正如你在 playbook 中所看到的，我们对检查是否需要安装 WordPress 以及插件和主题检查都有致命错误，因为我们在任务中已经考虑到了这些情况，playbook 正常运行并安装了软件堆栈、WordPress、插件和主题。

重新运行 playbook 会给我们之前出错的部分带来以下结果：

```
TASK [roles/wordpress : do we need to install wordpress?] ******************************************
changed: [box1]

TASK [roles/wordpress : install wordpress if needed] ***********************************************
skipping: [box1]

TASK [roles/wordpress : do we need to install the plugins?] ****************************************
changed: [box1] => (item=jetpack)
changed: [box1] => (item=wp-super-cache)
changed: [box1] => (item=wordpress-seo)
changed: [box1] => (item=wordfence)
changed: [box1] => (item=nginx-helper)

TASK [roles/wordpress : set a fact if we don't need to install the plugins] ************************
ok: [box1]

TASK [roles/wordpress : set a fact if we need to install the plugins] ******************************
skipping: [box1]

TASK [roles/wordpress : install the plugins if we need to or ignore if not] ************************
skipping: [box1] => (item=jetpack)
skipping: [box1] => (item=wp-super-cache)
skipping: [box1] => (item=wordpress-seo)
skipping: [box1] => (item=wordfence)
skipping: [box1] => (item=nginx-helper)

TASK [roles/wordpress : do we need to install the theme?] ******************************************
changed: [box1]

TASK [roles/wordpress : set a fact if we don't need to install the theme] **************************
ok: [box1]

TASK [roles/wordpress : set a fact if we need to install the theme] ********************************
skipping: [box1]

TASK [roles/wordpress : install the theme if we need to or ignore if not] **************************
skipping: [box1]

PLAY RECAP *****************************************************************************************
box1 : ok=34 changed=3 unreachable=0 failed=0
```

现在 WordPress 已经安装，我们应该能够通过浏览器访问`http://192.168.50.5.nip.io/`。正如你在这里所看到的，我们定义的主题正在运行，而不是 WordPress 默认主题：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/ec278635-7e4c-4990-8332-6cc6f14e3c40.png)

另外，如果你去`http://192.168.50.5.nip.io/wp-admin/`，你应该能够使用我们定义的用户名和密码登录 WordPress：

+   用户名：`ansible`

+   密码：`密码`

登录后，你应该会看到一些关于我们在 playbook 运行期间安装的插件需要配置的消息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/7cc6369b-51f5-4525-ad38-0eada8f26699.png)

随意尝试使用 WordPress 安装；另外，你可以通过运行以下命令来删除 Vagrant box：

```
$ vagrant destroy
```

然后启动一个新的副本，并使用本节开头的命令重新部署它。

# 总结

在本章中，我们已经重复使用了我们在上一章中介绍的许多原则，并开始部署一个完整的应用程序。好处在于这个过程既可重复又只需一个命令。

到目前为止，我们一直在针对 CentOS 7 Vagrant box。如果我们对 Ubuntu Vagrant box 运行我们的 playbook，playbook 将会出错。在下一章中，我们将看看如何使用相同的 playbook 来针对多个操作系统。

# 问题

1.  在`setup`模块执行期间收集的哪个事实可以告诉我们的 playbook 目标主机有多少处理器？

1.  使用`lineinfile`模块中的`backref`是否确保如果正则表达式不匹配则不会应用任何更改。

1.  解释为什么我们希望在 playbook 中构建逻辑来检查 WordPress 是否已经安装。

1.  我们使用哪个模块来定义作为 playbook 运行一部分的变量？

1.  我们传递给`shell`模块的哪个参数可以让我们想要运行的命令在我们选择的目录中执行？

1.  真或假：将 MariaDB 设置为绑定到`127.0.0.1`将允许我们从外部访问它。

1.  将您的 WordPress 网站主题更改为您选择的主题；请参阅[`wordpress.org/themes/`](https://wordpress.org/themes/)以获取一些选项。

# 进一步阅读

您可以在以下链接找到有关本章涵盖的技术的更多信息：

+   **NGINX**: [`nginx.org/`](http://nginx.org/)

+   **WordPress**: [`wordpress.org/`](https://wordpress.org/)

+   **WP-CLI**: [`wp-cli.org`](http://wp-cli.org)

+   **BuiltWith 的 CMS 统计数据**：[`trends.builtwith.com/cms`](https://trends.builtwith.com/cms)

+   **WordPress NGINX Codex**: [`codex.wordpress.org/Nginx`](https://codex.wordpress.org/Nginx)

+   **悉尼 WordPress 主题**：[`en-gb.wordpress.org/themes/sydney/`](https://en-gb.wordpress.org/themes/sydney/)

我们安装的插件的项目页面可以在以下位置找到：

+   **Jetpack**: [`en-gb.wordpress.org/plugins/jetpack/`](https://en-gb.wordpress.org/plugins/jetpack/)

+   **WP Super Cache**: [`en-gb.wordpress.org/plugins/wp-super-cache/`](https://en-gb.wordpress.org/plugins/wp-super-cache/)

+   **Yoast SEO**: [`en-gb.wordpress.org/plugins/wordpress-seo/`](https://en-gb.wordpress.org/plugins/wordpress-seo/)

+   **Wordfence**: [`en-gb.wordpress.org/plugins/wordfence/`](https://en-gb.wordpress.org/plugins/wordfence/)

+   **NGINX Helper**: [`wordpress.org/plugins/nginx-helper/`](https://wordpress.org/plugins/nginx-helper/)


# 第六章：针对多个发行版

正如上一章末尾提到的，到目前为止，我们一直在针对单个操作系统使用我们的 playbook。如果我们只打算针对 CentOS 7 主机运行我们的 playbook，那是很好的，但情况可能并非总是如此。

在本章中，我们将看看如何调整我们的 WordPress 安装 playbook 以针对 Ubuntu 17.04 服务器实例。

在本章中，我们将：

+   查看并实施操作系统相关的核心模块

+   讨论并应用针对多个发行版的最佳实践

+   看看如何使用 Ansible 清单来针对多个主机

# 技术要求

在本章中，我们将启动两个 Vagrant 盒子，所以你需要安装 Vagrant 并且能够访问互联网；这些盒子本身大约每个下载 300 到 500MB。

如果你要跟着做，适应我们的角色，你需要从上一章复制`lemp`文件夹并将其命名为`lemp-multi`。如果你不跟着做，你可以在[`github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter06/lemp-multi`](https://github.com/PacktPublishing/Learn-Ansible/tree/master/Chapter06/lemp-multi)找到`lemp-multi`的完整版本。

# 启动多个 Vagrant 盒子

在我们开始查看我们需要对 Ansible playbook 进行的更改之前，我们应该看看我们将如何同时启动两个运行不同操作系统的 Vagrant 盒子。可以从单个`Vagrantfile`启动两个 Vagrant 盒子；我们将使用以下一个：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

API_VERSION = "2"
DOMAIN      = "nip.io"
PRIVATE_KEY = "~/.ssh/id_rsa"
PUBLIC_KEY  = '~/.ssh/id_rsa.pub'
CENTOS_IP   = '192.168.50.6'
CENTOS_BOX  = 'centos/7'
UBUNTU_IP   = '192.168.50.7'
UBUNTU_BOX  = 'generic/ubuntu1704'

Vagrant.configure(API_VERSION) do |config|

  config.vm.define "centos" do |centos|
      centos.vm.box = CENTOS_BOX
      centos.vm.network "private_network", ip: CENTOS_IP
      centos.vm.host_name = CENTOS_IP + '.' + DOMAIN
      centos.ssh.insert_key = false
      centos.ssh.private_key_path = [PRIVATE_KEY,
      "~/.vagrant.d/insecure_private_key"]
      centos.vm.provision "file", source: PUBLIC_KEY, destination:
      "~/.ssh/authorized_keys"

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
      ubuntu.ssh.private_key_path = [PRIVATE_KEY,
      "~/.vagrant.d/insecure_private_key"]
      ubuntu.vm.provision "file", source: PUBLIC_KEY, destination:
      "~/.ssh/authorized_keys"

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

正如你所看到的，我们定义了两个不同的盒子，一个叫做`centos`，另一个叫做`ubuntu`，你应该用之前复制的`lemp`文件夹中的`Vagrantfile`替换它。

我们可以使用一个命令启动两台机器；要使用 VirtualBox，我们应该运行：

```
$ vagrant up 
```

或者要使用 VMware，我们可以运行：

```
$ vagrant up --provider=vmware_fusion
```

正如你从这里的终端输出中看到的，这启动了两个盒子：

```
Bringing machine 'centos' up with 'vmware_fusion' provider...
Bringing machine 'ubuntu' up with 'vmware_fusion' provider...
==> centos: Cloning VMware VM: 'centos/7'. This can take some time...
==> centos: Checking if box 'centos/7' is up to date...
==> centos: Verifying vmnet devices are healthy...
==> centos: Preparing network adapters...
==> centos: Starting the VMware VM...
==> centos: Waiting for the VM to receive an address...
==> centos: Forwarding ports...
 centos: -- 22 => 2222
==> centos: Waiting for machine to boot. This may take a few minutes...
 centos: SSH address: 127.0.0.1:2222
 centos: SSH username: vagrant
 centos: SSH auth method: private key
==> centos: Machine booted and ready!
==> centos: Setting hostname...
==> centos: Configuring network adapters within the VM...
 centos: SSH address: 127.0.0.1:2222
 centos: SSH username: vagrant
 centos: SSH auth method: private key
==> centos: Rsyncing folder: /Users/russ/lemp/ => /vagrant
==> centos: Running provisioner: file...
==> ubuntu: Cloning VMware VM: 'generic/ubuntu1704'. This can take some time...
==> ubuntu: Checking if box 'generic/ubuntu1704' is up to date...
==> ubuntu: Verifying vmnet devices are healthy...
==> ubuntu: Preparing network adapters...
==> ubuntu: Starting the VMware VM...
==> ubuntu: Waiting for the VM to receive an address...
==> ubuntu: Forwarding ports...
 ubuntu: -- 22 => 2222
==> ubuntu: Waiting for machine to boot. This may take a few minutes...
 ubuntu: SSH address: 127.0.0.1:2222
 ubuntu: SSH username: vagrant
 ubuntu: SSH auth method: private key
==> ubuntu: Machine booted and ready!
==> ubuntu: Setting hostname...
==> ubuntu: Configuring network adapters within the VM...
==> ubuntu: Running provisioner: file...
```

一旦盒子启动并运行，你可以使用机器名称 SSH 连接到它们：

```
$ vagrant ssh centos
$ vagrant ssh ubuntu
```

现在我们有两个运行在两个不同操作系统上的盒子，我们可以讨论我们需要对 playbook 进行的更改。首先，让我们看看对`Vagrantfile`的更改将如何影响我们的主机清单文件，正如你可以从这个文件中看到的那样：

```
centos ansible_host=192.168.50.6.nip.io 
ubuntu ansible_host=192.168.50.7.nip.io

[wordpress]
centos
ubuntu

[wordpress:vars]
ansible_connection=ssh
ansible_user=vagrant
ansible_private_key_file=~/.ssh/id_rsa
host_key_checking=False
```

现在我们有两个主机，一个叫做`centos`，另一个叫做`ubuntu`，我们将它们放在一个名为`wordpress`的组中，我们在那里设置一些公共变量。你应该更新你的`production`文件，因为我们将在下一节中使用它。

# 多操作系统考虑

查看在三个角色`stack-install`、`stack-config`和`wordpress`中使用的每个核心 Ansible 模块，我们使用了一些在我们新引入的 Ubuntu 盒子上不起作用的模块。让我们快速地逐个进行，并看看在针对两个非常不同的操作系统时需要考虑什么：

+   `yum`：`yum`模块是 Red Hat 系机器（如 CentOS）使用的包管理器，而 Ubuntu 基于 Debian，使用`apt`。我们需要拆分出使用`yum`模块的 playbook 的部分，以使用`apt`模块代替。

+   `yum_repository`：如前所述，我们将需要使用一个`apt`等效模块，即`apt_repository`。

+   `user`：`user`模块在两个操作系统上基本上是一样的，因为我们没有给我们的用户提升的特权。除了确保正确的组可用之外，我们没有任何特殊的考虑。

+   `template`、`file`、`copy`和`lineinfile`：这四个模块都将按预期工作；我们需要考虑的唯一问题是检查我们是否将文件复制到了盒子上的正确位置。

+   `service`：服务模块在两个操作系统上应该是一样的，所以我们应该没问题。

+   `mysql_user`和`mysql_db`：正如你所期望的，一旦 MySQL 安装并启动，这两个都将在两个操作系统上工作。

+   `selinux_permissive`：SELinux 主要用于基于 Red Hat 的操作系统，因此我们需要找到替代方案。

+   `get_url`、`stat`、`shell`和`set_fact`：这些应该在我们的目标操作系统上都能一致工作。

现在我们知道了在 Ubuntu 上运行与在 CentOS 上运行时需要审查现有 playbook 的哪些部分，我们可以开始让我们的角色在这两个操作系统上都能工作。

# 调整角色

那么我们如何在我们的角色中构建逻辑，只在不同的操作系统上执行角色的某些部分，而且我们也知道软件包名称会不同？我们如何为每个操作系统定义不同的变量集？

# 操作系统家族

我们在之前的章节中已经看过`setup`模块；这是一个收集有关我们目标主机的事实的模块。其中一个事实就是`ansible_os_family`；这告诉我们我们正在运行的操作系统类型。让我们在我们的两个主机上检查一下：

```
$ ansible -i production centos -m setup | grep ansible_os_family
$ ansible -i production ubuntu -m setup | grep ansible_os_family
```

正如你从以下终端输出中所看到的，CentOS 主机返回了 Red Hat，这是预期的。然而，Ubuntu 主机没有返回任何信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/7c8406e2-020d-43e1-a04c-7b7619cad888.png)

让我们看看为什么会这样。首先，我们可以重新运行命令，但这次去掉`grep`，这样我们就可以看到完整的输出：

```
$ ansible -i production ubuntu -m setup
```

这应该给你类似以下的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/de2eeb93-5e27-4e48-8cee-4b1d12533a27.png)

哦，我们出现了一个错误。为什么它报告没有安装 Python？运行以下命令将 SSH 到该服务器：

```
$ vagrant ssh ubuntu
```

使用 SSH 登录后，运行`which python`将显示 Python 二进制文件的路径。正如你所看到的，由于没有返回路径，所以没有安装。那 Python 3 呢？运行`which python3`确实返回了一个二进制文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/86d18150-7b81-4a08-83eb-215806581388.png)

通过运行`exit`来关闭我们的 SSH 会话。

我们应该怎么办？由于我们运行的 Ansible 版本晚于 2.2，我们可以告诉 Ansible 使用`/usr/bin/python3`而不是默认的`/usr/bin/python`。为此，我们需要更新我们的主机清单文件，以便只有 Ubuntu 主机添加`ansible_python_interpreter`变量以及更新后的路径。

有几种方法可以实现这一点；然而，现在，让我们只更新`production`主机清单文件中的以下行：

```
ubuntu ansible_host=192.168.50.7.nip.io
```

因此，它的读法如下：

```
ubuntu ansible_host=192.168.50.7.nip.io ansible_python_interpreter=/usr/bin/python3
```

更新后，我们应该能够运行以下命令：

```
$ ansible -i production wordpress -m setup | grep ansible_os_family 
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/f74756fe-258e-4e9b-b72b-ec3925f3ca78.png)

正如你所看到的，我们正在针对`wordpress`主机组，其中包含我们的两个主机，并且预期地，CentOS 主机返回`RedHat`，而 Ubuntu 主机现在返回`Debian`。现在我们已经有了一种识别每个主机上使用的操作系统的方法，我们可以开始调整角色。

# stack-install 角色

正如你可能已经猜到的，这个角色的大部分内容只是调用`yum`相关模块的任务，我们已经提到这将会改变。

我们要查看的角色的第一部分是`roles/stack-install/tasks/main.yml`文件的内容。目前，该文件包含使用`yum`和`yum_repository`模块安装我们期望的仓库和软件包的任务。

我们需要更新文件，但首先，将现有内容另存为名为`roles/stack-install/tasks/install-centos.yml`的文件。一旦你复制了内容，更新`roles/stack-install/tasks/main.yml`，使其包含这些内容：

```
---

- name: include the operating system specific variables
  include_vars: "{{ ansible_os_family }}.yml"

- name: install the stack on centos
  import_tasks: install-centos.yml
  when: ansible_os_family == 'RedHat'

- name: install the stack on ubuntu
  import_tasks: install-ubuntu.yml
  when: ansible_os_family == 'Debian'
```

正如你所看到的，我们正在使用`ansible_os_family`变量来包含变量和不同的任务。

该任务将包括以下文件之一，具体取决于任务在哪个操作系统上执行：

+   `roles/stack-install/vars/RedHat.yml`

+   `roles/stack-install/vars/Debian.yml`

然后它将包含以下两个文件中的一个，这些文件包含了操作系统的任务：

+   `install-centos.yml`

+   `install-ubuntu.yml`

我们已经知道`install-centos.yml`包含了我们的`main.yml`文件的旧内容；由于软件包名称和仓库 URL 也将发生变化，我们应该将`roles/stack-install/default/main.yml`的内容移动到`roles/stack-install/vars/RedHat.yml`，并将`roles/stack-install/default/main.yml`留空。

现在我们已经定义了角色的 CentOS 部分，我们可以看一下 Ubuntu 部分，从`roles/stack-install/vars/Debian.yml`的内容开始：

```
---

repo_packages:
  - "deb [arch=amd64,i386] http://mirror.sax.uk.as61049.net/mariadb/repo/10.1/ubuntu {{ ansible_distribution_release }} main"
  - "deb http://nginx.org/packages/mainline/ubuntu/ {{ ansible_distribution_release }} nginx"
  - "deb-src http://nginx.org/packages/mainline/ubuntu/ {{ ansible_distribution_release }} nginx"

repo_keys:
  - { key_server: "keyserver.ubuntu.com", key: "0xF1656F24C74CD1D8" }

repo_keys_url:
  - "http://nginx.org/keys/nginx_signing.key"

system_packages:
  - "software-properties-common"
  - "python3-mysqldb"
  - "acl"

stack_packages:
  - "nginx"
  - "mariadb-server"
  - "php7.0"
  - "php7.0-cli"
  - "php7.0-fpm"
  - "php7.0-gd"
  - "php7.0-json"
  - "php7.0-mbstring"
  - "php7.0-mysqlnd"
  - "php7.0-soap"
  - "php7.0-xml"
  - "php7.0-xmlrpc"

extra_packages:
  - "vim"
  - "git"
  - "unzip"
```

正如你所看到的，虽然我们保留了`system_packages`，`stack_packages`和`extra_packages`变量，但其中包含了不同的软件包名称。在`repo_packages`中也有类似的情况，我们更新了 URL，因为 CentOS 仓库将无法在 Ubuntu 上使用。最后，我们引入了两个新变量，`repo_keys`和`repo_keys_urls`；我们很快将看到这些变量的用途。

我们需要处理的最后一个文件是`roles/stack-install/tasks/install-ubuntu.yml`。和`install-centos.yml`一样，这个文件包含了我们需要添加的额外仓库和安装软件包的任务。

首先，我们需要安装一些我们继续进行其余任务所需的工具；这些工具已经在`system_packages`变量中定义，所以我们只需要添加以下任务：

```
- name: update cache and install the system packages
  apt:
    name: "{{ item }}"
    update_cache: "yes"
  with_items: "{{ system_packages }}"
```

现在我们已经安装了基本的先决条件，我们可以为我们将要添加的仓库添加密钥：

```
- name: add the apt keys from a key server
  apt_key:
    keyserver: "{{ item.key_server }}"
    id: "{{ item.key }}"
  with_items: "{{ repo_keys }}"

- name: add the apt keys from a URL
  apt_key:
    url: "{{ item }}"
    state: present
  with_items: "{{ repo_keys_url }}"
```

第一个任务从官方 Ubuntu 密钥存储中添加密钥，第二个任务从 URL 下载密钥。在我们的情况下，我们为官方 MariaDB 仓库添加了一个密钥，为 NGINX 主线仓库添加了一个密钥；如果没有这些密钥，我们将无法添加仓库，会出现关于不受信任的错误。

添加仓库的任务如下；它循环遍历`repo_packages`变量中的仓库 URL：

```
- name: install the repo packages
  apt_repository:
    repo: "{{ item }}"
    state: "present"
    update_cache: "yes"
  with_items: "{{ repo_packages }}"
```

playbook 的最后一部分安装了剩余的软件包：

```
- name: install the stack packages
  apt:
    name: "{{ item }}"
    state: "installed"
  with_items: "{{ stack_packages + extra_packages }}"
```

现在我们已经更新了`stack-install`角色，我们需要对`stack-config`角色做同样的操作。

# stack-config 角色

我们在这个角色中使用的大部分模块在我们的目标操作系统上都能正常工作，所以在这个角色中，我们只需要调整配置文件的路径等内容。我不会列出整个`roles/stack-config/tasks/main.yml`文件的内容，我只会强调需要进行的更改，从文件顶部开始：

```
- name: include the operating system specific variables
  include_vars: "{{ ansible_os_family }}.yml"
```

这将加载包含我们稍后在角色中需要使用的路径的变量；`roles/stack-config/vars/RedHat.yml`的内容是：

```
---

php_fpm_path: "/etc/php-fpm.d/www.conf"
php_ini_path: /etc/php.ini
php_service_name: "php-fpm"
```

`roles/stack-config/vars/Debian.yml`的内容是：

```
php_fpm_path: "/etc/php/7.0/fpm/pool.d/www.conf"
php_ini_path: "/etc/php/7.0/fpm/php.ini"
php_service_name: "php7.0-fpm"
```

正如你所看到的，我们需要进行的大部分更改是关于 PHP 配置文件的位置。在获取这些文件之前，我们需要在我们的`roles/stack-config/tasks/main.yml`文件中重新创建 WordPress 用户。因为在 Ubuntu 上，PHP-FPM 默认运行在不同的组下，所以没有创建 PHP-FPM 组，让我们创建一个，确保在`add the wordpress user`任务之前添加这些任务：

```
- name: add the wordpress group
  group: 
    name: "{{ wordpress_system.group }}"
    state: "{{ wordpress_system.state }}"
```

接下来，在 Ubuntu 上没有创建`/var/www/`文件夹，所以我们需要创建这个文件夹：

```
- name: create the global directory in /etc/nginx/
  file:
    dest: "/var/www/"
    state: "directory"
    mode: "0755"
```

在 CentOS 服务器上，组和文件夹已经存在，所以这些任务应该只显示`ok`。一旦它们被创建，用户将在两个服务器上都没有错误地创建，而且`add the wordpress user`任务也没有变化。

所有部署 NGINX 配置的任务都可以在不进行任何更改的情况下工作，所以我们可以继续进行 PHP 配置：

```
- name: copy the www.conf to /etc/php-fpm.d/
  template:
    src: "php-fpmd-www.conf.j2"
    dest: "{{ php_fpm_path }}"
  notify: "restart php-fpm"

- name: configure php.ini
  lineinfile: 
    dest: "{{ php_ini_path }}"
    regexp: "{{ item.regexp }}"
    line: "{{ item.replace }}"
    backup: "yes"
    backrefs: "yes"
  with_items: "{{ php.ini }}"
  notify: "restart php-fpm"
```

正如你所看到的，这两个任务都已经更新，包含了当前 playbook 目标操作系统相关的路径。

`restart php-fpm` 处理程序也已更新，因为两个操作系统上的 PHP-FPM 服务具有不同的名称；此任务应替换`roles/stack-config/handlers/main.yml`中的现有任务：

```
- name: "restart php-fpm"
  service:
    name: "{{ php_service_name }}"
    state: "restarted"
    enabled: "yes"
```

同样，在`roles/stack-config/tasks/main.yml`中，启动 PHP-FPM 的任务应根据此任务进行更新：

```
- name: start php-fpm
  service:
    name: "{{ php_service_name }}"
    state: "started"
```

接下来的两个更改是使以下任务仅在 CentOS 框上运行：

```
- name: configure the mariadb bind address
  lineinfile: 
    dest: "{{ mariadb.server_config }}"
    regexp: "#bind-address=0.0.0.0"
    line: "bind-address={{ mariadb.bind }}"
    backup: "yes"
    backrefs: "yes"
  when: ansible_os_family == 'RedHat'
```

这是因为 Ubuntu 上 MariaDB 的默认配置不包含`bind-address`，所以我们跳过它；下一个和最后一个任务如下：

```
- name: set the selinux allowing httpd_t to be permissive is required
  selinux_permissive:
    name: httpd_t
    permissive: true
  when: selinux.http_permissive == true and ansible_os_family == 'RedHat'
```

我们在 Ubuntu 框上跳过这一步，因为 SELinux 未安装并且与 Ubuntu 不兼容。

# wordpress 角色

`wordpress` 角色有一些小的更改；第一个更改是更新`roles/wordpress/defaults/main.yml`：

```
wordpress:
  domain: "http://{{ wordpress_domain }}/"
  title: "WordPress installed by Ansible on {{ os_family }}"
```

正如您所看到的，我们已将`wordpress.domain`更新为包含`wordpress_domain`变量，而`wordpress.title`现在包含`os_family`变量；我们通过在`roles/wordpress/tasks/main.yml`文件中添加以下任务来设置这两个变量：

```
- name: set a fact for the wordpress domain
  set_fact:
    wordpress_domain: "{{ ansible_ssh_host }}"
    os_family: "{{ ansible_os_family }}"
```

我们在这里这样做的原因是 Vagrant 没有正确设置我们的 Ubuntu 框的主机名为完全合格的域名，例如`192.168.50.7.nip.io`，因此我们使用在`production`清单主机文件中定义的我们正在 SSH 连接的主机。这个角色的其余部分保持不变。

# 运行 playbook

我们的`site.yml`文件没有任何更改，这意味着我们只需要运行以下命令来启动 playbook 运行：

```
$ ansible-playbook -i production site.yml
```

这将通过 playbook 运行，给出以下输出；请注意，我已经删除了 playbook 输出的一些部分：

```
PLAY [wordpress]

TASK [Gathering Facts]
ok: [centos]
ok: [ubuntu]

TASK [roles/stack-install : include the operating system specific variables] 
ok: [centos]
ok: [ubuntu]

TASK [roles/stack-install : install the repo packages] 
skipping: [ubuntu] => (item=[])
changed: [centos] => (item=[u'epel-release', u'https://centos7.iuscommunity.org/ius-release.rpm'])

TASK [roles/stack-install : add the NGINX mainline repo] 
skipping: [ubuntu]
changed: [centos]

TASK [roles/stack-install : update all of the installed packages] 
skipping: [ubuntu]
changed: [centos]

TASK [roles/stack-install : remove the packages so that they can be replaced] 
skipping: [ubuntu]
changed: [centos] => (item=[u'mariadb-libs.x86_64'])

TASK [roles/stack-install : install the stack packages] 
skipping: [ubuntu] => (item=[])
changed: [centos] => (item=[u'postfix', u'MySQL-python', u'policycoreutils-python', u'nginx', u'mariadb101u', u'mariadb101u-server', u'mariadb101u-config', u'mariadb101u-common', u'mariadb101u-libs', u'php72u', u'php72u-bcmath', u'php72u-cli', u'php72u-common', u'php72u-dba', u'php72u-fpm', u'php72u-fpm-nginx', u'php72u-gd', u'php72u-intl', u'php72u-json', u'php72u-mbstring', u'php72u-mysqlnd', u'php72u-process', u'php72u-snmp', u'php72u-soap', u'php72u-xml', u'php72u-xmlrpc', u'vim-enhanced', u'git', u'unzip'])

TASK [roles/stack-install : update cache and install the system packages] 
skipping: [centos] => (item=[])
changed: [ubuntu] => (item=[u'software-properties-common', u'python3-mysqldb', u'acl'])

TASK [roles/stack-install : add the apt keys from a key server] 
skipping: [centos]
changed: [ubuntu] => (item={u'key_server': u'keyserver.ubuntu.com', u'key': u'0xF1656F24C74CD1D8'})

TASK [roles/stack-install : add the apt keys from a URL] 
skipping: [centos]
changed: [ubuntu] => (item=http://nginx.org/keys/nginx_signing.key)

TASK [roles/stack-install : install the repo packages] 
skipping: [centos] => (item=epel-release)
skipping: [centos] => (item=https://centos7.iuscommunity.org/ius-release.rpm)
changed: [ubuntu] => (item=deb [arch=amd64,i386] http://mirror.sax.uk.as61049.net/mariadb/repo/10.1/ubuntu zesty main)
changed: [ubuntu] => (item=deb http://nginx.org/packages/mainline/ubuntu/ zesty nginx)
changed: [ubuntu] => (item=deb-src http://nginx.org/packages/mainline/ubuntu/ zesty nginx)

TASK [roles/stack-install : install the stack packages] 
skipping: [centos] => (item=[])
changed: [ubuntu] => (item=[u'nginx', u'mariadb-server', u'php7.0', u'php7.0-cli', u'php7.0-fpm', u'php7.0-gd', u'php7.0-json', u'php7.0-mbstring', u'php7.0-mysqlnd', u'php7.0-soap', u'php7.0-xml', u'php7.0-xmlrpc', u'vim', u'git', u'unzip'])

TASK [roles/stack-config : include the operating system specific variables] 
ok: [centos]
ok: [ubuntu]

TASK [roles/stack-config : add the wordpress group] 
ok: [centos]

TASK [roles/stack-config : create the global directory in /etc/nginx/] 
changed: [ubuntu]
ok: [centos]

TASK [roles/stack-config : add the wordpress user] 
changed: [centos]
changed: [ubuntu]

TASK [roles/stack-config : copy the nginx.conf to /etc/nginx/] 
changed: [ubuntu]
changed: [centos]

TASK [roles/stack-config : create the global directory in /etc/nginx/] 
changed: [ubuntu]
changed: [centos]

TASK [roles/stack-config : copy the restrictions.conf to /etc/nginx/global/] 
changed: [ubuntu]
changed: [centos]

TASK [roles/stack-config : copy the wordpress_shared.conf to /etc/nginx/global/] 
changed: [ubuntu]
changed: [centos]

TASK [roles/stack-config : copy the default.conf to /etc/nginx/conf.d/] 
changed: [ubuntu]
changed: [centos]

TASK [roles/stack-config : copy the www.conf to /etc/php-fpm.d/] 
changed: [ubuntu]
changed: [centos]

TASK [roles/stack-config : configure php.ini] 
changed: [ubuntu] => (item={u'regexp': u'^;date.timezone =', u'replace': u'date.timezone = Europe/London'})
changed: [centos] => (item={u'regexp': u'^;date.timezone =', u'replace': u'date.timezone = Europe/London'})
ok: [ubuntu] => (item={u'regexp': u'^expose_php = On', u'replace': u'expose_php = Off'})
changed: [centos] => (item={u'regexp': u'^expose_php = On', u'replace': u'expose_php = Off'})
changed: [ubuntu] => (item={u'regexp': u'^upload_max_filesize = 2M', u'replace': u'upload_max_filesize = 20M'})
changed: [centos] => (item={u'regexp': u'^upload_max_filesize = 2M', u'replace': u'upload_max_filesize = 20M'})

TASK [roles/stack-config : start php-fpm] 
changed: [ubuntu]
changed: [centos]

TASK [roles/stack-config : start nginx] 
changed: [ubuntu]
changed: [centos]

TASK [roles/stack-config : configure the mariadb bind address] 
skipping: [ubuntu]
changed: [centos]

TASK [roles/stack-config : start mariadb] 
ok: [ubuntu]
changed: [centos]

TASK [roles/stack-config : change mysql root password] 
changed: [centos] => (item=127.0.0.1)
changed: [ubuntu] => (item=127.0.0.1)
changed: [centos] => (item=::1)
changed: [ubuntu] => (item=::1)
changed: [ubuntu] => (item=192)
changed: [centos] => (item=192.168.50.6.nip.io)
changed: [ubuntu] => (item=localhost)
changed: [centos] => (item=localhost)

TASK [roles/stack-config : set up .my.cnf file] 
changed: [ubuntu]
changed: [centos]

TASK [roles/stack-config : delete anonymous MySQL user] 
ok: [ubuntu] => (item=127.0.0.1)
ok: [centos] => (item=127.0.0.1)
ok: [ubuntu] => (item=::1)
ok: [centos] => (item=::1)
ok: [ubuntu] => (item=192)
changed: [centos] => (item=192.168.50.6.nip.io)
ok: [ubuntu] => (item=localhost)
changed: [centos] => (item=localhost)

TASK [roles/stack-config : remove the MySQL test database] 
ok: [ubuntu]
changed: [centos]

TASK [roles/stack-config : set the selinux allowing httpd_t to be permissive is required] 
skipping: [ubuntu]
changed: [centos]

TASK [roles/wordpress : set a fact for the wordpress domain] 
ok: [centos]
ok: [ubuntu]

TASK [roles/wordpress : download wp-cli] 
changed: [ubuntu]
changed: [centos]

TASK [roles/wordpress : update permissions of wp-cli to allow anyone to execute it] 
changed: [ubuntu]
changed: [centos]

TASK [roles/wordpress : create the wordpress database] 
changed: [ubuntu]
changed: [centos]

TASK [roles/wordpress : create the user for the wordpress database] 
changed: [ubuntu] => (item=127.0.0.1)
changed: [centos] => (item=127.0.0.1)
ok: [ubuntu] => (item=::1)
ok: [centos] => (item=::1)
ok: [ubuntu] => (item=192)
ok: [centos] => (item=192.168.50.6.nip.io)
ok: [ubuntu] => (item=localhost)
ok: [centos] => (item=localhost)

TASK [roles/wordpress : are the wordpress files already there?] 
ok: [ubuntu]
ok: [centos]

TASK [roles/wordpress : download wordpresss] 
changed: [ubuntu]
changed: [centos]

TASK [roles/wordpress : set the correct permissions on the homedir] 
ok: [ubuntu]
changed: [centos]

TASK [roles/wordpress : is wordpress already configured?] 
ok: [centos]
ok: [ubuntu]

TASK [roles/wordpress : configure wordpress] 
changed: [ubuntu]
changed: [centos]

TASK [roles/wordpress : do we need to install wordpress?] 
fatal: [ubuntu]: FAILED! => 
...ignoring
fatal: [centos]: FAILED! => 
...ignoring

TASK [roles/wordpress : install wordpress if needed] 
changed: [ubuntu]
changed: [centos]

TASK [roles/wordpress : do we need to install the plugins?] 
failed: [ubuntu] (item=jetpack) => 
failed: [ubuntu] (item=wp-super-cache) => 
failed: [ubuntu] (item=wordpress-seo) => 
failed: [centos] (item=jetpack) => 
failed: [ubuntu] (item=wordfence) => 
failed: [centos] (item=wp-super-cache) => 
failed: [ubuntu] (item=nginx-helper) => 
failed: [centos] (item=wordpress-seo) => 
failed: [centos] (item=wordfence) => 
failed: [centos] (item=nginx-helper) =>

TASK [roles/wordpress : set a fact if we don't need to install the plugins] 
skipping: [centos]
skipping: [ubuntu]

TASK [roles/wordpress : set a fact if we need to install the plugins] 
ok: [centos]
ok: [ubuntu]

TASK [roles/wordpress : install the plugins if we need to or ignore if not] 
changed: [centos] => (item=jetpack)
changed: [ubuntu] => (item=jetpack)
changed: [ubuntu] => (item=wp-super-cache)
changed: [centos] => (item=wp-super-cache)
changed: [ubuntu] => (item=wordpress-seo)
changed: [centos] => (item=wordpress-seo)
changed: [ubuntu] => (item=wordfence)
changed: [centos] => (item=wordfence)
changed: [ubuntu] => (item=nginx-helper)
changed: [centos] => (item=nginx-helper)

TASK [roles/wordpress : do we need to install the theme?] 
fatal: [centos]: FAILED! => 
fatal: [ubuntu]: FAILED! =>

TASK [roles/wordpress : set a fact if we don't need to install the theme] 
skipping: [centos]
skipping: [ubuntu]

TASK [roles/wordpress : set a fact if we need to install the theme] 
ok: [centos]
ok: [ubuntu]

TASK [roles/wordpress : install the theme if we need to or ignore if not] 
changed: [centos]
changed: [ubuntu]

RUNNING HANDLER [roles/stack-config : restart nginx] 
changed: [ubuntu]
changed: [centos]

RUNNING HANDLER [roles/stack-config : restart php-fpm] 
changed: [ubuntu]
changed: [centos]

PLAY RECAP 
centos : ok=47 changed=37 unreachable=0 failed=0
ubuntu : ok=45 changed=33 unreachable=0 failed=0
```

一旦 playbook 完成，您应该能够在浏览器中访问`http://192.168.50.6.nip.io/`，并且您应该看到 WordPress 显示已安装在基于 Red Hat 的操作系统上：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/0e2f891d-2df3-4a23-847b-6f7c10c73198.png)

访问`http://192.168.50.7.nip.io/`将显示相同的主题，但它应该说明它正在运行 Debian-based 操作系统，就像这个截图中一样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-asb/img/f299f262-5804-43ee-bfe8-7df80942b997.png)

您可以尝试重新运行 playbook，以查看返回的结果，并且您还可以通过运行以下命令删除 Vagrant 框：

```
$ vagrant destroy
```

您将被问及是否要逐个删除每台机器；只需对两个提示都回答“是”。

# 摘要

在本章中，我们已经调整了我们的 WordPress 安装 playbook，以针对多个操作系统。我们通过使用 Ansible 的内置审计模块来确定 playbook 正在针对哪个操作系统，并仅运行适用于目标操作系统的任务来实现这一点。

在下一章中，我们将开始查看一些处理网络的核心 Ansible 模块。

# 问题

1.  真或假：我们需要仔细检查 playbook 中的每个任务，以确保它在两个操作系统上都能正常工作。

1.  哪个配置选项允许我们定义 Python 的路径，Ansible 将使用？

1.  解释为什么我们需要对配置和与 PHP-FPM 服务交互的任务进行更改。

1.  真或假：每个操作系统的软件包名称完全对应。

1.  更新 playbook，以便在每个不同的主机上安装不同的主题。

# 进一步阅读

您可以在[`www.ubuntu.com`](https://www.ubuntu.com)找到有关 Ubuntu 操作系统的更多信息。
