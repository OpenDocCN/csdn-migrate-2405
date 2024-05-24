# Ansible 剧本基础知识（二）

> 原文：[`zh.annas-archive.org/md5/F3D5D082C2C7CD8C77793DEE22B4CF30`](https://zh.annas-archive.org/md5/F3D5D082C2C7CD8C77793DEE22B4CF30AZXRT4567YJU8KI-9LO-0P0[-])
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：控制执行流程 - 条件

控制结构指的是对程序执行流程产生影响的任何事物。控制结构主要有以下两种类型：

+   条件

+   迭代

有时，我们需要根据变量的值、平台类型或甚至其他某些命令的结果有条件地执行代码。有时我们还需要迭代多个对象，例如列表哈希或多级变量。

大多数编程语言和工具使用强大但机器友好的构造，例如`if else`、`for`、`unless`、`do while`等等。然而，Ansible 忠实于其设计原则，成为一种人类友好的自动化语言，并且通过万能的`when`和`with_*`构造实现了相同的功能，这些构造更接近英语。让我们开始探索它是如何做到这一点的。

在本章中，我们将涵盖以下主题：

+   使用`when`语句进行条件控制

+   使用变量和事实跳过子例程

+   有选择地应用角色

+   Jinja2 模板中的条件控制结构

# 条件控制结构

条件控制结构允许 Ansible 根据某些条件选择替代路径、跳过任务或选择要导入的特定文件。在通用编程语言中，使用`if-then`、`else if`、`else`、`case`语句来完成此操作。Ansible 使用"`when`"语句。一些示例条件包括：

+   是否定义了某个变量

+   较早的命令序列是否成功

+   任务是否已经运行过

+   目标节点上的平台是否与支持的平台匹配

+   某个文件是否存在

## when 语句

我们已经使用了`when`语句来根据另一个命令的结果提取 WordPress 存档，即：

```
- name: download wordpress
    register: wp_download
- name: extract wordpress
    when: wp_download.rc == 0
```

这与编写 shell 片段大致相当，如下所示：

```
DOWNLOAD_WORDPRESS
var=`echo $?
if [$var -eq 0]
then
    EXTRACT_WORDPRESS()
fi
```

除了检查前面的代码，我们还可以根据任务本身的结果简单地编写条件，如下所示：

```
- name: extract wordpress
    when: wp_download|success
- name: notify devops engineers
    when: wp_download|failed
```

为了使失败的语句起作用，我们需要在注册变量的早期任务中添加`ignore_errors: True`语句。以下流程图描述了相同的逻辑：

![when 语句](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_05_01.jpg)

### 基于事实的选择

事实是检测平台特定信息并基于此进行选择的良好信息来源，尤其是在存在混合环境时。基于这个选择，我们可以：

+   决定是否执行任务

+   决定是否包含任务文件

+   决定是否导入文件

+   决定是否在目标节点上应用角色

在编写 MySQL 时，我们已经使用了基于事实的选择，其中我们使用了事实`ansible_os_family`来：

1.  为非 Debian 系统导入`vars`文件。

1.  为包安装包含特定于平台的任务。

下面的代码片段显示了两个用例：

![基于事实的选择](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_05_02.jpg)

# 重构 MySQL 角色

我们现有的 MySQL 角色只安装和配置服务器。往往我们只需要安装 MySQL 客户端包而不是服务器。我们没有能力有选择地这样做。

### 注意

**情景：**

我们被要求重构 MySQL 角色，并根据变量值有条件地安装 MySQL 服务器。默认情况下，它应该只安装 MySQL 客户端包。

布尔变量可以用来设置一个开关，我们将添加一个变量，并将其默认值设为`false`。这一次，我们将创建一个多级变量或嵌套哈希。

## 多级变量字典

到目前为止，我们一直将变量命名为`mysql_bind`、`mysql_port`等，并使用下划线对它们进行分类。如果您使用多级字典定义它们，那么变量可以更好地分类和组织，例如：

```
mysql:
  config:
    bind: 127.0.0.1
    port: 3306
```

然后可以在代码中以`mysql['config]['bind']`或`mysql['config]['port']`的方式访问多级变量。现在让我们更新`roles/mysql/defaults/main.yml`文件以使用多级变量，并创建一个名为`mysql.server`的新布尔变量，它充当标志：

![多级变量字典](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_05_03.jpg)

另外，我们还需要更新`mysql`角色中`vars`目录中的文件，以使用新风格定义变量，以及更新所有任务、处理程序和模板以适当地引用它们。这一过程作为文本的一部分添加，以避免冗余。

### 合并哈希

多级变量或本质上来说，从不同位置定义的字典可能需要被合并。例如，如果我们在角色`default`中定义默认配置参数，然后在角色的`vars`目录中覆盖了一些参数，那么结果变量`hash`应包含**defaults**中的项以及**vars**中覆盖的值。

让我们来看下面的屏幕截图：

![合并哈希](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_05_04.jpg)

但是，默认情况下，Ansible 将替换字典，在上面的示例中，我们不会得到一个合并的字典，而是会失去用户和端口`vars`，因为角色中的`vars`具有更高的优先级。这可以通过将`hash_behavior`参数设置为`merge`而不是`replace`来避免，如下所示：

```
# /etc/ansible/ansible.cfg
    hash_behaviour=merge
```

这应该在 Ansible 控制主机上设置，不需要我们重新启动任何服务。

## 有选择性地配置 MySQL 服务器

在重构代码并添加由变量控制的标志之后，我们已经准备好选择性地配置 MySQL 服务器了。我们有一个名为`mysql.server`的变量，它采用`True`/`False`的布尔值。此变量可用于决定是否跳过服务器配置，如下所示：

```
#file: roles/mysql/tasks/main.yml
- include: configure.yml
  when: mysql.server

- include: service.yml
  when: mysql.server
```

让我们还添加任务来安装 MySQL 客户端包以及 Ansible 的 MySQL 模块所需的 Python 绑定：

```
---
# filename: roles/mysql/tasks/install_Debian.yml
  - name: install mysql client
    apt:
      name: "{{ mysql['pkg']['client'] }}"
      update_cache: yes

  - name: install mysql server
    apt:
      name: "{{ mysql['pkg']['server'] }}"
      update_cache: yes
    when: mysql.server

  - name: install mysql python binding
    apt:
      name: "{{ mysql['pkg']['python'] }}"
```

在这里，包名称来自以下变量`hash`：

```
mysql:
pkg:
    server: mysql-server
    client: mysql-client
    python: python-mysqldb
```

默认情况下，`mysql.server`参数已设置为`False`。我们如何仅为数据库服务器启用此选项？我们可以有很多种方法来实现这一点。这次我们会选择剧本变量，因为我们有一个专门用于 DB 服务器的变量。

让我们看一下以下截图：

![有选择性地配置 MySQL 服务器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_05_05.jpg)

# Jinja2 模板中的条件控制结构

Ansible 使用 Jinja2 作为模板引擎。因此，除了 Ansible 任务支持的控制结构外，了解 Jinja2 控制结构也对我们很有用。Jinja2 的语法将控制结构封装在`{% %}`块内。对于条件控制，Jinja2 使用熟悉的`if`语句，其语法如下：

```
{% if condition %}
    do_some_thing
{% elif condition2 %}
    do_another_thing
{% else %}
    do_something_else
{% endif %}
```

## 更新 MySQL 模板

我们之前创建的用于生成`my.cnf`文件的模板假定其中引用的所有变量都在某处定义了。有可能情况并非总是如此，这可能导致在运行 Ansible 时出现错误。我们能够有选择地将配置参数包含在`my.cnf`文件中吗？答案是肯定的。我们可以检查变量是否被定义，只有在这种情况下，我们才将其添加到文件中，如下所示：

```
#filename: roles/mysql/template/my.cnf.j2
[mysqld]
user = {{ mysql['config']['user'] | default("mysql") }}
{% if mysql.config.pid is defined %}
pid-file = {{ mysql['config']['pid'] }}
{% endif %}
{% if mysql.config.socket is defined %}
socket = {{ mysql['config']['socket'] }}
{% endif %}
{% if mysql.config.port is defined %}
port = {{ mysql['config']['port'] }}
{% endif %}
{% if mysql.config.datadir is defined %}
datadir = {{ mysql['config']['datadir'] }}
{% endif %}
{% if mysql.config.bind is defined %}
bind-address = {{ mysql['config']['bind'] }}
{% endif %}
```

让我们分析上述代码：

+   由于我们正在为`mysql['config']['user']`参数设置默认值，因此无需检查它是否已定义。它已经被优雅地处理了。

+   对于所有其他参数，我们使用条件检查变量是否已定义，例如`if mysql.config.pid is defined`。如果未定义该参数，则会跳过该参数，而不会引发错误。

# 仅运行一次任务

有时，在播放书执行期间，角色中的特定任务可能需要仅执行一次，即使该角色应用于多个主机。这可以通过`run_once`条件来实现：

```
name: initialize wordpress database
script: initialize_wp_database.sh 
run_once: true
```

由于我们正在使用`run_once`选项，上述任务将在应用角色的清单中的第一个主机上运行。所有后续主机都将跳过此任务。

# 有条件地执行角色

我们之前创建的用于设置 Web 服务器的 Nginx 角色仅支持基于 Debian 的系统。在其他系统上运行此逻辑可能会导致失败。例如，Nginx 角色使用`apt`模块安装软件包，在依赖于`yum`软件包管理器的基于 RedHat 的系统上不起作用。可以通过添加`when`语句与事实来选择性地基于操作系统系列执行。以下是`www.yml`剧本中的片段：

```
#filename: www.yml (snippet)
- hosts: www
  roles:
    - { role: nginx, when: ansible_os_family == 'Debian' }
```

# 复习问题

您认为您是否已经充分理解了本章内容？尝试回答以下问题来测试您的理解：

1.  Ansible 中`if else`语句的替代方案是什么？

1.  如何有选择地导入特定于平台的变量？

1.  为什么 Jinja2 模板使用`__`和`__`来界定控制结构？

1.  如何跳过在不兼容平台上运行的角色？

# 总结

在本章中，你学习了如何使用`when`语句、条件导入、选择性包含等来控制执行流程。你还学会了如何使用变量和事实来有选择地跳过例程并执行特定于平台的子例程。我们对 MySQL 角色进行了重构，开始使用变量字典有条件地配置 MySQL 服务器，并使用更智能的模板来预检已定义的变量。

在下一章中，我们将开始探索第二种控制结构，即迭代控制结构，我们将开始循环数组和哈希。


# 第七章：迭代控制结构 - 循环

在前一章节中您了解了条件控制。我们对 Ansible 的控制结构的世界进行的旅程将继续学习迭代控制。我们经常需要创建一系列目录、安装一堆软件包、定义和遍历嵌套哈希或字典。传统的编程语言使用`for`或`while`循环进行迭代。Ansible 将它们替换为`with`语句。

在本章中，我们将学习：

+   如何使用`with`语句进行迭代控制

+   如何循环数组以一次创建多个对象

+   如何定义嵌套哈希并遍历它们以创建数据驱动的角色

# 万能的 with 语句

使用“瑞士军刀”实用工具`with`语句可以实现循环纯列表、解析字典、循环一系列数字、解析路径并有选择地复制文件，或者只是从列表中挑选一个随机项。`with`语句采用以下形式：

```
with_xxx
```

这里，`xxx`参数是需要循环的数据类型，例如，项、字典等。

以下表列出了`with`语句可以迭代的数据类型：

| 构造 | 数据类型 | 描述 |
| --- | --- | --- |
| `with_items` | 数组 | 用于循环数组项。例如，用于创建一组用户、目录，或者安装一系列软件包。 |
| `with_nested` | 嵌套循环 | 用于解析多维数组。例如，创建一个 MySQL 用户列表并为他们授予一组数据库的访问权限。 |
| `with_dict` | 哈希 | 用于解析键值对字典并创建虚拟主机。 |
| `with_fileglobs` | 文件模式匹配 | 用于解析路径并仅复制与特定模式匹配的文件。 |
| `with_together` | 集合 | 用于将两个数组合并为一个集合并循环遍历它。 |
| `with_subelements` | 哈希子元素 | 用于解析哈希的子元素。例如，遍历 SSH 密钥列表并将其分发给用户。 |
| `with_sequence` | 整数序列 | 用于循环一系列数字。 |
| `with_random_choice` | 随机选择 | 用于以随机顺序从数组中选择项目。 |
| `with_indexed_items` | 带索引的数组 | 这是一个带有索引的数组，当需要项目索引时很有用。 |

# 配置 WordPress 必备条件

在第四章安装 WordPress 的角色创建时，*引入您的代码 - 自定义命令和脚本*，我们创建了下载、提取和复制 WordPress 应用的任务。然而，这还不足以启动 WordPress，它有以下先决条件：

+   一个网络服务器

+   网络服务器的 PHP 绑定

+   MySQL 数据库和 MySQL 用户

一个 Nginx web 服务器和 MySQL 服务已经在我们的案例中安装。我们仍然需要安装并配置 PHP，以及为我们的 WordPress 应用程序所需的 MySQL 数据库和用户。为了处理 PHP 请求，我们选择实现 PHP5-FPM 处理程序，这是传统 FastCGI 实现的替代品。

# PHP5-FPM 角色

在 **PHP5-FPM** 中，**FPM** 代表 **FastCGI Process Manager**。PHP5-FPM 提供了比 **fastcgi** 更高级的功能，对于管理高流量站点非常有用。它适用于提供我们的 fifanews 站点，该站点每天预计会有数百万次点击。根据我们创建模块化代码的设计原则，我们将保持 PHP 功能在其自己的角色中。让我们使用 Ansible-Galaxy 命令初始化 PHP5-FPM 角色，如下所示：

```
$ ansible-galaxy init --init-path roles/ php5-fpm

```

## 定义一个数组

PHP 安装将涉及安装多个软件包，包括 `php5-fpm`、`php5-mysql` 和其他一些软件包。到目前为止，我们一直是一次编写一个任务。例如，让我们来看看以下代码片段：

```
  - name: install php5-fpm
    apt: name: "php5-fpm" 
  - name: install php5-mysql
    apt: name: "php5-mysql"
```

但是，当我们想要安装多个软件包时，这可能会变得重复，并导致冗余代码。为了致力于编写数据驱动的角色，我们将通过一个变量来推动软件包的安装，该变量获取一个软件包列表，然后对该列表进行迭代。让我们开始定义需要列出软件包的参数，如下所示：

```
---
#filename: roles/php5-fpm/defaults/main.yml
#defaults file for php5-fpm
php5:
  packages:
    - php5-fpm
    - php5-common
    - php5-curl
    - php5-mysql
    - php5-cli
    - php5-gd
    - php5-mcrypt
    - php5-suhosin
    - php5-memcache
  service:
    name: php5-fpm
```

这是前面代码的分析：

+   `php5` 变量是一个变量字典，其中包含我们传递给 `php5-fpm` 角色的所有参数。

+   `php5.packages` 参数是一个包的数组，在代码的每一行定义一个包。这将被传递给一个任务，该任务将迭代每个项目并安装它。

+   `php5.service` 参数定义了服务的名称，该名称将在服务任务中引用。

## 循环一个数组

现在让我们为 `php5-fpm` 角色创建任务。我们需要从数组中安装软件包，然后启动服务。我们将包的功能拆分为两个独立的任务文件，并从 `main.yml` 文件中调用它，如下所示：

```
---
#filename: roles/php5-fpm/tasks/main.yml
# tasks file for php5-fpm
- include_vars: "{{ ansible_os_family }}.yml"
  when: ansible_os_family != 'Debian'

- include: install.yml
- include: service.yml

#filename: roles/php5-fpm/tasks/install.yml
  - name: install php5-fpm and family
    apt:
      name: "{{ item }}"
    with_items: php5.packages
    notify:
     - restart php5-fpm service

#filename: roles/php5-fpm/tasks/service.yml
# manage php5-fpm service
- name: start php5-fpm service
  service:
    name: "{{ php5['service']['name'] }}"
    state: started
```

除了任务，还可以编写重新启动 `php5-fpm` 角色的处理程序，如下所示：

```
---
# filename: roles/php5-fpm/handlers/main.yml
# handlers file for php5-fpm
- name: restart php5-fpm service
  service: name="{{ php5['service']['name'] }}" state=restarted
```

让我们分析前面的代码：

+   **主:** `main.yml` 文件根据非 Debian 系统的 `ansible_os_family` 事实包含变量。这对于覆盖特定于平台的变量非常有用。在包含 `vars` 文件之后，主任务继续包含 `install.yml` 和 `service.yml` 文件。

+   **安装**：`install.yml` 文件是我们迭代先前定义的一个包数组的地方。由于该文件包含一个数组，我们使用 `with.items` 构造与 `php5.packages` 变量一起使用，并将 `{{ item }}` 参数传递为要安装的软件包的名称。我们也可以直接传递数组，如下所示：

    ```
      with_items:
        - php5-fpm
        - php5-mysql
    ```

+   **服务和处理器**：`service.yml` 文件和处理器 `main.yml` 文件管理 `php5-fom` 服务的启动和重新启动。它使用字典变量 `php5['service']['name']` 来确定服务名称。

# 创建 MySQL 数据库和用户账户

WordPress 是一个内容管理系统，需要一个可用的 MySQL DB 来存储数据，例如帖子、用户等。此外，它还需要一个具有适当权限的 MySQL 用户来从 WordPress 应用程序连接到数据库。在安装 MySQL 时会获得一个管理员用户，但是，根据需要创建额外的用户帐户并授予用户权限是一个好习惯。

## 创建哈希

**哈希**，哈希表的缩写，是键值对字典。它是一个有用的数据结构，用于创建多级变量，然后可以通过编程方式创建具有自己值的多个对象。我们将在 `group_vars`/`all` 文件中定义数据库和用户为字典项，如下所示：

```
#filename: group_vars/all
mysql_bind:  "{{ ansible_eth0.ipv4.address }}"
mysql:
  databases:
    fifalive:
      state: present
    fifanews:
      state: present
  users:
    fifa:
      pass: supersecure1234
      host: '%'
      priv: '*.*:ALL'
      state: present
```

这是上述代码的分析：

+   我们在 `group_vars`/`all` 文件中定义了此变量哈希，而不是在角色中。这是因为我们希望保持角色的通用性和共享性，而不添加特定于我们各自环境的数据。

+   我们将数据库和用户配置定义为多级字典或哈希。

### 嵌套哈希

通过以下图解释这个多级哈希：

![嵌套哈希](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_06_01.jpg)

以下是这个嵌套哈希结构的描述：

+   MySQL 变量是一个具有两个键的哈希：数据库和用户。例如：

    ```
    mysql:
        databases: value
         users: value
    ```

+   这两个键的每个值都是哈希，或关于要创建的数据库和用户的信息字典。例如：

    ```
    databases:
        fifalive: value
        fifanews: value
    ```

+   每个数据库本身都是键值对字典。例如，对于 MySQL 用户 `fifalive`，键值对是 "state:present"。

## 遍历哈希

创建数据库和用户账户通常需要创建具有模板的自定义脚本，然后使用命令模块调用。相反，Ansible 提供了一些现成的模块来执行与 MySQL 相关的任务，即 `mysql_db` 和 `mysql_user` 参数。使用 `with_dict` 语句，我们将遍历我们之前定义的数据库和用户字典，如下所示：

```
# filename: roles/mysql/tasks/configure.yml
 - name: create mysql databases
    mysql_db:
      name: "{{ item.key }}"
      state: "{{ item.value.state }}"
    with_dict: "{{ mysql['databases'] }}"

 - name: create mysql users
    mysql_user:
      name: "{{ item.key }}"
      host: "{{ item.value.host }}"
      password: "{{ item.value.pass }}"
      priv: "{{ item.value.priv }}"
      state: "{{ item.value.state }}"
    with_dict: "{{ mysql['users'] }}"
```

这是上述代码的分析：

+   `mysql['databases']` 和 `mysql['users']` 参数是使用 `with_dict` 语句传递给任务的字典

+   每个字典或哈希都有一个键值对，作为 `{{ item.key }}` 和 `{{ item.value }}` 参数传递

+   `{{ item.value }}` 参数是一个字典。此字典中的每个键然后称为 `{{ item.value.<key> }}`。例如，`{{ item.value.state }}` 参数

以下图解释了这个嵌套哈希是如何解析的：

![遍历哈希](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_06_02.jpg)

# 创建 Nginx 虚拟主机

安装完`php5-fpm`管理器并创建了 MySQL 数据库和用户账户后，剩下的配置是在 Nginx 中创建一个虚拟主机以服务我们的 WordPress 应用程序。之前安装的 Nginx Web 服务器只服务于一个简单的 HTML 页面，并不知道 WordPress 应用程序的存在或如何服务它。让我们从添加这些配置开始。

## 定义 PHP 站点信息

除了我们正在设置的`fifanews.com`站点外，我们可能还会在将来启动一些与足球相关的站点。因此，我们需要有能力以编程方式添加多个站点到同一个 Nginx 服务器上。创建一个定义站点信息的字典并将其嵌入到模板中听起来是一个不错的选择。由于站点信息是特定于我们的，我们将将变量哈希添加到`group_vars`文件中，如下所示：

```
#filename: group_vars/all
nginx:
  phpsites:
    fifanews:
      name: fifanews.com
      port: 8080
      doc_root: /var/www/fifanews
```

我们学习了如何从 Ansible 任务中解析这个字典。让我们添加一个任务，允许我们遍历这个字典，将值传递给模板，并创建虚拟主机配置：

```
#filename: roles/nginx/tasks/configure.yml
- name: create php virtual hosts
    template:
      src: php_vhost.j2
      dest: /etc/nginx/conf.d/{{ item.key }}.conf
    with_dict: "{{ nginx['phpsites'] }}"
    notify:
      - restart nginx service
```

字典中的每个项目都会传递给模板，这种情况下是传递给`php_vhost.j2`参数。然后，模板会读取哈希并创建一个虚拟主机模板，配置一个 PHP 应用程序，如下所示：

```
#filename: roles/nginx/templates/php_vhost.j2
#{{ ansible_managed }}

server {
    listen {{ item.value.port }};

  location / {
    root {{ item.value.doc_root }};
    index index.php;
  }

  location ~ .php$ {
    fastcgi_split_path_info ^(.+\.php)(.*)$;
    fastcgi_pass   backend;
    fastcgi_index  index.php;
    fastcgi_param  SCRIPT_FILENAME  {{ item.value.doc_root }}$fastcgi_script_name;
    include fastcgi_params;
  }
}
upstream backend {
  server 127.0.0.1:9000;
}
```

这是前述代码的分析：

+   `{{ ansible_managed }}`参数是一个特殊变量，它添加了一条注释，通知服务器该文件正在被 Ansible 管理，包括该文件在 Ansible 存储库中的路径、最后修改时间以及修改它的用户。

+   该模板获取字典项并解析其值，因为它是一个嵌套的哈希。该模板配置了使用`nginx.phpsites`设置的字典值创建 Nginx 的 php 虚拟主机的配置。

+   提供的字典中的配置参数包括文档根目录、端口、后端使用的内容，这使得 Nginx 知道如何处理传入的 PHP 请求，使用哪个后端，监听哪个端口等等。

最后，我们将新角色添加到`www.yaml`文件中，如下所示：

```
# www.yml
roles:
     - { role: nginx, when: ansible_os_family == 'Debian' }
     - php5-fpm
     - wordpress
```

使用以下命令运行 Playbook：

```
$ ansible-playbook -i customhosts site.yml

```

运行完成后，是时候测试我们的工作了。让我们在浏览器中加载以下 URL：

`http://<web_server_ip>:8080`

恭喜！我们已成功创建了一个带有 Nginx Web 服务器和 MySQL 后端的 WordPress PHP 应用程序，完全配置完毕。现在，我们准备设置我们的 fifanews 网站：

![定义 PHP 站点信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_06_03.jpg)

# 复习问题

您认为自己已经足够理解了本章内容吗？尝试回答以下问题来测试您的理解：

1.  在 Ansible 中，哪个语句替代了`for`循环？

1.  如何使用`with_____`语句迭代字典？

1.  如何向模板中添加一个语句，以打印修改时间和修改人？

1.  如何打印嵌套哈希的值？

# 概要

在本章中，您学习了如何迭代创建多个对象。我们从全能的`with`语句及其各种形式的概述开始。然后，我们更深入地探讨了迭代两种最基本的数据结构，即数组和哈希。`php5-fpm`角色接受一个包含软件包列表的数组，并创建一个循环安装这些软件包的任务。为了创建 MySQL 数据库和用户，我们定义了变量字典或哈希并对它们进行了迭代。最后，我们通过迭代嵌套字典添加了 Nginx 模板配置，以创建多个虚拟主机来提供 PHP 应用程序。

在下一章中，您将学习如何使用魔术变量发现有关其他节点的信息。


# 第八章：节点发现和集群化

对于大多数现实场景，我们需要创建一个计算节点集群，其上运行着相互连接的应用程序。例如，我们正在构建的 WordPress 网站需要将 Web 服务器和数据库连接在一起。

集群基础设施具有拓扑结构，其中一类节点应该能够发现关于不同或相同类别服务器的信息。例如，WordPress 应用服务器需要发现关于数据库服务器的信息，而负载均衡器需要了解每个 Web 服务器的 IP 地址/主机名，以便将流量发送到这些服务器。本章重点介绍 Ansible 提供的用于将节点分组并发现相互连接的节点属性的原语。

在本章中，我们将学习以下内容：

+   发现集群中其他节点的信息

+   使用发现的魔术变量动态生成配置

+   为什么以及如何启用事实缓存

# 使用魔术变量进行节点发现

我们已经看到了用户定义的变量以及系统数据，即事实。除了这些之外，还有一些变量用于定义关于节点、清单和播放的元信息，例如节点属于哪些组、哪些组包含在清单中、哪些节点属于哪些组等。这些隐式设置的变量称为**魔术**变量，对于发现节点和拓扑信息非常有用。下表列出了最有用的魔术变量及其描述：

| 魔术变量 | 描述 |
| --- | --- |
| `hostvars` | 这些是设置在另一台主机上的查找变量或事实。 |
| `groups` | 这是清单中组的列表。可以使用它来遍历一组节点以发现其拓扑信息。 |
| `group_names` | 这是节点所属的组列表。 |
| `inventory_hostname` | 这是清单文件中设置的主机名。它可能与`ansible_hostname`事实不同。 |
| `play_hosts` | 这是属于当前播放的所有主机的列表。 |

除了上表之外，还有一些额外的魔术变量，例如`delegate_to`、`inventory_dir`和`inventory_file`参数，但这些与节点发现无关，使用频率较低。

现在我们将创建一个新角色作为负载均衡器，该角色依赖于魔术变量提供的节点发现功能。

# 创建负载均衡器角色

我们创建了 Nginx 和 MySQL 角色来服务 WordPress 网站。但是，如果我们必须构建可扩展的网站，我们还需要添加一个负载均衡器。这个负载均衡器将作为传入请求的入口点，然后将流量分散到可用的 Web 服务器上。让我们考虑以下情况，我们的 fifanews 站点已经成为一瞬间的热门。流量呈指数增长，我们一直在使用的单个 Web 服务器方法正在出现问题。我们需要水平扩展并添加更多的 Web 服务器。一旦我们开始创建更多的 Web 服务器，我们还需要一些机制来平衡这些流量。我们被委托创建一个 `haproxy` 角色，它将自动发现我们集群中的所有 Web 服务器并将其添加到其配置中。

下图解释了使用 HAProxy 作为前端，在后端平衡 Web 服务器负载的情况。HAProxy 是一个广泛使用的开源 TCP/HTTP 负载均衡器。让我们看看下面的图表：

![创建负载均衡器角色](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_07_01.jpg)

在接下来的步骤中，我们不仅将创建一个 `haproxy` 模块，还将使用魔术变量自动配置其 IP 地址为所有 Web 服务器节点：

1.  让我们从使用以下命令创建编写此角色所需的框架开始：

    ```
    $ ansible-galaxy init --init-path roles/ mysql

    ```

    输出如下所示：

    ```
     haproxy was created successfully

    ```

1.  现在我们将向变量默认添加与 `haproxy` 角色相关的一些变量：

    ```
    ---
    # filename: roles/haproxy/defaults/main.yml
    haproxy:
      config:
        cnfpath: /etc/haproxy/haproxy.cfg
        enabled: 1
        listen_address: 0.0.0.0
        listen_port: 8080
      service: haproxy
      pkg: haproxy
    ```

    ### 提示

    尽管为 haproxy 支持的每个配置添加参数是一个好的做法，但在编写这个角色时，我们将坚持使用一部分参数；这对于节点发现特别有用。

1.  现在，让我们创建一些任务和处理程序，在 Ubuntu 主机上安装、配置和管理 haproxy 服务：

    ```
    ---
    # filename: roles/haproxy/tasks/main.yml
    - include: install.yml
    - include: configure.yml
    - include: service.yml

    ---
    # filename: roles/haproxy/tasks/install.yml
      - name: install haproxy
        apt:
          name: "{{ haproxy['pkg'] }}"

    ---
    # filename: roles/haproxy/tasks/configure.yml
     - name: create haproxy config
       template: src="img/haproxy.cfg.j2" dest="{{ haproxy['config']['cnfpath'] }}" mode=0644
       notify:
        - restart haproxy service

     - name: enable haproxy
       template: src="img/haproxy.default.j2" dest=/etc/default/haproxy mode=0644
       notify:
        - restart haproxy service

    ---
    # filename: roles/haproxy/tasks/service.yml
     - name: start haproxy server
       service:
         name: "{{ haproxy['service'] }}" 
         state: started

    ---
    # filename: roles/haproxy/handlers/main.yml
    - name: restart haproxy service
      service: name="{{ haproxy['service'] }}" state=restarted
    ```

以下是前述代码的分析：

+   根据最佳实践，我们为每个阶段创建了单独的任务文件：install、configure 和 service。然后我们从主任务文件，即 `tasks/main.yml` 文件中调用这些文件。

+   HAProxy 的配置文件将使用 Jinja2 模板创建在 `/etc/haproxy/haproxy.cfg` 中。除了创建配置外，我们还需要在 `/etc/defaults/haproxy` 文件中启用 `haproxy` 服务。

+   安装、服务和处理程序与我们之前创建的角色类似，因此我们将跳过描述。

我们在 `configure.yml` 文件中定义了模板的使用。现在让我们创建模板：

```
#filename: roles/haproxy/templates/haproxy.default
ENABLED="{{ haproxy['config']['enabled'] }}"

#filename: roles/haproxy/templates/haproxy.cfg.j2
global
        log 127.0.0.1 local0
        log 127.0.0.1 local1 notice
        maxconn 4096
        user haproxy
        group haproxy
        daemon

defaults
        log global
        mode http
        option httplog
        option dontlognull
        retries 3
        option redispatch
        maxconn 2000
        contimeout 5000
        clitimeout 50000
        srvtimeout 50000

listen fifanews {{ haproxy['config']['listen_address'] }}:{{ haproxy['config']['listen_port'] }}
        cookie  SERVERID rewrite
        balance roundrobin
    {% for host in groups['www'] %}
        server {{ hostvars[host]['ansible_hostname'] }} {{ hostvars[host]['ansible_eth1']['ipv4']['address'] }}:{{ hostvars[host]['nginx']['phpsites']['fifanews']['port'] }} cookie {{ hostvars[host]['inventory_hostname'] }} check
    {% endfor %}
```

我们在 `roles/haproxy/templates/haproxy.cfg.j2` 创建的第二个模板对于我们来说尤为重要，与节点发现相关。下图显示了标记了魔术变量的相关部分：

![创建负载均衡器角色](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_07_02.jpg)

让我们分析这个模板片段：

+   我们正在使用魔术变量 `groups` 来查找清单中属于 `www` 组的所有主机，如下所示：

    {% for host in groups['www'] -%}

+   对于每个发现的主机，我们使用 `hostvars` 参数获取事实以及用户定义的变量，这是另一个魔术变量。我们正在查找事实和用户定义的变量，以及另一个魔术变量 `inventory_hostname`，如下所示：

    {{ hostvars[host]['ansible_eth1']['ipv4']['address'] }}

    ```
    {{ hostvars[host]['inventory_hostname'] }}
    {{ hostvars[host]['nginx']['phpsites']['fifanews']['port'] }}
    ```

要将此角色应用于清单中定义的负载均衡器主机，我们需要创建一个 play，这应该是 `site.yml` 文件的一部分，这是我们的主 playbook：

```
---
#filename: lb.yml
- hosts: lb
  remote_user: vagrant
  sudo: yes
  roles:
     - { role: haproxy, when: ansible_os_family == 'Debian' }

---
# This is a site wide playbook 
# filename: site.yml
- include: db.yml
- include: www.yml
- include: lb.yml
```

现在，使用以下命令运行 playbook：

```
$ ansible-playbook -i customhosts site.yml

```

上述运行将安装 `haproxy` 并在后端部分的 `haproxy.cfg` 文件中添加所有 web 服务器的配置。`haproxy.cfg` 文件的示例如下所示：

```
listen fifanews 0.0.0.0:8080
     cookie  SERVERID rewrite
     balance roundrobin
     server  vagrant 192.168.61.12:8080 cookie 192.168.61.12 check
```

# 访问非 playbook 主机的事实

在早期的练习中，我们启动了主 playbook，该 playbook 调用所有其他 playbook 来配置整个基础架构。有时，我们可能只想配置基础架构的一部分，在这种情况下，我们可以只调用个别的 playbook，例如 `lb.yml`、`www.yml` 或 `db.yml`。让我们尝试仅为负载均衡器运行 Ansible playbook：

```
$ ansible-playbook -i customhosts lb.yml

```

哎呀！失败了！这是输出片段的快照：

![访问非 playbook 主机的事实](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_07_03.jpg)

Ansible 因为无法从主机中找到不再属于 playbook 的变量而退出出错。下面是当涉及到魔术变量时 Ansible 的行为方式：

+   当 Ansible 在主机上运行代码时，它开始收集事实。然后将这些事实存储在内存中，以供 playbook 运行期间使用。这是默认行为，可以关闭。

+   要使主机 B 从主机 A 发现变量，Ansible 应该在 playbook 的早期与主机 A 进行通信。

Ansible 的这种行为可能导致不良结果，并且可能限制主机发现关于仅属于其自己 play 的节点的信息。

## 使用 Redis 进行事实缓存

可以通过缓存事实来避免从非 playbook 主机中发现事实的失败。此功能已在 Ansible 1.8 版本中添加，并支持在 **Redis** 中缓存事实，在内存数据存储中的键值。这需要两个更改：

+   在 Ansible 控制节点上安装并启动 Redis 服务

+   配置 Ansible 将事实发送到 Redis 实例

现在让我们使用以下命令安装并启动 Redis 服务器：

```
$ sudo apt-get install redis-server
$ sudo service redis-server start
$ apt-get install python-pip
$ pip install redis

```

这将在 Ubuntu 主机上安装 Redis 并启动服务。如果您有基于 `rpm` 包的系统，可以按照以下方式安装：

```
$ sudo yum install redis
$ sudo yum install python-pip
$ sudo service start redis
$ sudo pip install redis

```

### 提示

在启用事实缓存之前，首先检查您是否正在运行与 1.8 版本相等或更高版本的 Ansible。您可以通过运行命令 `$ ansible –version` 来执行此操作。

现在我们已经启动了 Redis，是时候配置 Ansible 了。让我们按照以下步骤编辑 `ansible.cfg` 文件：

```
# filename: /etc/ansible/ansible.cfg
# Comment  following lines 
# gathering = smart
# fact_caching = memory
# Add  following lines 
gathering = smart
fact_caching = redis
fact_caching_timeout = 86400
fact_caching_connection = localhost:6379:0
```

现在让我们通过运行配置 web 服务器的 playbook 来验证这个设置：

```
$ ansible-playbook -i customhosts www.yml
$ redis-cli 
$ keys *

```

让我们来看下面的截图：

![使用 Redis 进行事实缓存](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_07_04.jpg)

现在我们将尝试再次运行负载均衡器 playbook，使用以下命令：

```
$ ansible-playbook -i customhosts lb.yml

```

这一次成功通过。它能够发现不属于 play 的 Web 服务器的事实。

## 在文件中缓存事实

尽管使用 Redis 是推荐的方法，但也可以将事实缓存到平面文件中。Ansible 可以使用 JSON 格式将事实写入文件。要将 JSON 文件作为格式启用，我们只需编辑`ansible.cfg`文件如下：

```
   # filename: /etc/ansible/ansible.cfg 
   fact_caching = jsonfile
fact_caching_connection = /tmp/cache
```

确保指定的目录存在且具有正确的权限：

```
$ mkdir /tmp/cache
$ chmod 777 /tmp/cache

```

完成这些更改后，我们所要做的就是运行 playbook，Ansible 将开始将事实写入以此目录下创建的主机的 JSON 文件中。

# 回顾问题

你认为你已经足够理解本章了吗？试着回答以下问题来测试你的理解：

1.  神奇变量与事实变量有何不同？它们用于什么？

1.  哪个神奇变量能让我们遍历一个 Web 服务器列表，并为每个枚举一个 IP 地址？

1.  为什么需要事实缓存？缓存事实的不同模式是什么？

1.  `inventory_hostname`事实变量是否总是与`ansible_hostname`事实变量相同？

# 摘要

在本章中，您学习了如何发现群集中其他节点的信息以将它们连接在一起。我们从介绍神奇变量开始，然后看了看最常用的变量。然后，我们开始为 haproxy 创建角色，它会自动发现 Web 服务器并动态创建配置。最后，我们看了一下如何访问不在 playbook 中的主机的信息的问题，并且您学会了如何通过启用事实缓存来解决它。神奇变量非常强大，特别是在使用 Ansible 编排基础架构时，自动发现拓扑信息非常有用。

在下一章中，您将学习如何使用 vault 安全地传递数据，这是一个加密的数据存储。


# 第九章：使用 Vault 加密数据

使用变量，我们学习了如何分离数据和代码。通常提供的数据是敏感的，例如，用户密码，数据库凭据，API 密钥和其他组织特定信息。Ansible-playbooks 作为源代码，通常存储在版本控制仓库中，如 **git**，这使得在协作环境中保护这些敏感信息变得更加困难。从 1.5 版本开始，Ansible 提供了一个称为 **vault** 的解决方案，用于安全地存储和检索此类敏感信息，使用经过验证的加密技术。使用 vault 的目的是加密数据，然后可以自由地与版本控制系统（如 git）共享，而不会泄露值。

在本章中，我们将学习以下主题：

+   了解 Ansible-vault

+   使用 Ansible-vault 保护数据

+   加密、解密和重新生成密钥操作

# Ansible-vault

Ansible 提供了一个名为 Ansible-vault 的实用程序，顾名思义，让您安全地管理数据。Ansible-vault 实用程序可以让您通过启动编辑器界面创建一个加密文件，或者加密现有文件。在任何一种情况下，它都会要求输入一个 vault 密码，然后使用该密码使用 AES 密码对数据进行加密。加密内容可以存储在版本控制系统中，而不会泄露。由于 AES 基于共享密码，解密时需要提供相同的密码。提供密码有两种选项，一种是在启动 Ansible 时运行 `--ask-vault-pass` 选项以提示输入密码，另一种是使用 `--vault-password-file` 选项提供包含密码的文件路径。

## 高级加密标准

**高级加密标准**（**AES**）是一种基于 **Rijndael** 对称分组密码的加密标准，得名于两位比利时密码学家 —— Vincent Rijmen 和 Joan Daemen，并由美国国家标准与技术研究院（**NIST**）在 2001 年首次建立。AES 是美国政府用来共享机密信息的算法，并且是最流行的对称密钥密码算法。AES 也是第一个由 **国家安全局**（**NSA**）批准的公开可访问的密码。

作为一个开放和流行的标准，Ansible 使用 AES 密码，密钥长度为 256 位，用于使用 vault 加密数据。

## 使用 Vault 加密什么？

Ansible-vault 可以加密任何结构化数据。由于 YAML 本身是一种结构化语言，几乎你为 Ansible 编写的一切都符合这个标准。以下是可以使用 vault 加密的内容的指示：

+   最常见的是，我们加密变量，可能包括以下内容：

    +   角色中的变量文件，例如，`vars` 和 `defaults`

    +   存货变量，例如，`host_vars`，`group_vars`

    +   使用 `include_vars` 或 `vars_files` 包含的变量文件

    +   通过 `-e` 选项传递给 Ansible-playbook 的变量文件，例如，`-e @vars.yml` 或 `-e @vars.json`

+   由于任务和处理程序也是 JSON 数据，因此可以使用 vault 对其进行加密。但这应该很少见。建议您加密变量并在任务和处理程序中引用它们。

以下是不能使用 vault 加密的指针：

+   由于 vault 的加密单位是文件，因此无法加密部分文件或值。您可以加密完整文件或不加密。

+   文件和模板无法加密，因为它们可能与 JSON 或 YML 不同。

以下数据是加密的良好候选对象：

+   凭证，例如，数据库密码和应用凭证

+   API 密钥，例如，AWS 访问密钥和秘密密钥

+   用于 web 服务器的 SSL 密钥

+   部署的私有 SSH 密钥

# 使用 Ansible-vault

以下表列出了 Ansible-vault 实用程序提供的所有子命令：

| 子命令 | 描述 |
| --- | --- |
| `create` | 这将使用编辑器从头开始创建一个加密文件。在运行命令之前，需要设置编辑器环境变量。 |
| `edit` | 这将使用编辑器编辑现有的加密文件，而不解密内容。 |
| `encrypt` | 这将使用结构化数据加密现有文件。 |
| `decrypt` | 这将解密文件。请谨慎使用，并且不要将解密后的文件提交到版本控制中。 |
| `rekey` | 这会更改用于加密或解密的密钥或密码。 |

## 加密数据

让我们使用 Ansible-vault 执行一些操作。我们将从创建一个加密文件开始。要从头开始创建新文件，Ansible-vault 使用 `create` 子命令。在使用此子命令之前，重要的是要在环境中设置一个编辑器，如下所示：

```
# setting up vi as editor
$ export EDITOR=vi
# Generate a encrypted file
$ ansible-vault create aws_creds.yml
Vault password:
Confirm Vault password:

```

运行此命令会打开一个由编辑器环境变量指定的编辑器。下面是您可能创建的用于以访问密钥和秘密密钥形式存储 AWS 用户凭证的 `aws_creds.yml` 文件示例。然后，这些密钥将用于向 Amazon web services 云平台发出 API 调用。保存此文件并退出编辑器将生成一个加密文件：

![加密数据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_08_01.jpg)

你可以通过运行以下命令检查创建的文件类型及其内容：

```
# Check file type and content
$ file aws_creds.yml
aws_creds.yml: ASCII text
$ cat aws_creds.yml
$ANSIBLE_VAULT;1.1;AES256
64616236666362376630366435623538336565393331333331663663636237636335313234313134
3337303865323239623436646630336239653864356561640a363966393135316661636562333932
61323932313230383433313735646438623032613635623966646232306433383335326566343333
3136646536316261300a616438643463656263636237316136356163646161313365336239653434
36626135313138343939363635353563373865306266363532386537623463623464376134353863
37646638636231303461343564343232343837356662316262356537653066356465353432396436
31336664313661306630653765356161616266653232316637653132356661343162396331353863
34356632373963663230373866313961386435663463656561373461623830656261636564313464
37383465353665623830623363353161363033613064343932663432653666633538

```

## 更新加密数据

要更新添加到加密文件中的 AWS 密钥，可以稍后使用 Ansible-vault 的 `edit` 子命令，如下所示：

```
$ ansible-vault edit aws_creds.yml
Vault password:

```

`edit` 命令执行以下操作：

1.  提示输入密码

1.  使用 AES 对称密码，即时解密文件

1.  打开编辑器界面，允许您更改文件的内容

1.  将文件保存后再次加密

还有另一种更新文件内容的方法。您可以按如下方式解密文件：

```
$ ansible-vault decrypt aws_creds.yml
Vault password:
Decryption successful

```

更新后，该文件可以像之前学过的那样再次加密。

## 旋转加密密钥

作为良好的安全实践，经常更改 Ansible-vault 使用的加密密钥是个好主意。当这种情况发生时，重新为之前使用 vault 加密的所有文件重新生成密钥是至关重要的。Ansible vault 提供了一个 `rekey` 子命令，可以如下使用：

```
$ ansible-vault rekey aws_creds.yml
Vault password:
New Vault password:
Confirm New Vault password:
Rekey successful

```

它要求输入当前密码，然后允许您指定并确认新密码。请注意，如果您正在使用版本控制管理此文件，则还需要提交更改。即使实际内容未更改，重新生成操作也会更新所创建的结果文件，该文件是我们存储库的一部分。

# 加密数据库凭据

早些时候在创建数据库用户时，我们在 `group_vars` 中以明文提供了密码。这可能是一个潜在的威胁，特别是当提交到版本控制存储库时。让我们加密它。我们将使用 `encrypt` 子命令，因为我们已经有了一个变量文件。

由于我们使用 `group_vars` 组提供数据库凭据，因此我们将如下加密 `group_vars/all` 文件：

```
$ ansible-vault encrypt group_vars/all
Vault password:
Confirm Vault password:
Encryption successful

```

对于加密，Ansible-vault 要求用户输入密码或密钥。使用此密钥，vault 加密数据并用加密内容替换文件。以下图表显示了 `group_vars/all` 文件的左侧明文内容和等效的右侧加密内容：

![加密数据库凭据](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_08_02.jpg)

现在此文件可以安全地检入版本控制系统并共享。但是，以下是用户应该注意的注意事项：

+   与纯文本不同，结果文件是以加密格式存储的。不可能获得不同的文件格式，例如 `git diff`，以便在提交到版本控制时比较更改。

+   无法直接在此文件上使用 `grep`、`sed` 或任何文本搜索或操作程序。唯一的方法是先解密它，运行文本操作工具，然后再加密回去。

### 提示

确保您为要在一个 Ansible-playbook 运行中解密的所有文件使用相同的密码。Ansible 一次只能接受一个密码值，如果在同一 playbook 中使用不同的密码对文件进行加密，则会失败。

现在让我们使用以下命令运行 Ansible playbook：

```
$ ansible-playbook -i customhosts site.yml
ERROR: A vault password must be specified to decrypt /vagrant/chap8/group_vars/all

```

它以错误失败！这是因为我们正在为 playbook 提供加密数据，而没有解密它的密钥。vault 的主要用途是在 Ansible 存储库中保护数据。最终，在运行 playbook 时需要解密这些值。解密密码可以使用 `--ask-vault-pass` 选项指定，如下所示：

```
$ ansible-playbook -i customhosts site.yml --ask-vault-pass

```

这将提示输入 "Vault 密码"，然后继续像往常一样运行 Ansible 代码。

# 使用密码文件

每次输入密码可能不是理想的。通常情况下，您可能还希望自动化启动 Ansible playbook 运行的过程，在这种情况下，交互式方式是不可行的。可以通过将密码存储在文件中并将文件提供给 Ansible playbook 运行来避免这种情况。密码应作为单行字符串提供在此文件中。

让我们创建一个密码文件并使用正确的权限保护它：

```
$ echo "password" > ~/.vault_pass
(replace password with your own secret)
$ chmod 600 ~/.vault_pass

```

### 提示

当保险库密码存储为明文时，任何访问此文件的人都可以解密数据。确保密码文件受到适当权限的保护，并且不添加到版本控制中。如果决定对其进行版本控制，请使用**gpg**或等效措施。

现在可以将此文件提供给 Ansible playbook，如下所示：

```
$ ansible-playbook -i customhosts site.yml --vault-password-file ~/.vault_pass

```

# 将保险库密码文件选项添加到 Ansible 配置

使用版本 1.7，还可以将`vault_password_file`选项添加到`ansible.cfg`文件的默认部分。

考虑以下：

```
[defaults]
  vault_password_file = ~/.vault_pass
```

上述选项使您可以自由地不需要每次都指定加密密码或密码文件。让我们看一下以下命令：

```
# launch ansible playbook run with encrypted data
# with vault_password_file option set in the config
$ ansible-playbook -i customhosts site.yml
$ ansible-vault encrypt roles/mysql/defaults/main.yml
Encryption successful
$ ansible-vault decrypt roles/mysql/defaults/main.yml
Decryption successful

```

此外，在从版本 1.7 开始时，可以将脚本提供给`vault_password_file`选项，而不是在文件中存储明文密码。使用脚本时，请确保：

+   脚本上启用了执行位

+   调用此脚本会在标准输出上输出密码。

+   如果脚本提示用户输入，则可以将其发送到标准错误

## 在模板中使用加密数据

您之前了解到，由于模板可能不是结构化文件，如 YAML 或 JSON，因此它无法加密。但是，有一种方法可以向模板添加加密数据。请记住，模板最终是即时生成的，动态内容实际上来自变量，这些变量可以加密。让我们讨论如何通过为 Nginx Web 服务器添加 SSL 支持来实现这一点。

## 为 Nginx 添加 SSL 支持

我们已经设置了一个 Nginx Web 服务器，现在让我们通过以下步骤为默认站点添加 SSL 支持：

1.  我们首先添加变量，如下所示：

    ```
    #file: roles/nginx/defaults/main.yml 
    nginx_ssl: true
    nginx_port_ssl: 443
    nginx_ssl_path: /etc/nginx/ssl
    nginx_ssl_cert_file: nginx.crt
    nginx_ssl_key_file: nginx.key
    ```

1.  让我们也创建自签名的 SSL 证书：

    ```
    $ openssl req -x509 -nodes -newkey rsa:2048 -keyout nginx.key -out nginx.crt

    ```

    上述命令将生成两个文件，`nginx.key`和`nginx.crt`。这些是我们将复制到 Web 服务器的文件。

1.  将这些文件的内容添加到变量中，并创建`group_vars/www`文件：

    ```
    # file: group_vars/www
    ---
    nginx_ssl_cert_content: |
        -----BEGIN CERTIFICATE-----
        -----END CERTIFICATE-----
    nginx_ssl_key_content: |
        -----BEGIN PRIVATE KEY-----
        -----END PRIVATE KEY-----
    ```

    在上述示例中，我们只是添加了将要替换为密钥和证书实际内容的占位符。这些密钥和证书不应暴露在版本控制系统中。

1.  让我们使用保险库加密此文件：

    ```
    $ ansible-vault encrypt group_vars/www
    Encryption successful

    ```

    由于我们已经在配置中提供了保险库密码的路径，因此 Ansible-vault 不会询问密码。

1.  现在让我们创建模板，以添加这些密钥：

    ```
    # filename: roles/nginx/templates/nginx.crt.j2
    {{ nginx_ssl_cert_content }}

    # filename: roles/nginx/templates/nginx.key.j2
    {{ nginx_ssl_key_content }}
    ```

1.  还要将一个虚拟主机`config`文件添加到 SSL 中：

    ```
    # filename: roles/nginx/templates/nginx.key.j2
    server {
      listen {{ nginx_port_ssl }};
      server_name {{ ansible_hostname }};
      ssl on;
      ssl_certificate {{ nginx_ssl_path }}/{{ nginx_ssl_cert_file }};
      ssl_certificate_key {{ nginx_ssl_path }}/{{ nginx_ssl_key_file }};

      location / {
        root {{ nginx_root }};
        index {{ nginx_index }};
      }
    }
    ```

1.  我们还需要创建一个任务文件来配置 SSL 站点，该文件将创建所需的目录、文件和配置：

    ```
    ---
    # filename: roles/nginx/tasks/configure_ssl.yml
     - name: create ssl directory
        file: path="{{ nginx_ssl_path }}" state=directory owner=root group=root
     - name: add ssl key 
        template: src=nginx.key.j2 dest="{{ nginx_ssl_path }}/nginx.key" mode=0644
     - name: add ssl cert 
        template: src=nginx.crt.j2 dest="{{ nginx_ssl_path }}/nginx.crt" mode=0644
     - name: create ssl site configurations 
        template: src=default_ssl.conf.j2 dest="{{ nginx_ssl_path }}/default_ssl.conf" mode=0644
        notify:
        - restart nginx service
    ```

1.  最后，让我们根据`nginx_ssl var`参数是否设置为 true 来选择性地调用此任务：

    ```
    # filename: roles/nginx/tasks/main.yml
     - include: configure_ssl.yml
        when: nginx_ssl
    ```

1.  现在，按照以下方式运行 playbook：

    ```
    $ ansible-playbook -i customhosts  site.yml

    ```

这应该配置在端口`443`上运行的默认 SSL 站点，使用自签名证书。现在，您应该能够使用`https`安全协议打开 Web 服务器地址，如下所示：

![为 Nginx 添加 SSL 支持](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_08_03.jpg)

当然，由于我们的证书是自签名的，而不是由指定的认证机构提供的，应该显示警告。

# 复习问题

你认为你已经足够理解这一章了吗？尝试回答以下问题来测试你的理解：

1.  为什么需要加密提供给 Ansible playbooks 的数据？

1.  AES 是什么，对称密钥密码是什么？

1.  更新之前使用 vault 加密的文件的两种方法是什么？

1.  添加到 Ansible 配置文件的参数，使其了解保险库密码文件的位置是什么？

# 摘要

在本章中，您学习了如何使用 Ansible-vault 对传递给 playbooks 的数据进行安全保护。我们从加密数据的需求开始，讲解了 vault 的工作原理以及它使用的密码。然后，我们开始深入了解 Ansible-vault 实用程序以及创建加密文件、解密、重新密钥等基本操作。您还学习了如何通过在持有数据库凭据的`vars`文件上运行 Ansible-vault 来加密现有文件。最后，我们为 Nginx 添加了 SSL 支持，您学会了如何使用 vault 安全地存储 Web 服务器的私钥和证书，并使用模板将它们复制。请注意，Ansible vault 提供了一种安全地向 Ansible 模块提供数据的方式。除了使用 vault 之外，还建议采取其他系统安全措施，这不在本文的讨论范围内。

在了解了 vault 之后，在下一章中，我们将开始学习使用 Ansible 管理多个环境（如开发、演示和生产）的各种方法。这些环境通常映射到软件开发工作流程。


# 第十章：管理环境

大多数组织在构建其基础架构时从单个环境开始。然而，随着复杂性的增长，我们必须有一个工作流程，涉及在开发环境中编写代码并对其进行测试，然后在预备或预生产环境中进行密集的 QA 循环，以确保代码在生产环境中的稳定性得到测试，然后我们最终发布它。为了模拟真实世界的行为，这些环境必须运行相同的应用程序堆栈，但很可能在不同的规模下运行。例如，预备环境将是生产的小规模副本，服务器较少，最常见的情况是，开发环境将在虚拟化环境中的个人工作站上运行。尽管所有这些环境都运行相同的应用程序堆栈，但它们必须彼此隔离，并且必须具有特定于环境的配置，如下所述：

+   `dev` 组中的应用程序不应指向预备中的数据库，反之亦然

+   生产环境可能有自己的软件包存储库

+   测试环境可能在端口 `8080` 上运行 Web 服务器，而其他所有环境都在端口 `80` 上运行

通过角色，我们可以创建一个模块化的代码来为所有环境配置相同的环境。 Ansible 的另一个重要特性是将代码与数据分开的能力。结合使用这两者，我们可以将基础架构建模成这样一种方式，我们可以创建特定于环境的配置，而无需修改角色。我们只需提供来自不同位置的变量即可创建它们。让我们来看一下下面的截图：

![管理环境](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_09_01.jpg)

前面的图示了同一组织内的三个不同环境，即开发、预备和生产环境。这三个环境都运行相同的应用程序堆栈，其中包括负载均衡器、Web 服务器和数据库服务器。但需要注意的两点是：

+   每个环境根据其规模不同，可以配置运行一个或多个角色（例如，`db` 加 `www`）的主机。

+   每个环境都与其他环境隔离开来。生产环境中的 Web 服务器不会连接到预备环境中的数据库，反之亦然。

在本章中，我们将介绍以下主题：

+   使用 Ansible 管理多个环境

+   分隔不同环境的库存文件

+   使用 `group_vars` 和 `host_vars` 组指定特定于环境的配置

# 管理环境的方法

您已经了解到需要创建具有相同角色但具有不同数据的不同环境。在撰写本文时，使用 Ansible 管理此类多个环境场景的方法不止一种。我们将在这里讨论两种方法，并且您可以根据自己的判断选择其中之一或创建您自己的方法。没有明确的创建环境的方式，但是以下是 Ansible 的内置功能，可能会派上用场：

+   使用清单将属于一个环境的主机分组并将它们与其他环境中的主机隔离开来

+   使用清单变量，如`group_vars`和`host_vars`组，提供特定于环境的变量

在我们继续之前，回顾一下适用于清单组、变量和优先规则的清单组将会很有用。

## 清单组和变量

您已经学习了 Ansible 清单遵循 INI 样式配置的需求，其中主机与方括号括起来的组标签一起组合，如下图所示：

![清单组和变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_09_02.jpg)

然后可以指定清单变量，以使其与这些组名称匹配，使用`group_vars`或在`host_vars`文件中匹配特定主机。除了这些组名称之外，还可以使用一个名为"`all`"的文件为`group_vars`和`host_vars`文件指定默认变量，从而产生以下结构：

![清单组和变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_09_03.jpg)

在这种情况下，如果你在`all`和`webserver`文件中指定了相同的变量，那么更具体的变量将优先。这意味着，如果你在`group_vars`下的`webserver`组中重新定义了一个变量，而在`all`中也定义了它，那么参数的值将被设置为在`webserver`中定义的更具体的值。这是我们在下面的方法中利用的行为。

## 方法 1 – 使用清单中的嵌套组

除了能够使用 INI 样式创建组外，Ansible 还支持嵌套组，其中一个完整的组可以是另一个父组的一部分。第一种方法就是基于这个特性的，并且将逐步讨论，如下所示：

1.  创建一个环境目录，用于存储特定环境的清单文件。最好以环境命名它们。添加属于该环境的主机并对它们进行分组。一个组可以根据任何标准进行分组，比如角色、位置、服务器机架等等。例如，创建一个名为"`webservers`"的组来添加所有的 Apache web 服务器，或者一个名为"`in`"的组来添加所有属于该位置的主机。

1.  添加一个以环境名称命名的父组，例如，production、development、staging 等，并将属于该环境的所有其他组包括为子组。每个这样的组又包括一组主机，例如：

    ```
    [dev:children]
      webservers
      databases
    ```

1.  现在，在`group_vars/all`文件中创建通用/默认组变量。然后，可以从特定于环境的文件中覆盖这些变量。

1.  要指定环境特定的变量，请创建`group_vars/{{env}}`文件，如下所示：

    ```
    group_vars
      |_ all
      |_ dev
      |_ stage
    ```

这也将覆盖`all`组中的变量。以下图示了使用此方法创建的文件结构： 

![方法 1 – 在清单中使用嵌套组](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_09_04.jpg)

创建完毕后，只需运行`ansible-playbook`命令即可调用特定于环境的清单。

例如，让我们看一下以下命令：

```
$ ansible-playbook -i environments/dev site.yml

```

## 方法 2 – 使用环境特定的清单变量

第二种方法不需要嵌套组，并依赖于 Ansible 的以下两个特性：

+   Ansible-playbook 的 `-i` 选项还接受一个目录，该目录可以包含一个或多个清单文件

+   主机和组变量可以相对于清单文件，并且还可以相对于 Ansible 仓库根目录中的`group_vars`和`host_vars`组

这种方法将为每个环境创建完全隔离的变量文件。我们创建的文件结构如下图所示：

![方法 2 – 使用环境特定的清单变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_09_05.jpg)

以下是用于此方法的逐步方法：

1.  在 Ansible 仓库的根目录下创建一个名为环境的目录。在此目录下，为每个环境创建一个目录。

1.  每个环境目录包含两个内容：

    +   主机清单。

    +   清单变量，例如，`group_vars`和`host_vars`。为了进行环境特定的更改，我们关注`group_vars`。

1.  每个环境都包含自己的`group_vars`目录，该目录又可以包含一个或多个文件，包括默认的`all`文件。没有两个环境共享这些变量。

### 提示

**注意**: 除了特定于环境的`group_vars`组外，还可以使用位于 Ansible-playbook 仓库顶部的`group_vars`文件。但是，建议不要在此方法中使用它，因为如果值相同，环境特定更改将被 playbook 的`group_vars`中的值覆盖。

使用此方法，可以针对特定环境启动 playbook，如下所示：

```
$ ansible-playbook -i environments/dev site.py

```

在这里，`environments/dev`是一个目录。

# 创建一个开发环境

在了解了如何管理环境之后，让我们尝试通过重构现有代码并创建一个 dev 环境来实践一下。为了测试它，让我们创建一个名为"`env_name`"的变量，并将 Nginx 的默认页面动态使用该变量并打印环境名称。然后，我们将尝试从环境中覆盖此变量。让我们看看以下步骤：

1.  让我们从设置默认变量开始：

    ```
    #group_vars/all
    env_name: default
    ```

1.  然后，在`roles/nginx/tasks/configure.yml`文件中，将 Nginx 任务更改为使用模板而不是静态文件，因此进行以下修改：

    ```
     - name: create home page for default site
        copy: src=index.html dest=/usr/share/nginx/html/index.html
    ```

    将其修改为以下代码：

    ```
     - name: create home page for default site
       template:
         src: index.html.j2
         dest: /usr/share/nginx/html/index.html
    ```

1.  现在，让我们尝试运行 playbook 而不创建环境：

    ```
    $ ansible-playbook -i customhosts www.yml

    ```

1.  运行完成后，让我们检查默认网页：![创建开发环境](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_09_06.jpg)

1.  它打印了我们从`group_vars/all`文件中设置的变量的值，默认值。

1.  现在，让我们创建一个文件，以便我们可以管理`dev`环境。由于我们将使用相同的一组主机，因此我们可以将现有的清单转换为 dev，并在环境名称后添加一个父组：

    ```
    $ mkdir environments/
    $ mv customhosts environments/dev 
     [ edit  environments/dev ]

    ```

1.  将所有组添加到`dev`环境中，如下所示：

    ```
    [dev:children]
    db
    www
    lb
    ```

    清单文件如下所示，我们必须进行以下更改：

    1.  现在，让我们为`dev`环境创建一个`group_vars`文件，并覆盖环境名称：

        ```
          #file: environments/dev
        env_name: dev
        ```

    1.  这一次，我们将以以下方式运行 playbook：

        ```
        $ ansible-playbook -i environments/dev www.yml

        ```

    我们将看到以下截图作为输出：

    ![创建开发环境](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_09_08.jpg)

# 复习问题

您是否认为自己已经足够了解本章了？尝试回答以下问题来测试您的理解：

1.  如何为同一环境指定多个主机清单？

1.  如果您在`environments/dev/group_vars/all`文件中定义了一个变量，同时在`group_vars/all`文件中也定义了相同的变量，哪个会优先？

1.  如何在主机清单文件中创建一组组？

# 概要

在本章中，您学习了如何创建与软件开发工作流程或阶段相对应的多个环境。我们从清单组和清单变量的简要概述开始，特别是`group_vars`文件。接着是用于管理环境的两种方法。最后，我们重构了我们的代码，继续创建了`dev`环境，并通过覆盖环境中的一个变量进行了测试。在下一章中，您将学习有关基础设施编排以及 Ansible 在编排复杂基础设施工作流程、零停机部署等方面的优势。


# 第十一章：使用 Ansible 编排基础架构

在不同的情况下使用编排可能意味着不同的事情。以下是一些编排场景的描述：

+   在一组主机上并行运行临时命令，例如，使用 `for` 循环遍历一组 Web 服务器以重新启动 Apache 服务。这是最原始的编排形式。

+   调用编排引擎启动另一个配置管理工具以确保正确的顺序。

+   以特定顺序配置多层应用程序基础设施，并能够对每个步骤进行精细控制，并且在配置多个组件时具有来回移动的灵活性。例如，安装数据库，设置 Web 服务器，返回数据库，创建模式，转到 Web 服务器以启动服务等。

大多数实际场景与最后一个场景相似，涉及多层应用堆栈和多个环境，重要的是按照一定顺序和协调的方式启动和更新节点。在继续下一步之前测试应用程序是否正常运行也很有用。首次设置堆栈与推送更新的工作流可能不同。有时您可能不希望立即更新所有服务器，而是分批处理以避免停机时间。

在本章中，我们将介绍以下主题：

+   编排场景

+   将 Ansible 用作基础架构编排引擎

+   实施滚动更新

+   使用标签、限制和模式

+   将测试构建到剧本中

# Ansible 作为编排器

在任何编排情景下，Ansible 都比其他工具更加出色。当然，正如 Ansible 的创建者所说，它不仅是一个配置管理工具，这是真的。 Ansible 可以在前面讨论的任何编排场景中找到自己的位置。它旨在管理复杂的多层部署。即使您的基础架构已经使用其他配置管理工具自动化了，您也可以考虑使用 Ansible 来编排这些工具。

让我们讨论 Ansible 提供的具体功能，这些功能对编排非常有用。

## 多个剧本和顺序

与大多数其他配置管理系统不同，Ansible 支持在不同时间运行不同的剧本来配置或管理相同的基础架构。您可以创建一个剧本来首次设置应用程序堆栈，另一个剧本按照一定的方式推送更新。剧本的另一个属性是它可以包含多个播放，这允许将应用程序堆栈中每个层的主机分组，并同时对其进行配置。

## 预任务和后任务

我们之前使用过前置任务和后置任务，在编排过程中非常相关，因为这些任务允许我们在运行播放之前和之后执行任务或运行验证。让我们以更新注册在负载均衡器上的 Web 服务器为例。使用前置任务，可以将 Web 服务器从负载均衡器中移除，然后将角色应用于 Web 服务器以推送更新，随后是后置任务，将 Web 服务器重新注册到负载均衡器中。此外，如果这些服务器由 **Nagios** 监控，可以在更新过程中禁用警报，然后使用前置任务和后置任务自动重新启用。这可以避免监控工具可能以警报的形式产生的噪音。

## 委托

如果你希望任务选择性地在某一类主机上运行，特别是当前播放范围之外的主机，Ansible 的委托功能会很方便。这与之前讨论的场景相关，并且通常与前置任务和后置任务一起使用。例如，在更新 Web 服务器之前，需要将其从负载均衡器中注销。现在，这个任务应该在播放范围之外的负载均衡器上运行。可以通过使用委托功能来解决这个问题。使用前置任务时，可以使用 `delegate_to` 关键字在负载均衡器上启动脚本，执行注销操作，如下所示：

```
- name: deregister web server from lb
  shell: < script to run on lb host >
  delegate_to: lbIf there areis more than one load balancers, anan inventory group can be iterated over as, follows: 
- name: deregister web server from lb
  shell: < script to run on lb host >
  delegate_to: "{{ item }}"
  with_items: groups.lb
```

## 滚动更新

这也被称为批量更新或零停机更新。假设我们有 100 个需要更新的 Web 服务器。如果我们在清单中定义它们并针对它们启动 playbook，Ansible 将同时开始更新所有主机。这也可能导致停机时间。为了避免完全停机并实现无缝更新，有意义的做法是分批更新，例如，每次更新 20 个。在运行 playbook 时，可以使用 `serial` 关键字指定批处理大小。让我们看一下以下代码片段：

```
- hosts: www
  remote_user: vagrant
  sudo: yes
  serial: 20 
```

## 测试

在编排过程中，不仅要按顺序配置应用程序，还要确保它们实际启动并按预期工作。Ansible 模块，如 `wait_for` 和 `uri`，可以帮助您将这些测试构建到 playbooks 中，例如：

```
- name: wait for mysql to be up
  wait_for: host=db.example.org port=3106 state=started
- name: check if a uri returns content
  uri: url=http://{{ inventory_hostname }}/api
  register: apicheck
```

`wait_for` 模块可以额外用于测试文件的存在。当你希望在继续之前等待服务可用时，它也非常有用。

## 标签

Ansible play 将角色映射到特定的主机。在运行 play 时，会执行从主要任务调用的整个逻辑。在编排时，我们可能只需要根据我们想要将基础架构带入的阶段来运行部分任务。一个例子是 zookeeper 集群，重要的是同时启动集群中的所有节点，或者在几秒钟的间隔内。Ansible 可以通过两阶段执行来轻松地实现这一点。在第一阶段，您可以在所有节点上安装和配置应用程序，但不启动它。第二阶段涉及几乎同时在所有节点上启动应用程序。这可以通过给个别任务打标签来实现，例如，configure、install、service 等。

举个例子，让我们来看下面的屏幕截图：

![标签](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_10_01.jpg)

在运行 playbook 时，所有具有特定标签的任务可以使用`--tags`来调用，如下所示：

```
$ Ansible-playbook -i customhosts site.yml –-tags install

```

标签不仅可以应用于任务，还可以应用于角色，如下所示：

```
{ role: nginx, when: Ansible_os_family == 'Debian', tags: 'www' }
```

如果一个特定的任务需要始终执行，即使通过标签进行过滤，使用一个名为`always`的特殊标签。这将使任务执行，除非使用了覆盖选项，比如`--skip-tags always`。

## 模式和限制

限制可以用来在主机的一个子集上运行任务，这些主机是通过模式进行筛选的。例如，以下代码将仅在属于`db`组的主机上运行任务：

```
$ Ansible-playbook -i customhosts site.yml --limit db

```

模式通常包含一组要包括或排除的主机。可以指定一个以上的模式组合，如下所示：

```
$ Ansible-playbook -i customhosts site.yml --limit db,lb

```

使用冒号作为分隔符可以进一步过滤主机。以下命令将在除了属于`www`和`db`组的主机之外的所有主机上运行任务：

```
$ Ansible-playbook -i customhosts site.yml --limit 'all:!www:!db'

```

请注意，通常这需要用引号括起来。在这个模式中，我们使用了`all`组，该组匹配清单中的所有主机，并且可以用`*`替代。接着是`!`来排除`db`组中的主机。这个命令的输出如下，显示了由于先前使用的过滤器，名称为`db`和`www`的 play 被跳过了，因为没有主机匹配：

![模式和限制](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/asb-plbk-ess/img/B03800_10_02.jpg)

现在让我们看看这些编排特性是如何运作的。我们将首先给角色打上标签，进而进行多阶段执行，然后编写一个新的 playbook 来管理对 WordPress 应用程序的更新。

# 给角色打标签

现在让我们开始给之前创建的角色打上标签。我们将创建以下标签，这些标签对应着应用程序管理中的阶段：

+   安装

+   配置

+   开始

这是给`haproxy`角色添加标签的例子。为了避免冗余，将其他角色加上标签的操作从文本中排除掉。我们可以给角色内的任务添加标签，或者在 playbook 中给整个角色加上标签。让我们从给任务加标签开始：

```
---
# filename: roles/haproxy/tasks/install.yml
  - name: install haproxy
    apt:
      name: "{{ haproxy['pkg'] }}"
    tags:
     - install

---
# filename: roles/haproxy/tasks/configure.yml
 - name: create haproxy config
    template: src="img/haproxy.cfg.j2" dest="{{ haproxy['config']['cnfpath'] }}" mode=0644
   notify:
    - restart haproxy service
   tags:
    - configure

 - name: enable haproxy
    template: src="img/haproxy.default.j2" dest=/and more/default/haproxy mode=0644
    notify:
    - restart haproxy service
    tags:
    - configure

---
# filename: roles/haproxy/tasks/service.yml
 - name: start haproxy server
    service:
      name: "{{ haproxy['service'] }}" 
      state: started
    tags:
    - start
```

在角色中打上标签后，我们还会在 playbooks 中打上角色的标签，如下所示：

```
# filename: db.yml
  roles:
- { role: mysql, tags: 'mysql' }

#filename: www.yml
  roles:
     - { role: nginx, when: Ansible_os_family == 'Debian', tags: [ 'www', 'nginx' ] }
     - { role: php5-fpm, tags: [ 'www', 'php5-fpm' ] }
     - { role: wordpress, tags: [ 'www', 'wordpress' ] }

#filename: lb.yml
  roles:
- { role: haproxy, when: Ansible_os_family == 'Debian', tags: 'haproxy' }
```

应用后，我们主要 playbook 的标签可以列举如下：

```
$ Ansible-playbook -i customhosts site.yml --list-tags

#Output:
playbook: site.yml

 play #1 (db): TAGS: []
 TASK TAGS: [configure, install, mysql, start]

 play #2 (www): TAGS: []
 TASK TAGS: [configure, install, nginx, php5-fpm, ssl, start, wordpress, www]

 play #3 (lb): TAGS: []
 TASK TAGS: [configure, haproxy, install, start]

```

使用标签和限制的组合使我们能够在 playbook 运行中精细控制执行的内容，例如：

```
# Run install tasks for haproxy, 
$ Ansible-playbook -i customhosts site.yml --tags=install --limit lb

# Install and configure all but web servers
$ Ansible-playbook -i customhosts site.yml --tags=install,configure --limit 'all:!www'

# Run all tasks with tag nginx
$ Ansible-playbook -i customhosts site.yml --tags=nginx

```

# 为 WordPress 创建一个编排 playbook

我们有一个站点范围的 playbook，即`site.yml`文件，该文件用于安装和配置完整的 WordPress 堆栈。然而，要实现无停机更新应用程序以及部署新版本，`site.yml`文件并不是理想的 playbook。我们希望遵循一个涉及以下步骤的工作流程：

1.  逐个更新 Web 服务器。这将避免任何停机时间。

1.  在更新之前，从 haproxy 负载均衡器中注销 Web 服务器。这将停止流量流向 Web 服务器，以避免停机时间。

1.  运行与 WordPress 应用程序相关的角色，即 Nginx、php5-fpm 和 WordPress。

1.  确保 Web 服务器正在运行并监听端口 80。

1.  将服务器重新注册到 haproxy 并重新开始发送流量。

让我们创建一个名为`update.yml`的 playbook，它正如之前解释的一样进行编排，并且使用了本章前面讨论的大部分功能。以下是这个 playbook：

```
 ---
# Playbook for updating web server in batches
# filename: update_www.yml
- hosts: www
  remote_user: vagrant
  sudo: yes
  serial: 1
  pre_tasks:
    - name: deregister web server from  load balancer
    shell: echo "disable server fifanews/{{ Ansible_hostname }}" | socat stdio /var/lib/haproxystats
    delegate_to: "{{ item }}"
    with_items: groups.lb
  roles:
    - { role: nginx, when: Ansible_os_family == 'Debian' }
    - php5-fpm
    - wordpress
  post_tasks:
    - name: wait for web server to come up 
    wait_for: host={{ inventory_hostname }} port=80 state=started
    - name: register webserver from  load balancer
    shell: echo "enable server fifanews/{{ Ansible_hostname }}" | socat stdio /var/lib/haproxystats
    delegate_to: "{{ item }}"
    with_items: groups.lb
```

让我们分析这段代码：

+   playbook 只包含一个 play，该 play 在属于`www 组`的主机上运行。

+   serial 关键字指定批大小，并允许无停机滚动更新。在我们的情况下，由于主机较少，我们选择逐个更新一个 Web 服务器。

+   在应用该角色之前，使用预任务部分从负载平衡器中注销主机，该部分运行一个带有**socat**的 shell 命令。这在所有负载平衡器上使用`delegate`关键字运行。Socat 是类似于并且功能更为丰富的 Unix 实用程序（nc）。

+   在注销主机后，应用角色；这将更新 Web 服务器的配置或部署新代码。

+   更新后，执行后任务，首先等待 Web 服务器启动并监听端口 80，只有在 Web 服务器准备就绪时，才将其重新注册到负载平衡器。

# 复习问题

你认为你已经足够了解本章了吗？尝试回答以下问题来测试你的理解：

1.  是否可能使用 Ansible 来编排另一个配置管理工具？

1.  如何使用 Ansible 实现无停机部署应用程序？

1.  `--limit`命令对 Ansible playbook 有什么作用？

1.  如何在 playbook 中针对给定角色运行任务的子集？

1.  使用预任务和后任务的目的是什么？

1.  可以使用哪些模块来从 playbook 运行测试？

1.  `always`标签为何如此特殊？

# 总结

我们在本章开始时讨论了编排是什么，不同的编排场景是什么，以及 Ansible 如何适应其中。您了解了 Ansible 在编排背景下的一系列丰富功能。这包括多 playbook 支持、预任务和后任务、标签和限制、运行测试等等。我们继续为之前创建的角色打标签，并学习如何使用标签、模式和限制的组合控制代码在哪些机器上运行的部分。最后，我们创建了一个新的 playbook 来编排工作流，更新 Web 服务器，其中包括零停机部署、委托、预任务和后任务以及测试。您还了解到 Ansible 可以适用于任何编排场景中。

这就是本书的结尾。在结束之前，我代表审阅者、编辑、贡献者和出版团队的其他成员，感谢您将本书视为您成为 Ansible 实践者的伴侣之一。

我们希望您现在已经熟悉了 Ansible 提供的各种原语，用于自动化常见基础设施任务、创建动态角色、管理多层应用程序配置、零停机部署、编排复杂基础设施等。我们希望您能够应用本书中所学知识创建有效的 Ansible playbook。


# 附录 A. 参考资料

有关 Ansible 的更多信息，请参阅以下网址：

+   **Ansible 文档**：[`docs.ansible.com/`](http://docs.ansible.com/)

+   **Jinja2 模板文档**：[`jinja.pocoo.org/docs/dev/`](http://jinja.pocoo.org/docs/dev/)

+   **Ansible 示例 Playbooks**：[`github.com/ansible/ansible-examples`](https://github.com/ansible/ansible-examples)

+   **由 Benno Joy 和 Jeff Geerling 撰写的 Ansible MySQL 角色**：

    +   [`github.com/bennojoy/mysql`](https://github.com/bennojoy/mysql)

    +   [`github.com/geerlingguy/ansible-role-mysql`](https://github.com/geerlingguy/ansible-role-mysql)

+   **Ansible Nginx 角色 by Benno Joy 和 DAUPHANT Julien**：[`github.com/jdauphant/ansible-role-nginx`](https://github.com/jdauphant/ansible-role-nginx)

+   **使用 Ansible 的多阶段环境**：[`rosstuck.com/multistage-environments-with-ansible/`](http://rosstuck.com/multistage-environments-with-ansible/)

+   **Ansible 项目关于如何创建 Ansible 环境的 Google 群组帖子**：[`groups.google.com/forum/#!topic/ansible-project/jd3cuR7rqCE`](https://groups.google.com/forum/#!topic/ansible-project/jd3cuR7rqCE)

+   **Jan-Piet Mens 撰写的 Ansible 中缓存事实的文章**：[`jpmens.net/2015/01/29/caching-facts-in-ansible/`](http://jpmens.net/2015/01/29/caching-facts-in-ansible/)

+   **Orchestration，You keep Using that Word by Michael DeHaan**：[`www.ansible.com/blog/orchestration-you-keep-using-that-word`](http://www.ansible.com/blog/orchestration-you-keep-using-that-word)
