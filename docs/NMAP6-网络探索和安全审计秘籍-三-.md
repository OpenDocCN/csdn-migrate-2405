# NMAP6 网络探索和安全审计秘籍（三）

> 原文：[`annas-archive.org/md5/0DC464DD8E91DC475CC40B74E4774B2B`](https://annas-archive.org/md5/0DC464DD8E91DC475CC40B74E4774B2B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：审计数据库

### 注意

本章向您展示了如何执行在许多情况下可能是非法、不道德、违反服务条款或不明智的一些操作。这里提供这些信息是为了让您了解如何保护自己免受威胁，并使自己的系统更加安全。在遵循这些说明之前，请确保您站在法律和道德的一边...运用您的力量为善！

在本章中，我们将涵盖：

+   列出 MySQL 数据库

+   列出 MySQL 用户

+   列出 MySQL 变量

+   在 MySQL 服务器中查找空密码的 root 帐户

+   暴力破解 MySQL 密码

+   检测 MySQL 服务器中的不安全配置

+   暴力破解 Oracle 密码

+   暴力破解 Oracle SID 名称

+   检索 MS SQL 服务器信息

+   暴力破解 MS SQL 密码

+   转储 MS SQL 服务器的密码哈希

+   在 MS SQL 服务器上通过命令行运行命令

+   在 MS SQL 服务器上查找具有空密码的 sysadmin 帐户

+   列出 MongoDB 数据库

+   检索 MongoDB 服务器信息

+   列出 CouchDB 数据库

+   检索 CouchDB 数据库统计信息

# 介绍

Web 应用程序必须存储不同类型的信息。根据情况，可能需要存储数百万条记录，并且这就是数据库的用武之地。数据库服务器至关重要，因为它们提供了一种方便的管理信息的方式，并且几乎可以为任何语言和数据库类型提供编程 API。

Nmap NSE 已经为许多数据库服务器添加了支持。系统管理员会发现，借助 Nmap，我们可以自动化处理与一堆数据库服务器打交道时的几项任务，例如运行查询以通知我们有关状态。另一方面，谨慎地保护数据库服务器必须小心进行，并且与保护 Web 服务器一样重要。Nmap 还通过支持自动化操作（例如检查空的 root 密码和不安全配置）来帮助我们。

本章涵盖了最常见的关系数据库（如 MySQL、MS SQL 和 Oracle）和`nosql`数据库（如 CouchDB 和 MongoDB）的不同 NSE 脚本。我们首先介绍了一些简单的任务，如检索状态信息和列出数据库、表和实例。我们还涵盖了暴力破解密码审核，因为在渗透测试评估期间，在数据库中找到弱密码或在某些情况下根本没有密码是常见的。在本章中，我还谈到了一个我最喜欢的 NSE 脚本，该脚本是使用 CIS MySQL 安全基准的部分编写的，用于审计不安全配置。在本章之后，我希望您能学会如何使用这些强大的 NSE 脚本来实施不同的安全和完整性检查，以保护您的基础设施。

# 列出 MySQL 数据库

MySQL 服务器可能包含多个数据库。作为具有合法访问权限的系统管理员或刚刚攻破服务器的渗透测试人员，我们可以使用 Nmap 列出可用的数据库。

此配方教您如何使用 Nmap NSE 列出 MySQL 服务器中的数据库。

## 如何做...

打开终端并输入以下命令：

```
$ nmap -p3306 --script mysql-databases --script-args mysqluser=<user>,mysqlpass=<password> <target>

```

数据库应该在脚本结果下列出。

```
3306/tcp open  mysql
| mysql-databases: 
|   information_schema
|   temp
|   websec
|   ids
|_  crm

```

## 工作原理...

使用参数`-p3306 --script mysql-databases --script-args mysqluser=<user>,mysqlpass=<password>`告诉 Nmap 尝试使用给定的凭据（`--script-args mysqluser=<user>,mysqlpass=<password>`）连接到 MySQL 服务器，并尝试列出服务器中所有可用的数据库。

脚本`mysql-databases`由 Patrik Karlsson 编写，以帮助 Nmap 用户枚举 MySQL 安装中的数据库。

## 还有更多...

如果找到空的 root 帐户，可以使用以下命令尝试枚举数据库：

```
# nmap -p3306 --script mysql-empty-password,mysql-databases <target> 

```

如果服务运行在 3306 以外的端口上，我们可以使用 Nmap 的服务检测（`-sV`），或使用参数`-p`手动设置端口。

```
# nmap -sV --script mysql-databases <target>$ nmap -p1111 –script mysql-databases <target>

```

## 另请参阅

+   *列出 MySQL 用户*配方

+   *列出 MySQL 变量*食谱

+   *在 MySQL 服务器中查找空密码的 root 账户*食谱

+   *暴力破解 MySQL 密码*食谱

+   *检测 MySQL 服务器中的不安全配置*食谱

# 列出 MySQL 用户

MySQL 服务器支持对数据库的细粒度访问，这意味着单个安装中可能有多个用户。

此食谱展示了如何使用 Nmap 枚举 MySQL 服务器中的用户。

## 如何操作...

打开终端并输入以下命令：

```
$ nmap -p3306 --script mysql-users --script-args mysqluser=<user>,mysqlpass=<pass> <target>

```

用户名列表将包括在`mysql-users`部分中：

```
3306/tcp open  mysql
| mysql-users: 
|   root
|   crm
|   web
|_  admin 

```

## 工作原理...

参数`-p3306 --script mysql-users --script-args mysqluser=<user>,mysqlpass=<pass>`使 Nmap 在发现运行在 3306 端口上的 MySQL 服务器时启动脚本`mysql-users`。

脚本`mysql-users`由 Patrik Karlsson 提交，它使用给定的认证凭据在 MySQL 服务器中枚举用户名。如果没有使用脚本参数`mysqluser`和`mysqlpass`设置认证凭据，它将尝试使用`mysql-brute`和`mysql-empty-password`的结果。

## 还有更多...

要枚举具有空密码的 root 账户的 MySQL 安装中的数据库和用户，请使用以下命令：

```
$ nmap -sV --script mysql-empty-password,mysql-databases,mysql-users <target>

```

如果 MySQL 服务器运行在 3306 端口之外，您可以使用 Nmap 的服务扫描，或者使用参数`-p`手动设置端口。

```
$ nmap -p3333 --script mysql-users <target>$ nmap -sV --script mysql-users <target>

```

## 另请参阅

+   *列出 MySQL 数据库*食谱

+   *列出 MySQL 变量*食谱

+   *在 MySQL 服务器中查找空密码的 root 账户*食谱

+   *暴力破解 MySQL 密码*食谱

+   *检测 MySQL 服务器中的不安全配置*食谱

# 列出 MySQL 变量

MySQL 服务器有几个环境变量，系统管理员和 Web 开发人员以不同的方式使用。

此食谱向您展示了如何使用 Nmap 列出 MySQL 服务器中的环境变量。

## 如何操作...

打开终端并输入以下 Nmap 命令：

```
$ nmap -p3306 --script mysql-variables --script-args mysqluser=<root>,mysqlpass=<pass> <target>

```

MySQL 变量将在`mysql-variables`下列出：

```
3306/tcp open  mysql
| mysql-variables: 
|   auto_increment_increment: 1
|   auto_increment_offset: 1
|   automatic_sp_privileges: ON
|   back_log: 50
|   basedir: /usr/
|   binlog_cache_size: 32768
|   bulk_insert_buffer_size: 8388608
|   character_set_client: latin1
|   character_set_connection: latin1
|   character_set_database: latin1
|   .
|   .
|   .
|   version_comment: (Debian)
|   version_compile_machine: powerpc
|   version_compile_os: debian-linux-gnu
|_  wait_timeout: 28800

```

## 工作原理...

我们使用参数`-p3306 --script mysql-variables --script-args mysqluser=<root>,mysqlpass=<pass>`使 Nmap 在发现运行在 3306 端口上的 MySQL 服务器时启动脚本`mysql-variables`。

脚本`mysql-variables`由 Patrik Karlsson 提交，它使用脚本参数`mysqluser`和`mysqlpass`作为对 MySQL 服务器的认证凭据，尝试枚举系统变量。

## 还有更多...

如果 MySQL 服务器运行在 3306 端口之外，我们可以使用 Nmap 的服务检测或手动使用`-p`参数设置端口。

```
$ nmap -sV --script mysql-variables <target>$ nmap -p5555 --script mysql-variables <target>

```

要从具有空 root 密码的 MySQL 服务器中检索数据库、用户名和变量，请使用以下命令：

```
$ nmap -sV --script mysql-variables,mysql-empty-password,mysql-databases,mysql-users <target>

```

## 另请参阅

+   *列出 MySQL 数据库*食谱

+   *列出 MySQL 用户*食谱

+   *在 MySQL 服务器中查找空密码的 root 账户*食谱

+   *暴力破解 MySQL 密码*食谱

+   *检测 MySQL 服务器中的不安全配置*食谱

# 在 MySQL 服务器中查找空密码的 root 账户

新系统管理员经常犯将 MySQL 服务器的 root 账户留空密码的错误。这是一个明显的安全漏洞，可能会被攻击者利用。渗透测试人员和系统管理员需要在坏人之前检测到这些易受攻击的安装。

此食谱将向您展示如何使用 Nmap 检查 MySQL 服务器上的空 root 密码。

## 如何操作...

打开终端并输入以下命令：

```
$ nmap -p3306 --script mysql-empty-password <target>

```

如果账户`root`或`anonymous`的密码为空，将在脚本结果中显示：

```
Nmap scan report for 127.0.0.1
Host is up (0.11s latency). 
3306/tcp open  mysql
| mysql-empty-password: 
|_  root account has empty password

```

## 工作原理...

参数`-p3306 --script mysql-empty-password`使 Nmap 在发现运行在 3306 端口上的 MySQL 服务器时启动 NSE 脚本`mysql-empty-password`。

此脚本由 Patrik Karlsson 提交，它连接到 MySQL 服务器并尝试使用空密码的账户`root`和`anonymous`。

## 还有更多...

要尝试自定义的用户名列表，您需要修改位于脚本目录中的 NSE 脚本`mysql-empty-password.nse`。在文件中找到以下行：

```
local users = {"", "root"}
```

并用您自己的用户名列表替换它，就像这样：

```
local users = {"plesk", "root","cpanel","test","db"}
```

只需保存并按照先前显示的方式运行它：

```
$ nmap -sV --script mysql-empty-password <target>
$ nmap -p3306 --script mysql-empty-password <target>

```

## 另请参阅

+   *列出 MySQL 数据库*配方

+   *列出 MySQL 用户*配方

+   *列出 MySQL 变量*配方

+   *强制破解 MySQL 密码*配方

+   *检测 MySQL 服务器中的不安全配置*配方

# 强制破解 MySQL 密码

Web 服务器有时会返回数据库连接错误，这些错误会显示 Web 应用程序使用的 MySQL 用户名。渗透测试人员可以使用这些信息来执行暴力破解密码审计。

这个配方描述了如何使用 Nmap 对 MySQL 服务器进行字典攻击。

## 如何做...

要使用 Nmap 对 MySQL 服务器进行暴力破解密码审计，请使用以下命令：

```
$ nmap -p3306 --script mysql-brute <target>

```

如果找到有效的凭证，它们将包含在`mysql-brute`输出部分中：

```
3306/tcp open  mysql
| mysql-brute: 
|   root:<empty> => Valid credentials
|_  test:test => Valid credentials

```

## 它是如何工作的...

脚本`mysql-brute`是由 Patrik Karlsson 编写的，当审计 MySQL 服务器时非常有帮助。它执行字典攻击以找到有效的凭证。成功率显然取决于运行脚本时使用的字典文件。

## 还有更多...

您的 MySQL 服务器可能在非标准端口上运行。您可以通过指定`-p`参数手动设置端口，或者使用 Nmap 的服务检测：

```
$ nmap -sV --script mysql-brute <target>$ nmap -p1234 --script mysql-brute <target>

```

脚本`mysql-brute`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可以用来调整您的暴力破解密码审计。

+   要使用不同的用户名和密码列表，请分别设置参数`userdb`和`passdb`：

```
$ nmap -p3306 --script mysql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

```

+   要在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
$ nmap -p3306 --script mysql-brute --script-args brute.firstOnly <target>

```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行它，请将其设置为`0`：

```
$ nmap -p3306 --script mysql-brute --script-args unpwdb.timelimit=0 <target>$ nmap -p3306 --script mysql-brute --script-args unpwdb.timelimit=60m <target>

```

### Brute 模式

`brute`库支持不同的模式，可以改变攻击中使用的用户名/密码组合。可用的模式有：

+   `user`：对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码

```
$ nmap --script mysql-brute --script-args brute.mode=user <target>

```

+   `pass`：对于`passdb`中列出的每个密码，将尝试`userdb`中的每个用户

```
$ nmap --script mysql-brute --script-args brute.mode=pass <target>

```

+   `creds`：这需要额外的参数`brute.credfile`

```
$ nmap --script mysql-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

```

## 另请参阅

+   *列出 MySQL 数据库*配方

+   *列出 MySQL 用户*配方

+   *列出 MySQL 变量*配方

+   *在 MySQL 服务器中查找空密码的 root 帐户*配方

+   *检测 MySQL 服务器中的不安全配置*配方

# 检测 MySQL 服务器中的不安全配置

数据库中的不安全配置可能会被攻击者滥用。**互联网安全中心**（**CIS**）发布了 MySQL 的安全基准，Nmap 可以使用这个基准来审计 MySQL 服务器的安全配置。

这个配方展示了如何使用 Nmap 检测 MySQL 服务器中的不安全配置。

## 如何做...

要检测 MySQL 服务器中的不安全配置，请输入以下命令：

```
$ nmap -p3306 --script mysql-audit --script-args 'mysql-audit.username="<username>",mysql-audit.password="<password>",mysql-audit.filename=/usr/local/share/nmap/nselib/data/mysql-cis.audit' <target>

```

每个控件都将被审查，并且结果中将包括`PASS`、`FAIL`或`REVIEW`的图例：

```
PORT     STATE SERVICE 
3306/tcp open  mysql 
| mysql-audit: 
|   CIS MySQL Benchmarks v1.0.2 
|       3.1: Skip symbolic links => PASS 
|       3.2: Logs not on system partition => PASS 
|       3.2: Logs not on database partition => PASS 
|       4.1: Supported version of MySQL => REVIEW 
|         Version: 5.1.41-3ubuntu12.10 
|       4.4: Remove test database => PASS 
|       4.5: Change admin account name => FAIL 
|       4.7: Verify Secure Password Hashes => PASS 
|       4.9: Wildcards in user hostname => PASS 
|       4.10: No blank passwords => PASS 
|       4.11: Anonymous account => PASS 
|       5.1: Access to mysql database => REVIEW 
|         Verify the following users that have access to the MySQL database 
|           user              host 
|           root              localhost 
|           root              builder64 
|           root              127.0.0.1 
|           debian-sys-maint  localhost 
|       5.2: Do not grant FILE privileges to non Admin users => PASS 
|       5.3: Do not grant PROCESS privileges to non Admin users => PASS 
|       5.4: Do not grant SUPER privileges to non Admin users => PASS 
|       5.5: Do not grant SHUTDOWN privileges to non Admin users => PASS 
|       5.6: Do not grant CREATE USER privileges to non Admin users => PASS 
|       5.7: Do not grant RELOAD privileges to non Admin users => PASS 
|       5.8: Do not grant GRANT privileges to non Admin users => PASS 
|       6.2: Disable Load data local => FAIL 
|       6.3: Disable old password hashing => PASS 
|       6.4: Safe show database => FAIL 
|       6.5: Secure auth => FAIL 
|       6.6: Grant tables => FAIL 
|       6.7: Skip merge => FAIL 
|       6.8: Skip networking => FAIL 
|       6.9: Safe user create => FAIL 
|       6.10: Skip symbolic links => FAIL 
| 
|_      The audit was performed using the db-account: root 

```

## 它是如何工作的...

脚本参数`-p3306 --script mysql-audit`告诉 Nmap 如果发现运行在 3306 端口上的 MySQL 服务器，则启动 NSE 脚本`mysql-audit`。

脚本`mysql-audit`是由 Patrik Karlsson 开发的，它使用基准 CIS MySQL 的部分检查不安全的配置。它也非常灵活，允许通过指定替代规则进行自定义检查。

## 还有更多...

如果您的 MySQL 服务器除了`root`和`debian-sys-maint`之外还有管理帐户，您应该在`$ nmap_path/nselib/data/mysql-cis.audit`中找到以下行，并将其添加到脚本中：

```
local ADMIN_ACCOUNTS={"root", "debian-sys-maint". "web"} 
```

请记住，您可以在单独的文件中编写自己的规则，并使用脚本参数`mysql-audit.fingerprintfile`来引用它。审计规则看起来像下面这样：

```
test { id="3.1", desc="Skip symbolic links", sql="SHOW variables WHERE Variable_name = 'log_error' AND Value IS NOT NULL", check=function(rowstab) 
        return { status = not(isEmpty(rowstab[1])) } 
end 
} 
```

MySQL 服务器可能在非标准端口上运行。使用 Nmap 的服务检测（`-sV`）或通过指定端口参数（`-p`）手动设置端口：

```
$ nmap -sV --script mysql-brute <target>$ nmap -p1234 --script mysql-brute <target>

```

## 另请参阅

+   *列出 MySQL 数据库*食谱

+   *列出 MySQL 用户*食谱

+   *列出 MySQL 变量*食谱

+   *在 MySQL 服务器中查找空密码的根帐户*食谱

+   *暴力破解 MySQL 密码*食谱

# 暴力破解 Oracle 密码

管理多个数据库的系统管理员通常需要根据组织的政策检查弱密码。渗透测试人员也利用弱密码获取未经授权的访问权限。方便的是，Nmap NSE 提供了一种执行远程暴力破解密码审计的方法，用于 Oracle 数据库服务器。

该食谱显示了如何使用 Nmap 对 Oracle 进行暴力破解密码审计。

## 如何做...

打开终端并使用以下参数运行 Nmap：

```
$ nmap -sV --script oracle-brute --script-args oracle-brute.sid=TEST <target>

```

在脚本输出部分将包括找到的任何有效凭据：

```
PORT     STATE  SERVICE REASON
1521/tcp open  oracle  syn-ack
| oracle-brute: 
|   Accounts
|     system:system => Valid credentials
|   Statistics
|_    Perfomed 103 guesses in 6 seconds, average tps: 17

```

## 它是如何工作的...

参数`-sV --script oracle-brute --script-args oracle-brute.sid=TEST`使 Nmap 在检测到 Oracle 服务器时针对实例`TEST`启动脚本`oracle-brute`。

脚本`oracle-brute`由 Patrik Karlsson 提交，它帮助渗透测试人员和系统管理员对 Oracle 服务器发起字典攻击，以尝试获取有效凭据。

## 还有更多...

更新文件`nselib/data/oracle-default-accounts.lst`以添加任何默认帐户。

脚本`oracle-brute`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可用于调整您的暴力破解密码审计。

+   要使用不同的用户名和密码列表，请分别设置参数`userdb`和`passdb`：

```
$ nmap -sV --script oracle-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

```

+   要在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
$ nmap -sV --script oracle-brute --script-args brute.firstOnly <target>

```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行，请将其设置为`0`：

```
$ nmap -sV --script oracle-brute --script-args unpwdb.timelimit=0 <target>$ nmap -sV --script oracle-brute --script-args unpwdb.timelimit=60m <target>

```

### 暴力模式

暴力库支持不同的模式，这些模式改变了攻击中使用的用户名/密码组合。可用的模式有：

+   `用户`：对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码

```
$ nmap --script oracle-brute --script-args brute.mode=user <target>

```

+   `密码`：对于`passdb`中列出的每个密码，将尝试`userdb`中的每个用户

```
$ nmap --script oracle-brute --script-args brute.mode=pass <target>

```

+   `凭据`：这需要额外的参数`brute.credfile`

```
$ nmap --script oracle-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

```

## 另请参阅

+   *暴力破解 Oracle SID 名称*食谱

# 暴力破解 Oracle SID 名称

Oracle 服务器具有 SID 名称，渗透测试人员需要找到它们。多亏了 Nmap，我们可以尝试通过对 TNS 监听器进行字典攻击来列出它们。

该食谱显示了如何使用 Nmap 对 Oracle SID 名称进行暴力破解。

## 如何做...

要暴力破解 Oracle SID 名称，请使用以下 Nmap 命令：

```
$ nmap -sV --script oracle-sid-brute <target>

```

找到的所有 SID 将包括在`oracle-sid-brute`的 NSE 脚本输出部分中：

```
PORT     STATE SERVICE REASON
1521/tcp open  oracle  syn-ack
| oracle-sid-brute: 
|   orcl
|   prod
|_  devel

```

## 它是如何工作的...

参数`-sV --script oracle-sid-brute`告诉 Nmap 启动服务检测（`-sV`）并使用 NSE 脚本`oracle-sid-brute`。

NSE 脚本`oracle-sid-brute`由 Patrik Karlsson 提交，以帮助渗透测试人员通过对 Oracle 的 TNS 进行字典攻击来枚举 Oracle SID。如果主机运行服务`oracle-tns`或端口 1521 打开，则将执行此脚本。

## 还有更多...

默认情况下，该脚本使用位于`nselib/data/oracle-sids`的字典，但您可以通过设置脚本参数`oraclesids`来指定不同的文件：

```
$ nmap -sV --script oracle-sid-brute --script-args oraclesids=/home/pentest/sids.txt <target>

```

## 另请参阅

+   *暴力破解 Oracle 密码*食谱

# 检索 MS SQL 服务器信息

系统管理员和渗透测试人员通常需要收集尽可能多的主机信息。基于 Microsoft 技术的基础设施中常见 MS SQL 数据库，Nmap 可以帮助我们从中收集信息。

该食谱显示了如何从 MS SQL 服务器检索信息。

## 如何做...

要通过使用 Nmap 从 MS SQL 服务器检索信息，请运行以下命令：

```
$ nmap -p1433 --script ms-sql-info <target>

```

MS SQL 服务器信息，如实例名称、版本号和端口，将包含在脚本输出中：

```
PORT     STATE SERVICE 
1433/tcp open  ms-sql-s 

Host script results: 
| ms-sql-info: 
|   Windows server name: CLDRN-PC 
|   [192.168.1.102\MSSQLSERVER] 
|     Instance name: MSSQLSERVER 
|     Version: Microsoft SQL Server 2011 
|       Version number: 11.00.1750.00 
|       Product: Microsoft SQL Server 2011 
|     TCP port: 1433 
|_    Clustered: No 

```

## 工作原理...

MS SQL 服务器通常在端口 1433 上运行。如果 MS SQL 服务器在该端口上运行，我们使用参数`-p1433 --script ms-sql-info`来启动 NSE 脚本`ms-sql-info`。

脚本`ms-sql-info`由 Chris Woodbury 和 Thomas Buchanan 提交。它连接到 MS SQL 服务器并检索实例名称、版本名称、版本号、产品名称、服务包级别、补丁列表、TCP/UDP 端口以及是否集群。如果可用，它会从 SQL Server Browser 服务（UDP 端口 1434）或从服务的探测中收集此信息。

## 还有更多...

如果端口 445 打开，您可以使用它通过管道检索信息。需要设置参数`mssql.instance-name`或`mssql.instance-all`：

```
$ nmap -sV --script-args mssql.instance-name=MSSQLSERVER --script ms-sql-info -p445 -v <target>
$ nmap -sV --script-args mssql.instance-all --script ms-sql-info -p445 -v <target>

```

输出如下：

```
PORT    STATE SERVICE     VERSION 
445/tcp open  netbios-ssn 

Host script results: 
| ms-sql-info: 
|   Windows server name: CLDRN-PC 
|   [192.168.1.102\MSSQLSERVER] 
|     Instance name: MSSQLSERVER 
|     Version: Microsoft SQL Server 2011 
|       Version number: 11.00.1750.00 
|       Product: Microsoft SQL Server 2011 
|     TCP port: 1433 
|_    Clustered: No 

```

### 仅在 MS SQL 的 NSE 脚本中强制扫描端口

NSE 脚本`ms-sql-brute`，`ms-sql-config.nse`，`ms-sql-empty-password`，`ms-sql-hasdbaccess.nse,ms-sql-info.nse`，`ms-sql-query.nse`，`ms-sql-tables.nse`和`ms-sql-xp-cmdshell.nse`可能尝试连接到未包括在您的扫描中的端口。要限制 NSE 仅使用扫描的端口，请使用参数`mssql.scanned-ports-only`：

```
$ nmap -p1433 --script-args mssql.scanned-ports-only --script ms-sql-* -v <target>

```

## 另请参阅

+   *暴力破解 MS SQL 密码*食谱

+   *转储 MS SQL 服务器的密码哈希*食谱

+   *通过 MS SQL 服务器的命令 shell 运行命令*食谱

+   *在 MS SQL 服务器上查找空密码的 sysadmin 帐户*食谱

# 暴力破解 MS SQL 密码

系统管理员和渗透测试人员通常需要检查弱密码，作为组织安全政策的一部分。Nmap 可以帮助我们对 MS SQL 服务器执行字典攻击。

本食谱介绍了如何使用 Nmap 对 MS SQL 服务器执行暴力破解密码审计。

## 操作步骤...

对 MS SQL 服务器执行暴力破解密码审计，运行以下 Nmap 命令：

```
$ nmap -p1433 --script ms-sql-brute <target>

```

如果找到任何有效帐户，它们将包含在脚本输出部分中：

```
PORT     STATE SERVICE 
1433/tcp open  ms-sql-s 
| ms-sql-brute: 
|   [192.168.1.102:1433] 
|     Credentials found: 
|_      sa:<empty>

```

## 工作原理...

MS SQL 服务器通常在 TCP 端口 1433 上运行。如果在端口 1433 上发现运行中的 MS SQL 服务器，参数`-p1433 --script ms-sql-brute`将启动 NSE 脚本`ms-sql-brute`。

脚本`ms-sql-brute`由 Patrik Karlsson 编写。它对 MS SQL 数据库执行暴力破解密码审计。此脚本依赖于库`mssql`。您可以在`http://nmap.org/nsedoc/lib/mssql.html`了解更多信息。

## 还有更多...

数据库服务器可能在非标准端口上运行。您可以通过指定`-p`参数手动设置端口，也可以使用 Nmap 的服务检测：

```
$ nmap -sV --script ms-sql-brute <target>$ nmap -p1234 --script ms-sql-brute <target>

```

请记住，如果 SMB 端口打开，我们可以使用管道来通过设置参数`mssql.instance-all`或`mssql.instance-name`来运行此脚本：

```
$ nmap -p445 --script ms-sql-brute --script-args mssql.instance-all <target>

```

输出如下：

```
PORT    STATE SERVICE 
445/tcp open  microsoft-ds 

Host script results: 
| ms-sql-brute: 
|   [192.168.1.102\MSSQLSERVER] 
|     Credentials found: 
|_      sa:<empty> => Login Success 

```

脚本`ms-sql-brute`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可用于调整暴力破解密码审计。

+   要使用不同的用户名和密码列表，设置参数`userdb`和`passdb`：

```
$ nmap -p1433 --script ms-sql-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

```

+   要在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
$ nmap -p1433 --script ms-sql-brute --script-args brute.firstOnly <target>

```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行，请将其设置为`0`：

```
$ nmap -p1433 --script ms-sql-brute --script-args unpwdb.timelimit=0 <target>$ nmap -p1433 --script ms-sql-brute --script-args unpwdb.timelimit=60m <target>

```

### 暴力模式

暴力库支持不同的模式，可改变攻击中使用的用户名/密码组合。可用的模式有：

+   `user`：对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码

```
$ nmap --script ms-sql-brute --script-args brute.mode=user <target>

```

+   `pass`：对于`passdb`中列出的每个密码，将尝试`userdb`中的每个用户

```
$ nmap --script ms-sql-brute --script-args brute.mode=pass <target>

```

+   `creds`：这需要额外的参数`brute.credfile`

```
$ nmap --script ms-sql-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

```

## 另请参阅

+   *检索 MS SQL 服务器信息*食谱

+   *转储 MS SQL 服务器的密码哈希*食谱

+   *通过 MS SQL 服务器的命令 shell 运行命令*食谱

+   *在 MS SQL 服务器上查找空密码的 sysadmin 帐户*食谱

# 转储 MS SQL 服务器的密码哈希

获得对 MS SQL 服务器的访问权限后，我们可以转储 MS SQL 服务器的所有密码哈希以破坏其他帐户。Nmap 可以帮助我们以可供**John the Ripper**破解工具使用的格式检索这些哈希。

此教程显示了如何使用 Nmap 转储 MS SQL 服务器的可破解密码哈希。

## 如何做...

要转储具有空 sysadmin 密码的 MS SQL 服务器的所有密码哈希，请运行以下 Nmap 命令：

```
$ nmap -p1433 --script ms-sql-empty-password,ms-sql-dump-hashes <target>

```

密码哈希将包含在`ms-sql-dump-hashes`脚本输出部分中：

```
PORT     STATE SERVICE  VERSION 
1433/tcp open  ms-sql-s Microsoft SQL Server 2011 
Service Info: CPE: cpe:/o:microsoft:windows 

Host script results: 
| ms-sql-empty-password: 
|   [192.168.1.102\MSSQLSERVER] 
|_    sa:<empty> => Login Success 
| ms-sql-dump-hashes: 
| [192.168.1.102\MSSQLSERVER] 
|     sa:0x020039AE3752898DF2D260F2D4DC7F09AB9E47BAB2EA3E1A472F49520C26E206D0613E34E92BF929F53C463C5B7DED53738A7FC0790DD68CF1565469207A50F98998C7E5C610 
|     ##MS_PolicyEventProcessingLogin##:0x0200BB8897EC23F14FC9FB8BFB0A96B2F541ED81F1103FD0FECB94D269BE15889377B69AEE4916307F3701C4A61F0DFD9946209258A4519FE16D9204580068D2011F8FBA7AD4 
|_    ##MS_PolicyTsqlExecutionLogin##:0x0200FEAF95E21A02AE55D76F68067DB02DB59AE84FAD97EBA7461CB103361598D3683688F83019E931442EC3FB6342050EFE6ACE4E9568F69D4FD4557C2C443243E240E66E10 

```

## 它是如何工作的...

MS SQL 服务器通常在 TCP 端口 1433 上运行。参数`-p1433 --script ms-sql-empty-password,ms-sql-dump-hashes`启动脚本`ms-sql-empty-password`，该脚本找到一个空的 root sysadmin 帐户，然后在端口 1433 上运行脚本`ms-sql-dump-hashes`。

`ms-sql-dump-hashes`脚本由 Patrik Karlsson 编写，其功能是检索 MS SQL 服务器的密码哈希，以便像 John the Ripper 这样的破解工具使用。此脚本依赖于`mssql`库。您可以在`http://nmap.org/nsedoc/lib/mssql.html`了解更多信息。

## 还有更多...

如果 SMB 端口打开，您可以使用它通过设置参数`mssql.instance-all`或`mssql.instance-name`来运行此脚本：

```
PORT    STATE SERVICE 
445/tcp open  microsoft-ds 

Host script results: 
| ms-sql-empty-password: 
|   [192.168.1.102\MSSQLSERVER] 
|_    sa:<empty> => Login Success 
| ms-sql-dump-hashes: 
| [192.168.1.102\MSSQLSERVER] 
|
  sa:0x020039AE3752898DF2D260F2D4DC7F09AB9E47BAB2EA3E1A472F49520C26E206D0613E34E92BF929F53C463C5B7DED53738A7FC0790DD68CF1565469207A50F98998C7E5C610 
|     ##MS_PolicyEventProcessingLogin##:0x0200BB8897EC23F14FC9FB8BFB0A96B2F541ED81F1103FD0FECB94D269BE15889377B69AEE4916307F3701C4A61F0DFD9946209258A4519FE16D9204580068D2011F8FBA7AD4 
|_    ##MS_PolicyTsqlExecutionLogin##:0x0200FEAF95E21A02AE55D76F68067DB02DB59AE84FAD97EBA7461CB103361598D3683688F83019E931442EC3FB6342050EFE6ACE4E9568F69D4FD4557C2C443243E240E66E10 

```

## 另请参阅

+   *检索 MS SQL 服务器信息*教程

+   *暴力破解 MS SQL 密码*教程

+   *在 MS SQL 服务器上通过命令 shell 运行命令*教程

+   *在 MS SQL 服务器上查找具有空密码的 sysadmin 帐户*教程

# 在 MS SQL 服务器上通过命令 shell 运行命令

MS SQL 服务器有一个名为`xp_cmdshell`的存储过程。此功能允许程序员通过 MS SQL 服务器执行命令。当启用此选项时，Nmap 可以帮助我们执行自定义 shell 命令。

此教程显示了如何通过 Nmap 在 MS SQL 服务器上运行 Windows 命令。

## 如何做...

打开您的终端并输入以下 Nmap 命令：

```
$ nmap --script-args 'mssql.username="<user>",mssql.password=""' --script ms-sql-xp-cmdshell -p1433 <target>

```

结果将包含在脚本输出部分中：

```
PORT     STATE SERVICE  VERSION 
1433/tcp open  ms-sql-s Microsoft SQL Server 2011 11.00.1750.00 
| ms-sql-xp-cmdshell: 
|   [192.168.1.102:1433] 
|     Command: net user 
|       output 
|       ====== 
| 
|       User accounts for \\ 
| 
|       ------------------------------------------------------------------------------- 
|       Administrator          cldrn             Guest 
|       postgres 
|       The command completed with one or more errors. 
| 
|_ 

```

## 它是如何工作的...

MS SQL 服务器通常在 TCP 端口 1433 上运行。参数`--script-args 'mssql.username="<user>",mssql.password=""' --script ms-sql-xp-cmdshell -p1433`使 Nmap 启动脚本`ms-sql-xp-cmdshell`，然后设置要在端口 1433 上运行的 MS SQL 服务器使用的身份验证凭据。

`ms-sql-xp-cmdshell`脚本由 Patrik Karlsson 编写。它尝试通过在 MS SQL 服务器上找到的存储过程`xp_cmdshell`运行 OS 命令。此脚本依赖于`mssql`库。其文档可以在[`nmap.org/nsedoc/lib/mssql.html`](http://nmap.org/nsedoc/lib/mssql.html)找到。

## 还有更多...

默认情况下，`ms-sql-xp-cmdshell`将尝试运行命令`ipconfig /all`，但您可以使用脚本参数`ms-sql-xp-cmdshell.cmd`指定不同的命令：

```
$ nmap --script-args 'ms-sql-xp-cmdshell.cmd="<command>",mssql.username="<user>",mssql.password=""' --script ms-sql-xp-cmdshell -p1433 <target>

```

如果服务器没有启用`xp_cmdshell`过程，则应该看到以下消息：

```
| ms-sql-xp-cmdshell: 
|   (Use --script-args=ms-sql-xp-cmdshell.cmd='<CMD>' to change command.) 
|   [192.168.1.102\MSSQLSERVER] 
|_    Procedure xp_cmdshell disabled. For more information see "Surface Area Configuration" in Books Online. 

```

如果您没有提供任何有效的身份验证凭据，将显示以下消息：

```
| ms-sql-xp-cmdshell: 
|   [192.168.1.102:1433] 
|_    ERROR: No login credentials. 

```

请记住，您可以将此脚本与`ms-sql-empty-password`结合使用，以自动检索具有空密码的 sysadmin 帐户的 MS SQL 服务器的网络配置：

```
$ nmap --script ms-sql-xp-cmdshell,ms-sql-empty-password -p1433 <target>

```

## 另请参阅

+   *检索 MS SQL 服务器信息*教程

+   *暴力破解 MS SQL 密码*教程

+   *转储 MS SQL 服务器的密码哈希*教程

+   *在 MS SQL 服务器上通过命令 shell 运行命令*教程

# 在 MS SQL 服务器上查找具有空密码的 sysadmin 帐户

渗透测试人员经常需要检查是否有管理帐户具有弱密码。借助 Nmap NSE 的一些帮助，我们可以轻松地检查是否有主机（或主机）具有具有空密码的 sysadmin 帐户。

这个教程教会我们如何使用 Nmap 查找具有空 sysadmin 密码的 MS SQL 服务器。

## 如何做...

要查找具有空`sa`帐户的 MS SQL 服务器，请打开终端并输入以下 Nmap 命令：

```
$ nmap -p1433 --script ms-sql-empty-password -v <target>

```

如果找到具有空密码的帐户，它将包含在脚本输出部分中：

```
PORT     STATE SERVICE 
1433/tcp open  ms-sql-s 
| ms-sql-empty-password: 
|   [192.168.1.102:1433] 
|_    sa:<empty> => Login Success 

```

## 它是如何工作的...

参数`-p1433 --script ms-sql-empty-password`使 Nmap 在发现端口 1433 上运行的 MS SQL 服务器时启动 NSE 脚本`ms-sql-empty-password`。

脚本`ms-sql-empty-password`由 Patrik Karlsson 提交，并由 Chris Woodbury 改进。它尝试使用用户名`sa`（系统管理员帐户）和空密码连接到 MS SQL 服务器。

## 还有更多...

如果端口 445 打开，您可以使用它通过管道检索信息。需要设置参数`mssql.instance-name`或`mssql.instance-all`：

```
$ nmap -sV --script-args mssql.instance-name=MSSQLSERVER --script ms-sql-empty-password -p445 -v <target>
$ nmap -sV --script-args mssql.instance-all --script ms-sql-empty-password -p445 -v <target>

```

输出将如下所示：

```
PORT    STATE SERVICE     VERSION 
445/tcp open  netbios-ssn 

Host script results: 
| ms-sql-empty-password: 
|   [192.168.1.102\MSSQLSERVER] 
|_    sa:<empty> => Login Success 

```

### 仅在 MS SQL 的 NSE 脚本中强制扫描端口

NSE 脚本`ms-sql-brute`，`ms-sql-config.nse`，`ms-sql-empty-password`，`ms-sql-hasdbaccess.nse,ms-sql-info.nse`，`ms-sql-query.nse`，`ms-sql-tables.nse`和`ms-sql-xp-cmdshell.nse`可能尝试连接到未包含在您的扫描中的端口。要限制 NSE 仅使用扫描的端口，请使用参数`mssql.scanned-ports-only`：

```
$ nmap -p1433 --script-args mssql.scanned-ports-only --script ms-sql-* -v <target>

```

## 另请参阅

+   *检索 MS SQL 服务器信息*的方法

+   *暴力破解 MS SQL 密码*的方法

+   *转储 MS SQL 服务器的密码哈希*的方法

+   *在 MS SQL 服务器上通过命令行运行命令*的方法

# 列出 MongoDB 数据库

MongoDB 可能在单个安装中包含多个数据库。列出数据库对系统管理员和渗透测试人员都很有用，而且有一个 NSE 脚本可以让他们轻松地甚至自动地执行此操作。

此方法描述了如何使用 Nmap 列出 MongoDB 中的数据库。

## 如何做到这一点...

通过使用 Nmap 列出 MongoDB 数据库，输入以下命令：

```
$ nmap -p 27017 --script mongodb-databases <target>

```

数据库将显示在脚本输出部分中：

```
PORT      STATE SERVICE 
27017/tcp open  mongodb 
| mongodb-databases: 
|   ok = 1 
|   databases 
|     1 
|       empty = true 
|       sizeOnDisk = 1 
|       name = local 
|     0 
|       empty = true 
|       sizeOnDisk = 1 
|       name = admin 
|     3 
|       empty = true 
|       sizeOnDisk = 1 
|       name = test 
|     2 
|       empty = true 
|       sizeOnDisk = 1 
|       name = nice%20ports%2C 
|_  totalSize = 0 

```

## 它是如何工作的...

如果在端口 27017 上发现运行中的 MongoDB 服务器，则启动 NSE 脚本`mongodb-databases`（`-p 27017 --script mongodb-databases`）。

脚本`mongodb-databases`由 Martin Holst Swende 提交，它尝试列出 MongoDB 安装中的所有数据库。

## 还有更多...

MongoDB 文档位于[`www.mongodb.org/display/DOCS/Home`](http://www.mongodb.org/display/DOCS/Home)。

此脚本依赖于库`mongodb`，其文档可以在[`nmap.org/nsedoc/lib/mongodb.html`](http://nmap.org/nsedoc/lib/mongodb.html)找到。

## 另请参阅

+   *检索 MongoDB 服务器信息*的方法

# 检索 MongoDB 服务器信息

在对 MongoDB 安装进行安全评估时，可以提取构建信息，如系统详细信息和服务器状态，包括可用连接数，正常运行时间和内存使用情况。

此方法描述了如何使用 Nmap 从 MongoDB 安装中检索服务器信息。

## 如何做到这一点...

打开你的终端并输入以下 Nmap 命令：

```
# nmap -p 27017 --script mongodb-info <target>

```

MongoDB 服务器信息将包含在脚本输出部分中：

```
PORT      STATE SERVICE 
27017/tcp open  mongodb 
| mongodb-info: 
|   MongoDB Build info 
|     ok = 1 
|     bits = 64 
|     version = 1.2.2 
|     gitVersion = nogitversion 
|     sysInfo = Linux crested 2.6.24-27-server #1 SMP Fri Mar 12 01:23:09 UTC 2010 x86_64 BOOST_LIB_VERSION=1_40 
|   Server status 
|     mem 
|       resident = 4 
|       virtual = 171 
|       supported = true 
|       mapped = 0 
|     ok = 1 
|     globalLock 
|       ratio = 3.3333098126169e-05 
|       lockTime = 28046 
|       totalTime = 841385937 
|_    uptime = 842 

```

## 它是如何工作的...

参数`-p 27017 --script mongodb-info`使 Nmap 在发现端口 27017 上运行的服务时启动 NSE 脚本`mongodb-info`。

脚本`mongodb-info`由 Martin Holst Swende 编写。它返回服务器信息，包括 MongoDB 数据库的状态和构建详细信息。

## 还有更多...

MongoDB 文档位于[`www.mongodb.org/display/DOCS/Home`](http://www.mongodb.org/display/DOCS/Home)。

此脚本依赖于库`mongodb`，其文档可以在[`nmap.org/nsedoc/lib/mongodb.html`](http://nmap.org/nsedoc/lib/mongodb.html)找到。

## 另请参阅

+   *列出 MongoDB 数据库*的方法

# 列出 CouchDB 数据库

CouchDB 安装可能包含许多数据库。 Nmap 为渗透测试人员或系统管理员提供了一种轻松列出可用数据库的方法，他们可能需要监视恶意数据库。

这个食谱将向您展示如何使用 Nmap 列出 CouchDB 服务器中的数据库。

## 如何做...

要使用 Nmap 列出 CouchDB 安装中的所有数据库，请输入以下命令：

```
# nmap -p5984 --script couchdb-databases <target>

```

结果将包括 CouchDB 在`couchdb-databases`输出部分返回的所有数据库：

```
PORT     STATE SERVICE VERSION 
5984/tcp open  httpd   Apache CouchDB 0.10.0 (Erlang OTP/R13B) 
| couchdb-databases: 
|   1 = nmap 
|_  2 = packtpub 

```

## 它是如何工作的...

参数`-p5984 --script couchdb-databases`告诉 Nmap 如果在端口 5984 上发现正在运行的 CouchDB HTTP 服务，则启动 NSE 脚本`couchdb-databases`。

脚本`couchdb-databases`由 Martin Holst Swende 编写，它列出了 CouchDB 服务中所有可用的数据库。它查询 URI`/_all_dbs`，并从返回的数据中提取信息：

```
["nmap","packtpub"]
```

## 还有更多...

您可以通过访问[`wiki.apache.org/couchdb/HTTP_database_API`](http://wiki.apache.org/couchdb/HTTP_database_API)了解有关 CouchDB HTTP 使用的 API 的更多信息。

## 另请参阅

+   *检索 CouchDB 数据库统计信息*食谱

# 检索 CouchDB 数据库统计信息

CouchDB HTTP 服务器可以返回对系统管理员非常有价值的统计信息。这些信息包括每秒请求次数、大小和其他有用的统计信息。幸运的是，Nmap 提供了一种简单的方法来检索这些信息。

这个食谱描述了如何使用 Nmap 检索 CouchDB HTTP 服务的数据库统计信息。

## 如何做...

打开您的终端并使用以下参数运行 Nmap：

```
# nmap -p5984 --script couchdb-stats 127.0.0.1 

```

结果将包括在脚本输出部分中：

```
PORT     STATE SERVICE 
5984/tcp open  httpd 
| couchdb-stats: 
|   httpd_request_methods 
|     PUT (number of HTTP PUT requests) 
|       current = 2 
|       count = 970 
|     GET (number of HTTP GET requests) 
|       current = 52 
|       count = 1208 
|   couchdb 
|     request_time (length of a request inside CouchDB without MochiWeb) 
|       current = 1 
|       count = 54 
|     open_databases (number of open databases) 
|       current = 2 
|       count = 970 
|     open_os_files (number of file descriptors CouchDB has open) 
|       current = 2 
|       count = 970 
|   httpd_status_codes 
|     200 (number of HTTP 200 OK responses) 
|       current = 27 
|       count = 1208 
|     201 (number of HTTP 201 Created responses) 
|       current = 2 
|       count = 970 
|     301 (number of HTTP 301 Moved Permanently responses) 
|       current = 1 
| count = 269 
|     500 (number of HTTP 500 Internal Server Error responses) 
|       current = 1 
|       count = 274 
|   httpd 
|     requests (number of HTTP requests) 
|       current = 54 
|       count = 1208 
|_  Authentication : NOT enabled ('admin party') 

```

## 它是如何工作的...

参数`-p5984 --script couchdb-stats`告诉 Nmap 如果 CouchDB HTTP 服务器正在运行，则启动 NSE 脚本`couchdb-stats`。

脚本`couchdb_stats`由 Martin Holst Swende 提交，它只执行一个任务：检索 CouchDB HTTP 服务的运行时统计信息。它通过请求 URI`/_stats/`并解析服务器返回的序列化数据来实现这一点：

```
{"current":1,"count":50,"mean":14.28,"min":0,"max":114,"stddev":30.40068420282675,"description":"length of a request inside CouchDB without MochiWeb"}
```

## 还有更多...

如果您发现一个没有受到身份验证保护的安装，您还应该检查以下 URI：

+   `/_utils/`

+   `/_utils/status.html`

+   `/_utils/config.html`

您可以通过访问[`wiki.apache.org/couchdb/Runtime_Statistics`](http://wiki.apache.org/couchdb/Runtime_Statistics)了解有关 CouchDB HTTP 服务器的运行时统计信息。

## 另请参阅

+   *列出 CouchDB 数据库*食谱


# 第六章：审计邮件服务器

### 注意

本章向您展示了如何执行在许多情况下可能是非法、不道德、违反服务条款或只是不明智的一些操作。这里提供这些信息是为了让您了解如何保护自己免受威胁，并使自己的系统更加安全。在遵循这些说明之前，请确保您站在法律和道德的一边...运用您的力量为善！

在本章中，我们将涵盖：

+   使用 Google 搜索发现有效的电子邮件帐户

+   检测开放中继

+   暴力破解 SMTP 密码

+   在 SMTP 服务器中枚举用户

+   检测后门 SMTP 服务器

+   暴力破解 IMAP 密码

+   检索 IMAP 邮件服务器的功能

+   暴力破解 POP3 密码

+   检索 POP3 邮件服务器的功能

+   检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75

# 介绍

邮件服务器几乎在任何组织中都可以使用，因为电子邮件已经成为首选的通信渠道，原因显而易见。邮件服务器的重要性取决于其中存储的信息。攻击者经常会入侵电子邮件帐户，并继续接管几乎每个网络应用程序中都有的“忘记密码”功能找到的所有其他帐户。有时，被入侵的帐户会在数月内被窃听，而没有人注意到，甚至可能被垃圾邮件发送者滥用。因此，任何优秀的系统管理员都知道拥有安全的邮件服务器是至关重要的。

在本章中，我将介绍不同的 NSE 任务，用于管理和监控邮件服务器。我还将展示渗透测试人员可用的攻击性方法。我们将涵盖最流行的邮件协议，如 SMTP、POP3 和 IMAP。

我们将回顾任务，如检索功能、枚举用户、暴力破解密码，甚至利用易受攻击的 Exim 服务器。最后，您还将学习如何使用 Nmap 自动抓取搜索引擎（如 Google Web 和 Google Groups）的电子邮件帐户，以收集我们可以在暴力破解攻击中使用的有效电子邮件帐户。

# 使用 Google 搜索发现有效的电子邮件帐户

查找有效的电子邮件帐户是渗透测试中的重要任务。电子邮件帐户经常用作某些系统和网络应用程序中的用户名。攻击者经常针对其中存储的高度敏感信息。

本教程向您展示了如何使用 Nmap 发现有效的电子邮件帐户，这些帐户可以用作某些网络应用程序中的用户名，也可以用于暴力破解密码审核，以查找弱凭据。

## 准备工作

对于此任务，我们需要一个 Nmap 官方未分发的 NSE 脚本。从[`seclists.org/nmap-dev/2011/q3/att-401/http-google-email.nse`](http://seclists.org/nmap-dev/2011/q3/att-401/http-google-email.nse)下载 NSE 脚本`http-google-search.nse`。

通过执行以下命令更新您的 NSE 脚本数据库：

```
# nmap --script-updatedb

```

将显示以下消息：

```
NSE: Updating rule database. 
NSE: Script Database updated successfully. 

```

## 如何做...

要使用 Nmap 通过 Google 搜索和 Google Groups 查找有效的电子邮件帐户，请输入以下命令：

```
$ nmap -p80 --script http-google-email <target>

```

找到的所有电子邮件帐户都将包含在脚本输出部分：

```
$ nmap -p80 --script http-google-email insecure.org
PORT   STATE SERVICE 
80/tcp open  http 
| http-google-email: 
| fyodor@insecure.org 
|_nmap-hackers@insecure.org 

```

## 它是如何工作的...

NSE 脚本`http-google-email`由 Shinook 编写。它使用搜索引擎 Google Web 和 Google Groups 来查找这些服务缓存的公共电子邮件帐户。

该脚本查询以下 URI 以获取结果：

+   [`www.google.com/search`](http://www.google.com/search)

+   [`groups.google.com/groups`](http://groups.google.com/groups)

参数`-p80 --script http-google-email`告诉 Nmap 在端口 80 上发现 Web 服务器时启动 NSE 脚本`http-google-email`。

## 还有更多...

要仅显示属于某个主机名的结果，请使用脚本参数`http-google-email.domain`：

```
$ nmap -p80 --script http-google-email --script-args http-google-email.domain=<hostname> <target>

```

要增加要爬行的页面数量，请使用脚本参数`http-google-email.pages`。默认情况下，此脚本仅请求五个页面：

```
$ nmap -p80 --script http-google-email --script-args http-google-email.pages=10 <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用标志`-d`进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *暴力破解 SMTP 密码*食谱

+   *枚举 SMTP 服务器中的用户*食谱

+   *暴力破解 IMAP 密码*食谱

+   *暴力破解 POP3 密码*食谱

# 检测开放继电

开放继电器是不安全的邮件服务器，允许第三方域在未经授权的情况下使用它们。它们被垃圾邮件发送者和网络钓鱼者滥用，并对组织造成严重风险，因为公共垃圾邮件黑名单可能会将它们添加并影响整个组织，该组织依赖于电子邮件到达目的地。

该食谱展示了如何使用 Nmap 检测开放继电器。

## 如何做...

打开终端，输入以下命令：

```
$ nmap -sV --script smtp-open-relay -v <target>

```

输出返回通过的测试数量和使用的命令组合：

```
Host script results:
| smtp-open-relay: Server is an open relay (1/16 tests)
|_MAIL FROM:<antispam@insecure.org> -> RCPT TO:<relaytest@insecure.org>

```

## 它是如何工作的...

脚本`smtp-open-relay`由 Arturo 'Buanzo' Busleiman 提交，它尝试 16 种不同的测试来确定 SMTP 服务器是否允许开放继电。如果打开了详细模式，它还会返回成功中继电子邮件的命令。

命令组合在脚本中是硬编码的，测试包括目标和源地址的不同字符串格式：

```
MAIL FROM:<user@domain.com>
250 Address Ok. 
RCPT TO:<user@adomain.com>
250 user@adomain.com OK 

```

如果收到 503 响应，脚本将退出，因为这意味着此服务器受到身份验证保护，不是开放继电。

如果端口 25、465 和 587 处于打开状态，或者在目标主机中找到服务`smtp`、`smtps`或`submission`，则脚本`smtp-open-relay`将执行（`-sV --script smtp-open-relay`）。

## 还有更多...

您可以通过指定脚本参数`smtp-open-relay.ip`和`smtp-open-relay.domain`来指定替代 IP 地址或域名：

```
$ nmap -sV --script smtp-open-relay -v --script-args smtp-open-relay.ip=<ip> <target>
$ nmap -sV --script smtp-open-relay -v --script-args smtp-open-relay.domain=<domain> <target>

```

通过指定脚本参数`smtp-open-relay.to`和`smtp-open-relay.from`来指定测试中使用的源和目标电子邮件地址：

```
$ nmap -sV --script smtp-open-relay -v --script-args smtp-open-relay.to=<Destination email address>,smtp-open-relay.from=<Source email address> <target>

```

### **调试 NSE 脚本**

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用标志`-d`进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *使用 Google 搜索发现有效的电子邮件帐户*食谱

+   *枚举 SMTP 服务器中的用户*食谱

+   *检测后门 SMTP 服务器*食谱

+   *检索 IMAP 邮件服务器的功能*食谱

+   *检索 POP3 邮件服务器的功能*食谱

+   *检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75*食谱

# 暴力破解 SMTP 密码

邮件服务器通常存储非常敏感的信息，渗透测试人员需要对其执行暴力破解密码审核，以检查是否存在弱密码。

此食谱将向您展示如何使用 Nmap 对 SMTP 服务器进行字典攻击。

## 如何做...

要通过 Nmap 对 SMTP 服务器进行字典攻击，输入以下命令：

```
$ nmap -p25 --script smtp-brute <target>

```

如果找到任何有效凭据，它们将包含在脚本输出部分中：

```
PORT    STATE SERVICE REASON
25/tcp  open  stmp    syn-ack
| smtp-brute: 
|   Accounts
|     acc0:test - Valid credentials
|     acc1:test - Valid credentials
|     acc3:password - Valid credentials
|     acc4:12345 - Valid credentials
|   Statistics
|_    Performed 3190 guesses in 81 seconds, average tps: 39

```

## 它是如何工作的...

NSE 脚本`smtp-brute`由 Patrik Karlsson 提交。它对 SMTP 服务器执行暴力破解密码审核。它支持以下身份验证方法：`LOGIN`、`PLAIN`、`CRAM-MD5`、`DIGEST-MD5`和`NTLM`。

默认情况下，脚本使用单词列表`/nselib/data/usernames.lst`和`/nselib/data/passwords.lst`，但可以轻松更改为使用替代单词列表。

参数`-p25 --script smtp-brute`使 Nmap 在端口 25 上发现 SMTP 服务器时启动 NSE 脚本`smtp-brute`。

## 还有更多...

脚本`smtp-brute`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可用于调整您的暴力破解密码审计。

+   使用不同的用户名和密码列表，设置参数`userdb`和`passdb`：

```
$ nmap -p25 --script smtp-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

```

+   在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
$ nmap -p25 --script smtp-brute --script-args brute.firstOnly <target>

```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行，请将其设置为`0`：

```
$ nmap -p25 --script smtp-brute --script-args unpwdb.timelimit=0 <target>
$ nmap -p25 --script smtp-brute --script-args unpwdb.timelimit=60m <target>

```

### 暴力模式

brute 库支持不同的模式，可改变攻击中使用的用户名/密码组合。可用的模式有：

+   `user`：对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码

```
$ nmap --script smtp-brute --script-args brute.mode=user <target>

```

+   `pass`：对于`passdb`中列出的每个密码，将尝试`userdb`中的每个用户

```
$ nmap --script smtp-brute --script-args brute.mode=pass <target>

```

+   `creds`：这需要额外的参数`brute.credfile`

```
$ nmap --script smtp-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。 Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *使用 Google 搜索发现有效的电子邮件帐户*配方

+   *在 SMTP 服务器中枚举用户*配方

+   *暴力破解 IMAP 密码*配方

+   *检索 IMAP 邮件服务器的功能*配方

+   *暴力破解 POP3 密码*配方

+   *检索 POP3 邮件服务器的功能*配方

# 在 SMTP 服务器中枚举用户

在 Web 应用程序中，使用电子邮件帐户作为用户名非常常见，当审计邮件服务器时，找到它们是必要的任务。通过 SMTP 命令枚举用户可以获得出色的结果，多亏了 Nmap 脚本引擎，我们可以自动化这项任务。

此配方显示如何使用 Nmap 列举 SMTP 服务器上的用户。

## 如何做...

通过使用 Nmap 在 SMTP 服务器上枚举用户，输入以下命令：

```
$ nmap -p25 –script smtp-enum-users <target>

```

找到的任何用户名都将包含在脚本输出部分中：

```
Host script results:
| smtp-enum-users:
|_  RCPT, webmaster

```

## 工作原理...

脚本`smtp-enum-users`由 Duarte Silva 编写，它尝试使用 SMTP 命令`RCPT`，`VRFY`和`EXPN`在 SMTP 服务器中枚举用户。

SMTP 命令`RCPT`，`VRFY`和`EXPN`可用于确定邮件服务器上帐户是否存在。让我们只看一下`VRFY`命令，因为它们都以类似的方式工作：

```
VRFY root
250 root@domain.com
VRFY eaeaea
550 eaeaea... User unknown

```

请注意，此脚本仅适用于不需要身份验证的 SMTP 服务器。如果是这种情况，您将看到以下消息：

```
| smtp-enum-users: 
|_  Couldn't perform user enumeration, authentication needed

```

## 还有更多...

您可以使用脚本参数`smtp-enum-users.methods`选择要尝试的方法（`RCPT`，`VRFY`和`EXPN`）以及尝试它们的顺序：

```
$ nmap -p25 –script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <target>
$ nmap -p25 –script smtp-enum-users --script-args smtp-enum-users.methods={RCPT, VRFY} <target>

```

要在 SMTP 命令中设置不同的域，请使用脚本参数`smtp-enum-users.domain`：

```
$ nmap -p25 –script smtp-enum-users --script-args smtp-enum-users.domain=<domain> <target>

```

脚本`smtp-enum-users`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可用于调整您的暴力破解密码审计。

+   要使用不同的用户名列表，请设置参数`userdb`：

```
$ nmap -p25 --script smtp-enum-users --script-args userdb=/var/usernames.txt <target>

```

+   在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
$ nmap -p25 --script smtp-enum-users --script-args brute.firstOnly <target>

```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行，请将其设置为`0`：

```
$ nmap -p25 --script smtp-enum-users --script-args unpwdb.timelimit=0 <target>
$ nmap -p25 --script smtp-enum-users --script-args unpwdb.timelimit=60m <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。 Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *使用 Google 搜索发现有效的电子邮件帐户*配方

+   *暴力破解 SMTP 密码*配方

+   *在 SMTP 服务器中枚举用户*配方

+   *检测后门 SMTP 服务器*配方

+   *暴力破解 IMAP 密码*配方

+   *检索 IMAP 邮件服务器的功能*配方

+   *暴力破解 POP3 密码*配方

+   *检索 POP3 邮件服务器的功能*配方

# 检测后门 SMTP 服务器

受损的服务器可能安装了流氓 SMTP 服务器，并被垃圾邮件发送者滥用。系统管理员可以使用 Nmap 来帮助他们监视网络中的邮件服务器。

这个配方展示了如何使用 Nmap 检测流氓 SMTP 服务器。

## 如何做...

打开您的终端并输入以下 Nmap 命令：

```
$ nmap -sV --script smtp-strangeport <target>

```

如果在非标准端口上发现邮件服务器，它将在脚本输出部分中报告：

```
PORT    STATE SERVICE  VERSION 
9999/tcp open  ssl/smtp Postfix smtpd 
|_smtp-strangeport: Mail server on unusual port: possible malware

```

## 它是如何工作的...

脚本`smtp-strangeport`由 Diman Todorov 提交。它检测在非标准端口上运行的 SMTP 服务器，这是流氓邮件服务器的指标。如果发现 SMTP 服务器在 25、465 和 587 端口之外的端口上运行，此脚本将通知您。

参数`-sV --script smtp-strangeport`使 Nmap 开始服务检测并启动 NSE 脚本`smtp-strangeport`，它将比较发现 SMTP 服务器的端口号与已知端口号 25、465 和 587。

## 还有更多...

我们可以使用这个脚本为您的邮件服务器设置一个监控系统，如果发现了一个流氓 SMTP 服务器，它会通知您。首先，创建文件夹`/usr/local/share/nmap-mailmon/`。

扫描您的主机并将结果保存在我们刚刚创建的`mailmon`目录中：

```
#nmap -oX /usr/local/share/nmap-mailmon/base.xml -sV -p- -Pn -T4 <target>

```

生成的文件将用于比较结果，并且它应该反映您已知的服务列表。现在，创建文件`nmap-mailmon.sh`：

```
#!/bin/bash 
#Bash script to email admin when changes are detected in a network using Nmap and Ndiff. 
# 
#Don't forget to adjust the CONFIGURATION variables. 
#Paulino Calderon <calderon@websec.mx> 

# 
#CONFIGURATION 
# 
NETWORK="YOURDOMAIN.COM" 
ADMIN=YOUR@EMAIL.COM 
NMAP_FLAGS="-sV -Pn -p- -T4 --script smtp-strangeport" 
BASE_PATH=/usr/local/share/nmap-mailmon/ 
BIN_PATH=/usr/local/bin/ 
BASE_FILE=base.xml 
NDIFF_FILE=ndiff.log 
NEW_RESULTS_FILE=newscanresults.xml 

BASE_RESULTS="$BASE_PATH$BASE_FILE" 
NEW_RESULTS="$BASE_PATH$NEW_RESULTS_FILE" 
NDIFF_RESULTS="$BASE_PATH$NDIFF_FILE" 

if [ -f $BASE_RESULTS ] 
then 
  echo "Checking host $NETWORK" 
  ${BIN_PATH}nmap -oX $NEW_RESULTS $NMAP_FLAGS $NETWORK 
  ${BIN_PATH}ndiff $BASE_RESULTS $NEW_RESULTS > $NDIFF_RESULTS 
  if [ $(cat $NDIFF_RESULTS | wc -l) -gt 0 ] 
  then 
    echo "Network changes detected in $NETWORK" 
    cat $NDIFF_RESULTS 
    echo "Alerting admin $ADMIN" 
    mail -s "Network changes detected in $NETWORK" $ADMIN < $NDIFF_RESULTS 
  fi 
fi 
```

不要忘记更新以下配置值：

```
NETWORK="YOURDOMAIN.COM" 
ADMIN=YOUR@EMAIL.COM 
NMAP_FLAGS="-sV -Pn -p- -T4 --script smtp-strangeport" 
BASE_PATH=/usr/local/share/nmap-mailmon/ 
BIN_PATH=/usr/local/bin/ 
BASE_FILE=base.xml 
NDIFF_FILE=ndiff.log 
NEW_RESULTS_FILE=newscanresults.xml 
```

使用以下命令使脚本`nmap-mailmon.sh`可执行：

```
#chmod +x /usr/local/share/nmap-mailmon/nmap-mailmon.sh

```

您现在可以添加以下`crontab`条目，以自动运行此脚本：

```
0 * * * * /usr/local/share/nmap-mon/nmap-mon.sh
```

重新启动 cron，您应该已成功安装了一个监控系统，如果发现流氓 SMTP 服务器，它将通知您。

## 另请参阅

+   *检测开放中继*配方

+   *检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75*配方

# 暴力破解 IMAP 密码

电子邮件帐户存储非常敏感的信息，审计邮件服务器的渗透测试人员必须检测可能危及电子邮件帐户和通过它们访问的信息的弱密码。

在这个配方中，我们将使用 Nmap 对 IMAP 密码进行暴力破解。

## 如何做...

要对 IMAP 执行暴力密码审计，请使用以下命令：

```
$ nmap -p143 --script imap-brute <target>

```

在脚本输出部分下，将列出找到的所有有效帐户：

```
PORT    STATE SERVICE REASON
143/tcp open  imap    syn-ack
| imap-brute: 
|   Accounts
|     acc1:test - Valid credentials
|     webmaster:webmaster - Valid credentials
|   Statistics
|_    Performed 112 guesses in 112 seconds, average tps: 1

```

## 它是如何工作的...

脚本`imap-brute`由 Patrik Karlsson 提交，它对 IMAP 服务器执行暴力密码审计。它支持`LOGIN`、`PLAIN`、`CRAM-MD5`、`DIGEST-MD5`和`NTLM`身份验证。

默认情况下，此脚本使用单词列表`/nselib/data/usernames.lst`和`/nselib/data/passwords.lst`，但您可以通过配置暴力库来更改这一点。

参数`-p143 --script imap-brute`告诉 Nmap 如果在 143 端口上发现 IMAP，则启动脚本`imap-brute`。

## 还有更多...

脚本`imap-brute`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可用于调整您的暴力密码审计。

+   要使用不同的用户名和密码列表，请分别设置参数`userdb`和`passdb`：

```
$ nmap -p143 --script imap-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

```

+   要在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
$ nmap -p143 --script imap-brute --script-args brute.firstOnly <target>

```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行它，请将其设置为 0：

```
$ nmap -p143 --script imap-brute --script-args unpwdb.timelimit=0 <target>
$ nmap -p143 --script imap-brute --script-args unpwdb.timelimit=60m <target>

```

### Brute 模式

暴力库支持不同的模式，可以改变攻击中使用的用户名/密码组合。可用的模式有：

+   `user`：对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码

```
$ nmap --script imap-brute --script-args brute.mode=user <target>

```

+   `pass`：对于`passdb`中列出的每个密码，将尝试`userdb`中的每个用户

```
$ nmap --script imap-brute --script-args brute.mode=pass <target>

```

+   `creds`：这需要额外的参数`brute.credfile`

```
$ nmap --script imap-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用标志`-d`进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *使用 Google 搜索发现有效的电子邮件帐户*配方

+   暴力破解 SMTP 密码的方法

+   在 SMTP 服务器中枚举用户的方法

+   检索 IMAP 邮件服务器的功能

+   暴力破解 POP3 密码的方法

+   检索 POP3 邮件服务器的功能

# 检索 IMAP 邮件服务器的功能

IMAP 服务器可能支持不同的功能。有一个名为`CAPABILITY`的命令允许客户端列出这些支持的邮件服务器功能，我们可以使用 Nmap 来自动化这个任务。

此方法向您展示了如何使用 Nmap 列出 IMAP 服务器的功能。

## 如何做...

打开您喜欢的终端并输入以下 Nmap 命令：

```
$ nmap -p143,993 --script imap-capabilities <target>

```

结果将包括在脚本输出部分下：

```
993/tcp  open     ssl/imap Dovecot imapd 
|_imap-capabilities: LOGIN-REFERRALS completed AUTH=PLAIN OK Capability UNSELECT THREAD=REFERENCES AUTH=LOGINA0001 IMAP4rev1 NAMESPACE SORT CHILDREN LITERAL+ IDLE SASL-IR MULTIAPPEND 

```

## 它是如何工作的...

脚本`imap-capabilities`由 Brandon Enright 提交，它尝试使用在 RFC 3501 中定义的`CAPABILITY`命令来列出 IMAP 服务器的支持功能。

参数`-p143,993 --script imap-capabilities`告诉 Nmap 在端口 143 或 993 上发现 IMAP 服务器时启动 NSE 脚本`imap-capabilities`。

## 还有更多...

对于 IMAP 服务器运行在非标准端口的情况，您可以使用端口选择标志`-p`，或者启用 Nmap 的服务检测：

```
#nmap -sV --script imap-capabilities <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   暴力破解 SMTP 密码的方法

+   在 SMTP 服务器中枚举用户的方法

+   检测后门 SMTP 服务器的方法

+   暴力破解 IMAP 密码的方法

+   检索 IMAP 邮件服务器的功能

+   暴力破解 POP3 密码的方法

+   检索 POP3 邮件服务器的功能

+   检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75 的方法

# 暴力破解 POP3 密码

电子邮件帐户存储着敏感信息。审计邮件服务器的渗透测试人员必须测试弱密码，这些密码可能帮助攻击者 compromise 重要的帐户。

此方法向您展示了如何使用 Nmap 对 POP3 邮件服务器进行暴力破解密码审计。

## 如何做...

要通过 Nmap 对 POP3 进行字典攻击，请输入以下命令：

```
$ nmap -p110 --script pop3-brute <target>

```

任何有效的帐户都将列在脚本输出部分下：

```
PORT    STATE SERVICE
110/tcp open  pop3
| pop3-brute: webmaster : abc123
|_acc1 : password

```

## 它是如何工作的...

`pop3-brute`由 Philip Pickering 提交，它对 POP3 邮件服务器进行暴力破解密码审计。默认情况下，它使用单词列表`/nselib/data/usernames.lst`和`/nselib/data/passwords.lst`作为用户名和密码组合。

## 还有更多...

脚本`pop3-brute`依赖于 NSE 库`unpwdb`。该库有几个脚本参数，可用于调整您的暴力破解密码审计。

+   要使用不同的用户名和密码列表，请设置参数`userdb`和`passdb`：

```
$ nmap -p110 --script pop3-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

```

+   要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行它，请将其设置为`0`：

```
$ nmap -p110 --script pop3-brute --script-args unpwdb.timelimit=0 <target>
$ nmap -p110 --script pop3-brute --script-args unpwdb.timelimit=60m <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   使用 Google 搜索发现有效的电子邮件帐户的方法

+   暴力破解 SMTP 密码的方法

+   在 SMTP 服务器中枚举用户的方法

+   检测后门 SMTP 服务器的方法

+   暴力破解 IMAP 密码的方法

+   检索 IMAP 邮件服务器的功能

+   暴力破解 POP3 密码的方法

+   检索 POP3 邮件服务器的功能

# 检索 POP3 邮件服务器的功能

POP3 邮件服务器可能支持 RFC 2449 中定义的不同功能。通过使用 POP3 命令，我们可以列出它们，并且由于 Nmap，我们可以自动化这个任务并将此服务信息包含在我们的扫描结果中。

这个配方将教你如何使用 Nmap 列出 POP3 邮件服务器的功能。

## 如何做...

打开您喜欢的终端并输入以下 Nmap 命令：

```
$ nmap -p110 --script pop3-capabilities <target>

```

服务器功能列表将包含在脚本输出部分：

```
PORT    STATE SERVICE 
110/tcp open  pop3 
|_pop3-capabilities: USER CAPA UIDL TOP OK(K) RESP-CODES PIPELINING STLS SASL(PLAIN LOGIN) 

```

## 它是如何工作...

脚本`pop3-capabilities`由 Philip Pickering 提交，它尝试检索 POP3 和 POP3S 服务器的功能。它使用 POP3 命令`CAPA`向服务器请求支持的命令列表。该脚本还尝试通过`IMPLEMENTATION`字符串和任何其他特定于站点的策略来检索版本字符串。

## 还有更多...

脚本`pop3-capabilities`适用于 POP3 和 POP3S。在非标准端口上运行的邮件服务器可以通过 Nmap 的服务扫描来检测：

```
$ nmap -sV --script pop3-capabilities <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *检测开放继电器*配方

+   *暴力破解 SMTP 密码*配方

+   *在 SMTP 服务器中枚举用户*配方

+   *检测后门 SMTP 服务器*配方

+   *暴力破解 IMAP 密码*配方

+   *检索 IMAP 邮件服务器的功能*配方

+   *暴力破解 POP3 密码*配方

+   *检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75*配方

# 检测易受攻击的 Exim SMTP 服务器版本 4.70 至 4.75

启用 DKIM 的 Exim SMTP 服务器 4.70 至 4.75 存在格式字符串错误，允许远程攻击者执行代码。 Nmap NSE 可以帮助渗透测试人员远程检测此漏洞。

这个配方说明了利用 Nmap 的 Exim SMTP 服务器的过程。

## 如何做...

打开你的终端并输入以下命令：

```
$ nmap --script smtp-vuln-cve2011-1764 --script-args mailfrom=<Source address>,mailto=<Destination address>,domain=<domain> -p25,465,587 <target>

```

如果 Exim 服务器存在漏洞，脚本输出部分将包含更多信息：

```
PORT   STATE SERVICE
587/tcp open  submission
| smtp-vuln-cve2011-1764: 
|   VULNERABLE:
|   Exim DKIM format string
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-1764  OSVDB:72156
|     Risk factor: High  CVSSv2: 7.5 (HIGH) (AV:N/AC:L/Au:N/C:P/I:P/A:P)
|     Description:
|       Exim SMTP server (version 4.70 through 4.75) with DomainKeys Identified
|       Mail (DKIM) support is vulnerable to a format string. A remote attacker
|       who is able to send emails, can exploit this vulnerability and execute
|       arbitrary code with the privileges of the Exim daemon.
|     Disclosure date: 2011-04-29
|     References:
|       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1764
|       http://osvdb.org/72156
|_      http://bugs.exim.org/show_bug.cgi?id=1106

```

## 它是如何工作的...

脚本`smtp-vuln-cve2011-1764`由 Djalal Harouni 编写。它通过发送格式不正确的 DKIM 标头并检查连接是否关闭或返回错误来检测易受攻击的 Exim SMTP 服务器 4.70-4.75 与**Domain Keys Identified Mail**（**DKIM**）。

## 还有更多...

默认情况下，脚本`smtp-vuln-cve2011-1764`在初始握手中使用`nmap.scanme.org`作为域，但您可以通过指定脚本参数`smtp-vuln-cve2011-1764.domain`来更改这一点：

```
$ nmap --script smtp-vuln-cve2011-1764 --script-args domain=<domain> -p25,465,587 <target>

```

要更改与源地址和目标地址对应的默认值`root@<domain>`和`postmaster@<target>`，请使用参数`smtp-vuln-cve2011-1764.mailfrom`和`smtp-vuln-cve2011-1764.mailto`：

```
$ nmap --script smtp-vuln-cve2011-1764 --script-args mailto=admin@0xdeadbeefcafe.com,mailfrom=test@0xdeadbeefcafe.com -p25,465,587 <target>

```

### 调试 NSE 脚本

如果运行任何 NSE 脚本时发生意外情况，请打开调试以获取更多信息。Nmap 使用`-d`标志进行调试，您可以设置 0 到 9 之间的任何整数：

```
$ nmap -p80 --script http-google-email -d4 <target>

```

## 另请参阅

+   *检测开放继电器*配方

+   *暴力破解 SMTP 密码*配方

+   *在 SMTP 服务器中枚举用户*配方

+   *检测后门 SMTP 服务器*配方

+   *暴力破解 IMAP 密码*配方

+   *检索 IMAP 邮件服务器的功能*配方

+   *暴力破解 POP3 密码*配方

+   *检索 POP3 邮件服务器的功能*配方
