# Metasploit Web 渗透测试实用指南（二）

> 原文：[`annas-archive.org/md5/53B22D5EEA1E9D6C0B08A2FDA60AB7A5`](https://annas-archive.org/md5/53B22D5EEA1E9D6C0B08A2FDA60AB7A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 Metasploit 进行 Web 应用程序枚举

枚举是足迹的一个子集，属于**渗透测试执行标准**（PTES）情报收集的第二阶段。执行枚举的主要优势是找到攻击端点，从中我们可以发动攻击或发动伪攻击有效负载，以确认漏洞是否存在于同一端点。在大多数渗透测试案例中，测试人员花费大约 60-70%的时间寻找信息。测试人员使用这些信息来识别一些新的漏洞。枚举越好，渗透测试的结果就越好。在本章中，我们将涵盖以下主题：

+   枚举简介

+   DNS 枚举

+   枚举文件

+   使用 Metasploit 进行爬取和抓取

# 技术要求

以下是本章的先决条件：

+   安装了 Metasploit 社区版（CE）的 Web 界面

+   基于*nix 系统或 Microsoft Windows 系统

+   用于枚举的通用单词列表-推荐使用 SecLists

# 枚举简介

在枚举过程中，我们从最初的足迹/侦察中检索到的所有信息将首次使用。对于渗透测试 Web 应用程序，我们需要对枚举过程有很好的理解。越好的侦察和枚举，我们就越快、越容易地找到 Web 应用程序中的漏洞。使用枚举，我们可以找到以下内容：

+   隐藏文件和目录

+   备份和配置文件

+   子域和虚拟主机

让我们首先看一下 DNS 枚举以及如何使用 Metasploit 进行 DNS 枚举。

# DNS 枚举

Metasploit 还可以用于从 DNS 记录中获取有关主机的信息，使用`dns_enum`辅助功能。此脚本使用 DNS 查询来获取信息，如**MX**（邮件交换器）、**SOA**（授权起始）、**SRV**（服务）记录。它可以在网络内外使用。有时，DNS 服务配置为可被公众访问；在这种情况下，我们可以使用`dns_enum`来查找内部网络主机、MAC 地址和 IP 地址。在本节中，我们将看一下`dns_enum`的用法：

1.  我们可以在模块搜索选项中使用`enum_dns`关键字来查找辅助功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/86063e91-ef33-46fa-a9a9-0f17c3ee0ddc.png)

1.  单击模块名称将重定向我们到选项页面，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/576a1d83-d7e2-4755-a277-81b1de9fbe03.png)

在这里，我们可以设置目标详细信息，例如我们正在使用的 DNS 服务器、域名以及我们希望脚本获取的记录。

1.  单击“运行模块”将创建一个新任务，输出将显示在下面的截图中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d9e200dc-743a-4632-9a6b-247cf1ae88ab.png)

现在让我们看看如何进一步改进以满足我们的需求，并使模块获取更多结果。

# 额外的工作-编辑源代码

Metasploit 中的`enum_dns`模块有点过时（我们可以检查 TLD 单词列表是否有更新）。因此，让我们定制模块以满足我们的需求。我们的想法是为`enum_dns`提供**顶级域**（TLD）单词列表，然后解析并检查条目以查询记录。从辅助功能的源代码中可以看到，它寻找的 TLD 不包括最近推出的新 TLD：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/be14fc73-abc2-4747-a2ce-8931e95ab362.png)

这可以在*第 302 行*中看到，在`modules/auxiliary/gather/enum.dns.rb`文件中，也可以通过访问以下链接在线访问：

[`github.com/rapid7/metasploit-framework/blob/f41a90a5828c72f34f9510d911ce176c9d776f47/modules/auxiliary/gather/enum_dns.rb#L302`](https://github.com/rapid7/metasploit-framework/blob/f41a90a5828c72f34f9510d911ce176c9d776f47/modules/auxiliary/gather/enum_dns.rb#L302)

从前面的源代码中，我们可以看到 TLD 存储在`tlds[]`数组中。让我们编辑代码以通过以下步骤更新 TLD。更新的 TLD 列表可以从**互联网编号分配机构**（**IANA**）网站找到：[`data.iana.org/TLD/tlds-alpha-by-domain.txt`](http://data.iana.org/TLD/tlds-alpha-by-domain.txt)：

1.  从上述 URL 下载 TLD 文件并删除以`#`开头的第一行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f4eb972f-0849-4f3e-a127-1f9e8caf708d.png)

1.  在修改 Metasploit 模块之前，使用以下命令备份`enum_dns.rb`文件：

```
cp /usr/local/share/metasploit-framework/modules/auxiliary/gather/enum_dns.rb enum_db.rb.bak
```

请注意，Metasploit 框架安装在`/usr/local/share`目录中。在我们的情况下，我们已将文件命名为`enum_dns.rb.bak`。

1.  现在，使用您选择的任何文本编辑器打开`enum_dns.rb`文件并转到第 29 行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4bf600d0-633b-440f-816a-696a40ce9811.png)

1.  让我们向代码添加另一个注册条目，以便我们可以将我们的 TLD 单词列表提供给 Metasploit 模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b8660043-be68-4f86-bfa5-e1b19d29c204.png)

在这个模块中，默认情况下禁用了 TLD 枚举。正如我们从上面的屏幕截图中所看到的，当`ENUM_TLD`选项设置为`TRUE`时，`ENUM_TLD`选项将通过用 IANA TLD 列表（旧列表）替换 TLD 来执行 TLD 扩展。

1.  让我们搜索`ENUM_TLD`字符串以查找`function()`，这将在启用 TLD 枚举选项时调用。

正如我们从下面的屏幕截图中所看到的，如果`ENUM_TLD`设置为`TRUE`，将调用`get_tld()`函数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0bda60f4-49f2-423f-b003-e8a81f296bc7.png)

1.  现在让我们看看`get_tld()`函数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b1e4ff33-bfa1-4b75-9f21-3b546f3eca9f.png)

1.  现在让我们添加一个代码部分，它将加载最新的 TLD 单词列表并将其保存在`tlds[]`数组中。请注意，我们已经从前面的屏幕截图中清空了 TLD 数组：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f1fe9b4a-4d97-4b51-9ea1-788638054bde.png)

我们在这里做了什么？以下表格解释了前面屏幕截图中使用的函数和代码结构：

| **代码** | **描述** |
| --- | --- |
| `tlds = []` | 这声明了一个数组。 |
| `tld_file = datastore['TLD_WORDLIST']` | 这将单词列表文件名（带位置）保存在`tld_file`变量中。 |
| `File.readlines(tld_file).each do &#124;tld_file_loop&#124;` | 这逐行读取 TLD 单词列表。 |
| `tlds << tld_file_loop.strip` | 这会从每行中剥离`\n`并将其保存在`tlds[]`数组中。 |

1.  现在，保存文件并在 msfconsole 中执行`reload`命令以重新加载框架中的模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7934daa7-d143-4cc8-8dcf-5ed1475fc940.png)

1.  现在让我们使用定制的`enum_dns`模块并执行`show options`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ce31cf36-6ceb-43ff-b29b-d5c3d62e045d.png)

正如我们从前面的屏幕截图中所看到的，我们已经将域设置为`google.com`以查找 Google 的 TLD。我们还将`TLD_WORDLIST`选项设置为我们更新的 TLD 单词列表。让我们执行它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/166f726a-4d14-44e3-a1ef-da829a0e53b7.png)

太棒了！更新后的 Metasploit 模块现在向我们显示了 TLD，这些 TLD 是提供给模块本身的。现在让我们继续下一节，在那里我们将使用 Metasploit 枚举文件和目录。

# 枚举文件

在渗透测试活动期间，枚举文件和目录是最重要的步骤之一。服务器端的小配置错误可能导致我们找到以下文件：

+   隐藏文件

+   备份文件

+   配置文件

+   重复文件

+   包含重要信息的文件，例如凭据文件、密码备份、错误日志、访问日志和调试跟踪

这些文件中包含的信息可以帮助我们计划对组织的进一步攻击。

以下是 Metasploit 框架中可用的一些辅助功能，可以帮助我们收集信息：

+   `dir_scanner`

+   `brute_dirs`

+   `prev_dir_same_name_file`

+   `dir_listing`

+   `copy_of_file`

+   `Backup_file`

以下是前述辅助功能的一些示例：

1.  我们可以使用 HTTP 目录扫描模块来查找目录列表，以及隐藏目录。我们可以使用`dir_scanner`关键字来查找模块，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2e16a2d3-9416-4d3b-a707-0b6244e8b5f1.png)

1.  单击模块名称将带我们到选项页面，在那里我们可以指定目标 IP/域名和端口号，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fc888306-d73b-4752-baee-d7eb52530630.png)

1.  单击运行模块将创建一个新任务，我们可以在任务窗口中看到输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f4a4d35c-781d-4d7b-9f08-41497755b2c2.png)

前面的屏幕截图显示了脚本发现的不同目录。

1.  扫描完成后，我们还可以在主机标签中查看目录列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/766de6fd-2ccd-452e-a9ac-27610d144367.png)

1.  我们转到分析标签，并选择进行扫描的主机。

1.  单击漏洞标签将显示辅助工具找到的所有目录的列表，如下面的屏幕截图所示。同样，我们可以使用本节开头列出的其他模块来执行进一步的枚举：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3c59a87f-6d52-4f6e-9de0-5b24d8347c16.png)

在接下来的部分，我们将学习使用 web 辅助程序进行爬行和抓取。

# 使用 Metasploit 进行爬行和抓取

Metasploit 还允许我们使用辅助程序进行爬行和抓取网页。当我们想要通过定义的模式从网站的源代码中抓取内容时，抓取是很有用的。它可以为我们提供诸如在注释中提到的目录、开发人员电子邮件和后台进行的 API 调用等信息：

1.  对于爬行，我们可以使用`crawl`关键字来查找模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c4c96131-923d-4396-ab2e-430e75b4bef6.png)

1.  我们将使用`msfcrawler`。单击模块将重定向我们到选项页面，在那里我们定义我们的目标、端口和深度。然后，单击运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/950e3cfa-5abf-43ed-bc6b-765f5c886045.png)

1.  将创建一个新任务，并在任务窗口中看到找到的页面列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0745ce83-4605-4686-bfca-be33c6b6f2b3.png)

1.  同样，我们可以使用 HTTP Scrape 模块`auxiliary/scanner/http/scraper`来抓取网页：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5360b1fc-bfc6-4bf5-ac85-f15c5593368f.png)

模式字段是我们定义的用于查找我们想要的任何元素的正则表达式。在我们的情况下，我们想要抓取[`prod.packtpub.com/`](https://prod.packtpub.com/)网站上脚本标记内的所有内容，所以我们的模式是`<script \ type=\"text\/javascript\" \ src=\"(.*)\"><\/script>)`。

运行模块将创建一个新任务，辅助程序将提取脚本标记中列出的所有数据，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/80c8f359-fcf1-40a1-a4bf-ba440c0c7eec.png)

接下来，让我们扫描虚拟主机。

# 扫描虚拟主机

Metasploit 还允许我们扫描配置在同一 IP 上的虚拟主机。虚拟主机是在单个服务器上托管多个域名，并且每个域名都配置有不同的服务。它允许单个服务器共享资源：

1.  我们将使用 Metasploit 控制台进行此模块。要搜索`vhost`模块，我们可以使用`vhost_scanner`关键字：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/532d57b5-0f46-4d7e-8d0e-68b252ada96e.png)

1.  我们设置`rhosts`和`domain`。在我们的情况下，我们使用了`packtpub.com`域和`151.101.21.124` IP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4dd23bf9-b5be-432d-ade0-bf7ed0f1b07f.png)

1.  我们通过输入`run`来运行模块。辅助程序将进行扫描，并打印出所有找到的`vhosts`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3c55d495-4b42-4ceb-b061-449f8d25b12b.png)

这个辅助工具也可以用于内部网络，以查找托管在同一服务器上但配置有不同域的不同内部应用程序。

# 总结

在本章中，我们涵盖了枚举，这是渗透测试生命周期中最重要的部分。我们从使用 Metasploit 模块枚举 DNS 开始，然后转向枚举文件和目录。最后，我们还研究了爬行模块以及`vhost`查找模块。

在下一章中，我们将学习如何使用 Web 应用程序扫描工具或 WMAP。WMAP 是一个用于对目标 Web 应用程序进行漏洞扫描的 Metasploit 插件。

# 问题

1.  我们可以使用自定义字典来枚举文件和目录吗？

1.  我们可以定制 Metasploit 有效载荷以一次性自动执行所有枚举吗？

1.  我们真的需要为抓取 HTTP 页面提供正则表达式吗？

# 进一步阅读

以下是一些可以供进一步阅读的网址：

+   [`www.offensive-security.com/metasploit-unleashed/`](https://www.offensive-security.com/metasploit-unleashed/)

+   [`resources.infosecinstitute.com/what-is-enumeration/`](https://resources.infosecinstitute.com/what-is-enumeration/)


# 第八章：使用 WMAP 进行漏洞扫描

漏洞评估是识别、排名和分类网络或应用程序中的漏洞的过程。它为组织提供了对其资产和面临的风险的理解。在使用 Metasploit 时，可以使用单独的辅助模块或可用的插件进行漏洞扫描。Metasploit 框架还允许我们添加自己的自定义插件，如果我们有自己的漏洞扫描器（内部）。

WMAP 是 Metasploit 的插件，它使用户可以根据扫描中使用的 Metasploit 模块对目标进行漏洞扫描。此插件的最佳功能之一是能够根据测试人员的要求使用尽可能多的 Metasploit 模块（包括自定义模块）进行漏洞扫描。测试人员可以创建多个配置文件以适应不同的情况。

在本章中，我们将学习以下主题：

+   了解 WMAP

+   WMAP 扫描过程

+   WMAP 模块执行顺序

+   向 WMAP 添加模块

+   使用 WMAP 进行集群扫描

# 技术要求

本章的先决条件如下：

+   Metasploit 框架（[`github.com/rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework)）

+   基于*nix 系统或 Microsoft Windows 系统

+   Metasploit 的 WMAP 插件

# 了解 WMAP

**WMAP**是用于扫描 Web 应用程序漏洞的*扫描器*插件。它不像 Burp Suite 或 Acunetix 那样是真正的扫描器，但它确实有自己的优势。在详细了解 WMAP 之前，让我们先试着了解其架构。

WMAP 架构简单而强大。WMAP 是作为插件加载到 MSF 中的迷你框架。它连接到 Metasploit 数据库以获取任何先前完成的扫描的结果。从数据库加载的结果（如主机名、URL、IP 等）将用于 Web 应用程序扫描。WMAP 使用 Metasploit 模块（如下图所示）来运行扫描，模块可以是任何类型的-辅助、利用等。一旦 WMAP 开始扫描目标，找到的所有工件和关键信息都将存储在 MSF 数据库中。WMAP 最强大的功能之一是其分布式（集群）扫描功能（在本章的*使用 WMAP 进行集群扫描*部分中介绍），它帮助 WMAP 通过*n*个节点（MSF 从属）扫描任意数量的 Web 应用程序。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0f0e2571-82d4-43d8-b1ae-f2d64273b510.png)

在详细了解如何使用 WMAP 之前，让我们先了解一下流程。

# WMAP 扫描过程

使用 WMAP 非常容易。我们在本节中为想要学习如何使用此插件的初学者定义了一个过程。扫描过程可以分为四个阶段-**数据侦察**、**加载扫描器**、**WMAP 配置**和**启动**。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c82f7da4-5c77-4725-87c3-41cc241700bc.png)

让我们先看看第一阶段-数据侦察。

# 数据侦察

在这个阶段，使用爬虫、代理和其他来源收集与目标相关的信息。然后将数据保存在 MSF 数据库中以供进一步使用。可以使用任何第三方工具获取数据，例如 Burp Suite 或 Acunetix。数据可以使用`db_import`命令导入到 MSF 中，因为 MSF 支持许多第三方工具。让我们看一个 Burp 扫描如何导入到 Metasploit 的例子。

以下截图显示了`db_import`命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/08c4d6cc-0cfc-467e-b51d-b43750ead426.png)

以下是将 Burp Suite 数据导出并导入到 Metasploit 的步骤：

1.  打开先前完成的域名扫描。它可以是主动的也可以是被动的。在我们的案例中，我们将使用[prod.packtpub.com](https://www.packtpub.com/in/)的被动扫描示例。以下截图的“问题”选项卡显示了 Burp 发现的各种问题：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/37c9bd5a-bb81-40e4-8591-5f5129e8a3c7.png)

1.  然后，我们将选择要传输到 Metasploit 的问题，右键单击。然后，我们选择“报告所选问题”选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ef205eb2-3506-4913-9cf2-df2ada166d01.png)

1.  将打开一个新窗口，要求我们选择报告的格式。我们选择 XML 并单击下一步：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8d67cba3-7ccf-4a59-8fdc-79c0243c86d0.png)

1.  在下一步中，我们可以指定报告中要包含的详细信息，然后单击下一步：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e0177741-3a97-4c63-be4f-30ca1c932cd2.png)

1.  然后，我们选择是否要包括来自扫描器的所选问题的请求和响应。我们选择两者并单击下一步：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6be9aec2-0f03-4679-9498-0df9a9d37019.png)

1.  接下来，它将要求我们选择要导出的所有问题。我们选择需要的问题并单击下一步：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/043ec93e-6fd7-4101-a0ea-b71485a1285b.png)

1.  在最后一步中，我们可以指定报告的目标路径和文件名，然后单击下一步：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/df71def4-7c78-40b0-a671-a16ebea1cdf5.png)

1.  报告现在将被导出，一旦导出完成，我们可以关闭窗口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e889d21b-1d47-4f8b-b356-dac2ea24903b.png)

1.  要将 Burp Suite 报告导入 Metasploit，我们可以简单地使用以下命令：

```
db_import test.xml
```

以下截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/512555e5-3c08-4fed-8e30-34e458375036.png)

1.  导入完成后，我们可以使用`hosts`命令查看报告中的所有主机，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b07927dc-cbd9-476d-a745-31fed3c3b146.png)

1.  要查看从 Burp Suite 扫描器导入的漏洞，我们可以使用`vulns`命令，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ce941dcb-54f9-480c-b236-7ddd7d926ce6.png)

现在信息已经导入到 Metasploit 中，WMAP 将自动检测和加载相同的信息，这意味着 Metasploit 中的主机现在将自动添加为 WMAP 模块中的站点。

# 加载扫描器

正如我们之前提到的，WMAP 实际上是一个加载在 MSF 中的插件。您可以通过输入`load`命令并按*Tab*键来查看 MSF 上的所有插件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b72d574b-ed9a-4aa7-bdfe-46d72177c230.png)

开始加载过程，以下是要遵循的步骤：

1.  让我们使用`load wmap`命令加载 WMAP 插件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8f638269-1723-4c07-ae13-3ec2e3736b5d.png)

1.  一旦插件加载完成，您可以使用`?`或`help`命令查看帮助部分，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/627fdbbf-3eb5-44e7-b039-24033371096c.png)

接下来，我们将看一下 WMAP 配置。

# WMAP 配置

您已经学会了如何在数据侦察阶段自动将目标添加到 WMAP 中。还有另一种方式可以将数据加载到 WMAP 中，那就是手动定义目标：

1.  让我们从创建一个新站点或工作空间开始执行我们的扫描。让我们看看我们用于站点创建的所有选项。键入`wmap_sites -h`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b67d7216-7520-4363-ba22-a6b55ca38446.png)

1.  现在让我们添加站点。有两种添加站点的方式 - 一种是直接通过 URL 或 IP。可以使用以下命令完成：

```
wmap_sites -a 151.101.21.32
```

以下截图显示了前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a02c7f92-2c8c-4e45-8715-7b3bb68a0e17.png)

1.  第二种方法是使用虚拟主机。当我们必须扫描多个虚拟主机时，这是非常有用的。要添加虚拟主机，我们可以使用以下命令：

```
wmap_sites -a <subdomain> , <IP Address>
```

以下是前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/773cf787-2e54-4eda-bd85-a35e37c46bd3.png)

1.  添加站点后，我们可以以类似的方式添加目标，可以是 IP/域名或虚拟主机（虚拟主机/域）。要通过 IP 添加目标，我们可以使用以下命令：

```
wmap_targets -t <IP Address>
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a46ef0c7-a418-4e60-bbb1-e568b6e226dc.png)

1.  要通过虚拟主机添加目标，我们使用以下命令：

```
wmap_targets -t <subdomain > , <IP Address>
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f62fa43f-8d36-4503-8d5f-577b0c60aef8.png)

1.  要查看将由 WMAP 运行的所有模块的列表，我们可以使用`wmap_modules -l`命令。命令的输出如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ceb4af93-7df2-4cee-bd1c-84ccbf69cbb1.png)

以下屏幕截图显示了文件/目录测试的模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/372aa366-a906-4d73-ade6-4a4906333fb6.png)

此阶段还包括 WMAP 扫描节点，可以配置这些节点，以便进行分布式 WMAP 扫描。可以使用`wmap_nodes`命令管理和配置节点。关于这一点将在本章的*使用 WMAP 进行集群扫描*部分进行讨论。完成最终配置后，下一阶段是启动 WMAP。

# 启动 WMAP

默认情况下，WMAP 在目标上运行所有模块，但您可以更改模块执行的顺序（这将在下一个主题中介绍）：

1.  要运行 WMAP，请执行以下命令：

```
wmap_run -e
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7612dd18-1fe0-4cf7-84d3-abb68db0f4bc.png)

执行前面的命令后，加载模块的执行将开始。在 WMAP 中没有暂停或恢复选项，所以你要么等待扫描完成，要么可以通过按*Ctrl*+*C*来中断扫描过程。

1.  要了解有关`wmap_run`命令的更多信息，可以执行`wmap_run -h`命令，以查看在启动时可以使用的其他可用选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7288d4c7-fc33-43ab-83fd-1fab75d5b628.png)

甚至可以基于模块使用关键字字符串或正则表达式启动 WMAP 扫描。在这种情况下，我们使用一个字符串，将在加载的模块列表中搜索任何`version`关键字：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/4d19d169-16d6-4a59-a8ff-ac114b952897.png)

我们可以根据需要使用正则表达式。现在我们已经了解了 WMAP 扫描过程的不同阶段。在下一节中，我们将了解 WMAP 中的执行顺序。

# WMAP 模块执行顺序

WMAP 按特定顺序运行加载的模块。顺序由数字值定义。默认情况下，用于 Web 扫描的第一个模块是`http_version`，其`OrderID=0`，`open_proxy`模块的`OrderID=1`。这也意味着`http_version`模块将首先执行，然后是`open_proxy`。测试人员可以通过相应地更改`OrderID`来改变模块执行的默认行为：

1.  模块执行顺序可以根据我们的需要进行更改。我们可以通过执行`wmap_modules -l`命令来获取`OrderID`。

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5873a26b-4a50-4a01-94cc-0124ec4b7f64.png)

1.  `OrderID`在 Metasploit 模块代码中设置。让我们看看`http_version`模块的`OrderID`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a615294e-6a77-4085-beb7-bf5d987084f2.png)

可以使用`register_wmap_options()`方法调整 WMAP 模块的执行顺序。

1.  让我们使用这种方法来更改`http_version`模块的`OrderID`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f68ed1e0-0c1e-4b3a-959c-30e883e396c6.png)

1.  现在让我们重新加载模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6e7213e5-dbfc-418e-9cf0-0e9cdc28b75a.png)

1.  重新加载后，我们使用`wmap_modules -l`命令列出模块，以查看更新后的模块执行顺序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fb6d6b1d-8ed6-441c-87ab-eee5d3f0b655.png)

从前面的屏幕截图中，我们可以看到`OrderID`现在已经更改。现在我们已经了解了模块执行顺序，让我们在下一节中向 WMAP 添加一个模块。

# 向 WMAP 添加模块

WMAP 允许我们添加自己的模块。这可以是来自 MSF 的模块，也可以完全从头开始制作我们自己的模块。让我们以 SSL 模块为例。以下截图显示了 WMAP 当前正在使用的两个模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3048bafb-ed99-49d5-8d73-1aa2f951bf38.png)

我们还可以添加基于 SSL 的扫描器模块（除了 MSF 中可用的 SSL Labs 模块）：

1.  我们将使用`ssllabs_scan`模块，它将使用 Qualys SSL Labs 的在线 SSL 扫描仪通过 Qualys 提供的公共 API 执行 SSL 扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3a58652e-4bbc-4216-9b2c-9a5634eac3f2.png)

1.  现在我们编辑此模块的源代码，以便我们可以添加可以在扫描中使用的必要库和方法：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/949c388f-d114-4a8b-95f7-2a8d0d0cbf06.png)

1.  我们在`MetasploitModule`类下面添加以下行：

```
include Msf::Auxiliary::WmapScanSSL
```

上述 WMAP 库提供了包含在扫描中的 WMAP SSL 扫描器模块的方法。这可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0bf01544-0647-460d-955d-90cee289b593.png)

仅添加库是不够的；仅添加库运行模块将导致错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/951d7ab6-2094-48a9-af2d-c004db2c5508.png)

原因是这是`HOSTNAME`数据存储，它是`ssllabs_scan`模块选项，并且 WMAP 插件根本没有捕获它。插件只定义了以下方法（参考`metasploit-framework/lib/msf/core/auxiliary/wmapmodule.rb`文件）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f12637ea-e809-4b66-a1e2-84b8ebeefde8.png)

在这种情况下，我们需要找到 WMAP 识别`ssllabs_scan`模块的`HOSTNAME`数据存储的方法。可能有很多变通方法，但我们将使用这个，因为对我们来说很方便：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c7ab1b1c-c6ad-4e7a-8d71-28b2e4b22fa9.png)

1.  我们将数据存储更改为从`datastore['HOSTNAME']`到`datastore['VHOST']`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/41cfd927-e255-4abd-88ac-2b67f1090152.png)

存储来自`HOSTNAME`数据存储的数据的变量将保存来自`VHOST`数据存储的数据。同时，WMAP 将通过`wmap_target_vhost()`方法识别`VHOST`数据存储：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ba6c51a3-0128-449a-9bf7-189146eee632.png)

1.  现在我们保存代码并返回到我们的 Metasploit 控制台，并通过输入`reload`重新加载模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0bbfedbf-cda2-4c90-8b51-0b015c690255.png)

我们还使用以下命令重新加载 WMAP 模块：

```
wmap_modules -r
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/aa0cf6f4-0ebd-43d3-8dcb-82a4d9e5d881.png)

1.  现在让我们列出模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c16b8210-783e-4272-9143-d0428c3c58f0.png)

模块已加载！

以下是可以在任何模块中使用的混合类型：

| **混合** | **描述** |
| --- | --- |
| **WmapScanSSL** | 对 SSL 服务运行一次扫描 |
| **WmapScanServer** | 对 Web 服务运行一次扫描 |
| **WmapScanDir** | 对目标中找到的每个目录运行扫描 |
| **WmapScanFile** | 对目标中找到的每个文件运行扫描 |
| **WmapScanUniqueQuery** | 对目标的每个请求中找到的每个唯一查询运行扫描 |
| **WmapScanQuery** | 对目标的每个请求中找到的每个查询运行扫描 |
| **WmapScanGeneric** | 在扫描完成后运行的模块（被动分析） |

1.  更新 WMAP 模块的操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/70b42d1e-692d-4ba0-b9c5-7c74342b5a64.png)

模块发现的漏洞保存在数据库中，可以通过执行`wmap_vulns -l`命令查看：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/957d009a-359f-4547-a573-3bbb5fd51955.png)

在下一节中，我们将看一下 WMAP 的分布式扫描功能。

# 使用 WMAP 进行集群扫描

WMAP 还可以用于对目标进行分布式评估。此功能允许在不同服务器上运行的多个 WMAP 实例以主从模型一起工作，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ac8c7517-bd02-414e-b365-7a32af79d0fd.png)

WMAP 主服务器会自动将目标分发到从服务器上，形成作业。作业完成后，将结果报告给主服务器，并将结果存储在主服务器的数据库中：

1.  让我们添加一个站点进行扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ab4ab1aa-1782-4c28-bd3a-d18146283184.png)

1.  使用`auxiliary/scanner/http/crawler`模块在站点上使用爬虫；相应地设置选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3c8c5b0d-d211-4663-824a-9542f360af52.png)

1.  运行爬虫以收集表单和页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/20210f40-6890-42a9-b769-5f941603cfe9.png)

1.  使用`wmap_sites -l`命令确认从爬行中找到的页面/表单的数量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/355c8523-4ea1-44bb-a17d-fe8d8d73ecbc.png)

1.  让我们为分布式扫描设置 WMAP 节点。我们将在节点上使用`msfrpcd -U <user> -P <password>`命令运行`msfrpcd`。此命令将在后台启动 RPC 服务器，以便 WMAP 与 Metasploit 进行交互：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1dbec482-1a53-4d29-9d71-7a6538ff7575.png)

1.  一旦节点配置好，我们将使用`wmap_nodes`命令来管理和利用这些节点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b16830b8-b948-49e6-8d83-02ee119eef68.png)

1.  我们将使用以下命令将节点添加到 WMAP 中：

```
wmap_nodes -a <IP> <RPC port> <SSL status - true/false> <rpc user> < rpc pass>
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/688f0888-7136-4396-aa52-6d8d35b0abcb.png)

1.  一旦节点连接，我们可以使用`wmap_nodes -l`命令列出节点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/51b815d3-b8d9-491d-91f4-8c8aa2ab9655.png)

1.  现在一切都设置好了。我们只需要为扫描程序定义目标。可以使用`wmap_targets`命令完成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/905131a1-cec9-494a-93e7-77a1bc6c0f28.png)

在本例中，我们使用了`-d`开关来根据 ID 添加目标。可以使用`wmap_sites -l`命令检索 ID。当前设置的问题是，所有在节点上执行的模块都将保存数据在节点上。

1.  如果要将数据保存在节点上，需要将节点连接到本地 MSF 数据库。可以使用以下命令完成：

```
wmap_nodes -d <local msf db IP> <local msf db port> <msf db user> <msf db pass> <msf db database name>
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/60acf6d3-8476-44ef-a267-e98b79e71e1c.png)

1.  现在使用`wmap_run -e`命令运行 WMAP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b1d8f76a-87c6-45cd-ba7a-5d3f6a4a0f2e.png)

WMAP 加载的每个模块都将相应地分布和在节点上执行。

WMAP 每个节点的**作业限制为 25 个**。这是为了防止节点负担过重。

1.  我们可以通过输入`wmap_nodes -l`来查看连接的节点列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/43943310-effc-4806-a765-3bd2760b9a21.png)

1.  我们还可以使用 WMAP 仅运行单个模块；例如，如果我们想要运行`dir_scanner`模块，可以使用以下命令：

```
wmap_run -m dir_scanner
```

以下是输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d4f6ac23-f36e-4b35-962c-92fddf67382c.png)

以下屏幕截图显示了发现的目录的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b4e22c65-1b53-48aa-8357-da525dd9dab8.png)

1.  如前面的屏幕截图所示，该模块开始列出找到的目录。要以树形结构查看输出，请使用此命令：

```
wmap_sites -s 1
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a42133a9-5e66-4a55-8a1e-4252229114b4.png)

1.  要查看分配给节点的当前作业，可以使用此命令：

```
wmap_nodes -j
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/35fb3358-59be-4936-aa07-021560c45a48.png)

1.  要删除节点，我们可以使用此命令：

```
wmap_nodes -c 1
```

这将从列表中删除节点 1。

# 总结

在本章中，我们了解了 WMAP 及其架构和扫描过程。接下来，我们学习了如何将来自不同工具（如 Burp Suite）的输出导入 Metasploit，并继续加载、配置和使用 WMAP 模块进行扫描。在本章末尾，我们看了如何在 WMAP 中使用集群扫描。

在下一章中，我们将研究 WordPress 的渗透测试。

# 问题

1.  分布式扫描可以使用多少个 WMAP 实例？

1.  WMAP 插件支持报告吗？

1.  我可以导入其他服务器日志和报告到 Metasploit 中，然后在 WMAP 中使用吗？

1.  我想进一步定制 WMAP 以适应我们组织的环境。我该怎么做？

1.  WMAP 支持每个节点多少个作业？

# 进一步阅读

+   有关 WMAP 网络扫描程序的更多信息，请访问以下链接：

[`www.offensive-security.com/metasploit-unleashed/wmap-web-scanner/`](https://www.offensive-security.com/metasploit-unleashed/wmap-web-scanner/)


# 第九章：使用 Metasploit（Nessus）进行漏洞评估

在本章中，我们将介绍使用 Nessus 桥接 Metasploit 框架进行漏洞评估的一些方法。Nessus 是 Tenable 公司开发的漏洞扫描器。它被广泛用于进行网络安全评估。Nessus 桥接允许 Metasploit 解析和导入 Nessus 的扫描结果到其自己的数据库进行进一步分析和利用。我们甚至可以使用桥接在 Metasploit 内部启动 Nessus 扫描。

在本章中，我们将涵盖以下主题：

+   Nessus 简介

+   使用 Metasploit 的 Nessus

+   基本命令

+   修补 Metasploit 库

+   通过 Metasploit 执行 Nessus 扫描

+   使用 Metasploit DB 进行 Nessus 扫描

+   在 Metasploit DB 中导入 Nessus 扫描

# 技术要求

本章的先决条件如下：

+   Metasploit 框架

+   *nix 系统/微软 Windows 系统用于主机机器

+   Nessus Home Edition 或 Professional Edition

# Nessus 简介

Nessus 是由 Tenable 开发的最常见和易于使用的漏洞扫描器之一。这种漏洞扫描器通常用于对网络进行漏洞评估，Tenable Research 已发布了 138,005 个插件，涵盖了 53,957 个 CVE ID 和 30,392 个 Bugtraq ID。大量的 Nessus 脚本（NASL）帮助测试人员扩大他们发现漏洞的范围。Nessus 的一些特点如下：

+   漏洞扫描（网络、Web、云等）

+   资产发现

+   配置审计（MDM、网络等）

+   目标配置

+   恶意软件检测

+   敏感数据发现

+   补丁审计和管理

+   策略合规审计

Nessus 可以从[`www.tenable.com/downloads/nessus`](https://www.tenable.com/downloads/nessus)下载。安装完成后，我们必须激活该工具。激活可以通过[`www.tenable.com/products/nessus/activation-code`](https://www.tenable.com/products/nessus/activation-code)上的代码完成。

# 使用 Metasploit 的 Nessus

许多渗透测试人员使用 Nessus，因为它可以与 Metasploit 一起使用。我们可以将 Nessus 与 Metasploit 集成，通过 Metasploit 执行其扫描。在本节中，我们将按照以下步骤将 Nessus 与臭名昭著的 Metasploit 集成：

1.  在继续之前，请确保您已成功安装 Nessus，并且可以从浏览器访问 Nessus Web 界面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b533025a-f883-481b-82c4-7eada2d01b4c.png)

1.  在 Metasploit 中，我们首先要使用`load nessus`命令在 msfconsole 中加载 Nessus 插件。这将加载 Metasploit 的 Nessus 桥接，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/806d0da9-4606-4566-bebf-b8ff7aa0a828.png)

1.  要查看插件提供的命令，请在 msfconsole 中执行`nessus_help`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a784d701-d6b8-4e69-8124-4b3eeae27467.png)

在我们可以对 Nessus 进行漏洞扫描之前，我们需要首先对其进行身份验证，这将在下一小节中完成。

# 通过 Metasploit 进行 Nessus 身份验证

Metasploit 使用 Nessus RESTful API 与 Nessus Core Engine 进行交互，只有在成功验证后才能完成。可以按以下方式完成：

1.  我们可以使用以下命令语法对 Nessus 进行身份验证：

```
nessus_connect username:password@hostname:port <ssl_verify/ssl_ignore> 
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7baf7045-fc1b-45ee-9526-a2443628007f.png)

`用户名`和`密码`是我们用来登录 Nessus Web 前端的。`主机名`可以是 Nessus 服务器的 IP 地址或 DNS 名称，`端口`是 Nessus Web 前端运行的 RPC 端口。默认情况下，它是 TCP 端口`8834`。

`ssl_verify`用于验证 Nessus 前端使用的 SSL 证书。默认情况下，服务器使用自签名证书，因此用户应该使用`ssl_ignore`。如果我们不想一遍又一遍地使用相同的命令，我们可以将凭据保存在 Metasploit 可以用于与 Nessus 进行身份验证的配置文件中。

1.  要保存凭据，我们可以执行`nessus_save`命令。这将以 YAML 文件格式保存凭据，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/05ae4a10-2efd-484c-83ab-0c5396eff77c.png)

此 YAML 配置文件的内容如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9e1f9f47-54f2-4516-b360-e9648f4a5902.png)

如果我们想要注销，我们可以在 msfconsole 中执行`nessus_logout`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/792ac3d5-6492-476b-8130-381ac7d3bbee.png)

现在我们已经成功通过 Nessus RESTful API 进行了身份验证，我们可以执行一些基本命令来开始。

# 基本命令

假设我们在一个组织中工作，并且只能通过 Metasploit 终端提供的凭据来访问 Nessus。在这种情况下，最好运行一些基本命令，以了解我们可以做什么和不能做什么。让我们在接下来的步骤中看看这些命令：

1.  我们可以在 msfconsole 中执行的第一个命令是`nessus_server_properties`。此命令将为我们提供有关扫描仪（类型、版本、UUID 等）的详细信息。根据扫描仪的类型，我们可以设置我们的扫描首选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a4cfe25a-287b-4fbf-a9be-437521e7f606.png)

1.  `nessus_server_status`命令用于确认扫描仪的状态，以便我们可以确定它是否已准备就绪。这在组织使用具有分布式扫描仪代理的基于云的 Nessus 时非常有帮助。该命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/faa12f16-6646-4c7b-86fa-292f9421971a.png)

1.  `nessus_admin`命令用于检查经过身份验证的用户是否是管理员，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/29b246f1-0669-4f5e-b8c9-d95e88c76880.png)

1.  `nessus_folder_list`命令用于查看 Nessus 中可供我们使用的目录。运行该命令将给出以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/12bc1b14-a19e-47d6-96cb-cfbc7fe0a5f1.png)

1.  `nessus_template_list`命令用于列出 Nessus 中所有可用的模板。（**注意**：我们可以使用`-h`标志来查看此命令的帮助部分）。可访问的模板将“Subscription Only”设置为`TRUE`。要使用所有模板，我们必须在线查找订阅。上述命令的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/aa697452-e348-4f96-a401-dd7c73df44ac.png)

在前面的截图中，`-h`标志用于查看命令的帮助部分。

1.  要查看在 Nessus 中配置的类别列表，我们执行`nessus_family_list`命令。执行此命令后，我们将看到所有可用类别（Family Names）及其相应的 Family ID 和插件数量，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1f78a5a8-5858-43dd-a4b2-9e952e039606.png)

1.  要列出某个类别中的所有插件，我们可以执行`nessus_plugin_list <family ID>`命令。这将显示我们在 Nessus 中可以使用的所有插件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5df58389-a68d-415c-8a58-acbf98847830.png)

1.  要详细了解插件，我们可以在 msfconsole 中执行`nessus_plugin_details <plugin ID>`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/45106ddc-01a7-4e64-ad27-0b3f739b93b2.png)

1.  要列出所有可用的自定义策略，我们可以执行`nessus_policy_list`命令。这将给我们提供策略 UUID，我们将使用它来执行漏洞扫描。这些策略用于执行自定义扫描。策略 UUID 可用于区分使用多个策略执行的不同扫描，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/dab12abf-4214-4360-a790-ed57b3287ee7.png)

要开始扫描，我们首先需要修补 Metasploit Gem，它负责与 Nessus RESTful API 通信（因为官方补丁尚未发布），以应对我们在运行扫描时可能遇到的错误。这是由`@kost`（[`github.com/kost`](https://github.com/kost)）开发的一个解决方法。如果不修补，Metasploit 将会抛出错误，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/56f16c03-eab5-4f53-9075-425ba3779b3e.png)

在下一节中，我们将看一下修补 Metasploit 库。

# 修补 Metasploit 库

自 Nessus 7.0 版本以来，状态更改请求（例如，创建/启动/暂停/停止/删除扫描）受到新的身份验证机制的保护。为了让 Metasploit 遵循新更新的用户身份验证机制，我们需要修补`nessus_rest` RubyGem。要做到这一点，只需在`RubyGems`目录中搜索`nessus_rest.rb`文件。不与 Nessus 的新身份验证机制交互的代码可以在**第 152 行**找到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/736150c9-b043-4bfc-93f1-3de027cf4841.png)

我们需要用这里给出的代码替换**第 152 行**的代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0071c2f0-8e20-4b9c-893a-6d9092f8e223.png)

代码可以在这里找到：[`github.com/kost/nessus_rest-ruby/pull/7/files`](https://github.com/kost/nessus_rest-ruby/pull/7/files)。

接下来，我们将执行 Nessus 扫描。

# 通过 Metasploit 执行 Nessus 扫描

现在我们已经修补了 Metasploit 库，让我们使用 Metasploit 进行 Nessus 扫描：

1.  修补完 gem 后，我们现在可以使用`nessus_scan_new <策略的 UUID> <扫描名称> <描述> <目标>`命令创建一个漏洞扫描任务，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/97bdcdbd-be5e-445c-9940-af9e77c55c23.png)

1.  任务创建后，我们可以通过执行`nessus_scan_list`命令来确认。`扫描 ID`将用于启动任务，所以让我们记下来，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6bd1ef53-48fd-467a-848c-c4f240d6c57f.png)

1.  让我们通过访问 Nessus web 界面来确认一下相同的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/594d7e0a-1ed7-4daf-8745-96d0ef4f7029.png)

正如我们在前面的截图中看到的，扫描任务已经创建，但尚未启动。

1.  要启动扫描任务，我们需要执行`nessus_scan_launch <扫描 ID>`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8f794d63-38e1-41a8-b51b-d8e9dead0134.png)

我们已经成功启动了扫描任务。

1.  让我们在 Nessus web 界面上确认一下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/71927e81-7c25-465b-83ae-b13fc120bed4.png)

1.  我们可以通过执行`nessus_scan_details <扫描 ID> <类别>`命令在 msfconsole 中看到与前面截图相同的详情：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2f367d5e-fbc5-4d6d-b8e8-a4c73898c017.png)

可以用以下可用类别来查看扫描详情：

+   **信息**：一般的扫描信息，包括扫描状态，用于扫描的策略，扫描名称，扫描目标，以及扫描的开始和结束时间

+   **漏洞**：Nessus 在给定目标上发现的漏洞列表，其中包括用于扫描目标的插件名称及其插件 ID，插件家族（类别）以及在目标上找到的实例总数

以下截图显示了漏洞命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1ceddb0e-6408-4179-ae60-298e19ab0433.png)

+   **历史**：这是上次启动相同扫描任务的时间。这包括**历史 ID**，扫描的**状态**，**创建日期**和**最后修改日期**。

以下截图显示了历史命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1c121956-c0b3-420a-af2d-abec8b45a95a.png)

1.  让我们从 Nessus web 界面上确认一下扫描详情：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/07936ea5-dfe1-4e8c-b025-4c4b3586b0f3.png)

1.  现在让我们执行`nessus_report_hosts <扫描 ID>`命令来查看扫描的总体摘要，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b2abc66d-6678-489c-b477-c6909e353624.png)

1.  要获取已识别的漏洞列表，可以执行`nessus_report_vulns <scan ID>`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2a2c4965-d5f9-4f84-bfda-3b0a755a6cd3.png)

使用 Metasploit 中的 Nessus 带来了一个好处：能够使用 Metasploit DB 进行扫描。在我们有一个存储在 Metasploit DB 中的目标列表并且想要对这些目标进行漏洞扫描的情况下，这可能非常有用。

# 使用 Metasploit DB 进行 Nessus 扫描

通过`nessus_db_scan <policy ID> <scan name> <scan description>`命令，可以将存储在 Metasploit DB 中的所有目标传递给 Nessus。在我们的情况下，我们在 Metasploit DB 中存储了目标`192.168.2.1` IP；执行此命令后，Nessus 将开始对存储在 Metasploit DB 中的目标 IP 进行扫描（不仅创建任务，还启动任务）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fc616bc7-03e5-4007-97f8-ef2ab16bf3c1.png)

按照以下步骤进行：

1.  让我们通过 Nessus web 界面确认前面的执行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/dde21120-d705-479b-9b54-a45d5bfafd2d.png)

1.  正如我们在前面的截图中所看到的，扫描正在进行中。在我们管理 Metasploit 工作区的情况下，我们可以使用`nessus_db_scan_workspace`命令。在下面的截图中，我们有一个目标 IP 存储在`NESSUS-WEB`工作区中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a8de8828-a0a6-46c0-94fb-2a3cd001da59.png)

1.  让我们执行`nessus_db_scan_workspace <policy ID> <scan name> <scan description> <workspace>`命令，在`192.168.2.1`上运行扫描，该扫描存储在`NESSUS-WEB`工作区中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c485dc8e-4dc7-4955-abd7-19be1825f05c.png)

正如我们在前面的截图中所看到的，我们已经成功创建了一个扫描任务，将扫描存储在`NESSUS-WEB`工作区中的所有主机。

如果我们执行`nessus_db_scan_workspace`命令，就必须手动启动扫描任务。

1.  让我们使用`nessus_scan_launch <scan ID>`命令启动扫描。成功启动扫描任务后，我们将再次使用`nessus_scan_details`命令获取扫描状态：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3478944c-f855-4383-9f16-80523def20f7.png)

正如我们从前面的截图中所看到的，扫描已完成。

扫描结果不会保存在工作区中；相反，我们可以手动导入结果，或者使用`nessus_db_import`命令导入结果。请记住，只有在使用 Nessus Manager 时，才能访问一些功能。

现在我们已经介绍了如何使用 Metasploit DB 执行 Nessus 扫描，让我们继续下一部分，介绍如何将 Nessus 扫描结果导入 Metasploit DB。

# 在 Metasploit DB 中导入 Nessus 扫描

当我们没有访问 REST API 时，就会使用这种方法，这些 API 负责将结果直接导入到 DB 中。简单的解决方法如下：

1.  首先，将 Nessus 结果导出到文件中，下载文件，然后使用`db_import`命令导入相同的文件。

1.  要导出结果，请使用`nessus_scan_export <scan ID> <export format>`命令。（可用的导出格式为 Nessus、HTML、PDF、CSV 或 DB）。在过程中将分配文件 ID。

1.  导出准备就绪后，执行`nessus_scan_report_download <scan ID> <file ID>`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/dc195a73-c979-431d-a94f-4e13f721f335.png)

正如我们在前面的截图中所看到的，我们已将结果导出为 Nessus 格式并下载了文件。

1.  现在，使用`db_import`命令导入相同的文件。

1.  接下来，让我们执行`vulns`命令，确认 Nessus 结果是否已成功导入到 DB 中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b7c13ac1-a15c-4c16-8904-3576687ef4cc.png)

1.  我们还可以通过执行`hosts`和`services`命令来确认前面的方法是否有效，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/49f77ce9-ff96-4809-9d3b-2c979476a66b.png)

如果使用正确，我们可以通过点击按钮（当然，还包括自定义的 Metasploit 脚本来管理项目和自动化）来高效地管理 VA 项目。

# 总结

在本章中，我们首先介绍了 Nessus 桥。然后我们学习了如何配置桥接。接下来，我们看到了如何从 Metasploit 控制台启动 Nessus 扫描，最后，我们学习了如何将扫描结果导入 Metasploit 数据库以供进一步使用。

在下一章中，我们将学习如何对**内容管理系统**（**CMS**）进行渗透测试，首先从流行的系统 WordPress 开始。

# 问题

1.  我需要在系统上安装 Nessus 才能与 Metasploit 一起运行吗？

1.  我可以在 Metasploit 中使用其他漏洞扫描器代替 Nessus 吗？

1.  Nessus 专业版可以与 Metasploit 一起使用吗？

1.  我可以通过 Metasploit 扫描多少个系统？

# 进一步阅读

以下链接是关于 Nessus 的官方博客文章，解释了为什么以及如何将 Nessus 与 Metasploit 一起使用：

[`www.tenable.com/blog/using-nessus-and-metasploit-together`](https://www.tenable.com/blog/using-nessus-and-metasploit-together)


# 第十章：内容管理系统（CMS）的渗透测试

内容管理系统（CMS）如 Drupal，WordPress，Magento 和 Joomla 非常受欢迎，非常适合编辑内容。然而，如果它们的安全性没有得到定期维护和检查，这些系统也很容易受到黑客的攻击。本节将详细介绍 CMS 的渗透测试，以及 CMS 中一些常见的漏洞和曝光（CVEs）。

本节包括以下章节：

+   第八章，*CMS 渗透测试 - WordPress*

+   第九章，*CMS 渗透测试 - Joomla*

+   第十章，*CMS 渗透测试 - Drupal*


# 第十一章：渗透测试 CMS-WordPress

CMS 代表内容管理系统-用于管理和修改数字内容的系统。它支持多个用户、作者和订阅者的协作。互联网上使用了许多 CMS，其中一些主要的是 WordPress、Joomla、PHPNuke 和**AEM（Adobe Experience Manager）**。在本章中，我们将研究一个著名的 CMS，WordPress。我们将看看如何对这个 CMS 进行渗透测试。

我们将在本章中涵盖以下主题：

+   WordPress 架构简介

+   使用 Metasploit 进行 WordPress 侦察和枚举

+   WordPress 的漏洞扫描

+   WordPress 利用

+   自定义 Metasploit 漏洞

# 技术要求

以下是本章的先决条件：

+   Metasploit 框架

+   安装的 WordPress CMS

+   配置了数据库服务器（建议使用 MySQL）

+   基本的 Linux 命令知识

# WordPress 简介

WordPress 是一个开源的 CMS，使用 PHP 作为前端，MySQL 作为后端。它主要用于博客，但也支持论坛、媒体库和在线商店。WordPress 由其创始人 Matt Mullenweg 和 Mike Little 于 2003 年 5 月 27 日发布。它还包括插件架构和模板系统。WordPress 插件架构允许用户扩展其网站或博客的功能和功能。截至 2019 年 2 月，WordPress.org 有 54,402 个免费插件和 1500 多个付费插件。WordPress 用户还可以自由创建和开发自己的自定义主题，只要他们遵循 WordPress 标准。

在查看 WordPress 枚举和利用之前，让我们首先了解 WordPress 运行的架构。

# WordPress 架构

WordPress 架构可以分为四个主要部分：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1056d453-80ca-47bc-8a3d-d62875c86981.png)

让我们看看各个部分：

+   **显示**：这包含对用户可见的 HTML、CSS 和 JavaScript 文件。

+   **主题/模板**：这包括表单、主题文件、不同的 WordPress 页面和部分，如评论、页眉、页脚和错误页面。

+   **WP-Engine**：这个引擎负责整个 CMS 的核心功能，例如 RSS 订阅、与数据库通信、设置、文件管理、媒体管理和缓存。

+   **WP-Backend**：这包括数据库、PHP 邮件程序 cron 作业和文件系统。

现在，让我们看看目录结构。

# 文件/目录结构

浏览 WordPress 目录将给我们一个文件/文件夹结构，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c018ede2-5f94-4353-a2e3-b48d6dcd1588.png)

让我们快速浏览一下这些文件夹和文件。

# 基本文件夹

让我们把这称为根目录。该目录包含三个文件夹，即`wp-admin`、`wp-content`和`wp-includes`，以及一堆 PHP 文件，包括最重要的`wp-config.php`。

基本文件夹包含 WordPress 核心操作所需的所有其他 PHP 文件和类。

# wp-includes

wp-includes 文件夹包含所有其他 PHP 文件和类，这些文件和类由前端使用，并且由 WordPress 核心所需。

# wp-admin

该文件夹包含 WordPress 仪表板的文件，用于执行所有管理任务，如撰写帖子、审核评论以及安装插件和主题。只有注册用户才能访问仪表板。

# wp-content

`wp-content`文件夹包含所有用户上传的数据，并再次分为三个子文件夹：

+   `themes`

+   `plugins`

+   `uploads`

`themes`目录包含安装在我们的 WordPress 网站上的所有主题。默认情况下，WordPress 带有两个主题：Twenty Twelve 和 Twenty Thirteen。

同样，`plugins`文件夹用于存储安装在我们的 WordPress 网站上的所有插件。自从我们启动网站以来上传的所有图像（和其他媒体文件）将存储在`uploads`目录中。这些按日，月和年分类。

现在您对 WordPress 的架构和文件/目录结构有了基本的了解，让我们开始渗透测试。

# WordPress 侦察和枚举

在开始利用 WordPress 的任何插件/主题/核心漏洞之前，第一步是确认网站是否在 WordPress 上。至于检测 WordPress 本身，有各种方法可以检测 WordPress CMS 的安装：

+   在 HTML 页面源代码中搜索`wp-content`字符串。

+   查找`/wp-trackback.php`或`/wp-links-opml.php`文件名 - 在 WordPress 安装的情况下它们返回 XML。

+   您还可以尝试`/wp-admin/admin-ajax.php`和`/wp-login.php`。

+   查找静态文件，如`readme.html`和`/wp-includes/js/colorpicker.js`。

一旦确认网站正在运行 WordPress，下一步就是了解目标服务器上运行的 WordPress 版本。为了实现这一点，您需要知道可以检测其版本号的不同方法。为什么要版本号？因为根据安装在目标服务器上的 WordPress 版本，您可以测试可能公开或可能不公开的基于插件或 WordPress 核心的漏洞。

# 版本检测

每个 WordPress 安装都带有一个版本号。在最新的 WordPress 版本中，默认情况下隐藏了版本号，但我们仍然可以枚举版本。在本节中，您将学习一些识别正在运行的 WordPress 版本的方法。

一些最常见的侦察技术是`Readme.html`，meta generator，feed（RDF，Atom 和 RSS），插件和主题（JS 和 CSS ver）以及哈希匹配。

# Readme.html

这是最简单的技术。我们所要做的就是访问`readme.html`页面，它会在中心披露版本号。该文件的原始目的是向 CMS 的首次用户提供有关如何继续安装和使用 WordPress 的信息。一旦安装和设置完成，它应该被删除。在使用任何工具（包括 Metasploit）之前，始终检查 WordPress 安装的版本号，然后再执行任何形式的利用。

因此，请确保您知道您要进行渗透测试的版本。您可以在以下截图中看到`readme.html`的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/47c8a71e-5612-43b5-94ea-6eec443de1b7.png)

接下来，我们将看 meta generator。

# Meta generator

`generator`名称属性的元标记通常被描述为用于生成文档/网页的软件。确切的版本号在元标记的`content`属性中披露。基于 WordPress 的网站通常在其源代码中具有此标记，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b6fe34bc-d909-4a69-9e73-e81b5c9a5f73.png)

接下来，我们将看到如何通过 JavaScript 和 CSS 文件获取版本。

# 通过 JavaScript 和 CSS 文件获取版本

找到版本号的另一种方法是查看以下文件的源代码。以下文件请求 JS 和 CSS 文件：

+   `wp-admin/install.php`

+   `wp-admin/upgrade.php`

+   `wp-login.php`

这些在其`ver`参数中披露了确切的版本号，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/aafbf7e7-e25a-4244-9ac6-0b2c6359a66b.png)

接下来，我们将看到如何通过 feed 获取版本。

# 通过 feed 获取版本

有时，版本信息也可能在网站的 feed 中披露。以下文件路径可用于披露版本信息：

+   `/index.php/feed/`

+   `/index.php/feed/rss/`

+   `/index.php/feed/rss2/`

+   `/index.php/comments/feed/`

+   `/index.php/feed/rdf/`（文件是本地下载的）

+   `/index.php/feed/atom/`

+   `/?feed=atom`

+   `/?feed=rss`

+   `/?feed=rss2`

+   `/?feed=rdf`

以下截图显示了通过 feeds 披露的版本信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/043846de-e277-4b4c-a10c-bb59af500c6f.png)

接下来，我们将看一下 OPML。

# 使用大纲处理标记语言（OPML）

OPML 是大纲处理标记语言（*定义为*每个节点包含一组具有字符串值的命名属性的树*）。以下文件允许 WordPress 从其他网站导入链接，只要它们以 OPML 格式存在，但访问此文件也会披露版本信息（在 HTML 注释标签之间），如下截图所示：

```
/wp-links-opml.php
```

这可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/acd12498-2ab0-49ba-882b-3874a991c629.png)

接下来，我们将看一下高级指纹识别。

# 唯一/高级指纹识别

这是另一种指纹识别 WordPress 确切版本的方法。顾名思义，这种技术非常独特。它是通过计算静态文件的哈希值，并将其与不同版本的 WordPress 发布中相同静态文件的哈希值进行比较来完成的。您可以通过执行以下命令来执行此操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c54f698d-13f1-42d6-9ba0-ba96b97f16c5.png)

要比较哈希值，请参阅以下 GitHub 存储库：[`github.com/philipjohn/exploit-scanner-hashes`](https://github.com/philipjohn/exploit-scanner-hashes)。

# 使用 Metasploit 进行 WordPress 侦察

Metasploit 有一个用于获取版本号的 WordPress 扫描器模块，`wordpress_scanner`。

让我们为此模块设置选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f98f065a-fd34-48b1-8a72-8398c6beb6b4.png)

一切准备就绪后，让我们运行它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d9f00ebc-e06b-4eb0-8a18-9d6e4347162e.png)

这是一个非常简单的扫描程序，尝试使用先前提到的技术找到版本号。

既然我们有了版本号，您可以参考以下案例研究，了解如何枚举和利用 WordPress 的漏洞。给出的漏洞都有详细解释。

# 使用 Metasploit 进行 WordPress 枚举

以下是攻击面，您可以在枚举时专注的地方：

+   用户名

+   主题

+   插件

使用 Metasploit 模块`auxiliary/scanner/http/wordpress_login_enum`，按照以下步骤操作：

1.  您可以尝试暴力破解用户名，也可以枚举用户名：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/a410ad68-667c-48f9-9d5d-d6ab51b0b52e.png)

1.  让我们设置选项，只枚举用户名并运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ad5d19e6-ebeb-478d-a1fd-7d49a6e50ce0.png)

1.  您现在可以尝试使用字典进行暴力破解。模块的默认选项使其能够执行暴力破解攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/880e5de1-ccee-4f47-84ad-d23ab23c885c.png)

1.  现在让我们设置选项。我们已经设置了从前面的枚举方法中找到的用户名：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3c9a8662-7c8e-48b5-b2a8-da48490f11cb.png)

1.  对于密码字典，使用`set PASS_FILE <file>`命令并运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/535be82d-a179-4cda-a41d-324305d50f11.png)

在下一节中，我们将看一下漏洞评估扫描。

# WordPress 漏洞评估

Metasploit 没有可以执行漏洞评估扫描的模块。但是，您可以编写一个充当第三方工具（如 WPscan）包装器的 Metasploit 模块，用于漏洞评估扫描。

我们编写了一个自定义的 Metasploit 模块，执行时将运行 WPscan，解析输出并打印出来。虽然该模块只是一个粗糙的包装代码，但您可以根据需要进一步修改它。以下是自定义 Metasploit 模块的示例代码：

1.  我们将首先添加所需的库，如下所示：

```
require 'open3'
require 'fileutils'
require 'json'
require 'pp'
```

1.  然后，我们添加 Metasploit 的`Auxiliary`类：

```
class MetasploitModule < Msf::Auxiliary
 include Msf::Auxiliary::Report
```

1.  我们定义模块的信息部分：

```
def initialize
 super(
 'Name' => 'Metasploit WordPress Scanner (WPscan)',
 'Description' => 'Runs wpscan via Metasploit',
 'Author' => [ 'Harpreet Singh', 'Himanshu Sharma' ]
 )
```

1.  在这里，我们将添加模块的`options`部分，通过它我们可以为测试添加目标 URL：

```
register_options(
 [
     OptString.new('TARGET_URL', [true, 'The target URL to be scanned using wpscan'])
 ]
 )
 end
```

1.  接下来，我们定义`target_url`方法，该方法将存储用户选项`TARGET_URL`：

```
def target_url
 datastore['TARGET_URL']
end
```

1.  我们还定义了`find_wpscan_path`方法，该方法将在系统中查找`wpscan`文件：

```
def find_wpscan_path
 Rex::FileUtils.find_full_path("wpscan")
end
```

1.  接下来，我们添加辅助模块执行方法`run`，并检查系统中是否安装了`wpscan`：

```
def run
 wpscan = find_wpscan_path
 if wpscan.nil?
 print_error("Please install wpscan gem via: gem install wpscan")
 end
```

如果找到`wpscan`，模块将首先创建一个带有随机字符的临时文件：

```
tmp_file_name = Rex::Text.rand_text_alpha(10)
```

1.  以下是`wpscan`执行块。这里将使用用户选项创建一个`wpscan`进程：

```
cmd = [ wpscan, "--url", target_url, "-o", "#{tmp_file_name}", "-f", "json", "--force" ]
 ::IO.popen(cmd, "rb") do |fd|
     print_status("Running WPscan on #{target_url}")
     print_line("\t\t\t\t(This may take some time)\n")
     fd.each_line do |line|
         print_status("Output: #{line.strip}")
     end
 end
```

执行完成后，模块将读取包含`wpscan`输出的临时文件：

```
json = File.read("/tmp/#{tmp_file_name}")
```

1.  现在，我们添加将解析 JSON 输出的代码块：

```
obj = JSON.parse(json)
 i = 0
 print_line("\n")
 print_status("-------------------------------------")
 print_status("Looking for some Interesting Findings")
 print_status("-------------------------------------")
 obj = obj.compact
```

在这里，我们正在查找 JSON 输出中的`interesting_findings`数组。我们将使用此数组打印在 WordPress 目标站点中发现的漏洞的详细信息：

```

 while (i <= obj['interesting_findings'].length) do
     if obj['interesting_findings'][i]['type'] == 'headers' && !(obj['interesting_findings'][i].nil?)
         obj['interesting_findings'][i]['interesting_entries'].each { |x|                     print_good("Found Some Interesting Enteries via Header detection: #{x}")}
         i += 1
     elsif obj['interesting_findings'][i]['type'] == 'robots_txt' && (!obj['interesting_findings'][i].nil?)
         obj['interesting_findings'][i]['interesting_entries'].each { |x| print_good("Found Some Interesting Enteries via robots.txt: #{x}")}
         i += 1
     else
         break
     end
 end
```

1.  我们添加了检查 JSON 输出中的`version`数组并解析 WordPress 版本的代码块：

```
 print_line("\n")
 print_status("--------------------------------------")
 print_status("Looking for the WordPress version now")
 print_status("--------------------------------------")
 if !(obj['version'].nil?)
     print_good("Found WordPress version: " + obj['version']['number'] + " via " + obj['version']['found_by'])
 else
     print_error("Version not found")
 end
```

我们解析了`wpscan`发现的漏洞总数，并打印出来（包括引用和 CVE 链接）：

```
 print_status "#{obj['version']['vulnerabilities'].count} vulnerabilities identified:"
 obj['version']['vulnerabilities'].each do |x|
 print_error("\tTitle: #{x['title']}")
 print_line("\tFixed in: #{x['fixed_in']}")
 print_line("\tReferences:")
 x['references'].each do |ref|
 if ref[0].include?'cve'
     print_line("\t\t- https://cve.mitre.org/cgi-bin/cvename.cgi?name=#{ref[1][0]}")
 elsif ref[0].include?'url'
     ref[1].each do |e|
     print_line("\t\t- #{e}")
 end
 elsif ref[0].include?'wpvulndb'
     print_line("\t\t- https://wpvulndb.com/vulnerabilities/#{ref[1][0]}")
 end
 end
 print_line("\n")
 end
```

1.  我们添加了用于检查已安装主题的代码块，使用`wpscan`：

```
 print_line("\n")
 print_status("------------------------------------------")
 print_status("Checking for installed themes in WordPress")
 print_status("------------------------------------------")
 if !(obj['main_theme'].nil?)
     print_good("Theme found: " + "\"" + obj['main_theme']['slug'] + "\"" + " via " + obj['main_theme']['found_by'] + " with version: " + obj['main_theme']['version']['number'])
 else
     print_error("Theme not found")
 end
```

我们还添加了使用`wpscan`枚举已安装插件的代码块：

```
 print_line("\n")
 print_status("---------------------------------")
 print_status("Enumerating installed plugins now")
 print_status("---------------------------------")
 if !(obj['plugins'].nil?)
     obj['plugins'].each do |x|
     if !x[1]['version'].nil?
         print_good "Plugin Found: #{x[0]}"
         print_status "\tPlugin Installed Version: #{x[1]['version']['number']}"
         if x[1]['version']['number'] < x[1]['latest_version']
             print_warning "\tThe version is out of date, the latest version is #{x[1]['latest_version']}"
         elsif x[1]['version']['number'] == x[1]['latest_version']
             print_status "\tLatest Version: #{x[1]['version']['number']} (up to date)"
         else
             print_status "\tPlugin Location: #{x[1]['location']}"
         end 
    else
     print_good "Plugin Found: #{x[0]}, Version: No version found"
 end
```

1.  然后，我们添加了查找已安装插件中发现的漏洞并根据 CVE 和引用 URL（包括`exploit-db` URL）进行映射的代码块：

```
 if x[1]['vulnerabilities'].count > 0
     print_status "#{x[1]['vulnerabilities'].count} vulnerabilities identified:"
 x[1]['vulnerabilities'].each do |b|
     print_error("\tTitle: #{b['title']}")
     print_line("\tFixed in: #{b['fixed_in']}")
     print_line("\tReferences:")
     b['references'].each do |ref2|
     if ref2[0].include?'cve'
         print_line("\t\t- https://cve.mitre.org/cgi-bin/cvename.cgi?name=#{ref2[1][0]}")
     elsif ref2[0].include?'url'
         ref2[1].each do |f|
         print_line("\t\t- #{f}")
     end
 elsif ref2[0].include?'exploitdb'
     print_line("\t\t- https://www.exploit-db.com/exploits/#{ref2[1][0]}/")
 elsif ref2[0].include?'wpvulndb'
     print_line("\t\t- https://wpvulndb.com/vulnerabilities/#{ref2[1][0]}")
 end
 end
 print_line("\n")
 end

 end
 end
 else
     print_error "No plugin found\n"
 end
```

1.  一切都完成后，删除此模块创建的临时文件：

```
File.delete("/tmp/#{tmp_file_name}") if File.exist?("/tmp/#{tmp_file_name}")
 end
end
```

以下是 WPscan 辅助模块的完整代码：

```
require 'open3'
require 'fileutils'
require 'json'
require 'pp'
class MetasploitModule < Msf::Auxiliary
 include Msf::Auxiliary::Report

 def initialize
 super(
 'Name' => 'Metasploit WordPress Scanner (WPscan)',
 'Description' => 'Runs wpscan via Metasploit',
 'Author' => [ 'Harpreet Singh', 'Himanshu Sharma' ]
 )

 register_options(
 [
     OptString.new('TARGET_URL', [true, 'The target URL to be scanned using wpscan'])
 ]
 )
 end

 def target_url
     datastore['TARGET_URL']
 end

 def find_wpscan_path
     Rex::FileUtils.find_full_path("wpscan")
 end

 def run
     wpscan = find_wpscan_path
     if wpscan.nil?
         print_error("Please install wpscan gem via: gem install wpscan")
     end
     tmp_file_name = Rex::Text.rand_text_alpha(10)
     cmd = [ wpscan, "--url", target_url, "-o", "#{tmp_file_name}", "-f", "json", "--force" ]
     ::IO.popen(cmd, "rb") do |fd|
         print_status("Running WPscan on #{target_url}")
         print_line("\t\t\t\t(This may take some time)\n")
         fd.each_line do |line|
             print_status("Output: #{line.strip}")
         end
 end

 json = File.read("/tmp/#{tmp_file_name}")
 obj = JSON.parse(json)
 i = 0
 print_line("\n")
 print_status("-------------------------------------")
 print_status("Looking for some Interesting Findings")
 print_status("-------------------------------------")
 obj = obj.compact
 while (i <= obj['interesting_findings'].length) do
     if obj['interesting_findings'][i]['type'] == 'headers' && !(obj['interesting_findings'][i].nil?)
         obj['interesting_findings'][i]['interesting_entries'].each { |x| print_good("Found Some Interesting Enteries via Header detection: #{x}")}
         i += 1
     elsif obj['interesting_findings'][i]['type'] == 'robots_txt' && (!obj['interesting_findings'][i].nil?)
         obj['interesting_findings'][i]['interesting_entries'].each { |x| print_good("Found Some Interesting Enteries via robots.txt: #{x}")}
         i += 1
     else
         break
     end
 end

 print_line("\n")
 print_status("--------------------------------------")
 print_status("Looking for the WordPress version now")
 print_status("--------------------------------------")
 if !(obj['version'].nil?)
     print_good("Found WordPress version: " + obj['version']['number'] + " via " + obj['version']['found_by'])
 else
     print_error("Version not found")
 end
 print_status "#{obj['version']['vulnerabilities'].count} vulnerabilities identified:"
 obj['version']['vulnerabilities'].each do |x|
 print_error("\tTitle: #{x['title']}")
 print_line("\tFixed in: #{x['fixed_in']}")
 print_line("\tReferences:")
 x['references'].each do |ref|
 if ref[0].include?'cve'
     print_line("\t\t- https://cve.mitre.org/cgi-bin/cvename.cgi?name=#{ref[1][0]}")
 elsif ref[0].include?'url'
     ref[1].each do |e|
     print_line("\t\t- #{e}")
 end
 elsif ref[0].include?'wpvulndb'
     print_line("\t\t- https://wpvulndb.com/vulnerabilities/#{ref[1][0]}")
 end
 end
 print_line("\n")
 end
 print_line("\n")

 print_status("------------------------------------------")
 print_status("Checking for installed themes in WordPress")
 print_status("------------------------------------------")
 if !(obj['main_theme'].nil?)
     print_good("Theme found: " + "\"" + obj['main_theme']['slug'] + "\"" + " via " + obj['main_theme']['found_by'] + " with version: " + obj['main_theme']['version']['number'])
 else
     print_error("Theme not found")
 end
 print_line("\n")
 print_status("---------------------------------")
 print_status("Enumerating installed plugins now")
 print_status("---------------------------------")
 if !(obj['plugins'].nil?)
     obj['plugins'].each do |x|
 if !x[1]['version'].nil?
     print_good "Plugin Found: #{x[0]}"
     print_status "\tPlugin Installed Version: #{x[1]['version']['number']}"
     if x[1]['version']['number'] < x[1]['latest_version']
         print_warning "\tThe version is out of date, the latest version is #{x[1]['latest_version']}"
     elsif x[1]['version']['number'] == x[1]['latest_version']
         print_status "\tLatest Version: #{x[1]['version']['number']} (up to date)"
     else
         print_status "\tPlugin Location: #{x[1]['location']}"
     end 
 else
     print_good "Plugin Found: #{x[0]}, Version: No version found"
 end
 if x[1]['vulnerabilities'].count > 0
     print_status "#{x[1]['vulnerabilities'].count} vulnerabilities identified:"
 x[1]['vulnerabilities'].each do |b|
     print_error("\tTitle: #{b['title']}")
     print_line("\tFixed in: #{b['fixed_in']}")
     print_line("\tReferences:")
     b['references'].each do |ref2|
     if ref2[0].include?'cve'
         print_line("\t\t- https://cve.mitre.org/cgi-bin/cvename.cgi?name=#{ref2[1][0]}")
     elsif ref2[0].include?'url'
         ref2[1].each do |f|
             print_line("\t\t- #{f}")
         end
     elsif ref2[0].include?'exploitdb'
         print_line("\t\t- https://www.exploit-db.com/exploits/#{ref2[1][0]}/")
     elsif ref2[0].include?'wpvulndb'
         print_line("\t\t- https://wpvulndb.com/vulnerabilities/#{ref2[1][0]}")
     end
 end

 print_line("\n")
 end
 end
 end
 else
     print_error "No plugin found\n"
 end
 File.delete("/tmp/#{tmp_file_name}") if File.exist?("/tmp/#{tmp_file_name}")
 end
end
```

以下是运行我们刚创建的自定义模块的步骤：

1.  将模块复制到`<path_to_metasploit>/modules/auxiliary/scanner/wpscan.rb`并启动 Metasploit：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/644d4153-ce63-42a6-a54b-f815a2cee11c.png)

1.  设置选项并运行模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9d4414cc-b40d-40a1-bd8e-dd7699618f12.png)

该模块还解析插件信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/277f5e1e-edef-46f5-8528-6ab302a8446f.png)

该模块不会将信息保存在数据库中，因此如果您愿意，可以自定义它来执行。该模块的唯一目的是枚举插件、主题和 WordPress 版本，并查找漏洞。在下一节中，我们将介绍利用。

# WordPress 利用部分 1-WordPress 任意文件删除

现在您已经了解了如何识别 WordPress 版本，让我们详细了解一些利用 WordPress 的方法。我们还将讨论利用过程的工作原理。

我们首先来看一下*WordPress 任意文件删除*漏洞。此漏洞允许任何经过身份验证的用户从服务器上删除文件。攻击者可以利用这一点来执行命令。让我们看看这个利用是如何工作的以及如何实现命令执行。

以下屏幕截图显示了在我们的本地主机上运行的 WordPress 博客：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0ab04930-fc56-4664-af10-4b4a39aaa041.png)

漏洞实际上是一个二次文件删除，我们上传和编辑图像，然后将我们文件的路径放入元数据中。当图像被删除时，WordPress 调用 unlink 函数自动删除包含我们文件路径的元数据，因此文件也被删除。让我们看一下基本的漏洞流程。

# 漏洞流程和分析

我们将深入挖掘此漏洞的根本原因。看一下`wp-admin/post.php`文件的以下屏幕截图。在这里，未经过滤的输入来自用户并存储在`$newmeta`中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/aee3e993-ad6e-49ed-9c92-3e693964d7ca.png)

在`wp-includes/post.php`文件中，相同的输入被传递给`wp_update_attachment_metadata()`，以作为序列化值存储在数据库中，`meta_key`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0b9b3840-f22c-458b-9d9e-dc515fe82c13.png)

当用户点击删除媒体按钮时，以下代码将要求从数据库中获取输入并将其存储在`$thumbfile`中。然后，调用 unlink 函数来删除指定的文件。缩略图链接元数据被删除，因为它包含了对`wp-config`的路径：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9d176a82-42bd-4132-9a70-39c6a17a9f36.png)

接下来，我们将使用 Metasploit 利用漏洞。

# 使用 Metasploit 利用漏洞

Metasploit 有一个内置的利用模块，可以删除服务器上的任意文件。我们将使用`wp-config`文件的示例，因为我们稍后将讨论如何使用此利用来将 shell 上传到服务器上：

1.  要使用该模块，我们在 msfconsole 中运行以下命令。

1.  使用`auxiliary/scanner/http/wp_arbitrary_file_deletion`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d2bc9cb7-fbaa-453f-860a-5b6740bd759e.png)

如前面的截图所示，我们输入了 RHOST、WordPress 用户名和密码以及配置文件的路径。在运行利用之前，让我们也看一下我们的 WordPress 数据库的`wp_postmeta`表中当前的条目，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/53d389a6-a53a-41d0-a30b-303861c28093.png)

`wp-config.php`文件现在也存在于服务器上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c71c4646-2b73-4088-8a97-5f8b7ae09e8a.png)

当执行模块时，Metasploit 会使用 WordPress 进行身份验证，并将`.gif`文件上传到服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8295e6bb-88a1-44fa-aca8-787f83e9bf1d.png)

再次查看`wp_postmeta`表的条目，我们看到现在存在一个附件，并且附件的元数据以序列化格式存储。元数据包含文件名、宽度、高度和 EXIF 标头等详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/8592b189-e21d-403a-ba7e-c39773d91c55.png)

接下来，利用将尝试编辑附件并将缩略图参数设置为我们要删除的文件的路径：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/b1d6b1bc-00d6-47ad-98c8-a7a373467017.png)

这会得到一个`302`响应，我们被重定向回帖子页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/30388210-f549-4906-b09f-e5cbed547012.png)

让我们看看在此请求之后数据库是如何更新的。再次查看`wp_postmeta`表，我们将看到已向序列化的`meta_value`列添加了两个新字符串。这些值是缩略图和配置文件的路径：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fdd2fb65-0ea0-41b4-b5d7-0643178b8b6b.png)

利用的下一步是删除已上传的附件，这将导致调用`unlink()`函数，从而删除配置文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9779c3d2-be73-4dc8-bf77-11eca91cd8f9.png)

接下来要考虑的问题是：**删除配置文件如何让我们在服务器上实现远程代码执行（RCE）**？

一旦`wp-config.php`文件被删除，WordPress 将重定向站点到`setup-config.php`，即默认的安装启动页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/622632d9-a1e2-4f15-aceb-dbad9613365a.png)

想法是在我们自己的服务器上创建一个数据库，并重新设置 WordPress 与我们自己的数据库：

以下截图显示了在我们自己的服务器上创建 MySQL 数据库的 SQL 命令。这个服务器需要被 WordPress 访问，所以我们必须确保 MySQL 正在运行并且允许远程登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/695bfe68-4adb-457d-a9fc-dcf6478e2819.png)

现在，我们点击继续并提供数据库连接详细信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f940bd9a-ec22-46c0-af9a-05884504e7d3.png)

完成后，下一步是创建 WordPress 用户进行登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c0cfd386-a692-4fdf-9780-25577512341b.png)

现在我们可以使用刚刚创建的 WordPress 用户登录。服务器上的 WordPress 实例现在已连接并配置为使用我们自己的数据库：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/eef9d31c-ac40-4ba6-915c-6a58eee3bafc.png)

由于我们对 WordPress CMS 具有管理员访问权限，因此我们可以使用 Metasploit 模块在站点上上传 shell。可以使用以下利用方法来实现：

```
use exploit/unix/webapp/wp_admin_shell_upload
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c0538732-e8c9-4f71-98d3-fae3a60d06dc.png)

让我们设置此利用要使用的选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/697f3f79-49d5-40b8-aabe-db873eac18b0.png)

现在，让我们执行该模块并等待魔法发生：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/87e0f3c8-c573-40f6-aa19-eef1ebf98f1c.png)

现在我们在服务器上有 meterpreter 访问权限。因此，已实现 RCE：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/211ab09b-0a74-4abb-9452-e7c2d101253e.png)

这是一个非常直接的利用。然后可以进一步破解哈希值以获得对管理员面板的访问权限，或者一旦获得明文密码，就可以使用 WordPress shell 上传模块在服务器上获取 meterpreter。在接下来的部分，我们将看一下 Google 地图插件中的未经身份验证的 SQL 注入。

# WordPress 利用第 2 部分-未经身份验证的 SQL 注入

让我们来看另一个 SQL 注入的案例，这是在 WordPress 谷歌地图插件中发现的。Metasploit 已经有一个内置的利用模块，可以从数据库中提取`wp_users`表：

```
auxiliary/admin/http/wp_google_maps_sqli
```

在运行模块之前，让我们看一下插件的源代码，并了解问题出在哪里。

# 漏洞流程和分析

查看`class.rest-api.php`的源代码，我们可以看到用户输入作为名为`fields`的`get`参数传递到`explode`函数中。`explode`函数用于*按指定字符串拆分字符串为多个部分*：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7896c1b7-2d14-47cf-b6e6-710917affa92.png)

然后，输入存储在`$imploded`变量中，使用`implode()`组合后直接传递到`SELECT`查询中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/2d450d07-01af-473d-af5f-69ae07fe2f80.png)

在这里，`$imploded`变量是注入点。这个漏洞也可以利用 Metasploit 模块来利用。

# 使用 Metasploit 利用漏洞

对目标运行利用程序将给我们显示存储在`wp_users`表中的数据，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5f63e3b9-aa74-4a75-8f06-91ea0173e857.png)

接下来，我们将看一下 WordPress 利用的第三部分和最后一部分。

# WordPress 利用第 3 部分-WordPress 5.0.0 远程代码执行

在本节中，我们将看一下 RCE 漏洞，这个漏洞存在于 WordPress 版本 5.0.0 及以下。这个利用链两个不同的漏洞来实现代码执行（路径遍历和本地文件包含）。Metasploit 已经有一个针对这个漏洞的模块。

# 漏洞流程和分析

第一个漏洞是 CVE-2019-8942，它覆盖了`post`元数据条目：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/79575cd5-bfee-4f91-88ba-54b9b2e272ff.png)

未经过消毒的用户输入然后传递到`wp_update_post()`，它不检查不允许的`post`元数据字段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/05675fe4-d972-464d-bfc8-899e7e590d49.png)

攻击者可以覆盖`_wp_attached_file`的 post 元数据键为他们的恶意文件。在这一点上，我们已经利用了 CVE-2019-8942。现在我们已经控制了在 post 元数据条目中可以覆盖的内容，让我们利用下一个漏洞 CVE-2019-8943，即路径遍历漏洞。利用这个漏洞，我们可以将我们上传的恶意文件的路径从先前利用的漏洞（CVE-2019-8942）更改为我们选择的路径以实现 RCE。

`wp_crop_image()`函数调用`get_attached_file()`函数时没有进行任何文件路径验证。因此，在服务器上上传的恶意图片文件将在调用`wp_crop_image()`函数时传递给`get_attached_file()`函数（在裁剪图片时）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/420d959f-dc5a-44f6-a353-c12ee2807714.png)

我们可以利用这个漏洞来改变我们上传的恶意文件的路径，并将裁剪后的图片保存在默认主题目录中，即`wp-content/themes/<default_theme>/<cropped-image>.jpg`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/c977730a-ad7d-4fbd-b74f-391c42dfdf80.png)

正如我们在上面的截图中所看到的，恶意图片被保存在默认主题文件夹中。现在我们的恶意图片已经就位，我们可以请求帖子，以便我们的 PHP 有效负载得到执行，从而实现 RCE。

# 使用 Metasploit 利用漏洞

可以使用以下命令在 Metasploit 控制台中选择模块：

```
use exploit/multi/http/wp_crop_rce
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e9b86a32-cf35-4d2c-991a-09e693695a93.png)

我们设置了如下截图中所示的必需选项。我们将需要 WordPress 博客上的低权限帐户，因为此漏洞需要身份验证以及上传和编辑媒体的权限：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/f8e38b91-b9c5-498c-b172-8108bf3dfc80.png)

利用发生在几个步骤中。Metasploit 模块的第一步是检查提供的`targeturi`是否正确：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/31153afb-0ed7-4a44-9ae1-90e84cef11a5.png)

得到 200 的 HTTP 响应代码后，确认了`targeturi`路径：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/5b78206a-09db-4e1c-a9ea-e4207e9b9fc8.png)

模块继续下一步——身份验证。在此步骤中，模块使用的用户名和密码将被使用。在与 WordPress 网站进行身份验证时，模块还请求重定向到一个不存在的页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ddfa5732-c0c0-4d37-934a-11ae67e1fccd.png)

HTTP 响应将重定向（302）到一个不存在的页面。这样做是为了从服务器获取会话 cookie。在此步骤之后的一切都是使用这些 cookie 完成的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/af2d092a-076a-4d86-b548-40da3ec12963.png)

让我们确认数据库状态：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/fd522b3e-4e20-4737-a891-f1552e0b3160.png)

现在会话已从服务器检索到，在下一步中，该模块请求`media-new.php`页面。该页面负责将媒体上传到 WordPress 网站：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/7b2c026a-c212-4aa9-80bb-45c770f1c9ac.png)

这里的目标是上传一个嵌入了我们有效载荷的图像：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/3640ee55-5e04-4fc6-b3c8-890c7eecb754.png)

然后，该模块上传了嵌入了我们的有效载荷的图像：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/bca11c05-baf5-487c-a6a2-36d58b4bd234.png)

正如我们在前面的截图中看到的，嵌入在图像中的有效载荷是`<?=`$_GET[0]`;?>`。我们使用这样一个压缩的有效载荷的原因是因为我们剩下的空间不多，用于执行有效载荷。另外，请注意，有效载荷嵌入在两个不同的地方——扫描标头后面和 EXIF 元数据中。嵌入两次的原因是为了确保有效载荷被执行。

WordPress 支持两种用于 PHP 的图像编辑扩展：**GD** **Library**和**Imagick**。GD Library 压缩图像并去除所有 EXIF 元数据。Imagick 不会去除任何 EXIF 元数据。这就是为什么该模块将有效载荷嵌入图像两次的原因。

上传时的路径和 POST 元数据存储在数据库中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/45360bc1-ee8b-40b9-a631-ce2f8835da76.png)

一旦恶意图像上传，响应中会分配一个 ID 给图像，并显示其完整路径：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/1ef665c6-bf8f-4c54-929c-c3cc18bdea92.png)

该模块检查 WordPress 网站是否容易受到 CVE-2019-8942 和 CVE-2019-8943 的攻击。它通过以下步骤来实现：

1.  通过查询所有附件来确认图像是否已上传或不。 

1.  它确保恶意图像以 400 x 300 的大小保存。（这将有助于进行虚假裁剪时。）

1.  它获取了更新的`wp_nonce`和编辑恶意图像时的更新文件名。

1.  它检查图像的 POST 元数据条目是否可以从`.jpg`被覆盖为`.jpg?/x`。如果更改了，就表明 WordPress 网站容易受到 CVE-2019-8942 的攻击。

1.  它裁剪图像（这里是一个虚假的裁剪）来检查 WordPress 网站是否容易受到 CVE-2019-8943 的攻击，即路径遍历漏洞。

1.  一旦模块确认了漏洞，它通过将 POST 元数据从`.jpg`覆盖为`.jpg?/../../../../themes/#{@current_theme}/#`{`@shell_name`}来利用 CVE-2019-8942：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/cd0c3186-7084-48ba-81fb-483fc174f2e2.png)

以下截图显示了`meta_value`列的更新值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/57c237e9-7099-4975-9039-1d5cf665dacb.png)

我们还可以在以下截图中看到，默认模板已更改为`cropped-zAdFmXvBCk.jpg`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/39360439-d3c9-4306-a03c-afa9d9bf9514.png)

然后，模块请求带有帖子 ID 的默认模板，并附加`0`参数以执行 RCE 的命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/191b9e8b-b961-4cd0-9264-bc37f3921191.png)

命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/dd4e6f35-a083-4f0d-8016-78723ce829a0.png)

接下来，模块会执行以下操作：

1.  它确认系统中是否存在 Base64 程序。

1.  它将 PHP meterpreter 转换为 Base64，并使用`echo <base64_of _PHP_meterpreter> | base64 -d > shell.php`将其上传到服务器。

1.  它请求上传的 PHP shell 以获得 meterpreter 访问。

1.  以下截图显示了 Base64 编码的 meterpreter 代码被写入 PHP 文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/6e6c0812-0bc1-470a-bc29-36b8cf4bf95d.png)

以下截图显示了从服务器成功建立的 meterpreter 连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/123bf68c-e1e1-4d7c-be49-0e7ad0a273d5.png)

在下一节中，我们将定制 Metasploit 利用。

# 走出舒适区-定制 Metasploit 利用

对于我们在上一节中使用的 Metasploit 模块`exploit/multi/http/wp_crop_rce`，我们需要设置模块的用户名和密码才能使其工作。但是如果在认证时有 reCAPTCHA 呢？模块肯定会失败，因为模块无法绕过获取会话 cookie 的方法：

1.  让我们修改模块，使其也能与`COOKIE`数据存储一起使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/ca7611b4-1b44-4b37-bf25-d9e214b9c3f8.png)

我们可以在以下截图中看到更新后的模块选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/9d1b52a6-91b5-4726-a056-ebd8c6ff167a.png)

1.  让我们为`COOKIE`数据存储定义一个函数：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/88b328c9-81f5-457f-bd52-48f1e13990c2.png)

1.  我们还需要根据响应代码验证 cookie。因此，让我们定义一个`validate_cookie()`函数；这将使用 200 的 HTTP 响应代码验证 cookie：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/e980a39e-1194-4140-8b9f-85ed97c37b86.png)

1.  现在，在`exploit()`函数中，让我们包括一个`fail-safe fail_with()`方法，以确保如果用户名或密码缺失，利用将会失败。如果 cookie 也没有设置，也会这样做：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/d97fd41b-955d-4a59-a6e6-9321257efaf2.png)

1.  如果用户名和密码缺失，模块将尝试使用`COOKIE`。让我们更新模块并为其设置`COOKIE`选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/0dd59fcf-afc4-4779-8b16-931841056b1b.png)

1.  现在，让我们运行模块，看魔术发生：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-web-pentest-mtspl/img/17ee4fc4-c9e4-4fdb-8ecb-ea27cd51970b.png)

我们已经使用`COOKIE`得到了 meterpreter！

# 摘要

在本章中，我们首先讨论了 WordPress 的架构，然后是目录结构。接下来，我们学习了如何对 WordPress 进行手动和自动化的侦察。之后，我们看了一些利用的例子，并逐步手动和使用 Metasploit 模块进行了整个利用过程的演示。

在下一章中，我们将学习如何对基于 Joomla 的**内容管理系统**（**CMS**）进行渗透测试。

# 问题

1.  所有版本的 WordPress 的侦察步骤都一样吗？

1.  我找到了一个`wp-admin`目录，但目录本身是不可访问的。在这种情况下我该怎么办？

1.  WordPress 可以免费下载吗？

# 进一步阅读

以下链接可用于了解更多有关 WordPress 的利用方法和最新发布的漏洞：

+   [`wpvulndb.com/`](https://wpvulndb.com/)

+   [`wpsites.net/wordpress-tips/3-most-common-ways-wordpress-sites-are-exploited/`](https://wpsites.net/wordpress-tips/3-most-common-ways-wordpress-sites-are-exploited/)

+   [`www.exploit-db.com/docs/english/45556-wordpress-penetration-testing-using-wpscan-and-metasploit.pdf?rss`](https://www.exploit-db.com/docs/english/45556-wordpress-penetration-testing-using-wpscan-and-metasploit.pdf?rss)
