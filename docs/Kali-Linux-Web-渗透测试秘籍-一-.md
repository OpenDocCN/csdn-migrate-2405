# Kali Linux Web 渗透测试秘籍（一）

> 译者：[飞龙](https://github.com/wizardforcel)

# 第一章：配置 Kali Linux

> 作者：Gilberto Najera-Gutierrez

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

在第一章中，我们会涉及如何准备我们的 Kali 以便能够遵循这本书中的秘籍，并使用虚拟机建立带有存在漏洞的 Web 应用的实验室。

## 1.1 升级和更新 Kali 

在我们开始 Web 应用安全测试之前，我们需要确保我们拥有所有必要的最新工具。这个秘籍涉及到使 Kali 和它的工具保持最新版本的基本步骤。

### 准备

我们从 Kali 已经作为主操作系统安装到计算机上，并带有网络连接来开始。这本书中所使用的版本为 2.0。你可以从 <https://www.kali.org/downloads/> 下载 live CD 和安装工具。

### 操作步骤

一旦你的 Kali 实例能够启动和运行，执行下列步骤：

1.  以 root 登录 Kali。默认密码是 toor，不带双引号。你也可以使用`su`来切换到该用户，或者如果喜欢使用普通用户而不是 root 的话，用`sudo`来执行单条命令。

2.  打开终端。

3.  运行`apt-get update`命令。这会下载可用于安装的包（应用和工具）的更新列表。

    ```
    apt-get update
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-1-1.jpg)
    
4.  一旦安装完成，执行下列命令来将非系统的包更新到最新的稳定版。

    ```
    apt-get upgrade
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-1-2.jpg)
    
5.  当被询问是否继续时，按下`Y`并按下回车。

6.  下面，让我们升级我们的系统。键入下列命令并按下回车：

    ```
    apt-get dist-upgrade
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-1-3.jpg)
    
7.  现在，我们更新了 Kali 并准备好了继续。

### 工作原理

这个秘籍中，我们涉及到了更新基于 Debian 的系统（比如 Kali）的基本步骤。首先以`update`参数调用`apt-get`来下载在所配置的仓库中，用于我们的特定系统的包的最新列表。下载和安装仓库中最新版本的所有包之后，`dist-update`参数下载和安装`upgrade`没有安装的系统包（例如内核和内核模块）。

> 这本书中，我们假设 Kali 已经作为主操作系统在电脑上安装。也可以将它安装在虚拟机中。这种情况下，要跳过秘籍“安装 VirtualBox”，并按照“为正常通信配置虚拟机”配置 Kali VM 的网络选项。

### 更多

有一些工具，例如 Metasploit 框架，拥有自己的更新命令。可以在这个秘籍之后执行它们。命令在下面：

```
msfupdate 
```

## 1.2 安装和运行 OWASP Mantra

OWASP（开放 Web 应用安全项目，<https://www.owasp.org/>）中的研究员已经将 Mozilla FIrefox 与 大量的插件集成，这些插件用于帮助渗透测试者和开发者测试 Web 应用的 bug 或安全缺陷。这个秘籍中，我们会在 Kali 上安装 OWASP Mantra（<http://www.getmantra.com/>），首次运行它，并查看一些特性。

大多数 Web 应用渗透测试都通过浏览器来完成。这就是我们为什么需要一个带有一组工具的浏览器来执行这样一个任务。OWASP Mantra 包含一系列插件来执行任务，例如：

+   嗅探和拦截 HTTP 请求

+   调试客户端代码

+   查看和修改 Cookie

+   收集关于站点和应用的信息

### 准备

幸运的是， OWASP Mantra 默认包含于 Kali 的仓库中。所以，要确保我们获得了浏览器的最新版本，我们需要更新包列表：

```
apt-get update
```

### 操作步骤

1.  打开终端并执行：

    ```
    apt-get install owasp-mantra-ff
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-2-1.jpg)
    
2.  在安装完成之后，访问菜单：` Applications | 03 - Web Application Analysis | Web Vulnerability Scanners | owasp-mantra-ff`来首次启动 Mantra。或者在终端中输入下列命令：

    ```
    owasp-mantra-ff
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-2-2.jpg)
    
3.  在新打开的浏览器中，点击 OWASP 图标之后点击`Tools`。这里我们可以访问到所有 OWASP Mantra 包含的工具。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-2-3.jpg)
    
4.  我们会在之后的章节中使用这些工具。

### 另见

你可能也对 Mantra on Chromium （MOC）感兴趣，这是 Mantra 的一个替代版本，基于 Chromium 浏览器。当前，它只对 Windows 可用：<http://www.getmantra.com/mantra-on-chromium.html>。

## 1.3 配置 Iceweasel 浏览器

如果我们不喜欢 OWASP Mantra，我们可以使用 Firefox 的最新版本，并安装我们自己的测试相关插件。Kali Linux 包含了 Iceweasel，另一个 Firefox 的变体。我们这里会使用它来看看如何在它上面安装我们的测试工具。

### 操作步骤

1.  打开 Iceweasel 并访问`Tools | Add-ons`。就像下面的截图这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-3-1.jpg)
    
2.  在搜素框中，输入`tamper data `并按下回车。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-3-2.jpg)
    
3.  在`Tamper Data `插件中点击`Install`。

4.  对话框会弹出，询问我们接受 EULA，点击`Accept and Install...`。

    > 你可能需要重启你的浏览器来完成特定插件的安装。

5.  下面，我们在搜索框中搜索`cookies manager+ `。

6.  在`cookies manager+ `插件中点击`Install`。

7.  现在，搜索`Firebug`。

8.  搜索和安装`Hackbar`。

9.  搜索和安装` HTTP Requester`。

0.  搜索和安装`Passive Recon`。

### 工作原理

目前为止，我们在 Web 浏览器中安装了一些工具，但是对 Web 应用渗透测试者来说，这些工具好在哪里呢？

+   `Cookies Manager+`：这个插件允许我们查看，并有时候修改浏览器从应用受到的 Cookie 的值。

+   `Firebug`：这是任何 Web 开发者的必需品。它的主要功能是网页的内嵌调试器。它也在你对页面执行一些客户端修改时非常有用。

+   `Hackbar`：这是一个非常简单的插件，帮助我们尝试不同的输入值，而不需要修改或重写完整的 URL。在手动检查跨站脚本工具和执行注入的时候，我们会很频繁地使用它。

+   `Http Requester`：使用这个工具，我们就能构造 HTTP 链接，包括 GET、POST 和 PUT 方法，并观察来自服务器的原始响应。

+   `Passive Recon`：它允许我们获得关于网站被访问的公共信息，通过查询 DNS 记录、WHOIS、以及搜索信息，例如邮件地址、链接和 Google 中的合作者。

+   `Tamper Data`：这个插件能够在请求由浏览器发送之后，捕获任何到达服务器的请求。这提供给我们了在将数据引入应用表单之后，在它到达服务器之前修改它的机会。

### 更多

有一些插件同样对 Web 应用渗透测试者有用，它们是：

+ XSS Me 
+ SQL Inject Me 
+ FoxyProxy 
+ iMacros 
+ FirePHP 
+ RESTClient 
+ Wappalyzer

## 1.4 安装 VirtualBox

这是我们的第四篇秘籍，会帮助我们建立虚拟机环境，并运行它来实施我们的渗透测试。我们会使用 VirtualBox 在这样的环境中运行主机。这个秘籍中，我们会了解如何安装 VirtualBox 以及使它正常工作。

### 准备

在我们在 Kali 中安装任何东西之前，我们都必须确保我们拥有最新版本的包列表：

```
apt-get update
```

### 操作步骤

1.  我们首先实际安装 VirtualBox：

    ```
    apt-get install virtualbox
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-4-1.jpg)
    
2.  安装完成之后，我们要在菜单中寻找 VirtualBox，通过访问`Applications | Usual applications | Accessories | VirtualBox`。作为替代，我们也可以从终端调用它：

    ```
    virtualbox
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-4-2.jpg)
    
现在，我们运行了 VirtualBox 并且已经准备好配置虚拟机来构建我们自己的测试环境。

### 工作原理

VirtualBox 允许我们在我们的 Kali 主机上通过虚拟化运行多个主机。通过它，我们可以使用不同的计算机和操作系统来挂载完整的环境。并同时运行它们，只要 Kali 主机的内存资源和处理能力允许。

### 更多

虚拟机扩展包，提供了 VirtualBox 的虚拟机附加特性，例如 USB 2.0/3.0 支持和远程桌面功能。它可以从 <https://www.virtualbox.org/wiki/Downloads> 下载。在下载完成后双击它，VirtualBox 会做剩余的事情。

### 另见

除此之外有一些可视化选项。如果你使用过程中感到不方便，你可以尝试：

+ VMware Player/Workstation
+ Qemu
+ Xen
+ KVM

## 1.5 创建漏洞虚拟机

现在我们准备好创建我们的第一个虚拟机，它是托管 Web 应用的服务器，我们使用应用来实践和提升我们的渗透测试技巧。

我们会使用叫做 OWASP BWA（ Broken Web Apps）的虚拟机，它是存在漏洞的 Web 应用的集合，特别为执行安全测试而建立。

### 操作步骤

1.  访问 <http://sourceforge.net/projects/owaspbwa/files/>，并下载最新版本的`.ova`文件。在本书写作过程中，它是`OWASP_Broken_Web_Apps_ VM_1.1.1.ova`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-5-1.jpg)
    
2.  等待下载完成，之后打开文件：

3.  VirtualBox 的导入对话框会显示。如果你打算修改机器名称或描述，你可以通过双击值来完成。我们会命名为`vulnerable_vm`，并且使剩余选项保持默认。点击`Import`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-5-2.jpg)

4.  导入需要花费一分钟，之后我们会看到我们的虚拟机显示在 VirtualBox 的列表中。让我们选中它并点击`Start`。

5.  在机器启动之后，我们会被询问登录名和密码，输入`root`作为登录名，`owaspbwa`作为密码，这样设置。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-5-3.jpg)
    
### 工作原理

OWASP BWA 是一个项目，致力于向安全从业者和爱好者提供安全环境，用于提升攻击技巧，并识别和利用 Web 应用中的漏洞，以便帮助开发者和管理员修复和防止漏洞。

这个虚拟机包含不同类型的 Web 应用，一些基于 PHP，一些基于 Java，甚至还有一些基于 .NET 的漏洞应用。也有一些已知应用的漏洞版本，例如 WordPress 或 Joomla。

### 另见

当我们谈论漏洞应用和虚拟机的时候，有很多选择。有一个著名网站含有大量的此类应用，它是 VulnHub（`https:// www.vulnhub.com/`）。它也有一些思路，帮助你解决一些挑战并提升你的技能。

这本书中，我们会为一些秘籍使用另一个虚拟机： bWapp Bee-box。它也可以从 VulnHub 下载：<https://www.vulnhub.com/entry/bwapp-beebox-v16,53/>。

## 1.6 获取客户端虚拟机

当我们执行中间人攻击（MITM）和客户端攻击时，我们需要另一台虚拟机来向已经建立的服务器发送请求。这个秘籍中，我们会下载 Microsoft Windows 虚拟机并导入到 VirtualBox 中。

### 操作步骤

1.  首先我们需要访问下载站点 <http://dev.modern.ie/tools/ vms/#downloads>。

2.  这本书中，我们会在 Win7 虚拟机中使用 IE8。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-6-1.jpg)
    
3.  文件下载之后，我们需要解压它。访问它下载的位置。

4.  右击它并点击`Extract Here`（解压到此处）。

5.  解压完成后，打开`.ova`文件并导入到 VirtualBox 中。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-6-2.jpg)
    
6.  现在启动新的虚拟机（名为`IE8 - Win7`），我们就准备好客户端了。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-6-3.jpg)

### 工作原理

Microsoft 向开发者提供了这些虚拟机来在不同的 Windows 和 IE 版本上测试它们的应用，带有 30 天的免费许可，这足以用于实验了。

作为渗透测试者，意识到真实世界的应用可能位于多个平台，这些应用的用户可能使用大量的不同系统和 Web 浏览器来和互相通信非常重要。知道了这个之后，我们应该使用任何客户端/服务器的设施组合，为成功的渗透测试做准备。

### 另见

对于服务端和客户端的虚拟机，如果你在使用已经构建好的配置时感到不便，你总是可以构建和配置你自己的虚拟机。这里是一些关于如何实现的信息：<https://www.virtualbox.org/manual/>。

## 1.7 为正常通信配置虚拟机

为了能够和我们的虚拟服务器和客户端通信，我们需要位于相同网段内。但是将带有漏洞的虚拟机放到局域网中可能存在安全风险。为了避免它，我们会在 VirtualBox 中做一个特殊的配置，允许我们在 Kali 中和服务器及客户端虚拟机通信，而不将它们暴露给网络。

### 准备

在我们开始之前，打开 VirtualBox 并且宝漏洞服务器和客户端虚拟机都关闭了。

### 操作步骤

1.  在 VirtualBox 中访问`File | Preferences… | Network`。

2.  选择`Host-only Networks`标签页。

3.  点击`+`按钮来添加新网络。

4.  新的网络（`vboxnet0`）会创建，它的详细窗口会弹出。如果没有，选项网络并点击编辑按钮来编辑它的属性。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-7-1.jpg)
    
5.  在对话框中，你可以指定网络配置。如果它不影响你的本地网络配置，将其保留默认。你也可以修改它并使用其它为局域网保留的网段中的地址，例如 10.0.0.0/8、172.16.0.0/12、192.168.0.0/16。

6.  合理配置之后，点击`OK`。

7.  下一步是配置漏洞虚拟机（vulnerable_vm）。选择它并访问它的设置。

8.  点击`Network `并且在`Attached to:`下拉菜单中，选择` Host-only Adapter`。

9.  在`Name`中，选择`vboxnet0`。

0.  点击`OK`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-7-2.jpg)
    
1.  在客户端虚拟机（`IE8 - Win7`）中执行第七步到第十步。

2.  在配置完两个虚拟机之后，让我们测试它们是否能真正通信。启动两个虚拟机。

3.  让我们看看宿主系统的网络通信：打开终端并输入：

    ```
    ifconfig
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-7-3.jpg)
   
4.  我们可以看到我们拥有叫做`vboxnet0 `的网络适配器，并且它的 IP 地址为 192.168.56.1。取决于你所使用的配置，这可能有所不同。

5.  登录 vulnerable_vm 并检查适配器`eth0`的 IP 地址。

    ```
    ifconfig 
    ```

6.  现在，让我们访问我们的客户端主机`IE8 - Win7`。打开命令行提示符并输入：

    ```
    ipconfig 
    ```
    
7.  现在，我们拥有了三台机器上的 IP 地址。

    +   192.168.56.1 ：宿主机
    +   192.168.56.102 ：vulnerable_vm 
    +   192.168.56.103 ：IE8 - Win7

8.  为了测试通信，我们打算从宿主机中 ping 两个虚拟机。

    ```
    ping -c 4 192.168.56.102 
    ping -c 4 192.168.56.103
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-7-4.jpg)
    
    ping 会发送 ICMP 请求给目标，并等待回复。这在测试网络上两个节点之间是否可以通信的时候非常有用。
    
9.  我们对两个虚拟机做相同操作，来检车到服务器和到另一台虚拟机的通信是否正常。

0.  IE8 - Win7 虚拟机可能不响应 ping，这是正常的，因为 Win7 的配置默认不响应 ping。为了检查连接性，我们可以从 Kali 主机使用`arping`。

    ```
    arping –c 4 192.168.56.103
    ```
    
### 工作原理

仅有主机的网络是虚拟网络，它的行为像 LAN，但是它仅仅能够访问宿主机，所运行的虚拟机不会暴露给外部系统。这种网络也为宿主机提供了虚拟适配器来和虚拟机通信，就像它们在相同网段那样。

使用我们刚刚完成的配置，我们就能够在客户端和服务器之间通信，二者都可以跟 Kali 主机通信，Kali 会作为攻击主机。

## 1.8 了解漏洞 VM 上的 Web 应用

OWASP BWA 包含许多 Web 应用，其内部含有常见攻击的漏洞。它们中的一些专注于一些特定技巧的实验，而其它尝试复制碰巧含有漏洞的，真实世界的应用。

这个秘籍中，我们会探索 vulnerable_vm，并了解一些其中包含的应用。

### 准备

我们需要启动我们的 vulnerable_vm，并正确配置它的网络。这本书中，我们会使用 192.168.56.102 作为它的 IP 地址。

### 操作步骤

1.  vulnerable_vm 启动后，打开 Kali 主机的 Web 浏览器并访问`http://192.168.56.102`。你会看到服务器所包含的所有应用列表。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-8-1.jpg)
    
2.  让我们访问`Damn Vulnerable Web Application`。

3.  使用`admin`作为用户名，`admin`作为密码。我们可以看到左边的菜单：菜单包含我们可以实验的所有漏洞的链接：爆破、命令执行、SQL 注入，以及其它。同样，DVWA 安全这部分是我们用于配置漏洞输入的安全（或复杂性）等级的地方。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-8-2.jpg)
    
4.  登出并返回服务器的主页。

5.  现在我们点击`OWASP WebGoat.NET`。这是个 .NET 应用，其中我们可以实验文件和代码注入攻击，跨站脚本，和加密漏洞。它也含有 WebGoat Coins Customer Portal，它模拟了商店应用，并可以用于实验漏洞利用和漏洞识别。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-8-3.jpg)
    
6.  现在返回服务器的主页。

7.  另一个包含在虚拟机中的有趣应用是 BodgeIt。它是基于 JSP 的在线商店的最小化版本。它拥有我们可以加入购物车的商品列表，带有高级选项的搜索页面，为新用户准备的注册表单，以及登录表单。这里没有到漏洞的直接引用，反之，我们需要自己找它们。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/1-8-4.jpg)
    
8.  我们在一个秘籍中不能浏览所有应用，但是我们会在这本书中使用它们。

### 工作原理

主页上的应用组织为六组：

+   训练应用：这些应用分为几部分，专注于实验特定的漏洞或攻击技巧。他它们中的一些包含教程、解释或其他形式的指导。

+   真实的，内部含有漏洞的应用：这些应用的行为就像真实世界的应用（商店】博客或社交网络）一样，但是开发者出于训练目的在内部设置了漏洞。

+   真实应用的旧（漏洞）版本：真是应用的旧版本，例如 WordPress 和 Joomla 含有已知的可利用的漏洞。这对于测试我们的漏洞识别技巧非常实用。

+   用于测试工具的应用：这个组中的应用可以用做自动化漏洞扫描器的基准线测试。

+   演示页面/小应用：这些小应用拥有一个或一些漏洞，仅仅出于演示目的。

+   OWASP 演示应用：OWASP AppSensor 是个有趣的应用，它模拟了社交网络并含有一些漏洞。但是他会记录任何攻击的意图，这在尝试学习的时候很有帮助。例如，如何绕过一些安全设备，例如网络应用防火墙。


# 第二章：侦查

> 作者：Gilberto Najera-Gutierrez

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

在每个渗透测试中，无论对于网络还是 Web 应用，都有一套流程。其中需要完成一些步骤，来增加我们发现和利用每个影响我们目标的可能的漏洞的机会。例如：

+   侦查

+   枚举

+   利用

+   维持访问

+   清理踪迹

在 Web 测试场景中，侦查是一个层面，其中测试者必须识别网络、防火墙和入侵检测系统中所有可能组件。它们也会收集关于公司、网络和雇员的最大信息。在我们的例子中，对于 Web 应用渗透测试，这个阶段主要关于了解应用、数据库、用户、服务器以及应用和我们之间的关系。

侦查是每个渗透测试中的必要阶段。我们得到了的目标信息越多，发现和利用漏洞时，我们拥有的选项就越多。

## 2.1 使用 Nmap 扫描和识别服务

Nmap 可能是世界上最广泛使用的端口扫描器。他可以用于识别活动主机、扫描 TCP 和 UDP 开放端口，检测防火墙，获得运行在远程主机上的服务版本，甚至是，可以使用脚本来发现和利用漏洞。

这个秘籍中，我们会使用 Nmap 来识别运行在目标应用上的所有服务。出于教学目的，我们会多次调用 Nmap 来实现它，但是这可以通过单个命令来完成。

### 准备

我们只需要将 vulnerable_vm 运行起来。

### 操作步骤

1.  首先，我们打算看看服务器是否响应 ping，或者服务器是否打开：

    ```
    nmap -sn 192.168.56.102
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-1-1.jpg)
    
2.  现在我们直到它打开了让我们看看打开了哪些端口：

    ```
    nmap 192.168.56.102
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-1-2.jpg)
    
3.  现在，我们要让 Nmap 向服务器询问正在运行的服务的版本，并且基于它猜测操作系统。

    ```
    nmap -sV -O 192.168.56.10
    ```
    
4.  我们可以看到，我们的 vulnerable_vm 使用 Linux 2.6 内核，并带有 Apache 2.2.14 Web 服务器，PHP 5.3.2，以及其它。

### 工作原理

Nmap 是个端口扫描器，这意味着它可以向一些指定 IP 的 TCP 或 UDP 端口发送封包，并检查是否有响应。如果有的话，这意味着端口是打开的，因此，端口上运行着服务。

在第一个名中，使用`-sn`参数，我们让 Nmap 只检查是否服务器响应 ICMP 请求（或 ping）。我们的服务器响应了，所以它是活动的。

第二个命令是调用 Nmap 的最简方式，它只指定目标 IP。所做的事情是先 ping 服务器，如果它响应了，Nmap 会向 1000 个 TCP 端口列表发送探针，来观察哪个端口响应，之后报告响应端口的结果。

第三个命令向第二个添加了如下两个任务：

+   `-sV`请求每个被发现的开放端口的标识（头部或者自我识别），这是它用作版本的东西。

+   `-O`告诉 Nmap，尝试猜测运行在目标上的操作系统。使用开放端口和版本收集的信息。

### 更多

有一些其它的实用参数：

+   `-sT`：通常，在 root 用户下运行 Nmap 时，它使用 SYN 扫描类型。使用这个参数，我们就强制让扫描器执行完全连接的扫描。它更慢，并且会在服务器的日志中留下记录，但是它不太可能被入侵检测系统检测到。

+   `-Pn`：如果我们已经知道了主机是活动的或者不响应 ping，我们可以使用这个参数告诉 Nmap 跳过 ping 测试，并扫描所有指定目标，假设它们是开启的。

+   `-v`：这会开启详细模式。Nmap 会展示更多关于它所做事情和得到回复的信息。参数可以在相同命令中重复多次：次数越多，就越详细（也就是说，`-vv`或`-v -v -v -v`）。

+   `-p N1,N2,Nn`：如果我们打算测试特定端口或一些非标准端口，我们可能想这个参数。`N1`到`Nn`是打算让 Nmap 扫描的端口。例如，要扫描端口 21，80 到 90，和 137，参数应为：` -p 21,80-90,137`。

+   ` --script=script_name`：Nmap 包含很多实用的漏洞检测、扫描和识别、登录测试、命令执行、用户枚举以及其它脚本。使用这个参数来告诉 Nmap 在目标的开放端口上运行脚本。你可能打算查看一些 Nmap 脚本，它们在：`https://nmap.org/nsedoc/scripts/`。

### 另见

虽然它最为流行，但是 Nmap 不是唯一可用的端口扫描器，并且，取决于不同的喜好，可能也不是最好的。下面是 Kali 中包含的一些其它的替代品：

+ unicornscan 
+ hping3 
+ masscan 
+ amap 
+ Metasploit scanning module

## 2.2 识别 Web 应用防火墙

Web 应用防火墙（WAF）是一个设备或软件，它可以检查发送到 Web 服务器的封包，以便识别和阻止可能的恶意封包，它们通常基于签名或正则表达式。

如果未检测到的 WAF 阻止了我们的请求或者封禁了我们的 IP，我们渗透测试中就要处理很多的麻烦。在执行渗透测试的时候，侦查层面必须包含检测和是被 WAF，入侵检测系统（IDS），或者入侵阻止系统（IPS）。这是必须的，为了采取必要的手段来防止被阻拦或禁止。

这个秘籍中，我们会使用不同的方法，并配合 Kali Linux 中的工具，阿里为检测和识别目标和我们之间的 Web 应用防火墙的存在。

### 操作步骤

1.  Nmap 包含了一些脚本，用于测试 WAF 的存在。让我们在 vulnerable-vm 上尝试它们：

    ```
    nmap -p 80,443 --script=http-waf-detect 192.168.56.102
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-2-1.jpg)
    
    好的，没检测到任何 WAF。所以这个服务器上没有 WAF。
    
2.  现在，让我们在真正拥有防火墙的服务器上尝试相同命令。这里，我们会使用` example.com`，但是你可以在任何受保护的服务器上尝试它。

    ```
    nmap -p 80,443 --script=http-waf-detect www.example.com
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-2-2.jpg)
    
    Imperva 是 Web 应用防火墙市场的主流品牌之一。就像我们这里看到的，有一个保护网站的设备。
    
3.  这里是另一个 Nmap 脚本，可以帮助我们识别所使用的设备，并更加精确。脚本在下面：

    ```
    nmap -p 80,443 --script=http-waf-fingerprint www.example.com
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-2-3.jpg)
    
4.  另一个 Kali Linux 自带的工具可以帮助我们检测和是被 WAF，它叫做`waf00f`。假设` www.example.com`是受 WAF 保护的站点：

    ```
    wafw00f www.example.com
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-2-4.jpg)
    
### 工作原理

WAF 检测的原理是通过发送特定请求到服务器，之后分析响应。例如，在` http-waf-detect`的例子中，它发送了一些基本的恶意封包，并对比响应，同时查找封包被阻拦、拒绝或检测到的标识。` http-waf-fingerprint`也一样，但是这个脚本也尝试拦截响应，并根据已知的不同 IDS 和 WAF 的模式对其分类。`wafw00f`也是这样。

## 2.3 查看源代码

查看网页的源代码允许我们理解一些程序的逻辑，检测明显的漏洞，以及在测试时有所参考，因为我们能够在测试之前和之后比较代码，并且使用比较结果来修改我们的下一次尝试。

这个秘籍中，我们会查看应用的源代码，并从中得出一些结论。

### 准备

为这个秘籍启动 vulnerable_vm。

### 操作步骤

1.  浏览 <http://192.168.56.102>。

2.  选择 WackoPicko 应用。

3.  右击页面并选择`View Page Source`（查看源代码）。会打开带有页面源代码的新窗口：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-3-1.jpg)
    
    根据源代码，我们可以发现页面所使用的库或外部文件，以及链接的去向。同时，在截图中可以看到，这个页面拥有一些隐藏的输入字段。选中的是` MAX_FILE_SIZE`，这意味着，当我们上传文件时，这个字段判断了文件允许上传的最大大小。所以，如果我们修改了这个值，我们可能就能够上传大于应用所预期的文件。这反映了一个重要的安全问题。
    
### 工作原理

网页的源代码在发现漏洞和分析应用对所提供输入的响应上非常有用。它也提供给我们关于应用内部如何工作，以及它是否使用了任何第三方库或框架的信息。

一些应用也包含使用 JS 或任何其它脚本语言编写的输入校验、编码和加密函数。由于这些代码在浏览器中执行，我们能够通过查看页面源代码来分析它，一旦我们看到了校验函数，我们就可以研究它并找到任何能够让我们绕过它或修改结果的安全缺陷。

## 4.4 使用 Firefox 分析和修改基本行为

Firebug 是个浏览器插件，允许我们分析网页的内部组件，例如表格元素、层叠样式表（CSS）类、框架以及其它。它也有展示 DOM 对象、错误代码和浏览器服务器之间的请求响应通信的功能。

在上一个秘籍中，我们看到了如何查看网页的 HTML 源代码以及发现影藏的输入字段。隐藏的字段为文件最大大小设置了一些默认值。在这个秘籍中，我们会看到如何使用浏览器的调试扩展，这里是 Firefox 或者 OWASP-Mantra 上的 Firebug。

### 准备

启动 vulnerable_vm，访问 <http://192.168.56.102/WackoPicko>。

### 操作步骤

1.  右击`Check this file`（检查此文件），之后选择` Inspect Element with Firebug`（使用 Firebug 查看元素）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-4-1.jpg)

2.  表单的第一个输入框存在`type="hidden" `参数，双击`hidden`。

3.  将`hidden`改成`text`之后按下回车键。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-4-2.jpg)
    
4.  现在双击参数值的 30000。

5.  将他改成 500000。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-4-3.jpg)
    
6.  现在，我们看到了页面上的新文本框，值为 500000。我们刚刚修改了文件大小上限，并添加了个表单字段来修改它。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-4-4.jpg)
    
### 工作原理

一旦页面被浏览器收到，所有元素都可以修改，来改变浏览器解释它的方式。如果页面被重新加载，服务器所生成的版本会再次展示。

Firebug 允许我们修改几乎每个页面在浏览器中显示的层面。所以，如果存在建立在客户端的控制逻辑，我们可以使用工具来操作它。

### 更多

Firebug 不仅仅是个取消输入框的隐藏或修改值的工具，它也拥有一些其它的实用功能：

+   `Console`标签页展示错误，警告以及一些在加载页面时生成的其它消息。

+   `HTML`标签页是我们刚刚使用的页面，它以层次方式展示 HTML，所以允许我们修改它的内容。

+   `CSS`标签页用于查看和修改页面使用的 CSS 风格。

+   `Script`让我们能够看到完整的 HTML 源代码，设置会打断页面加载的断点，执行到它们时会打断加载，以及检查脚本运行时的变量值。

+   `DOM`标签页向我们展示了 DOM（文档对象模型）对象，它们的值，以及层次结构。

+   `Net`展示了发送给服务器的请求和它的响应，它们的类型、尺寸、响应时间，和时间轴上的顺序。

+   `Cookies`包含由服务器设置的 Cookie，以及它们的值和参数，就像它的名字那样。

## 4.5 获取和修改 Cookie

Cookie 是由服务器发送给浏览器（客户端）的小型信息片段，用于在本地储存一些信息，它们和特定用户相关。在现代 Web 应用中，Cookie 用于储存用户特定的数据、例如主题颜色配置、对象排列偏好、上一个活动、以及（对我们更重要）会话标识符。

这个秘籍中，我们会使用浏览器的工具来查看 Cookie 的值，它们如何储存以及如何修改它们。

### 准备

需要运行我们的 vulnerable_vm。`192.168.56.102`用于该机器的 IP 地址，我们会使用  OWASP-Mantra 作为 Web 浏览器。

### 操作步骤

1.  浏览 <http://192.168.56.102/WackoPicko>。

2.  从 Mantra 的菜单栏访问`Tools | Application Auditing | Cookies Manager +`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-5-1.jpg)
    
    在这个截图中，我们可以从这个插件中看到所有该时刻储存的 Cookie，以及所有它们所属的站点。我们也可以修改它们的值，删除它们以及添加新的条目。
    
3.  从` 192.168.56.102 `选择`PHPSESSID`，之后点击`Edit`。

4.  将`Http Only `的值修改为`Yes`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-5-2.jpg)
    
    我们刚刚修改的参数（`Http Only`）告诉浏览器，Cookie 不能允许客户端脚本访问。
    
### 工作原理

Cookies Manager+ 是个浏览器插件，允许我们查看、修改或删除现有的 Cookie，以及添加新的条目。因为一些应用依赖于储存在这些 COokie 中的值，攻击者可以使用它们来输入恶意的模式，可能会修改页面行为，或者提供伪造信息用于获取高阶权限。

同时，在现代 Web 应用中，会话 Cookie 通常被使用，通常是登录完成之后的用户标识符的唯一兰苑。这会导致潜在的有效用户冒充，通过将 Cookie 值替换为某个活动会话的用户。

## 2.6 利用 robots.txt

要想进一步侦查，我们需要弄清楚是否站点有任何页面或目录没有链接给普通用户看。例如，内容管理系统或者内部网络的登录页面。寻找类似于它的站点会极大扩大我们的测试面，并给我们一些关于应用及其结构的重要线索。

这个秘籍中，我们会使用`robots.txt`文件来发现一些文件和目录，它们可能不会链接到主应用的任何地方。

### 操作步骤

1.  浏览 <http://192.168.56.102/vicnum/>。

2.  现在我们向 URL 添加`robots.txt`，之后我们会看到如下截图：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-6-1.jpg)
    
    这个文件告诉搜索引擎，`jotto`和`cgi-bin`的首页不允许被任何搜索引擎（User Agent）收录。
    
3.  让我们浏览 <http://192.168.56.102/vicnum/cgi-bin/>。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-6-2.jpg)
    
    我们可以直接点击和访问目录中的任何 Perl 脚本。
    
4.  让我们浏览 <http://192.168.56.102/vicnum/jotto/>。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-6-3.jpg)
    
5.  点击名称为`jotto`的文件，你会看到一些类似于下面的截图的东西：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-6-4.jpg)
    
    Jooto 是个猜测五个字符的单词的游戏，这会不会是可能答案的列表呢？通过玩这个游戏来检验它，如果是的话，我们就已经黑掉了这个游戏。
    
### 工作原理

`robots.txt`是 Web 服务器所使用的文件，用于告诉搜索引擎有关应该被索引，或者不允许查看的文件或目录的信息。在攻击者的视角上，这告诉了我们服务器上是否有目录能够访问但对公众隐藏。这叫做“以隐蔽求安全”（也就是说假设用户不会发现一些东西的存在，如果它们不被告知的话）。

## 2.7 使用 DirBuster 发现文件和文件夹

DirBuster 是个工具，用于通过爆破来发现 Web 服务器中的现存文件和目录。我们会在这个秘籍中使用它来搜索文件和目录的特定列表。

### 准备

我们会使用一个文本文件，它包含我们要求 DirBuster 寻找的单词列表。创建文本文件`dictionary.txt`，包含下列东西：

+ info 
+ server-status 
+ server-info 
+ cgi-bin 
+ robots.txt 
+ phpmyadmin 
+ admin 
+ login

### 操作步骤

1.  访问`Applications | Kali Linux | Web Applications | Web Crawlers | dirbuster`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-7-1.jpg)
    
2.  在 DIrBuster 的窗口中，将目标 URL 设置为 <http://192.168.56.102/>。

3.  将线程数设置为 20。

4.  选择` List based brute force `（基于爆破的列表）并点击`Browse`（浏览）。

5.  在浏览窗口中，选择我们刚刚创建的文件（`dictionary.txt`）。

6.  取消选择`Be Recursive`（递归）。

7.  对于这个秘籍，我们会让其它选项保持默认。

8.  点击`Start`（开始）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-7-2.jpg)
    
9.  如果我们查看`Resuults`（结果）标签页，我们会看到，DirBuster 已经找到了至少两个目录中的文件：` cgi-bin `和`phpmyadmin`。响应代码 200 意味着文件或目录存在且能够读取。PhpMyAdmin 是基于 Web 的 MySQL 数据库管理器，找到这个名称的目录告诉我们服务器中存在 DBMS，并且可能包含关于应用及其用户的相关信息。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-7-3.jpg)
    
### 工作原理

DirBuster 是个爬虫和爆破器的组合，它允许页面上的所有连接，但是同时尝试可能文件的不同名称。这些名称可以保存在文件中，类似于我们所使用的那个，或者可以由 DirBuster 通过“纯粹暴力破解”选项，并为生成单词设置字符集和最小最大长度来自动生成。

为了判断文件是否存在，DirBuster 使用服务器生成的响应代码。最常见的响应在下面列出：

+   `200 OK`：文件存在并能够读取。

+   `404 File not found`：文件不存在。

+   `301 Moved permanently`：这是到给定 URL 的重定向。

+   `401 Unauthorized`：需要权限来访问这个文件。

+   `403 Forbidden`：请求有效但是服务器拒绝响应。

## 2.8 使用 Cewl 分析密码

在每次渗透测试中，查查都必须包含分析层面，其中我们会分析应用、部门或过程的名称、以及其它被目标组织使用的单词。当需要设置人员相关的用户名或密码的时候，这会帮助我们判断可能常被使用的组合。

这个秘籍中，我们会使用 CeWL 来获取应用所使用的单词列表。并保存它用于之后的登录页面暴力破解。

### 操作步骤

1.  首先，我们查看 CeWL 的帮助我文件，来获得能够做什么的更好想法。在终端中输入：

    ```
    cewl --help
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-8-1.jpg)
    
2.  我们会使用 CeWL 来获得 vulnerable_ vm 中 WackoPicko 应用的单词。我们想要长度最小为 5 的单词，显示单词数量并将结果保存到`cewl_WackoPicko.txt`。

    ```
    cewl -w cewl_WackoPicko.txt -c -m 5 http://192.168.56.102/ WackoPicko/
    ```
    
3.  现在，我们打开 CeWL 刚刚生成的文件，并查看“单词数量”偶对的列表。这个列表仍然需要一些过滤来去掉数量多但是不可能用于密码的单词，例如“Services”，“Content”或者“information”。

4.  让我们删除一些单词来构成单词列表的首个版本。我们的单词列表在删除一些单词和数量之后，应该看起来类似下面这样：

+ WackoPicko 
+ Users 
+ person
+ unauthorized
+ Login
+ Guestbook
+ Admin
+ access
+ password
+ Upload
+ agree
+ Member
+ posted
+ personal
+ responsible
+ account
+ illegal
+ applications
+ Membership
+ profile

### 工作原理

CeWL 是个 Kali 中的工具，爬取网站并提取独立单词的列表。他它也可以提供每次单词的重复次数，保存结果到文件，使用页面的元数据，以及其它。

### 另见

其它工具也可用于类似目的，它们中的一些生成基于规则或其它单词列表的单词列表，另一些可以爬取网站来寻找最常用的单词。

+   Crunch：这是基于由用户提供的字符集合的生成器。它使用这个集合来生成所有可能的组合。Crunch 包含在 Kali 中。

+   Wordlist Maker (WLM)：WLM 能够基于字符集来生成单词列表，也能够从文本文件和网页中提取单词（<http://www.pentestplus.co.uk/wlm.htm>）。

+   Common User Password Profiler (CUPP)：这个工具可以使用单词列表来为常见的用户名分析可能的密码，以及从数据库下载单词列表和默认密码（<https://github.com/Mebus/cupp>）。

## 2.9 使用 John the Ripper 生成字典

John the Ripper 可能是世界上最受大多数渗透测试者和黑客欢迎的密码破解器。他拥有许多特性，例如自动化识别常见加密和哈希算法，使用字典，以及爆破攻击。因此，它允许我们对字典的单词使用规则、修改它们、以及在爆破中使用更丰富的单词列表而不用储存列表。最后这个特性是我们会在这个秘籍中使用的特性之一，用于基于极其简单的单词列表生成扩展字典。

### 准备

我们会使用上一节中生成的单词列表，来生成可能密码的字典。

### 操作步骤

1.  John 拥有只展示用于破解特定密码文件的密码的选项。让我们使用我们的单词列表来尝试它：

    ```
    john --stdout --wordlist=cewl_WackoPicko.txt
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-9-1.jpg)
    
2.  另一个 John 的特性是让我们使用规则，以多种方式来修改列表中的每个单词，以便生成更复杂的字典。

    ```
    john --stdout --wordlist=cewl_WackoPicko.txt --rules
    ```
    
    你可以在结果中看到，John 通过转换大小写、添加后缀和前缀，以及将字母替换为数字和符号（leetspeak）来修改单词。
    
3.  现在我们需要执行相同操作，但是将列表发送给文件，便于我们之后使用：

    ```
    john --stdout --wordlist=cewl_WackoPicko.txt --rules > dict_ WackoPicko.txt
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-9-2.jpg)
    
4.  现在，我们拥有了 999 个单词的字典，它会在之后使用，用于进行应用登录页面上的密码猜测攻击。

### 工作原理

虽然 John the Ripper 的目标并不是字典生成器，而是高效地使用单词列表来破解密码（它也做的非常好）。它的特性允许我们将其用于扩展现有单词列表，并创建更符合现代用户所使用的密码的字典。

这个秘籍中，我们使用了默认的规则集合来修改我们的单词。John 的规则定义在配置文件中，位于 Kali 的`/etc/john/john.conf`。

### 更多

有关为 John the Ripper 创建和修改规则的更多信息，请见：<http://www.openwall.com/john/doc/RULES.shtml>。

## 2.10 使用 ZAP 发现文件和文件夹

OWASP ZAP（Zed Attack Proxy）是个用于 Web 安全测试的全能工具。他拥有代理、被动和主动漏洞扫描器、模糊测试器、爬虫、HTTP 请求发送器，一起一些其他的有趣特性。这个秘籍中，我们会使用最新添加的“强制浏览”，它是 ZAP 内的 DisBuster 实现。

### 准备

这个秘籍中，我们需要将 ZAP 用做浏览器的代理。

1.  打开 OWASP ZAP，从应用的菜单栏中，访问`Applications | Kali Linux | Web Applications | Web Application Fuzzers | owasp-zap`。

2.  在 Mantra 或 Iceweasel 中，访问主菜单的` Preferences | Advanced | Network`，在`Connection`中点击`Settings`。

3.  选项`Manual proxy configuration`（手动代理配置），并将`127.0.0.1`设置为 HTTP 代理，8080 设置为端口。检查选项来为所有协议使用同一个代理，并点击`OK`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-10-1.jpg)
    
4.  现在，我们需要告诉 ZAP 从哪个文件获得目录名称。从 ZAP 的菜单中访问` Tools | Options | Forced Brows`，之后点击`Select File`。

5.  Kali 包含一些单词列表，我们会使用它们之一：选择文件`/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3small.txt`，之后点击`Open`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-10-2.jpg)
    
6.  提示框会告诉我们文件被加载了。点击`OK`之后再点击`OK`来离开`Options`对话框。

### 操作步骤

1.  合理配置代理之后，浏览 <http://192.168.56.102/ WackoPicko>。

2.  我们会看到 ZAP 通过显示我们刚刚访问的主机的树形结构，对这个行为作出反应。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-10-3.jpg)
    
3.  现在，在 ZAP 的左上方面板中（`Sites`标签页），右击` http://192.168.56.102 `站点下面的`WackoPicko `文件夹。之后在上下文菜单中，访问`Attack | Forced Browse directory`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-10-4.jpg)
    
4.  在底部的面板中，我们会看到显示了` Forced Browse`标签页。这里我们可以看到扫描的过程和结果。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/2-10-5.jpg)

### 工作原理

当我们配置浏览器来将 ZAP 用作代理的时候，它并不直接发送给服务器任何我们打算浏览的页面的请求，而是发到我们定义的地址。这里是 ZAP 监听的地址。之后 ZAP 将请求转发给服务器但是不分析任何我们发送的信息。

ZAP 的强制浏览的工作方式和 DIrBuster 相同，它接受我们所配置的字典，并向服务器发送请求，就像它尝试浏览列表中的文件那样。如果文件存在，服务器会相应地响应。如果文件不存在或不能被我们的当前用户访问，服务器会返回错误。

### 另见

Kali 中包含的另一个非常实用的代理是 Burp Suite。它也拥有一些特别有趣的特性。其中可用作强制浏览的替代品是 Intruder。虽然 Burp Suite 并不特地用于该目的，但是它是个值得研究的通用工具。


# 第三章：爬虫和蜘蛛

> 作者：Gilberto Najera-Gutierrez

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

渗透测试可以通过多种途径完成，例如黑盒、灰盒和白盒。黑盒测试在测试者没有任何应用的前置信息条件下执行，除了服务器的 URL。白盒测试在测试者拥有目标的全部信息的条件下执行，例如它的构造、软件版本、测试用户、开发信息，以及其它。灰盒测试是黑盒和白盒的混合。

对于黑盒和灰盒测试，侦查阶段对测试者非常必然，以便发现白盒测试中通常由应用所有者提供的信息。

我们打算采取黑盒测试方式，因为它涉及到外部攻击者用于获取足够信息的所有步骤，以便入侵应用或服务器的特定功能。

作为每个 Web 渗透测试中侦查阶段的一部分，我们需要浏览器每个包含在网页中的链接，并跟踪它展示的每个文件。有一些工具能够帮助我们自动和以及加速完成这个任务，它们叫做 Web 爬虫或蜘蛛。这些工具通过跟随所有到外部文件的链接和引用，有的时候会填充表单并将它们发送到服务器，保存所有请求和响应来浏览网页，从而提供给我们离线分析它们的机会。

这一章中，我们会涉及到一些包含在 Kali 中的爬虫的使用，也会查看我们感兴趣的文件和目录，来寻找常见的网页。

## 3.1 使用 Wget 为离线分析下载网页

Wget 是 GNU 项目的一部分，也包含在主流 linux 发行版中，包括 Kali。它能够递归为离线浏览下载网页，包括链接转换和下载非 HTML 文件。

这个秘籍中，我们会使用 Wget 来下载和 vulnerable_vm 中的应用相关的页面。

### 准备

这一章的所有秘籍都需要运行 vulnerable_vm。在这本书的特定场景中，它的 IP 地址为 192.168.56.102。

### 操作步骤

1.  让我们做第一次尝试，通过仅仅以一个参数调用 Wget 来下载页面。

    ```
    wget http://192.168.56.102/bodgeit/
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-1-1.jpg)
    
    我们可以看到，它仅仅下载了`index.html`文件到当前目录，这是应用的首页。
    
2.  我们需要使用一些选项，告诉 Wget 将所有下载的文件保存到特定目录中，并且复制我们设为参数的 URL 中包含的所有文件。让我们首先创建目录来保存这些文件：

    ```
    mkdir bodgeit_offline
    ```
    
3.  现在，我们会递归下载应用中所有文件并保存到相应目录中。

    ```
    wget -r -P bodgeit_offline/ http://192.168.56.102/bodgeit/

    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-1-2.jpg)
    
### 工作原理

像之前提到的那样，Wget 是个为下载 HTTP 内容创建的工具。通过`-r`参数，我们可以使其递归下载，这会按照它所下载的每个页面的所有连接，并同样下载它们。`-P`选项允许我们设置目录前缀，这是 Wget 会开始保存下载内容的目录。默认它设为当前目录。

### 更多

在我们使用 Wget 时，可以考虑一些其它的实用选项：

+   `-l`：在递归下载的时候，规定 Wget 的遍历深度可能很有必要。这个选项后面带有我们想要遍历的层级深度的数值，让我们规定这样的界限。

+   `-k`：在文件下载之后，Wget 修改所有链接，使其指向相应的本地文件，这会使站点能够在本地浏览。

+   `-p`：这个选项让 Wget 下载页面所需的所有图像，即使它们位于其它站点。

+   `-w`：这个选项让 Wget 在两次下载之间等待指定的描述。当服务器中存在防止自动浏览的机制时，这会非常有用。

## 3.2 使用 HTTrack 为离线分析下载页面

就像 HTTrack 的官网所说（`http://www.httrack.com`）：

> 它允许你从互联网下载 WWW 站点到本地目录中，递归构建所有目录、从服务器获得 HTML、图像，和其它文件到你的计算机中。

我们在这个秘籍中会使用 HTTrack 来下载应用站点的所有内容。

### 准备

HTTrack 没有默认在 Kali 中安装。所以我们需要安装它。

```
apt-get update 
apt-get install httrack
```

### 操作步骤

1.  我们的第一步是创建目录来储存下载的站点，输入：

    ```
    mkdir bodgeit_httrack 
    cd bodgeit_httrack
    ```
    
2.  使用 HTTrack 的最简单方式就是向命令中添加我们打算下载的 URL。

    ```
    httrack http://192.168.56.102/bodgeit/ 
    ```
    
    设置最后的`/`非常重要，如果遗漏了的话，HTTrack 会返回 404 错误，因为服务器根目录没有`bodgeit`文件。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-2-1.jpg)
    
3.  现在，如果我们访问文件` file:///root/MyCookbook/test/bodgeit_httrack/index. html`（或者你在你的测试环境中选择的目录），我们会看到，我们可以离线浏览整个站点：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-2-2.jpg)
    
### 工作原理

HTTrack 创建站点的完整静态副本，这意味着所有动态内容，例如用户输入的响应，都不会有效。在我们下载站点的文件夹中，我们可以看到下列文件和目录：

+   以服务器名称或地址命名的目录，包含所有下载的文件。

+   `cookies.txt`文件，包含用于下载站点的 cookie 信息。

+   `hts-cache`目录包含由爬虫检测到的文件列表，这是 httrack 所处理的文件列表。

+   `hts-log.txt `文件包含错误、警告和其它在爬取或下载站点期间的信息

+   ` index.html`文件重定向到副本的原始主页，它位于名称为服务器的目录中。

### 更多

HTTrack 也拥有一些扩展选项，允许我们自定义它的行为来更好符合我们的需求。下面是一些值得考虑的实用修改器：

+   `-rN`：将爬取的链接深度设置为 N。
+   `-%eN`：设置外部链接的深度界限。
+   `+[pattern]`：告诉 HTTrack 将匹配`[pattern]`的 URL 加入白名单，例如`+*google.com/*`。
+   `-[pattern]`：告诉 HTTrack 将匹配`[pattern]`的 URL 加入黑名单。
+   `-F [user-agent]`：允许我们定义用于下载站点的 UA（浏览器标识符）。

## 3.3 使用 ZAP 蜘蛛

在我们的计算机中将完整的站点下载到目录给予我们信息的静态副本，这意味着我们拥有了不同请求产生的输出，但是我们没有服务器的请求或响应状态。为了拥有这种信息的记录，我们需要使用蜘蛛，就像 OWASP ZAP 中集成的这个。

这个秘籍中，我们会使用 ZAP 的蜘蛛来爬取 vulnerable_vm 中的目录，并检查捕获的信息。

### 准备

对于这个秘籍，我们需要启动  vulnerable_vm 和 OWASP ZAP，浏览器需要配置来将 ZAP 用做代理。这可以通过遵循上一章中“使用 ZAP 发现文件和文件夹”中的指南来完成。

### 操作步骤

1.  为了让 ZAP 启动并使浏览器将其用作代理，浏览`http://192.168.56.102/bodgeit/`。

2.  在`Sites`标签页中，打开对应测试站点的文件夹（本书中是`http://192.168.56.102`）。

3.  右击`GET:bodgeit`。

4.  从下拉菜单中选择` Attack | Spider…`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-3-1.jpg)

5.  在对话框中，保留所有选项为默认并点击`Start Scan`。

6.  结果会出现在`Spider`标签页的底部面板中。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-3-2.jpg)

7.  如果我们打算分析独立文件的请求和响应，我们访问`Sites`标签并打开其中的`site`文件夹和`bodget`文件夹。让我们看一看`POST:contact.jsp(anticsrf,comments,null)`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-3-3.jpg)
    
    在右边，我们可以看到完整的请求，包含所使用的参数（下半边）。
    
8.  现在，选择右侧部分的`Reponse`标签页。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-3-4.jpg)
    
    在上半边中，我们可以看到响应头，包括服务器标识和会话 Cookie，在下版本我们拥有完整的 HTML 响应。在之后的章节中，我们会了解从已授权的用户获取这种 cookie，如何用于劫持用户会话以及执行冒充它们的操作。
    
### 工作原理

就像任何其它爬虫那样，ZAP 的蜘蛛跟随它找到的每个链接，位于每个包含请求范围以及其中的链接中的页面上。此外，蜘蛛会跟随表单响应、重定向和包含在`robots.txt `和`sitemap.xml`文件中的 URL。之后它会为之后分析和使用储存所有请求和响应、

### 更多

在爬取站点或目录之后，我们可能打算使用储存的请求来执行一些测试。使用 ZAP 的功能，我们能够执行下列事情：

+   在修改一些数据之后重放请求
+   执行主动和被动漏洞扫描
+   模糊测试输入参数来寻找可能的攻击向量
+   在浏览器中重放特定请求

## 3.4 使用 Burp Suite 爬取站点

Burp 几乎是最广泛用于应用渗透测试的工具，因为它拥有类似 ZAP 的功能，并含有一些独特的特性和易用的界面。Burp 不仅仅能够用于爬取站点，但是现在，作为侦查阶段的一部分，我们先涉及这个特性。

### 准备

通过访问 Kali 的`Applications `菜单，之后访问`03 Web Application Analysis | Web Application Proxies | burpsuite`来启动 Burp Suite，就像下面这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-4-1.jpg)
    
之后配置浏览器将其用做代理，通过 8080 端口，就像我们之前使用 ZAP 的那样。

### 操作步骤

1.  Burp 的代理默认配置为拦截所有请求，我们需要禁用它来不带拦截浏览。访问`Proxy`标签页并点击` Intercept is on `按钮，它就会变为`Intercept is off`，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-4-2.jpg)
    
2.  现在，在浏览器中，访问` http://192.168.56.102/bodgeit/`。

3.  在 Burp 的窗口中，当我们访问`Target`的时候，我们会看到其中含有我们正在浏览器的站点信息，以及浏览器产生的请求。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-4-3.jpg)
    
4.  现在，为了激活蜘蛛，我们右击`bodgeit `文件夹，并从菜单中选择`Spider this branch`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-4-4.jpg)

5.  Burp 会询问我们是否添加项目到这里，我们点击`Yes`。通常，Burp 的蜘蛛只爬取匹配定义在`Target `标签页中的`Scope`标签页中的模式的项目。

6.  之后，蜘蛛会开始运行。当它检测到登录表单之后，它会向我们询问登录凭据。我们可以忽略它，蜘蛛会继续，或者我们可以提交一些测试值，蜘蛛会填充这些值到表单中。让我们将两个字段，用户名和密码都填充为单词`test`，并点击`Submit form`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-4-5.jpg)
    
7.  下面，我们会要求在注册页中填充用户名和密码。我们通过点击`Ignore form`来忽略它。

8.  我们可以在`Spider`标签页中检查蜘蛛的状态。我们也可以通过点击` Spider is running `按钮来停止它。让我们现在停止它，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-4-6.jpg)
    
9.  我们可以在`Site map`标签页中检查蜘蛛生成的结果，它在`Target`中。让我们查看我们之前填充的登录请求：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-4-7.jpg)
    
### 工作原理

Burp 的蜘蛛遵循和其它蜘蛛相同的方式，但是它的行为有一些不同，我们可以让它在我们浏览站点的时候运行，它会添加我们跟随（匹配范围定义）的链接到爬取队列中。

就像 ZAP 那样，我们可以使用 Burp 的爬取结果来执行任何操作。我们可以执行任何请求，例如扫描（如果我们拥有付费版）、重放、比较、模糊测试、在浏览器中查看，以及其它。

## 3.5 使用 Burp 重放器重放请求

在分析蜘蛛的结果以及测试可能的表单输入时，发送相同请求的修改特定值的不同版本可能很实用。

这个秘籍中，我们会学到如何使用 Burp 的重放器来多次发送带有不同值的请求。

### 准备

我们从前一个秘籍的地方开始这个秘籍。启动 vulnerable_vm 虚拟机和 Burp 以及将浏览器合理配置来将 Burp 用做代理非常必要。

### 操作步骤

1.  我们的第一步是访问`Target`标签，之后访问蜘蛛所生成的登录页面请求（`http://192.168.56.102/bodgeit/login.jsp`），带有`username=test&password=test`的那个。

2.  右击请求并从菜单中选择`Send to Repeater`，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-5-1.jpg)
    
3.  现在我们切换到`Repeater`标签页。

4.  让我们点击`Go`来在右侧查看服务器的响应。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-5-2.jpg)
    
    在`Request`部分（图像左侧）中，我们可以看到发给服务器的原始请求。第一行展示了所使用的方法：POST，被请求的 URL 和协议：HTTP 1.1。下面一行，一直到 Cookie，都是协议头参数，在它们后面我们看到一个换行，之后是我们在表单输入的 POST 参数和值。
    
5.  在响应部分我们看到了一些标签页：`Raw`、`Headers`、`Hex`、`HTML`和`Render`。这些以不同形式展示相同的响应信息。让我们点击`Render`来查看页面，就像在浏览器中那样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-5-3.jpg)
    
6.  我们可以在请求端修改任何信息。再次点击`OK`并检查新的响应。对于测试目的，让我们将密码值替换为一个单引号，并发送请求。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-5-4.jpg)
    
    我们可以看到，我们通过修改输入变量的值触发了系统错误。这可能表明应用中存在漏洞。在后面的章节中，我们会涉及到漏洞的测试和识别，并深入探索它。
    
### 工作原理

Burp 的重放器允许我们手动为相同的 HTTP 请求测试不同的输入和场景，并且分析服务器提供的响应。这在测试漏洞的时候非常实用，因为测试者可以了解应用如何对多种所提供的输入反应，以及从而识别或利用设计、编程或配置中的可能缺陷。

## 3.6 使用 WebScarab

WebScarab 是另一个 Web 代理，拥有让渗透测试者感兴趣的特性。这个秘籍中，我们会使用它来爬取网站。

### 准备

作为默认配置，WebScarab 实用 8008 端口来捕获 HTTP 请求。所以我们需要配置我们的浏览器来在 localhost 中使用这个端口作为代理。你需要遵循与在浏览器中配置 OWASP ZAP、Burp Suite 的相似步骤。这里，端口必须是 8008。

### 操作步骤

1.  在 Kali 的`Applications `菜单中，访问` 03 Web Application Analysis | webscarab`来打开 WebScarab。

2.  浏览 vulnerable_vm 的 Bodgeit 应用（`http://192.168.56.102/ bodgeit/`）。我们会看到它出现在 WebScarab 的`Summary`标签页中。

3.  现在，右击 bodgeit 文件夹并从菜单选择` Spider tree `，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-6-1.jpg)
    
4.  在蜘蛛发现新文件过程中，所有请求会出现在概览的下半部分，树也会被填满。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-6-2.jpg)
    
    这个概览也展示了一些关于每个特定文件的相关信息。例如，是否存在注入或者可能为注入的漏洞，是否设置了 cookie，包含表单，或者是否表单含有隐藏字段。它也表明了代码或文件上传中存在注释。
    
5.  如果我们右击任何下半部分的请求，我们会看到可以对它们执行的操作。我们分析请求，找到路径`/bodgeit/search.jsp`，右击它，并选择 Show conversation`。新的窗口会弹出，并以多种格式展示响应和请求，就像下面这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-6-3.jpg)
    
6.  现在点击`Spider`标签页。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/3-6-4.jpg)
    
    这个标签页中，我们可以在` Allowed Domains` 和 `Forbidden Domains`中，使用正则表达式来调整蜘蛛抓取的内容。我们也可以使用`Fetch Tree`来刷新结果。我们也可以通过点击`Stop`按钮来停止蜘蛛。
    
### 工作原理

WebScarab 的蜘蛛类似于 ZAP 或者 Burp Suite，对发现网站中所有被引用文件或目录，而无需手动浏览器所有可能的链接，以及深度分析发给服务器的请求，并使用它们执行更多复杂的测试非常实用。

## 3.7 从爬取结果中识别相关文件和目录

我们已经爬取了应用的完整目录，并且拥有了被引用文件和目录的完整列表。下一步地然是识别这些文件哪个包含相关信息，或者是更可能发现漏洞的机会。

这篇不仅仅是个秘籍，更是用于文件和目录的常见名称、前后缀的总结，它们通常给渗透测试者提供有价值的信息，或者是可能导致整个系统沦陷的漏洞利用。

### 操作步骤

1.  首先，我们打算寻找登录和注册页面，它们可以给我们机会来成为应用的正常用户，或者通过猜测用户名和密码来冒充它们。一些名称和部分名称的例子是：

    +   Account 
    +   Auth 
    +   Login 
    +   Logon 
    +   Registration 
    +   Register 
    +   Signup 
    +   Signin
    
2.  另一个常见的用户名、密码来源和与之相关的漏洞是密码恢复页面：

    +   Change 
    +   Forgot 
    +   lost-password 
    +   Password 
    +   Recover 
    +   Reset
    
3.  下面，我们需要识别是否存在应用的管理员部分，这里有一组功能可能允许我们执行高权限的操作，例如：

    +   Admin 
    +   Config 
    +   Manager 
    +   Root
    
4.  其它有趣的目录是内容管理系统（CMS）的管理员、数据库或应用服务器之一，例如：

    +   Admin-console 
    +   Adminer 
    +   Administrator 
    +   Couch 
    +   Manager 
    +   Mylittleadmin 
    +   PhpMyAdmin 
    +   SqlWebAdmin 
    +   Wp-admin
    
5.  应用的测试和开发版通常没有保护，并且比最终发行版更容易存在漏洞，所以它们在我们搜索缺陷的时候是个很好的目标。这些目录的名称包含：

    +   Alpha 
    +   Beta 
    +   Dev 
    +   Development 
    +   QA 
    +   Test
    
6.  Web 服务器的信息和配置文件如下：

    +   config.xml 
    +   info 
    +   phpinfo 
    +   server-status 
    +   web.config
    
7.  此外，所有在` robots.txt `中标记为`Disallow `的目录和文件可能非常实用。

### 工作原理

一些前面列出的名称和它们的语言变体允许我们访问站点的首先部分，这是渗透测试中非常重要的步骤。它们中的一些能够提供给我们服务器，它的配置以及所使用的开发框架信息。其它的，例如 Tomcat 管理器和 JBoss 的登录页面，如果配置不当的话，会让我们（或恶意攻击者）获得服务器的控制。


# 第四章：漏洞发现

> 作者：Gilberto Najera-Gutierrez

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

我们现在已经完成了渗透测试的侦查阶段，并且识别了应用所使用的服务器和开发框架的类型，以及一些可能的弱点。现在是实际测试应用以及检测它的漏洞的时候了。

这一章中，我们会涉及到检测一些 Web 应用中常见漏洞的过程，以及允许我们发现和利用它们的工具。

我们也会用到 vulnerable_vm 中的应用，我们会使用 OWASP Mantra 作为浏览来执行这些测试。

## 4.1 使用 Hackbar 插件来简化参数分析

在测试 Web 应用时，我们需要和浏览器的地址栏交互，添加或修改参数，以及修改 URL。一些服务器的相应会包含重定向，刷新以及参数修改。所有这些改动都会使对相同变量尝试不同值的操作非常费时间。我们需要一些工具来使它们不那么混乱。

Hackbar 是 Firefox 插件，它的行为就像地址栏，但是不受由服务器响应造成的重定向或其它修改影响，这就是我们需要测试 Web 应用的原因。

这个秘籍中，我们会使用 Hackbar 来简化相同请求的不同版本的发送工作。

### 准备

如果你没有使用  OWASP Mantra，你需要在你的 Firefox 上安装 Hackbar。

### 操作步骤

1.  访问 DVWA 并且登录。默认的用户名/密码组合是`admin/admin`。

2.  在左侧的菜单上选择`SQL Injection`（SQL 注入）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-1-1.jpg)
    
3.  在` User ID `输入框中输入数字，并点击`Submit`（提交）。

    现在我们可以按下`F9`或者点击图标来显示 Hackbar。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-1-2.jpg)
    
    Hackbar 会赋值 URL 及其参数。我们也可以开启修改 POST 请求和 Referer 参数的选项。后者告诉服务器页面从哪里被请求。
    
4.  让我们做个简单的改动，将`id`参数值从`1`改成`2`，并点击`Execute`（执行）或者使用` Alt + X`快捷键。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-1-3.jpg)
    
    我们可以看到，参数`id`对应页面上的文本框，所以，我们可以使用 Hackbar 修改`id`来尝试任何值，而不需要修改文本框中的`User ID`并提交它。在测试拥有许多输入的表单，或者取决于输入重定向到其它页面的表单时，这非常便利。
    
5.  我们可以将一个有效值替换为另一个，但是如果我们输入了一个无效值作为`id`，会发生什么呢？尝试将单引号作为`id`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-1-4.jpg)
    
    通过输入应用非预期的字符，我们触发了一个错误，这在之后测试一些漏洞的时候非常有用。
    
### 工作原理

Hackbar 是带有一些实用特性的第二个地址栏，比如不受 URL 重定向影响，并且允许我们修改 POST 参数。

此外，Hackbar 可用于向我们的请求中添加 SQL 注入或跨站脚本代码段，以及哈希、加密和编码我们的输入。我们会在这一章后面的秘籍中深入探索 SQL 注入、跨站脚本，以及其他漏洞。

## 4.2 使用 Tamper Data 插件拦截或修改请求

有时候，应用拥有客户端的输入校验机制，它们通过 JavaScript，隐藏表单或者 POST 数据，并不能直接在地址栏中了解或看到。为了测试这些以及其它类型的变量，我们需要拦截浏览器发送的请求并且在它们到达服务器之前修改它们。这个秘籍中，我们会使用叫做 Tamper Data 的 Firefox 插件来拦截表单提交并且在它离开计算机之前修改一些值。

### 操作步骤

1.  从 Mantra 的菜单中访问 `Tools | Application Auditing | Tamper Data`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-2-1.jpg)
    
2.  会出现 Tamper Data 的窗口。现在，让我们浏览 < http://192.168.56.102/dvwa/login.php>。我们可以在插件中看到请求会话。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-2-2.jpg)
    
    > 每个浏览器产生的请求都会在活动时经过 Tamper Data。
    
3.  为了拦截请求并修改它的值，我们需要通过点击`Start  Tamper`来启动 Tamper。现在启动 Tamper。

4.  输入一些伪造的用户名密码组合。例如，` test/password`，之后点击`Login`。

5.  在确认框中，取消勾选` Continue Tampering?`并点击`Tamper`。`Tamper Popup`窗口会出现。

6.  在弹出窗口中，我们可以修改发送给服务器的信息，包括请求头和 POST 参数。将`username`和`password`改为正确的（`admin/admin`），之后点击`OK`。这应该在本书中使用，而不是 DVWA：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-2-3.jpg)
    
    在最后一步中，我们在表单中的值由浏览器发送给服务器之前修改了它们。因此，我们可以以正确的凭证而不是错误的凭证登录服务器。
    
### 工作原理

Tamper Data 会在请求离开浏览器之前捕获请求，并提供给我们时间来修改它包含的任何变量。但是，它也有一些限制，例如不能编辑 URL 或 GET 参数。

## 4.3 使用 ZAP 来查看和修改请求

虽然 Tamper Data 有助于测试过程，有时我们需要更灵活的方法来修改请求以及更多特性，例如修改用于发送它们的方法（即从 GET 改为 POST），或者使用其它工具为进一步的目的保存请求/响应对。

OWASP ZAP 不仅仅是 Web 代码，它不仅仅能够拦截流量，也拥有许多在上一章所使用的，类似于爬虫的特性，还有漏洞扫描器，模糊测试器，爆破器，以及其它。它也拥有脚本引擎，可以用于自动化操作或者创建新的功能。

这个秘籍中，我们会开始将 OWASP ZAP 用作代理，拦截请求，并在修改一些值之后将它发送给服务器。

### 准备

启动 ZAP 并配置浏览器在通过它发送信息。

### 操作步骤

1.  访问 <http://192.168.56.102/mutillidae/>。

2.  现在，访问菜单栏中的`OWASP Top 10 | A1 – SQL Injection | SQLi – Extract Data | User Info`。

3.  下一步是提升应用的安全等级。点击` Toggle Security`。现在`Security Level`应该是` 1 (Arrogant)`。

4.  将`test'`（包含单引号）作为`Name`，以及` password'`作为`Password`，并且点击` View Account Details`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-3-1.jpg)

    我们得到了警告消息，告诉我们输入中的一些字符不合法。这里，单引号被检测到了，并被应用的安全手段中止。
    
5.  点击`OK`来关闭警告。

    如果我们在 ZAP 中检查历史，我们可以看到没有发给服务器的请求，这是由于客户端校验机制。我们会使用请求拦截来绕过这个保护。
    
6.  现在我们开启请求拦截（在 ZAP 叫做断点），通过点击`"break on all requests`（中断所有请求）按钮。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-3-2.jpg)
    
7.  下面，我们输入了有效值`Name`和`Password`，就像`test`和`password`，并再次检查细节。

    ZAP 会转移焦点，并打开叫做`Break`的新标签页。这里是刚刚在页面上产生的请求，我们可以看到一个 GET 请求，带有在 URL 中发送的`username`和`password`参数。我们可以添加上一次尝试中不允许的单引号。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-3-3.jpg)
    
8.  为了继续而不会被 ZAP 打断，我们通过点击`Unset Break`按钮来禁用断点。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-3-4.jpg)
    
9.  通过播放按钮来提交修改后的请求。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-3-5.jpg)
    
    我们可以看到，应用在顶部提供给我们错误信息，所以这是它的保护机制，它在客户端检查用户输入，但是在服务端并没有准备好处理非预期的请求。
    
### 工作原理

这个秘籍中，我们使用 ZAP 代理来拦截有效的请求，将它修改为无效或而已请求，之后把它发给服务器并且触发非预期的行为。

前三步用于开启安全保护，便于应用可以将单引号检测为无效字符。

之后，我们产生测试请求，并证实了会执行一些校验。提示警告的时候，没有请求通过代理，这告诉了我们检验是在客户端进行的，可能使用 JavaScript。知道了这个之后，我们产生了合法的请求，并使用代理来拦截它，这让我们能够绕过客户端的保护。我们将该请求转换为恶意请求，并把它发给服务器，这使它不能被正确处理，并返回错误。

## 4.4 使用  Burp Suite 查看和修改请求

Burp Suite 和 OWASP ZAP 一样，也不仅仅是个简单的 Web 代理。它是功能完整的 Web 应用测试包。它拥有代理、请求重放器、请求自动化工具、字符串编码器和解码器，漏洞扫描器（Pro 版本中），以及其它实用的功能。

这个秘籍中，我们会执行上一个练习，但是这次使用 Burp Suite 的代理功能来拦截和修改请求。

### 准备

启动 Burp Suite 并让浏览器使用它的代理。

### 操作步骤

1.  浏览 <http://192.168.56.102/mutillidae/>。

2.  默认情况下，Burp 代理中的拦截器是开着的，所以他会捕获第一个请求。我们需要打开  Burp Suite 并点击` Proxy `标签页中的`Intercept is on`按钮。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-4-1.jpg)
    
3.  浏览器会继续加载页面。当它完成时，我们通过` Toggle Security `将当前的应用安全级别设置为` 1 (Arrogant)`。

4.  从菜单栏中访问` OWASP Top 10 | A1 – SQL Injection | SQLi – Extract Data | User Info`。

5.  在`Name`输入框中，对`Username`输入`user<>`（包括符号）。在`Password`输入框中，对`Password`输入`secret<> `。之后点击`View Account Details`。

    我们会得到警告，告诉我们我们可能向应用输入了一些危险字
符。

6.  现在我们直到这些符号在表单中并不允许，我们也知道了它是客户端的校验，因为代理的` HTTP history `标签页中没有任何请求出现。让我们尝试绕过这个保护。通过点击 Burp Suite 中的`Intercept is off`来开启消息拦截。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-4-2.jpg)
    
7.  下一步是发送有效数据，例如`user`和`secret`。

8.  代理会拦截该请求。现在我们修改`username`和`password`的值，通过添加禁止的字符`<>`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-4-3.jpg)
    
9.  我们可以发送编辑后的信息，并通过点击` Intercept is on`来禁用拦截，或者我们可能发酸发送他并保持消息拦截，通过点击`Forward`。对于这个练习，我们禁用拦截并检查结果。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-4-4.jpg)

### 工作原理

就像在上个秘籍中看到的那样，在请求经过由应用建立在客户端的验证机制之前，我们使用代理来捕获请求，并通过添加一些在检验中不允许的字符，修改了它的内容。

能够拦截和修改请求，对任何 Web 应用渗透测试来说都非常重要，不仅仅用于绕过一些客户端检验，就像我们在当前和上一个秘籍中所做的那样，也能够用于了解发送了哪个信息，以及尝试理解应用的内部原理。我们可能也需要基于我们的理解来添加、移除或替换一些值。

## 4.5 识别跨站脚本（XSS）漏洞

跨站脚本（XSS）是 Web 应用中最常见的漏洞之一。实际上，它位于 2013 年 OWASP Top 10 的第三名（<https://www.owasp.org/ index.php/Top_10_2013-Top_10>）。

这个秘籍中，我们会看到一些识别 Web 应用中跨站脚本漏洞的关键点。

### 操作步骤

1.  登录 DVWA 并访问反射型 XSS。

2.  测试漏洞的第一步是观察应用的正常响应。在文本框中输入名称并点击`Submit`按钮。我们使用`Bob`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-5-1.jpg)
    
3.  应用会使用我们提供的名称来拼接代码。如果我们不输入有效名称，而是输入一些特殊字符或数字会怎么样呢？让我们尝试`<'this is the 1st test'>`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-5-2.jpg)
    
4.  现在我们可以看到，我们输入在文本框汇总的任何东西都会反射到响应中，也就是说，它成为了响应中 HTML 页面的一部分。让我们检查页面源代码来分析它如何展示信息，就像下面截图中那样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-5-3.jpg)

    源码表明了输出中没有对任何特殊字符做编码。我们发送的特殊字符被反射回了页面，没有任何预处理。`<`和`>`符号适用于定义 HTML 标签的符号，我们可能能够在这里输入一些脚本代码。
    
5.  尝试输入一个名称，后面带有非常简单的脚本代码。

    ```
    Bob<script>alert('XSS')</script>
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-5-4.jpg)
    
    页面会执行脚本，并弹出提示框，表明这个页面上存在跨站脚本漏洞。
    
6.  现在检查源码来观察输入中发生了什么。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-5-5.jpg)
    
    我们的输入看起来作为 HTML 的一部分来处理。浏览器解释了`<script>`标签并执行了其中的代码，弹出了我们设置的提示框。
    
### 工作原理

跨站脚本漏洞在服务端和客户端中没有输入校验，并且输出没有合理编码时发生。这意味着应用允许我们输入用于 HTML 代码中的字符。一旦它被决定发送到页面中，并没有执行任何编码措施（例如使用 HTML 转义代码`&lt` 和 `&gt;`）来防止他们被解释为源代码。

这些漏洞可被攻击者利用来改变客户端的页面行为，并欺骗用户来执行它们不知道的操作，或偷取隐私信息。

为了发现 XSS 漏洞，我们需要遵循以下原则：

+   我们在输入框中输入的，准确来说是被发送的文本，用于形成在页面中展示的信息，这是反射型漏洞。

+   特殊的字符没有编码或转义。

+   源代码表明，我们的输入被集成到某个位置，其中它变成了 HTML 代码的一部分，并且会被浏览器解释。

### 更多

这个秘籍中，我们发现了反射型 XSS，也就是说这个脚本在每次我们发送请求时，并且服务器响应我们的恶意请求时都会执行。有另外一种 XSS 类型叫做“存储型”。存储型 XSS 可能会在输入提交之后立即展示，也可能不会。但是这种输入会储存在服务器（也可能是数据库）中，它会在用户每次访问储存数据时执行。

## 4.6 基于错误的 SQL 注入识别

注入在 OWASP top 10 列表中位列第一。这包含，我们会在这个秘籍中测试的漏洞：SQL 注入（SQLI），以及其它。

多数现代 Web 应用实现了某种类型的数据库，要么本地要么远程。SQL 是最流行的语言，在 SQLI 攻击中，攻击者向表单输入或请求中的其它参数注入 SQL 命令，使应用发送修改后的请求，来试图不正当使用应用和数据库通信。其中请求用于构建服务器中的 SQL 语句。

这个秘籍中，我们会测试 Web 应用的输入，来观察是否含有 SQL 注入漏洞。

### 操作步骤

登录 DWVA 并执行下列步骤：

1.  访问` SQL Injection`。

2.  类似于上一章，我们通过输入数字来测试应用的正常行为。将`User ID`设置为 1，并点击`Submit`。

    我们可以通过解释结果来得出，应用首先查询数据库，是否有 ID 等于 1 的用户，之后返回结果。
    
3.  下面，我们必须测试，如果我们发送一些应用的非预期结果，会发生什么。在输入框中输入`1'`并提交该 ID。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-6-1.jpg)

    这个错误信息告诉我们，我们修改了生成好的查询。这并不意味着这里确实有 SQL 注入，但是我们可以更进一步。

4.  返回 DWVA/SQL 注入页面。

5.  为了验证是否有基于错误的 SQL 输入，我们尝试另一个输入：`1''`（两个单引号）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-6-2.jpg)


6.  现在，我们要执行基本的 SQL 注入攻击，在输入框中输入`' or '1'='1`并提交。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-6-3.jpg)
    
    看起来我们获取了所有数据库中的注册用户。

### 工作原理

SQL 注入发生在输入在用于组成数据库查询之前没有校验的时候。让我们假设服务端的代码（PHP）拼装了一个请求，例如：

```php
$query = "SELECT * FROM users WHERE id='".$_GET['id']. "'";
```

这意味着，`id`参数中发送的数据会被集成进来，因为它在查询里面。将参数的引用替换为它的值，我们能得到：

```php
$query = "SELECT * FROM users WHERE id='"."1". "'";
```

所以，当我们发送恶意输入，就像之前那样，代码行会由 PHP 解释器读取，就像：

```php
$query = "SELECT * FROM users WHERE id='"."' or '1'='1"."'";
```

拼接为：

```php
$query = "SELECT * FROM users WHERE id='' or '1'='1'";
```

这意味着“选择`users`表中的任何条目，只要用户`id`等于空或者 1 等于 1”。然而 1 永远等于 1，这就意味着所有用户都复合条件。我们发送的第一个引号闭合了原始代码中的做引号，之后我们输入了一些 SQL 代码，不带有闭合的单引号，而是使用已经在服务端代码中该设置好的单引号。

### 更多

SQL 攻击比起显式应用的用户名，可能导致更严重的破坏。通过利用这些漏洞，攻击者可能会通过执行命令和提权来控制整个服务器。它也能够提取数据库中的所有信息，包括系统用户名称和密码。取决于服务器和内部网络的配置，SQL 注入漏洞可能是整个网络和内部设施入侵的入口。

## 4.7 识别 SQL 盲注

我们已经看到了 SQL 注入漏洞如何工作。这个秘籍中，我们会涉及到相同类型漏洞的不同变体，它不显式任何能够引导我们利用的错误信息或提示。我们会学习如何识别 SQL 盲注。

### 操作步骤

1.  登录 DVWA 并访问`SQL Injection (Blind)`。

2.  它看起来像是我们上一章了解的 SQL 注入。在输入框中输入`1`并点击`Submit`。

3.  现在我们首次测试`1'`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-7-1.jpg)
    
    我们没有得到任何错误信息，但是也没有结果，这里可能会发生一些有趣的事情。
    
4.  我们第二次测试`1''`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-7-2.jpg)
    
    `ID=1`的结果显示了，这意味着上一个结果`1'`产生了错误，并被应用捕获和处理掉了。很可能这里有个 SQL 注入漏洞，但是它是盲注，没有显示关于数据库的信息，所以我们需要猜测。
    
5.  让我们尝试识别，当用户注入永远为假的代码会发生什么。将` 1' and '1'='2 `设置为用户的 ID。
    
    `'1'`永远不会等于`'2'`，所以没有任何记录符合查询中的条件，并且没有人恶化结果。

6.  现在，尝试当 ID 存在时永远为真的请求：` 1' and '1'='1`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-7-3.jpg)
    
    这演示了页面上的盲注。如果我们的永远为假的 SQL 注入得到了不同的响应，并且永远为真的结果得到了另一个响应，这里就存在漏洞，因为服务器会执行代码，即使它不显示在响应中。
    
### 工作原理

基于错误的 SQL 输入和盲注都存在于服务端，也就是漏洞的那一段。应用在使用输入生成数据库查询之前并不过滤输入。二者的不同存在于检测和利用上。

在基于错误的 SQL 注入中，我们使用由服务器发送的错误来识别查询类型，表和列的名称。

另一方面，当我们视图利用盲注时，我们需要通过问问题来得到信息。例如，` "' and name like 'a%"`的意思是，“是否存在以`'a'`开头的用户？”如果我们得到了负面响应，我们会询问是否有以`'b'`开头的名称。在得到正面结果之后，我们会就会移动到第二个字符：`"' and name like 'ba%"`。所以我们会花费很多时间来检测和利用。

### 另见

下面的信息可能有助于更好的了解 SQL 盲注：

+   https://www.owasp.org/index.php/Blind_SQL_Injection 
+   https://www.exploit-db.com/papers/13696/ 
+   https://www.sans.org/reading-room/whitepapers/securecode/sqlinjection-modes-attack-defence-matters-23

## 4.8 识别 Cookie 中的漏洞

Cookie 是从网站发送的小型数据片段，它储存于用户的浏览器中。它们包含有关于这种浏览器或一些特定 Web 应用用户的信息。在现代 Web 应用汇总，Cookie 用于跟踪用户的会话。通过在服务端和客户端保存 Session ID，服务器能够同时识别由不同客户端产生的不同请求。当任何请求发送到服务器的时候，浏览器添加 Cookie 并之后发送请求，服务器可以基于这个 COokie 来识别会话。

这个秘籍中，我们会学到如何识别一些漏洞，它们允许攻击者劫持有效用户的会话。

### 操作步骤

1.  访问 <http://192.168.56.102/mutillidae/>。

2.  打开 Cookie Manager+ 并且删除所有 Cookie。这可以防止与之前的 Cookie 产生混乱。

3.  现在，在 Mutillidae II 中，访问`OWASP Top 10 | A3 – Broken Authentication and Session Management | Cookies`。

4.  在`Cookies Manager+ `中，我们会看到出现了两个新的 Cookie。`PHPSESSID `和`showhints`。选项前者并点击`Edit`来查看所有参数。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-8-1.jpg)
    
    `PHPSESSID `是基于 PHP 的 Web 应用的会话默认名称。通过查看 Cookie 中参数值，我们可以看到它可以经过安全和不安全的频道（HTTP 和 HTTPS）发送。同样，它可以被服务器读取，以及被客户端用过脚本代码读取，因为它并没有开启 HTTPOnly 标识。这就是说，这个应用的会话可以被劫持。
    
### 工作原理

这个秘籍中，我们检查了 Cookie 的某些之，虽然并不像上一个那么明显。在每次渗透测试中检查 Cookie 的配置非常重要，不正确的会话 Cookie 设置会打开会话劫持攻击的大门，以及错误使用受信任的用户账户。

如果 Cookie 没开启`HTTPOnly`标识，他就可以被脚本读取。因此，如果存在跨站脚本攻击漏洞，攻击者就能够得到有效会话的 ID，并且使用它来模拟应用中的真实用户。

Cookies Manager+ 中的安全属性，或者`Send For Encrypted Connections Only`选项告诉浏览器只通过加密的频道发送或接受该 Cookie（也就是说，只通过 HTTPS）。如果这个标志没有设置，攻击者可以执行中间人攻击（MITM），并且通过 HTTP 来得到会话 Cookie，这会使它显示为纯文本，因为 HTTP 是个纯文本的协议。这就再次产生了攻击者能够通过持有会话 ID 来模拟有效用户的场景。

### 更多

就像`PHPSESSID `是 PHP 会话 Cookie 的默认名称那样，其它平台也拥有名称，例如：

+   `ASP.NET_SessionId `是 ASP.NET 会话 Cookie 的名称。

+   `JSESSIONID`是 JSP 实现的会话 Cookie。

OWASP 有一篇非常透彻的文章，关于保护会话 ID 和会话 Cookie。

https://www.owasp.org/index.php/Session_Management_Cheat_Sheet

## 4.9 使用 SSLScan 获取 SSL 和 TLS 信息

我们在某种程度上，假设当一个连接使用带有 SSL 或 TLS 加密的 HTTPS 时，它是安全的，而且任何试图拦截它的攻击者都只会得到一些无意义的数字。但是，这并不绝对正确：HTTPS 服务器需要正确配置来提供有效的加密层，并保护用户不受 MITM 攻击或密码分析。一些 SSL 协议的实现和设计上的漏洞已经被发现了，所以，我们在任何 Web 应用渗透测试中都要测试安全连接的强制性。

这个秘籍中，我们会使用 SSLScan，它是 Kali Linux 所包含的工具，基于服务器的安全通信来分析服务器的配置文件（从客户端的角度）。

### 操作步骤

OWASP BWA 虚拟机已经配置好了 HTTPS 服务器，为了确保它正常工作，访问 <https://192.168.56.102/>，如果页面没有正常加载，你可能需要在继续之前检查你的配置文件。

2.  SSLScan 是个命令行工具（内建于 Kali），所以我们需要打开终端。

3.  基本的`sslscan`命令会提供给我们服务器的足够信息。

    ```
    sslscan 192.168.56.102
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-9-1.jpg)
    
    输出的第一部分告诉我们服务器的配置，包含常见的安全错误配置：重协商、压缩和 Heartbleed，它是最近在一些 TLS 实现中发现的漏洞。这里，一切看起来都很好。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-9-2.jpg)
    
    在第二部分中，SSLScan 会展示服务器接受的加密方式。正如我们看到的那样，它支持 SSLv3 和一些例如 DES 的方式，它现在是不安全的。它们以红色文字展示，黄色文字代表中等强度的加密。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-9-3.jpg)
    
    最后，我们看到了首选的加密方式，如果客户端支持它，服务器会尝试用于通信。最终，服务器会使用有关证书的信息。我们可以看到，它将中等强度的算法用于签名，并使用 RSA 弱密钥。密钥是弱的，因为他只有 1024 位的长度，安全标准推荐至少 2048 位。
    
### 工作原理

SSLScan 通过创建多个到 HTTPS 的链接来工作，并尝试不同的加密方式和客户端配置来测试它接受什么。

当浏览器链接到使用 HTTPS 的服务器时，它们交换有关浏览器可以使用什么以及服务器支持什么的信息。之后它们在使用高度复杂的算法上达成一致。如果配置不当的 HTTPS 服务器上出现了 MITM 攻击，攻击者就可以通过声称客户端值支持弱加密算法来欺骗服务器，假如是 SSLv2 上的 56 位 DES。之后攻击者会拦截使用该算法加密的通信，通信可能会在几天或几小时之内使用现代计算机破解。

### 更多

就像我们之前提到的那样，SSLScan 能够检测 Heartbleed，这是一个最近在 OpenSSL 实现中发现的有趣漏洞。 

Heartbleed 在 2014 年四月被发现。它由一个缓冲区导致，多于允许的数据可以从内存中读出，这是 OpenSSL TLS 中的情况。

实际上，Heartbleed 可以在任何未装补丁的支持 TLS 的 OpenSSL （1.0.1 到 1.0.1f 之间）服务器上利用。它从服务器内存中读取 64 KB 的纯文本数据，这能够重复执行，服务器上不会留下任何踪迹或日志。这意味着攻击者可以从服务器读取纯文本信息，包括服务器的的私钥或者加密正是，会话 Cookie 或 HTTPS 请求会包含用户的密码或其它敏感信息。更多 Heartbleed 的信息请见维基百科：<https://en.wikipedia.org/wiki/ Heartbleed>。

### 另见

SSLScan 并不是唯一从 SSL/TLS 获取加密信息的攻击。Kali 中也有另一个工具叫做 SSLyze 可以用作替代，并且有时候会提供额外信息给攻击者。

```
sslyze --regular www.example.com 
```

SSL/TLS 信息也可以通过 OpenSSL 命令获得：

```
openssl s_client -connect www2.example.com:443
```

## 4.10 查找文件包含

文件包含漏洞出现在开发者使用请求参数的时候，在服务端的代码中，参数可以被用户修改来动态选择加载或包含哪个页面。如果服务器执行了所包含的文件，这种漏洞可能导致整个系统的沦陷。

这个秘籍中，我们会测试 Web 应用来发现是否含有文件包含漏洞。

### 操作步骤

1.  登录 DVWA 并访问`File Inclusion`。

2.  我们需要编辑 GET 参数来测试包含。让我们尝试`index.php`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-10-1.jpg)

    看起来目录中没有`index.php`文件（或者它为空），也可能这意味着本地文件包含（LFI）可能出现。
    
3.  为了尝试 LFI，我们需要了解本地真正存在的文件名称。我们知道了 DVWA 根目录下存在`index.php`，所以我们对文件包含尝试目录遍历，将页面遍历设置为`../../index.php`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-10-2.jpg)
    
    这样我们就演示了 LFI 可能出现，并且路径遍历也可能出现（使用`../../`，我们就遍历了目录树）。
    
4.  下一步是尝试远程文件包含，包括储存在另一个服务器的我呢间，而不是本地文件，由于我们的测试虚拟机并没有连接互联网（或者它不应该联网，出于安全因素）。我们尝试带有完整 URL 的本地文件，就像它来自另一个服务器那样。我们也会尝试包含 Vicnum 的主页`?page=http://192.168.56.102/vicnum/index.html`，通过提供页面的 URL 作为参数，就像下面这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-10-3.jpg)
    
    我们能够通过提供完整 URL 使应用加载页面，这意味着我们可以包含远程文件，因此，存在远程文件包含（RFI）。如果被包含文件含有服务端可执行代码（例如 PHP），这种代码会被服务端执行。因此，攻击者可以执行远程命令，这样的话，整个系统很可能沦陷。
    
### 工作原理

如果我们使用 DVWA 的`View Source`按钮，我们可以看到服务端代码是：

```php
<?php 
$file = $_GET['page']; //The page we wish to display 
?>
```

这意味着`page`变量的值直接传给了文件名称，之后它被包含在代码中。这样，我们可以在服务端包含和执行任何我们想要的 PHP 或 HTML 文件，只要它可以通过互联网访问。存在 RFI 漏洞的情况下，服务器一定会在配置文件中打开`allow_url_fopen`和`allow_url_include`。否则它只能含有本地文件包含，如果文件包含漏洞存在的话。

### 更多

我们也可以使用本地文件包含来显示主机操作系统的相关文件。例如，试着包含`../../../../../../etc/passwd `，之后你就会得到系统用户和它们的主目录，以及默认 shell 的列表。

## 4.11 识别 POODLE 漏洞

就像上一章提到的那样，使用 SSLScan 获得 HTTPS 参数在一些条件下是可能的，尤其是中间人攻击者降级用于加密通信的安全协议和加密算法的时候。

POODLE 攻击使用这种条件来将 TLS 通信降级为 SSLv3 并强制使用易于被攻破的加密算法（CBC）。

这个秘籍中，我们会使用 Nmap 脚本来检测这种漏洞在测试服务器上是否存在。

### 准备

我们需要安装 Nmap 并下载特定为检测此漏洞而编写的脚本。

1.  访问` http://nmap.org/nsedoc/scripts/ssl-poodle.html`。

2.  下载` ssl-poodle.nse`文件。

3.  假设它下载到了你的 Kali 中的`/root/Downloads`中。下载打开终端并将它复制到 Nmap 的脚本目录中：

    ```
    cp /root/Downloads/ssl-poodle.nse /usr/share/nmap/scripts/
    ```
    
### 操作步骤

一旦你安装了脚本，执行下列步骤：

1.  打开终端并运行：

    ```
    nmap --script ssl-poodle -sV -p 443 192.168.56.102
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/4-11-1.jpg)

    
    我们告诉了 Nmap 要扫描`192.168.56.102`（我们的 vulnerable_vm）的 443 端口，识别服务版本并在它上面执行 ssl-poodle 脚本。一次你，我们可以断定，服务器有漏洞，因为它允许 使用` TLS_RSA_WITH_ AES_128_CBC_SHA`加密算法的 SSLv3 。
    
### 工作原理

我们下载的 Nmap 脚本和测试服务器建立了安全通信，并判断他是否支持 SSLv3 上的 CBC 加密算法。如果支持，它就存在漏洞。漏洞会导致任何拦截的信息都能被攻击者在很短的时间内解密。

### 另见

为了更好理解这个攻击，你可以查看一些这个加密实现最基本的解释。

+   Möller, Duong, and Kotowicz, This POODLE Bites: Exploiting the SSL 3.0 Fallback, https://www.openssl.org/~bodo/ssl-poodle.pdf 
+   https://en.wikipedia.org/wiki/Padding_oracle_attack 
+   https://en.wikipedia.org/wiki/Padding_%28cryptography%29#Block_cipher_mode_of_operation


# 第五章：自动化扫描

> 作者：Gilberto Najera-Gutierrez

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

几乎每个渗透测试项目都需要遵循严格的日程，多数由客户的需求或开发交谈日期决定。对于渗透测试者，拥有一种工具，它可以在很短的时间内执行单个应用上的多个测试，来尽可能在排期内识别最多漏洞很有帮助。自动化漏洞扫描器就是完成这种任务的工具，它们也用于发现替代的利用，或者确保渗透测试中不会遗漏了明显的事情。

Kali 包含一些针对 Web 应用或特定 Web 漏洞的漏洞扫描器。这一章中，我们会涉及到一些在渗透测试者和安全研究员中最广泛使用工具。

## 5.1 使用 Nikto 扫描

每个测试者的工具库中必定含有的工具就是 Nikto，它可能是世界上使用最广泛的自由扫描器。就像它的网站（<https://cirt.net/Nikto2>）上所说的那样：

> Nikto 是开源（GPL）的 Web 服务器扫描器，它对 Web 服务器执行综合扫描，包含超过 6700 个潜在的危险文件或程序，检查超过 1250 个服务器的过期版本，以及超过 270 个服务器上的特定问题。它也会检查服务器配置项，例如多个首页文件的存在，HTTP 服务器选项，也会尝试识别安装的 Web 服务器和软件。扫描的项目和插件也会经常更新，并可以自动更新。

这个秘籍中，我们会使用 Nikto 来搜索 Web 服务器中的漏洞并分析结果、

### 操作步骤

1.  Nikto 是个命令行工具，所以我们打开终端。

2.  我们会扫描 Peruggia 漏洞应用，并导出结果到 HTML 报告：

    ```
    nikto -h http://192.168.56.102/peruggia/ -o result.html
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-1-1.jpg)
    
    `-h`选项告诉 Nikto 扫描哪个主机，`-o`选项告诉在哪里存放输出，文件的扩展名决定了接受的格式。这里，我们使用`.html`来获得 HTML 格式的结果报告。输出也可以以 CSV、TXT 或 XML 格式。
    
3.  它需要一些时间来完成扫描。完成之后，我么可以打开`result.html`文件：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-1-2.jpg)
    
### 工作原理

这个秘籍中，我们使用 Nikto 来扫描应用并生成 HTML 报告。这个工具拥有一些更多的选项，用于执行特定扫描或生成特定输出格式。一些最实用的选项是：

+   `-H`：这会显示 Nikto 的帮助。

+   `-config <file>`：在扫描中用自定义的配置文件。

+   `-update`：更新插件数据库。

+   `-Format <format>`：这定义了输出格式，可以为 CSV、HTML、NBE（Nessus）、SQL、TXT 或 XML。例如 CSV、XML 和 NBE 的格式在我们打算将其用于其它工具的输入时非常实用。

+   `-evasion <techique>`：这使用一些编码技巧来帮助避免 Web 应用防火墙和入侵检测系统的检测。

+   `-list-plugins`：查看可用的测试插件。

+   `-Plugins <plugins>`：选择在扫描中使用哪个插件（默认为全部）。

+   `-port <port number>`：如果服务器使用非标准端口（80，443），我们可能会以这个选项来使用 Nikto。

## 5.2 使用 Wapiti 发现漏洞

Wapiti 是另一个基于终端的 Web 漏洞扫描器，它发送 GET 和 POST 请求给目标站点，来寻找下列漏洞（<http://wapiti. sourceforge.net/>）：

+   文件泄露

+   数据库注入

+   XSS

+   命令执行检测

+   CRLF 注入

+   XXE（XML 外部实体）注入

+   已知潜在危险文件的使用

+   可被绕过的`.htaccess `弱配置

+   提供敏感信息的备份文件（源码泄露）

这个秘籍中，我们使用 Wapiti 来发现我们的测试应用上的漏洞，并生成扫描报告。

### 操作步骤

1.  我们可以从终端窗口打开 Wapiti，例如：

    ```
    wapiti http://192.168.56.102/peruggia/ -o wapiti_result -f html -m "-blindsql"
    ```
    
    我们会扫描 vulnerable_vm 中的 Peruggia 应用，将输出保存为 HTML 格式，保存到` wapiti_result`目录中，并跳过 SQL 盲注检测。
    
2.  如果我们打开了报告目录，和`index.html`文件，我们会看到一些这样的东西：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-2-1.jpg)

    这里，我们可以看到 Wapiti 发现了 12 个 XSS 和 20 个文件处理漏洞。
    
3.  现在点击` Cross Site Scripting`（跨站脚本）。

4.  选项某个漏洞并点击`HTTP Request`。我们选择第二个，选中并复制请求的 URL 部分。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-2-2.jpg)
    
5.  现在，我们将 URL 粘贴到浏览器中，像这样：`http://192.168.56.102/ peruggia/index.php?action=comment&pic_id=%3E%3C%2Fform%3E%3Cscr ipt%3Ealert%28%27wxs0lvms89%27%29%3C%2Fscript%3E`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-2-3.jpg)
    
    我们确实发现了 XSS 漏洞。
    
### 工作原理

这个秘籍中，我们跳过了 SQL 盲注检测（`-m "-blindsql"`），因为这个应用存在这个漏洞。它会触发超时错误，使 Wapiti 在扫描完成之前关闭，因为 Wapiti 通过输入 `sleep()`命令来测试多次，直到服务器超过了超时门槛。同时，我们为输出选择了 HTML 格式（`-o html`），`wapiti_result`作为报告的目标目录，我们也可以选择其他格式，例如，JSON、OpenVAS、TXT 或 XML。

Wapiti 拥有一些其它的有趣的选项，它们是：

+   `-x <URL>`：从扫描中排除特定的 URL，对于登出和密码修改 URL 很实用。

+   `-i <file>`：从 XML 文件中恢复之前保存的扫描。文件名称是可选的，因为如果忽略的话 Wapiti 从`scan`文件夹中读取文件。

+   `-a <login%password>`：为 HTTP 登录使用特定的证书。

+   `--auth-method <method>`：为`-a`选项定义授权方式，可以为`basic`，`digest`，`kerberos` 或 `ntlm`。

+   `-s <URL>`：定义要扫描的 URL。

+   `-p <proxy_url>`：使用 HTTP 或 HTTPS 代理。

## 5.3 使用 OWASP ZAP 扫描漏洞

OWASP ZAP 是我们已经在这本书中使用过的工具，用于不同的任务，并且在它的众多特性中，包含了自动化的漏洞扫描器。它的使用和报告生成会在这个秘籍中涉及。

### 准备

在我们使用 OWASP ZAP 成功执行漏洞扫描之前，我们需要爬取站点：

1.  打开 OWASP ZAP 并配置浏览器将其用作代理。

2.  访问 `192.168.56.102/peruggia/`。

3.  遵循第三章“使用 ZAP 的蜘蛛”中的指南。

### 操作步骤

1.  访问 OWASP ZAP 的`Sites`面板，并右击`peruggia`文件夹。

2.  访问菜单中的`Attack | Active Scan`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-3-1.jpg)

3.  新的窗口会弹出。这里，我们知道我们的应用和服务器使用哪种技术，所以，访问`Technology`标签页，并只勾选`MySQL`、`PostgreSQL`和`Linux`，以及`Apache`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-3-2.jpg)
    
    这里我们可以配置我们的扫描器的`Scope`（从哪里开始扫描、在什么上下文中，以及其它）、`Input Vectors`（选项是否你打算测试 GET 和 POST 请求、协议头、Cookie 和其它选项）、` Custom Vectors `（向原始请求中添加特定的字符或单词作为攻击向量）、`Technology `（要执行什么技术特定的测试）、以及`Policy`（为特定测试选项配置参数）。
    
4.  点击`Start Scan`。

5.  `Active Scan `标签页会出现在面板顶部，并且所有请求都会出现在那里。当扫描完成时，我们可以在`ALerts`标签页中检查结果。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-3-3.jpg)
    
6.  如果我们选项某个警告，我们可以查看生成的请求，以及从服务器获得的响应。这允许我们分析攻击并判断是否是真正的漏洞，或者是误报。我们也可以使用这个信息来模糊测试，在浏览器中重放这个请求，或者深入挖掘以利用。为了生成 HTML 报告，就像前一个工具那样，在主菜单中访问`Report`之后选择` Generate HTML Report....`。

7.  新的对话框会询问文件名和位置。例如，设置`zap_result. html`并且在完成时打开文件：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-3-4.jpg)
    
### 工作原理

OWASP ZAP 能够执行主动和被动漏洞扫描。被动扫描是 OWASP ZAP 在我们浏览过、发送数据和点击链接程中进行的非入侵测试。主动测试涉及对每个表单变量或请求值使用多种攻击字符串，以便检测服务器的响应是否带有我们叫做“脆弱行为”的东西。

OWASP ZAP 使用多种技术生成测试字串，它对于首次识别目标所使用的技术非常实用，以便优化我们的扫描并减少被检测到或导致服务崩溃的可能。

这个工具的另一个有趣特性是，我们可以产生于漏洞检测中的请求，而且它的相应响应在检测的时候会位于相同窗口中。这允许我们快读判断它是真正的漏洞还是误报，以及是否要开发我们的漏洞证明（POC）还是开始利用。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-3-5.jpg)

### 更多

我们已经谈论到 Burp Suite。Kali 只包含了免费版本，它没有主动和被动扫描特性。强烈推荐你获得 Burp Suite 的专业版许可证，因为它拥有实用特性和免费版之上的改进，例如主动和被动漏洞扫描。

被动漏洞扫描在我们使用 Burp Suite 作为浏览器的代理，并浏览网页时发生。Burp 会分析所有请求和响应，同时查找对应已知漏洞的模式。

在主动扫描中，Burp 会发送特定的请求给服务器并检查响应来查看是否对应一些漏洞模式。这些请求是特殊构造的，用于触发带有漏洞的应用的特定行为。

## 5.4 使用 w3af 扫描

w3af 支持应用审计和攻击框架。它是开源的，基于 Python 的 Web 漏洞扫描器。它拥有 GUI 和命令行界面，都带有相同的功能。这个秘籍中，我们会使用 w3af 的 GUI 配置扫描和报告选项来执行扫描。

### 操作步骤

1.  为了启动 w3af 我们可以从应用菜单栏选择它，通过浏览`Applications | 03 Web Application Analysis | w3af`，或者从终端中：

    ```
    w3af_gui
    ```
    
2.  在`Profiles `部分中，我们选择`full_audit`。

3.  在插件部分中，访问`crawl`并选择` web_spider `（已经选择的项目）。

4.  我们不打算让扫描器测试所有服务器，而是我们让它测试应用。在插件部分中，选中`only_forward`选项并点击`Save`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-4-1.jpg)
    
5.  现在，我们会告诉 w3af 在完成时生成 HTML 报告。访问`output `插件并选中`html_file`。

6.  为了选择文件名称和保存报告的位置，修改`output_file`选项。这里我们会指定根目录下的`w3af_report.html`，点击`Save`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-4-2.jpg)
    
7.  现在在`Target`文本框中，输入打算测试的 URL，这里是`http://192.168.56.102/WackoPicko/`，并点击`Start`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-4-3.jpg)

8.  日志标签页会获得焦点，我们能够看到扫描的进程。我们需要等待它完成。

9.  完成之后，切换到`Results`标签页，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-4-4.jpg)
    
0.  为了查看详细的报告，在浏览器中打开`w3af_report.html`HTML 文件。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-4-5.jpg)


### 工作原理

w3af 使用配置文件来简化为扫描选择插件的任务，例如，我们可以定义只含有 SQL 注入的配置文件，它测试应用的 SQL 注入，不干其他的事情。` full_audit `配置使用一些插件，它们执行爬虫测试、提取可以用作密码的单词列表、测试大多数相关的 Web 漏洞，例如 XSS、SQLi、文件包含、目录遍历以及其它。我们修改了`web_spider`插件来前向爬取，以便我们可以专注于打算测试的应用，避免扫描到其它应用。我们也修改了输出插件来生成 HTML 报告，而不是控制台输出和文本文件。

w3af 也拥有一些工具，例如拦截代理、模糊测试器、文本编解码器、以及请求导出器，它可以将原始的请求转换为多种语言的源代码。

### 更多

w3af 的 GUI 有时会不稳定。在它崩溃以及不能完成扫描的情况下，它的命令行界面可以提供相同的功能。例如，为了执行我们刚才执行的相同扫描，我们需要在终端中做下列事情：

```
w3af_console 
profiles
use full_audit 
back 
plugins 
output config html_file 
set output_file /root/w3af_report.html 
save 
back 
crawl config web_spider 
set only_forward True 
save 
back 
back 
target 
set target http://192.168.56.102/WackoPicko/ 
save 
back 
start
```

## 5.5 使用 Vega 扫描器

Vega 是由加拿大公司 Subgraph 制作的 Web 漏洞扫描器，作为开源工具分发。除了是扫描器之外，它也可以用作拦截代理，以及在我们浏览器目标站点时扫描。

这个秘籍中，我们会使用 Vega 来发现 Web 漏洞。

### 操作步骤

1.  从应用菜单中选择它，访问`Applications | Kali Linux | Web Applications | Web Vulnerability Scanners | vega`，或者通过终端来打开 Vega：

    ```
    vega
    ```
    
2.  点击“开始新扫描“按钮。

3.  新的对话框会弹出。在标为`Enter a base URI for scan`的输入框中，输入`http://192.168.56.102/WackoPicko`来扫描应用。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-5-1.jpg)
    
4.  点击`Next`。这里我们可以选择在应用上运行那个模块。让我们保持默认。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-5-2.jpg)

5.  点击`Finish`来开始扫描。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-5-3.jpg)
    
6.  当扫描完成时，我们可以通过访问左边的`Scan Alerts `树来检查结果。漏洞详情会在右边的面板中展示，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-5-4.jpg)
    
### 工作原理

Vega 的工作方式是首先爬取我们指定为目标的 URL，识别表单和其它可能的数据输入，例如 Cookie 或请求头。一旦找到了它们，Vega 尝试不同的输入，通过分析响应并将它们与已知漏洞模式匹配来识别漏洞。

在 Vega 中，我们可以扫描单个站点或范围内的一组站点。我们可以通过选择在扫描中使用的模块，来选择要进行哪种测试。同样，我们可以使用身份（预保存的用户/密码组合）或者会话 Cookie 来为站点认证，并且从测试中排除一些参数。

作为重要的缺陷，它并没有报告生成或数据导出特性。所以我们需要在 Vega GUI 中查看所有的漏洞描述和详情。

## 5.6 使用 Metasploit 的 Wmap 发现 Web 漏洞

Wmap 本身并不是漏洞扫描器，他是个 Metasploit 模块，使用所有框架中的 Web 漏洞和服务器相关的模块，并使它们协调加载和对目标服务器执行。它的结果并不会导出为报告，但是会作为 Metasploit 数据库中的条目。

这个秘籍中，我们会使用 Wmap 来寻找 vulnerable_vm 中的漏洞，并使用 Metasploit 命令行工具来检查结果。

### 准备

在我们运行 Metasploit 的控制台之前，我们需要启动 所连接的数据库服务器，以便保存我们生成的结果：

```
service postgresql start
```

### 操作步骤

1.  启动终端并运行 Metasploit 控制台：

    ```
    msfconsole 
    ```
    
2.  加载完成后，加载 Wmap 模块：

    ```
    load wmap 
    ```
    
3.  现在，我们向 Wamp 中添加站点：

    ```
    wmap_sites -a http://192.168.56.102/WackoPicko/ 
    ```
    
4.  如果我们打算查看注册的站点：

    ```
    wmap_sites -l 
    ```
    
5.  现在我们将这个站点设为扫描目标：

    ```
    wmap_targets -d 0 
    ```
    
6.  如果我们打算插件所选目标，我们可以使用：

    ```
    wmap_targets -l 
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-6-1.jpg)
    
7.  现在，我们执行测试：

    ```
    wmap_run -e
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-6-2.jpg)
    
8.  我们需要使用 Metasploit 的命令来检查记录的漏洞：

    ```
    vulns 
    wmap_vulns
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/5-6-3.jpg)
    
### 工作原理

Wmap 使用 Metasploit 的模块来扫描目标应用和服务器上的漏洞。它从 Metasploit 的数据库和模块中获取站点信息，并将结果发送到数据库中。这个集成的一个非常实用的层面是，如果我们执行多个服务器上的渗透测试，并且在测试中使用 Metasploit，Wmap 会自动获得所有 Web 服务器的 IP 地址，和已知 URL，并将它们集成为站点，以便当我们打算执行 Web 评估时，我们只需要从站点列表中选择目标。

在执行`wmap_run`的时候，我们可以选择要执行哪个模块。通过`-m`选项和正则表达式。例如，下面的命令行会开启所有模块，除了包含`dos`的模块，这意味着没有拒绝服务测试：

```
wmap_run -m ^((?!dos).)*$ 
```

另一个实用的选项是`-p`。它允许我们通过正则表达式选择我们打算测试的路径，例如，在下一个命令中，我们会检查所有包含单词`login`的 URL。

```
wmap_run -p ^.*(login).*$
```

最后，如果我们打算导出我们的扫描结果，我们总是可以使用 Metasploit 的数据库特性。例如，在 MSF 控制台中使用下列命令来将整个数据库导出为 XML 文件。

```
db_export -f xml /root/database.xml
```
