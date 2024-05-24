# CentOS7 Linux 服务器秘籍（四）

> 原文：[`zh.annas-archive.org/md5/85DEE4E32CF6CFC6347B684FDF685546`](https://zh.annas-archive.org/md5/85DEE4E32CF6CFC6347B684FDF685546)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：提供邮件服务

在本章中，我们将涵盖：

+   使用 Postfix 配置域内邮件服务

+   使用 Postfix

+   使用 Dovecot 投递邮件

+   使用 Fetchmail

# 简介

本章是一系列配方的集合，提供了实施和维护当今互联网上最古老、最多才多艺的技术之一的必要步骤。每个人都希望能够发送和接收电子邮件，本章提供了部署这种服务所需的起点，以便及时且高效地进行。

# 使用 Postfix 配置域内邮件服务

Postfix 是一个**邮件传输代理**（**MTA**），负责使用 SMTP 协议在邮件服务器之间传输电子邮件。Postfix 现在是 CentOS 7 上的默认 MTA。在这里，与其他大多数关键网络服务一样，其默认配置允许发送邮件，但不接受来自本地主机以外的任何主机的传入网络连接。如果你只需要一个本地 Linux 用户邮件系统，并且从 localhost 发送邮件到其他外部邮件服务器，这是有道理的。但如果你想为自己的私有网络和域运行自己的集中式邮件服务器，这就相当限制了。因此，本配方的目的是将 Postfix 设置为域内邮件服务，允许网络中的任何主机发送电子邮件，如果收件人是本地域内的有效电子邮件地址，则将其投递到邮件服务器上的正确邮箱。

## 准备工作

要完成本配方，你需要一个具有 root 权限的 CentOS 7 操作系统的安装，你选择的基于控制台的文本编辑器，以及连接到互联网以下载额外的软件包。你需要正确设置你的本地网络，并确保所有想要通过你的单域邮件服务器发送邮件的计算机都在同一个网络中，并且可以 ping 通这个服务器。此外，为任何邮件服务器正确设置系统时间也非常重要。在开始配置之前，请应用第二章，“配置系统”中的“使用 NTP 和 chrony 套件同步系统时钟”配方。最后，你需要为你的邮件服务器设置一个**完全限定域名**（**FQDN**）。请参考第二章，“配置系统”中的“设置你的主机名并解析网络”配方。预计你的服务器将使用静态 IP 地址，并且它将维护一个或多个系统用户帐户。还假设你将按照本章中出现的顺序逐个配方地工作。

## 如何操作...

Postfix 默认安装在所有 CentOS 7 版本上，并且应该处于运行状态。在我们的示例中，我们希望为我们的网络 192.168.1.0/24 构建一个中央邮件服务器，其本地域名为`centos7.home`。

1.  首先以 root 身份登录，并测试 Postfix 是否已经在本地工作，并且可以向您的系统用户发送本地邮件。输入以下命令向指定的 Linux 用户`<username>`发送邮件：

    ```
    echo "This is a testmail" | sendmail <username>

    ```

1.  在 CentOS 7 上，Postfix 也已经配置为无需对配置文件进行任何更改即可向外部电子邮件地址发送邮件（但仅从 localhost）。例如，您可以直接使用：

    ```
    echo "This is a testmail" | sendmail contact@example.com

    ```

    ### 注意

    如果您没有受信任的域和证书支持您的 Postfix 服务器，在大量垃圾邮件的时代，大多数外部邮件服务器将拒绝或将此类邮件直接放入垃圾邮件文件夹。

1.  要查看本地邮件是否已成功投递，请显示最新的邮件日志（按*Ctrl*+*C*退出日志）：

    ```
    tail -f /var/log/maillog

    ```

1.  接下来，检查我们的服务器是否有可用的 FQDN。这是强制性的，如果没有正确设置，请参阅第二章，*配置系统*以设置一个（在我们的示例中，这将输出名称`mailserver.centos7.home`）：

    ```
    hostname --fqdn

    ```

1.  现在在打开此文件之前创建主 Postfix 配置文件的备份副本：

    ```
    cp /etc/postfix/main.cf /etc/postfix/main.cf.BAK && vi /etc/
    postfix/main.cf

    ```

1.  首先，我们希望 Postfix 监听所有网络接口，而不仅仅是本地接口。激活或取消注释以下行（这意味着删除行首的`#`符号），该行以`inet_interfaces`开头，使其读取如下：

    ```
    inet_interfaces = all

    ```

1.  现在，在下面的一些行中，您会找到读取`inet_interfaces = localhost.`的行。通过在行首放置一个`#`符号来禁用它或注释掉它：

    ```
    # inet_interfaces = localhost

    ```

1.  接下来，我们需要设置邮件服务器的本地域名。例如，如果我们的邮件服务器的 FQDN 是`mailserver.centos7.home`，并且这个邮件服务器负责为整个私有`centos7.home`域投递邮件，那么域名将是（最好将其放在读取`#mydomain = domain.tld`的行下方）：

    ```
    mydomain = centos7.home

    ```

1.  考虑到此服务器可能成为域范围内的邮件服务器，您现在应该更新以下以`mydestination`开头的行，使其读取如下（例如，在`mydestination`部分，注释掉第一行`mydestination`并取消注释第二行）：

    ```
    mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain

    ```

1.  接下来，我们需要指定相对于用户主目录的邮箱文件路径名。为此，向下滚动并找到以`home_mailbox`开头的行，并取消注释以下选项（删除行首的`#`符号）：

    ```
    home_mailbox = Maildir/

    ```

1.  保存并关闭文件。现在我们希望在防火墙中打开正确的 Postfix 服务器端口，以允许服务器接收 SMTP 连接：

    ```
    firewall-cmd --permanent --add-service=smtp && firewall-cmd --reload

    ```

1.  接下来，如下重新启动 Postfix 服务：

    ```
    systemctl restart postfix

    ```

1.  之后，登录到同一网络中的另一台计算机并安装**瑞士军刀 SMTP**（**swaks**），以远程测试我们的 Postfix 服务器连接。在 CentOS 上，输入以下内容（需要事先安装 EPEL 存储库）：

    ```
    yum install swaks

    ```

1.  现在，为了测试是否可以使用标准 SMTP 邮件端口 25 连接到我们新的 Postfix 服务器，我们的 Postfix 服务器运行在 IP 地址`192.168.1.100`，我们远程发送一封邮件给 Linux 系统用户`john`，他在我们的 Postfix 服务器上有一个系统用户账户：

    ```
    swaks --server 192.168.1.100 --to john@centos7.home

    ```

1.  Swaks 创建的输出应该给我们一个提示，表明邮件传输是否成功。例如（输出已被截断）：

    ```
    -> This is a test mailing
    <-  250 2.0.0 Ok: queued as D18EE52B38
     -> QUIT
    <-  221 2.0.0 Bye
    ```

1.  您还可以通过以用户`john`登录到 Postfix 服务器，然后检查并阅读您的本地邮箱收件箱，来测试最后一个命令是否成功，收件箱应该包含一个由 swaks 工具发送的测试邮件的文件（文件名在您的计算机上会有所不同），如下所示：

    ```
    ls ~/Maildir/new
    less ~/Maildir/new/14941584.Vfd02I1M246414.mailserver.centos7.home

    ```

## 它是如何工作的...

我们已经看到，Postfix 默认安装并运行在每个 CentOS 7 系统上，在其基本配置中，邮件服务器监听本地主机地址以接收邮件，因此您已经可以在服务器本地 Linux 系统用户之间发送本地邮件，而无需联系外部 MTA。它已经在运行，因为您的系统已经在使用它为多个本地服务，例如 crond 守护进程或发送关于安全漏洞的警告（例如，以非 sudo 用户身份运行`sudo`命令）。

在我们解释这个配方是如何工作之前，我们需要回顾一些关于 Postfix MTA 系统的更多基础知识。Postfix MTA 服务可以接收来自邮件客户端或其他远程 MTA 服务器的传入电子邮件，使用 SMTP 协议。如果传入的电子邮件是针对 MTA 服务器配置的最终目的地域（例如，一封发送到收件人地址`john@centos7.home`的邮件传入到配置的`centos7.home` Postfix MTA 服务器），它将把邮件投递到服务器上安装的本地邮箱（无论是在文件系统中还是在数据库系统中，如 MariaDB）。如果传入的邮件不是针对这个服务器，它将被转发（转发）到另一个 MTA。

请记住，这就是 Postfix 服务器所能做的一切，不多也不少：接收来自邮件客户端或其他 MTA 的传入 SMTP 连接，将邮件投递到服务器上的本地邮箱，并使用 SMTP 将邮件转发到其他 MTA。与普遍看法相反，Postfix 不能将其本地邮箱中的邮件传输给最终用户。这里我们需要另一种类型的 MTA，称为**投递代理**，它使用不同的邮件协议，如 IMAP 或 POP3。

在这个方法中，我们配置了我们的 Postfix 服务器，以便同一网络中的其他计算机和服务器也可以向我们的 Postfix 服务器发送邮件，这些邮件默认是被阻止的（默认情况下只有服务器本身可以发送邮件）。如果从我们网络中的另一台计算机发送的入站电子邮件，其收件人的电子邮件地址中的域名与我们的 Postfix 服务器的 FQDN 相同，那么它将被传递到由电子邮件的收件人部分定义的适当的本地邮箱；所有外部电子邮件地址都会被转发到一个外部 MTA。

那么我们从这次经历中学到了什么？

我们首先测试了是否可以向系统用户发送本地邮件。在这里，我们以 root 用户身份登录，并使用 Postfix 软件包中包含的 sendmail 程序向有效的本地系统用户发送邮件。每当你使用 sendmail 发送邮件时，你应该能够在`/var/log/maillog`文件中看到一些新行出现，该文件包含邮件的状态信息和其他重要的日志文本。如果你从`root`向用户`john`发送了一条消息，并且你的服务器的 FQDN 是`centos7.home`，那么追加到日志文件的新输出行应该包含一些内容，例如`from=<root@centos7.home>`，`to=<john@centos7.home>`，以及如果成功交付，则包含`status=sent`信息。如果没有出现这样的日志信息，请检查 Postfix 服务的运行状态。

随后，我们展示了我们服务器的 FQDN。正确设置这一点非常重要，因为这些信息将用于在连接到其他 MTA 或邮件客户端时对 Postfix 服务器进行身份验证。MTA 会检查其合作伙伴宣布的 FQDN，有些甚至会拒绝连接，如果未提供或与服务器的实际 DNS 域名不同。在我们的初步测试之后，我们开始编辑 Postfix 的主配置文件，首先对其进行了备份。如前所述，默认情况下，只有位于运行 Postfix 服务的同一服务器上的用户才能在它们之间发送邮件，因为服务器默认仅监听环回设备。因此，我们首先启用了 Postfix 以监听所有可用网络接口，使用`inet_interfaces = all`参数。这确保了我们网络中的所有客户端都可以连接到此服务器。接下来，我们使用`mydomain`参数设置了我们想要的 Postfix 域名。为了使 Postfix 在我们的网络中工作，此处定义的域名变量的值必须与我们的服务器网络的域名完全相同。之后，我们通过选择添加`$mydomain`参数的行来更改`mydestination`参数。这将定义我们的 Postfix 邮件服务器视为最终目的地的所有域。如果 Postfix 邮件服务器被配置为某个域的最终目的地，它将把消息投递到接收用户的本地邮箱，可以在`/var/spool/mail/<username>`（我们将在下一步更改此位置）而不是将邮件转发到其他 MTA（由于我们在示例中将`$mydomain`添加到了最终目的地的列表中，我们将投递所有发送到`centos7.home`域的邮件）。

在这里，您还需要记住，默认情况下，Postfix *信任*与 Postfix 服务器位于同一 IP 子网中的所有其他计算机（SMTP 客户端），以便通过我们的中央服务器向外部电子邮件地址发送邮件（转发邮件到外部 MTAs），这可能对您的网络策略来说过于宽松。由于电子邮件垃圾邮件是互联网上的一个持续问题，我们不希望允许任何用户滥用我们的邮件服务器发送垃圾邮件（开放中继邮件服务器会这样做；它从任何客户端接收任何内容并将其发送到任何邮件服务器），我们可以通过设置`mynetworks_style = host`来进一步提高安全性，该设置仅信任并允许本地主机向外部 MTAs 发送邮件。减少垃圾邮件风险的另一种方法可能是使用`mynetworks`参数，您可以在其中指定允许连接到我们的邮件服务器并通过它发送电子邮件的网络或 IP 地址；例如，`mynetworks = 127.0.0.0/8, 192.168.1.0/24`。要了解更多关于所有可用 Postfix 设置的信息，请参考 Postfix 配置参数手册，使用命令`man 5 postconf`。之后，我们更改了本地邮件应该存储的位置。默认情况下，所有传入邮件都发送到位于`/var/spool/mail/<username>`的中央邮箱空间。为了使本地用户能够在自己的主目录中接收邮件，我们为`home_mailbox`选项使用了`Maildir`参数，该参数将系统更改为将所有邮件发送到`/home/<username>/Maildir/`而不是。之后，我们在 firewalld 中打开了标准 SMTP 协议端口，使用 Postfix 用于与其他 MTAs 或发送传入邮件的邮件客户端通信的 SMPT 服务。

Postfix 已经配置为在启动时启动，但为了完成本节食谱，我们重新启动了 Postfix 服务，以便它接受新的配置设置。在这一阶段，配置 Postfix 的过程已经完成，但为了测试远程访问，我们需要登录到同一网络中的另一台计算机。在这里，我们安装了一个名为`swaks`的小型基于命令行的邮件客户端，它可以用来测试本地或远程 SMTP 服务器连接。我们通过向我们的远程 Postfix 邮件服务器发送邮件并提供收件人用户和我们的 SMTP 服务器的 IP 地址来运行测试。完成此操作后，您应该已收到测试消息，并且作为结果，您应该很高兴知道一切正常工作。但是，如果您碰巧遇到任何错误，则应参考位于`/var/log/maillog`的邮件服务器日志文件。

## 还有更多...

在本节食谱中，我们将更改您的电子邮件发件人地址，加密 SMTP 连接，并配置您的 BIND DNS 服务器以包含我们新邮件服务器的信息。

### 更改电子邮件的显示域名

如果一个 MTA 发送电子邮件，Postfix 默认会自动在发件人的电子邮件地址后附加主机名，除非另有明确说明，这是一个很好的功能，可以帮助你在本地网络中追踪哪台计算机发送了电子邮件（否则，如果你有多台计算机通过名为**root**的用户发送邮件，那么找到邮件的原始来源将会很困难）。通常在向远程 MTA 发送消息时，你不希望本地主机名出现在电子邮件中。

这里最好只保留域名。为了改变这一点，转到你想要从中发送邮件的 Postfix MTA，打开 Postfix 配置文件`/etc/postfix/main.cf`，并通过取消注释（删除行首的`#`符号）以下行来启用此功能以确定原始来源（之后重新启动 Postfix 服务）：

```
myorigin = $mydomain

```

### 使用 TLS-（SSL）加密进行 SMTP 通信

即使你在一个小型或私人环境中运行自己的 Postfix 服务器，也应该始终意识到，正常的 SMTP 流量将通过互联网以明文形式发送，这使得任何人都有可能嗅探通信。TLS 将允许我们在服务器和邮件客户端之间建立加密的 SMTP 连接，这意味着整个通信将被加密，第三方无法读取。为了做到这一点，如果你还没有购买官方 SSL 证书或为你的域名生成一些自签名证书，请先在这里创建一个（阅读第六章，*提供安全*中的*生成自签名证书*配方了解更多信息）。首先以 root 用户登录到你的服务器，然后转到标准证书位置：`/etc/pki/tls/certs`。接下来，创建一个包含证书及其嵌入的公钥以及私钥的 TLS/SSL 密钥对（输入你的 Postfix 的 FQDN 作为`通用名称`，例如，`mailserver.centos7.home`），为此输入`make postfix-server.pem`。之后，使用你喜欢的文本编辑器打开 Postfix 主配置文件`/etc/postfix/main.cf`，并在文件末尾添加以下行：

```
smtpd_tls_cert_file = /etc/pki/tls/certs/postfix-server.pem
smtpd_tls_key_file = $smtpd_tls_cert_file
smtpd_tls_security_level = may
smtp_tls_security_level = may
smtp_tls_loglevel = 1
smtpd_tls_loglevel = 1
```

然后保存并关闭此文件。请注意，将`smtpd_tls_security_level`设置为`may`将激活 TLS 加密（如果邮件客户端程序中可用），否则将使用未加密的连接。只有在您绝对确定所有向您的邮件服务器发送邮件的用户都支持此功能时，才应将此值设置为`encrypt`（这将强制在任何情况下都使用 SSL/TLS 加密）。如果任何发送者（外部 MTA 或邮件客户端）不支持此功能，连接将被拒绝。这意味着来自这些来源的电子邮件将不会被投递到您的本地邮箱。我们还为从我们的 Postfix 服务器到其他 MTAs 的可能的出站 SMTP 连接指定了 TLS 加密，使用`smtp_tls_security_level = may`。通过将 Postfix 的客户端和服务器模式 TLS 日志级别设置为`1`，我们可以获得更详细的输出，以便检查 TLS 连接是否正常工作。一些非常古老的邮件客户端使用古老的 465 端口进行 SSL/TLS 加密的 SMTP，而不是标准的 25 端口。

为了激活此功能，打开`/etc/postfix/master.cf`并搜索，然后取消注释（删除每行开头的`#`）以下行，使其读作：

```
smtps       inet   n       -       n       -       -       smtpd
-o syslog_name=postfix/smtps
-o smtpd_tls_wrappermode=yes
```

保存并关闭文件，然后重新启动 Postfix。接下来，我们需要在防火墙中打开 SMTPS 端口，以允许传入连接到我们的服务器。由于 CentOS 7 中没有可用的 SMTPS firewalld 规则，我们将首先使用`sed`实用程序创建我们自己的服务文件：

```
sed 's/25/465/g' /usr/lib/firewalld/services/smtp.xml | sed 's/Mail (SMTP)/Mail (SMTP) over SSL/g' > /etc/firewalld/services/smtps.xml
firewall-cmd --reload
firewall-cmd --permanent --add-service=smtps; firewall-cmd --reload

```

现在，您应该能够测试是否可以使用我们的`swaks`SMTP 命令行工具，使用`-tls`参数从远程计算机到运行在 IP 192.168.1.100 上的 Postfix 服务器建立 SMTPS 连接，例如`swaks --server 192.168.1.100 --to john@centos7.home -tls`。此命令行将测试 SMTP 服务器是否支持 TLS 加密（`STARTTLS`），并在任何原因不可用时退出并显示错误消息。正常工作的输出将如下所示（截断以仅向您显示最重要的行）：

```
 -> STARTTLS
<-  220 2.0.0 Ready to start TLS
=== TLS started with cipher TLSv1.2:ECDHE-RSA-AES128-GCM-SHA256:128
 ~> This is a test mailing
<~  250 2.0.0 Ok: queued as E36F652B38
```

然后，您还可以通过转到 Postfix 服务器上的主邮件日志文件并查找与上一步的 swaks 测试邮件相对应的以下行（您的输出将不同）来重新检查您的 TLS 设置：

```
Anonymous TLS connection established from unknown[192.168.1.22]: TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits)
```

### 配置 BIND 以使用您的新邮件服务器

在我们的域内 Postfix 服务器安装和配置完成后，我们现在应该使用 DNS 服务器在我们的域中宣布这一新的邮件服务。请参考第八章，*使用 FTP*，了解如何设置和配置 BIND 服务器，特别是如果您还没有阅读过，请阅读有关**邮件交换器**（**MX**）记录的部分。然后在您的 BIND 正向和相应的反向区域文件中添加一个新的 MX 记录。在您的正向区域文件中，为我们的 Postfix 服务器添加以下行，IP 为`192.168.1.100`：

```
IN      MX      10      mailhost.centos7.home.
mailhost                   IN      A       192.168.1.100
```

在您的反向区域文件中，您可以添加以下行：

```
100                 IN  PTR         mailhost.centos7.local.
```

# 使用 Postfix

在前面的一个教程中，我们学习了如何安装和配置 Postfix 作为我们的域内电子邮件服务器。在处理电子邮件时，Linux 提供了许多不同的工具和程序，我们已经向您展示了如何通过`sendmail`程序以及`swaks`工具发送电子邮件。在本教程中，我们将向您展示如何使用 Unix 和 Linux 中最常用的邮件工具之一，名为`mailx`，它具有`sendmail`包中缺少的一些有用功能，用于发送邮件或阅读您的邮箱。

## 如何操作...

我们将从在我们的服务器上安装`mailx`包开始，该服务器运行我们的域内 Postfix 服务，因为默认情况下 CentOS 7 上不提供它。

1.  首先以 root 身份登录并键入以下命令：

    ```
    yum install mailx

    ```

1.  最简单的方法是使用`mailx`的标准输入模式，如下所示：

    ```
    echo "this is the mail body." | mail -s "subject" john@centos7.home

    ```

1.  您还可以从文本文件发送邮件。这在从 shell 脚本调用`mailx`命令时很有用，使用多个收件人，或者向电子邮件附加一些文件：

    ```
    cat ~/.bashrc | mail -s "Content of roots bashrc file" john
    echo "another mail body" | mail -s "body" john,paul@example.com,chris
    echo "this is the email body" | mailx -s "another testmail but with attachment" -a "/path/to/file1" -a "/path/to/another/file" john@gmail.com

    ```

### 将 mailx 连接到远程 MTA

`mailx`相对于`sendmail`程序的一大优势是，我们可以直接连接并与远程 MTA 邮件服务器通信。为了测试这一功能，请登录到另一台基于 Linux 的计算机，该计算机应与我们的 Postfix 服务器位于同一网络中，安装`mailx`包，并通过我们的 Postfix 服务器的 IP 地址`192.168.1.100`发送邮件（我们已经在之前的教程中打开了传入 SMTP 防火墙端口）。在我们的示例中，我们将向用户`john`发送一封本地邮件：

```
echo "This is the body" | mail -S smtp=192.168.1.100 -s "This is a remote test" -v john@centos7.home

```

### 从邮箱中阅读本地邮件

不仅`mailx`程序可以将电子邮件消息发送到任何 SMTP 服务器，当在 Postfix 服务器上本地启动时，它还提供了一个方便的邮件阅读器界面，用于您的本地邮箱。如果您使用`-f`指定用户邮箱运行邮件程序，程序将开始显示所有收件箱电子邮件。但请记住，`mailx`只能在程序在同一服务器上启动时读取本地邮箱（如果您想使用它远程访问您的邮箱，则需要安装 MTA 访问代理，如 Dovecot—稍后介绍—使用 POP3 或 IMAP）。例如，作为 Linux 系统用户`john`登录到 Postfix 服务器，然后，要使用您的用户的本地邮箱打开邮件阅读器，请键入：`mailx -f ~/Maildir`。

现在你将看到当前收件箱中所有邮件消息的列表。如果你想阅读特定的邮件，你需要输入它的编号并按下*回车*键。阅读后，你可以输入*d*后跟*回车*来删除它，或者输入*r*后跟*回车*来回复它。要返回到当前邮件消息概览屏幕，输入*z*后跟*回车*。如果你有超过一屏的邮件消息，输入*z-*（z 减号）后跟*回车*来返回一页。输入*x*后跟*回车*来退出程序。要了解更多信息，请参考`mailx`手册（`man mailx`）。

## 它是如何工作的...

在这个示例中，我们展示了如何安装和使用`mailx`，这是一个用于发送和阅读互联网邮件的程序。它基于一个名为 Berkely mail 的旧 Unix 邮件程序，并提供了 POSIX `mailx`命令的功能。它应该安装在每个严肃的 CentOS 7 服务器上，因为它比`sendmail`程序有一些优势，并且理解 IMAP、POP3 和 SMTP 协议（如果你需要一个更加用户友好的邮件阅读器和发送器，你可以查看 mutt。输入`yum install mutt`来安装它。然后输入`man mutt`来阅读它的手册）。

我们从这次经历中学到了什么？

我们首先在 Postfix 服务器上使用 YUM 包管理器安装了`mailx`包。它包含了`mailx`命令行程序，可以通过`mail`或`mailx`命令运行。之后，我们使用`-s`参数运行程序，该参数指定电子邮件主题，并且还需要一个收件人电子邮件地址作为参数，可以是外部地址或本地 Linux 系统用户名或邮件。如果没有其他设置，`mailx`会默认它与邮件服务器在同一台服务器上运行，因此它会隐式地将邮件发送到本地主机 MTA，在我们的例子中是 Postfix。此外，在最简单的形式中，`mailx`启动时进入交互模式，允许你在命令行手动输入消息正文字段。这对于快速编写测试邮件很有用，但在大多数情况下，你会通过管道将内容从另一个来源输入到`mailx`。这里我们展示了如何使用`echo`命令将字符串写入`mailx`的标准输入（STDIN），但你也可以使用`cat`命令将文件内容输入到`mailx`。

一个常用的例子是通过`cron`在特定预定时间点将某种文件输出或失败命令的日志文件内容发送给管理员用户或系统报告。之后，我们发现可以通过逗号分隔电子邮件地址的方式向多个收件人发送邮件，并向您展示了如何使用`-a`选项在邮件中附带附件。在下一节中，我们向您展示了如何使用`-S`选项设置内部选项（`variable=value`）向远程 SMTP 邮件服务器发送邮件。如果您未在 DNS 服务器上指定标准邮件服务器，或者需要测试远程邮件服务器，这是一个非常有用的功能。最后，在最后一节中，我们向您展示了如何使用`mailx`在您的 Postfix 服务器上阅读本地邮箱。它具有方便的浏览功能，可以阅读、删除和回复，并为您的本地邮箱进行高级电子邮件管理。您可以通过在`mailx`交互式会话中输入命令，然后按下*回车*键来实现这一点。请记住，如果您不喜欢这种方式浏览邮件，您还可以始终使用命令行工具（如`grep`、`less`等）在用户`~/Maildir`目录中阅读或过滤邮件。例如，要搜索所有新邮件中区分大小写的`PackPub.com`关键字，请输入`grep -i packtpub ~/Maildir/new`。

# 使用 Dovecot 发送邮件

在之前的操作中，您已经了解了如何将 Postfix 配置为域范围的邮件传输代理。正如我们在本章第一个操作中学到的，Postfix 只理解 SMTP 协议，并且在将消息从另一个 MTA 或邮件用户客户端传输到其他远程邮件服务器或将邮件存储到其本地邮箱方面做得非常出色。存储或转发邮件后，Postfix 的工作就结束了。Postfix 只能理解和使用 SMTP 协议，并且不能将消息发送到除 MTA 之外的任何其他地方。邮件消息的任何可能的收件人现在都需要使用 ssh 登录到运行 Postfix 服务的服务器，并查看其本地邮箱目录，或者使用`mailx`本地查看其消息，以定期检查是否有新邮件。这是非常不方便的，没有人会使用这样的系统。相反，用户选择从自己的工作站访问和阅读邮件，而不是从我们的 Postfix 服务器所在的位置。因此，开发了另一组 MTA，有时称为**访问代理**，其主要功能是将本地邮箱消息从运行 Postfix 守护程序的服务器同步或传输到外部邮件程序，用户可以在其中阅读这些消息。这些 MTA 系统使用不同于 SMTP 的协议，即 POP3 或 IMAP。其中一个 MTA 程序是 Dovecot。大多数专业服务器管理员都认为 Postfix 和 Dovecot 是完美的合作伙伴，本操作的目的是学习如何配置 Postfix 与 Dovecot 配合工作，以便为我们的邮箱提供基本的 POP3/IMAP 和 POP3/IMAP over SSL（POP3S/IMAPS）服务，为本地网络上的用户提供行业标准的电子邮件服务。

## 准备就绪

要完成此操作，您需要一个具有 root 权限的 CentOS 7 操作系统的工作安装，您选择的基于控制台的文本编辑器，以及连接到互联网以下载其他软件包。还假设您按照本章中出现的顺序逐个操作，因此预计已将 Postfix 配置为域范围的邮件传输代理。

### 注意

本操作作为设置本地网络上受信任用户的 POP3S/IMAPS 服务的指南。如果不采取额外的安全措施，则不适合在互联网上使用。

## 如何操作...

Dovecot 默认不安装，因此我们必须首先按照给出的步骤安装必要的软件包：

1.  首先，以 root 身份登录并输入以下命令：

    ```
    yum install dovecot

    ```

1.  安装后，通过输入以下命令在启动时启用 Dovecot 服务：

    ```
    systemctl enable dovecot

    ```

1.  现在，在创建备份副本后，使用您喜欢的文本编辑器打开 Dovecot 主配置文件，方法是输入：

    ```
    cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.BAK
    vi /etc/dovecot/dovecot.conf

    ```

1.  首先通过激活（删除行首的`#`符号）并修改以下行来确认我们要使用的`协议`，使其读作：

    ```
    protocols = pop3 imap imaps pop3s

    ```

1.  接下来，启用 Dovecot 监听所有网络接口而不仅仅是回环地址。搜索行`#listen = *`, `::`，然后将其修改为：

    ```
    listen = *

    ```

1.  现在以通常的方式保存并关闭文件，然后在您最喜欢的文本编辑器中打开`10-mail.conf`文件之前，先对其进行备份：

    ```
    cp /etc/dovecot/conf.d/10-mail.conf /etc/dovecot/conf.d/10-mail.conf.BAK
    vi /etc/dovecot/conf.d/10-mail.conf

    ```

1.  向下滚动并取消注释（删除`#`字符）以下行，使其读作：

    ```
    mail_location = maildir:~/Maildir

    ```

1.  再次，在创建备份副本之前，以通常的方式保存并关闭文件，然后在您最喜欢的文本编辑器中打开以下文件：

    ```
    cp /etc/dovecot/conf.d/20-pop3.conf /etc/dovecot/conf.d/20-pop3.conf.BAK
    vi /etc/dovecot/conf.d/20-pop3.conf

    ```

1.  首先取消注释以下行：

    ```
    pop3_uidl_format = %08Xu%08Xv

    ```

1.  现在向下滚动并修改以下行：

    ```
    pop3_client_workarounds = outlook-no-nuls oe-ns-eoh

    ```

1.  以通常的方式保存并关闭文件。现在我们将允许纯文本登录。为此，在打开以下文件之前先进行备份：

    ```
    cp /etc/dovecot/conf.d/10-auth.conf /etc/dovecot/conf.d/10-auth.conf.BAK
    vi /etc/dovecot/conf.d/10-auth.conf

    ```

1.  将行`#disable_plaintext_auth = yes`更改为：

    ```
    disable_plaintext_auth = no

    ```

1.  保存并关闭文件。在我们的最终配置设置中，我们将告诉 Dovecot 使用我们的自签名服务器证书。只需使用本章另一食谱中的 Postfix 证书或创建一个新的（否则跳过此步骤）：

    ```
    cd /etc/pki/tls/certs; make postfix-server.pem

    ```

1.  在备份文件后打开 Dovecot 的标准 SSL 配置文件：

    ```
    cp /etc/dovecot/conf.d/10-ssl.conf /etc/dovecot/conf.d/10-ssl.conf.BAK
    vi /etc/dovecot/conf.d/10-ssl.conf

    ```

1.  现在将以下行（`ssl = required`）更改为读作：

    ```
    ssl = yes

    ```

1.  现在将以下两行更改为指向您服务器自己的证书路径：

    ```
    ssl_cert = < /etc/pki/tls/certs/postfix-server.pem
    ssl_key = </etc/pki/tls/certs/postfix-server.pem

    ```

1.  保存并关闭此文件。接下来，在我们的防火墙中启用 IMAP、IMAPS、POP3 和 POP3S 端口，以允许在相应端口上的传入连接。对于 POP3 和 IMAP，我们需要指定自己的`firewalld`服务文件，因为它们在 CentOS 7 中默认不可用：

    ```
    sed 's/995/110/g' /usr/lib/firewalld/services/pop3s.xml | sed 's/ over SSL//g' > /etc/firewalld/services/pop3.xml
    sed 's/993/143/g' /usr/lib/firewalld/services/imaps.xml | sed 's/ over SSL//g' > /etc/firewalld/services/imap.xml
    firewall-cmd --reload
    for s in pop3 imap pop3s imaps; do firewall-cmd --permanent --add-service=$s; done;firewall-cmd --reload

    ```

1.  现在在启动 Dovecot 服务之前保存并关闭文件：

    ```
    systemctl start dovecot

    ```

1.  最后，为了测试我们的新 POP3/SMTP 网络服务，只需在同一网络中的另一台计算机上登录并运行以下命令，使用`mailx`访问远程 Postfix 服务器上的本地邮箱，该服务器由 Dovecot 提供，使用不同的访问代理协议。在我们的示例中，我们希望使用 IP `192.168.1.100`远程访问系统用户`john`在 Postfix 服务器上的本地邮箱（要登录到 john 的账户，您需要他的 Linux 用户密码）：

    ```
    mailx -f pop3://john@192.168.1.100
    mailx -f imap://john@192.168.1.100

    ```

1.  接下来，为了测试安全连接，使用以下命令并在确认证书是自签名且不受信任时输入`yes`：

    ```
    mailx -v -S nss-config-dir=/etc/pki/nssdb -f pop3s://john@192.168.1.100
    mailx -v -S nss-config-dir=/etc/pki/nssdb -f imaps://john@192.168.1.100

    ```

1.  对于所有四个命令，您应该看到用户`john`邮箱的正常`mailx`收件箱视图，其中包含所有邮件消息，就像您在 Postfix 服务器上本地运行`mailx`命令以阅读本地邮件一样。

## 工作原理...

成功完成此配方后，您刚刚为网络中的所有有效服务器用户创建了一个基本的 POP3/SMTP 服务（带或不带 SSL 加密），该服务将从 Postfix 服务器向客户端的电子邮件程序传递本地邮件。每个本地系统用户都可以直接进行身份验证并连接到邮件服务器，并远程获取他们的邮件。当然，还有很多可以做的事情来增强服务，但现在您可以让所有本地系统账户持有者配置他们最喜欢的电子邮件桌面软件，使用您的服务器发送和接收电子邮件消息。

### 注意

与 IMAP 不同，POP3 将邮件从服务器下载到本地机器上，并在之后删除它们，而 IMAP 则与邮件服务器同步您的邮件，而不删除它们。

那么我们从这次经历中学到了什么？

我们首先通过安装 Dovecot 来开始这个配置过程。完成这一步后，我们启用了 Dovecot 在启动时运行，并接着对一系列配置文件进行了一些简短的修改。首先，我们需要确定在`/etc/dovecot/dovecot.cf`文件中的 Dovecot 配置文件中将使用哪种协议：IMAP、POP3、IMAPS 和 POP3S。与其他大多数基本的网络服务一样，安装后它们仅监听回环设备，因此我们启用了 Dovecot 以监听服务器上安装的所有网络接口。在`10-mail.conf`文件中，我们确认了 Dovecot 的邮箱目录位置（使用`mail_location`指令），这是 Postfix 在接收邮件时将它们放入的位置，以便 Dovecot 可以在这里找到它们并拾取。接下来，我们在`20-pop3.conf`文件中打开了 POP3 协议，添加了一个与各种电子邮件客户端（例如 Outlook 客户端）相关的修复，使用了`pop3_uidl_format`和`pop3_client_workarounds`指令。最后，我们通过在`/etc/dovecot/conf.d/10-auth.conf`文件中进行几处更改，启用了纯文本授权。请记住，在没有 SSL 加密的情况下使用纯文本授权与 POP3 或 IMAP 被认为是不安全的，但由于我们专注于局域网（为一组可信的服务器用户），我们不一定将此视为风险。之后，我们通过将`10-ssl.conf`文件中的`ssl`指令指向一些现有的自签名服务器证书，启用了 POP3 和 IMAP 的 SSL（POP3S 和 IMAPS）。在这里，我们将`ssl = required`更改为`ssl=yes`，以不强制客户端连接到 Dovecot 服务时使用 SSL 加密，因为我们确实希望给用户选择启用加密认证的选项，但如果他喜欢的话，不要将其作为强制性的，特别是对于较旧的客户端。之后，为了让我们的 Dovecot 服务可以从网络中的其他计算机访问，我们必须启用四个端口以允许 POP3、IMAP、POP3S 和 IMAPS，即 993、995、110、143，通过使用预定义的`firewalld`服务文件并为我们自己创建缺失的 IMAP 和 POP3 文件。稍后，我们启动了 Dovecot 服务，并使用`mailx`命令远程测试了我们新的 POP3/IMAP 服务器。通过提供一个`-f`文件参数，我们能够指定我们的协议和位置。对于使用 SSL 连接，我们需要提供一个额外的`nss-config-dir`选项，指向我们在 CentOS 7 中存储证书的本地网络安全性服务数据库。

记住，如果你遇到任何错误，你应该始终参考位于`/var/log/maillog`的日志文件。在真正的企业环境中不应使用纯文本授权，而应首选 POP3/IMAP 的 SSL。

## 还有更多...

在主配方中，你被展示了如何安装 Dovecot 以允许具有系统账户的受信任本地系统用户发送和接收电子邮件。这些用户将能够使用他们现有的用户名作为电子邮件地址的基础，但通过做一些改进，你可以快速启用别名，这是一种为现有用户定义替代电子邮件地址的方式。

要开始构建用户别名列表，你应该首先在你的首选文本编辑器中打开以下文件：

```
vi /etc/aliases

```

现在将你的新身份添加到文件末尾，其中`<username>`将是实际系统账户的名称：

```
#users aliases for mail
newusernamea:    <username>
newusernameb:    <username>

```

例如，如果你有一个名为`john`的用户，目前仅接受来自`john@centos7.home`的电子邮件，但你想为`john`创建一个名为`johnwayne@centos7.home`的新别名，你将这样写：

```
johnwayne:    john

```

为所有别名重复此操作，但完成后记得以通常的方式保存并关闭文件，然后运行以下命令：`newaliases`。

### 设置电子邮件软件

市场上有大量的电子邮件客户端，到目前为止，你将希望开始设置你的本地用户能够发送和接收电子邮件。这并不复杂，但为了有一个良好的起点，你将希望考虑以下原则。电子邮件地址的格式将是`system_username@domain-name.home`。

传入的 POP3 设置将类似于以下内容：

```
mailserver.centos7.home, Port 110
Username: system_username
Connection Security: None
Authentication: Password/None
```

对于 POP3S，只需将端口更改为`995`并使用`连接安全性`：`SSL/TLS`。对于 IMAP，只需将端口更改为`143`，对于 IMAPS 使用端口`993`和`连接安全性`：`SSL/TLS`。

外发的 SMTP 设置将类似于以下内容：

```
mailserver.centos7.home, Port 25
Username: system_username
Connection Security: None
Authentication: None
```

# 使用 Fetchmail

到目前为止，在本章中，我们已经向您展示了两种不同形式的 MTA。首先，我们向您介绍了 Postfix MTA，这是一种用于将电子邮件从邮件客户端路由到邮件服务器或邮件服务器之间，并使用 SMTP 协议将它们传递到邮件服务器上的本地邮箱的传输代理。然后，我们向您展示了另一种有时称为访问代理的 MTA，Dovecot 程序可以用于此目的。这将从本地 Postfix 邮箱向任何远程邮件客户端程序提供邮件，使用 POP3 或 IMAP 协议。现在，我们将向您介绍第三种 MTA，可以称为检索代理，并解释我们将使用 Fetchmail 程序的目的。如今，几乎每个人都有多个电子邮件帐户，来自一个或多个不同的邮件提供商，如果您需要登录所有这些不同的 Webmail 站点或使用邮件程序中的不同帐户，则可能难以维护。这就是 Fetchmail 发挥作用的地方。它是一个程序，在您的域内 Postfix 邮件服务器上运行，可以从您所有不同的邮件提供商那里检索所有不同的电子邮件，并将它们传递到 Postfix MTA 的本地用户邮箱中。一旦它们存储在适当的位置，用户就可以通过 Dovecot 访问代理提供的通常方式通过 POP3 或 IMAP 访问所有这些邮件。在本操作中，我们将向您展示如何安装并将 Fetchmail 集成到运行 Postfix MTA 的服务器中。

## 准备工作

要完成此操作，您需要具备 CentOS 7 操作系统的有效安装，拥有 root 权限，选择一个基于控制台的文本编辑器，以及连接到互联网以便下载额外的软件包。假设您是按照本章节中出现的顺序逐个进行操作，因此预计 Postfix 已配置为域内邮件传输代理（MTA），Dovecot 已安装以提供 POP3/IMAP 邮件访问服务。为了在本操作中测试 Fetchmail，我们还需要注册一些外部电子邮件地址：您需要外部电子邮件服务器地址的名称和您电子邮件提供商的端口，以及您的用户登录凭据。通常，您可以在电子邮件提供商网站的常见问题（FAQ）部分找到这些信息。此外，对于某些电子邮件地址，您需要在电子邮件设置中首先启用 POP3 或 IMAP，然后才能使用 Fetchmail。

## 操作步骤...

由于 Fetchmail 并非默认安装，因此我们必须首先安装必要的软件包。请按照以下步骤操作：

1.  首先，登录运行 Postfix 服务器的邮件服务器并输入：

    ```
    yum install fetchmail

    ```

1.  安装完成后，我们将登录到我们希望为其实现 Fetchmail 下载外部邮件的系统用户账户，在我们的例子中是系统用户`john`：`su - john`。现在让我们使用外部电子邮件地址配置 Fetchmail。如果您的邮件提供商名为`mailhost.com`，它在`pop.mailhost.com`上运行 POP3 服务器，在`imap.mailhost.com`上运行 IMAP，用户名为`<user-name>`，这里（请替换您自己的值）是一个示例命令行，用于测试与该提供商的连接并从中获取邮件：

    ```
    fetchmail pop.mailhost.com -p pop3 -u <user-name> -k -v

    ```

1.  如果您想使用同一提供商的 IMAP：

    ```
    fetchmail imap.mailhost.com -p IMAP -u <user-name> -v

    ```

1.  如果 Fetchmail 命令成功，所有新消息将从服务器下载到您的用户账户的本地邮箱中。

## 它是如何工作的...

在本教程中，我们向您展示了如何安装和测试 Fetchmail，它为我们的 Postfix 服务器上拥有本地邮箱的任何用户账户提供了自动邮件检索功能。因此，对于使用 POP3 或 IMAP 连接到邮件服务器的客户端，通过这种方式获取的邮件看起来就像正常的入站电子邮件。Fetchmail 常用于将所有不同的邮件账户合并到一个账户中，但如果您的邮件提供商没有良好的病毒或垃圾邮件过滤器，您也可以使用它。您从主机邮件服务器下载邮件，然后使用 SpamAssassin 或 ClamAV 等工具处理邮件，再将邮件发送给客户。

我们从这次经历中学到了什么？

我们首先通过安装 YUM 包来开始 Fetchmail 的配置。由于我们希望为名为`john`的系统用户邮箱设置 Fetchmail，接下来我们以该用户身份登录。之后，我们通过运行一个简单的命令行来测试 Fetchmail 程序，以从单个邮件提供商处获取邮件。如前所述，为了成功登录到外部邮件提供商，您需要知道服务器的准确登录信息（服务器地址、端口、用户名和密码，以及协议类型）才能使用 Fetchmail。

请记住，虽然一些电子邮件提供商允许用户决定是否使用 SSL 进行安全连接，但像[gmail.com](http://gmail.com)这样的主机仅允许安全连接。这意味着，如果主要电子邮件提供商不支持不带 SSL 连接的 POP3/IMAP 访问，本教程中所示的示例命令可能会失败。请继续阅读下一节，了解如何使用带有 SSL POP3/IMAP 加密的 Fetchmail。

如果您的邮件提供商同时提供 SSL 加密，您应该始终优先选择 SSL 加密。此外，一些提供商如[gmail.com](http://gmail.com)默认只允许用户通过 webmail 使用其服务，并禁用 POP3/IMAP 服务功能；您需要在提供商网站上的账户设置中启用它们（稍后说明）。

我们使用`-p`参数指定使用 fetchmail 命令的邮件协议。使用`-u`参数，我们指定了登录邮件服务器时使用的用户标识，这完全取决于我们的电子邮件提供商。对于 POP3，我们应用了`-k`标志，以确保电子邮件仅从服务器获取，但永远不会被删除（这是使用 POP3 协议时的默认行为）。最后，我们使用`-v`来使输出更加详细，并为我们简单的测试提供更多信息。如果您的电子邮件提供商支持 SSL，您还需要在 Fetchmail 命令中添加一个`-ssl`标志以及邮件服务器的根证书（请参阅下一节了解更多信息）。如果您运行前面的命令，Fetchmail 将立即开始询问服务器上的收件箱中的任何邮件，并将任何邮件下载到用户的本地邮箱。

## 还有更多...

在本节中，我们将向您展示如何配置 Fetchmail，以便使用 POP3S、IMAPS 以及 POP3 和 IMAP 协议从一些实际生活中的邮件提供商下载所有电子邮件到本地邮箱的 Postfix 服务器上，使用配置文件。最后，我们将向您展示如何自动化 Fetchmail 过程。

### 配置 Fetchmail 与 gmail.com 和 outlook.com 电子邮件账户

在这里，我们将配置 Fetchmail 将从以下不同的外部邮件账户下载：流行的[gmail.com](http://gmail.com)和[outlook.com](http://outlook.com)电子邮件提供商以及假设的`my-email-server.com`。

正如我们在主要配方中学到的，Fetchmail 默认通过命令行处理配置选项，这不应是您首选的使用 Fetchmail 自动从不同邮件账户下载邮件的方式。通常情况下，Fetchmail 应该作为服务在后台以守护模式运行，或者使用`cron`作业在启动时运行，并按照特定的时间间隔轮询定义在特殊配置文件中的一系列邮件服务器。通过这种方式，您可以方便地配置多个邮件服务器和一长串其他选项。

### 注意

在撰写本书时，为了使[gmail.com](http://gmail.com)与 Fetchmail 协同工作，您需要使用您的用户账户登录[gmail.com](http://gmail.com)网站，并首先在**转发和 POP/IMAP**中启用 IMAP。此外，在**我的账户**中的**登录与安全**下启用**允许安全性较低的应用程序**。对于[outlook.com](http://outlook.com)，登录到您的邮件账户网页，然后点击**选项**，再次点击**选项**，接着点击**使用 POP 连接设备和应用**，然后点击**启用 POP**。

无论是[outlook.com](http://outlook.com)还是[gmail.com](http://gmail.com)都使用安全的 POP3S 和 IMAPS 协议，因此您需要首先在您的 Fetchmail 服务器上下载并安装他们用于签署其 SSL 证书的根证书，以便能够使用他们的服务。在这里，我们可以安装 Mozilla CA 证书包，该证书包由 Mozilla 基金会编译，并包括所有主要网站和服务使用的最常用的根服务器证书，例如我们的邮件提供商使用的证书。对于[gmail.com](http://gmail.com)，我们需要 Equifax Secure Certificate Authority 根证书，而对于[outlook.com](http://outlook.com)，我们需要 Globalsign 的根服务器证书。Fetchmail 需要这些根证书来验证从电子邮件服务器下载的任何其他 SSL 证书的有效性。以 root 身份登录到您的 Postfix 服务器并安装以下软件包：

```
yum install ca-certificates

```

之后，以 Linux 系统用户身份登录，例如，`john`，我们将为其创建一个新的 Fetchmail 配置文件，并且他已经在我们的服务器上拥有位于其主目录下的`~/Maildir`的本地 Postfix 邮箱目录。在配置 Fetchmail 配置文件中的任何账户之前，您应该始终首先使用 Fetchmail 命令行测试到特定账户的连接和身份验证是否正常，如前一个配方所示。为了测试我们不同邮件提供商的账户，我们需要三个不同的命令行调用。为了测试您的提供商是否使用 SSL 加密，您需要`–ssl`标志；对于不允许非 SSL 连接的邮件提供商，典型的输出可能是：

```
Fetchmail: SSL connection failed.
Fetchmail: socket error while fetching from <userid>@<mailserver>
Fetchmail: Query status=2 (SOCKET)
```

如果您的 google 和 outlook 用户名是`johndoe`，在两个邮件提供商处进行测试，对于使用 IMAPS 协议尝试与 google 进行测试（在提示时输入您的电子邮件用户的密码）：

```
fetchmail imap.gmail.com -p IMAP --ssl -u johndoe@gmail.com -k -v
```

如果登录成功，输出应该类似于（已截断）：

```
Fetchmail: IMAP< A0002 OK johndoe@gmail.com authenticated (Success)
9 messages (2 seen) for johndoe at imap.gmail.com.
Fetchmail: IMAP> A0005 FETCH 1:9 RFC822.SIZE
```

对于使用 POP3S 测试[outlook.com](http://outlook.com)，请使用：

```
fetchmail pop-mail.outlook.com -p POP3 --ssl -u johndoe@outlook.com -k -v
```

成功后，输出应该类似于（已截断）：

```
Fetchmail: POP3> USER johndoe@outlook.com
Fetchmail: POP3< +OK password required
Fetchmail: POP3< +OK mailbox has 1 messages
```

对于我们在`my-email-server.com`上的第三个假设电子邮件账户，我们将使用不带 SSL 的 POP3 或 IMAP 来测试它，使用我们的账户：

```
fetchmail pop3.my-email-server.com -p POP3 -u johndoe -k -v
fetchmail imap.my-email-server.com -p IMAP -u johndoe  -v
```

您还应该检查从外部提供商获取的所有邮件是否已正确下载。使用`mailx`命令查看系统用户的本地邮箱（`mailx -f ~/Maildir`）。在我们成功验证 Fetchmail 能够连接到服务器并获取一些邮件之后，我们现在可以在系统用户的家目录中创建一个本地 Fetchmail 配置文件，以便自动化此过程并为多个邮件地址进行配置。首先使用`vi ~/.fetchmailrc`打开一个新文件。请记住，可以在命令行上放置的所有命令也可以在配置文件中使用，只是名称略有不同（并且更多）。现在输入以下内容（将`john`替换为您的实际 Linux 系统用户，`johndoe`替换为您的电子邮件用户账户名，`secretpass`替换为该账户的实际邮件密码）：

```
set postmaster "john"
set logfile fetchmail.log
poll imap.gmail.com with proto IMAP
user 'johndoe@gmail.com' there with password 'secretpass' is john here
ssl
fetchall
poll pop-mail.outlook.com with proto POP3
user 'johndoe@outlook.com' there with password 'secretpass' is john here
ssl
fetchall
poll pop3.my-email-server.com with proto POP3
user 'johndoe@my-email-server.com' there with password 'secretpass' is john here
fetchall
```

保存并关闭此文件。在此文件中，我们使用了以下重要命令：

+   `postmaster`：定义将接收 Fetchmail 遇到问题时的所有警告或错误邮件的本地 Linux 用户。

+   `logfile`：定义一个日志文件名，这对于我们监督和调试 Fetchmail 输出非常有帮助，当它在后台长时间连续运行时。

+   `poll`部分：指定从特定邮件提供商下载邮件。对于每个邮件账户，您将定义一个这样的轮询部分。如您所见，语法与我们测试单个连接时在命令行上使用的语法非常相似。使用`proto`定义`mail`协议，`user`是邮件账户的登录用户，`password`是账户的登录密码，使用`is <username> here`参数指定此邮件账户绑定到哪个本地系统用户账户。对于 SSL 连接，您需要`ssl`标志，我们指定了`fetchall`参数以确保我们也下载电子邮件提供商标记为`read`的所有电子邮件消息，否则 Fetchmail 不会下载已读邮件。

接下来更改`.fetchmailrc`文件的权限，因为它包含密码，因此不应被我们自己的用户以外的任何人读取：

```
chmod 600 ~/.fetchmailrc

```

最后，我们使用配置文件中的设置执行 Fetchmail。为了测试，我们将使用一个非常详细的参数：`fetchmail -vvvv`。现在，来自您所有不同电子邮件提供商的所有新邮件都应该被获取，因此之后您应该检查输出，看看每个服务器是否都已准备好并且可以像我们之前在命令行测试中进行的单个测试一样被轮询。所有新邮件都应该被下载到本地邮箱，因此为了阅读本地邮件，您可以像往常一样使用`mailx`命令，例如：`mail -f ~/Maildir`。

### 自动化 Fetchmail

正如刚才所说，我们现在可以随时手动启动轮询过程，只需在命令行中输入`fetchmail`即可。这将轮询并从我们在新配置文件中指定的邮件服务器获取所有新邮件，然后在处理每个条目一次后退出程序。现在仍然缺少的是一个机制，以特定间隔持续查询我们的邮件服务器，每当可以获取新邮件时更新我们的邮箱。您可以使用两种方法。要么将`fetchmail`命令作为 cron 作业运行，要么作为替代方案，您可以以守护进程模式启动 Fetchmail（在您的`.fetchmailrc`配置文件中使用参数`set daemon`激活它。）并将其置于后台。这样，Fetchmail 将始终运行，并在给定的时间点唤醒，开始轮询，直到处理完所有内容，然后回到睡眠状态，直到下一个间隔到达。

由于两种方法基本相同，这里我们将向您展示如何将 Fetchmail 作为 cron 作业运行，这设置起来要容易得多，因为我们不必创建一些自定义的 systemd 服务文件（目前在 CentOS 7 中没有现成的`fetchmail systemd`服务）。对于每个系统用户（例如，`john`），他们都有一个`fetchmail`配置文件，要每 10 分钟启动一次电子邮件服务器轮询过程，请输入以下命令一次以注册 cron 作业：

```
crontab -l | { cat; echo "*/10 * * * * /usr/bin/fetchmail &> /dev/null
"; } | crontab -

```

### 注意

不要将 Fetchmail 轮询周期设置得短于每 5 分钟一次，否则一些邮件提供商可能会阻止或禁止您，因为它只是使他们的系统过载。


# 第十二章：提供 Web 服务

在本章中，我们将介绍以下内容：

+   安装 Apache 并提供网页服务

+   启用系统用户并构建发布目录

+   实施基于名称的托管

+   使用 Perl 和 Ruby 实现 CGI

+   安装、配置和测试 PHP

+   保护 Apache

+   使用安全套接字层（SSL）设置 HTTPS

# 引言

本章是一系列食谱的集合，提供了为网页提供服务的必要步骤。从安装 Web 服务器到通过 SSL 提供动态页面，本章提供了在任何时间和任何地点实施行业标准托管解决方案所需的起点。

# 安装 Apache 并提供网页服务

在本食谱中，我们将学习如何安装和配置 Apache Web 服务器以启用静态网页服务。Apache 是世界上最受欢迎的开源 Web 服务器之一。它作为后端运行着超过一半的互联网网站，并可用于提供静态和动态网页。通常被称为`httpd`，它支持广泛的功能。本食谱的目的是向您展示如何轻松地使用 YUM 包管理器进行安装，以便您可以保持服务器最新的安全更新。Apache 2.4 在 CentOS 7 上可用。

## 准备就绪

要完成本食谱，您需要一个具有 root 权限的 CentOS 7 操作系统的有效安装，您选择的基于控制台的文本编辑器，以及连接到互联网以下载其他软件包的能力。预计您的服务器将使用静态 IP 地址和主机名。

## 如何操作...

Apache 默认未安装，因此我们将从使用 YUM 包管理器安装必要的软件包开始。

1.  首先，以 root 身份登录并输入以下命令：

    ```
    yum install httpd

    ```

1.  通过输入以下内容创建主页：

    ```
    vi /var/www/html/index.html

    ```

1.  现在添加所需的 HTML。您可以使用以下代码作为起点，但预计您会希望对其进行修改以满足您的需求：

    ```
    <!DOCTYPE html>
    <html lang="en">
    <head><title>Welcome to my new web server</title></head>
    <body><h1>Welcome to my new web server</h1>
    <p>Lorem ipsum dolor sit amet, adipiscing elit.</p></body>
    </html>
    ```

1.  您现在可以使用以下命令删除 Apache 2 测试页面：

    ```
    rm -f /etc/httpd/conf.d/welcome.conf

    ```

1.  完成这些步骤后，我们现在将考虑为基本使用配置`httpd`服务的需要。为此，打开您最喜欢的文本编辑器中的`httpd`配置文件，输入（在您已经备份文件之后）：

    ```
    cp /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.BAK
    vi /etc/httpd/conf/httpd.conf

    ```

1.  现在向下滚动找到行`ServerAdmin root@localhost`。设置此值的传统方法基于使用 webmaster 身份，因此只需修改电子邮件地址以反映更符合您自己需求的内容。例如，如果您的服务器的域名是`www.centos7.home`，那么您的条目将与此类似：

    ```
    ServerAdmin webmaster@centos7.home

    ```

1.  现在向下滚动几行，找到以下`ServerName`指令：`#ServerName www.example.com:80`。取消注释此行（即删除其前面的#符号），并将值`www.example.com`替换为更适合您自己需求的值。例如，如果您的服务器域名为`www.centos7.home`，则您的条目将如下所示：

    ```
    ServerName www.centos7.home:80

    ```

1.  接下来，我们将稍微扩展一下`DirectoryIndex`指令。找到`DirectoryIndex index.html`这一行，它是`<IfModule dir_module>`块的一部分，然后将其更改为：

    ```
    DirectoryIndex index.html index.htm

    ```

1.  保存并关闭文件，然后键入以下命令以测试配置文件：

    ```
    apachectl configtest

    ```

1.  接下来，让我们通过允许传入的`http`连接（默认为端口 80）到服务器来配置 Web 服务器的防火墙：

    ```
    firewall-cmd --permanent --add-service http && firewall-cmd --reload 

    ```

1.  现在继续设置`httpd`服务以在启动时启动并启动该服务：

    ```
    systemctl enable httpd && systemctl start httpd

    ```

1.  现在，您可以从与您的 Web 服务器位于同一网络中的任何计算机上测试`httpd`（两个系统应该能够相互看到并进行 ping 操作），通过将以下 URL 中的`XXX.XXX.XXX.XXX`替换为您的服务器 IP 地址，以查看我们创建的自定义 Apache 测试页面：

    ```
    http://XXX.XXX.XXX.XXX.

    ```

1.  或者，如果您没有 Web 浏览器，可以使用`curl`从网络中的任何计算机上获取我们的测试页面，以检查 Apache 是否正在运行：

    ```
    curl http://XXX.XXX.XXX

    ```

## 它是如何工作的...

Apache 是一个软件包，它使您能够发布和提供 Web 页面，并且更常被称为`httpd`、Apache2 或简称为 Apache。本食谱的目的是向您展示 CentOS 如何轻松地让您开始创建您的第一个网站。

那么我们从这次经历中学到了什么？

我们首先通过 YUM 包管理器安装了名为`httpd`的 Apache，并了解到在 CentOS 7 上，默认提供静态 HTML 的位置是`/var/www/html`。因此，我们的首要任务是创建一个合适的欢迎页面，我们将其放置在`/var/www/html/index.html`。我们使用了一个基本的 HTML 模板来帮助您起步，并期望您会希望自定义这个页面的外观和感觉。接着，我们删除了位于`/etc/httpd/conf.d/welcome.conf`的默认 Apache 2 欢迎页面。随后，下一步是在备份`httpd.conf`配置文件后，使用我们喜欢的文本编辑器打开它，以便在出现问题时可以恢复更改。首先，我们定义了服务器的电子邮件地址和服务器名称，这些信息通常出现在服务器生成的网页的错误消息中；因此，它应该反映您的域名。接下来，我们调整了`DirectoryIndex`指令，该指令定义了在请求目录时将首先发送给浏览器的文件。通常，人们请求的不是特定的网页而是目录。例如，如果您浏览到`www.example.com`，您请求的是一个目录，而`www.example.com/welcome.html`是一个特定的网页。默认情况下，Apache 发送请求目录中的`index.html`，但我们扩展了这一点，因为许多网站使用`.htm`扩展名。最后，我们以通常的方式保存并关闭了`httpd`配置文件，然后使用`apachectl configtest`命令检查 Apache 配置文件是否存在任何错误。这应该会打印出一条`Syntax OK`消息，然后我们可以启用`httpd`服务在启动时自动启动。我们必须在 firewalld 中打开标准的 HTTP 端口 80，以允许对服务器的传入 HTTP 请求，最后我们启动了`httpd`服务。请记住，如果配置文件已被更改，您也可以始终在不完全重启服务的情况下重新加载 Apache 的配置文件，方法是使用：`systemctl reload httpd`。完成这些步骤后，只需从同一网络中的另一台计算机打开浏览器，并选择一种查看我们新 Apache 启动页面的方法。您可以使用服务器的 IP 地址（例如，`http://192.168.1.100`），而那些支持主机名的人可以输入主机名（例如，`http://www.centos7.home`）。Apache 的访问和错误日志文件可以在`/var/log/httpd`中找到。要实时查看谁正在访问您的 Web 服务器，请打开`/var/log/httpd/access_log`；要查看所有错误，请输入`/var/log/httpd/error_log`。

尽管 Apache 是一个庞大的主题，我们无法涵盖其每一个细节，但在接下来的章节中，我们将继续揭示更多的功能，这些功能将帮助您构建一个理想的 Web 服务器。

# 启用系统用户和构建发布目录

在本食谱中，我们将学习 Apache 如何为您提供允许系统用户在其家目录中托管网页的选项。这种方法自 Web 托管开始以来就被 ISP 使用，并且在许多方面，由于它能够避免更复杂的虚拟托管方法，它继续蓬勃发展。在前一个食谱中，您被展示了如何安装 Apache Web 服务器，并且出于为系统用户提供托管设施的愿望，本食谱的目的是向您展示如何在 CentOS 7 中实现这一点。

## 准备就绪

要完成本食谱，您将需要一个具有 root 权限的工作 CentOS 7 操作系统安装和一个您选择的基于控制台的文本编辑器。预计您的服务器将使用支持主机名或域名的静态 IP 地址，并且 Apache Web 服务器已经安装并正在运行。此外，服务器上至少应有一个系统用户帐户。

## 如何操作...

为了提供本食谱所提供的功能，不需要额外的软件包，但我们需要对 Apache 配置文件进行一些修改。

1.  首先，以 root 身份登录，并在您最喜欢的文本编辑器中打开 Apache 用户目录配置文件，首先创建其备份副本，然后输入以下命令：

    ```
    cp /etc/httpd/conf.d/userdir.conf /etc/httpd/conf.d/userdir.conf.BAK
    vi /etc/httpd/conf.d/userdir.conf

    ```

1.  在文件中，找到读作`UserDir disabled`的指令。将其更改为以下内容：

    ```
    UserDir public_html

    ```

1.  现在滚动到`<Directory "/home/*/public_html">`部分，并用这里的块替换现有的块：

    ```
    <Directory /home/*/public_html>
        AllowOverride All
        Options Indexes FollowSymLinks
        Require all granted
    </Directory>
    ```

1.  保存并退出文件。现在以任何系统用户身份登录，以便与您的发布网页目录一起工作（`su - <username>`），然后在您的家目录中创建一个网页发布文件夹和一个新的用户主页：

    ```
    mkdir ~/public_html && vi ~/public_html/index.html

    ```

1.  现在添加所需的 HTML。您可以使用以下代码作为起点，但预计您会对其进行修改以满足自己的需求：

    ```
    <!DOCTYPE html>
    <html lang="en">
    <head><title>Welcome to my web folder's home page</title></head>
    <body><h1>Welcome to my personal home page</h1></body>
    </html>
    ```

1.  现在通过键入以下内容来修改 Linux 系统用户的`<username>`家目录的权限：

    ```
    chmod 711 /home/<username>

    ```

1.  将`public_html`的读/写权限设置为`755`，以便 Apache 稍后可以执行它：

    ```
    chmod 755 ~/public_html -R

    ```

1.  现在再次以 root 身份登录，使用`su - root`命令来适当地配置 SELinux，以便使用 http 家目录：

    ```
    setsebool -P httpd_enable_homedirs true

    ```

1.  作为 root，更改用户网页公共目录的 SELinux 安全上下文（这需要安装`policycoreutils-python`软件包），用户名为`<user>`：

    ```
    semanage fcontext -a -t httpd_user_content_t /home/<user>/public_html
    restorecon -Rv /home/<user>/public_html

    ```

1.  要完成本食谱，只需重新加载`httpd`服务配置：

    ```
    apachectl configtest && systemctl reload httpd

    ```

1.  您现在可以通过在任何浏览器中浏览到（适当替换<username>）：`http://<SERVER IP ADDRESS>/~<username>`来测试您的设置。

## 它是如何工作的...

在本食谱中，我们了解到通过在 Apache Web 服务器上启用用户目录来托管自己的对等体是多么容易。

我们从这次经历中学到了什么？

我们首先通过在 Apache 的`userdir.conf`中进行一些小的配置更改来开始这个配方，以便设置用户目录支持。我们通过将`UserDir`指令从禁用调整为指向每个用户主目录内的 HTML 网页目录的名称来激活用户目录，该目录将包含我们所有用户的网页内容，并将其称为`public_html`（您可以更改此目录名称，但`public_html`是命名它的既定标准）。然后，我们继续修改`<Directory /home/*/public_html>`标签。此指令将其封闭的所有选项应用于开始标签`/home/*/public_html`定义的文件系统部分。在我们的示例中，为该目录启用了以下选项：当目录没有`index.html`时，使用`Indexes`显示目录的文件和文件夹内容作为 HTML。正如我们将在配方*Securing Apache*中看到的，这应该避免用于您的网络根目录，而对于提供用户目录，如果您只想让您的家庭文件夹对您的同行可访问，以便他们可以快速共享一些文件（如果您有任何安全问题，请删除此选项），这可能是一个不错的选择。`FollowSymLinks`选项允许从`public_html`目录到文件系统中任何其他目录或文件的符号链接（`man ln`）。同样，避免在您的网络根目录中使用，但对于家庭目录，如果您需要在不将它们复制到其中的情况下使文件或文件夹在`public_html`文件夹中可访问，这可能很有用（用户目录通常有磁盘配额）。接下来，我们配置了对`public_html`文件夹的访问控制。我们通过设置`Require` `all granted`来实现这一点，这告诉 Apache，在这个`public_html`文件夹中，任何人都可以通过 HTTP 协议访问内容。如果您想限制对`public_html`文件夹的访问，则可以替换`all granted`为不同的选项。例如，要基于主机名允许访问，请使用`Require host example.com`。使用`ip`参数，我们可以将`public_html`文件夹限制为仅内部可用的网络，例如`Require ip 192.168.1.0/24`。如果您的 Web 服务器具有多个网络接口，并且一个 IP 地址用于连接到公共 Internet，另一个用于您的内部专用网络，这特别有用。您可以在`Directory`块内添加多个`Require`行。请始终至少设置`Require local`，这允许本地访问。

保存工作后，我们开始对主目录进行各种更改。首先，我们在用户的主目录中创建了实际的`public_html`文件夹，这将成为稍后个人网页发布的实际文件夹。接下来，我们将权限更改为`755`，这意味着我们的用户可以在文件夹中执行所有操作，但其他用户和组只能读取和执行其内容（并进入该文件夹）。这种权限是必需的，因为如果有人通过 Apache Web 服务器请求其内容，`public_html`文件夹中的所有文件都将由名为`apache`的用户和组`apache`访问。如果未为`其他用户`标志设置读取或执行权限（`man chmod`），我们将在浏览器中收到`访问被拒绝`的消息。如果我们不提前更改父`/home/<username>`目录的权限，也会出现这种情况，因为父目录权限可以影响其子文件夹的权限。CentOS Linux 中的普通用户主目录具有`700`权限，这意味着主目录的所有者可以执行任何操作，但其他所有人都完全被锁定在主文件夹及其内容之外。

如前所述，Apache 用户需要访问子文件夹`public_html`，因此我们必须将主文件夹的权限更改为`711`，以便其他人至少可以进入目录（然后也可以访问子文件夹`public_html`，因为这被设置为可读/写访问）。接下来，我们为 SELinux 设置新网页文件夹的安全上下文。在运行 SELinux 的系统上，必须将所有 Apache 网页发布文件夹设置为`httpd_user_content_t` SELinux 标签（及其内容），以便使它们对 Apache 可用。此外，我们确保设置了正确的 SELinux 布尔值以启用 Apache 主目录（默认情况下已启用）：`httpd_enable_homedirs`为`true`。阅读第十四章，*使用 SELinux*了解更多关于 SELinux 的信息。

您应该知道，管理主目录的过程应该为每个用户重复。您不必每次启用新系统用户时都重新启动 Apache，但是，在第一次完成这些步骤后，只需重新加载`httpd`服务的配置以反映对配置文件所做的初始更改即可。从这一点开始，您的本地系统用户现在可以使用基于其用户名的唯一 URL 发布网页。

# 实施基于名称的托管

通常情况下，如果您按照之前的步骤安装了 Apache，您可以托管一个可以通过服务器 IP 地址或 Apache 运行的域名访问的网站，例如`http://192.168.1.100`或`http://www.centos7.home`。这种系统对于服务器资源来说非常浪费，因为您需要为每个想要托管的域名单独安装服务器。**基于名称的**或**虚拟主机**用于在同一 Apache Web 服务器上托管多个域名。如果已经通过 DNS 服务器或本地`/etc/hosts`文件将多个不同的域名分配给您的 Apache Web 服务器的 IP 地址，则可以为每个可用的域名配置虚拟主机，以将用户引导至 Apache 服务器上包含站点信息的特定目录。任何现代的网络空间提供商都使用这种类型的虚拟主机将一个 Web 服务器的空间分割成多个站点。只要您的 Web 服务器能够处理其流量，就没有限制可以创建的站点数量。在本步骤中，我们将学习如何在 Apache Web 服务器上配置基于名称的虚拟主机。

## 准备工作

要完成本步骤，您需要一个具有 root 权限的 CentOS 7 操作系统的正常安装，以及您选择的基于控制台的文本编辑器。预计您的服务器将使用静态 IP 地址，Apache 已安装并正在运行，并且您已经在之前的步骤中启用了系统用户发布目录。如果没有事先设置一个或多个域名或子域名，虚拟主机将无法工作。

为了测试，您可以在`/etc/hosts`中设置（参见第二章中的“设置主机名和解决网络问题”步骤），或者在您的 BIND DNS 服务器中配置一些 A 或 CNAMES（参考第九章），使用不同的域名或子域名，如`www.centos7.home`，全部指向您的 Apache Web 服务器的 IP 地址。

### 注意

一个常见的误解是，Apache 可以自行为您的 Apache Web 服务器创建域名。这是不正确的。您希望使用虚拟主机将不同的域名连接到不同目录之前，需要在 DNS 服务器或`/etc/hosts`文件中设置这些域名，使其指向您的 Apache 服务器的 IP 地址。

## 如何操作...

为了本配方的目的，我们将构建一些具有以下 Apache 示例子域名的本地虚拟主机：`www.centos7.home`，`web1.centos7.home`，`web2.centos7.home`和`<username>.centos7.home`，对应于 Web 发布文件夹`/var/www/html`，`/var/www/web1`，`/var/www/web2`和`/home/<username>/public_html`，以及域的网络名称`centos7.home`。这些名称是可互换的，预计您将希望根据更适合您自己需求和情况的内容来定制此配方。

1.  首先，以 root 身份登录到您的 Apache 服务器，并创建一个新的配置文件，该文件将包含我们所有的虚拟主机定义：

    ```
    vi /etc/httpd/conf.d/vhost.conf

    ```

1.  现在，请输入以下内容，将`centos7.home`的值和用户名`<username>`定制以适应您自己的需求：

    ```
    <VirtualHost *:80>
        ServerName centos7.home
        ServerAlias www.centos7.home
        DocumentRoot /var/www/html/
    </VirtualHost>   
    <VirtualHost *:80>
        ServerName  web1.centos7.home
        DocumentRoot /var/www/web1/public_html/
    </VirtualHost>
    <VirtualHost *:80>
        ServerName  web2.centos7.home
        DocumentRoot /var/www/web2/public_html/
    </VirtualHost>
    <VirtualHost *:80>
        ServerName  <username>.centos7.home
        DocumentRoot /home/<username>/public_html/
    </VirtualHost>
    ```

1.  现在以通常的方式保存并关闭文件，然后继续为当前缺失的两个虚拟主机创建目录：

    ```
    mkdir -p /var/www/web1/public_html /var/www/web2/public_html

    ```

1.  完成此操作后，我们现在可以使用我们喜欢的文本编辑器为缺失的子域`web1`和`web2`创建默认索引页面，如下所示：

    ```
    echo "<html><head></head><body><p>Welcome to Web1</p></body></html>" > /var/www/web1/public_html/index.html
    echo "<html><head></head><body><p>Welcome to Web2</p></body></html>" > /var/www/web2/public_html/index.html

    ```

1.  现在重新加载 Apache Web 服务器：

    ```
    apachectl configtest && systemctl reload httpd

    ```

1.  现在，为了简单的测试目的，我们将在想要访问这些虚拟主机的客户端计算机的`hosts`文件中配置我们新的 Apache Web 服务器的所有子域，但请记住，您也可以在 BIND DNS 服务器中配置这些子域。以 root 身份登录到此客户端计算机（它需要与我们的 Apache 服务器在同一网络中），并将以下行添加到`/etc/hosts`文件中，假设我们的 Apache 服务器具有 IP 地址 192.168.1.100：

    ```
    192.168.1.100 www.centos7.home
    192.168.1.100 centos7.home
    192.168.1.100 web1.centos7.home
    192.168.1.100 web2.centos7.home
    192.168.1.100 john.centos7.home

    ```

1.  现在，在这台计算机上，打开浏览器并通过在地址栏中输入以下地址来测试（将`<username>`替换为您为虚拟主机定义的用户名）：`http://www.centos7.home`，`http://web1.centos7.home`，`http://web2.centos7.home`和`http://<username>.centos7.home`。

## 它是如何工作的...

本配方的目的是向您展示实现基于名称的虚拟主机是多么容易。这种技术将提高您的工作效率，采用这种方法将为您提供无限的机会来进行基于域名的网络托管。

那么，我们从这次经历中学到了什么？

我们首先创建一个新的 Apache 配置文件来存放我们所有的虚拟主机配置。请记住，在`/etc/httpd/conf.d/`目录中以`.conf`扩展名结尾的所有文件将在 Apache 启动时自动加载。接着，我们继续添加相关的指令块，从我们的默认服务器根目录`centos7.home`和别名`www.centos7.home`开始。任何虚拟主机块中最重要的选项是`ServerName`指令，它将我们 Web 服务器的 IP 地址的现有域名映射到文件系统上的特定目录。当然，您可以包含更多的设置，但之前的解决方案提供了基本的构建块，使您能够将其作为完美的起点。接下来，我们为我们的`centos7.home`子域`web1`、`web2`和`<username>`创建了单独的条目。请记住，每个虚拟主机都支持典型的 Apache 指令，并且可以根据您的需要进行定制。请参考官方的 Apache 手册（安装 YUM 包`httpd-manual`，然后转到位置`/usr/share/httpd/manual/vhosts/`）以了解更多信息。在我们为每个想要的子域创建了虚拟主机块之后，我们继续创建了存放实际内容的目录，并在每个目录中创建了一个基本的`index.html`。在这个例子中，我们的`web1`和`web2`内容目录被添加到了`/var/www`。这并不是说你不能在其他地方创建这些新文件夹。实际上，大多数生产服务器通常将这些新目录放在主文件夹中，如我们的`/home/<username>/public_html`示例所示。但是，如果您确实打算采用这种方法，请记住修改这些新目录的权限和所有权，以及 SELinux 标签（在`/var/www`之外，您需要将 Apache 目录标记为`httpd_sys_content_t`），以便它们可以按预期使用。最后，我们重新加载了 Apache Web 服务，以便我们的新设置会立即生效。然后，我们可以在客户端的`/etc/hosts`中或在 BIND DNS 服务器上正确设置后，直接在浏览器中使用子域名浏览到我们的虚拟主机。

# 使用 Perl 和 Ruby 实现 CGI

在本章之前的食谱中，我们的 Apache 服务仅提供静态内容，这意味着网页浏览器请求的所有内容在服务器上已经处于恒定状态，例如作为不会改变的纯 HTML 文本文件。Apache 只是将 Web 服务器上特定文件的内容作为响应发送到浏览器，然后在那里进行解释和渲染。如果没有办法改变发送给客户端的内容，互联网将会非常无聊，也不会像今天这样取得巨大成功。甚至连最简单的动态内容示例，例如显示带有 Web 服务器当前本地时间的网页，都不可能实现。

因此，早在 20 世纪 90 年代初，一些聪明的人开始发明机制，使 Web 服务器和安装在服务器上的可执行程序之间的通信成为可能，以动态生成网页。这意味着发送给用户的 HTML 内容可以根据不同的上下文和条件改变。这些程序通常用脚本语言编写，如 Perl 或 Ruby，但也可以用任何其他计算机语言编写，如 Python、Java 或 PHP（见后文）。因为 Apache 是用纯 C 和 C++编写的，所以它不能执行或解释任何其他编程语言，如 Perl。因此，需要在服务器和程序之间建立一座桥梁，定义一些外部程序如何与服务器交互。这些方法之一被称为**通用网关接口**（**CGI**），这是一种非常古老的方式来提供动态内容。大多数 Apache Web 服务器使用某种形式的 CGI 应用程序，在这个食谱中，我们将向您展示如何安装和配置 CGI 以与 Perl 和 Ruby 一起使用，以生成我们的第一个动态内容。

### 注意

还存在一些特殊的 Apache Web 服务器模块，如`mod_perl`、`mod_python`、`mod_ruby`等，这些模块通常应该被优先考虑，因为它们直接将语言的解释器嵌入到 Web 服务器进程中，因此与任何接口技术（如 CGI）相比，它们要快得多。

## 准备就绪

为了完成这个食谱，你需要一个带有 root 权限的 CentOS 7 操作系统的有效安装，你选择的基于控制台的文本编辑器，以及一个互联网连接，以便下载额外的软件包。

预计你的服务器将使用静态 IP 地址，Apache 已安装并正在运行，并且你的服务器支持一个或多个域或子域。

## 如何操作...

由于 Perl 和 Ruby 这两种脚本语言在 CentOS 7 Minimal 中默认不安装，我们将从使用 YUM 安装所有必需的软件包开始这个食谱。

1.  开始时，以 root 身份登录并输入以下命令：

    ```
    yum install perl perl-CGI ruby

    ```

1.  接下来，重新启动 Apache Web 服务器：

    ```
    systemctl restart httpd

    ```

1.  接下来，我们需要为使用 CGI 脚本适当地配置 SELinux：

    ```
    setsebool -P httpd_enable_cgi 1

    ```

1.  然后，我们需要为 SELinux 的工作更改我们`cgi-bin`目录的正确安全上下文：

    ```
    semanage fcontext -a -t httpd_sys_script_exec_t /var/www/cgi-bin
    restorecon -Rv /var/www/cgi-bin

    ```

### 创建你的第一个 Perl CGI 脚本

1.  现在通过打开新文件`vi /var/www/cgi-bin/perl-test.cgi`并输入以下内容来创建以下 Perl CGI 脚本文件：

    ```
    #!/usr/bin/perl
    use strict;
    use warnings;
    use CGI qw(:standard);
    print header;
    my $now = localtime;
    print start_html(-title=>'Server time via Perl CGI'),
    h1('Time'),
    p("The time is $now"),
    end_html;
    ```

1.  接下来，将文件权限更改为 755，以便我们的`apache`用户可以执行它：

    ```
    chmod 755 /var/www/cgi-bin/perl-test.cgi

    ```

1.  接下来，为了测试并实际看到从前面的脚本生成的 HTML，你可以在命令行上直接执行`perl`脚本；只需输入：

    ```
    /var/www/cgi-bin/perl-test.cgi

    ```

1.  现在在网络中的一台计算机上打开浏览器，运行你的第一个 Perl CGI 脚本，它将通过使用 URL 打印本地时间：

    ```
    http://<server name or IP address>/cgi-bin/perl-test.cgi

    ```

1.  如果脚本不工作，请查看日志文件`/var/log/httpd/error_log`。

### 创建你的第一个 Ruby CGI 脚本

1.  创建新的 Ruby CGI 脚本文件`vi /var/www/cgi-bin/ruby-test.cgi`，并放入以下内容：

    ```
    #!/usr/bin/ruby
    require "cgi"
    cgi = CGI.new("html4")
    cgi.out{
     cgi.html{
     cgi.head{ cgi.title{"Server time via Ruby CGI"} } +
     cgi.body{
     cgi.h1 { "Time" } +
     cgi.p { Time.now}
     }
     }
    }

    ```

1.  现在将文件权限更改为`755`，以便我们的`apache`用户可以执行它：

    ```
    chmod 755 /var/www/cgi-bin/ruby-test.cgi

    ```

1.  要实际查看从前面脚本生成的 HTML，您可以在命令行上直接执行 Ruby 脚本；只需键入`/var/www/cgi-bin/ruby-test.cgi`。当显示行`offline mode: enter name=value pairs on standard input`时，按*Ctrl*+*D*查看实际的 HTML 输出。

1.  现在，在您的网络中的计算机上打开一个浏览器，运行您的第一个 Ruby CGI 脚本，该脚本将通过以下 URL 打印本地时间：

    ```
    http://<server name or IP address>/cgi-bin/ruby-test.cgi

    ```

1.  如果它不工作，请查看日志文件`/var/log/httpd/error.log`。

## 它是如何工作的...

在这个配方中，我们向您展示了使用 CGI 创建一些动态网站是多么容易。当访问 CGI 资源时，Apache 服务器在服务器上执行该程序，并将输出发送回浏览器。这个系统的主要优点是 CGI 不受任何编程语言的限制，只要程序可以在 Linux 命令行上执行并生成某种形式的文本输出即可。CGI 技术的主要缺点是它是一种非常老旧且过时的技术：对 CGI 资源的每个用户请求都会启动程序的新进程。例如，对 Perl CGI 脚本的每个请求都会启动并将新的解释器实例加载到内存中，这将产生大量开销，因此使得 CGI 仅适用于较小的网站或较低的并行用户请求数。如前所述，还有其他技术可以解决这个问题，例如 FastCGI 或 Apache 模块，如`mod_perl`。

那么我们从这次经历中学到了什么？

我们从这个配方开始，以 root 身份登录，并安装了`perl`解释器和`CGI.pm`模块，因为它们不包含在 Perl 标准库中（我们将在脚本中使用它），以及安装了 Ruby 编程语言的`ruby`解释器。之后，为了确保我们的 Apache Web 服务器注意到我们系统上安装的新编程语言，我们重新启动了 Apache 进程。

接下来，我们确保 SELinux 已启用以与 CGI 脚本配合工作，然后我们为标准的 Apache `cgi-bin`目录`/var/www/cgi-bin`提供了正确的 SELinux 上下文类型，以允许系统范围内的执行。要了解更多关于 SELinux 的信息，请阅读第十四章，*使用 SELinux*。然后，我们将 Perl 和 Ruby CGI 脚本放入此目录，并使它们对 Apache 用户可执行。在主 Apache 配置文件中，`/var/www/cgi-bin`目录默认被定义为标准 CGI 目录，这意味着您放入此目录的任何可执行文件，只要具有适当的访问和执行权限以及`.cgi`扩展名，都会自动定义为 CGI 脚本，并且可以从您的网络浏览器访问和执行，无论它使用哪种编程或脚本语言编写。为了测试我们的脚本，我们随后打开了一个网络浏览器，并访问了 URL `http://<服务器名称或 IP 地址>/cgi-bin/`，后面跟着`.cgi`脚本的名称。

## 还有更多...

如果您希望在其他网站目录中也能执行 CGI 脚本，您需要将以下两行（`Options`和`AddHandler`）添加到任何虚拟主机或现有的`Directive`指令中，或者按照以下方式创建一个新的（请记住，您还需要为新的 CGI 位置设置 SELinux `httpd_sys_script_exec_t`标签）：

```
<Directory "/var/www/html/cgi-new">
   Options +ExecCGI
   AddHandler cgi-script .cgi
</Directory>
```

# 安装、配置和测试 PHP

**超文本预处理器**（**PHP**）仍然是用于 Web 开发的最流行的服务器端脚本语言之一。它已经支持一些很好的功能，例如开箱即用地连接到关系数据库（如 MariaDB），这可以用来非常快速地实现现代 Web 应用程序。虽然可以看到一些大型企业倾向于放弃 PHP 而转向一些新技术，如 Node.js（服务器端 JavaScript），但它仍然是消费者市场上的主要脚本语言。世界上每家托管公司都提供某种 LAMP 堆栈（Linux、Apache、MySQL、PHP）来运行 PHP 代码。此外，许多非常流行的 Web 应用程序都是用 PHP 编写的，例如 WordPress、Joomla 和 Drupal，因此可以说 PHP 几乎是任何 Apache Web 服务器的必备功能。在本操作指南中，我们将向您展示如何在 Apache Web 服务器上开始安装和运行 PHP，使用模块`mod_php`。

## 准备就绪

要完成此操作，您需要一个具有 root 权限的工作 CentOS 7 操作系统安装，以及您选择的基于控制台的文本编辑器和互联网连接。预计您的服务器将使用静态 IP 地址，Apache 已安装并正在运行，并且您的服务器支持一个或多个域或子域。

## 如何操作...

我们将从安装 PHP 超文本处理器开始，同时安装 Apache 的`mod_php`模块，这两者在 CentOS 7 最小安装中默认不安装。

1.  首先，以 root 身份登录并输入以下命令：

    ```
    yum install mod_php

    ```

1.  现在，在我们先对原始文件进行备份之后，让我们打开标准的 PHP 配置文件：

    ```
    cp /etc/php.ini /etc/php.ini.bak && vi /etc/php.ini

    ```

1.  找到行`; date.timezone =`并将其替换为您自己的时区。所有可用的 PHP 时区列表可以在`http://php.net/manual/en/timezones.php`找到。例如（请确保删除前面的`;`，因为这会禁用命令的解释；这称为注释掉），要将时区设置为欧洲柏林市，请使用：

    ```
    date.timezone = "Europe/Berlin"

    ```

1.  为了确保新模块和设置已正确加载，请重启 Apache Web 服务器：

    ```
    systemctl restart httpd

    ```

1.  为了与前一个配方中的 CGI 示例保持一致，我们将创建我们的第一个动态 PHP 脚本，该脚本将打印出当前本地服务器时间，并在脚本`vi /var/www/html/php-test.php`中运行流行的 PHP 函数`phpinfo()`，我们可以使用它来打印出重要的 PHP 信息：

    ```
    <html><head><title>Server time via Mod PHP</title></head>
    <h1>Time</h1>
    <p>The time is <?php print Date("D M d, Y G:i a");?></p><?php phpinfo(); ?></body></html>
    ```

1.  要实际查看从前面脚本生成的 HTML，您可以直接在命令行上执行 PHP 脚本；只需输入：`php /var/www/html/php-test.php`。

1.  现在，在您网络中的计算机上打开浏览器，运行您的第一个 PHP 脚本，该脚本将通过以下 URL 打印本地时间：`http://<服务器名称或 IP 地址>/php-test.php`。

## 如何操作...

在本配方中，我们向您展示了通过使用`mod_php`模块将 PHP 轻松安装并集成到任何 Apache Web 服务器中是多么容易。该模块启用了一个内部 PHP 解释器，该解释器直接在 Apache 进程中运行，比使用 CGI 更高效，并且应该是任何可用时的首选方法。

那么我们从这次经历中学到了什么？

我们从使用 YUM 安装`mod_php`模块开始本节，这将安装 PHP 作为依赖项，因为这两者都不在任何标准的 CentOS 7 最小安装中。安装`mod_php`添加了`/etc/php.ini`配置文件，我们在备份原始文件后打开了它。该文件是主要的 PHP 配置文件，应谨慎编辑，因为许多设置可能与您的 Web 服务器的安全性相关。如果您刚刚开始使用 PHP，请将文件中的所有内容保持原样，不要更改任何内容，除了`date.timezone`变量。我们将其设置为反映我们当前的时区，这对于 PHP 是必要的，因为它被许多不同的时间和日期函数使用（我们还将在我们第一个 PHP 脚本中使用一些日期函数，如下所示）。接下来，我们重新启动了 Apache Web 服务器，它也会自动重新加载 PHP 配置。之后，我们创建了我们的第一个 PHP 脚本，并将其放入主 Web 根目录`/var/www/html/php-test.php`；这会打印出当前服务器时间以及`phpinfo()` PHP 函数的结果。这为您提供了一个分类良好的表格概览，显示了当前的 PHP 安装，帮助您诊断与服务器相关的问题或查看哪些模块在 PHP 中可用。

与 CGI 相比，您可能会问自己为什么我们不需要将 PHP 脚本放入任何特殊文件夹，如`cgi-bin`。通过安装`mod_php`，一个名为`/etc/httpd/conf.d/php.conf`的 Apache 配置文件被部署到 Apache 配置文件夹中，这正是回答了这个问题，它指定了每当 PHP 脚本从 Web 目录中的任何位置获得`.php`扩展名时，它们将被执行为有效的 PHP 代码。

# 确保 Apache 安全

尽管 Apache HTTP 服务器是 CentOS 7 中包含的最成熟和最安全的服务器应用程序之一，但总有余地进行改进，并且有大量选项和技术可用于进一步强化您的 Web 服务器的安全性。虽然我们无法向用户展示每一个安全特性，因为这超出了本书的范围，但在本节中，我们将尝试教授在为生产系统保护 Apache Web 服务器时被认为是良好实践的内容。

## 准备工作

要完成本节，您需要一个具有 root 权限的 CentOS 7 操作系统的有效安装，以及您选择的基于控制台的文本编辑器。预计您的服务器将使用静态 IP 地址，并且 Apache 已安装并正在运行，并且您的服务器支持一个或多个域或子域。

## 如何操作...

大多数安全选项和技术都必须在 Apache 的主配置文件中设置，因此我们将从在喜欢的文本编辑器中打开它开始本节。

### 配置 httpd.conf 以提供更好的安全性

1.  首先，以 root 身份登录并打开 Apache 的主配置文件：

    ```
    vi /etc/httpd/conf/httpd.conf

    ```

1.  现在转到你的主文档根目录。为此，搜索名为：

    ```
    <Directory "/var/www/html">

    ```

1.  在开始`<Directory "/var/www/html">`和结束`</Directory>`标签之间找到行`Options Indexes FollowSymLinks`，然后通过在前面放置一个`#`来禁用（注释掉）该行，使其读取：

    ```
    #  Options Indexes FollowSymLinks

    ```

1.  现在滚动到配置文件的末尾，在`# Supplemental configuration`行之前插入以下行。我们不希望服务器通过标头泄露任何详细信息，因此我们输入：

    ```
    ServerTokens Prod

    ```

1.  之后，重新加载 Apache 配置以应用你的更改：

    ```
    apachectl configtest && systemctl reload httpd

    ```

### 移除不需要的 httpd 模块

即使是稳定性最高、成熟度最高、经过充分测试的程序也可能包含漏洞，正如最近关于 OpenSSL 中的 Heartbleed 漏洞或 Bash 中的 Shellshock 漏洞的新闻所显示的那样，Apache Web 服务器也不例外。因此，通常有益的是移除所有不需要的软件以限制功能，从而减少系统中出现安全问题的可能性。对于 Apache Web 服务器，我们可以移除所有不需要的模块以提高安全性（这也可以提高性能和内存消耗）。让我们通过审查所有当前安装的 Apache 模块来开始这个过程。

1.  要显示所有当前安装和加载的 Apache 模块，请以 root 用户身份输入：

    ```
    httpd -M

    ```

1.  前面命令输出的所有模块都通过`/etc/httpd/conf.modules.d`文件夹中的特殊配置文件加载到 Apache Web 服务器中，它们根据其主要目标分组到以下文件中：

    ```
    00-base.conf, 00-dav.conf, 00-lua.conf, 00-mpm.conf, 00-proxy.conf, 00-ssl.conf, 00-systemd.conf, 01-cgi.conf, 10-php.conf

    ```

1.  因此，与其逐一检查所有模块，`conf.modules.d`文件夹中的这种文件结构可以使我们的生活变得更加轻松，因为我们可以在整个模块组中启用/禁用。例如，如果你知道自己不需要任何 Apache DAV 模块，因为你不会提供任何 WebDAV 服务器，你可以通过将`00-dav.conf`配置文件的扩展名重命名来禁用所有与 DAV 相关的模块，因为只有以`.conf`结尾的文件才会被 Apache 自动读取和加载。为此，请输入：

    ```
    mv /etc/httpd/conf.modules.d/00-dav.conf /etc/httpd/conf.modules.d/00-dav.conf.BAK

    ```

1.  之后，重新加载 Apache 配置以将你的更改应用于模块目录：

    ```
    apachectl configtest && systemctl reload httpd

    ```

1.  如果你需要更精细的控制，你也可以在所有这些配置文件中启用/禁用单个模块。例如，在你的首选文本编辑器中打开`00-base.conf`，并通过在要禁用的行的开头添加`#`来禁用单个行。例如：

    ```
    # LoadModule userdir_module modules/mod_userdir.so

    ```

1.  如果你决定稍后使用一些禁用的模块文件，只需将`.BAK`文件重命名为原始文件名，或者在重新加载`httpd`之前，在特定的模块配置文件中删除`#`。

### 保护你的 Apache 文件

提高 Apache Web 服务器安全性的另一种简单方法是保护服务器端脚本和配置。在我们的场景中，有一个用户（root）单独负责并维护整个 Apache Web 服务器、网站（例如，将新的 HTML 页面上传到服务器）、服务器端脚本和配置。因此，我们将给予他/她完整的文件权限（读/写/执行）。`apache`用户仍然需要适当的读取和执行权限来服务和访问所有与 Apache 相关的文件，从而最小化您的 Apache Web 服务器向其他系统用户暴露潜在安全风险或通过 HTTP 攻击被破坏的风险。这可以通过两个步骤完成：

1.  首先，我们将更改或重置完整的 Apache 配置目录和标准 Web 根目录的所有权，所有者为`root`，组为`apache`：

    ```
    chown -R root:apache /var/www/html /etc/httpd/conf*

    ```

1.  之后，我们将更改文件权限，以便除了我们专门的`apache`用户（以及`root`）之外，任何人都无法读取这些文件：

    ```
    chmod 750 -R /var/www/html /etc/httpd/conf*

    ```

## 它是如何工作的...

我们从这个食谱开始，打开主 Apache 配置文件`httpd.conf`，以更改我们主 Apache 根 Web 内容目录`/var/www/html`的设置。在这里，我们禁用了完整的`Options`指令，包括`Indexes`和`FollowSymLinks`参数。正如我们所学，如果您从 Apache 服务器请求目录而不是文件，`index.html`或该目录中的`index.htm`文件将自动发送。现在，`Indexes`选项配置 Apache Web 服务器，以便如果在请求的目录中找不到这样的文件，Apache 将自动生成该目录内容的列表，就像您在命令行中输入`ls`（用于列出目录）一样，并将其作为 HTML 页面显示给用户。我们通常不希望这个功能，因为它可能会向未经授权的用户暴露秘密或私人数据，许多系统管理员会告诉您，索引通常被认为是一种安全威胁。`FollowSymLinks`指令也不应在生产系统中使用，因为如果您使用不当，它很容易暴露文件系统的一部分，例如完整的根目录。最后，我们添加了另一个措施来提高服务器的基本安全性，这是通过禁用服务器版本横幅信息来实现的。当 Apache Web 服务器生成网页或错误页面时，有价值的信息（例如 Apache 服务器版本和激活的模块）会自动发送到浏览器，潜在的攻击者可以从中获取有关您系统的宝贵信息。我们通过简单地将`ServerTokens`设置为`Prod`来阻止这种情况发生。之后，我们向您展示了如何禁用 Apache 模块以减少系统中错误和利用的一般风险。最后，我们展示了如何调整您的 Apache 文件权限，这也是一种很好的通用保护措施。

在加固 Apache Web 服务器时，有许多其他因素需要考虑，但大多数这些技术，如限制 HTTP 请求方法，`TraceEnable`，设置带有`HttpOnly`和安全标志的 cookie，禁用 HTTP 1.0 协议或 SSL v2，或使用有用的安全相关 HTTP 或自定义标头（如`X-XSS-Protection`）修改 HTTP 标头，都是更高级的概念，并且可能会过度限制通用目的的 Apache Web 服务器。

# 使用安全套接字层（SSL）设置 HTTPS

在本操作中，我们将学习如何通过使用 OpenSSL 创建自签名 SSL 证书来为 Apache Web 服务器添加安全连接。如果网站在服务器上运行时传输敏感数据，如信用卡或登录信息，则通常需要 Web 服务器。在前一个操作中，您已经了解了如何安装 Apache Web 服务器，随着对安全连接的需求不断增长，本操作的目的是向您展示如何通过教您如何扩展 Apache Web 服务器的功能来增强当前服务器配置。

## 准备工作

要完成此操作，您需要一个具有 root 权限的 CentOS 7 操作系统的有效安装，您选择的基于控制台的文本编辑器，以及互联网连接以便于下载额外的包。预计 Apache Web 服务器已安装并正在运行。在这里，我们将为 Apache 创建一个新的 SSL 证书。如果您想了解更多信息，请参考第六章，*提供安全性*，以获取有关生成自签名证书的建议。由于正确的域名对于 SSL 的工作至关重要，我们将继续将 Apache Web 服务器的配置域名命名为`centos7.home`以使此操作生效（根据您的需要进行更改）。

## 如何操作...

Apache 默认不支持 SSL 加密，因此我们将首先使用 yum 包管理器安装必要的包`mod_ssl`。

1.  首先，以 root 身份登录并输入以下命令：

    ```
    yum install mod_ssl

    ```

1.  在安装 mod_ssl 包的过程中，会自动生成一个自签名证书以及 Apache Web 服务器的密钥对；这些证书缺少您 Web 服务器域名的正确通用名称。在我们能够使用下一步中的`Makefile`重新生成我们自己的所需 SSL 文件之前，我们需要删除这些文件：

    ```
    rm /etc/pki/tls/private/localhost.key /etc/pki/tls/certs/localhost.crt

    ```

1.  我们现在需要为我们的 Apache Web 服务器创建我们打算使用的自签名证书和服务器密钥。为此，请输入以下命令：

    ```
    cd /etc/pki/tls/certs

    ```

1.  要创建自签名 Apache SSL 密钥对，包括证书及其嵌入的公钥以及私钥，请输入：

    ```
    make testcert

    ```

1.  在创建证书的过程中，首先您将被要求输入一个新的密码，然后验证它。之后，您需要第三次输入它。通常，输入一个安全的密码。然后，您将被问一系列问题。填写所有必需的详细信息，特别注意通用名称值。此值应反映您的 Web 服务器的域名或 SSL 证书所针对的 IP 地址。例如，您可以输入：

    ```
    www.centos7.home

    ```

1.  当您创建证书的过程完成后，我们将通过以下方式打开主要的 Apache SSL 配置（在备份之后）：

    ```
    cp /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf.BAK
    vi /etc/httpd/conf.d/ssl.conf

    ```

1.  向下滚动到以`<VirtualHost _default_:443>`开头的部分，并找到该块内的行`# DocumentRoot "/var/www/html"`。然后通过删除`#`字符来激活它，使其读作：

    ```
    DocumentRoot "/var/www/html"

    ```

1.  在下面，找到读作`#ServerName www.example.com:443`的行。激活此行并修改显示的值以匹配创建证书时使用的通用名称值，如下所示：

    ```
    ServerName www.centos7.home:443

    ```

1.  保存并关闭文件，接下来我们需要在我们的 firewalld 中启用 HTTPS 端口，以允许通过端口`443`进行传入的 HTTP SSL 连接：

    ```
    firewall-cmd --permanent --add-service=https && firewall-cmd --reload

    ```

1.  现在重新启动 Apache `httpd`服务以应用您的更改。请注意，如果提示，您必须输入创建 SSL 测试证书时添加的 SSL 密码：

    ```
    systemctl restart httpd

    ```

1.  做得好！现在您可以通过替换我们为服务器定义的所有可用 HTTP URL，使用 HTTPS 而不是 HTTP 来访问您的服务器。例如，转到`https://www.centos7.home`而不是`http://www.centos7.home`。

    ### 注意

    当您访问此网站时，您会收到一条警告消息，指出签名证书颁发机构是未知的。使用自签名证书时，这种异常是可以预料的，并且可以确认。

## 它是如何工作的...

我们通过使用 YUM 包管理器安装`mod_ssl`开始了这个过程，这是默认的 Apache 模块，用于启用 SSL。接下来，我们前往 CentOS 7 中所有系统证书的标准位置，即`/etc/pki/tls/certs`。在这里，我们可以找到一个`Makefile`，这是一个方便生成自签名 SSL 测试证书的辅助脚本，它为你隐藏了 OpenSSL 程序的复杂命令行参数。请记住，`Makefile`目前缺少一个`clean`选项，因此每次运行它时，我们都需要手动删除以前运行生成的任何旧版本文件，否则它将不会开始做任何事情。删除旧的 Apache SSL 文件后，我们使用`make`命令和`testcert`参数，这将为 Apache Web 服务器创建自签名证书，并将它们放在标准位置，这些位置已经在`ssl.conf`文件中配置好了（`SSLCertificateFile`和`SSLCertificateKeyFile`指令），因此我们不需要在这里做任何更改。在过程中，在完成一系列问题之前，你会被要求提供一个密码。完成问题，但要特别注意通用名称。正如在主配方中提到的，这个值应该反映你的服务器域名或 IP 地址。在下一阶段，你需要在你的首选文本编辑器中打开 Apache 的 SSL 配置文件，该文件位于`/etc/httpd/conf.d/ssl.conf`。在其中，我们启用了`DocumentRoot`指令，将其置于 SSL 控制之下，并激活了`ServerName`指令，其预期域值必须与我们定义的通用名称值相同。然后，我们保存并关闭了配置文件，并在防火墙中启用了 HTTPS 端口，从而允许通过标准 HTTPS `443`端口进行传入连接。完成这些步骤后，你现在可以享受使用自签名服务器证书的安全连接的好处。只需在任何 URL 地址前输入`https://`而不是`http://`即可。但是，如果你打算在面向公众的生产服务器上使用 SSL 证书，那么最好的选择是从受信任的证书颁发机构购买 SSL 证书。

## 还有更多...

我们了解到，由于我们的 SSL 证书受密码保护，因此每当需要重启 Apache Web 服务器时，都需要输入密码。这对于服务器重启来说是不切实际的，因为 Apache 会在没有密码的情况下拒绝启动。为了消除密码提示，我们将把密码放在一个特殊文件中，并确保只有 root 用户可以访问它。

1.  创建包含你密码的文件的备份：

    ```
    cp /usr/libexec/httpd-ssl-pass-dialog /usr/libexec/httpd-ssl-pass-dialog.BAK

    ```

1.  现在用以下内容覆盖这个密码文件，将命令行中的`XXXX`替换为你的当前 SSL 密码：

    ```
    echo -e '#!/bin/bash\necho "XXXX"' >  /usr/libexec/httpd-ssl-pass-dialog

    ```

1.  最后，更改权限，使得只有 root 用户可以读取和执行它们：

    ```
    chmod 500 /usr/libexec/httpd-ssl-pass-dialog

    ```


# 第十三章：操作系统级虚拟化

在本章中，我们将涵盖：

+   安装和配置 Docker

+   下载镜像并运行容器

+   从 Dockerfile 创建自己的镜像并上传到 Docker Hub

+   设置和使用私有 Docker 仓库

# 引言

本章是一系列食谱的集合，提供了安装、配置和使用 Docker 的基本步骤，Docker 是一个开放平台，通过操作系统级虚拟化技术构建、运输、共享和运行分布式应用程序，这种技术在 Linux 世界中已经存在多年，并且可以提供比传统虚拟化技术更快的速度和效率优势。

# 安装和配置 Docker

传统的虚拟化技术提供*硬件虚拟化*，这意味着它们创建了一个完整的硬件环境，因此每个**虚拟机**（**VM**）都需要一个完整的操作系统来运行它。因此，它们有一些主要缺点，因为它们很重，运行时会产生大量开销。这就是开源 Docker 容器化引擎提供有吸引力的替代方案的地方。它可以帮助您在 Linux 容器中构建应用程序，从而提供应用程序虚拟化。

这意味着您可以将任何选择的 Linux 程序及其所有依赖项和自己的环境打包，然后共享它或运行多个实例，每个实例都是完全隔离和分离的进程，在任何现代 Linux 内核上运行，从而提供本机运行时性能、易于移植性和高可扩展性。在这里，在本食谱中，我们将向您展示如何在您的 CentOS 7 服务器上安装和配置 Docker。

## 准备就绪

要完成本食谱，您需要一个具有 root 权限的 CentOS 7 操作系统的有效安装，您选择的基于控制台的文本编辑器，以及连接到互联网以便下载额外的`rpm`包和测试 Docker 镜像。

## 如何做到这一点...

虽然 Docker 在官方的 CentOS 7 仓库中作为一个包可用，但我们将在我们的系统上使用官方的 Docker 仓库来安装它。

1.  首先，以 root 身份登录并更新您的 YUM 包，然后使用以下命令下载并执行官方的 Docker Linux 安装脚本：

    ```
    yum update && curl -sSL https://get.docker.com/ | sh

    ```

1.  接下来，在启动 Docker 守护进程之前（第一次启动时会花费一些时间），启用 Docker 在启动时自动启动：

    ```
    systemctl enable docker && systemctl start docker

    ```

1.  最后，启动 Docker 后，您可以通过输入以下内容来验证它是否正常工作：

    ```
    docker run hello-world

    ```

## 它是如何工作的...

在 CentOS 7 上安装任何软件时，大多数情况下，使用官方 CentOS 仓库中的包而不是从第三方位置下载和安装是一个非常好的建议。在这里，我们通过使用官方 Docker 仓库安装 Docker 来做出例外。我们这样做是因为 Docker 是一个非常年轻的项目，发展迅速，变化频繁。虽然您可以使用 Docker 运行任何 Linux 应用程序，包括关键的 Web 服务器或处理机密数据的程序，但 Docker 程序中发现的或引入的错误可能会产生严重的安全后果。通过使用官方 Docker 仓库，我们确保始终能够尽快从这一快速发展的项目的开发者那里获得最新的更新和补丁。因此，将来任何时候您输入`yum update`，您的包管理器都会自动查询并检查 Docker 仓库，看看是否有新的 Docker 版本可供您使用。

那么我们从这次经历中学到了什么？

我们通过以 root 身份登录服务器并更新 YUM 包的数据库开始这个操作步骤。然后，我们使用一个命令从[`get.docker.com/`](https://get.docker.com/)下载并执行官方 Docker 安装脚本，一步完成。该脚本的作用是将官方 Docker 仓库添加到 YUM 包管理器作为新的包源，然后自动在后台安装 Docker。之后，我们通过使用`systemd`在启动时启用 Docker 服务并启动它。最后，为了测试我们的安装，我们发出了`docker run hello-world`命令，该命令从官方 Docker 注册表下载一个特殊的镜像来测试我们的安装。如果一切顺利，您应该会看到以下成功消息（输出已截断）：

```
Hello from Docker

```

这条消息表明您的安装似乎运行正常。

# 下载镜像并运行容器

一个常见的误解是 Docker 是一个运行容器的系统。Docker 只是一个构建工具，用于将任何基于 Linux 的软件及其所有依赖项打包到一个包含运行所需一切的完整文件系统中：代码、运行时、系统工具和系统库。运行 Linux 容器的技术称为操作系统级虚拟化，它提供了在每个现代 Linux 内核中默认构建的多个隔离环境。这保证了它无论部署在什么环境中都将始终以相同的方式运行；从而使您的应用程序具有可移植性。因此，当涉及到将您的 Docker 应用程序分发到 Linux 容器时，必须引入两个主要的概念性术语：**Docker 镜像**和**容器**。如果您曾经想设置并运行自己的 WordPress 安装，在本操作步骤中，我们将向您展示如何通过从官方 Docker Hub 下载预制的 WordPress 镜像来以最快的方式实现这一点；然后我们将从中运行一个容器。

## 准备就绪

要完成此教程，您需要一个具有 root 权限的 CentOS 7 操作系统的工作安装，您选择的基于控制台的文本编辑器，以及连接到互联网以便下载额外的 Docker 镜像。预计 Docker 已经安装并正在运行。

## 如何操作...

从 Docker Hub 下载的官方 WordPress 镜像不包含自己的 MySQL 服务器。相反，它依赖于外部的 MySQL 服务器，因此我们将从安装并运行一个从 Docker Hub 下载的 MySQL Docker 容器开始这个教程。

1.  首先，以 root 身份登录并键入以下命令，将`<PASSWORD>`替换为您自己选择的强 MySQL 数据库密码（在撰写本文时，最新的 WordPress 需要 MySQL v.5.7；这在未来可能会改变，因此请查看官方 WordPress Docker Hub 页面）：

    ```
    docker run --restart=always --name wordpressdb -e MYSQL_ROOT_PASSWORD=<PASSWORD> -e MYSQL_DATABASE=wordpress -d mysql:5.7

    ```

1.  接下来，安装并运行官方 WordPress 镜像，并将其作为 Docker 容器运行，将其连接到 MySQL 容器（提供与前一步骤相同的`<PASSWORD>`字符串）：

    ```
    docker run --restart=always -e WORDPRESS_DB_PASSWORD=<password> -d --name wordpress --link wordpressdb:mysql -p 8080:80 wordpress

    ```

1.  现在，MySQL 和 WordPress 容器应该已经在运行。要检查当前正在运行的容器，请键入：

    ```
    docker ps

    ```

1.  要获取所有 Docker WordPress 容器设置，请使用：

    ```
    docker inspect wordpress

    ```

1.  要检查我们的 WordPress 容器的日志文件，请运行以下命令：

    ```
    docker logs -f wordpress

    ```

1.  在同一网络中与运行 Docker 守护进程的服务器相连的计算机上打开浏览器，输入以下命令以访问您的 WordPress 安装（将 IP 地址替换为您的 Docker 服务器的 IP 地址）：

    ```
    http://<IP ADDRESS OF DOCKER SERVER>:8080/

    ```

## 它是如何工作的...

Docker 镜像是一组构成软件应用程序及其功能依赖的所有文件，以及有关您修改或改进其内容时所做的任何更改的信息（以更改日志的形式）。它是您的应用程序的不可运行、只读版本，可以与 ISO 文件相比较。如果您想运行这样的镜像，Linux 容器将自动从它创建出来。这就是实际执行的内容。它是一个真正的可扩展系统，因为您可以从同一镜像运行多个容器。正如我们所见，Docker 不仅仅是您需要与镜像和容器一起工作的工具，它还是一个完整的平台，因为它还提供了访问各种 Linux 服务器软件的预制镜像的工具。这整个 Docker 系统的美丽之处在于，大多数时候您不必重新发明轮子，试图从头开始创建自己的 Docker 镜像。只需访问 Docker Hub（[`hub.docker.com`](https://hub.docker.com)），搜索您想要作为容器运行的软件，找到它后，只需使用`docker run`命令，提供 Docker Hub 镜像的名称，就完成了。当考虑到尝试让最新流行的程序与您需要编译的所有依赖项一起工作并尝试安装它们时，Docker 真的可以成为救星。

那么我们从这次经历中学到了什么？

我们的旅程始于使用`docker run`命令，该命令从远程 Docker Hub 仓库下载了两个镜像并将其放入本地镜像存储（称为`mysql:5.7`和`wordpress`），然后运行它们（创建容器）。要获取机器上所有下载的镜像列表，请键入`docker images`。正如我们所见，两个`run`命令行都提供了`-e`命令行参数，我们需要设置一些基本的环境变量，这些变量随后将在容器内可见。这些包括我们想要运行的 MySQL 数据库以及设置和访问它们的 MySQL 根密码。这里我们看到 Docker 的一个非常重要的特性：能够相互通信的容器！通常，您可以将应用程序从不同的 Docker 容器部件堆叠在一起，使整个系统非常易于使用。另一个重要参数是`-p`，它用于从我们的主机端口`8080`创建到内部 HTTP 端口 80 的端口映射，并打开防火墙以允许此端口上的传入流量。`--restart=always`对于使图像容器可重新启动很有用，因此容器会在主机机器重新启动时自动重新启动。之后，我们向您介绍了 Docker 的`ps`命令行参数，该参数打印出所有正在运行的 Docker 容器。此命令应打印出两个名为`wordpressdb`和`wordpress`的运行容器，以及它们的`CONTAINER_ID`。此 ID 是唯一的 MD5 哈希，我们将在大多数 Docker 命令行输入中使用它，无论何时我们需要引用特定的容器（在本食谱中，我们通过容器名称引用，这也是可能的）。之后，我们向您展示了如何使用`inspect`参数打印出容器的配置。然后，为了以开放流的形式获取 Wordpress 容器的日志文件，我们使用了日志`-f`参数。最后，由于`-p 8080:80`映射允许在端口 8080 上对我们的服务器进行传入访问，因此我们可以从同一网络中的任何计算机使用浏览器访问我们的 Wordpress 安装。这将打开 Wordpress 安装屏幕。

### 注意

请注意，如果您在任何时候从 Docker 下载任何容器时遇到任何连接问题，例如`dial tcp: lookup index.docker.io: no such host`，请在再次尝试之前重新启动 Docker 服务。

## 还有更多...

在本节中，我们将向您展示如何启动和停止容器以及如何附加到您的容器。

### 停止和启动容器

在主配方中，我们使用了 Docker 的`run`命令，它实际上是两个其他 Docker 命令的包装：`create`和`start`。正如这些命令的名称所暗示的，`create`命令从现有镜像创建（克隆）一个容器，如果它不在本地镜像缓存中，则从给定的 Docker 注册表（如预定义的 Docker hub）下载它，而`start`命令实际上启动它。要获取计算机上所有容器（运行或停止）的列表，请输入：`docker ps -a`。现在识别一个停止或启动的容器，并找出其特定的`CONTAINER_ID`。然后，我们可以通过提供正确的`CONTAINER_ID`来启动一个停止的容器或停止一个运行的容器，例如`docker start CONTAINER_ID`。示例包括：`docker start 03b53947d812`或`docker stop a2fe12e61545`（`CONTAINER_ID`哈希值将根据你的计算机而变化）。

有时你可能需要删除一个容器；例如，如果你想在从镜像创建容器时完全更改其命令行参数。要删除容器，请使用`rm`命令（但请记住，它必须在停止后才能删除）：`docker stop b7f720fbfd23; docker rm b7f720fbfd23`

### 连接并与你的容器交互

Linux 容器是完全隔离的进程，在你的服务器上运行在分离的环境中，无法像使用`ssh`登录普通服务器那样登录到它。如果你需要访问容器的 BASH shell，则可以运行`docker exec`命令，这对于调试问题或修改容器（例如，安装新软件包或更新程序或文件）特别有用。请注意，这只适用于运行中的容器，并且你需要在运行以下命令之前知道容器的 ID（输入`docker ps`以查找）：`docker exec -it CONTAINER_ID /bin/bash`，例如`docker exec -it d22ddf594f0d /bin/bash`。一旦成功连接到容器，你将看到一个略有变化的命令行提示符，其中`CONTAINER_ID`作为主机名；例如，`root@d22ddf594f0d:/var/www/html#`。如果你需要退出容器，请输入`exit`。

# 通过 Dockerfiles 创建自己的镜像并上传到 Docker Hub

除了图像和容器，Docker 还有一个非常重要的术语叫做**Dockerfile**。Dockerfile 就像是一个创建特定应用程序环境的食谱，意味着它包含了构建特定镜像文件的蓝图和确切描述。例如，如果我们想要容器化一个基于 Web 服务器的应用程序，我们会在 Dockerfile 中定义所有依赖项，比如提供系统依赖项的基础 Linux 系统，如 Ubuntu、Debian、CentOS 等（这并不意味着我们*虚拟化*了完整的操作系统，而只是使用了系统依赖项），以及所有应用程序、动态库和服务，如 PHP、Apache 和 MySQL，还包括所有特殊的配置选项或环境变量。有两种方法可以构建自己的自定义镜像。一种方法是从我们之前在 Wordpress 食谱中下载的现有基础镜像开始，然后使用 BASH 附加到容器，安装额外的软件，对配置文件进行更改，然后将容器作为新镜像提交到注册表。或者，在本食谱中，我们将教您如何从新的 Dockerfile 为 Express.js Web 应用程序服务器构建自己的 Docker 镜像，并将其上传到您自己的 Docker Hub 账户。

## 准备就绪

要完成本食谱，您需要一个具有 root 权限的 CentOS 7 操作系统的工作安装，您选择的基于控制台的文本编辑器，以及连接到互联网以便与 Docker Hub 通信。预计 Docker 已经安装并正在运行。此外，为了将您的新镜像上传到 Docker Hub，您需要在 Docker Hub 上创建一个新的用户账户。只需访问[`hub.docker.com/`](https://hub.docker.com/)并免费注册。在我们的示例中，我们将使用一个虚构的新 Docker Hub 用户 ID，称为`johndoe`。

## 如何操作...

1.  首先，以 root 身份登录，使用您的 Docker Hub 用户 ID 创建一个新的目录结构（将`johndoe`目录名称适当地替换为您自己的 ID），并打开一个空的 Dockerfile，您将在其中放入镜像构建的蓝图：

    ```
    mkdir -p ~/johndoe/centos7-expressjs
    cd $_; vi Dockerfile

    ```

1.  将以下内容放入该文件中：

    ```
    FROM centos:centos7
    RUN yum install -y epel-release;yum install -y npm;
    RUN npm install express --save
    COPY . ./src
    EXPOSE 8080
    CMD ["node", "/src/index.js"]

    ```

1.  保存并关闭文件。现在创建您的第一个 Express.js Web 应用程序，我们将在新容器上部署它。在当前目录中打开以下文件：

    ```
    vi index.js

    ```

1.  现在将以下 JavaScript 内容放入：

    ```
    var express = require('express'), app = express();
    app.get('/', function (req, res) {res.send('Hello CentOS 7 cookbook!\n');});
    app.listen(8080);

    ```

1.  现在要从这个 Dockerfile 构建一个镜像，请保持在当前目录中，并使用以下命令（不要忘记此行末尾的点，并将`johndoe`替换为您自己的 Docker Hub ID）：

    ```
    docker build -t johndoe/centos7-expressjs .

    ```

1.  成功构建镜像后，让我们将其作为容器运行：

    ```
    docker run -p 8081:8080 -d johndoe/centos7-expressjs

    ```

1.  最后，测试我们是否可以向我们新创建的容器中运行的 Express.js Web 应用程序服务器发出 HTTP 请求：

    ```
    curl -i localhost:8081

    ```

1.  如果 Docker 镜像成功运行在 Express.js 服务器上，应该会出现以下 HTTP 响应（截断至最后一行）：

    ```
    Hello CentOS 7 cookbook!

    ```

### 将您的映像上传到 Docker Hub

1.  创建一个新的 Docker Hub 账号 ID，名为`johndoe`后，我们将开始使用以下命令登录网站——保持在您放置 Dockerfile 的目录中，例如`~/johndoe/centos7-expressjs`（在提示时提供用户名、密码和注册电子邮件）：

    ```
    docker login

    ```

1.  现在，要将本教程中创建的新映像推送到 Docker Hub（再次将`johndoe`替换为您自己的用户 ID），请使用：

    ```
    docker push johndoe/centos7-expressjs

    ```

1.  上传后，您将能够在 Docker Hub 网页搜索中找到您的映像。或者，您可以使用命令行：

    ```
    docker search expressjs

    ```

## 它是如何工作的...

在这篇简短的教程中，我们向您展示了如何创建您的第一个 Dockerfile，该文件将创建一个用于运行 Express.js 应用程序的 CentOS 7 容器，这是一种现代的 LAMP 堆栈替代方案，您可以在客户端和服务器端编程 JavaScript。

那么我们从这次经历中学到了什么？

如您所见，Dockerfile 是一种优雅的方式来描述创建映像的所有指令。命令易于理解，您使用特殊的关键字来指示 Docker 如何操作以从其生成映像。`FROM`命令告诉 Docker 我们应该使用哪个基础映像。幸运的是，已经有人从 CentOS 7 系统依赖项创建了基础映像（这将从 Docker Hub 下载）。接下来，我们使用`RUN`命令，它只是在 BASH 命令行上执行命令。我们使用此命令在我们的系统上安装依赖项以运行 Express.js 应用程序（它是基于 Node.js rpm 包的，我们首先通过安装 EPEL 存储库来访问它）。`COPY`命令将文件从我们的主机复制到容器上的特定位置。我们需要这个来复制我们的`index.js`文件，该文件将在稍后的步骤中创建我们所有的 Express.js Web 服务器代码到容器上。`EXPOSE`，顾名思义，将内部容器端口暴露给外部主机系统。由于默认情况下 Express.js 监听 8080 端口，我们需要在这里这样做。虽然到目前为止显示的所有这些命令只在创建映像时执行一次，但下一个命令`CMD`将在我们每次启动容器时运行。`node /src/index.js`命令将被执行，并指示系统使用`index.js`文件启动 Express.js Web 服务器（我们已经通过从主机复制它来提供此文件）。我们不想深入讨论程序的 JavaScript 部分——它只是处理 HTTP GET 请求并返回`Hello World`字符串。在本教程的第二部分中，我们向您展示了如何将我们新创建的映像推送到 Docker Hub。为此，请使用您的 Docker 用户账户登录。然后我们可以将我们的映像推送到存储库。

由于这是一个非常简单的 Dockerfile，关于这个主题还有很多要学习的内容。要查看 Dockerfile 中所有可用命令的列表，请使用`man Dockerfile`。此外，你应该访问 Docker Hub 并浏览一些有趣项目的 Dockerfiles（在*GitHub 上托管的源代码库*部分下），以学习如何仅用几个命令就能创建一些高度复杂的镜像文件。

# 设置和使用私有 Docker Registry

在本章的前一个配方中，我们已经了解到将自己的镜像上传到官方 Docker Hub 是多么容易，但我们在那里上传的所有内容都将公开。如果你在一个企业环境中处理私有或闭源项目，或者只是想在向所有人发布之前测试一些东西，那么你很可能更倾向于拥有自己的、受保护的或企业范围内的私有 Docker Registry。在本配方中，我们将向你展示如何设置和使用你自己的 Docker Registry，该 Registry 将在你自己的私有网络中可用，并通过 TLS 加密和用户认证进行保护，这样你就可以精确控制谁可以使用它（推送和拉取镜像到和从它）。

## 准备工作

要完成这个配方，你需要一个安装了 CentOS 7 操作系统并具有 root 权限的工作环境，一个你选择的基于控制台的文本编辑器，以及一个互联网连接以便下载额外的软件包。在我们的例子中，我们将在 IP 地址为`192.168.1.100`的服务器上安装 Docker Registry。根据你的需求适当调整配方的命令。你需要为这台服务器设置一个完全限定域名（FQDN），否则注册表将无法工作。为了简化，我们将使用`/etc/hosts`方法而不是设置和配置一个 DNS 服务器（如果你想这样做，请参阅第九章/Docker registry/g' | sed 's/<description>.*<\/description>//g' > /etc/firewalld/services/docker-reg.xml
    firewall-cmd --reload
    firewall-cmd --permanent --add-service=docker-reg; firewall-cmd --reload

    ```

### 需要在每个需要访问我们注册表的客户端上执行的步骤

1.  最后，我们可以通过在同一网络中的任何计算机上以 root 身份登录来测试连接到我们自己的新 TLS 增强的私有 Docker 注册表的用户身份验证。

1.  第一步是在每个想要连接到 Docker 注册表的客户端上安装 Docker：

    ```
    yum update && curl -sSL https://get.docker.com/ | sh

    ```

1.  接下来，在每个想要连接到我们新 Docker 注册表的客户端上，首先在客户端上设置服务器的证书，然后我们才能连接到它（此步骤仅在 CentOS 7 客户端上测试过）：

    ```
    mkdir -p /etc/docker/certs.d/$DCKREG\:5000
    curl http://$DCKREG/docker-registry.crt -o /tmp/cert.crt
    cp /tmp/cert.crt /etc/docker/certs.d/$DCKREG\:5000/ca.crt
    cp /tmp/cert.crt /etc/pki/ca-trust/source/anchors/docker-registry.crt
    update-ca-trust

    ```

1.  为了测试，我们首先从官方 Docker Hub 拉取一个新的小的测试镜像。使用您的 Docker Hub 帐户登录到官方 Docker Hub（请参阅本章中的前一个配方）：

    ```
    docker login

    ```

1.  现在拉取一个名为`busybox`的小镜像：

    ```
    docker pull busybox

    ```

1.  之后，将 Docker 注册表服务器切换到我们在此配方中设置的自己的服务器（输入用户名和密码，例如，`johndoe / mysecretpassword`。电子邮件字段留空）：

    ```
    docker login $DCKREG:5000

    ```

1.  接下来，为了将 Docker 镜像从客户端推送到我们新的私有 Docker 注册表，我们需要将其标记为在我们的注册表域中：

    ```
    docker tag busybox $DCKREG:5000/busybox

    ```

1.  最后，将镜像推送到我们自己的注册表：

    ```
    docker push $DCKREG:5000/busybox

    ```

1.  恭喜！你刚刚将你的第一个镜像推送到了你的私有 Docker 仓库。现在，你可以在任何配置为与我们的仓库通信的其他客户端上拉取这个镜像`$DCKREG:5000/busybox`。要获取所有可用镜像的列表，请使用（根据需要更改账户信息）：

    ```
    curl https://johndoe:mysecretpassword@$DCKREG:5000/v2/_catalog

    ```

## 它是如何工作的...

在本食谱中，我们向你展示了如何在服务器上的 Docker 容器中设置你自己的 Docker 注册表。理解这一点非常重要：你需要为你的注册表服务器配置一个 FQDN，因为这是整个系统工作的必要条件。

那么，我们从这次经历中学到了什么？

我们首先在每台计算机上通过`/etc/hosts`方法配置 Docker 注册表的完全限定域名（FQDN）。然后，我们在 Docker 注册表服务器上创建了一个新证书，该证书将用于客户端和注册表之间通过 TLS 加密进行安全通信。接下来，我们在`httpd`服务器上安装了新生成的证书，以便稍后所有客户端都可以访问；同时，在特定的 Docker 目录中，以便 Docker 也可以访问；并且在服务器默认信任的证书位置，我们还为该服务器重建了证书缓存。之后，我们使用`docker run`命令下载、安装并在该服务器上的 Docker 容器中运行我们的新 Docker 注册表。我们提供了一组参数来配置 TLS 加密和用户认证。

在下一步中，我们连接到注册表以创建新的`htpasswd`账户。每当你的注册表需要新账户时，你都可以重复此步骤。别忘了之后重启注册表容器。接下来，对于我们希望与之通信的每个客户端，我们都需要在服务器本身上的相同位置安装服务器证书；因此，我们从之前实现的 HTTP 源下载了它，并将其复制到各个位置。为了在客户端上测试，接下来我们连接到官方 Docker Hub 下载我们想要在下一步推送到我们自己的注册表的随机镜像。我们将`busybox`镜像下载到我们自己的镜像缓存中，然后切换到连接到我们的新私有 Docker 注册表。在我们能够将镜像上传到新位置之前，我们必须给它一个适合新服务器名称的适当标签，然后我们才能够将镜像推送到我们的新 Docker 注册表。该服务器现在在整个网络中端口 5000 上可用。请记住，如果你不想在客户端上再使用自己的注册表，你可以随时切换回官方`docker`仓库，使用`docker login`。

关于 Docker，还有很多东西需要学习。在本章的食谱中，我们只是触及了 Docker 平台的表面。如果你想了解更多关于它的信息，请考虑访问[`www.Packtpub.com`](https://www.Packtpub.com)，并查看该网站上提供的许多相关书籍。


# 第十四章：使用 SELinux

在本章中，我们将介绍以下主题：

+   安装和配置重要的 SELinux 工具

+   使用 SELinux 安全上下文

+   处理策略

+   故障排除 SELinux

# 引言

本章是一系列食谱的集合，旨在揭开**安全增强型 Linux**（**SELinux**）的神秘面纱，这是一种成熟的技术，用于使用基本安全系统中添加的额外安全功能来强化您的 Linux 系统。它在 CentOS 世界中已经存在多年，但对于许多系统管理员来说，它仍然是一个鲜为人知且令人困惑的话题。

# 安装和配置重要的 SELinux 工具

任何 Linux 系统最重要的安全特性是提供访问控制——通常称为**自主访问控制**（**DAC**）——它允许对象（如文件）的所有者为其设置安全属性（例如，使用`chown`和`chmod`命令决定谁可以读写文件）。虽然这种古老且非常简单的安全系统在古老的 UNIX 时代是足够的，但它并不能满足现代安全需求，其中服务器和服务不断连接到互联网。

通常，安全漏洞可以由攻击者通过利用有缺陷或配置错误的应用程序及其权限来发起。这就是为什么开发了 SELinux。其主要目的是增强 Linux 中 DAC 系统的安全性。它通过在 DAC 之上添加一个额外的安全层来实现这一点，该层称为**强制访问控制**（**MAC**），它可以为系统中的每个单独组件提供细粒度的访问控制。SELinux 已经在 CentOS 7 上启用，并且对于任何直接连接到互联网的服务器都是绝对推荐的。在本食谱中，我们将安装额外的工具并配置它们，以更好地管理您的 SELinux 系统，并帮助进行故障排除和监控过程。

## 准备工作

要完成这个食谱，您需要一个具有 root 权限的工作 CentOS 7 操作系统安装，以及一个互联网连接以下载额外的软件包。为了获得最佳学习体验，建议您按照本章中出现的顺序逐个食谱地进行，因为它们是相互构建的。

## 如何操作...

在本书中，我们已经应用了诸如`semanage`之类的程序，该程序来自`rpm` `policycoreutils-python`包，以管理我们的 SELinux 环境。如果您错过了安装它，我们将从这个食谱开始这样做（如果您之前已经这样做过，请跳过步骤 1）：

1.  以 root 身份登录并安装以下基本工具包以使用 SELinux：

    ```
    yum install policycoreutils-python

    ```

1.  现在，我们需要一些额外的工具，这些工具在本书的后续过程中也将需要：

    ```
    yum install setools setools-console setroubleshoot*

    ```

1.  接下来，安装并配置 SELinux 手册页，因为它们在 CentOS 7 上默认不可用，但对于获取有关特定策略、安全上下文和 SELinux 布尔值的详细信息非常重要。首先，我们需要安装另一个软件包：

    ```
    yum install policycoreutils-devel

    ```

1.  接下来，让我们为系统上当前可用的所有 SELinux 安全上下文策略生成所有手册页，然后更新手册页数据库：

    ```
    sepolicy manpage -a -p /usr/share/man/man8; mandb

    ```

## 它是如何工作的...

通过遵循这个配方，我们安装了日常工作中需要的所有 SELinux 工具。此外，我们生成了所有可用的 SELinux 手册页，这将是我们使用 SELinux 和解决 SELinux 服务问题时的主要信息来源。

SELinux 有两个主要和基本的术语，我们需要在深入了解本章其余部分的配方之前理解：**标签**（或更技术性地，安全上下文）和**策略**。从 SELinux 的角度来看，Linux 系统被划分为许多不同的对象。例如，对象是系统中的所有文件、进程、用户、套接字和管道。在 SELinux 上下文中，每个这样的对象都获得一个特殊的标签。SELinux 策略是使用定义在它们上的标签控制对这些对象的访问的规则：在每次尝试访问这样的对象（例如，文件读取）时，系统上可用的所有 SELinux 策略都将被搜索，以查看是否有针对特定标签的规则来做出访问控制决策（允许或拒绝访问）。

那么，我们从这次经历中学到了什么？

许多系统管理员似乎避免使用 SELinux*像瘟疫一样*，并且在许多指令手册和教程中倾向于在安装 CentOS 7 后立即完全禁用它，因为人们似乎害怕它，不想弄乱它，或者甚至感到沮丧，如果某些网络服务没有正确地从盒子中工作。通常，他们将任何连接问题归咎于 SELinux，因此看起来更容易完全禁用它，而不是通过深入了解 SELinux 的内部工作来找出真正的原因。如果你禁用它，你将错过 CentOS 7 最重要的安全功能之一，这可以在攻击事件中防止对你的系统造成很大伤害！在过去的几年中，SELinux 项目已经发展了很多，并且比以往任何时候都更容易使用。出现了许多方便的工具来使用它，并且我们得到了一套完整的工作策略来使用所有主要应用程序和服务。通过安装这些工具，我们现在准备好使用 SELinux 并以最方便的方式工作。

## 还有更多...

谈到 SELinux 时，有三种不同的模式。**增强**模式是唯一真正保护我们并增强服务器安全的模式，还有另外两种模式：**禁用**和**宽容**。禁用意味着 SELinux 被关闭，这在本书中永远不会成为我们的选项，并且不再进一步讨论，因为放弃这一出色的 CentOS 特性没有意义。当禁用时，我们的系统没有通过 SELinux 得到增强，我们手头唯一的保护来源是传统的 DAC 系统。宽容模式意味着 SELinux 已开启，策略规则已加载，所有对象都带有特定的安全上下文标签，但系统并不强制执行这些策略。这就像许多基于 Linux 的命令行工具的干运行参数：它在 SELinux 增强安全保护下模拟系统，并将系统记录的每个 SELinux 策略违规行为记录下来，就像在实际运行时一样。这是调试系统或分析正常强制运行对系统可能产生的后果的好方法。

通常，如果您不确定使用 SELinux 的影响，就会使用这种模式。由于这种模式并没有真正为我们提供任何额外的安全性，如果我们想要增强安全性，最终需要切换到**强制**模式！再次强调，这是唯一保护我们的模式；SELinux 完全运行，加载了所有策略，并在系统上强制执行这些规则。您应该始终在任何系统上追求强制模式！要查看当前模式，请使用命令`sestatus`。我们可以在输出中的`当前模式`行中看到当前的 SELinux 模式。在 CentOS 7 上，SELinux 默认处于强制模式，这再次告诉我们系统完全受到其保护。要将此模式更改为宽容模式，请使用命令`setenforce` `宽容`。现在，再次使用`sestatus`验证您的设置。要恢复更改回强制模式，请使用`setenforce enforcing`。使用`setenforce`设置 SELinux 模式只是暂时设置，它不会在重启后存活（查看`sestatus`输出中的`配置模式`文件）。要永久更改此设置，请打开`/etc/selinux/config`文件并更改`SELINUX=`配置参数。

# 使用 SELinux 安全上下文

正如我们从本章前一个配方中学到的，SELinux 都是关于标签和策略的。在本配方中，我们将向您展示如何使用这些标签，也称为安全上下文。

## 准备就绪

要完成这个配方，您需要一个具有 root 权限的 CentOS 7 操作系统的安装。假设您是通过本章的配方一步步进行的，那么到目前为止，您应该已经从前一个配方中安装了 SELinux 工具，并为策略生成了所有 SELinux 手册页。您可能会注意到，本配方中我们将向您展示的一些命令已经在本书的其他配方中应用过。我们将在这里详细解释它们。为了使用`netstat`程序，请使用 YUM 包管理器安装`net-tools`包。

## 如何做到这一点...

正如我们在之前的配方中学到的，SELinux 系统中的几乎每个组件都是一个对象（文件、目录、进程、用户等）。我们将从这个配方开始，向您展示如何使用`-Z`命令行标志打印出所有类型的对象的 SELinux 标签，这是 SELinux 系统上的许多基本 Linux 命令所支持的。

1.  首先，以 root 身份登录并键入以下命令，以从各种类型的对象探索 SELinux 安全上下文信息：

    ```
    id -Z
    ls -Z
    ps -auxZ
    netstat -tulpenZ

    ```

1.  接下来，要列出系统上所有文件和目录的可用安全上下文名称，请使用以下命令（我们仅过滤了`httpd`标签）：

    ```
    semanage fcontext -l | grep httpd

    ```

1.  接下来，让我们创建一个我们可以操作的新空文件：

    ```
    touch /tmp/selinux-context-test.txt

    ```

1.  显示新文件的当前安全上下文（应包含类型`user_tmp_t`）：

    ```
    ls -Z /tmp/selinux-context-test.txt

    ```

1.  最后，将`user_tmp_t`类型更改为随机的`samba_share_t`标签名称：

    ```
    semanage fcontext -a -t samba_share_t /tmp/selinux-context-test.txt
    restorecon -v /tmp/selinux-context-test.txt

    ```

1.  执行测试以验证您的更改：

    ```
    ls -Z /tmp/selinux-context-test.txt

    ```

## 它是如何工作的...

在本配方中，我们向您展示了如何显示各种 SELinux 对象类型的标签（安全上下文），如何显示所有可用标签名称，以及如何在文件对象的示例上修改或设置它们。在日常工作中，大多数管理员都会确认，我们必须管理安全上下文的最重要对象是文件、目录和进程。此外，您需要记住，每个 SELinux 对象只能有一个安全上下文。

那么，我们从这次经历中学到了什么？

正如我们所见，我们可以在许多不同的标准 Linux 命令行工具上使用`-Z`参数来打印出它们的 SELinux 安全上下文。在这里，我们向您展示了显示用户、文件和目录、进程以及网络连接标签的示例，我们可以使用`id`、`ls`、`ps`和`netstat`命令查询这些标签。在这些命令的输出中，我们看到每个此类对象的安全上下文标签都由三个值组成：用户（标记为`_u`）、角色（`_r`）和类型（`_t`）。类型字段被用作标准 SELinux 类型（称为目标型）中所有访问控制决策的主要机制，因此我们通常将整个 SELinux 访问控制过程称为**类型强制**（**TE**）。

对象标签中的其他值用户和角色对于非常高级的 SELinux 配置来说不是必要的，这里不讨论。为了显示我们系统上所有可用的上下文类型，使用命令行`seinfo -t`。这些 SELinux 类型是我们需要理解的一个非常重要的概念。对于文件和目录对象，它们用于*捆绑*相互关联的对象组，并且应该受到相同的保护或处理，以便我们可以对它们定义特定的策略规则。例如，我们可以将标准邮件假脱机目录`/var/spool/mail`中的每个文件分配为类型`mail_spool_t`，然后创建一个访问规则策略，在其中我们将使用此类型来允许特定的访问。在进程的上下文中，类型值称为域。在这里，类型用于隔离和*沙盒*进程：任何具有指定域名的进程只能与同一域中的其他进程通信和交互（有一些例外，如未讨论的转换）。通过域隔离进程大大降低了安全风险。当进程被攻陷时，它们只能损害自己，而不会影响其他任何东西。

### 注意

SELinux 有时被称为沙盒系统。从软件总是会有漏洞的假设出发，SELinux 提供了隔离软件组件的方法，使得一个组件的漏洞不会影响到另一个组件。

如果你输入`ps -auxZ`，你还会发现有一些进程在一个名为`unconfined_t`的域中运行。带有此标签的进程不受 SELinux 策略的保护，这意味着如果一个未受限的进程被攻陷，SELinux 不会阻止攻击者访问其他系统资源和数据。在这里，安全性退回到标准的 DAC 规则，这将成为你唯一的保护措施。

在我们讨论了如何显示安全上下文之后，接下来的章节中我们向您展示了如何设置和更改它们。在某些较旧的文档以及某些 SELinux 策略的`man`页中，您会遇到使用名为`chcon`的工具的示例，该工具用于修改对象的安全上下文。使用此工具已不再推荐，您应始终将此类命令行示例替换为较新的`semanage fcontext -a -t`命令行与`restorecon`程序的组合。对于`semanage`，您提供带有`-t`的标签类型名称，然后提供要为其设置标签的文件名。然后，使用`restorecon`，您提供要应用之前由`semanage`所做更改的文件名。这是因为安全上下文可以在两个级别上设置。它可以设置为策略并在文件系统级别上设置。`chcon`命令直接在文件系统上设置新上下文，而策略上下文未更改。这可能会导致问题，例如，如果您想稍后重置或更改文件系统的安全上下文（这称为重新标记）——这意味着所有安全上下文将从策略应用到文件系统，覆盖您使用`chcon`所做的所有更改。因此，最好使用`semanage`，它将写入策略，然后使用`restorecon`，它将使策略标签与文件系统同步，保持一切最新。如果您想为目录而不是单个文件设置标签，可以使用正则表达式；要查看一些示例和进一步的命令行选项，请键入`man semanage-fcontext`并浏览到`EXAMPLES`部分。

# 处理策略

在每个 SELinux 系统的核心是策略。这些是定义我们所有对象之间的访问权限和关系的精确规则。正如我们之前所学，我们系统的所有对象都有标签，其中一个标签是类型标识符，可用于执行策略中规定的规则。在每个启用 SELinux 的系统中，默认情况下，除非策略规则另有定义，否则对任何对象的所有访问都是禁止的。在本节中，我们将向您展示如何查询和自定义 SELinux 策略。您可能会注意到，本书中其他章节的一些命令已经应用于`httpd`或`ftpd`守护进程等。在这里，您将了解策略是如何工作的。

## 准备就绪

要完成此操作，您需要一个具有 root 权限的 CentOS 7 操作系统的正常安装。假设您是按照本章的食谱一个接一个地操作，那么到现在为止，您应该已经从之前的食谱中安装了 SELinux 工具，并为策略生成了所有 SELinux 手册页。对于我们这里的测试，我们将使用 Apache Web 服务器，因此请确保它已在您的系统上安装并运行（请参阅[第十二章](part0098_split_000.html#2TEN41-4cf34a6d07944734bb93fb0cd15cce8c "第十二章. 提供 Web 服务"），*提供 Web 服务*中的食谱*安装 Apache 并提供网页*）。

## 如何操作...

1.  首先，以 root 身份登录，并输入以下命令以显示所有 SELinux 布尔策略设置，仅过滤出`httpd`守护进程的设置：

    ```
    semanage boolean -l | grep httpd

    ```

1.  要获取有关特定策略及其包含的布尔值的更多信息，请阅读相应的手册页；例如，对于`httpd`，请输入以下内容：

    ```
    man httpd_selinux

    ```

1.  在这里，在`httpd`策略的手册页中，我们将找到有关每个可用的`httpd`策略布尔值的详细信息。例如，有一个关于`httpd_use_nfs`的部分。要切换单个策略功能，请使用`setsebool`命令以及策略布尔名称和`on`或`off`参数，如下所示：

    ```
    setsebool httpd_use_nfs on
    setsebool httpd_use_nfs off

    ```

## 它是如何工作的...

在本食谱中，我们向您展示了如何使用 SELinux 布尔值。请记住，SELinux 遵循最小权限模型，这意味着 SELinux 策略仅启用任何对象（如系统服务）执行其任务所需的最少功能，并且不会更多。这些策略功能可以通过相应的 SELinux 布尔值在运行时进行控制（激活或停用），而无需了解策略编写的内部工作原理。这是一个使策略可定制且极其灵活的概念。在本书的其他食谱中，我们已经通过启用 SELinux 布尔值来添加特殊策略功能，例如启用 Apache 或 FTP 主目录，这些功能默认情况下都是禁用的。

我们从这次经历中学到了什么？

SELinux Booleans 就像开关一样，用于启用或禁用 SELinux 策略中的某些功能。我们从这个菜谱开始使用 `semanage` 命令来显示系统上所有可用的 Booleans，并通过 `http` 过滤以获取仅与该服务相关的那些。如您所见，系统上有大量的 Booleans 可用，其中大多数是禁用或关闭的（最小权限模型）；要获取有关特定策略及其 Boolean 值的更多信息，请使用我们在之前的菜谱中安装的 SELinux 手册页。有时，找到感兴趣的特定手册页可能会很困难。使用以下命令搜索可用的手册页名称：`man -k _selinux | grep http`。在我们的示例中，`httpd_selinux` 是获取有关 `httpd` 策略详细信息的正确手册页。最后，如果我们决定切换特定的 SELinux Boolean 功能，我们将使用 `setsebool` 命令。您应该记住，以这种方式设置 Booleans 仅在重启之前有效。要使这些设置永久生效，请使用 `-p` 标志，例如，`setsebool -P httpd_use_nfs on`。

## 还有更多...

凭借我们从之前的菜谱中获得的所有知识，我们现在能够展示一个将所有内容结合起来的示例。在这里，我们将看到 `httpd` 服务的 SELinux 安全上下文和策略在行动。如果 Apache 网络服务器正在运行，我们可以使用以下行获取 `httpd` 进程的 SELinux 域名：

```
ps auxZ | grep httpd

```

这将向我们展示 `httpd` 域（类型）称为 `httpd_t`。要获取 Web 根目录的 SELinux 标签，请输入以下命令：

```
ls -alZ /var/www/html

```

这将告诉我们 Apache 网络服务器的 Web 根目录的安全上下文类型称为 `httpd_sys_content_t`。现在，有了这些信息，我们可以从我们的策略中获取 Apache 域的确切规则：

```
sesearch --allow | grep httpd_t

```

这将打印出每个 `httpd` 策略规则。如果我们过滤输出以获取 `httpd_sys_content_t` 上下文类型，以下行再次出现：

```
allow httpd_t httpd_sys_content_t : file { ioctl read getattr lock open } 

```

这向我们展示了哪些源目标上下文被允许访问，哪些目标目标上下文，以及使用哪些访问权限。在我们的 Apache Web 服务器示例中，这指定了运行在域`httpd_t`上的`httpd`进程可以访问、打开和修改文件系统上所有匹配`httpd_sys_content_t`上下文类型（所有位于`/var/www/html`目录中的文件都符合这一标准）的文件。现在，为了验证这条规则，创建一个临时文件并将其移动到 Apache Web 根目录：`echo "CentOS7 Cookbook" > /tmp/test.txt;mv /tmp/test.txt /var/www/html`。任何文件都会继承创建它的目录的安全上下文。如果我们直接在 Web 根目录中创建文件，或者复制文件（复制意味着创建一个副本），它将自动处于正确的`httpd_sys_content_t`上下文，并且完全可由 Apache 访问。但是，由于我们将文件从`/tmp`目录移动，它将保持在 Web 根目录中的`user_tmp_t`类型。如果你现在尝试获取 URL，例如，`curl http://localhost/test.txt`，你应该会收到 403 禁止消息。这是因为`user_tmp_t`类型不是`httpd_t`策略规则中文件对象的一部分，因为正如之前所说，默认情况下，未在策略规则中定义的一切都将被阻止。为了使文件可访问，我们现在将更改其安全上下文标签为正确的类型：

```
semanage fcontext -a -t httpd_sys_content_t /var/www/html/test.txt
restorecon -v /var/www/html/test.txt

```

现在再次获取`curl http://localhost/test.txt`，它应该是可访问的，并打印出正确的文本：CentOS7 cookbook。

请记住，如果你复制一个文件，安全上下文类型会从目标父目录继承。如果你想在复制时保留原始上下文，请使用`cp -preserve=context`命令。

# SELinux 故障排除

在本节中，你将学习如何排除 SELinux 策略故障，这通常在你被拒绝访问某些 SELinux 对象时需要，并且你需要找出原因。在本节中，我们将向你展示如何使用`sealert`工具，该工具将创建易于理解和处理的人类可读错误消息。

## 准备工作

为了完成本节，你需要一个具有 root 权限的 CentOS 7 操作系统的有效安装。假设你正在逐个阅读本章节，因此到现在为止，你应该已经安装了 SELinux 工具并应用了本章中的*Working with policies*节，因为我们将产生一些 SELinux 拒绝事件，以向你展示如何使用日志文件工具。

## 如何操作...

1.  开始之前，请以 root 身份登录并引发一个 SELinux 拒绝事件：

    ```
    touch /var/www/html/test2.html
    semanage fcontext -a -t user_tmp_t /var/www/html/test2.html
    restorecon -v /var/www/html/test2.html
    curl http://localhost/test2.html

    ```

1.  现在，让我们生成一个最新的人类可读日志文件：

    ```
    sealert -a /var/log/audit/audit.log

    ```

1.  在程序输出中，你将获得任何 SELinux 问题的详细描述，并且在每个所谓的警报末尾，你甚至会找到一个建议的解决方案来修复问题；在我们的示例中，感兴趣的警报应该读取（输出已截断），如下所示：

    ```
    SELinux is preventing /usr/sbin/httpd from open access on the file /var/www/html/test2.html.
    /var/www/html/test2.html default label should be httpd_sys_content_t

    ```

## 它是如何工作的...

在本食谱中，我们向您展示了如何轻松使用`sealert`程序解决 SELinux 问题。我们首先通过在 Web 根目录中创建一个新文件并为其分配错误的上下文类型值`user_tmp_t`来引发 SELinux 拒绝访问问题，该值在`httpd`策略中没有定义访问规则。然后，我们使用`curl`命令尝试获取网站，并在 SELinux 日志中实际产生**访问向量缓存**（**AVC**）拒绝消息。当 SELinux 拒绝访问时，会记录拒绝消息。所有 SELinux 日志信息的主要存储位置是审计日志文件，该文件位于`/var/log/audit/audit.log`，并且更容易阅读的拒绝消息也将写入`/var/log/messages`。在这里，我们不是手动搜索错误消息并合并两个日志文件，而是使用`sealert`工具，这是一个方便的程序，它将解析审计和消息日志文件，并以人类可读的格式呈现有价值的 AVC 内容。在每个警报消息的末尾，您还将找到一个针对问题的建议解决方案。请注意，这些是自动生成的消息，应在应用之前始终进行质疑。
