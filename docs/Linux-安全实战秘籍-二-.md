# Linux 安全实战秘籍（二）

> 原文：[`zh.annas-archive.org/md5/9B7E99EE96EAD6CC77971D4699E9954A`](https://zh.annas-archive.org/md5/9B7E99EE96EAD6CC77971D4699E9954A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：远程身份验证

在本章中，我们将讨论以下主题：

+   使用 SSH 进行远程服务器/主机访问

+   禁用或启用 SSH root 登录

+   通过基于密钥的登录限制远程访问到 SSH

+   远程复制文件

+   在 Ubuntu 上设置 Kerberos 服务器

# 使用 SSH 进行远程服务器/主机访问

**SSH**，或**安全外壳**，是一种协议，用于安全地登录到远程系统，是访问远程 Linux 系统的最常用方法。

## 准备工作

要了解如何使用 SSH，我们需要两个 Ubuntu 系统。一个将用作服务器，另一个将用作客户端。

## 操作步骤…

要使用 SSH，我们可以使用名为**OpenSSH**的免费软件。安装软件后，可以在 Linux 系统上使用`ssh`命令。我们将详细了解如何使用这个工具：

1.  如果要使用 SSH 的软件尚未安装，我们必须在服务器和客户端系统上都安装它。

+   在服务器系统上安装该工具的命令是：

```
 sudo apt-get install openssh-server

```

+   获得的输出将如下所示：

![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_01.jpg)

1.  接下来，我们需要安装软件的客户端版本：

```
sudo apt-get install openssh-client

```

+   获得的输出将如下所示：

![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_02.jpg)

1.  对于最新版本，安装软件后 SSH 服务将立即开始运行。如果默认情况下未运行，我们可以使用以下命令启动服务：

```
sudo service ssh start

```

+   获得的输出将如下所示：

![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_03.jpg)

1.  现在，如果我们想从客户端系统登录到服务器系统，命令将如下所示：

```
ssh remote_ip_address

```

这里，`remote_ip_address`指的是服务器系统的 IP 地址。该命令还假定客户端机器上的用户名与服务器机器上的用户名相同：

![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_04.jpg)

如果我们想使用不同的用户登录，命令将如下所示：

```
ssh username@remote_ip_address

```

+   获得的输出将如下所示：

![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_05.jpg)

1.  接下来，我们需要配置 SSH，以便根据我们的要求使用它。Ubuntu 中`sshd`的主要配置文件位于`/etc/ssh/sshd_config`。在对此文件的原始版本进行任何更改之前，使用以下命令创建备份：

```
sudo cp /etc/ssh/sshd_config{,.bak}

```

+   配置文件定义了服务器系统上 SSH 的默认设置。

1.  当我们在任何编辑器中打开文件时，我们可以看到 SSH 服务器监听传入连接的默认端口声明为`22`。我们可以将其更改为任何非标准端口以保护服务器免受随机端口扫描，从而使其更安全。假设我们将端口更改为`888`，那么下次客户端想要连接到 SSH 服务器时，命令将如下所示：

```
ssh -p port_number remote_ip_address

```

+   获得的输出将如下所示：

![操作步骤…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_06.jpg)

正如我们所看到的，当我们在不指定端口号的情况下运行命令时，连接会被拒绝。接下来，当我们提到正确的端口号时，连接将建立。

## 工作原理…

SSH 用于将客户端程序连接到 SSH 服务器。在一个系统上，我们安装`openssh-server`软件包使其成为 SSH 服务器，在另一个系统上，我们安装`openssh-client`软件包以将其用作客户端。

现在，保持服务器系统上的 SSH 服务运行，我们尝试通过客户端连接到它。

我们使用 SSH 的配置文件来更改设置，比如连接的默认端口。

# 禁用或启用 SSH root 登录

Linux 系统默认具有一个启用的 root 帐户。如果未经授权的用户获得 SSH root 访问权限，这不是一个好主意，因为这将使攻击者完全访问系统。

我们可以根据需要禁用或启用 SSH 的 root 登录，以防止攻击者获取对系统的访问权限。

## 准备工作

我们需要两个 Linux 系统，一个用作服务器，一个用作客户端。在服务器系统上，安装`openssh-server`软件包，如前面的示例所示。

## 操作步骤…

首先，我们将看到如何禁用 SSH root 登录，然后我们还将看到如何再次启用它：

1.  首先，在任何编辑器中打开 SSH 的主配置文件`/etc/ssh/sshd_config`。

```
sudo nano /etc/ssh/sshd_config

```

1.  现在寻找以下内容的行：

```
PermitRootLogin yes

```

1.  将值从`yes`更改为`no`。然后，保存并关闭文件：

```
PermitRootLogin no

```

+   获得的输出将如下所示：

![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_07.jpg)

1.  完成后，使用以下命令重新启动 SSH 守护程序服务：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_08.jpg)

1.  现在，让我们尝试以 root 身份登录。我们应该收到一个“权限被拒绝”的错误，因为 root 登录已被禁用：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_09.jpg)

1.  现在每当我们想要以 root 身份登录时，首先我们必须以普通用户身份登录。之后，我们可以使用`su`命令切换到 root 用户。因此，未在`/etc/sudoers`文件中列出的用户帐户将无法切换到 root 用户，系统将更加安全：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_10.jpg)

1.  现在，如果我们想要再次启用 SSH root 登录，我们只需要再次编辑`/etc/ssh/sshd_config`文件，并将选项从`no`更改为`yes`：

```
PermitRootLogin yes

```

+   获得的输出将如下所示：

![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_11.jpg)

1.  然后，再次使用以下命令重新启动服务：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_12.jpg)

1.  现在，如果我们再次尝试以 root 身份登录，它将起作用：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_13.jpg)

## 它是如何工作的…

当我们尝试使用 SSH 连接到远程系统时，远程系统会检查其在`/etc/ssh/sshd_config`中的配置文件，并根据该文件中提到的详细信息决定是否允许或拒绝连接。

当我们相应地更改`PermitRootLogin`的值时，工作也会发生变化。

## 还有更多…

假设我们在系统上有许多用户帐户，并且我们需要以这样的方式编辑`/etc/ssh/sshd_config`文件，即仅允许少数指定用户进行远程访问。

```
sudo nano /etc/ssh/sshd_config

```

添加以下行：

```
AllowUsers tajinder user1

```

现在重新启动`ssh`服务：

```
sudo service ssh restart

```

现在，当我们尝试使用`user1`登录时，登录是成功的。但是，当我们尝试使用未添加到`/etc/ssh/sshd_config`文件中的`user2`登录时，登录失败，并且我们收到“权限被拒绝”的错误，如下所示：

![还有更多…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_14.jpg)

# 通过基于密钥的登录限制远程访问 SSH

即使使用用户帐户的密码保护了 SSH 登录，我们也可以通过在 SSH 中使用基于密钥的身份验证来使其更加安全。

## 准备工作

要了解基于密钥的身份验证的工作原理，我们将需要两个 Linux 系统（在我们的示例中，都是 Ubuntu 系统）。其中一个应该安装了 OpenSSH 服务器软件包。

## 如何操作…

要使用基于密钥的身份验证，我们需要创建一对密钥——私钥和公钥。

1.  在客户端或本地系统上，我们将执行以下命令生成 SSH 密钥对：

```
ssh-keygen-t rsa
```

+   获得的输出将如下所示：

![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_15.jpg)

1.  在创建密钥时，我们可以接受默认值或根据我们的意愿进行更改。它还会要求输入一个密码，您可以设置为任何内容，或者留空。

1.  密钥对将在位置`~./ssh/`中创建。切换到此目录，然后使用命令`ls –l`查看密钥文件的详细信息：![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_16.jpg)

+   我们可以看到`id_rsa`文件只能被所有者读取和写入。此权限确保文件的安全性。

1.  现在我们需要将公钥文件复制到远程 SSH 服务器。为此，我们运行以下命令：

```
ssh-copy-id 192.168.1.101
```

+   获得的输出将如下所示：

![如何操作…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_17.jpg)

1.  将启动一个 SSH 会话，并提示您输入用户帐户的密码。一旦输入了正确的密码，密钥将被复制到远程服务器。

1.  一旦公钥成功复制到远程服务器，尝试使用`ssh 192.168.1.101`命令再次登录到服务器：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_18.jpg)

我们可以看到现在不需要提示输入用户帐户的密码。因为我们已经为 SSH 密钥配置了密码，所以它已经被要求。否则，我们将被要求输入密码而不需要输入密码。

## 工作原理...

当我们创建 SSH 密钥对并将公钥移动到远程系统时，它可以作为连接到远程系统的身份验证方法。如果远程系统中存在的公钥与本地系统生成的公钥匹配，并且本地系统具有私钥以完成密钥对，就可以登录。否则，如果任何密钥文件丢失，将不允许登录。

# 远程复制文件

使用 SSH 远程管理系统非常方便。然而，许多人可能不知道 SSH 也可以帮助远程上传和下载文件。

## 准备工作

尝试文件传输工具，我们只需要两个可以相互 ping 通的 Linux 系统。在一个系统上，应安装 OpenSSH 软件包并运行 SSH 服务器。

## 如何做...

Linux 有一系列工具，可以帮助在网络计算机之间传输数据。我们将在本节中看到其中一些工作原理：

1.  假设我们在本地系统上有一个名为`myfile.txt`的文件，我们想要将其复制到远程系统。执行此操作的命令如下：

```
scp myfile.txt tajinder@sshserver.com:~Desktop/

```

+   输出显示在以下截图中：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_20.jpg)

+   在这里，文件将被复制到的远程位置是连接使用的用户帐户的`Desktop`目录。

1.  当我们检查远程 SSH 系统时，可以看到文件`myfile.txt`已成功复制：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_21.jpg)

1.  现在，假设我们在本地系统上有一个名为`mydata`的目录，我们想要将其复制到远程系统。可以使用命令中的`-r`选项来执行此操作，如下所示：

```
scp -r mydata/ tajinder@sshserver.com:~Desktop/

```

+   输出显示在以下截图中：

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_22.jpg)

1.  再次检查远程服务器，可以看到`mydata`目录已成功复制并包含所有文件：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_23.jpg)

1.  现在我们将看到如何将文件从远程系统复制回本地系统。

+   首先，在远程服务器上创建一个文件。我们的文件是`newfile.txt`：

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_24.jpg)

1.  现在，在本地系统上，转到希望复制文件的目录。然后，按照所示的命令从远程系统复制文件到本地系统的当前目录中：

```
scp –r tajinder@sshserver.com:/home/tajinder/Desktop/newfile.txt

```

+   输出显示在以下截图中：

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_25.jpg)

1.  我们还可以使用`sftp`以交互方式从远程系统复制文件，使用 FTP 命令。

1.  要做到这一点，我们首先使用以下命令开始连接：

```
sftp tajinder@sshserver.com

```

+   查看命令的执行情况：

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_26.jpg)

1.  接下来，我们可以运行任何 FTP 命令。在我们的示例中，我们尝试使用`get`命令从远程系统获取文件，如下所示：

```
get sample.txt /home/tajinder/Desktop

```

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_27.jpg)

1.  在本地系统上，现在可以检查文件是否已成功复制。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_28.jpg)

1.  SSH 也可以通过 GNOME 工作。因此，我们可以使用 GNOME 文件浏览器与远程系统建立 SSH 连接，而不是使用命令行。

1.  在 GNOME 文件浏览器中，转到**文件** -> **连接到服务器...**。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_29.jpg)

1.  在下一个窗口中，按要求输入详细信息，然后单击**连接**。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_30.jpg)

1.  现在我们可以以图形方式从远程系统复制文件到本地系统，或者反之。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_31.jpg)

## 工作原理...

要通过 SSH 远程复制文件，我们使用`scp`工具。这有助于从客户系统复制单个文件或完整目录到服务器系统上的指定位置。要复制带有所有内容的目录，我们使用命令的`-r`选项。

我们使用相同的工具从远程 SSH 服务器复制文件到客户机。但是，为此我们需要知道服务器上文件的确切位置。

与`scp`一样，我们有`sftp`工具，它用于从服务器到客户端复制文件。**SFTP**（**安全文件传输协议**）比 FTP 更好，并确保数据安全传输。

最后，我们使用 GNOME 文件浏览器以图形方式连接并在服务器和客户端之间传输文件。

# 使用 Ubuntu 设置 Kerberos 服务器

Kerberos 是一种身份验证协议，用于通过使用秘密密钥加密和受信任的第三方在不受信任的网络上进行安全身份验证。

## 准备就绪

要设置和运行 Kerberos，我们需要三个 Linux 系统（在我们的示例中，我们使用了 Ubuntu）。它们应该能够相互通信，而且它们的系统时钟也应该准确。

我们已经为每个系统分配了主机名，如此处所述：

+   Kerberos 系统：`mykerberos.com`

+   SSH 服务器系统：`sshserver.com`

+   客户端系统：`sshclient.com`

这样做之后，编辑每个系统的`/etc/hosts`文件并添加以下细节：

![准备就绪](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_32.jpg)

您的系统的 IP 地址和主机名可能不同。只需确保在进行这些更改后，它们仍然可以相互 ping 通。

## 如何操作...

现在，让我们看看如何完成 Kerberos 服务器和其他系统的设置，以供我们的示例使用。

1.  第一步是安装 Kerberos 服务器。为此，我们将在`mykerberos.com`系统上运行给定的命令：

```
sudo apt-get install krb5-admin-server krb5-kdc

```

+   输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_33.jpg)

1.  在安装过程中，将会询问一些细节。按照这里提到的细节输入：

+   对于问题“默认的 Kerberos 版本 5 领域”，在我们的情况下答案是`MYKERBEROS.COM`：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_34.jpg)

1.  对于下一个问题，“您领域的 Kerberos 服务器：”，答案是`mykerberos.com`：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_35.jpg)

1.  在下一个屏幕上，问题是“您领域的管理服务器：”，答案是`mykerberos.com`：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_36.jpg)

1.  一旦我们回答了所有问题，安装过程将完成。下一步是创建一个新的领域。为此，我们使用这个命令：

```
sudo krb5_realm

```

+   输出如下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_37.jpg)

1.  在此过程中，我们将被要求为 Kerberos 数据库创建一个密码。我们可以选择任何密码。

1.  接下来，我们需要编辑`/etc/krb5.confand`文件，并修改如下截图所示的细节。如果文件中不存在任何行，我们还需要输入这些行。转到文件中的`libdefaults`部分，并修改如下所示的值：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_38.jpg)

1.  转到`realms`部分，并修改如下截图所示的细节：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_39.jpg)

1.  接下来，转到`domain_realm`部分，并输入如下所示的行：

```
mykerberos.com = MYKERBEROS.COM
.mykerberos.com = MYKERBEROS.COM

```

+   如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_40.jpg)

1.  接下来，我们需要向 Kerberos 数据库添加代表网络上的用户或服务的原则或条目。为此，我们将使用`kadmin.local`工具。必须为参与 Kerberos 身份验证的每个用户定义原则。

通过输入以下命令来运行工具：

```
sudo kadmin.local

```

这将启动`kadmin.local`提示，如下所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_41.jpg)

1.  要查看现有的原则，我们可以输入以下命令：

```
list princs

```

1.  现在，要为用户添加一个原则，我们使用`addprinc`命令。要添加`tajinder`帐户，我们使用如下命令：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_42.jpg)

1.  要向正在添加的帐户添加`admin`角色，命令如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_43.jpg)

1.  如果我们给任何用户分配管理员角色，则取消注释`/etc/krb5kdc/kadm.acl`文件中的`*/admin`行。

1.  要检查原则是否已正确应用，使用以下命令：

```
kinit

```

1.  完成 Kerberos 系统的设置后，我们现在转移到客户端系统。首先，我们需要使用以下屏幕截图中显示的命令安装 Kerberos 的客户端软件包：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_44.jpg)

1.  在安装过程中，将会询问与安装 Kerberos 服务器时相同的问题。在这里输入与之前相同的细节。

1.  安装完成后，检查我们是否仍然能够从`sshclient.com`系统 ping 通`mykerberos.com`。

1.  现在，根据我们在`mykerberos.com`中创建的原则，获取客户端机器的票证所使用的命令如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_45.jpg)

+   如果命令运行正常，表示它正常工作。

完成上一个命令后，我们转移到第三个系统，即我们正在使用的 SSH 服务器。我们需要在该系统上安装 SSH 服务器和`krb5-config`软件包。为此，我们运行以下命令：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_46.jpg)

+   同样，我们将被问及在安装 Kerberos 服务器时提出的相同问题。在这里输入与之前相同的细节。

1.  现在编辑`/etc/ssh/sshd_config`文件以启用以下行：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_47.jpg)

1.  删除`#`，如果尚未更改，则将值更改为`yes`。进行更改后，使用以下命令重新启动 SSH 服务器：

```
sudo service ssh restart

```

1.  接下来，我们将配置 Kerberos 服务器，使其与 SSH 服务器配合工作。为此，我们运行`kadmin.local`工具，然后运行以下命令：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_48.jpg)

1.  图像中的上述命令为 SSH 服务器添加了原则。接下来，我们运行以下屏幕截图中显示的命令以创建密钥文件：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_49.jpg)

1.  现在我们将使用以下命令将密钥文件从 Kerberos 服务器系统复制到 SSH 服务器系统：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_50.jpg)

1.  我们已将文件复制到 SSH 服务器系统的`/tmp/`目录。复制完成后，将文件移动到`/etc/`目录。

1.  现在在客户端系统上，编辑`/etc/ssh/ssh_config`文件，并修改如下行：

```
GSSAPIAuthentication yes
GSSAPIDelegateCredentials yes

```

1.  现在在客户端系统上，通过运行以下命令获取票证：

```
kinit tajinder
```

1.  一旦上述命令生效，尝试使用`ssh`从客户端系统登录到 SSH 服务器系统：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_05_51.jpg)

我们应该在不被要求输入密码的情况下得到认证。

## 工作原理...

首先，在第一个系统上安装所需的软件包以创建 Kerberos 服务器。安装完成后，为服务器配置创建一个领域。为了完成配置，我们执行`/etc/krb5.conf`文件中提到的更改。

然后，我们向 Kerberos 数据库添加一个原则，以添加要使用的用户帐户。

完成后，我们转移到下一个系统，并安装 Kerberos 用户软件包以创建客户端系统。然后，我们从 Kerberos 服务器系统获取用户帐户的票证，以在客户端上使用。

接下来，我们继续到第三个系统，在那里我们安装`Openssh-server`软件包以创建 SSH 服务器。然后，我们编辑 SSH 的配置文件以启用身份验证。

现在我们回到 Kerberos 服务器系统，并为 SSH 服务器添加一个原则。我们为 SSH 服务器创建一个密钥，然后使用`scp`命令将该密钥文件从 Kerberos 服务器传输到 SSH 服务器。

现在，如果我们尝试从客户端系统登录到 SSH 服务器系统，我们会在不需要输入密码的情况下登录，因为我们之前生成的密钥被用于身份验证。


# 第六章：网络安全

在本章中，我们将讨论以下内容：

+   管理 TCP/IP 网络

+   使用 Iptables 配置防火墙

+   阻止欺骗性地址

+   阻止传入流量

+   配置和使用 TCP Wrapper

# 管理 TCP/IP 网络

当计算机连接在一起形成网络并相互交换信息和资源时，管理这些网络信息对于系统管理员来说是一项重要的任务。

## 准备就绪

在开始对 TCP/IP 配置进行任何更改之前，请确保使用以下命令创建网络管理器配置文件的备份：

![准备就绪](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_01.jpg)

同样，以相同的方式创建`/etc/network/interfaces`文件的备份。

## 如何操作...

在本节中，我们将看看如何使用命令行手动配置网络设置：

1.  在开始手动配置之前，首先让我们检查当前的 IP 地址，该地址已由 DHCP 自动分配给系统。我们可以通过右键单击顶部右侧面板中的**Networking**图标，然后选择**Connection Information**来以图形方式检查详细信息，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_02.jpg)

我们可以看到我们系统的当前 IP 地址是**192.168.1.101**。

1.  接下来，我们使用命令行检查此信息。我们输入`ifconfig`命令来执行此操作。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_03.jpg)

1.  如果我们只想检查系统上可用的以太网设备，我们可以运行此命令：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_04.jpg)

上述命令将列出系统上所有可用以太网设备的一行描述。

1.  如果我们想要更详细地了解网络接口，我们可以使用`lshw`工具。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_05.jpg)

该工具还提供有关硬件的其他功能的详细信息。

1.  现在，我们将禁用网络管理器，然后手动设置 IP 地址的详细信息。要禁用网络管理器，请编辑`/etc/NetworkManager/NetworkManager.conf`文件。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_06.jpg)

将`managed=false`改为`managed=true`并保存文件。

1.  现在，在您选择的编辑器中打开`/etc/network/interfaces`文件。我们看到，默认情况下，关于`eth0`接口没有任何信息。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_07.jpg)

1.  编辑文件，并添加以下截图中显示的信息。确保根据您的网络设置添加 IP 详细信息。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_08.jpg)

完成后，保存文件，然后重新启动计算机以**解除**网络管理器。

1.  如果我们希望创建虚拟网络适配器，我们可以将以下行添加到`/etc/network/interfaces`文件中，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_09.jpg)

通过这样做，我们已经向单个以太网卡添加了两个 IP 地址。我们可以这样做来创建网络卡的多个实例。

1.  完成上述编辑后，使用以下任一命令重新启动网络服务：

```
service network-manager restart
/etc/init.d/networking restart

```

1.  接下来，让我们看看如何配置适当的名称服务器，如果 IP 地址是手动配置的话，将要使用它。

要进行更改，请在任何编辑器中编辑`/etc/resolv.conf`文件，并添加以下行：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_10.jpg)

通过遵循上述步骤，我们将能够成功配置 IP 详细信息。

## 它是如何工作的...

系统上的 TCP/IP 设置可以是自动管理或手动管理。根据`/etc/NetworkManager/NetworkManager.conf`文件中的内容，系统将了解设置是自动管理还是手动管理。

对于手动配置，我们编辑`/etc/network/interfaces`文件，并输入先前的 IP 详细信息。完成后，我们重新启动网络服务或完全重新启动系统以使更改生效。

# 使用 Iptables 配置防火墙

保护 Linux 系统所需的一个基本步骤是设置一个良好的防火墙。大多数 Linux 发行版都预装了不同的防火墙工具。**Iptables**是 Linux 发行版中的一个默认防火墙。在较旧版本的 Linux 内核中，Ipchains 是默认防火墙。

## 准备就绪

由于 Iptables 随 Linux 发行版一起提供，因此无需安装额外的工具来使用它。但是，建议使用 Iptables 时不要使用 root 帐户。相反，使用具有超级用户访问权限的普通帐户来有效地运行命令。

## 如何做...

我们可以使用 Iptables 定义不同的规则。这些规则在检查传入和传出的流量数据包时由内核跟随：

1.  我们在系统上需要做的第一件事是使用此命令检查安装了哪个版本的 Iptables：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_11.jpg)

1.  现在，我们将使用`-L`选项检查系统中是否已存在 Iptables 的任何规则。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_12.jpg)

1.  前面的输出也可以以一种格式看到，告诉我们每个策略所需的命令。为此，使用`-S`选项，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_13.jpg)

1.  现在，我们将检查 Iptables 默认加载了哪些模块，以了解它们的正确功能，使用此命令：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_14.jpg)

1.  让我们首先在 Iptables 中添加这个，这将确保当前所有在线连接即使在我们制定规则阻止不需要的服务之后也会保持在线：

```
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

```

在这里，`-A`选项将规则附加到现有表中。`INPUT`表示此规则将附加到 Iptables 的输入链。`-m conntrack --ctstate ESTABLISHED,RELATED`命令的下几个参数确保规则仅适用于当前在线的连接。然后，`-j ACCEPT`告诉 Iptables 接受并允许与前面指定的条件匹配的数据包。

1.  现在，如果我们再次检查 Iptables 中的规则列表，我们将看到我们的规则已添加。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_15.jpg)

1.  假设我们想通过 Iptables 允许 SSH 连接。为此，我们添加此规则：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_16.jpg)

我们使用端口`22`，因为它是 SSH 的默认端口。如果您已更改服务器上 SSH 的端口，请使用前面命令中的适当端口。

1.  我们还需要确保我们的服务器继续正常运行，让服务器上的服务在不被 Iptables 的规则阻止的情况下相互通信。为此，我们希望允许发送到环回接口的所有数据包。

我们添加以下规则以允许环回访问：

```
iptables -I INPUT 1 -i lo -j ACCEPT
```

1.  在这里，`-I`选项告诉`iptables`插入一个新规则而不是追加它。它需要添加新规则的链和位置。在前面的命令中，我们将此规则添加为`INPUT`链中的第一条规则，以便它是应用的第一条规则。

1.  现在，如果我们使用`-v`选项查看 Iptables 中的规则列表，我们会注意到`lo`环回接口的规则是我们的第一条规则。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_17.jpg)

1.  假设我们已根据要求添加了允许所有数据包的规则，我们必须确保进入`INPUT`链的任何其他数据包都应该被阻止。

为此，我们将通过运行此命令修改`INPUT`链：

```
iptables –A INPUT –j DROP 

```

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_18.jpg)

前面屏幕截图中的代码显示，已将丢弃所有数据包的规则添加到`INPUT`链的列表底部。这确保每当数据包进入时，Iptables 规则按指定顺序进行检查。如果没有规则与数据包匹配，它将被丢弃，从而默认阻止数据包被接受。

1.  到目前为止，我们在 Iptables 中添加的所有规则都是非持久的。这意味着一旦系统重新启动，Iptables 中的所有规则都将消失。

因此，为了保存我们创建的规则，然后在服务器重新启动时自动加载它们，我们可以使用`iptables-persistent`软件包。

1.  使用以下命令安装软件包：

```
apt-get install iptables-persistent

```

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_19.jpg)

1.  在安装过程中，您将被问及是否要保存当前的`iptables`规则并自动加载它们。根据您的要求选择**是**或**否**。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_20.jpg)

1.  安装完成后，我们可以通过运行此命令启动软件包：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_21.jpg)

## 工作原理...

在前面的示例中，我们使用 Linux 中的 Iptables 来配置系统上的防火墙。

首先，我们浏览`iptables`命令的基本选项，然后看看如何在`iptables`中添加不同的规则。我们添加规则以允许本地主机访问和传出的活动连接。然后，我们添加一条规则以允许 SSH 连接。

接下来，我们添加一条规则，拒绝不符合前面规则的每个其他传入数据包。

最后，我们使用`iptables-persistent`软件包来保存`iptables`的规则，即使在系统重新启动后也是如此。

# 阻止伪造的地址

IP 欺骗是攻击者用来向计算机服务器发送恶意数据包的一种常见技术。这是创建具有伪造 IP 地址的 IP 数据包的过程。它主要用于**拒绝服务**（**DoS**）等攻击。

## 准备工作

如果我们希望阻止伪造的 IP 地址，我们需要有一个 IP 地址或域名列表，从中这些伪造的连接一直试图连接。

## 如何操作...

我们将尝试通过它来创建`iptables`的基本规则集，通过它我们将限制所有传入数据包，除了对我们的使用必要的数据包：

1.  第一步是创建一个规则，允许访问环回接口，以便系统上的服务可以正确地在本地相互通信。执行此命令如下：

```
iptables -A INPUT -i lo -j ACCEPT

```

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_22.jpg)

这对系统正常运行是必要的。

1.  接下来，我们为由我们的系统发起的出站连接创建一条规则：

```
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

```

这将接受所有出站流量，包括我们尝试连接到的远程服务器的响应（例如我们访问的任何网站）：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_23.jpg)

1.  让我们创建一个用于`iptables`的表。我们将其称为`blocked_ip`，但您可以选择自己喜欢的名称：

```
iptables –N blocked_ip

```

这是我们将添加要阻止的伪造 IP 地址的表。

1.  现在，我们使用以下命令将此表插入到`iptables`的`INPUT`表中：

```
iptables -I INPUT 2 -j blocked_ip

```

请注意，我们使用数字`2`来确保此规则将成为 Iptables 中从顶部开始的第二个规则。

1.  接下来，让我们将一些不良 IP 添加到我们创建的`blocked_ip`表中：

```
iptables -A blocked_ip -s 192.168.1.115 -j DROP

```

我们在这里使用`192.168.1.115` IP 地址作为示例。您可以用要阻止的 IP 地址替换它。如果您有多个要阻止的 IP 地址，请逐个将它们添加到`iptables`中。

1.  使用以下命令可以查看`iptables`中的规则列表：

```
iptables –L

```

在以下截图中显示的详细信息中，您将注意到我们正在尝试阻止的 IP 地址。您可以根据需要指定单个 IP 地址或范围。

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_24.jpg)

1.  在 Iptables 中制定规则后，我们还可以编辑`/etc/host.conf`文件。在您选择的任何编辑器中打开文件。我正在使用`nano`：

```
nano /etc/host.conf

```

现在，按照以下示例在文件中添加或编辑以下行：

```
orderbind,hosts
nospoof on

```

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_25.jpg)

在前面的示例中，`nospoof on`选项执行主机名查找返回的 IP 地址与 IP 地址查找返回的主机名进行比较。如果比较失败，此选项将生成欺骗警告。

完成后，保存并关闭文件。这也有助于保护系统免受 IP 欺骗。

## 它是如何工作的...

为了阻止伪造的 IP 地址或任何其他 IP 地址，我们再次使用 Iptables，因为它是默认的防火墙，除非我们不想使用 Linux 可用的任何其他工具。

我们再次创建规则，以允许本地主机访问系统，并保持出站活动连接保持活动状态。然后，我们在 Iptables 中创建一个表，用于维护我们想要阻止的伪造 IP 地址的列表。我们将此表添加到 Iptables 的输入链中。然后，我们可以在需要时将任何 IP 地址添加到表中，并且它将自动被阻止。

我们还使用`/etc/host.conf`文件来保护系统免受 IP 欺骗。

# 阻止传入流量

Linux 系统管理员最重要的任务之一是控制对网络服务的访问。有时，最好在服务器上阻止所有传入流量，只允许所需的服务连接。

## 准备工作

由于我们在这里也将使用 Iptables，因此不需要额外的软件包来执行这些步骤。我们只需要一个具有`超级用户`访问权限的用户帐户。但最好不要使用`root`帐户。

## 如何做...

我们将配置 Iptables 拒绝除了已从系统内部发起的流量之外的所有流量（例如获取 Web 流量的 Web 浏览器或已经启动以更新软件包或其他软件的下载）：

1.  如前面的例子所示，Iptables 中的第一个规则将允许访问本地主机数据。运行此命令以允许访问：

```
iptables -A INPUT -i lo -j ACCEPT

```

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_26.jpg)

1.  下一个规则将是接受与出站连接相关的所有流量。这也包括远程服务器对我们系统连接的响应：

```
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

```

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_27.jpg)

1.  接下来，我们将添加一个规则，以接受**时间超过**的 ICMP 数据包。这对于限时连接设置很重要：

```
iptables -A INPUT -p icmp -m icmp --icmp-type 11 -j ACCEPT

```

1.  之后，我们将添加一个规则，以接受来自远程服务器的**目标不可达** ICMP 数据包：

```
iptables -A INPUT -p icmp -m icmp --icmp-type 3/4 -j ACCEPT

```

1.  然后，添加一个规则以接受 ping 请求/响应（Echo ICMP），以保持我们系统与可能需要 ping 的 Web 服务的连接保持活动状态：

```
iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

```

1.  添加了前述规则后，通过运行此命令检查 Iptables 中的列表：

```
iptables -L

```

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_28.jpg)

1.  我们将创建一个`iptables`表，其中包含一系列可接受的规则和服务：

```
iptables -N allowed_ip

```

然后将此表添加到 Iptables 的 INPUT 链中：

```
iptables -A INPUT -j allowed_ip

```

1.  让我们添加一个规则，以便在系统上允许对 SSH 的访问。为此，我们运行此命令：

```
iptables -A allowed_ip -p tcp --dport 22 -j ACCEPT

```

1.  如果我们检查 Iptables 中的规则列表，将得到以下结果：

```
iptable -L

```

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_29.jpg)

1.  一旦我们添加了规则以接受我们想要的流量，我们现在将拒绝所有其他未设置规则的流量。为此，我们添加此规则：

```
iptables -A INPUT -j REJECT --reject-with icmp-host-unreachable

```

通过这样做，每当有人尝试连接到服务器时，将向他们发送一个**主机不可达**的 ICMP 数据包，然后将终止连接尝试。

1.  在添加了所有前述规则之后，Iptables 现在看起来与以下截图类似：

```
iptables -L

```

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_30.jpg)

## 它是如何工作的...

为了在服务器上阻止所有传入流量并只允许出站连接，我们再次使用 Iptables，因为它是 Linux 的默认防火墙。

为了允许服务器内部的正常运行，我们允许访问本地主机。

接下来，为了保持出站连接活动，我们添加一个规则以接受**时间超过**、**目标不可达**和**Echo ICMP**数据包。

添加了这些规则后，我们可以决定是否希望允许特定服务（如 SSH）的任何传入流量，或者特定客户端地址的流量。为此，我们创建一个表格，以添加我们希望允许的客户端的 IP 地址列表。我们添加了一个规则，以允许根据我们的要求访问 SSH 服务或任何其他服务。

最后，我们添加了一个规则，拒绝所有未添加规则的流量。

# 配置和使用 TCP Wrapper

通过限制访问来保护服务器是一项关键措施，在设置服务器时绝不能忽视。使用 TCP Wrappers，我们可以只允许我们配置并支持 TCP Wrappers 的网络访问我们服务器的服务。

## 准备工作

为了演示这些步骤，我们使用两个位于同一网络上并且可以成功 ping 通对方的系统。一个系统将用作服务器，另一个将用作客户端。

## 如何做？

Linux 提供了多种工具来控制对网络服务的访问。TCP Wrappers 是其中之一，并添加了额外的保护层。在这里，我们将看看如何配置 TCP Wrappers 以定义不同主机的访问权限。

1.  首先，我们需要检查程序是否支持 TCP Wrappers。为此，首先使用`which`命令找到可执行程序的路径：

```
which sshd

```

![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_31.jpg)

在这里，我们以 SSH 程序为例。

1.  接下来，我们使用`ldd`程序来检查 SSH 程序与 TCP Wrappers 的兼容性：

```
ldd /usr/sbin/sshd

```

![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_32.jpg)

如果前面的命令输出了`libwrap.so`内容，这意味着该程序受 TCP Wrappers 支持。

1.  现在，每当 SSH 程序尝试使用 TCP Wrappers 连接到服务器时，将按照以下顺序检查两个文件：

+   `/etc/hosts.allow`：如果在此文件中找到程序的匹配规则，将允许访问

+   `/etc/hosts.deny`：如果在此文件中找到程序的匹配规则，将拒绝访问

1.  如果在这两个文件中没有找到特定程序的匹配规则，将允许访问。

1.  如果我们尝试在添加任何规则之前连接到 SSH 服务器，我们会看到它成功连接。![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_33.jpg)

1.  现在假设我们想要拒绝特定系统具有给定 IP 地址的 SSH 程序的访问。然后，我们将编辑`/etc/hosts.deny`文件，如下所示：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_34.jpg)

1.  如果我们尝试从已拒绝访问的特定系统连接到 SSH 服务器，将显示以下错误：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_35.jpg)

1.  如果我们希望允许所有程序和客户端访问，可以在这两个文件中添加零规则，或者将以下行添加到`/etc/hosts.allow`文件中：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_36.jpg)

1.  如果我们想要允许具有`192.168.1.106` IP 地址的特定客户端访问所有服务，然后我们将以下行添加到`/etc/hosts.allow`文件中：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_37.jpg)

1.  如果我们想要允许特定网络上的所有客户端访问 SSH，除了具有`192.168.1.100` IP 地址的特定客户端，我们可以对`/etc/hosts.allow`文件进行以下更改：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_38.jpg)

1.  进行了上述更改后，当我们尝试通过 SSH 连接时，我们会看到以下错误：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_39.jpg)

我们可以看到一旦更改了客户端的 IP 地址，现在允许 SSH 访问，这意味着特定网络上的所有客户端都可以访问 SSH，除了被拒绝的 IP 地址。

1.  前面的步骤阻止了在`/etc/hosts.allow`文件中定义的服务规则。然而，在服务器端，我们无法知道哪个客户端尝试访问服务器以及何时。因此，如果我们想要记录客户端的所有连接尝试，我们可以编辑`/etc/hosts.allow`文件，如下所示：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_40.jpg)

在前面的屏幕截图中，`spawn`关键字定义了每当客户端发出连接请求时，它将回显由`%h`选项指定的详细信息，并将其保存在`conn.log`日志文件中。

1.  现在，当我们阅读`conn.log`文件的内容时，我们看到了这些细节：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_06_41.jpg)

该文件包含了客户端尝试连接的时间以及来自哪个 IP 地址。使用`spawn`命令的不同参数可以捕获更多的细节。

## 它是如何工作的...

我们使用 TCP Wrapper 来限制 TCP Wrapper 软件包支持的程序的访问。

我们首先使用`ldd`工具检查我们想要限制的程序是否受 TCP Wrapper 支持。

然后，根据我们的需求，在`/etc/hosts.allow`或`/etc/hosts.deny`文件中添加一条规则。

我们添加一条规则，根据我们的需求限制来自特定客户端或整个网络的程序。

使用 TCP Wrapper 中的 spawn 选项，我们甚至可以为客户端或我们限制的程序所做的连接尝试维护日志。


# 第七章：安全工具

在本章中，我们将讨论：

+   Linux sXID

+   PortSentry

+   使用 Squid 代理

+   OpenSSL 服务器

+   Tripwire

+   Shorewall

# Linux sXID

在 Linux 中，通常文件具有读、写和执行权限。除了这些权限，它还可以具有特殊权限，如**设置所有者用户 ID**（**SUID**）和**在执行时设置组 ID**（**SGID**）。由于这些权限，用户可以从他们的帐户登录，仍然以实际文件所有者的权限运行特定的文件/程序（也可以是 root）。

sXid 是用于定期监视 SUID/SGID 的工具。使用这个工具，我们可以跟踪文件和文件夹中 SUID/SGID 的更改。

## 准备就绪

要使用这个工具，我们需要在 Linux 系统上安装`sxid`软件包。我们可以使用`apt-get`命令来安装软件包，或者我们可以下载软件包并手动配置和安装它。

## 如何操作...

要开始监视 SUID/SGID 文件和文件夹，我们首先安装软件包，然后根据我们的要求配置工具：

1.  第一步是安装`sxid`软件包。为此，我们运行以下命令：

```
apt-get install sxid

```

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_01.jpg)

1.  安装完成后，我们开始编辑文件`/etc/sxid.conf`，根据我们的要求使用该工具。在您选择的任何编辑器中打开文件：

```
nano /etc/sxid.conf

```

1.  在配置文件中，查找以下截图中显示的行：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_02.jpg)

如果您希望在运行`sxid`时将更改的输出发送到您的电子邮件地址，请将`EMAIL`的值更改为任何其他电子邮件 ID。

1.  接下来，查找读取`KEEP_LOGS`的行，并将值更改为您选择的任何数字值。这个数字定义了要保留多少个日志文件：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_03.jpg)

1.  如果您希望在`sXid`找不到更改时也获得日志，那么将`ALWAYS_NOTIFY`的值更改为`yes`：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_04.jpg)

1.  我们可以定义一个目录列表，用空格分隔，作为`sXID`的`SEARCH`选项的起始点进行搜索。

但是，如果我们希望从搜索中排除任何目录，我们可以在`EXCLUDE`选项下指定它：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_05.jpg)

假设我们有一个要搜索的目录`/usr/local/share`，并且在排除列表中已经提到了`/usr/local`目录，那么它仍然会被搜索。这对于排除一个主目录并且只指定一个目录变得有用。

1.  `/etc/sxid.conf`中还有许多可以根据我们的要求进行配置的选项。编辑文件后，保存并关闭文件。

1.  现在，如果我们想要手动运行`sXid`进行抽查，我们使用以下命令：

```
sxid -c /etc/sxid.conf -k

```

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_06.jpg)

在这里，`-c`选项有助于定义`config`文件的路径，如果命令没有自动选择。`-k`选项运行该工具。

## 它是如何工作的...

首先安装`sXid`软件包，然后通过编辑文件`/etc/sxid.conf`根据我们的要求进行配置。

一旦配置完成，我们就手动运行`sXid`进行抽查。

如果需要的话，我们甚至可以在`crontab`中添加一个条目，以便在定义的时间间隔内自动运行`sXid`。

# PortSentry

作为系统管理员，一个主要的关注点是保护系统免受网络入侵。

这就是**PortSentry**的作用。它有能力检测主机系统上的扫描，并以我们选择的方式对这些扫描做出反应。

## 准备就绪

为了演示 PortSentry 的实施和使用，我们需要在同一网络上有两个系统，它们可以相互 ping 通。

此外，我们需要在一个系统上安装`Nmap`软件包，该软件包将用作客户端，另一个系统上，我们将安装和配置`PortSentry`软件包。

要安装`Nmap`软件包，请使用以下命令：

```
apt-get install nmap

```

![准备就绪](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_07.jpg)

## 如何操作？

1.  在第一个系统上，我们使用以下命令安装`Portsentry`软件包：

```
apt-get install portsentry

```

![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_08.jpg)

1.  在安装过程中，将打开一个窗口，其中包含有关`Portsentry`的一些信息。只需单击“确定”继续：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_09.jpg)

1.  安装完成后，`portsentry`立即开始监视 TCP 和 UDP 端口。我们可以通过使用以下命令检查文件`/var/log/syslog`来验证这一点：

```
grep portsentry /var/log/syslog

```

![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_10.jpg)

我们可以在日志中看到与`portsentry`相关的消息。

1.  现在，在我们用作客户端的第二台机器上，运行如下所示的`Nmap`命令：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_11.jpg)

我们还可以使用`Nmap`的任何其他命令在第一个运行`portsentry`的系统上执行 TCP 或 UDP 扫描。要了解更多关于`Nmap`命令的信息，请参阅第一章，*Linux 安全问题*。

在上述结果中，我们可以看到即使在第一个系统上运行`portsentry`时，`Nmap`也能够成功扫描。

我们甚至可以尝试从客户端 ping 服务器系统，看看在安装`portsentry`后它是否正常工作。

1.  现在让我们通过编辑服务器系统上的文件`/etc/portsentry/portsentry.conf`来配置`portsentry`。

在您选择的编辑器中打开后，查找以下行并将值更改为`1`：

![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_12.jpg)

向下滚动，然后找到并取消注释以下行：

![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_13.jpg)

接下来，取消注释以下行：

![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_14.jpg)

完成后，保存并关闭文件。

1.  接下来，编辑文件`/etc/default/portsentry`：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_15.jpg)

在上面显示的行中，我们需要说明`portsentry`应该使用 TCP 还是 ATCP 协议。

1.  现在编辑文件`/etc/portsentry/portsentry.ignore.static`，并在底部添加一行，如下面的屏幕截图所示：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_16.jpg)

在这里，`192.168.1.104`是我们试图阻止的客户机的 IP 地址。

1.  现在通过运行以下命令重新启动`portsentry`服务：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_17.jpg)

1.  完成上述步骤后，我们将再次尝试在客户机上运行`Nmap`，看看它是否仍然正常工作：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_18.jpg)

我们可以看到现在`Nmap`无法扫描 IP 地址。

1.  如果我们尝试从客户端 ping 服务器，甚至那也不起作用：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_19.jpg)

1.  如果我们检查文件`/etc/hosts.deny`，我们将看到自动添加了以下行：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_20.jpg)

1.  同样，当我们检查文件`/var/lib/portsentry/portsentry.history`时，我们得到一个类似于下面图片中最后一行的结果：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_21.jpg)

## 工作原理...

我们使用两个系统。第一个系统充当`portsentry`服务器，而另一个充当客户端。

在第一个系统上，我们安装`portsentry`软件包，在第二个系统上，我们安装`Nmap`，用于演示工作。

现在我们从客户机对服务器执行`Nmap`扫描。我们可以看到它工作正常。

之后，我们根据要求配置`portsentry`，编辑各种文件。

编辑完成后，重新启动`portsentry`服务，然后再次尝试从客户端对服务器执行`Nmap`扫描。我们看到现在扫描无法正常工作。

# 使用 Squid 代理

Squid 是一个具有各种配置和用途的 Web 代理应用程序。Squid 具有大量的访问控制，并支持不同的协议，如 HTTP、HTTPS、FTP、SSL 等。

在本节中，我们将看到如何将 Squid 用作 HTTP 代理。

## 准备就绪

要在网络上的特定系统上安装和使用 Squid，请确保该特定系统具有足够的物理内存，因为 Squid 还可以作为缓存代理服务器工作，因此需要空间来维护缓存。

我们在示例中使用的是 Ubuntu 系统，Squid 可在 Ubuntu 存储库中获得，因此我们需要确保我们的系统是最新的。为此，我们运行以下命令：

```
apt-get update

```

之后，运行以下命令：

```
apt-get upgrade

```

## 如何操作...

要在我们的系统上安装和配置 Squid，我们必须采取以下步骤：

1.  第一步是安装`squid`软件包，为此，我们运行以下命令：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_22.jpg)

1.  一旦 Squid 安装完成，它将以默认配置开始运行，该配置定义了阻止网络上所有 HTTP/HTTPs 流量。

要检查这一点，我们只需要在网络上的任何系统上配置浏览器，使用代理系统的 IP 地址作为代理，如下面的截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_23.jpg)

1.  完成后，我们现在可以尝试访问任何网站，我们将看到一个错误屏幕，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_24.jpg)

1.  现在我们将开始配置我们的代理服务器，使其按照我们的要求工作。为此，我们将在任何编辑器中编辑文件`/etc/squid3/squid.conf`。

一旦文件在编辑器中打开，搜索读作：

`TAG: visible_hostname`：在这个类别下，添加一行——`visible_hostname ourProxyServer`：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_25.jpg)

在这里，`ourProxyServer`是我们给代理服务器起的名字。你可以选择任何你喜欢的名字。

1.  接下来，搜索读作`TAG: cache_mgr`的类别，并添加一行`cache_mgr email@yourdomainname`。在这里，提及管理员的电子邮件 ID，可以联系管理员而不是`email@yourdomainname`。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_26.jpg)

1.  接下来，我们搜索以下截图中显示的行。`http_port`变量定义了 Squid 代理将监听的端口。默认端口是 3128；但是，我们可以更改为任何未被使用的端口。我们甚至可以定义 Squid 监听多个端口，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_27.jpg)

1.  现在我们需要添加规则，根据我们的需求允许网络计算机上的流量。为此，我们将搜索读作`acl localnet src 10.0.0.8`。

在这里，我们添加了我们的规则`acl localnetwork src 192.168.1.0/24`，如下图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_28.jpg)

在上述规则中，`acl`用于定义一个新规则，`localnetwork`是我们给规则起的名字。`src`定义了将要传输到代理服务器的流量的来源。我们使用子网位数定义网络 IP 地址，如前面所示。

根据我们的需求，我们可以添加任意多的规则。

1.  接下来，搜索读作`http_access allow localhost`，并在其下添加一行`http_access allow localnetwork`，以开始使用我们在上一步中添加的规则，允许流量：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_29.jpg)

1.  完成上述配置步骤后，我们使用以下命令重新启动 Squid 服务：

```
service squid3 restart

```

1.  现在我们的 Squid 代理服务器正在运行。要检查，我们可以尝试从网络上的任何系统的浏览器访问代理服务器的 IP 地址：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_30.jpg)

上面的错误屏幕告诉我们 Squid 代理工作正常。

现在我们可以尝试访问任何其他网站，它应该根据我们在 Squid 的配置文件中添加的规则打开。

## 它是如何工作的...

我们首先安装 Squid 软件包。软件包安装完成后，我们编辑其配置文件`/etc/squid3/squid.conf`，并添加主机名、管理员的电子邮件 ID 以及 Squid 将监听的端口。

然后我们创建规则，允许同一网络中所有系统的流量。一旦保存了所有配置，我们重新启动 Squid 服务，我们的代理服务器现在正在工作。

# OpenSSL 服务器

SSL 是一种用于在互联网上传输敏感信息的协议。这可能包括帐户密码、信用卡详细信息等信息。SSL 最常用于与 HTTP 协议一起进行的网络浏览。

`OpenSSL`库提供了**安全套接字层（SSL）**和**传输层安全性（TLS）**协议的实现。

## 准备工作

为了演示`OpenSSL`的使用，我们需要两个系统。一个将用作服务器，我们将在其中安装`OpenSSL`软件包和 Apache。第二个系统将用作客户端。

## 如何做...

现在我们将看到如何使用`OpenSSL`为 Apache 创建自签名证书。这将有助于加密到服务器的流量：

1.  我们首先使用以下命令在第一个系统上安装`OpenSSL`软件包：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_31.jpg)

1.  接下来，我们将在同一系统上安装 Apache，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_32.jpg)

1.  安装 Apache 后，我们需要启用 SSL 支持，这在 Ubuntu 的 Apache 软件包中是标准的。为此，我们运行以下命令：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_33.jpg)

启用 SSL 支持后，按照上面的屏幕截图重启 Apache，使用以下命令：

```
service apache2 restart

```

1.  现在在 Apache 的配置目录中创建一个目录。这是我们将保存证书文件的地方，我们将在下一步中创建这些文件：

```
mkdir /etc/apache2/ssl

```

1.  现在我们将使用以下命令创建密钥和证书：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_34.jpg)

在上述命令中，`req –x509`指定我们将创建一个符合 X.509 **证书签名请求**（**CSR**）管理的自签名证书。

`-nodes`指定将创建不受任何密码保护的密钥文件。

`-days 365`告诉我们，正在创建的证书将在一年内有效。

`-newkeyrsa:2048`告诉我们，私钥文件和证书文件将同时创建，并且生成的密钥将为 2048 位长。

下一个参数`-keyout`指定要创建的私钥的名称。

`-out`参数提及正在创建的证书文件的名称。

1.  在创建密钥和证书文件时，将会询问您一些问题。根据您的配置提供详细信息。但是，读取`通用名称（例如服务器 FQDN 或您的名称）`的选项很重要，我们必须提供域名或服务器的公共 IP：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_35.jpg)

1.  接下来，我们需要编辑文件`/etc/apache2/sites-available/default`，以配置 Apache 使用在上一步中创建的密钥文件和证书文件。

找到并编辑如下屏幕截图中显示的行。对于`ServerName`，我们提供了 Apache 服务器系统的 IP 地址：

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_36.jpg)

在同一文件中，滚动到文件末尾，在`<VirtualHost>`块关闭之前，添加以下屏幕截图中给出的行。提及在创建这些文件时使用的密钥文件名和证书文件名：

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_37.jpg)

1.  现在，在客户端系统上，打开任何浏览器，并使用`https://`协议访问 Apache 服务器的公共 IP，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_38.jpg)

浏览器将显示有关连接不安全的警告消息，因为证书未经任何受信任的机构签名。

1.  单击**我了解风险**，然后单击**添加例外**按钮将证书添加到浏览器中：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_39.jpg)

1.  下一个窗口将显示有关服务器的一些信息。要继续并添加证书，请点击**确认安全异常**：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_40.jpg)

1.  如果您希望检查证书的更多细节，请在上一个屏幕上点击**查看**，您将会看到一个新窗口显示证书的完整细节，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_41.jpg)

1.  证书成功添加后，网页加载将完成，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_42.jpg)

## 工作原理...

在此设置中，我们使用两个系统。第一个是 Apache 服务器，我们在其中安装了`OpenSSL`软件包。第二个系统作为客户端，我们将尝试连接到 Apache Web 服务器。

在第一个系统上安装 Apache 和`OpenSSL`软件包后，我们为 Apache 启用 SSL 支持。然后，我们使用`OpenSSL`工具和一些参数创建服务器密钥和服务器证书文件。

之后，我们编辑文件`/etc/apache2/sites-available/default`，以便 Apache 可以使用我们创建的密钥和证书。

完成后，我们尝试通过客户端机器上的浏览器访问 Apache Web 服务器。

我们看到它要求将新证书添加到浏览器中，完成后，我们可以使用 HTTPS 协议访问 Web 浏览器。

# Tripwire

随着对服务器的攻击数量不断增加，安全地管理服务器变得越来越复杂。很难确定每次攻击是否已被有效阻止。

**Tripwire**是一种基于主机的**入侵检测系统**（**IDS**），可用于监视不同的文件系统数据点，然后在任何文件被修改或更改时向我们发出警报。

## 准备就绪

我们只需要在 Linux 系统上安装 Tripwire 软件包来配置我们的 IDS。在下一节中，我们将看到如何安装和配置该工具。

## 如何操作...

我们将在以下步骤中讨论如何在我们的 Ubuntu 系统上安装和配置 Tripwire：

1.  第一步将是使用`apt-get`安装 Tripwire 软件包，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_43.jpg)

1.  在安装过程中，它将显示一个信息窗口。按**确定**继续。

1.  在下一个窗口中，选择**Internet Site**作为邮件配置类型，然后按**确定**：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_44.jpg)

1.  下一个窗口将要求输入**系统邮件名称**。输入您正在配置 Tripwire 的系统的域名：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_45.jpg)

1.  在下一个屏幕上按*O*继续。

1.  现在我们将被问及是否要为 Tripwire 创建密码。选择**是**并继续：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_46.jpg)

1.  现在我们将被问及是否要重建配置文件。选择**是**并继续：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_47.jpg)

1.  接下来，选择**是**以重建 Tripwire 的策略文件：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_48.jpg)

1.  接下来，提供您希望为 Tripwire 配置的密码：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_49.jpg)

它还会在下一个屏幕上要求重新确认密码。

1.  接下来，为本地密钥提供一个密码，并在下一个屏幕上重新确认：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_50.jpg)

1.  下一个屏幕确认安装过程已成功完成。按**确定**完成安装：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_51.jpg)

1.  安装成功后，我们的下一步是初始化 Tripwire 数据库。为此，我们运行如下截图中显示的命令：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_52.jpg)

在前面的输出中，我们可以看到许多文件名显示为`没有这样的文件或目录`的错误。这是因为 Tripwire 扫描其配置文件中提到的每个文件，无论它是否存在于系统中。

1.  如果我们希望删除前面屏幕截图中显示的错误，我们必须编辑文件`/etc/tripwire/tw.pol`，并注释掉我们系统中不存在的文件/目录的行。如果愿意，我们甚至可以将其保留不变，因为这不会影响 Tripwire 的工作。

1.  我们现在将测试 Tripwire 的工作情况。为此，我们将通过运行以下命令创建一个新文件：

```
touch tripwire_testing

```

您可以根据自己的选择为文件选择任何名称。

1.  现在运行 Tripwire 交互命令来测试它是否正常工作。为此，命令如下：

```
tripwire --check --interactive

```

![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_53.jpg)

我们将得到一个输出，如前面的屏幕截图所示。 Tripwire 检查所有文件/目录，如果有任何修改，将显示在结果中：

![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_54.jpg)

在我们的案例中，它显示了如前面的屏幕截图所示的一行，告诉我们在`/root`目录中添加了一个名为`tripwire_testing`的文件。

如果我们希望保留所显示的更改，只需保存自动在编辑器中打开的结果文件。

在保存结果时，系统将提示您输入本地密码。输入您在安装 Tripwire 时配置的密码。

1.  最后，我们在 crontab 中添加一个条目，以便自动运行 Tripwire 来检查文件/目录中的更改。在您选择的任何编辑器中打开文件`/etc/crontab`并添加以下行：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_55.jpg)

在这里，`00 6`告诉我们 Tripwire 将在每天 6 点检查一次。

## 它是如何工作的...

首先安装 Tripwire 软件包，并在安装过程中填写所需的详细信息。安装完成后，我们初始化 Tripwire 数据库。

之后，我们检查 Tripwire 是否正常工作。为此，我们首先在任何位置创建一个新文件，然后运行 Tripwire 交互命令。命令完成后，我们在输出中看到显示已添加的新文件。这证实了 Tripwire 的完美工作。

然后，我们编辑 Crontab 配置，以便以特定间隔自动运行 Tripwire。

# Shorewall

您是否希望将 Linux 系统设置为小型网络的防火墙？ Shorewall 通过标准 Shorewall 工具帮助我们配置企业级防火墙。

Shorewall 实际上是建立在 Iptables 之上的。但是，Shorewall 使配置变得更加容易。

## 准备工作

需要安装并运行两张网络卡的 Linux 系统才能配置 Shorewall。一张卡将用作外部网络接口，第二张卡将用作内部网络接口。在我们的示例中，我们使用`eth0`作为外部接口，`eth1`作为内部接口。

根据网络配置配置两张卡。确保您能够 ping 本地网络上的另一个系统，也能够 ping 外部网络，即互联网上的某些内容。

在这个系统上，我们将安装 Shorewall 软件包，然后根据我们的要求进行配置。

## 操作步骤...

1.  我们首先使用`apt-get`命令在系统上安装`shorewall`：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_56.jpg)

1.  安装完成后，尝试启动`shorewall`。您将收到以下错误消息：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_57.jpg)

这意味着我们需要先配置 Shorewall，然后它才能开始运行。

1.  要配置 Shorewall，请在您选择的任何编辑器中编辑文件`/etc/default/shorewall`。查找包含`startup=0`的行，并将其值更改为以下内容：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_58.jpg)

1.  接下来，编辑文件`/etc/shorewall/shorewall.conf`，找到包含`IP_FORWARDING`的行。验证其值是否设置为`On`：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_59.jpg)

1.  Shorewall 的配置文件位于`/etc/shorewall`目录中。对于其工作至关重要的最低必需文件如下：

+   接口

+   策略

+   规则

+   区域

如果在安装后在`/etc/shorewall`目录中找不到这些文件中的任何一个，我们可以在目录`/usr/share/doc/shorewall/default-config/`中找到相同的文件。

从此位置复制所需文件到`/etc/shorewall`目录。

1.  现在编辑文件`/etc/shorewall/`interfaces，并按以下图像中显示的添加行：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_60.jpg)

我们在配置中将`eth0`称为`net`，将`eth1`称为`local`。只要是字母数字且不超过五个字符，您可以选择任何其他名称。

1.  接下来，编辑文件`/etc/shorewall/zones`。区域主要用于设置是否使用`ipv4`或`ipv6`：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_61.jpg)

在前面的配置中，`fw`指的是我，或者说是 Shorewall 防火墙本身。接下来的两行定义了两个网络接口的 ipv4。

1.  现在编辑策略文件`/etc/shorewall/`。该文件主要用于设置关于谁被允许去哪里的整体策略。

该文件中的每一行都是从上到下处理的，并且每一行都是按以下格式读取的：

如果从 ____ 发送数据包到 ____，则 ______。

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_62.jpg)

在我们的示例中，如果我们读取第一个策略，它将被读取为——如果从本地发送数据包到网络，则接受它。

您可以以相同的方式添加尽可能多的策略，Shorewall 防火墙将相应地工作。

1.  最后，编辑文件`/etc/shorewall/rules`。该文件用于创建对策略的例外。如果您希望允许外部网络中的人进入内部网络，则主要使用该文件。

示例规则文件如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_63.jpg)

我们已经添加了一条规则，该规则表示如果从`net`发送数据包到`fw`，并且使用端口号`80`的`tcp`协议，则接受该数据包。

1.  一旦我们根据要求配置了上述文件，我们可以通过运行以下命令来测试设置：

```
shorewall check

```

在显示的输出中，滚动到底部，如果显示`Shorewall 配置已验证`，这意味着设置已正确完成，Shorewall 现在可以用作防火墙：

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_07_64.jpg)

1.  现在重新启动 Shorewall 服务以应用设置，如下所示：

```
service shorewall restart

```

## 工作原理...

我们首先在系统上安装 Shorewall，该系统有两个网络接口卡。

安装完成后，我们编辑`/etc/default/shorewall`文件和`/etc/shorewall/shorewall.conf`文件。

然后我们在`/etc/shorewall`位置编辑或创建这些文件：interfaces、policy、rules 和 zones。然后根据要求向每个文件添加行。

编辑完成后，我们检查一切是否正常，然后启动 Shorewall 服务以启动我们的防火墙。


# 第八章：Linux 安全发行版

在本章中，我们将讨论以下主题：

+   Kali Linux

+   pfSense

+   DEFT - 数字证据和取证工具包

+   NST - 网络安全工具包

+   Helix

# Kali Linux

Kali 是一个基于 Debian 开发的 Linux 发行版，旨在进行安全测试。Kali 预装了数百种渗透测试工具，是一个可立即使用的操作系统。我们可以通过光盘、USB 媒体或虚拟机来运行它。

通过其最新版本的 Kali 2.0，在操作系统中进行了重大更改，将其转换为滚动发布模型。现在我们可以简单地在系统上安装 Kali 2.0，并通过正常更新获取其中工具的最新版本。这意味着我们不必等待 Kali 2.1 来获取最新的东西。

## 准备就绪

要探索 Kali 2.0，请从其官方网站下载最新版本 - [`www.kali.org/downloads/`](https://www.kali.org/downloads/)。

我们可以下载 ISO，然后将其刻录到 CD/DVD 上，或创建一个可引导的 USB 设备。我们甚至可以从上面给出的链接下载 Kali Linux VMWare、Virtual Box 或 ARM 镜像。

## 如何做...

Kali 2.0 包括其更新的开发环境和工具方面的重大变化。我们将探讨这些变化，以了解其中的区别：

1.  要开始使用 Kali，我们可以安装它，也可以通过实时选项来使用它。当我们通过实时选项启动时，我们会注意到 Grub 屏幕已经改变，并且变得更加简单易用。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_01.jpg)

1.  Kali 的主系统镜像已经移至 GNOME 3，重新设计了用户界面。我们可以在登录屏幕上注意到这些变化，它已经重新设计。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_02.jpg)

1.  在登录屏幕后出现的桌面屏幕也已经重新设计。我们可以在以下截图中看到新桌面屏幕的快照：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_03.jpg)

1.  当我们点击左上角的**应用程序**时，我们会看到菜单和工具类别已经重组：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_04.jpg)

1.  我们还可以通过点击侧边栏底部的**菜单**图标来访问工具。这样，我们可以一次看到所有的工具：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_05.jpg)

1.  Kali 2.0 包括内置的屏幕录制选项，实际上是 GNOME 3 的一部分。在右上角，点击录制图标，我们会得到**开始录制**的选项。现在，您可以通过单击一次在 Kali 上所做的任何事情来制作视频。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_06.jpg)

1.  如果我们希望访问 Kali 的**设置**菜单，我们会注意到它在**应用程序**菜单下不见了。要访问**设置**，请点击右上角的**电源**图标，然后会弹出一个菜单。

在此菜单中，我们在左下角看到**设置**图标。

![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_07.jpg)

1.  当我们在上一步中点击**设置**图标时，我们会得到如下所示的设置菜单。现在根据您的要求对系统的设置进行更改。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_08.jpg)

让我们点击**详细信息**以查看有关 Kali 2.0 的更多信息

1.  我们可以在以下截图中看到有关系统的详细信息。这包括有关 GNOME 版本的信息。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_09.jpg)

每当我们希望更新 Kali 时，只需点击**详细信息**窗口上的**检查更新**按钮。

1.  要继续并检查更新，请点击**继续**，否则点击**取消**取消更新过程。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_10.jpg)

1.  如果您的系统已经是最新的，将会出现如下所示的消息。否则，可以下载可用的更新。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_11.jpg)

## 它是如何工作的...

当我们启动 Kali 2.0 时，桌面屏幕已经改变。现在我们在屏幕左侧有一个侧边栏，可以帮助我们轻松访问应用程序。

左上角的**应用程序**菜单包含不同类别下的所有工具。也可以通过底部边栏上的**菜单**图标访问这些应用程序。

接下来，我们可以看到 Kali 2.0 现在包括一个内置的屏幕录制工具，可以从右上角的菜单中访问。在同一个菜单中，我们现在可以选择访问系统设置菜单。

然后，我们看到检查系统更新的选项，以保持 Kali 的最新状态。

Kali 2.0 包含更新的工具，并且每天从 Debian 拉取四次更新，以确保系统始终保持最新状态，并且定期实施安全更新。

# pfSense

作为网络管理员，拥有防火墙和路由器至关重要。当我们谈论设置防火墙时，我们可以选择简单地安装来自任何供应商的预配置防火墙，也可以设置自己的防火墙系统。

pfSense 是一个基于 FreeBSD 的开源 Linux 发行版，专门设计用作防火墙，可以通过 Web 界面轻松管理。

## 准备工作

首先，从以下链接下载 pfSense：

[`www.pfsense.org/download/mirror.php?section=downloads`](https://www.pfsense.org/download/mirror.php?section=downloads)

根据您的需求选择正确的计算机架构和平台。

下载 pfSense 后，将 ISO 文件刻录到 CD/DVD 媒体，或者甚至可以创建现场可启动的 USB 媒体。

我们还需要一台具有两个网络接口卡的系统来安装和配置 pfSense。

## 操作步骤...

为了在我们自己的系统上设置和配置防火墙，我们需要安装和配置 pfSense，以下步骤可以帮助我们完成这一过程。

1.  当我们使用 pfSense CD/DVD 或 USB 设备引导系统时，将出现如下的启动画面：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_12.jpg)

按*6*进行“配置引导选项”

1.  在下一个屏幕上，再次按*6*打开详细信息。然后，按*1*返回上一个屏幕。

回到第一个屏幕时，按*Enter*启动 pfSense。

1.  PfSense 将开始引导。在引导过程中，我们会看到一个屏幕，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_13.jpg)

按*I*安装 pfSense。在 20 秒内快速选择该选项。

1.  下一个屏幕要求“配置控制台”。选择*接受这些设置*选项，然后按*Enter*继续。

1.  在下一个屏幕上，如果是 pfSense 新手，则选择“快速/简单安装”。否则，在安装过程中可以选择“自定义安装”以获得更高级的选项。

1.  按“确定”继续安装。安装过程现在将开始。

1.  在安装过程中，将被要求选择要安装的内核配置。选择“标准内核”，因为我们正在将 pfSense 安装在台式机或个人电脑上。如果在嵌入式平台上安装，例如路由器板，我们可以选择“嵌入式内核”选项。

1.  安装完成后，选择“重新启动”并按*Enter*完成安装。

1.  在重新启动过程中，pfSense 的默认用户名和密码将如图所示显示：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_14.jpg)

1.  重新启动后，我们现在必须根据网络配置配置我们的接口卡。两个接口的名称将如图所示显示。在您的情况下，这些名称可能不同。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_15.jpg)

1.  现在会问您“是否要立即设置 VLAN”。此时输入`n`表示“否”。

1.  现在我们需要输入要用于 WAN 的接口名称。在我们的情况下，它是`le0`。根据您的配置输入名称。

接下来，输入要用于 LAN 的接口名称。在我们的示例中，它是`le1`。

![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_16.jpg)

然后，按`Y`继续设置。

1.  设置完接口后，我们将得到如下所示的 pfSense 菜单：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_17.jpg)

1.  如果到这一步为止 WAN 和 LAN 接口的 IP 地址没有正确设置，我们可以通过从前面的菜单中选择选项`2`来手动设置 IP 地址。

1.  选择要配置的接口，然后为其提供 IP 地址：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_18.jpg)

1.  接下来，输入子网和默认网关：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_19.jpg)

1.  按照相同的步骤为 LAN 接口进行操作。完成后，屏幕上会显示一个链接，可用于访问 pfSense 的`webConfigurator`界面。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_20.jpg)

在我们的情况下，它是—`http://192.168.1.115`

1.  现在，从与 pfSense 系统相同的本地网络上的任何系统的浏览器中访问前面的链接。访问链接后，我们会得到一个登录屏幕，如图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_21.jpg)

输入默认用户名`admin`和默认密码`pfsense`进行登录。登录后可以随后更改这些详细信息。

1.  成功登录后，我们会得到 pfSense 的主要仪表板。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_22.jpg)

## 工作原理...

我们从 pfSense CD/DVD 启动，然后选择在我们的系统上安装操作系统的选项。

要安装 pfSense，我们在启动时使用选项`I`，然后使用`Quick/Easy Install`。安装完成后，我们设置两个接口卡。第一张卡根据外部网络进行配置，使用菜单中的`设置接口 IP 地址`选项。然后，我们配置 IP 地址、子网和网关地址。

接下来，我们为第二张卡重复相同的过程，根据本地网络进行配置。

配置完成后，我们可以使用第二张卡的 IP 地址从同一网络系统上的任何浏览器访问 pfSense 的 Web 界面，并根据我们的要求自定义我们的路由器/防火墙。

# DEFT – 数字取证和取证工具包

在进行计算机取证时，重要的是使用的软件能够确保文件结构的完整性。它还应该能够分析正在调查的系统，而不会对数据进行任何更改、删除或更改。

**DEFT**是为取证而设计的，基于**Lubuntu**，后者本身又基于 Ubuntu。

## 准备就绪

DEFT 可以从这个链接下载：

[`www.deftlinux.net/download/`](http://www.deftlinux.net/download/)

下载后，我们可以将映像文件刻录到 CD/DVD 媒体上，或者创建一个可引导的 USB 媒体。

## 操作步骤...

要使用 DEFT，我们需要了解 OS 中包含了什么：

1.  一旦我们启动 DEFT CD/DVD 或 USB 媒体，我们就会得到启动屏幕。首先，我们需要选择语言。完成后，我们可以选择运行 DEFT live，或者我们可以在我们的系统上安装 DEFT。

1.  在我们的示例中，我们选择了启动 DEFT live。启动完成后，我们会得到 DEFT 的主屏幕。

1.  现在，让我们了解 DEFT 中提供的不同工具。

1.  在开始菜单中，**DEFT**下的第一个子菜单包含各种**分析**工具的列表。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_23.jpg)

1.  下一个子菜单显示所有反恶意软件工具：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_24.jpg)

1.  然后，我们有与**数据恢复**相关的工具子菜单。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_25.jpg)

1.  下一个子菜单包含一系列不同的哈希工具，可用于检查和比较任何文件的哈希。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_26.jpg)

1.  在下一个子菜单中，我们获得了用于成像的工具。这些工具可在取证调查期间用于创建需要调查的系统磁盘的映像。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_27.jpg)

1.  随着 DEFT 7 的发布，还添加了用于分析移动设备的工具。这些可以在子菜单**移动取证**下找到：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_28.jpg)

1.  下一个子菜单包含**网络取证**工具。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_29.jpg)

1.  下一个菜单 OSINT 包含开源情报工具。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_30.jpg)

1.  DEFT 还包含**密码恢复**工具，可以在下一个子菜单中找到。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_31.jpg)

1.  除了前面提到的工具类别，DEFT 还包含一些报告工具，这些工具在创建报告时可能会有用。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_32.jpg)

1.  DEFT 使用 WINE 在 Linux 下执行 Windows 工具，WINE 选项可以在主菜单下找到。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_33.jpg)

## 工作原理...

我们可以安装 DEFT，或者使用 Live CD 选项将其引导到我们的系统上。引导后，我们转到开始菜单，然后转到 DEFT 菜单。在这里，我们可以在不同类别下找到各种工具。我们可以使用分析工具、数据恢复工具、移动取证工具、网络取证工具等。

DEFT 中使用 WINE 在此执行 Windows 应用程序。

# NST - 网络安全工具包

Linux 有许多发行版主要用于渗透测试。其中之一是**网络安全工具包**（**NST**），它旨在提供易于访问的开源网络安全应用程序。

NST 基于 Fedora Linux，包含专业人员和网络管理员的工具。

## 准备工作

NST 可以从其网页或直接从此链接下载：

[`sourceforge.net/projects/nst/files/`](http://sourceforge.net/projects/nst/files/)

下载后，我们可以将 ISO 刻录到 CD/DVD 上，或创建一个可启动的 USB 媒体。

## 操作步骤...

当我们了解如何使用操作系统以及操作系统中包含的工具时，使用 NST 进行渗透测试变得很容易：

1.  要使用 NST，第一步是使用 NST 引导系统。我们可以选择使用实时选项引导，也可以直接在系统上安装 NST。在我们的示例中，我们选择了实时引导选项。您可以根据自己的需求选择任何选项。引导完成后，我们会得到 NST 的默认桌面，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_34.jpg)

1.  NST 配备了一个 Web 用户界面，这是一个控制面板，可以用来对 NST 进行任何操作。但是，只有在现有用户帐户设置了密码时才能访问。要设置密码，我们点击桌面上的**设置 NST 系统密码**图标。这将打开一个终端窗口，并给您创建新密码的选项：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_35.jpg)

1.  设置密码后，我们可以从我们选择的任何浏览器访问 NST Web 用户界面。要在本地系统上访问，我们可以使用地址`http://127.0.0.1:9980/nstwui`。

如果从本地网络上的其他系统访问，则使用运行 NST 的系统的 IP 地址。

![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_36.jpg)

打开链接后，我们会提示输入用户名和密码。输入详细信息，然后点击**确定**。

1.  现在我们看到了 NSTWUI 的登录页面。在左上角，我们可以看到运行 NST 的系统的详细信息。在此下方，我们有 NST 的菜单。![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_37.jpg)

我们还可以在右上角看到系统运行时间的信息。

![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_38.jpg)

1.  NST 配备了各种工具，其中之一是**bandwidthd**。该工具显示了网络使用情况的概述，我们可以通过转到菜单**网络** | **监视器** | **bandwidthd UI**来启用它：![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_39.jpg)

1.  一旦我们点击“**启动 Bandwidthd**”，该工具将开始运行。

1.  另一个可用的重要功能是使用 Web 界面通过 SSH 执行远程活动。转到菜单**系统** | **控制管理** | **运行命令**。

将打开一个窗口，如下图所示。我们可以在这里运行任何命令。

![操作步骤...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_40.jpg)

1.  NSTWUI 还允许管理员通过 Web 界面远程重新启动或关闭服务器。要这样做，转到菜单**系统** | **控制管理** | **重新启动**。

1.  点击**继续重新启动此 NST 系统**以确认。否则，点击**退出**取消。

1.  在下一个屏幕中，输入所示的文本，然后按**确定**。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_41.jpg)

## 它是如何工作的...

安装或引导 NST 后，第一步是为现有用户帐户设置密码。这是通过使用*设置 NST 系统密码*选项完成的。

设置密码后，我们通过任何浏览器访问系统的 IP 地址来通过 Web 用户界面访问 NST。

登录 NSTWUI 后，我们会得到与网络安全相关的各种工具列表。

我们探索了一些工具，如 bandwidthd 和 SSH。

# 螺旋

在进行取证分析时，我们必须以分钟级别查看文件系统，并分析许多事情，如程序的执行，文件的下载，文件的创建等。

在这种情况下，最好在分析开始时创建磁盘的取证镜像。Helix 是创建这种镜像的最佳选择。

Helix 是用于取证调查和事件响应的基于 Linux 的 Live CD。

## 准备工作

Helix 有免费和商业形式，其免费版本可以从以下链接下载：

[`www.e-fense.com/products.php`](http://www.e-fense.com/products.php)

下载后，我们可以将映像文件刻录到 CD/DVD 上，或者我们可以创建可引导的 USB 介质。

## 如何做？

为了演示 Helix 的使用，我们可以将其安装在我们的系统上，或者我们可以使用 Live CD/DVD 或 USB 介质，如下所示：

1.  要使用 Helix，我们使用 Helix 的 Live CD 引导系统。从出现的第一个屏幕中，我们选择**引导到 Helix Live CD**选项直接引导 Helix。但是，如果您希望在系统上安装 Helix，则可以使用**安装 Helix**选项。![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_42.jpg)

1.  现在，事件响应期间执行的第一步是创建硬盘/存储的镜像，以便以后进行调查。要创建硬盘的逐位复制，我们将使用 Helix 中提供的名为**Adepto**的工具。

1.  要打开**Adepto**，请转到开始菜单，然后在**取证与 IR**下找到该工具。![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_43.jpg)

1.  当 Adepto 启动时，我们会得到应用程序的主屏幕。我们可以输入用户名或留空，然后点击**Go**继续。

1.  下一个屏幕显示了我们想要复制的设备的信息。从下拉菜单中选择设备，我们可以得到有关该设备的所有信息。在我们的情况下，我们已经选择了要复制的 USB 设备。![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_44.jpg)

1.  现在我们点击顶部的**获取**选项卡继续。现在我们需要提供源和目的地信息。完成后，按**开始**继续：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_45.jpg)

1.  一旦点击**开始**，我们可以在开始按钮下方看到进度，如下所示：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_46.jpg)

1.  可以通过点击**日志**选项卡来检查日志中的过程细节。在日志中，我们可以看到源图像的哈希验证与我们的设备成功。![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_47.jpg)

1.  现在，下一步是克隆我们想要调查的 USB 设备。为此，我们点击**恢复/克隆**选项卡。输入源和目的地，然后按**克隆**开始：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_48.jpg)

1.  我们将看到底部发生的进度。克隆过程需要时间，这也可能取决于正在复制的磁盘的大小以及系统的处理能力：![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_49.jpg)

1.  克隆完成后，我们可以验证两个设备中的数据。我们可以看到我们在第二个 USB 设备中克隆的设备的精确图像。![如何做？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_50.jpg)

1.  Adepto 为我们提供了创建有关克隆过程中发生的事件的 PDF 报告的选项。

为此，请点击“责任链”选项卡，然后在底部点击“创建 PDF”。

![如何操作？](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_08_51.jpg)

## 工作原理是...

Helix 用于法证调查，在此过程中，一个重要的任务是创建被分析的硬盘的法证镜像。

我们已经通过 Adepto 工具了解了按照前面的步骤创建 USB 设备镜像的过程。


# 第九章：修补 Bash 漏洞

在本章中，我们将学习以下概念：

+   通过 Shellshock 了解 bash 漏洞

+   Shellshock 的安全问题

+   补丁管理系统

+   在 Linux 系统上应用补丁

# 通过 Shellshock 了解 bash 漏洞

Shellshock，或者称为 Bashdoor，是 Linux 和 Unix 操作系统中大多数版本中使用的漏洞。它于 2014 年 9 月 12 日被发现，影响使用 bash shell 的所有 Linux 发行版。Shellshock 漏洞使得可以使用环境变量远程执行命令。

## 准备工作

要理解 Shellshock，我们需要一个使用早于 4.3 版本的 bash 的 Linux 系统，该版本容易受到此漏洞的影响。

## 如何做…

在本节中，我们将看看如何设置我们的系统以了解 Shellshock 漏洞的内部细节：

1.  第一步是检查 Linux 系统上 bash 的版本，以便我们可以确定我们的系统是否容易受到 Shellshock 的影响。要检查 bash 的版本，我们运行以下命令：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_01.jpg)

从 4.3 版本开始的 Bash 版本据报告易受 Shellshock 影响。在我们的示例中，我们使用的是 Ubuntu 12.04 LTS 桌面版本。从前面的图像输出中，我们可以看到这个系统是有漏洞的。

1.  现在，让我们检查漏洞是否真的存在。为此，我们运行以下代码：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_02.jpg)

一旦运行了上述命令，如果输出中打印了`shellshock`，则漏洞已确认。

1.  让我们了解漏洞的内部情况。为此，我们首先需要了解 bash shell 的变量基础知识。

1.  如果我们想在 bash 中创建一个名为`testvar`的变量，并将`shellshock`值存储在其中，我们运行以下命令：

```
testvar=""shellshock''

```

现在，如果我们想要打印这个变量的值，我们可以使用`echo`命令，如下所示：

```
echo $testvar

```

1.  我们将通过运行`bash`命令打开一个 bash 的子进程。然后，我们再次尝试在子进程中打印`testvar`变量的值：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_03.jpg)

当我们尝试在子进程中打印该值时，我们看不到任何输出。

1.  现在，我们将尝试使用 bash 的环境变量重复上述过程。当我们启动一个新的 bash shell 会话时，一些变量可供使用，这些被称为**环境变量**。

1.  将我们的`testvar`变量设置为环境变量，我们将对其进行导出。一旦导出，我们也可以在子 shell 中使用它，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_04.jpg)

1.  当我们定义变量并导出它们时，同样地，我们可以定义一个函数并导出它，以便在子 shell 中使用。以下步骤显示了如何定义一个函数并导出它：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_05.jpg)

在上面的例子中，`x`函数已被定义，并且已使用`-f`标志导出。

1.  现在，让我们定义一个新变量，命名为`testfunc`，并为其赋值，如下所示：

```
testfunc=''() { echo ''shellshock'';}''

```

上述变量可以像普通变量一样访问：

```
echo $testfunc

```

接下来，我们将导出这个变量，使其成为一个环境变量，然后尝试从子 shell 中访问它，如下所示：

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_06.jpg)

在前面的结果中发生了一些意外的事情。在父 shell 中，该变量被视为普通变量。然而，在子 shell 中，它被解释为一个函数，并执行函数体。

1.  接下来，我们将终止函数的定义，然后将任意命令传递给它。![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_07.jpg)

在上面的例子中，一旦我们启动一个新的 bash shell，定义在函数外部的代码将在 bash 启动时执行。

这是 bash shell 中的漏洞。

## 工作原理…

我们首先检查系统上运行的 bash 版本。然后，我们运行一个众所周知的代码来确认 Shellshock 漏洞是否存在。

为了了解 Shellshock 漏洞是如何工作的，我们在 bash 中创建一个变量，然后尝试将其导出到子 shell 并在那里执行。接下来，我们尝试创建另一个变量，并将其值设置为`''() { echo ''shellshock'';}''`。这样做后，当我们将这个变量导出到子 shell 并在那里执行时，我们会看到它在子 shell 中被解释为一个函数并执行其中的内容。

这就是使 bash 容易受到 Shellshock 影响的地方，特别设计的变量可以在 bash 启动时用来运行任何命令。

# Shellshock 的安全问题

在这个几乎所有东西都在线的时代，在线安全是一个重要的问题。如今，许多 Web 服务器、Web 连接设备和服务都使用 Linux 作为平台。大多数 Linux 版本使用 Unix bash shell，因此*Shellshock*漏洞可能会影响大量的网站和 Web 服务器。

在上一个步骤中，我们详细了解了 Shellshock 漏洞。现在，我们将了解如何通过 SSH 利用这个漏洞。

## 准备工作

要利用 Shellshock 漏洞，我们需要两个系统。第一个系统将被用作受害者，并且应该容易受到 Shellshock 的影响。在我们的情况下，我们将使用 Ubuntu 系统作为易受攻击的系统。第二个系统将被用作攻击者，并且可以运行任何 Linux 版本。在我们的情况下，我们将在第二个系统上运行 Kali。

受害系统将运行`openssH-server`软件包。可以使用以下命令进行安装:

```
apt-get install openssh-server

```

我们将配置此系统为易受攻击的 SSH 服务器，以展示如何利用 Shellshock 漏洞。

## 如何操作...

要了解 Shellshock 漏洞如何被用来利用 SSH 服务器，我们需要首先将我们的 SSH 服务器配置为易受攻击的系统。为此，我们将按照以下步骤进行：

1.  第一步是在 SSH 服务器系统上添加一个名为`user1`的新用户账户。我们还将`/home/user1`添加为其主目录，`/bin/bash`作为其 shell:![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_08.jpg)

添加完账户后，我们通过检查`/etc/passwd`文件进行交叉检查。

1.  接下来，我们在`/home`中为`user1`创建一个目录，并将该目录的所有权授予`user1`账户。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_09.jpg)

1.  现在，我们需要通过授权密钥来验证攻击者登录到 SSH 服务器。为此，我们将首先在攻击者的系统上使用以下命令生成这些授权密钥:![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_10.jpg)

我们可以看到公钥/私钥已经生成。

1.  生成授权密钥后，我们将通过 SFTP 将公钥发送到远程 SSH 服务器。首先，我们将`id_rsa.pub`公钥文件复制到`桌面`，然后运行连接到 SSH 服务器的 SFTP 命令。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_11.jpg)

连接后，我们使用`put`命令传输文件。

1.  在受害者 SSH 服务器系统上，我们在`/home/user1/`目录下创建一个`.ssh`目录，然后将`id_rsa.pub`文件的内容写入到`/home/user1/.ssh/`目录下的`authorized_keys`文件中:![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_12.jpg)

1.  之后，我们编辑 SSH 的配置文件`etc/ssh/sshd_config`，并启用`PublicKeyAuthentication`变量。我们还检查`AuthorizedKeysFile`是否已经正确指定:![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_13.jpg)

1.  在成功完成上述步骤后，我们可以尝试从攻击者系统登录到 SSH 服务器，以检查是否会提示输入密码:![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_14.jpg)

1.  现在，我们将创建一个基本脚本，如果用户尝试传递`date`命令作为参数，它将显示**restricted**消息。但是，如果传递的不是`date`，它将被执行。我们将把这个脚本命名为`sample.sh`：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_15.jpg)

1.  创建脚本后，我们运行以下命令为其赋予可执行权限：

```
chmod +x sample.sh

```

1.  之后，我们在`authorized_keys`文件中使用`command`选项运行我们的`sample.sh`脚本，通过添加脚本的路径，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_16.jpg)

在`authorized_keys`文件中进行上述更改，以限制用户执行预定义的一组命令，将使公钥认证变得脆弱。

1.  现在，从攻击者的系统中，尝试通过 SSH 连接到受害系统，同时传递`date`作为参数。![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_17.jpg)

我们可以看到**restricted**消息被显示出来，因为我们将脚本添加到了`authorized_keys`文件中。

1.  接下来，我们尝试将我们的 Shellshock 漏洞利用作为参数传递，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_18.jpg)

我们可以看到，尽管我们在脚本中限制了`date`命令，但这次它被执行了，并且我们得到了`date`命令的输出。

让我们看看如何利用 Shellshock 漏洞来 compromise 一个运行任何可以触发带环境变量的 bash shell 的 Apache 服务器：

1.  如果受害系统上尚未安装 Apache，我们首先使用此命令安装它：

```
apt-get install apache2

```

安装完成后，我们使用此命令启动 Apache 服务器：

```
service apache2 start

```

1.  接下来，我们转到`/usr/lib/cgi-bin/`路径，并创建一个`example.sh`脚本，其中包含以下代码，以显示一些 HTML 输出：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_19.jpg)

然后，我们通过运行此命令使其可执行：

```
chmod +x example.sh

```

1.  从攻击者的系统中，我们尝试使用名为**curl**的命令行工具远程访问`example.sh`文件：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_20.jpg)

我们得到了预期的脚本输出，即`Example Page`。

1.  现在，让我们使用 curl 发送一个恶意请求到服务器，以打印受害系统的`/etc/passwd`文件的内容，通过运行此命令：

```
curl -A ''() { :;}; echo ""Content-type: text/plain""; echo; /bin/cat /etc/passwd http://192.168.1.104/cgi-bin/example.sh

```

![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_21.jpg)

我们可以在攻击者的系统中看到输出，显示了受害系统如何可以使用 Shellshock 漏洞进行远程访问。在上述命令中，`() { :;} ;`表示一个看起来像函数的变量。在这段代码中，函数是一个单独的`:`，它什么也不做，只是一个简单的命令。

1.  我们尝试另一个命令，如下所示，来查看受害系统当前目录的内容：![如何做…](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_22.jpg)

我们在上述输出中看到了受害系统的`root`目录的内容。

## 工作原理…

在我们的 SSH 服务器系统上，我们创建一个新的用户账户，并将 bash shell 分配为其默认 shell。我们还在`/home`中为这个新用户账户创建一个目录，并将其所有权分配给这个账户。

接下来，我们配置我们的 SSH 服务器系统来认证另一个系统，使用授权密钥连接到它。

然后，我们创建一个 bash 脚本来限制特定命令，比如`date`，并将此脚本路径添加到`authorized_keys`中使用`command`选项。

之后，当我们尝试从之前配置了授权密钥的其他系统连接到 SSH 服务器时，我们会注意到，如果我们在连接时传递`date`命令作为参数，该命令会受到限制。

然而，当使用 Shellshock 漏洞传递相同的`date`命令时，我们看到了`date`命令的输出，从而显示了 Shellshock 如何被用来利用 SSH 服务器。

类似地，我们通过创建一个示例脚本并将其放置在 Apache 系统的`/usr/lib/cgi-bin`目录中来利用 Apache 服务器。

然后，我们尝试使用 curl 工具从另一个系统访问这个脚本。

您会注意到，如果我们通过 curl 访问脚本时传递了**Shellshock exploit**，我们可以远程在 Apache 服务器上运行我们的命令。

# 补丁管理系统

在当前的计算场景中，漏洞和补丁管理是一个永无止境的循环的一部分。当计算机因已知漏洞而受到攻击以被利用时，这种漏洞的补丁已经存在；然而，它尚未正确地在系统上实施，从而导致攻击。

作为系统管理员，我们必须知道哪个补丁需要安装，哪个应该被忽略。

## 准备工作

由于可以使用 Linux 的内置工具进行补丁管理，因此在执行这些步骤之前不需要配置特定的设置。

## 操作步骤

保持系统更新的最简单和最有效的方法是使用内置的更新管理器，该管理器内置在 Linux 系统中。在这里，我们将探讨 Ubuntu 系统中更新管理器的工作原理：

1.  要在 Ubuntu 中打开**更新管理器**的图形版本，请点击左侧工具栏上的**Superkey**，然后输入**update**。在这里，我们可以看到**更新管理器**：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_23.jpg)

1.  当我们打开**更新管理器**时，会出现以下对话框，显示可用于安装的不同安全更新：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_24.jpg)

选择要安装的更新，然后单击**安装更新**以继续。

1.  在同一个窗口中，我们在左下角有一个**设置**按钮。当我们点击它时，会出现一个新的**软件源**窗口，其中有更多选项可以配置**更新管理器**。

1.  第一个选项卡是**Ubuntu 软件**，它显示了下载更新所需的存储库列表。我们根据自己的需求从列表中选择选项：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_25.jpg)

1.  如果我们点击**从...下载**选项，我们会得到一个选项来更改用于下载的存储库服务器。如果我们连接到当前选择的服务器存在任何问题或服务器速度慢，这个选项是有用的。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_26.jpg)

1.  从下拉列表中，当我们选择**其他...**选项时，我们会得到一个服务器选择列表，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_27.jpg)

1.  接下来的**其他软件**选项卡用于添加 Canonical 的合作伙伴存储库：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_28.jpg)

1.  我们可以从前面的图像中选择任何选项，并单击**编辑**以更改存储库详细信息，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_29.jpg)

1.  **更新**选项卡用于定义 Ubuntu 系统如何接收更新以及何时接收更新：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_30.jpg)

1.  **身份验证**选项卡包含有关软件提供者的身份验证密钥的详细信息，这些信息是从软件存储库的维护者那里获得的：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_31.jpg)

1.  最后一个选项卡是**统计信息**，适用于希望匿名向 Ubuntu 开发者项目提供数据的用户。这些信息有助于开发人员提高软件的性能和改善用户体验。![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_32.jpg)

1.  在这些选项卡中进行任何更改后，当我们点击**关闭**时，会提示我们确认是否应该在列表中显示新的更新。点击**重新加载**或**关闭**：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_33.jpg)

1.  如果我们想要检查更新管理器从中检索所有软件包的位置列表，我们可以检查`/etc/apt/sources.list`文件的内容。然后我们会得到这个结果：![如何操作...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_34.jpg)

## 工作原理

要更新我们的 Linux 系统，我们使用内置的更新管理器，根据 Linux 发行版。

在更新管理器中，我们可以安装所有可用的更新，或者根据我们的需求使用**设置**窗口进行配置。

在**设置**窗口中，我们有选项来显示可以下载更新的存储库列表。

**设置**窗口中的第二个选项卡让我们添加 Canonical 的第三方合作伙伴存储库。

使用下一个选项卡，我们可以指定何时以及何种类型的更新应该被下载。

我们还使用设置窗口检查软件提供商的身份验证密钥。

最后一个选项卡**统计**，帮助将数据发送给 Ubuntu 项目开发人员，以改进软件的性能。

# 在 Linux 系统上应用补丁

每当在任何软件中发现安全漏洞时，都会为该软件发布安全补丁，以便修复错误。通常，我们使用内置于 Linux 中的 Update Manager 来应用安全更新。但是，对于通过编译源代码安装的软件，Update Manager 可能不太有用。

对于这种情况，我们可以将补丁文件应用到原始软件源代码上，然后重新编译软件。

## 准备工作

由于我们将使用 Linux 的内置命令来创建和应用补丁，在开始以下步骤之前不需要做任何事情。我们将创建一个 C 语言的示例程序来了解创建补丁文件的过程。

## 如何做...

在本节中，我们将看看如何使用`diff`命令为程序创建补丁，然后我们将使用`patch`命令应用补丁。

1.  第一步将是创建一个简单的 C 程序，名为`example.c`，打印`This is an example`，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_35.jpg)

1.  现在，我们将创建`example.c`的副本，并将其命名为`example_new.c`。

1.  接下来，我们编辑新的`example_new.c`文件，向其中添加一些额外的代码行，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_36.jpg)

1.  现在，`example_new.c`可以被视为`example.c`的更新版本。

1.  我们将使用`diff`命令创建一个名为`example.patch`的补丁文件：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_37.jpg)

1.  如果我们检查补丁文件的内容，我们会得到这个输出：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_38.jpg)

1.  在应用补丁之前，我们可以使用`-b`选项备份原始文件。![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_39.jpg)

你会注意到一个新的`example.c.orig`文件已经被创建，这是备份文件。

1.  在实际打补丁之前，我们可以先运行补丁文件的干跑来检查是否有任何错误。为此，我们运行以下命令：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_40.jpg)

如果我们没有收到任何错误消息，这意味着补丁文件现在可以在原始文件上运行。

1.  现在，我们将运行以下命令来将补丁应用到原始文件上：

```
patch < example.patch

```

1.  在应用补丁后，如果我们现在检查`example.c`程序的内容，我们会看到它已经更新了一些额外的代码行，就像`example_new.c`中写的那样：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_41.jpg)

1.  一旦补丁应用到原始文件上，如果我们希望撤销它，可以使用`-R`选项来实现：![如何做...](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/prac-linux-sec-cb/img/B04234_09_42.jpg)

我们可以看到在打补丁后文件的大小差异。

## 它是如何工作的...

我们首先创建一个示例 C 程序。然后，我们创建它的副本，并添加几行代码以使其成为更新版本。之后，我们使用`diff`命令创建一个补丁文件。在应用补丁之前，我们通过干跑来检查是否有任何错误。

如果我们没有错误，我们使用 patch 命令应用补丁。现在，原始文件将具有与更新版本文件相同的内容。

我们也可以使用`-R`选项来撤销补丁。
