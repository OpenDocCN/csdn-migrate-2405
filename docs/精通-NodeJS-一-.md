# 精通 NodeJS（一）

> 原文：[`zh.annas-archive.org/md5/54EB7E80445F684EF94B4738A0764C40`](https://zh.annas-archive.org/md5/54EB7E80445F684EF94B4738A0764C40)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

互联网不再是被动消费的静态网站的集合。浏览器（和移动设备）用户希望获得更丰富和互动的体验。在过去的十年左右，网络应用程序已经开始类似于桌面应用程序。此外，对信息的社交特性的认识已经激发了新型界面和可视化的发展，这些界面和可视化模拟了动态网络状态，用户可以实时查看变化，而不是被困在过去的静态快照中。

尽管我们对软件的期望已经改变，但作为软件开发人员可用的工具并没有改变太多。计算机速度更快，多核芯片架构很常见。数据存储更便宜，带宽也更便宜。然而，我们仍然继续使用在十亿用户网站和云端虚拟机群的一键式管理之前设计的工具进行开发。

由于这个原因，网络应用程序的开发仍然是一个过于昂贵和缓慢的过程。开发人员使用不同的语言、编程风格，使代码维护、调试等变得复杂。非常经常，扩展问题出现得太早，超出了通常是一个小而经验不足的团队的能力。流行的现代软件功能，如实时数据、多人游戏和协作编辑空间，需要能够承载数千个同时连接而不弯曲的系统。然而，我们仍然局限于旨在帮助我们构建 CRUD 应用程序的框架，将单个关系数据库绑定到单个服务器上的单个用户，在桌面计算机上的浏览器上运行多页网站。

Node 帮助开发人员构建更具规模的网络应用程序。Node 基于 C++构建，并捆绑了 Google 的 V8 引擎，速度快，并且理解 JavaScript。Node 将世界上最流行的编程语言和最快的 JavaScript 编译器结合在一起，并通过 C++绑定轻松访问操作系统。Node 代表了网络软件设计和构建方式的变革。

# 本书内容

第一章 *理解 Node 环境*，简要描述了 Node 试图解决的特定问题，它们在 Unix 设计哲学中的历史和根源，以及 Node 作为系统语言的强大之处。我们还将学习如何在 V8（Node 的引擎）上编写优化的现代 JavaScript，包括对语言最新特性的简要介绍，这将帮助您升级您的代码。

第二章 *理解异步事件驱动编程*，深入探讨了 Node 设计的基本特征：事件驱动、异步编程。通过本章的学习，您将了解事件、回调和定时器在 Node 中的使用，以及事件循环如何实现跨文件系统、网络和进程的高速 I/O。我们还将了解现代并发建模构造，从默认的 Node 回调模式到 Promises、Generators、async/await 和其他流程控制技术。

第三章 *在节点和客户端之间传输数据*，描述了 I/O 数据流如何通过大多数网络软件编织在一起，由文件服务器发出或者作为对 HTTP GET 请求的响应进行广播。在这里，您将学习 Node 如何通过 HTTP 服务器、可读和可写文件流以及其他 I/O 集中的 Node 模块和模式的示例来促进网络软件的设计、实现和组合。您将深入了解流的实现，掌握 Node 堆栈的这一基本部分。

第四章 *使用 Node 访问文件系统*，介绍了在 Node 中访问文件系统时需要了解的内容，如何创建文件流进行读写，以及处理文件上传和其他网络文件操作的技术。您还将使用 Electron 实现一个简单的文件浏览应用程序。

第五章 *管理许多同时的客户端连接*，向您展示了 Node 如何帮助解决当代协作 Web 应用程序所需的高容量和高并发环境所伴随的问题。通过示例，学习如何高效地跟踪用户状态，路由 HTTP 请求，处理会话，并使用 Redis 数据库和 Express Web 应用程序框架对请求进行身份验证。

第六章 *创建实时应用程序*，探讨了 AJAX、服务器发送事件和 WebSocket 协议，在构建实时系统时讨论它们的优缺点，以及如何使用 Node 实现每个协议。我们通过构建一个协作文档编辑应用程序来结束本章。

第七章 *使用多个进程*，教授如何在多核处理器上分发 Node 进程集群，以及其他扩展 Node 应用程序的技术。对单线程和多线程环境编程的差异进行调查，讨论如何在 Node 中生成、分叉和与子进程通信，包括使用 PM2 进程管理器的部分。我们还构建了一个记录和显示多个同时连接的客户端通过一组 Web 套接字的鼠标操作的分析工具。

第八章 *扩展您的应用程序*，概述了一些检测何时扩展、如何扩展以及如何在多个服务器和云服务上扩展 Node 应用程序的技术，包括如何使用 RabbitMQ 作为消息队列，使用 NGINX 代理 Node 服务器，以及在应用程序中使用亚马逊网络服务的示例。本章以我们构建一个部署在 Heroku 上的强大的客户服务应用程序结束，您将学习如何使用 Twilio SMS 网关与 Node 配合使用。

第九章 *微服务*，介绍了微服务的概念——小型、独立的服务——以及我们是如何从单片和 3 层堆栈发展到大型独立服务的动态协作模式的。我们将学习如何使用 Seneca 和 Node 创建自动发现服务网格，使用 AWS Lambda 在云中创建无限可扩展的无服务器应用程序，最后，如何创建 Docker 容器并使用 Kubernetes 编排它们的部署。

第十章 *测试您的应用程序*，解释了如何使用 Node 实现单元测试、功能测试和集成测试。我们将深入探讨如何使用本机调试和测试模块、堆转储和 CPU 分析，最终使用 Mocha 和 Chai 构建测试套件。我们将涵盖使用 Sinon 进行模拟、存根和间谍，使用 Chrome DevTools 实时调试运行中的 Node 进程，以及如何使用 Puppeteer 实现 UI 代码的无头测试。

附录 A，*将您的工作组织成模块*，提供了使用 npm 包管理系统的技巧。在这里，您将学习如何创建、发布和管理包。

附录 B，*创建自己的 C++附加组件*，简要介绍了如何构建自己的 C++附加组件以及如何在 Node 中使用它们。我们还介绍了新的**NAN（Node 的本机抽象）**工具以及它如何帮助您编写跨平台、未来证明的附加组件。

# 本书所需内容

您需要对 JavaScript 有一定的了解，并在您的开发机器或服务器上安装 Node 的副本，版本为 9.0 或更高。您应该知道如何在这台机器上安装程序，因为您需要安装 Redis，以及其他类似 Docker 的库。安装 Git，并学习如何克隆 GitHub 存储库，将极大地改善您的体验。

您应该安装 RabbitMQ，以便您可以跟随使用消息队列的示例。当然，使用 NGINX 代理 Node 服务器的部分将需要您安装和使用该 Web 服务器。要构建 C++附加组件，您需要在系统上安装适当的编译器。

本书中的示例是在基于 UNIX 的环境（包括 Mac OS X）中构建和测试的，但您也应该能够在基于 Windows 的操作系统上运行所有 Node 示例。您可以从[`www.nodejs.org`](http://www.nodejs.org)获取适用于您系统的安装程序和二进制文件。

# 本书适用对象

本书适用于希望构建高容量网络应用程序的开发人员，例如社交网络、协作文档编辑环境、实时数据驱动的网络界面、网络游戏和其他 I/O 密集型软件。如果您是客户端 JavaScript 开发人员，阅读本书将教会您如何使用您已经了解的语言成为服务器端程序员。如果您是 C++黑客，Node 是使用该语言构建的开源项目，为您提供了一个绝佳的机会，在一个庞大且不断增长的社区中产生真正的影响，甚至通过帮助开发这一激动人心的新技术而获得名声。

本书还适用于技术经理和其他寻求了解 Node 的能力和设计理念的人。本书充满了 Node 如何解决现代软件公司在高并发、实时应用程序和通过不断增长的网络传输大量数据方面面临的问题的示例。Node 已经被企业所接受，您应该考虑将其用于您的下一个项目。

我们正在使用 Node 的最新版本（写作时为 9.x）。这是您需要准备好的唯一一本书，以便在未来几年中随着 Node 在企业中的持续发展。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“如果我们查看我们的`find-byte.c`文件，我们会看到我们的`render`方法返回包装在`View`组件中的内容”。

代码块设置如下：

```js
const s1 = "first string";
const s2 = "second string";
let s3 = s1 + s2;
```

任何命令行输入或输出都以以下方式编写：

```js
$ node --version
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
const char *s1 = "first string";
const char *s2 = "second string";
int size = strlen(s1) + strlen(s2);
char *buffer = (char *)malloc(size + 1);
strcpy(buffer, s1);
strcat(buffer, s2);
free(buffer);
```

**新术语**和**重要单词**以粗体显示。屏幕上显示的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“单击“下一步”按钮会将您移至下一个屏幕。”

警告或重要说明会以这样的方式出现在框中。

提示和技巧会以这样的方式出现。


# 第一章：了解节点环境

# 介绍 - JavaScript 作为系统语言

当 John Bardeen、Walter Brattain 和 William Shockley 于 1947 年发明了晶体管时，他们以至今仍在发现的方式改变了世界。从他们的革命性基石开始，工程师可以设计和制造比之前可能的数字电路复杂得多的数字电路。随后的每一个十年都见证了这些设备的新一代：更小、更快、更便宜，通常是数量级的提升。

到了 20 世纪 70 年代，公司和大学能够负担得起足够小以适合单个房间的大型计算机，并且足够强大，可以同时为多个用户提供服务。小型计算机是一种新的、不同类型的设备，需要新的和不同类型的技术来帮助用户充分利用这台机器。贝尔实验室的 Ken Thompson 和 Dennis Ritchie 开发了 Unix 操作系统和编程语言 C 来编写它。他们在系统中构建了进程、线程、流和分层文件系统等结构。今天，这些结构是如此熟悉，以至于很难想象计算机以其他方式工作。然而，它们只是由这些先驱者构建的结构，旨在帮助像我们这样的人理解内存和存储器中的数据模式。

C 是一种系统语言，对于熟悉输入汇编指令的开发人员来说，它是一种安全且功能强大的简写替代方案。在微处理器的熟悉环境中，C 使得低级系统任务变得容易。例如，你可以搜索一个内存块以找到特定值的字节。

```js
// find-byte.c 
int find_byte(const char *buffer, int size, const char b) {
   for (int i = 0; i < size; i++) {
         if (buffer[i] == b) {
               return i;
         }
   }
   return -1; 
}
```

到了 20 世纪 90 年代，我们可以用晶体管构建的东西再次发生了变化。个人电脑（PC）足够轻便和便宜，可以在工作场所和宿舍的桌面上找到。提高的速度和容量使用户可以从仅字符的电传打印机引导到具有漂亮字体和彩色图像的图形环境。通过以太网卡和电缆，你的计算机可以在互联网上获得静态 IP 地址，网络程序可以连接并与地球上的任何其他计算机发送和接收数据。

正是在这样的技术背景下，Sir Tim Berners-Lee 发明了万维网，Brendan Eich 创建了 JavaScript。JavaScript 是为熟悉 HTML 标签的程序员设计的，它是一种超越静态文本页面的动画和交互的方式。在网页的熟悉环境中，JavaScript 使得高级任务变得容易。网页充满了文本和标签，因此合并两个字符串很容易。

```js
// combine-text.js
const s1 = "first string";
const s2 = "second string";
let s3 = s1 + s2;
```

现在，让我们将每个程序移植到另一种语言和平台。首先，从之前的`combine-text.js`，让我们编写`combine-text.c`：

```js
// combine-text.c 
const char *s1 = "first string";
const char *s2 = "second string";
int size = strlen(s1) + strlen(s2);
char *buffer = (char *)malloc(size + 1); // One more for the 0x00 byte that terminates strings 
strcpy(buffer, s1);
strcat(buffer, s2);
free(buffer); // Never forget to free memory!
```

两个字符串文字很容易定义，但之后就变得更加困难。没有自动内存管理，作为开发人员，你需要确定需要多少内存，从系统中分配内存，写入数据而不覆盖缓冲区，然后在之后释放它。

其次，让我们尝试相反的操作：从之前的`find-byte.c`代码，让我们编写`find-byte.js`。在 Node 之前，不可能使用 JavaScript 来搜索特定字节的内存块。在浏览器中，JavaScript 无法分配缓冲区，甚至没有字节类型。但是在 Node 中，这既可能又容易。

```js
// find-byte.js
function find_byte(buffer, b) {
  let i;
  for (i = 0; i < buffer.length; i++) {
    if (buffer[i] == b) {
      return i;
    }
  }
  return -1; // Not found
}
let buffer = Buffer.from("ascii A is byte value sixty-five", "utf8");
let r = find_byte(buffer, 65); // Find the first byte with value 65
console.log(r); // 6 bytes into the buffer
```

从相隔几十年的计算机和人们使用它们的方式的计算机世代中出现，驱动这两种语言 C 和 JavaScript 的设计、目的或用途本来没有必然要结合在一起的真正原因。但它们确实结合在一起了，因为在 2008 年谷歌发布了 Chrome，2009 年 Ryan Dahl 编写了 Node.js。

应用之前仅用于操作系统的设计原则。Chrome 使用多个进程来渲染不同的标签，确保它们的隔离。Chrome 是开源发布的，构建在 WebKit 上，但其中的一部分是全新的。在丹麦的农舍里从头开始编码，Lars Bak 的 V8 使用隐藏类转换、增量垃圾收集和动态代码生成来执行（而不是解释）比以往更快的 JavaScript。

在 V8 的支持下，Node 可以多快地运行 JavaScript？让我们编写一个小程序来展示执行速度：

```js
// speed-loop.js
function main() {
  const cycles = 1000000000;
  let start = Date.now();
  for (let i = 0; i < cycles; i++) {
    /* Empty loop */
  }
  let end = Date.now();
  let duration = (end - start) / 1000;
  console.log("JavaScript looped %d times in %d seconds", cycles, duration);
}
main();
```

以下是`speed-loop.js`的输出：

```js
$ node --version
v9.3.0
$ node speed-loop.js
JavaScript looped 1000000000 times in 0.635 seconds
```

在`for`循环的主体中没有代码，但是您的处理器正在忙于递增`i`，将其与`cycles`进行比较，并重复这个过程。我写这篇文章时已经是 2017 年末了，我用的是一台配备 2.8 GHz 英特尔酷睿 i7 处理器的 MacBook Pro。Node v9.3.0 是当前版本，循环*十亿*次只需要*不到一秒*。

纯 C 有多快？让我们看看：

```js
/* speed-loop.c */
#include <stdio.h>
#include <time.h>
int main() {
  int cycles = 1000000000;
  clock_t start, end;
  double duration;
  start = clock();
  for (int i = 0; i < cycles; i++) {
    /* Empty loop */
  }
  end = clock();
  duration = ((double)(end - start)) / CLOCKS_PER_SEC;
  printf("C looped %d times in %lf seconds\n", cycles,duration);
  return 0;
}
```

以下是`speed-loop.c`的输出：

```js
$ gcc --version
Apple LLVM version 8.1.0 (clang-802.0.42)
$ gcc speed-loop.c -o speed-loop
$ ./speed-loop
C looped 1000000000 times in 2.398294 seconds
```

为了进行额外的比较，让我们尝试一种解释性语言，比如 Python：

```js
# speed-loop.py

import time

def main():

  cycles = 1000000000
  start = time.perf_counter()

  for i in range(0, cycles):
    pass # Empty loop

  end = time.perf_counter()
  duration = end - start
  print("Python looped %d times in %.3f seconds" % (cycles, duration))

main()
```

以下是`speed-loop.py`的输出：

```js
$ python3 --version
Python 3.6.1
$ python3 speed-loop.py
Python looped 1000000000 times in 31.096 seconds
```

Node 运行的速度足够快，以至于您不必担心您的应用程序可能会因执行速度而变慢。当然，您仍然需要考虑性能，但受到语言和平台选择以外的因素的限制，比如算法、I/O 和外部进程、服务和 API。由于 V8 编译 JavaScript 而不是解释它，Node 让您享受高级语言特性，如自动内存管理和动态类型，而无需放弃本地编译二进制的性能。以前，您必须选择其中一个；但现在，您可以两者兼得。这太棒了。

20 世纪 70 年代的计算是关于微处理器的，20 世纪 90 年代的计算是关于网页的。今天，2017 年，另一代新的物理计算技术再次改变了我们的机器。您口袋里的智能手机通过无线方式与云中的可扩展的按需付费软件服务进行通信。这些服务在 Unix 的虚拟化实例上运行，Unix 又在数据中心的物理硬件上运行，其中一些数据中心非常大，被策略性地放置在附近的水电站中获取电流。有了这样新颖和不同的机器，我们不应该感到惊讶，用户的可能性和开发人员的必要性也是新的和不同的，再次。

Node.js 将 JavaScript 想象成一个类似于 C 的系统语言。在网页上，JavaScript 可以操作头部和样式。作为系统语言，JavaScript 可以操作内存缓冲区、进程和流、文件和套接字。这种时代错位是由 V8 的性能所可能的，它将语言发送回 20 年前，将其从网页移植到微处理器芯片上。

“Node 的目标是提供一种简单的方式来构建可扩展的网络程序。”

- Node.js 的创始人 Ryan Dahl

在本书中，我们将学习专业 Node 开发人员用来解决当今软件挑战的技术。通过掌握 Node，您正在学习如何构建下一代软件。在本章中，我们将探讨 Node 应用程序的设计方式，以及它在服务器上的印记的形状和质地，以及 Node 为开发人员提供的强大的基本工具和功能集。在整个过程中，我们将逐渐探讨更复杂的示例，展示 Node 简单、全面和一致的架构如何很好地解决许多困难的问题。

# Unix 的设计哲学

随着网络应用程序规模的扩大，它必须识别、组织和维护的信息量也在增加。这种信息量，以 I/O 流、内存使用和处理器负载的形式，随着更多的客户端连接而扩大。这种信息量的扩大也给软件开发人员带来了负担。通常出现扩展问题，通常表现为无法准确预测大型系统的行为，从而导致其较小的前身的行为失败：

+   一个为存储几千条记录设计的数据层能容纳几百万条记录吗？

+   用于搜索少量记录的算法是否足够高效，可以搜索更多记录吗？

+   这个服务器能处理 10000 个同时的客户端连接吗？

创新的边缘是锋利的，切割迅速，给人更少的时间来思考，特别是当错误的代价被放大时。构成应用程序整体的对象的形状变得模糊且难以理解，特别是当对系统中的动态张力做出反应性的临时修改时。在规范中描述为一个小子系统的东西可能已经被补丁到了许多其他系统中，以至于其实际边界被误解。当这种情况发生时，准确追踪整体复合部分的轮廓就变得不可能了。

最终，一个应用程序变得不可预测。当一个人无法预测应用程序的所有未来状态或变化的副作用时，这是危险的。许多服务器、编程语言、硬件架构、管理风格等等，都试图克服随着增长而带来的风险问题，失败威胁着成功。通常情况下，更复杂的系统被作为解决方案出售。任何一个人对信息的掌握都是脆弱的。复杂性随着规模而增加；混乱随着复杂性而来。随着分辨率变得模糊，错误就会发生。

Node 选择了清晰和简单，回应了几十年前的一种哲学：

"编写程序，做一件事，并且做得很好。

编写程序以便协同工作。

编写处理文本流的程序，因为这是一个通用的接口。

-Peter H. Salus，《Unix 四分之一世纪》，1994

从他们创建和维护 Unix 的经验中，*Ken Thompson*和*Dennis Ritchie*提出了一个关于人们如何最好构建软件的哲学。*Ryan Dahl*在 Node 的设计中遵循这一哲学，做出了许多决定：

+   Node 的设计偏向简单而不是复杂

+   Node 使用熟悉的 POSIX API，而不是试图改进

+   Node 使用事件来完成所有操作，不需要线程

+   Node 利用现有的 C 库，而不是试图重新实现它们的功能

+   Node 偏向文本而不是二进制格式

文本流是 Unix 程序的语言。JavaScript 从一开始就擅长处理文本，作为一种 Web 脚本语言。这是一个自然的匹配。

# POSIX

**POSIX**，**可移植操作系统接口**，定义了 Unix 的标准 API。它被采用在基于 Unix 的操作系统和其他系统中。IEEE 创建并维护 POSIX 标准，以使来自不同制造商的系统兼容。在运行 macOS 的笔记本电脑上使用 POSIX API 编写 C 程序，以后在树莓派上构建它会更容易。

作为一个共同的基准，POSIX 古老、简单，最重要的是，所有类型的开发人员都熟悉。在 C 程序中创建一个新目录，使用这个 API：

```js
int mkdir(const char *path, mode_t mode);
```

这就是 Node 的特点：

```js
fs.mkdir(path[, mode], callback)
```

文件系统模块的 Node 文档一开始就告诉开发人员，这里没有什么新东西：

文件 I/O 是通过标准 POSIX 函数的简单包装提供的。

[`nodejs.org/api/fs.html`](https://nodejs.org/api/fs.html)

对于 Node 来说，*Ryan Dahl*实现了经过验证的 POSIX API，而不是试图自己想出一些东西。虽然在某些方面或某些情况下，这样的尝试可能更好，但它会失去 POSIX 给其他系统训练有素的新 Node 开发人员带来的即时熟悉感。

通过选择 POSIX 作为 API，Node 并不受限于上世纪 70 年代的标准。任何人都可以轻松编写自己的模块，调用 Node 的 API，同时向上呈现不同的 API。这些更高级的替代方案可以在达尔文式的竞争中证明自己比 POSIX 更好。

# 一切皆事件

如果程序要求操作系统在磁盘上打开一个文件，这个任务可能会立即完成。或者，磁盘可能需要一段时间才能启动，或者操作系统正在处理其他文件系统活动，需要等待才能执行新的请求。超越应用程序进程空间内存操作的任务，涉及到计算机、网络和互联网中更远的硬件，无法以相同的方式快速或可靠地进行编程。软件设计师需要一种方法来编写这些可能缓慢和不可靠的任务，而不会使他们的应用程序整体变得缓慢和不可靠。对于使用 C 和 Java 等语言的系统程序员来说，解决这个问题的标准和公认的工具是线程。

```js
pthread_t my_thread;
int x = 0;
/* Make a thread and have it run my_function(&x) */
pthread_create(&my_thread, NULL, my_function, &x);
```

如果程序向用户提问，用户可能会立即回答。或者，用户可能需要一段时间来思考，然后再点击“是”或“否”。对于使用 HTML 和 JavaScript 的 Web 开发人员，这样做的方法是事件，如下所示：

```js
<button onclick="myFunction()">Click me</button>
```

乍一看，这两种情况可能看起来完全不同：

+   在第一种情况下，低级系统正在将内存块从程序传输到程序，毫秒的延迟可能太大而无法测量

+   在第二种情况下，一个巨大的软件堆栈的顶层正在向用户提问

然而，在概念上，它们是相同的。Node 的设计意识到了这一点，并且在两者都使用了事件。在 Node 中，有一个线程，绑定到一个事件循环。延迟任务被封装，通过回调函数进入和退出执行上下文。I/O 操作生成事件数据流，并通过单个堆栈进行传输。并发由系统管理，抽象出线程池，并简化对内存的共享访问。

Node 向我们展示了 JavaScript 作为系统语言并不需要线程。此外，通过不使用线程，JavaScript 和 Node 避免了并发问题，这些问题会给开发人员带来性能和可靠性挑战，即使是对于熟悉代码库的开发人员也可能难以理解。在《第二章》《理解异步事件驱动编程》中，我们将深入探讨事件和事件循环。

# 标准库

Node 是建立在标准开源 C 库上的。例如，*TLS*和*SSL*协议是由*OpenSSL*实现的。不仅仅是采用 API，OpenSSL 的 C 源代码也包含在 Node 中并编译进去。当你的 JavaScript 程序对加密密钥进行哈希处理时，实际上并不是 JavaScript 在进行工作。你的 JavaScript 通过 Node 调用了 OpenSSL 的 C 代码。实质上，你在对本地库进行脚本编写。

使用现有和经过验证的开源库的设计选择帮助了 Node 的多个方面：

+   这意味着 Node 可以迅速出现在舞台上，具有系统程序员需要和期望的核心功能，这些功能已经存在。

+   它确保性能、可靠性和安全性与库相匹配

+   它也没有破坏跨平台使用，因为所有这些 C 库都已经被编写和维护多年，可以编译到不同的架构上

以前的平台和语言在努力实现软件可移植性时做出了不同的选择。例如，*100% Pure Java™ Standard*是*Sun Microsystems*的一个倡议，旨在促进可移植应用程序的开发。与其利用混合堆栈中的现有代码，它鼓励开发人员在 Java 中重写所有内容。开发人员必须通过编写和测试新代码来保持功能、性能和安全性达到标准。另一方面，Node 选择了一种设计，可以免费获得所有这些功能。

# 扩展 JavaScript

当他设计 Node 时，JavaScript 并不是*Ryan Dahl*的最初语言选择。然而，经过探索，他发现了一种现代语言，没有对流、文件系统、处理二进制对象、进程、网络等功能的看法。JavaScript 严格限制在浏览器中，对于这些功能没有用处，也没有实现这些功能。

受 Unix 哲学的指导，达尔坚持了一些严格的原则：

+   Node 程序/进程在单个线程上运行，通过事件循环来排序执行

+   Web 应用程序具有大量 I/O 操作，因此重点应该放在加快 I/O 上

+   程序流程总是通过异步回调来指导

+   昂贵的 CPU 操作应该拆分成单独的并行进程，并在结果到达时发出事件

+   复杂的程序应该由简单的程序组装而成

总的原则是，操作绝对不能阻塞。Node 对速度（高并发）和效率（最小资源使用）的渴望要求减少浪费。等待过程是一种浪费，特别是在等待 I/O 时。

JavaScript 的异步、事件驱动设计完全符合这一模式。应用程序表达对未来某个事件的兴趣，并在该事件发生时得到通知。这种常见的 JavaScript 模式应该对你来说很熟悉：

```js
Window.onload = function() {
  // When all requested document resources are loaded,
  // do something with the resulting environment
}
element.onclick = function() {
  // Do something when the user clicks on this element
}
```

I/O 操作完成所需的时间是未知的，因此模式是在发出 I/O 事件时请求通知，无论何时发生，都允许其他操作在此期间完成。

Node 为 JavaScript 添加了大量新功能。主要是提供了事件驱动的 I/O 库，为开发人员提供了系统访问权限，这是浏览器中的 JavaScript 无法做到的，比如写入文件系统或打开另一个系统进程。此外，该环境被设计为模块化，允许将复杂的程序组装成更小更简单的组件。

让我们看看 Node 如何导入 JavaScript 的事件模型，扩展它，并在创建强大系统命令的接口时使用它。

# 事件

Node API 中的许多函数会发出事件。这些事件是`events.EventEmitter`的实例。任何对象都可以扩展`EventEmitter`，为 Node 开发人员提供了一种简单而统一的方式来构建紧密的异步接口以调用对象方法。

以下代码将 Node 的`EventEmitter`对象设置为我们定义的函数构造函数的原型。每个构造的实例都将`EventEmitter`对象暴露给其原型链，提供对事件 API 的自然引用。计数器实例方法会发出事件，然后监听它们。创建一个`Counter`后，我们监听增加的事件，指定一个回调，Node 在事件发生时会调用它。然后，我们调用增加两次。每次，我们的`Counter`都会增加它持有的内部计数，然后发出增加的事件。这将调用我们的回调，将当前计数传递给它，我们的回调会将其记录下来：

```js
// File counter.js
// Load Node's 'events' module, and point directly to EventEmitter there
const EventEmitter = require('events').EventEmitter;
// Define our Counter function
const Counter = function(i) { // Takes a starting number
  this.increment = function() { // The counter's increment method
    i++; // Increment the count we hold
    this.emit('incremented', i); // Emit an event named incremented
  }
}
// Base our Counter on Node's EventEmitter
Counter.prototype = new EventEmitter(); // We did this afterwards, not before!
// Now that we've defined our objects, let's see them in action
// Make a new Counter starting at 10
const counter = new Counter(10);
// Define a callback function which logs the number n you give it
const callback = function(n) {
  console.log(n);
}
// Counter is an EventEmitter, so it comes with addListener
counter.addListener('incremented', callback);
counter.increment(); // 11
counter.increment(); // 12
```

以下是`counter.js`的输出：

```js
$ node counter.js
11
12
```

要删除绑定到`counter`的事件侦听器，请使用此代码：

```js
counter.removeListener('incremented', callback).
```

为了与基于浏览器的 JavaScript 保持一致，`counter.on`和`counter.addListener`是可以互换的。

Node 将`EventEmitter`引入 JavaScript，并使其成为你的对象可以扩展的对象。这大大增加了开发人员的可能性。使用`EventEmitter`，Node 可以以事件导向的方式处理 I/O 数据流，执行长时间运行的任务，同时保持 Node 异步、非阻塞编程的原则：

```js
// File stream.js
// Use Node's stream module, and get Readable inside
let Readable = require('stream').Readable;
// Make our own readable stream, named r
let r = new Readable;
// Start the count at 0
let count = 0;
// Downstream code will call r's _read function when it wants some data from r
r._read = function() {
  count++;
  if (count > 10) { // After our count has grown beyond 10
    return r.push(null); // Push null downstream to signal we've got no more data
  }
  setTimeout(() => r.push(count + '\n'), 500); // A half second from now, push our count on a line
};
// Have our readable send the data it produces to standard out
r.pipe(process.stdout);
```

以下是`stream.js`的输出：

```js
$ node stream.js
1
2
3
4
5
6
7
8
9
10
```

这个例子创建了一个可读流`r`，并将其输出传输到标准输出。每 500 毫秒，代码会递增一个计数器，并将带有当前计数的文本行推送到下游。尝试自己运行程序，你会看到一系列数字出现在你的终端上。

在第 11 次计数时，`r`将 null 推送到下游，表示它没有更多的数据要发送。这关闭了流，而且没有更多的事情要做，Node 退出了进程。

后续章节将更详细地解释流。在这里，只需注意将数据推送到流上会触发一个事件，你可以分配一个自定义回调来处理这个事件，以及数据如何向下游流动。

Node 一贯将 I/O 操作实现为异步的、事件驱动的数据流。这种设计选择使得 Node 具有出色的性能。与为长时间运行的任务（如文件上传）创建线程（或启动整个进程）不同，Node 只需要投入资源来处理回调。此外，在流推送数据的短暂时刻之间的长时间段内，Node 的事件循环可以自由地处理其他指令。

作为练习，重新实现`stream.js`，将`r`产生的数据发送到文件而不是终端。你需要使用 Node 的`fs.createWriteStream`创建一个新的可写流`w`：

```js
// File stream2file.js
// Bring in Node's file system module
const fs = require('fs');
// Make the file counter.txt we can fill by writing data to writeable stream w
const w = fs.createWriteStream('./counter.txt', { flags: 'w', mode: 0666 });
...
// Put w beneath r instead
r.pipe(w);
```

# 模块化

在他的书《Unix 编程艺术》中，Eric Raymond 提出了**模块化原则**：

“开发人员应该通过明确定义的接口将程序构建成由简单部分连接而成的程序，这样问题就是局部的，程序的部分可以在未来版本中被替换以支持新功能。这个原则旨在节省调试复杂、冗长和难以阅读的代码的时间。”

大型系统很难理解，特别是当内部组件的边界模糊不清，它们之间的交互又很复杂时。将大型系统构建成由小的、简单的、松耦合的部分组成的原则对软件和其他领域都是一个好主意。物理制造、管理理论、教育和政府都受益于这种设计哲学。

当开发人员开始将 JavaScript 用于更大规模和更复杂的软件挑战时，他们遇到了这个挑战。还没有一个好的方法（后来也没有一个通用的标准方法）来从更小的程序组装 JavaScript 程序。例如，你可能在顶部看到带有这些标签的 HTML 页面：

```js
<head>
<script src="img/fileA.js"></script>
<script src="img/fileB.js"></script>
<script src="img/fileC.js"></script>
<script src="img/fileD.js"></script>
...
</head>
```

这种方法虽然有效，但会导致一系列问题：

+   页面必须在需要或使用任何依赖之前声明所有潜在的依赖。如果在运行过程中，你的程序遇到需要额外依赖的情况，动态加载另一个模块是可能的，但是是一种单独的黑客行为。

+   脚本没有封装。每个文件中的代码都写入同一个全局对象。添加新的依赖可能会因为名称冲突而破坏之前的依赖。

+   `fileA`无法将`fileB`作为一个集合来处理。像`fileB.function1`这样的可寻址上下文是不可用的。

`<script>`标签可能是一个很好的地方，用于提供诸如依赖关系意识和版本控制等有用的模块服务，但它并没有这些功能。

这些困难和危险使得创建和使用 JavaScript 模块感觉比轻松更加危险。一个具有封装和版本控制等功能的良好模块系统可以扭转这一局面，鼓励代码组织和共享，并导致一个高质量的开源软件组件生态系统。

JavaScript 需要一种标准的方式来加载和共享离散的程序模块，在 2009 年找到了 CommonJS 模块规范。Node 遵循这个规范，使得定义和共享被称为**模块**或**包**的可重用代码变得容易。

选择了一个简单而令人愉悦的设计，一个包就是一个 JavaScript 文件的目录。关于包的元数据，比如它的名称、版本和软件许可证，存储在一个名为`package.json`的额外文件中。这个文件的 JSON 内容既容易被人类阅读，也容易被机器读取。让我们来看一下：

```js
{
  "name": "mypackage1",
  "version": "0.1.2",
  "dependencies": {
    "jquery": "³.1.0",
    "bluebird": "³.4.1",
  },
  "license": "MIT"
}
```

这个`package.json`定义了一个名为`mypackage1`的包，它依赖于另外两个包：**jQuery**和**Bluebird**。在包名旁边是一个版本号。版本号遵循**语义化版本（SemVer）**规则，格式为主版本号.次版本号.修订版本号。查看你的代码正在使用的包的递增版本号，这就是它的含义：

+   **主要版本：**API 的目的或结果发生了变化。如果你的代码调用了更新的函数，可能会出现错误或产生意外的结果。找出发生了什么变化，并确定它是否影响了你的代码。

+   **次要版本：**包增加了功能，但仍然兼容。运行所有的测试，然后就可以使用了。如果你感兴趣，可以查看文档，因为可能会有新的、更高级的 API 部分，以及你熟悉的函数和对象。

+   **修订版本：**包修复了一个 bug，提高了性能，或者进行了一些重构。运行所有的测试，然后就可以使用了。

包使得可以从许多小的、相互依赖的系统构建大型系统。也许更重要的是，包鼓励分享。关于 SemVer 的更详细信息可以在附录 A 中找到，*将你的工作组织成模块*，在那里更深入地讨论了 npm 和包。

“我在这里描述的不是一个技术问题。这是一群人聚在一起做出决定，迈出一步，开始一起构建更大更酷的东西。”

– Kevin Dangoor，CommonJS 的创始人

CommonJS 不仅仅是关于模块，实际上它是一整套标准，旨在消除一切阻碍 JavaScript 成为世界主导语言的东西，开源开发者*Kris Kowal*在 2009 年的一篇文章中解释了这一点。他将这些障碍中的第一个称为缺乏一个良好的模块系统。第二个障碍是缺乏一个标准库，包括文件系统的访问、I/O 流的操作，以及字节和二进制数据块的类型。如今，CommonJS 以给 JavaScript 提供了一个模块系统而闻名，而 Node 则是给了 JavaScript 系统级的访问：

[`arstechnica.com/information-technology/2009/12/commonjs-effort-sets-javascript-on-path-for-world-domination/`](https://arstechnica.com/information-technology/2009/12/commonjs-effort-sets-javascript-on-path-for-world-domination/)

**CommonJS**给了 JavaScript 包。有了包之后，JavaScript 需要的下一件事就是包管理器。Node 提供了 npm。

npm 作为包的注册表有两种访问方式。首先，在网站[www.npmjs.com](http://www.npmjs.com)，你可以链接和搜索包，基本上是在寻找合适的包。统计数据显示了包在过去一天、一周和一个月内被下载的次数，展示了它的受欢迎程度和使用情况。大多数包都链接到开发者的个人资料页面和 GitHub 上的开源代码，这样你就可以看到代码，了解最近的开发活动，并评判作者和贡献者的声誉。

访问 npm 的第二种方式是通过与 Node 一起安装的命令行工具 npm。使用 npm 作为工作站的传统软件包管理器，您可以全局安装软件包，在 shell 的路径上创建新的命令行工具。npm 还知道如何创建、读取和编辑`package.json`文件，并可以为您创建一个新的、空的 Node 软件包，添加它所需的依赖项，下载所有的代码，并保持一切更新。

除了 Git 和 GitHub，npm 现在正在实现上世纪 70 年代确定的软件开发梦想：代码可以更频繁地被重复使用，软件项目不需要经常从头开始编写。

早期尝试通过 CVS 和 Subversion 等版本控制系统以及像[SourceForge.net](http://SourceForge.net)这样的开源代码共享网站来实现这一目标，侧重于更大的代码和人员单位，并没有取得太多成果。

GitHub 和 npm 在两个重要方面采取了不同的方法：

+   更看重独立开发者的个人工作而不是社区会议和讨论，开发者可以更多地专注于代码而不是对话

+   偏爱小型、原子化的软件组件而不是完整的应用程序，封装的组合不仅发生在子例程和对象的微观层面，而且在更重要的应用程序设计的宏观层面上也发生了。

即使文档也可以通过新的方法变得更好：在单片软件应用程序中，文档往往是产品发货后可能发生或可能不会发生的事后想法。

对于组件，出色的文档对于向世界推销您的软件包是必不可少的，使其每天获得更多的公共下载量，并且作为开发者保持的社交媒体账户也会有更多的关注者。

Node 的成功在很大程度上归功于作为 Node 开发者可用的软件包的数量和质量。

有关创建和管理 Node 软件包的更详细信息可以在*附录 A，将您的工作组织成模块*中找到。

要遵循的关键设计理念是：尽可能使用软件包构建程序，并在可能的情况下共享这些软件包。您的应用程序的形状将更清晰，更易于维护。重要的是，成千上万的其他开发人员的努力可以通过 npm 直接包含到应用程序中，并且间接地通过共享软件包由 Node 社区的成员测试、改进、重构和重新利用。

与流行观念相反，npm 并不是 Node Package Manager 的缩写，*绝不应该被用作或解释为首字母缩写*：

[`docs.npmjs.com/policies/trademark`](https://docs.npmjs.com/policies/trademark)

# 网络

浏览器中的 I/O 受到严格限制，这是有很好的原因的——如果任何给定网站上的 JavaScript 可以访问您的文件系统，例如，用户只能点击他们信任的新网站的链接，而不是他们只是想尝试的网站。通过将页面保持在有限的沙盒中，Web 的设计使得从 thing1.com 导航到 thing2.com 不会像双击 thing1.exe 和 thing2.exe 那样产生后果。

当然，Node 将 JavaScript 重新塑造为系统语言，使其直接且无障碍地访问操作系统内核对象，如文件、套接字和进程。这使得 Node 可以创建具有高 I/O 需求的可扩展系统。很可能你在 Node 中编写的第一件事是一个 HTTP 服务器。

Node 支持标准的网络协议，除了 HTTP，还有 TLS/SSL 和 UDP。借助这些工具，我们可以轻松地构建可扩展的网络程序，远远超出了 JavaScript 开发人员从浏览器中了解的相对有限的 AJAX 解决方案。

让我们编写一个简单的程序，向另一个节点发送一个 UDP 数据包：

```js
const dgram = require('dgram');
let client = dgram.createSocket("udp4");
let server = dgram.createSocket("udp4");
let message = process.argv[2] || "message";
message = Buffer.from(message);
server
.on('message', msg => {
  process.stdout.write(`Got message: ${msg}\n`);
  process.exit();
})
.bind(41234);
client.send(message, 0, message.length, 41234, "localhost");
```

打开两个终端窗口，分别导航到您的代码包的第八章下的“扩展应用程序”文件夹。现在我们将在一个窗口中运行 UDP 服务器，在另一个窗口中运行 UDP 客户端。

在右侧窗口中，使用以下命令运行`receive.js`：

```js
$ node receive.js
```

在左侧，使用以下命令运行`send.js`：

```js
$ node send.js
```

执行该命令将导致右侧出现消息：

```js
$ node receive.js
Message received!
```

UDP 服务器是`EventEmitter`的一个实例，在绑定端口接收到消息时会发出消息事件。使用 Node，您可以使用 JavaScript 在 I/O 级别编写应用程序，轻松移动数据包和二进制数据流。

让我们继续探索 I/O、进程对象和事件。首先，让我们深入了解 Node 核心的机器 V8。

# V8、JavaScript 和优化

V8 是谷歌的 JavaScript 引擎，用 C++编写。它在虚拟机（Virtual Machine）内部编译和执行 JavaScript 代码。当加载到谷歌 Chrome 中的网页展示某种动态效果，比如自动更新列表或新闻源时，您看到的是由 V8 编译的 JavaScript 在工作。

V8 管理 Node 的主进程线程。在执行 JavaScript 时，V8 会在自己的进程中执行，其内部行为不受 Node 控制。在本节中，我们将研究通过使用这些选项来获得的性能优势，学习如何编写可优化的 JavaScript，以及最新 Node 版本（例如 9.x，我们在本书中使用的版本）用户可用的尖端 JavaScript 功能。

# 标志

有许多可用于操纵 Node 运行时的设置。尝试这个命令：

```js
$ node -h
```

除了`--version`等标准选项外，您还可以将 Node 标记为`--abort-on-uncaught-exception`。

您还可以列出 v8 可用的选项：

```js
$ node --v8-options
```

其中一些设置可以帮助您度过难关。例如，如果您在像树莓派这样的受限环境中运行 Node，您可能希望限制 Node 进程可以消耗的内存量，以避免内存峰值。在这种情况下，您可能希望将`--max_old_space_size`（默认约 1.5GB）设置为几百 MB。

您可以使用`-e`参数将 Node 程序作为字符串执行；在这种情况下，记录出您的 Node 副本包含的 V8 版本：

```js
$ node –e "console.log(process.versions.v8)"
```

值得您花时间尝试 Node/V8 的设置，既可以提高效用，也可以让您对发生的事情（或可能发生的事情）有更深入的了解。

# 优化您的代码

智能代码设计的简单优化确实可以帮助您。传统上，在浏览器中工作的 JavaScript 开发人员不需要关注内存使用优化，因为通常对于通常不复杂的程序来说，他们有很多内存可用。在服务器上，情况就不同了。程序通常更加复杂，耗尽内存会导致服务器崩溃。

动态语言的便利之处在于避免了编译语言所施加的严格性。例如，您无需明确定义对象属性类型，并且实际上可以随意更改这些属性类型。这种动态性使得传统编译变得不可能，但为 JavaScript 等探索性语言开辟了一些有趣的新机会。然而，与静态编译语言相比，动态性在执行速度方面引入了显著的惩罚。JavaScript 的有限速度经常被认为是其主要弱点之一。

V8 试图为 JavaScript 实现编译语言所观察到的速度。V8 将 JavaScript 编译为本机机器代码，而不是解释字节码，或使用其他即时技术。由于 JavaScript 程序的精确运行时拓扑无法提前知道（语言是动态的），编译包括两阶段的推测性方法：

1.  最初，第一遍编译器（*完整*编译器）尽快将您的代码转换为可运行状态。在此步骤中，类型分析和代码的其他详细分析被推迟，优先考虑快速编译-您的 JavaScript 可以尽可能接近即时执行。进一步的优化是在第二步完成的。

1.  一旦程序启动运行，优化编译器就开始监视程序的运行方式，并尝试确定其当前和未来的运行时特性，根据需要进行优化和重新优化。例如，如果某个函数以一致类型的相似参数被调用了成千上万次，V8 将使用基于乐观假设的优化代码重新编译该函数，假设未来的类型将与过去的类型相似。虽然第一次编译步骤对尚未知和未类型化的功能签名保守，但这个`热`函数的可预测纹理促使 V8 假设某种最佳配置文件，并根据该假设重新编译。

假设可以帮助我们更快地做出决定，但可能会导致错误。如果`热`函数 V8 的编译器只针对某种类型签名进行了优化，现在却使用违反该优化配置文件的参数调用了该函数怎么办？在这种情况下，V8 别无选择：它必须取消优化该函数。V8 必须承认自己的错误，并撤销已经完成的工作。如果看到新的模式，它将在未来重新优化。然而，如果 V8 在以后再次取消优化，并且如果这种优化/取消优化的二进制切换继续，V8 将简单地*放弃*，并将您的代码留在取消优化状态。

让我们看看一些方法来设计和声明数组、对象和函数，以便您能够帮助而不是阻碍编译器。

# 数字和跟踪优化/取消优化

ECMA-262 规范将 Number 值定义为“与双精度 64 位二进制格式 IEEE 754 值对应的原始值”。关键是 JavaScript 中没有整数类型；有一个被定义为双精度浮点数的 Number 类型。

出于性能原因，V8 在内部对所有值使用 32 位数字。这里讨论的技术原因太多，可以说有一位用于指向另一个 32 位数字，如果需要更大的宽度。无论如何，很明显 V8 将数字标记为两种类型的值，并在这些类型之间切换将会花费一些代价。尽量将您的需求限制在可能的情况下使用 31 位有符号整数。

由于 JavaScript 的类型不确定性，允许切换分配给插槽的数字的类型。例如，以下代码不会引发错误：

```js
let a = 7;
a = 7.77;
```

然而，像 V8 这样的推测性编译器将无法优化这个变量赋值，因为它*猜测*`a`将始终是一个整数的假设是错误的，迫使取消优化。

我们可以通过设置一些强大的 V8 选项，执行 Node 程序中的 V8 本机命令，并跟踪 v8 如何优化/取消优化您的代码来演示优化/取消优化过程。

考虑以下 Node 程序：

```js
// program.js
let someFunc = function foo(){}
console.log(%FunctionGetName(someFunc));
```

如果您尝试正常运行此程序，您将收到意外的令牌错误-在 JavaScript 中无法在标识符名称中使用模数（%）符号。带有%前缀的这个奇怪的方法是什么？这是一个 V8 本机命令，我们可以通过使用`--allow-natives-syntax`标志来打开执行这些类型的函数：

```js
node --allow-natives-syntax program.js
// 'someFunc', the function name, is printed to the console.
```

现在，考虑以下代码，它使用本机函数来断言关于平方函数的优化状态的信息，使用`％OptimizeFunctionOnNextCall`本机方法：

```js
let operand = 3;
function square() {
    return operand * operand;
}
// Make first pass to gather type information
square();
// Ask that the next call of #square trigger an optimization attempt;
// Call
%OptimizeFunctionOnNextCall(square);
square();
```

使用上述代码创建一个文件，并使用以下命令执行它：`node --allow-natives-syntax --trace_opt --trace_deopt myfile.js`。您将看到类似以下返回的内容：

```js
 [deoptimize context: c39daf14679]
 [optimizing: square / c39dafca921 - took 1.900, 0.851, 0.000 ms]
```

我们可以看到 V8 在优化平方函数时没有问题，因为操作数只声明一次并且从未改变。现在，将以下行追加到你的文件中，然后再次运行它：

```js
%OptimizeFunctionOnNextCall(square);
operand = 3.01;
square();
```

在这次执行中，根据之前给出的优化报告，你现在应该会收到类似以下的内容：

```js
**** DEOPT: square at bailout #2, address 0x0, frame size 8
 [deoptimizing: begin 0x2493d0fca8d9 square @2]
 ...
 [deoptimizing: end 0x2493d0fca8d9 square => node=3, pc=0x29edb8164b46, state=NO_REGISTERS, alignment=no padding, took 0.033 ms]
 [removing optimized code for: square]
```

这份非常有表现力的优化报告非常清楚地讲述了故事：一度优化的平方函数在我们改变一个数字类型后被取消了优化。鼓励你花一些时间编写代码并使用这些方法进行测试。

# 对象和数组

正如我们在研究数字时所学到的，当你的代码是可预测的时，V8 的工作效果最好。对于数组和对象也是如此。几乎所有以下的*不良实践*之所以不好，是因为它们会造成不可预测性。

记住，在 JavaScript 中，对象和数组在底层非常相似（导致了一些奇怪的规则，给那些取笑这门语言的人提供了无穷无尽的素材！）。我们不会讨论这些差异，只会讨论重要的相似之处，特别是在这两种数据结构如何从类似的优化技术中受益。

避免在数组中混合类型。最好始终保持一致的数据类型，比如*全部整数*或*全部字符串*。同样，尽量避免在数组中改变类型，或者在初始化后改变属性赋值的类型。V8 通过创建隐藏类来跟踪类型来创建对象的*蓝图*，当这些类型改变时，优化蓝图将被销毁并重建——如果你幸运的话。访问[`github.com/v8/v8/wiki/Design%20Elements`](https://github.com/v8/v8/wiki/Design%20Elements)获取更多信息。

不要创建带有间隙的数组，比如以下的例子：

```js
let a = [];
a[2] = 'foo';
a[23] = 'bar';
```

稀疏数组之所以不好，是因为 V8 可以使用非常高效的线性存储策略来存储（和访问）你的数组数据，或者它可以使用哈希表（速度要慢得多）。如果你的数组是稀疏的，V8 必须选择两者中效率较低的那个。出于同样的原因，始终从零索引开始你的数组。同样，永远不要使用*delete*来从数组中删除元素。你只是在那个位置插入一个*undefined*值，这只是创建稀疏数组的另一种方式。同样，要小心用空值填充数组——确保你推入数组的外部数据不是不完整的。

尽量不要预先分配大数组——边用边增长。同样，不要预先分配一个数组然后超出那个大小。你总是希望避免吓到 V8，使其将你的数组转换为哈希表。每当向对象构造函数添加新属性时，V8 都会创建一个新的隐藏类。尽量避免在实例化后添加属性。以相同的顺序在构造函数中初始化所有成员。相同的属性+相同的顺序=相同的对象。

记住，JavaScript 是一种动态语言，允许在实例化后修改对象（和对象原型）。因此，V8 为对象分配内存的方式是怎样的呢？它做出了一些合理的假设。在从给定构造函数实例化一定数量的对象之后（我相信触发数量是 8），假定这些对象中最大的一个是最大尺寸，并且所有后续实例都被分配了那么多的内存（初始对象也被类似地调整大小）。每个实例基于这个假定的最大尺寸被分配了 32 个快速属性槽。任何额外的属性都被放入一个（更慢的）溢出属性数组中，这个数组可以调整大小以容纳任何进一步的新属性。

对于对象和数组，尽量尽可能地定义数据结构的形状，包括一定数量的属性、类型等等，以便*未来*使用。

# 函数

通常经常调用函数，应该是你主要优化的焦点之一。包含 try-catch 结构的函数是不可优化的，包含其他不可预测结构的函数也是不可优化的，比如`with`或`eval`。如果由于某种原因，您的函数无法优化，请尽量减少使用。

一个非常常见的优化错误涉及使用多态函数。接受可变函数参数的函数将被取消优化。避免多态函数。

关于 V8 如何执行推测优化的优秀解释可以在这里找到：[`ponyfoo.com/articles/an-introduction-to-speculative-optimization-in-v8`](https://ponyfoo.com/articles/an-introduction-to-speculative-optimization-in-v8)

# 优化的 JavaScript

JavaScript 语言不断变化，一些重大的变化和改进已经开始进入本机编译器。最新 Node 构建中使用的 V8 引擎支持几乎所有最新功能。调查所有这些超出了本章的范围。在本节中，我们将提到一些最有用的更新以及它们如何简化您的代码，帮助您更容易理解和推理，更易于维护，甚至可能更高效。

在本书中，我们将使用最新的 JavaScript 功能。您可以使用 Promise、Generator 和 async/await 构造，从 Node 8.x 开始，我们将在整本书中使用这些功能。这些并发运算符将在第二章中深入讨论，*理解异步事件驱动编程*，但现在一个很好的收获是，回调模式正在失去其主导地位，特别是 Promise 模式正在主导模块接口。

实际上，最近在 Node 的核心中添加了一个新方法`util.promisify`，它将基于回调的函数转换为基于 Promise 的函数：

```js
const {promisify} = require('util');
const fs = require('fs');

// Promisification happens here
let readFileAsync = promisify(fs.readFile);

let [executable, absPath, target, ...message] = process.argv;

console.log(message.length ? message.join(' ') : `Running file ${absPath} using binary ${executable}`);

readFileAsync(target, {encoding: 'utf8'})
.then(console.log)
.catch(err => {
  let message = err.message;
  console.log(`
    An error occurred!
    Read error: ${message}
  `);
});
```

能够轻松地*promisify* `fs.readFile`非常有用。

您是否注意到其他可能对您不熟悉的新 JavaScript 结构？

# 帮助变量

在整本书中，您将看到`let`和`const`。这些是新的变量声明类型。与`var`不同，`let`是*块作用域*；它不适用于其包含的块之外：

```js
let foo = 'bar';

if(foo == 'bar') {
    let foo = 'baz';
    console.log(foo); // 1st
}
console.log(foo); // 2nd

// baz
// bar
// If we had used var instead of let:
// baz
// baz
```

对于永远不会改变的变量，请使用`const`，表示*constant*。这对编译器也很有帮助，因为如果变量保证永远不会改变，编译器可以更容易地进行优化。请注意，`const`仅适用于赋值，以下是非法的：

```js
const foo = 1;
foo = 2; // Error: assignment to a constant variable
```

但是，如果值是对象，`const`无法保护成员：

```js
const foo = { bar: 1 }
console.log(foo.bar) // 1
foo.bar = 2;
console.log(foo.bar) // 2
```

另一个强大的新功能是**解构**，它允许我们轻松地将数组的值分配给新变量：

`let [executable, absPath, target, ...message] = process.argv;`

解构允许您快速将数组映射到变量名。由于`process.argv`是一个数组，它始终包含 Node 可执行文件的路径和执行文件的路径作为前两个参数，我们可以通过执行`node script.js /some/file/path`将文件目标传递给上一个脚本，其中第三个参数分配给`target`变量。

也许我们还想通过这样的方式传递消息：

`node script.js /some/file/path This is a really great file!`

问题在于`This is a really great file!`是以空格分隔的，因此它将被分割成每个单词的数组，这不是我们想要的：

`[... , /some/file/path, This, is, a, really, great, file!]`

**剩余模式**在这里拯救了我们：最终参数`...message`将所有剩余的解构参数合并为一个数组，我们可以简单地`join(' ')`成一个字符串。这也适用于对象：

```js
let obj = {
    foo: 'foo!',
    bar: 'bar!',
    baz: 'baz!'
};

// assign keys to local variables with same names
let {foo, baz} = obj;

// Note that we "skipped" #bar
console.log(foo, baz); // foo! baz!
```

这种模式对于处理函数参数特别有用。在使用剩余参数之前，您可能会以这种方式获取函数参数：

```js
function (a, b) {
    // Grab any arguments after a & b and convert to proper Array
    let args = Array.prototype.slice.call(arguments, f.length);
}
```

以前是必要的，因为`arguments`对象不是真正的数组。除了相当笨拙外，这种方法还会触发像 V8 这样的编译器中的非优化。

现在，你可以这样做：

```js
function (a, b, ...args) {
    // #args is already an Array!
}
```

**展开模式**是反向的剩余模式——你可以将单个变量扩展为多个：

```js
const week = ['mon','tue','wed','thur','fri'];
const weekend = ['sat','sun'];

console.log([...week, ...weekend]); // ['mon','tue','wed','thur','fri','sat','sun']

week.push(...weekend);
console.log(week); // ['mon','tue','wed','thur','fri','sat','sun']
```

# 箭头函数

**箭头函数**允许你缩短函数声明，从`function() {}`到`简单 () => {}`。实际上，你可以替换一行代码：

`SomeEmitter.on('message', function(message) { console.log(message) });`

至于：

`SomeEmitter.on('message', message => console.log(message));`

在这里，我们失去了括号和大括号，更紧凑的代码按预期工作。

箭头函数的另一个重要特性是它们不会分配自己的`this`——箭头函数从调用位置继承`this`。例如，以下代码不起作用：

```js
function Counter() {
    this.count = 0;

    setInterval(function() {
        console.log(this.count++);
    }, 1000);
}

new Counter();
```

`setInterval`内的函数是在`setInterval`的上下文中调用的，而不是`Counter`对象的上下文，因此`this`没有任何与计数相关的引用。也就是说，在函数调用站点，`this`是一个`Timeout`对象，你可以通过在先前的代码中添加`console.log(this)`来检查自己。

使用箭头函数，`this`在定义的时候被分配。修复代码很容易：

```js
setInterval(() => { // arrow function to the rescue!
  console.log(this);
  console.log(this.count++);
}, 1000);
// Counter { count: 0 }
// 0
// Counter { count: 1 }
// 1
// ...
```

# 字符串操作

最后，你会在代码中看到很多反引号。这是新的**模板文字**语法，除其他功能外，它（终于！）使得在 JavaScript 中处理字符串变得更不容易出错和繁琐。你在示例中看到了如何轻松表达多行字符串（避免`'First line\n' + 'Next line\n'`这种构造）。字符串插值也得到了类似的改进：

```js
let name = 'Sandro';
console.log('My name is ' + name);
console.log(`My name is ${name}`);
// My name is Sandro
// My name is Sandro
```

这种替换在连接许多变量时特别有效，因为每个`${expression}`的内容都可以是任何 JavaScript 代码：

```js
console.log(`2 + 2 = ${2+2}`)  // 2 + 2 = 4
```

你也可以使用`repeat`来生成字符串：`'ha'.repeat(3) // hahaha`。

现在字符串是可迭代的。使用新的`for...of`结构，你可以逐个字符地拆分字符串：

```js
for(let c of 'Mastering Node.js') {
    console.log(c);
    // M
    // a
    // s
    // ...
}
```

或者，使用展开操作符：

```js
console.log([...'Mastering Node.js']);
// ['M', 'a', 's',...]
```

搜索也更容易。新的方法允许常见的子字符串查找而不需要太多仪式：

```js
let targ = 'The rain in Spain lies mostly on the plain';
console.log(targ.startsWith('The', 0)); // true
console.log(targ.startsWith('The', 1)); // false
console.log(targ.endsWith('plain')); // true
console.log(targ.includes('rain', 5)); // false
```

这些方法的第二个参数表示搜索偏移，默认为 0。`The`在位置 0 被找到，所以在第二种情况下从位置 1 开始搜索会失败。

很好，编写 JavaScript 程序变得更容易了。下一个问题是当程序在 V8 进程中执行时发生了什么？

# 进程对象

Node 的**process 对象**提供了有关当前运行进程的信息和控制。它是`EventEmitter`的一个实例，可以从任何范围访问，并公开非常有用的低级指针。考虑下面的程序：

```js
const size = process.argv[2];
const n = process.argv[3] || 100;
const buffers = [];
let i;
for (i = 0; i < n; i++) {
  buffers.push(Buffer.alloc(size));
  process.stdout.write(process.memoryUsage().heapTotal + "\n");
}
```

让 Node 使用类似这样的命令运行`process.js`：

```js
$ node process.js 1000000 100
```

程序从`process.argv`获取命令行参数，循环分配内存，并将内存使用情况报告回标准输出。你可以将输出流到另一个进程或文件，而不是记录回终端：

```js
$ node process.js 1000000 100 > output.txt
```

Node 进程通过构建单个执行堆栈开始，全局上下文形成堆栈的基础。这个堆栈上的函数在它们自己的本地上下文中执行（有时被称为**作用域**），这个本地上下文保持在全局上下文中。将函数的执行与函数运行的环境保持在一起的方式被称为**闭包**。因为 Node 是事件驱动的，任何给定的执行上下文都可以将运行线程提交给处理最终执行上下文。这就是回调函数的目的。

考虑下面的简单接口示意图，用于访问文件系统：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/ed1fbee2-0820-44ff-96b6-1bacc2f11e1d.png)

如果我们实例化`Filesystem`并调用`readDir`，将创建一个嵌套的执行上下文结构：

```js
(global (fileSystem (readDir (anonymous function) ) ) )
```

在 Node 内部，一个名为`libuv`的 C 库创建和管理事件循环。它连接到可以产生事件的低级操作系统内核模式对象，例如定时器触发、接收数据的套接字、打开读取的文件和完成的子进程。它在仍有事件需要处理时循环，并调用与事件相关的回调。它在非常低的级别上进行操作，并且具有非常高效的架构。为 Node 编写的`libuv`现在是许多软件平台和语言的构建块。

与此同时，执行堆栈被引入到 Node 的单进程线程中。这个堆栈保留在内存中，直到`libuv`报告`fs.readdir`已经完成，此时注册的匿名回调触发，解析唯一的待处理执行上下文。由于没有进一步的事件待处理，也不再需要维护闭包，整个结构可以安全地被拆除（从匿名开始逆序），进程可以退出，释放任何分配的内存。构建和拆除单个堆栈的方法就是 Node 的事件循环最终所做的。

# REPL

Node 的**REPL**（**Read-Eval-Print-Loop**）代表了 Node 的 shell。要进入 shell 提示符，通过终端输入 Node 而不传递文件名：

```js
$ node
```

现在您可以访问正在运行的 Node 进程，并可以向该进程传递 JavaScript 命令。此外，如果输入一个表达式，REPL 将回显表达式的值。作为这一点的一个简单例子，您可以使用 REPL 作为一个口袋计算器：

```js
$ node
> 2+2
4
```

输入`2+2`表达式，Node 将回显表达式的值`4`。除了简单的数字文字之外，您可以使用这种行为来查询、设置和再次查询变量的值：

```js
> a
ReferenceError: a is not defined
 at repl:1:1
 at sigintHandlersWrap (vm.js:22:35)
 at sigintHandlersWrap (vm.js:96:12)
 at ContextifyScript.Script.runInThisContext (vm.js:21:12)
 at REPLServer.defaultEval (repl.js:346:29)
 at bound (domain.js:280:14)
 at REPLServer.runBound [as eval] (domain.js:293:12)
 at REPLServer.<anonymous> (repl.js:545:10)
 at emitOne (events.js:101:20)
 at REPLServer.emit (events.js:188:7)
> a = 7
7
> a
7
```

Node 的 REPL 是一个很好的地方，可以尝试、调试、测试或以其他方式玩耍 JavaScript 代码。

由于 REPL 是一个本地对象，程序也可以使用实例作为运行 JavaScript 的上下文。例如，在这里我们创建了自己的自定义函数`sayHello`，将其添加到 REPL 实例的上下文中，并启动 REPL，模拟 Node shell 提示符：

```js
require('repl').start("> ").context.sayHello = function() {
  return "Hello";
};
```

在提示符处输入`sayHello()`，函数将向标准输出发送`Hello`。

让我们把这一章学到的一切都应用到一个交互式的 REPL 中，允许我们在远程服务器上执行 JavaScript：

1.  创建两个文件`client.js`和`server.js`，并输入以下代码。

1.  在自己的终端窗口中运行每个程序，将两个窗口并排放在屏幕上：

```js
// File client.js
let net = require("net");
let sock = net.connect(8080);
process.stdin.pipe(sock);
sock.pipe(process.stdout);

// File server.js
let repl = require("repl")
let net = require("net")
net.createServer((socket) => {
  repl
  .start({
    prompt: "> ",
    input: socket,
    output: socket,
    terminal: true
  }).on('exit', () => {
    socket.end();
  })
}).listen(8080);
```

`client.js`程序通过`net.connect`创建一个新的套接字连接到端口`8080`，并将来自标准输入（您的终端）的任何数据通过该套接字传输。同样，从套接字到达的任何数据都被传输到标准输出（返回到您的终端）。通过这段代码，我们创建了一种方式，将终端输入通过套接字发送到端口`8080`，并监听套接字可能发送回来的任何数据。

另一个程序`server.js`结束了循环。这个程序使用`net.createServer`和`.listen`来创建和启动一个新的 TCP 服务器。代码传递给`net.createServer`的回调接收到绑定套接字的引用。在该回调的封闭内部，我们实例化一个新的 REPL 实例，给它一个漂亮的提示符（这里是`>`，但可以是任何字符串），指示它应该同时监听来自传递的套接字引用的输入，并广播输出，指示套接字数据应该被视为终端数据（具有特殊编码）。

现在我们可以在客户端终端中输入`console.log("hello")`，并看到显示`hello`。

要确认我们的 JavaScript 命令的执行发生在服务器实例中，可以在客户端输入`console.log(process.argv)`，服务器将显示一个包含当前进程路径的对象，即`server.js`。

只需几行代码，我们就创建了一种远程控制 Node 进程的方式。这是迈向多节点分析工具、远程内存管理、自动服务器管理等的第一步。

# 总结

有经验的开发人员都曾经面对过 Node 旨在解决的问题：

+   如何有效地为成千上万的同时客户提供服务

+   将网络应用程序扩展到单个服务器之外

+   防止 I/O 操作成为瓶颈

+   消除单点故障，从而确保可靠性

+   安全可预测地实现并行性

随着每一年的过去，我们看到协作应用程序和软件负责管理并发水平，这在几年前被认为是罕见的。管理并发，无论是在连接处理还是应用程序设计方面，都是构建可扩展架构的关键。

在本章中，我们概述了 Node 的设计者试图解决的关键问题，以及他们的解决方案如何使开发人员社区更容易创建可扩展、高并发的网络系统。我们看到了 JavaScript 被赋予了非常有用的新功能，它的事件模型得到了扩展，V8 可以配置以进一步定制 JavaScript 运行时。通过示例，我们学习了 Node 如何处理 I/O，如何编程 REPL，以及如何管理输入和输出到进程对象。

Node 将 JavaScript 转化为系统语言，创造了一个有用的时代错位，既可以脚本套接字，也可以按钮，并跨越了几十年的计算机演变学习。

Node 的设计恢复了 20 世纪 70 年代 Unix 原始开发人员发现的简单性的优点。有趣的是，计算机科学在这段时间内反对了这种哲学。C++和 Java 倾向于面向对象的设计模式、序列化的二进制数据格式、子类化而不是重写以及其他政策，这些政策导致代码库在最终在自身复杂性的重压下崩溃之前往往增长到一百万行或更多。

然后出现了网络。浏览器的“查看源代码”功能是一个温和的入口，它将数百万网络用户带入了新一代软件开发人员的行列。Brendan Eich 设计 JavaScript 时考虑到了这些新手潜在开发人员。很容易从编辑标签和更改样式开始，然后很快就能编写代码。与新兴初创公司的年轻员工交谈，现在他们是专业开发人员、工程师和计算机科学家，许多人会回忆起“查看源代码”是他们开始的方式。

回到 Node 的时间扭曲，JavaScript 在 Unix 的创始原则中找到了类似的设计和哲学。也许将计算机连接到互联网给聪明人带来了新的、更有趣的计算问题要解决。也许又出现了一代新的学生和初级员工，并再次反抗他们的导师。无论出于何种原因，小型、模块化和简单构成了今天的主导哲学，就像很早以前一样。

在未来几十年，计算技术会发生多少次变化，足以促使当时的设计师编写与几年前教授和接受为正确、完整和永久的软件和语言截然不同的新软件？正如*阿瑟·C·克拉克*所指出的，试图预测未来是一项令人沮丧和危险的职业。也许我们会看到计算机和代码的几次革命。另一方面，计算技术很可能很快就会进入一个稳定期，在这段时间内，计算机科学家将找到并确定最佳的范例来教授和使用。现在没有人知道编码的最佳方式，但也许很快我们会知道。如果是这样的话，那么现在这个时候，当创建和探索以找到这些答案是任何人的游戏时，是一个非常引人入胜的时刻，可以与计算机一起工作和玩耍。

我们展示 Node 如何以一种有原则的方式智能地构建应用程序的目标已经开始。在下一章中，我们将更深入地探讨异步编程，学习如何管理更复杂的事件链，并使用 Node 的模型开发更强大的程序。


# 第二章：理解异步事件驱动编程

“预测未来的最好方法是创造它。”

– Alan Kay

通过使用事件驱动的异步 I/O 来消除阻塞进程是 Node 的主要组织原则。我们已经了解到这种设计如何帮助开发人员塑造信息并增加容量。Node 允许您构建和组织轻量级、独立的、无共享的进程，这些进程通过回调进行通信，并与可预测的事件循环同步。

随着 Node 的流行度增长，设计良好的事件驱动系统和应用程序的数量也在增加。要使一种新技术成功，它必须消除现有的问题，并/或以更低的时间、精力或价格成本为消费者提供更好的解决方案。在其年轻而富有活力的生命周期中，Node 社区已经合作证明了这种新的开发模式是现有技术的可行替代方案。基于 Node 的解决方案的数量和质量为企业级应用程序提供了进一步的证明，表明这些新想法不仅是新颖的，而且是受欢迎的。

在本章中，我们将更深入地探讨 Node 如何实现事件驱动编程。我们将首先解开事件驱动语言和环境从中获得和处理的想法和理论，以消除误解并鼓励掌握。在介绍事件之后，我们将重点介绍 Node.js 技术——事件循环。然后，我们将更详细地讨论 Node 如何实现定时器、回调和 I/O 事件，以及作为 Node 开发人员如何使用它们。我们还将讨论使用现代工具（如**Promises**、**Generators**和**async/await**）管理并发的方法。在构建一些简单但典型的文件和数据驱动应用程序时，我们将实践这些理论。这些示例突出了 Node 的优势，并展示了 Node 如何成功地简化了网络应用程序设计。

# Node 的独特设计

首先，让我们准确地看一下当您的程序要求系统执行不同类型的服务时的总时间成本。I/O 是昂贵的。在下图中（取自*Ryan Dahl*关于 Node 的原始演示），我们可以看到典型系统任务消耗多少个时钟周期。I/O 操作的相对成本令人震惊：

| L1 缓存 | 3 个周期 |
| --- | --- |
| L2 缓存 | 14 个周期 |
| RAM | 250 个周期 |
| 磁盘 | 41,000,000 个周期 |
| 网络 | 240,000,000 个周期 |

原因是很明显的：磁盘是一个物理设备，一个旋转的金属盘——存储和检索数据比在固态设备（如微处理器和存储芯片）之间移动数据要慢得多，或者说比在优化的芯片上的 L1/L2 缓存要慢得多。同样，数据在网络上不是瞬间移动的。光本身需要 0.1344 秒才能环绕地球！在一个由数十亿人定期在速度远远慢于光速的距离上相互交流的网络中，有许多弯路和少数直线，这种延迟会积累起来。

当我们的软件在我们桌子上的个人电脑上运行时，几乎没有或根本没有通过网络进行通信。与文字处理器或电子表格的交互中的延迟或故障与磁盘访问时间有关。为了提高磁盘访问速度，做了大量工作。数据存储和检索变得更快，软件变得更具响应性，用户现在期望在其工具中获得这种响应性。

随着云计算和基于浏览器的软件的出现，您的数据已经离开了本地磁盘，存在于远程磁盘上，并且您通过网络——互联网访问这些数据。数据访问时间再次显著减慢。网络 I/O 很慢。尽管如此，越来越多的公司正在将其应用程序的部分迁移到云中，一些软件甚至完全基于网络。

Node 旨在使 I/O 快速。它是为这个新的网络软件世界设计的，其中数据分布在许多地方，必须快速组装。许多传统的构建 Web 应用程序的框架是在一个单一用户使用桌面计算机，使用浏览器定期向运行关系数据库的单个服务器发出 HTTP 请求的时代设计的。现代软件必须预期成千上万个同时连接的客户端通过各种网络协议在任意数量的独特设备上同时更改庞大的共享数据池。Node 专门设计为帮助那些构建这种网络软件的人。

Node 设计所反映的思维突破一旦被认识到，就变得简单易懂，因为大多数工作线程都在等待——等待更多指令，等待子任务完成等。例如，被分配为服务命令“格式化我的硬盘”的进程将把所有资源用于管理工作流程，类似以下内容：

+   向设备驱动程序通知已发出格式请求

+   空闲，等待*不可知*的时间长度

+   接收格式完成的信号

+   通知客户端

+   清理；关闭：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/654909f4-ef43-4a75-9199-e145e067c376.png)

在前面的图中，我们看到一个昂贵的工人正在向客户收取固定的时间单位费用，无论是否正在做任何有用的工作（客户对活动和空闲一视同仁地付费）。换句话说，并不一定是真的，而且往往不是真的，组成总任务的子任务每个都需要相似的努力或专业知识。因此，为这种廉价劳动力支付高价是浪费的。

同情地说，我们还必须认识到，即使准备好并能够处理更多工作，这个工人也无法做得更好——即使是最有诚意的工人也无法解决 I/O 瓶颈的问题。这个工人是**I/O 受限**的。

相反，想象一种替代设计。如果多个客户端可以共享同一个工人，那么当一个工人因 I/O 瓶颈而宣布可用时，另一个客户端的工作可以开始吗？

Node 通过引入一个系统资源（理想情况下）**永远**不会空闲的环境，使 I/O 变得通用。Node 实现的事件驱动编程反映了降低整体系统成本的简单目标，主要通过减少 I/O 瓶颈的数量来鼓励共享昂贵的劳动力。我们不再拥有无能为力的僵化定价的劳动力块；我们可以将所有努力减少为精确界定形状的离散单位，因此可以实现更准确的定价。

一个协作调度了许多客户端工作的环境会是什么样子？这种事件之间的消息传递是如何处理的？此外，并发、并行、异步执行、回调和事件对 Node 开发人员意味着什么？

# 协作

与先前描述的阻塞系统相比，更可取的是一个协作工作环境，工人定期被分配新任务，而不是空闲。为了实现这样的目标，我们需要一个虚拟交换机，将服务请求分派给可用的工人，并让工人通知交换机他们的可用性。

实现这一目标的一种方法是拥有一个可用劳动力池，通过将任务委派给不同的工人来提高效率：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/57b70667-0b0f-44fa-a901-76806eda58ba.png)

这种方法的一个缺点是需要进行大量的调度和工人监视。调度程序必须处理源源不断的请求，同时管理来自工人的关于他们可用性的消息，将请求整理成可管理的任务并高效地排序，以便最少数量的工人处于空闲状态。

也许最重要的是，当所有工人都被预订满了会发生什么？调度程序是否开始从客户那里丢弃请求？调度也是资源密集型的，调度程序的资源也是有限的。如果请求继续到达，而没有工人可用来为其提供服务，调度程序会怎么做？管理队列？我们现在有一个情况，调度程序不再做正确的工作（调度），而是负责簿记和保持列表，进一步延长每个任务完成所需的时间。每个任务需要一定的时间，并且必须按到达顺序进行处理。这个任务执行模型堆叠了固定的时间间隔——*时间片*。这是*同步*执行。

# 排队

为了避免过载任何人，我们可以在客户和调度程序之间添加一个缓冲区。这个新的工人负责管理客户关系。客户不直接与调度程序交谈，而是与服务经理交谈，将请求传递给经理，并在将来的某个时候接到通知，说他们的任务已经完成。工作请求被添加到一个优先级工作队列（一个订单堆栈，最重要的订单在顶部），这个经理等待另一个客户走进门。

以下图表描述了情况：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/bcb39362-b03e-413f-9c99-a8e37f043fc4.png)

调度程序试图通过从队列中提取任务，将工人完成的任何包传回，并通常维护一个理智的工作环境，以确保没有任何东西被丢弃或丢失，来使所有工人保持忙碌。与沿着单个时间线逐个进行任务不同，多个同时运行在其自己的时间线上的任务并行运行。如果所有工人都处于空闲状态且任务队列为空，那么办公室可以休息一会儿，直到下一个客户到来。

这是 Node 通过*异步*工作而不是*同步*工作来获得速度的粗略示意图。现在，让我们深入了解 Node 的事件循环是如何工作的。

# 理解事件循环

在我们分解事件循环时，以下三点很重要：

+   事件循环在与您的 JavaScript 代码运行的相同（单个）线程中运行。阻塞事件循环意味着阻塞整个线程。

+   您不会启动和/或停止事件循环。事件循环在进程启动时开始，并在没有进一步的回调需要执行时结束。因此，事件循环可能永远运行。

+   事件循环将许多 I/O 操作委托给`libuv`，后者管理这些操作（使用 OS 本身的能力，如线程池），并在结果可用时通知事件循环。易于理解的单线程编程模型通过多线程的效率得到了加强。

例如，以下`while`循环永远不会终止：

```js
let stop = false;
setTimeout(() => {
  stop = true;
}, 1000);

while (stop === false) {};
```

即使有人可能期望，在大约一秒钟内，将布尔值`true`分配给变量`stop`，触发`while`条件并中断其循环；这永远不会发生。为什么？这个`while`循环通过无限运行来使事件循环饥饿，贪婪地检查和重新检查一个永远不会有机会改变的值，因为事件循环永远不会有机会安排我们的定时器回调进行执行。这证明了事件循环（管理定时器）并且在同一个线程上运行。

根据 Node 文档，“事件循环是 Node.js 执行非阻塞 I/O 操作的关键，尽管 JavaScript 是单线程的，但通过尽可能地将操作卸载到系统内核来实现。” Node 的设计者所做的关键设计选择是将事件循环实现为并发管理器。例如，通过`libuv`，OS 传递网络接口事件来通知基于 Node 的 HTTP 服务器与本地硬件的网络连接。

以下是事件驱动编程的描述（摘自：[`www.princeton.edu/~achaney/tmve/wiki100k/docs/Event-driven_programming.html`](http://www.princeton.edu/~achaney/tmve/wiki100k/docs/Event-driven_programming.html)），不仅清楚地描述了事件驱动范式，还向我们介绍了事件在 Node 中的处理方式，以及 JavaScript 是这种范式的理想语言。

在计算机编程中，事件驱动编程或基于事件的编程是一种编程范式，其中程序的流程由事件决定 - 即传感器输出或用户操作（鼠标点击，按键）或来自其他程序或线程的消息。事件驱动编程也可以被定义为一种应用架构技术，其中应用程序具有一个主循环，明确定义为两个部分：第一个是事件选择（或事件检测），第二个是事件处理[...]。事件驱动程序可以用任何语言编写，尽管在提供高级抽象的语言中更容易，比如闭包。有关更多信息，请访问[`www.youtube.com/watch?v=QQnz4QHNZKc`](https://www.youtube.com/watch?v=QQnz4QHNZKc)。

Node 通过将许多阻塞操作委托给 OS 子系统来使单个线程更有效，只有在有数据可用时才会打扰主 V8 线程。主线程（执行中的 Node 程序）通过传递回调来表达对某些数据的兴趣（例如通过`fs.readFile`），并在数据可用时得到通知。在数据到达之前，不会对 V8 的主 JavaScript 线程施加进一步的负担。如何做到的？Node 将 I/O 工作委托给`libuv`，如引用所述：[`nikhilm.github.io/uvbook/basics.html#event-loops`](http://nikhilm.github.io/uvbook/basics.html#event-loops)。

在事件驱动编程中，应用程序表达对某些事件的兴趣，并在发生时做出响应。从操作系统收集事件或监视其他事件源的责任由`libuv`处理，用户可以注册回调以在事件发生时被调用。

* Matteo Collina *创建了一个有趣的模块，用于对事件循环进行基准测试，可在以下网址找到：[`github.com/mcollina/loopbench`](https://github.com/mcollina/loopbench)。

考虑以下代码：

```js
const fs = require('fs');
fs.readFile('foo.js', {encoding:'utf8'}, (err, fileContents) => {
  console.log('Then the contents are available', fileContents);
});
console.log('This happens first');
```

该程序的输出是：

```js
> This happens first
> Then the contents are available, [file contents shown]
```

执行此程序时，Node 的操作如下：

1.  使用 V8 API 在 C++中创建了一个进程对象。然后将 Node.js 运行时导入到这个 V8 进程中。

1.  `fs`模块附加到 Node 运行时。V8 将 C++暴露给 JavaScript。这为您的 JavaScript 代码提供了对本机文件系统绑定的访问权限。

1.  `fs.readFile`方法传递了指令和 JavaScript 回调。通过`fs.binding`，`libuv`被通知文件读取请求，并传递了原始程序发送的回调的特别准备版本。

1.  `libuv`调用了必要的操作系统级函数来读取文件。

1.  JavaScript 程序继续运行，打印`This happens first`。因为有一个未解决的回调，事件循环继续旋转，等待该回调解析。

1.  当操作系统完全读取文件描述符时，通过内部机制通知`libuv`，并调用传递给`libuv`的回调，从而为原始 JavaScript 回调准备重新进入主（V8）线程。

1.  原始的 JavaScript 回调被推送到事件循环，并在循环的近期刻度上被调用。

1.  文件内容被打印到控制台。

1.  由于没有进一步的回调在飞行中，进程退出。

在这里，我们看到了 Node 实现的关键思想，以实现快速、可管理和可扩展的 I/O。例如，如果在前面的程序中对`foo.js`进行了 10 次读取调用，执行时间仍然大致相同。每个调用都将由`libuv`尽可能高效地管理（例如，通过使用线程并行化调用）。尽管我们的代码是用 JavaScript 编写的，但实际上我们部署了一个非常高效的多线程执行引擎，同时避免了操作系统异步进程管理的困难。

现在我们知道了文件系统操作可能是如何工作的，让我们深入了解 Node 在事件循环中如何处理每种异步操作类型。

# 事件循环排序、阶段和优先级

事件循环通过阶段进行处理，每个阶段都有一个要处理的事件队列。来自 Node 文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/d3cdf6c5-7bf6-4a11-8fc0-fdba8cd39ffb.png)

对开发人员相关的阶段如下：

+   **定时器**：延迟到未来某个指定的毫秒数的回调，比如`setTimeout`和`setInterval`

+   **I/O 回调**：在被委托给 Node 的管理线程池后返回到主线程的准备好的回调，比如文件系统调用和网络监听器

+   **轮询/检查**：主要是根据`setImmediate`和`nextTick`的规则排列在堆栈上的函数

当套接字或其他流接口上有数据可用时，我们不能立即执行回调。JavaScript 是单线程的，所以结果必须同步。我们不能在事件循环的中间突然改变状态，这会导致一些经典的多线程应用程序问题，比如竞争条件、内存访问冲突等。

要了解更多关于 Node 如何绑定到`libuv`和其他核心库的信息，请查看`fs`模块的代码：[`github.com/nodejs/node/blob/master/lib/fs.js`](https://github.com/nodejs/node/blob/master/lib/fs.js)。比较`fs.read`和`fs.readSync`方法，观察同步和异步操作的实现方式的不同；注意在`fs.read`中传递给原生`binding.read`方法的包装回调。要深入了解 Node 设计的核心部分，包括队列实现，请阅读 Node 源代码：[`github.com/joyent/node/tree/master/src`](https://github.com/joyent/node/tree/master/src)。查看`fs_event_wrap.cc`中的`FSEventWrap`。调查`req_wrap`类，这是 V8 引擎的包装器，在`node_file.cc`和其他地方部署，并在`req_wrap.h`中定义。

进入事件循环时，Node 实际上会复制当前指令队列（也称为**堆栈**），清空原始队列，并执行其副本。处理这个指令队列被称为**tick**。如果`libuv`在单个主线程（V8）上处理此 tick 开始时复制的指令链时异步接收到结果（包装为回调），这些结果将被排队。一旦当前队列被清空并且其最后一条指令完成，队列将再次被检查以执行下一个 tick 上的指令。这种检查和执行队列的模式将重复（循环），直到队列被清空，并且不再期望有更多的数据事件，此时 Node 进程退出。

接下来，让我们看看 Node 的事件接口。

# 监听事件

现代网络软件因为各种原因变得越来越复杂，并且在很多方面改变了我们对应用程序开发的看法。大多数新平台和语言都试图解决这些变化。Node 也不例外，JavaScript 也不例外。

学习 Node 意味着学习事件驱动编程，将软件组合成模块，创建和链接数据流，生成和消耗事件及其相关数据。基于 Node 的架构通常由许多小进程和/或服务组成，这些进程和/或服务通过事件进行通信 - 内部通过扩展`EventEmitter`接口并使用回调，外部通过几种常见的传输层之一（例如 HTTP，TCP），或通过覆盖这些传输层之一的薄消息传输层（例如 0MQ，Redis PUBSUB 和 Kafka）。

这些进程很可能由几个免费、开源和高质量的 npm 模块组成，每个模块都配备了单元测试和/或示例和/或文档。

上一章向您介绍了`EventEmitter`接口。这是我们在逐章移动时将遇到的主要事件接口，因为它为许多暴露事件接口的 Node 对象提供了原型类，例如文件和网络流。不同模块 API 暴露的各种`close`、`exit`、`data`和其他事件都表示了`EventEmitter`接口的存在，随着我们的学习，我们将了解这些模块和用例。

在本节中，我们的目标是讨论一些较少为人知的事件源：信号、子进程通信、文件系统更改事件和延迟执行。

# 信号

事件驱动编程就像硬件中断编程。中断正是其名称所暗示的。它们利用中断控制器、CPU 或任何其他设备正在执行的任务，要求立即为它们的特定需求提供服务。

事实上，Node 进程对象公开了标准**可移植操作系统接口（POSIX）**信号名称，因此 Node 进程可以订阅这些系统事件。

正如[`en.wikipedia.org/wiki/POSIX_signal`](http://en.wikipedia.org/wiki/POSIX_signal) 所定义的，“信号是 Unix、类 Unix 和其他符合 POSIX 标准的操作系统中使用的一种有限的进程间通信形式。它是异步通知，发送给进程或同一进程中的特定线程，以通知其发生的事件。”

这是将 Node 进程暴露给操作系统信号事件的一种非常优雅和自然的方式。可以配置监听器来捕获指示 Node 进程重新启动或更新某些配置文件，或者简单地进行清理和关闭的信号。

例如，当控制终端检测到*Ctrl* + *C*（或等效）按键时，**SIGINT**信号将发送到进程。此信号告诉进程已请求中断。如果 Node 进程已将回调绑定到此事件，则该函数可能在终止之前记录请求，执行其他清理工作，甚至忽略请求：

```js
// sigint.js
console.log("Running...");

// After 16 minutes, do nothing
setInterval(() => {}, 1e6); // Keeps Node running the process

// Subscribe to SIGINT, so some of our code runs when Node gets that signal
process.on("SIGINT", () => {
    console.log("We received the SIGINT signal!");
    process.exit(1);
});
```

以下是`sigint.js`的输出：

```js
$ node sigint.js
Running...
(then press Ctrl+C)
We received the SIGINT signal!
```

此示例启动了一个长时间间隔，因此 Node 不会因无其他任务而退出。当您通过控制进程的终端从键盘发送*Ctrl* + *C*时，Node 会从操作系统接收信号。您的代码已订阅了该事件，Node 会运行您的函数。

现在，考虑这样一种情况，即 Node 进程正在进行一些持续的工作，例如解析日志。能够向该进程发送信号，例如更新配置文件或重新启动扫描，可能是有用的。您可能希望从命令行发送这些信号。您可能更喜欢由另一个进程执行此操作 - 这种做法称为**进程间通信**（IPC）。

创建一个名为`ipc.js`的文件，并键入以下代码：

```js
// ipc.js
setInterval(() => {}, 1e6);
process.on("SIGUSR1", () => {
    console.log("Got a signal!");
});
```

运行以下命令：

```js
$ node ipc.js
```

与以前一样，Node 将在运行空函数之前等待大约 16 分钟，保持进程开放，因此您将不得不使用*Ctrl *+ *C*来恢复提示符。请注意，即使在这里，我们没有订阅 SIGINT 信号，这也可以正常工作。

`SIGUSR1`（和`SIGUSR2`）是用户定义的信号，由操作系统不知道的特定操作触发。它们用于自定义功能。

要向进程发送命令，必须确定其**进程 ID**。有了 PID，您就可以寻址进程并与其通信。如果`ipc.js`在通过 Node 运行后分配的 PID 是`123`，那么我们可以使用`kill`命令向该进程发送`SIGUSR1`信号：

```js
$ kill –s SIGUSR1 123
```

在 UNIX 中查找给定 Node 进程的 PID 的一个简单方法是在系统进程列表中搜索正在运行的程序名称。如果`ipc.js`当前正在执行，可以通过在控制台/终端中输入以下命令行来找到其 PID：

使用`ps aux | grep ipc.js`命令。试试看。

# 子进程

Node 设计的一个基本部分是在并行执行或扩展系统时创建或分叉进程，而不是创建线程池。我们将在本书中以各种方式使用这些子进程。现在，重点将放在理解如何处理子进程之间的通信事件上。

要创建一个子进程，需要引入 Node 的`child_process`模块，并调用`fork`方法。传递新进程应执行的程序文件的名称：

```js
let cp = require("child_process");
let child = cp.fork(__dirname + "/lovechild.js");
```

您可以使用这种方法保持任意数量的子进程运行。在多核机器上，操作系统将分配分叉出的进程到可用的硬件核心上。将 Node 进程分布到核心上，甚至分布到其他机器上，并管理 IPC 是一种稳定、可理解和可预测的方式来扩展 Node 应用程序。

扩展前面的示例，现在分叉进程（`parent`）可以发送消息，并监听来自分叉进程（`child`）的消息。以下是`parent.js`的代码：

```js
// parent.js
const cp = require("child_process");
let child = cp.fork(__dirname + "/lovechild.js");

child.on("message", (m) => {
  console.log("Child said: ", m); // Parent got a message up from our child
});
child.send("I love you"); // Send a message down to our child
```

以下是`parent.js`的输出：

```js
$ node parent.js
Parent said:  I love you
Child said:  I love you too
(then Ctrl+C to terminate both processes)
```

在那个文件旁边，再创建一个文件，命名为`lovechild.js`。这里的子代码可以监听消息并将其发送回去：

```js
// lovechild.js
process.on("message", (m) => {
  console.log("Parent said: ", m); // Child got a message down from the parent
  process.send("I love you too"); // Send a message up to our parent
});
```

不要自己运行`lovechild.js`；`--parent.js`会为您进行分叉！

运行`parent.js`应该会分叉出一个子进程并向该子进程发送消息。子进程应该以同样的方式回应：

```js
Parent said:  I love you
Child said:  I love you too
```

运行`parent.js`时，请检查您的操作系统任务管理器。与之前的示例不同，这里将有两个 Node 进程，而不是一个。

另一个非常强大的想法是将网络服务器的对象传递给子进程。这种技术允许多个进程，包括父进程，共享服务连接请求的责任，将负载分布到核心上。

例如，以下程序将启动一个网络服务器，分叉一个子进程，并将父进程的服务器引用传递给子进程：

```js
// net-parent.js
const path = require('path');
let child = require("child_process").fork(path.join(__dirname, "net-child.js"));
let server = require("net").createServer();

server.on("connection", (socket) => {
  socket.end("Parent handled connection");
});

server.listen(8080, () => {
  child.send("Parent passing down server", server);
});
```

除了将消息作为第一个参数发送给子进程之外，前面的代码还将服务器句柄作为第二个参数发送给自己。我们的子服务器现在可以帮助家族的服务业务：

```js
// net-child.js
process.on("message", function(message, server) {
  console.log(message);
  server.on("connection", function(socket) {
    socket.end("Child handled connection");
  });
});
```

这个子进程应该会在您的控制台上打印出发送的消息，并开始监听连接，共享发送的服务器句柄。

重复连接到`localhost:8080`的服务器将显示由子进程处理的连接或由父进程处理的连接；两个独立的进程正在平衡服务器负载。当与之前讨论的简单进程间通信协议相结合时，这种技术展示了*Ryan Dahl*的创作如何成功地提供了构建可扩展网络程序的简单方法。

我们只用了几行代码就连接了两个节点。

我们将讨论 Node 的新集群模块，它扩展并简化了之前在第七章中讨论的技术，*使用多个进程*。如果您对服务器处理共享感兴趣，请访问集群文档：[`nodejs.org/dist/latest-v9.x/docs/api/cluster.html`](https://nodejs.org/dist/latest-v9.x/docs/api/cluster.html)

# 文件事件

大多数应用程序都会对文件系统进行一些操作，特别是那些作为 Web 服务的应用程序。此外，专业的应用程序可能会记录有关使用情况的信息，缓存预渲染的数据视图，或者对文件和目录结构进行其他更改。Node 允许开发人员通过`fs.watch`方法注册文件事件的通知。`watch`方法会在文件和目录上广播更改事件。

`watch`方法按顺序接受三个参数：

+   正在被监视的文件或目录路径。如果文件不存在，将抛出**ENOENT（没有实体）**错误，因此建议在某个有用的先前点使用`fs.exists`。

+   一个可选的选项对象，包括：

+   持久（默认为 true 的布尔值）：Node 会保持进程活动，只要还有*事情要做*。将此选项设置为*false*，即使你的代码仍然有一个文件监视器在监视，也会让 Node 关闭进程。

+   递归（默认为 false 的布尔值）：是否自动进入子目录。注意：这在不同平台上的实现不一致。因此，出于性能考虑，你应该明确控制你要监视的文件列表，而不是随意监视目录。

+   编码（默认为`utf8`的字符串）：传递文件名的字符编码。你可能不需要更改这个。

+   `listener`函数，接收两个参数：

+   更改事件的名称（`rename`或`change`之一）

+   已更改的文件名（在监视目录时很重要）

这个例子将在自身上设置一个观察者，更改自己的文件名，然后退出：

```js
const fs = require('fs');
fs.watch(__filename, { persistent: false }, (event, filename) => {
  console.log(event);
  console.log(filename);
})

setImmediate(function() {
  fs.rename(__filename, __filename + '.new', () => {});
});
```

两行，`rename`和原始文件的名称，应该已经打印到控制台上。

在任何时候关闭你的观察者通道，你想使用这样的代码：

```js
let w = fs.watch('file', () => {});
w.close();
```

应该注意，`fs.watch`在很大程度上取决于主机操作系统如何处理文件事件，Node 文档中也提到了这一点：

“fs.watch API 在各个平台上并不完全一致，并且在某些情况下不可用。”

作者在许多不同的系统上对该模块有非常好的体验，只是在 OS X 实现中回调函数的文件名参数为空。不同的系统也可能强制执行大小写敏感性，无论哪种方式。然而，一定要在你特定的架构上运行测试 —— 信任，但要验证。

或者，使用第三方包！如果你在使用 Node 模块时遇到困难，请检查 npm 是否有替代方案。在这里，作为`fs.watch`的问题修复包装器，考虑*Paul Miller*的*chokidar*。它被用作构建系统（如 gulp）的文件监视工具，以及许多其他项目。参考：[`www.npmjs.com/package/chokidar`](https://www.npmjs.com/package/chokidar)。

# 延迟执行

有时需要推迟执行一个函数。传统的 JavaScript 使用定时器来实现这一目的，使用众所周知的`setTimeout`和`setInterval`函数。Node 引入了另一种推迟执行的方式，主要是作为控制回调函数在 I/O 事件和定时器事件之间执行顺序的手段。

正如我们之前看到的，管理定时器是 Node 事件循环的主要工作之一。两种延迟事件源，使开发人员能够安排回调函数的执行在排队的 I/O 事件之前或之后，分别是`process.nextTick`和`setImmediate`。现在让我们来看看这些。

# process.nextTick

作为原生 Node 进程模块的一种方法，`process.nextTick`类似于熟悉的`setTimeout`方法，它延迟执行其回调函数直到将来的某个时间点。然而，这种比较并不完全准确；所有请求的`nextTick`回调函数列表都被放在事件队列的头部，并在当前脚本的执行之后（JavaScript 代码在 V8 线程上同步执行）和 I/O 或定时器事件之前，按顺序处理。

在函数中使用`nextTick`的主要目的是将结果事件的广播推迟到当前执行堆栈上的监听器在调用者有机会注册事件监听器之前，给当前执行的程序一个机会将回调绑定到`EventEmitter.emit`事件。

把这看作是一个模式，可以在任何想要创建自己的异步行为的地方使用。例如，想象一个查找系统，可以从缓存中获取，也可以从数据存储中获取新鲜数据。缓存很快，不需要回调，而数据 I/O 调用需要它们。

第二种情况中回调的需求支持对回调行为的模拟，在第一种情况中使用`nextTick`。这允许一致的 API，提高了实现的清晰度，而不会使开发人员负担起确定是否使用回调的责任。

以下代码似乎设置了一个简单的事务；当`EventEmitter`的一个实例发出开始事件时，将`Started`记录到控制台：

```js
const events = require('events');
function getEmitter() {
  let emitter = new events.EventEmitter();
  emitter.emit('start');
  return emitter;
}

let myEmitter = getEmitter();

myEmitter.on("start", () => {
  console.log("Started");
});
```

然而，你可能期望的结果不会发生！在`getEmitter`中实例化的事件发射器在返回之前发出`start`，导致后续分配的监听器出现错误，它到达时已经晚了一步，错过了事件通知。

为了解决这种竞争条件，我们可以使用`process.nextTick`：

```js
const events = require('events');
function getEmitter() {
  let emitter = new events.EventEmitter();
  process.nextTick(() => {
    emitter.emit('start');
  });
  return emitter;
}

let myEmitter = getEmitter();
myEmitter.on('start', () => {
  console.log('Started');
});
```

这段代码在 Node 给我们`start`事件之前附加了`on("start")`处理程序，并且可以正常工作。

错误的代码可能会递归调用`nextTick`，导致代码无休止地运行。请注意，与在事件循环的单个轮次内对函数进行递归调用不同，这样做不会导致堆栈溢出。相反，它会使事件循环饥饿，使微处理器上的进程繁忙，并可能阻止程序发现 Node 已经完成的 I/O。

# setImmediate

`setImmediate`在技术上是定时器类的成员，与`setInterval`和`setTimeout`一起。但是，它与时间无关——没有*毫秒数*等待发送参数。

这个方法实际上更像是`process.nextTick`的一个同级，有一个非常重要的区别：通过`nextTick`排队的回调将在 I/O 和定时器事件之前执行，而通过`setImmediate`排队的回调将在 I/O 事件之后调用。

这两种方法的命名令人困惑：Node 实际上会在你传递给`setImmediate`的函数之前运行你传递给`nextTick`的函数。

这个方法确实反映了定时器的标准行为，它的调用将返回一个对象，可以传递给`clearImmediate`，取消你对以后运行函数的请求，就像`clearTimeout`取消使用`setTimeout`设置的定时器一样。

# 定时器

定时器用于安排将来的事件。当需要延迟执行某些代码块直到指定的毫秒数过去时，用于安排特定函数的周期性执行等等时，就会使用它们。

JavaScript 提供了两个异步定时器：`setInterval()`和`setTimeout()`。假设读者完全了解如何设置（和取消）这些定时器，因此将不会花费太多时间讨论语法。我们将更多地关注定时和间隔的陷阱和不太为人知的细节。

关键要点是：在使用定时器时，不应该对定时器触发注册的回调函数之前实际过去的时间量或回调的顺序做任何假设。Node 定时器不是中断。定时器只是承诺尽可能接近指定的时间执行（但绝不会提前），与其他事件源一样，受事件循环调度的约束。

关于定时器你可能不知道的一件事是-我们都熟悉`setTimeout`的标准参数：回调函数和超时间隔。你知道传递给`callback`函数的还有许多其他参数吗？`setTimeout(callback, time, [passArg1, passArg2…])`

# setTimeout

超时可以用来推迟函数的执行，直到未来的某个毫秒数。

考虑以下代码：

```js
setTimeout(a, 1000);
setTimeout(b, 1001);
```

人们会期望函数`b`会在函数`a`之后执行。然而，这并不能保证-`a`可能在`b`之后执行，或者反过来。

现在，考虑以下代码片段中存在的微妙差异：

```js
setTimeout(a, 1000);
setTimeout(b, 1000);
```

在这种情况下，`a`和`b`的执行顺序是可以预测的。Node 基本上维护一个对象映射，将具有相同超时长度的回调分组。*Isaac Schlueter*，Node 项目的前任领导，现任 npm Inc.的首席执行官，这样说：

正如我们在[`groups.google.com/forum/#!msg/nodejs-dev/kiowz4iht4Q/T0RuSwAeJV0J`](https://groups.google.com/forum/#!msg/nodejs-dev/kiowz4iht4Q/T0RuSwAeJV0J)上发现的，“[N]ode 为每个超时值使用单个低级定时器对象。如果为单个超时值附加多个回调，它们将按顺序发生，因为它们位于队列中。但是，如果它们位于不同的超时值上，那么它们将使用不同的线程中的定时器，因此受[CPU]调度程序的影响。”

在相同的执行范围内注册的定时器回调的顺序并不能在所有情况下可预测地决定最终的执行顺序。此外，超时的最小等待时间为一毫秒。传递零、-1 或非数字的值将被转换为这个最小值。

要取消超时，请使用`clearTimeout(timerReference)`。

# setInterval

有许多情况可以想象到定期执行函数会很有用。每隔几秒轮询数据源并推送更新是一种常见模式。每隔几毫秒运行动画的下一步是另一种用例，还有收集垃圾。对于这些情况，`setInterval`是一个很好的工具：

```js
let intervalId = setInterval(() => { ... }, 100);
```

每隔 100 毫秒，发送的回调函数将执行，这个过程可以使用`clearInterval(intervalReference)`来取消。

不幸的是，与`setTimeout`一样，这种行为并不总是可靠的。重要的是，如果系统延迟（比如一些糟糕的写法的阻塞`while`循环）占据事件循环一段时间，那么在这段时间内设置的间隔将在堆栈上排队等待结果。当事件循环变得不受阻塞并解开时，所有间隔回调将按顺序被触发，基本上是立即触发，失去了它们原本意图的任何时间延迟。

幸运的是，与基于浏览器的 JavaScript 不同，Node 中的间隔通常更加可靠，通常能够在正常使用场景中保持预期的周期性。

# unref 和 ref

一个 Node 程序没有理由保持活动状态。只要还有等待处理的回调，进程就会继续运行。一旦这些被清除，Node 进程就没有其他事情可做了，它就会退出。

例如，以下愚蠢的代码片段将使 Node 进程永远运行：

```js
let intervalId = setInterval(() => {}, 1000);
```

即使设置的回调函数没有任何有用或有趣的内容，它仍然会被调用。这是正确的行为，因为间隔应该一直运行，直到使用`clearInterval`停止它。

有一些情况下，使用定时器来对外部 I/O、某些数据结构或网络接口进行一些有趣的操作，一旦这些外部事件源停止发生或消失，定时器本身就变得不必要。通常情况下，人们会在程序的其他地方捕获定时器的无关状态，并从那里取消定时器。这可能会变得困难甚至笨拙，因为现在需要不必要地纠缠关注点，增加了复杂性。

`unref`方法允许开发人员断言以下指令：当这个定时器是事件循环处理的唯一事件源时，继续终止进程。

让我们将这个功能测试到我们之前的愚蠢示例中，这将导致进程终止而不是永远运行：

```js
let intervalId = setInterval(() => {}, 1000);
intervalId.unref();
```

请注意，`unref`是启动定时器时返回的不透明值的一个方法，它是一个对象。

现在，让我们添加一个外部事件源，一个定时器。一旦这个外部源被清理（大约 100 毫秒），进程将终止。我们向控制台发送信息来记录发生了什么：

```js
setTimeout(() => {
  console.log("now stop");
}, 100);

let intervalId = setInterval(() => {
  console.log("running")
}, 1);

intervalId.unref();
```

你可以使用`ref`将定时器恢复到正常行为，这将撤消`unref`方法：

```js
let intervalId = setInterval(() => {}, 1000);
intervalId.unref();
intervalId.ref();
```

列出的进程将继续无限期地进行，就像我们最初的愚蠢示例一样。

快速测验！运行以下代码后，日志消息的预期顺序是什么？

```js
const fs = require('fs');
const EventEmitter = require('events').EventEmitter;
let pos = 0;
let messenger = new EventEmitter();

// Listener for EventEmitter
messenger.on("message", (msg) => {
  console.log(++pos + " MESSAGE: " + msg);
});

// (A) FIRST
console.log(++pos + " FIRST");

//  (B) NEXT
process.nextTick(() => {
  console.log(++pos + " NEXT")
})

// (C) QUICK TIMER
setTimeout(() => {
  console.log(++pos + " QUICK TIMER")
}, 0)

// (D) LONG TIMER
setTimeout(() => {
  console.log(++pos + " LONG TIMER")
}, 10)

// (E) IMMEDIATE
setImmediate(() => {
  console.log(++pos + " IMMEDIATE")
})

// (F) MESSAGE HELLO!
messenger.emit("message", "Hello!");

// (G) FIRST STAT
fs.stat(__filename, () => {
  console.log(++pos + " FIRST STAT");
});

// (H) LAST STAT
fs.stat(__filename, () => {
  console.log(++pos + " LAST STAT");
});

// (I) LAST
console.log(++pos + " LAST");
```

这个程序的输出是：

```js
FIRST (A).
MESSAGE: Hello! (F).
LAST (I).
NEXT (B).
QUICK TIMER (C).
FIRST STAT (G).
LAST STAT (H).
IMMEDIATE (E).
LONG TIMER (D).
```

让我们分解上述代码：

A、F 和 I 在主程序流中执行，因此它们将在主线程中具有第一优先级。这是显而易见的；你的 JavaScript 按照它们被编写的顺序执行指令，包括发出回调的同步执行。

主调用堆栈耗尽后，事件循环现在几乎可以开始处理 I/O 操作。这是`nextTick`请求被执行的时刻，它们排在事件队列的最前面。这时 B 被显示出来。

其余的顺序应该是清楚的。定时器和 I/O 操作将被处理（C、G、H），然后是`setImmediate`回调的结果（E），始终在执行任何 I/O 和定时器响应之后到达。

最后，长时间超时（D）到达，这是一个相对遥远的未来事件。

请注意，重新排列此程序中的表达式不会改变输出顺序，除了可能重新排列 STAT 结果之外，这只意味着它们以不同的顺序从线程池返回，但仍然作为与事件队列相关的正确顺序的一组。

# 并发和错误

Node 社区的成员每天都在开发新的包和项目。由于 Node 的事件性质，回调渗透到这些代码库中。我们已经考虑了事件可能如何通过回调排队、分发和处理的关键方式。让我们花点时间概述最佳实践，特别是关于设计回调和处理错误的约定，并讨论在设计复杂的事件和回调链时一些有用的模式。特别是，让我们看看在本书中会看到的新 Promise、Generator 和 async/await 模式，以及现代 Node 代码的其他示例。

# 并发管理

自从项目开始以来，简化控制流一直是 Node 社区关注的问题。事实上，这种潜在的批评是*Ryan Dahl*在向 JavaScript 开发者社区介绍 Node 时讨论的第一个预期批评之一。

由于延迟代码执行通常需要在回调中嵌套回调，因此 Node 程序有时会开始类似于侧向金字塔，也被称为“末日金字塔”。你见过吧：深度嵌套的代码，4 层或 5 层甚至更深，到处都是花括号。除了语法上的烦恼，你也可以想象在这样的调用堆栈中跟踪错误可能会很困难——如果第三层的回调抛出异常，谁负责处理这个错误？第二层吗？即使第二层正在读取文件，第三层正在查询数据库？这有意义吗？很难理解异步程序流的含义。

# 回调

幸运的是，Node 的创建者们早早就就如何构造回调达成了理智的共识。遵循这一传统是很重要的。偏离会带来意外，有时是非常糟糕的意外，总的来说，这样做会自动使 API 变得笨拙，而其他开发人员会迅速厌倦。

一个要么通过执行`callback`返回函数结果，要么处理`callback`接收到的参数，要么在 API 中设计`callback`的签名。无论考虑的是哪种情况，都应该遵循与该情况相关的惯例。

传递给`callback`函数的第一个参数是任何错误消息，最好是以错误对象的形式。如果不需要报告错误，这个位置应该包含一个空值。

当将`callback`传递给函数时，它应该被分配到函数签名的最后一个位置。API 应该一贯地按照这种方式设计。

在错误和`callback`之间可能存在任意数量的参数。

创建错误对象：`new Error("Argument must be a String!")`

# Promises

就像一些政客一样，Node 核心在支持 Promises 之前反对它们。*Mikeal Rogers*在讨论为什么 Promises 从最初的 Node 核心中被移除时，提出了一个强有力的论点，即将功能开发留给社区会导致更强大的核心产品。你可以在这里查看这个讨论：[`web.archive.org/posts/broken-promises.html`](https://web.archive.org/posts/broken-promises.html)

从那时起，Promises 已经获得了非常庞大的追随者，Node 核心也做出了改变。Promises 本质上是标准回调模式的替代品，而标准回调模式在 Node 中随处可见。曾经，你可能会这样写：

```js
API.getUser(loginInfo, function(err, user) {
    API.getProfile(user, function(err, profile) {
        // ...and so on
    }
});
```

如果 API 改为"Promisified"（回想一下前一章中的`util.promisify`？），你对前面的异步控制流的描述将使用 Promise 链来描述：

```js
let promiseProfile = API.getUser(loginInfo)
.then(user => API.getProfile(user))
.then(profile => {
    // do something with #profile
})
.catch(err => console.log(err))
```

这至少是一个更紧凑的语法，读起来更容易一些，操作的链条更长；然而，这里有更多有价值的东西。

`promiseProfile`引用了一个 Promise 对象。Promises 只执行一次，达到错误状态（未完成）或完成状态，你可以通过`then`提取最后的不可变值，就像我们之前对 profile 所做的那样。当然，Promises 可以被分配给一个变量，并且该变量可以传递给尽可能多的消费者，甚至在解决之前。由于`then`只有在有值可用时才会被调用，无论何时，Promises 都被称为未来状态的承诺。

也许最重要的是，与回调不同，Promises 能够管理许多异步操作中的错误。如果你回头看一下本节开头的示例回调代码，你会看到每个回调中都有`err`参数，反映了 Node 的核心错误优先回调风格。每个错误对象都必须单独处理，因此前面的代码实际上会开始看起来更像这样：

```js
API.getUser(loginInfo, function(err, user) {
  if(err) {
    throw err;
  }
  API.getProfile(user, function(err, profile) {
    if(err) {
      throw err;
    }
    // ...and so on
  }
});
```

观察每个错误条件必须单独处理。在实践中，开发人员希望对这段代码进行"手动"包装，比如使用`try...catch`块，以某种方式捕获这个逻辑单元中的所有错误并以集中的方式进行管理。

使用 Promises，你可以免费获得这些。任何`catch`语句都会捕获链中之前的任何`then`抛出的错误。这使得创建一个通用的错误处理程序变得轻而易举。更重要的是，Promises 允许执行链在错误发生后继续。你可以将以下内容添加到前面的 Promise 链中：

```js
.catch(err => console.log(err))
.then(() => // this happens no matter what happened previously)
```

通过 Promises，你可以在更少的空间中组合相当复杂的异步逻辑流，缩进有限，错误处理更容易处理，值是不可变的且可交换的。

Promise 对象的另一个非常有用的特性是，这些未来解析的状态可以作为一个块来管理。例如，想象一下，为了满足对用户配置文件的查询，你需要进行三次数据库调用。与其总是串行地链式调用这些调用，你可以使用`Promise.all`：

```js
const db = {
  getFullName: Promise.resolve('Jack Spratt'),
  getAddress: Promise.resolve('10 Clean Street'),
  getFavorites: Promise.resolve('Lean'),
};

Promise.all([
  db.getFullName() 
  db.getAddress() 
  db.getFavorites() 
])
.then(results => {
  // results = ['Jack Spratt', '10 Clean Stree', 'Lean']
})
.catch(err => {...})
```

在这里，所有三个 Promise 将被同时触发，并且将并行运行。并行运行调用当然比串行运行更有效率。此外，`Promise.all`保证最终的 thenable 接收到一个按照调用者位置同步结果位置排序的结果数组。

你最好熟悉一下完整的 Promise API，你可以在 MDN 上阅读：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)

尽管 Promises 现在是原生的，但仍然存在一个“用户空间”模块，bluebird，它继续提供一个引人注目的替代 Promises 实现，具有附加功能，通常执行速度更快。你可以在这里阅读更多关于 bluebird 的信息：[`bluebirdjs.com/docs/api-reference.html`](http://bluebirdjs.com/docs/api-reference.html)。

# async/await

与其用一个专门的数据结构来包装满足条件，比如一个带有许多函数块和括号和特殊上下文的 Promise，为什么不简单地让异步表达式既能实现异步执行，又能实现程序的进一步执行（同步）直到解决？

`await`操作符用于等待一个 Promise。它只在`async`函数内部执行。`async/await`并发建模语法自 Node 8.x 以来就可用。这里演示了`async/await`被用来复制之前的`Promise.all`的例子：

```js
const db = {
  getFullName: Promise.resolve('Jack Spratt'),
  getAddress: Promise.resolve('10 Clean Street'),
  getFavorites: Promise.resolve('Lean'),
}

async function profile() {
  let fullName = await db.getFullName() // Jack Spratt
  let address = await db.getAddress() // 10 Clean Street
  let favorites = await db.getFavorites() // Lean

  return {fullName, address, favorites};
}

profile().then(res => console.log(res) // results = ['Jack Spratt', '10 Clean Street', 'Lean'
```

不错，对吧？你会注意到`profile()`返回了一个 Promise。一个`async`函数*总是*返回一个 Promise，尽管我们在这里看到，函数本身可以返回任何它想要的东西。

Promises 和`async`/`await`像老朋友一样合作。这里有一个递归目录遍历器，演示了这种合作：

```js
const {join} = require('path');
const {promisify} = require('util');
const fs = require('fs');
const readdir = promisify(fs.readdir);
const stat = promisify(fs.stat);

async function $readDir (dir, acc = []) {
  await Promise.all((await readdir(dir)).map(async file => {
    file = join(dir, file);
    return (await stat(file)).isDirectory() && acc.push(file) && $readDir(file, acc);
  }));
  return acc;
}

$readDir(`./dummy_filesystem`).then(dirInfo => console.log(dirInfo));

// [ 'dummy_filesystem/folderA',
// 'dummy_filesystem/folderB',
// 'dummy_filesystem/folderA/folderA-C' ]
```

这个递归目录遍历器的代码非常简洁，只比上面的设置代码稍长一点。由于`await`期望一个 Promise，而`Promise.all`将返回一个 Promise，所以通过`readDir` Promise 返回的每个文件运行，然后将每个文件映射到另一个等待的 Promise，该 Promise 将处理任何递归进入子目录，根据需要更新累加器。这样阅读，`Promise.all((await readdir(dir)).map`的结构读起来不像一个基本的循环结构，其中深层异步递归以一种简单易懂的过程化、同步的方式进行建模。

一个纯 Promise 的替代版本可能看起来像这样，假设与`async`/`await`版本相同的依赖关系：

```js
function $readDir(dir, acc=[]) {
  return readdir(dir).then(files => Promise.all(files.map(file => {
    file = join(dir, file);
    return stat(file).then(fobj => {
      if (fobj.isDirectory()) {
        acc.push(file);
        return $readDir(file, acc);
      }
    });
  }))).then(() => acc);
};
```

这两个版本都比回调函数更清晰。`async/await`版本确实兼顾了两者的优点，并创建了一个简洁的表示，类似于同步代码，可能更容易理解和推理。

使用`async/await`进行错误处理也很容易，因为它不需要任何特殊的新语法。对于 Promises 和`catch`，同步代码错误存在一个小问题。Promises 捕获发生在`then`块中的错误。例如，如果你的代码调用的第三方库抛出异常，那么该代码不会被 Promise 包装，而且该错误*不会被`catch`*捕获。

使用`async/await`，你可以使用熟悉的`try...catch`语句：

```js
async function makeError() {
    try {
        console.log(await thisDoesntExist());
    } catch (error) {
        console.error(error);
    }
}

makeError();
```

这避免了所有特殊错误捕获结构的问题。这种原生的、非常可靠的方法将捕获`try`块中任何地方抛出的任何东西，无论执行是同步还是异步。

# 生成器和迭代器

生成器是可以暂停和恢复的函数执行上下文。当你调用一个普通函数时，它可能会`return`一个值；函数完全执行，然后终止。生成器函数将产生一个值然后停止，但是生成器的函数上下文不会被销毁（就像普通函数一样）。你可以在以后的时间点重新进入生成器并获取更多的结果。

一个例子可能会有所帮助：

```js
function* threeThings() {
    yield 'one';
    yield 'two';
    yield 'three';
}

let tt = threeThings();

console.log(tt); // {} 
console.log(tt.next()); // { value: 'one', done: false }
console.log(tt.next()); // { value: 'two', done: false }
console.log(tt.next()); // { value: 'three', done: false }
console.log(tt.next()); // { value: undefined, done: true }
```

通过在生成器上标记一个星号（`*`）来声明生成器。在第一次调用`threeThings`时，我们不会得到一个结果，而是得到一个生成器对象。

生成器符合新的 JavaScript 迭代协议（[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Iteration_protocols#iterator`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Iteration_protocols#iterator)），对于我们的目的来说，这意味着生成器对象公开了一个`next`方法，该方法用于从生成器中提取尽可能多的值。这种能力来自于生成器实现了 JavaScript 迭代协议。那么，什么是迭代器？

正如[`developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Iterators_and_Generators`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Iterators_and_Generators)所说，

“当对象知道如何一次从集合中访问一个项，并跟踪其在该序列中的当前位置时，它就是一个迭代器。在 JavaScript 中，迭代器是提供了一个 next()方法的对象，该方法返回序列中的下一个项。此方法返回一个具有两个属性的对象：done 和 value。”

我们可以仅使用迭代器来复制生成器示例：

```js
function demoIterator(array) {
  let idx = 0;
  return {
    next: () => {
      return idx < array.length ? {
        value: array[idx++],
        done: false
      } : { done: true };
    }
  };
}
let it = demoIterator(['one', 'two', 'three']);
console.log(it); // { next: [Function: next] }
console.log(it.next()); // { value: 'one', done: false }
console.log(it.next()); // { value: 'two', done: false }
console.log(it.next()); // { value: 'three', done: false }
console.log(it.next()); // { done: true }
```

你会注意到，结果与生成器示例几乎相同，但在第一个结果中有一个重要的区别：迭代器只是一个具有 next 方法的对象。它必须完成维护自己的内部状态的所有工作（在先前的示例中跟踪`idx`）。生成器是迭代器的工厂；此外，它们完成了维护和产生自己的状态的所有工作。

从迭代器继承，生成器产生具有两个属性的对象：

+   **done**：一个布尔值。如果为 true，则生成器表示它没有剩余的内容可以`yield`。如果你把生成器想象成流（这不是一个坏的类比），那么你可能会将这种模式与流结束时`Readable.read()`返回 null 的模式进行比较（或者如果你愿意，也可以将其与`Readable`在完成时推送 null 的方式进行比较）。

+   **value**：最后一个`yield`的值。如果`done`为 true，则应该忽略。

生成器被设计用于迭代上下文，与循环类似，提供了函数执行上下文的强大优势。你可能已经写过类似这样的代码：

```js
function getArraySomehow() {
  // slice into a copy; don't send original
  return ['one','two','buckle','my','shoe'].slice(0); 
}

let state = getArraySomehow();
for(let x=0; x < state.length; x++) {
    console.log(state[x].toUpperCase());
}
```

这是可以的，但也有缺点，比如需要创建对外部数据提供程序的本地引用，并在此块或函数终止时维护该引用。我们应该将`state`设置为全局变量吗？它应该是不可变的吗？例如，如果底层数据发生变化，例如向数组添加了一个新元素，我们如何确保`state`被更新，因为它与我们应用程序的真实状态是断开的？如果有什么意外地覆盖了`state`会怎么样？数据观察和绑定库存在，设计理论存在，框架存在，可以正确地封装数据源并将不可变版本注入执行上下文；但如果有更好的方法呢？

生成器可以包含和管理自己的数据，并且即使发生变化也可以`yield`正确的答案。我们可以使用生成器实现先前的代码：

```js
function* liveData(state) {
    let state = ['one','two','buckle','my','shoe'];
    let current;

    while(current = state.shift()) {
        yield current;
    }
}

let list = liveData([]);
let item;
while (item = list.next()) {
    if(!item.value) {
        break;
    }
    console.log('generated:', item.value);
}
```

生成器方法处理所有发送回值的“样板”，并自然地封装了状态。但在这里似乎没有显著的优势。这是因为我们正在使用生成器执行顺序和立即运行的迭代。生成器实际上是用于承诺一系列值的情况，只有在请求时才生成单个值，随着时间的推移。我们真正想要创建的不是一次性按顺序处理数组，而是创建一个连续的通信过程链，每个过程“tick”都计算一个结果，并能看到先前过程的结果。

考虑以下情况：

```js
function* range(start=1, end=2) {
    do {
        yield start;
    } while(++start <= end)
}

for (let num of range(1, 3)) {
    console.log(num);
}
// 1
// 2
// 3
```

您可以向生成器传递参数。我们通过传递范围边界来创建一个`range`状态机，进一步调用该机器将导致内部状态改变，并将当前状态表示返回给调用者。虽然为了演示目的，我们使用了遍历迭代器（因此生成器）的`for...of`方法，但这种顺序处理（会阻塞主线程直到完成）可以被*异步化*。

生成器的运行/暂停（而不是运行/停止）设计意味着我们可以将迭代看作不是遍历列表，而是捕获一组随时间变化的过渡事件。这个想法对于**响应式编程**（[`en.wikipedia.org/wiki/Reactive_programming`](https://en.wikipedia.org/wiki/Reactive_programming)）是核心的。让我们通过另一个例子来思考一下生成器的这种特殊优势。

对于这些类型的数据结构，还有许多其他操作。这样想可能会有所帮助：生成器对未来值的序列就像 Promises 对单个未来值一样。Promises 和生成器都可以在生成时传递（即使有些最终值仍在解析中，或者尚未排队等待解析），一个通过`next()`接口获取值，另一个通过`then()`接口获取值。

# 错误和异常

一般来说，在编程中，术语*错误*和*异常*经常可以互换使用。在 Node 环境中，这两个概念并不相同。错误和异常是不同的。此外，在 Node 中，错误和异常的定义并不一定与其他语言和开发环境中类似的定义相一致。

在 Node 程序中，**错误**条件通常是应该被捕获和处理的非致命条件，最明显地体现在典型的 Node 回调模式所显示的*错误作为第一个参数*约定中。**异常**是一个严重的错误（系统错误），一个明智的环境不应该忽视或尝试处理。

在 Node 中会遇到四种常见的错误上下文，并且应该有可预测的响应：

+   **同步上下文**：这通常发生在函数的上下文中，检测到错误的调用签名或其他非致命错误。函数应该简单地返回一个错误对象；`new Error(…)`，或者其他一致的指示函数调用失败的指示器。

+   **异步上下文**：当期望通过触发`callback`函数来响应时，执行上下文应该传递一个`Error`对象，并将适当的消息作为该`callback`的第一个参数。

+   **事件上下文**：引用 Node 文档：“当`EventEmitter`实例遇到错误时，典型的操作是触发一个错误事件。错误事件在 node 中被视为特殊情况。如果没有监听器，那么默认操作是打印堆栈跟踪并退出程序。”在预期的情况下使用事件。

+   **Promise 上下文**：Promise 抛出或以其他方式被拒绝，并且此错误在`.catch`块中被捕获。重要提示：您应该始终使用真正的`Error`对象拒绝 Promises。 *Petka Antonov*，流行的 B*luebird* Promises 实现的作者，讨论了为什么：[`github.com/petkaantonov/bluebird/blob/master/docs/docs/warning-explanations.md`](https://github.com/petkaantonov/bluebird/blob/master/docs/docs/warning-explanations.md)

显然，这些情况是在控制的方式下捕获错误，而不是在整个应用程序不稳定之前。在不过分陷入防御性编码的情况下，应该努力检查输入和其他来源的错误，并妥善处理它们。

始终返回正确的`Error`对象的另一个好处是可以访问该对象的堆栈属性。错误堆栈显示错误的来源，函数链中的每个链接以及导致错误的函数。典型的`Error.stack`跟踪看起来像这样：

```js
> console.log(new Error("My Error Message").stack);
 Error: My Error Message
     at Object.<anonymous> (/js/errorstack.js:1:75)
     at Module._compile (module.js:449:26)
     at Object.Module._extensions..js (module.js:467:10)
     ...

```

同样，堆栈始终可以通过`console.trace`方法获得：

```js
> console.trace("The Stack Head")
 Trace: The Stack Head
     at Object.<anonymous> (/js/stackhead.js:1:71)
     at Module._compile (module.js:449:26)
     at Object.Module._extensions..js (module.js:467:10)
     ...
```

应该清楚这些信息如何帮助调试，有助于确保我们应用程序的逻辑流是正确的。

正常的堆栈跟踪在十几个级别后会截断。如果更长的堆栈跟踪对您有用，请尝试*Matt Insler*的**longjohn**：[`github.com/mattinsler/longjohn`](https://github.com/mattinsler/longjohn)

此外，运行并检查您的捆绑包中的`js/stacktrace.js`文件，以获取有关在报告错误或测试结果时如何使用堆栈信息的一些想法。

异常处理是不同的。异常是意外或致命错误，已经使应用程序不稳定。这些应该小心处理；处于异常状态的系统是不稳定的，未来状态不确定，并且应该优雅地关闭和重新启动。这是明智的做法。

通常，异常在`try`/`catch`块中捕获：

```js
try {
  something.that = wontWork;
} catch (thrownError) {
  // do something with the exception we just caught
} 
```

在代码库中使用`try`/`catch`块并尝试预期所有错误可能变得难以管理和笨拙。此外，如果发生您没有预料到的异常，未捕获的异常会怎么样？您如何从上次中断的地方继续？

Node 没有标准内置的方法来处理未捕获的关键异常。这是平台的一个弱点。未捕获的异常将继续通过执行堆栈冒泡，直到它到达事件循环，在那里，就像在机器齿轮中的扳手一样，它将使整个进程崩溃。我们最好的办法是将`uncaughtException`处理程序附加到进程本身：

```js
process.on('uncaughtException', (err) => {
  console.log('Caught exception: ' + err);
 });

setTimeout(() => {
  console.log("The exception was caught and this can run.");
}, 1000);

throwAnUncaughtException();

// > Caught exception: ReferenceError: throwAnUncaughtException is not defined
// > The exception was caught and this can run.
```

虽然我们异常代码后面的内容都不会执行，但超时仍然会触发，因为进程设法捕获了异常，自救了。然而，这是处理异常的一种非常笨拙的方式。`domain`模块旨在修复 Node 设计中的这个漏洞，但它已经被弃用。正确处理和报告错误仍然是 Node 平台的一个真正弱点。核心团队正在努力解决这个问题：[`nodejs.org/en/docs/guides/domain-postmortem/`](https://nodejs.org/en/docs/guides/domain-postmortem/)

最近，引入了类似的机制来捕获无法控制的 Promise，当您未将 catch 处理程序附加到 Promise 链时会发生这种情况：

```js
process.on('unhandledRejection', (reason, Prom) => {
  console.log(`Unhandled Rejection: ${p} reason: ${reason}`);
});
```

`unhandledRejection`处理程序在 Promise 被拒绝并且在事件循环的一个回合内未附加错误处理程序时触发。

# 考虑事项

任何开发人员都在经常做出具有深远影响的决定。很难预测从新代码或新设计理论中产生的所有可能后果。因此，保持代码的简单形式并迫使自己始终遵循其他 Node 开发人员的常见做法可能是有用的。以下是一些您可能会发现有用的准则：

+   通常，尽量追求浅层代码。这种重构在非事件驱动的环境中并不常见。通过定期重新评估入口和出口点以及共享函数来提醒自己。

+   考虑使用不同的、可组合的微服务来构建你的系统，我们将在第九章中讨论，*微服务*。

+   在可能的情况下，为`callback`重新进入提供一个公共上下文。闭包在 JavaScript 中是非常强大的工具，通过扩展，在 Node 中也是如此，只要封闭的回调的上下文帧长度不过大。

+   给你的函数命名。除了在深度递归结构中非常有用之外，当堆栈跟踪包含不同的函数名称时，调试代码会更容易，而不是匿名函数。

+   认真考虑优先级。给定结果到达或`callback`执行的顺序实际上是否重要？更重要的是，它是否与 I/O 操作有关？如果是，考虑使用`nextTick`和`setImmediate`。

+   考虑使用有限状态机来管理你的事件。状态机在 JavaScript 代码库中非常少见。当`callback`重新进入程序流时，它很可能改变了应用程序的状态，而异步调用本身的发出很可能表明状态即将改变。

# 使用文件事件构建 Twitter 动态

让我们应用所学知识。目标是创建一个服务器，客户端可以连接并从 Twitter 接收更新。我们首先创建一个进程来查询 Twitter 是否有带有`#nodejs`标签的消息，并将找到的消息以 140 字节的块写入到`tweets.txt`文件中。然后，我们将创建一个网络服务器，将这些消息广播给单个客户端。这些广播将由`tweets.txt`文件上的写事件触发。每当发生写操作时，都会从上次已知的客户端读取指针异步读取 140 字节的块。这将一直持续到文件末尾，同时进行广播。最后，我们将创建一个简单的`client.html`页面，用于请求、接收和显示这些消息。

虽然这个例子显然是刻意安排的，但它展示了：

+   监听文件系统的更改，并响应这些事件

+   使用数据流事件来读写文件

+   响应网络事件

+   使用超时进行轮询状态

+   使用 Node 服务器本身作为网络事件广播器

为了处理服务器广播，我们将使用**服务器发送事件**（**SSE**）协议，这是 HTML5 的一部分，正在标准化的新协议。

首先，我们将创建一个 Node 服务器，监听文件的更改，并将任何新内容广播给客户端。打开编辑器，创建一个名为`server.js`的文件：

```js
let fs = require("fs");
let http = require('http');

let theUser = null;
let userPos = 0;
let tweetFile = "tweets.txt";
```

我们将接受一个单个用户连接，其指针将是`theUser`。`userPos`将存储此客户端在`tweetFile`中上次读取的位置：

```js
http.createServer((request, response) => {
  response.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Access-Control-Allow-Origin': '*'
  });

  theUser = response;

  response.write(':' + Array(2049).join(' ') + '\n');
  response.write('retry: 2000\n');

  response.socket.on('close', () => {
    theUser = null;
  });
}).listen(8080);
```

创建一个监听端口`8080`的 HTTP 服务器，它将监听并处理单个连接，存储`response`参数，表示连接服务器和客户端的管道。`response`参数实现了可写流接口，允许我们向客户端写入消息：

```js
let sendNext = function(fd) {
  let buffer = Buffer.alloc(140);
  fs.read(fd, buffer, 0, 140, userPos * 140, (err, num) => {
    if (!err && num > 0 && theUser) {
      ++userPos;
      theUser.write(`data: ${buffer.toString('utf-8', 0, num)}\n\n`);
      return process.nextTick(() => {
        sendNext(fd);
      });
    }
  });
};
```

我们创建一个函数来向客户端发送消息。我们将从绑定到我们的`tweets.txt`文件的可读流中拉取 140 字节的缓冲区，每次读取时将我们的文件位置计数器加一。我们将这个缓冲区写入到将我们的服务器与客户端绑定的可写流中。完成后，我们使用`nextTick`排队重复调用相同的函数，重复直到出现错误、不再接收数据或客户端断开连接：

```js
function start() {
  fs.open(tweetFile, 'r', (err, fd) => {
    if (err) {
      return setTimeout(start, 1000);
    }
    fs.watch(tweetFile, (event, filename) => {
      if (event === "change") {
        sendNext(fd);
      }
    });
  });
};

start();
```

最后，我们通过打开`tweets.txt`文件并监视任何更改来启动这个过程，每当写入新的推文时调用`sendNext`。当我们启动服务器时，可能还没有存在要读取的文件，因此我们使用`setTimeout`进行轮询，直到存在一个文件。

现在我们有一个服务器在寻找文件更改以进行广播，我们需要生成数据。我们首先通过**npm**为 Node 安装**TWiT** Twitter 包。

然后我们创建一个进程，其唯一工作是向文件写入新数据：

```js
const fs = require("fs");
const Twit = require('twit');

let twit = new Twit({
  consumer_key: 'your key',
  consumer_secret: 'your secret',
  access_token: 'your token',
  access_token_secret: 'your secret token'
});
```

要使用这个示例，您需要一个 Twitter 开发者帐户。或者，还有一个选项，可以更改相关代码，简单地将随机的 140 字节字符串写入`tweets.txt: require("crypto").randomBytes(70).toString('hex')：`

```js
let tweetFile = "tweets.txt";
let writeStream = fs.createWriteStream(tweetFile, {
  flags: "a" // indicate that we want to (a)ppend to the file
});
```

这将建立一个流指针，指向我们的服务器将要监视的同一个文件。

我们将写入这个文件：

```js
let cleanBuffer = function(len) {
  let buf = Buffer.alloc(len);
  buf.fill('\0');
  return buf;
};
```

因为 Twitter 消息永远不会超过 140 字节，所以我们可以通过始终写入 140 字节的块来简化读/写操作，即使其中一些空间是空的。一旦我们收到更新，我们将创建一个*消息数量* x 140 字节宽的缓冲区，并将这些 140 字节的块写入该缓冲区：

```js
let check = function() {
  twit.get('search/tweets', {
    q: '#nodejs since:2013-01-01'
  }, (err, reply) => {
    let buffer = cleanBuffer(reply.statuses.length * 140);
    reply.statuses.forEach((obj, idx) => {
      buffer.write(obj.text, idx*140, 140);
    });
    writeStream.write(buffer);
  })
  setTimeout(check, 10000);
};

check();
```

现在我们创建一个函数，每 10 秒被要求检查是否包含`#nodejs`标签的消息。Twitter 返回一个消息对象数组。我们感兴趣的是消息的`#text`属性。计算表示这些新消息所需的字节数（140 x 消息数量），获取一个干净的缓冲区，并用 140 字节的块填充它，直到所有消息都被写入。最后，这些数据被写入我们的`tweets.txt`文件，导致发生变化事件，我们的服务器得到通知。

最后一部分是客户端页面本身。这是一个相当简单的页面，它的操作方式应该对读者来说很熟悉。需要注意的是使用 SSE 监听本地主机上端口`8080`。当从服务器接收到新的推文时，应该清楚地看到一个列表元素被添加到无序列表容器`#list`中：

```js
<!DOCTYPE html>
<html>
<head>
    <title></title>
</head>

<script>

window.onload = () => {
  let list = document.getElementById("list");
  let evtSource = new EventSource("http://localhost:8080/events");

  evtSource.onmessage = (e) => {
    let newElement = document.createElement("li");
    newElement.innerHTML = e.data;
    list.appendChild(newElement);
  }
}

</script>
<body>

<ul id="list"></ul>

</body>
</html>
```

要了解更多关于 SSE 的信息，请参阅第六章，*创建实时应用程序*，

或者您可以访问：[`developer.mozilla.org/en-US/docs/Web/API/Server-sent_events`](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)。

# 总结

使用事件进行编程并不总是容易的。控制和上下文切换，定义范式，通常会使新手对事件系统感到困惑。这种看似鲁莽的失控和由此产生的复杂性驱使许多开发人员远离这些想法。入门编程课程的学生通常会形成这样一种心态，即程序流程可以被指示，一个执行流程不是从 A 到 B 顺序进行的程序会使人难以理解。

通过研究架构问题的演变，Node 现在正试图解决网络应用程序的问题——在扩展和代码组织方面，一般数据和复杂性量级方面，状态意识方面，以及明确定义的数据和过程边界方面。我们学会了如何智能地管理这些事件队列。我们看到了不同的事件源如何可预测地堆叠以供事件循环处理，以及远期事件如何使用闭包和智能回调排序进入和重新进入上下文。我们还了解了新的 Promise、Generator 和 async/await 结构，旨在帮助管理并发。

现在我们对 Node 的设计和特性有了基本的领域理解，特别是使用它进行事件编程的方式。现在让我们转向更大、更高级的应用程序知识。
