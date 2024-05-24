# 精通 C++ 游戏开发（四）

> 原文：[`annas-archive.org/md5/C9DEE6A3AC368562ED493911597C48C0`](https://annas-archive.org/md5/C9DEE6A3AC368562ED493911597C48C0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：多人游戏

自从我最早的游戏冒险以来，我发现分享体验总是让它更加难忘。在那些日子里，多人游戏的概念围绕着与朋友一起在沙发上玩游戏或者与其他游戏爱好者聚在一起举办一场史诗般的**LAN**（本地区域网络）派对。自那时以来，情况发生了巨大变化，现在在线、全球共享的游戏体验已成为新常态。在本章中，我们将介绍如何为您的游戏项目添加多人支持的概念，重点关注网络多人游戏。正如我之前所说，计算机网络的话题是一个非常庞大和多样化的话题，需要比我们现在有的时间和空间更多的时间来全面覆盖。因此，我们将重点介绍高层概述，并在需要时深入讨论。在本章中，我们将涵盖以下主题：

+   多人游戏简介

+   网络设计和协议开发

+   创建客户端/服务器

# 游戏中的多人游戏简介

简而言之，多人游戏是一种视频游戏类型，可以让多人同时玩。而单人游戏通常是围绕一个玩家与人工智能对手竞争和实现预定目标，而多人游戏则是围绕与其他人类玩家的互动而设计的。这些互动可以是竞争、合作伙伴关系，或者简单的社交互动。多人互动的实现方式可以根据地点和类型的因素而有所不同，从同屏多人游戏的格斗游戏到在线多人角色扮演游戏，用户共享一个共同的环境。在接下来的部分，我们将看一些多人互动可以包含在视频游戏中的各种方式。

# 本地多人游戏

游戏中的多人游戏概念最早出现在本地多人游戏的形式中。很早以前，很多游戏都有两人模式。一些游戏会实现一种称为回合制多人游戏的两人模式，玩家可以轮流玩游戏。尽管如此，开发者早早就看到了共享体验的好处。甚至最早的游戏，比如《Spacewar!》（1962）和《PONG》（1972）也是让玩家互相对抗的。街机游戏的兴起推动了本地多人游戏，比如《Gauntlet》（1985）这样的游戏提供了最多四个玩家的合作游戏体验。

大多数本地多人游戏可以分为几类，回合制、共享单屏或分屏多人游戏。

回合制，顾名思义，是一种多人游戏模式，玩家轮流使用单个屏幕玩游戏。一个很好的回合制多人游戏的例子是原版的《超级马里奥兄弟》，适用于**任天堂娱乐系统**（**NES**）。在这个游戏中，如果选择了双人模式，第一个玩家扮演马里奥角色；当玩家死亡时，第二个玩家轮到，扮演另一个兄弟路易吉。

共享单屏多人游戏是一种常见的本地多人游戏模式，每个玩家的角色都在同一个屏幕上。每个玩家同时控制他们的角色/化身。这种模式非常适合对战游戏，比如体育和格斗游戏，以及合作游戏，比如平台游戏和解谜游戏。这种模式今天仍然非常受欢迎，一个很好的例子就是最近发布的《杯头》游戏。

# 单屏多人游戏

分屏多人游戏是另一种流行的本地多人游戏模式，其中每个玩家在整个本地屏幕上都有自己的游戏视图。每个玩家同时控制自己的角色/化身。这种模式非常适合对战游戏，如射击游戏。尽管大多数选择实施分屏模式的游戏都是双人游戏，但有些游戏支持多达四名本地玩家，本地屏幕被垂直和水平分成四分之一。一个很好的实施分屏多人游戏的游戏是第一人称射击游戏《光环》。

# 局域网

随着个人电脑在 20 世纪 90 年代初的大量普及，将计算机连接在一起共享信息的想法很快成为大多数计算机用户的核心需求。连接多台计算机的早期方法之一是通过局域网（LAN）。LAN 允许有限区域内的计算机进行连接，例如大学、办公室、学校，甚至个人住所。除非在 LAN 所在的有限区域内，否则默认情况下无法连接 LAN。虽然商业计算世界已经采用了 LAN 计算的想法，但游戏行业真正开始使用这项技术进行多人游戏是在 1993 年发布《毁灭战士》时。

自从互联网被广泛采用以来，基于局域网的多人游戏的流行度已经下降。尽管如此，局域网仍然是当今电子竞技联赛等比赛中进行多人游戏的方式。基于局域网的多人游戏也催生了一种称为**局域网聚会**的现象。局域网聚会是玩家们聚集在同一物理位置，将所有计算机连接在一起以便彼此游玩的活动。这些活动通常持续多天，玩家们会跋涉长途前来参加。局域网聚会是 20 世纪 90 年代初至 90 年代末游戏界的一个重要组成部分，对于参与其中的任何玩家来说，这是一种与其他玩家联系的难忘方式。

# 在线多人游戏

互联网的普及带来了全球玩家以全新方式连接和游玩的能力。与旧时的局域网聚会不同，玩家现在可以在家中舒适的环境中与世界各地的玩家一起游玩和竞争。在线多人游戏的历史可以追溯到早期的例子，如**MUD**（多用户地下城），用户可以通过互联网玩简单的角色扮演游戏。在线多人游戏几乎涵盖了当今游戏的各种类型，从第一人称射击游戏到实时策略游戏。基于互联网的游戏还催生了一种称为**大型多人在线**（MMO）游戏的新类型游戏。在 MMO 中，大量玩家可以在单个实例或世界中连接和互动。迄今为止最受欢迎的 MMO 游戏之一是《魔兽世界》。

# 网络设计和协议开发

在设计和开发多人游戏时，两个最重要的考虑因素是决定要使用的网络拓扑和连接协议。每个选择对实施和游戏本身都有重大影响。在本章的下一部分中，我们将介绍不同的网络拓扑和使用的协议，并讨论它们的各种影响和考虑因素。

# 网络拓扑

简单来说，网络拓扑是网络上的计算机如何连接在一起的方式。对于在线游戏，网络拓扑将决定如何组织网络上的计算机，以允许用户接收游戏的更新。计算机如何组网将决定整体多人游戏设计的许多方面，每种拓扑类型都有其自身的优势和劣势。在接下来的部分中，我们将介绍游戏开发中使用的两种最流行的拓扑结构，即客户端/服务器和点对点模型。

# 点对点

在点对点网络中，每个玩家都与游戏实例中的每个其他玩家连接。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/d3d659e4-2a88-41f3-89bb-e8c3d6ec723a.png)

点对点网络通常采用非权威设计。这意味着没有单一实体控制游戏状态，因此每个玩家必须处理自己的游戏状态，并将任何本地更改通知给其他连接的玩家。这意味着由于这种拓扑结构，我们需要考虑一些问题。首先是带宽；正如你可能想象的那样，使用这种设计需要在玩家之间传递大量数据。事实上，连接的数量可以表示为一个二次函数，其中每个玩家将有 O(n-1)个连接，这意味着对于这种网络拓扑结构，总共将有 O(2n)个连接。这种网络设计也是对称的，这意味着每个玩家都必须具有相同的可用带宽，用于上传和下载流。我们需要考虑的另一个问题是权威的概念。

正如我在这里提到的，处理点对点网络中的权威的最常见方法是让所有玩家共享对网络上每个其他玩家的更新。由于以这种方式处理权威的结果是玩家同时看到两种情况发生，即玩家自己的输入立即更新游戏状态以及其他玩家移动的模拟。由于其他玩家的更新需要在网络上传播，因此更新不是即时的。当本地玩家收到更新时，比如说将对手移动到（x，y，z）的位置，对手在收到更新时仍然在那个位置的可能性很低，这就是为什么需要对其他玩家的更新进行模拟。模拟更新的最大问题是随着延迟的增加，模拟变得越来越不准确。我们将在本章的下一节讨论处理更新延迟和模拟的技术。

# 客户端/服务器

在客户端-服务器拓扑结构中，一个实例被指定为服务器，所有其他玩家实例都连接到它。每个玩家实例（客户端）只会与服务器通信。服务器反过来负责将玩家的所有更新通知给网络上连接的其他客户端。以下图片展示了这种网络拓扑结构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/15371b3c-817a-4dd0-8f36-3efc7ed10f5d.png)

虽然不是唯一的方法，但客户端-服务器网络通常实现了一种权威设计。这意味着，当玩家执行动作，比如将他们的角色移动到另一个地方时，这些信息以更新的形式发送到服务器。服务器会检查更新是否正确，如果是，服务器会将此更新信息传递给网络上连接的其他玩家。如果客户端和服务器在更新信息上发生分歧，服务器被认为是正确的版本。与点对点拓扑结构一样，在实施时需要考虑一些事情。在带宽方面，理论上，每个玩家的带宽要求不会随着连接的玩家数量而改变。如果我们将其表示为二次方程，给定 n 个玩家，连接的总数将是 O(2n)。然而，与点对点拓扑结构不同，客户端-服务器拓扑结构是不对称的，这意味着服务器只有 O(n)个连接，或者每个客户端一个连接。这意味着随着连接的玩家数量增加，支持连接所需的带宽将线性增加。也就是说，在实践中，随着更多玩家加入，需要模拟更多对象，这可能会导致客户端和服务器的带宽需求略微增加。

权威设计被认为比作弊更安全。这是因为服务器完全控制游戏状态和更新。如果从玩家传递了可疑的更新，服务器可以忽略它，并向其他客户端提供正确的更新信息。

# 理解协议

在深入实现多人游戏之前，了解事情是如何处理的非常重要。其中最重要的一个方面是数据如何在两台计算机之间交换。这就是协议的作用。尽管在网络上有许多不同的数据交换方式，但在本节中，我们将重点关注主机到主机层协议的**传输控制协议/互联网协议（TCP/IP）**模型。

# TCP/IP 模型

TCP/IP 模型是一个协议套件的描述，它是一组旨在共同工作以将数据从一台计算机传输到另一台计算机的协议。它以两个主要协议（TCP 和 IP）命名。TCP/IP 被认为是当今的事实标准协议，并已取代了较旧的协议套件，如 IPX 和 SPX。TCP/IP 协议套件可以分解为以下图像中显示的 4 层模型：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/8101e9f1-4a5d-41d6-b776-6243c8ca3b9d.png)

大多数现代网络课程教授 7 层 OSI 模型。OSI 模型是一种理想化的网络模型，目前还没有实际实现。

这四层分别是应用层、传输层、网络层和数据链路层。应用层代表用户的数据并处理编码和对话控制。一个众所周知的应用层协议是**超文本传输协议（HTTP）**，这是我们日常使用的网站的协议。传输层，也称为主机到主机层，支持各种设备和网络之间的低级通信，独立于所使用的硬件。我们将在下一节深入探讨这一层。网络层确定数据通过网络的最佳路径并处理寻址。这一层中最常见的协议是**互联网协议（IP）**。IP 有两个版本：IPv4 标准和 IPv6 标准。第四层也是最后一层是数据链路或网络访问层。数据链路层指定组成网络的硬件设备和媒体。常见的数据链路协议是以太网和 Wi-Fi。

现在我们对层有了一般的了解，让我们更仔细地看一下游戏开发中最常用的两个网络层协议：TCP 和 UDP。

# UDP – 用户数据报协议

首先，让我们看看**用户数据报协议（UDP）**。UDP 是一个非常轻量级的协议，可用于从一台主机的指定端口传递数据到另一台主机的指定端口。一次发送的数据组称为数据报。数据报由 8 字节的头部和随后要传递的数据组成，称为有效载荷。UDP 头部如下表所示：

| **位#** | 0 | 16 |
| --- | --- | --- |
| 0-31 | 源端口 | 目标端口 |
| 32-63 | 长度 | 校验和 |

UDP 头部

逐位分解：

+   **源端口**：（16 位）这标识传递数据的端口的来源。

+   **目标端口**：（16 位）这是传递数据的目标端口。

+   **长度**：（16 位）这是 UDP 头部和数据有效载荷的总长度。

+   **校验和**：（16 位，可选）这是根据 UDP 头部、有效载荷和 IP 头部的某些字段计算的校验和。默认情况下，此字段设置为全零。

因为 UDP 是一个如此简单的协议，它放弃了一些功能以保持轻量级。一个缺失的功能是两个主机之间的共享状态。这意味着不会有努力来确保数据报的完整传递。不能保证数据到达时会按正确的顺序，甚至是否会到达。这与我们将要看的下一个协议 TCP 协议非常不同。

# TCP - 传输控制协议

与 UDP 不同，TCP 协议创建了两个主机之间的传输恒定连接，这允许可靠的数据流在两个主机之间来回传递。TCP 还试图确保所有发送的数据实际上都被接收并且按正确的顺序。随着这些附加功能的增加，也带来了一些额外的开销。TCP 连接的头部比 UDP 的要大得多。TCP 头部的表格格式如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/477d5bac-3328-4025-b9d0-fb7219a94faa.png)

TCP 头部

对于 TCP 连接，数据传输的一个单位称为一个段。一个段由 TCP 头部和在该单个段中传递的数据组成。

让我们逐位分解如下：

+   源端口：（16 位）这标识了正在传递的数据的起始端口。

+   **目标端口**：（16 位）这是正在传递的数据的目标端口。

+   **序列号**：（32 位）这是一个唯一的标识号。由于 TCP 试图让接收方按照发送顺序接收数据，通过 TCP 传输的每个字节都会收到一个序列号。这些数字允许接收方和发送方通过遵循这些数字的顺序来确保顺序。

+   **确认号**：（32 位）这是发送方正在传递的下一个数据字节的序列号。实质上，这充当了所有序列号低于此号码的数据的确认。

+   **数据偏移**：（4 位）这指定了头部以 32 位字为单位的长度。如果需要，它允许添加自定义头部组件。

+   **控制位**：（9 位）这保存了头部的元数据。

+   **接收窗口**：（16 位）这传达了发送方用于传入数据的剩余缓冲空间的数量。在尝试维护流量控制时，这很重要。

+   **紧急指针**：（16 位）这是该段中数据的第一个字节和紧急数据的第一个字节之间的增量值。这是可选的，只有在头部的元数据中设置了`URG`标志时才相关。

# 介绍套接字

在 OSI 模型中，有几种不同类型的套接字确定了传输层的结构。最常见的两种类型是流套接字和数据报套接字。在本节中，我们将简要介绍它们以及它们的区别。

# 流套接字

流套接字用于不同主机之间可靠的双向通信。您可以将流套接字视为类似于打电话。当一个主机呼叫时，另一个主机的连接被初始化；一旦连接建立，双方可以来回通信。连接像流一样是恒定的。

流套接字的使用示例可以在我们在本章前面讨论过的传输控制协议中看到。使用 TCP 允许数据以序列或数据包的形式发送。如前所述，TCP 维护状态并提供了一种确保数据到达并且顺序与发送时相同的方法。这对于许多类型的应用程序非常重要，包括 Web 服务器、邮件服务器和它们的客户端应用程序之间的通信。

在后面的部分，我们将看看如何使用传输控制协议实现自己的流套接字。

# 数据报套接字

与流套接字相反，数据报套接字更像是寄信而不是打电话。数据报套接字连接是单向的，是不可靠的连接。不可靠是指您无法确定数据报套接字数据何时甚至是否会到达接收方。无法保证数据到达的顺序。

如前一节所述，用户数据报协议使用数据报套接字。虽然 UDP 和数据报套接字更轻量级，但在只需要发送数据时，它们提供了一个很好的选择。在许多情况下，创建流套接字、建立然后维护套接字连接的开销可能过大。

数据报套接字和 UDP 通常用于网络游戏和流媒体。当客户端需要向服务器发出短查询并且希望接收单个响应时，UDP 通常是一个不错的选择。为了提供这种发送和接收服务，我们需要使用 UDP 特定的函数调用`sendto()`和`recvfrom()`，而不是在套接字实现中看到的`read()`和`write()`。

# 创建一个简单的 TCP 服务器

在本节中，我们将看一下使用前面部分讨论的套接字技术实现一个简单的 TCP 服务器示例的过程。然后可以扩展此示例以支持各种游戏需求和功能。

由于为每个平台创建服务器的过程略有不同，我已将示例分成了两个不同的版本。

# Windows

让我们首先看看如何在 Windows 平台上使用 WinSock 库创建一个简单的套接字服务器，该服务器将监听连接并在建立连接时打印一个简单的调试消息。有关完整实现，请查看代码存储库的`Chapter10`目录：

```cpp
…
#include <stdio.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define PORT "44000" /* Port to listen on */

…
```

首先，我们有我们的包含文件。这使我们能够访问我们需要创建套接字的库（这对其他平台来说是不同的）。

```cpp
…
 if ((iResult = WSAStartup(wVersion, &wsaData)) != 0) {
     printf("WSAStartup failed: %d\n", iResult);
     return 1;
 }
```

跳转到主方法，我们开始初始化底层库。在这种情况下，我们使用 WinSock 库。

```cpp

 ZeroMemory(&hints, sizeof hints);
 hints.ai_family = AF_INET;
 hints.ai_socktype = SOCK_STREAM;
 if (getaddrinfo(NULL, PORT, &hints, &res) != 0) {
     perror("getaddrinfo");
     return 1;
 }
```

接下来，我们为套接字设置寻址信息。

```cpp
 sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
 if (sock == INVALID_SOCKET) {
     perror("socket");
     WSACleanup();
     return 1;
 }
```

然后我们创建套接字，传入我们在寻址阶段创建的元素。

```cpp
    /* Enable the socket to reuse the address */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseaddr,
        sizeof(int)) == SOCKET_ERROR) {
        perror("setsockopt");
        WSACleanup();
        return 1;
    }
```

创建完套接字后，最好设置套接字以便在关闭或重置时能够重用我们定义的地址。

```cpp
    if (bind(sock, res->ai_addr, res->ai_addrlen) == SOCKET_ERROR) {
        perror("bind");
        WSACleanup();
        return 1;
    }
    if (listen(sock, 1) == SOCKET_ERROR) {
        perror("listen");
        WSACleanup();
        return 1;
    }
```

现在我们可以绑定我们的地址，最后监听连接。

```cpp
…
    while(1) {
        size_t size = sizeof(struct sockaddr);
        struct sockaddr_in their_addr;
        SOCKET newsock;
        ZeroMemory(&their_addr, sizeof (struct sockaddr));
        newsock = accept(sock, (struct sockaddr*)&their_addr, &size);
        if (newsock == INVALID_SOCKET) {
            perror("accept\n");
        }
        else {
            printf("Got a connection from %s on port %d\n",
                inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port));
 …
        }
    }
```

在我们的主循环中，我们检查新的连接，当接收到一个有效的连接时，我们会在控制台上打印一个简单的调试消息。

```cpp
    /* Clean up */
    closesocket(sock);
    WSACleanup();
    return 0;
}
```

最后，我们必须清理自己。我们关闭套接字并调用`WSACleanup`函数来初始化清理 WinSock 库。

就是这样。现在我们有一个简单的服务器，它将在我们指定的端口`44000`上监听传入的连接。

# macOS

对于 macOS（和其他*nix 系统），该过程与 Windows 示例非常相似，但是我们需要使用不同的库来帮助我们支持。

```cpp
#include <stdio.h>
#include <string.h> /* memset() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#define PORT    "44000"
…
```

首先，我们有包含文件，在这里我们使用系统套接字，*nix 系统上基于 BSD 实现。

```cpp
int main(void)
{
    int sock;
    struct addrinfo hints, *res;
    int reuseaddr = 1; /* True */
    /* Get the address info */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(NULL, PORT, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }
```

在我们的主函数中，我们首先设置寻址信息。

```cpp
    /* Create the socket */
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == -1) {
        perror("socket");
        return 1;
    }
```

然后我们创建套接字，传入我们在寻址阶段创建的元素。

```cpp
    /* Enable the socket to reuse the address */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) == -1) {
        perror("setsockopt");
        return 1;
    }
```

创建完套接字后，最好设置套接字以便在关闭或重置时能够重用我们定义的地址。

```cpp
    if (bind(sock, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind");
        return 1;
    }

    if (listen(sock, 1) == -1) {
        perror("listen");
        return 1;
    }
```

现在我们可以绑定我们的地址，最后监听连接。

```cpp
    while (1) {
        socklen_t size = sizeof(struct sockaddr_in);
        struct sockaddr_in their_addr;
        int newsock = accept(sock, (struct sockaddr*)&their_addr, &size);
        if (newsock == -1) {
            perror("accept");
        }
        else {
            printf("Got a connection from %s on port %d\n",
                    inet_ntoa(their_addr.sin_addr), htons(their_addr.sin_port));
            handle(newsock);
        }
    }
```

在我们的主循环中，我们检查新的连接，当接收到一个有效的连接时，我们会在控制台上打印一个简单的调试消息。

```cpp
    close(sock);
    return 0;
}
```

最后，我们必须清理自己。在这种情况下，我们只需要关闭套接字。

就是这样。现在我们有一个简单的服务器，它将在我们指定的端口`44000`上监听传入的连接。

为了测试我们的示例，我们可以使用现有的程序，比如**putty**来连接到我们的服务器。或者我们可以创建一个简单的客户端，这个项目就留给你来完成。虽然只是一个简单的服务器，但这为构建你自己的实现提供了一个起点。

# 总结

在本章中，我们迈出了重要的一步，以了解多人游戏是如何在更低的层次上实现的。你学习了关于 TCP/IP 协议栈和不同的网络拓扑在游戏开发中的使用。我们研究了使用 UDP 和 TCP 协议来在客户端-服务器设置中传递数据。最后，我们看了一些开发者在开始实现多人游戏功能时面临的问题。在下一章中，我们将看看如何将我们的游戏带入一个新的领域——虚拟现实。


# 第十一章：虚拟现实

**虚拟现实**（**VR**）是当今游戏开发中非常热门的话题。在本章中，我们将看看如何利用 C++的强大功能来创建沉浸式的 VR 体验。需要注意的是，虽然用于示例集成的 SDK 可用于 macOS，但本章中介绍的硬件和示例代码尚未在 macOS 上进行测试，也不能保证支持。还需要注意的是，您需要一台 VR 头戴式显示器和一台性能强大的 PC 和显卡来运行本章的示例。建议您拥有与英特尔 i5-4590 或 AMD FX 8350 相匹配或超过的 CPU，以及与 NVIDIA GeForce GTX 960 或 AMD Radeon R9 290 相匹配或超过的 GPU。在本章中，我们将涵盖以下主题：

+   当前 VR 硬件

+   VR 渲染概念

+   头戴式显示器 SDK

+   实施 VR 支持

# 快速 VR 概述

VR 是一种计算机技术，利用各种形式的硬件通过逼真的图像、声音和其他感觉来生成用户在重建或虚构环境中的物理存在的模拟。处于 VR 环境中的用户能够环顾周围的人工世界，并且随着 VR 技术的新进展，还能在其中移动并与虚拟物品或对象进行交互。虽然 VR 技术可以追溯到 20 世纪 50 年代，但随着计算机图形、处理和性能的最新进展，VR 技术已经出现了复苏。著名的科技巨头，如 Facebook、索尼、谷歌和微软，都在虚拟和增强现实技术上进行了大笔投资。自鼠标发明以来，用户与计算机的交互方式从未有过如此大的创新潜力。VR 的用例不仅限于游戏开发。许多其他领域都希望利用 VR 技术来扩展他们自己独特的交互方式。医疗保健、教育、培训、工程、社会科学、营销，当然还有电影和娱乐，都为具有本书和游戏开发中学到的技能集的开发人员提供了有前途的机会。我经常建议寻求改变步调或新挑战的游戏开发人员，将目光投向新兴的 VR 开发领域，作为他们知识和技能基础的替代用途。

# 当前 VR 硬件

作为开发人员，我们正处于 VR 硬件开发的非常幸运的时期。在 VR 硬件方面有许多不同的选择，包括投影系统，如**CAVE**，**头戴式显示器**（**HMDs**），甚至基于手机的系统，如 Google Daydream 和 Cardboard。在这里，我们将重点关注沉浸式 PC 和主机驱动的 HMDs。这些 HMD 背后的大部分技术都非常相似。这里列出的每个 HMD 在运动方面至少有**六个自由度**（**6DOF**），即在 3D 空间中的头部跟踪，并且一些甚至具有基本的空间意识，通常称为*房间感知*。对于这些头戴式显示器的开发，从高层次上来说，可以以类似的方式进行，但了解每个不同设备的基本情况是很有必要的。接下来，我们将快速浏览目前消费者可以获得的一些最常见的头戴式显示器。

# Oculus Rift CV1

最初作为众筹项目开始，Oculus Rift 已成为目前最受欢迎的头戴式显示器之一。Oculus Rift 已经推出了几个版本。最初的两个硬件发布是面向开发人员的（DK1 和 DK2）。在 Facebook 收购 Oculus 后，这家社交媒体巨头发布了硬件的第一个商用版本，称为**消费者版本 1**（**CV1**）。虽然在**Steam**游戏平台上受到支持，但 Oculus 与自己的启动器和软件平台紧密相连。该头戴式显示器目前仅支持 PC 开发：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/233cdd18-da4f-49ba-aaf2-df46b2c88dad.png)

以下是 Oculus Rift CV1 的特点：

+   **屏幕类型**：AMOLED

+   **分辨率**：每只眼睛 1080 x 1200

+   **视野**：~110⁰

+   **头部跟踪**：IMU（指南针、加速计、陀螺仪），红外光学跟踪

最低推荐的 PC 规格如下：

+   **GPU**：NVIDIA GeForce GTX 970 或 AMD Radeon R9 290

+   **CPU**：Intel i5-4590 或 AMD FX 8350

+   **RAM**：8 GB

+   **操作系统**：Windows 7

# HTC Vive

可以说是目前最受欢迎的头戴式显示器，HTC Vive 是由 HTC（一家智能手机和平板电脑制造商）和 Valve 公司（一家以 Steam 游戏平台闻名的游戏公司）共同创建的。与 Oculus Rift 直接比较，HTC Vive 在设计上有许多相似之处，但在许多开发人员看来，略有不同之处使 HTC Vive 成为更优秀的硬件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/7c31b745-88c6-4288-b02e-d2871d5f1be2.jpg)![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/520be352-da41-4fa4-9afe-90559bc7d79b.jpg)

以下是 HTC Vive 的特点：

+   **屏幕类型**：AMOLED

+   **分辨率**：每只眼睛 1080 x 1200

+   **视野**：110⁰

+   **头部跟踪**：IMU（指南针、加速计、陀螺仪），2 个红外基站

最低推荐的 PC 规格如下：

+   **GPU**：NVIDIA GeForce GTX 970 或 AMD Radeon R9 290

+   **CPU**：Intel i5-4590 或 AMD FX 8350

+   **RAM**：4 GB

+   **操作系统**：Windows 7，Linux

# 开源虚拟现实（OSVR）开发套件

另一个非常有趣的硬件选择是由雷蛇和 Sensics 开发的 OSVR 套件。 OSVR 的独特之处在于它是一个开放许可、非专有硬件平台和生态系统。这使得开发人员在设计其 AR/VR 体验时有很大的自由度。OSVR 也是一个软件框架，我们很快会介绍。该框架与硬件一样，是开放许可的，旨在跨平台设计：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/1155357a-8f9e-40d5-af16-a4ce34315a52.jpg)

以下是 OSVR 的特点：

+   屏幕类型：AMOLED

+   **分辨率**：每只眼睛 960 x 1080

+   **视野**：100⁰

+   **头部跟踪**：IMU（指南针、加速计、陀螺仪），红外光学跟踪

最低推荐的 PC 规格如下：

+   **GPU**：NVIDIA GeForce GTX 970 或 AMD Radeon R9 290

+   **CPU**：Intel i5-4590 或 AMD FX 8350

+   **RAM**：4 GB

+   **操作系统**：跨平台支持

# 索尼 PlayStation VR

最初被称为**Project Morpheus**，索尼 PlayStation VR 是索尼公司进入 VR 领域的产品。与此列表中的其他头戴式显示器不同，索尼 PlayStation VR 头戴式显示器不是由 PC 驱动，而是连接到索尼 PlayStation 4 游戏主机。通过使用 PS4 作为其平台，索尼 PlayStation VR 头戴式显示器有 3000 多万的游戏主机用户：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/38bde5a4-a6e8-407b-b44f-30801ab071cf.jpg)

以下是索尼 PlayStation VR 的特点：

+   **屏幕类型**：AMOLED

+   **分辨率**：每只眼睛 960 x 1080

+   **视野**：~100⁰

+   **头部跟踪**：IMU（指南针、加速计、陀螺仪），红外光学跟踪

+   **控制台硬件**：索尼 PlayStation 4

# Windows Mixed Reality 头戴式显示器

最新进入 VR 硬件领域的是 Windows Mixed Reality 启用的一组头戴式显示器。虽然不是单一的头戴式显示器设计，但 Windows Mixed Reality 具有一套规格和软件支持，可以从 Windows 10 桌面实现 VR。被称为**混合现实**（**MR**），这些头戴式显示器的独特功能是其内置的空间感知或房间感知。其他头戴式显示器，如 Oculus Rift 和 HTC Vive，支持类似的功能，但与 Windows MR 设备不同，它们需要额外的硬件来支持跟踪。这种缺乏额外硬件意味着 Windows MR 头戴式显示器应该更容易设置，并有可能使 PC 供电的 VR 体验更加便携：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/7b8ab8b2-99a6-4c0a-a83a-8a28695a7fb8.jpg)

以下是 Windows MR 头戴式显示器的特点：

+   **屏幕类型**：各种

+   **分辨率**：各种

+   **视野**：各种

+   **头部跟踪**：基于头戴式内部 9DoF 追踪系统

最低推荐的 PC 规格如下：

+   **GPU**：NVIDIA GeForce GTX 960，AMD Radeon RX 460 或集成的 Intel HD Graphics 620

+   **CPU**：Intel i5-4590 或 AMD FX 8350

+   **内存**：8 GB

+   **操作系统**：Windows 10

# VR 渲染概念

从渲染的角度来看 VR，很快就会发现 VR 提出了一些独特的挑战。这部分是由于需要达到一些必要的性能基准和当前渲染硬件的限制。在渲染 VR 内容时，需要以比标准高清更高的分辨率进行渲染，通常是两倍或更多。渲染还需要非常快速，每只眼睛的帧率达到 90 帧或更高是基准。这，再加上抗锯齿和采样技术的使用，意味着渲染 VR 场景需要比以 1080p 分辨率以 60 帧每秒运行的标准游戏多五倍的计算能力。在接下来的章节中，我们将介绍在渲染 VR 内容时的一些关键区别，并涉及一些你可以实施以保持性能的概念。

# 使用视锥体

在开发 VR 就绪引擎时最大的区别在于理解如何在处理多个视点时构建适当的、裁剪的视锥体。在典型的非 VR 游戏中，你有一个单一的视点（摄像头），从中创建一个视锥体。如果需要完整的复习，请参考本书早些时候的内容，但这个视锥体决定了将被渲染并最终显示在屏幕上给用户的内容。以下是一个典型视锥体的图示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/09ce5ebe-8a4b-42a3-9907-400cfc948b74.png)

在 VR 渲染时，每只眼睛至少有一个视锥体，通常显示在单个头戴式显示器上，意味着在单个屏幕上显示一对图像，从而产生深度的错觉。通常这些图像描绘了场景的左眼和右眼视图。这意味着我们必须考虑两只眼睛的位置，并通过结合它们来产生最终的渲染视锥体。以下是这些视锥体的图示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/7feba28c-0c2e-47e8-8980-0bd056436155.png)

当创建一个结合了左右眼视锥体的单个视锥体时，实际上是非常容易的。如下图所示，你需要将新视锥体的顶点放在两只眼睛之间并略微向后移动。然后移动近裁剪平面的位置，使其与任一眼睛视锥体的裁剪平面对齐。这对于最终的显示**视锥体剔除**是很重要的。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/820bfde5-6d8c-4ea7-9574-32035e768475.png)

你可以使用一些简单的数学计算来计算这个视锥体，使用**瞳距**（**IPD**）来演示，正如 Oculus Rift 团队的 Cass Everitt 在以下图示中所展示的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/e8cbe7fd-05cc-48cb-862d-f9af0cf32b60.png)

我们也可以通过简单地对共享眼睛视锥体的顶部和底部平面进行剔除来简化这个过程。虽然在技术上并不形成完美的视锥体，但使用一个测试单个平面的剔除算法将产生期望的效果。

好消息是大部分可以被抽象化，而且在许多头戴式显示器 SDK 中都有方法来帮助你。然而，重要的是要理解在非 VR 场景渲染中，视锥体的使用方式与 VR 中的不同。

# 提高渲染性能

当使用单个摄像头和视点时，就像大多数非 VR 游戏一样，我们可以简单地将渲染过程视为引擎内的一个步骤。但是当使用多个视点时，情况就不同了。当然，我们可以将每个视点视为一个单独的渲染任务，依次处理，但这会导致渲染速度慢。

如前一节所示，每只眼睛看到的内容有很大的重叠。这为我们提供了通过共享和重用数据来优化我们的渲染过程的绝佳机会。为此，我们可以实现**数据上下文**的概念。使用这个概念，我们可以对哪些元素是唯一适用于单只眼睛进行分类，哪些元素可以共享进行分类。让我们看看这些数据上下文以及如何使用它们来加快我们的渲染速度：

+   **帧上下文**：简而言之，帧上下文用于任何需要被渲染且与视角无关的元素。这将包括诸如天空盒、全局反射、水纹理等元素。任何可以在视点之间共享的东西都可以放在这个上下文中。

+   **眼睛上下文**：这是不能在视点之间共享的元素的上下文。这将包括在渲染时需要立体视差的任何元素。我们还可以在这个上下文中存储每只眼睛的数据，这些数据将在我们的着色器计算中使用。

通过将数据简单地分成不同的上下文，我们可以重新组织我们的渲染过程，使其看起来类似于以下内容：

```cpp
RenderScene(Frame f)
{
  ProcessFrame(f); //Handle any needed globally shared calculations
  RenderFrame(f); //Render any globally shared elements
  for(int i=0; i<numview points; i++) //numview points would be 2 for                            stereo
    {
      ProcessEye(i, f); //Handle any per eye needed calculations
      RenderEye(i, f); //Render any per eye elements
    }
}
```

虽然这在表面上看起来很基本，但这是一个非常强大的概念。通过以这种方式分离渲染并共享我们可以的内容，我们大大提高了整体渲染器的性能。这是最简单的优化之一，但回报却很大。我们还可以将这种方法应用到如何设置我们的着色器统一变量上，将它们分成上下文片段：

```cpp
layout (binding = 0) uniform FrameContext
{
  Mat4x4 location; //modelview
  Mat4x4 projection;
  Vec3 viewerPosition;
  Vec3 position;
}frame;
layout (binding = 1) uniform EyeContext
{
  Mat4x4 location; //modelview
  Mat4x4 projection;
  Vec3 position;
}eye;
```

从概念上讲，数据的这种分割非常有效，每个数据片段都可以在不同的时间更新，从而提供更好的性能。

这基本上描述了以高层次处理多个视点的 VR 渲染的高效方法。如前所述，在开发中，与硬件和管道连接相关的大部分设置都在我们开发的 SDK 中被抽象掉了。在下一节中，我们将看一些这些 SDK，并通过查看在我们的示例引擎中实现 SDK 来结束本章。

# 头显 SDK

有许多 SDK 可用于实现各种头显和支持硬件，大多数制造商以某种形式提供自己的 SDK。在接下来的章节中，我们将快速查看开发 PC 驱动 HMD VR 体验时最常用的三个 SDK：

+   Oculus PC SDK（[`developer.oculus.com/downloads/package/oculus-sdk-for-windows/`](https://developer.oculus.com/downloads/package/oculus-sdk-for-windows/)）：此 SDK 专为在 C++中开发 Oculus Rift HMD 体验和游戏而创建。核心 SDK 提供了开发人员访问渲染、跟踪、输入和其他核心硬件功能所需的一切。核心 SDK 由其他支持音频、平台和头像的 SDK 支持。

+   **OpenVR**（[`github.com/ValveSoftware/openvr`](https://github.com/ValveSoftware/openvr)）：这是由 Valve 公司提供的默认 API 和 SteamVR 平台的运行时的 SDK。这也是 HTC Vive HMD 开发的默认 SDK，但设计为支持多个供应商。这意味着您可以在不知道连接了哪个 HMD 的情况下，针对多个 HMD 进行开发。这将是我们在示例引擎中实现的 SDK。

+   **OSVR**（[`osvr.github.io/`](http://osvr.github.io/)）：OSVR SDK，正如其名称所示，是一个设计用于与多个硬件供应商配合使用的开源 SDK。这个 SDK 是同名头显 OSVR 的默认 SDK。该项目由雷蛇和 Sensics 领导，许多大型游戏合作伙伴也加入了。OSVR SDK 可用于 Microsoft Windows、Linux、Android 和 macOS。

# 实现 VR 支持

与本书中讨论过的许多其他系统一样，从头开始实现 VR 支持可能是一个非常具有挑战性和耗时的过程。然而，就像其他系统一样，存在着可以帮助简化和简化过程的库和 SDK。在下一节中，我们将介绍如何使用 Valve 公司提供的 OpenVR SDK 向我们的示例引擎添加 VR 渲染支持。我们将只完整地介绍主要要点。要查看每种方法的更完整概述，请参考示例代码中的注释，并访问 OpenVR SDK Wiki 获取更多 SDK 特定信息（[`github.com/ValveSoftware/openvr/wiki`](https://github.com/ValveSoftware/openvr/wiki)）。

# 验证 HMD

首先，我们需要做一些事情来设置我们的硬件和环境。我们需要首先测试一下计算机上是否连接了头显。然后我们需要检查 OpenVR 运行时是否已安装。然后我们可以初始化硬件，最后询问一些关于其功能的问题。为此，我们将向我们的`GameplayScreen`类添加一些代码；为简洁起见，我们将跳过一些部分。完整的代码可以在代码存储库的`Chapter11`文件夹中的示例项目中找到。

让我们首先检查一下计算机是否连接了 VR 头显，以及 OpenVR（SteamVR）运行时是否已安装。为此，我们将在`Build()`方法中添加以下内容：

```cpp
void GameplayScreen::Build()
{
  if (!vr::VR_IsHmdPresent())
   {
      throw BookEngine::Exception("No HMD attached to the system");
   }
  if (!vr::VR_IsRuntimeInstalled())
   {
      throw BookEngine::Exception("OpenVR Runtime not found");
   }
}
```

在这里，如果这些检查中的任何一个失败，我们会抛出一个异常来处理和记录。现在我们知道我们有一些硬件和所需的软件，我们可以初始化框架。为此，我们调用`InitVR`函数：

```cpp
InitVR();
```

`InitVR`函数的主要目的是依次调用 OpenVR SDK 的`VR_Init`方法。为了做到这一点，它需要首先创建和设置一个错误处理程序。它还需要我们定义这将是什么类型的应用程序。在我们的情况下，我们声明这将是一个场景应用程序，`vr::VRApplication_Scene`。这意味着我们正在创建一个将绘制环境的 3D 应用程序。还有其他选项，比如创建实用程序或仅覆盖应用程序。最后，一旦 HMD 初始化完成，没有错误，我们要求头显告诉我们一些关于它自身的信息。我们使用`GetTrackedDeviceString`方法来做到这一点，我们很快就会看到。整个`InitVR`方法看起来像下面这样：

```cpp
void GameplayScreen::InitVR()
{
   vr::EVRInitError err = vr::VRInitError_None;
   m_hmd = vr::VR_Init(&err, vr::VRApplication_Scene);
   if (err != vr::VRInitError_None)
   {
     HandleVRError(err);
   }
   std::cout << GetTrackedDeviceString(m_hmd,
   vr::k_unTrackedDeviceIndex_Hmd,vr::Prop_TrackingSystemName_String)
   << std::endl;
   std::clog << GetTrackedDeviceString(m_hmd,                  vr::k_unTrackedDeviceIndex_Hmd, vr::Prop_SerialNumber_String)<<        std::endl;
}
```

`HandleVRError`方法只是一个简单的辅助方法，它接受传入的错误并抛出一个要处理和记录的错误，同时提供错误的英文翻译。以下是该方法的全部内容：

```cpp
void GameplayScreen::HandleVRError(vr::EVRInitError err)
{
  throw BookEngine::Exception(vr::VR_GetVRInitErrorAsEnglishDescription(err));
}
```

`InitVR`函数调用的另一个方法是`GetTrackedDeviceString`函数。这是 OpenVR 示例代码的一部分，允许我们返回有关附加设备的一些信息的函数。在我们的情况下，我们要求返回附加设备的系统名称和序列号属性（如果可用）：

```cpp
std::string GameplayScreen::GetTrackedDeviceString(vr::IVRSystem * pHmd, vr::TrackedDeviceIndex_t unDevice, vr::TrackedDeviceProperty prop, vr::TrackedPropertyError * peError)
{
  uint32_t unRequiredBufferLen = pHmd-                  >GetStringTrackedDeviceProperty(unDevice, prop, NULL, 0, peError);
    if (unRequiredBufferLen == 0)
      return "";

   char *pchBuffer = new char[unRequiredBufferLen];
   unRequiredBufferLen = pHmd->GetStringTrackedDeviceProperty(unDevice,   prop, pchBuffer, unRequiredBufferLen, peError);
   std::string sResult = pchBuffer;
   delete[] pchBuffer;
   return sResult;
}
```

最后，在我们的`Build`方法中，现在我们已经完成了初始化步骤，我们可以通过询问系统`VRCompositor`函数是否设置为 NULL 以外的值来检查一切是否顺利。如果是，那意味着一切准备就绪，我们可以询问我们的 HMD 希望我们的渲染目标大小是多少，并在控制台窗口中显示为字符串输出：

```cpp
if (!vr::VRCompositor())
 {
   throw BookEngine::Exception("Unable to initialize VR compositor!\n ");
 }
m_hmd->GetRecommendedRenderTargetSize(&m_VRWidth, &m_VRHeight);

std::cout << "Initialized HMD with suggested render target size : " << m_VRWidth << "x" << m_VRHeight << std::endl;
}
```

我们需要做的最后一件事是确保在程序完成时进行清理。在`GamplayScreen`的`Destroy`方法中，我们首先检查 HMD 是否已初始化；如果是，我们调用`VR_Shutdown`方法并将`m_hmd`变量设置为 NULL。在应用程序关闭时调用`VR_Shutdown`非常重要，因为如果不这样做，OpenVR/SteamVR 可能会挂起，并且可能需要重新启动才能再次运行：

```cpp
void GameplayScreen::Destroy()
{
   if (m_hmd)
    {
       vr::VR_Shutdown();
       m_hmd = NULL;
    }
}
```

现在，如果我们继续运行这个示例，在控制台窗口中，您应该看到类似以下的内容：

**![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/3587d745-2294-4081-b48f-3a57744be739.png)**

# 渲染

现在我们已经设置好了 HMD 并与我们的引擎进行了通信，下一步是对其进行渲染。实际上，这个过程并不复杂；如前所述，SDK 已经为我们处理了很多事情。为了尽可能简单，这个示例只是一个简单的渲染示例。我们不处理头部跟踪或输入，我们只是简单地在每只眼睛中显示不同的颜色。与之前的示例一样，为了节省时间和空间，我们只会涵盖重要的元素，让您掌握概念。完整的代码可以在代码库的`Chapter11`文件夹中的示例项目中找到。

正如我们之前讨论的那样，在立体视觉渲染时，通常会渲染一个被分成两半的单个显示器。然后我们将适当的数据传递给每半部分，取决于在该眼睛中可见的内容。回顾一下*使用视锥*部分，了解为什么会这样。这归结为我们需要为每只眼睛创建一个帧缓冲。为此，我们有一个`RenderTarget`类，它创建帧缓冲，附加纹理，最后创建所需的视口（即总显示宽度的一半）。为了节省空间，我不会打印出`RenderTarget`类；它非常简单，我们以前已经见过。相反，让我们继续设置和实际处理在 HMD 中显示场景的函数。首先，我们需要将我们的`RenderTarget`连接到我们的纹理，并且为了正确实现清除和设置缓冲区。为此，我们将以下内容添加到`GameplayScreen`的`OnEntry`方法中：

```cpp
BasicRenderTarget leftRT(1, vrApp.rtWidth, vrApp.rtHeight);
BasicRenderTarget rightRT(1, vrApp.rtWidth, vrApp.rtHeight);

leftRT.Init(leftEyeTexture.name);
rightRT.Init(rightEyeTexture.name);

glClearColor(1.0f, 0.0f, 0.0f, 1.0f);
leftRT.fbo.Bind(GL_FRAMEBUFFER);
glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
  {
    throw std::runtime_error("left rt incomplete");
  }
glClearColor(0.0f, 1.0f, 0.0f, 1.0f);
rightRT.fbo.Bind(GL_FRAMEBUFFER);
glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
if (glCheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
  {
    throw std::runtime_error("right rt incomplete");
  }
glBindFramebuffer(GL_FRAMEBUFFER, 0);

glClearColor (0.0f, 0.0f, 1.0f, 1.0f);
```

我不会逐行讲解之前的代码，因为我们以前已经看过了。现在，我们的缓冲区和纹理已经设置好，我们可以继续添加绘图调用了。

OpenVR SDK 提供了处理显示 VR 场景复杂部分所需的方法。大部分这些复杂工作是由合成器系统完成的。正如 Valve 所说的那样，*“合成器通过处理失真、预测、同步和其他细微问题，简化了向用户显示图像的过程，这些问题可能对于获得良好的 VR 体验而言是一个挑战。”*

为了连接到合成器子系统，我们创建了一个名为`SubmitFrames`的简单方法。这个方法接受三个参数——每只眼睛的纹理和一个布尔值，用于指定颜色空间是否应该是`线性`。在撰写本文时，我们总是希望指定颜色空间应该是`Gamma`，适用于`OpenGL`。在方法内部，我们获取希望渲染到的设备，设置颜色空间，转换纹理，然后将这些纹理提交给`VRCompositor`，然后在幕后处理将纹理显示到正确的眼睛上。整个方法看起来像下面这样：

```cpp
void GameplayScreen::SubmitFrames(GLint leftEyeTex, GLint rightEyeTex, bool linear = false)
{
 if (!m_hmd)
  {
    throw std::runtime_error("Error : presenting frames when VR system handle is NULL");
  }
  vr::TrackedDevicePose_t trackedDevicePose[vr::k_unMaxTrackedDeviceCount];
  vr::VRCompositor()->WaitGetPoses(trackedDevicePose,        vr::k_unMaxTrackedDeviceCount, nullptr, 0);

  vr::EColorSpace colorSpace = linear ? vr::ColorSpace_Linear :    vr::ColorSpace_Gamma;

  vr::Texture_t leftEyeTexture = { (void*)leftEyeTex,    vr::TextureType_OpenGL, colorSpace };
  vr::Texture_t rightEyeTexture = { (void*)rightEyeTex,   vr::TextureType_OpenGL, colorSpace };

  vr::VRCompositor()->Submit(vr::Eye_Left, &leftEyeTexture);
  vr::VRCompositor()->Submit(vr::Eye_Right, &rightEyeTexture);

  vr::VRCompositor()->PostPresentHandoff();
}
```

有了我们的`SubmitFrames`函数，我们可以在`GameplayScreen`更新中调用该方法，就在`glClear`函数调用之后：

```cpp
…
glClear(GL_COLOR_BUFFER_BIT);
SubmitFrames(leftEyeTexture.id, rightEyeTexture.id);
```

如果您现在运行示例项目，并且已经安装了必要的 SteamVR 框架，您应该会看到头戴显示器的每只眼睛显示不同的颜色。

# 总结

虽然这只是对 VR 开发世界的快速介绍，但它应该为您的体验创意提供了一个很好的测试基础。我们学习了如何处理多个视图截头体，了解了各种硬件选项，最后看了一下我们如何使用 OpenVR SDK 为我们的示例引擎添加 VR 支持。随着硬件的进步，VR 将继续获得动力，并将继续向新领域推进。全面了解 VR 渲染的工作原理将为您的开发知识储备提供新的深度水平。
