# HTML5 多人游戏开发（一）

> 原文：[`zh.annas-archive.org/md5/58B015FFC16EF0C30C610502BF4A7DA3`](https://zh.annas-archive.org/md5/58B015FFC16EF0C30C610502BF4A7DA3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎来到《使用 HTML5 开发多人游戏》。本书将教你如何开发支持多个玩家在同一游戏世界中互动的游戏，并如何执行网络编程操作以实现这样的系统。它涵盖了诸如 WebSockets 和 JavaScript 中的客户端和服务器端游戏编程，延迟减少技术以及处理来自多个用户的服务器查询等主题。我们将通过从头到尾开发两款实际的多人游戏来实现这一目标，并在此过程中还将教授 HTML5 游戏开发的各种主题。本书的目的是教会你如何使用 HTML5 为多个玩家创建游戏世界，他们希望通过互联网进行竞争或互动。

# 本书涵盖内容

第一章, *开始多人游戏编程*，介绍了网络编程，重点是设计多人游戏。它通过引导你创建一个实时的井字棋游戏，来说明多人游戏开发的基本概念。

第二章, *设置环境*，描述了 JavaScript 开发领域的最新技术，包括通过 Node.js 在服务器端使用 JavaScript。它还描述了当前的技术，以管理 JavaScript 的开发周期和资源管理工具，如 Npm、Bower、Grunt 等。

第三章, *实时喂养蛇*，将现有的单人 Snake 游戏改造成具有使用先前描述的工具在同一游戏世界中与多个玩家一起玩的能力。还描述和演示了大厅、房间、匹配和处理用户查询的概念，为 Snake 游戏增加了功能。本章介绍了当今行业中最强大和广泛使用的 WebSocket 抽象——socket.io。

第四章, *减少网络延迟*，教授了减少网络延迟的技术，以创建流畅的游戏体验。其中最常见的技术之一——客户端预测，被演示并应用到了前一章描述的 Snake 游戏中。游戏服务器代码也被更新，以提高性能，引入了第二个更新循环。

第五章, *利用前沿技术*，描述了在网络平台上进行游戏开发所发现的令人兴奋的机会。它解释了 WebRTC、HTML5 的游戏手柄、全屏模式和媒体捕获 API。其他承诺和实验性技术和 API 也在此处描述。

第六章, *添加安全和公平游戏*，涵盖了与网络游戏相关的常见缺陷和安全漏洞。在这里，描述和演示了常见的技术，使你能够开发提供无作弊游戏体验的游戏。

# 本书所需内容

要使用本书，你需要安装 Node.js 和 Npm，现代的网络浏览器（如 Google Chrome 5.0，Firefox 3.5，Safari 5.0 或 Internet Explorer 9.0 及更高版本），以及文本编辑器或集成开发环境（IDE）。你还需要基本到中级的 JavaScript 知识，以及一些先前的游戏编程经验，最好是 JavaScript 和 HTML5。

# 本书的受众

本书的目标读者是能制作基本单人游戏的 HTML5 游戏开发人员，他们现在想尽快学习如何在他们的 HTML5 游戏中快速加入多人游戏功能。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些示例以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“第一个将以`action`的值为键，第二个将以`data`的键为值。”

代码块设置如下：

```js
wss.on('connection', function connection(ws) {
    board.on(Board.events.PLAYER_CONNECTED, function(player) {
        wss.clients.forEach(function(client) {
            board.players.forEach(function(player) {
                client.send(makeMessage(events.outgoing.JOIN_GAME, player));
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```js
validator.isEmail('foo@bar.com'); //=> true
validator.isBase64(inStr);
validator.isHexColor(inStr);
validator.isJSON(inStr);
```

任何命令行输入或输出都以以下方式编写：

```js
npm install socket.io --save
npm install socket.io-client –save

```

### 注意

警告或重要说明显示在这样的框中。

### 提示

提示和技巧显示如下。


# 第一章：开始多人游戏编程

如果你正在阅读这本书，很有可能你已经是一名游戏开发者。如果是这样，那么你已经知道编写自己的游戏是多么令人兴奋，无论是专业地还是作为一种非常耗时但非常令人满足的爱好。现在你已经准备将你的游戏编程技能提升到下一个水平——也就是说，你已经准备在基于 JavaScript 的游戏中实现多人功能。

如果你已经开始使用 HTML5 和 JavaScript 为**Open Web Platform**创建多人游戏，那么你可能已经意识到个人台式电脑、笔记本电脑或移动设备并不是与另一个玩家分享游戏世界的最合适的设备，因此，为了使用 JavaScript 创建令人兴奋的多人游戏，需要一些形式的网络技术。

在本章中，我们将讨论以下原则和概念：

+   网络和网络编程范式的基础知识

+   使用 HTML5 进行套接字编程

+   编写游戏服务器和游戏客户端

+   回合制多人游戏

# 了解网络的基础知识

据说，如果没有先了解计算机网络和网络编程的学科，就无法编写利用网络的游戏。虽然对任何主题有深入的了解对于从事该主题的人来说都是有益的，但我不认为你必须了解关于游戏网络的所有知识才能编写一些非常有趣和引人入胜的多人游戏。说这种情况就像说一个人需要成为西班牙语的学者才能做一个简单的墨西哥卷饼。因此，让我们来看看网络的最基本和基本概念。在本节结束时，你将了解足够的计算机网络知识，可以开始，并且可以轻松地为你的游戏添加多人游戏方面。

需要记住的一件事是，尽管网络游戏并不像单人游戏那样古老，但计算机网络实际上是一个非常古老且经过深入研究的主题。一些最早的计算机网络系统可以追溯到 20 世纪 50 年代。尽管一些技术随着时间的推移有所改进，但基本思想仍然是一样的：两台或更多台计算机连接在一起，以建立机器之间的通信。通过通信，我指的是数据交换，比如在机器之间来回发送消息，或者一台机器只发送数据，另一台只接收数据。

通过这个对网络概念的简要介绍，你现在已经对网络主题有了一定的了解，足以知道网络游戏所需的是什么——尽可能接近实时地交流的两台或更多台计算机。

到目前为止，应该很清楚这个简单的概念是如何让我们能够将多个玩家连接到同一个游戏世界中的。实质上，我们需要一种方法来在连接到游戏会话的所有玩家之间共享全局游戏数据，然后继续更新每个玩家关于其他每个玩家的信息。通常有几种不同的技术用于实现这一点，但最常见的两种方法是点对点和客户端-服务器。这两种技术都提供了不同的机会，包括优势和劣势。一般来说，两者都没有特别优于另一种，但不同的情况和用例可能更适合其中一种技术。

## 点对点网络

通过点对点架构将玩家连接到同一个虚拟游戏世界是一种简单的方法。尽管名称可能暗示只涉及两个对等体（“节点”），但根据定义，点对点网络系统是指两个或更多个节点直接连接在一起，没有中央系统编排连接或信息交换。

在典型的点对点设置中，每个对等体都扮演着与其他对等体相同的功能，即它们都消耗相同的数据并共享它们产生的数据，以便其他人保持同步。在点对点游戏的情况下，我们可以用一个简单的*井字棋*游戏来说明这种架构。

![点对点网络](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_01_01.jpg)

一旦两名玩家之间建立了连接，谁开始游戏就在游戏板上标记一个单元格。这些信息通过电线传递给另一个对等体，后者现在知道了对手所做的决定，并因此可以更新自己的游戏世界。一旦第二名玩家收到了由第一名玩家最新移动所导致的游戏最新状态，第二名玩家就能够通过检查游戏板上的一些可用空间来进行自己的移动。然后这些信息被复制到第一名玩家那里，他可以更新自己的世界，并通过进行下一个期望的移动来继续这个过程。

这个过程会一直持续，直到其中一个对等体断开连接或者游戏以基于游戏自身业务逻辑的某个条件结束。在*井字棋*游戏的情况下，游戏将在其中一名玩家在棋盘上标记了三个空格形成一条直线，或者所有九个单元格都被填满，但没有一名玩家成功连接三个单元格的情况下结束。

点对点网络游戏的一些好处如下：

+   **快速数据传输**：在这里，数据直接传输到其预定目标。在其他架构中，数据可能首先传输到一些集中节点，然后中央节点（或者在下一节中我们将看到的“服务器”）联系其他对等体，发送必要的更新。

+   **更简单的设置**：你只需要考虑游戏的一个实例，一般来说，它处理自己的输入，将其输入发送给其他连接的对等体，并处理它们的输出作为自己系统的输入。这在回合制游戏中特别方便，例如，大多数棋盘游戏，比如*井字棋*。

+   **更可靠**：这里一个离线的对等体通常不会影响其他对等体。然而，在一个两人游戏的简单情况下，如果其中一名玩家无法继续，游戏很可能会无法继续进行。不过，想象一下，如果所涉及的游戏有数十甚至数百个连接的对等体。如果其中一些突然失去了互联网连接，其他人可以继续玩。但是，如果有一个连接所有节点的服务器并且服务器宕机，那么其他玩家将不知道如何与彼此交流，也不会知道发生了什么。

另一方面，点对点架构的一些明显缺点如下：

+   **无法信任传入数据**：在这里，你无法确定发送者是否修改了数据。输入到游戏服务器的数据也会受到同样的挑战，但一旦数据经过验证并广播到所有其他对等体，你就可以更有信心地认为每个对等体从服务器接收到的数据至少已经经过了清理和验证，并且更可信。

+   **容错率可能非常低**：在我们之前讨论的*点对点网络*的好处部分中提出了相反的观点；如果足够多的玩家共享游戏世界，一个或多个崩溃不会使游戏对其他对等体不可玩。现在，如果我们考虑到任何突然崩溃的玩家对其他玩家产生负面影响的许多情况，我们就可以看到服务器如何可以轻松从崩溃中恢复。

+   **向其他对等体广播时的数据重复**：想象一下，你的游戏是一个简单的 2D 横向卷轴游戏，许多其他玩家与你共享这个游戏世界。每当其中一个玩家向右移动时，你会收到该玩家的新的（x，y）坐标，并且能够更新自己的游戏世界。现在，想象一下，你将你的玩家向右移动了几个像素；你将不得不将这些数据发送给系统中的所有其他节点。

总的来说，点对点是一种非常强大的网络架构，仍然被许多游戏行业广泛使用。由于当前的点对点网络技术仍处于起步阶段，今天大多数基于 JavaScript 的游戏不使用点对点网络。出于这个原因和其他很快就会变得明显的原因，我们将几乎专注于另一种流行的网络范式，即客户端-服务器架构。

## 客户端-服务器网络

**客户端-服务器网络**架构的理念非常简单。如果你闭上眼睛，你几乎可以看到一个点对点图。它们之间最明显的区别是，每个节点都是平等的对等体，而其中一个节点是特殊的。也就是说，每个节点（客户端）不是连接到每个其他节点，而是连接到一个名为*服务器*的主要集中节点。

虽然客户端-服务器网络的概念似乎足够清晰，也许一个简单的比喻可能会让你更容易理解这种网络格式中每种类型节点的角色，并将其与点对点区分开（*McConnell*，*Steve*，*(2004)* *Code Complete*，*Microsoft Press*）。在点对点网络中，你可以将其视为一群朋友（对等体）在派对上进行对话。他们都可以直接与参与对话的其他对等体交谈。另一方面，客户端-服务器网络可以被视为一群朋友在餐馆吃饭。如果餐馆的客户想要点菜单上的某样东西，他或她必须与服务员交谈，服务员是那群人中唯一能够访问所需产品并为客户提供服务的人。

简而言之，服务器负责向一个或多个客户端提供数据和服务。在游戏开发的背景下，最常见的情况是两个或多个客户端连接到同一个服务器；服务器将跟踪游戏以及分布的玩家。因此，如果两个玩家要交换只与他们两个有关的信息，通信将从第一个玩家经过服务器传递并最终到达第二个玩家那里。

![客户端服务器网络](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_01_02.jpg)

在我们之前关于点对点的部分中看到的*井字棋*游戏中涉及的两名玩家的例子中，我们可以看到客户端-服务器模型中事件流是多么相似。再次强调，主要区别在于玩家彼此不知道对方，只知道服务器告诉他们的内容。

虽然你可以很容易地通过使用服务器仅仅连接两个玩家来模拟点对点模型，但通常服务器的使用要比这更加活跃。在网络游戏中，有两种方式可以让服务器参与，即授权方式和非授权方式。也就是说，你可以将游戏逻辑的执行严格放在服务器端，或者你可以让客户端处理游戏逻辑、输入验证等。如今，大多数使用客户端-服务器架构的游戏实际上使用这两种方式的混合（授权和非授权服务器，我们将在本书的后面讨论）。但无论如何，服务器的生命周期的目的是接收来自每个客户端的输入，并将该输入分发到连接的客户端池中。

不管你决定使用授权服务器还是非授权服务器，你会注意到客户端-服务器游戏的一个挑战是你需要编写整个堆栈的两端。即使你的客户端只是从用户那里获取输入，将其转发到服务器，并渲染从服务器接收到的任何数据；如果你的游戏服务器只是将它从每个客户端接收到的输入转发给其他每个客户端，你仍然需要编写游戏客户端和游戏服务器。

本章后面我们将讨论游戏客户端和服务器。目前，我们真正需要知道的是，这两个组件是将这种网络模型与点对点网络区分开来的关键。

客户端-服务器网络游戏的一些好处如下：

+   **关注点分离**：如果你了解软件开发，你就会知道这是你应该始终追求的。也就是说，良好的、可维护的软件是由离散的组件编写的，每个组件都只做一件“事”，而且做得很好。编写单独的专门组件让你可以专注于一次执行一个任务，使得你的游戏更容易设计、编码、测试、推理和维护。

+   **集中化**：尽管这一点可以被反对也可以被支持，但通过一个中心位置进行所有通信使得更容易管理这样的通信，强制执行任何必要的规则，控制访问等等。

+   **减轻客户端的工作量**：客户端不再需要负责从用户和其他对等体获取输入，验证所有输入，与其他对等体共享数据，渲染游戏等等，客户端只需要专注于做其中的一部分，让服务器来分担一部分工作。当我们谈论移动游戏以及微妙的劳动分工如何影响整体玩家体验时，这一点尤为重要。例如，想象一个游戏中有 10 名玩家参与同一个游戏世界。在点对点设置中，每当一个玩家采取行动时，他或她需要将该行动发送给其他九名玩家（换句话说，需要进行九次网络调用，导致更多的移动数据使用）。另一方面，在客户端-服务器配置中，一个玩家只需要将他或她的行动发送给一个对等体，也就是服务器，然后服务器负责将该数据发送给其余的九名玩家。

无论服务器是否具有授权性，客户端-服务器架构的一些常见缺点如下：

+   **通信需要更长时间传播**：在最理想的情况下，从第一个玩家发送到第二个玩家的每条消息传递时间都会比点对点连接长一倍。也就是说，消息首先从第一个玩家发送到服务器，然后从服务器发送到第二个玩家。今天有许多技术用于解决这种情况下面临的延迟问题，其中一些我们将在第四章中更深入地讨论，*减少网络延迟*。然而，根本的困境将始终存在。

+   **由于移动部件更复杂**：无论你如何切割披萨，你需要编写的代码越多（相信我，当你为游戏构建两个独立的模块时，你会写更多的代码），你的心智模型就需要越大。虽然你的大部分代码可以在客户端和服务器之间重复使用（特别是如果你使用了成熟的编程技术，比如面向对象编程），但归根结底，你需要管理更高级别的复杂性。

+   **单点故障和网络拥塞**：到目前为止，我们大多讨论的是只有少数玩家参与同一游戏的情况。然而，更常见的情况是少数玩家组在同一时间玩不同的游戏。

以两人玩*Tic-tac-toe*的游戏为例，想象一下有成千上万的玩家在单人游戏中面对面。在点对点设置中，一旦一对玩家直接配对，就好像没有其他玩家在享受那个游戏。唯一能阻止这两个玩家继续游戏的是他们彼此之间的连接。

另一方面，如果同样成千上万的玩家通过一个位于两者之间的服务器相互连接，那么两个被孤立的玩家可能会注意到消息之间出现严重的延迟，因为服务器忙于处理所有来自其他玩家的消息。更糟糕的是，这两个玩家现在不仅需要担心彼此之间通过服务器维持连接，还希望服务器与他们和对手之间的连接保持活动状态。

总的来说，客户端-服务器网络中涉及的许多挑战都经过深入研究和理解，你在多人游戏开发过程中可能会遇到的许多问题已经被其他人解决了。客户端-服务器是一种非常流行和强大的游戏网络模型，而通过 HTML5 和 JavaScript 可用的所需技术已经得到了很好的发展和广泛的支持。

## 网络协议 - UDP 和 TCP

通过讨论玩家如何在某种形式的网络上进行交流，我们只是浅尝辄止，实际上并没有涉及到通信是如何实际完成的。让我们来描述一下协议是什么，以及它们如何应用于网络和更重要的是多人游戏开发。

协议一词可以被定义为*一组约定*或*详细的程序计划* [引用[Def. 3,4]。(n.d.)。在 Merriam Webster Online 中检索到 2015 年 2 月 12 日，从[`www.merriam-webster.com/dictionary/protocol`](http://www.merriam-webster.com/dictionary/protocol)]。在计算机网络中，协议向消息的接收方描述数据的组织方式，以便对其进行解码。例如，想象一下，您有一个多人对打游戏，并且您想告诉游戏服务器，您的玩家刚刚发出了一个踢的命令，并向左移动了 3 个单位。您应该向服务器发送什么？您发送一个值为“kick”的字符串，然后是数字 3 吗？否则，您首先发送数字，然后是一个大写字母“K”，表示所采取的行动是踢？我试图表达的观点是，如果没有一个被充分理解和达成一致的协议，就不可能成功和可预测地与另一台计算机进行通信。

我们将在本节中讨论的两种网络协议，也是多人联机游戏中最广泛使用的两种协议，分别是**传输控制协议**（**TCP**）和**用户数据报协议**（**UDP**）。这两种协议都提供了网络系统中客户端之间的通信服务。简单来说，它们是允许我们以可预测的方式发送和接收数据包的协议。

当数据通过 TCP 发送时，源机器中运行的应用程序首先与目标机器建立连接。一旦建立了连接，数据以数据包的形式传输，以便接收方的应用程序可以将数据按适当的顺序重新组合。TCP 还提供了内置的错误检查机制，因此，如果数据包丢失，目标应用程序可以通知发送方应用程序，并且任何丢失的数据包都会被重新发送，直到整个消息被接收。

简而言之，TCP 是一种基于连接的协议，可以保证完整数据的按正确顺序传递。我们周围有许多需要这种行为的用例。例如，当您从 Web 服务器下载游戏时，您希望确保数据正确传输。您希望在用户开始玩游戏之前，游戏资产能够被正确完整地下载。虽然这种交付保证听起来非常令人放心，但也可以被认为是一个缓慢的过程，有时可能比知道数据将完整到达更重要，我们稍后会简要看到。

相比之下，UDP 在不使用预先建立的连接的情况下传输数据包（称为*数据报*）。该协议的主要目标是以非常快速和无摩擦的方式向某个目标应用程序发送数据。实质上，您可以将 UDP 视为勇敢的员工，他们打扮成公司的吉祥物站在店外挥舞着大型横幅，希望至少有一些经过的人会看到他们并给他们业务。

起初，UDP 可能看起来像是一种鲁莽的协议，但使 UDP 如此令人渴望和有效的用例包括许多情况，当您更关心速度而不是偶尔丢失数据包，获取重复数据包或以无序方式获取它们时。您可能还希望在您不关心接收方的回复时选择 UDP 而不是 TCP。使用 TCP 时，无论您是否需要接收方的某种确认或回复，它仍然需要时间来回复您，至少确认消息已收到。有时，您可能不在乎服务器是否收到了数据。

![网络协议 - UDP 和 TCP](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_01_03.jpg)

UDP 比 TCP 更好的选择的一个更具体的例子是，当你需要从客户端获取心跳信号，让服务器知道玩家是否还在游戏中时。如果你需要让服务器知道会话仍然活跃，并且偶尔丢失一个心跳信号并不重要，那么使用 UDP 是明智的选择。简而言之，对于任何不是关键任务且可以承受丢失的数据，UDP 可能是最佳选择。

最后，要记住，就像点对点和客户端-服务器模型可以并行构建一样，同样你的游戏服务器可以是授权和非授权的混合体，绝对没有理由为什么你的多人游戏只能使用 TCP 或 UDP。使用特定情况需要的任何协议。

## 网络套接字

还有一个我们将非常简要地介绍的协议，只是为了让你看到在游戏开发中需要网络套接字。作为 JavaScript 程序员，你无疑熟悉**超文本传输协议**（**HTTP**）。这是 Web 浏览器用来从 Web 服务器获取你的游戏的应用层协议。

虽然 HTTP 是一个可靠地从 Web 服务器检索文档的协议，但它并不是为实时游戏而设计的；因此，它并不是这个目的的理想选择。HTTP 的工作方式非常简单：客户端向服务器发送请求，然后服务器返回响应给客户端。响应包括一个完成状态码，向客户端指示请求是正在处理中，需要转发到另一个地址，或者已成功或错误地完成（*超文本传输协议（HTTP/1.1）：身份验证*，*（1999 年 6 月）*。[`tools.ietf.org/html/rfc7235`](https://tools.ietf.org/html/rfc7235)）

有几件事情需要注意关于 HTTP，这将清楚地表明在客户端和服务器之间的实时通信需要更好的协议。首先，每次接收到响应后，连接就会关闭。因此，在发出每个请求之前，必须与服务器建立新的连接。大多数情况下，HTTP 请求将通过 TCP 发送，相对而言，这可能会比较慢。

其次，HTTP 在设计上是一个无状态协议。这意味着，每次你从服务器请求资源时，服务器都不知道你是谁以及请求的上下文是什么。（它不知道这是你的第一个请求，还是你经常请求。）这个问题的一个常见解决方案是在每个 HTTP 请求中包含一个唯一的字符串，服务器会跟踪这个字符串，并因此可以持续提供有关每个个体客户端的信息。你可能会认识到这是一个标准的*会话*。这种解决方案的主要缺点，至少在实时游戏方面，是将会话 cookie 映射到用户会话需要额外的时间。

最后，使 HTTP 不适合多人游戏编程的主要因素是通信是单向的——只有客户端可以连接到服务器，服务器通过同一连接回复。换句话说，游戏客户端可以告诉游戏服务器用户输入了一个出拳命令，但游戏服务器无法将这些信息传递给其他客户端。想象一下自动售货机。作为机器的客户，我们可以请求我们想要购买的特定物品。我们通过向自动售货机投入货币来正式化这个请求，然后按下适当的按钮。

在任何情况下，自动售货机都不会向附近站立的人发出命令。这就像等待自动售货机发放食物，期望人们之后再往里面投钱。

对于 HTTP 功能的缺乏，答案非常简单。网络套接字是连接中允许客户端和服务器进行双向通信的端点。把它想象成电话通话，而不是自动售货机。在电话通话期间，任何一方都可以在任何时候说任何他们想说的话。最重要的是，双方之间的连接在整个对话期间保持打开状态，使通信过程非常高效。

![网络套接字](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_01_04.jpg)

**WebSocket**是建立在 TCP 之上的协议，允许基于 Web 的应用程序与服务器进行双向通信（*WebSocket Protocol*，*（2011 年 12 月）*。[`tools.ietf.org/html/rfc6455 RFC 6455`](http://tools.ietf.org/html/rfc6455 RFC 6455)）。创建 WebSocket 的方式包括多个步骤，包括从 HTTP 升级到 WebSocket 的协议升级。幸运的是，所有繁重的工作都是由浏览器和 JavaScript 在幕后完成的，我们将在下一节中看到。现在，这里的关键要点是，通过 TCP 套接字（是的，还有其他类型的套接字，包括 UDP 套接字），我们可以可靠地与服务器通信，服务器也可以根据需要回应我们。

# JavaScript 中的套接字编程

现在让我们通过讨论将一切联系在一起的工具——JavaScript 和 WebSocket——来结束关于网络连接、协议和套接字的对话，从而使我们能够使用开放 Web 的语言编写出色的多人游戏。

## WebSocket 协议

现代浏览器和其他 JavaScript 运行时环境已经在 JavaScript 中实现了 WebSocket 协议。不要误以为只因为我们可以在 JavaScript 中创建 WebSocket 对象，WebSocket 就是 JavaScript 的一部分。定义 WebSocket 协议的标准是与语言无关的，可以在任何编程语言中实现。因此，在开始部署使用 WebSocket 的 JavaScript 游戏之前，请确保将运行游戏的环境使用了实现了 WebSockets 的**ECMA**标准。换句话说，并非所有浏览器在您请求 WebSocket 连接时都知道该怎么做。

就目前而言，今天最流行的浏览器（即 Google Chrome，Safari，Mozilla Firefox，Opera 和 Internet Explorer）的最新版本（即本文撰写时）实施了 RFC 6455 的最新修订版。 WebSockets 的旧版本（如协议版本-76、7 或 10）正在逐渐被弃用，并已被一些先前提到的浏览器移除。

### 注意

关于 WebSocket 协议最令人困惑的事情可能是每个协议版本的命名方式。最初的草案（可以追溯到 2010 年）被命名为*draft-hixie-thewebsocketprotocol-75*。下一个版本被命名为*draft-hixie-thewebsocketprotocol-76*。有些人将这些版本称为 75 和 76，这可能会相当令人困惑，特别是因为协议的第四个版本被命名为*draft-ietf-hybi-thewebsocketprotocol-07*，在草案中被命名为 WebSocket Version 7。协议的当前版本（*RFC 6455*）是 13。

让我们快速看一下我们将在 JavaScript 代码中使用的编程接口（API），以与 WebSocket 服务器进行交互。请记住，我们需要编写使用 WebSockets 消耗数据的 JavaScript 客户端，以及使用 WebSockets 但扮演服务器角色的 WebSocket 服务器。随着我们讨论一些示例，两者之间的区别将变得明显。

### 创建客户端 WebSocket

以下代码片段创建了一个新的 WebSocket 类型对象，将客户端连接到某个后端服务器。构造函数需要两个参数；第一个是必需的，表示 WebSocket 服务器正在运行并期望连接的 URL。第二个 URL 在本书中不会使用，它是服务器可能实现的可选子协议列表。

```js
var socket = new WebSocket('ws://www.game-domain.com');
```

尽管这一行代码可能看起来很简单且无害，但请记住以下几点：

+   我们不再处于 HTTP 领域。现在，WebSocket 服务器的地址以`ws://`开头，而不是`http://`。同样，当我们使用安全（加密）套接字时，我们将指定服务器的 URL 为`wss://`，就像在`https://`中一样。

+   这对您可能显而易见，但 WebSockets 入门者常犯的一个常见错误是，在您可以使用上述代码建立连接之前，您需要在该域上运行一个 WebSocket 服务器。

+   WebSockets 实现了同源安全模型。正如您可能已经在其他 HTML5 功能中看到的那样，同源策略规定，只有在客户端和服务器位于同一域中时，才能通过 JavaScript 访问资源。

### 提示

对于不熟悉同源（也称为**同源**）策略的人来说，在这种情况下，构成域的三个要素是正在访问的资源的协议、主机和端口。在上一个示例中，协议、主机和端口号分别是`ws`（而不是`wss`、`http`或`ssh`）、`www.game-domain.com`（任何子域，如`game-domain.com`或`beta.game-domain.com`都将违反同源策略），以及 80（默认情况下，WebSocket 连接到端口 80，使用`wss`时连接到端口 443）。

由于上一个示例中的服务器绑定到端口 80，我们不需要显式指定端口号。但是，如果服务器配置为在不同的端口上运行，比如 2667，那么 URL 字符串需要包括一个冒号，后面跟着需要放在主机名末尾的端口号，如`ws://www.game-domain.com:2667`。

与 JavaScript 中的其他所有内容一样，WebSocket 实例尝试异步连接到后端服务器。因此，在确保服务器已连接之前，您不应尝试在新创建的套接字上发出命令；否则，JavaScript 将抛出一个可能会使整个游戏崩溃的错误。可以通过在套接字的`onopen`事件上注册回调函数来实现这一点：

```js
var socket = new WebSocket('ws://www.game-domain.com');
socket.onopen = function(event) {
   // socket ready to send and receive data
};
```

一旦套接字准备好发送和接收数据，您可以通过调用套接字对象的`send`方法向服务器发送消息，该方法接受一个字符串作为要发送的消息。

```js
// Assuming a connection was previously established
socket.send('Hello, WebSocket world!');
```

然而，通常情况下，您会希望向服务器发送更有意义的数据，例如对象、数组和其他具有自己含义的数据结构。在这些情况下，我们可以简单地将我们的数据序列化为 JSON 字符串。

```js
var player = {
   nickname: 'Juju',
   team: 'Blue'
};

socket.send(JSON.stringify(player));
```

现在，服务器可以接收该消息，并将其作为客户端发送的相同对象结构进行处理，方法是通过 JSON 对象的解析方法运行它。

```js
var player = JSON.parse(event.data);
player.name === 'Juju'; // true
player.team === 'Blue'; // true
player.id === undefined; // true
```

如果您仔细查看上一个示例，您会注意到我们从某个事件对象的`data`属性中提取通过套接字发送的消息。您会问，那个事件对象是从哪里来的？好问题！我们从套接字的`onmessage`事件上注册回调函数的方式在套接字的客户端和服务器端上接收消息是相同的。我们只需在套接字的`onmessage`事件上注册回调函数，每当接收到新消息时，就会调用该回调。传递给回调函数的参数将包含一个名为 data 的属性，其中包含发送的原始字符串对象的消息。

```js
socket.onmessage = function(event) {
   event instanceof MessageEvent; // true

   var msg = JSON.parse(event.data);
};
```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您还可以在 socket 对象上注册回调的其他事件包括`onerror`，每当与 socket 相关的错误发生时触发，以及`onclose`，每当 socket 的状态更改为*CLOSED*时触发；换句话说，每当服务器以任何原因关闭与客户端的连接或连接的客户端关闭其连接时。

如前所述，socket 对象还将具有一个名为`readyState`的属性，其行为类似于 AJAX 对象（或更恰当地说是`XMLHttpRequest`对象）中同名属性。该属性表示连接的当前状态，并且在任何时间点都可以具有四个值之一。该值是一个无符号整数，介于 0 和 3 之间，包括这两个数字。为了清晰起见，在 WebSocket 类上有四个与实例的`readyState`属性的四个数值相对应的常量。这些常量如下：

+   `WebSocket.CONNECTING`：其值为 0，表示客户端和服务器之间的连接尚未建立。

+   `WebSocket.OPEN`：其值为 1，表示客户端和服务器之间的连接已经打开并准备就绪。每当对象的`readyState`属性从 CONNECTING 更改为 OPEN 时（这只会在对象的生命周期中发生一次），将调用`onopen`回调。

+   `WebSocket.CLOSING`：其值为 2，表示连接正在关闭。

+   `WebSocket.CLOSED`：其值为 3，表示连接现在已关闭（或者根本无法打开）。

一旦`readyState`已经更改为新值，它将永远不会在同一 socket 对象实例中返回到先前的状态。因此，如果一个 socket 对象正在 CLOSING 或已经变为*CLOSED*，它将永远不会再次*OPEN*。在这种情况下，如果您希望继续与服务器通信，您将需要一个新的 WebSocket 实例。

总之，让我们总结一下之前讨论过的简单 WebSocket API 功能，并创建一个方便的函数，简化与游戏服务器通信时的数据序列化、错误检查和错误处理：

```js
function sendMsg(socket, data) {
   if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(data));

      return true;
   }

   return false;
};
```

# 游戏客户端

在本章的前面，我们讨论了基于客户端-服务器模式的多人游戏的架构。由于这是我们将在整本书中开发的游戏所采用的方法，让我们定义一些游戏客户端将要履行的主要角色。

从更高的层次来看，游戏客户端将是人类玩家与游戏宇宙的其余部分（包括游戏服务器和连接到它的其他人类玩家）之间的接口。因此，游戏客户端将负责接收玩家的输入，将其传达给服务器，接收服务器的任何进一步指令和信息，然后再次将最终输出呈现给人类玩家。根据所使用的游戏服务器类型（我们将在下一节和未来章节中讨论此问题），客户端可以比仅仅是从服务器接收静态数据的输入应用程序更复杂。例如，客户端很可能会模拟游戏服务器的操作，并将此模拟的结果呈现给用户，而服务器则执行真正的计算并将结果告知客户端。这种技术的最大卖点在于，由于客户端几乎立即响应输入，游戏对用户来说会显得更加动态和实时。

# 游戏服务器

游戏服务器主要负责将所有玩家连接到同一个游戏世界，并保持它们之间的通信。然而，你很快就会意识到，有些情况下，你可能希望服务器比一个路由应用程序更复杂。例如，即使其中一名玩家告诉服务器通知其他参与者游戏结束了，并且发送消息的玩家是赢家，我们可能仍然希望在决定游戏是否真的结束之前确认信息。

有了这个想法，我们可以将游戏服务器标记为两种类型之一：权威或非权威。在权威游戏服务器中，游戏逻辑实际上一直在内存中运行（尽管通常不像游戏客户端一样渲染任何图形输出），每个客户端通过其对应的套接字发送消息将信息报告给服务器，服务器更新当前游戏状态并将更新发送回所有玩家，包括原始发送者。这样我们就可以更加确定从服务器传来的任何数据都经过了验证并且是准确的。

在一个非权威的服务器中，客户端在游戏逻辑执行中扮演了更加重要的角色，这给了客户端更多的信任。正如之前建议的，我们可以取长补短，创造两种技术的混合。在这本书中，我们将拥有一个严格的权威服务器，但客户端是智能的，可以自行完成一些工作。然而，由于服务器对游戏有最终决定权，因此客户端从服务器接收的任何消息都被视为最终真相，并且超越了客户端自己的任何结论。

# 将所有内容整合在一起 - 井字棋

在我们对网络、WebSockets 和多人游戏架构的新知识疯狂之前，让我们通过创建一个非常激动人心的*井字棋*网络游戏，以最简单的方式应用这些原则。我们将使用纯 WebSockets 与服务器通信，服务器将使用纯 JavaScript 编写。由于这个 JavaScript 将在服务器环境中运行，我们将使用**Node.js**（参考[`nodejs.org/`](https://nodejs.org/)），你可能在这一点上对它很熟悉，也可能不熟悉。现在不要太担心 Node.js 的具体细节。我们已经专门为 Node.js 和其相关生态系统的入门编写了一整章。现在，尽量专注于这个游戏的网络方面。

![将所有内容整合在一起 - 井字棋](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_01_05.jpg)

当然，你对*井字棋*很熟悉。两名玩家轮流在一个 9x9 的网格上标记一个方格，谁能标记三个相同的标记，形成水平、垂直或对角线的直线，谁就赢了。如果所有九个方格都被标记，并且之前提到的规则没有被满足，那么游戏就以平局结束。

## Node.js - 宇宙的中心

正如承诺的，我们将在下一章深入讨论 Node.js。现在，只需知道 Node.js 是我们开发策略的基本部分，因为整个服务器将使用 Node 编写，所有其他支持工具都将利用 Node 的环境。我们将在这个第一个演示游戏中使用的设置包含三个主要部分，即**web 服务器**、**游戏服务器**和**客户端文件**（游戏客户端所在的地方）。

![Node.js - 宇宙的中心](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_01_06.jpg)

现在我们需要担心的主要是六个文件。其余的文件都是由 Node.js 和相关工具自动生成的。至于我们的六个脚本，每个脚本的作用如下。

### /Player.js 类

这是一个非常简单的类，主要用于描述游戏客户端和服务器的期望。

```js
/**
 *
 * @param {number} id
 * @param {string} label
 * @param {string} name
 * @constructor
 */
var Player = function(id, label, name) {
    this.id = id;
    this.label = label;
    this.name = name;
};

module.exports = Player;
```

当我们谈论 Node.js 的基础知识时，最后一行将会有更详细的解释。现在，你需要知道的是它使`Player`类在服务器代码以及发送到浏览器的客户端代码中都可用。

此外，我们很可能只需在整个游戏中使用对象字面量来表示我们所抽象出的`player`对象。我们甚至可以使用一个包含这三个值的数组，其中每个元素的顺序代表元素的含义。顺便说一句，我们甚至可以使用逗号分隔的字符串来表示这三个值。

正如你所看到的，通过创建一个全新的类来存储三个简单的值，这里产生了一些冗余，但这使得代码更易于阅读，因为现在我们知道了游戏在请求`Player`时建立的契约。它将期望在那里存在名为`id`、`label`和`name`的属性。

在这种情况下，`id`可以被认为有点多余，因为它的唯一目的是识别和区分玩家。重要的是两个玩家有一个唯一的 ID。标签属性是每个玩家将在棋盘上打印的内容，这也恰好是两个玩家之间的一个唯一值。最后，名称属性用于以人类可读的方式打印每个玩家的名称。

### /BoardServer.js 类

这个类抽象了*井字棋*游戏的表示，定义了一个接口，我们可以在其中创建和管理一个有两个玩家和一个棋盘的游戏世界。

```js
var EventEmitter = require('events').EventEmitter;
var util = require('util');

/**
 *
 * @constructor
 */
var Board = function() {
    this.cells = [];
    this.players = [];
    this.currentTurn = 0;
    this.ready = false;

    this.init();
};

Board.events = {
    PLAYER_CONNECTED: 'playerConnected',
    GAME_READY: 'gameReady',
    CELL_MARKED: 'cellMarked',
    CHANGE_TURN: 'changeTurn',
    WINNER: 'winner',
    DRAW: 'draw'
};

util.inherits(Board, EventEmitter);
```

由于这段代码只打算在服务器上运行，它充分利用了 Node.js。脚本的第一部分导入了两个核心 Node.js 模块，我们将利用它们而不是重新发明轮子。第一个是`EventEmitter`，它允许我们广播关于游戏发生的事件。其次，我们导入一个实用类，让我们轻松地利用面向对象编程。最后，我们定义了一些与`Board`类相关的静态变量，以简化事件注册和传播。

```js
Board.prototype.mark = function(cellId) {
    // …
    if (this.checkWinner()) {
        this.emit(Board.events.WINNER, {player: this.players[this.currentTurn]});
    }
};
```

`Board`类公开了几种方法，驱动程序可以调用这些方法来向其中输入数据，并在发生某些情况时触发事件。正如前面提到的方法所示，每当玩家成功在棋盘上标记一个可用的方块时，游戏就会广播该事件，以便驱动程序知道游戏中发生了什么；然后它可以通过相应的套接字联系每个客户端，并让他们知道发生了什么。

### /server.js 类

在这里，我们有一个驱动程序，它使用我们之前描述的`Board`类来强制执行游戏规则。它还使用 WebSockets 来维护连接的客户端，并处理他们与游戏的个体交互。

```js
var WebSocketServer = require('ws').Server;
var Board = require('./BoardServer');
var Player = require('./Player');

var PORT = 2667;
var wss = new WebSocketServer({port: PORT});
var board = new Board();

var events = {
    incoming: {
        JOIN_GAME: 'csJoinGame',
        MARK: 'csMark',
        QUIT: 'csQuit'
    },
    outgoing: {
        JOIN_GAME: 'scJoinGame',
        MARK: 'scMark',
        SET_TURN: 'scSetTurn',
        OPPONENT_READY: 'scOpponentReady',
        GAME_OVER: 'scGameOver',
        ERROR: 'scError',
        QUIT: 'scQuit'
    }
};

/**
 *
 * @param action
 * @param data
 * @returns {*}
 */
function makeMessage(action, data) {
    var resp = {
        action: action,
        data: data
    };

    return JSON.stringify(resp);
}

console.log('Listening on port %d', PORT);
```

这个 Node.js 服务器脚本的第一部分导入了我们自定义的类（`Board`和`Player`）以及一个方便的第三方库`ws`，它帮助我们实现 WebSocket 服务器。这个库处理诸如初始连接设置、协议升级等事情，因为这些步骤不包括在 JavaScript WebSocket 对象中，该对象只是用作客户端。在一些方便的对象之后，我们有一个等待在`ws://localhost:2667`上连接的工作服务器。

```js
wss.on('connection', function connection(ws) {
    board.on(Board.events.PLAYER_CONNECTED, function(player) {
        wss.clients.forEach(function(client) {
            board.players.forEach(function(player) {
                client.send(makeMessage(events.outgoing.JOIN_GAME, player));
            });
        });
    });

    ws.on('message', function incoming(msg) {
        try {
            var msg = JSON.parse(msg);
        } catch (error) {
            ws.send(makeMessage(events.outgoing.ERROR, 'Invalid action'));
            return;
        }

        try {
            switch (msg.action) {
                case events.incoming.JOIN_GAME:
                    var player = new Player(board.players.length + 1, board.players.length === 0 ? 'X' : 'O', msg.data);
                    board.addPlayer(player);
                    break;
                // ...
            }
        } catch (error) {
            ws.send(makeMessage(events.outgoing.ERROR, error.message));
        }
    });
});
```

这个服务器的其余重要部分发生在中间。为了简洁起见，我们只包括了`Board`类发出的事件的事件处理程序注册的一个示例，以及对套接字接收到的事件注册的`callback`函数。（你是否认出了`ws.on('message', function(msg){})`函数调用？这是 Node 中等价于我们之前讨论的客户端 JavaScript`socket.onmessage = function(event){}`的函数调用。）

这里的重要之处在于我们如何处理来自游戏客户端的消息。由于客户端只能向我们发送单个字符串作为消息，我们如何知道消息是什么？由于客户端可以向服务器发送许多类型的消息，我们在这里创建了自己的小协议。也就是说，每条消息都将是一个序列化的`JSON`对象（也称为对象文字），具有两个属性。第一个属性将以`action`的值为键，第二个属性将以`data`的值为键，具体取决于指定的操作。从这里，我们可以查看`msg.action`的值，并相应地做出响应。

例如，每当客户端连接到游戏服务器时，它会发送一个带有以下值的消息。

```js
{
    action: events.outgoing.JOIN_GAME,
    data: "<player nickname>"
};
```

一旦服务器将该对象作为`onmessage`事件的有效载荷接收，它就可以知道消息的含义以及玩家昵称的预期值。

### /public/js/Board.js 类

这个类与`BoardServer.js`非常相似，主要区别在于它还处理 DOM（即浏览器渲染和管理的 HTML 元素），因为游戏需要呈现给人类玩家。

```js
/**
 *
 * @constructor
 */
var Board = function(scoreBoard) {
    this.cells = [];
    this.dom = document.createElement('table');
    this.dom.addEventListener('click', this.mark.bind(this));
    this.players = [];
    this.currentTurn = 0;
    this.ready = false;

    this.scoreBoard = scoreBoard;

    this.init();
};

Board.prototype.bindTo = function(container) {
    container.appendChild(this.dom);
};

Board.prototype.doWinner = function(pos) {
    this.disableAll();
    this.highlightCells(pos);
};
```

出于简洁起见，我们选择不显示游戏逻辑的大部分内容。这里需要注意的重点是，这个版本的 Board 类非常了解 DOM，并且对游戏决策和游戏规则的执行非常被动。由于我们使用的是权威服务器，这个类会按照服务器的指示进行操作，比如标记自己以指示某个参与者赢得了游戏。

### /public/js/app.js 类

与`server.js`类似，这个脚本是我们游戏的驱动程序。它有两个功能：接收用户输入并驱动服务器，以及使用从服务器接收的输入来驱动棋盘。

```js
var socket = new WebSocket('ws://localhost:2667');

var scoreBoard = [
    document.querySelector('#p1Score'),
    document.querySelector('#p2Score')
];

var hero = {};
var board = new Board(scoreBoard);

board.onMark = function(cellId){
    socket.send(makeMessage(events.outgoing.MARK, {playerId: hero.id, cellId: cellId}));
};

socket.onmessage = function(event){
    var msg = JSON.parse(event.data);

    switch (msg.action) {
        case events.incoming.GAME_OVER:
            if (msg.data.player) {
                board.doWinner(msg.data.pos);
            } else {
                board.doDraw();
            }

            socket.send(makeMessage(events.outgoing.QUIT, hero.id));
            break;

        case events.incoming.QUIT:
            socket.close();
            break;
    }
};

socket.onopen = function(event) {
    startBtn.removeAttribute('disabled');
    nameInput.removeAttribute('disabled');
    nameInput.removeAttribute('placeholder');
    nameInput.focus();
};
```

再次需要注意的是客户端服务器是多么以 DOM 为中心。还要注意客户端对从服务器接收的消息是多么顺从。如果服务器在发送给客户端的消息中指定的操作是`GAME_OVER`，客户端会清理一切，告诉玩家游戏结束了，要么是因为有人赢得了游戏，要么是因为游戏以平局结束，然后告诉服务器它准备断开连接。再次，客户端等待服务器告诉它下一步该做什么。在这种情况下，它等待服务器清理，然后告诉客户端断开连接。

# 摘要

在本章中，我们讨论了网络和网络编程范式的基础知识。我们看到了 WebSockets 如何使得在 HTML5 中开发实时多人游戏成为可能。最后，我们使用广泛支持的 Web 技术实现了一个简单的游戏客户端和游戏服务器，并构建了一个有趣的*井字棋*游戏。

在下一章中，我们将介绍 JavaScript 开发领域的最新技术，包括通过 Node.js 在服务器端使用 JavaScript。本章将教授您使用工作流和资源管理工具（如 NPM、Bower、Grunt 等）来管理 JavaScript 开发周期的当前技术。


# 第二章：设置环境

上一章的目标是介绍使用当前 HTML5 技术进行 JavaScript 多人游戏编程。虽然我们讨论了一个真正的多人游戏的实现，但并没有提到如何管理更复杂的项目。

除了诸如 WebSockets 之类的新技术之外，我们还可以将发生在 Web 平台内的巨大进步归功于已经创建的支持项目管理和 HTML5 和 JavaScript 开发工作流的支持工具。

在本章中，我们将讨论以下原则和概念：

+   在**Node.js**中开发 JavaScript 应用程序

+   编写模块化的 JavaScript 应用程序

+   使用**npm**管理 Node.js 包

+   使用**Bower**管理客户端包

+   自动化 JavaScript 开发

# Node.js 中的 JavaScript 在浏览器之外

不久前，所谓的 Web 开发人员很少使用 JavaScript，只有在 Web 表单需要客户端验证时才会用到。由于 CSS 不像今天这样先进，或者至少没有得到广泛支持，JavaScript 也被用来创建图像滚动效果。不久前，JavaScript 和程序员这两个词是不太搭配的。

然而，时代在变化，技术在进化。如今，合格的 JavaScript 程序员受到追捧，并且相对于其他编程语言的程序员来说，薪酬竞争力非常强。这反映了 JavaScript 语言变得多么受欢迎和强大。

因此，JavaScript 正在稳步从*世界上最被误解的编程语言*（*Crockford*，*Douglas（2001）*。[`javascript.crockford.com/javascript.html`](http://javascript.crockford.com/javascript.html)）变成一个企业级语言，它被用于浏览器内部以及独立程序，包括服务器应用程序。正如上一章所解释和说明的，当它被用于游戏的客户端构建以及游戏服务器时，JavaScript 以不同的方式被使用。

你可能记得游戏服务器不一定要用 JavaScript 编写。事实上，游戏客户端根本不知道服务器是用什么语言编写的，因为它与服务器的所有通信都是通过 WebSocket 协议进行的。然而，由于我们希望最大化我们可以在客户端和服务器之间共享的代码量，同时减少我们编写的总代码量，我们将以一种可以实现代码共享的方式编写我们的游戏。这就是 Node.js 发挥作用的地方。

## Node.js

毫无疑问，你现在应该已经听说过 Node.js 了。对于那些不太确定 Node 实际是什么的人来说，它只是建立在谷歌 Chrome 的 JavaScript 引擎（也称为**V8**）之上的运行时环境。换句话说，Node 既不是 JavaScript 的特殊版本，也不是独立的 JavaScript 引擎，而是一个整个的生态系统，碰巧利用了谷歌的开源 JavaScript 引擎，这可能是当今世界上的七大奇迹之一。

![Node.js](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_02_01.jpg)

值得一提的是 Node.js 的两个特点是它不依赖于浏览器，以及每个 I/O 操作都是异步的。

至于它不是浏览器环境，您不会像在浏览器中那样找到 window 对象。此外，由于 Node.js 环境中不存在浏览器施加的任何限制，您可以充分利用底层操作系统。首先，想象一下到目前为止您一直在使用的服务器端语言，或者您考虑使用来编写我们在第一章中讨论的游戏服务器的任何编程语言，*开始多人游戏编程*。然后，在您的脑海中用 JavaScript 替换该语言。这就是 Node.js 提供的重要优势。

在堆栈的两端（服务器端和客户端）使用 JavaScript 的一些好处包括以下内容：

+   您可以共享为服务器和客户端编写的大量代码

+   您只需要掌握一种语言

+   JavaScript 是一种强大的语言，解决了其他语言中存在的许多问题

+   由于 JavaScript 是单线程的，您永远不会遇到死锁或许多与多线程编程相关的问题

到目前为止，我希望您能够看到 Node.js 在 HTML5 多人游戏开发中有多么基础，或者至少在本书中有多么关键。在我们深入探讨一些基本概念之前，让我们确保您可以在系统上安装和运行它。

## 安装 Node.js

在系统上安装 Node.js 的两种推荐方法是从官方网站[`www.nodejs.org`](http://www.nodejs.org)下载可执行文件，或者通过编译源代码手动安装。根据您选择的操作系统，您还可以通过某些软件包管理系统或类似工具安装它。无论您决定采取哪种方法，请确保安装最新的稳定版本，截至撰写本文时，最新版本是 0.12.0。

一旦您在系统上安装了 Node.js，您可以通过打开终端窗口并输入以下命令来进行测试：

```js
node
console.log('Hello, World!');
```

如果在安装过程中一切顺利，您应该会看到类似于以下截图中显示的输出：

![安装 Node.js](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_02_02.jpg)

您可以通过在终端上运行以下命令来检查已安装的 Node.js 版本：

```js
node --version
```

尽管今天（撰写本文时，即 2015 年初）可用的最新版本是 0.12.0，但本书中描述的所有脚本都是在版本 0.10.25 中编写和测试的。对于向后和向前兼容性问题和疑问，请务必参考 Node.js 的官方待办事项。

# 编写模块化 JavaScript

在 Node.js 出现之前，鉴于 JavaScript 的臭名昭著的限制，开发人员可能对其最大的抱怨是缺乏对模块化开发过程的内置支持。

模块化 JavaScript 开发的最佳实践是在字面对象内创建组件，以某种方式行为类似于命名空间。这个想法是在全局范围内创建一个对象，然后使用该对象内的命名属性来表示您将声明类、函数、常量等的特定命名空间（或至少 JavaScript 等效项）。

```js
var packt = packt || {};
packt.math = packt.math || {};
packt.math.Vec2 = function Vec2(x, y) {// …
};

var vec2d = new packt.math.Vec2(0, 1);
vec2d instanceof packt.math.Vec2; // true
```

在上一个代码片段中，我们在`packt`变量不存在的情况下创建一个空对象。如果存在，我们不会用空对象替换它，而是将一个引用分配给`packt`变量。我们在 math 属性中也是一样，其中我们添加了一个名为`Vec2d`的构造函数。现在，我们可以自信地创建特定向量类的实例，知道如果我们的全局范围内还有其他向量库，即使它也被命名为`Vec2`，它也不会与我们的版本冲突，因为我们的构造函数位于`packt.math`对象内。

虽然这种方法在很长一段时间内运行得相对良好，但它确实有三个缺点：

+   每次键入整个命名空间都需要很多工作

+   不断引用深层嵌套的函数和属性会影响性能

+   您的代码很容易被粗心的赋值替换为顶级 `namespace` 属性

好消息是，今天有一种更好的方法来编写 JavaScript 模块。通过认识到旧方式的缺点，一些提出的标准出现了，以解决这个问题。

## CommonJS

2009 年，Mozilla 的开发人员创建了一个旨在定义一种从浏览器中解放出来的 JavaScript 应用程序的方式的项目。 (参见 [`en.wikipedia.org/wiki/CommonJS`](http://en.wikipedia.org/wiki/CommonJS).) 这种方法的两个显著特点是 `require` 语句，它类似于其他语言提供的功能，以及 `exports` 变量，从这里来的所有代码将被包含在对 require 函数的后续调用中。每个导出的模块都驻留在单独的文件中，这样就可以识别 `require` 语句引用的文件，并隔离组成模块的代码。

```js
// - - - - - - -
// player.js

var Player = function(x, y, width, height) {
   this.x = x;
   this.y = y;
   this.width = width;
   this.height = height;
};

Player.prototype.render = function(delta) {
   // ...
};

module.exports = Player;
```

这段代码在名为 `player.js` 的文件中创建了一个模块。这里的要点如下：

+   您实际模块的内容是您所熟悉和热爱的相同的旧式 JavaScript

+   您希望导出的任何代码都分配给 `module.exports` 变量

在我们讨论如何使用这个模块之前，让我们详细说明之前提到的最后一点。由于 JavaScript 闭包的工作原理，我们可以引用文件中（在文件内部）未直接通过 `module.exports` 导出的值，这些值无法在模块外部访问（或修改）。

```js
// - - - - - - -
// player.js

// Not really a constant, but this object is invisible outside this module/file
var defaults = {
   width: 16,
   height: 16
};

var Player = function(x, y, width, height) {
   this.x = x;
   this.y = y;
   this.width = width || defaults.width;
   this.height = height || defaults.height;
};

Player.prototype.render = function(delta) {
   // ...
};

module.exports = Player;
```

请注意，`Player` 构造函数接受宽度和高度值，这些值将分配给该类实例的本地和对应的宽度和高度属性。但是，如果我们省略这些值，那么我们将回退到 `defaults` 对象中指定的值，而不是将未定义或空值分配给实例的属性。好处是该对象无法在模块外部任何地方访问，因为我们没有导出该变量。当然，如果我们使用 EcmaScript 6 的 `const` 声明，我们可以实现只读的命名常量，以及通过 EcmaScript 5 的 `Object.defineProperty`，将可写位设置为 false。然而，这里的要点仍然是，未导出的模块外部的任何东西都无法直接访问模块中未通过 `module.exports` 导出的值。

现在，为了使用 CommonJs 模块，我们需要确保可以在文件系统中本地访问代码。在其最简单的形式中，一个 require 语句将寻找一个文件（相对于所提供的文件）来包含，其中文件的名称与 require 语句匹配。

```js
// - - - - - - -
// app.js

var Player = require('./player.js');
var hero = new Player(0, 0);
```

要在 app.js 文件中运行脚本，我们可以在与存储 `app.js` 相同的目录中使用以下命令：

```js
node app.js
```

假设 `app.js` 和 `player.js` 文件存储在同一个目录中，Node 应该能够找到名为 `player.js` 的文件。如果 `player.js` 存储在 `app.js` 的父目录中，那么 `require` 语句需要如下所示：

```js
// - - - - - - -
// test/player_test.js

var Player = require('./../player.js');
var hero = new Player(0, 0);
```

正如您将在后面看到的，我们可以使用 Node 的包管理系统非常容易地导入模块或整个库。这样做会使导入的包以一种有条理的方式存储，从而使将它们引入您的代码变得更容易。

另一种导入模块的方式是简单地在 require 语句中包含导出模块的名称，如下所示：

```js
// - - - - - - -
// app.js

var Player = require('player.js');
var hero = new Player(0, 0);
```

如果您运行先前的文件，您将看到一个致命的运行时错误，看起来像以下的屏幕截图：

![CommonJS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_02_03.jpg)

Node 无法找到`player.js`文件的原因是，当我们不使用前导句号指定文件名（这意味着包含的文件是相对于当前脚本的），它会在与当前脚本相同的目录中寻找名为`node_modules`的目录中的文件。

如果 Node 无法在`node_modules`中找到匹配的文件，或者当前目录没有这样命名的目录，它将在与当前脚本的父目录中的`require`语句类似的目录中寻找名为`node_modules`的目录以及同名的文件。如果在那里搜索失败，它将再向上查找一个目录级别，并在那里的`node_modules`目录中寻找文件。搜索将一直持续到文件系统的根目录。

将文件组织成可重用的、自包含模块的另一种方法是将文件捆绑在`node_modules`中的一个目录中，并利用一个代表模块入口点的`index.js`文件。

```js
// - - - - - - -
// node_modules/MyPlayer/index.js

var Player = function(x, y, width, height) {
   this.x = x;
   this.y = y;
   this.width = width;
   this.height = height
};

module.exports = Player;

// - - - - - - -
// player_test.js

var Player = require('MyPlayer');

var hero = new Player(0, 0);
console.log(hero);
```

请注意，模块的名称，在`require`语句中指定的，现在与`node_modules`中的一个目录的名称匹配。当名称不以指示相对或绝对路径的字符（"`/`"，"`./`"或"`../`"）开头，并且文件扩展名被省略时，可以确定 Node 将寻找一个目录而不是与`require`函数中提供的名称匹配的文件。

当 Node 查找目录名称时，如前面的示例所示，它将首先在匹配的目录中查找`index.js`文件并返回其内容。如果 Node 找不到`index.js`文件，它将查找一个名为`package.json`的文件，这是描述模块的清单文件。

```js
// - - - - - - -
// node_modules/MyPlayer/package.json

{
   "name": "MyPlayer",
   "main": "player.js"
}
```

假设我们已将`node_modules/MyPlayer/index.js`文件重命名为`node_modules/MyPlayer/player.js`，一切将与以前一样工作。

在本章后面，当我们谈论 npm 时，我们将更深入地了解`package.json`，因为它在 Node.js 生态系统中扮演着重要的角色。

## RequireJS

试图解决 JavaScript 缺乏本地脚本导入和标准模块规范的另一个项目是 RequireJS。 （参见[`requirejs.org/`](http://requirejs.org/)。）实际上，RequireJS 是**异步模块定义**（**AMD**）规范的一个特定实现。 AMD 是一个定义模块及其依赖项可以异步加载的 API 的规范[Burke，James（2011）。[`github.com/amdjs/amdjs-api/wiki/AMD`](https://github.com/amdjs/amdjs-api/wiki/AMD)]。

CommonJS 和 RequireJS 之间的一个显著区别是，RequireJS 设计用于在浏览器内部使用，而 CommonJS 并没有考虑浏览器。然而，这两种方法都可以适应浏览器（在 CommonJS 的情况下）以及其他环境（在 RequireJS 的情况下）。

与 CommonJS 类似，RequireJS 可以被认为有两部分：一个模块定义脚本和一个消费（或需要）模块的第二个脚本。此外，与 CommonJS 类似但在 RequireJS 中更明显的是，每个应用程序都有一个单一的入口点。这是需要开始的地方。

```js
// - - - - - - -
// index.html

<script data-main="scripts/app" src="img/require.js"></script>
```

在这里，我们在 HTML 文件中包含`require.js`库，指定入口点，这由`data-main`属性表示。一旦库加载，它将尝试加载名为`app.js`的脚本，该脚本位于名为`scripts`的目录中，该目录存储在与主机`index.html`文件相同的路径上。

这里需要注意的两件事是，`scripts/app.js`脚本是异步加载的，而不是使用`script`标签时浏览器默认加载所有脚本的方式。此外，`scripts/app.js`本身可以要求其他脚本，这些脚本将依次异步加载。

按照惯例，入口脚本（在上一个示例中为`scripts/app.js`）将加载一个配置对象，以便 RequireJS 可以适应您自己的环境，然后加载真正的应用程序入口点。

```js
// - - - - - - -
// scripts/app.js

requirejs.config({
    baseUrl: 'scripts/lib',
    paths: {
        app: '../app'
    }
});

requirejs(['jquery', 'app/player'], function ($, player) {
    // ...
});
```

在上一个示例中，我们首先配置了脚本加载器，然后我们需要两个模块——首先是`jQuery`库，然后是一个名为`player`的模块。配置块中的`baseUrl`选项告诉 RequireJS 从`scripts/lib`目录加载所有脚本，这是相对于加载`scripts/app.js`的文件（在本例中为`index.html`）。路径属性允许您对`baseUrl`创建异常，重写以`app`字符串开头的脚本的路径，这被称为**模块 ID**。当我们需要`app/player`时，RequireJS 将加载一个相对于`index.html`的脚本`scripts/app/player.js`。

一旦加载了这两个模块，RequireJS 将调用传递给`requirejs`函数的回调函数，按照指定的顺序将请求的模块作为参数添加进去。

您可能会想知道为什么我们谈论了 CommonJS 和 RequireJS，因为目标是在服务器和客户端之间尽可能共享尽可能多的代码。覆盖两种方法和工具的原因仅是为了完整性和信息目的。由于 Node.js 已经使用 CommonJS 作为其模块加载策略，几乎没有理由在服务器上使用 RequireJS。而不是混合使用 RequireJS 在浏览器中使用，通常做法（这将是本书其余部分的选择）是在所有地方使用 CommonJS（包括**客户端**代码），然后在客户端代码上运行一个名为**Browserify**的工具，使得可以在浏览器中加载使用 CommonJS 的脚本。我们将很快介绍 Browserify。

# 使用 Npm 管理 Node.js 包

Npm 是 JavaScript 的包管理器，类似于 PHP 的**Composer**或 Python 的**Pip**。（转到[`www.npmjs.com/`](https://www.npmjs.com/)。）有些人可能会告诉您 npm 代表 Node Package Manager，但尽管自 0.6.3 版本以来一直是 Node.js 的默认包管理器，npm 并不是一个首字母缩写词。因此，您经常会看到 npm 以小写形式拼写。

要快速检查是否已安装 npm，可以使用终端窗口查询已安装的 npm 版本。

```js
npm -v
```

有关如何在特定操作系统上安装 npm 的说明，请确保您遵循 npm 官方网站上的指南。本书中示例代码和演示应用程序使用的版本是 1.3.10。

使用 npm 安装第三方包时，可以选择将其安装在项目的本地位置，也可以全局安装，以便在系统的任何位置都可见该包。

```js
npm install watch
```

默认情况下，当您安装一个包（在上一个示例中，我们安装了一个名为`watch`的包，用于监视目录和文件的更改）时，如果没有标志，该包将被安装在本地（假设`package.json`文件也存在），并保存到执行命令的相对位置的`node_modules`目录中。

要全局或系统范围安装一个包，只需在安装命令后附加`-g`标志：

```js
npm install watch -g
```

按照惯例，如果您需要一个通过`require`语句在代码中使用的包，您将希望将该包保存在本地。如果意图是从命令行中使用包作为可执行代码，那么通常会希望全局安装它。

如果要在`package.json`清单上构建，以便项目依赖的本地包可以共享并轻松安装，可以手动编辑清单文件，在“`dependencies`”键下的`json`对象中添加依赖项，或者让 npm 为您执行此操作，但不要忘记指定`--save`标志：

```js
npm install watch --save
```

请注意，运行上一个命令将下载组成所请求包的代码到你的工作目录，并更新你的`package.json`清单，以便以后更新包或根据需要重新安装它们。换句话说，你可以随时使用你现有的`package.json`文件来重建你的开发环境，就第三方依赖而言。

一旦你在`package.json`文件中指定了一个或多个依赖项，你可以通过运行 npm 来安装它们，如下所示：

```js
npm install
```

这将下载清单文件中的所有依赖项并保存到`node_modules`中。

同样，你可以通过使用 update 命令通过 npm 更新包：

```js
npm update
```

如果你不知道如何开始创建一个`package.json`清单文件，你可以让 npm 帮助你填写最常见属性的空白部分。

```js
npm init
```

这将加载一个交互式实用程序，要求你为清单的各种属性输入值，比如包名称、版本、作者名称等。它还提供了一些默认值，这样你可以忽略你不知道它们的属性，或者你可以信任 npm 提供的任何后备选项，让你很容易快速获得一个清单文件。

```js
npm init
// … assume all proposed default values

// - - - - - - -
// package.json

{
  "name": "npm",
  "version": "0.0.0",
  "description": "ERROR: No README data found!",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "BSD-2-Clause"
}
```

一旦你有了一个通用的`package.json`清单，你可以用 npm install 命令将你的依赖项添加到其中。

```js
npm install browserify --save

// - - - - - - -
// package.json

{
  "name": "npm",
  "version": "0.0.0",
  "description": "ERROR: No README data found!",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "BSD-2-Clause" ,
  "dependencies": {
    "browserify": "~9.0.3"
  }
}
```

当然，你可以随时手动编辑文件来更改值或删除你认为不必要的属性，比如许可证、描述或版本。有些属性只有在你计划私下或与全局 npm 注册表共享你的包时才有意义。其他值，比如脚本，用于方便开发。例如，我们可以注册一个脚本，当我们运行`npm <script value>`时执行。

```js
// - - - - - - -
// package.json

{
 "scripts": {
    "test": "node test.js"
  }
}

// - - - - - - -
// test.js

console.log('testing npm scripts');
```

因此，我们可以让 Node 通过 npm 运行一个名为`test.js`的脚本，命令如下：

```js
npm test
```

虽然在这种情况下使用 npm 可能不会节省很多输入，但它确实使其他人更容易知道，例如，如何运行你的测试，即使你的测试运行器脚本没有以任何特定的标准形式命名或执行。

# 使用 Bower 管理前端包

如果你对 npm 作为后端 JavaScript 包管理器并不满意，也许 Bower 会让你更加快乐。 （参见[`bower.io/`](http://bower.io/)。）Bower 的工作方式与 npm 非常相似。事实上，我们刚刚讨论的大多数 npm 命令和约定在 Bower 中都可以直接使用。

事实上，Bower 本身是一个通过 npm 安装的 Node.js 模块：

```js
npm install bower -g
```

我们可以以与 npm 相同的方式与 Bower 交互。

```js
bower init
// … using all proposed defaults

// - - - - - - -
// bower.json

{
  name: 'npm',
  version: '0.0.0',
  homepage: 'https://github.com/formigone',
  authors: [
    'Rodrigo Silveira <webmaster@rodrigo-silveira.com>'
  ],
  license: 'MIT',
  ignore: [
    '**/.*',
    'node_modules',
    'bower_components',
    'test',
    'tests'
  ]
}
```

Bower 使用`bower.json`清单文件，到目前为止，这应该对你来说看起来有些熟悉。要安装依赖项，要么手动编辑清单，要么利用 Bower。

```js
bower install jquery –save

// - - - - - - -
// bower.json

{
  name: 'npm',
  version: '0.0.0',
  homepage: 'https://github.com/formigone',
  authors: [
    'Rodrigo Silveira <webmaster@rodrigo-silveira.com>'
  ],
  license: 'MIT',
  ignore: [
    '**/.*',
    'node_modules',
    'bower_components',
    'test',
    'tests'
  ],
  "dependencies": {
    "jquery": "~2.1.3"
  }
}
```

到目前为止，Bower 和 npm 之间的主要区别是，Bower 处理前端依赖项，可以是 JavaScript、CSS、HTML、字体文件等。Bower 将依赖项保存在`bower_components`目录中，类似于 npm 的`node_dependencies`。

## Browserify

最后，让我们使用这个非常方便的 npm 包来利用我们的 CommonJS 模块（以及 Node 的原生模块）在浏览器中使用。这正是 Browserify 的作用：它接受一个入口点脚本，从该文件递归地跟随所有 require 语句，然后内联构建的依赖树中的所有文件，并返回一个单一文件。（参见[`browserify.org/`](http://browserify.org/)。）这样，当浏览器在你的脚本中遇到一个 require 语句时，它不必从文件系统中获取文件；它从同一个文件中获取文件。

```js
sudo npm install browserify -g
```

一旦我们安装了 Browserify（再次强调，因为这是用作命令行工具，我们要全局安装它），我们可以将所有的 CommonJS 文件“捆绑”在一起。

```js
// - - - - - - -
// app.js

var Player = require('MyPlayer');

var hero = new Player(0, 0);
console.log(hero);

// - - - - - - -
// node_modules/MyPlayer/index.js

var defaults = {
   width: 16,
   height: 16
};

var Player = function(x, y, width, height) {
   this.x = x;
   this.y = y;
   this.width = width || defaults.width;
   this.height = height || defaults.height;
};

Player.prototype.render = function(delta) {
   // ...
};

module.exports = Player;
```

Browserify 将负责根据需要引入所有的依赖项，以便输出文件具有所有准备好供使用的依赖项，就像上面的代码示例中所示的那样。

Browserify 将入口点的名称作为第一个参数，并默认将输出打印到标准输出。或者，我们可以指定一个文件名，将捆绑保存在那里。

```js
browserify app.js -o bundle.js
```

Browserify 现在将创建一个名为`bundle.js`的文件，我们可以在 HTML 文件中包含它，并在浏览器中使用。此外，我们可以使用 npm 注册表中的许多可用工具之一来压缩输出文件。

```js
sudo npm install uglify-js -g
uglifyjs bundle.js -o bundle.min.js --source-map bundle.min.js.map
```

运行上述代码将安装一个名为**UglifyJS**的 node 包，它可以非常智能地解析、混淆、压缩和收缩我们的`bundle.js`文件。（参考[`github.com/mishoo/UglifyJS`](https://github.com/mishoo/UglifyJS)。）输出文件将非常小，并且对人类来说完全不可读。作为奖励，它还创建了一个`source map`文件，这样我们就可以通过将其映射回原始的`bundle.js`文件来调试被最小化的文件。

# 自动化您的工作流程

到目前为止，我们已经学会了执行以下任务：

+   编写可导入其他模块的模块化 JavaScript 代码

+   通过 CommonJS 和 Browserify 在客户端和服务器端代码中重用模块

+   使用 npm 管理 node 包

+   使用 Bower 管理客户端包

现在，我们准备以一种方式将所有这些内容整合起来，以便摆脱我们运行所有这些命令的负担。试想一下，如果您必须编写几行代码，保存您的工作，跳到命令行，运行 Browserify，然后运行 Uglify-js，然后运行您的单元测试，然后运行其他几个 npm 工具，最后跳到浏览器，刷新浏览器，看到更新后的应用程序正在运行。哦，等等！您忘记重新启动游戏服务器，它是一个 Node.js 应用程序，在更改这些文件后需要重新启动。所以，您回到终端，运行几个命令，最终，您会在浏览器中看到新的代码。

如果刚才的思维练习让我们所涵盖的这些精彩工具看起来像是很多工作，保持冷静。我们还有另一套工具可以让我们的生活变得更轻松，JavaScript 开发是一种美妙的事情（与通常所说的相反，特别是那些不使用我们将要讨论的工具的人）。

## Grunt

**Grunt**是一个流行的任务运行工具，可以自动化您可能需要执行的重复任务，例如运行单元测试、捆绑组件、缩小捆绑包、从源文件注释创建 API 文档等。（参考[`gruntjs.com/`](http://gruntjs.com/)。）

Grunt 使用插件的概念，这些插件是特定的任务配置，可以共享和重复使用。例如，您可能希望有一个插件来监视目录的更改，然后在触发更改时运行 Browserify。（换句话说，每次保存文件时，都会运行一个任务。）

您可以手动编写自己的插件；尽管这是一个简单的过程，但它足够冗长，所以我们不会在本书中详细介绍。幸运的是，Grunt 有一个庞大的插件列表，几乎包含了您所需的所有插件，或者至少是我们在本书中需要的所有插件。

```js
npm install grunt-cli -g
```

毫不奇怪！我们通过 npm 安装 Grunt。接下来，我们需要使用 npm 和`package.json`安装 Grunt 插件；唯一的区别是我们将它们列在`devDependencies`下，而不是 dependencies 下。

```js
npm install grunt --save-dev
npm install grunt-browserify --save-dev
npm install grunt-contrib-watch --save-dev
npm install grunt-contrib-uglify --save-dev
```

接下来，我们创建一个`Gruntfile.js`来配置我们的任务。这个文件指定了*目标*，并定义了每个目标的行为。大多数情况下，您只需查看您使用的插件的示例配置文件，然后调整它以满足您的需求。

在使用 watch 和 Browserify 的特定情况下，我们只需要告诉 watch 插件在观察到变化时运行 Browserify 任务，并且在 Browserify 任务中，我们需要指定最基本的设置：一个入口文件和一个输出捆绑文件。

构成`Gruntfile`的四个部分如下：

+   一个样板包装函数

+   每个任务的配置

+   手动加载每个任务使用的插件

+   每个任务的注册，以便 Grunt 可以执行它们

```js
// - - - - - - -
// Gruntfile.js
module.exports = function(grunt) {

  grunt.initConfig({
    browserify: {
      client: {
        src: ['./app.js'],
        dest: 'bundle.js'
      }
    },
    watch: {
      files: ['**/*'],
      tasks: ['browserify'],
    }
  });

  grunt.loadNpmTasks('grunt-browserify');
  grunt.loadNpmTasks('grunt-contrib-watch');

  grunt.registerTask('default', ['watch']);

};
```

在`grunt.initConfig`内，您配置每个任务，属性名称与任务名称匹配。然后，您调用`loadNpmTasks`函数加载每个插件并加载相应的依赖项。最后，您指定默认任务以及任何自定义任务，并将它们映射到它们的依赖项。使用任务注册中使用的名称将运行特定的任务。

```js
grunt browserify
```

前面的命令将运行 browserify 任务，该任务已经配置和加载如前所示。如果您运行 grunt 命令而没有指定任务，将运行`default`任务，这种情况下将运行 watch 任务。

## Gulp

**Gulp**是 Grunt 的一个流行的替代品，它声称通过提供更简单的配置来改进 Grunt。（参考[`gulpjs.com/`](http://gulpjs.com/)。）你使用哪种工具取决于你。就像你开什么样的车或者去哪家快餐店一样，使用 Gulp 或 Grunt 完全取决于口味和个人偏好。

```js
npm install gulp -g
npm install gulp-uglify --save-dev
npm install gulp --save-dev
```

Gulp 使用`gulpfile.js`作为其配置文件。

```js
// - - - - - - -
// gulpfile.js

var gulp = require('gulp');
var uglify = require('gulp-uglify');

gulp.task('minify', function () {
   gulp.src('app.js')
      .pipe(uglify())
      .pipe(gulp.dest('build'))
});
```

与 Grunt 相比，前面的配置看起来更加简单。如果你看到一个名为 minify 的任务被注册，它会取一个名为`app.js`的源文件，首先进行 uglify，然后保存到一个构建目录，那么你猜对了。

要运行任务，您可以指定一个默认任务，或者使用以下命令显式运行先前提到的任务：

```js
gulp minify
```

# 总结

在本章中，我们涵盖了很多内容，解释了 Node.js 为我们带来的机会，将 JavaScript 带到服务器上。我们看到了在 JavaScript 中构建可管理的模块的方法，在堆栈的两端共享和重用这些模块，并使用 npm、Bower、Grunt 和 Gulp 等管理和工作流工具来自动化开发过程。

现在，我们已经准备充分利用 Node.js 生态系统以及可用的强大的支持工作流工具。从这里开始，我们将回到编写游戏，通过构建一个有趣的多人蛇游戏。我们将讨论一些概念，这些概念将允许我们将玩家匹配到同一个游戏世界中，这是将玩家带入游戏的基本部分。


# 第三章：实时喂蛇

在现在已经涵盖了介绍性材料之后，是时候让橡皮碰到路了。本章将指导您将单人游戏升级为多人游戏。

与我们在第一章中开发的游戏不同，*开始多人游戏编程*，这款游戏需要实时进行，而不是回合制，这给我们带来了一系列挑战。一旦我们解决了跨两个或更多玩家同步实时游戏世界所涉及的基本问题，我们将研究其他基本但更深入的概念。

在本章中，我们将讨论以下原则和概念：

+   修复您的游戏循环以进行多人游戏

+   实施权威服务器

+   大厅和房间系统

+   匹配算法

+   使用**Socket.io**进行套接字编程

# 游戏开发的 hello world

当你学习编程时，肯定写过一个*hello world*程序。在游戏开发中，我会说每个开发者都应该从经典的*hello world*游戏——贪吃蛇开始。概念很简单：在屏幕上移动一个方块，收集特殊方块，使您的方块拉伸成一系列相连的方块，类似于蛇的移动。如果你把蛇的头撞到它的身体，你就输了。

![游戏开发的 hello world](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_03_01.jpg)

这个实现只允许蛇向上、向下、向左或向右移动。一旦您指定了蛇的移动方向，它将继续沿着该方向移动，直到您将其移动到另一个方向。作为奖励，这个特定的实现允许您在屏幕上环绕——也就是说，如果您移动到屏幕的一侧之外，蛇将出现在相反的一侧。

捕捉红色方块会使蛇增长一个额外的方块，并将您的得分增加 10 分。将蛇撞到自己会停止游戏循环，并打印一个简单的游戏结束消息。

为了使这个初始版本保持简单，没有任何额外的屏幕，包括主入口屏幕。游戏加载完毕后游戏就开始了。随着我们在这个单人版本的游戏上进行扩展，我们将添加必需的屏幕，使其更直观和用户友好，以便多个玩家加入游戏。

## 设置游戏

这个初始的单人版本的游戏的目标是使用尽可能少的代码制作一个可玩的游戏，使用我们可以构建的最基本的模型。因此，许多额外的细节留作练习。

为了为游戏添加服务器端组件做好准备，我们使用 Node.js 编写了游戏的第一个版本，并使用 Browserify 将其导出到浏览器中，如第二章中所讨论的那样，*设置环境*。

### package.json

为了使一切尽可能简单，我们将使用一个`package.json`文件，它只需要**Express**框架来帮助我们进行路由和 Grunt 插件来帮助我们使用 Browserify 自动构建和导出我们的模块：

```js
// ch3/package.json
{
    "name": "snake-ch3",
    "dependencies": {
        "express": "*",
        "express-generator": "*"
    },
    "devDependencies": {
        "grunt": "~0.4.5",
        "grunt-browserify": "~3.4.0",
        "grunt-contrib-uglify": "~0.8.0",
        "grunt-contrib-watch": "~0.6.1"
    }
}
```

### 注意

**Express.js**是一个用于 Node.js 的 Web 框架，它允许我们非常快速地设置整个 Web 服务器来托管和提供我们的游戏。（参考[`expressjs.com/`](http://expressjs.com/)。）虽然 Express 在我们的项目中扮演着重要角色，因为它路由用户请求以获取适当的文件，但了解它的工作原理并不是本章或本书的先决条件。我们将涵盖足够的绝对基础知识，让您开始使用这个强大的框架。

有了这一切，我们使用 Express 命令行工具来构建项目。

```js
npm install
express snake-ch3
cd snake-ch3
npm install

```

执行上述命令序列后，我们已经设置好了我们的 Node.js 服务器的样板，其中包括 Express 的所有默认设置，对于我们的目的来说，这将完全正常工作。如果由于任何原因出现问题，将会有足够的错误消息帮助您理解问题所在。假设在输入上述命令后一切都进行得很顺利，您现在可以通过以下命令启动服务器来测试项目：

```js
npm start

```

这将在端口`3000`上启动服务器，您可以在现代浏览器上加载`http://localhost:3000/`。

![package.json](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_03_03.jpg)

项目结构现在看起来像前面的屏幕截图中的那样，除了红框内的文件不会被 Express Generator 生成。我们将手动创建和编辑这些文件，您将在接下来的几节中看到。

### Index.jade

默认情况下，Express 会创建一个显示欢迎消息的索引文件。由于我们现在只需要一个屏幕来显示游戏，我们将编辑这个文件以满足我们自己的目的：

```js
// ch3/snake-ch3/views/index.jade
extends layout

block content
  div#gameArea
    p#scoreA SCORE: <span>000000</span>
    p#gameOver.animated.pulse.hidden Game Over
    canvas#gameCanvas
    div#statsPanel
  script(src='/js/app.build.js')
```

如果你用力眨眼，你会看到 HTML 标记。如果你不熟悉 Express 默认使用的 Jade 模板语言，不用担心。在模板中，我们创建了一个`<p>`元素，用来显示当前得分，一个用于游戏结束消息的元素，以及一个用来渲染游戏的 canvas 元素。我们还包括了主脚本文件，这是 Grunt 任务的输出，它将所有文件连接起来，并在它们上运行 Browserify，以便我们可以在浏览器中加载它。由于`index.jade`是本书中我们将看到的 Jade 的唯一内容，我们不会进一步深入讨论。有关 Jade 的工作原理和功能的更多信息，请访问其网站[`www.jade-lang.com`](http://www.jade-lang.com)。

## 游戏模块

有了上述结构，现在我们所需要的只是实现游戏的几个类。我们将用五个类来实现这个，这样当我们实现游戏服务器时，我们可以重用单独的逻辑片段。

### Game.js

这是我们将实现的`game.js`文件：

```js
// ch3/snake-ch3/share/game.js
var Game = function (fps) {
    this.fps = fps;
    this.delay = 1000 / this.fps;
    this.lastTime = 0;
    this.raf = 0;

    this.onUpdate = function (delta) {
    };
    this.onRender = function () {
    };
};

Game.prototype.update = function (delta) {
    this.onUpdate(delta);
};

Game.prototype.render = function () {
    this.onRender();
};

Game.prototype.loop = function (now) {
    this.raf = requestAnimationFrame(this.loop.bind(this));

    var delta = now - this.lastTime;
    if (delta >= this.delay) {
        this.update(delta);
        this.render();
        this.lastTime = now;
    }
};

Game.prototype.start = function () {
    if (this.raf < 1) {
        this.loop(0);
    }
};

Game.prototype.stop = function () {
    if (this.raf > 0) {
        cancelAnimationFrame(this.raf);
        this.raf = 0;
    }
};

module.exports = Game;
```

这个模块是我们项目的基石。它定义了一个非常简单的接口，抽象了一个简单的游戏循环。当我们实现这个类时，我们所需要做的就是定义`update()`和`render()`方法。

您会注意到使用了`requestAnimationFrame`，这是浏览器定义的一个特殊函数，帮助我们渲染游戏。由于游戏服务器不会渲染游戏，它也不会有这个函数可用，所以当我们开始在服务器上工作时，我们需要适应这一点。我们将在下一节更多地讨论帧速率的独立性。

### snake.js

我们将向我们的`snake.js`文件添加以下代码：

```js
// ch3/snake-ch3/share/snake.js
var keys = require('./keyboard.js');
var EventEmitter = require('events').EventEmitter;
var util = require('util');

var Snake = function (id, x, y, color_hex, width, height) {
    this.id = id;
    this.color = color_hex;
    this.head = {x: x, y: y};
    this.pieces = [this.head];
    this.width = width || 16;
    this.height = height || 16;
    this.readyToGrow = false;
    this.input = {};
};

Snake.events = {
    POWER_UP: 'Snake:powerup',
    COLLISION: 'Snake:collision'
};

util.inherits(Snake, EventEmitter);

Snake.prototype.setKey = function (key) {
    this.input[keys.UP] = false;
    this.input[keys.DOWN] = false;
    this.input[keys.LEFT] = false;
    this.input[keys.RIGHT] = false;
    this.input[key] = true;
};

Snake.prototype.update = function (delta) {
    if (this.readyToGrow) {
        this.pieces.push({x: -10, y: -10});
        this.readyToGrow = false;
    }

    for (var len = this.pieces.length, i = len - 1; i > 0; i--) {
        this.pieces[i].x = this.pieces[i - 1].x;
        this.pieces[i].y = this.pieces[i - 1].y;
    }

    if (this.input[keys.LEFT]) {
        this.head.x += -1;
    } else if (this.input[keys.RIGHT]) {
        this.head.x += 1;
    } else if (this.input[keys.UP]) {
        this.head.y += -1;
    } else if (this.input[keys.DOWN]) {
        this.head.y += 1;
    }
};

Snake.prototype.checkCollision = function(){
    var collide = this.pieces.some(function(piece, i){
        return i > 0 && piece.x === this.head.x && piece.y === this.head.y;
    }, this);

    if (collide) {
        this.emit(Snake.events.COLLISION, {id: this.id, point: this.head, timestamp: performance.now()});
    }
};

Snake.prototype.grow = function() {
    this.readyToGrow = true;
    this.emit(Snake.events.POWER_UP, {id: this.id, size: this.pieces.length, timestamp: performance.now()});
};

module.exports = Snake;
```

蛇类扩展了 Node 的`EventEmitter`类，以便它可以向主应用程序发出事件。这样我们就可以隔离类的具体行为，并将其与任何根据我们的选择对蛇作出响应的具体实现解耦。

我们还创建了一个简单的界面，主应用程序可以使用它来控制蛇。同样，由于此版本的即时目标是在浏览器中运行游戏，我们将利用浏览器特定的功能，这种情况下是`window.performance.now()`，当需要时我们将用兼容 Node.js 的模块替换它。

## 其他支持模块

还有三个其他类（即`fruit.js`，`keyboard.js`和`renderer.js`），它们仅仅包装了 canvas 和 canvas 上下文对象，一个 JavaScript 等价的枚举，帮助我们引用键盘输入，以及一个简单的点，我们将用它来表示蛇将吃的小球。为简洁起见，我们将省略这些类的代码。

### app.client.js

这是我们的`app.client.js`模块应该是什么样子的：

```js
// ch3/snake-ch3/share/app.client.js
game.onUpdate = function (delta) {
    var now = performance.now();

    // Check if there's no fruits left to be eaten. If so, create a new one.
    if (fruits.length < 1) {
        fruitDelta = now - lastFruit;

        // If there's been enough time without a fruit for the snakes,
        // create a new one at a random position, and place it in the world
        if (fruitDelta >= fruitDelay) {
            fruits[0] = new Fruit(
              parseInt(Math.random() * renderer.canvas.width / BLOCK_WIDTH / 2, 10),
              parseInt(Math.random() * renderer.canvas.width / BLOCK_HEIGHT / 2, 10),
              '#c00', BLOCK_WIDTH, BLOCK_HEIGHT
         );
        }
    }

    player.update(delta);
    player.checkCollision();

    // Check if the snake has gone outside the game board.
    // If so, wrap it around to the other side
    if (player.head.x < 0) {
        player.head.x = parseInt(renderer.canvas.width / player.width, 10);
    }

    if (player.head.x > parseInt(renderer.canvas.width / player.width, 10)) {
        player.head.x = 0;
    }

    if (player.head.y < 0) {
        player.head.y = parseInt(renderer.canvas.height / player.height, 10);
    }

    if (player.head.y > parseInt(renderer.canvas.height / player.height, 10)) {
        player.head.y = 0;
    }

    // Check if there's a fruit to be eaten. If so, check if the snake has just
    // eaten it. If so, grow the player that ate it.
    if (fruits.length > 0) {
        if (player.head.x === fruits[0].x && player.head.y === fruits[0].y) {
            fruits = [];
            player.grow();
            lastFruit = now;
        }
    }
};

game.onRender = function () {
    ctx.clearRect(0, 0, renderer.canvas.width, renderer.canvas.height);

    ctx.fillStyle = player.color;
    player.pieces.forEach(function(piece){
        ctx.fillRect(
           piece.x * player.width,
           piece.y * player.height,
           player.width,
           player.height
        );
    });

    fruits.forEach(function(fruit){
        ctx.fillStyle = fruit.color;
        ctx.fillRect(
           fruit.x * fruit.width,
           fruit.y * fruit.height,
           fruit.width,
           fruit.height
        );
    });
};
```

`app.client` 模块的第一部分是游戏的具体实现，它导入所有必需的类和模块，并实例化游戏循环和玩家类。接下来（如前所述），我们实现了两个游戏循环生命周期方法，即 `update` 和 `render` 方法。当我们添加多人游戏功能时，我们需要对这两个方法进行的唯一更改是更新和渲染一组蛇，而不是单个蛇。

由于每个玩家的实际更新都委托给了 `snake` 类本身，游戏循环对该方法内部的操作没有任何问题。事实上，游戏循环甚至不关心 `update` 方法的输出，我们稍后会看到。关键在于游戏循环的 `update` 方法允许游戏中的每个实体在更新阶段更新自身。

同样，在渲染阶段，游戏循环只关心渲染它想要渲染的每个实体的当前状态。虽然我们也可以委托蛇和其他可视实体的渲染，但为了简单起见，我们将具体的渲染留在游戏循环内部。

最后，在 `app.client` 模块的末尾，我们连接到我们关心的传入事件。在这里，我们监听由 `snake` 对象创建的游戏事件。`Snake.events.POWER_UP` 和 `Snake.events.COLLISION` 自定义事件让我们执行回调函数，以响应蛇吃掉颗粒和与自身碰撞时的情况。

接下来，我们绑定键盘并监听按键事件。由于我们实现的游戏机制，我们不关心未被按下的任何键，这就是为什么我们不为这些事件注册任何监听器。这段代码块将来可以进行重构，因为客户端接收此类输入的方式将与服务器不同。例如，客户端仍然会直接从用户那里接收输入，使用相同的键盘事件作为输入，但服务器将从用户那里接收此输入，通过套接字连接通知服务器其状态：

```js
// whenever we receive a POWER_UP event from the game, we
// update the player's score and display its value inside scoreWidget.
player.on(Snake.events.POWER_UP, function(event){
    var score = event.size * 10;
    scoreWidgets.filter(function( widget){
        return widget.id === event.id;
    })
        .pop()
        .el.textContent = '000000'.slice(0, - (score + '').length) + score + '';
});

// whenever we receive a COLLISION event from the game, we
// stop the game and display a game over message to the player.
player.on(Snake.events.COLLISION, function(event){
    scoreWidgets.filter(function(widget){
        return widget.id === event.id;
    })
        .pop()
        .el.parentElement.classList.add('gameOver');

    game.stop();
    setTimeout(function(){
        ctx.fillStyle = '#f00';
        ctx.fillRect(event.point.x * player.width, event.point.y * player.height, player.width, player.height);
    }, 0);

    setTimeout(function(){
        gameOver.classList.remove('hidden');
    }, 100);
});

document.body.addEventListener('keydown', function (e) {
    var key = e.keyCode;

    switch (key) {
        case keys.ESC:
            game.stop();
            break;
        case keys.SPACEBAR:
            game.start();
            break;
        case keys.LEFT:
        case keys.RIGHT:
        case keys.UP:
        case keys.DOWN:
            player.setKey(key);
            break;
        case keys.D:
            console.log(player.pieces);
            break;
    }
});
```

# 游戏循环

正如你所知，游戏循环是任何实时游戏的核心。尽管游戏循环的功能相当简单，但现在让我们考虑一下同时运行游戏服务器和客户端的一些影响。

## 帧率独立性

游戏循环的目的只是确保游戏以一致有序的方式运行。例如，如果我们在更新游戏状态之前绘制当前游戏状态，玩家在与游戏交互时可能会发现游戏略微不同步，因为当前显示的内容至少会比玩家期望的要滞后一个帧。

此外，在 JavaScript 的基于事件的输入系统中，如果我们每次从用户那里接收输入就更新游戏，可能会导致游戏的不同部分在不同时间更新，使体验更加不同步。

因此，我们设置了游戏循环，以确保在处理和缓存任何输入之后，直到游戏循环的下一个 `tick`，我们可以在游戏步骤的 `update` 阶段应用输入，然后渲染更新的结果：

帧率独立性

这个问题最明显的解决方案是在游戏中建模输入空间；然后，在 `update` 阶段查询并相应地做出响应。在其他编程环境中，我们可以直接查询输入设备。由于 JavaScript 暴露事件，我们无法询问运行时左键当前是否被按下。

接下来，我们需要更新游戏，这在大多数情况下意味着我们会微调一些东西。在更新了几帧之后，我们在每次迭代中更新的这些小动作将合并在一起，形成平滑的运动。实际上，一旦游戏循环完成一个周期，我们需要再次调用游戏循环以进行下一个周期的循环：

```js
while (true) {
   update();
   render();
}
```

在大多数其他编程语言中，传统的游戏循环可能看起来像前面的代码片段，但在 JavaScript 中我们不能这样做，因为 while 循环会阻塞 JavaScript 的单个线程，导致浏览器锁死：

```js
function tick() {
   setTimeout(tick, 0.016);
   update();
   render();
}
```

在 JavaScript 中更合适的方法是使用定时器函数（`setTimeout`或`setInterval`）之一来调用游戏步骤方法。虽然这个解决方案实际上是有效的，不像 while 循环的想法，但我们可能会遇到一些问题，比如游戏消耗太多 CPU（以及移动设备的电池寿命），特别是当游戏不运行时循环继续执行。如果 JavaScript 忙于其他事情，定时器方法也可能会出现问题，`tick`函数无法像我们希望的那样频繁地被调用。

### 注意

也许你会想知道为什么我们在`tick`方法的开头而不是结尾调用`setTimeout`和`requestAnimationFrame`，而不是在方法内部的代码实际执行后。

之所以这样做是因为调用这两个函数中的任何一个都只是简单地安排`callback`函数在下一个事件循环周期运行。调用`setTimeout`或`requestAnimationFrame`会立即将执行返回给调用它的函数的下一个命令，然后函数的其余部分执行完成。

一旦函数返回，JavaScript 将执行事件循环中添加的下一个代码片段，换句话说，如果 JavaScript 在执行我们的游戏`tick`方法或其他事件发生时检测到用户输入，这些事件将被添加到队列中，并在 tick 方法返回后处理。因此，如果我们等到 tick 方法的结尾再次使用事件循环调度它，我们可能会发现 tick 方法在排队等候（以便它可以再次获得 CPU 的使用权）之前，其他回调将被处理。

通过提前调度`tick`方法，我们可以确保它在当前执行完成后尽快再次被调用，即使在当前执行期间触发了其他事件，并且其他代码被放入事件循环中。

最后，在 JavaScript 中编写游戏循环的最合适的方法是使用较新的`window.requireAnimationFrame`函数：

```js
function tick(timestamp) {
   var rafId = requestAnimationFrame(tick);
   update();
   render();
}
```

`requestAnimationFrame`是浏览器中实现的一个方便的函数，我们可以使用它来要求浏览器在进行下一次重绘之前调用我们的回调函数。由于浏览器内部工作超出了 JavaScript 的范围，刷新率现在处于操作系统级别，这更加精确。此外，由于浏览器知道何时需要重绘，并且比 JavaScript 更接近显示设备，它可以进行许多我们无法做到的优化。

调用`requestAnimationFrame`将返回一个整数值，该值将映射到回调列表中提供的函数。我们可以使用这个 ID 号来取消触发我们的回调，当浏览器确定它应该触发时。这是一种方便的方法，可以暂停游戏循环的执行，而不需要在回调的开头使用条件语句，这通常大部分时间都会评估为 false（或者我们希望如此）。

最后，我们提供给`RequestAnimationFrame`的回调函数将会传递一个时间戳数值，格式为`DOMHighResTimeStamp`类型。这个时间戳代表了在给定周期内，使用`RequestAnimationFrame`注册的回调被触发的时间。我们可以使用这个数值来计算自上一帧以来的时间差，从而将我们的游戏循环脱离时间空间连续性，接下来我们将讨论这一点。

## 基于时间的游戏循环

现在我们已经有了一种有效的方法，可以使我们的游戏更新速度与底层硬件的能力一样快，我们只需要控制更新发生的速率。一种选择是确保游戏循环在至少经过一定时间后才再次执行。这样我们就不会更新得比我们必须要更新的更频繁。另一种选择是计算上一次更新所花费的时间，并将该数字发送到更新函数中，以便根据时间差移动所有内容：

![基于时间的游戏循环](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_03_05.jpg)

如前图所示，如果我们在一个浏览器或设备上以两倍的速度更新游戏，那么更新单帧所需的时间（也称为**时间差**）也会减半。使用这个时间差作为物理更新的因素，我们可以使每次更新相对于更新单帧所需的时间。换句话说，在整整一秒钟内，我们可以选择在几次更新中每次更新的幅度更大，或者在同一秒内多次更新游戏，但每次更新的幅度更小。在一秒结束时，我们仍然会移动相同的距离。

## 多个游戏循环

在不同的 CPU 上平稳一致地运行游戏本身就是一种胜利。既然我们已经过了这一关，现在让我们考虑如何在客户端和服务器上实现这一点。

在浏览器上，我们可以使用`requestAnimationFrame`来为用户运行游戏，就像之前演示的那样。然而，在服务器上，没有`requestAnimationFrame`。更糟糕的是，我们无法以每秒 60 次的速度将更新发送到所有参与者。理论上，我们完全可以这样做——也许在服务器在短短几秒内就会过热并崩溃之前。换句话说，对于同一服务器中的每个游戏来说，每秒运行 60 次更新会给服务器带来巨大的负载。因此，我们需要减慢服务器上更新的速度。

首先，由于 Node.js 中没有`requestAnimationFrame`，我们知道我们不能使用它。然而，由于游戏服务器的游戏循环的具体实现与游戏客户端的游戏循环是分开的，我们可以选择 Node 提供的另一种计时器机制。

其次，我们需要在服务器上运行第二个计时器，以便以更慢的速度向客户端发送更新。如果我们实际上尝试以每秒 60 帧的速度向每个客户端发送更新，我们很快就会使服务器过载，并且性能会下降。

解决客户端更新问题的方法是以更慢但一致的速度发送更新，允许服务器以可扩展的方式成为游戏状态的最终权威。在服务器发送更新之间，如果游戏需要更快的更新，我们可以让游戏客户端以最佳方式更新自身；然后，一旦它从服务器接收到信息，我们可以根据需要修复客户端状态。

在 Node.js 中，有两个常用的计时器函数，可以作为`setTimeout()`的高分辨率替代品。这两个函数分别是`setImmediate()`和`process.nextTick()`。你会选择使用这两个函数而不是`setTimeout()`的原因是因为`setTimeout()`不能保证你指定的延迟，也不能保证事件执行的顺序。

作为更好的替代方案，我们可以使用`setImmediate`来安排一个回调，在当前坐在事件队列上的每个事件之后运行。我们还可以使用`process.nextTick`，它将安排回调在当前代码块执行完毕后立即运行。

虽然`process.nextTick`似乎是两者之间更好的选择，但请记住它不会给 CPU 执行事件队列中的其他代码的机会（或允许 CPU 休息），导致执行占用 CPU 的 100％。因此，在您的 Node.js 游戏模拟中的游戏循环的特定用例中，您可能最好使用`setImmediate`。

如前所述，游戏服务器将运行两个定时器或循环。第一个是物理更新循环，将使用`setImmediate`来尝试以完整的 60 fps 高效运行。第二个将是客户端同步循环，不需要运行得那么快。

客户端同步循环的目的是权威性地告诉客户端游戏的真实状态，以便每个客户端可以更新自身。如果我们试图让服务器在每一帧调整每个客户端，游戏和服务器都会变得非常缓慢。一个简单而广泛使用的解决方案是每秒只同步几次客户端。与此同时，每个客户端可以在本地玩游戏，然后在服务器更新其状态时进行任何必要的更正。

# 实施权威服务器

这个服务器的策略是为了两个不同的目的运行两个游戏循环。第一个循环是物理更新，我们会以接近客户端循环频率的频率运行。第二个循环，我们称之为客户端同步循环，以较慢的速度运行，并在每个时刻将整个游戏状态发送给每个连接的客户端。

此时，我们只关注让服务器按照我们描述的方式工作。客户端的当前实现将继续像以前一样工作，本地管理整个游戏逻辑。客户端从服务器接收的任何数据（使用游戏同步循环）将只被渲染。在本书的后面，我们将讨论客户端预测的概念，其中我们将使用游戏同步循环的输入作为游戏逻辑的实际输入，而不仅仅是无意识地渲染它。

## 游戏服务器接口

从当前游戏客户端的实现中要改变的第一件事是分解输入和输出点，以便它们可以与中间的套接字层通信。我们可以将其视为一个编程接口，指定服务器和客户端将如何通信。

为此，让我们在项目中创建一个简单的模块，作为 JavaScript 中没有枚举的可怜之人的枚举。尽管此模块中的数据不是不可变的，但它将给我们带来优势，因为 IDE 将自动建议值，在我们犯拼写错误时纠正我们，并将我们所有的意图放在一个地方。按照惯例，任何以*server*_ 开头的事件代表服务器的操作。例如，名为`server_newRoom`的事件要求服务器创建一个新房间：

```js
// ch3/snake-ch3/share/events.js

module.exports = {
    server_spawnFruit: 'server:spawnFruit',
    server_newRoom: 'server:newRoom',
    server_startRoom: 'server:startRoom',
    server_joinRoom: 'server:joinRoom',
    server_listRooms: 'server:listRooms',
    server_setPlayerKey: 'server:setPlayerKey',

    client_newFruit: 'client:newFruit',
    client_roomJoined: 'client:roomJoined',
    client_roomsList: 'client:roomsList',
    client_playerState: 'client:playerState'
};
```

我们现在使用此模块中定义的字符串值来注册回调并以一致和可预测的方式在客户端和服务器之间发出套接字事件。例如，当我们发出名为`modules.exports.server_spawnFruit`的事件时，我们知道意图是让服务器接收到一个名为`spawnFruit`的动作。此外，您会注意到我们将使用`socket.io`来抽象化客户端和服务器之间的套接字通信。如果您现在想开始使用`socket.io`，请随时跳到本章末尾并阅读*Socket.io*部分。

```js
var gameEvents = require('./share/events.js');

socket.on(gameEvents.server_spawnFruit, function(data){
   var pos = game.spawnFruit(data.roomId, data.maxWidth, data.maxHeight);

   socket.emit(gameEvents.client_newFruit, pos);
});
```

在给定的示例中，我们首先将我们的模块包含到`gameEvents`变量中。然后，我们注册一个回调函数，每当套接字接收到`server_spawnFruit`事件时就会调用该函数。据推测，这段代码在某个服务器代码中，因为键名开头的 server 关键字指示了这一点。这个回调函数接受一个由客户端创建的数据参数（在套接字的另一端发送命令的人）。这个数据对象包含了生成游戏中新水果对象所需的数据。

接下来，我们使用套接字事件中的输入数据执行一些任务（在这种情况下，我们生成一个随机位置，可以在游戏世界中添加水果）。有了这些数据，我们向客户端发出一个套接字命令，发送我们刚刚生成的位置。

## 更新游戏客户端

在客户端代码中要改变的第一件事是添加不同的屏幕。至少，我们需要两个不同的屏幕。其中一个屏幕将是游戏板，就像我们迄今为止实现的那样。另一个是大厅，我们稍后会详细讨论。简而言之，大厅是玩家在加入特定房间之前所在的区域，我们稍后也会讨论。

![更新游戏客户端](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/mtpl-gm-dev-h5/img/B04669_03_06.jpg)

在大厅中，玩家可以选择加入现有房间或创建并加入一个没有玩家的新房间。

在一个完美的世界中，你的游戏引擎会为多个屏幕提供很好的支持。由于我们正在编写的示例游戏不是用这样的游戏引擎编写的，我们将只使用基本的 HTML 和 CSS，并在同一个 HTML 文件中编写每个屏幕以及任何支持的道具和小部件：

```js
// ch3/snake-ch3/views/index.jade

extends layout

block content
  div#lobby
    h1 Snake
    div#roomList

 div#main.hidden
    div#gameArea
      p#scoreA SCORE: <span>000000</span>
      p#gameOver.animated.pulse.hidden Game Over
      canvas#gameCanvas
      div#statsPanel

  script(src='/js/socket.io.js')
  script(src='/js/app.build.js')
```

在上一个模板中只有三个代码块。首先，我们有一个 ID 为`lobby`的`div`元素，其中我们动态添加了一个可用游戏房间的列表。接下来，有一个 ID 为`main`的`div`元素，最初带有一个名为`hidden`的类，因此这个屏幕最初是不可见的。最后，我们包括了`socket.io`库以及我们的应用程序。

绑定到 HTML 结构的最简单方法是创建模块范围的全局变量，引用每个所需的节点。一旦这些引用就位，我们就可以附加必要的事件侦听器，以便玩家可以与界面交互：

```js
// ch3/snake-ch3/share/app.client.js

var roomList = document.getElementById('roomList');
var screens = {
    main: document.getElementById('main'),
    lobby: document.getElementById('lobby')
};

// …

socket.on(gameEvents.client_roomsList, function (rooms) {
    rooms.map(function (room) {
        var roomWidget = document.createElement('div');
        roomWidget.textContent = room.players.length + ' player';
        roomWidget.textContent += (room.players.length > 1 ? 's' : '');

        roomWidget.addEventListener('click', function () {
            socket.emit(gameEvents.server_joinRoom, {
                    roomId: room.roomId,
                    playerId: player.id,
                    playerX: player.head.x,
                    playerY: player.head.y,
                    playerColor: player.color
                }
            );
        });

        roomList.appendChild(roomWidget);
    });

    var roomWidget = document.createElement('div');
    roomWidget.classList.add('newRoomWidget');
    roomWidget.textContent = 'New Game';

    roomWidget.addEventListener('click', function () {
        socket.emit(gameEvents.server_newRoom, {
            id: player.id,
            x: player.head.x,
            y: player.head.y,
            color: player.color,
            maxWidth: window.innerWidth,
            maxHeight: window.innerHeight
        });
    });

    roomList.appendChild(roomWidget);
});

socket.on(gameEvents.client_roomJoined, function (data) {
    // ...
    screens.lobby.classList.add('hidden');
    screens.main.classList.remove('hidden');
});
```

由于初始游戏屏幕是大厅，并且大厅的标记已经可见，我们不需要做其他设置。我们只需注册一个套接字回调，当我们收到可用房间列表时就调用它，并在准备好时将单独的 HTML 节点附加到 DOM 上。

在不同的套接字回调函数内部，这次是与`roomJoined`自定义事件相关联的回调函数，我们首先使大厅屏幕不可见，然后使主屏幕可见。我们通过添加和移除名为 hidden 的 CSS 类来实现这一点，其定义如下代码片段所示：

```js
// ch3/snake-ch3/public/css/style.css

.hidden {
    display: none;
}
```

# 理解游戏循环

我们需要对原始游戏代码进行的下一组更改是在`game`类中。你会记得，这个类定义了一个基本的游戏生命周期，暴露了`update`和`render`函数，由使用它的人来实现。

由于在这个类中定义的游戏循环的核心（在`Game.prototype.loop`中找到）使用了`window.requestAnimationFrame`，我们需要摆脱这个调用，因为它在 Node.js（或者在浏览器之外的任何其他环境）中都不可用。

通常用于允许我们灵活地编写一个既在浏览器中使用又在服务器中使用的单个模块的技术是将浏览器和服务器特定的函数封装在一个自定义模块中。

使用 Browserify，我们可以编写两个分开的模块，包装环境特定的功能，但在代码中只引用一个。通过配置 Browserify 属性，我们可以告诉它在看到对自定义包装模块的`require`语句时编译不同的模块。为简单起见，我们只在这里提到了这种能力，但在本书中我们不会深入讨论。相反，我们将编写一个单一组件，它可以在运行时自动检测所处的环境并做出相应的响应。

```js
// ch3/snake-ch3/share/tick.js
var tick = function () {
    var ticks = 0;
    var timer;

    if (typeof requestAnimationFrame === 'undefined') {
        timer = function (cb) {
            setTimeout(function () {
                cb(++ticks);
            }, 0);
        }
    } else {
        timer = window.requestAnimationFrame;
    }

    return function (cb) {
        return timer(cb);
    }
};

module.exports = tick();
```

tick 组件由一个函数组成，根据`window.requestAnimationFrame`的可用性返回两个函数中的一个。这种模式一开始可能看起来有些混乱，但它的好处在于它只在初始设置之后检测环境一次，然后每次都根据环境进行特定功能。

请注意，我们从这个模块导出的是对`tick`的调用，而不仅仅是一个引用。这样，当我们需要这个模块时，在客户端代码中被引用的是`tick`返回的函数。在浏览器中，这将是对`window.requestAnimationFrame`的引用，在 node 中，它将是一个调用`setTimeout`的函数，通过向其传递一个递增的数字，类似于浏览器版本的`tick`。

## 游戏客户端的游戏循环

现在，抽象的游戏循环类已经准备在任何环境中使用，让我们看看如何重构现有的客户端实现，以便它可以由连接到权威服务器的 socket 驱动。

请注意，我们不再确定何时生成新的水果。在客户端上，我们只检查如何移动玩家角色。我们可以让服务器告诉我们每一帧蛇在哪里，但这会使应用程序负担过重。我们也可以只在服务器同步状态时渲染主要蛇，但这会使整个游戏看起来非常慢。

我们所做的是在这里复制整个逻辑，并在同步时忽略服务器对其的说法。稍后，我们将讨论客户端预测；在那时，我们将在这里添加一些逻辑来纠正我们在服务器同步时发现的任何差异。

```js
// ch3/snake-ch3/share/app.client.js

game.onUpdate = function (delta) {
    // The client no longer checks if the player has eaten a fruit.
    // This task has now become the server's jurisdiction.
    player.update(delta);
    player.checkCollision();

    if (player.head.x < 0) {
        player.head.x = parseInt(renderer.canvas.width / player.width, 10);
    }

    if (player.head.x > parseInt(renderer.canvas.width / player.width, 10)) {
        player.head.x = 0;
    }

    if (player.head.y < 0) {
        player.head.y = parseInt(renderer.canvas.height / player.height, 10);
    }

    if (player.head.y > parseInt(renderer.canvas.height / player.height, 10)) {
        player.head.y = 0;
    }

    if (fruits.length > 0) {
        if (player.head.x === fruits[0].x && player.head.y === fruits[0].y) {
            fruits = [];
            player.grow();
        }
    }
};
```

## 游戏服务器的游戏循环

这就是事情变得令人兴奋的地方。在我们为服务器端代码实现游戏循环之前，我们首先需要实现一个 API，客户端将使用它来查询服务器并发出其他命令。

在这个项目中使用`express`的一个好处是它与`Socket.io`非常配合。在本章后面专门介绍 Socket.io 之前，我们的主服务器脚本将如下所示：

```js
// ch3/snake-ch3/app.js

// …

var io = require('socket.io')();
var gameEvents = require('./share/events.js');
var game = require('./server/app.js');

var app = express();
app.io = io;

// …

io.on('connection', function(socket){
    // when a client requests a new room, create one, and assign
    // that client to this new room immediately.
    socket.on(gameEvents.server_newRoom, function(data){
        var roomId = game.newRoom(data.maxWidth, data.maxHeight);
        game.joinRoom(roomId, this, data.id, data.x, data.y, data.color);
    });

    // when a client requests to join an existing room, assign that
    // client to the room whose roomId is provided.
    socket.on(gameEvents.server_joinRoom, function(data){
        game.joinRoom(data.roomId, this, data.playerId, data.playerX, data.playerY, data.playerColor);
    });

    // when a client wishes to know what all the available rooms are,
    // send back a list of roomIds, along with how many active players
    // are in each room.
    socket.on(gameEvents.server_listRooms, function(){
        var rooms = game.listRooms();
        socket.emit(gameEvents.client_roomsList, rooms);
    });
});
```

在默认的 Express `app.js`脚本中，我们导入了`Socket.io`，游戏事件模块，以及我们之前定义的游戏应用程序，这将在本章的其余部分中讨论。

接下来，在设置 Express 完成后，我们设置与客户端的 socket 通信。第一步是等待连接建立，这将使我们可以访问绑定到单个客户端的单个 socket。

一旦我们有了一个活跃的 socket，我们通过向每个事件注册自定义事件监听器来配置我们关心的所有事件。您会注意到，先前提到的一些示例事件监听器也会向请求的 socket 发出事件，而其他的则只是在游戏对象上调用方法。两种情况之间的区别在于，当我们只需要与单个客户端（请求的客户端）通信时，我们直接从事件监听器中联系该 socket。然而，有时我们可能希望与连接到同一房间的所有 socket 进行通信。在这种情况下，我们必须让游戏对象通知所有需要的玩家，因为它将知道所有属于给定房间的客户端。

# 大厅和房间系统

游戏房间和大厅的概念对多人游戏至关重要。为了理解其工作原理，可以将游戏服务器视为人们一起玩游戏的建筑物。

在进入建筑物之前，玩家可以站在建筑物前面，欣赏外墙的美丽。在我们的比喻中，凝视建筑物的前面相当于被游戏介绍的启动画面所欢迎。

进入建筑物后，玩家可能会看到一些选项供其选择，比如他或她可能想去的可用楼层的列表。在一些游戏中，您可以选择要玩的游戏类型以及难度级别。可以将此视为乘坐电梯到特定楼层。

最后，您到达了一个大厅。与现实生活中大厅的工作方式类似，在多人游戏中，大厅是多个玩家在进入进行游戏的特定房间之前去的一个特殊房间。在大厅中，您可以看到可用的房间，然后选择一个加入。

一旦您决定加入哪个房间，您现在可以进入该房间并与其他玩家一起参与现有游戏。或者，您可以加入一个空房间，并等待其他人加入。

通常情况下，多人游戏中永远不会有空房间。每个房间至少有一个玩家，并且每个玩家一次只能属于一个房间。一旦所有玩家离开房间，游戏服务器将删除该房间并释放相关资源。

## 实现大厅

通过对大厅的基本理解，我们可以以多种方式实现它。一般来说，大厅实际上是所有玩家在最终进入进行特定游戏的房间之前加入的一个特殊房间。

实现这一点的一种方法是将服务器中的所有套接字连接跟踪为一个数组。在实际操作中，这些套接字数组就是您的大厅。一旦玩家连接到大厅（换句话说，一旦玩家连接到您的服务器），他或她就可以与其他玩家进行通信，并可能成为大厅中其他玩家之间对话的观察者。

在我们的情况下，大厅简单明了。玩家在启动游戏时会自动分配到大厅。一旦进入大厅，玩家可以向服务器查询可用房间的列表。然后，玩家可以发出套接字命令加入现有房间或创建一个新房间：

```js
// ch3/snake-ch3/server/app.js

var Game = require('./../share/game.js');
var gameEvents = require('./../share/events.js');
var Room = require('./room.js');

// ...

/** @type {Array.<Room>} */
var rooms = [];

module.exports = {
    newRoom: function(maxWidth, maxHeight){
        var room = new Room(FPS, maxWidth, maxHeight);
        rooms.push(room);
        return rooms.length - 1;
    },

    listRooms: function(){
        return rooms.map(function(room, index) {
            return {
                roomId: index,
                players: room.players.map(function(player){
                    return {
                        id: player.snake.id,
                        x: player.snake.head.x,
                        y: player.snake.head.y,
                        color: player.snake.color
                    };
                })
            };
        });
    },

    joinRoom: function(roomId, socket, playerId, playerX, playerY, playerColor) {
        var room = rooms[roomId];
        var snake = new Snake(playerId, playerX, playerY, playerColor, 1, 1);
        room.join(snake, socket);

        socket.emit(gameEvents.client_roomJoined, {roomId: roomId});
    },
};
```

请记住，我们的主服务器脚本公开了一个接口，套接字可以使用该接口与游戏服务器进行通信。前面提到的脚本是接口通信的后端服务。连接到服务器的实际套接字存储在并由 Socket.io 管理。

可用房间列表是作为一个`Room`对象数组实现的，我们将在下一节详细讨论。请注意，每个房间都需要至少两样东西。首先，房间需要一种方法来分组玩家并与这些玩家一起运行游戏。其次，房间需要一种方法，让客户端和服务器能够唯一识别每个单独的房间。

识别各个房间的两种简单方法是确保每个房间对象都有一个 ID 属性，该属性需要在整个游戏空间中是唯一的，或者我们可以使用存储房间的数组索引。

为简单起见，我们选择了第二种方法。请记住，如果我们删除一个房间并将其从房间数组中切割出来，一些玩家可能现在指向错误的房间 ID。

例如，假设数组中有三个房间，房间的 ID 分别为 0、1 和 2。假设每个房间都有几个玩家参与游戏。最后，想象一下，房间 ID 为 0 的所有玩家离开了游戏。如果我们将数组中的第一个房间切掉（存储在索引 0 处），那么数组中原来的第二个元素（以前存储在索引 1 处）将被移到数组的前面（索引 0）。数组中的第三个元素也会改变，将存储在索引 1 处而不是索引 2。因此，原来在房间 1 和 2 中的玩家现在将以相同的房间 ID 报告给游戏服务器，但服务器将把第一个房间报告为第二个房间，而第二个房间将不存在。因此，我们必须避免通过切掉空房间来删除它们。请记住，JavaScript 可以表示的最大整数是 2⁵³（等于 9,007,199,254,740,992），因此如果我们只是在房间数组的末尾添加新房间，我们不会用完数组中的槽位。

## 实现房间

游戏房间是一个模块，实现了游戏类并运行游戏循环。这个模块看起来与客户端游戏非常相似，因为它引用了玩家和水果对象，并在每个游戏时刻更新游戏状态。

您会注意到一个不同之处是服务器中没有渲染阶段。此外，房间将需要公开一些方法，以便服务器应用程序可以根据需要管理它。由于每个房间都引用了其中的所有玩家，服务器中的每个玩家都由套接字表示，因此房间可以联系到连接到它的每个玩家：

```js
// ch3/snake-ch3/server/room.js

var Game = require('./../share/game.js');
var Snake = require('./../share/snake.js');
var Fruit = require('./../share/fruit.js');
var keys = require('./../share/keyboard.js');
var gameEvents = require('./../share/events.js');

/** @type {Game} game */
var game = null, gameUpdateRate = 1, gameUpdates = 0;
var players = [], fruits = [], fruitColor = '#c00';
var fruitDelay = 1500, lastFruit = 0, fruitDelta = 0;

var Room = function (fps, worldWidth, worldHeight) {
    var self = this;
    game = new Game(fps);

    game.onUpdate = function (delta) {
        var now = process.hrtime()[1];
        if (fruits.length < 1) {
            fruitDelta = now - lastFruit;

            if (fruitDelta >= fruitDelay) {
                var pos = {
                    x: parseInt(Math.random() * worldWidth, 10),
                    y: parseInt(Math.random() * worldHeight, 10)
                };

                self.addFruit(pos);
                players.map(function(player){
                    player.socket.emit(gameEvents.client_newFruit, pos);
                });
            }
        }

        players.map(function (player) {
            player.snake.update(delta);
            player.snake.checkCollision();

            if (player.snake.head.x < 0) {
                player.snake.head.x = worldWidth;
            }

            if (player.snake.head.x > worldWidth) {
                player.snake.head.x = 0;
            }

            if (player.snake.head.y < 0) {
                player.snake.head.y = worldHeight;
            }

            if (player.snake.head.y > worldHeight) {
                player.snake.head.y = 0;
            }

            if (fruits.length > 0) {
                if (player.snake.head.x === fruits[0].x
                    && player.snake.head.y === fruits[0].y) {
                    fruits = [];
                    player.snake.grow();
                }
            }
        });

        if (++gameUpdates % gameUpdateRate === 0) {
            gameUpdates = 0;
            var data = players.map(function(player){
                return player.snake;
            });
            players.map(function(player){
                player.socket.emit(gameEvents.client_playerState, data);
            });

            lastFruit = now;
        }
    };
};

Room.prototype.start = function () {
    game.start();
};

Room.prototype.addFruit = function (pos) {
    fruits[0] = new Fruit(pos.x, pos.y, fruitColor, 1, 1);
};

Room.prototype.join = function (snake, socket) {
    if (players.indexOf(snake.id) < 0) {
        players.push({
            snake: snake,
            socket: socket
        });
    }
};

Room.prototype.getPlayers = function(){
    return players;
};

module.exports = Room;
```

请注意，玩家数组保存了包含对蛇对象的引用以及实际套接字的对象文字列表。这样，两个资源在同一个逻辑位置上。每当我们需要对房间中的每个玩家进行 ping 时，我们只需映射玩家数组，然后通过`player.socket.emit`访问套接字。

此外，请注意，同步循环放置在主游戏循环内，但我们只在一定数量的帧经过后才触发同步循环内的逻辑。目标是定期同步所有客户端。

# 在游戏房间内匹配玩家

在我们将各种概念分解为简单的基本原理之后，您将看到实现每个模块并不像一开始听起来那么复杂。玩家匹配就是一个例子。

在游戏房间中，您可能希望以不同的方式匹配玩家。虽然我们的示例游戏没有进行任何复杂的匹配（我们允许玩家盲目匹配自己），但您应该知道这里有更多的选择。

以下是一些关于如何将玩家匹配到同一个游戏世界的想法。请记住，有第三方服务，比如谷歌的 Play 服务 API，可以帮助你处理这些问题。

## 邀请朋友进入你的世界

匹配玩家的最吸引人的方式之一利用了当今世界的社交方面。通过与社交网络服务集成（或使用由玩家填充的自己的社交网络），您可以让玩家选择邀请朋友一起玩。

虽然这可能是一种有趣的体验，但不言而喻的是，两个玩家必须同时在线才能进行游戏。通常，这意味着当玩家向他或她的朋友发送邀请时，会向朋友发送一封包含有关邀请信息的电子邮件。每当朋友加入游戏房间并且两个玩家准备好时，游戏就可以开始了。

这种技术的一个变种是只显示可用的朋友（即已经在线并且在大厅或游戏房间中的朋友）。这样游戏可以立即开始，或者在朋友退出当前游戏后立即开始。

## 自动匹配

也许，您没有社交网络可以利用，或者，玩家不在乎对手是谁。当您希望玩家能够快速进入并玩一局游戏时，自动匹配是一个很好的选择。

有更具体的方法可以自动匹配玩家（例如，根据他们的技能或其他标准自动匹配玩家），但在最基本的形式中，您需要为第一个玩家创建一个私人房间（私人房间指的是一个不列出供任何玩家加入的房间，只有游戏服务器知道它），然后等待匹配的玩家加入该房间。

## 基于技能的匹配

另一种常见的玩家匹配到同一游戏房间的方式是根据他们的技能水平将玩家分组。跟踪玩家的技能水平的方式至少可以有三种确定方式，即询问用户他或她的技能水平是什么，监控他们在单个会话期间的表现，或者在多个会话中持久化玩家的信息。

第一种选择是最容易实现的。通常的做法是通过显示一个菜单，其中有三个或更多的选项，要求玩家从这些选项中选择，例如业余、高级和摇滚明星。根据这个选择，然后您将尝试与同一组的其他玩家匹配。

这种方法的一个可能的好处是，没有与游戏的过去历史（从服务器的角度来看）的新玩家可以立即开始与更高级的玩家对战。另一方面，同样的功能也可能被认为是这种方法的一个缺点，因为真正高级的玩家可能只希望与同样技能水平的玩家对战，而可能会因为与声称拥有更高技能水平的较差玩家匹配而感到沮丧。

第二个选项是让每个人从同一水平开始（或者随机分配新玩家的第一个技能水平）。然后，随着更多的游戏进行，应用程序可以跟踪每个玩家的胜利和失败以及有关每个玩家的其他元数据，以便您可以将每个玩家分成当前的技能水平。

例如，一个玩家可能在一个初学者房间开始游戏。在赢得两场比赛并且没有输掉任何一场之后，您可以将这个玩家放入一个高级房间。在玩家玩了额外的两三场比赛并且赢得了两三场胜利之后，您现在可以认为这个玩家处于超高级水平。

这种方法的明显缺点是，它假设一个个体玩家会保持足够长的登录时间来进行多次游戏。根据您设计的游戏类型，大多数玩家甚至不会登录完成单个游戏会话。

然而，如果您的游戏是这种类型的理想选择（即单个游戏的持续时间不超过几分钟），那么这种匹配技术非常有效，因为您不需要编写任何长期持久性逻辑或需要验证用户。

最后，您可以通过在某种后端数据库中持久化他们的信息来跟踪玩家的技能水平。在大多数情况下，这将需要玩家拥有个人帐户，在游戏开始之前需要进行身份验证。

同样，在某些情况下，您可能希望使用现有的第三方服务来验证玩家，并可能在服务本身中持久化您生成的有关他们的信息。

虽然这可能会变得非常复杂和引人入胜，但基本概念很简单——计算一些可以用来推断玩家技能水平的分数，并将该信息存储在某个地方，以便以后可以检索。从这个角度来看，您可能可以通过使用 HTML5 的本地存储 API 在本地存储玩家当前的技能水平来实现这种持久性。这样做的主要缺点是，这些数据将被困在玩家的机器上，因此如果玩家使用不同的机器（或者清除本地存储数据），您将无法访问这些数据。

# Socket.io

在第一章中，*开始多人游戏编程*，我们使用原生 HTML5 套接字实现了第一个演示游戏。尽管 WebSockets 仍然非常棒，但不幸的是，它们仍然严重依赖于玩家使用的特定浏览器。

今天，每个现代浏览器都配备了完整的 WebSockets 实现，特别是在移动设备上，世界似乎正在趋同。然而，可能有一种例外情况，用户的浏览器不完全支持 WebSockets，但支持 canvas（或者其他 HTML5 API），这时 Socket.io 就派上用场了。

简而言之，Socket.io 是一个开源库，提供了对套接字的出色抽象。不仅如此，Socket.io 还使实现前端套接字客户端将使用的后端服务变得非常容易。

实现服务器端代码就像指定连接的端口，然后实现您感兴趣的事件的回调一样容易。

现在，本书并不是想要掌握 Socket.io 的每个方面的全面指南，对于该库提供的许多功能，也不会过于描述。然而，您可能会发现 Socket.io 提供了令人惊叹的客户端支持。换句话说，如果使用套接字的浏览器没有实现 WebSockets 规范，那么 Socket.io 将回退到其他一些可以用于与服务器异步通信的技术。虽然其中一些技术可能对实时游戏来说太慢（例如，如果浏览器不支持其他技术，Socket.io 最终会回退到使用 HTML iFrames 与服务器通信），但了解该库的强大之处还是很有好处的。

## 安装 Socket.io

我们将通过 NPM 将 Socket.io 引入我们的项目。一定要使用本书中使用的版本（1.3.5），因为一些方法或配置可能会有所不同。

```js
npm install socket.io --save
npm install socket.io-client –save

```

再次强调，由于我们使用 Express 框架来简化创建 Node.js 服务器的工作，我们将 Socket.io 与 Express 集成。

```js
// ch3/snake-ch3/app.js

var express = require('express');
var io = require('socket.io')();

// ...

var app = express();
app.io = io;

// ...

io.on('connection', function(socket){
        console.log('New client connected. Socket ready!');
    });
});
```

我们需要做的第一件事是`require` Socket.io 以及 Express 和服务器脚本的所有其他依赖项。然后，我们利用 JavaScript 的动态特性将 Socket.io 添加到 Express 实例中。我们这样做是因为 Socket.io 还没有完全设置好，因为我们需要访问 Express 使用的 HTTP 服务器。在我们的情况下，按照当前标准，我们使用 Express Version 4.9.0 以及 express-generator，它会在`<project-name>/bin/www`下生成一个文件，其中进行低级服务器设置。这是我们将 Socket.io 集成到 Express 中的地方，通过将 Express 使用的相同服务器附加到我们的 Socket.io 实例中。

```js
// ch3/snake-ch3/bin/www

#!/usr/bin/env node
var debug = require('debug')('snake-ch3');
var app = require('../app');

app.set('port', process.env.PORT || 3000);

var server = app.listen(app.get('port'), function() {
  debug('Express server listening on port ' + server.address().port);
});

app.io.attach(server);
```

## 客户端 Socket.io

最后一步是在我们的客户端 JavaScript 中使用 Socket.io 库。在这里，只有两个简单的步骤，如果你以前做过任何 JavaScript 编程，那么你肯定已经习惯了。

首先，我们将客户端库复制到我们的公共目录，以便我们可以将其包含到我们的客户端代码中。为此，将`ch3/snake-ch3/node_modules/socket.io-client/socket.io.js`文件复制到`ch3/snake-ch3/public/js/socket.io.js`。接下来，使用脚本标签在您的 HTML 文件中包含该库。

为了在客户端代码中开始使用套接字，你所需要做的就是通过需要它的域来实例化它，服务器正在运行的域。

```js
// ch3/snake-ch3/share/app.client.js

var socket = require('socket.io-client')(window.location.origin);

// …

socket.on('connect', function () {
    socket.emit(gameEvents.server_listRooms);
});
```

现在，套接字将立即异步地尝试连接到您的服务器。一旦它这样做，连接事件将触发，相应的回调也将被触发，您将知道套接字已经准备好使用。从那时起，您可以开始向套接字的另一端发出事件。

# 总结

希望这一章让你对多人游戏开发的独特方面感到兴奋。我们将一个现有的单人贪吃蛇游戏分解成了一个权威服务器组件和一个由套接字驱动的前端组件。我们使用 Socket.io 将游戏客户端和服务器以非常无缝的方式与 Express 进行了链接。我们还讨论了游戏大厅和游戏房间的概念，以及将玩家匹配到同一个游戏世界的方法。

在下一章中，我们将通过添加客户端预测和校正以及输入插值来改进我们的贪吃蛇游戏，以减少网络延迟。我们还将修复游戏服务器的游戏循环，以实现更流畅和更高效的游戏。
