# JavaScript 区块链编程学习手册（一）

> 原文：[`zh.annas-archive.org/md5/FF38F4732E99A2380E8ADFA2F873CF99`](https://zh.annas-archive.org/md5/FF38F4732E99A2380E8ADFA2F873CF99)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

借助本书，您将使用 JavaScript 编程语言构建自己的区块链原型和去中心化网络。构建自己的区块链将帮助您了解与区块链相关的各种概念，例如区块链技术在幕后是如何工作的，去中心化的区块链网络如何运作，以及如何使用 JavaScript 编写区块链和去中心化网络。此外，您将了解为什么区块链是如此安全和有价值的技术。

本书中构建的区块链将具有类似于比特币或以太坊等真实区块链上的功能，例如挖掘新区块的能力，创建新的不可变交易，并执行工作证明以保护区块链。除此之外，您的区块链还将包含许多其他重要功能。随着您进一步阅读各章节，您将有机会探索这些功能。

完成本书后，您将彻底了解区块链技术的实际运作方式，以及为什么这项技术如此安全和有价值。您还将深刻了解去中心化的区块链网络是如何运作的，以及为什么去中心化是保护区块链的重要特性。

# 本书适合对象

*使用 JavaScript 学习区块链编程*适用于希望学习区块链编程或使用 JavaScript 框架构建自己的区块链的 JavaScript 开发人员。

# 本书涵盖内容

第一章，*设置项目*，介绍了区块链的实际含义，并使读者了解其功能。然后，您将学习如何设置项目，以创建自己的区块链。

第二章，*构建区块链*，介绍了如何向您的区块链添加各种功能。您将在区块链中实现这些功能，创建一些令人惊叹的方法，如`createNewBlock`，`creatNewTransaction`和`getLastBlock`。一旦这些方法添加到区块链中，您将测试它们以验证其是否完美运行。此外，您还将了解哈希方法，即 SHA256 哈希，并实现一种方法来为您的区块数据生成哈希。此外，您还将了解工作证明是什么，它如何有益于区块链以及如何实现它。

第三章，*通过 API 访问区块链*，解释了如何在项目中设置 Express.js，以及如何使用它来构建 API/服务器。然后，您将为区块链构建各种服务器端点，并测试这些端点以验证它们是否正常工作。

第四章，*创建去中心化的区块链网络*，介绍了如何为您的区块链设置去中心化网络。在本章中，您将学习有关如何设置各种节点并将它们互连以形成网络的许多新概念。您还将定义各种端点，例如`/register-and-broadcast-node`，`/register-node`和`/register-nodes-bulk`。这些端点将帮助您实现去中心化的区块链网络。

第五章，*同步网络*，解释了如何同步整个去中心化的区块链网络，以便在区块链的所有节点上具有相同的交易数据和区块。您将通过重构端点来实现网络同步，将数据广播到网络中的所有节点。

第六章，*共识算法*，解释了如何构建自己的共识算法，该算法实现了最长链规则。通过实现这个算法，您将构建一个类似于现实生活中的区块链。

第七章，*区块浏览器*，解释了如何构建一个令人惊叹的用户界面，以便探索您在本书中构建的区块链。

第八章，*总结*，提供了本书学习过程中所学到的一切的快速总结。您还将探索如何改进您开发的区块链。

# 为了充分利用本书

建议具有基本的 JavaScript 知识。您还需要在系统上安装 Node.js。

本书中的示例代码和实现是在 macOS 上执行的。但是，如果您想要在 Windows PC 上实现所有这些，您将需要安装必要的要求。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，并按照屏幕上的指示操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为**[`github.com/PacktPublishing/Learn-Blockchain-Programming-with-JavaScript`](https://github.com/PacktPublishing/Learn-Blockchain-Programming-with-JavaScript)**。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富图书和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这是一个例子："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```js
Blockchain.prototype.createNewBlock = function () { 

}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 

}
```

任何命令行输入或输出都以以下方式编写：

```js
cd dev
touch blockchain.js  test.js
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子："转到更多工具，然后选择开发者工具选项。"

警告或重要说明会以这种方式出现。

提示和技巧会以这种方式出现。


# 第一章：设置项目

欢迎来到*使用 JavaScript 学习区块链编程*。正如其名称所示，在本书中，您将学习如何使用 JavaScript 编程语言从头开始构建一个完全功能的区块链。您构建的区块链将具有类似于比特币或以太坊等生产级区块链中找到的功能。

在本书中，您将通过学习如何构建自己的区块链和理解分散网络来了解区块链技术的实际工作原理。在本书结束时，您将拥有一个托管在分散网络上的完整的区块链原型，并且您将对区块链在幕后实际工作的知识和理解有了很大的收获。

我们将在本书中创建的区块链将能够执行以下功能：

+   执行工作证明以保护区块链

+   通过挖矿过程创建新的区块

+   创建新的不可变交易

+   验证整个区块链以及每个区块内的所有数据

+   检索地址/交易/区块数据

除此之外，区块链还将具有许多其他重要功能。随着您阅读本书的更多章节，您将有机会探索这些功能。

要跟随本书，您只需要一台计算机和一些关于 JavaScript 编程语言的基本知识。

首先，在本书的介绍章节中，让我们试着了解区块链实际上是什么。这将帮助您熟悉区块链的概念，因为这是本书的先决条件。然后我们将继续学习如何设置项目来创建我们自己的区块链。

所以，让我们开始吧！

# 什么是区块链？

在本节中，让我们简要解释一下什么是区块链。简而言之，**区块链**是一个不可变的、分布式分类帐。现在，这些词可能看起来很复杂，但当我们试图解释它们时，就会很容易理解。让我们从探索分类帐的实际含义开始。分类帐只是一组财务账户或交易（或者换句话说，人们进行的交易记录）。

让我们看下面的示例，以更好地理解分类帐。在这个例子中，Kim 支付给 Joe 30 美元，Kevin 支付给 Jen 80 美元。分类帐只是用来跟踪这些交易的文件。您可以在以下截图中看到这一点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/56ad2763-e822-4175-abe2-5082258544eb.png)

那么，区块链不可变意味着什么？这意味着它永远不能被改变。因此，一旦交易被记录，就无法撤销。其他无法更改的因素包括发送的金额或参与交易的人。一旦交易完成，该交易的任何方面都无法更改，因为它是不可变的。

今天，我们看到许多应用程序、平台和网络都是集中化的。以 Facebook 为例。使用 Facebook 的每个人都必须相信这家公司正在保护他们的数据并且不滥用它。与此相比，区块链是不同的。区块链技术不像 Facebook、Google 或大多数其他实体那样集中化。相反，它是一个分布式网络，这意味着任何给定的区块链网络都不受单一实体控制，而是由普通人运行。比特币等区块链由全球数千人支持和托管。因此，我们的所有数据，或者在这种情况下的分类帐，不受单一公司或实体的支配。这证明了区块链技术的巨大好处，因为通过分布式，我们不必信任单一公司来保护我们的数据。相反，我们的数据由成千上万个不同的人组成的整个网络持久保存。

每个为区块链网络做出贡献的个人都被称为节点，每个节点都有相同的分类账副本。因此，分类账数据在整个网络中进行托管和同步。

因此，区块链是一个不可变的分布式分类账。这意味着这是一个分类账，其中的交易永远不会被更改，区块链本身分布在网络中，并由成千上万的独立个人、团体或节点运行。

区块链是一种非常强大的技术，尽管它仍处于起步阶段，但它的未来非常令人兴奋。区块链技术可以应用于今天的世界，使某些行业更安全、高效和可信。一些可能通过区块链技术转变的行业包括金融服务、医疗保健、信用、政府、能源行业等。几乎每个行业都可以从更安全、分布式的数据管理形式中受益。您可以看到，区块链技术目前正处于一个非常令人兴奋的阶段，许多人对它的未来充满期待。

现在我们知道了什么是区块链，让我们开始设置项目环境来构建我们的区块链。

# 你将学到什么...

本书将通过从头开始构建自己的区块链来帮助您更深入地了解区块链技术。区块链是一种相当新的技术，虽然一开始学习起来可能会有些困难和有些压倒性，但我们将采取一步一步的方法，以便了解它在底层是如何工作的。当您完成本书时，您将对区块链技术的工作原理有很扎实的理解，并且您还将构建自己的整个区块链。

在本书中，我们将首先构建区块链本身。在这一点上，我们将构建一个具有以下能力的区块链数据结构：

+   验证工作

+   挖掘新区块

+   创建交易

+   验证链

+   检索地址数据和其他功能

此后，我们将创建一个 API 或服务器，允许我们通过互联网与我们的区块链进行交互。通过我们的 API，我们将能够使用我们构建到区块链数据结构中的所有功能。

此外，您将学习创建一个去中心化网络。这意味着我们将有多个运行的服务器，作为独立的节点。我们还将确保所有节点之间正确地相互交互，并以正确的格式共享数据。此外，您将学习如何通过确保任何新创建的节点或交易都在整个网络中广播来同步整个网络。

接下来，我们将开始创建共识算法。该算法将用于确保我们整个区块链保持同步，并且该算法将用于确保我们网络中的每个节点都具有正确的区块链数据。

最后，我们将创建一个区块浏览器。这将是一个用户界面，允许我们以用户友好的方式探索我们的区块链，还将允许我们查询特定的区块交易和地址。

然而，首先，我们需要设置我们的开发环境。

# 环境设置

让我们开始构建我们的区块链项目。我们要做的第一件事是打开我们的终端，并通过在终端中输入命令来创建我们的区块链目录，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/b9863d09-28c2-49e4-a8ab-dcd202cb9222.png)

让我们首先创建一个名为`programs`的文件夹。在这个文件夹里，让我们创建一个名为`blockchain`的目录。这个目录目前是空的。在这个`blockchain`目录里，我们将进行所有的编程。我们将在这个`blockchain`目录中构建我们的整个区块链。

现在我们的`blockchain`目录已经准备好了，我们需要做的第一件事是向其中添加一些文件夹和文件。我们想要放入目录的第一个文件夹将被称为`dev`，因此我们要确保我们在`blockchain`目录中，然后让我们在终端中输入以下命令：

```js
mkdir dev
```

在这个`dev`目录中，我们将进行大部分编码工作。这是我们将构建区块链数据结构并创建与区块链交互的 API、测试它以及完成其他类似任务的地方。接下来，在这个`dev`文件夹中，让我们创建两个文件：`blockchain.js`和`test.js`。为此，请在终端中输入以下命令：

```js
cd dev
touch blockchain.js test.js
```

在上述命令行中的`touch`命令将帮助我们创建提到的文件。`blockchain.js`文件是我们将输入代码以创建区块链的地方，`test.js`文件是我们将编写代码来测试我们的区块链的地方。

接下来，让我们通过在终端中输入以下命令返回到我们的`blockchain`目录：

```js
cd .. 
```

在`blockchain`目录中，让我们运行以下命令来创建 npm 项目：

```js
npm init 
```

运行上述命令后，您将在终端上获得一些选项。要设置项目，您只需通过这些选项按*Enter*即可。

因此，这基本上是我们需要做的一切，以便设置我们的项目文件夹结构。现在，如果您转到我们的`blockchain`目录并使用 Sublime 或 Atom（或您喜欢的任何其他文本编辑器）打开它，您将看到文件结构，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/f0671fe2-1d57-4273-a4e4-c90ad9102ee1.png)

`blockchain`目录包括我们刚刚创建的`dev`文件夹。在`dev`文件夹中，我们可以看到我们的`blockchain.js`和`test.js`文件。此外，当我们运行`npm init`命令时，它会为我们创建`package.json`文件。这个`.json`文件将跟踪我们的项目和我们需要的任何依赖项，使我们能够运行脚本。在后续章节中，我们将在`package.json`文件中进行更多工作，因此随着我们在本书中的进展，您将更加熟悉它。

# 项目源代码

在我们开始编写区块链之前，值得注意的是，本书的整个源代码可以在 GitHub 上找到，链接如下：[`github.com/PacktPublishing/Learn-Blockchain-Programming-with-JavaScript`](https://github.com/PacktPublishing/Learn-Blockchain-Programming-with-JavaScript)。在这个存储库中，您将找到整个项目的完成代码，并且您还将能够探索我们将在后续章节中构建的所有文件。因此，这可能是您在阅读本书时使用的一个很好的资源。

# 摘要

总结一下这个介绍性的章节，我们首先探讨了区块链的实际含义以及它的运作方式。然后我们开始设置项目以创建我们自己的区块链。我们还快速概述了本书中您将学习的所有主题。

在下一章中，我们将通过学习构造函数、原型对象、区块方法、交易方法以及许多其他重要概念来构建我们的区块链。


# 第二章：构建区块链

在上一章中，我们了解了区块链是什么以及它的功能。此外，我们还学习了如何设置项目来构建我们的区块链。在本章中，您将开始构建区块链及其所有功能。首先，让我们使用构造函数创建区块链数据结构，然后通过向其原型添加不同类型的功能来为我们的区块链添加许多不同类型的功能。

然后，我们将赋予区块链某些功能，例如创建新的区块和交易，以及对数据和区块进行哈希的能力。我们还将赋予它进行工作证明和许多其他区块链应该具备的功能。然后，我们将通过测试添加的功能来确保区块链是完全功能的。

通过逐步构建区块链的每个部分，您将更好地了解区块链在幕后实际上是如何工作的。您还可能意识到，一旦您深入其中，创建区块链并不像听起来那么复杂。

在本章中，我们将涵盖以下主题：

+   学习如何创建区块链构造函数

+   构建和测试各种方法，如`createNewBlock`、`createNewTransaction`和`hashBlock`，以为区块链添加功能

+   了解工作证明是什么，并学习如何为我们的区块链实现它

+   创建和测试创世区块

所以，让我们开始吧！

# 在我们开始之前...

在构建区块链之前，有两个关键概念我们需要熟悉。这些重要概念如下：

+   JavaScript 构造函数

+   原型对象

# JavaScript 构造函数的解释

熟悉构造函数很重要，因为我们将使用它来构建我们的区块链数据结构。到目前为止，您一定想知道构造函数是什么，它实际上是做什么。

构造函数只是一个创建对象类并允许您轻松创建该特定类的多个实例的函数。这实际上意味着构造函数允许您非常快速地创建大量对象。由于它们都是同一类的一部分，所以创建的所有这些对象都将具有相同的属性和功能。现在，当您第一次听到这些时，所有这些可能看起来有点令人困惑，但不要担心——我们将尝试通过一个示例来理解构造函数是什么。

以 Facebook 为例。Facebook 拥有超过 15 亿用户，它们都是同一类的对象，并具有类似的属性，如姓名、电子邮件、密码、生日等。对于我们的示例，假设我们正在构建 Facebook 网站，并希望为其创建一堆不同的用户。我们可以通过创建一个`User`构造函数来实现这一点。

要学习和探索构造函数，让我们使用 Google Chrome 控制台。我们可以通过打开 Google Chrome 并简单地按下*command* + *option* + *J*（Mac 用户）或*Ctrl* + *Shift* + *I*（Windows 用户）来访问控制台。或者，我们可以简单地转到菜单选项，转到“更多工具”，然后选择“开发者工具”选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/cdd62f3b-e3ef-4f56-a595-2c1f57330fbe.png)

按照上述步骤将为您打开控制台，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/172ac298-046d-45f0-9bdc-79c5baaa110d.png)

在本示例中，我们将编写的构造函数将允许我们创建多个用户或多个用户对象，这些对象将具有相同的属性和功能。创建此`User`构造函数的代码如下所示：

```js
function User() { 

}
```

在括号`()`内，让我们传递我们希望每个`User`对象具有的属性。我们将传递诸如`firstName`、`lastName`、`age`和`gender`等属性，因为我们希望所有的用户对象都具有这些组件。

然后，我们使用`this`关键字将这些参数分配给我们的`User`对象，如下面的代码块所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/9ddd09c9-3fe2-485d-9a6a-c9457654c039.png)

这就是我们在 JavaScript 中定义构造函数的方法。现在，通过阅读上面的代码块，你可能会想知道我们做了什么，`this`关键字是什么意思。

我们将使用这个构造函数来创建很多用户对象。`this`关键字只是简单地指向我们将要创建的每一个用户对象。现在可能看起来有点令人不知所措，但让我们通过一些例子来更清楚地理解它。

让我们开始使用我们的`User`构造函数。要创建一些`User`对象，也称为`User`实例，请按照以下步骤进行：

1.  我们要创建的第一个用户 - 让我们称之为`user1` - 将被定义如下：

```js
var user1 = new User('John','Smith',26,'male');
```

在上面的代码中，你可能已经注意到我们使用了`new`关键字来调用我们的构造函数并创建一个用户对象，这就是我们让构造函数工作的方法。

1.  然后按下*Enter*，`user1`就出现在系统中。现在，如果我们在控制台中输入`user1`，我们将能够看到我们在上一步中创建的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/d44eaca9-749c-471a-8d79-efead9ca8491.png)

在上面的输出截图中，我们可以看到`user1`是`User`类的一个对象。我们还可以看到`user1`的`firstName`是`John`，`lastName`是`Smith`，`age`是`26`，`gender`是`male`，因为这些是我们传入构造函数的参数。

1.  为了更清晰，尝试添加一个用户。这一次，我们将创建另一个名为`user200`的用户，并将其传递到`new User()`函数中，传入用户的属性，例如名字为`Jill`，姓氏为`Robinson`，年龄为`25`，性别为`female`。

```js
var user200 = new User('Jill', 'Robinson', 25, 'female');
```

1.  按下*Enter*，我们的新`user200`将出现在系统中。现在，如果我们在控制台中输入`user200`并按下*Enter*，我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/902899d7-1de6-4a56-b8af-ffc15758e7fe.png)

在上面的输出中，我们可以看到`user200`是`User`类的一个对象，就像`user1`一样，她的名字是`Jill`，姓氏是`Robinson`，年龄是`25`，性别是`female`，因为这些是我们传入构造函数的参数。

现在，你可能想知道我们提到的所有这些属性是如何被正确分配的。这都是由我们之前提到的`this`关键字所致。当我们创建我们的构造函数时，我们使用`this`关键字来分配属性。当涉及到构造函数时，`this`关键字不是指代它所在的函数 - 在我们的例子中是`User`函数。相反，`this`指的是将由构造函数创建的对象。

这意味着，如果我们使用构造函数来创建一个对象，我们必须确保属性和它们的对象是名字、姓氏、年龄和性别，或者无论何时你创建你的构造函数，都要将`firstName`属性设置为等于传入的`firstName`参数，并对其余属性做同样的操作。

这就是构造函数的工作原理，以及`this`关键字在构造函数中扮演的重要角色。

# 原型对象的解释

在编写区块链数据结构之前，我们需要讨论的另一个重要概念是原型对象。**原型对象**只是一个多个其他对象可以引用以获取它们需要的任何信息或功能的对象。对于我们在上一节中讨论的示例，我们的每个构造函数都将有一个原型，它们的所有实例都可以引用。让我们通过探索一些例子来尝试理解原型对象的含义。

例如，如果我们拿出我们在上一节中创建的`User`构造函数，我们可以将这些属性放在它的原型上。然后，我们所有的用户实例，如`user1`和`user200`，都将可以访问并使用该原型。让我们在`User`原型上添加一个属性并看看会发生什么。要在用户原型上添加一个属性，我们将输入以下代码：

```js
User.prototype. 
```

然后让我们在上面的代码中添加属性的名称。例如，假设我们想要一个属性电子邮件域：

```js
User.prototype.emailDomain 
```

对于我们的示例，假设 Facebook 希望每个用户都有一个`@facebook.com`的电子邮件地址，因此我们将设置电子邮件域属性如下：

```js
User.prototype.emailDomain = '@facebook.com';
```

现在让我们再次检查我们的`user1`对象：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/12909ac8-5180-4732-9a08-be947497cc3e.png)

在上面的截图中，我们可以看到`user1`没有我们刚刚添加的电子邮件域属性。但是，我们可以展开`user1`对象以及它的 dunder proto，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/bbf3d80b-4db6-45bc-8621-12d5e3ead677.png)

当我们这样做时，我们可以观察到我们刚刚添加的`emailDomain`属性，它被设置为`@facebook.com`。

只是为了澄清，dunder proto 和我们实际放置`emailDomain`属性的原型对象实际上并不完全相同，但非常相似。基本上，我们放在构造函数原型上的任何东西都可以访问我们使用构造函数创建的任何对象的 dunder proto。

因此，如果我们在构造函数原型上放置`emailDomain`，我们将可以在`user1` dunder proto、`user200` dunder proto 以及我们创建的任何其他用户实例的 dunder proto 上访问它。

现在让我们回到`emailDomain`属性。我们将`emailDomain`属性放在用户原型上。我们可以看到我们在实际的`user200`对象上没有该属性，但是我们在`user200`的 dunder proto 下有该属性。因此，如果我们输入以下命令，我们仍然可以访问该属性：

```js
user200.emailDomain
```

然后我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/aa4732f7-2141-488c-bb2a-a583599f70ec.png)

因此，这就是原型对象的工作原理。如果我们在构造函数的原型上放置一个属性，那么构造函数的所有实例都将可以访问该属性。

对于我们可能希望所有实例都具有的任何方法或函数，都适用相同的情况。让我们看另一个例子，假设我们希望所有用户实例都有一个`getEmailAddress`方法。我们可以将其放在构造函数的原型上，如下所示：

```js
User.prototype.getEmailAddress = function () { 
}    
```

现在让我们让这个`getEmailAddress`方法返回一些特定的属性，如下所示（高亮显示）：

```js
User.prototype.getEmailAddress = function () { 
 return this.firstName + this.lastName + this.emailDomain;
} 
```

现在`user1`和`user200`都应该在它们的 dunder proto 下有这个方法，所以让我们来检查一下。在我们的用户下输入，并在它们的 dunder proto 下你将看到前面的函数，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/33ba858a-1e99-4237-99ab-ce881768de47.png)

在上面的截图中，我们可以观察到`user1`和`user200`都在它们的 dunder proto 下有`getEmailAddress`方法。

现在，如果我们输入`user200.getEmailAddress`然后调用它，该方法将为我们创建 user200 的 Facebook 电子邮件地址，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/cf1af2a5-d453-4cc1-b182-f30a7f095b92.png)

如果我们为`user1`调用该方法，类似的事情也会发生：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/27d5b431-3bee-4bef-a976-634e3cb30c4d.png)

这就是我们如何使用原型对象与构造函数。如果我们希望我们的构造函数实例都具有相同的属性，或者都具有相同的方法，我们将把它放在原型上，而不是构造函数本身。这将有助于保持实例更加精简和清晰。

这是我们需要了解的所有背景信息，以便开始编写我们的区块链数据结构。在接下来的部分中，我们将通过使用构造函数和原型对象来开始构建我们的区块链。

# 区块链构造函数

让我们开始构建我们的区块链数据结构。我们将首先通过使用 Sublime 编辑器打开我们区块链目录中的所有文件。如果你习惯使用其他编辑器，也可以使用。在你喜欢的任何编辑器中打开我们整个区块链目录。

我们将在我们在第一章中创建的`dev/blockchain.js`文件中构建整个区块链数据结构，*设置项目*。让我们通过使用我们在上一节中学到的构造函数来构建这个区块链数据结构。所以，让我们开始：

对于构造函数，请键入以下内容：

```js
function Blockchain () {
}
```

目前，`Blockchain()`函数不会接受任何参数。

接下来，在我们的构造函数内部，我们将添加以下术语：

```js
function Blockchain () {
    this.chain = [];
    this.newTransactions = [];
}
```

在上面的代码块中，`[]`定义了一个数组，而`this.chain = [];`是我们的区块链的核心所在。我们挖掘的所有区块都将存储在这个特定的数组中作为一个链，而`this.newTransactions = [];`是我们将在放入区块之前创建的所有新交易的存储位置。

现在，所有这些可能看起来有点混乱和令人不知所措，但不用担心。让我们在未来的部分深入了解这一点。

在定义上述函数时，我们已经开始了创建区块链数据结构的过程。现在，你可能会想为什么我们要使用构造函数来构建我们的区块链数据结构，而不是类；答案是这只是一种偏好。在 JavaScript 中，我们更喜欢使用构造函数而不是类，因为在 JavaScript 中实际上并没有类。JavaScript 中的类只是构造函数和对象原型的一种糖衣。所以，我们更喜欢坚持使用构造函数。

但是，如果你想使用类来创建区块链，你可以像下面的代码块一样做：

```js
class Blockchain {
    constructor() {
        this.chain = [];
        this.newTransactions = [];
    }

    // Here you can build out all of the methods 
    // that we are going to write inside of this
    // Blockchain class. 

}
```

所以，无论你喜欢使用构造函数还是类，都可以正常工作。

就是这样 - 通过定义我们的函数，我们已经开始了构建我们的区块链数据结构的过程。在后续部分中，我们将继续构建。

# 构建`createNewBlock`方法

让我们继续构建我们的区块链数据结构。在上一节中定义了我们的构造函数之后，我们想要做的下一件事是在我们的`Blockchain`函数中放置一个方法。我们将要创建的这个方法将被称为`createNewBlock`。顾名思义，这个方法将为我们创建一个新的区块。让我们按照下面提到的步骤来构建这个方法：

1.  `createNewBlock`方法将定义如下：

```js
Blockchain.prototype.createNewBlock = function () { 

}
```

1.  现在我们在我们的区块链`prototype`对象上有了这个`createNewBlock`方法。这个方法将使用下面代码行中突出显示的三个参数：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 

}
```

我们将在后面的部分深入学习这三个参数，所以如果你对它们不熟悉，不用担心。

1.  现在，我们在`createNewBlock`方法内想要做的下一件事是创建一个`newBlock`对象。让我们定义如下：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 
    const newBlock = { 

 }; 

}
```

这个`newBlock`对象将成为我们`BlockChain`中的一个新区块，因此所有数据都将存储在这个区块中。这个`newBlock`对象是我们区块链的一个非常重要的部分。

1.  接下来，在`newBlock`对象上，我们将有一个`index`属性。这个`index`值基本上就是区块编号。它将描述`newBlock`在我们的链中的区块编号（例如，它可能是第一个区块）：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 
    const newBlock = { 
        index: this.chain.length + 1,     
    };   

}
```

1.  我们接下来的属性将是一个`timestamp`，因为我们想知道区块是什么时候创建的：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 
    const newBlock = { 
        index: this.chain.length + 1,
        timestamp: Date.now(),       
    };   

}
```

1.  接下来，我们要添加的属性是`transactions`。当我们创建一个新区块时，我们将希望将所有新的交易或者刚刚创建的待处理交易放入新区块中，以便它们在我们的区块链中，并且永远不会被更改：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 
    const newBlock = { 
        index: this.chain.length + 1,
        timestamp: Date.now(),
        transactions: this.newTransactions,          
    };   

}
```

前面突出显示的代码行表示区块中的所有交易应该是等待放入区块中的新交易。

1.  我们区块的下一个属性将是一个`nonce`，它将等于我们之前传递到函数中的`nonce`参数：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 
    const newBlock = { 
        index: this.chain.length + 1,
        timestamp: Date.now(),
        transactions: this.newTransactions, 
        nonce: nonce,         
    };   

}
```

现在，你可能想知道`nonce`是什么。基本上，nonce 来自于工作证明。在我们的情况下，这只是一个数字；它无关紧要。这个 nonce 基本上证明了我们通过使用`proofOfWork`方法以合法的方式创建了这个新区块。

现在所有这些可能看起来有点混乱，但不要担心——一旦我们在区块链数据结构上建立更多内容，就会更容易理解所有东西是如何一起工作的，从而创建一个功能性的区块链。所以，如果你现在不理解 nonce 是什么，不要担心。我们将在后续章节中处理这个属性，随着我们的进展，它会变得更清晰。

1.  接下来的属性将是一个`hash`：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 
    const newBlock = { 
        index: this.chain.length + 1,
        timestamp: Date.now(),
        transactions: this.newTransactions, 
        nonce: nonce,
        hash: hash,         
    };   

}
```

基本上，这个`hash`将是我们`newBlock`的数据。发生的情况是我们将我们的交易或者`newTransactions`传递到一个哈希函数中。这意味着我们所有的交易将被压缩成一个代码字符串，这将是我们的`hash`。

1.  最后，我们`newBlock`上的最后一个属性将是我们的`previousBlockHash`：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 
    const newBlock = { 
        index: this.chain.length + 1,
        timestamp: Date.now(),
        transactions: this.newTransactions, 
        nonce: nonce,
        hash: hash,
        previousBlockHash: previousBlockHash,          
    };   

}
```

这个`previousBlockHash`属性与我们的`hash`属性非常相似，只是我们的`hash`属性处理的是我们当前区块的数据哈希成一个字符串，而`previousBlockHash`属性处理的是我们上一个区块或者当前区块的上一个区块的数据哈希成一个字符串。

因此，`hash`和`previousBlockHash`都是哈希。唯一的区别是`hash`属性处理的是当前区块的数据，而`previousBlockHash`属性处理的是上一个区块的数据的哈希。这就是如何创建一个新区块，这就是我们区块链中每个区块的样子。

1.  继续我们的`createNewBlock`方法，我们接下来要做的是将`this.newTransaction`设置为空数组，如下所示：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 
    const newBlock = { 
        index: this.chain.length + 1,
        timestamp: Date.now(),
        transactions: this.newTransactions, 
        nonce: nonce,
        hash: hash,
        previousBlockHash: previousBlockHash,          
    };

    this.newTransaction = [];  

}
```

我们这样做是因为，一旦我们创建了新的区块，我们就将所有新的交易放入`newBlock`中。因此，我们希望清空整个新交易数组，以便我们可以为下一个区块重新开始。

1.  接下来，我们要做的就是将我们创建的新区块推入我们的链中，然后我们将返回`newBlock`：

```js
Blockchain.prototype.createNewBlock = function (nonce, previousBlockHash, hash) { 
    const newBlock = { 
        index: this.chain.length + 1,
        timestamp: Date.now(),
        transactions: this.newTransaction, 
        nonce: nonce,
        hash: hash,
        previousBlockHash: previousBlockHash,          
    };

    this.newTransaction = [];
    this.chain.push(newBlock);    

    return newBlock; 
}
```

通过添加这最后两行代码，我们的`createNewBlock`方法已经准备好了。基本上，这个方法在高层次上所做的就是创建一个新区块。在这个区块内，我们有我们的交易和自上一个区块被挖掘以来创建的新交易。创建了新区块后，让我们清空新交易，将新区块推入我们的链中，然后简单地返回我们的新区块。

# 测试`createNewBlock`方法

现在让我们测试我们在前面部分创建的`createNewBlock`方法：

1.  我们需要做的第一件事是导出我们的`Blockchain`构造函数，因为我们将在我们的`test.js`文件中使用这个函数。因此，为了导出构造函数，我们将转到`blockchain.js`文件的底部，输入以下代码行，然后保存文件：

```js
module.exports = Blockchain;
```

1.  接下来，转到`dev/test.js`文件，因为这是我们将测试`createNewBlock`方法的地方。现在，在`dev/test.js`文件中，我们要做的第一件事是导入我们的`Blockchain`构造函数，因此输入以下内容：

```js
const Blockchain = require('./blockchain');
```

上述代码行只是需要或调用`blockchain.js`文件。

# 测试 Blockchain 构造函数

让我们按照以下方式测试 Blockchain 构造函数：

1.  让我们创建一个`Blockchain`构造函数的实例，因此我们将添加以下代码行：

```js
const bitcoin = new Blockchain();
```

1.  上一行代码中的`bitcoin`变量只是用作示例。然后我们添加以下代码行：

```js
console.log(bitcoin); 
```

通过上述代码行，`bitcoin`应该是我们的区块链。目前这里没有数据或区块，但它应该作为一个区块链记录出来。让我们保存`test.js`文件并运行测试，观察终端窗口上的输出。

1.  现在转到我们的终端窗口。在这里，我们目前在`blockchain`目录中，我们的`test.js`文件在我们的`dev`文件夹中，因此在终端中输入以下命令：

```js
node dev/test.js
```

上述代码行将允许我们运行我们编写的测试来测试我们的`Blockchain`构造函数。

1.  现在按下*Enter*，我们将在终端窗口上观察`Blockchain`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/23de40f9-44af-44a7-891e-a3e534e61291.png)

从上述截图的输出中，我们可以观察到`Blockchain`有一个空的链和一个空的交易数组。这正是我们预期的输出。

# 测试 createNewBlock 方法

让我们按照以下步骤测试 createNewBlock 方法：

1.  首先，在我们创建`bitcoin`变量的地方下面，输入以下突出显示的代码行：

```js
const Blockchain = require('./blockchain');

const bitcoin = new Blockchain();

bitcoin.createNewBlock();

console.log(bitcoin); 
```

1.  这个`createNewBlock()`方法需要三个参数，比如`nonce`、`previousBlockHash`和`hash`。为了测试目的，我们现在可以随便传入一些值。这里，nonce 只是一个数字。然后我们将为我们的`previousBlockHash`创建一个虚拟哈希，然后为我们的`hash`参数创建另一个哈希，如下所示：

```js
bitcoin.createNewBlock(2389,'OIUOEREDHKHKD','78s97d4x6dsf');
```

现在，我们正在创建我们的`bitcoin`区块链，然后在我们的比特币区块链中创建一个新区块。当我们退出比特币区块链时，我们应该有一个区块。

1.  保存此文件并在终端中再次运行我们的`test.js`文件。然后您将观察到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/0dae3277-99de-4416-985e-14a3168953f9.png)

在上述截图中，您可以观察到`chain`数组中的整个区块链数据结构。它里面有一个区块，或者说一个对象。这个区块还有我们传递的`hash`、`nonce`和`previousBlockHash`参数。它还有`timestamp`和`index`为`1`。它没有交易，因为我们还没有创建任何交易。因此，我们可以得出结论，`createNewBlock`方法运行正常。

1.  现在让我们通过在我们的链中创建更多的区块来进一步测试我们的方法。让我们多次复制以下代码行，然后尝试更改其中的值：

```js
bitcoin.createNewBlock(2389,'OIUOEREDHKHKD','78s97d4x6dsf');
```

1.  复制代码并更改值后保存文件。现在，当我们运行`test.js`文件时，我们应该在我们的链中有三个区块，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/8eb516d6-29bd-48e1-b177-dd2895418bfc.png)

在上述截图中，您可能已经观察到`chain`数组中的三个区块。这些都是我们用`createNewBlock`方法创建的所有区块。

# 构建 getLastBlock 方法

现在，我们要添加到我们的`Blockchain`构造函数中的下一个方法将是`getLastBlock`。这个方法将简单地返回我们区块链中的最后一个块。按照下面提到的步骤来构建这个方法：

1.  转到我们的`dev/blockchain.js`文件，在我们的`createNewBlock`方法之后添加以下内容：

```js
Blockchain.prototype.getLastBlock = function () { 

}
```

1.  在`getLastBlock`方法中，我们将输入以下突出显示的代码行：

```js
Blockchain.prototype.getLastBlock = function () { 
    return this.chain[this.chain.length - 1];

}
```

在上述代码中的`[this.chain.length - 1];`定义了链中块的位置，在我们的情况下是前一个块，因此通过`1`进行否定。这个方法简单明了，我们将在后面的章节中使用它。

# 创建`createNewTransaction`方法

我们要添加到我们的区块链构造函数中的下一个方法是`createNewTransaction`。这个方法将为我们创建一个新的交易。让我们按照下面提到的步骤来创建这个方法：

1.  通过在我们的`getLastBlock`方法之后添加以下代码来开始构建这个方法：

```js
Blockchain.prototype.createNewTransaction = function () {

}
```

1.  `function ()`将接收三个参数，如下所示：

```js
Blockchain.prototype.createNewTransaction = function (amount, sender, recipient) {

}
```

这三个参数的作用如下：

+   `amount`：此参数将接收交易金额或此交易发送的金额。

+   `sender`：这将接收发件人的地址。

+   `recipient`：这将接收收件人的地址。

1.  我们在`createNewTransaction`方法中要做的下一件事是创建一个交易对象。因此，将以下代码添加到我们的方法中：

```js
const newTransaction = {

}
```

1.  这个对象将有三个属性。它将有一个`amount`，一个`sender`和一个`recipient`。这些都是我们传递给`function()`的相同三个参数。因此，输入以下内容：

```js
Blockchain.prototype.createNewTransaction = function (amount, sender, recipient) {
    const newTransaction = {
        amount: amount,
 sender: sender,
 recipient: recipient,
    };

}
```

这就是我们的交易对象将会是什么样子。我们在`Blockchain`上记录的所有交易都将看起来像这样。它们都将有一个金额，一个发件人和一个收件人，这非常简单明了。

1.  我们现在要做的下一件事是将这个`newTransaction`数据推送到我们的`newTransactions`数组中。让我们在`newTransaction`对象之后添加以下代码来实现这一点：

```js
this.newTransactions.push(newTransaction);
```

因此，我们刚刚创建的新交易现在将被推送到我们的`newTransactions`数组中。

现在，让我们试着理解一下这个`newTransactions`数组实际上是什么。基本上，这个`newTransactions`数组在我们的区块链上会有很多人进行很多不同的交易。他们将会把钱从一个人发送到另一个人，这将会重复发生。每当创建一个新交易时，它都会被推送到我们的`newTransactions`数组中。

然而，这个数组中的所有交易实际上并没有被确定下来。它们实际上还没有被记录在我们的区块链上。当挖掘新块时，也就是创建新块时，所有这些新交易基本上只是待处理交易，并且尚未被验证。当我们使用`createNewBlock`方法创建新块时，它们将被验证，确定下来，并记录在我们的区块链上。

在我们的`createNewBlock`方法中，您可以观察到在`transactions: this.newTransactions`中，我们将新块上的交易设置为`newTransactions`或我们区块链中的待处理交易。您可以将我们区块链上的`newTransactions`属性视为待处理交易属性。

为了方便参考，让我们实际上将代码中的所有`newTransactions`属性更改为`pendingTransactions`属性。总的来说，当创建新交易时，它被推送到我们的`pendingTransactions`数组中。然后，当挖掘新块或创建新块时，我们的所有待处理交易都会记录在我们的区块链上，然后它们就被确定下来，永远不能被更改。

所有这一切的重点是，在我们的方法结束之前，我们希望返回我们将能够找到新交易的区块，因为当新交易被挖掘时，我们的新交易将在下一个区块中。因此，我们只需输入以下代码：

```js
this.newTransactions.push(newTransaction);
return.this.getlastBlock()['index'] + 1;
```

在上述代码中，`this.getlastBlock()`为我们返回一个区块对象。我们想要获取这个区块的 index 属性 - 添加`['index']`将为我们提供链中最后一个区块的索引，添加`+ 1`将为我们提供我们的交易被推送到的区块的编号。

让我们快速回顾一下，`createNewTransaction`方法只是创建一个`newTransaction`对象，然后我们将`newTransaction`推送到我们的`pendingTransactions`数组中。最后，我们返回`newTransaction`将被添加到的区块的编号。

# 测试 createNewTransaction 方法

让我们测试在上一节中创建的`createNewTransaction`方法。提醒一下：这一节将会非常有趣，因为在这里你将真正开始理解区块链有多强大，以及区块和交易是如何相互作用的。您还将学习交易如何记录在区块链中。所以让我们开始吧：

1.  我们将在我们的`test.js`文件中测试我们的`createNewTransaction`方法。在这个文件中，我们已经需要了我们的`blockchain.js`文件，并创建了一个名为`bitcoin`的`Blockchain`的新实例，我们在文件末尾记录了它。快速查看以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/841dc351-8c46-47a1-b1ac-276b187e57eb.png)

1.  现在，在我们的`test.js`文件中，我们要做的第一件事是使用我们的`createNewBlock`方法创建一个新的区块，类似于我们在*测试 createNewBlock 方法*部分所做的。在您的`test.js`文件中输入以下内容：

```js
bitcoin.createNewBlock(789457,'OIUOEDJETH8754DHKD','78SHNEG45DER56');
```

1.  接下来，我们要做的是创建一些新的交易来测试我们的`createNewTransaction`方法。这个`createNewTransaction`方法接受三个参数，比如`amount`，`sender`和`recipient`。让我们将这个交易数据添加到我们的测试用例中：

```js
bitcoin.createNewTransaction(100,'ALEXHT845SJ5TKCJ2','JENN5BG5DF6HT8NG9');
```

在上述代码行中，我们将交易金额设置为`100`，发送方和接收方的地址设置为一些随机哈希数。

您可能已经注意到地址中的`ALEX`和`JEN`的名称。我们添加这些只是为了简化发送方和接收方的识别。实际上，您很可能不会在地址开头看到这种名称。我们这样做是为了更容易地引用这些地址。

现在，让我们快速总结一下我们在测试用例中到目前为止所做的事情。看一下以下代码块：

```js
const Blockchain = require('./blockchain');

const bitcoin = new Blockchain();

bitcoin.createNewBlock(789457,'OIUOEDJETH8754DHKD','78SHNEG45DER56');

bitcoin.createNewTransaction(100,'ALEXHT845SJ5TKCJ2','JENN5BG5DF6HT8NG9');

console.log(bitcoin); 
```

在上述代码中，我们首先需要了比特币区块链，然后创建了一个新的区块。之后，我们创建了一个新的交易，然后记录了比特币区块链。

当我们运行这个`test.js`文件时，我们应该期望看到我们的比特币区块链，它应该有一个链中的区块以及`pendingTransactions`数组中的一个交易，因为我们在创建交易后还没有挖掘或创建新的区块。让我们保存这个文件并运行它看看我们得到什么。

1.  现在转到您的终端窗口，输入以下命令，然后按*Enter*：

```js
node dev/test.js 
```

我们可以在终端窗口上观察比特币区块链，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/8384e707-7642-4498-8e43-335168607f06.png)

在您的窗口输出和上述截图中，您可以观察到我们的链，其中有我们创建的一个区块。在我们的`pendingTransactions`数组中，我们有一个待处理的交易，这是我们在测试用例中创建的交易。从测试的输出来看，我们可以得出结论，到目前为止，我们的`createNewTransaction`方法运行正常。

# 向我们的区块链添加待处理交易

现在让我们试着理解如何将`pendingTransaction`放入我们实际的`chain`中。我们这样做的方式是通过挖掘一个新的区块或创建一个新的区块。现在就让我们这样做：

1.  在创建`newTransaction`之后，让我们使用`createNewBlock`方法创建一个新的区块，如下面的代码所示：

```js
const Blockchain = require('./blockchain');

const bitcoin = new Blockchain();

bitcoin.createNewBlock(789457,'OIUOEDJETH8754DHKD','78SHNEG45DER56');

bitcoin.createNewTransaction(100,'ALEXHT845SJ5TKCJ2','JENN5BG5DF6HT8NG9');

bitcoin.createNewBlock(548764,'AKMC875E6S1RS9','WPLS214R7T6SJ3G2');

console.log(bitcoin);
```

我们所做的是创建一个区块，创建一个交易，然后挖掘一个新的区块。现在我们创建的交易应该出现在我们的第二个区块中，因为我们在创建交易后挖掘了一个区块。

1.  现在保存文件并再次运行测试。让我们看看从中得到了什么。去你的终端，再次输入`node dev/test.js`命令并按*Enter*。你将看到以下截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/a9ef7fc6-b02d-4298-a717-ff658920faad.png)

在这里，我们再次拥有了我们的整个区块链，其中有两个区块，因为我们挖掘了两个区块。这个链有我们的第一个区块（索引：1），其中没有交易，还有我们的第二个区块（索引：2），在其中，如果你看我们的交易，它说有一个包含项目的数组，而第一个区块的交易数组中没有项目。

1.  现在仔细看看第二个区块的交易数组。我们应该期望看到我们之前创建的交易。让我们对我们的测试案例进行以下突出显示的修改：

```js
const Blockchain = require('./blockchain');

const bitcoin = new Blockchain();

bitcoin.createNewBlock(789457,'OIUOEDJETH8754DHKD','78SHNEG45DER56');

bitcoin.createNewTransaction(100,'ALEXHT845SJ5TKCJ2','JENN5BG5DF6HT8NG9');

bitcoin.createNewBlock(548764,'AKMC875E6S1RS9','WPLS214R7T6SJ3G2');

console.log(bitcoin.chain[1]);
```

1.  在这个修改中，我们只是登出了我们链中的第二个区块。代码中的`[1]`定义了第二个区块的位置。保存这个文件并运行它。在输出中，你可以观察到我们只是登出了我们链中的第二个区块，并且你可以看到，对于交易，它有一个包含一个对象的数组。查看以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/9f82129a-ed23-4cb4-852e-effb7e1052b5.png)

这个对象是我们在测试中创建的交易。我们在这里所做的就是创建一个交易，然后通过创建一个新的区块或挖掘一个新的区块来挖掘它，现在我们的交易就在其中了。

现在，让我们进行几个更多的示例，以帮助澄清这里发生了什么。让我们在`createNewBlock`方法之后再次复制并粘贴`createNewTransaction`方法三次。根据需要修改金额。

这里发生的情况是，从顶部开始，我们首先创建一个区块，然后创建一个交易。然后我们创建或挖掘一个新的区块，所以我们应该有一个没有交易的区块和另一个有一个交易的区块。在创建第二个区块后，我们创建了另外三个新的交易。此时，这三个新的交易应该都在我们的`pendingTransactions`数组中，因为我们在创建这三个交易后没有创建新的区块。最后，我们再次登出我们的比特币区块链。你的测试现在应该类似于以下内容：

```js
const Blockchain = require('./blockchain');

const bitcoin = new Blockchain();

bitcoin.createNewBlock(789457,'OIUOEDJETH8754DHKD','78SHNEG45DER56');

bitcoin.createNewTransaction(100,'ALEXHT845SJ5TKCJ2','JENN5BG5DF6HT8NG9');

bitcoin.createNewBlock(548764,'AKMC875E6S1RS9','WPLS214R7T6SJ3G2');

bitcoin.createNewTransaction(50,'ALEXHT845SJ5TKCJ2','JENN5BG5DF6HT8NG9');
bitcoin.createNewTransaction(200,'ALEXHT845SJ5TKCJ2','JENN5BG5DF6HT8NG9');
bitcoin.createNewTransaction(300,'ALEXHT845SJ5TKCJ2','JENN5BG5DF6HT8NG9');

console.log(bitcoin);
```

现在，如果我们保存文件并运行它，我们应该在我们的链中有两个区块，并且在`pendingTransactions`数组中也应该有三个交易。让我们看看我们在这里得到了什么。你将在屏幕上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/30c69a57-08f5-4a1f-ab4c-f47ba6c35ce0.png)

在上面的截图中，你可以看到我们的区块链。在这个链中，我们有两个区块，就像我们期望的那样，并且在我们的`pendingTransactions`数组中，我们有三个交易，这就是我们在测试文件中创建的三个交易。

接下来我们要做的是将这些待处理的交易放入我们的链中。为此，让我们挖掘另一个区块。只需在我们创建的三个交易后复制并粘贴`creatNewBlock`方法，并根据需要修改其参数。当我们现在运行测试时，这三个待处理的交易应该出现在我们的新区块中。保存文件并运行测试。你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/6b8768ca-64a2-493a-ae89-f895e71c5a5f.png)

所以，我们有我们的区块链，其中有三个区块。我们的`pendingTransactions`数组目前是空的，但是那三笔交易去哪了呢？事实证明，它们应该在我们创建的最后一个区块中，也就是索引：3 区块。在这第三个区块中，我们有我们的交易，应该是我们刚刚创建的三笔交易。让我们通过对我们测试代码的最后一行进行微小修改来更深入地了解一下，即`console.log(bitcoin.chain[2]);`。这里的值`2`指定了链中的第三个区块。让我们保存这个修改并再次运行测试。你将看到链中的第三个区块：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/3d4a892c-7972-4159-ad4b-b929943e13fc.png)

在交易数组中，你可以看到我们有我们创建的所有三个交易。这就是我们的`createNewTransaction`和`createNewBlock`方法是如何一起工作的。

如果你对这两种方法如何工作或它们如何一起工作有困难，我们鼓励你在`test.js`文件中进行一些实验，创建一些新的区块，创建一些新的交易，记录一些不同的信息，并对这些事情如何工作有一个很好的理解。

# 对数据进行哈希处理

我们将要看的下一个方法并添加到我们的区块链数据结构中的是`hashBlock`。这个`hashBlock`方法将接收我们的区块并将其数据哈希成一个固定长度的字符串。这个哈希数据将会是随机的。

实质上，我们将把一些数据块传递到这个哈希方法中，作为返回我们将得到一个固定长度的字符串，这个字符串将简单地是从我们传入的数据或我们传入的区块生成的哈希数据。

要将`hashBlock`方法添加到我们的区块链数据结构中，请在我们的`createNewTransaction`方法之后输入以下代码行：

```js
Blockchain.prototype.hashBlock = function(blockdata) {

}
```

在我们的`hashBlock`方法中，`blockdata`将是我们要生成哈希的区块数据的输入数据。

那么，我们如何将一个或多个数据块转换为哈希字符串呢？为了生成哈希数据，我们将使用一个名为**SHA256**的哈希函数。

# 理解 SHA256 哈希函数

**SHA256**哈希函数接收任何文本字符串，对该文本进行哈希处理，并返回一个固定长度的哈希字符串。

要更好地了解哈希数据的样子，请访问[`passwordsgenerator.net/sha256-hash-generator/`](https://passwordsgenerator.net/sha256-hash-generator/)。这是一个哈希生成器。如果你在文本框中输入任何文本，你将得到哈希数据作为输出。

例如，如果我们将`CodingJavaScript`放入文本框中，返回给我们的哈希看起来像以下截图中突出显示的那样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/c0859648-a484-478f-a7e0-75ce71d7340a.png)

在前面的截图中我们可以观察到的输出哈希看起来是随意的，因此有助于保持数据的安全。这就是为什么 SHA256 哈希如此安全的原因之一。

现在，如果我们在输入字符串中添加另一个字符，或者以任何方式改变我们的输入字符串，整个输出哈希将完全改变。例如，如果我们在输入字符串的末尾添加一个感叹号，输出哈希将完全改变。你可以在以下截图中观察到这一点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/35373ad6-ebe7-411b-83cb-56ae2ac854d0.png)

你可以尝试通过在输入字符串的末尾添加新字符来进行实验。你会观察到随着我们添加或删除字符，整个输出哈希每次都会发生巨大的变化，从而生成新的随机模式。

你可能想观察与 SHA256 哈希相关的另一件事是，对于任何给定的输入，输出将始终相同。例如，对于我们的输入字符串`codingJavaScript!`，你将始终得到与之前截图中显示的相同的哈希输出。这是 SHA256 哈希的另一个非常重要的特性。对于任何给定的输入，从该输入返回的输出或哈希将始终相同。

因此，这就是 SHA256 哈希的工作原理。在下一节中，我们将在我们的`hashBlock`方法中实现 SHA256 哈希函数。

# hashBlock 方法

让我们构建我们的`hashBlock`方法。在这个方法中，我们要使用 SHA256 哈希来哈希我们的区块数据。按照下面提到的步骤进行：

1.  使用 SHA256 哈希函数，将其作为 npm 库导入。要做到这一点，去谷歌搜索栏中输入 SHA256，或访问[`www.npmjs.com/package/sha256`](https://www.npmjs.com/package/sha256)。在这个网站上，你将看到我们需要在终端中输入的命令。我们需要在终端中输入以下命令：

```js
npm i sha 256--save
```

1.  完成后，按*Enter*。在以下命令中的`--save`将保存此库作为我们的依赖项。现在，在我们的区块链文件结构中，你可能会看到`node_modules`文件夹已经出现。在这个文件夹中，我们下载了 SHA256 库和所有其他依赖项。

1.  要使用这个 SHA256 库，我们需要将库导入到我们的代码中，这样我们才能使用它。在我们的代码开头，输入以下行：

```js
const sha256 = require('sha256');  
```

上述代码行指定了我们在`blockchain.js`文件中存储的 SHA256 哈希函数，存储为变量 SHA256。通过导入它，我们可以在我们的`hashBlock`方法中使用它。

1.  现在，在我们的`hashBlock`方法中要做的第一件事是更改它所接受的参数。我们将用`previousBlockHash`、`currentBlockData`和`nonce`替换`blockData`参数：

```js
Blockchain.prototype.hashBlock = function(previousBlockHash, currentBlockData, nonce) {

}
```

这三个参数将是我们在`hashBlock`方法中要进行哈希的数据。所有这些数据将来自我们链中的一个单一区块，我们将对这些数据进行哈希，本质上是对一个区块进行哈希。然后我们将得到一个哈希字符串作为返回。

1.  我们要做的第一件事是将所有这些数据转换为单个字符串，因此在我们的`hashBlock`方法中添加以下代码行：

```js
const dataAsString = previousBlockHash + nonce.tostring()+ JSON.stringify( currentBlockData);
```

在上述代码中，`previousBlockHash`已经是一个字符串。我们的 nonce 是一个数字，所以我们将使用`toString`将其更改为字符串。此外，我们的`currentBlockData`将是一个对象，一个包含我们的交易或某种 JSON 数据的数组。它将是一个数组或一个对象，`JSON.stringify`将简单地将该数据（以及任何对象或数组）转换为字符串。一旦运行了整行代码，我们将简单地将所有传递的数据连接成一个单一的字符串。

1.  现在，我们要做的下一件事是创建我们的哈希，如下所示：

```js
const hash = sha256(dataAsString);
```

这是我们从区块或我们传递给函数的所有区块数据中创建哈希的方法。

1.  我们要做的最后一件事就是简单地返回哈希，因此在完成这个方法之前，添加以下内容：

```js
return hash;
```

这是我们的`hashBlock`方法将如何工作。在接下来的部分中，我们将测试这个方法，看看它是否完美地工作。

# 测试 hashBlock 方法

让我们在`test.js`文件中测试我们的`hashBlock`方法。与我们在之前的部分中所做的类似，在我们的`test.js`文件中，我们应该导入我们的区块链数据结构，创建一个新的区块链实例，并将其命名为`bitcoin`。现在，让我们测试我们的`hashBlock`方法：

1.  为此，在我们的`test.js`文件中输入以下突出显示的代码行：

```js
const Blockchain = require ('./blockchain'); 
const bitcoin = new Blockchain (); 

bitcoin.hashBlock();
```

1.  我们的`hashBlock`方法需要三个参数：`previousBlockHash`、`currentBlockData`和`nonce`。让我们在调用`hashBlock`方法的部分之前定义这些变量。我们将从定义`previousBlockHash`开始：

```js
const previousBlockHash = '87765DA6CCF0668238C1D27C35692E11';
```

目前，这个随机字符串/哈希数据将作为我们的`previousBlockHash`的输入。

1.  接下来，我们创建`currentBlockData`变量。这个`currentBlockData`将简单地是一个包含在这个区块中的所有交易的数组。我们将简单地使用这个区块中的交易作为我们的`currentBlockData`，所以在这个数组中，我们将不得不创建一些交易对象，如下所示：

```js
const currentBlockData = [
    {
        amount: 10,
        sender: 'B4CEE9C0E5CD571',
        recipient: '3A3F6E462D48E9',  
    }  
]
```

1.  接下来，至少复制这个交易对象三次，以在数组中创建更多的交易对象，然后根据需要对数据进行修改，目的是改变金额和寄件人和收件人的地址。这将使我们的`currentBlockData`成为一个包含三个交易的数组。

1.  最后，我们必须在我们的`hashBlock`方法中分配`nonce`值：

```js
const nonce = 100;
```

1.  在定义了这些变量之后，我们调用`hashBlock`方法，并传递`previousBlockHash`和`currentBlockData`参数，以及`nonce`：

```js
bitcoin.hashBlock(previousBlockHash, currentBlockData, nonce );
```

1.  此外，让我们尝试将结果推送到终端窗口，以便我们可以观察它。为了做到这一点，我们将不得不对我们之前的代码进行一些微小的修改：

```js
console.log(bitcoin.hashBlock(previousBlockHash, currentBlockData, nonce));
```

在这个测试案例中，我们使用所有正确的参数调用我们的`hashBlock`方法。当我们运行这个文件时，我们应该能够在终端窗口观察到哈希值。

1.  现在保存这个`test.js`文件并运行它，检查我们是否得到了我们期望的输出。

1.  打开你的终端窗口，输入`node dev/test.js`命令，让我们观察一下结果。你将能够观察到与我们的`hashBlock`方法输出相似的结果哈希值。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/34c4b7d1-ad74-482c-b25e-d190cf2d079e.png)

看起来我们的`hashBlock`方法工作得相当好。

1.  尝试更仔细地探索一下`hashBlock`方法。正如前一节所解释的，如果我们改变传递给`hashBlock`方法的一些数据，将会完全改变我们返回的哈希值。

1.  现在尝试通过更改寄件人或收件人地址中的一个字母来测试数据哈希的这个特性。然后保存文件，并再次使用`node dev/test.js`运行它。你将观察到一个完全不同的哈希数据作为输出，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/6b78757c-e711-4dce-93a8-0aa93d024e7f.png)

在上面的截图中，你可以观察到哈希数据和它们之间的差异。

现在，如果我们撤销了对寄件人或收件人地址所做的更改，并再次运行我们的哈希方法，我们将能够观察到与我们最初得到的相同的哈希值。这是因为我们传递的数据与第一次相同。你可以尝试尝试改变数据并观察输出，以进一步探索`hashBlock`方法。

经过这个测试，我们可以得出结论，我们的`hashBlock`方法完美地工作。

# 什么是工作证明？

接下来，我们要添加到我们的区块链数据结构中的方法是`proofOfWork`方法。这个方法对于区块链技术非常重要和必要。正是因为这个方法，比特币和许多其他区块链才如此安全。

现在，你一定对**工作量证明**（PoW）是什么感到好奇。如果我们看一下我们的区块链，每个区块链基本上都是一个区块列表。每个区块都必须被创建并添加到链中。然而，我们不希望随便创建并添加任何区块到链中。我们希望确保每个添加到链中的区块都是合法的，具有正确的交易和正确的数据。这是因为如果它没有正确的交易或正确的数据，那么人们可能会伪造自己拥有多少比特币，并从其他人那里窃取钱财。因此，每次创建新的区块时，我们首先必须通过 PoW 来确保它是一个合法的区块。

`proofOfWork`方法将接收`currentBlockData`和`previousBlockHash`。从我们提供的数据中，`proofOfWork`方法将尝试生成一个特定的哈希。在我们的示例中，这个特定的哈希将以四个零开头。因此，通过给定的`currentBlockData`和`previousBlockHash`，该方法将以某种方式生成一个以四个零开头的结果哈希。

现在让我们试着理解我们如何做到这一点。正如我们在前面的部分中学到的，从 SHA256 生成的哈希基本上是随机的。因此，如果得到的哈希基本上是随机的，那么我们如何从我们当前的区块生成一个以四个零开头的哈希呢？唯一的方法是通过反复试错或猜测和检查。因此，我们将不得不多次运行我们的`hashBlock`方法，直到最终有一次幸运地生成一个以四个零开头的哈希。

现在，你可能会想到我们的`hashBlock`方法的输入是`previousBlockHash`、`currentBlockData`和`nonce`参数。当实际上，我们总是传递完全相同的数据时，这三个参数可能会生成多个不同的哈希，这个问题会让你感到困惑。此外，正如我们从上一节中所知，每当我们传入特定的数据时，我们总是会得到从该数据生成的相同的结果哈希。

那么，我们如何改变这些数据，而不改变我们的`currentBlockData`或`previousBlockHash`，但我们仍然可以得到一个以四个零开头的结果哈希呢？这个问题的答案是，我们将不断改变 nonce 值。

现在这一切可能看起来有点混乱，所以让我们试着通过对`proofOfWork`中实际发生的事情进行一些分解来澄清一下。

基本上，我们的`proofOfWork`中正在发生的事情是，我们将反复对我们的区块进行哈希，直到找到正确的哈希，这个哈希可以是以四个零开头的任何哈希。我们将通过不断增加 nonce 值来改变我们的`hashBlock`方法的输入。第一次运行我们的`hashBlock`方法时，我们将从 0 开始 nonce 值。然后，如果得到的结果哈希不以四个零开头，我们将再次运行我们的`hashBlock`方法，只是这一次我们将 nonce 值增加 1。如果我们再次没有得到正确的哈希值，我们将增加 nonce 值并再次尝试。如果这样不起作用，我们将再次增加 nonce 值并再次尝试。然后我们将不断运行这个`hashBlock`方法，直到找到一个以四个零开头的哈希。这就是我们的`proofOfWork`方法的功能。

你可能会想知道这个`proofOfWork`方法是如何确保区块链安全的。原因是为了生成正确的哈希，我们将不得不多次运行我们的`hashBlock`方法，这将消耗大量的能量和计算能力。

因此，如果有人想要回到区块链并尝试更改一个区块或该区块中的数据 - 也许是为了获得更多的比特币 - 他们将不得不进行大量的计算并使用大量的能量来创建正确的哈希。在大多数情况下，回头尝试重新创建已经存在的区块或尝试用自己的虚假数据重新挖掘已经存在的区块是不可行的。除此之外，我们的`hashBlock`方法不仅接受`currentBlockData`，还接受前一个`BlockHash`。这意味着区块链中的所有区块都通过它们的数据链接在一起。

如果有人试图回去重新挖掘或重新创建已经存在的区块，他们还必须重新挖掘和重新创建每一个在他们重新创建的第一个区块之后的每一个区块。这将需要大量的计算和能量，对于一个成熟的区块链来说是不可行的。一个人必须进去，通过工作证明重新创建一个区块，然后通过为每个区块进行新的工作证明来重新创建每个区块。这对于任何一个成熟的区块链来说都是不可行的，这就是为什么区块链技术如此安全的原因。

总结一下，我们的`proofOfWork`方法基本上会重复哈希我们的`previousBlockHash`，`currentBlockData`和一个 nonce，直到我们得到一个以四个零开头的可接受的生成的哈希。

这一切可能看起来很压抑，现在可能有点混乱，但不用担心 - 我们将在接下来的部分构建`proofOfWork`方法，然后我们将用许多不同类型的数据进行测试。这将帮助您更加熟悉`proofOfWork`方法的功能以及它如何保护区块链。

# 创建`proofOfWork`方法

让我们构建我们在前一节中讨论过的`proofOfWork`方法：

1.  在`hashBlock`方法之后，定义`proofOfWork`方法如下：

```js
Blockchain.prototype.proofOfWork = function() {

}
```

1.  这个方法接受两个参数：`previousBlockHash`和`currentBlockData`：

```js
Blockchain.prototype.proofOfWork = function( previousBlockHash, currentBlockData) { 

}
```

1.  在我们的方法内部，我们要做的第一件事是定义一个 nonce：

```js
Blockchain.prototype.proofOfWork = function( previousBlockHash, currentBlockData) { 
    let nonce = 0;

}
```

1.  接下来，我们要对我们的所有数据进行第一次哈希，所以输入以下突出显示的代码行：

```js
Blockchain.prototype.proofOfWork = function( previousBlockHash, currentBlockData) { 
    let nonce = 0;
    let hash = this.hashBlock(previousBlockHash, currentBlockData,
     nonce); 
}
```

在前面的代码中，您可能会注意到我们使用了`let`这个术语，因为我们的 nonce 和 hash 都会随着我们在方法中的移动而改变。

1.  我们接下来要做的是不断运行`hashBlock`方法，直到我们得到以四个零开头的哈希。我们将通过`while`循环来重复执行这个操作：

```js
Blockchain.prototype.proofOfWork = function( previousBlockHash, currentBlockData) { 
    let nonce = 0;
    let hash = this.hashBlock(previousBlockHash, currentBlockData,
     nonce); 
    while (hash.substring(0, 4) !== '0000' {

 }  
}
```

1.  如果我们创建的哈希值不以四个零开头，我们将希望再次运行我们的哈希，只不过这次使用不同的 nonce 值。因此，在`while`循环内，添加以下突出显示的代码行：

```js
Blockchain.prototype.proofOfWork = function( previousBlockHash, currentBlockData) { 
    let nonce = 0;
    let hash = this.hashBlock(previousBlockHash, currentBlockData,
    nonce); 
    while (hash.substring(0, 4) !== '0000' {
        nonce++;
 hash = this.hashBlock(previousBlockHash, currentBlockData,
        nonce);
    }  
}
```

在`while`循环内，我们再次运行我们的`hashBlock`方法，使用完全相同的数据，只是这次我们的 nonce 增加并且等于 1 而不是 0。这将是我们的 while 循环的第一次迭代。现在，在第一次迭代之后，生成的新哈希不具有前四个字符等于 0000 的特性。在这种情况下，我们将希望生成一个新的哈希。因此，我们的 while 循环将再次运行，nonce 值将再次增加到 2，并且将生成一个新的哈希。如果该哈希也不以四个零开头，那么`while`循环将再次运行，nonce 值将再次增加，并且将再次生成哈希。

我们的循环将继续这样做，直到得到以四个零开头的哈希。这可能需要很多次迭代。这可能发生 10 次，10,000 次或 100,000 次。

这个循环是所有计算将发生的地方，这就是为什么`proofOfWork`方法会消耗如此多的能量——有很多计算在进行。我们将继续通过`while`循环，直到生成一个以四个零开头的合适的哈希。当我们最终得到正确的哈希时，我们的`while`循环将停止运行，在`proofOfWork`结束时，它将简单地返回给我们提供有效哈希的 nonce 值：

```js
Blockchain.prototype.proofOfWork = function( previousBlockHash, currentBlockData) { 
    let nonce = 0;
    let hash = this.hashBlock(previousBlockHash, currentBlockData, nonce); 
    while (hash.substring(0, 4) !== '0000' {
        nonce++;
        hash = this.hashBlock(previousBlockHash, currentBlockData, nonce);
    }  
    return nonce;
}
```

所以，这就是我们的`proofOfWork`方法是如何工作和验证哈希的。

在接下来的部分，我们将测试我们的`proofOfWork`方法，确保它能正常工作。我们还将研究为什么我们返回一个 nonce 值而不是返回哈希。

# 测试`proofOfWork`方法

让我们测试一下我们的`proofOfWork`方法，确保它能正常工作。我们将在`test.js`文件中测试这个方法。所以，让我们开始吧：

1.  打开`test.js`文件。你可能会观察到数据与前一节文件中的以下截图类似，*测试 hashBlock 方法*：

*![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/bba3d0e1-4701-4b4d-9edc-4dab25d74b65.png)*

1.  如果你的`test.js`文件中没有任何数据，就像在上面的截图中显示的那样添加到你的`test.js`文件中，然后你就可以开始测试数据了。

1.  为了测试我们的`proofOfWork`方法，我们需要`previousBlockHash`和`currentBlockData`。所以，在我们的测试用例中，去掉 nonce 值，并在我们的文件中添加以下代码行：

```js
console.log(bitcoin.proofOfWork(previousBlockHash, currentBlockData));
```

现在，我们从`proofOfWork`方法中应该得到的结果是一个 nonce 值。我们的`proofOfWork`方法本质上是测试看看什么是与我们的块数据和`previousBlockHash`一起哈希的正确 nonce 值，以生成一个以四个零开头的结果块哈希。在这里，`proofOfWork`为我们找到了正确的 nonce。

1.  保存这个文件，并在终端窗口中输入`node dev/test.js`命令来运行我们的测试。测试运行后，你会看到一个数字作为输出出现在屏幕上：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/4890a799-e9e5-4e2f-9b82-52ea58c75933.png)

这个数字表示的是，我们的`proofOfWork`方法花了 27,470 次迭代来找到一个以四个零开头的哈希。

1.  现在，为了深入了解整个过程，我们可以在`while`循环中记录我们尝试的每个哈希值。我们将不得不对我们的`while`循环进行一些微小的修改，就像下面的代码块中突出显示的那样：

```js
while (hash.substring(0, 4) !== '0000' {
    nonce++;
    hash = this.hashBlock(previousBlockHash, currentBlockData,
    nonce);
    console.log(hash);
}
```

当我们现在运行我们的测试文件时，会发生的是我们应该能够在终端中看到 27,000 个不同的哈希值被记录出来。除了最后一个之外，这些哈希值都不会以四个零开头。只有最后一个被记录出来的哈希值应该以四个零开头，因为在我们的方法之后，这将终止并返回获得有效哈希值的 nonce 值。

现在再次保存我们的`test.js`文件。你现在可以在屏幕上观察到有大量不同的哈希值被记录到终端中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/0b29a624-1279-4b4b-b0a9-d0c8be618fc4.png)

你还可以观察到，每个被记录出来的哈希值的开头都不会连续出现四个零，直到我们得到最终值。

基本上，这里发生的是我们从`currentBlockData`、`previousBlockHash`和值为 0 的`nonce`生成哈希。然后，对于下一个哈希，我们将`nonce`递增 1。所以，输入数据都是一样的，但是`nonce`值会递增，直到获得有效的哈希。最终，在 27,470 次迭代中，通过 nonce 值获得了有效的哈希。

现在让我们尝试使用我们的`hashBlock`方法。在我们的`dev/test.js`文件中，删除`proofOfWork`方法，并添加以下代码行：

```js
console.log(bitcoin.hashBlock(previousBlockHash, currentBlockData, nonce));
```

在上述代码中，对于 nonce，让我们输入值 27,470。这个值是我们从`proofOfWork`方法中获得的。

我们观察到的输出是使用正确的 nonce 值运行单个哈希，我们通过运行`proofOfWork`方法获得。通过这样做，我们应该在第一次尝试时生成一个以四个零开头的哈希。让我们保存并运行它。一旦测试运行，您将看到以四个零开头的单个哈希，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/cd81285c-c159-4a11-a439-8c12ae5f37ea.png)

`proofOfWork`是区块链技术的一个非常重要的部分。从测试结果中可以看出，计算它非常困难 - 我们花了超过 27,000 次迭代才生成正确的哈希。因此，`proofOfWork`需要大量的能量和许多计算，非常难以计算。

一旦我们有了正确的证明或生成所需哈希的 nonce 值，我们应该很容易验证我们是否有了正确的 nonce 值。我们可以通过简单地将其传递到我们的`hashBlock`方法中来验证这一点 - 我们将获得以四个零开头的哈希。

生成工作证明需要大量工作，但验证其正确性非常容易。因此，如果我们想要回到我们的区块链并检查一个块是否有效，我们只需对该块的数据与前一个块的哈希和从`proofOfWork`挖掘该块时生成的 nonce 进行哈希。如果这给我们返回一个以四个零开头的有效哈希，那么我们已经知道该块是有效的。

因此，从我们的测试中，我们可以得出结论，`proofOfWork`方法的工作符合预期。

# 创建创世区块

我们的区块链数据结构中还需要添加的一件事是创世块。但是什么是创世块？嗯，创世块只是任何区块链中的第一个块。

为了创建我们的创世区块，我们将在`Blockchain()`构造函数内部使用`createNewBlock`方法。转到`dev/blockchain.js`文件，并在区块链构造函数内部输入以下突出显示的代码行：

```js
function Blockchain () {
    this.chain = [];
    this.pendingTransactions =[];
    this.createNewBlock();         
}
```

正如我们在前一节中观察到的，`createNewBlock`方法接受 nonce 的值，`previousBlockHash`和哈希作为参数。由于我们在这里使用`createNewBlock`方法创建创世区块，我们将不会有这些提到的参数。相反，我们只会传入一些任意的参数，如以下代码块中所示：

```js
function Blockchain () {
    this.chain = [];
    this.pendingTransactions =[];
    this.createNewBlock(100, '0', '0');         
}
```

在上面的代码中，我们将 nonce 值传递为`100`，`previousBlockHash`为`0`，哈希值为`0`。这些都只是任意值；您可以添加任何您希望添加的值。

请注意，在创建我们的创世区块时传入这种任意参数是可以的，但是当我们使用`createNewBlock`方法创建新的区块时，我们将不得不传递参数的合法值。

现在保存文件，让我们在`test.js`文件中测试创世区块。

# 测试创世区块

在`dev/test.js`文件中，我们将首先导入我们的区块链数据结构或区块链构造函数，然后将我们的区块链实例化为`bitcoin`。然后我们将以以下方式退出比特币区块链：

```js
const Blockchain = require ('./blockchain');
const bitcoin = new Blockchain ();

console.log(bitcoin);
```

保存此文件，并在终端中键入`node dev/test.js`来运行测试。

运行测试后，我们可以观察到创世区块，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/90baad26-9808-4f2d-b0b3-d502b17bcc25.png)

在上面的截图中，对于链数组，您可以看到我们的链中有一个块。这个块是我们的创世块，它的 nonce 为 100，哈希为 0，`previousBlockHash`为`0`。因此，我们所有的区块链都将有一个创世块。

# 摘要

在本章中，我们首先构建了构造函数，然后继续创建了一些令人惊奇的方法，比如`createNewBlock`、`creatNewTransaction`、`getLastBlock`等。然后我们学习了哈希方法，SHA256 哈希，并创建了一个为我们的区块数据生成哈希的方法。我们还学习了什么是工作量证明以及它是如何工作的。在本章中，您还学会了如何测试我们创建的各种方法，并检查它们是否按预期工作。在以后的章节中，我们将更多地与区块链进行交互，本章学到的方法将对我们非常有用。

如果您想更加熟悉区块链数据结构，建议您打开`test.js`文件，测试所有方法，尝试玩弄它们，观察它们如何一起工作，并且享受其中的乐趣。

在下一章中，我们将构建一个 API 来与我们的区块链进行交互和使用。那将是真正有趣的开始。


# 第三章：通过 API 访问区块链

构建区块链在上一章中，我们构建了我们的区块链数据结构的开端。在本章中，我们将构建一个 API，允许我们与我们的区块链进行交互。为了构建 API，我们将使用 Express.js 库创建一个服务器，然后我们将构建三个不同的端点，这些端点将允许我们与我们的区块链进行交互。

让我们开始从头构建我们的 API。在本章中，我们将涵盖以下主题：

+   设置 Express.js

+   构建 API 基础

+   安装 Postman 和 body-parser

+   构建`/blockchain`端点

+   构建`/transaction`端点

+   构建`/mine`端点

+   测试端点

# 设置 Express.js

让我们开始构建我们的 API 或我们的服务器来与我们的区块链数据结构进行交互。我们将在一个新文件中构建我们的 API，并将其放入我们的`dev`文件夹中。让我们创建一个新文件并将其命名为`api.js`；这就是我们将构建整个 API 的地方：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/418a386b-6fe0-4556-bf50-a72ef42cfb8b.png)

# 安装 Express.js

现在，我们将使用一个名为`Express.js`的库来构建一个服务器或 API。让我们按照下面提到的步骤来安装它：

1.  因此，前往 Google，搜索`Express.js npm`，并点击第一个链接（[`www.npmjs.com/package/express`](https://www.npmjs.com/package/express)）。这将带您到以下页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/97d810b1-7148-424e-9170-78940bc18516.png)

1.  我们必须将其安装为依赖项，因此我们必须在终端中运行以下命令：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/39ae1b21-f1b8-4402-8234-f7034c436bda.png)

现在我们在项目中有 Express 库作为依赖项。

# 使用 Express.js

使用 Express 非常简单：让我们看看如何使用它：

1.  只需复制文档中的示例代码，并将其粘贴到我们的`api.js`文件中：

```js
var express = require('express')
var app = express()

app.get('/', function (req, res) {
 res.send('Hello World')
})

app.listen(3000)
```

正如您所看到的，在我们的文件顶部，我们正在要求`express`，这是我们刚刚下载的库，然后我们正在创建一个`app`。这个`app`将帮助我们处理不同的端点或不同的路由。

例如，我们有一个`get`端点，它只是`/`。通过这个端点，我们发送`Hello World`的响应。整个服务器都在端口`3000`上监听。

1.  要启动此服务器，我们转到终端并运行以下命令：

```js
node dev/api.js
```

1.  现在我们的服务器应该正在运行。我们可以通过在浏览器中点击`get`端点路由来测试这一点，这个路由将简单地是一个端口为`3000`的本地主机。

1.  在浏览器中打开一个新标签，并输入`localhost:3000`。在这里你会看到文本 Hello World：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/89f476ff-ec18-4e5e-9c86-008e8d49e4bc.png)

1.  这是从端点发送给我们的响应。我们可以将文本更改为任何我们想要的，所以让我们将`Hello World`更改为`Hello Coding JavaScript!`：

```js
var express = require('express')
var app = express()

app.get('/', function (req, res) {
 res.send('Hello Coding JavaScript!')
})

app.listen(3000)
```

1.  现在保存并重新启动服务器，通过在终端中再次运行以下命令：

```js
node dev/api.js
```

1.  刷新浏览器标签，您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/ceb988cd-1f4c-4a15-946b-f3369d81f104.png)

就是这样！使用 Express 非常简单和容易。我们将使用 Express.js 库构建所有端点。

# 构建 API 基础

在本节中，我们将继续构建我们的区块链 API，然后我们将首先构建以下三个端点：

+   第一个端点是`/blockchain`，它允许我们获取整个区块链，以便我们可以查看其中的数据。

+   第二个端点是`/transaction`，它允许我们创建一个新的交易。

+   第三个端点是`/mine`，它将允许我们使用我们在上一章中制作的`proofOfWork`方法来挖掘一个新的区块。这将是一个非常强大的端点，也将很有趣。

这基本上将成为我们的区块链 API 的基础。在`dev/networkNode.js`文件中，让我们定义这些端点如下：

```js
const express = require('express');
const app = express();

app.get('/blockchain', function (req, res) {

});

app.post('/transaction', function(req, res) {

});

app.get('/mine', function(req, res) {

});

app,listen(3000);
```

现在，我们还要做的一件事是对`listen`方法进行一些修改：

```js
app,listen(3000, function(){
    console.log('listening on port 3000...'); 

});
```

我们已经向这个方法添加了另一个参数，即一个函数。在这个函数内部，我们只是打印出`Listening on port 3000`字符串。我们这样做的原因只是为了当我们的端口实际运行时，我们会看到这个文本。让我们去我们的终端，再次运行我们的`api.js`文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/792cf9c8-0202-4775-b407-ffdd1cfbc256.png)

如您所见，上面的截图显示我们正在监听端口`3000`。每当我们看到这个文本时，我们知道我们的服务器正在运行。

# 安装 Postman 和 body-parser

在这一部分，我们将在我们的环境中工作，使我们的开发过程变得更容易一些。我们要做的第一件事是安装一个叫做`nodemon`的新包。在我们的终端中的`blockchain`目录中，我们将写入`npm i nodemon --save`命令：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/5968fff1-e3a4-4233-8d87-eede8d1cce1f.png)

每当我们对文件进行更改并保存时，这个 nodemon 库会自动为我们重新启动服务器，这样我们就不必每次更改都要回到终端和代码之间来重新启动服务器。

要使用 nodemon，我们将打开我们的`package.json`文件。在`"scripts"`处，我们将添加一个新的脚本：

```js
{
 "name": "javaScript-blockchain",
 "version": "1.0.0",
 "description": "",
 "main": "index.js",
 "scripts": {
     "test": "echo \"Error: no test specified\" && exit 1",
     "start": "nodemon --watch dev -e js dev/api.js"
 }
 "author": "",
 "license": "ISC",
 "dependencies": {
     "express": "⁴.16.3",
     "nodemon": "¹.17.3",
     "sha256": "⁰.2.0"
 }
}
```

我们已经添加了`"start": "nodemon --watch dev -e js dev/api.js"`。这意味着当我们运行`start`命令时，我们希望`nodemon`监视我们的`dev`文件夹，并关注我们所有的 JavaScript 文件。每当这些 JS 文件中的一个被更改并保存时，我们希望 nodemon 为我们重新启动`dev/api.js`文件。保存`package.json`文件。现在，每当我们在`dev`文件夹中进行更改并保存时，我们的服务器将自动重启。让我们测试一下。

让我们去我们的终端。我们的服务器现在应该正在使用 nodemon：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/47f2c8f5-a9d7-4772-baac-29a9606a9def.png)

我们使用`npm start`命令启动了服务器。您可以看到它正在监听端口`3000`。每当我们更改我们的 JS 文件并保存时，我们会看到我们的服务器会自动重启：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/455346c7-ff50-4824-8520-574eb858ce55.png)

如您所见，服务器再次监听端口`3000`。这只是一个工具，我们用它来让开发对我们来说稍微容易一些。现在，我们想要使用的另一个工具叫做 Postman。

# 安装 Postman

Postman 工具允许我们调用任何我们的 post 端点，并通过我们的请求将数据发送到这些端点。让我们了解如何安装它：

1.  转到[`www.getpostman.com`](https://www.getpostman.com)并下载该应用程序。下载应用程序后，我们可以运行一些小测试，看看如何使用这个 Postman 应用程序来访问我们的`/transaction`端点。

1.  下载 Postman 应用程序后打开它。您将看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/72ba3dea-426e-4216-a1c6-ecc5a4cd4e87.png)

1.  现在，在 Postman 应用程序中，我们将向`http://localhost:3000/transaction`发出 post 请求：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/3b86b437-349e-427a-999c-d5aff285f942.png)

1.  为了测试`/transaction`端点是否工作，让我们在输出中发送一些东西。在我们的`/transaction`端点中，我们添加了以下行：

```js
app.post('/transaction', function(req, res) {
    res.send('It works!!!');
});
```

1.  保存文件，现在当我们访问这个端点时，我们应该得到文本`It works!!!`的返回。点击发送按钮，您将得到输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/109ae641-2a75-41fe-ad41-09b65930b7ba.png)

1.  现在，大多数情况下，当我们在 API 中访问`post`端点时，我们都希望向其发送数据。例如，当我们访问`/transaction`端点时，我们希望创建一个新的交易。因此，我们必须向`/transaction`端点发送交易数据，比如交易金额、发送者和接收者。我们可以使用 Postman 来做到这一点，而且实际上非常简单。我们要做的是在我们的 post 请求的正文中发送一些信息。你可以通过点击 Body 选项卡来实现：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/44f794e7-5400-448d-be08-beacc53be751.png)

1.  接下来，确保选中了原始选项，并从下拉列表中选择了 JSON（application/json）。你还可以看到我们已经创建了一个 JSON 对象，并放入了一些数据。我们已经将`amount`设置为`20`比特币，发送者的地址和接收者的地址。

请记住，所有内容都必须以 JSON 格式呈现，因此我们需要将所有引号都用双引号括起来，否则术语将无法工作。

1.  为了测试我们是否在端点内收到了所有这些信息，我们将打印整个`req.body`。`req.body`就是我们在 JSON 对象中创建的信息：

```js
app.post('/transaction', function(req, res) {
    console.log(req.body);
    res.send(`The amount of the transaction is ${req.body.amount}
     bitcoin.`);
});
```

正如你所看到的，我们还在响应中发送了一些不同的信息。我们在反引号中添加了一个句子，并且还使用了`${req.body.amount}`进行了一些字符串插值，这将返回`amount`。

1.  现在，为了使`${req.body.amount}`起作用，我们需要安装另一个库以访问这些信息。让我们回到终端；我们将退出当前监听端口`3000`的进程，并安装一个名为`body-parser`的包：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/d3b60653-9e7c-4a06-8bf1-77a733fb2257.png)

1.  现在让我们再次用`npm start`启动我们的服务器。

1.  当使用`body-parser`时，我们只需在文件顶部导入它：

```js
const express = require('express');
const app = express();
const bodyParser = require('body-parser');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
```

为了使用`body-parser`库，我们添加了下面两行。这两行代码的作用是说明如果请求中带有 JSON 数据或表单数据，我们只需解析这些数据，以便在任何端点中访问。因此，无论我们访问哪个端点，我们的数据都会首先经过`body-parser`，以便我们可以访问数据，然后在接收数据的端点中使用。

1.  现在我们使用了`body-parser`，我们应该能够访问这个金额。让我们保存`api.js`文件，并尝试发送请求，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/8b3cd1e5-b80a-4193-927a-012d555ffdf1.png)

成功了！我们得到了返回的字符串，其中说明交易金额为 20 比特币。

在我们的终端中，由于我们记录了整个`req.body`，我们可以看到关于金额、发送者和接收者的所有信息都被显示出来：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/b895ca0d-903f-4b37-8730-b6fd14848d98.png)

太好了！现在，还有一件重要的事情要注意，那就是在本章的其余部分，你应该始终保持服务器运行，这意味着你应该始终运行`npm start`命令，这样我们才能使用我们的 API，访问不同的端点，并测试它是否有效。

# 构建/blockchain 端点

让我们继续构建我们的区块链 API。在这一部分，我们将与我们的`/blockchain`端点进行交互。这意味着我们将不得不从我们的`blockchain.js`文件中导入我们的区块链：

```js
const Blockchain = require('./blockchain');
```

我们现在已经导入了我们的区块链数据结构或区块链构造函数。接下来，我们要创建一个区块链的实例。我们可以这样做：

```js
const bitcoin = new Blockchain();
```

现在我们有了我们的区块链构造函数的一个实例，并且我们将其称为`bitcoin`。你可以自己决定叫什么，但我会简单地称其为`bitcoin`。

让我们在`/blockchain`端点上继续构建。这个端点将会将整个区块链发送回给调用它的人。为了做到这一点，我们将添加一行代码来发送响应：

```js
app.get('/blockchain', function(req, res) {
    res.send(bitcoin);
});
```

信不信由你，这就是我们为这个端点要做的全部。

# 测试/blockchain 端点

现在我们可以通过在浏览器中使用它来测试这个端点是否工作：

1.  让我们转到我们的浏览器并访问`localhost:3000/blockchain`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/503448a4-018c-4402-acd9-ffb44f94f206.png)

1.  正如你所看到的，我们得到了整个区块链。现在，你可能已经注意到这有点难以阅读，所以为了使其可读，让我们下载一个名为**JSON 格式化程序**的 Chrome 扩展。你可以在谷歌上搜索并将该扩展添加到你的 Chrome 浏览器中。安装完成后，再次刷新页面，你将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/2d76eacc-200d-4d26-a56e-6ff6b5e62555.png)

正如你所看到的，我们以更易读的 JSON 格式得到了我们的数据。你可以看到我们有`chain`，其中有一项 - 我们的创世区块 - 以及`pendingTransaction`区块。这很酷，我们可以知道我们的`/blockchain`端点正在工作，因为我们得到了整个区块链。

# 构建/transaction 端点

在这一部分，我们将构建我们的交易端点。让我们按照下面提到的步骤进行：

1.  在开始之前，请确保在处理我们的区块链时，你的服务器正在运行。我们可以通过在终端中运行`npm start`命令来做到这一点。

1.  让我们转到我们的`api.js`文件并构建我们的交易端点。首先，去掉我们之前在`/transaction`端点中添加的示例代码，并在我们的区块链中创建一个新的交易。为此，我们将使用我们在第二章中构建的`blockchain.js`文件中的`createNewTransaction`方法，*构建区块链*。

1.  如你所知，我们的`createNewTransaction`方法接受三个参数：`amount`，`sender`和`recipient`：

```js
Blockchain.prototype.createNewTransaction = function(amount, sender, recipient) {
  const newTransaction = {
    amount: amount,
    sender: sender,
    recipient: recipient
  };

  this.pendingTransactions.push(newTransaction);

  return this.getLastBlock()['index'] + 1;
};
```

1.  这个方法返回我们新交易将被添加到的区块编号或索引。这就是我们创建交易所需的一切，所以在我们的`/transaction`端点中，我们将添加以下行：

```js
app.post('/transaction', function(req, res) {
  const blockIndex = bitcoin.createNewTransaction(req.body.amount,
   req.body.sender, req.body.recipient) 
});
```

1.  在我们的端点中，我们假设所有这些数据都是通过`req.body`从调用这个端点的人那里发送过来的。结果将保存在`blockIndex`中，这就是我们将发送回给调用这个端点的人的内容。我们将把它作为一个`note`发送回去：

```js
app.post('/transaction', function(req, res) {
  const blockIndex = bitcoin.createNewTransaction(req.body.amount,
  req.body.sender, req.body.recipient) 
 res.json({ note:`Transaction will be added in block
    ${blockIndex}.`});
});
```

正如你所看到的，这个注释将告诉我们交易将被添加到哪个区块。我们使用了字符串插值来传递`blockIndex`的值。让我们保存这个文件并使用 Postman 测试这个端点。

# 测试/transaction 端点

现在让我们转到 Postman 并应用与我们之前设置的类似的设置：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/2e18b623-0efa-4793-8b9d-4588c791ea3c.png)

我们已经选择了 POST 请求，并且我们的目标是`/transaction`端点。在 Body 选项卡中，我们已经勾选了 raw，并且文本已经选择为 JSON 格式。我们在 JSON 对象中传入了`amount`，`sender`和`recipient`的值，这将成为我们的`req.body`，并且我们将发送所有的交易数据到这个对象上。借助于我们在`/transaction`端点中提到的`req.body`，我们可以访问金额、发送者的地址和接收者。

现在让我们测试这个端点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/a32bfbbb-8d3d-4490-967c-392cf1ea74d4.png)

正如你所看到的，当我们在 Postman 上点击发送按钮时，我们得到了交易将被添加到第 2 个区块的输出。我们之所以在这里得到第 2 个区块，是因为在我们初始化区块链时已经创建了一个区块，这就创建了创世区块。因此，这个交易被添加到了第 2 个区块。

我们可以测试确保这个端点工作正确的另一种方法是访问我们的`/blockchain`端点。当我们访问这个端点时，我们应该期望得到我们整个的区块链。在那个区块链中，应该有一个单独的区块 - 我们的创世区块 - 还应该有一个待处理的交易，这就是我们刚刚创建的交易。让我们转到浏览器，访问`localhost:3000/blockchain`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/c049edde-9d4e-414e-a974-17a774777378.png)

正如你所看到的，整个对象就是我们整个的区块链 - 第一部分是我们的链，其中包含创世区块，第二部分是我们的待处理交易，我们刚刚创建。我们的`/transaction`端点完美地工作。

# 构建/mine 端点

让我们构建我们的区块链 API 的最终端点：挖矿端点，这将挖矿并创建一个新的区块：

1.  为了创建一个新的区块，我们将使用我们在`blockchain.js`文件中已经定义的`createNewBlock`方法。让我们转到我们的`api.js`文件，并在`/mine`端点中创建一个新的区块：

```js
app.get('/mine', function(req, res) {
    const newBlock = bitcoin.createNewBlock();
});
```

1.  这个`createNewBlock`方法接受三个参数：`nonce`，`previousBlockHash`和`hash`：

```js
Blockchain.prototype.createNewBlock = function(nonce, previousBlockHash, hash) {
  const newBlock = {
    index: this.chain.length + 1,
    timestamp: Date.now(),
    transactions: this.pendingTransactions,
    nonce: nonce,
    hash: hash,
    previousBlockHash: previousBlockHash
  };

  this.pendingTransactions = [];
  this.chain.push(newBlock);

  return newBlock;
};
```

1.  现在我们必须进行计算，以获得所有这三个数据，所以让我们开始。让我们从获取上一个区块开始，以便我们可以获取它的 hash：

```js
app.get('/mine', function(req, res) {
  const lastBlock = bitcoin.getLastBlock();
  const previousBlockHash = lastBlock['hash'];
```

正如你所看到的，我们已经创建了`lastBlock`，它是我们链中的最后一个区块 - 或者是我们新区块的上一个区块。为了获取上一个区块的`hash`，我们创建了`previousBlockHash`。有了这个，我们现在可以有我们的`previousBlockHash`，这是我们`createNewBlock`方法下一个需要的参数之一。

1.  接下来，让我们获取我们的`nonce`。为了为我们的区块生成一个`nonce`，我们需要生成一个`proofOfWork`，这是我们在`blockchain.js`文件中创建的：

```js
Blockchain.prototype.proofOfWork = function(previousBlockHash, currentBlockData) {
  let nonce = 0;
  let hash = this.hashBlock(previousBlockHash, currentBlockData,
  nonce);
  while (hash.substring(0, 4) !== '0000') {
    nonce++;
    hash = this.hashBlock(previousBlockHash, currentBlockData,
    nonce);
  }

  return nonce;
};
```

1.  在我们的`/mine`端点，我们将添加以下行：

```js
const nonce = bitcoin.proofOfWork(previousBlockHash, currentBlockData);
```

1.  因此，从我们的`proofOfWork`方法中，我们将得到一个`nonce`返回给我们。让我们将其保存为我们的`nonce`变量。我们的`proofOfWork`方法接受两个参数：`previousBlockHash`，我们已经有了，和`currentBlockData`。让我们定义我们的`currentBlockData`：

```js
const currentBlockData = {
    transactions: bitcoin.pendingTransactions,
    index: lastBlock['index'] + 1
  };
```

我们有我们的`currentBlockData`作为一个对象，其中包含数据。这些数据将简单地包括这个区块中的`transactions`，还有一个`index`，这是我们将要创建的新区块的索引；我们的`lastBlock`的索引加 1。`currentBlockData`对象将简单地是这个新区块中存在的`transactions`和它的`index`。有了这个，我们现在可以计算我们的`nonce`，就像我们用我们的`previousBlockHash`和`currentBlockData`一样。

1.  现在，我们的`createNewBlock`方法必须接受的最后一个参数是这个新区块的`hash`，所以让我们现在计算一下。为了创建这个新区块的`hash`，我们将使用我们的`hashBlock`方法。我们将在我们的`/mine`端点中添加以下行：

```js
const blockHash = bitcoin.hashBlock(previousBlockHash, currentBlockData, nonce);
```

如你所知，我们已经在`blockchain.js`文件中创建了`hashBlock`方法。这个方法接受三个参数：`previousBlockHash`，`currentBlockData`和`nonce`。我们已经有了所有这些参数，所以我们正在调用它，并将结果保存在一个名为`blockHash`的变量中。

1.  我们现在有了我们运行`createNewBlock`方法所需的所有参数，所以让我们分配这些参数：

```js
const newBlock = bitcoin.createNewBlock(nonce, previousBlockHash, blockHash);
```

这里发生的事情非常棒。正如你所看到的，有很多不同的计算涉及到创建这个新区块，我们能够通过使用我们的区块链数据结构来进行所有这些计算。这是一个非常强大的数据结构，我们的区块链现在可以通过使用`proofOfWork`来挖掘新的区块，这与许多其他区块链的功能类似。

1.  在这一点上，我们已经创建了我们的新区块，我们真正需要做的就是将响应发送给挖掘这个区块的人。接下来，我们将在我们的`/mine`端点中添加以下行：

```js
res.json({
  note: "New block mined successfully",
  block: newBlock
});
```

我们只是简单地发送一个说明新块挖掘成功的消息，以及我们刚刚创建的`newBlock`。现在，发送这个`newBlock`不会以任何方式影响我们的区块链。我们发送`newBlock`是为了让创建或挖掘这个新块的人知道它的样子。

1.  现在只剩下一件事情要做：每当有人挖掘一个新块，他们都会得到一个奖励。我们所要做的就是创建一个交易，给挖掘这个新块的人发送一点比特币作为奖励。为此，在`/mine`端点内部，我们将创建一个新的交易：

```js
bitcoin.createNewTransaction(12.5, "00", nodeAddress);
```

目前，在 2018 年，真正的比特币区块链中挖掘新块的奖励是 12.5 比特币。为了保持与真正的比特币一致，我们的奖励也将是`12.5`比特币。作为发送者地址，我们已经放入了值`00`。这样，每当我们在我们的网络上查看交易时，我们知道如果有一个交易是从地址`00`发出的，那就是一个挖矿奖励。

现在我们只需要一个接收者的地址，`nodeAddress`。我们需要把`12.5`比特币发送给挖掘新块的人，但是怎么找到呢？嗯，我们将把这个奖励发送给我们当前所在的节点，也就是我们正在使用的整个 API 文件。我们可以把整个 API 都当作比特币区块链中的一个网络节点。

在未来的章节中，我们将拥有我们 API 的多个实例，并且它们将作为大型干净区块链中的不同网络节点。现在，每当我们访问我们创建的任何端点时，我们总是只与这一个网络节点进行通信。然而，由于我们知道所有的区块链技术都是分散的，并且托管在许多不同的网络节点上，随着我们进一步进行，我们将创建更多的网络节点。但是现在，我们整个的区块链只托管在这一个网络节点上。

现在，每当我们访问`/mine`端点时，我们都希望奖励这个节点挖掘新块。为了给这个节点应得的`12.5`比特币奖励，我们需要一个地址来发送比特币，所以让我们现在为这个节点创建一个地址。

为了为这个节点创建一个地址，我们将使用我们的终端导入一个叫做`uuid`的新库：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/6288cd40-7b48-478d-9e51-c41be1352ef2.png)

一旦你输入了`npm i uuid --save`命令并按下*Enter*，包就会被添加。你可以使用`npm start`命令重新启动服务器。

现在让我们在`api.js`文件的顶部部分导入我们的新的`uuid`库：

```js
const uuid = require('uuid/v1');
```

正如你所看到的，我们已经导入了`uuid`库的第 1 个版本。这个库为我们创建了一个唯一的随机字符串，我们将使用这个字符串作为这个网络节点的地址。为此，我们将添加以下行：

```js
const nodeAddress = uuid().split('-').join('');
```

关于我们从这个库得到的字符串，我们想要改变的一件事是，它里面有一些破折号——我们不希望地址里有任何破折号。在这里，我们只是简单地将该字符串在所有的破折号上分割，然后用一个空字符串重新连接。我们将得到的`nodeAddress`是一个随机字符串，保证是独一无二的。我们真的希望这个字符串是独一无二的，因为我们不希望有两个节点有相同的地址，否则我们会把比特币发送给错误的人，那就不好了。现在我们只需将这个`nodeAddress`变量传递给我们的`createNewTransaction`方法。

在下一部分，我们将测试我们的`/mine`端点，以及我们的`/transaction`和`/blockchain`端点，以确保它们都能正确地工作和互动。

# 测试端点

在这一部分，我们将测试我们的`/mine`端点，以及我们的`/transaction`和`/blockchain`端点，以确保一切都能很好地协同工作。

在测试之前，最好将`proofOfWork`方法中的`console.log`语句删除。这是因为有它只会让你的程序工作更加艰难，因此计算所需的时间会更长。

# /mine 端点测试

首先，让我们测试我们在上一节中构建的`/mine`端点。让我们转到浏览器，访问`localhost:3000/blockchain`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/27159860-0515-4ad1-b755-cfc39e6f70dc.png)

现在，我们有整个区块链，链中有一个区块 - 我们的创世区块 - 也没有待处理交易。

现在让我们打开另一个标签页，点击我们的`/mine`端点。这应该为我们挖矿并创建一个新的区块：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/8a3c1bae-7c6a-4f15-a9e9-912ee486e2b1.png)

我们收到了一条新的区块成功挖掘的消息。我们还收到了我们的新区块，并且我们可以看到区块上的所有数据。它里面有一个哈希，还有前一个区块的哈希，即创世区块，以及一个交易。也许你会想，我们并没有创建交易，那么这笔交易是从哪里来的呢？实际上，这笔交易是我们放入端点的挖矿奖励，即`12.5`比特币的挖矿奖励交易。看起来我们的挖矿端点运行良好。

# 测试/blockchain 端点

为了测试并确保我们确实创建了这个新区块，我们可以转回到我们的`/blockchain`端点并刷新页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/b973345b-7a12-47b2-9cd6-10a03ce396ff.png)

成功了。我们现在的链中有两个区块：一个是创世区块，另一个是我们刚刚创建的区块。第二个区块中也有交易，其中包括奖励。

让我们再挖掘一个区块来再次测试。转到我们的`/mine`端点并刷新页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/62c65840-d91e-4324-864e-3b800ce08803.png)

我们刚刚挖掘了另一个区块，这是我们的第三个区块。我们可以看到我们得到了`timestamp`和另一笔交易，即挖矿奖励，还有我们的其他数据。现在让我们转回到我们的`/blockchain`端点并刷新页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/f551127f-285d-44b3-8f00-52d320304f15.png)

正如你所看到的，我们有三个区块。区块 3 是我们刚刚创建的区块，里面有我们的挖矿奖励交易。还有一件事要注意的是，我们的`previousBlockHash`实际上与我们的区块 2 的`hash`对齐。这有助于保护我们的区块链，这很好。

# 测试/transaction 端点

现在让我们使用我们的`/transaction`端点创建一些交易。为此，请转到 Postman，确保设置与之前相同，并进行以下更改：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/b9b13fa5-473f-4b01-a561-a5f54f307980.png)

我们将`amount`设置为`1000`比特币。我们将保留发送方和接收方地址不变，但你可以根据需要进行更改。一旦我们提交到`/transaction`端点，我们应该得到文本交易的响应，该交易将被添加到第 4 个区块中，我们确实得到了这个响应。这笔交易被添加到第 4 个区块，因为我们的链中已经有了三个区块。

让我们进行另一个示例交易。在这里，我们将`amount`更改为`50`比特币，并对发送方和接收方的地址进行一些更改。因此，当我们发送此请求时，我们应该得到相同的响应：交易将被添加到第 4 个区块。这是因为我们还没有挖掘新的区块。让我们试一试：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/ad5f9a4a-5d5f-487f-b92f-8773b8e4ef06.png)

这很有效。现在让我们再次获取整个区块链。这次，我们应该期望得到与我们刚刚创建的相同的区块链和两笔待处理交易。让我们刷新页面并查看输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/a56bf39c-d051-43ed-94fd-7b8ecc38ecb0.png)

你会注意到这里有三个区块和两笔待处理交易。现在，如果我们转到我们的`/mine`端点并刷新页面，这两笔待处理交易将被添加到第 4 个区块中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/a5584741-a1fa-4161-a36c-2348cca735ca.png)

我们已成功挖掘了一个新的区块。它包含我们的数据，也有三笔交易。前两笔交易是我们在 Postman 中创建的，第三笔是我们的挖矿奖励交易。现在，如果我们回到我们的`/blockchain`端点并刷新它，我们会看到两笔待处理的交易已经消失，并且它们已被添加到第 4 个区块中。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/74d7086d-490a-4234-9463-78585bbd3250.png)

正如您所看到的，第 4 个区块包含了所有三笔交易，我们的`pendingTransactions`现在为空。效果很好。现在，我鼓励您创建更多的交易并挖掘另一个区块，以确保一切都正常工作。

通过构建整个 API 和区块链，并真正理解代码的工作原理，更容易理解区块链技术的实际运作方式，您也会意识到其中很多实际上并不那么复杂。

在测试这些端点的任何时候，如果您对文件进行更改并保存，服务器将重新启动。这将导致区块链的新实例，这意味着到目前为止创建的所有内容都将被清除。

# 摘要

在本章中，我们学习了如何在项目中设置 Express.js，以及如何使用它来构建我们的 API/服务器。然后我们安装了 Postman，并了解了如何使用它来测试我们的端点。之后，我们继续构建了服务器的各种端点，并测试它们以验证它们是否正常工作。

在下一章中，我们将创建一个节点网络或去中心化网络来托管我们的区块链，就像在现实世界中托管的那些一样。


# 第四章：创建分散的区块链网络

在本章中，让我们专注于构建分散的区块链网络。我们的区块链目前的工作方式是我们有一个单一的区块链，而访问它的唯一方式是通过 API：我们的单一服务器。这个服务器非常集中，这并不好，因为 API 完全控制着区块链和添加到其中的数据。

在现实世界中，所有区块链技术都托管在分散网络中。在本章中，这就是我们要专注于构建的内容。我们将通过创建各种 API 实例来构建一个分散的区块链网络。这些 API 实例中的每一个都将成为我们区块链网络中的一个网络节点。所有这些节点将共同工作来托管我们的区块链。

这样一来，不仅仅是一个单一的网络节点完全控制着我们的区块链。相反，我们的区块链托管在整个分散网络中。这样，如果我们的网络中有一个坏的参与者，或者有人试图欺骗系统，我们可以参考其他网络节点来查看我们的区块链内部应该是什么样的真实数据，以及我们的区块链实际上应该是什么样的。

我们的区块链托管在分散网络中非常强大，因为它极大地增加了我们的区块链的安全性，因此我们不必只信任一个单一实体来处理我们所有的数据。

在本章中，我们将涵盖以下主题：

+   学习如何创建和测试多个节点

+   将`currentNodeUrl`添加到我们的网络

+   为分散网络添加新的端点

+   构建`/register-and-broadcast-node`端点

+   构建和测试`/register-node`端点

+   添加和测试`/register-nodes-bulk`端点

+   测试所有网络端点

让我们开始创建我们的分散网络。

# 创建多个节点

让我们从构建分散网络开始：

1.  要创建我们的分散区块链网络，我们首先需要对我们的`api.js`文件进行一些修改。

1.  在我们的分散网络中，我们将有多个 API 实例，每个实例都将充当网络节点。由于我们将处理多个网络节点，最好将我们的`api.js`文件重命名为`networkNode.js`以便易于引用。

1.  要设置分散网络，我们将不得不多次运行`networkNode.js`文件。每次运行文件时，我们希望它作为不同的网络节点。我们可以通过在每次运行时在不同的端口上运行文件来实现这一点。为了每次都有不同的端口值，我们将把端口作为一个变量。为此，在我们的`dev/networkNode.js`的代码开头添加以下行：

```js
const port = process.argv[2]; 
```

1.  接下来，打开`package.json`文件并对`start`命令进行修改。我们要做的是转到命令的末尾，并传递我们想要网络节点运行的端口号的变量。在我们的示例中，我们希望我们的网络节点在端口号`3001`上运行。因此，在启动命令的末尾传递`3001`作为变量：

```js
"start": "nodemon --watch dev -e js dev/api.js 3001"
```

为了访问这个变量，我们在我们的`networkNode.js`文件中传递了`process.argv`变量。那么，`process.argv`变量是什么？这个变量简单地指的是我们运行启动服务器的`start`命令。

您可以将前面的`start`命令视为元素数组。命令的第一个和第二个元素由“nodemon --watch dev -e js dev/api.js”组成，命令的第三个元素是`3001`变量。

如果您想向命令添加更多变量，只需在其后添加更多变量。

因此，为了在`start`命令中访问端口变量，我们将变量作为`process.argv [2]`传递，因为这个数组从`0`索引开始，我们的端口变量是开始命令中的第三个元素。为了简化这个过程，我们可以通过在位置 2 处声明`process.argv`来访问`3001`变量。因此，我们可以在`dev/networkNode.js`文件中访问我们的`port`变量。

1.  接下来，我们想要使用`port`变量。因此，在`dev/networkNode.js`文件中，转到底部，我们已经提到了以下代码：

```js
app.listen(3000, function() {
    console.log('Listening on port 3000...');
});
```

1.  一旦找到这个，对其进行如下突出显示的修改：

```js
app.listen(port, function() {
    console.log(`Listening on port ${port}...`);
});
```

在前面的代码块中，我们用我们的`port`变量替换了硬编码的`3000`端口号。我们还通过使用字符串插值和传递端口变量，将`Listening on port 3000...`改为`Listening on port ${port}...`。现在，当我们运行`networkNode.js`文件时，它应该在端口`3001`上监听，而不是在端口`3000`上。

1.  在运行`networkNode.js`文件之前，我们需要更改的一个小细节是在`package.json`文件的`start`命令中，我们需要将`api.js`文件的名称更改为`networkNode.js`。

1.  现在我们已经准备好通过传入我们想要的任何端口变量来运行`networkNode.js`文件。

1.  让我们运行`networkNode.js`文件。在终端窗口中，输入`npm start`。通过输入这个命令，服务器应该开始监听端口`3001`，正如我们在下面的截图中所观察到的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/05dc694f-141a-40f3-97a1-13d3447bd607.png)

1.  从前面的截图中，我们可以观察到服务器正在监听端口`3001`。我们可以通过在浏览器中输入`localhost:3001/blockchain`来进一步验证这一点。您应该看到类似于下面截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/a719f771-fc07-439e-8331-8c20cf0f3043.png)

1.  从前面的截图中，我们可以看到我们的区块链现在托管在端口`3001`上，而不是在端口`3000`上。如果我们去端口`3000`，就会像下面的截图所示的那样，什么也没有。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/501f3d91-83ef-475e-821b-ba73449070e9.png)

# 运行多个`networkNode.js`实例

接下来我们要做的事情是运行多个`networkNode.js`实例。为此，我们将在`package.json`文件中添加一些命令：

1.  首先，在`package.json`文件中，我们必须将`"start"`命令更改为`"node_1"`。现在，当我们运行此命令时，它将启动我们的第一个节点，即端口`3001`上的节点。让我们试一试。

1.  保存文件，转到终端，并通过输入`^C%`取消之前的进程。在这样做之后，而不是输入`npm start`，输入`npm run node_1`。通过这个命令，运行我们的`node_1`在端口`3001`上：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/95ea347b-d753-4eb7-8441-cc8cd4bf1b5e.png)

在这个过程中，我们真正做的是将`npm start`命令更改为`npm run node_1`。

1.  对于我们的分散网络，我们希望同时运行几个这样的节点。让我们回到我们的`package.json`文件，并添加类似于`"node_1"`的更多命令。为此，将`"node_1": "nodemon --watch dev -e js dev/networkNode.js 3001",`命令复制四次，然后对这些命令进行修改，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/bb271a9f-6803-490c-96f2-15ccdc17cbbb.png)

1.  现在，保存这个修改，让我们回到终端并启动其他网络节点。从上一次运行中，我们有第一个节点`node_1`在端口`3001`上运行。对于这次运行，我们将希望在端口`3002`上运行第二个节点`node_2`。因此，只需输入`npm run node_2`然后按*Enter*。我们将在屏幕上观察到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/1401807f-a32a-4a46-9add-3e9884fd2169.png)

我们现在有一个运行在端口`3001`上的网络节点，另一个运行在端口`3002`上的网络节点。按照类似的过程在剩下的端口上运行剩下的网络节点。

为了更好地可视化和易于理解，建议您尝试在终端窗口的不同标签上运行每个节点。

通过遵循这个过程，我们实际上正在创建我们的`networkNode.js`文件的五个不同实例。因此，基本上，我们有五个不同的网络节点在运行。

在浏览器中，我们可以通过更改`localhost:3001/blockchain`中的端口号来检查这些网络节点中的每一个。通过这样做，我们将在不同的端口上得到不同的区块链。

# 测试多个节点

我们将继续探索上一节中创建的五个独立网络节点。到目前为止，您可能已经运行了所有五个网络节点。如果没有，请回到上一节，了解如何使这些节点中的每一个运行是值得推荐的。我们目前拥有的，即五个独立运行的网络节点，实际上并不是一个网络。我们只有五个独立的节点或我们的 API 的五个独立实例，但它们没有以任何方式连接。为了验证这些网络节点没有连接，我们可以进行一些测试：

1.  所以，让我们转到 Postman，并尝试通过在我们正在运行的不同网络节点上命中`/transaction`端点来进行一些不同的交易。

1.  我们要进行的第一笔交易将是到我们托管在端口`3001`上的网络节点。因此，让我们进入正文，并输入一些随机交易数据，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/65cccdf0-f3aa-4357-974d-3a132f5d3b74.png)

1.  我们的交易数据有 30,000 比特币，我们将其发送到端口`3001`上托管的网络节点。单击发送按钮，如果交易成功，您将获得以下响应，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/1e7ac10a-deee-434a-b4ad-ffcb10faf3bd.png)

1.  现在让我们向托管在端口`3003`上的网络节点进行 10 比特币的交易。然后单击发送按钮将交易发送到端口`3003`上的网络节点。在这里，您也将看到类似的响应。

1.  现在我们已经将交易数据发送到网络节点，让我们验证一下。转到浏览器，然后转到`localhost:3001/blockchain`，然后按*Enter*。您将看到一个类似的响应，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/f09a700f-459c-4b9e-ac96-6eaa7bfdc362.png)

从前面的屏幕截图中，您可以看到我们有一个未决的 30,000 比特币交易。这是我们刚刚添加的交易之一。

1.  现在，在另一个标签中，如果我们转到`localhost:3002/blockchain`，您将看到我们没有未决交易，因为我们没有向这个网络节点发送任何交易：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/16eb2397-7d30-4ec1-aff6-6549cc2a0d9b.png)

1.  接下来，如果我们转到`localhost:3003/blockchain`，您将看到我们有一个未决的 10 比特币交易：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/3eaf03d0-47f1-4a5b-a1ca-30942869c4e7.png)

这是我们进行的另一笔交易。

如果我们去`localhost:3004/blockchain`和`localhost:3005/blockchain`，那里应该没有交易，因为我们没有向这些网络节点发送任何交易。

从这次测试中我们可以得出的结论是，尽管我们有五个不同的网络节点并行运行，但它们没有以任何方式连接。因此，本章的主要目的将是将所有网络节点连接到彼此，以建立一个去中心化的网络。

# 添加当前节点 URL

在测试我们的节点之后，我们要做的下一件事是稍微修改`package.json`中的命令。我们要这样做的原因是因为我们希望我们的每个网络节点都知道它们当前所在的 URL。例如，它们可能在`http://localhost:3001`、`localhost:3002`、`localhost:3003`等上。因此，我们希望每个节点都知道它所托管的 URL。

在我们的`package.json`中，作为我们每个命令的第三个参数，我们将添加节点的 URL。因此，我们第一个节点的 URL 将简单地是`http://localhost:3001`。很可能对于我们的第二个节点，它将是`http://localhost:3002`。同样，您可以像下面的截图所示为其余节点添加 URL：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/ee845e2e-6061-4be3-87ce-65abd81fd763.png)

添加 URL 后，保存文件。现在我们已经将每个节点的 URL 作为参数传递给我们用来运行每个节点的命令。因此，我们应该可以在我们的文件内访问这些 URL，就像我们在我们的文件内访问我们的端口变量一样。

现在让我们转到`blockchain.js`文件，并在定义常量的部分，我们将输入以下内容：

```js
const currentNodeUrl = process.argv[3];
```

使用此命令，我们应该可以通过使用`currentNodeUrl`变量访问当前节点的 URL。

现在我们应该将`currentNodeUrl`分配给我们的`Blockchain`数据结构。我们通过在我们的`function Blockchain {}`内输入以下突出显示的代码行来执行此操作：

```js
function Blockchain() {
       this.chain = [];
       this.pendingTransactions = [];

       this.currentNodeUrl = currentNodeUrl;

       this.createNewBlock();
};
```

接下来，我们还希望我们的区块链能意识到我们网络中的所有其他节点。因此，我们将在上述突出显示的代码行下面添加以下代码：

```js
this.networkNodes = [];
```

在接下来的部分，我们将用我们网络中所有其他节点的节点 URL 填充这个数组，以便每个节点都能意识到我们区块链网络中的所有其他节点。

# 新端点概述

在我们的区块链中，我们现在想要创建一个网络，并且有一种方法来注册我们的所有不同节点。因此，让我们创建一些端点，这将使得我们可以向我们的网络注册节点成为可能。

# 定义`/register-and-broadcast-node`端点

我们创建的第一个端点将是`/register-and-broadcast-node`，定义如下：

```js
app.post('/register-and-broadcast-node', function (req, res) {

});
```

上述端点将注册一个节点并将该节点广播到整个网络。它将通过在`req` body 中传递我们要注册的节点的 URL 来执行此操作。因此，在上述端点内输入以下内容：

```js
const newNodeUrl = req.body.newNodeUrl;
```

我们现在不会构建这个端点，但是当我们在后面的部分中使用它时，我们将发送要添加到我们网络中的新节点的 URL。然后我们将进行一些计算并将节点广播到整个网络，以便所有其他节点也可以添加它。

# 创建/register-node 端点

`/register-node`将是我们将添加到我们网络中的下一个端点。定义如下：

```js
app.post('/register-node', function (req, res) {

});
```

这个端点将在网络中注册一个节点。

# `register-and-broadcast-node`和`register-node`端点之间的区别

现在让我们试着理解`/register-and-broadcast-node`和`/register-node`端点的不同之处。基本上，这里将发生的是，每当我们想要向我们的网络注册一个新节点时，我们将会命中`/register-and-broadcast-node`端点。这个端点将在自己的服务器上注册新节点，然后将这个新节点广播到所有其他网络节点。

这些网络节点将在`/register-node`端点内简单地接受新的网络节点，因为所有这些节点所要做的就是简单地注册广播节点。我们只希望它们注册新节点；我们不希望它们广播新节点，因为这已经发生了。

如果网络中的所有其他节点也广播新节点，那将严重影响我们的区块链网络性能，并导致一个无限循环，导致我们的区块链崩溃。因此，当所有其他网络节点接收到新节点的 URL 时，我们只希望它们注册而不广播。

# 定义/register-nodes-bulk 终端

在本节中，我们将构建的最终终端将是`/register-nodes-bulk`终端：

```js
app.post('/register-nodes-bulk', function (req, res) {

});
```

此终端将一次注册多个节点。

# 了解所有终端如何一起工作

在这个阶段了解所有这些终端可能会有点混乱，所以让我们尝试通过图表来理解。在下图中，我们有我们的区块链网络：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/71f53dfa-9348-46fe-8838-40c861f1dc5f.png)

现在假设这五个网络节点已经相互连接，从而形成我们的去中心化网络。另外，假设我们想要将托管在`localhost:3009`上的节点添加到我们的网络中。

我们要做的第一件事是将该节点添加到我们的网络中，即在我们的网络节点中的一个上命中`register-and-broadcast-node`终端：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/5a7ab59d-188a-4e1d-90b1-ea2e81232cee.png)

当我们命中`register-and-broadcast-node`终端时，我们需要发送我们想要添加到我们的网络中的新节点的 URL。对于我们的示例，URL 是`localhost:3009`。这是向我们的网络添加新节点的第一步。我们必须使用新节点的 URL 作为数据命中我们的`register-and-broadcast-node`终端。

在上图中，我们命中的网络节点将在其自己的节点上注册这个新的 URL，然后将这个新节点的 URL 广播到网络的其余部分。我们的网络中的所有其他节点将在`register-node`终端接收到这些数据：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/ec42ecbb-8b21-4f13-890e-fb1269c45861.png)

我们将在所有其他网络节点上命中`register-node`终端，因为我们不需要再广播数据，我们只需要注册它。

现在，在所有其他网络节点上注册了新的 URL 后，我们的原始节点将向新节点发出请求，并命中`register-node-bulk`终端：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/3664b8e3-8571-4e2f-aabf-db42c9e92719.png)

此外，原始节点将传递所有其他节点的 URL。因此，此调用将注册网络中已经存在的所有其他节点与新节点。

此时，该节点现在是网络的一部分，网络中的所有节点也将意识到网络中存在的所有其他节点。

现在让我们再次回顾整个过程。我们要做的第一件事是在我们的网络中的一个节点上命中`/register-and-broadcast-node`终端，以添加一个新节点到我们的网络中。此终端将注册新节点的 URL，然后将该新 URL 广播到网络中的所有其他节点。广播完成后，我们命中的原始网络节点将向新网络节点发送请求，并命中`register-nodes-bulk`终端。通过这样做，它将注册网络中的所有其他节点与我们的新节点。

因此，当整个过程完成时，所有这些节点将成为我们去中心化的区块链网络的一部分，并且它们将相互注册。

这就是这三个终端如何一起工作的。在接下来的部分，我们将构建`register-and-broadcast-node`终端。

# 构建/register-and-broadcast-node 终端

让我们开始构建我们的注册和广播节点终端。这个终端的功能将是向自身注册新节点，然后将新节点广播到网络中已经存在的所有其他节点。所以，让我们开始构建这个终端：

1.  从前面的部分，在`dev/networkNode.js`文件中，我们已经有以下代码：

```js
app.post('/register-and-broadcast-node', function(req, res) {
       const newNodeUrl = req.body.newNodeUrl;
```

在这里，我们定义了一个名为`newNodeUrl`的变量，这个`newNodeUrl`数据将被传递到请求体中，类似于我们将交易数据传递到交易端点的方式。有了`newNodeUrl`的访问权限，我们想要做的第一件事是注册节点到节点的`register-and-broadcast-node`端点。

1.  要注册它，我们所要做的就是将`newNodeUrl`放入我们的`blockchain`数据结构的`networkNodes`数组中。为此，在前面的代码块中添加以下突出显示的代码：

```js
app.post('/register-and-broadcast-node', function(req, res) {
       const newNodeUrl = req.body.newNodeUrl;
      bitcoin.networkNodes.push(newNodeUrl); 
```

1.  通过添加上述代码行，我们将`newNodeUrl`推送到`networkNodes`数组中。只有在数组中`newNodeUrl`尚未存在时才这样做。通过以下`if`语句来检查：

```js
app.post('/register-and-broadcast-node', function(req, res) {
       const newNodeUrl = req.body.newNodeUrl;
      if (bitcoin.networkNodes.indexOf(newNodeUrl) == -1) bitcoin.networkNodes.push(newNodeUrl);
```

`if`语句正在检查`newNodeUrl`是否已经存在于`networkNodes`数组中。如果不存在，则将其添加到数组中。因此，借助上述代码块，`newNodeUrl`将被注册到`register-and-broadcast-node`端点。

1.  现在我们已经注册了`newNodeUrl`，现在我们要做的是将其广播到网络中的所有其他节点。为此，在 if 块之后添加以下代码行：

```js
bitcoin.networkNodes.forEach(networkNodeUrl => {
    //... '/register-node' 

}
```

在上述代码块中，对于已经存在于网络中的每个网络节点，或者对于已经存在于`networkNodes`数组中的每个网络节点，我们都希望通过命中注册节点端点来注册我们的`newNodeUrl`。为此，我们将不得不在这个端点向每个单独的节点发出请求。

1.  我们将通过导入一个新的库来进行此请求。让我们去终端导入这个库。在终端中，我们将取消我们的第一个网络节点，然后输入以下命令：

```js
npm install request-promise --save 
```

1.  安装这个`request-promise`库将允许我们向网络中的所有其他节点发出请求。一旦安装了该库，再次输入`npm run node_1`来重新启动第一个节点。

1.  现在让我们去`dev/networkNode.js`文件，并将我们刚刚下载的库导入到代码中。在开头输入以下代码来导入库：

```js
const rp = require('request-promise');
```

在上述代码行中，`rp`代表请求承诺。

1.  现在让我们在`register-and-broadcast-node`端点中使用这个库。在这里，我们必须将我们的`newNodeUrl`广播到我们网络中的所有其他节点。使用我们刚刚导入的`request-promise`库来完成这个操作。

我们将要添加到代码中的下一些步骤可能看起来有点混乱，但不要担心。步骤完成后，我们将逐步走过代码，确保一切对您来说都是清晰的。现在让我们看看以下步骤：

1.  我们的`request-promise`库的第一件事是定义我们将使用的一些选项，因此输入以下突出显示的代码行：

```js
bitcoin.networkNodes.forEach(networkNodeUrl => {
    const requestOptions = {

 }

}
```

1.  在这个对象中，我们想要定义我们要为每个请求使用的选项。

1.  我们要定义的第一个选项是我们要命中的 URI/URL。我们知道我们要命中所有其他`networkNodeUrl`上的`register-node`端点。因此，我们将在前面的代码块中添加以下突出显示的代码行：

```js
bitcoin.networkNodes.forEach(networkNodeUrl => {
    const requestOptions = {
    uri: networkNodeUrl + '/register-node', 
    }

}
```

1.  接下来，我们想定义我们要使用的方法。要命中`register-node`端点，我们将不得不使用`POST`方法，因此在前面的代码块中添加以下代码：

```js
method: 'POST',
```

1.  然后我们想知道我们将传递哪些数据，所以添加以下内容：

```js
body: { newNodeUrl: newNodeUrl }
```

1.  最后，我们要将`json`选项设置为 true，这样我们就可以将其作为 JSON 数据发送：

```js
json: true
```

1.  这些是我们要用于每个请求的选项。现在让我们看看如何使用这些选项。在`requestOptions`块之后，添加以下代码行：

```js
rp(requestOptions)
```

1.  上述请求将返回一个 promise 给我们，我们希望将所有这些 promise 放在一个数组中。因此，在`forEach`循环之前和之内，执行以下突出显示的更改：

```js
const regNodesPromises = [];
bitcoin.networkNodes.forEach(networkNodeUrl => {
    const requestOptions = {
        uri: networkNodeUrl + '/transaction',
        method: 'POST',
        body: newTransaction,
        json: true
    };
 regNodesPromises.push(rp(requestOptions));
});
```

1.  现在在`forEach`循环之外，我们希望运行我们请求的所有 promise。在循环之后添加以下代码：

```js
Promise.all(regNodesPromises)
.then(data => {
    //use the data...
});
```

# 继续在/register-and-broadcast-node 端点上工作

在这一部分，让我们继续构建我们的`register-and-broadcast-node`端点。到目前为止，我们已经在当前网络节点上注册了新节点，并且已经将新节点广播到我们网络中的所有其他节点。因此，我们正在访问我们网络中所有其他节点上的`register-node`端点。另外，目前我们假设那些其他节点正在注册新节点，虽然我们还没有构建它，但我们假设它正在工作。

在整个广播完成后，我们必须将目前在我们网络中的所有节点注册到我们正在添加到网络中的新节点。为此，我们将使用我们的`request-promise`库。因此，我们需要定义一些选项，如下面的代码中所突出显示的：

```js
Promise.all(regNodesPromises)
.then(data => {
   const bulkRegisterOptions = { 
        uri: newNodeUrl + '/register-nodes-bulk'  
        method: 'POST',
 body: {allNetworkNodes: [...bitcoin.networkNodes,
        bitcoin.currentNodeUrl]} 
 json:true
 }; 
  });
});
```

在上述代码中，我们定义了要使用的选项（如`uri`）以及`POST`方法。在 body 选项中，我们定义了`allNetworkNodes`数组，并且在这个数组内，我们希望包含我们网络中所有节点的所有 URL，以及我们当前所在节点的 URL。此外，您可能已经注意到我们在数组中使用了扩展运算符`...`，因为`bitcoin.networkNodes`是一个数组，我们不希望一个数组嵌套在另一个数组中。相反，我们希望展开这个数组的所有元素并将它们放入我们的外部数组中。最后，我们希望将`json`定义为`true`。

接下来，我们想要发出请求，因此在选项块之后，添加以下内容：

```js
return rp(bulkRegisterOptions);
```

之后，添加以下内容：

```js
.then (data => {

})
```

在上述代码行中的`data`变量实际上将是我们从上述 promise 中收到的数据。我们不打算对这些数据做任何处理，但我们想要使用`.then`，因为我们想在我们的端点内进行下一步操作。但是，我们只能在上述 promise 完成后才能这样做。

在这个端点内我们必须完成的最后一步是向调用它的人发送一个响应。因此，输入以下突出显示的代码行：

```js
.then (data => {
    res.json({ note: 'New Node registered with network successfully' });
});
```

这就是我们的`register-and-broadcast-node`端点。

# `register-and-broadcast-node`端点功能的快速回顾

现在让我们再次运行这个端点，以便快速总结我们在这个端点中所做的工作，以便更好地理解这一点。每当我们想要将新节点注册到我们的网络时，`register-and-broadcast-node`端点是我们想要访问的第一个点。在这个端点内我们要做的第一件事是获取`newNodeUrl`并将其通过将其推入我们的`networkNodes`数组中注册到当前节点。

我们接下来要做的一步是将这个`newNodeUrl`广播到我们网络中的其他节点。我们是在`forEach`循环内做这个操作。在这个循环内发生的一切就是我们向我们网络中的每个其他节点发出请求。我们正在向`register-node`端点发出这个请求。然后我们将所有这些请求推入我们的`register-node`promise 数组中，然后简单地运行所有这些请求。

一旦所有这些请求都完成且没有任何错误，我们可以假设`newNodeUrl`已成功注册到我们的所有其他网络节点。

广播完成后，我们要做的下一件事是将我们网络中已经存在的所有网络节点注册到我们的新节点上。为了做到这一点，我们向新节点发出单个请求，然后命中`register-nodes-bulk`端点。我们传递给这个端点的数据是我们网络中已经存在的所有节点的 URL。

然后我们运行`rp(bulkRegisterOptions);`，尽管我们还没有构建`register-nodes-bulk`端点，但我们假设它正在工作，并且我们的所有网络节点已经成功地注册到我们的新节点上。一旦发生这种情况，我们的所有计算就完成了，我们只需发送一条消息，说明新节点已成功注册到网络中。

在这一点上，这可能看起来很多，但不要担心；建议您继续前进。在接下来的部分，我们将构建我们的`register-node`端点，然后是我们的`register-nodes-bulk`端点。随着我们的操作，一切都会变得更清晰。

# 构建/register-node 端点

现在我们已经构建了`/register-and-broadcast-node`端点，是时候继续进行一些不那么复杂的事情了。在本节中，让我们开始构建`register-node`端点。与我们在上一节中构建的端点相比，这将非常简单。

这个`register-node`端点是网络中的每个节点都将接收到由我们的`register-and-broadcast-node`端点发送的广播。这个`register-node`端点唯一需要做的就是将新节点注册到接收到请求的节点上。

要开始构建`register-node`端点，请按照以下步骤进行：

1.  我们要做的第一件事是定义`newNodeUrl`；因此，添加以下突出显示的代码行：

```js
// register a node with the network
app.post('/register-node', function(req, res) {
       const newNodeUrl = req.body.newNodeUrl;
});
```

上一行代码只是简单地说明要使用发送到`req.body`的`newNodeUrl`的值。这是我们发送到`/register-node`端点的数据，我们将把新的`nodeNodeUrl`保存为`newNodeUrl`变量。

1.  接下来，我们要将`newNodeUrl`变量注册到接收到请求的节点上。为此，请添加以下突出显示的代码行：

```js
// register a node with the network
app.post('/register-node', function(req, res) {
      const newNodeUrl = req.body.newNodeUrl; bitcoin.networkNodes.push(newNodeUrl);
});
```

上面的代码将我们的新节点注册到我们当前所在的节点。我们要做的就是将`newNodeUrl`简单地推送到当前节点的`networkNodes`数组中。

1.  现在，我们要做的最后一件事就是发送一个响应，所以输入以下突出显示的代码行：

```js
// register a node with the network
app.post('/register-node', function(req, res) {
      const newNodeUrl = req.body.newNodeUrl;bitcoin.networkNodes.push(newNodeUrl);
      res.json({ note: 'New node registered successfully.' }); 
});
```

1.  接下来，我们要在这个端点内进行一些错误处理。我们唯一要做的就是，如果`newNodeUrl`在数组中不存在，就将其添加到我们的`networkNodes`数组中。为了做到这一点，我们将在`bitcoin.networkNodes.push(newNodeUrl)`的开头添加一个 if 语句。但在此之前，让我们定义一个变量，如下所示：

```js
// register a node with the network
app.post('/register-node', function(req, res) {
      const newNodeUrl = req.body.newNodeUrl;
 const nodeNotAlreadyPresent = 
         bitcoin.networkNodes.indexOf(newNodeUrl) == -1; bitcoin.networkNodes.push(newNodeUrl);
       res.json({ note: 'New node registered successfully.' }); 
});
```

上面突出显示的行是在说明，如果`newNodeUrl`的索引是-1，或者换句话说，如果`newNodeUrl`在我们的网络节点中不存在，那么`nodeNotAlreadyPresent`变量将为 true。如果`newNodeUrl`已经存在于我们的`networkNodes`数组中，那么这个变量将为 false。

1.  在 if 语句中，我们要说明的是，如果`newNodeUrl`不在我们的`networkNodes`数组中，则通过运行`bitcoin.networkNodes.push(newNodeUrl)`将其添加进去：

```js
if (nodeNotAlreadyPresent ) bitcoin.networkNodes.push(newNodeUrl);
```

1.  接下来，我们还要处理另一种情况，即如果`newNodeUrl`实际上是我们当前所在节点的 URL，我们不希望将`newNodeUrl`推送到我们的`networkNodes`数组中。为了在代码中提到这个条件，我们首先必须定义一个变量：

```js
const notCurrentNode = bitcoin.currentNodeUrl !== newNodeUrl;
```

前面的一行只是评估`bitcoin.currentNodeUrl !== newNodeUrl`表达式，该表达式说明`currentNodeUrl`是否等于`newNodeUrl`。如果不是，则`notCurrentNode`变量将为 true。如果它们相等，则变量将为 false。

1.  接下来，我们只需将`notCurrentNode`变量添加到我们的 if 语句中，如下所示：

```js
if (nodeNotAlreadyPresent && notCurrentNode ) bitcoin.networkNodes.push(newNodeUrl);
```

这个 if 语句中发生的事情是，如果新节点不在我们的`networkNodes`数组中，并且新节点的 URL 与我们当前所在的节点不同，那么我们只想将新节点添加到我们的`networkNodes`数组中。

我们在端点内部进行错误处理。

# 测试/register-node 端点

在本节中，让我们测试`/register-node`端点，以确保它正常工作并更好地了解其工作原理。

# 安装请求库

在测试端点之前，我们需要进行一个小更新。更新涉及安装请求库。在几个部分之前，我们安装了`request-promise`库。现在，为了测试我们刚刚创建的端点，可能需要我们也安装请求库，这取决于我们安装的`request-promise`库的版本。

要安装请求库，只需转到终端，并在`blockchain`目录中运行以下命令：

```js
npm install request --save
```

# 端点测试

在进行测试之前，请检查您的终端中是否有我们的五个网络节点都在运行。如果没有，那么您将需要设置它们。使用 Postman 测试`register-node`端点：

1.  首先，我们将在地址栏中输入`http://localhost:3001/register-node`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/75f40672-7bbe-403e-adcb-4d41009a6ce7.png)

当我们访问这个端点时，我们需要在`req.body`上发送`newNodeUrl`作为数据。我们现在需要设置它。因此，在 Postman 的 Body 选项卡中，我们希望选择原始和 JSON（application/json）作为文本。

1.  然后，在文本框中，创建一个对象并添加以下代码：

```js
{
    "newNodeUrl":""
}
```

1.  现在假设我们要使用端口`3002`上运行的节点注册我们运行在端口`3001`上的节点。将以下内容添加到我们之前的代码中：

```js
{
    "newNodeUrl":"http://localhost:3002"
}
```

到目前为止，我们已经使用运行在`localhost:3002`上的节点注册了我们运行在`localhost:3001`上的节点。因此，当我们访问`http://localhost:3001/register-node`时，我们的`localhost:3002`应该出现在第一个节点（即`localhost:3001`）的`networkNodes`数组中，因为这个`register-node`端点通过将节点放入`networkNodes`数组中来注册节点。

1.  要验证这一点，打开 Postman 并单击发送按钮。您将收到响应“新节点成功注册”。现在转到浏览器，输入`localhost:3001/blockchain`到地址栏，然后按*Enter*。您将看到类似于以下截图所示的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/089da3ad-3891-4605-9b36-62bc7a6d15cd.png)

由于我们刚刚使用`localhost:3001`上的当前节点注册了我们的第二个节点，因此我们的第二个节点的 URL 现在在这个数组中。

按照相同的步骤，您也可以尝试注册其他节点。尝试进行实验。这将帮助您更清楚地了解已注册的节点。如果遇到任何问题，请尝试重新阅读整个过程。

我们要注意的一件重要的事情是，如果我们现在转到`localhost:3002/blockchain`，我们会发现`networkNodes`数组中没有注册的网络节点。

理想情况下，我们希望发生的是，当我们注册一个新节点时，我们希望它也进行反向注册。因此，如果我们使用`3001`上的节点注册`localhost:3002`，那么我们`3002`上的节点应该注册`localhost:3001`。这样，这两个节点都将彼此知晓。

实际上，我们已经在`register-and-broadcast-node`端点内构建了这个功能。一旦我们构建了这三个端点，我们提到的功能将正常工作。

# 构建/register-nodes-bulk 端点

我们要构建的下一个端点是我们的`register-nodes-bulk`端点；这是我们需要构建的最终端点。我们一直在处理的这三个端点将共同工作，创建我们的去中心化区块链网络。

在开始构建端点之前，让我们试着理解一下`register-nodes-bulk`端点的作用。每当一个新节点被广播到网络中的所有其他节点时，我们希望获取已经存在于网络中的所有节点，并将这些数据发送回我们的新节点，以便新节点可以注册和识别已经存在于网络中的所有节点。

`register-nodes-bulk`端点将接受包含已经存在于网络中的每个节点的 URL 的数据。然后，我们将简单地注册所有这些网络节点到新节点。

新节点是命中`register-nodes-bulk`端点的节点。这个端点只会在我们的网络中添加新节点时才会命中。

1.  要构建`register-nodes-bulk`端点，我们将假设我们当前网络中的所有节点 URL 都作为数据传递，并且我们可以在`req.body.allNetworkNodes`属性上访问它们。这是因为在`Promise.all(regNodesPromise)`块中调用此端点时，我们正在发送`allNetworkNodes`数据。在这里，我们正在将`allNetworkNodes`发送到`register-nodes-bulk`端点。这将使我们能够在端点内部访问`allNetworkNodes`数据。

1.  让我们在之前创建的`register-nodes-bulk`端点中添加以下代码行：

```js
app.post('/register-nodes-bulk', function (req, res) {
    const allNetworkNodes = req.body.allNetowrkNodes;

});
```

1.  接下来，让我们循环遍历`allNetworkNodes`数组中存在的每个节点 URL，并将其注册到新节点，如下所示：

```js
app.post('/register-nodes-bulk', function (req, res) {
    const allNetworkNodes = req.body.allNetowrkNodes;
    allNetworkNodes.forEach(networkNodeUrl => { 
 //...
 });

});
```

1.  现在，在循环中我们要做的就是将每个网络节点 URL 注册到我们当前所在的节点，也就是正在添加到网络中的新节点：

```js
app.post('/register-nodes-bulk', function (req, res) {
    const allNetworkNodes = req.body.allNetowrkNodes;
    allNetworkNodes.forEach(networkNodeUrl => { 
        bitcoin.networkNodes.push(metworkNodeUrl);
    });

});
```

在上面突出显示的代码行中发生的情况是，当我们通过`forEach`循环遍历所有网络节点时，我们通过将`networkNodeUrl`推送到我们的`networkNodes`数组中来注册每一个节点。

每当我们命中`/register-nodes-bulk`端点时，我们都在添加到网络中的新节点上。所有这些`networkNodeUrls`都将被注册到我们正在添加的新节点上。

1.  现在有几种情况下，我们不希望将`networkNodeUrl`添加到我们的`networkNodes`数组中。为了处理这些情况，我们将使用一个 if 语句。但在此之前，我们需要定义一个条件语句，如下所示：

```js
const nodeNotAlreadyPresent = bitcoin.networkNodes.indexOf(networkNodeUrl) == -1;
```

如果`networkNodeUrl`已经存在于`networkNodes`数组中，我们就不希望将其添加到`networkNodes`数组中；这就是我们在条件语句中提到的。

这个语句所做的就是测试我们当前所在的`networkNodeUrl`是否存在于我们的`networkNodes`数组中。从这里，它将简单地将其评估为真或假。

1.  现在我们可以添加`nodeNotAlreadyPresent`变量和 if 语句，如下面的代码中所突出显示的那样：

```js
app.post('/register-nodes-bulk', function (req, res) {
    const allNetworkNodes = req.body.allNetowrkNodes;
    allNetworkNodes.forEach(networkNodeUrl => {
    const nodeNotAlreadyPresent = 
      bitcoin.networkNodes.indexOf(networkNodeUrl) == -1; 
        if(nodeNotAlreadyPresent)bitcoin.networkNodes.push(networkNodeUrl);
 });

});
```

上面的 if 语句说明，如果节点尚未存在于我们的`networkNodes`数组中，那么我们将注册该节点。

1.  现在，另一种情况是，如果要注册的网络节点具有与我们当前所在的网络节点相同的 URL，我们就不希望注册该网络节点。为了处理这个情况，我们需要另一个变量：

```js
const notCurrentNode = bitcoin.currentNodeUrl !==networkNodeUrl
```

1.  接下来，将这个变量添加到我们的`if`语句中：

```js
app.post('/register-nodes-bulk', function (req, res) {
    const allNetworkNodes = req.body.allNetowrkNodes;
    allNetworkNodes.forEach(networkNodeUrl => {
    const nodeNotAlreadyPresent = 
      bitcoin.networkNodes.indexOf(networkNodeUrl) == -1; 
        if(nodeNotAlreadyPresent && notCurrentNode)
         bitcoin.networkNodes.push(networkNodeUrl);
 });

});
```

基本上，在`if`语句中我们所陈述的是，当我们循环遍历每个要添加的网络节点时，如果该节点尚未存在于我们的网络节点数组中，并且该节点不是我们当前节点的 URL，那么我们就要将`networkNodeUrl`添加到我们的`networkNodes`数组中。

1.  完成`forEach`循环后，我们将注册所有已经存在于我们区块链网络中的网络节点。在这一点上，我们所要做的就是发送回一个响应，如下所示：

```js
app.post('/register-nodes-bulk', function (req, res) {
    const allNetworkNodes = req.body.allNetowrkNodes;
    allNetworkNodes.forEach(networkNodeUrl => {
    const nodeNotAlreadyPresent = 
      bitcoin.networkNodes.indexOf(networkNodeUrl) == -1; 
        if(nodeNotAlreadyPresent && notCurrentNode)
         bitcoin.networkNodes.push(networkNodeUrl);
 });
res.json({note: 'Bulk registration successful.' });

});
```

让我们快速回顾一下我们到目前为止所做的工作。我们构建的端点接受所有网络节点作为数据，然后我们循环遍历已经存在于我们区块链网络中的所有网络节点。对于每个节点，只要它尚未注册到`currentNode`并且不是与`currentNode`相同的 URL，我们就会将该节点添加到我们的`networkNodes`数组中。

# 测试/register-nodes-bulk 端点

在这一部分，我们将测试我们的`register-nodes-bulk`端点，以确保它正常工作。这将使我们清楚地了解它的工作原理：

1.  为了测试这个端点，我们将前往 Postman。在这里，我们将命中`localhost:3001/register-nodes-bulk`端点。当我们测试这个端点时，我们期望收到一些数据，即`allNetworkNodes`数组。

1.  因此，在 Postman 的 body 选项卡中，选择原始选项和 JSON（application/json）格式，将以下代码添加到 body 中：

```js
{
    "allNetworkNodes": []
}
```

1.  在这个数组中，将包含已经存在于我们区块链网络中的所有节点的 URL：

```js
{
    "allNetworkNodes": [
    "http://localhost:3002",
    "http://localhost:3003",
    "http://localhost:3004"
    ]
}
```

1.  当我们现在运行这个请求时，我们应该在运行在`localhost:3001`上的节点上注册这三个 URL。让我们看看是否有效。点击发送按钮，您将收到一个回复，说明批量注册成功。

1.  现在，如果我们转到浏览器，我们可以双重检查它是否有效。在地址栏中，键入`localhost:3001/blockchain`，然后按*Enter*。您将看到`networkNodes`数组中添加的三个 URL，因为它们是批量注册的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/2e1a0bbc-6040-460b-9646-cf19e3c289e3.png)

同样，您可以尝试通过将新节点添加到不同 URL 上的其他节点来进行实验。您将观察到这些节点的`networkNodes`数组中的类似响应。

因此，看起来我们的`register-node-bulk`端点正在按照预期工作。

# 测试所有网络端点

根据我们在前面部分学到的知识，我们知道我们的`register-node`路由和`register-nodes-bulk`路由都正常工作。因此，在本节中，让我们把它们全部整合起来，测试我们的`register-and-broadcast-node`路由，该路由同时使用了`register-node`路由和`register-nodes-bulk`路由。

`register-and-broadcast-node`端点将允许我们通过创建网络并向其添加新节点来构建分散的区块链网络。让我们立即进入我们的第一个示例，以更好地理解它。为了理解`register-and-broadcast-node`路由的工作原理，我们将使用 Postman。

在 Postman 应用程序中，我们要发出一个 post 请求，以在`localhost:3001`上注册和广播节点。但在这之前，只需确保所有四个节点都在运行，以便我们可以测试路由。

此时，我们根本没有网络；我们只有五个独立的节点在运行，但它们没有以任何方式连接。因此，我们将要做的第一个调用只是简单地将两个节点连接在一起，以形成我们网络的开端。我们现在将一个节点注册到我们在端口`3001`上托管的节点。当我们命中`register-and-broadcast-node`端点时，我们必须发送一个要注册的`newNodeUrl`。在 Postman 中，添加以下代码：

```js
{
    "newNodeUrl": ""
}
```

对于这个第一次测试，我们想要将我们托管在端口`3002`上的第二个节点注册到我们的第一个节点。为此，我们将添加以下突出显示的代码：

```js
{
    "newNodeUrl": "http://localhost:3002"
}
```

现在，当我们发出这个请求时，它应该将我们托管在`localhost:3002`上的节点注册到我们托管在`localhost:3001`上的节点。让我们通过单击“发送”按钮来验证这一点。您将看到类似于以下屏幕截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/719bee39-e7d4-4552-9b50-cd0c070994bd.png)

从前面的屏幕截图中，我们可以看到新节点已成功注册到网络。让我们通过转到浏览器来验证这一点。

在浏览器中，您将可以访问所有正在运行的五个节点。我们现在已经将端口`3002`上的节点注册到了托管在`localhost:3001`上的节点。因此，如果我们现在在浏览器上刷新页面，我们将看到`localhost:3002`已经在端口`3001`的`networkNodes`数组中注册了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/ec380a6e-515f-4e6d-a627-9c42a1c50b87.png)

从前面的屏幕截图中，我们可以看到我们已经注册了`localhost:3002`。现在，如果我们转到`localhost:3002`，我们应该在它的`networkNodes`数组中有`localhost:3001`注册。让我们刷新并看看我们在这里得到了什么：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/b260a295-1f23-477d-90b5-046958542553.png)

从前面的屏幕截图中，我们可以看到两个节点现在已经形成了一个网络，并将彼此注册为网络节点。

接下来，让我们向这个网络添加另一个节点。让我们回到 Postman，并将`localhost:3002`更改为`localhost:3003`。我们将向在`3001`上的节点发出请求：

```js
{
    "newNodeUrl": "http://localhost:3003"
}
```

这应该是将我们托管在`localhost:3003`上的节点与网络中的所有其他节点注册。因此，`3003`应该注册到`3001`和`3002`。让我们发送这个请求，看看它是否成功注册。如果成功注册，您将看到类似于以下屏幕截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/835f911b-b92d-46a7-ac78-6ef5f8f25530.png)

让我们在浏览器中验证这一点。当我们在`localhost:3001`中刷新时，我们应该在`networkNodes`数组中有`localhost:3003`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/cc8bbbbe-1f83-4a38-8369-62c7b9dca2cb.png)

现在，由于`localhost:3002`也是网络的一部分，它的`networkNodes`数组中应该有`localhost:3003`。当我们发出这个请求时，我们是发给`3001`而不是`3002`。`localhost:3002`已经是网络的一部分，广播注册了`3003`与网络中存在的所有网络节点。要验证这一点，请刷新`3002`上的`networkNodes`数组。您将看到类似于以下屏幕截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/8980a924-52f1-41b1-9ca1-2956b5d55f59.png)

从前面的屏幕截图中，我们可以看到我们的第三个节点现在也在`localhost:3002`的`networkNodes`数组中。此外，如果我们转到`localhost:3003`上的`networkNodes`并刷新页面，我们应该在`networkNodes`数组中有`3001`和`3002`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/2d8d197b-0d69-4ab6-acd0-d967272e99b2.png)

因此，我们现在有一个由`3001`、`3002`和`3003`节点组成的网络。这些节点已经相互注册。

现在，让我们回到 Postman，并按照注册初始节点的相同步骤，将剩下的`localhost:3004`和`localhost:3005`注册到网络中。

在将`3004`和`3005`注册到网络后，如果您转到浏览器，所有这些注册节点应该在它们的`networkNodes`数组中包含`localhost:3004`和`localhost:3005`。刷新`localhost:3001`页面，您将看到类似于以下屏幕截图中显示的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-bc-prog-js/img/64d347a1-5324-4e30-918f-851087536f20.png)

同样地，如果您刷新其他页面，您将能够观察到所有节点，类似于我们在前面的屏幕截图中观察到的。

这就是我们建立了一个由五个不同节点组成的去中心化网络。

现在，您可能想知道所有这些是如何工作的。它之所以能够工作，是因为当我们发出`"newNodeUrl": "http://localhost:3004"`的请求时，我们实际上是在添加一个命令，将`3004`添加到网络中。但是`localhost:3004`如何在一次请求中意识到整个网络呢？

如果您还记得前面的部分，当我们构建`/register-and-broadcast-node`端点时，实际上进行了大量的计算。因此，如果我们看一下`/register-and-broadcast-node`端点的代码，我们可以看到我们的`register-and-broadcast-node`端点内部发生的第一件事是接收`newNodeUrl`，然后通过访问它们的`register-node`端点将其广播到网络中的每个节点。因此，网络中的每个节点都将意识到新添加的节点。

有关完整的代码，请访问[`github.com/PacktPublishing/Learn-Blockchain-Programming-with-JavaScript/blob/master/dev/networkNode.js`](https://github.com/PacktPublishing/Learn-Blockchain-Programming-with-JavaScript/blob/master/dev/networkNode.js)，并参考以此注释开头的代码块：`//registering a node and broadcasting it the network`。

然后，在广播发生后，我们向刚刚添加的新节点发送请求，并使用新节点注册网络中已经存在的所有网络节点。这就是反向注册发生的地方。在这一点上，网络中的所有原始节点都意识到了新节点，而新节点也意识到了网络中的所有其他节点。因此，网络中的所有节点都意识到了彼此，这是我们的区块链正常工作所必须发生的事情。

因此，我们构建的这三个端点（`register-and-broadcast-node`、`register-node`和`register-nodes-bulk`）非常强大，因为它们共同工作以创建一个分散的区块链网络。这就是我们在本章中构建的内容。

在本书的这一部分，建议您花一些时间玩弄这些端点，创建不同的具有不同节点的网络，并进行一些测试，以更熟悉它的工作原理。

如果您对我们所涵盖的任何概念或主题感到困惑，建议您再次阅读本章的所有部分。您会惊讶地发现，在您已经对即将发生的事情和我们将要构建的内容有一些背景之后，第二次阅读时您可以学到多少东西。

# 总结

我们现在已经完成了创建我们的分散网络。在本章中，我们学习了许多新概念。我们开始学习如何创建我们 API 的多个实例以及如何使用它们来设置我们的分散网络。然后，我们定义了各种端点，如`register-and-broadcast-node`、`register-node`和`register-nodes-bulk`。之后，我们构建了这些端点并对其进行了测试。

在下一章中，我们将学习如何同步网络。
