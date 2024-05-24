# Meteor JS 框架入门指南（一）

> 原文：[`zh.annas-archive.org/md5/A6A998711E02B953FECB90E097CD1168`](https://zh.annas-archive.org/md5/A6A998711E02B953FECB90E097CD1168)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

我们生活在一个惊人的时代。医学、通信、物理以及所有其他科学领域的进步为我们提供了创建一些在短短一段时间前简直是无法创造的事物的机会。

然而，我们并不容易感到惊奇。我们已经开始期待奇妙的进步，因此曾经令人惊叹的事物变得……嗯……是预期的。真正让人感到惊奇的事物确实不多，确实，要找到让我们感到惊喜的东西。它重新点燃了我们所有人内心深藏的童年惊奇感，因为它曾被夺走。

好吧，准备好重新找回那份惊奇吧。一群决心创造一些奇妙事物的计算机科学家创建了一个名为 Meteor 的新 JavaScript 平台。你可能在想，“一个新的 JavaScript 平台？那没什么特别的。”如果 Meteor 只是那样，你说得对，但幸运的是，故事并没有就此结束。

Meteor 是一个反应式的、简单的、强大的应用平台，能够用几行代码生成复杂、健壮的网页应用。

在网页应用的背景下，它是尖端的。使用经过验证的、被证实的设计模式，Meteor 为构建网页应用的所有困难和单调部分做了所有工作。你可以专注于构建一个具有最新创新的所有最新创新，如反应式编程、模板、插件以及客户端缓存/同步。你不需要陷入写另一个数据库接口或学习一个新的模板引擎等浪费时间的活动。

最好的部分是，它很容易学习。令人惊讶地简单。你将会看到一个应用在你眼前焕然一新，当你回顾它创建所需的代码行数，并与传统开发方法进行比较时，你可能会发现自己说出“哇”或“他们是怎么做到的？”

这本书将带你领略 Meteor 的主要功能，并展示如何从零开始创建一个应用。到了本书末尾，你将创建一个可以工作的、有用的应用，并且你将彻底理解 Meteor 的不同之处。这可能听起来有些夸张，但如果你愿意接受创新和意外可以定义为惊人的观点，那么准备好感到惊奇吧！

# 本书涵盖内容

第一章，*安装和设置*，让你在几分钟内开始使用 Meteor，并展示你如何快速、轻松地构建一个完全功能性的、有用的应用。

第二章，*响应式编程……它是有生命的！*，教你关于响应式编程的一切，以及如何在 Meteor 中利用响应性创建令人惊叹、反应灵敏的应用。

第三章，*为什么 Meteor 如此出色！*，帮助你了解 Meteor 使用的设计模式，并展示这些强大模式的具体示例。

第四章，*模板*，深入介绍了 Meteor 模板，并教你如何使用模板为您的借阅图书馆应用程序奠定基础。

第五章，*数据，Meteor 风格！*，帮助你了解 Meteor 如何处理数据，使得企业级应用变得简单而健壮。它还帮助你快速有效地在应用程序中实现 Meteor 的数据处理。

第六章，*应用程序和文件夹结构*，展示了您可以对默认配置进行哪些更改，以使您的应用程序更加安全、可扩展和用户友好。

第七章，*打包和部署*，帮助你成为 Meteor 打包系统的专家，包括如何包含许多流行的第三方框架。学习如何将 Meteor 应用程序部署到您的开发、测试和生产环境。

# 本书所需材料

要运行书中的示例，需要以下软件：

+   操作系统：

    +   Mac：OS X 10.6 及以上([`www.apple.com`](http://www.apple.com))

    +   Linux：x86 或 x86_64，Debian([`www.debian.org`](http://www.debian.org))和基于 Red Hat 的系统([`www.redhat.com`](http://www.redhat.com))

+   Meteor：版本 0.5.0 及以上([`docs.meteor.com/#quickstart`](http://docs.meteor.com/#quickstart))

# 本书面向人群

本书面向具有 HTML 和 JavaScript 一定了解的应用程序开发者、设计师或分析师，他们希望学习关于 Meteor 的知识，以及 JavaScript 社区内部向完全功能、健壮的网页应用的新运动。

如果您正在寻找了解如何以及在何时使用最新且最具创新性的网络技术的方法，以便将其应用于您的应用程序开发项目，本书适合您。

# 约定

在本书中，您将发现多种文本样式，以区分不同类型的信息。以下是一些这些样式的示例及其含义：

文本中的代码词汇如下所示："我们已经通过使用`categories`模板创建了我们的分类。"

代码块如下所示：

```js
<body>
  <div id="lendlib">
    <div id="categories-container">
      {{> categories}}
    </div>   
    <div id="list">
      {{> list}} 
    </div> 
  </div> 
</body> 
```

当我们希望将您的注意力吸引到代码块的特定部分时，相关行或项目以粗体显示：

```js
<body>
 <div id="lendlib">
    <div id="categories-container">
      {{> categories}}
    </div>   
 <div id="list">
 {{> list}} 
 </div> 
 </div> 
</body>
```

任何命令行输入或输出如下所示：

```js
> meteor remove autopublish

```

**新术语**和**重要词汇**以粗体显示。例如，在屏幕上、菜单或对话框中看到的单词，在文本中会以这种方式出现："在我们庆祝之前，请点击**服装**分类。"

### 注意

警告或重要说明以框的形式出现。

### 提示

技巧和窍门就像这样出现。

# 读者反馈

我们的读者的反馈总是受欢迎的。告诉我们你对这本书的看法——你喜欢什么或者可能不喜欢什么。读者反馈对我们来说非常重要，帮助我们开发出您真正能从中受益的标题。

发送一般性反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在消息的主题中提及书名。

如果您在某个话题上有专业知识，并且有兴趣撰写或贡献一本书，请查看我们在 [www.packtpub.com/authors](http://www.packtpub.com/authors) 上的作者指南。

# 客户支持

如今你已成为 Packt 书籍的骄傲拥有者，我们有很多事情可以帮助你充分利用你的购买。

## 下载示例代码

您可以从您在 [`www.PacktPub.com`](http://www.PacktPub.com) 的账户上下载您购买的所有 Packt 书籍的示例代码文件。如果您在其他地方购买了这本书，您可以访问 [`www.PacktPub.com/support`](http://www.PacktPub.com/support) 并注册，以便将文件直接通过电子邮件发送给您。

## 勘误表

虽然我们已经尽一切努力确保我们内容的准确性，但错误确实会发生。如果您发现我们的一本书中有一个错误——可能是文本或代码中的错误——我们将非常感谢您能向我们报告。通过这样做，您可以节省其他读者的挫折感，并帮助我们改进本书的后续版本。如果您发现任何勘误，请通过访问 [`www.packtpub.com/support`](http://www.packtpub.com/support)，选择您的书籍，点击 **errata** **submission** **form** 链接，并输入您的勘误详情。一旦您的勘误得到验证，您的提交将被接受，勘误将被上传到我们的网站，或添加到该标题的错误部分现有的勘误列表中。您可以通过选择您的标题从 [`www.packtpub.com/support`](http://www.packtpub.com/support) 查看任何现有的勘误。

## 盗版问题

互联网上版权材料的盗版是一个持续存在的问题，涵盖所有媒体。在 Packt，我们对保护我们的版权和许可证非常认真。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们地址或网站名称，以便我们可以寻求补救措施。

如果您发现可疑的盗版材料，请通过 `<copyright@packtpub.com>` 与我们联系。

我们感激您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

## 问题

如果您在阅读书籍时遇到任何问题，可以通过 `<questions@packtpub.com>` 联系我们，我们会尽力解决。


# 第一章：设置和安装

在底层，Meteor 其实只是一堆文件和脚本，旨在让构建 Web 应用程序变得更容易。这是描述某样东西如此优雅的一种糟糕方式，但它帮助我们更好地理解我们在使用什么。

毕竟，米拉·库尼斯其实只是一堆组织包裹在骨骼周围，里面有一些重要的器官。我知道你现在可能恨我因为这个描述，但你知道我的意思。她很美。Meteor 也是。但我们不能就停留在那。如果我们想要在我们的 own 上重现这种美丽，我们必须了解到底发生了什么。

所以，文件和脚本……我们将带你了解如何在你的 Linux 或 Mac OS X 系统上正确安装 Meteor 包，然后看看这个文件和脚本的包如何运行。请注意，Windows 支持即将推出，但截至本文写作时，只有 Linux 和 Mac 版本可用。

在本章中，你将学习到：

+   通过 curl 下载并安装 Meteor

+   加载一个示例应用程序

+   进行更改并观察 Meteor 的实际运行

# 使用 curl 安装

安装文件和脚本有几种方法。你可以手动下载和传输文件，你可以使用一个有很多“下一步”按钮的漂亮安装向导/包，或者你可以像*真正的*开发者那样做，使用命令行。这会让你变得更有男子气概。然而，我现在想想，这可能并不是一个非常想要的事情。好吧，没有头发；我撒谎了。但仍然，你想使用命令行，相信我。相信刚刚对你撒谎的那个人。

`curl`（如果你想弄得花哨一点，就是 cURL）是一个命令行工具，用于使用标准 URL 位置传输文件和运行脚本。你可能已经知道了，或者你可能不在乎。无论如何，我们描述了一下，现在我们继续使用它。

打开一个终端窗口或命令行，并输入以下内容：

```js
$ curl https://install.meteor.com | /bin/sh

```

### 提示

**下载示例代码**

你可以从你账户中下载你购买的所有 Packt 书籍的示例代码文件。[`www.PacktPub.com`](http://www.PacktPub.com)有你购买这本书以外的所有书籍的示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，以便文件直接发送到你的邮箱。

这将会在你的系统上安装 Meteor。`curl`是去获取脚本的命令。[`install.meteor.com`](https://install.meteor.com)是脚本的 URL/位置，`/bin/sh`当然是脚本解释器“Shell”的位置，它将会运行脚本。

一旦你运行了此脚本，假设你有互联网连接和适当的权限，你就会看到 Meteor 包的下载和安装：

![使用 curl 安装](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_01_08.jpg)

在前面的安装文本中我们要找的关键信息是 Meteor 的位置：

```js
Installing Meteor to /usr/local/meteor

```

这个位置将根据您是在 Linux 还是 Mac OS X 上运行而有所不同，但它将 Meteor 置于一个可以从其他任何地方访问 Meteor 脚本的位置。这将在一分钟内变得很重要。现在，让我们看看 Meteor 安装完成后会得到什么友好消息：

```js
Meteor installed! To get started fast:

 $ meteor create ~/my_cool_app
 $ cd ~/my_cool_app
 $ meteor

Or see the docs at:

 docs.meteor.com

```

太好了！您已成功安装 Meteor，并且您正在创建您的第一个 Meteor 网络应用程序的路上！

### 提示

你应该收藏[`docs.meteor.com`](http://docs.meteor.com) 作为您前进过程中宝贵的参考资料。

# 加载示例应用程序

Meteor 的了不起的人们包括几个示例应用程序，您可以快速创建并玩耍，帮助您更好地了解 Meteor 能做什么。

对于我们将要构建的应用程序来说，`todos`示例是最接近的匹配，所以我们将基于那个示例进行构建。我们将再次使用命令行，所以如果你还开着它，那真是太棒了！如果没有，打开一个终端窗口，然后按照以下步骤操作。

## 选择您的文件位置

为了以后能记住它们的位置，我们将把这本书的所有文件放在`~/Documents/Meteor`文件夹中。我们需要创建那个文件夹：

```js
$ mkdir ~/Documents/Meteor

```

现在，我们希望处于那个目录中：

```js
$ cd ~/Documents/Meteor

```

## 加载示例应用程序

现在，我们可以使用 Meteor `create`命令和`--example`参数来创建`todos`示例应用程序的本地副本：

```js
$ meteor create –-example todos

```

与 Meteor 安装本身一样，`create`命令脚本也有一个友好的成功消息：

```js
todos: created.
To run your new app:
 cd todos
 meteor

```

多么方便，甚至还有下一步要做什么的说明！让我们按照我们忠实的好命令行朋友的指示去做吧。

## 启动示例应用程序

要启动一个 Meteor 应用程序，我们需要处于应用程序目录本身。这是因为 Meteor 正在寻找运行应用程序所需的启动文件、HTML 和 JavaScript。所有这些都在应用程序文件夹中，所以让我们去那里：

```js
$ cd todos

```

这让我们进入了`~/Documents/Meteor/todos`文件夹，我们准备运行应用程序：

```js
$ meteor

```

是的，就是它。Meteor 为我们处理所有事情，阅读所有文件和脚本，并设置 HTTP 监听器：

```js
[[[[[ ~/Documents/Meteor/todos ]]]]]

Running on: http://localhost:3000/

```

现在，我们可以使用我们得到的 URL（`http://localhost:3000/`），并在网页浏览器中查看示例应用程序。

## 预览应用程序

打开您最喜欢的网页浏览器（我们将使用 Chrome，但任何现代更新过的浏览器都可以）并导航到`http://localhost:3000/`。

您应该看到以下屏幕，其中已经添加了一些待办事项列表：

![预览应用程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_01_01.jpg)

如果你想的话，你可以去探索一下应用程序。给列表添加一个新项目，更改列表，添加一个新标签，或者标记项目为完成。随意操作，朋友！如果我们将来所做的更改与你如果在做很多更改的情况下屏幕上显示的完全一致，那是不可能的，但你会很顺利地跟上的。

## 救命！我改动太多了！

你是否害怕变化，希望你的屏幕看起来与我们的示例屏幕一模一样？没问题，只需从一个干净的实例开始。

1.  在命令行：

    ```js
    Ctrl + C

    ```

1.  这将停止运行的应用程序。现在向上移动一个目录：

    ```js
    $ cd ..

    ```

1.  删除`todos`应用程序：

    ```js
    $ rm –R todos

    ```

1.  再次创建 todos 示例应用程序：

    ```js
    $ meteor create --example todos

    ```

1.  切换到新目录，启动 Meteor，一切就绪：

    ```js
    $ cd todos
    $ meteor

    ```

# 进行代码更改

好了，我们的应用程序现在在浏览器中运行。现在我们想看看当我们做一些代码更改时会发生什么。

Meteor 最好的特性之一是响应式编程和热代码推送。

以下内容来自[`docs.meteor.com/#reactivity`](http://docs.meteor.com/#reactivity)：

### 注意

Meteor 采用响应式编程的概念。这意味着你可以用简单的命令式风格编写代码，当你的代码依赖的数据发生变化时，结果将自动重新计算。

更简单地说，这意味着你对 HTML、JavaScript 或数据库所做的任何更改都会自动被采纳并传播。

你不必重新启动应用程序，甚至不必刷新你的浏览器。所有更改都实时地被整合，应用程序被动地接受这些更改。

让我们来看一个例子。

## 从 todos 更改为 items

随着我们对 Meteor 的深入了解，我们希望建立一个可以工作的应用程序：一个有用且复杂到足以让我们体验 Meteor 的所有主要特性的应用程序。我们将构建一个借阅图书馆，我们可以跟踪我们拥有什么物品（例如，广告男人第一季），将这些物品组织成类别（例如，DVD），并跟踪我们借给这些物品的人。

为了看到这方面的开始，让我们将*todos*列表更改为*items*列表，并将*list*一词更改为*category*，因为这个词听起来更酷。

首先，确保应用程序正在运行。你可以通过打开一个浏览器窗口，指向`http://localhost:3000/`来进行此操作。如果应用程序正在运行，你将看到你的`todos`应用程序。如果你的应用程序没有运行，请确保按照*启动示例应用程序*部分中给出的步骤操作。

现在，我们需要打开并编辑`todos.html`文件。用你最喜欢的文本/代码编辑器打开`~/Documents/Meteor/todos/client/todos.html`。

1.  在`head`部分更改`title`：

    ```js
    <head>
      <title>Items</title>
    </head>
    ```

1.  接着保存文件，然后在浏览器中查看。页面将自动刷新，你会看到标题从**Todos**更改为**Items**：![从 todos 更改为 items](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_01_02.jpg)

    现在，标题将显示单词**Items**：

    ![从 todos 更改为 items](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_01_03.jpg)

这就是 Meteor 在起作用！它正在监控任何文件的变化，当它看到一个文件发生变化时，它告诉你的浏览器有变化，并应该刷新自己以获取最新版本。

继续前进，我们将从头开始构建一个应用程序，因此我们不想对这个示例应用程序做太多更改。然而，我们仍然希望至少清理掉其他可见的`todo`和`list`引用。

1.  回到您的文本编辑器，对大约第 20 行的`<h3>`标签进行以下更改：

    ```js
    <template name="lists">
      <h3>Item Categories</h3>
    ```

    保存此更改，您将在浏览器中看到更改反映。左侧标题栏原本显示以下文本：

    ![从 todos 更改为 items](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_01_04.jpg)

    现在它将更改为以下内容：

    ![从 todos 更改为 items](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_01_05.jpg)

1.  我们还需要处理一个区域，我们已经成功将我们的`todos`应用程序转换为`items`应用程序。

    如果您注意到，在分类列表的底部，当前打开的盒子写着**新列表**：

    ![从 todos 更改为 items](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_01_06.jpg)

    我们需要将其改为**新分类**。在第 39 行进行以下代码更改：

    ```js
    <div id="createList">
      <input type="text" id="new-list" placeholder="New category" />
    </div>
    ```

1.  保存您的更改，并检查您的工作：![从 todos 更改为 items](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_01_07.jpg)

# 摘要

太成功了！在本章中，你已经成功安装了 Meteor 框架，加载了一个示例应用程序，并对该应用程序进行了更改，熟悉了文件更改和 Meteor 的反应性质。你现在可以开始构建你自己的 Meteor 应用程序，并了解更多使用 Meteor 开发带来的优雅特性和优势。


# 第二章．响应式编程…它是有生命的！

正如您在第一章中所学到的，*设置和安装*，Meteor 采用响应式编程模型。这意味着您的客户端/浏览器不仅关心显示数据，还关心数据的变化，这样它就可以“反应”这些变化。这些寻找数据变化的数据区域称为**响应式上下文**。

我们将开始我们的借贷图书馆应用程序，为未来的章节打下基础，并使用 Meteor 内置的响应式上下文来跟踪和传播我们应用程序的变化，以便所有监听的客户端都能接收到。

在本章中，您将学习到：

+   创建您的第一个真实应用程序

+   使用响应式编程来跟踪和自动更新变化

+   从多个浏览器窗口探索和测试您数据的变化

# 创建借贷图书馆

这个世界上有两种人。那些记得他们借给谁东西的人，和那些买了很多东西两次的人。如果你和你的 UPS 送货司机很熟，这个应用程序就是为你准备的！

使用 Meteor，我们将建立一个借贷图书馆。我们将跟踪我们所有的东西，以及我们借给了谁，这样下次我们记不起我们把线性压缩扳手放在哪里时，我们只需查找我们最后借给了谁，然后去向他们要回来。

而且当同一个朋友说，“你确定你借给我了吗？”我们可以回答，“是的，史蒂夫，我确定我借给了你！我看到你正在享受我的慷慨借出的线性压缩扳手带来的数字有线电视，为什么不自己去找它，这样我也可以在家享受数字有线电视的好处呢？！”

好吧，好吧，也许史蒂夫也忘记了。也许他是个骗子，他把你的扳手卖了来支付他的炸 Twinkies®习惯。无论如何，你都有自己的自定义 Meteor 应用程序，可以证明你并没有发疯。如果他确实为了油炸嘉年华食品而卖了它，至少你可以让他和他的存货一起分享，然后你可以在他家看比赛。

## 创建基本应用程序

我们首先要做的就是创建基本应用程序，然后我们可以根据需要进行扩展。

1.  首先，导航到您的应用程序文件夹。这可以随便放在哪里，但如前所述，我们将使用`~/Documents/Meteor`作为根文件夹：

    ```js
    $ cd ~/Documents/Meteor

    ```

1.  现在我们为我们的借贷图书馆应用程序创建基本文件夹结构：

    ```js
    $ meteor create LendLib

    ```

1.  像往常一样，我们将获得关于如何启动应用程序的说明。让我们先试试看，以确保一切都创建得正确：

    ```js
    $ cd LendLib
    $ meteor

    ```

    这将导航到借贷图书馆文件夹`~/Documents/Meteor/LendLib`并运行应用程序。

1.  打开一个浏览器，导航到`http://localhost:3000/`。你应该看到以下屏幕：![创建基本应用程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_01.jpg)

1.  你好世界是远远不够的，所以让我们把它改为借阅图书馆。在你的最喜欢的编辑器中打开`~/Documents/Meteor/LendLib/LendLib.html`。在顶部（第 9 行左右），你会看到负责我们问候的模板 HTML 代码片段。大胆把`Hello World`改为`Lending Library`：

    ```js
    <template name="hello">
      <h1>Lending Library</h1>
      {{greeting}}
      <input type="button" value="Click" />
    </template>
    ```

1.  保存那个更改，页面将刷新：![创建基本应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_02.jpg)

    欢迎信息不在 HTML 文件中，然而。如果你注意到了，它在一个名为 greeting 的模板函数中找到：

    ```js
    {{greeting}}
    ```

1.  我们也来改一下。打开`~/Documents/Meteor/LendLib/LendLib.js`，将问候模板函数更改如下：

    ```js
    if (Meteor.isClient) {
      Template.hello.greeting = function () {
      return "my list.";
      };
    ```

1.  保存更改，你的页面将更新：![创建基本应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_03.jpg)

## 创建一个集合

好，你刚刚静态文件做了一些小改动，但我们真正想看到的是些动态的、响应式的编程，还有实时的 HTML！

我们需要附加一个数据源：一些可以跟踪我们项目的东西。通常，这确实是一个相当的过程，但 Meteor 使之变得简单，支持 Minimongo（MongoDB 的轻量级版本）内置。

### 提示

要了解更多关于 NoSQL 数据库（特别是 MongoDB，Meteor 内部默认使用的数据库）的信息，你可以访问以下网站：

更多信息请访问[`en.wikipedia.org/wiki/NoSQL`](http://en.wikipedia.org/wiki/NoSQL)

更多信息请访问[`www.mongodb.org/`](http://www.mongodb.org/)

更多信息请访问[`www.packtpub.com/books/all?keys=mongodb`](http://www.packtpub.com/books/all?keys=mongodb)

让我们创建我们的集合。在`LendLib.js`中，我们想添加以下作为第一行，然后保存更改：

```js
var lists = new Meteor.Collection("Lists");

if (Meteor.isClient) {
…
```

这将在 MongoDB 中创建一个新的集合。由于它在`LendLib.js`文件中的任何其他内容之前，所以集合可供客户端和服务器查看。如我们所见，它是持久的，一旦在其中输入值，任何访问页面的客户端都可以检索它们。

要查看这个持久对象，我们需要使用我们网页的控制台。

## 浏览器控制台的乐趣

**浏览器控制台**是大多数现代浏览器默认提供的调试工具，或者通过插件作为附加组件。

### 提示

要深入了解如何在 Chrome 中使用控制台，请查看[`developer.chrome.com/extensions/tut_debugging.html`](http://developer.chrome.com/extensions/tut_debugging.html)。

1.  由于我们使用的是 Chrome，控制台默认可用。在一个指向`http://localhost:3000/`的浏览器窗口中，输入快捷键组合*[command]* + *[option]* + *i*，或者你可以在页面的任何地方右键点击并选择**检查元素**：![浏览器控制台的乐趣](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_04.jpg)

    这将打开我们的调试工具。我们现在想要进入控制台。

1.  点击调试菜单栏最右边的**控制台**图标：![浏览器控制台的乐趣](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_05.jpg)

    你现在将有一个闪烁的光标，你准备检查我们新创建的集合！

1.  在控制台中输入以下命令并按*Enter*：

    ```js
    > lists

    ```

    你应该得到一个返回的对象，说 Meteor 集合：

    ![浏览器控制台的乐趣](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_06.jpg)

## 添加一些数据

这意味着我们的更改已被接受，我们有一个新的持久集合！它是空的，但让我们做点什么来改变这一点：

1.  在浏览器控制台中输入以下命令以创建几个示例类别：

    ```js
    > lists.insert({Category:"DVDs", items: {Name:"Mission Impossible",Owner:"me",LentTo:"Alice"}});
    > lists.insert({Category:"Tools", items: {Name:"Linear Compression Wrench",Owner:"me",LentTo: "STEVE"}});
    ```

    每个命令执行后，你将获得一个 GUID（类似于`f98c3355-18ce-47b0-82cc-142696322a06`），这是 Meteor 用来告诉你项目已正确保存的方式。我们作为天生的怀疑论者，将要检查这一过程。

1.  输入以下命令：

    ```js
    > lists.findOne({Category: "DVDs"});
    ```

    你应该得到一个对象，旁边有一个可扩展的图标。

1.  点击那个图标来展开，你应该有以下内容：![添加一些数据](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_07.jpg)

    我们可以通过输入命令`lists.findOne({Category:"Tools"})`来同样检查我们的工具集合，但我们不需要这样做。这次我们将相信 Meteor 已经正确地输入了。然而，我们确实希望检查对象是否持久存在。

    刷新网页。你的控制台将清空，但我们输入的类别已经保存在持久的 Meteor 集合中，因此我们可以再次检查它们是否还在。

1.  在控制台中输入以下命令：

    ```js
    > lists.find({}).count();

    ```

    这个命令查找`lists`集合中的所有记录，并给我们一个总数。如果一切按计划进行，你应该得到一个`2`的计数。

我们正在前进！我们已经创建了两个类别，每个类别中有一个项目。我们还验证了`lists`集合正在从会话到会话中保存。现在，让我们看看如何在我们的页面上显示这个。

## 在 HTML 中显示集合

我们现在将看到我们在初始化项目时创建的 HTML 页面中的集合栩栩如生。这个页面将使用模板，它们是响应式的，允许我们的集合发生变化时，页面无需刷新即可立即更新。这种类型的响应式编程，页面 DOM 可以无需刷新即可立即更新，称为**Live HTML**。

### 小贴士

要了解更多关于 Live HTML 的信息，请查阅以下网址的 Meteor 文档：

[`docs.meteor.com/#livehtml`](http://docs.meteor.com/#livehtml)

1.  在`~/Documents/Meteor/LendLib/LendLib.html`仍然打开的情况下，找到`body`标签，并添加一个新的**模板**声明：

    ```js
    <body>
      {{> hello}}
     <div id="categories-container">
     {{> categories}}
     </div> 
    </body>
    ```

    这将创建一个新的`div`，其内容由名为`categories`的`template partial`填充。

1.  现在，在页面的最底部，让我们添加类别`template partial`的骨架：

    ```js
    <template name="categories">
    </template>

    ```

    这不会改变页面的外观，但我们现在有一个`template partial`，我们可以列出我们的类别。

1.  让我们放入我们的节标题：

    ```js
    <template name="categories">
     <div class="title">my stuff</div>
    </template>
    ```

1.  现在让我们把我们的类别放进去：

    ```js
    <template name="categories">
      <div class="title">my stuff</div>
     <div id="categories">

     </div>
    </template>
    ```

    这样在`div`中创建了类别，我们可以遍历并列出所有类别。如果我们只有一个记录要处理，代码将如下所示：

    ```js
    <div class="category">
     {{Category}}
    </div>

    ```

1.  但是我们需要将其包装在一个循环中（在这个例子中，一个`#each`语句），这样我们才能获取所有类别：

    ```js
    <template name="categories">
      <div class="title">my stuff</div>
      <div id="categories">
     {{#each lists}}
     <div class="category">
     {{Category}}
     </div>
     {{/each}}
      </div>
    </template>
    ```

    注意我们正在告诉模板“对于`lists`集合中的每个记录”使用我们的`{{#each lists}}`命令，然后，“显示类别”使用`{{Category}}`。

1.  保存这些更改，然后查看网页：![在 HTML 中显示集合](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_08.jpg)

    看起来并没有太大不同。是的，我们有我们的头部（**我的东西**），但是我们刚刚创建的模板的类别在哪里？

    为了让类别显示出来，我们还需要完成一步。目前，我们刚刚创建的模板没有指向任何东西。换句话说，我们有一个 lists 集合，我们有一个模板，但我们没有连接它们的底层 JavaScript 函数。让我们处理一下那部分。

    在`~/Documents/Meteor/LendLib/LendLib.js`中我们可以看到一些`Template`函数：

    ```js
    Template.hello.greeting = function () {...

    ...

    Template.hello.events = { ...
    ```

    这些代码块正在将 JavaScript 函数和对象连接到 HTML hello`template`。Meteor 内置的`Template`对象使这成为可能，我们将遵循相同的模式来连接我们的 categories`template`。

1.  我们想要向任何监听的客户端声明，categories 模板有一个`lists`集合。我们通过在`Template.hello.events = {...}`代码块下方输入以下代码来实现：

    ```js
    Template.hello.events = {
    ...
    };

    Template.categories.lists = function () {
    };

    ```

    ### 提示

    Template 声明必须位于`if (Meteor.isClient) {...}`代码块内，以便客户端可以获取更改，而服务器会忽略它。

1.  现在我们已经为所有模板声明了`lists`集合，我们可以让函数返回来自`Meteor.Collection`查询的结果。我们使用`find()`命令来实现：

    ```js
    Template.categories.lists = function () {
     return lists.find({}, {sort: {Category: 1}});
    };
    ```

    这段代码将找到`lists`集合中的每个记录，并按`Category`（名称）对结果进行排序。保存这些更改，你现在将看到一个填充了类别的列表：

    ![在 HTML 中显示集合](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_09.jpg)

## 清理

我们正在快速接近一个可以工作的应用程序，我们希望它看起来超级光滑和干净。让我们对我们的代码进行一些清理，并添加一些 CSS 以提高可读性：

1.  我们不再需要问候语。让我们去掉它。从`LendLib.html`中删除以下高亮显示的行并保存页面：

    ```js
    <body>
     {{> hello}}
      <div id="categories">
        {{> categories}}
      </div>
    </body>

    <template name="hello">
     <h1>Lending Library</h1>
     {{greeting}}
     <input type="button" value="Click" />
    </template>
    <template name="categories">
    ```

    我们现在想保留`LendLib.js`中的 Template.hello 声明，作为参考。我们现在注释掉它们，稍后当它们不再需要时删除它们：

    ```js
    /*

    Template.hello.greeting = function () {
    ...
    };

    Template.hello.events = {
    ...
    };

    */

    ```

1.  现在，让我们添加 Twitter Bootstrap 框架，它让我们轻松拥有大量样式：

    1.  打开终端窗口，在`/LendLib/`中创建一个`client`文件夹：

        ```js
        $ mkdir ~/Documents/Meteor/LendLib/client

        ```

    1.  访问[`twitter.github.com/bootstrap/assets/bootstrap.zip`](http://twitter.github.com/bootstrap/assets/bootstrap.zip)下载最新的 Bootstrap 框架，然后将其解压到`~/Documents/Meteor/LendLib/client`文件夹中。

        因为 Meteor 会读取并使用应用程序文件夹中的每一个文件，我们希望消除这些冗余的文件。我们不必太担心效率问题，但有些事情确实令人羞愧，留下这么多无用的代码就是其中之一，与享受《暮光之城》系列电影没什么两样。

    1.  导航到 bootstrap 文件夹：

        ```js
        $ cd ~/Documents/Meteor/LendLib/client/bootstrap

        ```

    1.  删除不需要的文件：

        ```js
        $ rm js/bootstrap.js
        $ rm css/bootstrap.css
        $ rm css/bootstrap-responsive.css

        ```

        ### 提示

        如果你熟悉 Bootstrap，你可以直接复制`images`、`min.js`和`min.css`文件，而不是按照前面的说明操作。

    经过这些更改后，你的 UI 应该非常干净简洁：

    ![清理](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_10.jpg)

1.  让我们快速使其更加醒目和可读。在`LendLib.html`中，让我们将头部标签从`div`更改为`h2`：

    ```js
    <template name="categories">
    <h2 class="title">my stuff</h2>
    ```

1.  让我们把分类变成一个漂亮的按钮组：

    ```js
    <div id="categories" class="btn-group">
    {{#each lists}}
    <div class="category btn btn-inverse">
    {{Category}}
    </div>
       {{/each}}
    ```

    这给了我们一个独特、干净的页面：

    ![清理](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_11.jpg)

# 创建一个反应

在我们创建了基本模板和集合，并且 Meteor 将我们的`lists`集合放入了反应式上下文之后，我们现在可以继续观察反应式编程模型在实际工作中的表现。

导航到我们的借阅图书馆页面`http://localhost:3000/`，并打开浏览器控制台窗口。

在控制台中输入以下命令：

```js
> lists.insert({Category:"Fraggles"});

```

你会立刻看到页面更新。但注意，这次页面没有完全刷新！那是因为在幕后，Meteor 正在跟踪我们的反应式上下文（在这个例子中是`lists`集合）的变化，并在变化发生后立即更新`template`。

让我们再做些改动。再次输入相同的`Fraggles`命令：

```js
> lists.insert({Category:"Fraggles"});

```

与之前一样，一个新的**Fraggles**按钮立刻出现：

![创建一个反应](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_12.jpg)

但我们现在的 Fraggles 分类太多了。确实有很多 Fraggles，但除非你是个奇怪的收藏家，否则你不需要*两个*分类。所以我们去掉它们：

```js
> lists.remove({Category:"Fraggles"})

```

这个命令查找任何`Category = "Fraggles"`的记录并将它们删除。

为了更好地管理我们的收藏品，添加一个收藏品集合条目可能更好，所以我们来这样做：

```js
> lists.insert({Category:"Collectibles"})

```

正如你所看到的，更改是即时的，无需页面刷新。

# 多个客户端

好的事物应该分享。Meteor 理解这一点，正如我们即将亲自看到的那样，反应式编程模型允许我们在多个客户端之间实时共享更新。

保持你的 Chrome 网页打开在`http://localhost:3000/`，然后打开一个新的浏览器标签页，导航到同一页面。

### 提示

如果你想更高级一点，可以用多个浏览器（Firefox、Opera 或 Safari）进行这个实验——每个会话都是实时的并且具有反应性！

你现在打开了两个客户端，它们模拟了不同的人、在不同的地点、使用不同的计算机打开应用程序。Meteor 的反应式模型允许你对所有客户端一视同仁，其中一个客户端所做的更改将会传播到所有其他客户端。

在关注新的第二个浏览器的同时，在浏览器#1 的控制台中输入以下命令：

```js
> lists.insert({Category:"Vinyl Records"})

```

你会注意到更改传播到了*两个*浏览器，再次没有刷新页面：

![多个客户端](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_02_13.jpg)

随意添加任何额外的集合，删除或重命名等。稍作实验，注意这些更改如何能够立即对所有监听的客户端生效。Meteor 遵循一个非常强大的范式，在下一章中，我们将能够确切地看到为什么这是 web 应用程序开发中的一个如此重要和具有颠覆性的变革。

# 总结

在本章中，你已经成功地为你的新 Meteor 应用创建了框架。你亲自见证了新的项目是如何迅速被创建的，而且你仅仅用几行代码就创建了一些主要的数据库和模板功能。你亲眼看到了实时 HTML 和反应式编程的实际应用，现在你准备更深入地了解 Meteor 引擎。你已经征服了冰山之巅，我的朋友。休息一下，喝杯冰镇饮料，为更深入的 Meteor 精彩做好准备！


# 第三章：为什么 Meteor 如此出色！

Meteor 是一种具有颠覆性（以一种好的方式！）的技术。它使一种新类型的网络应用程序成为可能，这种应用程序采用了**模型-视图-视图模型**（**MVVM**）设计模式。

这一章解释了网络应用程序是如何改变的，为什么这很重要，以及 Meteor 是如何通过 MVVM 特别地使现代网络应用程序成为可能的。

到本章末尾，你将学到：

+   现代网络应用程序是什么样的

+   MVVM 意味着什么，以及它有何不同

+   如何使用 Meteor 的 MVVM 创建现代网络应用程序

+   在 Meteor 中使用模板——开始使用 MVVM

# 现代网络应用程序

我们的世界正在改变。

随着显示、计算和存储能力的不断进步，几年前还不可能实现的事情现在不仅成为可能，而且对于优秀的应用程序的成功至关重要。特别是网络领域经历了显著的变化。

## 网络应用程序的起源（客户端/服务器）

从一开始，网络服务器和客户端就模仿了**傻瓜终端**的计算方式，其中服务器具有比客户端多得多的处理能力，对数据执行操作（例如将记录写入数据库、进行数学计算、文本搜索等），将数据转换为可读格式（例如将数据库记录转换为 HTML 等），然后将结果服务于客户端，由用户显示使用。

换句话说，服务器做所有的工作，而客户端更多的是作为一个显示器，或者说是傻瓜终端。这种设计模式的名称是……等一下……叫做**客户端/服务器**设计模式：

![网络应用程序的起源（客户端/服务器）](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_03_01.jpg)

这种设计模式源自 20 世纪 60 年代和 70 年代的傻瓜终端和大中型计算机，正是它促成了我们所知的网络的诞生，并且一直是我们思考互联网时所想到的设计模式。

## 机器的崛起（MVC）

在网络出现之前（以及自那以后），桌面能够运行如电子表格或文字处理程序等应用程序，而无需与服务器进行通信。这类应用程序能够在其强大的桌面环境中完成所需的一切。

在 20 世纪 90 年代初，桌面计算机变得更快更好。越来越多地配置了高性能的计算机。同时，网络也开始兴起。人们开始认为将高性能桌面应用程序（也就是**胖应用**）与网络客户端/服务器应用程序（也就是**瘦应用**）相结合，可以产生最好的效果。这种类型的应用程序——与傻瓜终端相反——被称为**智能应用**。

创建了许多面向商业的智能应用，但最简单的例子可以在计算机游戏中找到。**大型多人在线游戏**（**MMOs**）、第一人称射击游戏和实时战略游戏都是智能应用，在这些应用中，信息（数据**模型**）通过服务器在机器之间传递。在这种情况下，客户端做的不仅仅是显示信息。它执行大部分处理（或**控制**）并将数据转换为需要显示的内容（**视图**）。

这种设计模式很简单，但非常有效。它被称为**模型-视图-控制器**（**MVC**）模式。

![机器的崛起（MVC）](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_03_02.jpg)

模型拥有所有的数据。在智能应用的上下文中，模型是由服务器提供的。客户端从服务器请求模型。一旦客户端获得模型，它就在这些数据上执行操作/逻辑，然后准备将其显示在屏幕上。这个应用程序的部分（与服务器通信、修改数据模型以及准备数据显示的数据）被称为**控制器**。控制器向视图发送命令，视图显示信息，并在屏幕上发生某些事件（例如按钮点击）时向控制器报告。控制器接收那些反馈，执行逻辑，并更新模型。如此循环。

由于网络浏览器被设计成“愚蠢的客户端”，使用浏览器作为智能应用的想法是不可能的。相反，智能应用是建立在诸如微软.NET、Java 或 Macromedia（现 Adobe）Flash 之类的框架上。只要安装了框架，你就可以访问网页来下载/运行智能应用。

有时你可以在浏览器内运行应用程序，有时你可以在下载之前运行它，但无论如何，你都在运行一种新类型的网络应用程序，在这种应用程序中，应用程序可以与服务器通信并共享处理工作负载。

## 浏览器成长了（MVVM）

从 2000 年代初开始，MVC 模式出现了一个新的变化。开发者开始意识到，对于连接/企业级的“智能应用”，实际上有一个嵌套的 MVC 模式。

服务器（控制器）通过使用业务对象对数据库信息（模型）执行业务逻辑，然后将该信息传递给客户端应用程序（一个“视图”）。

客户端从服务器接收这些信息，并将其视为自己的个人“模型”。然后客户端将作为一个适当的控制器，执行逻辑，并将信息发送给视图以在屏幕上显示。

所以，对于服务器 MVC 的“视图”是第二个 MVC 的“模型”。

![浏览器成长了（MVVM）](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_03_03.jpg)

然后我想到，“为什么要止步于两个？” 没有理由说一个应用不能有*多个*嵌套的 MVC，每个视图都成为下一个 MVC 的模型。实际上，在客户端方面，这样做的确有一个很好的理由。

将实际显示逻辑（如“这个提交按钮放在这里”和“文本区域值已更改”）与客户端对象逻辑（如“用户可以提交这个记录”和“电话号码已更改”）分离，使得大部分代码可以被重用。对象逻辑可以移植到另一个应用程序中，您所做的只是更改显示逻辑，以将相同的模型和控制器代码扩展到不同的应用程序或设备。

从 2004-2005 年起，这个想法被马丁·福勒（Martin Fowler）和微软（Microsoft）针对智能应用进行了改进和修改（称为**展示模型**），称为**模型-视图-视图模型**（Model View View-Model）。虽然严格来说并不是嵌套 MVC 的同一件事，但 MVVM 设计模式将嵌套 MVC 的概念应用于前端应用程序。

![浏览器成长（MVVM）](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_03_04.jpg)

随着浏览器技术（HTML 和 JavaScript）的成熟，创建直接在 HTML 网页内使用 MVVM 设计模式的智能应用变得可能。这种模式使得直接从浏览器运行完整尺寸的应用程序成为可能。不再需要下载多个框架或单独的应用程序。现在，您可以从访问一个 URL 获得与以前从购买包装产品获得相同的功能。

# 一个大型的 Meteor 出现了！

Meteor 将 MVVM 模式推向了新的高度。通过应用 `handlebars.js`（或其他模板库）的模板化，并利用即时更新，它真正使得网页应用程序能够像一个完整的、健壮的智能应用程序一样行动和表现。

让我们通过一些概念来了解 Meteor 是如何做到这一点的，然后我们开始将这个应用到我们的 Lending Library 应用程序中。

## 缓存和同步数据（模型）

Meteor 支持一种在客户端和服务器上相同的缓存和同步数据模型。

![缓存和同步数据（模型）](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_03_05.jpg)

当客户端注意到数据模型的更改时，它首先在本地缓存这些更改，然后尝试与服务器同步。同时，它正在监听来自服务器的更改。这使得客户端能够拥有数据模型的本地副本，因此它可以快速地将任何更改的结果发送到屏幕，而无需等待服务器响应。

此外，您会注意到这是 MVVM 设计模式的开始，嵌套在一个 nested MVC 中。换句话说，服务器发布数据更改，并将其数据更改视为自身 MVC 模式中的“视图”。客户端订阅这些更改，并将其更改视为 MVVM 模式中的“模型”。

![缓存和同步数据（模型）](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_03_06.jpg)

这个的一个代码示例在 Meteor 中非常简单（尽管如果您愿意，您可以使其更复杂，从而使其更具控制性）：

```js
var lists = new Meteor.Collection("lists");
```

这一行代码的作用是声明存在一个`lists`数据模型。客户端和服务器都会有它的版本，但它们对待自己的版本方式不同。客户端将订阅服务器宣布的变化，并相应地更新其模型。服务器将发布变化，并监听来自客户端的变化请求，并根据这些请求更新*它的*模型（它的主副本）。

哇。一行代码就能做到这么多！当然，还有很多我们没有提到，但这超出了本章节的范围，所以我们继续吧。

### 提示

为了更好地理解 Meteor 的数据同步，请参阅 Meteor 文档中“发布和订阅”部分的*发布和订阅*。[`docs.meteor.com/#publishandsubscribe`](http://docs.meteor.com/#publishandsubscribe)。

## 模板化的 HTML（视图）

Meteor 客户端通过使用模板来渲染 HTML。

HTML 中的模板也称为**视图数据绑定**。简单来说，视图数据绑定是如果数据变化，会以不同方式显示的一块共享数据。

HTML 代码有一个占位符。根据变量的值，将在该占位符中放置不同的 HTML 代码。如果这个变量的值发生变化，占位符中的代码也会随之变化，从而产生不同的视图。

让我们来看一个非常简单的数据绑定，这个你实际上不需要 Meteor 也能做到，来阐明这个观点。

在`LendLib.html`中，你会看到一个 HTML（Handlebar）模板表达式：

```js
<div id="categories-container">
 {{> categories}}
</div>
```

这个表达式是一个 HTML 模板的占位符，下面就是它：

```js
<template name="categories">
<h2 class="title">my stuff</h2>...
```

所以，`{{> categories}}`基本上是在说“在这里放`categories`模板中的任何东西。”具有相应名称的 HTML 模板正在提供这些内容。

如果你想看看数据变化会如何改变显示效果，将`h2`标签改为`h4`标签，并保存更改：

```js
<template name="categories">
<h4 class="title">my stuff</h4>...
```

你会在浏览器中看到效果（“我的东西”变得微小）。这是一个模板——或者说是视图数据绑定——在起作用！将`h4`改回`h2`并保存更改。除非你喜欢这个更改。这里没有判断...好吧，也许有一点判断。它又丑又小，很难阅读。说真的，你应该改回去，否则有人看到会嘲笑你的！

好吧，现在我们知道什么是视图数据绑定，让我们来看看 Meteor 是如何使用它们的。

在`LendLib.html`中的 categories 模板内，你还会找到更多的 Handlebar 模板：

```js
<template name="categories">
  <h4 class="title">my stuff</h4>
  <div id="categories" class="btn-group">
    {{#each lists}}
      <div class="category btn btn-inverse">
        {{Category}}
      </div>
    {{/each}}
  </div>
</template>
```

第一个 Handlebar 表达式是一对的一部分，是一个`for-each`语句。`{{#each lists}}`告诉解释器执行其下方的动作（在这个例子中，创建一个新的`div`）对于`lists`集合中的每个项目。`lists`是数据的一部分。`{{#each lists}}`是占位符。

现在，在`#each lists`表达式中，还有一个 Handlebar 表达式。

```js
{{Category}}

```

由于这位于`#each`表达式内部，`Category`是`lists`的隐含属性。也就是说`{{Category}}`等同于说`this.Category`，其中`this`是`for each`循环中的当前项目。因此，占位符表示“在这里添加`this.Category`的值。”

现在，如果我们查看`LendLib.js`，我们将看到模板背后的值。

```js
Template.categories.lists = function () {
  return lists.find(...
```

在这里，Meteor 声明了一个名为`lists`的模板变量，该变量位于名为`categories`的模板内。这个变量碰巧是一个函数。这个函数返回`lists`集合中的所有数据，我们之前定义了这个集合。记得这个命令吗？

```js
var lists = new Meteor.Collection("lists");
```

那个`lists`集合是由声明的`Template.categories.lists`返回的，因此当`lists`集合发生变化时，变量也会得到更新，模板的占位符也会相应地改变。

让我们实际操作一下。在指向`http://localhost:3000`的网页上，打开浏览器控制台并输入以下行：

```js
> lists.insert({Category:"Games"});
```

这将更新`lists`数据集合（模型）。模板将看到这个变化，并更新 HTML 代码/占位符。`for each`循环将额外运行一次，为`lists`中的新条目，然后你会看到以下屏幕：

![模板化的 HTML（视图）](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_03_07.jpg)

关于 MVVM 模式，HTML 模板代码是客户端视图的一部分。任何数据的变化都会自动反映在浏览器中。

## Meteor 的客户端代码（视图模型）

如前一部分所述，`LendLib.js`包含了模板变量，它将客户端模型与 HTML 页面连接起来，这是客户端的视图。在`LendLib.js`内部，作为对视图或模型变化的反应的任何逻辑都是视图模型的一部分。

视图模型负责跟踪模型的变化并以一种视图可以拾取变化的方式呈现这些变化。它还负责监听来自视图的变化。

在这里，变化并不意味着按钮点击或文本被输入。相反，我们指的是模板值的改变。声明的模板是视图模型，或者说*视图的模型*。

这意味着客户端控制器拥有其模型（来自服务器的数据）并且知道如何处理这个模型，视图拥有其模型（一个模板）并且知道如何显示该模型。

# 让我们创建一些模板

现在我们将看到 MVVM 设计模式的实际例子，同时对我们的借阅图书馆进行操作。通过控制台添加类别是一个有趣的练习，但它不是长期的解决方案。让我们设法让我们可以在页面上进行此类操作。

打开`LendLib.html`，在`{{#each lists}}`表达式之前添加一个新按钮。

```js
<div id="categories" class="btn-group">
<div class="category btn btn-inverse" id="btnNewCat">&plus;</div>
{{#each lists}}
```

这将向页面添加一个加号按钮。

![让我们创建一些模板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_03_08.jpg)

现在，如果我们点击它，我们想要将那个按钮换成文本字段。所以让我们使用 MVVM 模式构建这个功能，并使其基于模板中的一个变量的值。

添加以下代码行：

```js
<div id="categories" class="btn-group">
  {{#if new_cat}}
 {{else}}
      <div class="category btn btn-inverse" id="btnNewCat">&plus;</div>
  {{/if}} 
{{#each lists}} 
```

第一行`{{#if new_cat}}`检查`new_cat`是`true`还是`false`。如果是`false`，`{{else}}`部分触发，这意味着我们还没有表示我们想要添加一个新的类别，所以我们应该显示带有加号的按钮。

在这种情况下，由于我们还没有定义它，`new_cat`将变为`false`，所以显示不会改变。现在让我们添加 HTML 代码，如果我们想要添加一个新的类别：

```js
<div id="categories" class="btn-group">
  {{#if new_cat}}
    <div class="category">
      <input type="text" id="add-category" value="" />
 </div>
    {{else}}
      <div class="category btn btn-inverse" id="btnNewCat">&plus;</div>
  {{/if}} 
{{#each lists}} 
```

我们添加了一个输入字段，当`new_cat`为`true`时显示。除非它是，否则输入字段不会显示，所以现在它是隐藏的。那么我们如何使`new_cat`等于`true`呢？

如果您还没有保存更改，请保存您的更改，并打开`LendingLib.js`。首先，我们在列表模板声明下方声明一个`Session`变量。

```js
Template.categories.lists = function () {
  return lists.find({}, {sort: {Category: 1}});
};
// We are declaring the 'adding_category' flag
Session.set('adding_category', false);

```

现在，我们声明新的模板变量`new_cat`，它将是一个返回`adding_category`值的函数：

```js
// We are declaring the 'adding_category' flag
Session.set('adding_category', false);
// This returns true if adding_category has been assigned a value //of true
Template.categories.new_cat = function () {
 return Session.equals('adding_category',true);
};

```

保存这些更改，你会发现什么都没有变化。Ta-daaa!

实际上，这正是它应该的样子，因为我们还没有做任何改变`adding_category`值的事情。现在我们来做这件事。

首先，我们将声明我们的点击事件，它将改变我们的`Session`变量的值。

```js
Template.categories.new_cat = function () {
  return Session.equals('adding_category',true);
};
Template.categories.events({
 'click #btnNewCat': function (e, t) {Session.set('adding_category', true);Meteor.flush();
 focusText(t.find("#add-category"));
 }
});

```

让我们看看下一行：

```js
Template.categories.events({

```

这条线声明将在类别模板中找到事件。

现在让我们看看下一行：

```js
'click #btnNewCat': function (e, t) {

```

这条线告诉我们，我们在寻找 HTML 元素上的点击事件，其`id="btnNewCat"`（我们在`LendingLib.html`上已经创建了它）。

```js
Session.set('adding_category', true);
Meteor.flush();
focusText(t.find("#add-category"));

```

我们设置`Session`变量`adding_category = true`，我们刷新 DOM（清除任何不正常的内容），然后使用表达式`id="add-category"`将焦点设置到输入框。

还有一件事要做，那就是快速添加助手函数`focusText()`。在`if (Meteor.isClient)`函数的闭合标签之前，添加以下代码：

```js
/////Generic Helper Functions/////
//this function puts our cursor where it needs to be.
function focusText(i) {
 i.focus();
 i.select();
};

} //------closing bracket for if(Meteor.isClient){}
```

现在当你保存更改，并点击加号![让我们创建一些模板]按钮时，你会看到以下输入框：

![让我们创建一些模板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_03_09.jpg)

太棒了！

它仍然没有用，但我们想要暂停一下，反思一下刚才发生了什么。我们在 HTML 页面中创建了一个条件模板，它将根据一个*变量*的值显示输入框或加号按钮。

这个变量属于视图模型。也就是说，如果我们通过点击事件改变变量的值，那么视图会自动更新。在 Meteor 应用程序中，我们刚刚完成了一个 MVVM 模式！

为了真正说明这一点，我们添加了对`lists`集合的更改（也是视图模型的一部分，记得吗？），并找出一个在完成后隐藏`input`字段的方法。

首先，我们需要为`keyup`事件添加一个监听器。换句话说，我们希望监听用户在框中输入内容并按下*回车*时。当发生这种情况时，我们希望能够根据用户输入的内容添加一个类别。首先，让我们声明事件处理程序。在`#btnNewCat`的`click`事件之后，让我们添加另一个事件处理程序：

```js
focusText(t.find("#add-category"));
},
'keyup #add-category': function (e,t){
 if (e.which === 13)
 {
 var catVal = String(e.target.value || "");
 if (catVal)
 {
 lists.insert({Category:catVal});Session.set('adding_category', false);
 }
 }
}
});
```

我们在点击函数的末尾添加一个`","`，然后添加了`keyup`事件处理程序。

```js
if (e.which === 13)

```

这一行检查我们是否按下了*Enter*/回车键。

```js
var catVal = String(e.target.value || "");
if (catVal)

```

这检查输入字段是否有什么值。

```js
lists.insert({Category:catVal});

```

如果这样做，我们希望在`lists`集合中添加一个条目。

```js
Session.set('adding_category', false);

```

然后我们希望隐藏输入框，这可以通过简单地修改`adding_category`的值来实现。

还有一件事要做，我们就完成了。如果我们点击`input`框以外的区域，我们希望隐藏它，并恢复加号按钮。到现在为止，我们已经知道如何在 MVVM 模式内部实现这一点，所以让我们添加一个快速函数来更改`adding_category`的值。在`keyup`事件处理程序之后再添加一个逗号，并插入以下事件处理程序：

```js
        Session.set('adding_category', false);
      }
    }
  },
  'focusout #add-category': function(e,t){
 Session.set('adding_category',false); 
 }
});
```

保存你的更改，让我们来看一下实际效果！在你的网页浏览器中，访问`http://localhost:3000`，点击加号符号——添加单词**衣服**并按下*回车*。

你的屏幕现在应该类似于以下内容：

![让我们创建一些模板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_03_10.jpg)

如果你想添加更多类别，请随意添加。此外，尝试点击加号按钮，输入一些内容，然后点击输入框以外的区域。

# 总结

在本章中，你学习了网页应用程序的历史，并了解了我们从传统的客户端/服务器模型是如何发展到完整的 MVVM 设计模式的。你已经看到了 Meteor 如何使用模板和同步数据使管理变得非常容易，为我们提供了视图、视图逻辑和数据之间的清晰分离。最后，你向借阅图书馆添加了更多内容，添加了一个用于添加类别的按钮，而且你都是通过修改视图模型而不是直接编辑 HTML 来完成的。在下一章中，我们将真正开始工作，添加各种模板和逻辑，让我们的借阅图书馆焕发生机！


# 第四章：模板

到目前为止，我们只是对模板有了一个简单的了解，现在我们准备深入其中，使用 MVVM 设计模式创建一个工作应用程序。本章将深入介绍模板系统，并展示如何实现显示逻辑、向模型添加设计考虑（创建视图模型）以及处理数据流。

在本章中，您将完成以下任务：

+   完成借阅图书馆的核心功能

+   创建多个模板和模板逻辑

+   在数据模型中添加、删除和更新条目

+   观察响应性在实际工作中的应用，并在您的应用程序中使用它

# 一个新的 HTML 模板

我们已经通过使用`categories`模板创建了我们的分类。现在，我们想要将其提升到下一个级别，显示我们可能想让（除了 STEVE 之外的）人们借阅的实际项目。所以，当我们点击一个分类时，我们应该得到一个**项目**的**列表**。

让我们使用这个术语。我们需要一个地方来显示一个`list`。所以，让我们稍微修改一下`~/Documents/Meteor/LendLib/LendLib.html`代码的开头部分：

```js
<body>
 <div id="lendlib">
    <div id="categories-container">
      {{> categories}}
    </div>   
 <div id="list">
 {{> list}} 
 </div> 
 </div> 
</body>
```

通过添加这段代码，我们做了两件事：

1.  我们将`id="categories-container"`的`div`元素包裹在名为`lendlib`的`div`内。这是出于样式考虑，这样我们的`list`就能与`categories`模板大致对齐。

1.  我们在它下面添加了一个`div`，`id="list"`，并添加了一个对新模板的调用：`{{> list}}`。这是我们用于`items`的`list`的模板/占位符，我们将在接下来的部分中看到。

现在，我们已经创建了一个非常易于维护的结构，文档中有了明确的界限。我们知道`categories`（分类）将要放在哪里，我们也知道`items`（项目）的`list`（列表）将要放在哪里。

现在让我们来看看列表模板本身。虽然不简单，但仍然不难。在`LendLib.html`的最后，我们`categories`模板的闭合`</template>`标签下方，放置以下代码：

```js
<template name="list"> 
 <ul id="lending_list"> 
 {{#each items}} 
 <li class="lending_item alert"> 
 <button type="button" class="close delete_item" id="{{Name}}">×</button>

 {{Name}}

 {{#if lendee_editing}} 
 <input type="text" id="edit_lendee" class="span2 pull-right" value=""/> 
 {{else}} 
 <div class="lendee pull-right label {{LendClass}}"> {{Lendee}}</div> 
 {{/if}} 
 </li> 
 {{/each}} 
 {{#if list_selected}}
 <li class="alert-success" id="btnAddItem">&plus; 
 {{#if list_adding}}
 <input class="span4" id="item_to_add" size="32" type="text"> 
 {{/if}} 
 </li> 
 {{/if}} 
 </ul> 
</template>

```

让我们一步一步地来看，这样我们就明白每一行代码的作用：

```js
<template name="list"> 
 <ul id="lending_list"> 
 {{#each items}}
...

```

在这里，我们声明了一个 HTML`<template>`，名为`"list"`，以匹配我们在主体部分调用的列表模板。我们创建了一个无序列表`<ul>`，并给它一个`id`，这样我们以后如果需要的话就可以引用它。

然后我们开始一个模板化的`each`语句。这次，我们要遍历`items`。我们还没有创建 Meteor 的`items`模板，但我们应该很快就会做到。

```js
 <li class="lending_item alert"> 
 <button type="button" class="close delete_item" id="{{Name}}">×</button> 

 {{Name}}

```

现在，在`each`语句下，我们创建了一个`<li>`元素，并给它赋予了两个类名。`lending_item`这个类名是为了让我们能在视图模型（Meteor 模板代码）中引用它。`alert`这个类名是为了 Bootstrap，这样它就能漂亮地显示出来。

接下来，我们创建一个 `button`，如果我们选择删除项目，我们可以使用它。注意，我们给它一个 ID `id="{{Name}}"`。这将从 `items` View-Model 中读取，如果我们想从我们的 `items` 集合中删除 `item`，这将使我们的工作在未来变得容易得多。这个 `button` 上还有两个类名。`close` 是为 Bootstrap 添加的，`delete_item` 是添加的，这样我们可以在 View-Model 中引用它。

现在，就在那个下面，我们又有另一个模板占位符 `{{Name}}`。这样我们可以在显示元素内部使用项目的标题（例如，在 DVD 项目中，标题可能是 "Mission Impossible"）。我们很快就会看到它的实际应用。

现在我们开始了一系列条件语句。第一个条件语句与我们需要编辑谁在借阅我们的项目，或者 **借阅者** 有关：

```js
 {{#if lendee_editing}} 
 <input type="text" id="edit_lendee" class="span2 pull-right" value=""/> 
 {{else}} 
 <div class="lendee pull-right label {{LendClass}}"> {{Lendee}}</div> 
 {{/if}} 
 </li>
 {{/each}}

```

我们首先使用一个 `if` 语句来检查这个 `item` 的当前模式是否为 `lendee_editing`。也就是说，如果我们想编辑借阅者，我们就会处于 "lendee editing" 模式，因此（在我们的 JavaScript 文件中）`Template.list.lendee_editing` 会返回 `true`。如果是这种情况，我们需要一个文本框，因此包含了 `<input>` 元素，以及它的相关 `id`。

另一种情况——这也是默认情况——我们只想显示借阅者是谁，如果有的话。如果没有，我们可能想改变颜色或其他什么，但仍然希望它显示出来。所以，我们创建一个带有 Bootstrap 样式的 `label`，其形式为一个 `<div>` 元素。

在类声明的末尾，我们看到一个模板变量：`...{{LendClass}}"`。这个类添加是样式上的。它将告诉我们的 CSS 模板是显示为 "free"（有人可以借阅它）还是 "lent out"（借出）。如果是绿色，它是免费的，如果是红色，有人已经借走了。代表颜色的 CSS 类名将在 `LendLib.js` 中由 `item.LendClass` 属性确定，我们稍后会创建它。

然后我们来看一下 `div` 内的值：`{{Lendee}}`。这同样也是 `LendLib.js` 中的一个属性，作为 `item.Lendee` 属性，它会显示借阅者的名字，或者如果没有人借阅的话，显示 "free"。

然后我们有结束的 `</li>` 标签，以及 `each` 以 `{{/each}}` 结束。

现在，我们有了第二个 `if` 语句，而这个实际上是嵌套的 `if`。这个 `if` 语句在 `each` 语句之外，所以它不是针对特定项目的。这个 `if` 语句显示一个带 **+** 符号的浅绿色条，或者一个表单形式的 `<input>` 元素文本框，以便我们可以向我们的列表中添加项目：

```js
 {{#if list_selected}} 
 <li class="alert-success" id="btnAddItem">&plus; 
 {{#if list_adding}} 
 <input class="span4" id="item_to_add" size="32" type="text"> 
 {{/if}} 
 </li> 
 {{/if}} 
 </ul> 
</template>

```

所以我们看到第一个 `if` 语句，它取决于我们是否甚至显示任何列表项。如果我们正在显示，这意味着我们选择了一个列表。或者说，我们处于 `list_selected` 模式。跟踪这个是 View-Model 的工作的一部分，所以 `Template.list.list_selected` 可以在 `LendLib.js` 中找到。

然后我们创建一个`<li>`元素，用 Bootstrap 的`alert-success`类将其样式设置为绿色，并添加`+`号。

接下来是我们的嵌套（第二个）`if`。这个是检查我们是否在添加项列表。如果是，我们处于`list_adding`模式，因此我们将以`<input>`元素的形式显示文本框。如果不是，我们只会保留那个漂亮的浅绿色盒子，里面只有**+**号。

最后，我们结束嵌套的`if`，我们的`</li>`，我们的父级`if`，我们的`</ul>`，和我们的`</template>`。

# 粘合在一起

视图模型（MVVM）或控制器（MVC）或呈现器（MVP）被认为是 MV*应用程序模型的粘合剂。这是因为它将所有视图项，比如按钮或文本框，粘合到了模型上。

这个解释很复杂，是吧？好吧，你尝试着为它做更好的解释。它确实填补了空白，并将模型和视图粘合在一起。这个术语是别人发明的，不是我们，所以让我们抛开批判性观点，继续吧？

在本节中，我们将逐步讲解需要在`~/Documents/Meteor/LendLib/LendLib.js`中进行的所有更改，以将模板和数据模型粘合在一起。

## 我们的 items 视图模型

在我们在第二章创建的数据模型中，*响应式编程…它是有生命的！*，我们在创建几个`list`时添加了一些示例`items`。如果你还记得的话，我们是这样通过浏览器控制台操作的：

```js
> lists.insert({Category:"DVDs", items: [{Name:"Mission Impossible",Owner:"me",LentTo:"Alice"}]});
```

你会注意到那里有一个层级结构。`lists`集合中的每一个`list`都有一个`items`对象，它是一个数组：

```js
Items: [...]
```

我们需要将这个`items`数组呈现到我们的 HTML 模板中，但我们还需要一些额外的属性，以便视图知道如何处理它。具体来说，我们需要做的是：

+   返回借阅者姓名，如果没有借阅者则返回"free"（`item.Lendee`）

+   根据项目是否已借出（`item.LendClass`），返回 CSS 类（红色或绿色）。

所以，我们将从当前选定的列表中获取`items`集合，添加`Lendee`和`LendClass`属性，并使模板可用。

打开`~/Documents/Meteor/LendLib/LendLib.js`。

在`function focusText(...`的闭合`}`花括号后立即添加以下代码：

```js
};//<-----This is the end tag for focusText() -----

Template.list.items = function () {
 if (Session.equals('current_list',null)) return null; 
 else 
 { 
 var cats = lists.findOne({_id:Session.get('current_list')}); 
 if (cats&&cats.items) 
 { 
 for(var i = 0; i<cats.items.length;i++) { 
 var d = cats.items[i];  d.Lendee = d.LentTo ? d.LentTo : "free"; d.LendClass = d.LentTo ? 
 "label-important" : "label-success"; 
 }
 return cats.items; 
 }
 } 
};

```

我们将逐步讲解这个问题。

```js
Template.list.items = function () {
if (Session.equals('current_list',null)) return null; 
```

在这里，我们声明了`Template.list.items`函数，并检查是否选择了`list`。如果选择了`list`，`Session`变量`current_list`中将有一个值。如果没有，就没有返回任何东西的必要，所以我们直接返回 null。

### 提示

这就是视图模型在工作。它正在读取给定类别的内容，并根据用户是否选择了列表，将当前 UI 状态融入其中。这是粘合剂在工作。

如果选中了某个项目，我们首先需要找到类别。我们称之为`cats`，因为这个名字更短，尽管它不是严格意义上的最佳命名约定。但我们在乎吗？我们这样做是为了好玩，而且`cats`很棒！

```js
else 
{ 
  var cats = lists.findOne({_id:Session.get('current_list')}); 
```

我们正在使用 MongoDB 命令`findOne()`，并将`current_list`会话参数作为`_id`在选择器/查询中传递。如果有什么被选中，我们将得到一个单一的类别/列表。让我们确保我们确实这样做，并且我们还能得到`items`。

如果没有返回任何内容，或者该类别中没有`items`，我们真的需要确定`Lendee`或`LendClass`吗？所以让我们创建一个`if`语句，和一个在`if`内的`for`语句，只有在我们有值得迭代的元素时才会执行：

```js
    if (cats&&cats.items)
    { 
      for(var i = 0; i<cats.items.length;i++) {
        var d = cats.items[i]; 
  d.Lendee = d.LentTo ? d.LentTo : "free"; 
  d.LendClass = d.LentTo ? "label-important" : "label-success";
      }; 
      return cats.items; 
    }; 
  }; 
};
```

首先，我们检查`cats`和`cats.items`是否未定义/为空。

接下来，我们遍历`items`中的所有值（如果你还记得，`items`是一个数组）。为了更容易，我们声明变量`d = cats.item[i]`。

现在我们添加了`Lendee`属性，检查项目是否借给了任何人，`LentTo`属性。如果没有（如果`LentTo`不存在），我们将分配字符串`"free"`。

同样，如果`LentTo`存在，我们将红色 Bootstrap 标签类`label-important`作为`LendClass`。如果项目没有借出，我们将使用绿色 Bootstrap 类`label-success`。

最后，在我们的新`Lendee`和`LendClass`属性分配之后，我们将返回`cats.items`。我们没有将这些属性保存到我们的模型中。那是因为它们*不是*模型的一部分。它们由视图使用，因此我们只通过 View-Model 模板使它们可用。

## 附加视图状态

现在我们需要为所有不同的视图状态声明模板。也就是说，我们需要向 View-Model/session 添加属性，这样我们才能知道我们在看什么，我们在编辑什么，以及应该隐藏/显示什么。具体来说，我们需要在四种情况下访问状态值：

+   我们在看列表吗？（`list_selected`）

+   我们在看哪个列表？（`list_status`）

+   我们在向列表中添加项目吗？（`list_adding`）

+   我们在更新借阅人吗？（`lendee_editing`）

在`LendLib.js`中我们新创建的 items 模板/函数下方添加以下代码：

```js
      return cats.items; 
    }; 
  }; 
}; // <---- ending bracket for Template.list.items function ----

Template.list.list_selected = function() { 
 return ((Session.get('current_list')!=null) && (!Session.equals('current_list',null))); 
}; 

Template.categories.list_status = function(){ 
 if (Session.equals('current_list',this._id)) 
 return ""; 
 else 
 return " btn-inverse"; 
}; 

Template.list.list_adding = function(){ 
 return (Session.equals('list_adding',true)); 
}; 

Template.list.lendee_editing = function(){ 
 return (Session.equals('lendee_input',this.Name)); 
};

```

让我们逐一分析这些模板函数。

```js
Template.list.list_selected = function() { 
return ((Session.get('current_list')!=null) && (!Session.equals('current_list',null))); 
}
```

`Session`变量`current_list`可以是`undefined`或`null`。如果是`undefined`，`Session.equals('current_list'),null)`将返回`true`。所以我们需要检查这两种情况，很不幸。

```js
Template.categories.list_status = function(){ 
if (Session.equals('current_list',this._id)) 
return ""; 
else 
return "btn-inverse"; 
}; 
```

`list_status`用于告诉类别按钮是否应显示为选中状态。最容易的方法是通过一个 CSS 类。Bootstrap 使用`btn-inverse`显示黑白文本，但这是我们默认的按钮外观。因此，因为我们使用了完全相反的颜色方案，我们将使用 Bootstrap 的普通黑白外观来显示选中的类别。

换句话说，对于`current_list`，我们将返回`""`（默认按钮的外观和感觉）。对于所有其他列表/类别，我们将返回`"btn-inverse"`，以改变 CSS 样式。

你可能想知道`this._id`。在这个实例中，`this`指的是 MongoDB 记录（技术上来说是文档游标），而`._id`是那个“记录”的唯一 MongoDB 标识符。这称为**上下文**，在这种情况下使用 HTML 模板时，上下文是从哪里调用模板的列表/类别元素。

```js
Template.list.list_adding = function(){ 
  return (Session.equals('list_adding',true)); 
}
```

这个真的很直接。如果`Session`变量`list_adding`是`true`，我们在添加到列表。如果不是，我们就不添加。

```js
Template.list.lendee_editing = function(){ 
  return (Session.equals('lendee_input',this.Name)); 
}
```

为了检查我们是否应该进入借阅者编辑模式，我们将检查`Session`变量`lendee_input`，看它是否有值，以及这个值是否是我们刚刚点击物品的`Name`。再次说明，这是隐含的上下文。这次，不是列表，而是项目。我们怎么知道这个？因为函数是从哪里调用的。还记得 HTML 吗？

```js
<li class="lending_item alert"> 
  <button type="button" class="close delete_item" id="{{Name}}">×</button> 
{{Name}} 

{{#if lendee_editing}}
```

注意我们如何在`if`语句中使用`lendee_editing`，正好在我们使用`{{Name}}`之后。这显示了上下文。`LendLib.js`中的`this.Name`与`LendLib.html`中的`{{Name}}`具有相同的上下文。换句话说，`this.Name`引用了与`{{Name}}`相同的属性。

既然我们在 HTML 模板中，我们需要对 HTML 类别模板进行一次更改。我们等到现在，这样更改才有意义。当你做出以下代码更改时，你会看到模板`{{list_status}}`和`{{_id}}`的使用，以及为什么`this._id`的上下文突然变得有意义。

在`LendLib.html`中找到以下行（应该在第 27 行左右）：

```js
{{#each lists}}
  <div class="category btn btn-inverse">
    {{Category}} 
</div> 

{{/each}}
```

然后将其更改为如下代码片段的样子：

```js
{{#each lists}}
  <div class="category btn {{list_status}}" id="{{_id}}">
    {{Category}}
  </div> 

{{/each}}
```

## 添加事件

我们现在将连接所有事件。不是在 HTML（我们的视图）中这样做，而是在模板声明（我们的视图模型）中这样做。

第一个发生在`Template.categories.events`声明中，因为我们需要添加一个事件，来改变`Session`变量`current_list`。如果你记得的话，`current_list`帮助我们知道是否有选中的列表（`list_selected`）以及那个列表是什么（`list_status`）。

在`LendLib.js`中，在`Template.categories.events`函数的`'focusout #add-category'`事件声明和最后的`});`括号之间，添加以下代码：

```js
        Session.set('adding_category', false);
      } 
    } 
  }, 
  'focusout #add-category': function(e,t){
    Session.set('adding_category',false);
  }, 
 'click .category': selectCategory 
});
```

### 小贴士

不要忘记在`'focusout... function(e,t){...}`代码块后面加上逗号（`,`）。

这为具有 CSS 类`"category"`的每个按钮添加了点击事件，并调用`selectCategory()`函数。我们现在就声明那个函数。

在`focusText()`函数之后，在`Template.list.items`声明之前，添加以下代码：

```js
function selectCategory(e,t){ Session.set('current_list',this._id);
}  

Template.list.items = function () {
...
```

是的，你本可以把这个放在任何地方。是的，你本可以简单地在一个点击事件声明中嵌入一个通用函数。那么为什么放在这里呢？因为这样能让我们的代码更具可读性，而且我们需要一个部分来处理所有将要需要的添加/删除/更新调用，所以正好放在这里。

是的，很简单。它只是用`this._id`更新了`Session`变量`current_list`。这里`this`的上下文是类别/列表，因此`_id`是记录的 MongoDB 生成的 ID。

好的，现在我们已经处理了所有类别的 events，让我们来处理项目的 events。在`if (Meteor.is_client) {...`代码块的最后一行，在闭合的`}`括号内，放入以下代码：

```js
Template.list.lendee_editing = function(){ 
  ... 
} 	 

Template.list.events({ 
 'click #btnAddItem': function (e,t){
 Session.set('list_adding',true); 
 Meteor.flush(); 
 focusText(t.find("#item_to_add")); 
 }, 
 'keyup #item_to_add': function (e,t){ 
 if (e.which === 13) 
 { 
 addItem(Session.get('current_list'),e.target.value); 
 Session.set('list_adding',false); 
 } 
 }, 
 'focusout #item_to_add': function(e,t){ 
 Session.set('list_adding',false); 
 }, 
 'click .delete_item': function(e,t){ 
 removeItem(Session.get('current_list'),e.target.id); 
 }, 
 'click .lendee' : function(e,t){
 Session.set('lendee_input',this.Name); 
 Meteor.flush();
 focusText(t.find("#edit_lendee"),this.LentTo); 
 }, 
 'keyup #edit_lendee': function (e,t){ 
 if (e.which === 13) 
 { 
 updateLendee(Session.get('current_list'),this.Name,
 e.target.value); 
 Session.set('lendee_input',null); 
 } 
 if (e.which === 27) 
 {
 Session.set('lendee_input',null); 
 } 
 } 
});

}//<----this is the closing bracket for if(Meteor.is_client) ----
```

六个事件！看起来比实际更吓人。像往常一样，让我们一步步分解。

```js
Template.list.events({ 
  'click #btnAddItem': function (e,t){
    Session.set('list_adding',true); 
    Meteor.flush(); 
    focusText(t.find("#item_to_add")); 
  },
```

我们声明`Template.lists.events`，并枚举我们的事件。第一个是为添加一个项目。添加项目的按钮有趣的是，命名为`btnAddItem`，所以我们只需要添加声明，然后写我们的函数。

我们将`list_adding`设置为`true`。由于我们使用`Session.set()`，这种变化会通过我们的模板级联。这是一个反应，或者说反应式编程在起作用。我们还调用`Meteor.flush()`以确保清理 UI，然后，作为对用户的礼貌，我们将文本框（名为`item_to_add`）聚焦，这样我们的亲爱的用户就可以开始打字了。

```js
  'keyup #item_to_add': function (e,t){
    if (e.which === 13) 	   
    {
      addItem(Session.get('current_list'),e.target.value);
      Session.set('list_adding',false);
    }
  },
```

### 提示

你可以在 Meteor 文档中了解更多关于`Meteor.flush()`做的事情，地址是[`docs.meteor.com/#meteor_flush`](http://docs.meteor.com/#meteor_flush)。

下一个事件是基于我们的`item_to_add`文本框的`keyup`事件。如果我们按下*Enter*或 Return 键（`e.which === 13`），我们将调用`addItem()`函数来更新数据模型，然后我们将隐藏文本框。我们怎么做呢？当然设置`list_adding = false`。再次强调，通过`Session.set()`来做会使这种变化通过我们的模板级联。

你可能还漏掉了一件别的事情：记得我们曾在第二章, *响应式编程…它是有生命的！*, 使用控制台手动添加一个类别/列表吗？变化立刻反映在 HTML DOM 中。这里也是同样的道理。当`addItem()`更新数据模型时，这个变化会触发`Template.list.items`的模板刷新。

```js
  'focusout #item_to_add': function(e,t){
    Session.set('list_adding',false);
  }, 
```

触发器创造了一个情境，这样如果我们改变主意不想添加一个`item`，我们只需要点击离开它。如果文本框`item_to_add`触发了`focusout`事件，我们将设置`Session`变量`list_adding`为`false`，模板将会级联。

```js
  'click .delete_item': function(e,t){ 
    removeItem(Session.get('current_list'),e.target.id); 
  },
```

记得我们曾在 HTML`列表`模板中创建了那个小小的![Adding events]按钮吗？这个按钮属于 CSS 类`delete_item`，当用户点击它时，我们将调用`removeItem()`函数，传递`current_list`和被点击的 HTML 元素中的`id`，碰巧是`Name`项（我们在`LendingLib.html`的第 39 行添加了`id="{{Name}}"`）。

```js
  'click .lendee' : function(e,t){
    Session.set('lendee_input',this.Name); 
    Meteor.flush();
    focusText(t.find("#edit_lendee"),this.LentTo); 	
  }, 
```

现在，我们关注`lendee`部分/按钮。如果你还记得，我们在`LendingLib.html`中设置了一个带有 CSS 类`lendee`的`<div>`元素。我们现在声明，无论何时点击其中一个`<div>`元素，我们都将执行与想要向`list`添加`item`非常相似的操作：

1.  将控制文本框可见性的`Session`变量设置为`true`（`lendee_input`）。

1.  刷新 UI（`Meteor.flush()`）。

1.  设置文本框的焦点（`focusText()`）。

还有一个事件处理程序：

```js
  'keyup #edit_lendee': function (e,t){
    if (e.which === 13)
    {
      updateLendee(Session.get('current_list'),this.Name,
      e.target.value); 
      Session.set('lendee_input',null); 
    }
    if (e.which === 27) 
    { 		   
      Session.set('lendee_input',null); 	  
    }
  }
});
```

具有`id="edit_lendee"`的文本框有两个`keyup`条件。

如果我们按下*Enter*或 Return（`e.which === 13`），我们将使用`updateLendee()`更新数据模型上的`LentTo`属性。然后通过将`lendee_input`设置为`null`来隐藏文本框。记住，更新数据模型，设置一个`Session`变量将导致模板刷新（又是反应式编程）。

如果我们决定不喜欢这些更改，我们将按下*Esc*键（`e.which === 27`），在这种情况下，我们将`lendee_input`设置为`null`，让反应式编程隐藏文本框。

## 模型更新

我们还剩下两件事要做。我们需要照顾好让我们的应用变得漂亮（不过还不是现在），我们需要创建刚刚在`events`部分提到的`addItem()`、`removeItem()`和`updateLendee()`函数。

所以让我们开始工作！在`LendingLib.js`中的帮助器部分（正好在`Template.lists.items`上方，第 68 行左右），让我们添加我们的`addItem()`函数：

```js
function addItem(list_id,item_name){
 if (!item_name&&!list_id)
 return; 
 lists.update({_id:list_id}, 
 {$addToSet:{items:{Name:item_name}}}); 
}

Template.list.items = function () {
...
```

`addItem()`函数有两个参数：`list_id`和`item_name`。

`list_id`用于`update`语句的选择器（查询）部分，而`item_name`包含要添加到新`item`的`item.Name`属性的值。

但首先，我们需要检查是否有`item_name`和`list_id`的值。如果没有，我们就会`return`。

现在，我们将对`lists`集合调用 MongoDB 的`update()`函数。`{_id:list_id}`是选择器。我们告诉 MongoDB 找到具有`_id` `= list_id`的记录。然后我们告诉 MongoDB 我们将要执行哪种更新。在这种情况下，我们将使用`$addToSet`，它将追加到一个数组中。我们要追加什么？

`{items:...`表示我们正在更新`items[]`数组。`{Name:item_name}`是我们要添加的，它是`Name`属性。这相当于说`item.Name = item_name`。

一旦我们添加了这个功能，正如你现在可能已经猜到的那样，模板将自动更新，因为数据模型发生了变化。停下来思考一下。在六行代码中，我们执行了一个更新查询*并*将更改传播到我们的 UI。六行！这难道不是很神奇吗？

接下来我们处理`removeItem()`：

```js
function removeItem(list_id,item_name){ 
if (!item_name&&!list_id) 
return; 
lists.update({_id:list_id}, 
{$pull:{items:{Name:item_name}}}); 
}

Template.list.items = function () {
...
```

哇，这看起来与`addItem()`函数非常相似。事实上，我们确实使用了相同的`update()`函数，只是这次使用了不同的操作。这次我们将使用`$pull`，从`items[]`数组中删除一个元素，其中`Name == item_name`。再一次，我们只需要六行代码。数据模型和 UI 都将自动更新。

现在我们来处理`updateLendee()`，这有点复杂，但只是因为 Meteor 实际上使用的是 minimongo，这是 MongoDB 的一个简化版，且不支持游标变量。这意味着，我们不是使用类似于`items.$.Name`的东西，其中`$`是游标位置，而是需要遍历`items[]`数组，更新值，然后调用一个更新操作，用我们的更新后的数组替换整个`items[]`数组。下面是我们在`LendLib.js`中是这样做的：

```js
function updateLendee(list_id,item_name,lendee_name){
 var l = lists.findOne({"_id":list_id , 
 "items.Name":item_name}); 
 if (l&&l.items) 
 { 
 for (var i = 0; i<l.items.length; i++)
 { 
 if (l.items[i].Name === item_name)
 {
 l.items[i].LentTo = lendee_name;
 } 
 }
 lists.update({"_id":list_id},{$set:{"items":l.items}}); 
 } 
};

Template.list.items = function () {
...
```

我们获取了`list_id`、`item_name`和`lendee_name`，这样我们就可以找到正确的记录（我们用`list_id`和`item_name`来做到这一点），然后用`lendee_name`中的值更新`LentTo`属性。

为了节省一些打字，我们声明了一个变量`l`，使用了 MongoDB 的`findOne()`函数。这个函数需要一个由两部分组成的选择器语句：`_id:list_id`和`"items.Name":item_name`。这个选择器基本上是在说：“找到一个记录，其中`_id == list_id`且`items[]`数组中有一个记录，其中`Name == item_name`。”

如果`l`有一个值，并且`l`也有`items`，我们将进入我们的`for`循环。在这里，我们特别检查哪个数组元素具有`Name == item_name`。如果我们找到一个，我们将`LentTo`属性设置为`lendee_name`。

一旦我们完成了`for`循环，我们将调用 MongoDB 的`update()`函数，并使用`$set`操作用新的`{"items":l.items}`替换旧的`items[]`数组。自动更新再次发生，我们的 UI（视图）和数据文档（模型）再次保持同步。

## 样式更新

现在，你可以运行这个应用程序。它将是一场视觉灾难，因为我们还没有设置任何 CSS 样式，但让我们快速搞定这件事。我们都会盯着一场车祸看的，承认吧！确保你的应用程序正在运行（在控制台输入`> meteor`）并导航到`http://localhost:3000`：

![样式更新](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_04_01.jpg)

点击**DVDs**，你应该会看到**Mission Impossible**的其中一个条目：

![样式更新](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_04_02.jpg)

这并没有那么糟糕，除了有些宽度和高度问题，但那是因为我们使用了 Bootstrap。让我们继续解决剩下的 UI 问题。

首先，我们在`LendLib.js`中有一个最后的更改。更改`focusText()`函数（位于大约第 55 行）：

```js
//this function puts our cursor where it needs to be. 
function focusText(i) {
  i.focus();
  i.select(); 
};
```

现在应该是这样的：

```js
//this function puts our cursor where it needs to be. 
function focusText(i,val) {
  i.focus(); 
 i.value = val ? val : ""; 
  i.select(); 
};
```

这个更改只是使得当我们去编辑一个已经有值的东西（比如借阅人）时，这个值会传输到文本框中。这使得用户更容易看到当前借阅人是谁。`val ? val : ""`这个条件语句是必要的，因为如果`val`没有被传递或者是 null，`"undefined"`会被放进文本框中。

我们现在想要更新所有其他视觉特性的 CSS。我们在这里不会详细介绍 CSS，因为有更好的方法来处理它，而且我们不是 CSS 专家。所以只需将以下内容添加到`~/Documents/Meteor/LendLib/LendLib.css`中，并保存更改：

```js
/* CSS declarations go here */ 
#lendlib{ 
 width:535px; 
 margin:0 auto; 
} 
#categorybuttons{ 
 width:100%; 
} 
#lending_list{
 list-style:none; 
 margin:0; 
 padding:0; 
} 
#lending_list li{ 
 list-style:none; 
 margin:5px; 
} 
#lending_list li.lending_item:hover{ 
 background-color:#fc6; 
 color:#630; 
} 
#lending_item{
 vertical-align:middle; 
} 
#add_item{
 padding-left:5px; 
} 
#btnAddItem{
 padding:10px;
 border-radius:5px; 
} 
#btnAddItem:hover{
 background-color:#B7F099; 
} 
#edit_lendee{
 padding-top:0; 
 margin-top:-2px; 
} 

```

如果你保持了`http://localhost:3000`打开，你的浏览器将自动刷新。如果你没有，重新打开它（确保 Meteor 正在运行）并观察结果：

![样式更新](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_04_03.jpg)

不要忘记测试你所有的新的功能！添加新的类别，将项目添加到列表中，更改借阅人，删除借阅人，删除项目等等，只是感受一下模型更新有多快和多干净。

现在，打开两个浏览器，都指向`http://localhost:3000`。你会注意到，在一个浏览器中做的更改在另一个浏览器中也会反映出来！就像之前一样，Meteor 正在处理客户端和服务器之间的数据模型同步，任何在客户端上的更改都会通过服务器传播到其他客户端。

![样式更新](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/gtst-mtr-js-fw/img/0823OS_04_04.jpg)

一旦你创建了足够多的项目和列表，就可以继续下一章。

# 总结

在本章中，你已经完成了你借贷图书馆应用的模板、事件和数据模型部分。你已经创建了语句来添加、删除和更新你的记录，并实现了 UI 状态的改变。你亲自看到了响应式编程是如何工作的，并对你所使用的上下文有了坚实的基础。你现在能够从零开始创建一个应用，使用 Meteor 的核心功能快速开发并拥有健壮的功能。在下一章中，你将更深入地了解 Meteor 的数据缓存和同步方法，并加强你的应用。
