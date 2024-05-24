# 通过创建有趣的游戏学习 HTML5（二）

> 原文：[`zh.annas-archive.org/md5/0598834ED79056F95FE4B258BB7FBDFD`](https://zh.annas-archive.org/md5/0598834ED79056F95FE4B258BB7FBDFD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：理解 HTML5 的重要性

在我们深入探讨本章将构建的游戏之前，我们将研究为什么在多个不同的浏览器中部署 HTML 和 JavaScript 应用程序可能会很困难。我们将重点关注这些问题的简单和实用解决方案，特别是关于今天使用的 HTML5 和最新 API。

我们将在本章中构建的游戏是一个基本的果冻重力游戏。它将利用 HTML5 的新 API 进行矢量图形、本地音频处理和拖放。作为这个游戏渲染系统的支撑，我们将使用旧的 JavaScript 定时器，正如我们将看到的，这对于我们需要每秒多次更新的这种游戏来说并不合适。幸运的是，现代浏览器已经解决了这个问题，并考虑到了我们对高效渲染引擎的需求。然而，我们不会在下一个游戏之前讨论这个新功能。只是为了完整起见，这个新功能被称为**requestAnimationFrame**。

# 浏览器兼容性

任何做过任何网页开发的人都很快就对不同浏览器解释和渲染相同代码的方式产生了非常深刻和彻底的厌恶。然而，如果我们深入研究一下这种现象，并寻找这些差异的根本原因，一些人会惊讶地意识到问题并不是看起来那样。虽然找到渲染差异的原因很容易，例如，一些浏览器以不同的方式定义框模型，但找到代码差异的原因可能并不那么清晰。令人惊讶的是，一些开发人员似乎对 JavaScript 语言感到厌恶，因为一些代码在某些浏览器中运行方式不同。然而，事实是 JavaScript 实际上是相当可移植的，它的 API 非常稳定和一致。

信不信由你，这些头疼大部分是由 DOM API 引起的，而不是 JavaScript 本身。一些浏览器以一种方式注册与 DOM 相关的事件，而其他浏览器则不承认该方法，而是使用自己的变体。对于操作 DOM 元素和子树也是如此。

例如，从 DOM 中删除节点的一种方法是在节点本身上调用`remove`方法。然而，截至目前，只有极少数浏览器公开了这个功能。通常，浏览器允许我们通过在父节点上调用`removeChild`方法，传递要从父节点中删除的子节点的引用，来从 DOM 树中删除节点。

这里要强调的关键点是：JavaScript 本身在不同浏览器中非常一致，但浏览器允许我们通过编程方式与 DOM 进行交互的方式，尽管这通常是通过 JavaScript 完成的，但在不同浏览器中可能会有所不同。虽然这对任何人来说都不是新闻，当然也不是 HTML5 独有的，但重要的是要记住，我们用于编程 Web 平台的主要工具，也就是 JavaScript，是一个非常强大和一致的工具。我们需要记住的问题是 DOM API（以及 CSS，尽管这个特定问题正在变得越来越不是问题，因为浏览器开始就与之相关的共同标准达成一致）。

## 支持不同的浏览器

在开发 HTML5 应用程序时，我们可以采取不同的方法来确保代码在不同浏览器中运行相同，并且设计也相同。其中一些做法是痛苦和繁琐的，另一些是不可靠的，还有一些是足够好的。不幸的是，只要今天存在这么多浏览器差异，就不会有一个单一的解决方案完全消除这个问题。

在编写在不同浏览器中运行几乎相同的代码时，主要目标有两个：尽可能少地为每个浏览器编写独特的代码，以及编写能够优雅降级的代码。专门针对特定浏览器的一些独特功能是一回事，但维护两个或更多个独立的代码库是完全不同的问题。记住，你可能写的最好的代码，无论是在执行效率还是安全性方面，都是你根本不需要写的代码。你写的代码越多，你的代码就越容易出错和故障。因此，避免写太多与你正在编写的其他代码相同的代码，但为不同的浏览器编写独特的代码。

虽然追求完美主义可能是一个很好的品质，但我们必须现实一点，我们不会很快达到完美。不仅如此，在大多数情况下（特别是涉及到视频游戏的所有情况），我们不需要编写接近完美的软件。在一天结束时，无论你是否同意，软件开发的目标是生产足够好的软件。只要程序解决了它被编写的问题，并以合理的方式做到这一点，那么从实际目的来看，我们可以说这个软件是好的。

在我们介绍完这些原则后，当你开发 HTML5 应用程序时，包括面向全球数亿人的游戏时，请记住这两个原则。确实，有一些特定于浏览器的功能可能会使游戏无法玩或者至少使用户体验有很大不同，最终结果可能不理想。但是，要密切关注你真正想要实现的目标，以便辨别哪些浏览器差异是足够好的。可能某个特定浏览器的功能被使用的用户太少，以至于这个功能没有成本效益。然而，我们绝对不希望部署一个无法使用的产品。

## HTML5 库和框架

在我们寻求以成本效益的方式支持多个浏览器时，我们可以放心地知道我们并不孤单。今天，有许多旨在解决浏览器兼容性问题的开源项目，我们可能可以玩字母游戏，为字母表中的每个字母命名一个不同的 HTML5 库或框架。

这些工具存在的主要原因通常有两个，即抽象掉浏览器差异和加快开发速度。虽然今天的大多数 JavaScript 工具提供的抽象试图为客户端提供统一浏览器差异的接口，但许多这些库也提供功能，简单地加快开发时间和工作量。

### jQuery

到目前为止，最受欢迎的 JavaScript 库是一个叫做 jQuery 的库。如果你以前没有听说过 jQuery，那么很可能你刚从一个非常深沉和深刻的冬眠中醒来，而你的身体穿越了遥远的星系。使用 jQuery 的一些主要好处包括非常强大的 DOM 查询和操作引擎，一个非常简单、统一的 XHR（XML HTTP 请求，也称为 Ajax）接口，以及通过一个良好定义的插件接口来扩展它的能力。

使用 JavaScript 库，特别是 jQuery，可以节省开发时间和精力的一个例子是尝试向服务器发出异步请求。没有 jQuery，我们需要编写一些样板代码，以便不同的浏览器都表现一致。代码如下：

```js
var xhr = null;

// Attempt to create the xhr object the popular way
try {
  xhr = new XMLHttpRequest();
}
// If the browser doesn't support that construct, try a different one
catch (e) {
  try {
    xhr = new ActiveXObject("Microsoft.XMLHTTP");
  }
  // If it still doesn't support the previous 2 xhr constructs, just give up
  catch (e) {
    throw new Error("This browser doesn't support AJAX");
  }

// If we made it this far, then the xhr object is set, and the rest
// of the API is identical independent of which version we ended up with
xhr.open("GET", "//www.some-website.com", true);
xhr.onreadystatechange = function(response) {
  // Process response
  // (...)
};

xhr.send();
```

现在，相比之下，可以使用以下代码使用 jQuery 来实现相同的功能：

```js
$.ajax({
  type: "GET",
  url: "//www.some-website.com",
  async: true,  /* This parameter is optional, as its default value is true */
  complete: function(response) {
    // Process response
    // (…)
  }
});
```

jQuery 的 XHR 功能的一个很棒的地方是它非常灵活。至少，我们可以以完全跨浏览器的方式实现与上一个代码中相同的行为，如下面的代码所示：

```js
$.get("//www.some-website.com", function(response) {
  // Process response
  // (…)
});
```

总之，用很少的工作、时间和代码就可以做很多事情，这也带来了额外的好处，即该库是由一个非常专注和活跃的社区开发的。有关 jQuery 的更多信息，请访问官方网站[`www.jquery.com`](http://www.jquery.com)。

### Google Web Toolkit

另一个流行且非常强大的 JavaScript 工具是 Google Web Toolkit（GWT）。首先，GWT 不仅仅是一个提供了一些 JavaScript 抽象的库，而是一个完整的开发工具包，使用 Java 语言（本身具有所有的优势），然后将 Java 代码编译和转换为高度优化的、特定于浏览器的 JavaScript 代码。

愚蠢地将 jQuery 与 GWT 进行比较，因为它们解决不同的问题，并对 Web 开发有完全不同的看法。然而，值得一提的是，虽然 jQuery 是一个很棒的工具，几乎每个网页开发者的工具箱中都可以找到，但它并不适用于实际的游戏开发。另一方面，Google Web Toolkit 虽然不是小型琐碎的 HTML 和 JavaScript 项目的最合适工具，但非常适合游戏开发。事实上，流行的游戏《愤怒的小鸟》在开发 Google Chrome 版本时使用了 Google Web Toolkit。

总之，虽然 GWT 足够成为一本独立的书的主题，但在你接手下一个大型 Web 开发项目时，考虑使用它是一个很好的选择，其中一个目标是为你的应用程序提供多个浏览器的支持。有关 Google Web Toolkit 的更多信息，请访问官方网站[`developers.google.com/web-toolkit/`](https://developers.google.com/web-toolkit/)。

## 支持具有有限 HTML5 功能的浏览器

正如前面提到的，上述由浏览器引起的开发头疼问题都不是 HTML5 特有的。然而，重要的是要知道，HTML5 并没有解决这个问题（尚未）。此外，HTML5 带来了全新的跨浏览器噩梦。例如，虽然大多数与 HTML5 相关的 API 在文档规范中得到了很好的定义，但也有许多 API 目前处于实验阶段（有关实验性 API 和供应商前缀的讨论，请参阅在线章节《设置环境》和第二章《HTML5 排版》，在那里这个主题得到了更全面的讨论）。除此之外，还有一些浏览器尚未支持某些 HTML5 功能，或者目前提供有限的支持，或者更糟糕的是，它们通过与其他浏览器不同的接口提供支持。

再次，作为网页开发者，我们在创建新应用程序时必须始终把用户放在首要位置。由于浏览器兼容性问题仍然存在，一些人认为 HTML5 仍然是未来的事情，其新功能的实用性尚未得到验证。本节的其余部分将描述我们如何在今天使用 HTML5 而不必担心不太理想的浏览器，并为使用这些浏览器的用户提供功能性应用程序。

### 优雅地降级

如果您仔细关注先前的代码片段，我们尝试创建一个在许多不同浏览器中工作的**XHR**对象，您会注意到，如果执行代码的浏览器不支持代码搜索的两个选项中的一个，代码会故意停止执行。这是一个很好的例子，说明我们不应该这样做，如果可能的话。每当特定功能对某个浏览器不可用时，第一选择应该是提供替代构造，即使这种替代方法并不能完全提供相同的行为。我们应该尽力在最坏的情况下提供一个功能性的体验，即浏览器完全不支持我们要实现的功能的情况。

例如，HTML5 提供了一种新的存储机制，类似于 cookie（换句话说，是一种简单的键值对存储），但主要区别在于这种存储机制完全将数据存储在客户端，并且这些数据永远不会作为 HTTP 请求的一部分来回传输到服务器。虽然这种存储系统的具体内容和工作原理将在本书的后面进行介绍，但我们可以总结说，这种存储系统（称为本地存储）存储键值对，并通过一个名为`localStorage`的 Window 对象的属性的明确定义的接口来实现。

```js
localStorage.setItem("name", "Rodrigo Silveira");
localStorage.length == 1; // true
localStorage.getItem("name"); // "Rodrigo Silveira"
localStorage.removeItem("name");
localStorage.length; // == 0
```

本地存储的一个强大应用是缓存用户发出的异步请求，以便后续请求可以直接从浏览器的本地存储中获取，从而避免往返到服务器。然而，如果浏览器不支持本地存储，在这种特定情况下的最坏情况是应用程序需要再次从服务器获取后续请求。虽然这并不实用或高效，但这绝对不是一个应该让人担心的问题，除非这意味着我们需要编写大量额外的代码来测试`localStorage`对象的存在，从而在每次需要使用它时污染代码库，因为会有很多重复的条件语句。

这种问题的一个简单解决方案是使用 polyfills，我们将在接下来更深入地讨论。简而言之，polyfill 是一个 JavaScript 替代方案，当原始实现尚不可用时，浏览器可以使用它。这样，如果浏览器需要，您可以加载 polyfill，而代码库的其余部分可以通过原始接口使用功能，而不知道它正在使用哪种实现。对于`localStorage`，我们可以简单地检查真实的 API 是否可用，并在不可用时编写模拟其行为的代码。以下代码片段展示了这种行为：

```js
// If the browser doesn't know anything about localStorage,
// we create our own, or at least an interface that respond
// to the calls we'd make to the real storage object.
if (window.localStorage === undefined) {
  var FauxLocalStorage = function() {
    var items = {};
    this.length = 0;

    this.setItem = function(key, value) {
      items[key] = value;
      this.length++;
      };

    this.getItem = function(key) {
      if (items[key] === undefined)
        return undefined;

        return items[key];
      };

    this.removeItem = function(key) {
      if (items[key] === undefined)
        return undefined;

      this.length--;
        return delete items[key];
      };
  };

  // Now there exists a property of window that behaves just like
  // one would expect the local storage object to (although in this example
  // the functionality is reduced in order to make the point)
  window.localStorage = new FauxStorage();
}

// This code will work just fine whether or not the browser supports the real
// HTML5 API for local storage. No exceptions will be thrown.
localStorage.setItem("name", "Rodrigo Silveira");
localStorage.length == 1; // true
localStorage.getItem("name"); // "Rodrigo Silveira"
localStorage.removeItem("name");
localStorage.length; // == 0
```

尽管前面的 polyfill 实际上并没有存储任何数据超出当前会话，但这种本地存储 polyfill 的特定实现可能足够满足特定应用程序的需求。至少，这种实现允许我们编写符合官方接口的代码（调用规范定义的真实方法），并且浏览器不会抛出异常，因为这些方法确实存在。最终，每当不支持 HTML5 API 的浏览器使用我们的 polyfill 时，由于条件检查了浏览器是否支持该功能，这个条件将不再触发加载 polyfill，因此客户端代码将始终引用原始实现，而主源代码不需要进行任何更改。

虽然考虑 polyfills 对我们有什么作用是相当令人兴奋的，但细心的学生会很快注意到，编写完整、安全和准确的 polyfills 比在样式表中添加简单的 CSS hack 以使设计与不同浏览器兼容要复杂一些。即使之前展示的样本本地存储 polyfill 相对复杂，它也没有完全模仿官方接口，也没有完全实现它所实现的少量功能。很快，有组织的学生会问自己应该期望花费多少时间来编写防弹 polyfills。我很高兴地报告，答案在下一节中给出并解释。

### Polyfills

回答前面的问题，即您应该期望花费多少时间来编写自己的强大 polyfills，以便能够开始使用 HTML5 功能，并且仍然使您的代码在多个不同的浏览器上运行，答案是零。除非您真的想要为不同的浏览器编写后备方案的经验，否则没有理由自己编写库等，因为这个领域已经有数百名其他开发人员为社区分享了他们的工作。

使用 polyfills 时，我们无法在 HTML5 项目的顶部使用单个 JavaScript 导入来神奇地扩展每个不足的浏览器，使它们 100％准备好使用 HTML5。然而，有许多单独的项目可用，因此，如果您想要使用特定元素，只需导入该特定的 polyfill 即可。虽然没有一个确定的来源可以找到所有这些 polyfills，但是简单地通过 Google 或 Bing 搜索您想要的特定功能，应该可以迅速连接到适当的 polyfill。

### Modernizr

值得一提的一个工具是 Modernizr。这个 JavaScript 库检查加载它的页面，并检测用户浏览器中可用的 HTML5 功能。这样，我们可以非常容易地检查特定 API 是否可用，并相应地采取行动。

截至目前，当前版本的 Modernizr 允许我们测试特定的 API 或功能，并在测试结果为正或负时加载特定的 polyfills，这使得在需要时添加 polyfills 非常容易和轻松。

此外，Modernizr 还包括 HTML5 Shiv，这是一个非常小的 JavaScript 片段，允许我们在不识别它们的浏览器中使用所有 HTML5 语义标签。请注意，这不会添加标签的实际功能，而只是允许您通过 CSS 样式化这些标签。原因是在 Internet Explorer 8 及更低版本中，如果我们尝试为浏览器不识别的元素添加样式，它将简单地忽略应用于它的任何 CSS。然而，使用 Modernizr，这些元素被创建（使用 JavaScript），因此浏览器知道这些标签，从而允许应用 CSS。

有关 Modernizr 的更多信息，请访问官方网站[`modernizr.com/`](http://modernizr.com/)。

# 游戏

我们将在本章中构建的项目游戏简称为*基本果冻摇摆重力游戏*。游戏的目标是喂我们的主角足够多的果冻，以至于他吃得太多而生病并倒在地板上。主角通过键盘上的左右箭头键控制，为了吃果冻，您只需将主角放在一个下落的果冻下面。每次喂主角一个果冻，他的健康指数都会略微下降。一旦喂了足够多的果冻，健康指数降到零，主角就会生病晕倒。如果让果冻掉在地板上，除了果冻到处溅开之外，什么也不会发生。这就是一个基本的果冻摇摆重力游戏。您能为乔治王子提供足够多的果冻直到他昏倒吗？

![游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_04_01.jpg)

为了演示一些关于 HTML5 游戏开发的原则，我们将完全使用 DOM 元素构建这个游戏。虽然这种方法通常不是理想的方法，但你会注意到许多游戏在大多数现代浏览器和今天的普通台式机或笔记本电脑上仍然表现得相当不错。然而，正如我们将在接下来的章节中学到的那样，HTML5 中有一些技术、工具和 API 对于游戏开发来说更加合适。

此外，与本书一贯的做法一样，大多数游戏元素在复杂性方面都会保持在最低水平，以便能够轻松解释和理解。特别是在这个游戏中，我们只会使用 SVG 图形作为概念验证，而不是深入探讨 SVG 标准为我们提供的潜力和机会。拖放也是如此，还有很多可以做的事情。

## 代码结构

这段代码的结构非常简单。游戏中的每个元素都是通过 CSS 绝对定位的，并且每个元素都由一些带有背景图像或一些 CSS3 属性的 HTML 容器组成，这些属性赋予它们圆角、阴影等新鲜外观。尽管有些人可能更喜欢面向对象的编程而不是函数式编程，更喜欢更好的内聚而不是到处都是全局变量，但在这个游戏中，我们将采取这种方法，并专注于 HTML5 方面，而不是游戏的设计。同样，图形的风格和质量也是如此。你在这个游戏中看到的所有东西都是我用一个免费的照片编辑程序创建的，而且我用不到 30 分钟的时间就创建了你在游戏中看到的所有图形。这主要是为了表明即使你预算有限，或者没有专门的图形设计团队，也可以构建有趣的游戏。

由于我们将所有的 SVG 实体都直接加载到 HTML 结构中，我们将它们放在一个对用户隐藏的`div`容器中，然后克隆我们需要的每个实体，并在游戏中使用它们。我们对所有果冻和英雄都使用这种技术。英雄 SVG 与从矢量编辑软件导出的内容保持一致。果冻 SVG 稍作修改，去掉了它们设计时的所有颜色，并用 CSS 类替换。这样我们可以创建不同的 CSS 类来指定不同的颜色，每个果冻 SVG 的新实例都被分配一个随机类。最终结果是一个单一的 SVG 模型隐藏在不可见的`div`容器中，每个实例都被赋予不同的颜色，而不需要额外的代码，以增加游戏的多样性。我们也可以随机分配不同大小和旋转给每个果冻实例，但这被留作读者的练习。

```js
<body>
  <div class="health-bar">
    <span></span>
  </div>

    <h1 id="message"></h1>

    <div id="table"></div>
    <div id="bowl"></div>
    <div id="bowl-top-faux-target"></div>
    <div id="bowl-top" class="dragging-icon bowl-closed"
      draggable="true"
      ondragstart="doOnDragStart(event)"
      ondragend="doOnDragEnd(event)"></div>
    <div id="bowl-top-target"
      ondrop="startGame()"
      ondragover="doOnDrop(event)"
      ondragleave="doOnDragLeave(event)"></div>

    <div class="dom-recs">
      <svg class="hero-svg">
      (…)
      </svg>
      <svg class="jelly-svg">
      (…)
      </svg>
    </div>
</body>
```

虽然我们可以使用数据属性而不是 ID 属性来表示所有这些元素，但在这种情况下，使用它们而不是 ID 并没有真正的好处，就像在这种情况下使用 ID 而不是数据属性也没有好处一样。

请注意，`bowl-top`可以拖放到两个目标上。实际上，只有一个目标，即`bowl-top-target`元素。另一个看起来像目标的元素，巧妙地被赋予了`bowl-top-faux-target`的 ID，只是为了视觉效果。由于真正的放置目标（拖动元素可以在拖动选项结束时放置的元素）只有在鼠标指针移动到它上面时才会被激活，所以在桌子上没有足够的空间来实现`bowl-top`似乎被放置在一个小轮廓区域的期望效果。

最后，在游戏中使用了一个全局计时器，用于控制我们调用游戏循环函数`tick()`的频率。虽然这不是一章关于正确游戏设计的内容，但我要指出，您应该避免诱惑去为不同目的创建多个计时器。有些人在这方面毫不犹豫，会通过一个独立于主游戏计时器的唯一计时器触发事件。这样做，特别是在 HTML5 游戏中，可能会对性能和所有事件的同步产生负面影响。

## API 使用

游戏中使用的三个 API 是音频、SVG 和拖放。接下来将简要解释这些 API 在游戏中的使用方式，其中只给出了功能的概述。然而，在下一节中，我们将详细了解这些功能实际上是如何使用的，以及如何在这种和其他情况下使用它。有关此游戏的完整源代码，请查看 Packt Publishing 网站上的书页。

### 网络音频

音频被用作永无止境的循环，作为背景音乐，以及当果冻被发射，弹跳，溅在地板上，或被饥饿的英雄吃掉时，会发出单独的音效。当英雄因吃太多果冻而最终死亡时，也会发出一个老式的音效。

游戏中每个音频实体的管理方式是通过一个简单的封装，其中包含对单独音频文件的引用，并公开一个接口，允许我们播放文件，淡入淡出音频文件，以及将新的音频文件添加到此类管理的音频列表中。代码如下：

```js
// ** By assigning an anonymous function to a variable, JavaScript
// allows us to later call the variable's referenced function with
// the keyword 'new'. This style co function creation essentially 
// makes the function behave like a constructor, which allows us to
// simulate classes in JavaScript
var SoundFx = function() {
  // Every sound entity will be stored here for future use
  var sounds = {};

  // ------------------------------------------------------------
  // Register a new sound entity with some basic configurations
  // ------------------------------------------------------------
  function addSound(name, file, loop, autoplay) {

    // Don't create two entities with the same name
    if (sounds[name] instanceof Audio)
      return false;

      // Behold, the new HTML5 Audio element!
      sounds[name] = new Audio();
      sounds[name].src = file;
      sounds[name].controls = false;
      sounds[name].loop = loop;
      sounds[name].autoplay = autoplay;
    }

    // -----------------------------------------------------------
    // Play a file from the beginning, even if it's already playing
    // -----------------------------------------------------------
  function play(name) {
    sounds[name].currentTime = 0;
    sounds[name].play();
  }

    // -----------------------------------------------------------
    // Gradually adjust the volume, either up or down
    // -----------------------------------------------------------
  function fade(name, fadeTo, speed, inOut) {
    if (fadeTo > 1.0)
      return fadeOut(name, 1.0, speed, inOut);

    if (fadeTo < 0.000)
      return fadeOut(name, 0.0, speed, inOut);

      var newVolume = parseFloat(sounds[name].volume + 0.01 * inOut);

    if (newVolume < parseFloat(0.0))
      newVolume = parseFloat(0.0);

      sounds[name].volume = newVolume;

    if (sounds[name].volume > fadeTo)
      setTimeout(function(){ fadeOut(name, fadeTo, speed, inOut); }, speed);
    else
      sounds[name].volume = parseFloat(fadeTo);

      return sounds[name].volume;
  }

    // -----------------------------------------------------------
    // A wrapper function for fade()
    // ------------------------------------------------------------
    function fadeOut(name, fadeTo, speed) {
      fade(name, fadeTo, speed, -1);
    }

    // -----------------------------------------------------------
    // A wrapper function for fade()
    // -----------------------------------------------------------
    function fadeIn(name, fadeTo, speed) {
      fade(name, fadeTo, speed, 1);
    }

    // -----------------------------------------------------------
    // The public interface through which the client can use the class
    // -----------------------------------------------------------
    return {
      add: addSound,
      play: play,
      fadeOut: fadeOut,
      fadeIn: fadeIn
    };
};
```

接下来，我们实例化了一个自定义的`SoundFx`类型的全局对象，其中存储了游戏中使用的每个音频剪辑。这样，如果我们想播放任何类型的声音，我们只需在这个全局引用上调用`play`方法。看一下以下代码：

```js
// Hold every sound effect in the same object for easy access
var sounds = new SoundFx();

// Sound.add() Parameters:
// string: hash key
// string: file url
// bool: loop this sound on play?
// bool: play this sound automatically as soon as it's loaded?
sounds.add("background", "sound/techno-loop-2.mp3", true,  true);
sounds.add("game-over",  "sound/game-over.mp3",     false, false);
sounds.add("splash",     "sound/slurp.mp3",         false, false);
sounds.add("boing",      "sound/boing.mp3",         false, false);
sounds.add("hit",        "sound/swallow.mp3",       false, false);
sounds.add("bounce",     "sound/bounce.mp3",        false, false);
```

### 可伸缩矢量图形（SVG）

如前所述，游戏中使用 SVG 的方式受限于 SVG 规范非常强大且可能相当复杂。正如您将在 SVG API 的深入描述中看到的那样，我们可以对通过 SVG 绘制的每个基本形状做很多事情（例如原生动画化英雄的面部表情，或使每个果冻摇晃或旋转等）。

当果冻触地时，我们将代表果冻溅开的精灵切换成了一个相当巧妙的方法。当我们使用矢量编辑软件绘制果冻矢量时，我们创建了两个分离的图像，每个代表果冻的不同状态。这两个图像叠放在一起，以便正确对齐。然后，在 HTML 代码中，我们为这些图像分配了一个 CSS 类。这些类分别称为 jelly-block 和 splash，代表果冻的自然状态和果冻溅在地板上。在这两个类中，一个矢量被隐藏，另一个没有。根据每个果冻元素的状态，这两个类来回切换。这只需简单地将这两个矢量组中的一个分配给父 svg 元素的`jelly-svg-on`和`jelly-svg-off`两个类之一，如下面的代码所示：

```js
.jelly-svg-off g.jelly-block, .jelly-svg-on g.splash {
    display: none;
}

.jelly-svg-off g.splash, .jelly-svg-on g.jelly-block {
    display: block;
}
```

前面的样式驱动方式很简单。默认情况下，每个果冻元素都被赋予`jelly-svg-on`的 CSS 类，这意味着果冻没有溅开。然后，当计算出果冻已经触地时，我们移除该类，并添加`jelly-svg-off`的 CSS 类，如下面的代码片段所示：

```js
// Iterate through each jelly and check its state
for (var i in jellies) {

  // Don't do anything to this jelly entity if it's outside the screen,
  // was eaten, or smashed on the floor
  if (!jellies[i].isInPlay())
    continue;

    // Determine if a jelly has already hit the floor
    stillFalling = jellies[i].getY() + jellies[i].getHeight() * 2.5 < document.body.offsetHeight;

    // If it hasn't hit the floor, let gravity move it down
    if (stillFalling) {
      jellies[i].move();
    } else {

    // Stop the jelly from falling
    jellies[i].setY(document.body.offsetHeight - jellies[i].getHeight() - 75);

      // Swap the vectors
      jellies[i].swapClass("jelly-svg-on", "jelly-svg-off");
      jellies[i].setInPlay(false);

      // Play the corresponding sound to this action
      sounds.play("splash");
    }
}
```

### 拖放

与 SVG 在游戏中的使用方式类似，拖放以次要的方式进入最终产品，而 Web 音频则占据主导地位。然而，拖放在游戏中扮演的角色可以说是最重要的，它启动了游戏。与其让游戏在页面加载时立即开始播放，或者让用户按下按钮或按键来开始游戏，玩家需要将盖子从存放所有果冻的碗中拖出，并将其放在桌子上碗的旁边。

HTML5 中拖放的工作方式简单而直观。我们至少注册一个对象作为可拖动对象（您拖动的对象），至少注册一个其他对象作为放置目标（可将可拖动对象放入其中的对象）。然后，我们为适用于拖放行为的任何事件注册回调函数。

在游戏中，我们只监听了五个事件，两个在可拖动元素上，三个在放置目标元素上。首先，我们监听用户首次拖动可拖动对象时触发的事件（拖动开始），我们会对此做出响应，使碗盖图像不可见，并在鼠标指针后面放置一个盖子的副本，以便看起来用户真的在拖动那个盖子。

接下来，我们监听用户最终释放鼠标按钮时触发的事件，表示拖动动作的结束（拖动结束）。在这一点上，我们只需将碗盖恢复到最初的位置，放在碗的顶部。每当拖动动作结束，且放置在有效的放置目标内时（用户没有在预期的位置放置盖子），就会触发此事件，从根本上重新启动该过程。

我们在放置目标上监听的三个事件是`onDragLeave`、`onDragOver`和`onDrop`。每当可拖动对象放置在放置目标内时，目标的`onDrop`事件就会被触发。在这种情况下，我们所做的就是调用`startGame()`函数，这将启动游戏。作为`startGame`函数的设置的一部分，我们将碗盖元素移动到放置的确切像素位置，并删除可拖动属性，以便用户无法再拖动该元素。

`onDragOver`和`onDragLeave`函数分别在鼠标指针移动到目标对象上方和悬停在目标对象外部时触发。在我们的情况下，在这些函数中我们所做的就是切换碗盖和在拖动发生时显示在鼠标指针后面的图像的可见性。可以在以下代码中看到：

```js
// ------------------------------------------------------------
// Fired when draggable starts being dragged (onDragStart)
// ------------------------------------------------------------
function doOnDragStart(event) {
  if (bowlTop.isReady) {
    event.target.style.opacity = 0.0;
    event.dataTransfer.setDragImage(bowlTop, 100, 60);
  }
}

// ------------------------------------------------------------
// Fired when draggable is released outside a target (onDragEnd)
// ------------------------------------------------------------
function doOnDragEnd(event) {
  event.target.style.opacity = 1.0;
  document.querySelector("#bowl-top-faux-target").style.opacity = 0.0;
}

// ------------------------------------------------------------
// Fired when draggable enters target (onDragOver)
// ------------------------------------------------------------
function doOnDragOver(event) {
  event.preventDefault();
  document.querySelector("#bowl-top-faux-target").style.opacity = 1.0;
}

// ------------------------------------------------------------
// Fired when draggable is hovered away from a target (onDragLeave)
// ------------------------------------------------------------
function doOnDragLeave(event) {
  document.querySelector("#bowl-top-faux-target").style.opacity = 0.0;
}

// ------------------------------------------------------------
// Fired when draggable is dropped inside a target (onDrop)
// ------------------------------------------------------------
function startGame() {

  // Keep the game from starting more than once
  if (!isPlaying) {

    // Register input handlers
    document.body.addEventListener("keyup", doOnKeyUp);
    document.body.addEventListener("keydown", doOnKeyDown);

    // Reposition the bowl lid
    var bowlTop = document.querySelector("#bowl-top");
    bowlTop.classList.remove("bowl-closed");
    bowlTop.style.left = (event.screenX - bowlTop.offsetWidth + 65) + "px";
    bowlTop.style.top = (event.screenY - bowlTop.offsetHeight + 65 * 0) + "px";

    // Disable dragging on the lid by removing the HTML5 draggable attribute
    bowlTop.removeAttribute("draggable");
    bowlTop.classList.remove("dragging-icon");

    newJelly();
      isPlaying = true;

      // Start out the main game loop
      gameTimer = setInterval(tick, 15);
    }
};
```

# Web 音频

新的 Web 音频 API 定义了一种在浏览器中播放音频而无需单个插件的方法。对于高级别的体验，我们可以简单地在整个 HTML 页面中添加一些音频标签，浏览器会负责显示播放器供用户进行交互和播放、暂停、停止、倒带、快进和调整音量。或者，我们可以使用可用的 JavaScript 接口，并使用它来控制页面上的音频标签，或者实现更强大和复杂的任务。

关于浏览器支持和 Web 音频 API 的一个关键细节是，不同的浏览器支持不同的文件格式。在定义音频标签时，类似于图像标签，我们指定源文件的路径。不同的是，对于音频，我们可以为同一文件指定多个源（但是不同的格式），然后浏览器可以选择它支持的文件，或者在支持多个文件格式的情况下选择最佳选项。目前，所有主要浏览器都支持三种音频格式，即`.mp3`、`.wav`和`.ogg`。截至目前，没有一种音频格式在所有主要浏览器中都受支持，这意味着每当我们使用 Web 音频 API 时，如果我们希望触及尽可能多的受众，我们将需要每个文件的至少两个版本。

最后，请记住，尽管我们可以（而且应该）为每个音频元素指定多个音频文件，但每个浏览器只下载其中一个文件。这是一个非常方便（和显而易见）的功能，因为下载多个相同文件的副本将非常低效且占用带宽。

## 如何使用它

使用 Web 音频 API 的最简单方法是使用内联 HTML5 元素。其代码如下：

```js
<audio>
  <source src="img/sound-file.mp3" type="audio/mpeg" />
  <source src="img/sound-file.ogg" type="audio/ogg" />
</audio>
```

将上述片段添加到页面上不会导致任何可见的结果。为了对标签添加更多控制，包括向页面添加播放器以便用户可以与其交互，我们可以从与标签相关的元素中进行选择。这些属性如下：

+   **autoplay**：一旦浏览器下载完成，它立即开始播放文件。

+   **controls**：它显示一个可视化播放器，通过它用户可以控制音频播放。

+   **loop**：用于无限循环播放文件。

+   **muted**：当音频输出被静音时使用。

+   **preload**：它指定浏览器如何预加载音频资源。

通过 JavaScript 实现类似的结果，我们可以创建一个类型为音频的 DOM 元素，或者实例化一个类型为 Audio 的 JavaScript 对象。添加可选属性的方式与我们对任何其他 JavaScript 对象所做的方式相同。请注意，创建 Audio 的实例与创建对 DOM 元素的引用具有完全相同的效果：

```js
// Creating an audio file from a DOM element
var soundOne = document.createElement("audio");
soundOne.setAttribute("controls", "controls");

soundOneSource = document.createElement("source");
soundOneSource.setAttribute("src", "sound-file.mp3");
soundOneSource.setAttribute("type", "audio/mpeg");

soundOne.appendChild(soundOneSource);

document.body.appendChild(soundOne);

// Creating an audio file from Audio
var soundTwo = new Audio("sound-file.mp3");
soundTwo.setAttribute("controls", "controls");

document.body.appendChild(soundTwo);
```

尽管 JavaScript 音频对象可能看起来更容易处理，特别是因为它采用了令人惊叹的构造函数参数，可以节省我们一行代码，但它们的行为完全相同，并且只有在运行时才能够区分它们。一个小细节是，当我们在 JavaScript 中创建音频引用时，不需要将其附加到 DOM 以播放文件。

无论您决定如何处理此设置步骤，一旦我们在 JavaScript 中有音频对象的引用，我们就可以使用与该对象相关的许多事件和属性来控制它。音频对象如下：

+   **play()**：开始播放文件。

+   **pause()**：它停止播放文件，并保持 currentTime 不变。

+   **paused**：表示当前播放状态的布尔值。

+   **canPlayType**：用于查找浏览器是否支持特定的音频类型。

+   **currentSrc**：它返回当前分配给对象的文件的绝对路径。

+   **currentTime**：它以浮点数形式返回当前播放位置（以秒为单位）。

+   **duration**：它以浮点数形式返回总播放时间（以秒为单位）。

+   **ended**：一个布尔值，指示 currentTime 是否等于 duration。

+   **readyState**：它指示源文件的下载状态。

+   **volume**：它指示文件的当前音量，范围从 0 到 1，包括 0 和 1。这个数字是相对于当前系统音量的。

# SVG

**可缩放矢量图形**（**SVG**）简称为 SVG，是一种描述图形的基于 XML 的格式。这种格式可能看起来足够复杂，以至于被误认为是用于 2D 图形的完整编程语言，但实际上它只是一种标记语言。虽然对一些 Web 开发人员来说，SVG 可能是新的，但该规范最早是在 1999 年开发的。

矢量图形和光栅图形（即位图）的主要区别在于图形的描述方式。在位图中，每个像素基本上由三个或四个数字表示，表示该单个像素的颜色（RGB），以及可能的不透明度级别。从更广泛的意义上看，位图只不过是像素网格。另一方面，矢量图形由一系列数学函数描述，这些函数描述了线条、形状和颜色，而不是整个图像上的每个单独点。简而言之，矢量图形在缩放其尺寸方面表现出色彩，如下面的屏幕截图所示：

![SVG](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_04_02.jpg)

如果放大或尝试拉伸矢量图形，它将始终与原始图像一样平滑，因为形状是使用相同的数学函数定义（如左侧图像所示）。另一方面，光栅图形只由相同的像素网格定义。缩放该网格只意味着将网格的尺寸乘以，导致右侧图像所代表的方块状、像素化的图像。

现在，SVG 标准不仅仅定义了形状、线条、路径和颜色。规范还定义了可以应用于任何单个基元、一组基元或整个 SVG 上下文的变换和动画。规范还允许 SVG 成为一种非常可访问的格式，这意味着可以将文本和其他元数据直接包含到文件中，以便其他应用程序可以以除了图形之外的其他方式理解文件。例如，搜索引擎可以爬行和索引，不仅您的网页，还有任何 SVG 图形。

由于 SVG 是基于文本的（与存储二进制数据相反，例如音频文件），因此也可以使用诸如流行的 Gzip 之类的压缩算法来压缩 SVG 图像，这在当今的 Web 开发世界中非常普遍。当 SVG 文件保存为自己的独立文件时，它被赋予扩展名`.svg`。如果文件经过 Gzip 压缩，那么扩展名应该是`.svgz`，这样浏览器就知道在处理之前解压缩文件。

SVG 文件可以以几种不同的方式在 HTML 文件中使用。由于文件本身可以保存为自己的文件，因此可以使用对象标签将整个文件嵌入到页面中，也可以使用普通图像标签，甚至可以使用 XHR 对象从服务器获取其内容，并将其注入到 HTML 文档中。或者，SVG 文件的内容可以手动复制到主机 HTML 文件中，以便其内容内联导入。

要将 SVG 图形内联导入到 HTML 文档中，我们只需插入一个`svg`标签，其中包含所有内容作为其子节点。截至目前，XML 命名空间属性是必需的，还需要版本号，如下面的代码所示：

```js
<body>
  <svg

    version="1.1"
    width="150"
    height="150">

    <circle
      cx="75"
      cy="75"
      r="50"
      stroke="black"
      stroke-width="2"
      fill="red"></circle></svg>
</body>
```

虽然对于一个简单的红色圆圈来说可能很容易，但一旦图像变得更加复杂，就很难在一个文件中管理所有内容。因此，简单保存所有 SVG 文件并单独导入它们可能更方便。这种方法也更适合资源共享和重用，因为我们可以在多个文件中导入相同的图形，而无需每次都复制整个文件。

```js
<body>
  <object type="image/svg+xml" data="red-circle.svg"
    width="100" height="100">
  </object>

  <img src="img/red-circle.svg" width="100" height="100" />
</body>
```

在我们深入一些实际示例之前，关于 SVG 的最后一点是，父`svg`标签内的每个节点（包括父节点）都由浏览器管理。因此，这些节点中的每一个都可以通过 CSS 进行样式设置。如果这还不够，SVG 图形中的每个节点都可以注册浏览器事件，允许我们与图形及其所有单独组件进行交互，就像大多数其他 DOM 元素一样。这使得 SVG 成为一种非常动态、高度灵活的图形格式。

如果 SVG 实例与 HTML 内联，则我们可以直接引用父 svg 节点，或者通过 JavaScript 直接引用任何子节点。一旦我们有了这个引用，我们就可以像处理任何其他 DOM 元素一样处理对象。然而，如果 SVG 是外部的，我们需要多做一步，将实际的 SVG 文件加载到 JavaScript 变量中。一旦完成了这一步，我们就可以像处理本地文件一样处理 SVG 的子树。

```js
<body>
  <object type="image/svg+xml" data="red-circle.svg"
    width="100" height="100">
  </object>

  <script>
    var obj = document.querySelector("object");

    // Very important step! Before calling getSVGDocument, we must register
        // a callback to be fired once the SVG document is loaded.
    obj.onload = function(){
      init(obj.getSVGDocument());
    };

    function init(svg) {
      var circles = svg.getElementsByTagName("circle");

      // Register click handler on all circles
      for (var i = 0, len = circles.length; i < len; i++) {
        circles[i].addEventListener("click", doOnCircleClick);
      }

      // When a circle element is clicked, it adds a CSS class "blue"
            // to itself.
    function doOnCircleClick(event) {
      this.classList.add("blue");
    }
  }
  </script>
</body>
```

关于前面代码片段的一些重要细节，你应该始终记住的是：

+   导入的 SVG 文档被视为外部文档（类似于 Iframe），这意味着该文档之外的任何 CSS（如宿主文档）都不在其范围之内。因此，如果你想对从`getSVGDocument()`调用中的 SVG 节点应用 CSS 类，那么该 CSS 类必须在最初导入的同一个 SVG 文件中定义。

+   SVG 的 CSS 属性略有不同。例如，你会定义填充颜色而不是背景颜色。基本上，用在 SVG 元素本身上的属性，也是你在相应的样式表声明中会用到的属性。

+   任何特定于浏览器的 CSS 属性都可以应用到 SVG 节点上（例如，过渡、光标等）。

因此，前面的示例是通过以下`.svg`文件完成的，作为相应的`red-circle.svg`文件，如下面的代码片段中所使用的：

```js
<svg

  version="1.1"
  width="150"
  height="150">

<style type="text/css">
.blue {
  /* CSS Specific to SVG */
  fill: #0000ff;

  /* CSS Specific to the browser */
  cursor: pointer;
  -webkit-transition: fill 1.25s;
}
</style>
  <circle
    cx="75"
    cy="75"
    r="50"
    stroke="black"
    stroke-width="2"
    fill="red"></circle>
</svg>
```

## 如何使用它

尽管强烈建议在组合复杂的 SVG 图形时使用专业的矢量编辑软件，比如 Inkspace 或 Adobe Illustrator，但本节将带你了解 SVG 组合的基础知识。这样你就可以手工绘制基本的形状和图表，或者至少熟悉 SVG 绘制的基础知识。

请记住，无论你是通过之前描述的任何方法将 SVG 图形导入到 HTML 中，内联绘制它们，甚至通过 JavaScript 动态创建它们，你都需要将 XML 命名空间包含到根`svg`元素中。这是 SVG 新手常犯的一个错误，可能导致你的图形在页面上不显示。

我们可以用 SVG 绘制的原始形状有矩形、圆、椭圆、线、折线、多边形和路径。其中一些原始形状共享属性（如宽度和高度），而其他一些具有特定于该形状的属性（如圆的半径）。在 SVG 图形中看到的一切都是这些原始形状在某种组合中使用的结果。

SVG 中的一切都是在 SVG 画布内绘制的，由父`svg`标签定义。这个画布总是矩形的，即使它内部的形状可以是由任何原始形状创建的任何形状。此外，画布有自己的坐标系，将原点放在画布的左上角。画布的宽度和高度（由父`svg`标签确定）决定了绘图区域的尺寸，所有`svg`的子元素内部的（x，y）点都是相对于该点的。

作为以下示例的样板，我们将假设有一个外部的`svg`文件，我们将把画布大小设置为 1000 x 1000 像素，并在其中绘制。要查看每个示例的最终结果，你可以使用前一节中描述的任何一种方法来将 SVG 图像加载到 HTML 文件中。以下代码片段显示了如何定义`svg`标签：

```js
<svg  version="1.1" width="1000" height="1000">
</svg>
```

用 SVG 绘制矩形就像它可以得到的那样简单。只需为`rect`元素指定宽度和高度，就可以了。可选地，我们可以指定描边宽度和描边颜色（其中描边就是边框），以及背景颜色。看一下下面的代码：

```js
<svg  version="1.1" width="1000" height="1000">
  <rect
    width="400"
    height="150" />
</svg>
```

默认情况下，每个形状都在原点（x = 0，y = 0）处呈现，没有描边（`stroke-width = 0`），并且背景颜色（填充）设置为全黑（十六进制值为#000000，RGB 值为 0, 0, 0）。

圆是通过指定至少三个属性来绘制的，即*x*和*y*位置（由`cx`和`cy`表示），以及半径值（由字母`r`表示）。圆的中心位于位置（`cx`，`cy`），半径长度不考虑描边的宽度，如果存在的话。

```js
<svg  version="1.1" width="1000" height="1000">
  <circle
    cx="0"
    cy="0"
    r="300"
    fill="#ff3" />

  <circle
    cx="200"
    cy="200"
    r="100"
    fill="#a0a" />
</svg>
```

您会注意到，默认情况下，就像定位的 DOM 元素一样，每个节点都具有相同的 z-index。因此，如果两个或更多元素重叠，无论哪个元素最后被绘制（意味着它在父元素之外的位置更远），都会呈现在顶部。

椭圆与圆非常相似，唯一的区别是它们在每个方向（垂直和水平）都有一个半径。除此之外，绘制椭圆与绘制圆是完全相同的。当然，我们可以通过绘制两个半径长度相同的椭圆来模拟圆。

```js
<svg  version="1.1" width="1000" height="1000">
  <ellipse
    cx="400"
    cy="300"
    rx="300"
    ry="100"
    fill="#ff3" />

  <ellipse
    cx="230"
    cy="200"
    rx="75"
    ry="75"
    fill="#a0a" />
  <ellipse
    cx="560"
    cy="200"
    rx="75"
    ry="75"
    fill="#a0a" />
</svg>
```

有了这些基本形状，我们现在将继续绘制更复杂的形状。现在不仅仅是按照几个预定义的点和长度进行绘制，我们可以选择在我们将要绘制的形状中准确放置每个点。虽然这使得手工绘制形状稍微困难，但也使得可能性更加广泛。

绘制一条线既简单又快速。只需在 SVG 坐标空间内指定两个点，就可以得到一条线。每个点由一个枚举的（x，y）对指定。

```js
<svg  version="1.1" width="1000" height="1000">
  <line
    x1="50"
    y1="50"
    x2="300"
    y2="500"
    stroke-width="50"
    stroke="#c00" />
</svg>
```

接下来我们将介绍折线，它是常规线的扩展。线和折线之间的区别在于，正如其名称所示，折线是一组线的集合。而常规线只接受两个坐标点，折线接受两个或更多点，并按顺序连接它们。此外，如果我们为折线指定了填充颜色，最后一个点将连接到第一个点，并且由该封闭区域形成的形状将应用填充。显然，如果没有指定填充，折线将呈现为由直线组成的简单形状。

```js
<svg  version="1.1" width="1000" height="1000">
  <polyline
    points="50, 10, 100, 50, 30, 100, 175, 300, 250, 10, 10, 400"
    fill="#fff"
    stroke="#c00"
    stroke-width="10"/>
</svg>
```

我们将要看的下一个形状是多边形。与折线非常相似，多边形的绘制方式与折线完全相同，但有两个非常重要的区别。首先，多边形必须至少有三个点。其次，多边形总是一个封闭的形状。这意味着序列的最后一个点和第一个点在物理上是连接的，而在折线中，只有通过填充才会进行连接，如果为折线分配了填充的话：

```js
<svg  version="1.1" width="1000" height="1000">
    <polygon
        points="50, 10, 100, 50, 30, 100, 175, 300, 250, 10, 10, 400"
        fill="#fff"
        stroke="#c00"
        stroke-width="10"/>
</svg>
```

![如何使用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_04_03.jpg)

在前面的屏幕截图的左侧显示了折线，而右侧的形状是使用完全相同的点来描述其位置和方向的多边形。两者之间唯一的区别是多边形是强制闭合的。当然，我们也可以通过简单地手动连接最后一个点和第一个点来模拟这种行为，使用折线。

SVG 还允许我们使用平滑曲线来绘制非常复杂的形状，而不是之前介绍的基于线的形状。为此，我们可以使用路径元素，起初可能有点复杂，因为它有几个不同的属性可以操作。路径的一个关键特点是它允许我们将指针移动到坐标空间内的位置，或者画一条线到一个点。

描述路径的所有路径属性都放在`d`属性中。这些属性如下：

+   **M**：移动到

+   **L**：线到

+   **H**：水平线到

+   **V**：垂直线到

+   **C**：曲线到

+   **S**：平滑曲线到

+   **Q**：二次贝塞尔曲线

+   **T**：平滑二次贝塞尔曲线

+   **A**：椭圆弧

+   **Z**：关闭路径

这些属性可以根据需要重复多次，尽管将整体绘图分解为多个较小的路径可能是个好主意。将较大的绘图分成多个路径的一些原因是使图形更易管理，更易于故障排除和更易于理解。代码如下：

```js
<svg  version="1.1" width="1000" height="1000">
  <path
    d="M 100 100
    L 100 300
    M 250 100
    L 250 300
    M 400 100
    L 400 300"
    fill="transparent"
    stroke-width="45"
    stroke="#333" />
</svg>
```

除非你练习并训练自己查看路径描述，否则很难仅凭这些代码来可视化路径。花点时间，逐个查看每个属性。前面的示例首先将指针移动到点(100, 100)，然后从该点画一条线到另一个点(100, 300)。这样就从指针上次位置到由线条指定的点画了一条垂直线。接下来，光标从原来的位置改变到一个新位置(250, 100)。请注意，简单地移动光标不会影响任何以前的绘图调用，也不会在那时进行任何绘图。最后，画了第二条垂直线到点(250, 300)。第三条线与第一条线的距离相等。这可以在以下截图中看到：

![如何使用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_04_04.jpg)

请注意，我们为填充、描边、描边宽度等定义的任何值都将应用于整个路径。想要不同的填充和描边值的解决方案是创建额外的路径。

绘制曲线仍然有点复杂。曲线需要三个值，即两个控制点和最终绘制线的点。为了说明控制点的工作原理，请观察以下示例：

```js
<svg  version="1.1" width="1000" height="1000">
  <path
    d="M 250 100
    L 250 300
    M 400 100
    L 400 300"
    fill="transparent"
    stroke-width="45"
    stroke="#333" />
  <path
    d="M 150 300
    C 200 500,
    450 500,
    500 300"

    fill="transparent"
    stroke-width="45"
    stroke="#333" />

  <circle
    cx="150"
    cy="300"
    r="8"
    fill="#c00" />
  <circle
    cx="200"
    cy="500"
    r="8"
    fill="#c00" />
  <line
    x1="150"
    y1="300"
    x2="200"
    y2="500"
    stroke-width="5"
    stroke="#c00" />

  <circle
    cx="450"
    cy="500"
    r="8"
    fill="#c00" />
  <circle
    cx="500"
    cy="300"
    r="8"
    fill="#c00" />
  <line
    x1="450"
    y1="500"
    x2="500"
    y2="300"
    stroke-width="5"
    stroke="#c00" />
</svg>
```

在执行上述代码时，如下截图所示，我们可以看到控制点与线的曲率之间的关系：

![如何使用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_04_05.jpg)

这是一个三次贝塞尔曲线，红线显示了第一个和最后一个曲线点与控制点连接的位置。

手动绘制所需的曲线正是一个相当复杂的问题。不同的曲线函数之间的行为不同，因此一定要尝试它们，直到你对它们的工作方式有了很好的感觉。请记住，尽管至少要有一些了解这些曲线和其他绘图原语的工作方式是个好主意，但强烈建议您始终使用适当的软件来帮助您创建您的绘图。理想情况下，我们会利用我们的创造力来创建绘图，让计算机来找出如何使用 SVG 表示它。

### 注意

路径的描述属性可以使用小写字母或大写字母来指定。区别在于大写字母表示点是绝对的，小写字母表示点是相对的。相对和绝对点的概念与 HTML 中的不完全相同，其中相对偏移意味着目标点相对于其自身原始位置的相对位置，而绝对点是完全相对于元素的父级的位置。

在 SVG 世界中，绝对点是相对于画布的原点，而相对点是相对于上次定义的点。例如，如果将指针移动到位置(10, 10)，然后使用值为 10 15 进行相对移动，指针将最终停在位置(10, 15)而不是位置(10, 15)，而是在 x 位置上离开 10 个单位，在 y 位置上离开 15 个单位。然后指针的新位置将是位置(20, 25)。

最后，SVG 能够将文本呈现到屏幕上。想象一下，如果要使用线条和路径手动渲染每个字母会耗费多少时间。幸运的是，SVG API 规定了一个非常简单的文本呈现接口。

```js
<svg  version="1.1" width="1000" height="1000">
  <text
    x="100"
    y="300"
    fill="#c00"
    stroke="#333"
    stroke-width="2"
    style="font-size: 175px">I Love HTML5!</text>
</svg>
```

现在，SVG 标准不仅仅是定义形状、线条、路径和颜色。规范还定义了元素组，可以将一组节点组合在一起，使它们可能作为一个单一单元一起处理。还有变换、动画、渐变，甚至是照片滤镜，所有这些都可以应用于之前描述的简单基元。看一下下面的代码：

```js
<svg  version="1.1" width="1000" height="1000">
  <rect
    x="500"
    y="500"
    width="900"
    height="600"
    fill="#c00"
    stroke="#333"
    stroke-width="2"
    transform="translate(800, 50)
      rotate(55, 0, 0)
      scale(0.25)">

    <animate
      dur="1.5s"
      attributeName="x"
      values="-50; 100; -50"
      repeatCount="indefinite" />

    <animate
      dur="1.5s"
      attributeName="height"
      values="50; 300; 50"
      repeatCount="indefinite" />
  </rect>
</svg>
```

# 拖放

尽管手动创建拖放功能并不是一个非常具有挑战性的任务，但 HTML5 将拖放提升到了一个全新的水平。通过新的 API，我们可以做的远不止让浏览器处理拖放操作。该接口允许自定义拖动的方式，拖动动作的外观，可拖动对象携带的数据等等。此外，不必担心在不同平台和设备上跟踪低级事件的方式是一个不错的、受欢迎的功能。

对于好奇的读者来说，我们可以实现自己的拖放行为的方式实际上非常简单；首先，我们监听要拖动的元素上的鼠标按下事件。当这种情况发生时，我们设置一个鼠标按下标志，一旦鼠标抬起事件被触发，无论是在我们希望拖动的元素上还是其他地方，我们就取消这个标志。接下来，我们监听鼠标移动事件，检查鼠标是否按下。如果鼠标在鼠标按下标志被设置的情况下移动，我们就有了一个拖动动作。处理它的一种方式是每次鼠标移动时更新可拖动元素的位置，然后在鼠标抬起事件被调用时设置元素的位置。当然，还有一些小细节我们需要跟踪，或者至少要注意，比如如何检测可拖动元素被放置的位置，以及如何在需要时将其移回原来的位置。

好消息是，浏览器提供的拖放 API 非常灵活和高效。自从这个功能首次引入以来，许多开发人员继续使用 JavaScript 实现它，原因有很多，但主要是因为很多人觉得原生的 HTML5 版本使用起来有点困难、有 bug，或者不如他们选择使用的其他库提供的版本实用。然而，如今这个 API 得到了广泛支持，相当成熟，并且深受推荐。

## 如何使用它

现在，拖放 API 的工作方式非常直接。首先，我们需要通过将`draggable`属性设置为 true 来标记一个或多个元素为可拖动，如下面的代码所示：

```js
<ul>
  <li draggable="true" class="block"
    ondragstart="doOnDragStart(event)"
    data-name="Block 1">Block #1</li>
</ul>
```

仅仅这一步就可以使这些元素都可拖动。当然，除非我们有一个放置这些元素的地方，否则这没有任何用处。信不信由你，我们实际上可以在任何地方放置一个被拖动的元素。问题在于，我们没有任何代码来处理放置元素的事件。我们可以在任何元素上注册这样的事件，包括 body 标签，例如。下面的代码中展示了这一点：

```js
document.body.ondragover = doOnDragOver;
document.body.ondragleave = doOnDragLeave;
document.body.ondrop = doOnDrop;

function doOnDragOver(event) {
  event.preventDefault();
  document.body.classList.add("dropme");
}

function doOnDragLeave(event) {
  event.preventDefault();
  document.body.classList.remove("dropme");
}

function doOnDrop(event) {
  event.preventDefault();
  document.body.classList.remove("dropme");
  var newItem = document.createElement("li");
  newItem.setAttribute("draggable", true);
  newItem.classList.add("block");

  document.querySelector("ul").appendChild(newItem);
}
```

在这个例子中，每当一个列表元素在页面的任何地方被放置时，我们都会向无序列表追加一个新的列表元素，因为页面上的每个元素都是 body 节点的子元素。此外，每当可拖动的元素悬停在 body 元素上时，我们会添加一个名为`dropme`的 CSS 类，这是为了给用户提供一个视觉反馈，让他们知道拖动事件正在发生。当可拖动的元素被放置时，我们会从 body 元素中移除该类，表示拖动动作的结束。

使用拖放 API 的一种方法是在对象之间传输数据。这些数据可以是字符串，或者可以转换为字符串的任何数据类型。我们可以通过在拖动操作期间设置`dataTransfer`对象来实现这一点。数据必须在系统触发拖动开始函数时设置。与`dataTransfer`数据相关联的键可以是我们选择的任何字符串，如下面的代码所示。

```js
function doOnDragStart(event) {
    // First we set the data when the drag event first starts
 event.dataTransfer.setData("who-built-me", event.target.getAttribute("data-name"));
}

function doOnDrop(event) {
    event.preventDefault();
    document.body.classList.remove("dropme");

    var num = document.querySelectorAll("li").length + 1;

    // Then we retrieve that data when the drop event is fired by the browser
 var builtBy = event.dataTransfer.getData("who-built-me");

    var newItem = document.createElement("li");
    newItem.ondragstart = doOnDragStart;
    newItem.setAttribute("draggable", true);
    newItem.setAttribute("data-name", "Block " + num);
    newItem.innerText = "Block #" + num + ", built by " + builtBy;

    newItem.classList.add("block");

    document.querySelector("ul").appendChild(newItem);
}
```

# 总结

本章涉及了浏览器支持和代码可移植性这个非常重要的话题。作为高效的开发者，我们应该始终努力创建可维护的代码。因此，我们支持的浏览器越多，我们就越高效。为了帮助我们实现这个目标，我们可以创建封装了从浏览器到浏览器，从设备到设备都有所不同的代码的抽象。另一个选择是使用其他人编写的现有 polyfill，从而以可能更少的工作量和更可靠地实现相同的功能。

我们在本章构建的游戏利用了三个 HTML5 API，即拖放、Web 音频和 SVG。HTML5 提供的本机拖放远不止是在屏幕上拖动 DOM 元素。通过它，我们可以定制与拖放操作相关的许多可视元素，以及指定通过可拖动元素和放置目标携带的数据。

Web 音频允许我们管理多个音频实体。虽然大多数现代浏览器支持多种音频格式，但目前还没有一种音频格式被所有这些现代 Web 浏览器支持。因此，建议我们通过 API 链接每个音频文件的至少两种不同版本，以便所有现代浏览器都能播放该文件。虽然我们可以为每个音频元素指定多个来源（其中每个来源是相同文件的不同版本，但以不同格式编码），但浏览器足够智能，只下载它支持和知道如何播放的文件，或者对它来说最合适的文件。这样可以缩短加载时间，节省用户和服务器的带宽。

可伸缩矢量图形是一种基于 XML 的二维图形描述语言，可以以多种方式嵌入到网页中。由于所有的图形元素都不过是由浏览器渲染到 SVG 画布上的 XML 节点，每个图形元素都由浏览器管理，因此可以通过 CSS 进行样式设置，并且可以与用户输入事件相关联。我们还可以为由浏览器生成的事件（比如元素加载、聚焦、失焦等）注册回调函数。

最后，我们看到 JavaScript 提供的定时器函数都不适合快速游戏。幸运的是，有一个新的渲染 API，我们将在下一章中介绍，可以用来克服 JavaScript 定时器的不足。使用请求动画帧接口可以让我们更有效地渲染游戏，因为浏览器本身管理所使用的定时器，并且可以使我们的游戏更加 CPU 友好，不会渲染不可见的屏幕（比如当浏览器最小化或者焦点在不同的标签页上时）。

在下一章中，我们将编写一个传统的贪吃蛇游戏，主要关注点是使用 Canvas API 渲染整个游戏场景（而不是使用原始 DOM 元素），应用程序缓存以进行离线游戏，Web Workers 以及新而强大的 JavaScript 类型数组。正如本章前面提到的，我们还将看一下在 HTML5 应用程序中以新的方式渲染非常动态的图形，使用 requestAnimationFrame 来访问浏览器自己的渲染管道。


# 第四章：使用 HTML5 捕捉蛇

这一章是一个两部分系列的第一部分，在这里我们将构建游戏的第一个版本，然后在下一章中使用更多的 HTML5 API 来增加趣味性。两个版本都是完整可玩的，但是在同一章节中涵盖所有 API 会使章节变得非常庞大，因此我们将事情分解成更小的块，并编写两个单独的游戏。

游戏的第一个版本将涵盖五个新概念，即**HTML5 的 2D 画布 API**，**离线应用缓存**，**Web Workers**，**类型数组**和**requestAnimationFrame**。画布元素允许我们绘制 2D 和 3D 图形，并以非常低的级别操作图像数据，获得对单个像素信息的访问。离线应用缓存，也称为应用缓存，允许我们将特定资产从服务器缓存到用户的浏览器中，以便应用程序即使在没有互联网访问时也能工作。Web Workers 是一种类似线程的机制，允许我们在与主 UI 线程分离的单独线程中执行 JavaScript 代码。这样，用户界面永远不会被阻塞，用户也不会看到**页面无响应**的警告。`Typed arrays`是一种新的本机 JavaScript 数据类型，类似于数组，但效率更高，专门设计用于处理二进制数据。最后，requestAnimationFrame 是浏览器提供的一个 API，帮助我们执行基于时间的动画。我们可以让浏览器进行繁重的工作，优化动画，超出我们在 JavaScript 中单独实现的范围，而不是多次每秒使用 JavaScript 计时器（`setTimeout`或`setInterval`）来执行动画。

# 游戏

你肯定以前见过或玩过这个游戏。你在一个 2D 网格中控制一条蛇，只能向上、下、左或右移动。当你改变蛇头移动的方向时，蛇身的每一部分都会逐渐改变方向，跟随着头部。如果你撞到墙壁或蛇的身体，你就输了。如果你引导蛇头经过一个水果，蛇的身体就会变大。蛇变得越大，游戏就越具挑战性。此外，蛇移动的速度可以增加，增加额外的挑战。为了保持这个经典游戏的老派特性，我们选择了老派的图形和字体，如下面的截图所示：

![游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_01.jpg)

图像显示了游戏的外观和感觉。游戏刚开始时，蛇的总体长度为零——只有头部存在。一开始，蛇会随机放置在游戏网格的某个位置，并且没有给予一个初始移动方向。玩家可以用箭头键控制蛇，一旦蛇开始朝特定方向移动，就无法停止。例如，如果蛇向右移动，玩家可以将其向上或向下移动（但不能向后）。如果玩家希望将蛇向左移动（当它当前向右移动时），唯一可能的方法是先将蛇向上移动，然后向左移动，或者向下移动，然后向左移动。

每当游戏网格上没有水果时，会随机添加一个水果到网格中。该水果会一直留在那里，直到玩家吃掉它，此时会在网格中添加一个新的水果。为增加难度，如果蛇在几秒内无法到达水果，我们可以让水果消失。

## API 使用

游戏中使用的每个 API 的一般描述和演示如下。要了解每个功能是如何整合到最终游戏中的，请查看以下代码部分。有关此游戏的完整源代码，请查看 Packt Publishing 网站上的书页。

在引入`requestAnimationFrame`之前，开发人员在 JavaScript 中创建动画的主要方法是使用定时器重复调用一个逐渐更新正在动画的元素的属性的函数。虽然这是一种简单直接的方法，但浏览器通过`requestAnimationFrame`提供的一些额外好处。首先，浏览器使用单个动画周期来处理页面的渲染，因此我们使用相同的周期进行的任何渲染都将导致更平滑的动画，因为浏览器可以为我们优化动画。此外，由于渲染将由浏览器的内部渲染机制完成，我们的动画在运行我们的动画的浏览器选项卡未显示时不会运行。这样我们就不会浪费电池寿命来动画显示不可见的内容。

## 如何使用

使用`requestAnimationFrame`非常简单，类似于`setTimeout`。我们在全局窗口对象上调用`requestAnimationFrame`函数，传递一个回调函数，该函数在浏览器准备好再次运行动画周期时执行。当调用回调函数时，会传递一个时间戳，通常在我们使用`requestAnimationFrame`注册的动画函数内部使用。

`requestAnimationFrame`有两种常见的使用方式，两种方式都能实现相同的结果。在第一种方法中，您定义动画函数时不引用`requestAnimationFrame`。然后，第二个函数调用该动画函数，然后调用`requestAnimationFrame`。

```js
function myAnimationLoop(time) {
   // 1\. Perform the animation
   myAnimation(time);

   // 2\. Register with request animation frame
   requestAnimationFrame(myAnimationLoop);
}

function myAnimation(time) {
   // Perform animation here
}
```

常用的第二种模式非常相似，只包括主要的动画函数。该函数本身负责在需要时调用`requestAnimationFrame`。

```js
function myAnimation(time) {
   // 1\. Perform the animation
   myAnimation(time);

   // 2\. Register with request animation frame
   requestAnimationFrame(myAnimationLoop);
}
```

时间参数有用的原因是，因为大多数情况下，您希望动画在不同的计算机上以更多或更少相同的速度运行。`requestAnimationFrame`尝试以尽可能接近每秒 60 次的速度运行。但是，根据您在其中执行的代码，该速率可能会显著下降。显然，更快的硬件能够更快地执行您的代码，并因此比一些较慢的硬件更频繁地显示在屏幕上。为了弥补这种可能性，我们可以使用实际时间来控制动画代码运行的频率。这样，我们可以指定一个刷新率上限，如果特定计算机能够以比这个速率更快的速度运行，可以简单地减慢该计算机的速度，所有用户都能体验到大致相同的动画。

这种技术的一种可能实现如下所示。虽然这可能看起来像是很多步骤，但概念实际上非常简单。其要点是：我们设置两个变量，一个用于跟踪动画运行的速度上限（以**每秒帧数**（**fps**）为单位），另一个用于跟踪上次渲染帧的时间。然后，每当动画函数执行时，我们获取当前时间，减去上次渲染帧的时间，并检查它们的差是否大于或等于我们选择的理想 fps。如果小于我们期望的 fps，我们不会进行任何动画，但仍会注册`requestAnimationFrame`在未来回调我们。

我们这样做直到经过足够的时间，以便我们可以实现每秒帧数（换句话说，我们可能运行的最快帧速率就是我们的 fps）。如果系统运行速度比这慢，我们无能为力。这种技术的作用是控制最大速度。

一旦`requestAnimationFrame`调用了我们的动画函数，并且自上次渲染帧以来已经过了足够的时间，我们就会更新所有需要的数据，用于动画渲染到屏幕上（或者让浏览器完成，如果可以的话），并更新跟踪上次更新帧的变量。

```js
// 1\. Create some element
var el = document.createElement("h1");
el.textContent = "I Love HTML5!";
el.style.position = "absolute";

// 2\. Attach it to the document
document.body.appendChild(el);

// 3\. Set some variables to control the animation
var loop = 0;
var lastFrame = 0;
var fps = 1000 / 60;

// 4\. Perform the animation one frame at a time
function slideRight(time) {

   // 5\. Control the animation to a set frames per second
   if (time - lastFrame >= fps) {

      var left = parseInt(el.style.left);

      // 6\. Perform the animation while some condition is true
      if (left + el.offsetWidth < document.body.offsetWidth) {
         el.style.left = (left + loop) + "px";
         loop += 5;

         // 7\. Perform the time control variable
         lastFrame = time;
      } else {

         // 8\. If the animation is done, return from this function
         el.style.left = document.body.offsetWidth - el.offsetWidth;
         return true;
      }
   }

   // 9\. If the animation is not done yet, do it again
   requestAnimationFrame(slideRight);
}

// 10\. Register some event to begin the animation
el.addEventListener("click", function(){
   el.style.left = 0;
   loop = 0;
   slideRight(0);
});
```

这个简单的代码片段创建了一个**文档对象模型**（**DOM**）元素，为其设置一些文本，并为其注册了一个点击处理程序。当调用点击处理程序时，我们重置元素的一些样式属性（即将元素放在屏幕的最左侧），并启动动画例程。动画例程每帧将元素向右移动一点，直到元素到达屏幕的右侧。如果元素尚未到达屏幕的右侧，或者换句话说，如果动画尚未完成，我们执行动画（移动元素几个像素），然后将其自身注册到`requestAnimationFrame`，从而继续循环。一旦动画完成，我们就简单地停止调用`requestAnimationFrame`。

记住的一个关键点是，浏览器使用`requestAnimationFrame`的主要优化之一是只在有东西需要渲染时调用它（换句话说，当包含页面的选项卡相对于其他选项卡处于活动状态时）。因此，如果用户在动画进行中切换选项卡，动画将暂停，直到再次选择该选项卡。

换句话说，我们应该让`requestAnimationFrame`调用处理游戏渲染的代码，而不是更新游戏状态的代码。这样，即使浏览器没有渲染，与动画相关的值仍会被动画化，但我们不会浪费 CPU 和 GPU 的功率，渲染看不见的东西。但是一旦浏览器选项卡再次变为活动状态，最新的数据状态将被渲染，就好像它一直在渲染一样。

这种技术对游戏特别有用，因为我们可能不希望用户切换浏览器选项卡时整个游戏都暂停。另一方面，我们总是可以通过在不需要时不向屏幕渲染数据来节省用户的电池。

### 注意

请记住，`requestAnimationFrame`将按定义将动画循环的帧速率限制为显示器的刷新速率。因此，`requestAnimationFrame`并不打算替代本机定时器实现，特别是在我们希望回调函数以与显示器刷新速率独立且可能更高的速率被调用的情况下。

# 类型化数组

多年来，JavaScript 引擎的速度变得惊人地快。然而，仅仅能够更快地处理数据并不一定等同于能够做更强大的事情。以 WebGL 为例。仅仅因为浏览器现在具有理解 OpenGL ES 的能力，并不一定意味着它具有我们开发人员需要利用的所有工具。

好消息是，JavaScript 语言也在一些方面取得了进展，以满足这一需求和其他需求。近年来 JavaScript 的一个新增内容是一种新的数据类型：类型化数组。一般来说，类型化数组提供了与 JavaScript 中已有的数组类型类似的结构。然而，这些新数组更加高效，并且是针对二进制数据设计的。

你问为什么和如何类型化数组比普通数组更高效？好吧，让我们看一个简单的例子，我们只是以旧的方式遍历一个整数数组。尽管大多数 JavaScript 引擎并不特别困难地快速完成这项任务，但我们不要忽视引擎需要做的所有工作。

```js
var nums = [1, 2, 3, 4, 5];
for (var i = 0, len = nums.length; i < len; i++) {
   // ...
}
```

由于 JavaScript 不是强类型的，数组`nums`不受限于保存任何特定类型的数据。此外，`nums`数组可以为其中的每个元素存储不同的数据类型。虽然这对程序员来说有时可能很方便，但 JavaScript 引擎需要弄清楚每个元素存储在哪里，以及存储在该位置的数据类型是什么。与您可能认为的相反，在`nums`数组中的这五个元素可能不是存储在连续的内存块中，因为 JavaScript 就是这样做的。

另一方面，使用类型化数组，数组中的每个元素只能是`整数`或`浮点数`。根据我们选择的数组类型，我们可以有不同类型的`整数`或`浮点数`（`有符号`，`无符号`，8、16 或 32 位），但数组中的每个元素始终是我们决定使用的相同数据类型（整数或浮点数）。这样，浏览器就可以准确并立即知道`nums[3]`元素在内存中的位置，即在内存地址`nums + 3`处。这是因为类型化数组存储在连续的内存块中，就像 C 和 C++中的数组结构一样（顺便说一句，这是实现大多数，如果不是所有 JavaScript 引擎的语言）。

类型化数组的主要用例是，正如之前暗示的那样，WebGL（我们将在第六章中介绍，*为您的游戏添加功能*）。在 WebGL 中，我们可以直接从 JavaScript 执行 3D 渲染，可能需要处理超过一百万个元素的`整数`缓冲区。这些缓冲区可以用来表示我们希望绘制到屏幕上的 3D 模型。现在，想象一下浏览器需要遍历这样一个数组需要多长时间。对于每个元素，它都必须跟随一个内存位置，检查该位置的值，确保该值是一个数字，尝试将该值转换为数字，然后最终使用该值。听起来是不是很多工作？那是因为确实是。有了类型化数组，它可以以尽可能快的速度运行整个数组，知道每个元素确实是一个数字，并且确切地知道每个元素占用多少内存，因此跳转到下一个内存地址是一个一致和可预测的过程。

类型化数组也用于 2D 画布上下文。正如我们将在本章后面的画布 API 部分中看到的，我们可以从画布中绘制的任何内容中获取像素数据的方法。所有这些像素数据只是一个 8 位夹紧的`无符号整数`的长数组。这意味着该数组中的每个元素只能是介于 0 和 255 之间的`整数`值，这正是像素的可接受值。

## 如何使用它

使用类型化数组非常简单。如果您至少有一些 C 或 C++的经验，那么了解它们的工作原理可能会更容易。创建类型化数组的最简单方法是声明我们的数组变量，并为它分配特定类型的类型化数组实例。

```js
var typedArr = new Int32Array(10);
```

在这个例子中，我们创建了一个`整数`数组的实例，其中每个元素可以是正数或负数（`有符号`）。每个元素将以 32 位数字的形式存储。我们传递的`整数`参数表示数组的大小。创建了这个数组之后，它的大小就不能改变了。浏览器会悄悄地忽略分配给它的任何超出其范围的值，以及任何非法值。

除了对这种特殊数组中可以存储什么的限制之外，对于未经训练的人来说，它可能看起来就像是一个普通的 JavaScript 数组。但是，如果我们深入研究一下，我们会注意到数组和类型化数组之间还有一些区别。

```js
typedArr instanceof Int32Array; // True
typedArr.length == 10; // True

typedArr.push(23); // TypeError: <Int32Array> has no method 'push'
typedArr.pop(); // TypeError: <Int32Array> has no method 'pop'
typedArr.sort(); // TypeError; <Int32Array> has no method 'sort'

typedArr.buffer instanceof ArrayBuffer; // True
typedArr.buffer.byteLength == 40; //True

typedArr instanceof Array; // False
```

我们注意到的第一件事是，数组确实是一个`Int32Array`，而不是一个数组。接下来，我们很高兴地知道`length`属性仍然存在。到目前为止一切顺利。然后，事情开始分开，与普通数组相关的简单方法不再存在。不仅如此，类型化数组对象中还有一个名为`buffer`的新属性。这个缓冲区对象是`ArrayBuffer`类型，它有一个`byteLength`属性。在这种情况下，我们可以看到缓冲区的长度是`40`。很容易看出这个`40`是从哪里来的：`buffer`包含 10 个元素（`typedArr.length`），每个元素都是 32 位长（4 字节），总共在`ArrayBuffer`中有`40`字节（因此属性名为`byteLength`）。

由于类型化数组没有像普通 JavaScript 数组那样的辅助函数，我们使用旧的数组表示法来读取和写入数据，其中我们通过索引进入数组以读取或写入一个值。

```js
var typedArr = new Uint32Array(3);

typedArr[] = 0; // SyntaxError

typedArr[0] = 3;
typedArr[1] = 4;
typedArr[2] = 9;

for (var i = 0, len = typedArr.length; i < len; i++) {
   typedArr[i] >= 0; // True
}
```

再次强调一点，与普通 JavaScript 数组相关的任何辅助函数或快捷方式都不适用于类型化数组，注意，尝试在不提供索引的情况下访问元素将导致浏览器抛出异常。

### ArrayBuffer 和 ArrayBufferView

尽管所有先前的例子都直接使用了特定类型的数组，但类型化数组的工作方式要比那更复杂一些。实现被分解为两个单独的部分，即数组缓冲区和视图（或更具体地说，数组缓冲区视图）。数组缓冲区只是分配的一块内存，所以我们可以在那里存储我们的数据。关于这个缓冲区的事情是，它没有与之关联的类型，所以我们无法访问该内存来存储数据，或者从中读取数据。

为了能够使用数组缓冲区分配的内存空间，我们需要一个视图。尽管这个视图的基本类型是`ArrayBufferView`，但我们实际上需要`ArrayBufferView`的一个子类，它为数组缓冲区中存储的数据定义了一个特定的类型。

```js
var buffer = new ArrayBuffer(32);
buffer.byteLengh == 32; // True

var i32View = new Int32Array(buffer);
i32View.length == 8; // True
```

这就是事情可能变得有点混乱的地方。数组缓冲区以字节为单位工作。作为复习，一个字节由 8 位组成。一个位是一个单一的二进制数字，它可以有一个值，要么是零，要么是一。这是数据在计算机中以最基本的格式表示的方式。

现在，如果一个缓冲区以字节为单位工作，当我们在示例中创建我们的缓冲区时，我们创建了一个`32`字节的块。我们创建的视图可以是九种可能类型之一，每种类型都指定了不同的数据大小（以位而不是字节为单位）。因此，类型为`Int32`的视图表示一个每个元素都是 32 位长的`整数`的缓冲区。换句话说，32 位视图可以恰好容纳 8 个字节（1 字节=8 位；32 位=8 字节），如下面的屏幕截图所示：

![ArrayBuffer and ArrayBufferView](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_03.jpg)

数组缓冲区以字节为单位工作。在图中，有 4 个字节，尽管视图类型是以位为单位工作的。因此，如果我们使用 32 位视图，将导致一个长度恰好为一个元素的数组。如果视图使用 16 位数据类型，那么数组将有 2 个元素（4 个字节除以 16 位）。最后，如果视图使用 8 位数据类型，那么存储在 4 个字节缓冲区中的数组将有 4 个元素。

### 提示

始终要记住的一件重要的事情是，当你创建一个数组缓冲区时，你选择的长度必须完全能够被你创建的数组缓冲区视图的大小整除。如果缓冲区中没有足够的空间来容纳整个字节，JavaScript 将抛出一个`RangeError`类型的错误。

在下图中，缓冲区只足够大以容纳 8 位，所有位都必须由整个字节占用。因此，视图是一个 8 位数，恰好可以容纳一个整个元素，这是可以的。16 位元素只能容纳一半的元素，这是不可能的。32 位元素同样只能容纳一部分，这也是不允许的。

![ArrayBuffer 和 ArrayBufferView](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_04.jpg)

正如您所看到的，只要数组缓冲区的位长度是视图中使用的数据类型的位大小的倍数，事情就会很顺利。如果视图为 8 位长，则 8、16、24、32 或 40 字节的数组缓冲区都可以很好地工作。如果视图为 32 位长，则缓冲区必须至少为 4 字节长（32 位）、8 字节（64 位）、24 字节（96 位）等。然后，通过将缓冲区中的字节数除以视图表示的数据类型的字节数，我们可以计算出我们可以放入所述数组的总元素数。

```js
// 96 bytes in the buffer
var buffer = new ArrayBuffer(96);

// Each element in the buffer is 32 bits long, or 4 bytes
var view = new Int32Array(buffer);

// 96 / 4 = 24 elements in this typed array
view.length == 24;
```

## 类型化数组视图类型

总之，一个普通的数组缓冲区没有实际大小。虽然创建一个长度为 5 字节的数组缓冲区没有意义，但我们可以这样做。只有在创建了数组缓冲区后，我们才能创建一个视图来保存缓冲区。根据缓冲区的字节大小，我们可以通过选择适当的数据类型来确定数组缓冲区视图可以访问多少元素。目前，我们可以从九种数据类型中为数组缓冲区视图选择。

+   **Int8Array**：它是一个 8 位长的`有符号整数`，范围从 32,768 到 32,767

+   **Uint8Array**：它是一个 8 位长的`无符号整数`，范围从 0 到 65,535

+   **Uint8ClampedArray**：它是一个 8 位长的`无符号整数`，范围从 0 到 255

+   **Int16Array**：它是一个 16 位长的`有符号整数`，范围从 2,147,483,648 到 2,147,483,647

+   **Uint16Array**：它是一个 16 位长的`无符号整数`，范围从 0 到 4,294,967,295

+   **Int32Array**：它是一个 32 位长的`有符号整数`，范围从 9,223,372,036,854,775,808 到 9,223,372,036,854,775,807

+   **Uint32Array**：它是一个 32 位长的`无符号整数`，范围从 0 到 18,446,744,073,709,551,615

+   **Float32Array**：它是一个 32 位长的`有符号浮点数`，范围为 3.4E +/- 38（7 位数）

+   **Float64Array**：它是一个 64 位长的`有符号浮点数`，范围为 1.7E +/- 308（15 位数）

不用说，视图类型越大，缓冲区就需要越大来容纳数据。显然，创建的缓冲区越大，浏览器就需要为您设置更多的内存，无论您最终是否使用该内存。因此，我们应该始终注意我们实际可能需要多少内存，并尽量不要分配超过这个数量。如果为了表示游戏中的蛇而分配了一个 64 位长的 10,000 个元素的数组，这将是一种可怕的资源浪费，比如我们在本章中正在构建的游戏中，蛇的最大大小可能不会超过 50 个元素，每个元素的值也不会超过 10。

考虑到这些限制，我们可以计算出一个粗略但乐观的数组大小为 50，其中每个元素只需要 8 位（因为我们只需要大约 10 个唯一的值）。因此，50 个元素乘以每个一个字节，给我们一个总缓冲区大小为 50 字节。这应该足够我们的目的，而仅此缓冲区的内存消耗应该保持在 0.05 KB 左右。不错。

最后，您可能已经注意到，本节的第一部分演示了不使用显式`ArrayBuffer`构造来创建类型化数组。

```js
// Create a typed array with 4 elements, each 32 bits long
var i32viewA = new Int32Array(4);

// Create the same typed array, but using an explicit ArrayBuffer first
var buffer = new ArrayBuffer(16)
var i32viewB = new Int32Array(buffer)
```

虽然上面的两个类型化数组指向两个独立的内存位置，但在运行时它们是相同的，无法区分（除非实际的数组保存了不同的值，当然）；这里的重点是数组缓冲器视图构造函数可以接受`ArrayBuffer`，或者简单的`integer`。如果使用`ArrayBuffer`，所有上面提到的限制都适用，并且必须小心处理。如果只提供一个`integer`，浏览器将自动为您创建一个适当大小的数组缓冲器。在实践中，有时候会有少数情况和原因，您会想要手动创建一个独立的数组缓冲器。然而，值得注意的是，即使每个视图是不同的数据类型，也完全可以为同一个数组缓冲器创建多个数组缓冲器视图。请记住，由于缓冲器指向单个内存位置，因此绑定到同一个缓冲器的所有视图都共享该内存空间。

# 画布

也许没有其他 HTML5 功能像画布 API 一样强大，特别是对于 Web 平台的游戏开发。尽管我们可能已经拥有规范中的每一个功能，以及浏览器可能支持的任何即将推出的功能，但要使用 HTML 和 JavaScript 制作高质量、引人入胜、有趣的游戏几乎是不可能的。画布 API 允许我们在浏览器上创建 2D 和 3D 图形。它还允许我们操纵画布上存储的图形数据，甚至可以到像素级别。

画布图形和 SVG 图形之间的一个主要区别是，SVG 图形是基于矢量的，而画布图形始终是光栅图形，另外一个区别是画布是一个单一的 HTML 元素，其中绘制的所有内容在实际上对浏览器来说都是不存在的。因此，画布上绘制的任何实体的事件处理必须在应用程序级别进行处理。画布上有一些通用事件，我们可以观察和响应，比如点击、移动事件和键盘事件。除此之外，我们可以自由地做任何我们想做的事情。

除了在 HTML5 画布上可以进行基于形状的绘制之外，API 还有三个主要用例。我们可以创建基于精灵的 2D 游戏，完整的 3D 游戏（使用 WebGL 和画布的帮助），以及操纵照片。最后一个提到的用例：照片处理，尤其有趣。API 有一个非常方便的函数，不仅允许我们将画布中的数据导出为 PNG 或 JPG 图像，而且还支持各种类型的压缩。这意味着我们可以在画布上绘制，加载图形（例如照片），以像素级别操纵数据（例如应用类似 Photoshop 的滤镜），旋转、拉伸、缩放，或者以其他方式玩弄数据。然后，API 允许我们将这些数据导出为一个可以保存到文件系统的压缩文件。

对于本书的目的，我们将重点关注画布 API 的方面，这些方面对游戏开发最有用。尽管 WebGL 是画布元素的一个非常令人兴奋的方面，但我们将在第六章中简要介绍它，*为您的游戏添加功能*。对于画布 API 上其他可用的功能，我们将在下一节中简要介绍并举例说明。

## 如何使用它

我们需要了解关于画布元素的第一件事是，它有两个部分。一个是物理画布元素，另一个是我们可以通过它绘制到画布的渲染上下文。截至目前，我们可以在现代浏览器中使用两个渲染上下文，即`CanvasRenderingContext2D`和`WebGLRenderingContext`。

要获取画布的渲染上下文的引用，我们需要在画布元素本身上调用一个`factory`方法。

```js
var canvasA = document.createElement("canvas");
var ctx2d = canvas.getContext("2d");
ctx2d instanceof CanvasRenderingContext2D; // True

var canvasB = document.createElement("canvas");
var ctx3d = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
ctx3d instanceof WebGLRenderingContext; // True
```

请注意，使用备用上下文是针对带有前缀的`experimentalwebgl`上下文。截至目前，大多数支持 WebGL 的浏览器都会通过实验标签来支持它。

本节的其余部分将专门涉及`CanvasRenderingContext2D` API。虽然从技术上讲，可以使用 WebGL 的 3D 画布上下文来完成 2D 画布上下文可以做的一切，但这两个 API 共同之处仅在于它们与 HTML5 画布元素的关联。WebGL 本身就是一种完整的编程语言，单独的一章是远远不够的。

现在，2D 渲染上下文的一个非常重要的方面是它的坐标空间。与大多数计算机坐标系统类似，原点位于画布的左上角。水平轴向右增加，垂直轴向下增加。用于表示画布的内存中的网格大小由生成渲染上下文的画布的物理大小决定，而不是画布的样式大小。这是一个无法过分强调的关键原则。默认情况下，画布是 300 x 150 像素。即使我们通过**层叠样式表**（**CSS**）调整了画布的大小，它生成的渲染上下文仍然是那个大小（除非我们物理调整了画布的大小）。一旦渲染上下文被创建，它就无法调整大小。

```js
<style>
canvas {
   border: 3px solid #ddd;
   width: 500px;
   height: 300px;
}
</style>

<script>
   var canvas = document.createElement("canvas");
   var ctx = canvas.getContext("2d");

   document.body.appendChild(canvas);

   alert(ctx.canvas.width);
</script>
```

![如何使用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_05.jpg)

边框是为了使画布对我们有些可见，因为默认情况下，画布是透明的。

您将观察到 CSS 规则确实应用于画布元素，即使画布的实际大小仍然是默认的 300 x 150 像素。如果我们在画布中间画一个圆，圆看起来会变形，因为应用于画布的样式会拉伸实际绘制圆的坐标空间。

### clearRect

我们将要查看的第一个绘图函数是`clearRect`。这个函数所做的就是清除画布的一个矩形区域。这个函数是在上下文对象上调用的，就像我们将在 2D 画布上进行的所有绘图调用一样。它所需要的四个参数依次代表了从画布原点的 x 和 y 偏移量，以及要清除的宽度和高度距离。请记住，与其他流行的绘图 API 不同，最后两个参数不是从原点开始测量的——它们是从由前两个参数指定的点的位移距离。

```js
var canvas = document.querySelector("canvas");
var ctx = canvas.getContext("2d");

// Clear the entire canvas
ctx.clearRect(0, 0, canvas.width, canvas.height);

// Only clear the half inside area of the canvas
ctx.clearRect(canvas.width * 0.25, canvas.height * 0.25,
   canvas.width * 0.5, canvas.height * 0.5);

// Clear a square 100x100 at the lower right bottom of the canvas
ctx.clearRect(canvas.width - 100, canvas.height - 100, 100, 100);
```

通常，当每秒渲染许多帧时，我们会在绘制下一帧之前调用此函数来清除整个画布。幸运的是，在大多数 JavaScript 引擎中，这个函数的性能表现相当不错；因此，我们不需要过多担心定期优化要清除的精确区域。

### 填充和描边

在绘制诸如线条、路径、文本和其他形状等本机对象时，我们将处理描边和填充的概念；就像在 SVG 中一样，描边是指原始图形的轮廓（如边框或类似物），而填充是覆盖形状内部的内容。

我们可以通过将任何颜色分配给`fillStyle`或`strokeStyle`属性来更改用于填充形状的颜色，或者用于描边形状的颜色。颜色可以是任何有效的 CSS 颜色字符串。

```js
// Short hand hex colors are fine
ctx.fillStyle = "#c00";
ctx.fillRect(0, 0, canvas.width, canvas.height);

// Keyword colors are fine, though not as precise
ctx.strokeStyle = "white";

ctx.lineWidth = 10;
ctx.strokeRect(25, 25, 100, 100);
ctx.strokeRect(175, 25, 100, 100);

// Alpha transparency is also allowed
ctx.fillStyle = "rgba(100, 255, 100, 0.8)";

ctx.fillRect(5, 50, canvas.width - 10, 50);
```

![填充和描边](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_06.jpg)

任何有效的 CSS 颜色字符串都可以分配给 2D 渲染上下文中的颜色属性，包括带有不透明度的颜色。

### 注意

特别注意渲染上下文的行为很像一个状态机。一旦设置了填充或描边样式，以及任何其他属性，该属性将保持该值，直到您更改它。

另外，请注意，您发出的每个后续绘图调用都会绘制在画布上已有的内容之上。因此，我们可以通过仔细安排绘图调用的顺序来分层形状和图像。

### 线条

绘制线条就像调用`lineTo`函数一样简单，它只接受两个参数，表示线条的终点。对`lineTo`的后续调用将绘制一条线到函数调用指定的点，从上一次绘制线条的地方开始。更具体地说，线条从当前绘制指针的位置开始。

默认情况下，指针没有定义在任何地方，因此将线条绘制到其他点几乎没有意义。为了解决这个问题，我们可以使用`moveTo`函数，它可以移动绘制指针而不绘制任何东西。

最后，对`lineTo`的任何调用只是在内存中设置点。为了最终绘制线条，我们需要快速调用 stroke 函数。一旦进行了这个调用，当前设置的任何属性（如线宽和描边样式）都会被绘制。因此，在实际描边线条之前更改线条属性没有什么好处，而且可能会对性能产生负面影响。

```js
ctx.fillStyle = "#fff";
ctx.fillRect(0, 0, canvas.width, canvas.height);

// This call is completely useless
ctx.strokeStyle = "#c0c";
ctx.lineWidth = 5;

ctx.moveTo(0, 0);
ctx.lineTo(100, 100);
ctx.lineTo(canvas.width, 0);

// This call is also useless because the line hasn't been drawn yet
ctx.strokeStyle = "#ca0";
ctx.moveTo(10, canvas.height - 10);
ctx.lineTo(canvas.width - 10, canvas.height * 0.5);

// This color is applied to every line drawn so far
ctx.strokeStyle = "#f5a";

// The line is finally drawn here
ctx.stroke();
```

![线条](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_07.jpg)

形状只有在调用`stroke()`之后才会被绘制，此时会使用当前的样式属性。

### 形状

我们可以非常轻松地绘制几种不同的形状。这些是矩形和圆。虽然没有像绘制矩形的`rect`函数那样的圆函数。但是，有一个`arc`函数，我们可以从中绘制圆。

`rect`函数接受四个参数，与`fillRect`完全相同。`arc`接受一个 x 和一个 y 坐标，然后是半径、起始角度（以弧度而不是度数表示）、结束角度和一个布尔值，指定弧是顺时针绘制还是逆时针绘制。要绘制一个圆，我们可以绘制一个从 0 到 PI 乘以 2 的弧，这与 360 度相同。

```js
ctx.fillStyle = "#fff";
ctx.strokeStyle = "#c0c";

ctx.fillRect(0, 0, canvas.width, canvas.height);

ctx.rect(10, 10, 50, 50);
ctx.rect(75, 50, 50, 50);

ctx.moveTo(180, 100);
ctx.arc(180, 100, 30, 1, 3, true);

ctx.moveTo(225, 40);
ctx.arc(225, 40, 20, 0, Math.PI * 2, false);

ctx.stroke();
```

![形状](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_08.jpg)

弧（包括圆）是从它们的中心绘制的，而不是从轮廓上的某一点开始。

### 文本

在 HTML5 画布上绘制文本也非常简单。函数`fillText`接受一个字符串（要绘制的文本），以及一个 x 和 y 坐标，文本开始绘制的位置。此外，我们可以通过设置文本样式属性字符串到字体属性来对文本进行样式设置，就像通过 CSS 对文本进行样式设置一样。

```js
ctx.fillStyle = "#fff";
ctx.fillRect(0, 0, canvas.width, canvas.height);

ctx.fillStyle = "#f00";
ctx.font = "2.5em 'Times New Roman'";

ctx.fillText("I Love HTML5!", 20, 75);
```

### 变换

画布 API 还定义了一些变换函数，允许我们对上下文的坐标系进行平移、缩放和旋转。在变换坐标系之后，我们可以像平常一样在画布上绘制，变换会应用到绘制上。

```js
ctx.fillStyle = "#fff";
ctx.fillRect(0, 0, canvas.width, canvas.height);

// Now the origin is at point 50x50
ctx.translate(50, 50);

ctx.fillStyle = "#f00";
ctx.fillRect(0, 0, 50, 50);
```

旋转和缩放也是一样的。`scale`函数接受一个值，用于在每个轴上缩放坐标系。`rotation`函数接受一个参数，即要将坐标系旋转的角度（以弧度表示）。

```js
ctx.fillStyle = "#fff";
ctx.fillRect(0, 0, canvas.width, canvas.height);

// With transformations, order is very important
ctx.scale(2, 1);
ctx.translate(50, 50);
ctx.rotate(0.80);
ctx.translate(10, -20);

ctx.fillStyle = "#f00";
ctx.fillRect(0, 0, 50, 50);
```

![变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_09.jpg)

在变换中，顺序非常重要。

### 绘制图像

从游戏开发的角度来看，2D 画布 API 最令人兴奋和有用的功能可能就是它能够在上面绘制图像。对我们来说，幸运的是，有几种方法可以直接在画布上绘制常规的 JPG、GIF 或 PNG 图像，包括处理从源到目标的图像缩放的函数。

关于画布元素，我们需要注意的另一点是它遵循相同的源策略。这意味着，为了能够在画布上绘制图像，尝试绘制图像的脚本必须与图像来自相同的域（以及相同的协议和端口号）。任何尝试从不同域加载图像到画布上下文的操作都会导致浏览器抛出异常。

```js
ctx.fillStyle = "#fff";
ctx.fillRect(0, 0, canvas.width, canvas.height);

var img = new Image();
img.onload = function(){
   ctx.drawImage(img, 0, 0, this.width, this.height);
};

img.src = "img/html5-logo.png";
```

绘制图像的最简单调用只需要五个参数。第一个是图像的引用。接下来的两个参数是图像将被绘制到画布上的 x 和 y 位置，最后两个参数是将图像绘制到画布上的宽度和高度。如果最后两个参数不保持原始图像的宽高比，结果将是扭曲而不是裁剪。另外，请注意，如果原始图像大于画布，或者如果图像是从偏移处绘制的，以至于图像的一部分超出了画布，那么额外的数据将不会被绘制（显然），画布将忽略视图区域外的像素：

![绘制图像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_10.jpg)

在画布渲染上绘制的 HTML5 标志。

一个非常重要的观察是，如果浏览器在调用`drawImage`时尚未完成从服务器下载图像资源，那么画布将不会绘制任何东西，因为要绘制到画布上的图像尚未加载。在使用某种游戏循环多次每秒绘制相同图像到画布的情况下，这并不是一个问题，因为图像最终加载时，游戏循环的下一次通过将成功绘制图像。然而，在只调用一次绘制图像的情况下（就像上面的例子一样），我们只有一次机会来绘制图像。因此，非常重要的是，我们不要在图像实际加载到内存并准备好绘制到画布之前进行调用。

为了确保在图像从服务器完全下载后才调用将图像绘制到画布的操作，我们可以简单地在图像的加载事件上注册一个回调函数。这样，一旦图像下载完成，浏览器就可以触发回调，最终可以调用绘制图像的操作。这样，我们可以确保在我们想要在画布中呈现图像时，图像确实已经准备好了。

还有另一个版本的相同函数，它考虑了从源到目的地的缩放。在上面的情况下，源图像大于画布。我们可以告诉画布将整个图像绘制到画布的较小区域，而不是使用照片编辑软件调整图像的大小。缩放由画布自动完成。我们还可以将图像绘制到比图像本身更大的区域，但这样做将根据我们缩放图像的程度而导致像素化。

该函数的参数是源图像，源 x 和 y 坐标（换句话说，从图像本身开始采样源图像的位置），源宽度和高度（换句话说，采样源图像的量），以及目标 x 和 y，然后是宽度和高度。

```js
ctx.fillStyle = "#fff";
ctx.fillRect(0, 0, canvas.width, canvas.height);

var img = new Image();
img.onload = function(){

   ctx.drawImage(img,
      // Sample part of the upper left corner of the source image
      35, 60, this.width / 2, this.height / 2,

      // And draw it onto the entire canvas, even if it distorts the image
      0, 0, canvas.width, canvas.height);
};

img.src = "img/html5-logo.png";
```

![绘制图像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_11.jpg)

在画布渲染上绘制的 HTML5 标志的一部分，有一些故意的拉伸。

### 操作像素

现在我们知道如何将图像绘制到画布中，让我们将事情推进一步，处理在画布中绘制的单个像素。有两个函数可以用来实现这一点。一个函数允许我们从画布上下文中检索像素数据，另一个函数允许我们将像素缓冲区放回到画布上下文中。此外，还有一个函数允许我们将像素数据作为数据 URL 检索出来，这意味着我们可以将画布中的图像数据保存到用户的文件系统中，就像我们可以使用`<img />`标签中的常规图像一样。

```js
ctx.fillStyle = "#fff";
ctx.fillRect(0, 0, canvas.width, canvas.height);

var img = new Image();
img.onload = function(){
   ctx.drawImage(img, 35, 60, this.width / 2, this.height / 2, 0, 0, canvas.width, canvas.height);

   // Extract pixel data from canvas context
   var pixels = ctx.getImageData(0, 0, canvas.width, canvas.height);

   pixels instanceof ImageData; // True
   pixels.data instanceof Uint8ClampedArray; // True
   pixels.width == canvas.width; // True
   pixels.height == canvas.height; // True

   // Insert pixel data into canvas context
   ctx.putImageData(pixels, 0, 0);
};

img.src = "img/html5-logo.png";
```

要获取表示当前在画布上绘制的内容的像素数据，我们可以使用`getImageData`函数。四个参数是源图像上的 x 和 y 偏移量，以及要提取的宽度和高度。请注意，这个函数的输出是一个`ImageData`类型的对象，它有三个属性，即宽度、高度和包含实际像素信息的类型化数组。正如本章前面提到的，这个类型化数组是`Uint8ClampedArray`类型的，其中每个元素只能是一个值在 0 到 255 之间的整数。

像素数据是一个长度为(`canvas.width x canvas.height x 4`)的缓冲区。也就是说，每四个元素代表一个像素，按照红色、绿色、蓝色和 alpha 通道的顺序表示像素。因此，为了通过这个画布 API 操纵图像，我们对这个像素缓冲区进行各种计算，然后可以使用`putImageData`函数将其放回画布。

`putImageData`的三个参数是`ImageData`对象，以及目标画布上的 x 和 y 偏移量。从那里，画布将尽可能地呈现图像数据，裁剪任何多余的数据，否则会被绘制在画布外部。

作为我们可以用图像做的一个例子，我们将取出我们在画布上绘制的 HTML5 标志，并对代表它的像素数据应用灰度函数。如果这听起来像一个复杂的任务，不用担心。虽然有几种不同的公式可以将彩色图像转换为灰度图像，但最简单的方法是简单地对每个像素的红色、绿色和蓝色值求平均值。

```js
ctx.fillStyle = "#fff";
ctx.fillRect(0, 0, canvas.width, canvas.height);

var img = new Image();
img.onload = function(){
   ctx.drawImage(img, 35, 60, this.width / 2, this.height / 2, 0, 0, canvas.width, canvas.height);

   // Extract pixel data from canvas context
   var pixels = ctx.getImageData(0, 0, canvas.width, canvas.height);

   // Iterate over every four elements, which together represent a single pixel
   for (var i = 0, len = pixels.data.length; i < len; i += 4) {
      var red = pixels.data[i];
      var green = pixels.data[i + 1];
      var blue = pixels.data[i + 2];
      var gray = (red + green + blue) / 3;

     // PS: Alpha channel can be accessed at pixels.data[i + 3]

      pixels.data[i] = gray;
      pixels.data[i + 1] = gray;
      pixels.data[i + 2] = gray;
   }

   // Insert pixel data into canvas context
   ctx.putImageData(pixels, 0, 0);
};

img.src = "img/html5-logo.png";
```

![操作像素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-h5-crt-fun-gm/img/6029OT_05_12.jpg)

操纵图像并不比对代表图像的像素缓冲区中的每个像素进行各种计算更复杂。

最后，我们可以通过调用`toDataURL`函数来从画布中导出图像。特别注意，这个函数是在画布对象上调用的，而不是在渲染上下文对象上调用的。画布对象的`toDataURL`函数接受两个可选参数，即表示输出图像的 MIME 类型的字符串，以及一个介于`0.0`和`1.0`之间的`float`，表示输出图像的质量。如果输出图像类型不是`"image/jpeg"`，则忽略质量参数。

```js
   ctx.putImageData(pixels, 0, 0);

   var imgUrl_LQ = canvas.toDataURL("image/jpeg", 0.0);
   var out = new Image();
   out.src = imgUrl_LQ;
   document.body.appendChild(out);

   var imgUrl_HQ = canvas.toDataURL("image/jpeg", 1.0);
   var out = new Image();
   out.src = imgUrl_HQ;
   document.body.appendChild(out);

   var imgUrl_raw = canvas.toDataURL("image/png");
   var out = new Image();
   out.src = imgUrl_raw;
   document.body.appendChild(out);
```

# Web workers

Web workers 带来了在主 UI 线程之外执行代码的能力。这种类似线程的行为使我们能够执行长时间的任务而不阻塞用户界面。当一个 JavaScript 任务花费太长时间来完成时，浏览器会向用户显示一个警报，让用户知道页面没有响应。使用 web workers，我们可以解决这个问题。

关于 web workers，我们需要牢记一些限制。首先，workers 在 DOM 之外运行，因此任何与 DOM 相关的功能在 worker 线程内不可用。此外，workers 没有共享内存的概念——传递给 worker 的任何数据都会被复制到它自己的内存空间中。最后，传递给和从 worker 传递的任何对象都可以包含任何数据类型，除了函数。如果尝试传递函数给 worker（或者包含对函数引用的对象），浏览器将抛出一个**DataCloneError**（DOM Exception 25）。

另一方面，workers 完全能够发起 XHR 请求（Ajax 调用），启动其他 workers，并停止其他 workers，包括它们自己。一旦 worker 被终止，它就不能再启动，类似于其他语言中可用的其他线程构造。

## 如何使用它

在这一部分，我们将创建一个示例迷你应用程序，该应用程序在一个工作线程中生成素数。用户可以在应用程序中输入一个数字，应用程序将返回一个小于该数字的素数列表。然后这些素数将被传回主应用程序，主应用程序将把素数列表返回给用户。

要开始使用 Web Workers，我们必须首先创建一个单独的 JavaScript 文件，该文件将在工作线程中运行。该脚本将通过消息与其父线程通信。为了从父线程接收消息，工作线程需要注册一个回调函数，每当有消息传递给它时就会被调用。

```js
self.addEventListener("message", getPrimes);
```

当接收到消息时，该函数在工作线程和其父线程中都会被调用，并且会传递一个`MessageEvent`对象。该对象包含许多属性，包括时间戳，最重要的是一个数据属性，其中包含传递给工作线程的任何数据。

要向工作线程或其父级发送消息，我们只需在适当的对象上调用`postMessage`函数（无论是工作对象还是在工作线程中的 self 对象），并将数据与函数调用一起传递。这些数据可以是单个值、数组或任何类型的对象，只要不包括函数。

最后，要创建一个`worker`对象，我们只需创建`Worker`类的一个实例，并将工作脚本的路径作为构造函数参数传递。这个`worker`对象将需要为它想要观察的任何事件注册回调函数：`onMessage`或`onError`。要终止工作线程，我们可以直接在工作对象上调用`terminate`函数，或者在工作脚本上调用`close`函数。

```js
// index.html
var worker = new Worker("get-primes.worker.js");

worker.addEventListener("message", function(event){
   var primes = event.data.primes;
   var ul = document.createElement("ul");

   // Parse each prime returned from the worker
   for (var i = 0, len = primes.length; i < len; i++) {
      var li = document.createElement("li");
      li.textContent = primes[i];
      ul.appendChild(li);
   }

   // Clear any existing list items
   var uls = document.querySelectorAll("ul");
   for (var i = 0, len = uls.length; i < len; i++)
      uls[i].remove();

   // Display the results
   document.body.appendChild(ul);
});

var input = document.createElement("input");
input.addEventListener("keyup", function(event){
   var key = event.which;

   // Call the worker when the Enter key is pressed
   if (key == 13 /* Enter */) {
      var input = this.value;

      // Only use input that's a positive number
      if (!isNaN(input) && input > 0) {
         worker.postMessage({max: input});
      } else if (input == -1) {
         worker.terminate();
         this.remove();
      }
   }
});

input.setAttribute("autofocus", true);
document.body.appendChild(input);
```

在上面的片段中，我们设置了两件事：一个工作线程和一个输入字段。然后我们在输入字段上设置了一个`keydown`监听器，这样用户就可以输入一个数字发送到工作线程。要将这个数字发送到工作线程，用户必须按下**Enter**键。当发生这种情况时，输入字段中的数字将是工作线程生成的最大可能的素数。如果用户输入数字`-1`，则工作线程将被终止，并且输入字段将从 DOM 中移除。

为了简单起见，工作线程将使用**埃拉托斯特尼筛法**来查找素数。请记住，这个练习只是一个概念验证，用来说明 Web Workers 的工作原理，而不是高级数学课程。

```js
// get-primes.worker.js

// Register the onMessage callback
self.addEventListener("message", getPrimes);

// This function implements the Sieve of Eratosthenes to generate the primes.
// Don't worry about the algorithm so much – focus on the Worker API
function getPrimes(event) {

   var max = event.data.max;
   var primes = [];
   var d = [];

   for (var q = 2; q < max; q++) {
      if (d[q]) {
         for (var i = 0; i < d[q].length; i++) {
            var p = d[q][i];
            if (d[p + q])
               d[p + q].push(p);
            else
               d[p + q] = [p];
         }
         delete d[q];
      } else {
         primes.push(q);
         if (q * q < max)
            d[q * q] = [q];
      }
   }

   // Return the list of primes to the parent thread
   self.postMessage({primes: primes});
}
```

如何使用它

只要工作线程没有被终止，就可以无限次地调用工作线程。一旦终止，工作线程就可以被删除，因为从那时起它就没有任何有用的目的了。

# 离线应用程序缓存

离线应用程序缓存是一种在浏览器上存储资产以供用户在未连接到互联网时使用的方法。这个 API 进一步消除了本地应用程序和 Web 应用程序之间的任何障碍，因为它消除了将 Web 应用程序与本地应用程序区分开来的主要特征——对全球网络的连接需求。尽管用户显然仍然需要在某个时候连接到网络，以便可以最初下载应用程序；之后，应用程序可以完全从用户的缓存中运行。

离线应用程序缓存的主要用例可能是当用户的连接不稳定、一致或者在每次使用应用程序时都不连接的情况。这在游戏中尤其如此，因为用户可能选择在某些时间玩某个在线游戏，但之后离线。同样，如果游戏需要连接到后端服务器，以执行任何任务（例如检索新的游戏数据），只要用户连接，资源就可以再次被缓存在本地，新数据可以在用户的连接不可用时再次使用。

## 如何使用它

离线应用程序缓存 API 的核心是清单文件，它指定了浏览器应该为离线使用缓存哪些资源，哪些资源绝对不能被缓存，以及当尝试连接到服务器但找不到连接时浏览器应该做什么。

当加载应用程序时，清单文件与用户请求的 HTML 文件一起提供。更具体地说，主机 HTML 文件指定了清单文件的路径，然后浏览器并行获取和处理主应用程序的下载和处理。这是通过根`html`标记中的`manifest`属性完成的。

```js
<!doctype html>
<html manifest="manifest.appcache">
```

请注意，上面的片段指定了一个名为`manifest.appcache`的清单文件，位于指定清单的 HTML 文件相同的目录中。文件的名称和扩展名完全是任意的。按照惯例，许多开发人员简单地将清单命名为`manifest.appcache`、`manifest`（没有扩展名）或`appcache.manifest`。但是，这个文件也可以被命名为`manifest.php?id=2642`、`my-manifest-file.txt`或`the_file.json`。

要记住的一件重要的事情是，清单文件必须以正确的 MIME 类型提供。如果浏览器尝试获取根 HTML 标记中`manifest`属性中列出的任何文件，并且 MIME 类型不是`text/cache-manifest`，那么浏览器将拒绝清单，并且不会发生离线应用程序缓存。

设置文件的 MIME 类型有很多种方法，但通常这是服务器设置。如果使用 Apache 服务器，比如我们在 WAMP、MAMP 或 LAMP 中使用的服务器（请参阅在线章节《设置环境》），我们可以通过`.htaccess`文件轻松实现这一点。例如，在我们项目的根目录中，我们可以创建一个名为`.htaccess`的文件，其中包含以下代码：

```js
AddType text/cache-manifest .appcache
```

这将告诉服务器为任何扩展名为`.appcache`的文件添加正确的 MIME 类型。当然，如果您决定调整`htaccess`文件以为其他文件扩展名提供`cache-manifest` MIME 类型，如果您选择的扩展名已经与其他 MIME 类型相关联（例如`.json`），可能会遇到问题。

清单文件的第一行必须是以下字符串：

```js
CACHE MANIFEST
```

如果这一行不存在，整个 API 将不起作用。如果在上述列出的字符串之前有多余的空格，浏览器将抛出以下错误，指示文件清单无效，并且不会被缓存：

```js
Application Cache Error event: Failed to parse manifest
```

### 注意

在游戏中使用离线应用程序缓存时，请确保密切关注浏览器的 JavaScript 控制台。如果出现任何问题，比如找不到清单文件、解析清单或加载清单中描述的任何资源，浏览器会通过引发异常来告诉您发生了错误，但它会继续执行。与大多数致命的 JavaScript 异常不同，致命的离线应用程序缓存异常不会停止或影响启动缓存过程的脚本的执行。因此，您可能会遇到应用程序缓存异常而不知道，因此熟悉浏览器支持的任何开发人员工具，并充分利用它。

清单的其余部分可以分为三个主要类别，即要缓存的资产、永远不要缓存的资产和回退资产。注释可以放置在文件的任何位置，并以井号表示。井号后的整行将被清单解析器忽略。

```js
CACHE MANIFEST

# HTML5 Snake, Version 1.0.0

CACHE:
index.html
js/next-empty.worker.js
js/renderer.class.js
js/snake.class.js
img/block-green.png
img/fruit-01.png
fonts/geo.woff
fonts/vt323.woff
css/style.css

NETWORK:
*

FALLBACK:
fallback.html
```

通过在网络部分使用通配符，我们指示任何未在缓存下指定的资源都属于网络部分，这意味着这些资源不会被缓存。在没有网络访问时尝试加载这些资源将导致加载回退文件。这是一个很好的选择，可以让用户知道需要网络访问，而无需特殊处理任何额外的代码。

一旦清单被解析并且所有资源都被缓存，所有资源将保持缓存，直到用户删除离线应用程序缓存数据（或浏览器缓存的所有数据），或者清单被更改。即使清单文件中只有一个字符发生变化，浏览器也会认为它是一个更新，因此所有资源都会被重新缓存。因此，许多开发人员在清单文件的顶部写下了一行注释，其中包括一些版本号，用于标识清单的唯一版本。这样，如果一个或多个资产发生变化，我们可以通过简单地更改清单文件中列出的版本号来强制浏览器重新缓存这些资产。请记住，浏览器只会检查清单文件中的文本，以确定是否需要下载新的资源。如果资源发生变化（比如，您更新了清单中列出的 JavaScript 代码，或者一些图形，或者任何其他资源），但清单文本没有变化，这些资源将不会从服务器上拉取，用户将继续使用应用程序中过时的资产，因为资产只从缓存中加载。

# 代码

这个游戏的布局实际上非常简单。HTML 只有三个小部件：游戏的标题，玩家当前得分的计分板，以及跨多个游戏的总高分计分板。这个最后的计分板在这个版本的游戏中没有使用，我们将在下一个游戏中更深入地讨论它（参见第五章，“改进蛇游戏”）。

```js
<h1>HTML5 Snake</h1>

<section id="scores">
   <h3>Score: <span>0</span></h3>
   <h3>High Score: <span>0</span></h3>
</section>

<section id="gameMenu" class="hide">
   <h3>Ready!</h3>
   <button>Play</button>
</section>
```

为了将游戏中所有不同组件的各种责任分开，我们将整个游戏的渲染抽象成一个单独的`Renderer`类。这个类负责向给定的`canvas`引用绘制数据。它绘制的数据，无论是蛇还是其他对象，都以类型化数组的形式传递给它，表示实体要绘制的坐标，以及在类型化数组指定的位置绘制的图像资源。 `Renderer`类还包括一些辅助函数，帮助我们轻松清除画布，并将`x`和`y`点转换为用于遍历表示 2D 数组的扁平数组的索引。

```js
var Renderer = function(canvas) {

   var canvas = canvas;
   var ctx = canvas.getContext("2d");
   var width = canvas.width;
   var height = canvas.height;

   var getIndex = function(x, y) {
      return width * y + x;
   };

   var getPosition = function(index) {
      return {
         x: index % width,
         y: parseInt(index / width)
      };
   };

   this.clear = function() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
   };

   this.draw = function(points, img) {
      for (var i = 0, len = points.length; i < len; i += 2) {
         ctx.drawImage(img, points[i] * img.width, points[i + 1] * img.height, img.width, img.height);
      }
   };
};
```

接下来，我们创建了一个`Snake`类，它封装了与蛇相关的所有数据和行为。这个类存储的数据包括蛇头的当前位置，蛇身的当前长度，代表蛇的绘制图像，以及蛇是否存活。它处理的行为包括移动蛇和处理用户输入（为简单起见，这些都包含在这个类中）。还有一些辅助函数，允许我们将其他行为委托给客户端。例如，通过公开的 API，客户端可以在每一帧检查蛇是否超出了世界网格，它是否吃了水果，或者蛇是否撞到了自己的身体。客户端还可以使用提供的 API 对蛇采取行动，比如设置它的生命属性（死或活），以及重置用于绘制蛇的图像，或者它的任何其他属性。

```js
var Snake = function(x, y, width, height, maxSize) {
   var isAlive = true;
   var size = 0;
   var body = new Int8Array(maxSize * 2);
   for (var i = 0, len = body.length; i < len; i++)
      body[i] = -1;
   body[0] = x, body[1] = y;
   var worldWidth = width;
   var worldHeight = height;
   var skin;
   var dir = { 38: false, 40: false, 37: false, 39: false };
   var keys = { UP: 38, DOWN: 40, LEFT: 37, RIGHT: 39 };
   // To move the snake, we first move each body part to where the
   // part before it used to be, starting at the tail and moving
   // towards the head. Lastly, we update the head's position
   var move = function() {
      // Traverse the snake backwards and shift each piece one spot
      for (var i = size * 2 + 1; i > 1; i -= 2) {
         body[i] = body[i - 2];
         body[i - 1] = body[i - 3];
      }
      if (dir[keys.UP]) {
         body[1]--;
      } else if (dir[keys.DOWN]) {
         body[1]++;
      } else if (dir[keys.LEFT]) {
         body[0]--;
      } else if (dir[keys.RIGHT]) {
         body[0]++;
      }
   };
   // Update the snake's position vectors on key presses
   this.doOnKeyDown = function(event) {
      var key = event.which;
      // Don't process a key that's already down
      if (dir[key])
         return;
      dir[keys.UP] = false;
      dir[keys.DOWN] = false;
      dir[keys.LEFT] = false;
      dir[keys.RIGHT] = false;
      if (key == keys.UP && !dir[keys.DOWN]) {
         return dir[keys.UP] = true;
      } else if (key === keys.DOWN && !dir[keys.UP]) {
         return dir[keys.DOWN] = true;
      } else if (key === keys.LEFT && !dir[keys.RIGHT]) {
         return dir[keys.LEFT] = true;
      } else if (key === keys.RIGHT && !dir[keys.LEFT]) {
         return dir[keys.RIGHT] = true;
      }
   };
   // This allows us to use different images to represent the snake
   this.setSkin = function(img) {
      skin = new Image();
      skin.onload = function() {
         skin.width = this.width;
         skin.height = this.height;
      };
      skin.src = img;
   };
      this.move = move;
   this.getSkin = function() { return skin; };
   this.setDead = function(isDead) { isAlive = !isDead; };
   this.isAlive = function() { return isAlive; };
   this.getBody = function() { return body; };
   this.getHead = function() { return {x: body[0], y: body[1]}; };
   this.grow = function() { if (size * 2 < body.length) return size++; };
   // Check if the snake is at a certain position on the grid
   this.isAt = function(x, y, includeHead) {
      var offset = includeHead ? 0 : 2;
      for (var i = 2, len = body.length; i < len; i += 2) {
         if (body[i] == x && body[i + 1] == y)
            return true;
      }
      return false;
   };
   this.reset = function(x, y) {
      for (var i = 0, len = body.length; i < len; i++)
         body[i] = -1;
      body[0] = x;
      body[1] = y;
      size = 0;
      isAlive = true;
      dir[keys.UP] = false;
      dir[keys.DOWN] = false;
      dir[keys.LEFT] = false;
      dir[keys.RIGHT] = false;
   };
};
```

与`snake`类类似，我们还创建了一个类来封装蛇将要吃的水果。`snake`类和`fruit`类之间唯一的区别是`fruit`类除了出现在地图上之外不会做任何其他事情。在实际目的上，`fruit`类与`snake`类共享一个公共实体接口，允许它们被重置为默认状态，设置它们的位置，并检查碰撞。

```js
var fruit = {
   position: new Int8Array(2),
   reset: function() {
      this.position[0] = -1;
      this.position[1] = -1;
   },
   isAt: function(x, y) {
      return this.position[0] == x && this.position[1] == y;
   },
   img: null
};
```

最后，在主代码中，我们执行以下设置任务：

+   创建一个 canvas 元素并将其附加到 DOM。

+   实例化`renderer`、`snake`和`fruit`对象。

+   创建一个游戏循环，在没有水果存在时在网格上放置一个水果，更新蛇的位置，检查蛇的位置，并将游戏状态渲染到画布上。

我们还使用游戏循环来连接记分牌小部件，以增强用户体验。游戏的完整源代码可在 Packt Publishing 网站上的书页上找到，还包括额外的菜单，但由于简洁起见，这些菜单已经从这里显示的代码片段中删除。

在这个游戏循环中，我们还利用了`requestAnimationFrame`API。为了确保不同的 CPU 和 GPU 以相同的速度渲染游戏，我们在游戏循环内添加了一个简单的帧速率控制器。帧速率由一个变量控制，指定游戏应该尝试以多少 fps 运行。

```js
function gameLoop() {
   // Only do anything here if the snake is not dead
   if (snake.isAlive()) {

      // Make the frame rate no faster than what we determine (30 fps)
      renderTime.now = Date.now();
      if (renderTime.now - renderTime.last >= renderTime.fps) {
         // If there is no fruit on the grid, place one somewhere. Here we
         // use a web worker to calculate an empty square on the map
         if (fruit.position[0] < 0) {
            cellGen.postMessage({
               points: snake.getBody(),
               width: worldWidth,
               height: worldHeight
            });
         } else {

            snake.move();
            head = snake.getHead();

            // Check if the snake has ran into itself, or gone outside the grid
            if (snake.isAt(head.x, head.y, false) ||
                   head.x < 0 || head.y < 0 ||
                   head.x >= worldWidth || head.y >= worldHeight) {
               snake.setDead(true);
            }

            // Check if the snake has eaten a fruit
            if (fruit.isAt(head.x, head.y)) {
               fruit.reset();
               snake.grow();
               score.up();
            }

            renderTime.last = renderTime.now;
         }
      }

      // Render everything: clear the screen, draw the fruit, draw the snake,
      // and register the callback with rAF
      renderer.clear();
      renderer.draw(fruit.position, fruit.img);
      renderer.draw(snake.getBody(), snake.getSkin());
      requestAnimationFrame(gameLoop);
   }

   // If the snake is dead, stop rendering and disable
   // the key handlers that controlled the snake
   else {
      document.body.removeEventListener("keydown", snake.doOnKeyDown);
   }
}
```

# 总结

在本章中，我们开始使用备受期待的 canvas API 进行 2D 渲染。我们研究了通过 canvas 渲染上下文可用的各种绘图函数，包括绘制简单的线条和形状，从外部图像源绘制图像，像素操作和图像提取，这使我们能够将画布上的图像保存回用户的文件系统。

我们还研究了通过 Web Worker 接口可用的新线程系统。这使我们能够释放用户界面线程，同时执行长时间运行的任务，否则会锁定界面，并导致浏览器显示非响应页面警报。不幸的是，Web Worker 存在一些限制，因为工作线程之间没有共享内存，也不允许在工作线程中关联或允许 DOM。尽管如此，HTML5 的这一壮丽新功能仍然可以完成许多工作。

在本章中，我们涵盖的另一个 HTML5 特定 API 是离线应用程序缓存。通过这种机制，我们可以从 Web 服务器保存特定资产，将其存储为快速、高可用的缓存，由用户的浏览器提供支持。浏览器保存的特定资产由清单文件指定，虽然它是一个简单的基于文本的文件，并且必须由服务器以`text/cache-manifest` MIME 类型提供。

最后，我们还研究了 JavaScript 语言的两个新功能，使游戏开发更加高效和令人兴奋。这两个功能中的第一个是`requestAnimationFrame`，它允许我们在单个同步调用中渲染所有内容，由浏览器自己管理。这通常是渲染所有图形的最佳方式，因为浏览器可以高度优化渲染过程。第二个功能是类型化数组数据类型，它允许更高效的数据存储和访问。这对游戏开发特别有吸引力，因为我们可以通过使用这种新的数据类型获得额外的性能提升，即使它看起来和行为几乎与常规数组完全相同。因此，使用类型化数组编写新代码应该完全没有学习曲线，因为迁移使用数组的现有代码是一种真正的享受。

在下一章中，我们将继续改进 Snake 游戏，使其更加健壮和功能丰富。我们将学习另外四个 HTML5 API，即 sessionStorage、localStorage、IndexedDB 和 web messaging。
