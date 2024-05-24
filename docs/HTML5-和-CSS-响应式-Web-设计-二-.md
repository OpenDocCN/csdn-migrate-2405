# HTML5 和 CSS 响应式 Web 设计（二）

> 原文：[`zh.annas-archive.org/md5/BF3881984EFC9B87954F91E00BDCB9A3`](https://zh.annas-archive.org/md5/BF3881984EFC9B87954F91E00BDCB9A3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：响应式 Web 设计的 HTML5

如果您正在寻求使用 HTML5 **应用程序编程接口**（**API**）的指导，我要引用一部伟大的西部电影中的一句话，说：“我不是你的 Huckleberry”。

我想和您一起看看 HTML5 的“词汇”部分；它的语义。更简洁地说，我们可以如何使用 HTML5 的新元素来描述我们在标记中放置的内容。本章大部分内容与响应式 Web 设计无关。然而，HTML 是构建所有基于 Web 的设计和应用程序的基础。谁不想在最坚实的基础上构建？

您可能会想知道“HTML5 到底是什么？”如果是这样，我会告诉您，HTML5 只是给 HTML 的最新版本的描述，这是我们用来构建网页的标签语言。HTML 本身是一个不断发展的标准，之前的主要版本是 4.01。

关于 HTML 的版本和时间线的更多背景信息，您可以阅读维基百科条目[`en.wikipedia.org/wiki/HTML#HTML_versions_timeline`](http://en.wikipedia.org/wiki/HTML#HTML_versions_timeline)。

### 提示

HTML5 现在是 W3C 的推荐标准。您可以在[`www.w3.org/TR/html5/`](http://www.w3.org/TR/html5/)上阅读规范。

本章我们将涵盖的主题有：

+   HTML5 得到了多大的支持？

+   正确开始 HTML5 页面

+   轻松的 HTML5

+   新的语义元素

+   文本级语义

+   过时的功能

+   将新元素投入使用

+   **Web 内容可访问性指南**（**WCAG**）可访问性符合和**Web 可访问性倡议-可访问丰富的互联网应用程序**（**WAI-ARIA**）用于更具可访问性的 Web 应用程序

+   嵌入媒体

+   响应式视频和 iFrames

+   关于“离线优先”的说明

### 注意

HTML5 还提供了处理表单和用户输入的特定工具。这一系列功能大大减轻了像 JavaScript 这样的资源密集型技术对表单验证等方面的负担。然而，我们将在第九章中单独讨论 HTML5 表单，*用 HTML5 和 CSS3 征服表单*。

# HTML5 标记-所有现代浏览器都能理解

如今，我看到的大多数网站（包括我自己制作的所有网站）都是使用 HTML5 编写的，而不是旧的 HTML 4.01 标准。

所有现代浏览器都理解 HTML5 的新语义元素（新的结构元素、视频和音频标签），甚至旧版本的 Internet Explorer（Internet Explorer 9 之前的版本）也可以使用一个小的“polyfill”来渲染这些新元素。

### 注意

**什么是 polyfill？**

术语**polyfill**是由 Remy Sharp 创造的，意指用 Polyfilla（在美国称为**Spackling Paste**）填补旧浏览器中的裂缝。因此，polyfill 是 JavaScript 的“垫片”，可以在旧浏览器中有效地复制新功能。然而，重要的是要意识到 polyfill 会给您的代码增加额外的负担。因此，即使您可以添加 15 个 polyfill 脚本使 Internet Explorer 6 渲染网站与其他浏览器完全相同，也并不意味着您一定应该这样做。

如果您需要启用 HTML5 结构元素，我建议查看 Remy Sharp 的原始脚本（[`remysharp.com/2009/01/07/html5-enabling-script/`](http://remysharp.com/2009/01/07/html5-enabling-script/)）或创建 Modernizr 的自定义版本（[`modernizr.com`](http://modernizr.com)）。如果您还没有接触或使用 Modernizr，下一章中有一个完整的部分介绍它。

考虑到这一点，让我们来考虑一下 HTML5 页面的开始。让我们了解所有的开放标签以及它们的作用。

# 正确开始 HTML5 页面

让我们从 HTML5 文档的开头开始。如果搞砸了这部分，你可能会花很长时间想知道为什么你的页面表现得不像应该的那样。前几行应该是这样的：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset=utf-8>
```

让我们逐个讨论这些标签。通常情况下，每次创建网页时它们都是一样的，但相信我，了解它们的作用是值得的。

## 文档类型

`doctype`是一种向浏览器传达我们拥有的文档类型的方式。否则，它可能不知道如何使用其中的内容。

我们用 HTML5 的`doctype`声明打开了我们的文档：

```html
<!DOCTYPE html>
```

如果你喜欢小写字母，那么`<!doctype html>`也是一样好的。没有任何区别。

这是从 HTML 4.01 页面中的一个受欢迎的变化。它们过去通常是这样开始的：

```html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
```

这真是一个巨大的痛苦！难怪我过去常常复制粘贴它！

另一方面，HTML5 的`doctype`非常简短，只是`<!DOCTYPE html>`。有趣的事实（至少对我来说）：实际上它最终变成这样是因为确定这是告诉浏览器以“标准模式”渲染页面的最短方法。

### 提示

想要了解“怪癖”和“标准”模式是什么吗？维基百科可以帮到你：[`en.wikipedia.org/wiki/Quirks_mode`](http://en.wikipedia.org/wiki/Quirks_mode)

## HTML 标签和 lang 属性

在`doctype`声明之后，我们打开了`html`标签；我们文档的根标签。我们还使用`lang`属性来指定文档的语言，然后我们打开了`<head>`部分。

```html
<html lang="en">
<head>
```

## 指定备用语言

根据 W3C 规范（[`www.w3.org/TR/html5/dom.html#the-lang-and-xml:lang-attributes`](http://www.w3.org/TR/html5/dom.html#the-lang-and-xml:lang-attributes)），`lang`属性指定了元素内容的主要语言，以及包含文本的元素属性的语言。如果你不是用英语编写页面，最好指定正确的语言代码。例如，对于日语，HTML 标签将是`<html lang="ja">`。要查看完整的语言列表，请查看[`www.iana.org/assignments/language-subtag-registry`](http://www.iana.org/assignments/language-subtag-registry)。

## 字符编码

最后，我们指定字符编码。由于它是一个空元素（不能包含任何内容），它不需要闭合标签：

```html
<meta charset="utf-8">
```

除非你有充分的理由指定其他值，否则字符集的值几乎总是`utf-8`。对于好奇的人，关于这个主题的更多信息可以在[`www.w3.org/International/questions/qa-html-encoding-declarations#html5charset`](http://www.w3.org/International/questions/qa-html-encoding-declarations#html5charset)找到。

# 轻松的 HTML5

我记得，在学校的时候，我们非常严厉（但实际上非常好）的数学老师偶尔会缺席。班上会松一口气，因为替代老师通常是一个随和的人。他安静地坐着，不会大声喊叫或不断刺激我们。他在我们工作时不坚持要求安静，也不太在意我们是否遵守他解决问题的方式，重要的是答案以及我们如何得出答案。如果 HTML5 是一位数学老师，它就是那位随和的替代老师。现在我将解释这个奇怪的类比。

如果你注意写代码的方式，通常会大部分使用小写字母，用引号括起属性值，并为脚本和样式表声明“类型”。例如，也许你链接到一个样式表，就像这样：

```html
<link href="CSS/main.css" rel="stylesheet" type="text/css" />
```

HTML5 不需要如此精确，它也可以接受这样的写法：

```html
<link href=CSS/main.css rel=stylesheet >
```

你注意到了吗？没有结束标签/斜杠，属性值周围没有引号，也没有类型声明。然而，轻松的 HTML5 并不在乎。第二个例子和第一个一样有效。

这种更宽松的语法适用于整个文档，不仅仅是链接的资产。例如，如果你喜欢，可以这样指定一个 div：

```html
<div id=wrapper>
```

这是完全有效的 HTML5。插入图像也是一样：

```html
<img SRC=frontCarousel.png aLt=frontCarousel>
```

这也是有效的 HTML5。没有结束标签/斜杠，没有引号，大小写字母混合。你甚至可以省略诸如开头的`<head>`标签，页面仍然验证。XHTML 1.0 会对此有何看法？

### 提示

想要一个快捷的 HTML5 代码？考虑使用 HTML5 Boilerplate（[`html5boilerplate.com/`](http://html5boilerplate.com/)）。这是一个预先制作的“最佳实践”HTML5 文件，包括必要的样式，polyfills 和可选工具，如 Modernizr。你可以通过查看代码获得很多很好的提示，还可以根据自己的特定需求定制模板。强烈推荐！

## HTML5 标记的合理方法

就个人而言，我喜欢以“XHTML”风格编写我的标记。这意味着关闭标签，引用属性值，并遵循一致的大小写。有人可能会争辩说放弃其中一些做法会节省一些数据字节，但这就是工具的用途（如果需要，可以剥离任何不必要的字符/数据）。我希望我的标记尽可能易读，也鼓励其他人这样做。我认为代码的清晰度应该胜过简洁性。

因此，在编写 HTML5 文档时，我认为你可以编写干净易读的代码，同时仍然可以利用 HTML5 所提供的经济效益。举例来说，对于 CSS 链接，我会选择以下方式：

```html
<link href="CSS/main.css" rel="stylesheet"/>
```

我保留了闭合标签和引号，但省略了`type`属性。这里要说明的是，你可以找到一个让自己满意的水平。HTML5 不会对你大喊大叫，在班上标记你的标记，并让你站在角落里戴着愚人帽子，因为你的标记没有验证（难道只有我的学校这样做吗？）。但是，你想怎么写你的标记都可以。

我在开玩笑吗？我现在就想让你知道，如果你在编写代码时不引用属性值和不关闭标签，我会默默地评判你。

### 提示

尽管 HTML5 的语法更宽松，但检查你的标记是否有效总是值得的。有效的标记更具可访问性。W3C 验证器就是为了这个目的而创建的：[`validator.w3.org/`](http://validator.w3.org/)

我已经够抨击“嬉皮士”风格标记的作者了。让我们看看 HTML5 的更多好处。

## 万岁强大的<a>标签

HTML5 的一个巨大的优势是现在我们可以将多个元素包装在一个`<a>`标签中（喔耶！是时候了，对吧？）。以前，如果你想让你的标记验证，就必须将每个元素包装在自己的`<a>`标签中。例如，看看以下 HTML 4.01 代码：

```html
<h2><a href="index.html">The home page</a></h2>
<p><a href="index.html">This paragraph also links to the home page</a></p>
<a href="index.html"><img src="img/home-image.png" alt="home-slice" /></a>
```

有了 HTML5，我们可以放弃所有单独的`<a>`标签，而是用一个标签包装整个组：

```html
<a href="index.html">
  <h2>The home page</h2>
  <p>This paragraph also links to the home page</p>
  <img src="img/home-image.png" alt="home-slice" />
</a>
```

需要记住的唯一限制是，可以理解的是，你不能在另一个`<a>`标签中包装一个`<a>`标签（因为，嗯，显而易见），或者另一个交互元素，如`button`（因为，嗯，显而易见！），也不能在`<a>`标签中包装一个表单（因为，嗯，你懂的）。

# HTML5 中的新语义元素

如果我查看 OS X 字典中“语义”一词的定义，它被定义为：

> *“与语言学和逻辑有关的分支，关注意义”。*

对于我们的目的，语义是赋予我们的标记意义的过程。这为什么重要？很高兴你问。

大多数网站遵循相当标准的结构约定；典型的区域包括标题、页脚、侧边栏、导航栏等。作为网页作者，我们通常会为我们使用的 div 命名，以更清晰地指定这些区域（例如，`class="Header"`）。但是，就代码本身而言，任何用户代理（Web 浏览器、屏幕阅读器、搜索引擎爬虫等）查看它时无法确定每个`div`元素的目的。辅助技术的用户也会发现很难区分一个`div`和另一个`div`。HTML5 旨在通过新的语义元素解决这个问题。

### 注意

要获取 HTML5 元素的完整列表，请舒服地将浏览器指向[`www.w3.org/TR/html5/semantics.html#semantics`](http://www.w3.org/TR/html5/semantics.html#semantics)。

我们不会在这里涵盖所有新元素，只是我认为在日常响应式 Web 设计中最有益或有趣的元素。让我们深入了解。

## `<main>`元素

很长一段时间，HTML5 没有元素来划分页面的主要内容。在网页的正文中，这将是包含主要内容块的元素。

起初，有人认为不在其他新的语义 HTML5 元素之一内的内容，通过否定，将成为主要内容。幸运的是，规范发生了变化，现在我们有了更具有声明性的方式来分组主要内容；这个名为`<main>`的标签。

无论您是包装页面的主要内容还是基于 Web 的应用程序的主要部分，`main`元素都是您应该将所有内容分组的元素。以下是规范中特别有用的一行：

> “文档的主要内容区域包括该文档独有的内容，不包括在一组文档中重复的内容，例如站点导航链接、版权信息、站点标识和横幅以及搜索表单（除非文档或应用程序的主要功能是搜索表单）。”

值得注意的是，每个页面上不应该有多个主要内容（毕竟，您不能有两个主要内容），它不应该被用作其他语义 HTML5 元素的后代，例如`article`、`aside`、`header`、`footer`、`nav`或`header`。但它们可以存在于主要元素中。

### 注意

阅读关于主要元素的官方说明：[`www.w3.org/TR/html5/grouping-content.html#the-main-element`](http://www.w3.org/TR/html5/grouping-content.html#the-main-element)

## `<section>`元素

`<section>`元素用于定义文档或应用程序的通用部分。例如，您可以选择围绕您的内容创建部分；一个部分用于联系信息，另一个部分用于新闻提要等。重要的是要理解它并不是用于样式目的。如果您需要包装一个元素仅用于样式化，您应该继续像以前一样使用`div`。

在开发基于 Web 的应用程序时，我倾向于使用`section`作为可视组件的包装元素。它提供了一种简单的方法来查看标记中组件的开始和结束。

您还可以自行判断是否应该使用基于内容的部分（例如`h1`）来确定是否应该使用部分。如果没有，您最好选择`div`。

### 注意

要查看 W3C HTML5 规范中关于`<section>`的内容，请访问以下网址：

[`www.w3.org/TR/html5/sections.html#the-section-element`](http://www.w3.org/TR/html5/sections.html#the-section-element)

## <nav>元素

`<nav>`元素用于包装到其他页面或同一页面内部的主要导航链接。它并不严格用于页脚（尽管可以），以及其他常见的其他页面链接组。

如果您通常使用无序列表（`<ul>`）和一堆列表标签（`li`）标记您的导航元素，您可能更适合使用`nav`和一些嵌套的`a`标签。

### 注意

要了解 W3C HTML5 规范对`<nav>`的说明，请访问以下网址：

[`www.w3.org/TR/html5/sections.html#the-nav-element`](http://www.w3.org/TR/html5/sections.html#the-nav-element)

## `<article>`元素

`<article>`元素和`<section>`一样容易引起混淆。我肯定在它们的规范之前读了很多遍，才明白它们的含义。这是我对规范的重新阐述。`<article>`元素用于包装一个独立的内容块。在构建页面时，问一下，您打算在`<article>`标签中使用的内容是否可以作为一个整体被复制到另一个网站上，并且仍然完全有意义？另一种思考方式是，您打算用`<article>`包装的内容是否实际上构成了 RSS 订阅中的一个单独的文章？显而易见的应该用`<article>`元素包装的内容的例子是博客文章或新闻报道。请注意，如果嵌套`<article>`元素，假定嵌套的`<article>`元素主要与外部文章相关。

### 注意

有关 W3C HTML5 规范对`<article>`的说明，请访问[`www.w3.org/TR/html5/sections.html#the-article-element`](http://www.w3.org/TR/html5/sections.html#the-article-element)。

## `<aside>`元素

`<aside>`元素用于与周围内容有关的内容。在实际操作中，我经常用它来制作侧边栏（当它包含合适的内容时）。它也被认为适合用于拉引语、广告和导航元素组。基本上，任何与主要内容不直接相关的内容都可以放在`<aside>`中。如果这是一个电子商务网站，我会考虑像“购买此商品的顾客还购买了”这样的区域作为`<aside>`的首选内容。

### 注意

有关 W3C HTML5 规范对`<aside>`的说明，请访问[`www.w3.org/TR/html5/sections.html#the-aside-element`](http://www.w3.org/TR/html5/sections.html#the-aside-element)。

## `<figure>`和`<figcaption>`元素

规范涉及`figure`元素：

> 这样可以用来注释插图、图表、照片、代码清单等。

以下是我们如何使用它来修改第一章的一部分标记：

```html
<figure class="MoneyShot">
  <img class="MoneyShotImg" src="img/scones.jpg" alt="Incredible scones" />
  <figcaption class="ImageCaption">Incredible scones, picture from Wikipedia</figcaption>
</figure>
```

您可以看到`<figure>`元素用于包装这个小的独立块。在内部，`<figcaption>`用于为父`<figure>`元素提供标题。

当图片或代码需要在旁边加上一点标题时（这在内容的主要文本中不合适），这是完美的。

### 注意

`figure`元素的规范可以在[`www.w3.org/TR/html5/grouping-content.html#the-figure-element`](http://www.w3.org/TR/html5/grouping-content.html#the-figure-element)找到。

`figcaption`的规范在[`www.w3.org/TR/html5/grouping-content.html#the-figcaption-element`](http://www.w3.org/TR/html5/grouping-content.html#the-figcaption-element)。

## `<details>`和`<summary>`元素

您有多少次想要在页面上创建一个简单的打开和关闭“小部件”？点击时打开一个带有附加信息的面板的摘要文本。HTML5 通过`details`和`summary`元素实现了这种模式。考虑一下这个标记（您可以打开本章代码中的`example3.html`来自己尝试）：

```html
<details>
    <summary>I ate 15 scones in one day</summary>
    <p>Of course I didn't. It would probably kill me if I did. What a way to go. Mmmmmm, scones!</p>
</details>
```

在 Chrome 中打开时，默认只显示摘要文本：

![`<details>`和`<summary>`元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_04_02.jpg)

单击摘要文本的任何位置都会打开面板。再次单击它会切换关闭。如果您希望面板默认打开，可以将`open`属性添加到`details`元素中：

```html
<details open>
    <summary>I ate 15 scones in one day</summary>
    <p>Of course I didn't. It would probably kill me if I did. What a way to go. Mmmmmm, scones!</p>
</details>
```

![`<details>`和`<summary>`元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_04_03.jpg)

支持的浏览器通常会添加一些默认样式来指示面板可以打开。在 Chrome（以及 Safari）中，这是一个深色的披露三角形。要禁用这个，你需要使用一个 WebKit 特定的私有伪选择器：

```html
summary::-webkit-details-marker {
  display: none;
}
```

当然，你可以使用相同的选择器来以不同的样式显示标记。

目前，没有办法对打开和关闭进行动画处理。也没有（非 JavaScript）的办法在打开不同的详细信息面板时关闭其他详细信息面板（在同一级别）。我不确定这些愿望中的任何一个会（或应该）得到解决。你应该把它看作是一种通过 JavaScript 的`display: none;`切换来促进你所做的事情。

遗憾的是，截至我写这篇文章时（2015 年中），Firefox 或 Internet Explorer 不支持此元素（它们只将这两个元素呈现为内联元素）。存在 Polyfills（[`mathiasbynens.be/notes/html5-details-jquery`](https://mathiasbynens.be/notes/html5-details-jquery)），希望很快就会完全实现。

## `<header>`元素

实际上，`<header>`元素可以用于站点页眉的“标志”区域。它也可以用作其他内容的介绍，比如`<article>`元素中的一个部分。你可以在同一页上使用它多次（例如，你可以在页面上的每个`<section>`中都有一个`<header>`）。

### 注意

这是 W3C HTML5 规范对`<header>`的说明：

[`www.w3.org/TR/html5/sections.html#the-header-element`](http://www.w3.org/TR/html5/sections.html#the-header-element)

## `<footer>`元素

`<footer>`元素应该用于包含所在部分的信息。例如，它可能包含指向其他文档的链接或版权信息。与`<header>`一样，如果需要，它可以在页面中多次使用。例如，它可以用于博客的页脚，也可以用于博客文章中的`footer`部分。但是，规范解释说，博客文章作者的联系信息应该用`<address>`元素包装。

### 注意

查看 W3C HTML5 规范对`<footer>`的说明：

[`www.w3.org/TR/html5/sections.html#the-footer-element`](http://www.w3.org/TR/html5/sections.html#the-footer-element)

## `<address>`元素

`<address>`元素专门用于标记其最近的`<article>`或`<body>`祖先的联系信息。要混淆事情，要记住它不应该用于邮政地址等（除非它们确实是所讨论内容的联系地址）。相反，邮政地址和其他任意联系信息应该用老式的`<p>`标签包装。

我不喜欢`<address>`元素，因为根据我的经验，将物理地址标记为自己的元素会更有用，但这是我的个人抱怨。希望这对你来说更有意义。

### 注意

有关 W3C HTML5 规范对`<address>`的更多信息，请查看：

[`www.w3.org/TR/html5/sections.html#the-address-element`](http://www.w3.org/TR/html5/sections.html#the-address-element)

## 关于 h1-h6 元素的说明

直到最近我才意识到，使用`h1`-`h6`标签标记标题和副标题是不鼓励的。我说的是这种情况：

```html
<h1>Scones:</h1>
<h2>The most resplendent of snacks</h2>
```

以下是 HTML5 规范的一句引用：

h1-h6 元素不得用于标记副标题、副标题、替代标题和标语，除非打算用作新部分或子部分的标题。

这绝对是规范中最不明确的句子之一！哎呀！

那么，我们应该如何编写这样的情况呢？规范实际上有一个专门的部分（[`www.w3.org/TR/html5/common-idioms.html#common-idioms`](http://www.w3.org/TR/html5/common-idioms.html#common-idioms)）来专门讨论这个问题。就我个人而言，我更喜欢旧的`<hgroup>`元素，但可惜的是，那艘船已经启航了（更多信息请参见*过时的 HTML 功能*部分）。因此，为了遵循规范的建议，我们之前的例子可以重写为：

```html
<h1>Scones:</h1>
<p>The most resplendent of snacks</p>
```

# HTML5 文本级语义

除了我们已经看过的结构和分组元素之外，HTML5 还修改了一些以前被称为内联元素的标签。HTML5 规范现在将这些标签称为文本级语义（[`www.w3.org/TR/html5/text-level-semantics.html#text-level-semantics`](http://www.w3.org/TR/html5/text-level-semantics.html#text-level-semantics)）。让我们看一些常见的例子。

## `<b>`元素

从历史上看，`<b>`元素意味着“使其加粗”（[`www.w3.org/TR/html4/present/graphics.html#edef-B`](http://www.w3.org/TR/html4/present/graphics.html#edef-B)）。这是从以前样式选择是标记的一部分的时代。然而，现在你可以正式地将其仅用作 CSS 中的样式钩，因为 HTML5 规范现在声明`<b>`是：

> *“b 元素表示吸引注意力的文本范围，用于实用目的，而不传达任何额外的重要性，并且没有暗示另一种声音或情绪，例如文档摘要中的关键词，评论中的产品名称，交互式文本驱动软件中的可操作单词，或文章导言。”*

虽然现在没有特定的含义与之相关联，但由于它是文本级的，它不打算用于包围大量的标记，对此请使用`div`。您还应该知道，因为它在历史上用于加粗文本，如果您希望`<b>`标签内的内容不显示为加粗，通常需要在 CSS 中重置字体重量。

## `<em>`元素

好的，举起手来，我经常只是把`<em>`用作样式钩。我需要改变我的方式，因为在 HTML5 中：

`em`元素表示其内容的重点强调。

因此，除非您真的希望强调所包含的内容，否则请考虑使用`<b>`标签或者在相关情况下使用`<i>`标签。

## `<i>`元素

HTML5 规范将`<i>`描述为：

> *“...以另一种声音或情绪，或以其他方式偏离正常散文的方式，表明文本的不同质量。”*

可以说，它不仅仅用于使某物变斜体。例如，我们可以使用它来标记文本行中的奇怪名称：

```html
<p>However, discussion on the hgroup element is now frustraneous as it's now gone the way of the <i>Raphus cucullatus</i>.</p>
```

### 注意

HTML5 中有许多其他文本级语义标签。要了解完整的信息，请查看规范的相关部分，网址如下：

[`www.w3.org/TR/html5/text-level-semantics.html#text-level-semantics`](http://www.w3.org/TR/html5/text-level-semantics.html#text-level-semantics)

# 过时的 HTML 功能

除了脚本链接中的语言属性之类的东西，HTML 中还有一些您可能习惯使用的其他部分，现在在 HTML5 中被认为是“过时的”。重要的是要意识到在 HTML5 中有两种过时功能的阵营——符合和不符合。符合功能仍然可以工作，但会在验证器中生成警告。实际上，如果可以的话最好避免使用它们，但如果您使用它们，也不会导致天塌下来。不符合功能在某些浏览器中可能仍然可以渲染，但如果您使用它们，您会被认为是非常非常淘气的，并且您可能在周末得不到奖励！

在过时和不符合规范的功能方面，有相当多的功能。我承认很多我从未使用过（有些我甚至从未见过！）。你可能会有类似的反应。然而，如果你感兴趣，你可以在[`www.w3.org/TR/html5/obsolete.html`](http://www.w3.org/TR/html5/obsolete.html)找到完整的过时和不符合规范的功能列表。值得注意的过时和不符合规范的功能包括`strike`、`center`、`font`、`acronym`、`frame`和`frameset`。

HTML5 中还有一些早期草案中存在的功能，现在已经被删除了。`hgroup`就是一个例子。该标签最初被提议用于包装标题组；一个标题`h1`和一个副标题`h2`可能被包装在`hgroup`元素中。然而，关于`hgroup`元素的讨论现在已经变得无用，因为它已经像 Raphus cucullatus 一样消失了（去吧，谷歌一下，你知道你想要的）。

# 使用 HTML5 元素

现在是练习刚刚学习的一些元素的时候了。让我们重新访问第一章中的示例，*响应式网页设计的基本知识*。如果我们将下面的标记与第一章中的原始标记进行比较（记住，你可以从[`rwd.education`](http://rwd.education)网站或 GitHub 存储库下载所有示例），你可以看到我们刚刚学习的新元素在下面的示例中是如何使用的。

```html
<article>
  <header class="Header">
    <a href="/" class="LogoWrapper"><img src="img/SOC-Logo.png" alt="Scone O'Clock logo" /></a>
    <h1 class="Strap">Scones: the most resplendent of snacks</h1> 
	</header>
  <section class="IntroWrapper">
    <p class="IntroText">Occasionally maligned and misunderstood; the scone is a quintessentially British classic.</p>
    <figure class="MoneyShot">
      <img class="MoneyShotImg" src="img/scones.jpg" alt="Incredible scones" />
      <figcaption class="ImageCaption">Incredible scones, picture from Wikipedia</figcaption>
    </figure>
  </section>
  <p>Recipe and serving suggestions follow.</p>
  <section class="Ingredients">
    <h3 class="SubHeader">Ingredients</h3>
  </section>
  <section class="HowToMake">
    <h3 class="SubHeader">Method</h3>
  </section>
  <footer>
    Made for the book, <a href="http://rwd.education">'Resonsive web design with HTML5 and CSS3'</a> by <address><a href="http://benfrain">Ben Frain</a></address>
  </footer>
</article>
```

## 运用常识进行元素选择

我已经删除了大部分内部内容，这样我们就可以集中精力关注结构。希望你会同意，很容易区分出标记的不同部分。然而，在这一点上，我也想提供一些建议；如果你并不总是为每个特定情况选择正确的元素，这并不是世界末日。例如，在前面的例子中，我使用`<section>`还是`<div>`并不是很重要。如果我们在应该使用`<i>`时使用了`<em>`，我并不认为这是对人类的罪行；W3C 的人员不会因为你做出了错误的选择而追捕你。只需运用一点常识。也就是说，如果你能在相关情况下使用`<header>`和`<footer>`等元素，那么这样做就具有固有的可访问性好处。

# WCAG 和 WAI-ARIA 用于更易访问的网页应用程序

即使自 2011 年至 2012 年编写本书的第一版以来，W3C 在使作者更容易编写更易访问的网页方面已经取得了进展。

## WCAG

WCAG 的存在是为了提供：

> *“一个共享的标准，用于满足国际上个人、组织和政府的网页内容可访问性需求。”*

对于更普通的网页（而不是单页面网页应用程序等），集中精力关注 WCAG 指南是有意义的。它们提供了许多（大多数是常识）关于如何确保您的网页内容可访问的指南。每个建议都被评为符合级别：A、AA 或 AAA。有关这些符合级别的更多信息，请参阅[`www.w3.org/TR/UNDERSTANDING-WCAG20/conformance.html#uc-levels-head`](http://www.w3.org/TR/UNDERSTANDING-WCAG20/conformance.html#uc-levels-head)。

你可能会发现，你已经遵守了许多指南，比如为图像提供替代文本。然而，你可以在[`www.w3.org/WAI/WCAG20/glance/Overview.html`](http://www.w3.org/WAI/WCAG20/glance/Overview.html)上快速了解这些指南，然后在[`www.w3.org/WAI/WCAG20/quickref/`](http://www.w3.org/WAI/WCAG20/quickref/)上建立自己的自定义快速参考清单。

我鼓励每个人花一两个小时看一看这个清单。许多指南都很容易实施，并为用户带来实际的好处。

## WAI-ARIA

WAI-ARIA 的目标主要是解决使网页上的动态内容可访问的问题。它提供了一种描述自定义小部件（Web 应用程序中的动态部分）的角色、状态和属性的方法，以便辅助技术用户能够识别和使用它们。

例如，如果屏幕上的小部件显示不断更新的股票价格，那么如何盲人用户访问页面时知道呢？WAI-ARIA 试图解决这些问题。

### 不要为语义元素使用角色

以前建议为标题和页脚添加“地标”角色，如下所示：

```html
<header role="banner">A header with ARIA landmark banner role</header>
```

然而，现在认为这是多余的。如果您查看前面列出的任何元素的规范，都有一个专门的*允许的 ARIA 角色属性*部分。以下是来自 section 元素的相关解释：

> “允许的 ARIA 角色属性值：”
> 
> *region role (default - do not set), alert, alertdialog, application, contentinfo, dialog, document, log, main, marquee, presentation, search or status."*

其中关键部分是“role（默认-不设置）”。这意味着在元素本身已经隐含了 ARIA 角色时，明确添加 ARIA 角色到元素是没有意义的。规范中的一条说明现在已经明确表明了这一点。

> “在大多数情况下，设置与默认隐式 ARIA 语义匹配的 ARIA 角色和/或 aria-*属性是不必要的，也不建议这样做，因为这些属性已经由浏览器设置。”

## 如果您只记住一件事

您可以尽可能使用正确的元素来帮助辅助技术。`header`元素比`div class="Header"`更有用。同样，如果页面上有一个按钮，请使用`<button>`元素（而不是`span`或其他样式看起来像`button`的元素）。我知道`button`元素并不总是允许精确的样式（例如，它不喜欢被设置为`display: table-cell`或`display: flex`），在这种情况下至少选择次佳选择；通常是`<a>`标签。

## 进一步了解 ARIA

ARIA 不仅限于地标角色。要进一步了解，可以在[`www.w3.org/TR/wai-aria/roles`](http://www.w3.org/TR/wai-aria/roles)上找到角色的完整列表和简洁的用法描述。

对于这个话题的轻松看法，我还推荐 Heydon Pickering 的书《Apps For All: Coding Accessible Web Applications》（可在[`shop.smashingmagazine.com/products/apps-for-all-coding-accessible-web-applications`](https://shop.smashingmagazine.com/products/apps-for-all-coding-accessible-web-applications)上获取）。

### 提示

**免费使用非视觉桌面访问（NVDA）测试您的设计**

如果您在 Windows 平台上开发，并且想要免费使用 NVDA 测试您的 ARIA 增强设计，您可以在以下网址获取：

[`www.nvda-project.org/`](http://www.nvda-project.org/)

谷歌现在还为 Chrome 浏览器提供免费的“辅助开发者工具”（可跨平台使用）；非常值得一试。

还有越来越多的工具可以帮助您快速测试自己的设计，例如[`michelf.ca/projects/sim-daltonism/`](https://michelf.ca/projects/sim-daltonism/)是一个 Mac 应用程序，可以让您切换色盲类型，并在浮动调色板中预览。

最后，OS X 还包括 VoiceOver 实用程序，用于测试您的网页。

希望对 WAI-ARIA 和 WCAG 的简要介绍为您提供了足够的信息，让您更多地考虑如何支持辅助技术。也许在您的下一个 HTML5 项目中添加辅助技术支持会比您想象的更容易。

作为所有辅助功能的最终资源，A11Y 项目主页上有很多有用的链接和建议，网址为[`a11yproject.com/`](http://a11yproject.com/)。

# 在 HTML5 中嵌入媒体

对许多人来说，当苹果拒绝在其 iOS 设备中添加对 Flash 的支持时，HTML5 首次进入他们的词汇表。Flash 已经在市场上占据了主导地位（有人会认为是市场垄断），成为通过网络浏览器提供视频的首选插件。然而，苹果决定不使用 Adobe 的专有技术，而是依靠 HTML5 来处理丰富的媒体渲染。虽然 HTML5 在这个领域本来就取得了良好的进展，但苹果对 HTML5 的公开支持使其获得了重大的优势，并帮助其媒体工具在更广泛的社区中获得了更大的影响力。

正如你所想象的，Internet Explorer 8 及更低版本不支持 HTML5 视频和音频。大多数其他现代浏览器（Firefox 3.5+，Chrome 4+，Safari 4，Opera 10.5+，Internet Explorer 9+，iOS 3.2+，Opera Mobile 11+，Android 2.3+）都可以很好地处理它。

## 以 HTML5 方式添加视频和音频

在 HTML5 中，视频和音频非常简单。以前使用 HTML5 媒体的唯一真正困难之处在于列出媒体的备用源格式（因为不同的浏览器支持不同的文件格式）。如今，MP4 在桌面和移动平台上都是无处不在的，使得通过 HTML5 在网页中包含媒体变得轻而易举。以下是如何在页面中链接到视频文件的“简单至极”的示例：

```html
<video src="img/myVideo.mp4"></video>
```

HTML5 允许一个`<video></video>`标签（或者用于音频的`<audio></audio>`）来完成所有繁重的工作。还可以在开放和闭合标签之间插入文本，以通知用户存在问题。通常还有其他属性需要添加，比如`height`和`width`。让我们添加这些：

```html
<video src="img/myVideo.mp4" width="640" height="480">What, do you mean you don't understand HTML5?</video>
```

现在，如果我们将前面的代码片段添加到我们的页面中，并在 Safari 中查看它，它将出现，但没有播放控件。要获得默认的播放控件，我们需要添加`controls`属性。我们还可以添加`autoplay`属性（不建议-众所周知，每个人都讨厌自动播放的视频）。这在以下代码片段中进行了演示：

```html
<video src="img/myVideo.mp4" width="640" height="480" controls autoplay> What, do you mean you don't understand HTML5?</video>
```

前面的代码片段的结果如下截图所示：

![以 HTML5 方式添加视频和音频](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/B03777_04_01.jpg)

其他属性包括`preload`来控制媒体的预加载（早期的 HTML5 采用者应该注意，preload 取代了 autobuffer），`loop`来重复播放视频，以及`poster`来定义视频的海报帧。如果视频播放可能会有延迟（或者缓冲可能需要一些时间），这将非常有用。要使用属性，只需将其添加到标签中。以下是包括所有这些属性的示例：

```html
<video src="img/myVideo.mp4" width="640" height="480" controls autoplay preload="auto" loop poster="myVideoPoster.png">What, do you mean you don't understand HTML5?</video>
```

### 旧版浏览器的回退功能

`<source>`标签使我们能够根据需要提供备用方案。例如，除了提供视频的 MP4 版本外，如果我们想要确保 Internet Explorer 8 及更低版本有合适的备用方案，我们可以添加 Flash 回退。更进一步，如果用户在浏览器中没有任何合适的播放技术，我们可以提供文件本身的下载链接。以下是一个示例：

```html
<video width="640" height="480" controls preload="auto" loop poster="myVideoPoster.png">
    <source src="img/myVideo.mp4" type="video/mp4">  
    <object width="640" height="480" type="application/x-shockwave-flash" data="myFlashVideo.SWF">
      <param name="movie" value="myFlashVideo.swf" />
      <param name="flashvars" value="controlbar=over&amp;image=myVideoPoster.jpg&amp;file=myVideo.mp4" />
      <img src="img/myVideoPoster.png" width="640" height="480" alt="__TITLE__"
           title="No video playback capabilities, please download the video below" />
    </object>
    <p><b>Download Video:</b>
  MP4 Format:  <a href="myVideo.mp4">"MP4"</a>
    </p>
</video>
```

该代码示例和示例视频文件（我在英国肥皂剧《加冕街》中出现，当时我还有头发，希望能与德尼罗一起出演）以 MP4 格式在本章代码的`example2.html`中。

## 音频和视频标签的工作方式几乎相同

`<audio>`标签遵循相同的原则，具有相同的属性（不包括`width`，`height`和`poster`）。两者之间的主要区别在于`<audio>`没有用于可见内容的播放区域。

# 响应式 HTML5 视频和 iFrames

我们已经看到，支持旧版浏览器会导致代码膨胀。以`<video>`标签开始的一两行最终变成了 10 行或更多行（还有一个额外的 Flash 文件），只是为了让旧版的 Internet Explorer 满意！就我个人而言，我通常愿意放弃 Flash 回退，以追求更小的代码占用空间，但每个用例都不同。

现在，我们可爱的 HTML5 视频实现的唯一问题是它不是响应式的。没错，在一个使用 HTML5 和 CSS3 的响应式网页设计示例中，它并没有“响应”。

值得庆幸的是，对于 HTML5 嵌入视频，修复很容易。只需在标记中删除任何高度和宽度属性（例如，删除`width="640" height="480"`），并在 CSS 中添加以下内容：

```html
video { max-width: 100%; height: auto; }
```

然而，虽然这对于我们可能在本地托管的文件效果很好，但它并没有解决嵌入在 iFrame 中的视频的问题（比如 YouTube、Vimeo 等）。以下代码将在页面中添加来自 YouTube 的《午夜逃亡》电影预告：

```html
<iframe width="960" height="720" src="img/watch?v=B1_N28DA3gY" frameborder="0" allowfullscreen></iframe>
```

然而，如果按原样添加到页面上，即使添加了之前的 CSS 规则，如果视口小于 960px 宽，事情就会开始被裁剪。

解决这个问题最简单的方法是使用加利西 CSS 大师 Thierry Koblentz 开创的一个小 CSS 技巧；基本上是为视频创建一个正确宽高比的框。我不想泄露这位魔术师的解释，去阅读一下[`alistapart.com/article/creating-intrinsic-ratios-for-video`](http://alistapart.com/article/creating-intrinsic-ratios-for-video)。

如果你感到懒惰，甚至不需要计算宽高比并自己插入，有一个在线服务可以为你做到。只需转到[`embedresponsively.com/`](http://embedresponsively.com/)，粘贴你的 iFrame URL 进去。它会为你生成一小段简单的代码，你可以粘贴到你的页面中。例如，我们的《午夜逃亡》预告片的结果如下：

```html
<style>.embed-container { position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; max-width: 100%; height: auto; } .embed-container iframe, .embed-container object, .embed-container embed { position: absolute; top: 0; left: 0; width: 100%; height: 100%; }</style><div class='embed-container'><iframe src='http://www.youtube.com/embed/B1_N28DA3gY' frameborder='0' allowfullscreen></iframe></div>
```

就是这样，简单地添加到你的页面，就完成了：我们现在有了一个完全响应式的 YouTube 视频（注意：孩子们，不要理会 DeNiro 先生；吸烟有害健康）！

# 关于“离线优先”的说明

我相信构建响应式网页和基于 Web 的应用程序的理想方式是“离线优先”。这种方法意味着网站和应用程序将继续工作和加载，即使没有互联网连接。

HTML5 离线 Web 应用程序（[`www.w3.org/TR/2011/WD-html5-20110525/offline.html`](http://www.w3.org/TR/2011/WD-html5-20110525/offline.html)）是为了实现这个目标而指定的。

尽管离线 Web 应用程序的支持很好（[`caniuse.com/#feat=offline-apps`](http://caniuse.com/#feat=offline-apps)），遗憾的是，这并不是一个完美的解决方案。虽然设置起来相对简单，但存在许多限制和陷阱。在这本书的范围之外记录它们都是不可能的。相反，我建议阅读 Jake Archibald 在这个主题上的幽默而全面的文章：[`alistapart.com/article/application-cache-is-a-douchebag`](http://alistapart.com/article/application-cache-is-a-douchebag)。

因此，我认为虽然使用离线 Web 应用程序（如[`diveintohtml5.info/offline.html`](http://diveintohtml5.info/offline.html)中的教程）和 LocalStorage（或两者的某种组合）可以实现离线优先体验，但更好的解决方案将很快出现。我寄希望于“Service Workers”（[`www.w3.org/TR/service-workers/`](http://www.w3.org/TR/service-workers/)）。

在撰写本文时，Service Workers 仍然是一个相对较新的规范，但我建议你观看这个 15 分钟的介绍：[`www.youtube.com/watch?v=4uQMl7mFB6g`](https://www.youtube.com/watch?v=4uQMl7mFB6g)。阅读这篇介绍[`www.html5rocks.com/en/tutorials/service-worker/introduction/`](http://www.html5rocks.com/en/tutorials/service-worker/introduction/)，并在[`jakearchibald.github.io/isserviceworkerready/`](https://jakearchibald.github.io/isserviceworkerready/)检查支持情况。

我希望如果我写第三版这本书的时候，我们能够考虑全面概述和实施这种技术。保持乐观。

# 总结

在本章中，我们涵盖了很多内容。从创建一个符合 HTML5 验证的页面的基础知识，到将丰富媒体（视频）嵌入我们的标记，并确保它具有响应性。

虽然不是专门针对响应式设计，但我们也讨论了如何编写语义丰富和有意义的代码，并考虑了如何确保页面对于依赖辅助技术的用户来说是有意义和可用的。

出于必要性，这是一个非常标记密集的章节，所以现在让我们改变方向。在接下来的几章中，我们将拥抱 CSS 的强大和灵活性。首先，让我们看看 CSS 3 和 4 选择器的强大功能，新的视口相关 CSS 单位，以及诸如 calc 和 HSL 颜色等功能。它们都将使我们能够创建更快、更有能力和更易维护的响应式设计。


# 第五章：CSS3-选择器、排版、颜色模式和新功能

在过去的几年里，CSS 已经拥有了许多新功能。一些功能使我们能够对元素进行动画和变换，其他功能允许我们创建背景图像、渐变、蒙版和滤镜效果，还有一些功能允许我们使 SVG 元素栩栩如生。

我们将在接下来的几章中了解所有这些功能。首先，我认为看一下过去几年中 CSS 中发生的一些基本变化会很有用：我们如何在页面上选择元素，我们可以使用哪些单位来样式和调整我们的元素，以及现有（和未来）伪类和伪元素如何使 CSS 变得更加强大。我们还将看看如何在我们的 CSS 代码中创建分支，以便在不同浏览器中支持不同的功能。

在本章中，我们将学习以下内容：

+   CSS 规则的解剖（定义规则、声明和属性、值对）

+   响应式设计的快速和方便的 CSS 技巧（多列、换行、截断/文本省略、滚动区域）

+   在 CSS 中实现功能分支（如何使一些规则适用于一些浏览器，而另一些规则适用于其他浏览器）

+   如何使用子字符串属性选择器选择 HTML 元素

+   基于 nth 的选择器是什么以及我们如何使用它们

+   伪类和伪元素是什么（`:empty`, `::before`, `::after`, `:target`, `:scope`）

+   CSS Level 4 选择器模块中的新选择器（`:has`）

+   CSS 变量和自定义属性是什么，以及如何编写它们

+   CSS `calc`函数是什么以及如何使用它

+   利用与视口相关的单位（`vh`、`vw`、`vmin`和`vmax`）

+   如何使用`@font-face`进行网络排版

+   RGB 和 HSL 颜色模式与 Alpha 透明度

# 没有人知道所有的东西

没有人能知道所有的东西。我已经使用 CSS 工作了十多年，每周我仍然会在 CSS 中发现一些新东西（或重新发现我已经忘记的东西）。因此，我认为试图了解每种可能的 CSS 属性和值的排列组合实际上并不值得追求。相反，我认为更明智的做法是掌握可能性。

因此，在本章中，我们将集中讨论一些在构建响应式网页设计时我发现最有用的技术、单位和选择器。我希望你能够掌握解决开发响应式网页设计时遇到的大多数问题所需的知识。

# CSS 规则的解剖

在探索 CSS3 所提供的一些功能之前，为了避免混淆，让我们先确定一下我们用来描述 CSS 规则的术语。考虑以下示例：

```html
.round { /* selector */
  border-radius: 10px; /* declaration */
}
```

这个规则由选择器（`.round`）和声明（`border-radius: 10px;`）组成。声明进一步由属性（`border-radius:`）和值（`10px;`）定义。我们对此有了共识吗？太好了，让我们继续前进。

### 提示

**记得检查用户的支持情况**

随着我们越来越深入了解 CSS3，请不要忘记访问[`caniuse.com/`](http://caniuse.com/)，如果您想了解特定 CSS3 或 HTML5 功能的当前浏览器支持水平。除了显示浏览器版本支持（可按功能搜索），它还提供了来自[`gs.statcounter.com/`](http://gs.statcounter.com/)的最新全局使用统计数据。

# 快速实用的 CSS 技巧

在我的日常工作中，我发现我经常使用一些 CSS3 功能，而其他一些几乎从不使用。我认为分享我经常使用的那些可能会很有用。这些是 CSS3 的好东西，可以让生活变得更轻松，特别是在响应式设计中。它们可以相对轻松地解决以前可能是小头疼的问题。

## 响应式设计的 CSS 多列布局

是否曾经需要使单个文本出现在多个列中？您可以通过将内容拆分为不同的标记元素，然后进行相应的样式设置来解决问题。但是，仅出于样式目的而更改标记永远不是理想的。CSS 多列布局规范描述了我们如何轻松地跨越一个或多个内容片段跨越多个列。考虑以下标记：

```html
<main>
    <p>lloremipsimLoremipsum dolor sit amet, consectetur
<!-- LOTS MORE TEXT -->
</p>
    <p>lloremipsimLoremipsum dolor sit amet, consectetur
<!-- LOTS MORE TEXT -->
</p>
</main>
```

使用 CSS 多列，您可以以多种方式使所有内容跨越多列流动。您可以使列具有特定的列宽（例如 12em），或者您可以指定内容需要跨越一定数量的列（例如 3 列）。

让我们看看实现这些情景所需的代码。对于固定宽度的列，请使用以下语法：

```html
main {
  column-width: 12em;
}
```

这意味着无论视口大小如何，内容都将跨越宽度为 12em 的列。更改视口将动态调整显示的列数。您可以通过查看`example_05-01`（或 GitHub 存储库：[`github.com/benfrain/rwd`](https://github.com/benfrain/rwd)）在浏览器中查看此内容。

考虑一下页面在 iPad 纵向方向（768px 宽视口）上的呈现方式：

![CSS 多列布局用于响应式设计](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_01.jpg)

然后在 Chrome 桌面上（大约 1100px 宽的视口）：

![CSS 多列布局用于响应式设计](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_02.jpg)

简单的响应式文本列，工作量最小；我喜欢它！

### 固定列，可变宽度

如果您更喜欢保持固定数量的列并改变宽度，可以编写以下规则：

```html
main {
  column-count: 4;
}
```

### 添加间隙和列分隔符

我们甚至可以进一步添加指定的列间隙和分隔符：

```html
main {
  column-gap: 2em;
  column-rule: thin dotted #999;
  column-width: 12em;
}
```

这给我们带来了以下结果：

![添加间隙和列分隔符](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_03.jpg)

要阅读 CSS3 多列布局模块的规范，请访问[`www.w3.org/TR/css3-multicol/`](http://www.w3.org/TR/css3-multicol/)。

目前，尽管在 W3C 的 CR 状态，但您可能仍需要供应商前缀以获得最大的兼容性。

我对使用 CSS 多列的唯一警告是，对于较长的文本跨度，它可能导致用户体验不佳。在这些情况下，用户将不得不在页面上上下滚动以阅读文本的列，这可能有点繁琐。

# 自动换行

您有多少次不得不将一个大 URL 添加到一个小空间中，然后感到绝望？看一下[`rwd.education/code/example_05-04`](http://rwd.education/code/example_05-04)。问题也可以在以下屏幕截图中看到；请注意，URL 正在超出其分配的空间。

![Word wrapping](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_04.jpg)

通过简单的 CSS3 声明很容易解决这个问题，碰巧的是，这也适用于 Internet Explorer 5.5 以前的旧版本！只需添加：

```html
word-wrap: break-word;
```

到包含元素，效果如下截图所示。

![Word wrapping](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_05.jpg)

哇，长长的 URL 现在完美地换行了！

## 文本省略

文本截断过去是服务器端技术的专属领域。现在我们可以仅使用 CSS 进行文本省略/截断。让我们来考虑一下。

考虑这个标记（您可以在`rwd.education/code/ch5/example_05-03/`上在线查看此示例）：

```html
<p class="truncate">OK, listen up, I've figured out the key eternal happiness. All you need to do is eat lots of scones.</p>
```

但实际上我们希望将文本截断为 520px 宽。所以看起来像这样：

![Text ellipsis](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_14.jpg)

以下是使其发生的 CSS：

```html
.truncate {
  width: 520px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: no-wrap;
}
```

### 提示

您可以在[`dev.w3.org/csswg/css-ui-3/`](http://dev.w3.org/csswg/css-ui-3/)上阅读有关`text-overflow`属性的规范。

每当内容的宽度超过定义的宽度时（如果它在一个灵活的容器内，宽度也可以设置为百分比，比如 100%），它将被截断。`white-space: no-wrap`属性/值对用于确保内容不会在周围的元素内换行。

## 创建水平滚动面板

希望您知道我是什么意思？水平滚动面板在 iTunes 商店和 Apple TV 上很常见，用于显示相关内容的面板（电影、专辑等）。当水平空间足够时，所有项目都是可见的。当空间有限时（考虑移动设备），面板可以从一侧滚动到另一侧。

滚动面板在现代 Android 和 iOS 设备上特别有效。如果您手头有一部现代 iOS 或 Android 设备，请在那上面看看下一个示例，同时在 Safari 或 Chrome 等桌面浏览器上查看：[`rwd.education/code/ch5/example_05-02/`](http://rwd.education/code/ch5/example_05-02/)。

我创建了一个 2014 年票房最高的电影的滚动面板。在 iPhone 上看起来是这样的：

![创建水平滚动面板](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_11.jpg)

我其实有点作弊。这种技术的关键是`white-space`属性，它实际上自 CSS 2.1 以来就存在了（[`www.w3.org/TR/CSS2/text.html`](http://www.w3.org/TR/CSS2/text.html)）。然而，我打算将它与新的 Flexbox 布局机制一起使用，所以希望你不介意？

为了使这种技术起作用，我们只需要一个比其内容总和更窄的包装器，并在*x*轴上将其宽度设置为自动。这样，如果有足够的空间，它就不会滚动，但如果没有，它就会滚动。

```html
.Scroll_Wrapper {
  width: 100%;
  white-space: nowrap;
  overflow-x: auto;
  overflow-y: hidden;
}

.Item {
  display: inline-flex;
}
```

通过使用`white-space: nowrap`，我们在说'当找到空白字符时，不要换行这些元素'。然后为了保持所有内容在一行中，我们将该容器的所有第一个子元素设置为内联显示。我们在这里使用`inline-flex`，但它也可以很容易地是内联、`inline-block`或`inline-table`。

### 提示

**::before 和::after 伪元素**

如果查看示例代码，您会注意到`::before`伪元素用于显示项目的编号。如果使用伪元素，请记住`::before`或`::after`要显示，它们必须有内容值，即使只是空格。当这些伪元素被显示时，它们就会分别像该元素的第一个和最后一个子元素一样行为。

为了使事情看起来更美观，我将尽可能隐藏滚动条。不幸的是，这些是特定于浏览器的，所以您需要手动添加它们（自动添加器工具不会添加它们，因为它们是专有属性）。我还将为 WebKit 浏览器（通常是 iOS 设备）添加触摸样式惯性滚动。现在更新的`.Scroll_Wrapper`规则看起来像这样：

```html
.Scroll_Wrapper {
  width: 100%;
  white-space: nowrap;
  overflow-x: auto;
  overflow-y: hidden;
  /*Give us inertia style scrolling on WebKit based touch devices*/
  -webkit-overflow-scrolling: touch;
  /*Remove the scrollbars in supporting versions of IE*/
  -ms-overflow-style: none;
}

/*Stops the scrollbar appearing in WebKit browsers*/
.Scroll_Wrapper::-webkit-scrollbar {
  display: none;
}
```

当空间有限时，我们得到一个漂亮的可滚动水平面板。否则，内容就合适。

然而，这种模式有一些注意事项。首先，在撰写本文时，Firefox 没有允许隐藏滚动条的属性。其次，较旧的 Android 设备无法执行水平滚动（是的，真的）。因此，我倾向于通过特性检测来限定这种模式。我们将看看下面的工作原理。

# 在 CSS 中实现特性分支

当您构建响应式网页设计时，试图提供一个在每个设备上都能正常工作的单一设计，一个简单的事实是，您经常会遇到某些设备不支持的功能或技术。在这些情况下，您可能希望在您的 CSS 中创建一个分支；如果浏览器支持某个功能，则提供一段代码，如果不支持，则提供不同的代码。这是 JavaScript 中`if/else`或`switch`语句处理的情况。

我们目前有两种可能的方法。一种完全基于 CSS，但浏览器实现较少，另一种只能在 JavaScript 库的帮助下实现，但支持范围更广。让我们依次考虑每种方法。

## 特性查询

在 CSS 中分叉代码的本机解决方案是使用'Feature Queries'，这是 CSS 条件规则模块 3 级的一部分（[`www.w3.org/TR/css3-conditional/`](http://www.w3.org/TR/css3-conditional/)）。然而，目前，CSS 条件规则在 Internet Explorer（截至版本 11）和 Safari（包括 iOS 设备直到 iOS 8.1）中缺乏支持，因此支持几乎不普遍。

特性查询遵循与媒体查询类似的语法。考虑这个：

```html
@supports (flashing-sausages: lincolnshire) {
  body {
    sausage-sound: sizzling;
    sausage-color: slighty-burnt;
    background-color: brown;
  }
}
```

这里的样式只有在浏览器支持`flashing-sausages`属性时才会应用。我非常确信没有浏览器会支持`flashing-sausages`功能（如果他们支持，我希望得到充分的认可），因此`@supports`块内的样式将不会应用。

让我们考虑一个更实际的例子。如果浏览器支持 Flexbox，则使用 Flexbox，否则使用其他布局技术。考虑这个例子：

```html
@supports (display: flex) {
  .Item {
    display: inline-flex;
  }
}

@supports not (display: flex) {
  .Item {
    display: inline-block;
  }
}
```

在这里，我们为浏览器支持某个功能定义了一个代码块，为不支持该功能的情况定义了另一个代码块。如果浏览器支持`@supports`（是的，我意识到这很令人困惑），这种模式是可以的，但如果不支持，将不会应用任何这些样式。

如果您想覆盖不支持`@supports`的设备，最好先编写默认声明，然后在支持`@support`的声明之后编写特定的声明，这样如果支持`@support`存在，先前的规则将被覆盖，如果浏览器不支持`@support`，则将忽略`@support`块。因此，我们之前的示例可以重新设计为：

```html
.Item {
  display: inline-block;
}

@supports (display: flex) {
  .Item {
    display: inline-flex;
  }
}
```

## 组合条件

您还可以结合条件。假设我们只想在支持 Flexbox 和`pointer: coarse`的情况下应用一些规则（如果您错过了，我们在第二章中介绍了'pointer'交互媒体特性，*媒体查询-支持不同的视口*）。可能会是这样：

```html
@supports ((display: flex) and (pointer: coarse)) {
  .Item {
    display: inline-flex;
  }
}
```

这里我们使用了`and`关键字，但我们也可以使用`or`，或者用它来代替。例如，如果我们愿意在支持前两个属性/值组合或支持 3D 变换时应用样式：

```html
@supports ((display: flex) and (pointer: coarse)) or (transform: translate3d(0, 0, 0)) {
  .Item {
    display: inline-flex;
  }
}
```

请注意，在上一个示例中，额外的括号将灵活和指针条件与变换条件分开。

不幸的是，正如我之前提到的，对`@support`的支持远非普遍。哎呀！一个响应式网页设计师该怎么办？不要担心，有一个很棒的 JavaScript 工具完全能够应对这一挑战。

## Modernizr

在`@supports`在浏览器中得到更广泛实现之前，我们可以使用一个名为 Modernizr 的 JavaScript 工具。目前，这是促进代码分叉的最健壮的方式。

当在 CSS 中需要分叉时，我尝试采用渐进增强方法。渐进增强意味着从简单的可访问代码开始；至少为功能较弱的设备提供功能设计的代码。然后逐渐增强更强大的设备的代码。

### 提示

我们将在第十章中更详细地讨论渐进增强，*接近响应式网页设计*。

让我们看看如何使用 Modernizr 来促进渐进增强和分叉我们的 CSS 代码。

### 使用 Modernizr 进行特性检测

如果您是 Web 开发人员，很可能已经听说过 Modernizr，即使您可能尚未使用它。这是一个 JavaScript 库，您可以在页面中包含它来对浏览器进行特性测试。要开始使用 Modernizr，只需在页面的`head`部分包含指向下载文件的链接即可：

```html
<script src="img/modernizr-2.8.3-custom.min.js"></script>
```

有了这个，当浏览器加载页面时，任何包含的测试都会运行。如果浏览器通过了测试，Modernizr 会方便地（对我们的目的）向根 HTML 标签添加相关的类。

例如，Mondernizr 完成其任务后，页面的 HTML 标签上的类可能如下所示：

```html
<html class="js no-touch cssanimations csstransforms csstransforms3d csstransitions svg inlinesvg" lang="en">
```

在这种情况下，只测试了一些功能：动画，变换，SVG，内联 SVG 和对触摸的支持。有了这些类，代码可以被分叉，就像这样：

```html
.widget {
  height: 1rem;
}

.touch .widget {
  height: 2rem;
}
```

在上面的例子中，小部件项目通常只有 1rem 高，但如果 HTML 上存在触摸类（感谢 Modernizr），那么小部件将有 2rem 高。

我们也可以改变逻辑：

```html
.widget {
  height: 2rem;
}

.no-touch .widget {
  height: 1rem;
}
```

这样，我们将默认为项目高度为 2rem，并在出现`no-touch`类时调整高度。

无论您想如何构造结构，Modernizr 都提供了一种广泛支持的方式来分叉功能。当您想要使用`transform3d`等功能但仍为无法使用它的浏览器提供一个可用的替代品时，您会发现它特别有用。

### 提示

Modernizr 可以为您可能需要在其上分叉代码的大多数事物提供准确的测试，但并非所有事物都是如此。例如，溢出滚动通常很难进行准确测试。在设备类别不愉快的情况下，可能更有意义的是在不同的功能上分叉您的代码。例如，由于旧版 Android 版本难以进行水平滚动，您可能会使用`no-svg`进行分叉（因为 Android 2-2.3 也不支持 SVG）。

最后，您可能希望结合测试来创建自己的自定义测试。这有点超出了这里的范围，但如果这是您感兴趣的事情，请查看[`benfrain.com/combining-modernizr-tests-create-custom-convenience-forks/`](http://benfrain.com/combining-modernizr-tests-create-custom-convenience-forks/)。

# 新的 CSS3 选择器及其使用方法

CSS3 为在页面内选择元素提供了令人难以置信的能力。您可能认为这听起来并不那么花哨，但相信我，它会让您的生活变得更轻松，您会喜欢 CSS3 的！我最好对这个大胆的说法进行限定。

## CSS3 属性选择器

您可能已经使用 CSS 属性选择器创建规则。例如，考虑以下规则：

```html
img[alt] {
  border: 3px dashed #e15f5f;
}
```

这将针对标记中具有`alt`属性的任何图像标记。或者，假设我们想选择所有具有`data-sausage`属性的元素：

```html
[data-sausage] {
  /* styles */
}
```

您只需要在方括号中指定属性。

### 提示

`data-*`类型的属性是在 HTML5 中引入的，用于提供一个无法通过任何其他现有机制合理存储的自定义数据的位置。这些的规范描述可以在[`www.w3.org/TR/2010/WD-html5-20101019/elements.html`](http://www.w3.org/TR/2010/WD-html5-20101019/elements.html)找到。

您还可以通过指定属性值来缩小范围。例如，考虑以下规则：

```html
img[alt="sausages"] {
  /* Styles */
}
```

这将仅针对具有`alt`属性为`sausages`的图像。例如：

```html
<img class="oscarMain" src="img/sausages.png" alt="sausages" />
```

到目前为止，这听起来像是“我们在 CSS2 中也可以做到这一点”。CSS3 给派对带来了什么？

## CSS3 子字符串匹配属性选择器

CSS3 让我们根据其属性选择器的子字符串选择元素。听起来很复杂。其实不是！这三个选项是属性是否：

+   以前缀开始

+   包含一个实例

+   以后缀结束

让我们看看它们是什么样子的。

### “以...开始”的子字符串匹配属性选择器

考虑以下标记：

```html
<img src="img/ace-film.jpg" alt="film-ace">
<img src="img/rubbish-film.jpg" alt="film-rubbish">
```

我们可以使用“以...开始”的子字符串匹配属性选择器来选择这两个图像，就像这样：

```html
img[alt^="film"] {
    /* Styles */
}
```

所有这些中的关键字符都是`^`符号（该符号称为**caret**，尽管它也经常被称为“帽子”符号），意思是“以...开始”。因为两个`alt`标签都以`film`开头，我们的选择器选择了它们。

### “包含一个实例”的子字符串匹配属性选择器

'包含一个实例'子字符串匹配属性选择器的语法如下：

```html
[attribute*="value"] {
  /* Styles */
}
```

与所有属性选择器一样，如果需要，您可以将它们与类型选择器（引用实际使用的 HTML 元素）结合使用，尽管个人认为只有在必要时才这样做（以防您想要更改所使用的元素类型）。

让我们来试一个例子。考虑这个标记：

```html
<p data-ingredients="scones cream jam">Will I get selected?</p>
We can select that element like this:
[data-ingredients*="cream"] {
  color: red;
}
```

所有这些中的关键字符是`*`符号，在这种情况下表示“包含”。

'以...开头'选择器在这个标记中不起作用，因为属性中的字符串并没有以'cream'开头。但它确实*包含* 'cream'，因此'包含一个实例'子字符串属性选择器找到了它。

### '以...结尾'子字符串匹配属性选择器

“以...结尾”子字符串匹配属性选择器的语法如下：

```html
[attribute$="value"] {
  /* Styles */
}
```

一个例子应该有所帮助。考虑这个标记：

```html
<p data-ingredients="scones cream jam">Will I get selected?</p>
<p data-ingredients="toast jam butter">Will I get selected?</p>
<p data-ingredients="jam toast butter">Will I get selected?</p>
```

假设我们只想选择`data-ingredients`属性中包含 scones、cream 和 jam 的元素（第一个元素）。我们不能使用'包含一个实例'（它会选择所有三个）或'以...开头'（它只会选择最后一个）子字符串属性选择器。但是，我们可以使用'以...结尾'子字符串属性选择器。

```html
[data-ingredients$="jam"] {
color: red;
}
```

所有这些中的关键字符是`$`（美元）符号，表示“以...结尾”。

## 属性选择的陷阱

属性选择中有一个需要理解的“陷阱”：属性被视为单个字符串。考虑这个 CSS 规则：

```html
[data-film^="film"] {
  color: red;
}
```

也许让你惊讶的是，它不会选择这个，即使属性中的一个单词以`film`开头：

```html
<span data-film="awful moulin-rouge film">Moulin Rouge is dreadful</span>
```

这是因为这里的`data-film`属性不是以`film`开头的，在这种情况下它是以 awful 开头的（如果你看过《红磨坊》，你会知道它一开始就很糟糕，而且永远不会好转）。

除了我们刚才看到的子字符串匹配选择器，还有几种解决方法。您可以使用空格分隔选择器（注意波浪线符号），它一直支持到 Internet Explorer 7：

```html
[data-film~="film"] {
  color: red;
}
```

您可以选择整个属性：

```html
[data-film="awful moulin-rouge film"] {
  color: red;
}
```

或者，如果您只想根据属性中的一些字符串的存在来进行选择，您可以连接一对（或者需要的数量）'包含一个实例'子字符串属性选择器：

```html
[data-film*="awful"][data-film*="moulin-rouge"] {
  color: red;
}
```

在这方面没有“正确”的做法，这实际上取决于您尝试选择的字符串的复杂性。

## 属性选择器允许您选择以数字开头的 ID 和类

在 HTML5 之前，以数字开头的 ID 或类名是无效的标记。HTML5 取消了这一限制。在涉及 ID 时，仍然有一些事情需要记住。ID 名称中不应该有空格，并且在页面上必须是唯一的。有关更多信息，请访问[`www.w3.org/html/wg/drafts/html/master/dom.html`](http://www.w3.org/html/wg/drafts/html/master/dom.html)。

尽管在 HTML5 中可以以数字开头命名 ID 和类值，但 CSS 仍限制您不能使用以数字开头的 ID 和类选择器（[`www.w3.org/TR/CSS21/syndata.html`](http://www.w3.org/TR/CSS21/syndata.html)）。

幸运的是，我们可以通过使用属性选择器轻松解决这个问题。例如，`[id="10"]`。

# CSS3 结构伪类

CSS3 使我们能够更有力地选择基于 DOM 结构的元素。

让我们考虑一个常见的设计处理；我们正在为较大的视口设计导航栏，并且希望除了最后一个链接之外的所有链接都在左侧。

从历史上看，我们需要通过向最后一个链接添加类名来解决这个问题，以便我们可以选择它，就像这样：

```html
<nav class="nav-Wrapper">
  <a href="/home" class="nav-Link">Home</a>
  <a href="/About" class="nav-Link">About</a>
  <a href="/Films" class="nav-Link">Films</a>
  <a href="/Forum" class="nav-Link">Forum</a>
  <a href="/Contact-Us" class="nav-Link nav-LinkLast">Contact Us</a>
</nav>
```

这本身可能会有问题。例如，有时，让内容管理系统向最后一个列表项添加类可能会非常困难。幸运的是，在这种情况下，这不再是一个问题。我们可以使用 CSS3 结构伪类来解决这个问题以及许多其他问题。

## :last-child 选择器

CSS 2.1 已经有了一个适用于列表中第一项的选择器：

```html
div:first-child {
  /* Styles */
}
```

然而，CSS3 添加了一个选择器，也可以匹配最后一个：

```html
div:last-child {
  /* Styles */
}
```

让我们看看那个选择器如何解决我们之前的问题：

```html
@media (min-width: 60rem) {
  .nav-Wrapper {
    display: flex;
  }
  .nav-Link:last-child {
    margin-left: auto;
  }
}
```

还有一些有用的选择器，用于当某物是唯一的项目时：`:only-child`和唯一的类型：`:only-of-type`。

## nth-child 选择器

`nth-child`选择器让我们解决更困难的问题。使用与之前相同的标记，让我们考虑一下 nth-child 选择器如何允许我们选择列表中的任何链接。

首先，选择每隔一个列表项怎么样？我们可以这样选择奇数项：

```html
.nav-Link:nth-child(odd) {
  /* Styles */
}
```

或者，如果您想选择偶数：

```html
.nav-Link:nth-child(even) {
  /* Styles */
}
```

## 理解 nth 规则的作用

对于初学者来说，基于 nth 的选择器可能看起来很吓人。然而，一旦你掌握了逻辑和语法，你会惊讶于你可以用它们做什么。让我们来看看。

CSS3 用几个基于 nth 的规则给了我们令人难以置信的灵活性：

+   `nth-child(n)`

+   `nth-last-child(n)`

+   `nth-of-type(n)`

+   `nth-last-of-type(n)`

我们已经看到在基于 nth 的表达式中可以使用（奇数）或（偶数）值，但（n）参数还可以以另外两种方式使用：

作为整数；例如，`:nth-child(2)`将选择第二个项目

作为数字表达式；例如，`:nth-child(3n+1)`将从 1 开始，然后选择每三个元素

整数属性很容易理解，只需输入您想要选择的元素编号。

选择器的数字表达式版本对于普通人来说可能有点令人困惑。如果数学对你来说很容易，我为这一部分道歉。对于其他人，让我们来分解一下。

### 分解数学

让我们考虑页面上的 10 个 span（您可以通过查看`example_05-05`来玩弄这些）：

```html
<span></span>
<span></span>
<span></span>
<span></span>
<span></span>
<span></span>
<span></span>
<span></span>
<span></span>
<span></span>
```

默认情况下，它们的样式将是这样的：

```html
span {
  height: 2rem;
  width: 2rem;
  background-color: blue;
  display: inline-block;
}
```

正如你所想象的，这给了我们一行中的 10 个方块：

![分解数学](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_06.jpg)

好吧，让我们看看如何使用基于 nth 的选择来选择不同的项目。

为了实用性，当考虑括号内的表达式时，我从右边开始。所以，例如，如果我想弄清楚(2n+3)会选择什么，我从最右边的数字开始（这里的三表示从左边数第三个项目），并且知道它将从那一点开始选择每第二个元素。因此添加这个规则：

```html
span:nth-child(2n+3) {
  color: #f90;
  border-radius: 50%;
}
```

在浏览器中的结果：

![分解数学](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_07.jpg)

如您所见，我们的 nth 选择器目标是第三个列表项，然后是之后的每第二个列表项（如果有 100 个列表项，它将继续选择每第二个列表项）。

如何从第二个项目开始选择所有内容？虽然你可以写成`:nth-child(1n+2)`，但实际上你不需要第一个数字 1，因为除非另有说明，n 等于 1。因此，我们可以只写`:nth-child(n+2)`。同样，如果我们想选择每三个元素，而不是写成`:nth-child(3n+3)`，我们可以只写`:nth-child(3n)`，因为每三个项目都会从第三个项目开始，而不需要明确说明。表达式也可以使用负数，例如，`:nth-child(3n-2)`从-2 开始，然后选择每三个项目。

您还可以更改方向。默认情况下，一旦找到选择的第一部分，随后的选择将沿着 DOM 中的元素向下（因此在我们的示例中从左到右）。但是，您可以用减号来颠倒这一点。例如：

```html
span:nth-child(-2n+3) {
  background-color: #f90;
  border-radius: 50%;
}
```

这个例子再次找到第三个项目，然后沿着相反的方向选择每两个元素（在 DOM 树中向上，因此在我们的示例中从右到左）：

![分解数学](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_08.jpg)

希望基于 nth 的表达式现在完全合乎逻辑了？

`nth-child`和`nth-last-child`的区别在于`nth-last-child`变体是从文档树的相反端起作用的。例如，`:nth-last-child(-n+3)`从末尾开始的 3 开始，然后选择其后的所有项目。这是浏览器中该规则给我们的内容：

![分解数学](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_09.jpg)

最后，让我们考虑`：nth-of-type`和`：nth-last-of-type`。虽然前面的例子计算任何类型的子元素（始终记住`nth-child`选择器会选择同一 DOM 级别的所有子元素，而不管类），`：nth-of-type`和`：nth-last-of-type`让您可以具体指定要选择的项目类型。考虑以下标记（`example_05-06`）：

```html
<span class="span-class"></span>
<span class="span-class"></span>
<span class="span-class"></span>
<span class="span-class"></span>
<span class="span-class"></span>
<div class="span-class"></div>
<div class="span-class"></div>
<div class="span-class"></div>
<div class="span-class"></div>
<div class="span-class"></div>
```

如果我们使用了选择器：

```html
.span-class:nth-of-type(-2n+3) {
  background-color: #f90;
  border-radius: 50%;
}
```

尽管所有元素都具有相同的`span-class`，但实际上我们只会针对`span`元素（因为它们是首选类型）。这是被选中的内容：

![分解数学](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_10.jpg)

我们将看到 CSS4 选择器如何解决这个问题。

### 提示

**CSS3 不像 JavaScript 和 jQuery 那样计数！**

如果您习惯使用 JavaScript 和 jQuery，您会知道它从 0 开始计数（基于零索引）。例如，如果在 JavaScript 或 jQuery 中选择元素，整数值 1 实际上是第二个元素。然而，CSS3 从 1 开始，因此值为 1 的是它匹配的第一个项目。

## 响应式网页设计中的基于 nth 的选择

最后，让我们考虑一个真实的响应式网页设计问题，以及我们如何使用基于 nth 的选择来解决它。

还记得`example_05-02`中的水平滚动面板吗？让我们考虑一下在水平滚动不可能的情况下它可能会是什么样子。因此，使用相同的标记，让我们将 2014 年票房前十的电影变成网格。对于某些视口，网格将只有两个项目宽，随着视口的增加，我们显示三个项目，并且在更大的尺寸上，我们仍然显示四个。然而，这里有一个问题。无论视口大小如何，我们都希望防止底部的任何项目具有底部边框。您可以在`example_05-09`中查看此代码。

这是四个宽项目的外观：

![响应式网页设计中的基于 nth 的选择](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_12.jpg)

看到下面两个项目底部的烦人边框了吗？这就是我们需要移除的。但是，我希望有一个强大的解决方案，这样如果底部行还有另一个项目，边框也会被移除。现在，因为在不同的视口上每行的项目数量不同，我们还需要在不同的视口上更改基于 nth 的选择。为了简洁起见，我将向您展示匹配每行四个项目的选择（较大的视口）。您可以查看代码示例，以查看在不同视口上修改后的选择。

```html
@media (min-width: 55rem) {
  .Item {
    width: 25%; 
  }
  /*  Get me every fourth item and of those, only ones that are in the last four items */
  .Item:nth-child(4n+1):nth-last-child(-n+4),
  /* Now get me every one after that same collection too. */
  .Item:nth-child(4n+1):nth-last-child(-n+4) ~ .Item {
    border-bottom: 0;
  }
}
```

### 注意

您会注意到我们在链接基于 nth 的伪类选择器。重要的是要理解，第一个不会过滤下一个的选择，而是元素必须匹配每个选择。对于我们之前的例子，第一个元素必须是四个中的第一个项目，并且也必须是最后四个中的一个。

很好！由于基于 nth 的选择，我们有一套防御性规则，可以删除底部边框，而不管视口大小或我们显示的项目数量如何。

![响应式网页设计中的基于 nth 的选择](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_13.jpg)

## 否定（:not）选择器

另一个方便的选择器是否定伪类选择器。这用于选择除其他东西之外的所有内容。考虑这个：

```html
<div class="a-div"></div>
<div class="a-div"></div>
<div class="a-div"></div>
<div class="a-div not-me"></div>
<div class="a-div"></div>
```

然后这些样式：

```html
div {
  display: inline-block;
  height: 2rem;
  width: 2rem;
  background-color: blue;
}

.a-div:not(.not-me) {
  background-color: orange;
  border-radius: 50%;
}
```

我们的最终规则将使具有`.a-div`类的每个元素变为橙色和圆形，但`div`也具有`.not-me`类除外。您可以在代码示例的`example_05-07`文件夹中找到该代码（请记住，您可以在[`rwd.education/`](http://rwd.education/)上找到所有代码示例）。

### 提示

到目前为止，我们主要看了所谓的结构伪类（关于这方面的完整信息可在[`www.w3.org/TR/selectors/`](http://www.w3.org/TR/selectors/)找到）。然而，CSS3 还有许多其他选择器。如果你正在开发一个 Web 应用程序，值得查看完整的 UI 元素状态伪类列表（[`www.w3.org/TR/selectors/`](http://www.w3.org/TR/selectors/)），因为它们可以帮助你根据某些东西是否被选中来定位规则。

## 空的(:empty)选择器

我遇到过这样的情况，我有一个元素，在里面包含一些填充，并且动态插入内容。有时它会有内容，有时没有。问题是，当它不包含内容时，我仍然看到填充。考虑一下`example_05-08`中的 HTML 和 CSS：

```html
<div class="thing"></div>
.thing {
  padding: 1rem;
  background-color: violet;
}
```

在那个`div`中没有任何内容，我仍然看到`background-color`。幸运的是，我们可以很容易地隐藏它，就像这样：

```html
.thing:empty {
  display: none;
}
```

然而，要小心`:empty`选择器。例如，你可能认为这是空的：

```html
<div class="thing"> </div>
```

不是！看看里面的空白。空白不是没有空间！

然而，要让事情更加混乱，要知道评论不会影响元素是否有空白或不。例如，这仍然被认为是空的：

```html
<div class="thing"><!--I'm empty, honest I am--></div>
```

### 提示

**伪元素的修正**

伪元素自 CSS2 以来就存在，但 CSS3 规范对它们的使用语法进行了非常轻微的修订。为了提醒你，直到现在，`p:first-line`会定位`<p>`标签中的第一行。或者`p:first-letter`会定位第一个字母。然而，CSS3 要求我们用双冒号来区分这些伪元素和伪类（比如`nth-child()`）。因此，我们应该写成`p::first-letter`。然而，需要注意的是，Internet Explorer 8 及更低版本不理解双冒号语法，它们只理解单冒号语法。

## 无论视口如何，都对`:first-line`做一些事情

关于`:first-line`伪元素，你可能会发现一个特别方便的地方是它是特定于视口的。例如，如果我们写下以下规则：

```html
p::first-line {
  color: #ff0cff;
}
```

正如你所期望的，第一行呈现为一种可怕的粉色。然而，在不同的视口上，它呈现为不同的文本选择。

因此，不需要改变标记，使用响应式设计，有一种方便的方法可以使文本的第一行（如浏览器呈现的，而不是在标记中显示的）与其他行不同。

# CSS 自定义属性和变量

由于 CSS 预处理器的流行，CSS 开始获得一些更多的“编程”特性。其中之一是自定义属性。它们更常被称为变量，尽管这不一定是它们唯一的用例。你可以在[`dev.w3.org/csswg/css-variables/`](http://dev.w3.org/csswg/css-variables/)找到完整的规范。需要警告的是，截至 2015 年初，浏览器实现还很少（只有 Firefox）。

CSS 自定义属性允许我们在样式表中存储信息，然后可以在该样式表中利用或者通过 JavaScript 进行操作。一个明显的用例是存储字体系列名称，然后引用它。以下是我们创建自定义属性的方法：

```html
:root {
  --MainFont: 'Helvetica Neue', Helvetica, Arial, sans-serif;
}
```

在这里，我们使用`:root`伪类将自定义属性存储在文档根中（尽管你可以将它们存储在任何你喜欢的规则中）。

### 提示

`:root`伪类总是引用文档结构中最顶层的父元素。在 HTML 文档中，这总是 HTML 标签，但对于 SVG 文档（我们在第七章中看到 SVG，*使用 SVG 实现分辨率独立性*），它将引用不同的元素。

自定义属性总是以两个破折号开始，然后是自定义名称，然后是它的结束，就像 CSS 中的其他属性一样；用一个冒号表示。

我们可以用`var()`符号引用该值。就像这样：

```html
.Title {
  font-family: var(--MainFont);
}
```

你显然可以以这种方式存储尽可能多的自定义属性。这种方法的主要好处是，你可以更改变量内的值，而每个使用该变量的规则都会得到新的值，而无需直接修改它们。

预计将来这些属性可能会被 JavaScript 解析和利用。关于这种疯狂的东西，你可能会对新的 CSS 扩展模块感兴趣：

[`dev.w3.org/csswg/css-extensions/`](http://dev.w3.org/csswg/css-extensions/)

# CSS calc

你有多少次试图编写布局并想到类似“它需要是父元素宽度的一半减去 10 像素”这样的东西？这在响应式网页设计中特别有用，因为我们永远不知道将查看我们网页的屏幕大小。幸运的是，CSS 现在有了一种方法来做到这一点。它被称为`calc()`函数。以下是 CSS 中的示例：

```html
.thing {
  width: calc(50% - 10px);
}
```

加法、减法、除法和乘法都受支持，因此可以解决以前无法使用 JavaScript 解决的一系列问题。

浏览器支持相当不错，但一个值得注意的例外是 Android 4.3 及以下版本。请阅读规范：[`www.w3.org/TR/css3-values/`](http://www.w3.org/TR/css3-values/)。

# CSS 4 级选择器

CSS 选择器 4 级（最新版本是 2014 年 12 月 14 日的编辑草案，[`dev.w3.org/csswg/selectors-4/`](http://dev.w3.org/csswg/selectors-4/)）中规定了许多新的选择器类型。然而，就在我写这篇文章的时候，浏览器中还没有它们的实现。因此，我们只看一个例子，因为它们可能会发生变化。

关系伪类选择器来自“逻辑组合”（[`dev.w3.org/csswg/selectors-4/`](http://dev.w3.org/csswg/selectors-4/)）部分的最新草案。

## :has 伪类

这个选择器采用这种格式：

```html
a:has(figcaption) {
  padding: 1rem;
}
```

如果`a`标签包含`figcaption`，这将为任何`a`标签添加填充。你也可以与否定伪类结合来反转选择：

```html
a:not(:has(figcaption)) {
  padding: 1rem;
}
```

如果`a`标签不包含`figcaption`元素，这将添加填充。

我要诚实地说，现在在这份草案中，并没有太多新的选择器让我感到兴奋。但谁知道他们在开始在浏览器中使用之前会想出什么呢？

## 响应式视口百分比长度（vmax、vmin、vh、vw）

现在我们改变一下方向。我们已经看过如何在响应式世界中选择项目。但是如何调整它们的大小呢？CSS 值和单位模块 3 级（[`www.w3.org/TR/css3-values/`](http://www.w3.org/TR/css3-values/)）引入了视口相关单位。这对于响应式网页设计非常有用，因为每个单位都是视口的百分比长度：

+   vw 单位（视口宽度）

+   vh 单位（视口高度）

+   vmin 单位（视口最小值；等于 vw 或 vh 中较小的一个）

+   vmax（视口最大值；等于 vw 或 vh 中较大的一个）

浏览器支持也不错（[`caniuse.com/`](http://caniuse.com/)）。

想要一个模态窗口，它的高度是浏览器高度的 90%？这很容易：

```html
.modal {
  height: 90vh;
}
```

### 提示

视口相关单位虽然很有用，但一些浏览器的实现方式很奇怪。例如，iOS 8 中的 Safari 在你从页面顶部滚动时会改变可视屏幕区域（它会缩小地址栏），但不会对报告的视口高度进行任何更改。

然而，当与字体结合时，也许可以找到更多这些单位的实用性。例如，现在可以轻松创建根据视口大小而调整大小的文本。

现在，我可以立即向你展示。但是，我想使用一个不同的字体，这样无论你是在 Windows、Mac 还是 Linux 上查看示例，我们都能看到相同的东西。

好吧，我要诚实地说，这是一个廉价的手段，让我记录一下我们如何在 CSS3 中使用 Web 字体。

# 网络排版

多年来，网络一直不得不使用一些无聊的“网络安全”字体。当设计中必不可少的一些花哨的排版时，有必要用图形元素替代它，并使用文本缩进规则将实际文本从视口中移开。哦，快乐！

在这一过程中，还有一些创新的方法可以在页面上添加花哨的排版。sIFR（[`www.mikeindustries.com/blog/sifr/`](http://www.mikeindustries.com/blog/sifr/)）和 Cufón（[`cufon.shoqolate.com/generate/`](http://cufon.shoqolate.com/generate/)）分别使用 Flash 和 JavaScript 重新制作文本元素，使其显示为它们原本打算的字体。幸运的是，CSS3 提供了一种现在已经准备好大放异彩的自定义网络排版的方法。

## @font-face CSS 规则

`@font-face` CSS 规则自 CSS2 以来就存在（但随后在 CSS 2.1 中消失了）。甚至 Internet Explorer 4 部分支持它（不是吗）！那么，当我们应该谈论 CSS3 时，它在这里做什么呢？

事实证明，`@font-face`被重新引入到了 CSS3 字体模块中（[`www.w3.org/TR/css3-fonts`](http://www.w3.org/TR/css3-fonts)）。由于在网络上使用字体的历史法律泥潭，直到最近几年，它才开始作为网络排版的事实解决方案而受到严重关注。

与网页上涉及资产的任何内容一样，没有单一的文件格式。就像图像可以是 JPG、PNG、GIF 和其他格式一样，字体也有自己的一套可供选择的格式。嵌入式开放类型（扩展名为`.eot`的文件）字体是 Internet Explorer（而不是其他任何人）的首选。其他人更喜欢更常见的 TrueType（`.ttf`文件扩展名），同时还有 SVG 和 Web 开放字体格式（`.woff` / `.woff2`扩展名）。

现在，需要为不同的浏览器实现提供相同字体的多个文件版本。

然而，好消息是为每个浏览器添加每种自定义字体格式很容易。让我们看看如何！

## 使用@font-face 实现网络字体

CSS 提供了一个`@font-face`“at-rule”来引用在线字体，然后可以用于显示文本。

现在有许多查看和获取网络字体的好资源，包括免费和付费的。我个人最喜欢免费字体的是 Font Squirrel（[`www.fontsquirrel.com/`](http://www.fontsquirrel.com/)），尽管谷歌也提供免费网络字体，最终使用`@font-face`规则提供（[`www.google.com/webfonts`](http://www.google.com/webfonts)）。还有来自 Typekit（[`www.typekit.com/`](http://www.typekit.com/)）和 Font Deck（[`www.fontdeck.com/`](http://www.fontdeck.com/)）的优秀付费服务。

在这个练习中，我将下载 Roboto。它是后来 Android 手机使用的字体，所以如果你有其中之一，它会很熟悉。否则，你只需要知道它是一种可爱的界面字体，设计用于在小屏幕上非常易读。你可以在[`www.fontsquirrel.com/fonts/roboto`](http://www.fontsquirrel.com/fonts/roboto)上自己获取它。

### 注意

如果可以下载特定于您打算使用的语言的字体的“子集”，请这样做。这意味着由于不包含您不打算使用的语言的字形，结果文件大小将小得多。

下载了`@font-face`套件后，打开 ZIP 文件，里面有不同 Roboto 字体的文件夹。我选择了 Roboto Regular 版本，在该文件夹中，字体以各种文件格式（WOFF、TTF、EOT 和 SVG）存在，还有一个包含字体堆栈的`stylesheet.css`文件。例如，Roboto Regular 的规则如下：

```html
@font-face {
    font-family: 'robotoregular';
    src: url('Roboto-Regular-webfont.eot');
    src: url('Roboto-Regular-webfont.eot?#iefix') format('embedded-opentype'),
         url('Roboto-Regular-webfont.woff') format('woff'),
         url('Roboto-Regular-webfont.ttf') format('truetype'),
         url('Roboto-Regular-webfont.svg#robotoregular') format('svg');
    font-weight: normal;
    font-style: normal;
}
```

就像供应商前缀的工作方式一样，浏览器将应用来自该属性列表的样式（如果适用，较低的属性优先），并忽略它不理解的样式。这样，无论使用什么浏览器，都应该有一个可以使用的字体。

现在，尽管这段代码对于复制和粘贴的粉丝来说非常棒，但重要的是要注意字体存储的路径。例如，我倾向于从 ZIP 文件中复制字体并将其存储在一个名为`fonts`的文件夹中，该文件夹与我的`css`文件夹处于同一级别。因此，由于我通常将这个字体堆栈规则复制到我的主样式表中，我需要修改路径。因此，我的规则变成了：

```html
@font-face {
    font-family: 'robotoregular';
    src: url('../fonts/Roboto-Regular-webfont.eot');
    src: url('../fonts/Roboto-Regular-webfont.eot?#iefix') format('embedded-opentype'),
         url('../fonts/Roboto-Regular-webfont.woff') format('woff'),
         url('../fonts/Roboto-Regular-webfont.ttf') format('truetype'),
         url('../fonts/Roboto-Regular-webfont.svg#robotoregular') format('svg');
    font-weight: normal;
    font-style: normal;
}
```

然后只需设置正确的字体和重量（如果需要）即可为相关的样式规则设置正确的字体。看看`example_05-10`，它与`example_05-09`的标记相同，我们只是将这个`font-family`声明为默认值：

```html
body {
  font-family: robotoregular;
}
```

网络字体的一个额外好处是，如果合成文件使用与代码中使用的相同字体，您可以直接从合成文件中插入大小。例如，如果 Photoshop 中的字体大小为 24px，我们可以直接插入该值，或者将其转换为更灵活的单位，如 REM（假设根字体大小为 16px，24/16=1.5rem）。

然而，正如我之前提到的，现在我们可以使用视口相对大小。我们可以在这里使用它们，以便根据视口空间的大小来调整文本的大小。

```html
body {
  font-family: robotoregular;
  font-size: 2.1vw;
}

@media (min-width: 45rem) {
  html,
  body {
    max-width: 50.75rem;
    font-size: 1.8vw;
  }
}

@media (min-width: 55rem) {
  html,
  body {
    max-width: 78.75rem;
    font-size: 1.7vw;
  }
}
```

如果您在浏览器中打开该示例并调整视口大小，您会看到只需几行 CSS，我们就可以使文本按照可用空间进行缩放。美妙！

## 关于自定义@font-face 排版和响应式设计的说明

网络排版的`@font-face`方法总体上非常好。在使用响应式设计技术时需要注意的唯一注意事项是字体文件的大小。例如，如果设备需要渲染我们示例的 Roboto Regular 的 SVG 字体格式，它需要额外获取 34 KB，而使用标准的网络安全字体（如 Arial）则不需要。我们在示例中使用了英文子集来减小文件大小，但这并不总是一个选项。如果您希望获得最佳的网站性能，请务必检查自定义字体的大小，并谨慎使用。

# 新的 CSS3 颜色格式和 alpha 透明度

到目前为止，在本章中，我们已经看到 CSS3 如何赋予我们新的选择能力，并使我们能够向设计中添加自定义排版。现在，我们将看看 CSS3 允许我们以前根本不可能的方式处理颜色的方法。

首先，CSS3 提供了两种声明颜色的新方法：RGB 和 HSL。此外，这两种格式使我们能够在它们旁边使用 alpha 通道（分别为 RGBA 和 HSLA）。

## RGB 颜色

**红色、绿色和蓝色**（**RGB**）是一个存在几十年的着色系统。它通过为颜色的红色、绿色和蓝色分量定义不同的值来工作。例如，红色可以在 CSS 中定义为十六进制值`#fe0208`：

```html
.redness {
  color: #fe0208;
}
```

### 提示

关于如何更直观地理解十六进制值的出色文章，我可以推荐 Smashing Magazine 上的这篇博文：[`www.smashingmagazine.com/2012/10/04/the-code-side-of-color/`](http://www.smashingmagazine.com/2012/10/04/the-code-side-of-color/)

然而，使用 CSS3，该颜色同样可以用 RGB 值来描述：

```html
.redness {
  color: rgb(254, 2, 8);
}
```

大多数图像编辑应用程序在其颜色选择器中以 HEX 和 RGB 值显示颜色。例如，Photoshop 的颜色选择器显示了 R、G 和 B 框，显示了每个通道的值。例如，R 值可能是 254，G 值为 2，B 值为 8。这很容易转换为 CSS 的`color`属性值。在 CSS 中，定义颜色模式（例如 RGB）后，红色、绿色和蓝色的值以逗号分隔的顺序放在括号内（就像我们在之前的代码中所做的那样）。

## HSL 颜色

除了 RGB，CSS3 还允许我们将颜色值声明为**色调、饱和度和亮度**（**HSL**）。

### 提示

**HSL 不同于 HSB！**

不要犯错误认为图像编辑应用程序（如 Photoshop）中的颜色选择器中显示的**色调、饱和度和亮度**（**HSB**）值与 HSL 相同-它并不相同！

HSL 如此令人愉快的原因在于，根据给定的值，很容易理解将表示的颜色。例如，除非你是某种颜色选择忍者，否则我敢打赌你无法立即告诉我 rgb(255, 51, 204)是什么颜色？没有人？我也不知道。然而，告诉我 hsl(315, 100％, 60％)的值，我可以猜测它在品红色和红色之间（实际上是一种节日粉色）。我怎么知道的？很简单。

HSL 基于 360°的色轮。它看起来像这样：

![HSL 颜色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_05_15.jpg)

HSL 颜色定义中的第一个数字代表色调。从我们的色轮上可以看到，黄色在 60°，绿色在 120°，青色在 180°，蓝色在 240°，品红色在 300°，最后红色在 360°。因此，如上述 HSL 颜色的色调为 315，很容易知道它将在品红色（在 300°）和红色（在 360°）之间。

HSL 定义中的后两个值是饱和度和亮度，以百分比表示。这些只是改变基本色调。要获得更饱和或“色彩丰富”的外观，请在第二个值中使用更高的百分比。控制亮度的最终值可以在 0％至 100％之间变化，0％表示黑色，100％表示白色。

因此，一旦您将颜色定义为 HSL 值，仅通过改变饱和度和亮度百分比就可以轻松创建变化。例如，我们的红色可以用以下 HSL 值来定义：

```html
.redness {
  color: hsl(359, 99%, 50%);
}
```

如果我们想要制作稍暗一些的颜色，我们可以使用相同的 HSL 值，仅改变亮度（最终值）百分比值：

```html
.darker-red {
  color: hsl(359, 99%, 40%);
}
```

总之，如果你能记住“年轻人可以是混乱的顽童”（或者你想记住的任何其他助记符）的话，你就能大致写出 HSL 颜色值，而不需要使用取色器，并且还可以创建变化。在办公室派对上向 Ruby、Node 和.NET 的聪明人展示这个技巧，赢得一些快速的赞赏吧！

## Alpha 通道

到目前为止，你可能会想为什么我们要使用 HSL 或 RGB 而不是多年来一直在使用的可靠的 HEX 值。HSL 和 RGB 与 HEX 的不同之处在于它们允许使用 alpha 透明通道，因此元素下面的东西可以透过来。

HSLA 颜色声明在语法上类似于标准的 HSL 规则。但是，除此之外，您必须将值声明为`hsla`（而不仅仅是`hsl`），并添加一个额外的不透明度值，以十进制值表示，介于 0（完全透明）和 1（完全不透明）之间。例如：

```html
.redness-alpha {
  color: hsla(359, 99%, 50%, .5);
}
```

RGBA 语法遵循与 HSLA 等效项相同的约定：

```html
.redness-alpha-rgba {
  color: rgba(255, 255, 255, 0.8);
}
```

### 提示

**为什么不直接使用不透明度？**

CSS3 还允许使用 opacity 声明设置元素的不透明度。值在 0 和 1 之间以十进制增量设置（例如，设置为 0.1 的不透明度为 10％）。然而，这与 RGBA 和 HSLA 不同之处在于，在元素上设置不透明度值会影响整个元素。而使用 HSLA 或 RGBA 设置值与此同时允许元素的特定部分具有 alpha 层。例如，一个元素可以具有背景的 HSLA 值，但其中的文本为纯色。

## 使用 CSS 颜色模块 4 进行颜色操作

尽管在非常早期的规范阶段，但在不久的将来，通过使用`color()`函数在 CSS 中进行颜色操作应该是可能的。

在有广泛的浏览器支持之前，最好由 CSS 预处理器/后处理器来处理这种情况（给自己一个忠告，立即买一本关于这个主题的书；我推荐那位了不起的人 Ben Frain 的《面向设计师的 Sass 和 Compass》）。

您可以在[`dev.w3.org/csswg/css-color-4/`](http://dev.w3.org/csswg/css-color-4/)上关注 CSS 颜色模块 4 的进展。

# 总结

在本章中，我们已经学会了如何使用 CSS3 的新选择器轻松地选择几乎我们在页面上需要的任何东西。我们还看到了如何可以快速制作响应式的列和滚动面板，以解决常见且令人讨厌的问题，比如长 URL 换行。我们现在也了解了 CSS3 的新颜色模块，以及如何使用 RGB 和 HSL 应用颜色，包括透明的 alpha 层，以产生出色的美学效果。

在本章中，我们还学会了如何使用`@font-face`规则将网络排版添加到设计中，最终摆脱了单调的网络安全字体的束缚。尽管有了所有这些新特性和技术，我们只是触及了 CSS3 的潜力表面。让我们继续前进，看看 CSS3 如何通过文本阴影、盒子阴影、渐变和多重背景等方式，使响应式设计尽可能快速、高效和易于维护。


# 第六章：使用 CSS3 创建令人惊叹的美学效果

CSS3 的美学特性在响应式设计中非常有用，因为使用 CSS3 可以在许多情况下替换图像。这可以节省时间，使您的代码更易维护和灵活，并且减少了最终用户的页面“重量”。即使在典型的固定宽度桌面设计中，这些好处也是有用的，但在响应式设计中更加重要，因为在这些情况下使用 CSS 可以轻松地在不同的视口上创建不同的美学效果。

在本章中，我们将涵盖：

+   如何使用 CSS3 创建文本阴影

+   如何使用 CSS3 创建框阴影

+   如何使用 CSS3 创建渐变背景

+   如何使用 CSS3 创建多个背景

+   使用 CSS3 背景渐变创建图案

+   如何使用媒体查询实现高分辨率背景图像

+   如何使用 CSS 滤镜（以及它们的性能影响）

让我们深入了解。

### 提示

**供应商前缀**

在实现实验性的 CSS 时，只需记住通过工具添加相关的供应商前缀，而不是手动添加。这可以确保最广泛的跨浏览器兼容性，并且也可以避免添加不再需要的前缀。在大多数章节中，我都提到了 Autoprefixer（[`github.com/postcss/autoprefixer`](https://github.com/postcss/autoprefixer)），因为在撰写本文时，我认为它是最好的工具。

# 使用 CSS3 创建文本阴影

CSS3 中最广泛实现的功能之一是`text-shadow`。与`@font-face`一样，它曾经存在过，但在 CSS 2.1 中被删除了。幸运的是，它现在又回来了，并得到了广泛支持（适用于所有现代浏览器和 Internet Explorer 9 及以上版本）。让我们来看一下基本的语法：

```html
.element {
    text-shadow: 1px 1px 1px #ccc;
}
```

请记住，简写规则中的值总是向右和向下排列（或者如果您喜欢，可以认为是顺时针）。因此，第一个值是阴影向右的量，第二个是向下的量，第三个值是模糊的量（阴影在消失之前移动的距离），最后一个值是颜色。

可以使用负值来实现左侧和上方的阴影。例如：

```html
.text {
    text-shadow: -4px -4px 0px #dad7d7;
}
```

颜色值不需要定义为十六进制值。它同样可以是 HSL(A)或 RGB(A)：

```html
text-shadow: 4px 4px 0px hsla(140, 3%, 26%, 0.4);
```

但请记住，浏览器必须同时支持 HSL/RGB 颜色模式和`text-shadow`才能呈现效果。

您还可以使用任何其他有效的 CSS 长度单位来设置阴影值，例如 em、rem、ch、rem 等。就个人而言，我很少使用 em 或 rem 单位来设置`text-shadow`值。因为这些值总是非常低，使用 1px 或 2px 通常在所有视口上看起来都不错。

由于媒体查询，我们还可以轻松地在不同的视口尺寸下移除文本阴影。关键在于 none 值：

```html
.text {
    text-shadow: .0625rem .0625rem 0 #bfbfbf;
}
@media (min-width: 30rem) {
    .text {
        text-shadow: none;
    }
}
```

### 提示

另外，值得知道的是，在 CSS 中，如果一个值以零开头，比如 0.14s，就不需要写前导零：.14s 和 0.14s 是完全相同的。

## 在不需要时省略模糊值

如果`text-shadow`不需要添加模糊，可以从声明中省略该值，例如：

```html
.text {
    text-shadow: -4px -4px #dad7d7;
}
```

这是完全有效的。如果没有声明第三个值，浏览器会假定前两个值是偏移量。

## 多个文本阴影

可以通过逗号分隔两个或多个阴影来添加多个文本阴影。例如：

```html
.multiple {
    text-shadow: 0px 1px #fff,4px 4px 0px #dad7d7;
}
```

此外，由于 CSS 对空白字符宽容，如果有助于可读性，您可以像这样布置值：

```html
.text { 
    font-size: calc(100vmax / 40); /* 100 of vh or vw, whichever is larger divided by 40 */
    text-shadow: 
    3px 3px #bbb, /* right and down */
    -3px -3px #999; /* left and up */
}
```

### 提示

您可以在[`www.w3.org/TR/css3-text/`](http://www.w3.org/TR/css3-text/)上阅读`text-shadow`属性的 W3C 规范。

# 框阴影

框阴影允许您在应用到元素的外部或内部创建一个框形阴影。一旦了解了文本阴影，框阴影就很简单了；基本上，它们遵循相同的语法：水平偏移、垂直偏移、模糊、扩展（我们稍后会讨论扩展），以及颜色。

只需要四个可能的长度值中的两个（在没有最后两个的情况下，颜色的值定义阴影颜色，模糊半径使用零值）。让我们看一个简单的例子：

```html
.shadow {
    box-shadow: 0px 3px 5px #444;
}
```

默认的 box-shadow 设置在元素的外部。另一个可选的关键字，inset，允许在元素内部应用 box-shadow。

## 内部阴影

box-shadow 属性也可以用来创建内部阴影。语法与普通的盒子阴影相同，只是值以关键字 inset 开头：

```html
.inset {
    box-shadow: inset 0 0 40px #000;
}
```

一切都像以前一样运作，但声明的`inset`部分指示浏览器在内部设置效果。如果你看 example_06-01，你会看到每种类型的例子：

![内部阴影](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_01.jpg)

## 多个阴影

像 text-shadow 一样，您可以应用多个 box-shadow。用逗号分隔 box-shadow，它们按照从底部到顶部（最后到第一个）的顺序应用，如它们在列表中列出的那样。通过想到规则（在代码中）中最接近顶部的声明在浏览器中显示时出现在顺序的“顶部”，来提醒自己顺序。与 text-shadow 一样，您可能会发现使用空格在视觉上堆叠不同的 box-shadow 很有用：

```html
box-shadow: inset 0 0 30px hsl(0, 0%, 0%), 
            inset 0 0 70px hsla(0, 97%, 53%, 1);
```

### 提示

在代码中堆叠更长的、多个值，一个在另一个下面，当使用版本控制系统时有一个额外的好处；它使得在“diff”两个文件版本时更容易发现差异。这就是我将选择器组堆叠在一起的主要原因。

## 理解扩展

说实话，多年来我并没有真正理解 box-shadow 的扩展值到底是做什么的。我认为“扩展”这个名字并不有用。把它想象成一个偏移更有帮助。让我解释一下。

看看 example_06-02 中左边的盒子。这是应用了标准的 box-shadow。右边的盒子应用了负的扩展值。它是用第四个值设置的。这是相关的代码：

```html
.no-spread {
  box-shadow: 0 10px 10px;
}

.spread {
  box-shadow: 0 10px 10px -10px;
}
```

这是每个效果（右边带有扩展值的元素）：

![理解扩展](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_02.jpg)

扩展值允许您按指定的数量在所有方向上扩展或收缩阴影。在这个例子中，负值将阴影向后拉。结果是我们只在底部看到阴影，而不是在所有方向看到模糊“泄漏”出来（因为负的扩展值正在抵消模糊）。

### 注意

您可以在[`www.w3.org/TR/css3-background/`](http://www.w3.org/TR/css3-background/)阅读 box-shadow 属性的 W3C 规范。

# 背景渐变

过去的日子里，要在元素上实现背景渐变，需要平铺一个薄的渐变图形切片。作为图形资源，这是一个相当经济的权衡。一张只有一两个像素宽的图像不会耗尽带宽，在单个站点上可以用于多个元素。

然而，如果我们需要调整渐变，仍然需要往返到图形编辑器。而且，偶尔，内容可能会“突破”渐变背景，超出图像的固定大小限制。这个问题在响应式设计中更加严重，因为页面的部分可能在不同的视口上增加。

然而，使用 CSS 背景图像渐变，事情要灵活得多。作为 CSS 图像值和替换内容模块 3 级的一部分，CSS 使我们能够创建线性和径向背景渐变。让我们看看如何定义它们。

### 提示

CSS 图像值和替换内容模块 3 级的规范可以在[`www.w3.org/TR/css3-images/`](http://www.w3.org/TR/css3-images/)找到。

## 线性渐变符号

线性渐变符号，在其最简单的形式中，看起来像这样：

```html
.linear-gradient {
    background: linear-gradient(red, blue); 
}
```

这将创建一个线性渐变，从红色开始（默认从顶部开始）到蓝色。

### 指定渐变方向

现在，如果您想为梯度指定一个方向，有几种方法。梯度将始终从您发送它的相反方向开始。但是，当没有设置方向时，梯度将始终默认为从上到下的方向。例如：

```html
.linear-gradient {
    background: linear-gradient(to top right, red, blue); 
}
```

在这种情况下，梯度朝右上方。它从左下角开始是红色，逐渐变为右上角的蓝色。

如果你更喜欢数学，你可能会认为写梯度会像这样：

```html
.linear-gradient {
    background: linear-gradient(45deg, red, blue); 
}
```

但是，请记住，在矩形框上，一个梯度向'右上方'（始终是应用于的元素的右上方）的梯度将以与`45deg`（始终是从其起始点开始的 45 度）略有不同的位置结束。

值得知道的是，您还可以在盒子内部可见之前开始梯度。例如：

```html
.linear-gradient {
    background: linear-gradient(red -50%, blue); 
}
```

这将呈现一个梯度，就好像它在盒子内部甚至在可见之前就开始了。

实际上，在上一个例子中，我们使用了一个颜色停止来定义颜色应该开始和结束的位置，所以让我们更全面地看一下。

### 颜色停止

背景梯度最方便的地方可能是颜色停止。它们提供了在梯度中设置哪种颜色在哪一点使用的方法。使用颜色停止，您可以指定您可能需要的复杂性。考虑这个例子：

```html
.linear-gradient {
  margin: 1rem;  
  width: 400px;
  height: 200px;
  background: linear-gradient(#f90 0, #f90 2%, #555 2%, #eee 50%, #555 98%, #f90 98%, #f90 100%);
}
```

这是`linear-gradient`的呈现方式：

![颜色停止](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_03.jpg)

在这个例子（`example_06-03`）中，没有指定方向，因此默认的从上到下的方向适用。

梯度内的颜色停止以逗号分隔，并通过给出首先颜色，然后停止的位置来定义。通常建议不要在一个符号中混合使用单位，但您可以。您可以拥有尽可能多的颜色停止，并且颜色可以写为关键字、HEX、RGBA 或 HSLA 值。

### 提示

请注意，多年来已经有许多不同的背景梯度语法，因此这是一个特别难以手工编写回退的领域。冒着听起来像是一张破碎的唱片的风险（孩子们，如果你不知道'唱片'是什么，请问爸爸妈妈），使用诸如 Autoprefixer 之类的工具可以让您的生活更轻松。这样，您可以编写当前的 W3C 标准语法（如前面详细介绍的）并自动为您创建之前的版本。

阅读 W3C 规范，了解线性背景梯度[`www.w3.org/TR/css3-images/`](http://www.w3.org/TR/css3-images/)。

### 为旧版浏览器添加回退

作为旧版浏览器的简单回退，只需首先定义一个纯色背景。这样，旧版浏览器将至少在不理解后面定义的梯度时呈现一个纯色背景。例如：

```html
.thing {
  background: red;
  background: linear-gradient(45deg, red, blue); 
}
```

## 径向背景梯度

在 CSS 中创建径向梯度同样简单。这些通常从一个中心点开始，并以椭圆或圆形平滑地扩展开来。

这是径向背景梯度的语法（您可以在`example_06-04`中进行操作）：

```html
.radial-gradient {  
    margin: 1rem;
    width: 400px;
    height: 200px;
    background: radial-gradient(12rem circle at bottom,  yellow, orange, red);
}
```

### 径向梯度语法的分解

在指定属性（`background:`）之后，我们开始`radial-gradient`符号。首先，在第一个逗号之前，我们定义梯度的形状或大小和位置。我们上面使用了 12rem 圆形来定义形状和大小，但考虑一些其他例子：

+   `5em`将是一个尺寸为 5em 的圆。如果只给出尺寸，可以省略'circle'部分。

+   `circle`将是容器的完整尺寸的圆形（如果省略，则径向梯度的大小默认为'最远的角' - 关于尺寸关键字的更多信息）

+   `40px 30px`将是一个椭圆，就像在一个 40px 宽，30px 高的框内绘制一样

+   `ellipse`将创建一个椭圆形状，适合元素内

接下来，在尺寸和/或形状之后，我们定义位置。默认位置是中心，但让我们看看其他可能性以及它们如何定义：

+   **在右上方** 从右上方开始径向渐变

+   **在右侧 100px 顶部 20px** 从右侧边缘 100px 和顶部边缘 20px 开始渐变

+   **在左侧中心** 从元素的左侧中间开始

我们以逗号结束我们的大小、形状和位置 '参数'，然后定义任何颜色停止；它们的工作方式与 `linear-gradient` 完全相同。

为了简化表示：在第一个逗号之前是大小、形状和位置，然后在其后是尽可能多的颜色停止（每个停止之间用逗号分隔）。

## 响应式尺寸的方便 'extent' 关键字

对于响应式工作，您可能会发现按比例调整渐变的大小比使用固定像素尺寸更有优势。这样，当元素的大小发生变化时，您就知道自己已经覆盖到了（从字面上和比喻上）。有一些方便的尺寸关键字可以应用于渐变。您可以像这样写它们，而不是使用任何尺寸值：

```html
background: radial-gradient(closest-side circle at center, #333, blue);
```

以下是它们各自的作用：

+   `closest-side`: 形状与盒子最靠近中心的边相遇（对于圆形），或者与最靠近中心的水平和垂直边相遇（对于椭圆）。

+   `closest-corner`: 形状与盒子的最近角完全相遇

+   `farthest-side`: 与 `closest-side` 相反，不是形状与最近的边相遇，而是大小与离其中心最远的边相遇（或在椭圆的情况下，与最远的垂直和水平边相遇）。

+   `farthest-corner`: 形状扩展到盒子的中心到最远角

+   `cover`: 与 `farthest-corner` 相同

+   `contain`: 与 `closest-side` 相同

阅读 W3C 规范，了解径向背景渐变 [`www.w3.org/TR/css3-images/`](http://www.w3.org/TR/css3-images/)。

### 提示

**完美的 CSS3 线性和径向渐变的快捷方法**

如果手动定义渐变看起来很费力，那么有一些很棒的在线渐变生成器。我个人最喜欢的是 [`www.colorzilla.com/gradient-editor/`](http://www.colorzilla.com/gradient-editor/)。它使用图形编辑器风格的 GUI，允许您选择颜色、停止、渐变样式（支持线性和径向渐变），甚至是您想要最终渐变的颜色空间（HEX、RGB(A)、HSL(A)）。还有很多预设的渐变可用作起点。如果这还不够，它甚至为您提供了可选的代码，用于修复 Internet Explorer 9 以显示渐变和为旧版浏览器提供备用的纯色。还不确定？那么您是否能够根据现有图像中的渐变值生成 CSS 渐变？我想这可能会说服您。

# 重复渐变

CSS3 还赋予了我们创建重复背景渐变的能力。让我们看看它是如何完成的：

```html
.repeating-radial-gradient {
    background: repeating-radial-gradient(black 0px, orange 5px, red 10px);
}
```

这就是它的样子（不要看太久，可能会引起恶心）：

![重复渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_04.jpg)

首先，用重复前缀 `linear-gradient` 或 `radial-gradient`，然后它遵循与正常渐变相同的语法。在这里，我使用了黑色、橙色和红色之间的像素距离（分别为 0px、5px 和 10px），但您也可以选择使用百分比。为了获得最佳效果，建议在渐变中使用相同的测量单位（如像素或百分比）。

### 注意

阅读 W3C 关于重复渐变的信息 [`www.w3.org/TR/css3-images/`](http://www.w3.org/TR/css3-images/)。

还有一种使用背景渐变的方法我想和你分享。

# 背景渐变图案

尽管我经常在设计中使用微妙的线性渐变，但对于径向渐变和重复渐变的实际用途较少。然而，聪明的人们已经利用渐变的力量来创建背景渐变图案。让我们看一个来自 CSS 忍者 Lea Verou 的 CSS3 背景图案集合的例子，可在[`lea.verou.me/css3patterns/`](http://lea.verou.me/css3patterns/)上找到。

```html
.carbon-fibre {
    margin: 1rem;  
    width: 400px;
    height: 200px;
    background:
    radial-gradient(black 15%, transparent 16%) 0 0,
    radial-gradient(black 15%, transparent 16%) 8px 8px,
    radial-gradient(rgba(255,255,255,.1) 15%, transparent 20%) 0 1px,
    radial-gradient(rgba(255,255,255,.1) 15%, transparent 20%) 8px 9px;
    background-color:#282828;
    background-size:16px 16px;
}
```

这是在浏览器中得到的效果，一个`carbon-fibre`背景效果：

![背景渐变图案](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_05.jpg)

怎么样？只需几行 CSS3 代码，我们就有了一个易于编辑、响应式和可伸缩的背景图案。

### 提示

您可能会发现在规则的末尾添加`background-repeat: no-repeat`会更好地理解它的工作原理。

与往常一样，借助媒体查询，可以针对不同的响应式场景使用不同的声明。例如，尽管渐变图案在较小的视口上可能效果很好，但在较大的视口上最好使用纯色背景：

```html
@media (min-width: 45rem) {
    .carbon-fibre {
        background: #333;
    }
}
```

您可以在`example_06-05`中查看此示例。

# 多重背景图像

尽管现在有点过时，但过去构建页面时通常需要在页面顶部和底部使用不同的背景图像，或者在页面内的内容部分使用不同的背景图像。在 CSS2.1 时代，通常需要额外的标记（一个用于页眉背景，另一个用于页脚背景）来实现这种效果。

使用 CSS3，您可以在元素上堆叠尽可能多的背景图像。

以下是语法：

```html
.bg {
    background: 
        url('../img/1.png'),
        url('../img/2.png'),
        url('../img/3.png');
}
```

与多个阴影的堆叠顺序一样，首先列出的图像在浏览器中最靠近顶部。如果愿意，您还可以在同一声明中添加背景的一般颜色，如下所示：

```html
.bg {
    background: 
    url('../img/1.png'),
    url('../img/2.png'),
    url('../img/3.png') left bottom, black;
}
```

最后指定颜色，这将显示在上面指定的每个图像下面。

### 提示

在指定多个背景元素时，您不必将不同的图像堆叠在不同的行上；我只是发现这种写法更容易阅读代码。

不理解多重背景规则的浏览器（如 Internet Explorer 8 及更低版本）将完全忽略该规则，因此您可能希望在 CSS3 多重背景规则之前立即声明一个“正常”的背景属性，作为非常老的浏览器的后备。

使用多个背景图像时，只要使用带有透明度的 PNG 文件，任何部分透明的背景图像都会显示在另一个背景图像下面。但是，背景图像不必彼此叠放，也不必都是相同的尺寸。

## 背景大小

要为每个图像设置不同的尺寸，请使用`background-size`属性。当使用多个图像时，语法如下：

```html
.bg {
    background-size: 100% 50%, 300px 400px, auto;
}
```

每个图像的尺寸值（首先是宽度，然后是高度）都是按照在背景属性中列出的顺序，用逗号分隔声明的。与上面的示例一样，您可以在每个图像旁边使用百分比或像素值，以及以下内容：

+   `auto`：将元素设置为其本机大小

+   `cover`：将图像扩展，保持其纵横比，以覆盖元素的区域

+   `contain`：将图像扩展到元素内适应其最长的一侧，同时保持纵横比

## 背景位置

如果您有不同尺寸的不同背景图像，接下来您会希望能够以不同的方式定位它们。幸运的是，`background-position`属性也可以实现这一点。

让我们将所有这些背景图像功能与我们在之前章节中看到的一些响应式单位放在一起。

让我们创建一个简单的太空场景，由一个单一元素和三个背景图像组成，设置为三种不同的尺寸，并以三种不同的方式定位：

```html
.bg-multi {
    height: 100vh;
    width: 100vw;
    background:
        url('rosetta.png'), 
        url('moon.png'),
        url('stars.jpg');
    background-size: 75vmax, 50vw, cover;
    background-position: top 50px right 80px, 40px 40px, top center;
    background-repeat: no-repeat;
}
```

您将在浏览器中看到类似于这样的东西：

![背景位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_06.jpg)

我们在底部有星星图片，然后是顶部的月亮，最后是顶部的罗塞塔空间探测器的图片。您可以在`example_06-06`中自行查看。请注意，如果调整浏览器窗口，响应式长度单位（`vmax`，`vh`和`vw`）可以很好地工作，并保持比例，而基于像素的单位则不行。

### 注意

如果没有声明`background-position`，则会应用默认位置为左上角。

## 背景简写

有一种简写方法可以将不同的背景属性组合在一起。您可以在[`www.w3.org/TR/css3-background/`](http://www.w3.org/TR/css3-background/)的规范中阅读它。然而，到目前为止，我的经验是它会产生不稳定的结果。因此，我建议使用长格式方法，先声明多个图像，然后是大小，然后是位置。

### 注意

阅读 W3C 关于多个背景元素的文档，网址为[`www.w3.org/TR/css3-background/`](http://www.w3.org/TR/css3-background/)。

# 高分辨率背景图片

由于媒体查询，我们可以加载不同的背景图片，不仅在不同的视口大小，还在不同的视口分辨率下。

例如，这是为'普通'和高 DPI 屏幕指定背景图片的官方方式。您可以在`example_06-07`中找到这个：

```html
.bg {
    background-image: url('bg.jpg');
}
@media (min-resolution: 1.5dppx) {
    .bg {
        background-image: url('bg@1_5x.jpg');
    }
}
```

媒体查询的编写方式与宽度、高度或其他能力测试一样。在这个例子中，我们定义了`bg@1_5x.jpg`应该使用的最小分辨率为 1.5dppx（每个 CSS 像素的设备像素）。如果需要的话，我们也可以使用**dpi**（每英寸点数）或**dpcm**（每厘米点数）单位。然而，尽管支持较差，我发现 dppx 是最容易理解的单位；因为 2dppx 是两倍的分辨率，3dppx 将是三倍的分辨率。在 dpi 中考虑这一点就比较棘手。'标准'分辨率将是 96dpi，两倍分辨率将是 192dpi，依此类推。

目前对于'dppx'单位的支持并不是很好（在[`caniuse.com/`](http://caniuse.com/)上检查您的目标浏览器），因此为了使其在各处都能平稳运行，您需要编写几个版本的媒体查询分辨率，或者像往常一样，依赖工具来为您添加前缀。

### 提示

**关于性能的简短说明**

只需记住，大图像可能会减慢您网站的速度，并导致用户体验不佳。虽然背景图片不会阻止页面的渲染（在等待背景图片时，您仍然会看到页面的其余部分被绘制到页面上），但它会增加页面的总重量，这对于用户支付数据来说很重要。

# CSS 滤镜

`box-shadow`存在一个明显的问题。正如其名称所暗示的那样，它仅限于应用于元素的矩形 CSS 框形状。这是一个使用 CSS 制作的三角形形状的屏幕截图（您可以在`example_06-08`中查看代码），应用了一个框阴影：

![CSS filters](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_07.jpg)

并不完全是我所希望的。幸运的是，我们可以通过 CSS 滤镜来解决这个问题，这是 Filter Effects Module Level 1 的一部分（[`www.w3.org/TR/filter-effects/`](http://www.w3.org/TR/filter-effects/)）。它们的支持并不像`box-shadow`那样广泛，但在渐进增强的方法中效果很好。如果浏览器不理解如何处理滤镜，它就会简单地忽略它。对于支持滤镜的浏览器，这些花哨的效果会被渲染出来。

这是相同的元素，应用了 CSS `drop-shadow`滤镜，而不是`box-shadow`：

![CSS filters](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_08.jpg)

以下是 CSS 滤镜的格式：

```html
.filter-drop-shadow {
    filter: drop-shadow(8px 8px 6px #333);
}
```

在`filter`属性之后，我们指定要使用的滤镜，在这个例子中是`drop-shadow`，然后传入滤镜的参数。`drop-shadow`遵循与`box-shadow`类似的语法，因此这很容易；x 和 y 偏移量，模糊度，然后是扩散半径（都是可选的），最后是颜色（同样是可选的，尽管我建议为了一致性而指定颜色）。

### 提示

CSS 滤镜实际上是基于具有更广泛支持的 SVG 滤镜的。我们将在第七章中看到基于 SVG 的等效物，*使用 SVG 实现分辨率独立性*。

## 可用的 CSS 滤镜

有几个滤镜可供选择。我们将逐一查看。虽然大多数滤镜的图像随后会出现，但阅读本书的读者（使用单色图像的硬拷贝）可能会难以注意到差异。如果你处于这种情况，请记住你仍然可以通过打开`example_06-08`在浏览器中查看各种滤镜。我现在将列出每一个适当的值。正如你所想象的那样，更多的值意味着更多的滤镜应用。在使用图像的地方，相关代码之后会显示图像。

+   `filter: url ('./img/filters.svg#filterRed')`: 让你指定要使用的 SVG 滤镜。

+   `filter: blur(3px)`: 使用单个长度值（但不是百分比）。![可用的 CSS 滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_09.jpg)

+   `filter: brightness(2)`: 使用从 0 到 1 或 0%到 100%的值。0/0%是黑色，1/100%是'正常'，而任何超过这个值的都会使元素更亮。![可用的 CSS 滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_10.jpg)

+   `filter: contrast(2)`: 使用从 0 到 1 或 0%到 100%的值。0/0%是黑色，1/100%是'正常'，而任何超过这个值的都会提高颜色对比度。![可用的 CSS 滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_11.jpg)

+   `filter: drop-shadow(4px 4px 6px #333)`: 我们之前详细讨论过`drop-shadow`。

+   `filter: grayscale(.8)`: 使用从 0 到 1 的值，或者 0%到 100%的值来对元素应用不同程度的灰度。0 的值将没有灰度，而 1 的值将完全是灰度。![可用的 CSS 滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_12.jpg)

+   `filter: hue-rotate(25deg)`: 使用从 0 到 360 度的值来调整颜色在色轮周围的颜色。![可用的 CSS 滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_13.jpg)

+   `filter: invert(75%)`: 使用从 0 到 1 的值，或者 0%到 100%的值来定义元素颜色反转的程度。![可用的 CSS 滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_14.jpg)

+   `filter: opacity(50%)`: 使用从 0 到 1 的值，或者 0%到 100%的值来改变元素的不透明度。这类似于你已经熟悉的`不透明度`属性。然而，正如我们将看到的那样，滤镜可以组合，这允许不透明度与其他滤镜一起组合。![可用的 CSS 滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_15.jpg)

+   `filter: saturate(15%)`: 使用从 0 到 1 的值，或者 0%到 100%的值来去饱和图像，超过 1/100%则增加额外的饱和度。![可用的 CSS 滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_16.jpg)

+   `filter: sepia(.75)`: 使用从 0 到 1 的值，或者 0%到 100%的值使元素呈现出更多的深褐色。0/0%使元素保持原样，而任何超过这个值的都会应用更多的深褐色，最多为 1/100%。![可用的 CSS 滤镜](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_17.jpg)

## 组合 CSS 滤镜

你也可以轻松地组合滤镜；只需用空格分隔它们。例如，这是如何一次应用`不透明度`，`模糊`和`深褐色`滤镜的：

```html
.MultipleFilters {
    filter: opacity(10%) blur(2px) sepia(35%);
}
```

### 注意

注意：除了`hue-rotate`之外，使用滤镜时，不允许使用负值。

我想你会同意，CSS 滤镜提供了一些非常强大的效果。这些也是我们可以从一种情况过渡到另一种情况的效果。我们将在第八章中看到如何做到这一点，*过渡，转换和动画*。

然而，在你对这些新玩具感到兴奋之前，我们需要就性能进行一次成熟的对话。

# 关于 CSS 性能的警告

在谈到 CSS 性能时，我希望你记住一件事：

|   | *"建筑在括号外，性能在括号内。"* |   |
| --- | --- | --- |
|   | --*Ben Frain* |

让我扩展一下我的小格言：

就我所能证明的，担心 CSS 选择器（大括号外的部分）是快还是慢是毫无意义的。我在[`benfrain.com/css-performance-revisited-selectors-bloat-expensive-styles/`](http://benfrain.com/css-performance-revisited-selectors-bloat-expensive-styles/)中试图证明这一点。

然而，从 CSS 的角度来看，真正会使页面停滞不前的一件事是“昂贵”的属性（大括号内的部分）。当我们在某些样式方面使用术语“昂贵”时，它简单地意味着它给浏览器带来了很多开销。这是浏览器发现过于繁重的事情。

我们可以根据常识猜测什么可能会导致浏览器额外工作。基本上，任何在绘制屏幕之前必须计算的东西。例如，比较一个具有纯色背景的标准 div 和一个半透明图像，放在由多个渐变组成的背景之上，带有圆角和`drop-shadow`。后者更昂贵；它将导致浏览器进行更多的计算工作，随后会导致更多的开销。

因此，当您应用滤镜等效果时，请谨慎行事，并在可能的情况下测试页面速度是否在您希望支持的最低功率设备上受到影响。至少，在 Chrome 中打开开发工具功能，如连续页面重绘，并切换任何可能会导致问题的效果。这将为您提供数据（以毫秒为单位，显示当前视口绘制所需的时间），以便更明智地决定应用哪些效果。数字越低，页面的性能越快（尽管要注意浏览器/平台会有所不同，因此尽可能在真实设备上进行测试）。

有关此主题的更多信息，我建议参考以下资源：

[`developers.google.com/web/fundamentals/performance/rendering/`](https://developers.google.com/web/fundamentals/performance/rendering/)

![CSS 性能警告](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-h5c3-2e/img/3777_06_18.jpg)

## 关于 CSS 蒙版和裁剪的说明

在不久的将来，CSS 将能够在 CSS 蒙版模块 1 级中提供蒙版和裁剪。这些功能将使我们能够使用形状或任意路径（通过 SVG 或多边形点的方式指定）裁剪图像。遗憾的是，尽管规范处于更高级的 CR 阶段，但在我写这篇文章时，浏览器的实现仍然太多 bug，无法推荐。但是，这是一个不断变化的情况，因此在您阅读本文时，实现可能已经非常稳定。对于好奇的人，我将向您推荐规范[`www.w3.org/TR/css-masking/`](http://www.w3.org/TR/css-masking/)。

我认为克里斯·科耶在这篇文章中很好地解释了支持方面的情况：

[`css-tricks.com/clipping-masking-css/`](http://css-tricks.com/clipping-masking-css/)

最后，萨拉·苏艾丹在这篇文章中提供了一个关于未来可能实现的概述和解释：

[`alistapart.com/article/css-shapes-101`](http://alistapart.com/article/css-shapes-101)

# 摘要

在本章中，我们已经研究了一些最有用的 CSS 功能，用于在响应式网页设计中创建轻量级的美学效果。CSS3 的背景渐变减少了我们对背景效果图像的依赖。我们甚至考虑了它们如何用于创建无限重复的背景图案。我们还学习了如何使用文本阴影来创建简单的文本增强和使用盒子阴影来为元素的外部和内部添加阴影。我们还研究了 CSS 滤镜。它们使我们能够仅使用 CSS 实现更令人印象深刻的视觉效果，并且可以组合以获得真正令人印象深刻的结果。

在下一章中，我们将把注意力转向创建和使用 SVG（可伸缩矢量图形），它们通常被简称为 SVG。虽然这是一种非常成熟的技术，但只有在当前响应式和高性能网站的环境下，它才真正成熟起来。
