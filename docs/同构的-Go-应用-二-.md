# 同构的 Go 应用（二）

> 原文：[`zh.annas-archive.org/md5/70B74CAEBE24AE2747234EE512BCFA98`](https://zh.annas-archive.org/md5/70B74CAEBE24AE2747234EE512BCFA98)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：同构模板

在上一章中，我们介绍了 GopherJS，并涵盖了执行各种前端操作的代码示例。我们在客户端执行的有趣任务之一是使用内联 Go 模板进行模板渲染。然而，在 Web 浏览器中呈现内联 Go 模板并不是一个可维护的解决方案。首先，将 HTML 代码与 Go 源代码混合在一起，随着项目代码库的增长，可能会变得难以维护。此外，现实世界的 Web 应用程序通常需要具有多个模板文件，这些文件通常以布局层次结构嵌套在一起。除此之外，Go 标准库中的模板包特别设计用于在服务器端呈现模板，因为它依赖于从文件系统访问模板文件。

为了充分发挥模板在各种环境中的功能，我们需要一个解决方案，提供更多灵活性，以在给定项目的一组模板中呈现任何模板。通过使用 Isomorphic Go 工具包中的`isokit`包，可以找到这种灵活性。使用`isokit`包的功能，我们可以在服务器端或客户端呈现属于模板集的模板，并且我们将在本章中向您展示如何实现这一点。

具体来说，本章将涵盖以下主题：

+   网页模板系统

+   IGWEB 页面结构

+   模板类别

+   自定义模板函数

+   向内容模板提供数据

+   同构模板渲染

# 网页模板系统

在 Web 编程中，**网页模板**是描述网页应如何呈现给用户的文本文档。在本书中，我们将专注于 Go 的`html/template`包中的 Web 模板——该包实现了适用于 Web 应用程序的数据驱动模板。

Web 模板（我们将在以后简称为*模板*）是文本文档，通常以 HTML 实现，并可能包含嵌入其中的特殊命令。在 Go 中，我们将这些命令称为*操作*。我们通过将它们放在一对开放和关闭的双大括号中（`{{`和`}}`）来表示模板中的操作。

模板是以直观和可接受的方式向用户呈现数据的手段。实际上，您可以将模板视为我们打扮数据的手段。

在本书中，我们将使用`.tmpl`文件扩展名来指定 Go 模板源文件。您可能会注意到其他一些 Go 项目使用`.html`扩展名。没有硬性规定要优先选择其中一个扩展名，只需记住一旦选择了要使用的文件扩展名，最好坚持使用它，以促进项目代码库的统一性。

模板与**网页模板系统**一起使用。在 Go 中，我们有强大的`html/template`包来呈现模板。当我们使用术语*呈现模板*时，我们指的是通过**模板引擎**处理一个或多个模板以及**数据对象**的过程，生成 HTML 网页输出，如*图 4.1*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/e3e99fcd-9757-43c8-a6ef-4409d6d14330.png)

图 4.1：网页模板系统如何呈现网页

*图 4.1*中的关键组件，**模板引擎**、**模板数据对象**和**模板**，可以被归类为**网页模板系统**的组成部分。每个组件在呈现网页输出方面都起着重要作用，在接下来的章节中，我们将考虑每个组件在生成要在 Web 浏览器中显示的 HTML 输出过程中所起的作用。在本章中，我们将构建 IGWEB 的关于页面。

# 模板引擎

模板引擎的主要责任是获取一个或多个模板文件以及一个数据对象，并生成文本输出。在我们特定的研究领域，等距网络开发中，这种文本输出是以 HTML 格式的，并且可以被 Web 客户端消耗。在 Go 中，`html/template`包可以被视为我们的模板引擎。

当模板引擎激活时，由路由处理程序激活，当需要提供 HTML 输出时。从等距网络应用程序的角度来看，模板引擎可以由服务器端路由处理程序和客户端路由处理程序激活。

当模板引擎从服务器端路由处理程序激活时，生成的 HTML 网页输出将通过 Web 服务器实例使用`http.ResponseWriter`写入到服务器响应中的 Web 客户端。这种活动通常发生在首次访问网站上的页面时，并且初始页面请求在服务器端得到服务。在这种情况下，从模板引擎返回的 HTML 描述了完整的 HTML 网页文档，并包括开头和结尾的`<html>`和`<body>`标签。

当模板引擎从客户端路由处理程序激活时，生成的 HTML 内容将呈现在完全呈现的网页的指定区域。我们将在 IGWEB 上的特定区域为给定网页的客户端呈现 HTML 内容，该区域称为*主要内容区域*。我们将在本章后面讨论主要内容区域，即`<div>`容器。客户端模板呈现通常发生在用户与网站进行后续交互时，例如当用户单击导航栏中的链接以访问网站上的特定页面时。在这种情况下，从模板引擎返回的 HTML 仅代表 HTML 网页的一部分。

值得注意的是，Go 带有两个模板包。`text/template`包用于生成文本，`html/template`包用于生成 HTML 输出。`html/template`包提供与`text/template`包相同的接口。在本书中，我们特别关注生成 HTML 网页输出，这就是为什么我们将专注于`html/template`包的原因。`html/template`包通过生成安全的 HTML 输出提供了额外的安全性，而常规的`text/template`包则不会这样做。这就是为什么最好使用`html/template`包进行 Web 开发的目的。

# 模板数据对象

模板数据对象（或简称*数据对象*）的主要责任是为给定模板提供要呈现给用户的数据。在我们将要构建的“关于”页面中，有两个需要呈现的数据。第一个需求是微妙的，它是将显示在 Web 浏览器标题栏窗口中的网页标题，或作为包含网页的 Web 浏览器选项卡的标题。第二个数据需求更深刻，它是数据对象，应在“关于”页面上显示的土拨鼠列表。

我们将使用`shared/templatedata/about.go`源文件中定义的`templatedata`包中的以下`About`结构来满足“关于”页面的数据需求：

```go
type About struct {
  PageTitle string
  Gophers []*models.Gopher
}
```

`PageTitle`字段表示应在 Web 浏览器标题栏中显示的网页标题（或作为 Web 浏览器选项卡的标题）。`Gophers`字段是指向`Gopher`结构的指针切片。`Gopher`结构表示应在“关于”页面上显示的土拨鼠，即 IGWEB 团队的成员。

`Gopher`结构的定义可以在`shared/models`文件夹中的`gopher.go`源文件中找到：

```go
type Gopher struct {
  Name string
  Title string
  Biodata string
  ImageURI string
  StartTime time.Time
}
```

`Name`字段代表地鼠的姓名。`Title`字段代表 IGWEB 组织赋予特定地鼠的头衔。`Biodata`字段代表特定地鼠的简要个人资料。我们使用了 loren ipsum 生成器，在这个字段中生成了一些拉丁文的随机胡言乱语。`ImageURI`字段是应该显示的地鼠图片的路径，相对于服务器根目录。地鼠的图片将显示在页面的左侧，地鼠的个人资料将显示在页面的右侧。

最后，`StartTime`字段代表地鼠加入 IGWEB 组织的日期和时间。我们将以标准时间格式显示地鼠的开始时间，本章后面我们将学习如何通过实现自定义模板函数来使用 Ruby 风格格式显示开始时间。在第九章，*齿轮-可重用组件*中，我们将学习如何以人类可读的时间格式显示开始时间。

# 模板

模板负责以直观和易懂的方式向用户呈现信息。模板构成同构 Web 应用的视图层。Go 模板是标准 HTML 标记和轻量级模板语言的组合，它为我们提供了执行标记替换、循环、条件控制流、模板嵌套以及使用管道构造在模板中调用自定义模板函数的手段。所有上述活动都可以使用模板操作来执行，我们将在本书中使用它们。

IGWEB 项目的模板可以在`shared/templates`文件夹中找到。它们被视为同构模板，因为它们可以在服务器端和客户端上使用。现在我们将探索 IGWEB 的网页布局组织，然后直接查看实现 IGWEB 网页结构所需的模板。

# IGWEB 页面结构

*图 4.2*描绘了 IGWEB 网页结构的线框设计。该图为我们提供了网站的基本布局和导航需求的良好想法：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/3c6bfd34-adfd-4181-ae26-8bdcdae0d8ea.png)

图 4.2：IGWEB 线框设计

通过将网页结构组织成这些个别区域，我们可以划分出每个区域在整个网页结构中所扮演的独特功能。让我们继续检查构成页面结构的每个个别区域。

1.  页眉

1.  主要内容区域

1.  页脚

# 页眉

如*图 4.2*所示，页眉区域出现在网页顶部。它标志着网页的开始，并且对品牌、导航和用户交互很有用。它由顶部栏和导航栏组成。

# 顶部栏

如*图 4.2*所示，顶部栏是存在于页眉内的子区域。在顶部栏的最左侧是 IGWEB 的标志。除了用于品牌目的，标志还作为导航组件，因为用户点击它时，他们将返回到主页。在顶部栏的最右侧是辅助用户控件，用于激活特定功能——购物车和实时聊天功能。

# 导航栏

如*图 4.2*所示，导航栏是存在于页眉内的子区域。导航区域包括指向网站各个页面的链接。

# 主要内容区域

主要内容区域，如*图 4.2*所示，位于页眉区域和页脚区域之间。网页的内容将显示在这里。例如，关于页面将在主要内容区域显示 IGWEB 团队地鼠的图片和简介信息。

# 页脚

如*图 4.2*所示，页脚区域出现在网页底部。它包含网站的版权声明。页脚标志着网页的结束。

现在我们已经为 IGWEB 建立了网页结构，我们将学习如何使用预先计划的 Go 模板层次结构来实现结构。为了提高我们的理解，我们将根据它们的功能目的将模板组织成类别。

# 模板类别

根据功能目的将模板组织成类别，可以让我们在实现网页结构时更加高效。模板可以根据它们在实现网页结构中所起的作用，分为以下三类：

+   布局模板

+   部分模板

+   常规模板

**布局模板**描述整个网页的一般布局。它们为我们提供了页面结构的鸟瞰图，并让我们了解所有其他模板如何适应其中。

**部分模板**只包含网页的一部分，因此它们被称为**部分**。它们是部分性质的，因为它们旨在满足网页区域内的特定需求，比如显示网页的页脚。

**常规模板**包含特定网站部分的内容，并且这些内容应该显示在主要内容区域。在接下来的部分中，我们将检查每个模板类别，并考虑为每个类别执行的相应模板实现。

# 布局模板

页面布局模板，也称为**布局模板**，包含整个网页的结构。由于它们定义了网页的整体结构，它们需要其他模板（部分和常规）来完成。对于同构的网络应用程序，这些类型的模板用于在服务器端呈现网页，用于发送到客户端的初始网页响应。在 IGWEB 项目中，我们将布局模板放在`shared/templates/layouts`文件夹中。

# 网页布局模板

以下是在`shared/templates/layouts`目录中的`webpage_layout.tmpl`源文件中找到的网页布局模板：

```go
<!doctype html>
<html>
  {{ template "partials/header_partial" . }}

    <div id="primaryContent" class="pageContent">
      {{ template "pagecontent" . }}
    </div>

    <div id="chatboxContainer">
    </div>

  {{ template "partials/footer_partial" . }}
</html>
```

请注意，布局模板覆盖了整个网页，从开头的`<html>`标签到结束的`</html>`标签。布局模板发出了渲染`header`部分模板、`pagecontent`常规模板和`footer`部分模板的`template`动作（以粗体显示）。

在`partials/header_partial`模板名称和闭合的一对大括号`}}`之间的点`.`被称为动作。模板引擎认为这是一个命令，应该用在模板执行时传入的数据对象的值来替换。通过在这里放置点，我们确保页眉部分模板可以访问被传入模板的数据对象，这个模板负责显示网站页眉区域的内容。请注意，我们对`pagecontent`模板和`partials/footer_partial`模板也做了同样的操作。

# 部分模板

部分模板，也称为**部分**，通常包含网页特定区域的部分内容。部分模板的示例包括网页的页眉和页脚。当在页面布局模板中包含页眉和页脚时，页眉和页脚部分模板非常有用，因为页眉和页脚将预设在网站的所有网页上。让我们看看页眉和页脚部分模板是如何实现的。在 IGWEB 项目中，我们将部分模板放在`shared/templates/partials`文件夹中。

# 页眉部分模板

以下是在`shared/templates/partials`文件夹中的`header_partial.tmpl`源文件中找到的页眉部分的示例：

```go
<head>
  <title>{{.PageTitle}}</title> 
  <link rel="icon" type="image/png" href="/static/images/isomorphic_go_icon.png">
  <link rel="stylesheet" href="/static/css/pure.css">
  <link rel="stylesheet" type="text/css" href="/static/css/cogimports.css">
  <link rel="stylesheet" type="text/css" href="/static/css/alertify.core.css" />
  <link rel="stylesheet" type="text/css" href="/static/css/alertify.default.css" />
 <link rel="stylesheet" type="text/css" href="/static/css/igweb.css">
  <script type="text/javascript" src="img/alertify.js" type="text/javascript"></script>
  <script src="img/cogimports.js" type="text/javascript"></script>
 <script type="text/javascript" src="img/client.js"></script>
</head>
<body>

<div id="topbar">{{template "partials/topbar_partial"}}</div>
<div id="navbar">{{template "partials/navbar_partial"}}</div>
```

在开头的`<head>`和结尾的`</head>`标签之间，我们包括网站图标以及外部 CSS 样式表和外部 JavaScript 源文件。`igweb.css`样式表定义了 IGWEB 网站的样式（以粗体显示）。`client.js` JavaScript 源文件是客户端 Web 应用程序的 JavaScript 源文件，它通过 GopherJS 转译为 JavaScript（以粗体显示）。

请注意，我们在头部部分模板中使用`template`操作（以粗体显示）来呈现顶部栏和导航栏部分模板。我们在这里不包括点`.`，因为这些部分模板不需要访问数据对象。顶部栏和导航栏的内容都在各自的`<div>`容器中。

# 顶部栏部分模板

以下是在`shared/templates/partials`文件夹中的`topbar_partial.tmpl`源文件中找到的顶部栏部分模板：

```go
<div id="topbar" >
  <div id="logoContainer" class="neon-text"><span><a href="/index">igweb</a></span></div>
  <div id="siteControlsContainer">
    <div id="shoppingCartContainer" class="topcontrol" title="Shopping Cart"><a href="/shopping-cart"><img src="img/cart_icon.png"></a></div>
    <div id="livechatContainer" class="topcontrol" title="Live Chat"><img id="liveChatIcon" src="img/msg_icon.png"></div>
  </div>
</div>
```

顶部栏部分模板是一个静态模板的很好例子，其中没有动态操作。它没有在其中定义`template`操作，它的主要目的是包含 HTML 标记以呈现网站标志、购物车图标和在线聊天图标。

# 导航栏部分模板

以下是在`shared/templates/partials`文件夹中的`navbar_partial.tmpl`源文件中找到的导航栏部分模板的示例：

```go
<div id="navigationBar">
<ul>
  <li><a href="/index">Home</a></li>
  <li><a href="/products">Products</a></li>
  <li><a href="/about">About</a></li>
  <li><a href="/contact">Contact</a></li>
</ul>
</div>
```

导航栏部分模板也是一个静态模板。它包含一个`div`容器，其中包含组成 IGWEB 导航栏的导航链接列表。这些链接允许用户访问主页、产品、关于和联系页面。

# 页脚部分模板

以下是在`shared/templates/partials`文件夹中的`footer_partial.tmpl`源文件中找到的页脚部分模板的示例：

```go
<footer>
<div id="copyrightNotice">
<p>Copyright &copy; IGWEB. All Rights Reserved</p>
</div>
</footer>
</body>
```

页脚部分模板也是一个静态模板，其当前唯一目的是包含 IGWEB 网站的版权声明的 HTML 标记。

现在我们已经涵盖了构成网页结构的所有部分模板，是时候来看看常规模板从服务器端和客户端的角度看是什么样子了。

# 常规模板

**常规模板**用于保存要在网页上显示的主要内容。例如，在关于页面中，主要内容将是关于 IGWEB 团队地鼹鼠的信息以及他们个人的图片。

在本章中，我们将构建关于页面。通过检查其线框设计（见*图 4.3*），我们可以清楚地看到关于页面主要内容区域中的内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/827e74b7-b222-454c-a3a3-ebee1049e08a.png)

图 4.3：关于页面的线框设计

对于 IGWEB 团队中的每只地鼹鼠，我们将显示地鼹鼠的图片、姓名、头衔以及关于其角色的简要描述（随机生成的拉丁文胡言乱语）。我们还将以几种不同的时间格式显示地鼹鼠加入 IGWEB 团队的日期/时间。

我们将以明显不同的方式呈现关于页面，具体取决于呈现是在服务器端还是客户端进行。在服务器端，当我们呈现关于页面时，我们需要一个页面模板，即一个常规模板，其中包含整个网页的布局，以及包含关于页面的内容。在客户端，我们只需要呈现关于页面中包含的内容以填充主要内容区域，因为网页已经在初始页面加载时为我们呈现出来。

在这一点上，我们可以定义常规模板的两个子类别：*页面模板*将满足我们的服务器端渲染需求，*内容模板*将满足我们的客户端渲染需求。在 IGWEB 项目中，我们将把常规模板放在`shared/templates`文件夹中。

# 关于页面的页面模板

以下是关于页面的页面模板示例，来自`shared/templates`文件夹中的`about_page.tmpl`源文件：

```go
{{ define "pagecontent" }}
{{ template "about_content" . }}
{{ end }}
{{ template "layouts/webpage_layout" . }}
```

我们在页面模板中使用`define`操作来定义包含我们声明为`pagecontent`部分的模板部分的区域。我们有一个相应的`end`操作来标记`pagecontent`部分的结束。请注意，在定义和结束操作之间，我们使用模板操作来包含名为`about_content`的模板。还要注意，我们使用点（`.`）操作将数据对象传递给`about_content`模板。

此页面模板是一个很好的示例，显示了我们如何在常规模板中呈现布局模板。在模板的最后一行，我们声明了一个`template`操作，以加载名为`layouts/webpage_layout`的网页布局模板。再次注意，我们使用点（`.`）操作将数据对象传递给网页布局模板。

现在我们已经检查了`about_page`模板，是时候检查`about_content`模板了。

# 关于页面的内容模板

以下是内容模板的示例，该模板被呈现到关于页面中的主要内容区域中，来自`shared/templates`文件夹中的`about_content.tmpl`源文件：

```go
<h1>About</h1>

<div id="gopherTeamContainer">
  {{range .Gophers}}

    <div class="gopherContainer">

      <div class="gopherImageContainer">
        <img height="270" src="img/strong>">
      </div>

      <div class="gopherDetailsContainer">
          <div class="gopherName"><h3><b>{{.Name}}</b></h3></div>
          <div class="gopherTitle"><span>{{.Title}}</span></div> 
          <div class="gopherBiodata"><p>{{.Biodata}}</p></div>
          <div class="gopherStartTime">
            <p class="standardStartTime">{{.Name}} joined the IGWEB team on <span class="starttime">{{.StartTime}}).</p>
            <p class="rubyStartTime">That's <span class="starttime">{{.StartTime | rubyformat}}</span> in Ruby date format.</p>
            <div class="humanReadableGopherTime">That's <div id="Gopher-{{.Name}}" data-starttimeunix="{{.StartTime | unixformat}}" data-component="cog" class="humanReadableDate starttime"></div> in Human readable format.</div>
          </div>
      </div>
    </div>

  {{end}}
</div>
```

我们使用`range`操作来遍历模板提供的数据对象的 Gophers 属性（以粗体显示）。请注意，我们使用点（`.`）操作来访问数据对象的`Gophers`属性。请记住，`Gophers`属性是指向`Gopher`结构的指针切片。我们使用`end`操作来表示`range`循环操作的结束（以粗体显示）。

需要注意的是，内容模板在服务器端和客户端都是必需的。请记住，在服务器端，需要呈现完整的网页布局，以及内容模板。在客户端，我们只需要呈现内容模板。

请注意，在最后两个打印`StartTime`字段的地方，我们使用管道（`|`）运算符使用自定义函数格式化`StartTime`字段。首先，我们使用`rubyformat`函数以 Ruby 日期/时间格式显示`StartTime`值，然后我们使用`unixformat`函数将`"data-starttimeunix"`属性填充为`StartTime`值的 Unix 时间表示。让我们看看这些自定义函数在 IGWEB 项目代码库中是如何定义的。

# 自定义模板函数

我们在`shared/templatefuncs`文件夹中找到的`funcs.go`源文件中定义了我们的自定义模板函数。

```go
package templatefuncs

import (
  "strconv"
  "time"
)

func RubyDate(t time.Time) string {
  layout := time.RubyDate
  return t.Format(layout)
}

func UnixTime(t time.Time) string {
  return strconv.FormatInt(t.Unix(), 10)
}
```

`RubyDate`函数使用`time.RubyDate`常量指定的时间布局显示给定的时间。我们在模板中使用`rubyformat`函数名称调用该函数。

如前所述，在关于内容模板（`shared/templates/about_content.tmpl`）中，我们使用管道（`|`）运算符将`rubyformat`函数应用于`StartTime`，如下所示：

```go
<p class="rubyStartTime">That's <span class="starttime">{{.StartTime | rubyformat}}</span> in Ruby date format.</p>
```

通过这种方式，自定义模板函数为我们提供了灵活性，可以在模板中格式化值，以满足项目可能需要的独特需求。也许你会想，我们如何将`rubyformat`名称映射到`RubyDate`函数。我们创建一个包含此映射的模板函数映射；我们将在本章后面介绍如何在不同环境中使用模板函数映射。

`templates`、`templatedata`和`templatefuncs`这三个子文件夹位于`shared`文件夹中，这意味着这些文件夹中的代码可以在不同环境中使用。实际上，`shared`文件夹及其子文件夹中包含的任何代码都是用于在不同环境中共享的代码。

我们将在第九章中介绍`UnixTime`函数，模板中称为`unixformat`函数，*齿轮-可重用组件*。

# 向内容模板提供数据

我们将要提供给关于内容模板的数据对象是指向代表 IGWEB 团队上每只地鼠的`Gopher`结构体的指针切片。我们的模板数据对象的`Gophers`属性将从 Redis 数据存储中获取地鼠切片，并与数据对象的`PageTitle`属性一起填充到“关于”页面的模板数据对象中。

我们在数据存储对象上调用`GetGopherTeam`方法，以获取属于 IGWEB 团队的地鼠切片。以下是在`common/datastore`文件夹中找到的`redis.go`源文件中`GetGopherTeam`函数的声明：

```go
func (r *RedisDatastore) GetGopherTeam() []*models.Gopher {

  exists, err := r.Cmd("EXISTS", "gopher-team").Int()

  if err != nil {
    log.Println("Encountered error: ", err)
    return nil
  } else if exists == 0 {
    return nil
  }

  var t []*models.Gopher
  jsonData, err := r.Cmd("GET", "gopher-team").Str()

  if err != nil {
    log.Print("Encountered error when attempting to fetch gopher team data from Redis instance: ", err)
    return nil
  }

  if err := json.Unmarshal([]byte(jsonData), &t); err != nil {
    log.Print("Encountered error when attempting to unmarshal JSON gopher team data: ", err)
    return nil
  }

  return t

}
```

`GetGopherTeam`函数检查`Redis`数据库中是否存在`gopher-team`键。地鼠切片以 JSON 编码的数据形式存储在`Redis`数据库中。如果`gopher-team`键存在，我们尝试将 JSON 编码的数据解码为`t`变量，这是指向`Gopher`结构体的指针切片。如果我们成功解码了 JSON 数据，我们将返回`t`变量。

到目前为止，我们已经创建了获取将显示在“关于”页面上的地鼠团队数据的方法。你可能会想，为什么我们不能只是用地鼠的切片作为数据对象，将其传递给关于内容模板，然后就完成了呢？为什么我们需要传递一个类型为`templatedata.About`的数据对象给关于内容模板呢？

对这两个问题的一言以蔽之的答案是*可扩展性*。目前，“关于”部分不仅需要地鼠的切片，还需要一个页面标题，该标题将显示在网页浏览器的标题窗口和/或网页浏览器标签中。因此，对于 IGWEB 的所有部分，我们已经创建了相应的结构体，以在`shared/templatedata`文件夹中为网站的每个页面建模个别数据需求。由于`templatedata`包位于`shared`文件夹中，因此`templatedata`包是同构的，可以在各种环境中访问。

我们在`shared/templatedata`文件夹中的`about.go`源文件中定义了`About`结构：

```go
type About struct {
  PageTitle string
  Gophers []*models.Gopher
}
```

`PageTitle`字段是`string`类型的，是“关于”页面的标题。`Gophers`字段是指向`Gopher`结构体的指针切片。这个切片代表将在关于页面上显示的地鼠团队。正如我们在本章前面看到的，我们将在内容模板中使用`range`操作来遍历切片并显示每只地鼠的个人资料信息。

回到可扩展性的话题，`templatedata`包中定义的结构体字段并不是固定不变的。它们是为了随着时间的推移而改变，以适应特定网页的未来需求。

例如，如果 IGWEB 产品经理决定他们应该有地鼠团队成员在办公室工作、学习和玩耍的照片，以供公共关系用途，他们可以通过向`About`结构体添加名为`OfficeActivityImages`的新字段来轻松满足这一要求。这个新字段可以是一个字符串切片，表示应该在“关于”页面上显示的地鼠图片的服务器相对路径。然后，我们将在模板中添加一个新的部分，通过`range`遍历`OfficeActivityImages`切片，并显示每张图片。

到目前为止，我们已经满足了“关于”页面的数据需求，并且我们已经准备好了所有的模板。现在是时候专注于如何在服务器端和客户端执行模板的渲染了。这就是同构模板渲染发挥作用的地方。

# 同构模板渲染

等同模板渲染允许我们在不同环境中渲染和重用模板。在 Go 中渲染模板的传统程序依赖于通过文件系统访问模板，但这带来了一些限制，阻止我们在客户端上渲染相同的模板。我们需要承认这些限制，以充分理解等同模板渲染为我们带来的好处。

# 基于文件系统的模板渲染的限制

在与客户端共享模板渲染责任时，我们需要承认模板渲染工作流程中的某些限制。首先，模板文件是在 Web 服务器上定义的。

让我们考虑一个例子，遵循经典的 Web 应用程序架构，以充分理解我们面临的限制。以下是一个使用模板文件`edit.html`进行服务器端模板渲染的示例，取自 Go 网站的*编写 Web 应用程序*文章（[`golang.org/doc/articles/wiki/`](https://golang.org/doc/articles/wiki/)）：

```go
func editHandler(w http.ResponseWriter, r *http.Request) {
  title := r.URL.Path[len("/edit/"):]
  p, err := loadPage(title)
  if err != nil {
      p = &Page{Title: title}
  }
 t, _ := template.ParseFiles("edit.html")
 t.Execute(w, p)
}
```

`editHandler`函数负责处理`/edit`路由。最后两行（以粗体显示）特别值得我们考虑。调用`html/template`包中的`ParseFiles`函数来解析`edit.html`模板文件。模板解析后，调用`html/template`包中的`Execute`函数来执行模板以及`p`数据对象，它是一个`Page`结构。生成的网页输出然后使用`http.ResponseWriter` `w`作为网页响应写出到客户端。

Go 网站的*编写 Web 应用程序*文章是一篇了解使用 Go 进行经典的服务器端 Web 应用程序编程的优秀文章。我强烈建议您阅读这篇文章：[`golang.org/doc/articles/wiki/`](https://golang.org/doc/articles/wiki/)。

以这种方式渲染模板的缺点是，我们被锚定在服务器端文件系统上，`edit.html`模板文件所在的地方。我们面临的困境是，客户端需要访问模板文件的内容才能在客户端上渲染模板。在客户端无法调用`ParseFiles`函数，因为我们无法访问本地文件系统上可以读取的任何模板文件。

现代 Web 浏览器中实施的强大安全沙箱阻止客户端从本地文件系统访问模板文件，这是正确的。相比之下，从服务器端调用`ParseFiles`函数是有意义的，因为服务器端应用程序实际上可以访问服务器端文件系统，模板就驻留在那里。

那么我们如何克服这一障碍呢？`isokit`包通过提供我们从服务器端文件系统中收集一组模板，并创建一个内存模板集的能力来拯救我们。

# 内存中的模板集

`isokit`包具有以等同方式渲染模板的功能。为了以等同方式思考，在模板渲染时，我们必须摆脱以往在文件系统中渲染模板的思维方式。相反，我们必须考虑在内存中维护一组模板，我们可以通过给定的名称访问特定模板。

当我们使用术语“内存”时，我们并不是指内存数据库，而是指模板集在运行的应用程序本身中持续存在，无论是在服务器端还是客户端。模板集在应用程序运行时保持驻留在内存中供应用程序利用。

`isokit`包中的`Template`类型表示等同模板，可以在服务器端或客户端上呈现。在`Template`的类型定义中，注意到`*template.Template`类型被嵌入：

```go
type Template struct {
  *template.Template
  templateType int8
}
```

嵌入`*template.Template`类型允许我们利用`html/template`包中定义的`Template`类型的所有功能。`templateType`字段指示我们正在处理的模板类型。以下是带有此字段所有可能值的常量分组声明：

```go
const (
  TemplateRegular = iota
  TemplatePartial
  TemplateLayout
)
```

正如你所看到的，常量分组声明已经考虑到我们将处理的所有模板类别：常规模板、部分模板和布局模板。

让我们看一下`isokit`包中的`TemplateSet`结构是什么样子的：

```go
type TemplateSet struct {
  members map[string]*Template
  Funcs template.FuncMap
  bundle *TemplateBundle
  TemplateFilesPath string
}
```

`members`字段是一个`map`，键的类型是`string`，值是指向`isokit.Template`结构的指针。`Funcs`字段是一个可选的函数映射(`template.FuncMap`)，可以提供给模板集，以在模板内调用自定义函数。`bundle`字段是模板包。`TemplateBundle`是一个`map`，其中键表示模板的名称（`string`类型），值是模板文件的内容（也是`string`类型）。`TemplateFilesPath`字段表示所有 Web 应用程序等同模板所在的路径。

`TemplateBundle`结构如下：

```go
type TemplateBundle struct {
  items map[string]string
}
```

`TemplateBundle`结构的`items`字段只是一个具有`string`类型键和`string`类型值的`map`。`items`映射起着重要作用，它是将在服务器端进行`gob`编码的数据结构，并且我们将通过服务器端路由`/template-bundle`将其暴露给客户端，在那里可以通过 XHR 调用检索并解码，如*图 4.4*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/866af4e4-0fb8-4963-a065-9106142a273c.png)

图 4.4 模板包中的项目如何传输到客户端

模板包类型发挥着关键作用，因为我们将其用作在客户端重新创建内存中的模板集的基础。这使我们能够为客户端提供完整的模板集。现在我们已经了解到可以利用模板集的概念来等同地呈现模板，让我们看看实际操作中是如何完成的。

# 在服务器端设置模板集

让我们来看一下`igweb`文件夹中的`igweb.go`源文件开头的变量声明：

```go
var WebAppRoot string
var WebAppMode string
var WebServerPort string
var DBConnectionString string
var StaticAssetsPath string
```

此处声明的变量对于 Web 服务器实例的正常运行至关重要。`WebAppRoot`变量负责指定`igweb`项目文件夹的位置。`WebServerPort`变量负责指定 Web 服务器实例应在哪个端口上运行。`DBConnectionString`变量用于指定到数据库的连接字符串。`StaticAssetsPath`变量用于指定包含项目的所有静态（非动态）资产的目录。这些资产可能包括 CSS 样式表、JavaScript 源文件、图像、字体以及任何不需要是动态的东西。

我们在`init`函数中初始化变量：

```go
func init() {

  WebAppRoot = os.Getenv("IGWEB_APP_ROOT")
  WebAppMode = os.Getenv("IGWEB_MODE")
  WebServerPort = os.Getenv("IGWEB_SERVER_PORT")
  DBConnectionString = os.Getenv("IGWEB_DB_CONNECTION_STRING")

  // Set the default web server port if it hasn't been set already
  if WebServerPort == "" {
    WebServerPort = "8080"
  }

  // Set the default database connection string
  if DBConnectionString == "" {
    DBConnectionString = "localhost:6379"
  }

  StaticAssetsPath = WebAppRoot + "/static"

}
```

`WebAppRoot`和`WebServerPort`变量分别从`IGWEB_APP_ROOT`和`$IGWEB_SERVER_PORT`环境变量中获取。

我们将在第十一章中介绍`WebAppMode`变量和`$IGWEB_MODE`环境变量，*部署等同 Go Web 应用程序*。

如果`$IGWEB_SERVER_PORT`环境变量未设置，默认端口设置为`8080`。

`DBConnectionString`变量被赋予值`"localhost:6379"`, 这是 Redis 数据库实例运行的主机名和端口。

`StaticAssetsPath`变量被分配给`static`文件夹，该文件夹位于`WebAppRoot`文件夹内。

让我们来看看`main`函数的开头：

```go
func main() {

  env := common.Env{}

  if WebAppRoot == "" {
    fmt.Println("The IGWEB_APP_ROOT environment variable must be set before the web server instance can be started.")
    os.Exit(1)
  }

  initializeTemplateSet(&env, false)
  initializeDatastore(&env)
```

在`main`函数的开头，我们检查`WebAppRoot`变量是否已设置，如果没有设置，我们就退出应用程序。设置`$IGWEB_APP_ROOT`环境变量的最大优势之一是，我们可以从系统上的任何文件夹中发出`igweb`命令。

在`main`函数中，我们初始化了`env`对象。在调用`initializeDatastore`函数初始化数据存储之后，我们调用`initializeTemplateSet`函数（以粗体显示），将`env`对象的引用传递给函数。这个函数，正如你从它的名字中猜到的那样，负责初始化模板集。我们将在第十一章中使用传递给函数的`bool`类型的第二个参数，*部署一个同构的 Go Web 应用程序*。

让我们来看看`initializeTemplateSet`函数：

```go
func initializeTemplateSet(env *common.Env, oneTimeStaticAssetsGeneration bool) {
  isokit.WebAppRoot = WebAppRoot
  isokit.TemplateFilesPath = WebAppRoot + "/shared/templates"
  isokit.StaticAssetsPath = StaticAssetsPath
  isokit.StaticTemplateBundleFilePath = StaticAssetsPath + "/templates/igweb.tmplbundle"

  ts := isokit.NewTemplateSet()
  funcMap := template.FuncMap{"rubyformat": templatefuncs.RubyDate, "unixformat": templatefuncs.UnixTime}
  ts.Funcs = funcMap
  ts.GatherTemplates()
  env.TemplateSet = ts
}
```

我们首先初始化`isokit`包的`WebAppRoot`、`TemplateFilesPath`和`StaticAssetsPath`变量的导出变量。通过调用`isokit`包中的`NewTemplateSet`函数，我们创建了一个新的模板集`ts`。

在我们创建模板集对象`ts`之后，我们声明了一个函数映射`funcMap`。我们用两个自定义函数填充了我们的映射，这些函数将暴露给我们的模板。第一个函数的键是`rubyformat`，值是`templatefuncs`包中找到的`RubyDate`函数。这个函数将返回给定时间值的 Ruby 格式。第二个函数的键是`unixformat`，这个函数将返回给定时间值的 Unix 时间戳。我们用我们刚刚创建的`funcMap`对象填充了模板集对象的`Funcs`字段。现在，我们模板集中的所有模板都可以访问这两个自定义函数。

到目前为止，我们已经准备好了模板集，但还没有填充模板集的`bundle`字段。为了做到这一点，我们必须调用`TemplateSet`对象的`GatherTemplate`方法，该方法将收集`isokit.TemplateFilesPath`指定的目录及其所有子目录中找到的所有模板。模板文件的名称（不包括`.tmpl`文件扩展名）将用作 bundle 映射中的键。模板文件的字符串内容将用作 bundle 映射中的值。如果模板是布局或部分，它们各自的目录名称将包含在名称中以引用它们。例如，`partials/footer.tmpl`模板的名称将是`partials/footer`。

现在我们的模板集已经准备好了，我们可以填充`env`对象的`TemplateSet`字段，这样我们的服务器端应用程序就可以访问模板集。这在以后会很方便，因为它允许我们从服务器端 Web 应用程序中定义的任何请求处理程序函数中访问模板集，从而使我们能够渲染模板集中存在的任何模板。

# 注册服务器端处理程序

在`igweb.go`源文件的`main`函数中初始化模板集之后，我们创建了一个新的 Gorilla Mux 路由器，并调用`registerRoutes`函数来注册服务器端 Web 应用程序的所有路由。让我们来看看`registerRoutes`函数中对客户端 Web 应用程序正常运行至关重要的行：

```go
// Register Handlers for Client-Side JavaScript Application
r.Handle("/js/client.js", isokit.GopherjsScriptHandler(WebAppRoot)).Methods("GET")
r.Handle("/js/client.js.map", isokit.GopherjsScriptMapHandler(WebAppRoot)).Methods("GET")

// Register handler for the delivery of the template bundle
r.Handle("/template-bundle", handlers.TemplateBundleHandler(env)).Methods("POST")
```

我们为`/js/client.js`路由注册了一个处理程序，并指定它将由`isokit`包中的`GopherjsScriptHandler`函数处理。这将把路由与通过在`client`目录中运行`gopherjs build`命令构建的`client.js` JavaScript 源文件相关联。

我们以类似的方式处理`client.js.map`的`map`文件。我们注册了一个`/js/client.js.map`路由，并指定它将由`isokit`包中的`GopherjsScriptMapHandler`函数处理。

现在我们已经注册了 JavaScript 源文件和 JavaScript 源`map`文件的路由，这对我们的客户端应用程序的功能至关重要，我们需要注册一个路由来访问模板包。我们将在`r`路由对象上调用`Handle`方法，并指定`/template-bundle`路由将由`handlers`包中的`TemplateBundleHandler`函数处理。客户端将通过 XHR 调用检索此路由，并且服务器将以`gob`编码数据的形式发送模板包。

我们注册的最后一个路由，目前对我们来说特别重要的是`/about`路由。以下是我们注册`/about`路由并将其与`handlers`包中的`AboutHandler`函数关联的代码行：

```go
r.Handle("/about", handlers.AboutHandler(env)).Methods("GET")
```

现在我们已经看到了如何在服务器端 Web 应用程序中设置模板集，以及如何注册对我们在本章中重要的路由，让我们继续查看服务器端处理程序，从`handlers`包中的`TemplateBundleHandler`函数开始。

# 提供模板包项目

以下是`handlers`文件夹中`templatebundle.go`源文件中的`TemplateBundleHandler`函数：

```go
func TemplateBundleHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    var templateContentItemsBuffer bytes.Buffer
    enc := gob.NewEncoder(&templateContentItemsBuffer)
    m := env.TemplateSet.Bundle().Items()
    err := enc.Encode(&m)
    if err != nil {
      log.Print("encoding err: ", err)
    }
    w.Header().Set("Content-Type", "application/octet-stream")
    w.Write(templateContentItemsBuffer.Bytes())
  })

}
```

将数据编码为`gob`格式的代码应该看起来很熟悉，就像我们在第三章的*在前端使用 GopherJS*中的*传输 gob 编码数据*部分中对 cars 切片进行 gob 格式编码一样。在`TemplateBundleHandler`函数内部，我们首先声明`templateContentItemsBuffer`，类型为`bytes.Buffer`，它将保存`gob`编码数据。然后我们创建一个新的`gob`编码器`enc`。紧接着，我们将创建一个`m`变量，并将其赋值为模板包映射的值。我们调用`enc`对象的`Encode`方法，并传入对`m`映射的引用。此时，`templateContentItemsBuffer`应该包含代表`m`映射的`gob`编码数据。我们将写出一个内容类型标头，以指定服务器将发送二进制数据(`application/octet-stream`)。然后我们将通过调用其`Bytes`方法写出`templateContentItemsBuffer`的二进制内容。在本章的*在客户端设置模板集*部分，我们将看到客户端 Web 应用程序如何获取模板包项目，并利用它在客户端上创建模板集。

# 从服务器端渲染 about 页面

现在我们已经看到了服务器端应用程序如何将模板包传输到客户端应用程序，让我们来看看`handlers`文件夹中`about.go`源文件中的`AboutHandler`函数。这是负责渲染`About`页面的服务器端处理程序函数：

```go
func AboutHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
 gophers := env.DB.GetGopherTeam()
 templateData := templatedata.About{PageTitle: "About", Gophers: gophers}
 env.TemplateSet.Render("about_page", &isokit.RenderParams{Writer: w, Data: templateData})
  })
}
```

`AboutHandler`函数有三个职责：

+   从数据存储中获取 gophers

+   创建模板数据对象

+   渲染`About`页面模板

在函数中定义的第一行代码从数据存储中获取 gopher 对象，其中 gopher 对象表示单个 gopher 团队成员。在我们的示例数据集中，有三个 gophers：Molly，Case 和 Wintermute。

第二行代码用于设置`templatedata.About`类型的模板数据对象。这是将被输入模板的数据对象。数据对象的`PageTitle`属性用于显示页面标题，我们将使用对象的`Gophers`属性填充从数据存储中检索到的 gopher 对象的切片。

在处理程序函数的第三行，我们调用模板集的`Render`方法来呈现模板。传递给该方法的第一个参数是要呈现的模板的名称。在这种情况下，我们已经指定要呈现`about_page`模板。请注意，这是一个页面模板，不仅会呈现关于页面内容，还会呈现整个网页布局，除了主要内容区域部分外，还包括网页的页眉、顶部栏、导航栏和页脚区域。

函数的第二个参数是模板渲染参数（`isokit.RenderParams`）。我们已经用`http.ResponseWriter` `w`填充了`Writer`字段。此外，我们已经用我们刚刚创建的`templateData`对象填充了`Data`字段，该对象表示应提供给模板的数据对象。

就是这样。现在我们可以在服务器端呈现此模板。我们现在已经实现了经典的 Web 应用程序架构流程，其中整个网页都是从服务器端呈现的。我们可以在`http://localhost:8080/about`访问关于页面。以下是从服务器端呈现的关于页面的外观：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/d2c0612e-9e58-4e6c-a86d-014515d6a91b.png)

图 4.5 从服务器端呈现的关于页面

# 在客户端设置模板集

现在我们已经看到了 Web 模板如何在服务器端呈现，是时候关注 Web 模板如何在客户端呈现了。我们客户端 Web 应用程序的主要入口点是`client.go`源文件中`client`文件夹中定义的`main`函数：

```go
func main() {

  var D = dom.GetWindow().Document().(dom.HTMLDocument)
  switch readyState := D.ReadyState(); readyState {
  case "loading":
    D.AddEventListener("DOMContentLoaded", false, func(dom.Event) {
      go run()
    })
  case "interactive", "complete":
    run()
  default:
    println("Encountered unexpected document ready state value!")
  }

}
```

首先，我们将文档对象分配给`D`变量，我们在这里执行了通常的别名操作，以节省一些输入。然后，我们在文档对象的`readyState`属性上声明了一个`switch`块。我们通过在`Document`对象上调用`ReadyState`方法来获取文档对象的`readyState`。

文档的 readyState 属性描述了文档的加载状态。您可以在 Mozilla 开发者网络上阅读有关此属性的更多信息：[`developer.mozilla.org/en-US/docs/Web/API/Document/readyState`](https://developer.mozilla.org/en-US/docs/Web/API/Document/readyState)。

在第一个`case`语句中，我们将检查`readyState`值是否为`"loading"`，如果是，则表示文档仍在加载中。我们设置一个事件侦听器来监听`DOMContentLoaded`事件。`DOMContentLoaded`事件将告诉我们网页已完全加载，此时我们可以调用`run`函数作为 goroutine。我们将`run`函数作为 goroutine 调用，因为我们不希望`run`函数内部的任何操作被阻塞，因为我们是从事件处理程序函数中调用它的。

在第二个`case`语句中，我们将检查`readyState`值是否为`interactive`或`complete`。`interactive`状态表示文档已经完成加载，但可能还有一些资源，如图像或样式表，尚未完全加载。`complete`状态表示文档和所有子资源都已完成加载。如果`readyState`是交互式或完整的，我们将调用`run`函数。

最后，`default`语句处理意外行为。理想情况下，我们永远不应该达到`default`情况，如果我们确实达到了，我们将在 Web 控制台中打印一条消息，指示我们遇到了意外的文档`readyState`值。

我们在`main`函数中创建的功能为我们提供了宝贵的好处，即能够从 HTML 文档的`<head>`部分作为外部 JavaScript 源文件导入我们的 GopherJS 生成的 JavaScript 源文件`client.js`，如下所示（用粗体显示）：

```go
<head>
  <title>{{.PageTitle}}</title> 
  <link rel="icon" type="image/png" href="/static/images/isomorphic_go_icon.png">
  <link rel="stylesheet" href="/static/css/pure.min.css">
  <link rel="stylesheet" type="text/css" href="/static/css/cogimports.css">
  <link rel="stylesheet" type="text/css" href="/static/css/igweb.css">
  <script src="img/cogimports.js" type="text/javascript" async></script>
 <script type="text/javascript" src="img/client.js"></script>
</head>
```

这意味着我们不必在关闭`</body>`标签之前导入外部 JavaScript 源文件，以确保网页已完全加载。在头部声明中包含外部 JavaScript 源文件的过程更加健壮，因为我们的代码特别考虑了`readyState`。另一种更脆弱的方法对`readyState`漠不关心，并且依赖于包含的`<script>`标签在 HTML 文档中的位置才能正常工作。

在`run`函数内，我们将首先在 Web 控制台中打印一条消息，指示我们已成功进入客户端应用程序：

```go
println("IGWEB Client Application")
```

然后，我们将从本章前面设置的服务器端`/template-bundle`路由中获取模板集：

```go
templateSetChannel := make(chan *isokit.TemplateSet)
funcMap := template.FuncMap{"rubyformat": templatefuncs.RubyDate, "unixformat": templatefuncs.UnixTime, "productionmode": templatefuncs.IsProduction}
go isokit.FetchTemplateBundleWithSuppliedFunctionMap(templateSetChannel, funcMap)
ts := <-templateSetChannel
```

我们将创建一个名为`templateSetChannel`的通道，类型为`*isokit.TemplateSet`，我们将在其中接收`TemplateSet`对象。我们将创建一个包含`rubyformat`和`unixformat`自定义函数的函数映射。然后，我们将从`isokit`包中调用`FetchTemplateBundleWithSuppliedFunctionMap`函数，提供我们刚刚创建的`templateSetChannel`以及`funcMap`变量。

`FetchTemplateBundleWithSuppliedFunctionMap`函数负责从服务器端获取模板包项映射，并使用此映射组装模板集。除此之外，接收到的`TemplateSet`对象的`Funcs`属性将使用`funcMap`变量填充，确保自定义函数对模板集中的所有模板都是可访问的。成功调用此方法后，模板集将通过`templateSetChannel`发送。最后，我们将使用从`templateSetChannel`接收到的`*isokit.TemplateSet`值来分配`ts`变量。

我们将创建`Env`对象的新实例，我们将在整个客户端应用程序中使用它：

```go
env := common.Env{}
```

然后，我们将`TemplateSet`属性填充为我们刚刚创建的`Env`实例：

```go
env.TemplateSet = ts
```

为了避免每次需要访问`Window`对象时都要输入`dom.GetWindow()`，以及访问`Document`对象时都要输入`dom.GetWindow().Document()`，我们可以将`env`对象的`Window`和`Document`属性填充为它们各自的值：

```go
env.Window = dom.GetWindow()
env.Document = dom.GetWindow().Document()
```

当用户点击网站的不同部分时，我们将动态替换主要内容`div`容器的内容。我们将填充`env`对象的`PrimaryContent`属性以保存主要内容`div`容器：

```go
env.PrimaryContent = env.Document.GetElementByID("primaryContent")
```

当我们需要从路由处理程序函数内访问此`div`容器时，这将非常方便。它使我们免于每次在路由处理程序中需要时执行 DOM 操作来检索此元素。

我们将调用`registerRoutes`函数，并将`env`对象的引用作为函数的唯一输入参数提供给它：

```go
registerRoutes(&env)
```

此函数负责注册所有客户端路由及其关联的处理程序函数。

我们将调用`initializePage`函数，并将`env`对象的引用提供给它：

```go
initializePage(&env)
```

此函数负责为给定的客户端路由初始化网页上的交互元素和组件。

在`registerRoutes`函数中，有两个特别感兴趣的任务：

1.  创建客户端路由

1.  注册客户端路由

# 创建客户端路由

首先，我们将创建`isokit`路由对象的新实例，并将其分配给`r`变量：

```go
 r := isokit.NewRouter()
```

# 注册客户端路由

第二行代码注册了客户端`/about`路由，以及与之关联的客户端处理函数`AboutHandler`，来自`handlers`包。

```go
 r.Handle("/about", handlers.AboutHandler(env))
```

我们将在第五章中更详细地介绍`registerRoutes`函数的其余部分，*端到端路由*。

# 初始化网页上的交互元素

`initializePage`函数将在网页首次加载时调用一次。它的作用是初始化使用户能够与客户端 Web 应用程序进行交互的功能。这将是给定网页的相应`initialize`函数，负责初始化事件处理程序和可重用组件（齿轮）。

在`initializePage`函数内部，我们将从窗口位置对象的`PathName`属性中提取`routeName`；`http://localhost:8080/about` URL 的路由名称将是`"about"`。

```go
l := strings.Split(env.Window.Location().Pathname, "/")
routeName := l[1]

if routeName == "" {
  routeName = "index"
}
```

如果没有可用的`routeName`，我们将把值赋给`"index"`，即主页的路由名称。

我们将在`routeName`上声明一个`switch`块，以下是处理`routeName`等于`"about"`的情况的相应`case`语句：

```go
case "about":
  handlers.InitializeAboutPage(env)
```

关于页面的指定`initialize`函数是`InitializeAboutPage`函数，它在`handlers`包中定义。此函数负责在`About`页面上启用用户交互。

既然我们已经在客户端设置了模板集，并注册了`/about`路由，让我们继续看看客户端的`About`页面处理函数。

# 从客户端渲染关于页面

以下是在`client/handlers`文件夹中找到的`about.go`源文件中`AboutHandler`函数的定义：

```go
func AboutHandler(env *common.Env) isokit.Handler {
  return isokit.HandlerFunc(func(ctx context.Context) {
    gopherTeamChannel := make(chan []*models.Gopher)
    go FetchGopherTeam(gopherTeamChannel)
    gophers := <-gopherTeamChannel
    templateData := templatedata.About{PageTitle: "About", Gophers: gophers}
    env.TemplateSet.Render("about_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
    InitializeAboutPage(env)
  })
}
```

我们首先创建一个名为`gopherTeamChannel`的通道，我们将使用它来检索`Gopher`实例的切片。我们将调用`FetchGopherTeam`函数作为一个 goroutine，并将`gopherTeamChannel`作为函数的唯一输入参数。

然后，我们将接收从`gopherTeamChannel`返回的值，并将其赋给`gophers`变量。

我们将声明并初始化`templateData`变量，即`about_content`模板的数据对象，其类型为`templatedata.About`。我们将设置模板数据对象的`PageTitle`属性，并使用我们刚刚创建的`gophers`变量填充`Gophers`属性。

我们将在模板集对象上调用`Render`方法来渲染关于模板。我们传递给函数的第一个参数是模板的名称，即对应于关于内容模板的`about_content`。在服务器端，我们使用了`about_page`模板，因为我们还需要生成整个网页布局。由于我们是从客户端操作，这不是必要的，因为我们只需要用`about_content`模板的渲染内容填充主要内容区域。

`Render`方法的第二个和最后一个参数是`isokit.RenderParams`类型的渲染参数。让我们检查一下在`RenderParams`对象中设置的每个属性。

`Data`属性指定模板将使用的模板数据对象。

`Disposition`属性指定将相对于相关目标元素呈现的模板内容的处理方式。`isokit.PlacementReplaceInnerContents`处理方式指示渲染器替换相关目标元素的内部内容。

`Element`属性指定渲染器应该考虑的相关目标元素。我们将把模板的渲染内容放在主要内容`div`容器中，因此我们将`env.PrimaryContent`分配给`Element`属性。

`PageTitle`属性指定应该使用的网页标题。模板数据对象的`PageTitle`属性在客户端端和服务器端一样重要，因为客户端渲染器有能力更改网页的标题。

最后，我们调用`InitializeAboutPage`函数来启用需要用户交互的功能。如果“关于”页面是网站上渲染的第一个页面（从服务器端），则`InitalizeAboutPage`函数将从`client.go`源文件中的`initializePage`函数中调用。如果我们随后点击导航栏上的“关于”链接而着陆在“关于”页面上，则请求将由客户端的`AboutHandler`函数处理，并通过调用`InitializeAboutPage`函数来启用需要用户交互的功能。

在“关于”页面的用户交互方面，我们只有一个可重用的组件，用于以人类可读的格式显示时间。我们不设置任何事件处理程序，因为在这个特定页面上没有任何按钮或用户输入字段。在这种情况下，我们将暂时跳过`InitializeAboutPage`函数，并在第九章“齿轮-可重用组件”中返回它。我们将在第五章“端到端路由”中向您展示为特定网页设置事件处理程序的`initialize`函数的示例。

`FetchGopherTeam`函数负责对`/restapi/get-gopher-team` Rest API 端点进行 XHR 调用，并检索出出现在“关于”页面上的地鼠列表。让我们来看看`FetchGopherTeam`函数：

```go
func FetchGopherTeam(gopherTeamChannel chan []*models.Gopher) {
  data, err := xhr.Send("GET", "/restapi/get-gopher-team", nil)
  if err != nil {
    println("Encountered error: ", err)
  }
  var gophers []*models.Gopher
  json.NewDecoder(strings.NewReader(string(data))).Decode(&gophers)
  gopherTeamChannel <- gophers
}
```

我们通过从`xhr`包中调用`Send`函数来进行 XHR 调用，并指定我们将使用`GET` HTTP 方法进行调用。我们还指定调用将被发往`/restapi/get-gopher-team`端点。`Send`函数的最后一个参数是`nil`，因为我们不会从客户端向服务器发送任何数据。

如果 XHR 调用成功，服务器将以 JSON 编码的数据作出响应，表示地鼠的一个切片。我们将创建一个新的 JSON 解码器，将服务器的响应解码为`gophers`变量。最后，我们将通过`gopherTeamChannel`发送`gophers`切片。

现在是时候检查一下负责处理我们的 XHR 调用以获取 IGWEB 团队地鼠的 Rest API 端点了。

# Gopher 团队 Rest API 端点

`/restapi/get-gopher-team`路由由`endpoints`文件夹中的`gopherteam.go`源文件中定义的`GetGopherTeamEndpoint`函数处理：

```go
func GetGopherTeamEndpoint(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    gophers := env.DB.GetGopherTeam()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(gophers)
  })
}
```

我们将声明并初始化`gophers`变量，以调用`env.DB`的 Redis 数据存储对象的`GetGopherTeam`方法返回的值。然后，我们将设置一个标头，指示服务器将发送 JSON 响应。最后，我们将使用 JSON 编码器将地鼠的切片编码为 JSON 数据。数据通过`http.ResponseWriter` `w`发送到客户端。

我们现在已经设置好了从客户端渲染“关于”页面所需的一切。我们可以通过在导航栏上点击“关于”链接来查看我们的客户端渲染的“关于”页面。以下是客户端渲染的“关于”页面的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/30089b59-1891-4621-84ef-65e9290362dd.png)

图 4.6 从客户端渲染的“关于”页面

您能看出服务器端渲染的“关于”页面和客户端渲染的页面之间有什么区别吗？你不应该看到任何区别，因为它们实际上是相同的！我们通过简单地在主要内容区域`div`容器中渲染“关于”页面内容，避免了用户必须观看完整页面重新加载。

看一下显示每个地鼠的开始时间。这里呈现的第一个时间遵循 Go 的默认时间格式。第二个时间是使用 Ruby 日期格式的时间。请记住，我们使用自定义函数以这种格式呈现时间。第三个开始时间以人类可读的格式显示。它使用可重用组件来格式化时间，我们将在第九章中介绍，*齿轮-可重用组件*。

现在我们知道如何同构渲染模板，我们将按照相同的流程处理 IGWEB 上的其他页面。

# 总结

在本章中，我们向您介绍了 Web 模板系统以及构成它的各个组件-模板引擎、模板数据对象和模板。我们探讨了 Web 模板系统的每个组件的目的，并为 IGWEB 设计了 Web 页面结构。我们涵盖了三种模板类别：布局模板、部分模板和常规模板。然后，我们将 IGWEB 页面结构的每个部分实现为模板。我们向您展示了如何定义自定义模板函数，以便在各种环境中重用。

然后，我们向您介绍了同构模板渲染的概念。我们确定了标准模板渲染的局限性，基于从文件系统加载模板文件，并介绍了由`isokit`包提供的内存模板集，以同构方式渲染模板。然后，我们演示了如何在服务器端和客户端上设置模板集并渲染“关于”页面。

在本章中，我们简要介绍了路由，只是为了理解如何在服务器端和客户端注册`/about`路由及其关联的处理程序函数。在第五章中，*端到端路由*，我们将更详细地探讨端到端应用程序路由。


# 第五章：端到端路由

**端到端应用程序路由**是使我们能够利用经典 Web 应用程序架构和单页面应用程序架构的优势的魔力。在实现现代 Web 应用程序时，我们必须在满足两个不同受众（人类和机器）的需求之间取得平衡。

首先让我们从人类用户的角度考虑体验。当人类用户直接访问我们在上一章演示的“关于”页面时，模板渲染首先在服务器端执行。这为人类用户提供了一个初始页面加载，因为网页内容是立即可用的，所以被认为是快速的。这是经典的 Web 应用程序架构的特点。对于用户与网站的后续交互采取了不同的方法。当用户从导航菜单点击“关于”页面的链接时，模板渲染在客户端执行，无需进行完整的页面重新加载，从而提供更流畅和流畅的用户体验。这是单页面应用程序架构的特点。

机器用户包括定期访问网站的各种搜索引擎爬虫。正如您在第一章中学到的，*使用 Go 构建同构 Web 应用程序*，单页面应用程序主要不利于搜索引擎，因为绝大多数搜索引擎爬虫没有智能来遍历它们。传统的搜索引擎爬虫习惯于解析已经呈现的格式良好的 HTML 标记。训练这些爬虫解析用于实现单页面应用程序架构的 JavaScript 要困难得多。如果我们希望获得更大的搜索引擎可发现性，我们必须满足我们的机器受众的需求。

在实现 IGWEB 的产品相关页面时，我们将学习如何在本章中实现这一目标，即在满足这两个不同受众的需求之间取得平衡。

在本章中，我们将涵盖以下主题：

+   路由视角

+   产品相关页面的设计

+   实现与产品相关的模板

+   建模产品数据

+   访问产品数据

+   使用 Gorilla Mux 注册服务器端路由

+   服务器端处理程序函数

+   使用 isokit 路由器注册客户端路由

+   客户端处理程序函数

+   Rest API 端点

# 路由视角

让我们从服务器端和客户端的角度考虑 Isomorphic Go Web 应用程序中的路由工作原理。请记住，我们的目标是利用端到端路由为机器用户提供网页内容访问，并为人类用户提供增强的用户体验。

# 服务器端路由

*图 5.1*描述了 Isomorphic Go 应用程序中的初始页面加载，实现了经典的 Web 应用程序架构。客户端可以是通过提供 URL 访问网站的 Web 浏览器或机器（机器）。URL 包含客户端正在访问的路由。例如，`/products`路由将提供产品列表页面。`/product-detail/swiss-army-knife`路由将提供网站上销售的瑞士军刀产品的产品详细页面。请求路由器负责将路由映射到其指定的路由处理程序函数。我们将在服务器端使用的请求路由器是 Gorilla Mux 路由器，它在`mux`包中可用：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/bd37be68-f694-4e99-8e5a-dffc6f412520.png)

图 5.1：Isomorphic Go 应用程序中的初始页面加载

路由处理程序负责服务特定路由。它包含一组逻辑，用于执行给定路由的任务。例如，`/products`路由的路由处理程序负责获取要显示的产品，从相关模板中呈现产品列表网页，并将响应发送回客户端。来自 Web 服务器的响应是一个 HTML 文档，其中包含与关联的 CSS 和 JavaScript 源文件的链接。返回的 Web 页面也可能包含内联的 CSS 或 JavaScript 部分。

请注意，尽管图表描绘了 Golang 在 Web 浏览器内运行，但实际上在 Web 浏览器内运行的是 Go 程序的 JavaScript 表示（使用 GopherJS 转译）。当客户端接收到服务器响应时，Web 页面将在 Web 浏览器内的用户界面中呈现。

# 客户端路由

*图 5.2*描述了从 Isomorphic Go 应用程序的客户端角度实现单页面应用程序架构的路由。

在*图 5.1*中，客户端只是简单地呈现 Web 页面服务器响应的角色。现在，除了显示呈现的 Web 页面外，客户端还包含请求路由器、路由处理程序和应用程序业务逻辑。

我们将使用`isokit`包中的 isokit 路由器执行客户端路由。客户端路由器的工作方式与服务器端路由器类似，只是不是评估 HTTP 请求，而是拦截在网页上定义的超链接的点击，并将其路由到客户端自身定义的特定路由处理程序。服务特定路由的客户端路由处理程序通过 Rest API 端点与服务器交互，通过发出 XHR 请求访问。来自 Web 服务器的响应是可以采用各种格式的数据，如 JSON、XML、纯文本和 HTML 片段，甚至是 Gob 编码的数据。在本章中，我们将使用 JSON 作为数据交换的手段。应用程序的业务逻辑将决定数据的处理方式，并且可以在用户界面中显示。此时，所有渲染操作都可以在客户端上进行，从而可以防止整个页面重新加载：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/563dbef7-1158-4954-a3a3-6146c5f0d36e.png)

图 5.2：端到端路由包括两端的路由器

# 产品相关页面的设计

IGWEB 的产品相关页面包括产品列表页面和产品详细页面。产品页面，也可以称为产品列表页面，将显示用户可以从网站购买的商品列表。如*图 5.3*所示的线框图，每个产品都包含产品的缩略图，产品价格，产品名称，产品的简要描述，以及将产品添加到购物车的按钮。点击产品图片将带用户进入给定产品的产品详细页面。访问产品列表页面的路由是`/products`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/6d8d4c86-627c-409f-9dda-730870fbfc1b.png)

图 5.3：产品页面的线框设计

产品详细页面包含有关单个产品的信息。如*图 5.4*所示的线框设计，产品详细页面包括产品的全尺寸图像、产品名称、产品价格、产品的长描述以及将产品添加到购物车的按钮。访问产品详细页面的路由是`/product-detail/{productTitle}`。`{productTitle}`是产品的**SEO**（搜索引擎优化）友好名称，例如，瑞士军刀产品的`{productTitle}`值将是`"swiss-army-knife"`。通过在`/product-detail`路由中定义 SEO 友好的产品名称，我们使搜索引擎机器人更容易索引网站，并从产品详细 URL 集合中推导出语义含义。事实上，搜索引擎友好的 URL 被称为**语义 URL**。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/5a11f748-d1e1-466f-99ad-906801884842.png)

图 5.4：产品详细页面的线框设计

# 实现与产品相关的模板

实现与产品相关的模板包括实现产品列表页面的模板和产品详细页面的模板。产品列表页面如*图 5.3*所示，产品详细页面如*图 5.4*所示。我们将实现模板来实现这些线框设计。

# 实现产品列表页面的模板

让我们来看看`shared/templates`目录中找到的`products_page.tmpl`源文件：

```go
{{ define "pagecontent" }}
{{template "products_content" . }}
{{end}}
{{template "layouts/webpage_layout" . }}
```

这是产品列表页面的页面模板。这个模板的主要目的是呈现`products_content`模板的内容，并将其放置在网页布局中。

让我们来看看`shared/templates`目录中找到的`products_content.tmpl`源文件：

```go
<h1>Products</h1>

<div id="productsContainer">
  {{if .Products}}
  {{range .Products}}
  <div class="productCard">
    <a href="{{.Route}}">
    <div class="pricebox"><span>${{.Price}}</span></div>
    <div class="productCardImageContainer">
      <img src="img/{{.ThumbnailPreviewURI}}">
    </div>
    </a>
    <div class="productContainer">

    <h3><b>{{.Name}}</b></h3> 
    <p>{{.Description}}</p> 

    <div class="pure-controls">
      <button class="addToCartButton pure-button pure-button-primary" data-sku="{{.SKU}}">Add To Cart</button>
    </div>

    </div>
  </div>
  {{end}}
  {{else}}
    <span>If you're not seeing any products listed here, you probably need to load the sample data set into your Redis instance. You can do so by <a target="_blank" href="/config/load-sample-data">clicking this link</a>.</span>
  {{end}}
</div>
```

这是产品列表页面的内容模板。这个模板的目的是显示所有可供销售的产品。在`productsContainer` `div`元素内，我们指定了一个`{{if}}`条件，检查是否有产品可供显示。如果有产品可用，我们使用`{{range}}`模板动作来遍历所有可用的`Product`对象，并生成每个产品卡所需的 HTML 标记。我们定义了一个锚（`<a>`）标签，使图像可点击，这样用户可以直接点击产品图像进入产品详细页面。我们还定义了一个按钮，将产品添加到购物车中。

如果没有产品可供显示，我们会到达`{{else}}`条件，并放置一个有用的消息，指示需要将产品从样本数据集加载到 Redis 数据库实例中。为了方便读者，我们提供了一个可以点击的超链接，点击后将样本数据填充到 Redis 实例中。

# 实现产品详细页面的模板

让我们来看看`shared/templates`目录中找到的`product_detail_page.tmpl`源文件：

```go
{{ define "pagecontent" }}
{{template "product_detail_content" . }}
{{end}}
{{template "layouts/webpage_layout" . }}
```

这是产品详细页面的页面模板。其主要目的是呈现`product_detail_content`模板的内容，并将其放置在网页布局中。

让我们来看看`shared/templates`目录中找到的`product_detail_content.tmpl`源文件：

```go
<div class="productDetailContainer">

  <div class="productDetailImageContainer">
    <img src="img/{{.Product.ImagePreviewURI}}">
  </div>

  <div class="productDetailHeading">
    <h1>{{.Product.Name}}</h1>
  </div>

  <div class="productDetailPrice">
    <span>${{.Product.Price}}</span>
  </div>

  <div class="productSummaryDetail">
    {{.Product.SummaryDetail}}
  </div>

  <div class="pure-controls">
    <button class="addToCartButton pure-button pure-button-primary" data-sku="{{.Product.SKU}}">Add To Cart</button>
  </div>

</div>
```

在这个模板中，我们定义了呈现产品详细页面的产品详细容器所需的 HTML 标记。我们呈现产品图像以及产品名称、产品价格和产品的详细摘要。最后，我们声明了一个按钮，将产品添加到购物车中。

# 对产品数据进行建模

我们在`shared/models/product.go`源文件中定义了`Product`结构来对产品数据进行建模。

```go
package models

type Product struct {
  SKU string
  Name string
  Description string
  ThumbnailPreviewURI string
  ImagePreviewURI string
  Price float64
  Route string
  SummaryDetail string
  Quantity int
}
```

`SKU`字段代表产品的库存单位（`SKU`），这是代表产品的唯一标识。在提供的样本数据集中，我们使用递增的整数值，但是这个字段是`string`类型的，以便将来可以容纳包含字母数字的 SKU，以实现可扩展性。`Name`字段代表产品的名称。`Description`字段代表将包含在产品列表页面中的简短描述。`ThumbnailPreviewURI`字段提供产品缩略图的路径。`Price`字段代表产品的价格，类型为`float64`。`Route`字段是给定产品的服务器相对路径到产品详细页面。`SummaryDetail`字段代表产品的长描述，将显示在产品详细页面中。最后，`Quantity`字段是`int`类型，代表目前在购物车中的特定产品数量。在下一章中，当我们实现购物车功能时，我们将使用这个字段。

# 访问产品数据

对于我们的产品数据访问需求，我们在 Redis 数据存储中定义了两种方法。`GetProducts`方法将返回一个产品切片，并满足产品列表页面的数据需求。`GetProductDetail`方法将返回给定产品的配置信息，满足产品详细页面的数据需求。

# 从数据存储中检索产品

让我们来看看在`common/datastore/redis.go`源文件中定义的`GetProducts`方法：

```go
func (r *RedisDatastore) GetProducts() []*models.Product {

  registryKey := "product-registry"
  exists, err := r.Cmd("EXISTS", registryKey).Int()

  if err != nil {
    log.Println("Encountered error: ", err)
    return nil
  } else if exists == 0 {
    return nil
  }

  var productKeys []string
  jsonData, err := r.Cmd("GET", registryKey).Str()
  if err != nil {
    log.Print("Encountered error when attempting to fetch product registry data from Redis instance: ", err)
    return nil
  }

  if err := json.Unmarshal([]byte(jsonData), &productKeys); err != nil {
    log.Print("Encountered error when attempting to unmarshal JSON product registry data: ", err)
    return nil
  }

  products := make([]*models.Product, 0)

  for i := 0; i < len(productKeys); i++ {

    productTitle := strings.Replace(productKeys[i], "/product-detail/", "", -1)
    product := r.GetProductDetail(productTitle)
    products = append(products, product)

  }
  return products
}
```

在这里，我们首先检查 Redis 数据存储中是否存在产品注册键`"product-registry"`。如果存在，我们声明一个名为`productKeys`的字符串切片，其中包含要显示在产品列表页面上的所有产品的键。我们在 Redis 数据存储对象`r`上使用`Cmd`方法来发出 Redis 的`"GET"`命令，用于检索给定键的记录。我们将`registryKey`作为方法的第二个参数。最后，我们将方法调用链接到`.Str()`方法，将输出转换为字符串类型。

# 从数据存储中检索产品详细信息

Redis 数据存储中的产品注册数据是表示字符串切片的 JSON 数据。我们使用`json`包中的`Unmarshal`函数将 JSON 编码的数据解码为`productKeys`变量。现在，我们已经获得了应该显示在产品列表页面上的所有产品键，是时候为每个键创建一个产品实例了。我们首先声明将成为产品切片的`products`变量。我们遍历产品键并得出`productTitle`值，这是产品的 SEO 友好名称。我们将`productTitle`变量提供给 Redis 数据存储的`GetProductDetail`方法，以获取给定产品标题的产品。我们将获取的产品赋给`product`变量，并将其追加到`products`切片中。一旦`for`循环结束，我们将收集到应该显示在产品列表页面上的所有产品。最后，我们返回`products`切片。

让我们来看看在`common/datastore/redis.go`源文件中定义的`GetProductDetail`方法：

```go
func (r *RedisDatastore) GetProductDetail(productTitle string) *models.Product {

  productKey := "/product-detail/" + productTitle
  exists, err := r.Cmd("EXISTS", productKey).Int()

  if err != nil {
    log.Println("Encountered error: ", err)
    return nil
  } else if exists == 0 {
    return nil
  }

  var p models.Product
  jsonData, err := r.Cmd("GET", productKey).Str()

  if err != nil {
    log.Print("Encountered error when attempting to fetch product data from Redis instance: ", err)
    return nil
  }

  if err := json.Unmarshal([]byte(jsonData), &p); err != nil {
    log.Print("Encountered error when attempting to unmarshal JSON product data: ", err)
    return nil
  }

  return &p

}
```

我们将`productKey`变量声明为`string`类型，并赋予产品详细页面的路由值。这涉及将`"/product-detail"`字符串与给定产品的`productTitle`变量连接起来。我们检查产品键是否存在于 Redis 数据存储中。如果不存在，我们从方法中返回；如果存在，我们继续声明`p`变量为`Product`类型。这将是函数将返回的变量。Redis 数据存储中存储的产品数据是`Product`对象的 JSON 表示。我们将 JSON 编码的数据解码为`p`变量。如果我们没有遇到任何错误，我们将返回`p`，它代表了请求的`productTitle`变量的`Product`对象，该变量被指定为`GetProductDetail`方法的输入参数。

到目前为止，我们已经满足了在`/products`路由上显示产品列表和在`/product-detail/{productTitle}`路由上显示产品概要页面的数据需求。现在是时候注册与产品相关页面的服务器端路由了。

# 使用 Gorilla Mux 注册服务器端路由

我们将使用 Gorilla Mux 路由器来处理服务器端应用程序的路由需求。这个路由器非常灵活，因为它不仅可以处理简单的路由，比如`/products`，还可以处理带有嵌入变量的路由。回想一下，`/product-detail`路由包含嵌入的`{productTitle}`变量。

我们将首先创建一个 Gorilla Mux 路由器的新实例，并将其分配给`r`变量，如下所示：

```go
  r := mux.NewRouter()
```

以下是在`igweb.go`源文件中定义的`registerRoutes`函数中的代码部分，我们在这里注册路由以及它们关联的处理函数：

```go
r.Handle("/", handlers.IndexHandler(env)).Methods("GET")
r.Handle("/index", handlers.IndexHandler(env)).Methods("GET")
r.Handle("/products", handlers.ProductsHandler(env)).Methods("GET")
r.Handle("/product-detail/{productTitle}", handlers.ProductDetailHandler(env)).Methods("GET")
r.Handle("/about", handlers.AboutHandler(env)).Methods("GET")
r.Handle("/contact", handlers.ContactHandler(env)).Methods("GET", "POST")

```

我们使用`Handle`方法将路由与负责处理该路由的处理函数关联起来。例如，当遇到`/products`路由时，它将由`handlers`包中定义的`ProductsHandler`函数处理。`ProductsHandler`函数将负责从数据存储中获取产品，使用产品记录从模板中呈现产品列表页面，并将网页响应发送回网页客户端。类似地，`/product-detail/{productTitle}`路由将由`ProductDetailHandler`函数处理。这个处理函数将负责获取单个产品的产品记录，使用产品记录从模板中呈现产品详细页面，并将网页响应发送回网页客户端。

# 服务器端处理函数

现在我们已经为与产品相关的页面注册了服务器端路由，是时候来检查负责处理这些路由的服务器端处理函数了。

# 产品列表页面的处理函数

让我们来看一下`handlers`目录中找到的`products.go`源文件：

```go
package handlers

import (
  "net/http"

  "github.com/EngineerKamesh/igb/igweb/common"
  "github.com/EngineerKamesh/igb/igweb/shared/templatedata"
  "github.com/isomorphicgo/isokit"
)

func ProductsHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    products := env.DB.GetProducts()
    templateData := &templatedata.Products{PageTitle: "Products", Products: products}
    env.TemplateSet.Render("products_page", &isokit.RenderParams{Writer: w, Data: templateData})
  })
}
```

在这里，我们通过在 Redis 数据存储对象`env.DB`上调用`GetProducts`方法来获取产品切片，该产品切片在产品页面上展示。我们声明了`templatedata.Products`类型的`templateData`变量，它代表将传递给模板引擎的数据对象，以及`products_page`模板，以渲染产品页面。`PageTitle`字段代表网页标题，`Products`字段是要在产品页面上显示的产品切片。

在`ProductsHandler`函数内部，我们调用数据存储对象的`GetProducts`方法，从数据存储中获取可供显示的产品。然后，我们创建一个模板数据实例，其`PageTitle`字段值为`"Products"`，并将从数据存储中获取的产品分配给`Products`字段。最后，我们从模板集中渲染`products_page`模板。关于我们传递给`env.TemplateSet`对象的`Render`方法的`RenderParams`对象，我们将`Writer`属性设置为`w`变量，即`http.ResponseWriter`，并将`Data`属性设置为`templateData`变量，即将提供给模板的数据对象。此时，渲染的网页将作为服务器响应发送回 Web 客户端。

图 5.5 显示了在访问`/products`路由后生成的产品页面，方法是访问以下链接：`http://localhost:8080/products`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/d0b0b6da-70a7-4a86-9e6d-f66e37778726.png)

图 5.5：产品页面

现在我们能够显示产品页面，让我们来看一下产品详细页面的处理函数。

# 产品详细页面的处理函数

让我们检查`handlers`目录中找到的`productdetail.go`源文件：

```go
package handlers

import (
  "net/http"

  "github.com/EngineerKamesh/igb/igweb/common"
  "github.com/EngineerKamesh/igb/igweb/shared/templatedata"
  "github.com/gorilla/mux"
  "github.com/isomorphicgo/isokit"
)

func ProductDetailHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    productTitle := vars["productTitle"]
    product := env.DB.GetProductDetail(productTitle)
    templateData := &templatedata.ProductDetail{PageTitle: product.Name, Product: product}
    env.TemplateSet.Render("product_detail_page", &isokit.RenderParams{Writer: w, Data: templateData})
  })
}
```

这是处理`/product/{productTitle}`路由的处理函数。请记住，这是嵌入变量的路由。在`ProductDetailHandler`函数内部，我们首先通过调用`mux`包的`Vars`函数来收集路由中定义的变量。我们将`r`，即`http.Request`的指针，作为`Vars`函数的输入参数。该函数的结果是`map[string]string`类型的映射，其中键是路由中变量的名称，值是该特定变量的值。例如，如果我们访问`/product-detail/swiss-army-knife`路由，键将是`"productTitle"`，值将是`"swiss-army-knife"`。

我们获取路由中提供的`productTitle`变量的值，并将其赋给`productTitle`变量。然后，我们通过向数据存储对象的`GetProductDetail`方法提供`productTitle`变量来获取产品对象。然后，我们设置我们的模板数据对象，设置页面标题和产品记录的字段。最后，我们在模板集上调用渲染方法，指示我们要渲染`product_detail_page`模板。我们将`http`响应写入对象和模板数据对象分配给渲染`params`对象的相应字段，该对象作为模板集的渲染方法的第二个参数传入。

此时，我们已经准备好渲染产品详细页面所需的一切。让我们访问`http://localhost:8080/products/swiss-army-knife`上的瑞士军刀产品详细页面。以下是在 Web 浏览器中呈现的产品详细页面：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/246bdb8e-387d-49a4-ba26-10f3bddf3e98.png)

图 5.6：瑞士军刀的产品详细页面

现在我们已经使`/products`和`/product-title/{productTitle}`路由对人类和机器都可用，并且我们已经实现了经典的 Web 应用程序架构。我们的机器用户（搜索引擎机器人）将会满意，因为他们可以轻松地索引产品列表页面上所有产品的链接，并且可以轻松解析每个产品详细页面上的 HTML 标记。

然而，我们还没有完全满足我们的人类观众。您可能已经注意到，从产品列表页面点击单个产品会导致整个页面重新加载。在短暂的瞬间，屏幕可能会在离开一个页面并在 Web 浏览器中呈现下一个页面的过渡中变白。当我们从产品详细页面点击导航菜单中的产品链接返回到产品列表页面时，同样会发生完整的页面重新加载。我们可以通过在初始页面加载后实现单页面架构来增强用户在网页之间的过渡体验。为了做到这一点，我们需要定义客户端路由以及它们相关的客户端路由处理程序函数。

# 使用 isokit 路由器注册客户端路由

在客户端，我们使用 isokit 路由器来处理路由。isokit 路由器通过拦截超链接的单击事件并检查超链接是否包含在其路由表中定义的路由来工作。

我们可以使用 isokit 路由器对象的`Handle`方法在路由表中注册路由。`Handle`方法接受两个参数——第一个参数是路由，第二个参数是应该服务该路由的处理程序函数。请注意，声明和注册路由的代码与服务器端的 Gorilla Mux 路由器非常相似。由于这种相似性，使用 isokit 路由器在客户端注册路由是直接的，感觉像是第二天性。

以下是在`client`文件夹中找到的`client.go`源文件中定义的`registerRoutes`函数的代码部分，该函数负责注册路由：

```go
  r := isokit.NewRouter()
  r.Handle("/index", handlers.IndexHandler(env))
 r.Handle("/products", handlers.ProductsHandler(env))
 r.Handle("/product-detail/{productTitle}", handlers.ProductDetailHandler(env))
  r.Handle("/about", handlers.AboutHandler(env))
  r.Handle("/contact", handlers.ContactHandler(env))
  r.Listen()
  env.Router = r
```

在这里，我们首先通过从`isokit`包中调用`NewRouter`函数创建一个新的 isokit 路由器，并将其分配给`r`变量。我们已经为产品列表页面定义了`/products`路由，以及为产品详细页面定义了`/product-data/{productTitle}`路由。在定义所有路由之后，我们调用路由器对象`r`的`Listen`方法。`Listen`方法负责为所有超链接添加事件侦听器，以侦听单击事件。在路由器的路由表中定义的链接将在单击事件发生时被拦截，并且它们相关的客户端路由处理程序函数将为它们提供服务。最后，我们将`r`路由器分配给`env`对象的`Router`字段，以便我们可以在客户端 Web 应用程序中访问路由器。

# 客户端处理程序函数

现在我们已经在客户端注册了与产品相关的页面的路由，让我们来看看负责服务这些路由的客户端路由处理程序函数。

# 产品列表页面的处理程序函数

让我们来看看`client/handlers`目录中`products.go`源文件中的`ProductsHandler`函数：

```go
func ProductsHandler(env *common.Env) isokit.Handler {
  return isokit.HandlerFunc(func(ctx context.Context) {

    productsChannel := make(chan []*models.Product)
    go FetchProducts(productsChannel)
    products := <-productsChannel
    templateData := &templatedata.Products{PageTitle: "Products", Products: products}
    env.TemplateSet.Render("products_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
    InitializeProductsPage(env)
    env.Router.RegisterLinks("#primaryContent a")
  })
}
```

回想一下，在*图 5.2*中描述的图表中，客户端 Web 应用通过对 Rest API 端点的 XHR 调用访问服务器端功能。在这里，我们创建`productsChannel`通道来检索`Product`对象的切片。我们调用`FetchProducts`函数，该函数将对服务器上负责检索要在产品页面上显示的可用产品列表的 Rest API 端点进行 XHR 调用。请注意，我们将`FetchProducts`函数作为 goroutine 调用。我们必须这样做以确保 XHR 调用不会阻塞。我们将`productsChannel`通道作为`FetchProducts`函数的唯一输入参数。然后，我们通过`productsChannel`通道检索产品列表并将其分配给`products`变量。

我们创建一个新的模板数据对象实例`templateData`，并设置`PageTitle`和`Products`字段的相应字段。之后，我们在`env.TemplateSet`对象上调用`Render`方法，指定我们要渲染`products_content`模板。在我们提供给`Render`函数的`RenderParams`对象中，我们使用模板数据对象`templateData`设置`Data`字段。我们将`Disposition`字段设置为`isokit.PlacementReplaceInnerContents`，以指定渲染的位置应替换相关元素的内部 HTML 内容。我们将`Element`字段设置为主要内容`div`容器，其中主页面内容被渲染。我们调用`InitializeProductsEventHandlers`函数来设置产品页面中找到的事件处理程序。对于产品页面，唯一需要事件处理程序的 DOM 元素是“添加到购物车”按钮，我们将在第六章 *同构交接*中介绍。

就客户端路由而言，`ProductsHandler`函数中的最后一行代码是最重要的一行代码。当模板渲染器渲染每个产品卡时，我们需要拦截每个产品项的链接。我们可以通过提供一个查询选择器来告诉 isokit 路由器拦截这些链接，该查询选择器将定位主要内容`div`容器中的链接。我们通过调用 isokit 路由器对象的`RegisterLinks`方法并指定查询选择器应为`"#primaryContent a"`来实现这一点。这将确保拦截所有产品项的链接，并且当我们单击产品项时，客户端路由处理程序将启动并服务请求，而不是执行完整的页面重新加载以到达`/product-detail/{productTitle}`路由。

# 获取产品列表

现在我们已经看到了客户端路由处理程序函数的工作原理，让我们来看看`FetchProducts`函数，该函数用于对服务器进行 XHR 调用并收集要在页面上显示的产品列表：

```go
func FetchProducts(productsChannel chan []*models.Product) {

  data, err := xhr.Send("GET", "/restapi/get-products", nil)
  if err != nil {
    println("Encountered error: ", err)
    return
  }
  var products []*models.Product
  json.NewDecoder(strings.NewReader(string(data))).Decode(&products)

  productsChannel <- products
}
```

在这里，我们使用`xhr`包来对服务器进行 XHR 调用。我们从`xhr`包中调用`Send`函数，并指定我们的请求将使用`GET`方法，并且我们将对`/restapi/get-products`端点进行请求。对于函数的第三个参数，我们传递了一个值`nil`，以指示我们在 XHR 调用中不发送数据。如果 XHR 调用成功，我们将从服务器接收 JSON 数据，该数据将表示`Product`对象的切片。我们创建一个新的 JSON 解码器来解码数据并将其存储在`products`变量中，然后将其发送到`productsChannel`。我们将在*用于服务此 XHR 调用的 Rest API 端点*部分中检查服务此 XHR 调用的 Rest API 端点。

此时，我们的 Web 应用程序已经实现了能够在与网站的后续交互中渲染产品页面而不引起完整页面重新加载的目标。例如，如果我们访问`http://localhost:8080/about`上的关于页面，初始页面加载将在服务器端进行。如果我们通过单击导航菜单中的产品链接来启动后续交互，客户端路由将启动，并且产品页面将加载，而不会发生完整的页面重新加载。

在*验证客户端路由功能*部分，我们将向您展示如何使用 Web 浏览器的检查器验证客户端路由是否正常运行。现在是时候实现产品详细页面的客户端路由处理程序了。

# 产品详细页面的处理程序函数

让我们来看看`client/handlers`目录中的`productdetail.go`源文件中定义的`ProductDetailHandler`函数：

```go
func ProductDetailHandler(env *common.Env) isokit.Handler {
  return isokit.HandlerFunc(func(ctx context.Context) {
    routeVars := ctx.Value(isokit.RouteVarsKey("Vars")).(map[string]string)
    productTitle := routeVars[`product-detail/{productTitle}`]
    productChannel := make(chan *models.Product)
    go FetchProductDetail(productChannel, productTitle)
    product := <-productChannel
    templateData := &templatedata.ProductDetail{PageTitle: product.Name, Product: product}
    env.TemplateSet.Render("product_detail_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
    InitializeProductDetailPage(env)
  })
}
```

`ProductDetailHandler`函数返回一个`isokit.Handler`值。请注意，我们将`isokit.HandlerFunc`指定为闭包，以便我们可以对我们的客户端处理程序函数执行依赖注入`env`对象。请注意，`isokit.HandlerFunc`的输入参数是`context.Context`类型。这个上下文对象很重要，因为它包含嵌入在路由中的变量信息。通过在`ctx`上下文对象上调用`Value`方法，我们可以通过将`"Vars"`键指定给上下文对象来获取路由变量。请注意，我们执行类型断言以指定从上下文对象获取的值是`map[string]string`类型。我们可以通过提供`product-detail/{productTitle}`键从路由中提取`productTitle`的值。`productTitle`的值很重要，因为我们将在向服务器发出 XHR 调用以获取产品对象时将其作为路由变量发送。

我们创建一个产品渠道`productChannel`，用于发送和接收`Product`对象。我们调用`FetchProductDetail`函数，提供`productChannel`和`productTitle`作为函数的输入参数。请注意，我们将函数作为 goroutine 调用，成功运行函数后，我们将通过`productChannel`发送一个产品对象。

我们设置模板数据对象，为`PageTitle`和`Product`字段指定值。然后我们将页面标题设置为产品名称。完成后，我们调用模板集对象的`Render`方法，并指定要渲染`product_detail_content`模板。我们设置渲染参数对象的字段，填充模板数据对象、位置和模板将被渲染到的相关元素的字段，这是主要内容`<div>`容器。最后，我们调用`InitializeProductDetailEventHanders`函数，该函数负责设置产品详情页面的事件处理程序。这个页面唯一需要处理程序的元素是“添加到购物车”按钮，我们将在下一章中介绍。

# 获取产品详情

让我们来看看`client/handlers`文件夹中`productdetail.go`源文件中定义的`FetchProductDetail`函数：

```go
func FetchProductDetail(productChannel chan *models.Product, productTitle string) {

  data, err := xhr.Send("GET", "/restapi/get-product-detail"+"/"+productTitle, nil)
  if err != nil {
    println("Encountered error: ", err)
    println(err)
  }
  var product *models.Product
  json.NewDecoder(strings.NewReader(string(data))).Decode(&product)

  productChannel <- product
}
```

这个函数负责向服务器端的 Rest API 端点发出 XHR 调用，以提供产品数据。该函数接受产品渠道和产品标题作为输入参数。我们通过调用`xhr`包的`Send`函数来进行 XHR 调用。请注意，在函数的第二个输入参数（我们发出请求的目的地）中，我们将`productTitle`变量连接到`/restapi/get-product-detail`路由。因此，例如，如果我们想请求瑞士军刀的产品对象，我们将指定路由为`/restapi/get-product-detail/swiss-army-knife`，在这种情况下，`productTitle`变量将等于`"swiss-army-knife"`。

如果 XHR 调用成功，服务器将返回 JSON 编码的产品对象。我们使用 JSON 解码器解码从服务器返回的 JSON 数据，并将`product`变量设置为解码的`Product`对象。最后，我们通过`productChannel`传递`product`。

# Rest API 端点

服务器端的 Rest API 端点非常方便。它们是在幕后向客户端 Web 应用程序提供数据的手段，我们将这些数据应用到相应的模板上，以显示页面内容，而无需进行完整的页面重新加载。

现在，我们将考虑创建这些 Rest API 端点所需的内容。我们首先必须在服务器端为它们注册路由。我们将遵循本章开头为产品列表页面和产品详细页面所做的相同过程。唯一的区别是我们的处理程序函数将在`endpoints`包中而不是在`handlers`包中。这里的根本区别在于`handlers`包包含将完整网页响应返回给 Web 客户端的处理程序函数。另一方面，`endpoints`包包含将数据返回给 Web 客户端的处理程序函数，很可能是以 JSON 格式返回。

以下是`igweb.go`源文件中的代码部分，我们在其中注册了我们的 Rest API 端点：

```go
r.Handle("/restapi/get-products", endpoints.GetProductsEndpoint(env)).Methods("GET")
r.Handle("/restapi/get-product-detail/{productTitle}", endpoints.GetProductDetailEndpoint(env)).Methods("GET")
```

请注意，驱动客户端产品页面的数据需求的`/restapi/get-products`路由由`endpoints`包中的`GetProductsEndpoint`函数提供服务。

同样，驱动客户端产品详细页面的`/restapi/get-product-detail/{productTitle}`路由由`endpoints`包中的`GetProductDetailEndpoint`函数提供服务。

# 获取产品列表的端点

让我们来看一下端点文件夹中的`products.go`源文件：

```go
package endpoints

import (
  "encoding/json"
  "net/http"

  "github.com/EngineerKamesh/igb/igweb/common"
)

func GetProductsEndpoint(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    products := env.DB.GetProducts()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(products)
  })
}
```

在`GetProductsEndpoint`函数内部，我们首先通过调用数据存储对象`env.DB`的`GetProducts`方法来获取将在客户端产品页面上显示的产品切片。然后，我们设置一个标头来指示服务器响应将以 JSON 格式返回。最后，我们使用 JSON 编码器将产品切片编码为 JSON 数据，并使用`http.ResponseWriter` `w`将其写出。

# 获取产品详细信息的端点

让我们来看一下端点文件夹中的`productdetail.go`源文件：

```go
package endpoints

import (
  "encoding/json"
  "net/http"

  "github.com/EngineerKamesh/igb/igweb/common"
  "github.com/gorilla/mux"
)

func GetProductDetailEndpoint(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    vars := mux.Vars(r)
    productTitle := vars["productTitle"]
    products := env.DB.GetProductDetail(productTitle)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(products)
  })
}
```

在`GetProductDetailEndpoint`函数内部，我们通过调用`mux`包中的`Vars`函数并将路由对象`r`作为唯一输入参数来获取嵌入的路由变量。然后，我们获取`{productTitle}`嵌入式路由变量的值并将其分配给变量`productTitle`。我们将`productTitle`提供给数据存储对象`env.DB`的`GetProductDetail`方法，以从数据存储中检索相应的`Product`对象。我们设置一个标头来指示服务器响应将以 JSON 格式返回，并使用 JSON 编码器将`Product`对象编码为 JSON 数据，然后使用`http.ResponseWriter` `w`将其发送到 Web 客户端。

我们现在已经达到了一个重要的里程碑。我们以一种对人类和机器都友好的方式实现了与产品相关的页面。当用户最初访问产品列表页面时，通过在 Web 浏览器中输入 URL（`http://localhost:8080/products`），页面在服务器端呈现，并将 Web 页面响应发送回客户端。用户能够立即看到网页，因为网页响应是预先呈现的。这种行为展现了经典 Web 应用程序架构的期望特征。

当人类用户发起后续交互时，通过单击产品项目，产品详细页面将从客户端呈现，并且用户无需经历完整页面重新加载。这种行为展现了 SPA 架构的期望特征。

机器用户（搜索引擎爬虫）也满意，因为他们可以遍历产品页面上的每个产品项目的链接并轻松索引网站，因为我们使用了语义化的 URL 以及搜索引擎爬虫可以理解的良好形式的 HTML 标记。

# 验证客户端路由功能

为了确保客户端路由正常运行，您可以执行以下过程：

1.  在您的 Web 浏览器中访问产品页面并打开 Web 浏览器的检查器。

1.  点击网络选项卡以查看网络流量，并确保过滤 XHR 调用。现在，点击产品项目以进入产品的详细页面。

1.  通过点击导航菜单上的“产品”链接返回产品页面。

重复此过程多次，您应该能够看到后台进行的所有 XHR 调用。*图 5.7*包括此过程的屏幕截图，以验证客户端路由是否正常运行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/5d31a4c4-b979-476b-8daf-fb608ee1a690.png)

图 5.7：Web 控制台中的 XHR 调用确认客户端路由正常运行

# 总结

在本章中，我们在构建与产品相关的页面时为 IGWEB 实现了端到端的应用程序路由。我们首先使用 Gorilla Mux 路由器注册了服务器端路由。我们将每个路由与相应的服务器端路由处理程序函数关联起来，该函数将为服务器端路由提供服务。然后，我们检查了产品相关页面的服务器端路由处理程序函数的实现。

在满足了实现初始页面加载的经典 Web 应用程序架构的需求后，我们通过首先在客户端注册与产品相关的页面的路由，使用 isokit 路由器，转向了客户端。就像我们在服务器端所做的那样，我们将每个客户端路由与相应的客户端路由处理程序函数关联起来，该函数将为客户端路由提供服务。您学会了如何实现客户端路由处理程序以及如何从中对服务器端 Rest API 端点进行 XHR 调用。最后，您学会了如何创建处理 XHR 请求并向客户端返回 JSON 数据的服务器端 Rest API 端点。

与数据存储的内容驱动的可用产品列表一样，与产品相关的页面具有持久状态。在用户与网站的交互改变了给定状态的情况下，我们如何维护状态？例如，如果用户向购物车中添加商品，我们如何维护购物车的状态并在服务器端和客户端之间进行同步？您将在第六章中了解*同构交接*，即在服务器端和客户端之间交接状态的过程。在此过程中，我们将为网站实现购物车功能。


# 第六章：同构交接

在同构 Go web 应用的开发中，前两章介绍了两个关键技术。首先，您学习了如何利用内存模板集在各种环境中呈现模板。其次，您学习了如何在客户端和服务器端执行端到端路由。客户端路由是使客户端 Web 应用程序以单页面模式运行的魔法。

上述技术现在为我们提供了在客户端本身导航到网站的不同部分并在各种环境中呈现任何给定模板的能力。作为同构 Go web 应用的实施者，我们的责任是确保在客户端和服务器之间维护状态。例如，在呈现产品页面时，如果产品列表在客户端和服务器端呈现方式不同，那就没有意义。客户端需要与服务器紧密合作，以确保状态（在这种情况下是产品列表）得到维护，这就是*同构交接*发挥作用的地方。

**同构交接**是指服务器将状态交接给客户端，客户端使用传递的状态在客户端呈现网页的过程。请记住，服务器传递给客户端的状态必须包括用于呈现服务器端网页响应的完全相同的状态。同构交接本质上允许客户端无缝地在服务器端中断的地方继续进行。在本章中，我们将重新访问与产品相关的页面，以了解状态如何从服务器端维护到客户端。此外，我们还将通过为这些页面中的“添加到购物车”按钮添加事件处理程序来完成产品相关页面的实施。

IGWEB 网站的购物车功能将在本章中实施，它将允许我们考虑用户可以通过向购物车中添加和删除商品来改变购物车状态的情景。我们将使用同构交接来确保购物车的当前状态在服务器和客户端之间无缝地维护。通过正确维护购物车的状态，我们可以保证从服务器端呈现的购物车页面始终与从客户端呈现的购物车页面匹配。

在本章中，我们将涵盖以下主题：

+   同构交接程序

+   为产品相关页面实现同构交接程序

+   为购物车实现同构交接

# 同构交接程序

同构 Web 应用程序开发中的一个重要主题是在服务器和客户端之间共享的能力。在同构 Web 应用程序中，服务器和客户端必须协同工作，以无缝地维护应用程序中特定工作流程的状态。为了做到这一点，服务器必须与客户端共享用于在服务器端呈现 Web 页面输出的当前状态。

# ERDA 策略

同构交接程序包括以下四个步骤：

1.  编码

1.  注册

1.  解码

1.  附加

我们可以使用缩写**ERDA**（**编码-注册-解码-附加**）来轻松回忆每个步骤。事实上，我们可以将实施同构交接程序的步骤统称为**ERDA 策略**。

通过实施同构交接程序的四个步骤，如*图 6.1*所示，我们可以确保状态在服务器和客户端之间成功持久化：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/b775dd1b-10c7-4646-88b4-5fae1ef16669.png)

图 6.1：实现同构交接的 ERDA 策略

第一步，编码，涉及将代表我们希望保留到客户端的状态的数据对象编码为数据交换格式（JSON、Gob、XML 等）。随后的步骤都在客户端上执行。第二步，注册，涉及注册客户端路由及其相应的处理程序函数。第三步，解码，涉及解码从服务器检索到的编码数据，通过 Rest API 端点，并利用它在客户端呈现网页的模板。第四步，附加，涉及将任何需要的事件处理程序附加到呈现的网页上，以实现用户交互。

*图 6.2*描述了在服务器端和客户端上涉及的关键模块，用于实现等同手 off 过程：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/2acedc0f-703d-4bc2-bcf3-8a6b05c716b0.png)

图 6.2：实现等同手 off 过程的关键模块

编码步骤是在服务器端 Web 应用程序中存在的 Rest API 端点内执行的。注册步骤是在客户端 Web 应用程序中存在的路由处理程序内执行的。解码步骤是在调用客户端模板渲染器之前执行的。附加步骤是通过在客户端实现 DOM 事件处理程序来执行的。

现在我们已经介绍了 ERDA 策略中的每个步骤，让我们详细探讨每个步骤。

# 编码步骤

我们的目标是在客户端重新生成状态，首先要识别代表我们希望保留的状态的数据对象，以便在特定网页中保持状态。要识别对象，我们只需要查看生成渲染的网页输出的服务器端处理程序函数。例如，在产品列表页面中，`Product`对象的片段将是我们希望保留到客户端的数据对象，以便客户端呈现的网页呈现相同的产品列表。

我们可以通过实现 Rest API 端点（在*图 6.2*中描述）将`Product`对象的片段暴露给客户端。编码步骤（在*图 6.1*中描述）包括将`Product`对象的片段编码为通用数据交换格式。对于本章，我们将使用 JSON（JavaScript 对象表示）格式对对象进行编码。客户端 Web 应用程序可以通过向 Rest API 端点发出 XHR 调用来访问编码对象。

现在编码状态对象可用，实现等同手 off 过程的其余步骤发生在客户端。

# 注册步骤

为了完成注册步骤（在*图 6.1*中描述），我们必须首先注册客户端路由及其相应的处理程序函数（在*图 6.2*中的路由处理程序框中描述）。例如，对于产品页面，我们将注册`/products`路由及其关联的处理程序函数`ProductsHandler`。当用户从导航栏点击产品链接时，点击事件将被 isokit 路由拦截，并且与处理`/products`路由的处理程序函数`ProductsHandler`相关联的处理程序函数将被调用。路由处理程序函数扮演着执行等同手 off 过程的最后两个步骤——解码和附加的角色。

请记住，如果用户首先通过在 Web 浏览器中输入 URL 直接访问网页而着陆在`/products`路由上，服务器端处理程序函数将启动，并且产品页面将在服务器端呈现。这使我们能够立即呈现网页，为用户提供被认为是快速的页面加载。

# 解码步骤

在路由处理程序函数中，我们发起一个 XHR 调用到 Rest API 端点，该端点将返回编码数据，表示我们希望在客户端保持的状态。一旦获取到编码数据，我们将执行等同交接过程的第三步**解码**（在*图 6.1*中描述）。在这一步中，我们将编码数据解码回对象实例。然后利用对象实例填充模板数据对象的相应字段，传递给模板渲染器（在*图 6.2*中描述），以便网页可以在客户端成功渲染，与在服务器端渲染的方式相同。

# 附加步骤

第四步也是最后一步，附加（在*图 6.1*中描述），负责将事件处理程序（在*图 6.2*中描述）附加到渲染的网页中存在的 DOM 元素上。例如，在产品页面中，我们需要将事件处理程序附加到网页上找到的所有“添加到购物车”按钮上。当按下“添加到购物车”按钮时，相应的产品将被添加到用户的购物车中。

到目前为止，我们已经铺设了实现给定网页的等同交接过程所需的基础工作。为了巩固我们对等同交接的理解，让我们考虑两个具体的例子，在这两个例子中我们实现了该过程的所有四个步骤。首先，我们将在产品相关页面实现等同交接过程，包括产品列表页面(`/products`)和产品详情页面(`/product-detail/{productTitle}`)。其次，我们将为购物车页面实现等同交接过程。第二个例子将更加动态，因为用户可以改变状态，用户可以随意添加和删除购物车中的商品。这种能力允许用户对购物车的当前状态施加控制。

# 为产品相关页面实现等同交接

如前所述，与产品相关的页面包括产品列表页面和产品详情页面。我们将遵循 ERDA 策略，为这些页面实现等同交接过程。

# 为产品模型实现排序接口

在开始之前，我们将在`shared/models/product.go`源文件中定义一个名为`Products`的新类型，它将是`Product`对象的切片：

```go
type Products []*Product
```

我们将`Products`类型实现`sort`接口，定义以下方法：

```go
func (p Products) Len() int { return len(p) }
func (p Products) Less(i, j int) bool { return p[i].Price &lt; p[j].Price }
func (p Products) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
```

通过检查`Less`方法，您将能够看到我们将按照产品价格升序（从低到高）对产品列表页面上显示的产品进行排序。

乍一看，我们可能会认为从 Redis 数据库获取的产品已经按照某种预定顺序排序。然而，如果我们希望等同交接成功，我们不能凭假设操作；我们必须凭事实操作。为了做到这一点，我们需要一个可预测的产品排序标准。

这就是为什么我们要为`Products`类型实现`sort`接口的额外工作，以便我们有一个可预测的标准，按照这个标准在产品列表页面上列出产品。这为我们提供了一个基准，用于验证等同交接的成功，因为我们只需要确认客户端渲染的产品列表页面与服务器端渲染的产品列表页面相同即可。确实很有帮助，我们有一个共同的、可预测的标准，产品按价格升序排序。

我们在`redis.go`源文件的`GetProducts`方法中添加以下行（以粗体显示）以对产品进行排序：

```go
func (r *RedisDatastore) GetProducts() []*models.Product {

  registryKey := "product-registry"
  exists, err := r.Cmd("EXISTS", registryKey).Int()

  if err != nil {
    log.Println("Encountered error: ", err)
    return nil
  } else if exists == 0 {
    return nil
  }

  var productKeys []string
  jsonData, err := r.Cmd("GET", registryKey).Str()
  if err != nil {
    log.Print("Encountered error when attempting to fetch product registry data from Redis instance: ", err)
    return nil
  }

  if err := json.Unmarshal([]byte(jsonData), &productKeys); err != nil {
    log.Print("Encountered error when attempting to unmarshal JSON product registry data: ", err)
    return nil
  }

  products := make(models.Products, 0)

  for i := 0; i &lt; len(productKeys); i++ {

    productTitle := strings.Replace(productKeys[i], "/product-detail/", "", -1)
    product := r.GetProductDetail(productTitle)
    products = append(products, product)

  }
 sort.Sort(products)
  return products
}
```

# 为产品列表页面实现等同交接

首先，我们必须实现**编码**步骤。为此，我们需要决定必须持久化到客户端的数据。通过检查负责渲染产品列表网页的服务器端处理函数`ProductsHandler`，我们可以轻松识别必须持久化到客户端的数据：

```go
func ProductsHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    products := env.DB.GetProducts()
    templateData := &templatedata.Products{PageTitle: "Products", Products: products}
    env.TemplateSet.Render("products_page", &isokit.RenderParams{Writer: w, Data: templateData})
  })
}
```

产品列表页面负责显示产品列表，因此，必须将`products`变量（加粗显示）持久化到客户端，这是`Product`对象的切片。

现在我们已经确定了需要持久化到客户端以维护状态的数据，我们可以创建一个 Rest API 端点`GetProductsEndpoint`，负责以 JSON 编码形式将产品切片传递给客户端：

```go
func GetProductsEndpoint(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    products := env.DB.GetProducts()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(products)
  })
}
```

我们在服务器端完成了实现同构交接的工作，现在是时候转向客户端了。

要实现**注册**步骤，我们在`client.go`源文件中的`registerRoutes`函数中添加以下行，以注册`/products`路由及其关联的处理函数`ProductsHandler`：

```go
  r.Handle("/products", handlers.ProductsHandler(env))
```

**解码**和**附加**步骤在`ProductsHandler`函数内执行：

```go
func ProductsHandler(env *common.Env) isokit.Handler {
  return isokit.HandlerFunc(func(ctx context.Context) {

    productsChannel := make(chan []*models.Product)
    go FetchProducts(productsChannel)
    products := &lt;-productsChannel
    templateData := &templatedata.Products{PageTitle: "Products", Products: products}
    env.TemplateSet.Render("products_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
    InitializeProductsPage(env)
    env.Router.RegisterLinks("#primaryContent a")
  })
}
```

首先，我们调用`FetchProducts`函数的 goroutine 来从服务器端的端点获取产品列表。**解码**步骤（加粗显示）在`FetchProducts`函数内执行：

```go
func FetchProducts(productsChannel chan []*models.Product) {

  data, err := xhr.Send("GET", "/restapi/get-products", nil)
  if err != nil {
    println("Encountered error: ", err)
    return
  }
  var products []*models.Product
  json.NewDecoder(strings.NewReader(string(data))).Decode(&products)

  productsChannel &lt;- products
}
```

从 Rest API 端点获取编码数据后，我们使用 JSON 解码器将编码数据解码回`Product`对象的切片。然后我们将结果发送到`productsChannel`，在`ProductsHandler`函数内接收。

现在我们有了用于填充产品列表页面上产品列表的数据对象，我们可以填充`templatedata.Products`结构的`Products`字段。回想一下，`templateData`是将传递到`env.TemplateSet`对象的`Render`方法中的数据对象：

```go
  templateData := &templatedata.Products{PageTitle: "Products", Products: products}
    env.TemplateSet.Render("products_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
```

到目前为止，我们已经完成了同构交接过程的第三步，这意味着我们可以有效地在客户端上渲染产品列表页面。但是，我们还没有完成，因为我们必须完成最后一步，即将 DOM 事件处理程序附加到渲染的网页上。

在`ProductsHandler`函数内，有两个调用对执行**附加**步骤至关重要：

```go
    InitializeProductsPage(env)
    env.Router.RegisterLinks("#primaryContent a")
```

首先，我们调用`InitializeProductsPage`函数添加必要的事件处理程序，以启用产品列表页面的用户交互：

```go
func InitializeProductsPage(env *common.Env) {

  buttons := env.Document.GetElementsByClassName("addToCartButton")
  for _, button := range buttons {
    button.AddEventListener("click", false, handleAddToCartButtonClickEvent)
  }

}
```

我们通过在`env.Document`对象上调用`GetElementsByClassName`方法，并指定`"addToCartButton"`类名，来检索产品列表页面上存在的所有加入购物车按钮。

当单击“加入购物车”按钮时，将调用`handleAddToCartButtonClickEvent`函数。在实现购物车功能时，我们将介绍这个函数。

让我们回到`ProductsHandler`函数。我们将在 Isokit 路由器对象上调用`RegisterLinks`方法，并指定 CSS 查询选择器`"#primaryContent a"`：

```go
env.Router.RegisterLinks("#primaryContent a")
```

这样可以确保在客户端渲染网页时，所有产品项链接的点击事件都将被客户端路由拦截。这将允许我们在客户端自身渲染产品详细页面，而无需执行完整的页面重新加载。

到目前为止，我们已经为产品列表页面实现了同构交接过程。要在客户端渲染产品列表页面，请在导航栏中单击产品链接。要在服务器端渲染产品列表页面，请直接在 Web 浏览器中输入以下 URL：`http://localhost:8080/products`。*图 6.3*显示了在客户端上渲染的产品列表页面：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/c7a8d2c3-eaeb-4b87-8b59-f24345b695ba.png)

图 6.3：在客户端上渲染的产品列表页面

您还可以刷新网页以强制在服务器端呈现页面。我们可以通过比较在客户端加载的网页和在服务器端加载的网页来验证等同手交接程序是否正确实现。由于两个网页都是相同的，我们可以确定等同手交接程序已成功实现。

# 为产品详细页面实现等同手交接

成功在产品列表页面上使用 ERDA 策略实现了等同手交接程序后，让我们专注于为产品详细页面实现等同手交接。

要实现**编码**步骤，我们首先需要确定表示我们希望保存到客户端的状态的数据对象。我们通过检查`handlers/productdetail.go`源文件中找到的`ProductDetailHandler`函数来识别数据对象。这是负责服务`/product-detail`路由的服务器端处理程序函数：

```go
func ProductDetailHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    productTitle := vars["productTitle"]
    product := env.DB.GetProductDetail(productTitle)
    templateData := &templatedata.ProductDetail{PageTitle: product.Name, Product: product}
    env.TemplateSet.Render("product_detail_page", &isokit.RenderParams{Writer: w, Data: templateData})
  })
}
```

从 Redis 数据存储中获取产品对象（以粗体显示）。该对象包含将显示在产品页面上的产品数据；因此，这是我们需要保存到客户端的对象。

`endpoints/productdetail.go`源文件中的`GetProductDetailEndpoint`函数是负责向客户端提供 JSON 编码的`Product`数据的 Rest API 端点：

```go
func GetProductDetailEndpoint(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    vars := mux.Vars(r)
    productTitle := vars["productTitle"]
    product := env.DB.GetProductDetail(productTitle)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(product)
  })
}
```

在`GetProductDetailEndpoint`函数内部，我们从 Redis 数据存储中获取产品对象，并将其编码为 JSON 格式数据。

现在我们已经处理了**编码**步骤，我们可以在客户端上实现接下来的三个步骤。

要实现**注册**步骤，我们在`client.go`源文件中添加以下行，以注册`/product-detail`路由及其关联的处理程序函数：

```go
r.Handle("/product-detail/{productTitle}", handlers.ProductDetailHandler(env))
```

**解码**和**附加**步骤由`ProductDetailHandler`函数执行：

```go
func ProductDetailHandler(env *common.Env) isokit.Handler {
  return isokit.HandlerFunc(func(ctx context.Context) {
    routeVars := ctx.Value(isokit.RouteVarsKey("Vars")).(map[string]string)
    productTitle := routeVars[`product-detail/{productTitle}`]
    productChannel := make(chan *models.Product)
 go FetchProductDetail(productChannel, productTitle)
    product := &lt;-productChannel
    templateData := &templatedata.ProductDetail{PageTitle: product.Name, Product: product}
    env.TemplateSet.Render("product_detail_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
    InitializeProductDetailPage(env)
  })
}
```

在`ProductDetailHandler`函数内部，我们调用`FetchProductDetail`函数作为一个 goroutine 来获取产品对象。**解码**步骤（以粗体显示）是在`FetchProductDetail`函数内部实现的：

```go
func FetchProductDetail(productChannel chan *models.Product, productTitle string) {

  data, err := xhr.Send("GET", "/restapi/get-product-detail"+"/"+productTitle, nil)
  if err != nil {
    println("Encountered error: ", err)
    println(err)
  }
  var product *models.Product
  json.NewDecoder(strings.NewReader(string(data))).Decode(&product)

  productChannel &lt;- product
}
```

我们发出 XHR 调用到 Rest API 端点，以获取编码的`Product`数据。我们使用 JSON 解码器将编码数据解码回`Product`对象。我们将`Product`对象发送到`productChannel`，在那里它会在`ProductDetailHandler`函数中接收到。

回到`ProductDetailHandler`函数，我们使用产品数据对象来填充产品详细页面上的产品信息。我们通过填充`templatedata.ProductDetail`对象的 Product 字段来实现这一点。再次回想一下，`templateData`变量是将传递到`env.TemplateSet`对象的`Render`方法中的数据对象：

```go
    templateData := &templatedata.ProductDetail{PageTitle: product.Name, Product: product}
    env.TemplateSet.Render("product_detail_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
```

到目前为止，我们已经完成了等同手交接程序的第三步，这意味着我们现在可以在客户端上呈现产品详细页面。现在，是时候完成程序的最后一步**附加**，通过将 DOM 事件处理程序附加到呈现的网页上的各自 UI 元素上。

我们调用`InitializeProductDetailPage`函数来添加必要的事件处理程序，以启用产品列表页面的用户交互：

```go
func InitializeProductDetailPage(env *common.Env) {

  buttons := env.Document.GetElementsByClassName("addToCartButton")
  for _, button := range buttons {
    button.AddEventListener("click", false, handleAddToCartButtonClickEvent)
  }
}
```

与`InitializeProductsPage`函数类似，我们检索网页上的所有“Add To Cart”按钮，并指定事件处理程序函数`handleAddToCartButtonClickEvent`，当单击“Add To Cart”按钮时将调用该函数。

到目前为止，我们已经为产品详细页面实现了等同手递手的过程。要在客户端渲染产品详细页面，请点击产品列表页面中的产品图片。要在服务器端渲染产品详细页面，请在网页浏览器中输入产品的 URL。例如，瑞士军刀的产品详细页面的 URL 是`http://localhost:8080/product-detail/swiss-army-knife`。*图 6.4*描述了在客户端渲染的瑞士军刀产品详细页面：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/64e2d5c3-b3f8-40bf-8b83-0e87a03a3e66.png)

图 6.4：在客户端渲染的产品详细页面

同样，我们可以通过确认在客户端渲染的网页与在服务器端渲染的网页相同来验证等同手递手过程是否正常运行。由于两个网页是相同的，我们可以得出结论，我们已经成功实现了产品详细页面的等同手递手过程。

# 实现购物车的等同手递手

现在我们已经为与产品相关的网页实现了等同手递手，是时候开始实现 IGWEB 的购物车功能了。我们将从设计购物车网页开始。

# 设计购物车页面

购物车页面的设计，如*图 6.5*中的线框设计所示，与产品列表页面非常相似。每个产品项目将包含产品的缩略图大小的图片，产品价格，产品名称和产品的简要描述，就像产品列表页面一样。除了这些字段，购物车页面还将有一个字段来显示数量，即购物车中特定产品的数量，以及一个“从购物车中移除”按钮，点击该按钮将从购物车中移除产品：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/8142b3e2-4b7b-4c15-95b0-907ace76b234.png)

图 6.5：显示购物车中有产品的购物车页面的线框设计

请记住，第一个线框设计涵盖了购物车已经填充了物品的情况。我们还必须考虑当购物车为空时页面的设计。购物车可能在用户首次访问 IGWEB 网站时为空，或者当用户完全清空购物车时。*图 6.6*是购物车页面的线框设计，描述了购物车为空的情况：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/1e37fbad-adbc-4c02-99b5-dfb451524763.png)

图 6.6：当购物车为空时，购物车页面的线框设计

现在我们已经确定了购物车页面的设计，是时候实现模板来实现设计了。

# 实现购物车模板

我们将使用购物车页面模板来在服务器端渲染购物车。以下是购物车页面模板的内容，定义在`shared/templates/shopping_cart_page.tmpl`源文件中：

```go
{{ define "pagecontent" }}
{{template "shopping_cart_content" . }}
{{end}}
{{template "layouts/webpage_layout" . }}
```

正如您可能已经注意到的，购物车页面模板调用了一个`shopping_cart_content`子模板，负责渲染购物车本身。

以下是购物车内容模板的内容，定义在`shared/templates/shopping_cart_content.tmpl`源文件中：

```go
&lt;h1&gt;Shopping Cart&lt;/h1&gt;

{{if .Products }}
{{range .Products}}
  &lt;div class="productCard"&gt;
    &lt;a href="{{.Route}}"&gt;
    &lt;div class="pricebox"&gt;&lt;span&gt;${{.Price}}&lt;/span&gt;&lt;/div&gt;
    &lt;div class="productCardImageContainer"&gt;
      &lt;img src="img/{{.ThumbnailPreviewURI}}"&gt;
    &lt;/div&gt;
    &lt;/a&gt;
    &lt;div class="productContainer"&gt;

    &lt;h3&gt;&lt;b&gt;{{.Name}}&lt;/b&gt;&lt;/h3&gt; 

    &lt;p&gt;{{.Description}}&lt;/p&gt; 

    &lt;div class="productQuantity"&gt;&lt;span&gt;Quantity: {{.Quantity}}&lt;/span&gt;&lt;/div&gt;

    &lt;div class="pure-controls"&gt;
      &lt;button class="removeFromCartButton pure-button pure-button-primary" data-sku="{{.SKU}}"&gt;Remove From Cart&lt;/button&gt;
    &lt;/div&gt;

    &lt;/div&gt;
  &lt;/div&gt;

{{end}}
{{else}}
&lt;h2&gt;Your shopping cart is empty.&lt;/h2&gt;
{{end}}
```

使用 `if` 操作，我们检查是否有任何商品要在购物车中显示。如果有，我们使用 `range` 操作来渲染每个购物车商品。我们渲染模板的名称、缩略图预览和描述，以及数量。最后，我们渲染一个按钮，以从购物车中移除产品。请注意，我们嵌入了一个名为 `data-sku` 的数据属性，将产品的唯一 `SKU` 代码与按钮元素一起包含在内。稍后，当我们通过单击此按钮调用 Rest API 端点来移除购物车商品时，这个值会派上用场。

如果购物车中没有要显示的商品，控制流将到达 `else` 操作。在这种情况下，我们将显示购物车为空的消息。

最后，我们将使用结束模板操作来表示 `if-else` 条件块的结束。

# 模板数据对象

将传递给模板渲染器的模板数据对象将是一个 `templatedata.ShoppingCart` 结构体（在 `shared/templatedata/shoppingcart.go` 源文件中定义）：

```go
type ShoppingCart struct {
  PageTitle string
  Products []*models.Product
}
```

`PageTitle` 字段将用于显示网页标题，`Products` 字段是 `Product` 对象的切片，将用于显示当前在购物车中的产品。

现在我们已经有了模板，让我们来看看如何对购物车进行建模。

# 对购物车进行建模

`ShoppingCartItem` 结构体在 `shared/models/shoppingcart.go` 源文件中定义，表示购物车中的商品：

```go
type ShoppingCartItem struct {
  ProductSKU string `json:"productSKU"`
  Quantity int `json:"quantity"`
}
```

`ProductSKU` 字段保存产品的 `SKU` 代码（用于区分产品的唯一代码），`Quantity` 字段保存用户希望购买的特定产品的数量。每当用户在产品列表或产品详细页面上点击“添加到购物车”按钮时，该特定产品的数量值将在购物车中递增。

`ShoppingCart` 结构体，也在 `shoppingcart.go` 源文件中定义，表示购物车：

```go
type ShoppingCart struct {
  Items map[string]*ShoppingCartItem `json:"items"`
}
```

`Items` 字段是一个项目的映射，其键为 `string` 类型（将是产品 `SKU` 代码），值将是指向 `ShoppingCartItem` 结构体的指针。

`NewShoppingCart` 函数是一个构造函数，用于创建 `ShoppingCart` 的新实例：

```go
func NewShoppingCart() *ShoppingCart {
  items := make(map[string]*ShoppingCartItem)
  return &ShoppingCart{Items: items}
}
```

`ShoppingCart` 类型的 `ItemTotal` 方法负责返回当前购物车中的商品数量：

```go
func (s *ShoppingCart) ItemTotal() int {
  return len(s.Items)
}
```

`ShoppingCart` 类型的 `IsEmpty` 方法负责告诉我们购物车是否为空：

```go
func (s *ShoppingCart) IsEmpty() bool {

  if len(s.Items) &gt; 0 {
    return false
  } else {
    return true
  }

}
```

`ShoppingCart` 类型的 `AddItem` 方法负责向购物车中添加商品：

```go
func (s *ShoppingCart) AddItem(sku string) {

  if s.Items == nil {
    s.Items = make(map[string]*ShoppingCartItem)
  }

  _, ok := s.Items[sku]
  if ok {
    s.Items[sku].Quantity += 1

  } else {
    item := ShoppingCartItem{ProductSKU: sku, Quantity: 1}
    s.Items[sku] = &item
  }

}
```

如果特定产品商品已经存在于购物车中，每次新请求添加产品商品时，`Quantity` 字段将递增一次。

同样，`ShoppingCart` 类型的 `RemoveItem` 方法负责从购物车中删除特定产品类型的所有商品：

```go
func (s *ShoppingCart) RemoveItem(sku string) bool {

  _, ok := s.Items[sku]
  if ok {
    delete(s.Items, sku)
    return true
  } else {
    return false
  }

}
```

`ShoppingCart` 类型的 `UpdateItemQuantity` 方法负责更新购物车中特定产品的数量：

```go
func (s *ShoppingCart) UpdateItemQuantity(sku string, quantity int) bool {

  _, ok := s.Items[sku]
  if ok {
    s.Items[sku].Quantity += 1
    return true
  } else {

    return false
  }

}
```

# 购物车路由

通过实现 `ShoppingCart` 类型，我们现在已经有了业务逻辑，可以驱动购物车功能。现在是时候注册服务器端路由，以实现购物车。

我们在 `igweb.go` 源文件中的 `registerRoutes` 函数中注册了 `/shopping-cart` 路由及其关联的处理程序函数 `ShoppingCartHandler`：

```go
r.Handle("/shopping-cart", handlers.ShoppingCartHandler(env))
```

路由处理程序函数 `ShoppingCartHandler` 负责在服务器端生成购物车页面的网页。

我们还注册了以下 Rest API 端点：

+   获取商品列表（`/restapi/get-cart-items`）

+   添加商品（`/restapi/add-item-to-cart`）

+   移除商品（`/restapi/remove-item-from-cart`）

# 获取商品列表

用于获取购物车中物品列表的，我们将注册`/restapi/get-cart-items`端点：

```go
r.Handle("/restapi/get-cart-items", endpoints.GetShoppingCartItemsEndpoint(env)).Methods("GET")
```

这个端点将由`GetShoppingCartItemsEndpoint`处理函数处理。这个端点负责将购物车编码为 JSON 编码数据，并提供给客户端应用程序。请注意，我们使用 HTTP 的`GET`方法来调用这个端点。

# 添加物品

用于将物品添加到购物车的，我们将注册`/restapi/add-item-to-cart`端点：

```go
r.Handle("/restapi/add-item-to-cart", endpoints.AddItemToShoppingCartEndpoint(env)).Methods("PUT")
```

这个路由将由`AddItemToShoppingCartEndpoint`处理函数处理。请注意，由于我们在 web 服务器上执行了一个改变操作（添加购物车物品），所以在调用这个端点时，我们使用 HTTP 的`PUT`方法。

# 移除物品

用于从购物车中移除特定产品类型的物品及其所有数量的，我们将注册`/restapi/remove-item-from-cart`端点：

```go
r.Handle("/restapi/remove-item-from-cart", endpoints.RemoveItemFromShoppingCartEndpoint(env)).Methods("DELETE")
```

这个端点将由`RemoveItemFromShoppingCartEndpoint`处理函数处理。再次请注意，由于我们在 web 服务器上执行了一个改变操作（移除购物车物品），所以在调用这个端点时，我们使用 HTTP 的`DELETE`方法。

# 会话存储

与产品记录存储在 Redis 数据库中不同，用户选择放入购物车的物品是瞬时的，并且是针对个人定制的。在这种情况下，将购物车的状态存储在会话中比存储在数据库中更有意义。

我们将使用 Gorilla 的`sessions`包来创建会话并将数据存储到会话中。我们将利用`session.NewFileSystemStore`类型将会话数据保存到服务器的文件系统中。

首先，我们将在`common/common.go`源文件中的`common.Env`结构体中添加一个新字段（以粗体显示），该字段将保存`FileSystemStore`实例，以便在整个服务器端 web 应用程序中访问：

```go
type Env struct {
  DB datastore.Datastore
  TemplateSet *isokit.TemplateSet
  Store *sessions.FilesystemStore
}
```

在`igweb.go`源文件中定义的`main`函数内，我们将调用`initializeSessionstore`函数并传入`env`对象：

```go
initializeSessionstore(&env)
```

`initializeSessionstore`函数负责在服务器端创建会话存储：

```go
func initializeSessionstore(env *common.Env) {
  if _, err := os.Stat("/tmp/igweb-sessions"); os.IsNotExist(err) {
    os.Mkdir("/tmp/igweb-sessions", 711)
  }
  env.Store = sessions.NewFilesystemStore("/tmp/igweb-sessions", []byte(os.Getenv("IGWEB_HASH_KEY")))
}
```

在`if`条件中，我们首先检查会话数据将被存储的指定路径`/tmp/igweb-sessions`是否存在。如果路径不存在，我们将调用`os`包中的`Mkdir`函数来创建文件夹。

我们将调用`sessions`包中的`NewFileSystemStore`函数来初始化一个新的文件系统会话存储，传入会话将被保存的路径和会话的身份验证密钥。我们将用新创建的`FileSystemStore`实例填充`env`对象的`Store`属性。

现在我们已经准备好了会话存储，让我们实现服务器端的`ShoppingCartHandler`函数。

# 服务器端购物车处理函数

在`handlers/shoppingcart.go`中定义的`ShoppingCartHandler`函数负责为`/shopping-cart`路由提供服务。

```go
func ShoppingCartHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
```

服务器端购物车处理函数的主要目的是为购物车网页生成输出。

回想一下，与产品相关页面的处理函数是从 Redis 数据存储中检索产品列表的。另一方面，购物车处理函数是从服务器端会话中获取购物车中物品列表的。

我们将声明`templateData`对象和购物车的变量：

```go
    var templateData *templatedata.ShoppingCart
    var cart *models.ShoppingCart
```

我们已经定义并初始化了`gorilla.SessionStore`类型的`igwSession`变量，它将保存我们的服务器端会话：

```go
    igwSession, _ := env.Store.Get(r, "igweb-session")
```

回想一下，我们可以通过访问`env`对象的`Store`属性来访问`FileSystemStore`对象。我们调用会话存储对象的`Get`方法，传入`http.Request`的指针`r`和会话的名称`"igweb-session"`。

如果会话不存在，将自动为我们创建一个名为`"igweb-session"`的新会话。

要访问会话中的值，我们使用`igwSession`对象的`Values`属性，它是一个键值对的映射。键是字符串，值是空接口`interface{}`类型，因此它们可以保存任何类型（因为 Go 中的所有类型都实现了空接口）。

在`if`条件块中，我们检查`Values`映射中是否存在`"shoppingCart"`会话键的值：

```go
if _, ok := igwSession.Values["shoppingCart"]; ok == true {
      // Shopping cart exists in session
      decoder := json.NewDecoder(strings.NewReader(string(igwSession.Values["shoppingCart"].([]byte))))
      err := decoder.Decode(&cart)
      if err != nil {
        log.Print("Encountered error when attempting to decode json data from session: ", err)
      }
```

使用`"shoppingCart"`键访问购物车对象的 JSON 编码值。如果会话中存在购物车，我们使用 JSON 解码器对象的`Decode`方法解码 JSON 对象。如果成功解码 JSON 对象，则将解码后的对象存储在`cart`变量中。

现在我们从会话中有了购物车对象，我们需要获取购物车中每个商品的产品信息。我们通过调用数据存储对象的`GetProductsInShoppingCart`方法，并将`cart`变量作为输入参数提供给该方法来实现。

```go
products := env.DB.GetProductsInShoppingCart(cart)
```

该函数将返回要在购物车页面上显示的产品切片。请注意，我们使用从数据存储获取的产品切片来填充`templatedata.ShoppingCart`对象的`Products`字段：

```go
templateData = &templatedata.ShoppingCart{PageTitle: "Shopping Cart", Products: products}
```

由于我们将利用这个产品切片来呈现服务器端的购物车模板页面，从`GetProductsInShoppingCart`方法返回的产品切片是我们在实现同构交接时需要持久保存到客户端的状态数据。

如果会话中不存在`"shoppingCart"`键，则控制流会进入`else`块：

```go
    } else {
      // Shopping cart doesn't exist in session
      templateData = &templatedata.ShoppingCart{PageTitle: "Shopping Cart", Products: nil}
    }
```

在这种情况下，我们将`templatedata.ShoppingCart`结构体的`Products`字段设置为`nil`，以表示购物车中没有产品，因为购物车在会话中不存在。

最后，我们通过在模板集对象上调用`Render`方法，传入我们希望呈现的模板的名称（`shopping_cart_page`模板）以及呈现参数来呈现购物车页面：

```go
  env.TemplateSet.Render("shopping_cart_page", &isokit.RenderParams{Writer: w, Data: templateData})
  })
}
```

请注意，我们已将`RenderParams`对象的`Writer`属性设置为`http.ResponseWriter`，`w`，并将`Data`属性设置为`templateData`变量。

让我们来看看在 Redis 数据存储中定义的`GetProductsInShoppingCart`方法（在`common/datastore/redis.go`源文件中找到）：

```go
func (r *RedisDatastore) GetProductsInShoppingCart(cart *models.ShoppingCart) []*models.Product {

  products := r.GetProducts()
  productsMap := r.GenerateProductsMap(products)

  result := make(models.Products, 0)
  for _, v := range cart.Items {
    product := &models.Product{}
    product = productsMap[v.ProductSKU]
    product.Quantity = v.Quantity
    result = append(result, product)
  }
  sort.Sort(result)
  return result

}
```

该方法的作用是返回购物车中所有产品的`Product`对象切片。`ShoppingCart`结构体简单地跟踪产品的类型（通过其`SKU`代码）以及购物车中该产品的`Quantity`。

我们声明一个`result`变量，它是`Product`对象的切片。我们循环遍历每个购物车项目，并从`productsMap`中检索`Product`对象，提供产品的`SKU`代码作为键。我们填充`Product`对象的`Quantity`字段，并将`Product`对象追加到`result`切片中。

我们调用 sort 包中的`Sort`方法，传入`result`切片。由于我们已经为`Products`类型实现了排序接口，`result`切片中的`Product`对象将按价格升序排序。最后，我们返回`result`切片。

# 购物车端点

此时，当我们完成服务器端功能以实现购物车功能时，我们也准备开始实现同构交接程序，遵循 ERDA 策略。

# 获取购物车中商品的端点

让我们来看看购物车的 Rest API 端点，这些端点帮助服务于客户端 Web 应用程序所依赖的操作。让我们从负责获取购物车中商品的端点函数`GetShoppingCartItemsEndpoint`开始，这个端点函数执行了等同交接过程中的**编码**步骤。

以下是`GetShoppingCartItemsEndpoint`函数的源代码列表：

```go
func GetShoppingCartItemsEndpoint(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    var cart *models.ShoppingCart
    igwSession, _ := env.Store.Get(r, "igweb-session")

    if _, ok := igwSession.Values["shoppingCart"]; ok == true {
      // Shopping cart exists in session
      decoder := json.NewDecoder(strings.NewReader(string(igwSession.Values["shoppingCart"].([]byte))))
      err := decoder.Decode(&cart)
      if err != nil {
        log.Print("Encountered error when attempting to decode json data from session: ", err)
      }

      products := env.DB.GetProductsInShoppingCart(cart)
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(products)

    } else {
      // Shopping cart doesn't exist in session
      cart = nil
      w.Header().Set("Content-Type", "application/json")
      json.NewEncoder(w).Encode(cart)
      return
    }

  })
}
```

在这个函数中，我们从会话中获取购物车。如果我们能够成功地从会话中获取购物车，我们就使用 JSON 编码器对`ShoppingCart`对象进行编码，并使用`http.ResponseWriter` `w`进行写入。

如果会话中不存在购物车，我们就简单地对`nil`的值进行 JSON 编码（在客户端等同于 JavaScript 的`null`），并使用`http.ResponseWriter` `w`在响应中写出。

有了这段代码，我们已经完成了等同交接过程中的编码步骤。

# 添加商品到购物车的端点

我们在`AddItemToShoppingCartEndpoint`中声明了一个`m`变量（加粗显示），类型为`map[string]string`，这是负责向购物车添加新商品的端点函数：

```go
func AddItemToShoppingCartEndpoint(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    igwSession, _ := env.Store.Get(r, "igweb-session")
    decoder := json.NewDecoder(r.Body)
    var m map[string]string
    err := decoder.Decode(&m)
    if err != nil {
      log.Print("Encountered error when attempting to decode json data from request body: ", err)
    }
    defer r.Body.Close()

    var cart *models.ShoppingCart
```

我们使用 JSON 解码器来解码请求体，其中包含从客户端发送的 JSON 编码的映射。该映射将包含要添加到购物车的产品的`SKU`值，给定`"productSKU"`键。

我们将检查会话中是否存在购物车。如果存在，我们将把购物车的 JSON 数据解码回`ShoppingCart`对象：

```go
if _, ok := igwSession.Values["shoppingCart"]; ok == true {
      // Shopping Cart Exists in Session
      decoder := json.NewDecoder(strings.NewReader(string(igwSession.Values["shoppingCart"].([]byte))))
      err := decoder.Decode(&cart)
      if err != nil {
        log.Print("Encountered error when attempting to decode json data from session: ", err)
      }
```

如果购物车不存在，控制流将到达`else`块，我们将创建一个新的购物车：

```go
} else {
      // Shopping Cart Doesn't Exist in Session, Create a New One
      cart = models.NewShoppingCart()
    }
```

然后我们将调用`ShoppingCart`对象的`AddItem`方法来添加产品项：

```go
cart.AddItem(m["productSKU"])
```

要向购物车添加商品，我们只需提供产品的`SKU`值，这个值可以从`m`映射变量中获取，通过访问`productSKU`键的映射值。

我们将把购物车对象编码为其 JSON 表示形式，并保存到会话中，会话键为`"shoppingCart"`：

```go
    b := new(bytes.Buffer)
    w.Header().Set("Content-Type", "application/json")
    err = json.NewEncoder(b).Encode(cart)
    if err != nil {
      log.Print("Encountered error when attempting to encode cart struct as json data: ", err)
    }
 igwSession.Values["shoppingCart"] = b.Bytes()
 igwSession.Save(r, w)
    w.Write([]byte("OK"))
  })
```

然后我们将响应`"OK"`写回客户端，以表明成功执行了向购物车添加新商品的操作。

# 从购物车中移除商品的端点

以下是`RemoveItemFromShoppingCartEndpoint`的源代码列表，这个端点负责从购物车中移除特定产品的所有商品：

```go
func RemoveItemFromShoppingCartEndpoint(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    igwSession, _ := env.Store.Get(r, "igweb-session")
    decoder := json.NewDecoder(r.Body)
    var m map[string]string
    err := decoder.Decode(&m)
    if err != nil {
      log.Print("Encountered error when attempting to decode json data from request body: ", err)
    }
    defer r.Body.Close()

    var cart *models.ShoppingCart
    if _, ok := igwSession.Values["shoppingCart"]; ok == true {
      // Shopping Cart Exists in Session
      decoder := json.NewDecoder(strings.NewReader(string(igwSession.Values["shoppingCart"].([]byte))))
      err := decoder.Decode(&cart)
      if err != nil {
        log.Print("Encountered error when attempting to decode json data from session: ", err)
      }
    } else {
      // Shopping Cart Doesn't Exist in Session, Create a New One
      cart = models.NewShoppingCart()
    }

    for k, v := range cart.Items {
      if v.ProductSKU == m["productSKU"] {
        delete(cart.Items, k)
      }
    }

    b := new(bytes.Buffer)
    w.Header().Set("Content-Type", "application/json")
    err = json.NewEncoder(b).Encode(cart)
    if err != nil {
      log.Print("Encountered error when attempting to encode cart struct as json data: ", err)
    }
    igwSession.Values["shoppingCart"] = b.Bytes()
    igwSession.Save(r, w)

    w.Write([]byte("OK"))

  })
}
```

请记住，对于给定的产品，我们可以有多个数量。在当前的购物车实现中，如果用户点击“从购物车中移除”按钮，那么该产品（以及所有数量）将从购物车中移除。

我们首先从会话中获取 JSON 编码的购物车数据。如果存在，我们将 JSON 对象解码为一个新的`ShoppingCart`对象。如果会话中不存在购物车，我们就简单地创建一个新的购物车。

我们遍历购物车中的商品，如果我们能够在购物车中找到包含与从客户端 Web 应用程序获取的`m`映射变量中提供的相同产品`SKU`代码的产品，我们将通过调用内置的`delete`函数（加粗显示）从购物车对象的`Items`映射中删除该元素。最后，我们将向客户端写出一个 JSON 编码的响应，表示操作已成功完成。

现在我们已经在服务器端设置了端点，是时候看看客户端需要实现购物车功能的最后部分了。

# 在客户端实现购物车功能

为了完成 ERDA 策略的**注册**步骤，我们将在`client/client.go`源文件中的`registerRoutes`函数中注册`/shopping-cart`路由及其关联的处理函数`ShoppingCartHandler`：

```go
r.Handle("/shopping-cart", handlers.ShoppingCartHandler(env))
```

请记住，当用户点击导航栏中的购物车图标访问购物车时，将会触发此路由。点击购物车图标后，将调用`ShoppingCartHandler`函数。

让我们来看一下`ShoppingCartHandler`函数：

```go
func ShoppingCartHandler(env *common.Env) isokit.Handler {
  return isokit.HandlerFunc(func(ctx context.Context) {
    renderShoppingCartItems(env)
  })
}
```

这个函数的主要目的是调用`renderShoppingCartItems`函数在客户端上渲染购物车。我们已经将渲染购物车及其内容的逻辑整合到`renderShoppingCartItems`函数中，以便在用户从购物车中移除商品时重新渲染购物车页面。

# 渲染购物车

`renderShoppingCartItems`函数负责执行 ERDA 策略的最后两个步骤，即**解码**和**附加**步骤。以下是`renderShoppingCartItems`函数的源代码清单：

```go
func renderShoppingCartItems(env *common.Env) {

  productsChannel := make(chan []*models.Product)
  go fetchProductsInShoppingCart(productsChannel)
  products := &lt;-productsChannel
  templateData := &templatedata.ShoppingCart{PageTitle: "Shopping Cart", Products: products}
  env.TemplateSet.Render("shopping_cart_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
  InitializeShoppingCartPage(env)
  env.Router.RegisterLinks("#primaryContent a")
}
```

在这个函数中，我们创建了一个名为`productsChannel`的新通道，这是一个我们将用来发送和接收产品切片的通道。我们调用`fetchProductsInShoppingCart`函数作为一个 goroutine，并将`productsChannel`作为函数的输入参数。该函数负责通过执行 XHR 调用从服务器获取购物车中的产品项目。

以下是`fetchProductsInShoppingCart`函数的源代码清单：

```go
func fetchProductsInShoppingCart(productsChannel chan []*models.Product) {

 data, err := xhr.Send("GET", "/restapi/get-cart-items", nil)
 if err != nil {
 println("Encountered error: ", err)
 println(err)
 }
 var products []*models.Product
 json.NewDecoder(strings.NewReader(string(data))).Decode(&products)

 productsChannel &lt;- products
}
```

在这个函数中，我们只是对 Rest API 端点`/restapi/get-cart-items`进行 XHR 调用，该端点负责返回表示产品切片的 JSON 编码数据。我们使用 JSON 解码器将编码的产品切片解码到`products`变量中。最后，我们通过`productsChannel`发送`products`变量。

让我们回到`renderShoppingCartItems`函数，并从`productsChannel`接收产品切片，然后我们将使用接收到的产品设置`templateData`对象的`Products`属性：

```go
templateData := &templatedata.ShoppingCart{PageTitle: "Shopping Cart", Products: products}
```

然后我们将在客户端上渲染购物车模板：

```go
env.TemplateSet.Render("shopping_cart_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
```

到目前为止，我们已经完成了 ERDA 策略的**解码**步骤。

为了完成 ERDA 策略的**附加**步骤，我们将调用`InitializeShoppingCartEventHandlers`函数，以便将任何所需的事件监听器附加到购物车网页上。

以下是`InitializeShoppingCartEventHandlers`函数的源代码清单：

```go
func InitializeShoppingCartPage(env *common.Env) {

  buttons := env.Document.GetElementsByClassName("removeFromCartButton")
  for _, button := range buttons {
    button.AddEventListener("click", false,
      func(event dom.Event) {
        handleRemoveFromCartButtonClickEvent(env, event)

      })
  }

}
```

这个函数负责在购物车网页上的每个产品容器中找到的所有“从购物车中移除”按钮上附加点击事件。当点击“从购物车中移除”按钮时，调用的事件处理函数是`handleRemoveFromCartButtonClickEvent`函数。

通过在购物车网页上的“从购物车中移除”按钮上附加事件监听器，我们已经完成了 ERDA 策略的第四步，也是最后一步。购物车功能的同构交接实现已经完成。

# 从购物车中移除商品

让我们来看一下`handleRemoveFromCartButtonClickEvent`函数，当点击“从购物车中移除”按钮时会调用该函数：

```go
func handleRemoveFromCartButtonClickEvent(env *common.Env, event dom.Event) {
  productSKU := event.Target().GetAttribute("data-sku")
  go removeFromCart(env, productSKU)
}
```

在这个函数中，我们从事件目标元素的`data-sku`属性中获取产品的`SKU`代码。然后我们调用`removeFromCart`函数作为一个 goroutine，传入`env`对象和`productSKU`。

以下是`removeFromCart`函数的源代码清单：

```go
func removeFromCart(env *common.Env, productSKU string) {

  m := make(map[string]string)
  m["productSKU"] = productSKU
  jsonData, _ := json.Marshal(m)

  data, err := xhr.Send("DELETE", "/restapi/remove-item-from-cart", jsonData)
  if err != nil {
    println("Encountered error: ", err)
    notify.Error("Failed to remove item from cart!")
    return
  }
  var products []*models.Product
  json.NewDecoder(strings.NewReader(string(data))).Decode(&products)
  renderShoppingCartItems(env)
  notify.Success("Item removed from cart")
}
```

在`removeFromCart`函数中，我们创建一个新地图`m`，用于存储`productSKU`。我们可以通过提供`"productSKU"`键从`m`地图中访问产品的`SKU`值。我们打算通过请求主体将此地图发送到 Web 服务器。我们选择`map`类型的原因是，我们希望使我们的解决方案具有可扩展性。将来，如果有任何其他信息应发送到服务器，我们可以将该值作为地图中的附加键值对的一部分包含进来。

我们将地图编码为其 JSON 表示，并对 Web 服务器进行 XHR 调用，发送地图 JSON 数据。最后，我们调用`renderShoppingCartItems`函数来渲染购物车商品。请记住，通过调用此函数，我们将执行 XHR 调用以获取购物车中最新的产品（代表购物车的当前状态）。这确保了我们将拥有购物车的最新状态，因为我们再次使用服务器端会话（购物车状态存储在其中）作为我们的唯一真相来源。

# 将商品添加到购物车

“添加到购物车”按钮的功能以类似的方式实现。请记住，在与产品相关的页面上，如果单击任何“添加到购物车”按钮，将调用`handleAddToCarButton`函数。以下是该函数的源代码列表：

```go
func handleAddToCartButtonClickEvent(event dom.Event) {
  productSKU := event.Target().GetAttribute("data-sku")
  go addToCart(productSKU)
}
```

与`handleRemoveFromCartButtonClickEvent`函数类似，在`handleAddToCart`函数内，我们通过获取带有`“data-sku”`键的数据属性，从事件目标元素中获取产品的`SKU`代码。然后我们调用`addToCart`函数作为一个 goroutine，并将`productSKU`作为输入参数提供给函数。

以下是`addToCart`函数的源代码列表：

```go
func addToCart(productSKU string) {

  m := make(map[string]string)
  m["productSKU"] = productSKU
  jsonData, _ := json.Marshal(m)

  data, err := xhr.Send("PUT", "/restapi/add-item-to-cart", jsonData)
  if err != nil {
    println("Encountered error: ", err)
    notify.Error("Failed to add item to cart!")
    return
  }
  var products []*models.Product
  json.NewDecoder(strings.NewReader(string(data))).Decode(&products)
  notify.Success("Item added to cart")
}
```

在`addToCart`函数中，我们对 Web 服务器上负责向购物车添加项目的 Rest API 端点进行 XHR 调用。在进行 XHR 调用之前，我们创建一个包含`productSKU`的地图，然后将地图编码为其 JSON 表示。我们使用 XHR 调用将 JSON 数据发送到服务器端点。

我们现在可以在客户端显示购物车，还可以适应用户与购物车的交互，特别是将产品添加到购物车和从购物车中删除产品。

本章介绍的购物车实现仅用于说明目的。读者可以自行实现进一步的功能。

# 验证购物车功能

现在是时候验证购物车的状态是否从服务器到客户端保持不变，因为用户向购物车中添加和删除项目。

验证等价交接是否成功实施非常简单。我们只需要验证服务器端生成的购物车页面是否与客户端生成的购物车页面相同。通过单击购物车图标，我们可以看到客户端生成的网页。在购物车页面上单击刷新按钮，我们可以看到服务器端生成的网页。

一开始，购物车中没有放置任何物品。*图 6.7*是一个截图，描述了购物车处于空状态时的情况：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/ed44a1f1-4a86-4597-9bc5-0d161404ba33.png)

图 6.7：购物车为空时的购物车页面

在客户端渲染的购物车页面与服务器端渲染的页面匹配，表明购物车的空状态得到了正确维护。

现在，让我们通过点击导航栏上的产品链接来访问产品列表页面。通过点击“添加到购物车”按钮，向购物车中添加一些商品。然后点击网站顶部栏中的购物车图标返回到购物车页面。*图 6.8*是一个截图，显示了购物车中添加了一些商品：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/23dbfb75-e299-4ca5-8a6f-83f747859260.png)

图 6.8：购物车页面中有一些商品在购物车中

在检查客户端渲染的购物车页面与服务器端渲染的页面是否匹配后，我们可以确定购物车的状态已成功维护。

现在，通过点击每个产品上的“从购物车中移除”按钮，从购物车中移除所有商品。一旦购物车为空，我们可以执行相同的验证步骤，检查客户端渲染的页面与服务器端渲染的页面是否相同，以确定购物车状态是否成功维护。

在这一点上，我们可以确认等同手交程序已成功实现了购物车功能。

您可能已经注意到，当我们向购物车添加商品时，屏幕右下角会显示通知，如*图 6.9*所示。请注意，通知显示在网页的右下角，并指示产品已成功添加到购物车中。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/2636829e-fbcb-4a38-b257-db6f8a6da20b.png)

图 6.9：当商品被添加到购物车时，通知出现在页面的右下角

请注意，当从购物车中移除商品时，也会出现类似的通知。我们利用了一个可重用的组件“齿轮”来生成这个通知。我们将在第九章中介绍负责生成这些通知的齿轮的实现，*齿轮-可重用组件*。

# 总结

在本章中，我们向您介绍了*等同手交*，即服务器将状态传递给客户端的方式。这是一个重要的过程，允许客户端在等同的网络应用程序中继续服务器中断的工作。我们演示了 ERDA 策略，以实现产品相关网页和购物车网页的等同手交。在实现购物车功能时，我们创建了一个服务器端会话存储，它充当了用户购物车当前状态的真相来源。我们实现了服务器端端点来实现从购物车获取商品、向购物车添加商品和从购物车删除商品的功能。最后，我们通过确认客户端渲染的网页与服务器端渲染的网页完全相同来验证等同手交是否成功实现。

我们还依赖服务器端的真相来源来维护与客户端的状态。对于与产品相关的页面，真相来源是 Redis 数据存储，对于购物车页面，唯一的真相来源是服务器端的会话存储。在第七章中，*等同网络表单*，我们将考虑如何处理超出基本用户交互的情况。您将学习如何接受客户端生成的数据，通过等同网络表单提交。您将学习如何验证和处理用户提交的数据，通过在 IGWEB 的联系网页上实现联系表单。
